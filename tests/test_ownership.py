import hashlib
import time

import pytest
from fastapi.testclient import TestClient

from backend.store import Store, canonical, uid
from test_platform import PASSWORD, system, invited, post
from test_sharing import setup_identity, create, grant, sign, payload, b64
from test_sharing_passphrase import rewrap


def setup(system):
    app,owner,_=system;who=setup_identity(owner);next_client=invited(app,owner);successor=setup_identity(next_client)
    vault=create(owner,who)
    assert post(owner,'/team-vaults/'+vault+'/invite',grant(who,successor,vault,'editor')).status_code==200
    assert post(next_client,'/team-vaults/'+vault+'/accept',{}).status_code==200
    return app,owner,who,next_client,successor,vault


def digest_view(team):
    value={key:team[key] for key in ('id','workspace','owner','owner_fingerprint','epoch','revision','rotation_required','browser_policy','manifest','payload')}
    value['grants']=sorted([{'user_id':m['user_id'],'role':m['role'],'accepted':bool(m['accepted']),'envelope':m['envelope']} for m in team['grants']],key=lambda m:m['user_id'])
    return hashlib.sha256(canonical(value).encode()).hexdigest()


def proposal(client,owner,successor,vault,former='removed'):
    team=client.get('/api/team-vaults/'+vault).json()
    document={'action':'team_vault.ownership.v1','version':1,'id':uid(),'vault_id':vault,'workspace':team['workspace'],'owner':owner['id'],'recipient':successor['id'],'owner_fingerprint':owner['fingerprint'],'recipient_fingerprint':successor['fingerprint'],'state_digest':digest_view(team),'revision':team['revision'],'epoch':team['epoch'],'former_owner_role':former,'expires_at':int(time.time()+900)}
    return {'document':document,'signature':sign(owner,document)}


def propose(client,body,vault):
    response=post(client,'/team-vaults/'+vault+'/ownership',body)
    assert response.status_code==200,response.text
    return response.json()['proposal']


def resign_acceptance(body,successor,authorization):
    document={'action':'team_vault.ownership_accept.v1','state_digest':authorization['document']['state_digest'],**{k:v for k,v in body.items() if k!='signature'}}
    body['signature']=sign(successor,document)
    return body


def acceptance(owner_client,successor,authorization,identities):
    document=authorization['document'];vault=document['vault_id'];team=owner_client.get('/api/team-vaults/'+vault).json()
    manifest={'id':vault,'workspace':team['workspace'],'owner':successor['id'],'owner_fingerprint':successor['fingerprint']}
    grants=[]
    for member in team['grants']:
        if member['user_id']==team['owner'] and document['former_owner_role']=='removed':continue
        role='owner' if member['user_id']==successor['id'] else document['former_owner_role'] if member['user_id']==team['owner'] else member['role']
        grants.append(grant(successor,identities[member['user_id']],vault,role,team['epoch']+1))
    body={'proposal_id':document['id'],'revision':team['revision'],'manifest_signature':sign(successor,manifest),'payload':payload(vault,team['epoch']+1),'grants':grants}
    return resign_acceptance(body,successor,authorization)


def test_two_sided_transfer_preserves_scope_and_revokes_old_connections_and_plans(system):
    app,owner,who,next_client,successor,vault=setup(system)
    before=owner.get('/api/team-vaults/'+vault).json();body=proposal(owner,who,successor,vault)
    authorization=propose(owner,body,vault)
    assert owner.get('/api/workspace').json()['ownership_requests']==[]
    assert next_client.get('/api/workspace').json()['ownership_requests'][0]['vault_id']==vault
    assert next_client.get('/api/team-vaults').json()['vaults'][0]['ownership_pending']
    assert owner.get('/api/team-vaults/'+vault).json()==before
    assert next_client.get('/api/team-vaults/'+vault+'/ownership').json()['proposal']['status']=='pending'
    assert post(owner,'/team-vaults/'+vault+'/ownership',proposal(owner,who,successor,vault)).status_code==409
    tokens=[]
    for client in (owner,next_client):
        paired=post(client,'/companions',{'kind':'shared','vault_id':vault,'password':PASSWORD,'label':'Fixture browser'})
        assert paired.status_code==200;tokens.append(paired.json()['token'])
    from test_credential_actions import approval
    action,_=approval(next_client,vault,'shared')
    personal=post(owner,'/vaults',{'name':'Personal scope'}).json()['id']
    personal_token=post(owner,'/companions',{'vault_id':personal,'password':PASSWORD,'label':'Personal fixture'}).json()['token']
    accepted=acceptance(owner,successor,authorization,{who['id']:who,successor['id']:successor})
    response=post(next_client,'/team-vaults/'+vault+'/ownership/accept',accepted)
    assert response.status_code==200,response.text
    assert response.json()=={'owner':successor['id'],'epoch':2,'revision':2,'shared_connections_revoked':True}
    current=next_client.get('/api/team-vaults/'+vault).json()
    assert current['owner']==successor['id'] and current['role']=='owner'
    assert current['payload']==accepted['payload'] and current['epoch']==2
    assert next_client.get('/api/workspace').json()['ownership_requests']==[]
    assert [member['user_id'] for member in current['grants']]==[successor['id']]
    assert owner.get('/api/team-vaults/'+vault).status_code==404
    browser=TestClient(app)
    for token in tokens:assert browser.get('/api/companion/vault',headers={'Authorization':'Bearer '+token}).status_code==401
    assert browser.get('/api/companion/vault',headers={'Authorization':'Bearer '+personal_token}).status_code==200
    with app.state.store.connect() as c:
        assert c.execute('SELECT status FROM credential_actions WHERE id=?',(action,)).fetchone()[0]=='cancelled'
        audit=Store.audit(c,before['workspace']);assert audit['valid'] and audit['events'][-1]['action']=='team_vault.ownership_transferred'
    assert post(next_client,'/team-vaults/'+vault+'/ownership/accept',accepted).status_code==409


@pytest.mark.parametrize('former',['viewer','editor','admin'])
def test_former_owner_keeps_only_explicitly_approved_role(system,former):
    _,owner,who,next_client,successor,vault=setup(system)
    authorization=propose(owner,proposal(owner,who,successor,vault,former),vault)
    body=acceptance(owner,successor,authorization,{who['id']:who,successor['id']:successor})
    assert post(next_client,'/team-vaults/'+vault+'/ownership/accept',body).status_code==200
    current=owner.get('/api/team-vaults/'+vault).json()
    assert current['role']==former and current['owner']==successor['id']
    assert post(owner,'/team-vaults/'+vault+'/ownership',proposal(owner,who,successor,vault)).status_code==403


@pytest.mark.parametrize('change',['save','policy','invite','accept'])
def test_snapshot_binding_rejects_content_or_permission_changes_without_partial_writes(system,change):
    app,owner,who,next_client,successor,vault=setup(system)
    third=invited(app,owner,'viewer',email='third@example.test');third_id=setup_identity(third)
    if change=='accept':assert post(owner,'/team-vaults/'+vault+'/invite',grant(who,third_id,vault)).status_code==200
    authorization=propose(owner,proposal(owner,who,successor,vault),vault)
    body=acceptance(owner,successor,authorization,{who['id']:who,successor['id']:successor,third_id['id']:third_id})
    if change=='save':assert post(owner,'/team-vaults/'+vault+'/save',{'revision':1,'payload':payload(vault)}).status_code==200
    elif change=='policy':assert post(owner,'/team-vaults/'+vault+'/browser-policy',{'browser_fill':False}).status_code==200
    elif change=='invite':assert post(owner,'/team-vaults/'+vault+'/invite',grant(who,third_id,vault)).status_code==200
    else:assert post(third,'/team-vaults/'+vault+'/accept',{}).status_code==200
    expected=owner.get('/api/team-vaults/'+vault).json()
    assert next_client.get('/api/team-vaults/'+vault+'/ownership').json()['proposal']['status']=='stale'
    assert post(next_client,'/team-vaults/'+vault+'/ownership/accept',body).status_code==409
    assert owner.get('/api/team-vaults/'+vault).json()==expected


@pytest.mark.parametrize('damage',['signature','digest','scope','recipient_fingerprint','extra'])
def test_invalid_owner_authorization_does_not_create_a_proposal(system,damage):
    _,owner,who,next_client,successor,vault=setup(system)
    body=proposal(owner,who,successor,vault)
    if damage=='signature':body['signature']=b64(b'\0'*64)
    elif damage=='digest':body['document']['state_digest']='0'*64
    elif damage=='scope':body['document']['workspace']='e'*24
    elif damage=='recipient_fingerprint':body['document']['recipient_fingerprint']='0'*64
    else:body['document']['password']='forbidden-fixture'
    response=post(owner,'/team-vaults/'+vault+'/ownership',body)
    assert response.status_code in {409,422},response.text
    assert next_client.get('/api/team-vaults/'+vault+'/ownership').json()['proposal'] is None


@pytest.mark.parametrize('damage',['proof','manifest','member_set','roles','epoch'])
def test_malformed_recipient_consent_rolls_back_every_vault_change(system,damage):
    _,owner,who,next_client,successor,vault=setup(system)
    authorization=propose(owner,proposal(owner,who,successor,vault,'admin'),vault)
    body=acceptance(owner,successor,authorization,{who['id']:who,successor['id']:successor})
    if damage=='proof':body['signature']=b64(b'\0'*64)
    else:
        if damage=='manifest':body['manifest_signature']=b64(b'\0'*64)
        elif damage=='member_set':body['grants']=body['grants'][:1]
        elif damage=='roles':body['grants'][0]['role']='viewer'
        elif damage=='epoch':body['payload']['epoch']=8
        resign_acceptance(body,successor,authorization)
    expected=owner.get('/api/team-vaults/'+vault).json()
    assert post(next_client,'/team-vaults/'+vault+'/ownership/accept',body).status_code==422
    assert owner.get('/api/team-vaults/'+vault).json()==expected


def test_only_intended_recipient_can_accept_and_either_party_can_stop(system):
    app,owner,who,next_client,successor,vault=setup(system)
    authorization=propose(owner,proposal(owner,who,successor,vault),vault)
    body=acceptance(owner,successor,authorization,{who['id']:who,successor['id']:successor})
    assert post(owner,'/team-vaults/'+vault+'/ownership/accept',body).status_code==403
    assert TestClient(app).post('/api/team-vaults/'+vault+'/ownership/accept',json=body).status_code==401
    assert next_client.post('/api/team-vaults/'+vault+'/ownership/accept',json=body).status_code==403
    identifier=authorization['id']
    assert post(next_client,'/team-vaults/'+vault+'/ownership/'+identifier+'/cancel',{}).json()['status']=='declined'
    assert post(next_client,'/team-vaults/'+vault+'/ownership/accept',body).status_code==409
    another=propose(owner,proposal(owner,who,successor,vault),vault)
    assert post(owner,'/team-vaults/'+vault+'/ownership/'+another['id']+'/cancel',{}).json()['status']=='cancelled'


def test_expired_recipient_authorization_cannot_take_ownership(system,monkeypatch):
    _,owner,who,next_client,successor,vault=setup(system)
    authorization=propose(owner,proposal(owner,who,successor,vault),vault)
    body=acceptance(owner,successor,authorization,{who['id']:who,successor['id']:successor})
    monkeypatch.setattr('backend.ownership.time.time',lambda:authorization['document']['expires_at']+1)
    assert next_client.get('/api/team-vaults/'+vault+'/ownership').json()['proposal']['status']=='expired'
    assert post(next_client,'/team-vaults/'+vault+'/ownership/accept',body).status_code==409


def test_policy_change_and_reversal_cannot_revive_an_earlier_approval(system):
    _,owner,who,next_client,successor,vault=setup(system)
    authorization=propose(owner,proposal(owner,who,successor,vault),vault)
    body=acceptance(owner,successor,authorization,{who['id']:who,successor['id']:successor})
    policy=owner.get('/api/team-vaults/'+vault).json()['browser_policy']
    assert post(owner,'/team-vaults/'+vault+'/browser-policy',{**policy,'browser_fill':False}).status_code==200
    assert post(owner,'/team-vaults/'+vault+'/browser-policy',policy).status_code==200
    assert next_client.get('/api/team-vaults/'+vault+'/ownership').json()['proposal']['status']=='stale'
    assert post(next_client,'/team-vaults/'+vault+'/ownership/accept',body).status_code==409


def test_pending_or_workspace_viewer_cannot_be_named_as_successor(system):
    app,owner,who,next_client,successor,vault=setup(system)
    third=invited(app,owner,'reviewer',email='readonly@example.test');reader=setup_identity(third)
    assert post(owner,'/team-vaults/'+vault+'/invite',grant(who,reader,vault)).status_code==200
    body=proposal(owner,who,reader,vault)
    assert post(owner,'/team-vaults/'+vault+'/ownership',body).status_code==422
    assert post(third,'/team-vaults/'+vault+'/accept',{}).status_code==200
    with app.state.store.connect(write=True) as c:
        c.execute('UPDATE members SET role=? WHERE user=? AND workspace=?',('viewer',reader['id'],owner.get('/api/me').json()['workspace']))
    assert post(owner,'/team-vaults/'+vault+'/ownership',proposal(owner,who,reader,vault)).status_code==422


@pytest.mark.parametrize('changing',['owner','recipient'])
def test_sharing_passphrase_change_cancels_pending_authorizations(system,changing):
    _,owner,who,next_client,successor,vault=setup(system)
    authorization=propose(owner,proposal(owner,who,successor,vault),vault)
    body=acceptance(owner,successor,authorization,{who['id']:who,successor['id']:successor})
    client,identity=(owner,who) if changing=='owner' else (next_client,successor)
    assert post(client,'/sharing/identity/passphrase',rewrap(identity)).status_code==200
    assert next_client.get('/api/team-vaults/'+vault+'/ownership').json()['proposal']['status']=='cancelled'
    assert post(next_client,'/team-vaults/'+vault+'/ownership/accept',body).status_code==409


def test_transfer_unblocks_offboarding_of_a_vault_owner_who_is_not_workspace_owner(system):
    app,admin,_=system
    creator=invited(app,admin,'analyst',email='creator@example.test');owner=setup_identity(creator)
    next_client=invited(app,admin,'reviewer',email='successor@example.test');successor=setup_identity(next_client)
    vault=create(creator,owner)
    assert post(creator,'/team-vaults/'+vault+'/invite',grant(owner,successor,vault,'editor')).status_code==200
    assert post(next_client,'/team-vaults/'+vault+'/accept',{}).status_code==200
    assert post(admin,'/members/'+owner['id']+'/offboard',{'password':PASSWORD}).status_code==409
    authorization=propose(creator,proposal(creator,owner,successor,vault),vault)
    body=acceptance(creator,successor,authorization,{owner['id']:owner,successor['id']:successor})
    assert post(next_client,'/team-vaults/'+vault+'/ownership/accept',body).status_code==200
    assert post(admin,'/members/'+owner['id']+'/offboard',{'password':PASSWORD}).status_code==200
    assert next_client.get('/api/team-vaults/'+vault).json()['role']=='owner'


def test_pending_third_party_grant_keeps_its_role_and_acceptance_state(system):
    app,owner,who,next_client,successor,vault=setup(system)
    third=invited(app,owner,'viewer',email='pending@example.test');reader=setup_identity(third)
    assert post(owner,'/team-vaults/'+vault+'/invite',grant(who,reader,vault)).status_code==200
    authorization=propose(owner,proposal(owner,who,successor,vault),vault)
    body=acceptance(owner,successor,authorization,{who['id']:who,successor['id']:successor,reader['id']:reader})
    assert post(next_client,'/team-vaults/'+vault+'/ownership/accept',body).status_code==200
    current=next_client.get('/api/team-vaults/'+vault).json()
    member=next(row for row in current['grants'] if row['user_id']==reader['id'])
    assert member['role']=='viewer' and not member['accepted']
    assert third.get('/api/team-vaults/'+vault).json()['payload'] is None
    assert third.get('/api/team-vaults/'+vault+'/ownership').status_code==409


def test_wrong_workspace_cannot_inspect_or_accept_a_transfer(system):
    _,owner,who,next_client,successor,vault=setup(system)
    authorization=propose(owner,proposal(owner,who,successor,vault),vault)
    body=acceptance(owner,successor,authorization,{who['id']:who,successor['id']:successor})
    another=post(next_client,'/workspaces',{'name':'Unrelated client'}).json()['id']
    assert post(next_client,'/workspaces/'+another+'/switch',{}).status_code==200
    assert next_client.get('/api/team-vaults/'+vault+'/ownership').status_code==404
    assert post(next_client,'/team-vaults/'+vault+'/ownership/accept',body).status_code==404
    assert next_client.get('/api/workspace').json()['ownership_requests']==[]


def test_idempotent_invitation_acceptance_does_not_invalidate_a_proposal(system):
    _,owner,who,next_client,successor,vault=setup(system)
    authorization=propose(owner,proposal(owner,who,successor,vault),vault)
    assert post(next_client,'/team-vaults/'+vault+'/accept',{}).status_code==200
    assert next_client.get('/api/team-vaults/'+vault+'/ownership').json()['proposal']['status']=='pending'
