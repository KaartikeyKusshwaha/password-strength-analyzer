import base64
import time

import pytest
from fastapi.testclient import TestClient

from backend.store import Store, uid
from test_platform import PASSWORD, system, invited, post
from test_companions import envelope
from test_multivault import create, protected_envelope
from test_sharing import setup_identity, create as create_team, grant
from test_credential_actions import personal, approval, browser_token, claim


def activity(client, vault, kind='personal', suffix=''):
    return client.get('/api/vault-activity/'+kind+'/'+vault+suffix)


def test_personal_lifecycle_is_private_vault_scoped_and_contains_no_ciphertext(system):
    app,client,_=system;first=create(client,'Personal');second=create(client,'Client')
    payload=protected_envelope(first['id'])
    assert post(client,'/vault?vault_id='+first['id'],{'revision':0,'envelope':payload}).status_code==200
    pair=post(client,'/companions',{'label':'Private browser label','password':PASSWORD,'vault_id':first['id']}).json()
    headers={'Authorization':'Bearer '+pair['token']}
    browser=TestClient(app)
    assert browser.post('/api/companion/vault',headers=headers,json={'revision':1,'envelope':payload}).status_code==200
    rewrapped={**payload,'wrapped_key':base64.b64encode(b'n'*48).decode()}
    assert post(client,'/vault?vault_id='+first['id'],{'revision':2,'envelope':rewrapped}).status_code==200
    events=activity(client,first['id']).json()
    actions=[e['action'] for e in events['events']]
    assert {'vault.created','vault.initialized','vault.companion_connected','vault.browser_saved','vault.saved','vault.protection_changed','vault.companions_revoked'}<=set(actions)
    assert all(e['actor_label']=='You' for e in events['events'])
    assert not events['independently_verified'] and events['source']=='service_record'
    text=str(events)
    for private in ('ciphertext','wrapped_key',pair['token'],'Private browser label',second['id']):
        assert private not in text
    assert [e['action'] for e in activity(client,second['id']).json()['events']]==['vault.created']
    other=invited(app,client)
    assert activity(other,first['id']).status_code==404
    assert TestClient(app).get('/api/vault-activity/personal/'+first['id']).status_code==401
    assert browser.get('/api/vault-activity/personal/'+first['id'],headers=headers).status_code==401
    with app.state.store.connect() as c:
        personal=Store.audit(c,'personal:'+client.get('/api/me').json()['id'])
        assert personal['valid']
    assert browser.get('/api/companion/vault',headers=headers).status_code==401


def test_personal_history_spans_own_workspaces_without_exposing_unrelated_logs(system):
    app,client,_=system;vault=create(client,'Private')
    me=client.get('/api/me').json()
    with app.state.store.connect(write=True) as c:
        Store.event(c,me['workspace'],me['id'],'vault.properties_updated',vault['id'])
        Store.event(c,me['workspace'],me['id'],'auth.mfa_enabled',me['id'])
        Store.event(c,me['workspace'],'different-user','vault.saved',vault['id'])
    next_workspace=post(client,'/workspaces',{'name':'Second context'}).json()['id']
    assert post(client,'/workspaces/'+next_workspace+'/switch',{}).status_code==200
    assert post(client,'/vaults/'+vault['id'],{'name':'Updated private name'}).status_code==200
    events=activity(client,vault['id']).json()['events']
    assert len(events)==3
    assert all(e['action'] in {'vault.created','vault.properties_updated'} for e in events)
    assert not any(e['actor']=='different-user' for e in events)


def test_keyset_pagination_is_bounded_and_stable_while_new_events_arrive(system):
    app,client,_=system;vault=create(client)
    me=client.get('/api/me').json()
    with app.state.store.connect(write=True) as c:
        for _ in range(7):Store.event(c,'personal:'+me['id'],me['id'],'vault.saved',vault['id'])
    first=activity(client,vault['id'],suffix='?limit=3').json()
    assert len(first['events'])==3 and first['next_before']==first['events'][-1]['id']
    with app.state.store.connect(write=True) as c:
        Store.event(c,'personal:'+me['id'],me['id'],'vault.saved',vault['id'])
    second=activity(client,vault['id'],suffix='?limit=3&before='+str(first['next_before'])).json()
    third=activity(client,vault['id'],suffix='?limit=3&before='+str(second['next_before'])).json()
    all_events=first['events']+second['events']+third['events']
    assert len({e['id'] for e in all_events})==8 and third['next_before'] is None
    assert [e['id'] for e in all_events]==sorted((e['id'] for e in all_events),reverse=True)
    assert activity(client,vault['id']).json()['events'][0]['id']>first['events'][0]['id']


@pytest.mark.parametrize('suffix',['?limit=0','?limit=101','?before=0','?before=-1','?before=9223372036854775808','?before=bad'])
def test_pagination_rejects_invalid_bounds(system,suffix):
    _,client,_=system
    assert activity(client,create(client)['id'],suffix=suffix).status_code==422


def test_shared_activity_requires_current_membership_accepted_grant_and_workspace(system):
    app,client,_=system;owner=setup_identity(client);vault=create_team(client,owner)
    other=invited(app,client,'viewer');reader=setup_identity(other)
    assert post(client,'/team-vaults/'+vault+'/invite',grant(owner,reader,vault)).status_code==200
    assert activity(other,vault,'shared').status_code==404
    assert post(other,'/team-vaults/'+vault+'/accept',{}).status_code==200
    result=activity(other,vault,'shared').json()
    assert {'team_vault.created','team_vault.invited','team_vault.invitation_accepted'}=={e['action'] for e in result['events']}
    assert result['events'][0]['actor_label']=='You'
    assert any(e['actor_label']=='owner@example.test' for e in result['events'])
    separate=post(client,'/workspaces',{'name':'Other workspace'}).json()['id']
    assert activity(client,vault,'shared',suffix='?workspace='+separate).status_code==200
    assert post(client,'/workspaces/'+separate+'/switch',{}).status_code==200
    assert activity(client,vault,'shared').status_code==404
    original=other.get('/api/me').json()['workspace']
    assert post(client,'/workspaces/'+original+'/switch',{}).status_code==200
    assert post(client,'/team-vaults/'+vault+'/revoke/'+reader['id'],{}).status_code==200
    assert activity(other,vault,'shared').status_code==404
    assert 'team_vault.access_revoked' in {e['action'] for e in activity(client,vault,'shared').json()['events']}


def test_action_events_are_joined_to_their_vault_without_reading_encrypted_manifest(system):
    _,client,_=system;first=create(client);second=create(client,'Other')
    identifier=uid()
    body={'id':identifier,'vault_id':first['id'],'kind':'personal','entry_count':1,'expires_at':int(time.time()+1800),'envelope':{'version':1,'iv':base64.b64encode(b'i'*12).decode(),'ciphertext':base64.b64encode(b'opaque-encrypted-private-manifest').decode()}}
    assert post(client,'/account-actions',body).status_code==200
    assert post(client,'/account-actions/'+identifier+'/cancel',{}).status_code==200
    result=activity(client,first['id']).json()
    assert {'credential_action.approved','credential_action.cancelled'}<={e['action'] for e in result['events']}
    assert 'credential_action.approved' not in {e['action'] for e in activity(client,second['id']).json()['events']}
    assert 'manifest' not in str(result) and identifier not in str(result)


def test_archive_and_default_changes_are_real_recorded_events(system):
    _,client,_=system;first=create(client);second=create(client,'Recovery',is_default=True)
    assert 'vault.default_changed' in {e['action'] for e in activity(client,first['id']).json()['events']}
    assert post(client,'/vaults/'+first['id'],{'name':'Old personal','archived':True}).status_code==200
    assert 'vault.archived' in {e['action'] for e in activity(client,first['id']).json()['events']}
    assert post(client,'/vaults/'+first['id'],{'name':'Old personal','archived':False}).status_code==200
    assert 'vault.restored' in {e['action'] for e in activity(client,first['id']).json()['events']}


def test_workspace_offboarding_records_affected_vault_and_removes_timeline_access(system):
    app,client,_=system;owner=setup_identity(client);vault=create_team(client,owner)
    other=invited(app,client,'reviewer');reader=setup_identity(other)
    assert post(client,'/team-vaults/'+vault+'/invite',grant(owner,reader,vault)).status_code==200
    assert post(other,'/team-vaults/'+vault+'/accept',{}).status_code==200
    assert activity(other,vault,'shared').status_code==200
    assert post(client,'/members/'+reader['id']+'/offboard',{'password':PASSWORD}).status_code==200
    assert activity(other,vault,'shared').status_code==401
    assert 'team_vault.access_revoked' in {e['action'] for e in activity(client,vault,'shared').json()['events']}


def test_claim_interruption_resume_and_expiry_are_recorded_once_at_processing_time(system):
    app,client,_=system;vault=personal(client);identifier,_=approval(client,vault)
    browser,headers=browser_token(app,client,vault)
    assert claim(browser,headers,identifier).status_code==200
    with app.state.store.connect(write=True) as c:
        c.execute('UPDATE credential_actions SET lease_expires=? WHERE id=?',(time.time()-1,identifier))
    for _ in range(2):assert browser.get('/api/companion/actions',headers=headers).status_code==200
    assert claim(browser,headers,identifier,resume=True).status_code==200
    with app.state.store.connect(write=True) as c:
        c.execute('UPDATE credential_actions SET expires_at=? WHERE id=?',(time.time()-1,identifier))
    for _ in range(2):assert client.get('/api/account-actions').status_code==200
    events=activity(client,vault).json()['events']
    actions=[e['action'] for e in events]
    for expected in ('approved','claimed','interrupted','resumed','expired'):
        assert actions.count('credential_action.'+expected)==1
    assert next(e for e in events if e['action']=='credential_action.expired')['actor_label']=='System'
