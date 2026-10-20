"""Native crypto signatures and authorization boundaries for shared vaults."""
import base64
import hashlib
import json
from functools import lru_cache

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
from fastapi.testclient import TestClient

from backend.store import Store, canonical, uid
from test_platform import PASSWORD, system, invited, post


def b64(value):
    return base64.b64encode(value).decode()


@lru_cache(maxsize=1)
def encryption_public():
    # These generated fixture keys are never used outside tests.
    return rsa.generate_private_key(public_exponent=65537,key_size=3072).public_key().public_bytes(serialization.Encoding.DER,serialization.PublicFormat.SubjectPublicKeyInfo)


def setup_identity(client):
    user=client.get('/api/me').json()['id']
    private=ec.generate_private_key(ec.SECP256R1())
    public={'encryption':b64(encryption_public()),'signing':b64(private.public_key().public_bytes(serialization.Encoding.DER,serialization.PublicFormat.SubjectPublicKeyInfo))}
    body={'public':public,'encrypted':{'version':1,'salt':b64(b's'*16),'iv':b64(b'i'*12),'ciphertext':b64(b'opaque-encrypted-test-identity'*6)}}
    response=post(client,'/sharing/identity',body)
    assert response.status_code==200,response.text
    return {'id':user,'public':public,'fingerprint':hashlib.sha256(canonical(public).encode()).hexdigest(),'private':private,'body':body}


def sign(who,document):
    r,s=decode_dss_signature(who['private'].sign(canonical(document).encode(),ec.ECDSA(hashes.SHA256())))
    return b64(r.to_bytes(32,'big')+s.to_bytes(32,'big'))


def grant(sender,recipient,identifier,role='viewer',epoch=1):
    document={'version':1,'vault_id':identifier,'recipient':recipient['id'],'issuer':sender['id'],'epoch':epoch,'role':role,'recipient_fingerprint':recipient['fingerprint'],'issuer_fingerprint':sender['fingerprint'],'wrapped_key':b64(b'opaque-fixture-wrapped-key'.ljust(384,b'.'))}
    return {**document,'signature':sign(sender,document)}


def payload(identifier,epoch=1):
    return {'version':1,'context':identifier,'epoch':epoch,'iv':b64(b'i'*12),'ciphertext':b64(b'opaque-fixture-encrypted-team-vault')}


def create(client,owner):
    identifier=uid();workspace=client.get('/api/me').json()['workspace']
    document={'id':identifier,'workspace':workspace,'owner':owner['id'],'owner_fingerprint':owner['fingerprint']}
    body={'id':identifier,'name':'Client accounts','manifest_signature':sign(owner,document),'payload':payload(identifier),'grant':grant(owner,owner,identifier,'owner')}
    result=post(client,'/team-vaults',body)
    assert result.status_code==200,result.text
    return identifier


def test_identity_is_private_create_once_and_public_directory_is_workspace_scoped(system):
    app,client,_=system
    owner=setup_identity(client);other=invited(app,client)
    assert post(client,'/sharing/identity',owner['body']).status_code==409
    assert client.get('/api/sharing/identity').json()['identity']['encrypted']==owner['body']['encrypted']
    assert other.get('/api/sharing/identity').json()['identity'] is None
    directory=other.get('/api/sharing/directory').json()
    assert next(m for m in directory['members'] if m['id']==owner['id'])['public']==owner['public']
    assert 'encrypted' not in json.dumps(directory)
    assert TestClient(app).get('/api/sharing/identity').status_code==401
    isolated=post(client,'/workspaces',{'name':'Isolated workspace'}).json()['id']
    post(client,'/workspaces/'+isolated+'/switch',{})
    assert len(client.get('/api/sharing/directory').json()['members'])==1


def test_pending_invite_cannot_read_payload_and_viewer_cannot_write(system):
    app,client,_=system
    other=invited(app,client,'viewer');owner=setup_identity(client);reader=setup_identity(other);identifier=create(client,owner)
    assert other.get('/api/team-vaults/'+identifier).status_code==404
    assert post(client,'/team-vaults/'+identifier+'/invite',grant(owner,reader,identifier,'editor')).status_code==422
    assert post(client,'/team-vaults/'+identifier+'/invite',grant(owner,reader,identifier)).status_code==200
    pending=other.get('/api/team-vaults/'+identifier).json()
    assert pending['payload'] is None and pending['grants']==[] and not pending['accepted']
    assert post(other,'/team-vaults/'+identifier+'/save',{'revision':1,'payload':payload(identifier)}).status_code==403
    assert post(other,'/team-vaults/'+identifier+'/accept',{}).status_code==200
    assert other.get('/api/team-vaults/'+identifier).json()['payload']==payload(identifier)
    assert post(other,'/team-vaults/'+identifier+'/save',{'revision':1,'payload':payload(identifier)}).status_code==403
    assert 'wrapped_key' not in client.get('/api/report').text


def test_signatures_scope_and_roles_are_validated_before_access_is_stored(system):
    app,client,_=system
    other=invited(app,client);owner=setup_identity(client);recipient=setup_identity(other);identifier=create(client,owner)
    valid=grant(owner,recipient,identifier,'editor')
    for replacement in [{'role':'admin'},{'epoch':2},{'vault_id':uid()},{'recipient_fingerprint':'0'*64},{'signature':b64(b'x'*64)}]:
        response=post(client,'/team-vaults/'+identifier+'/invite',{**valid,**replacement})
        assert response.status_code in {409,422},response.text
    assert other.get('/api/team-vaults').json()['vaults']==[]
    assert post(client,'/team-vaults/'+identifier+'/invite',valid).status_code==200
    assert post(other,'/team-vaults/'+identifier+'/accept',{}).status_code==200
    assert post(other,'/team-vaults/'+identifier+'/save',{'revision':1,'payload':payload(identifier)}).status_code==200
    assert post(client,'/team-vaults/'+identifier+'/save',{'revision':1,'payload':payload(identifier)}).status_code==409
    assert post(other,'/team-vaults/'+identifier+'/save',{'revision':2,'payload':payload(uid())}).status_code==422


def test_revocation_requires_exact_remaining_members_and_next_epoch_rotation(system):
    app,client,_=system
    other=invited(app,client);owner=setup_identity(client);recipient=setup_identity(other);identifier=create(client,owner)
    post(client,'/team-vaults/'+identifier+'/invite',grant(owner,recipient,identifier,'editor'))
    post(other,'/team-vaults/'+identifier+'/accept',{})
    assert post(client,'/team-vaults/'+identifier+'/revoke/'+recipient['id'],{}).status_code==200
    assert other.get('/api/team-vaults/'+identifier).status_code==404
    assert post(other,'/team-vaults/'+identifier+'/save',{'revision':1,'payload':payload(identifier)}).status_code==404
    assert post(client,'/team-vaults/'+identifier+'/save',{'revision':1,'payload':payload(identifier)}).status_code==409
    rotated={'revision':1,'payload':payload(identifier,2),'grants':[grant(owner,owner,identifier,'owner',2)]}
    assert post(client,'/team-vaults/'+identifier+'/rotate',{**rotated,'grants':rotated['grants']+[grant(owner,recipient,identifier,'editor',2)]}).status_code==422
    assert post(client,'/team-vaults/'+identifier+'/rotate',rotated).status_code==200
    assert post(client,'/team-vaults/'+identifier+'/rotate',rotated).status_code==409
    assert post(client,'/team-vaults/'+identifier+'/save',{'revision':2,'payload':payload(identifier,1)}).status_code==422
    assert post(client,'/team-vaults/'+identifier+'/save',{'revision':2,'payload':payload(identifier,2)}).status_code==200


def test_admin_can_delegate_only_editor_or_viewer_and_cannot_remove_owner(system):
    app,client,_=system
    second=invited(app,client,email='admin@example.test');third=invited(app,client,email='third@example.test')
    owner=setup_identity(client);admin=setup_identity(second);reader=setup_identity(third);identifier=create(client,owner)
    post(client,'/team-vaults/'+identifier+'/invite',grant(owner,admin,identifier,'admin'));post(second,'/team-vaults/'+identifier+'/accept',{})
    assert post(second,'/team-vaults/'+identifier+'/invite',grant(admin,reader,identifier,'admin')).status_code==403
    assert post(second,'/team-vaults/'+identifier+'/invite',grant(admin,reader,identifier,'editor')).status_code==200
    invitation=third.get('/api/team-vaults/'+identifier).json()['grant']
    assert invitation['issuer_grant']['recipient']==admin['id'] and invitation['issuer_grant']['issuer']==owner['id']
    assert post(second,'/team-vaults/'+identifier+'/revoke/'+owner['id'],{}).status_code==409


def test_team_vaults_do_not_cross_workspace_or_personal_vault_boundaries(system):
    app,client,_=system
    owner=setup_identity(client);identifier=create(client,owner)
    created=post(client,'/workspaces',{'name':'Another client'}).json()['id'];post(client,'/workspaces/'+created+'/switch',{})
    assert client.get('/api/team-vaults').json()['vaults']==[]
    assert client.get('/api/team-vaults/'+identifier).status_code==404
    assert client.get('/api/vaults').json()['vaults']==[]
    assert post(client,'/team-vaults/'+identifier+'/rotate',{'revision':1,'payload':payload(identifier,2),'grants':[grant(owner,owner,identifier,'owner',2)]}).status_code==404


def test_offboarding_revokes_workspace_session_grants_devices_and_jobs_but_preserves_personal_vault(system):
    from test_companions import envelope
    app,client,_=system
    other=invited(app,client);owner=setup_identity(client);recipient=setup_identity(other);identifier=create(client,owner)
    post(client,'/team-vaults/'+identifier+'/invite',grant(owner,recipient,identifier,'editor'));post(other,'/team-vaults/'+identifier+'/accept',{})
    personal=post(other,'/vaults',{'name':'Personal'}).json()['id']
    assert post(other,'/vault?vault_id='+personal,{'revision':0,'envelope':envelope()}).status_code==200
    device=post(other,'/device-connections',{'label':'Owned device','targets':['127.0.0.1'],'password':PASSWORD})
    assert device.status_code==200,device.text
    workspace=client.get('/api/me').json()['workspace']
    with app.state.store.connect(write=True) as c:
        for kind in ('operations','jobs'):
            Store.put(c,workspace,kind,{'id':uid(),'created_by':recipient['id'],'status':'running'})
    assert post(other,'/members/'+owner['id']+'/offboard',{'password':PASSWORD}).status_code==403
    assert post(client,'/members/'+recipient['id']+'/offboard',{'password':'incorrect-fixture'}).status_code==401
    assert other.get('/api/team-vaults/'+identifier).status_code==200
    result=post(client,'/members/'+recipient['id']+'/offboard',{'password':PASSWORD})
    assert result.status_code==200,result.text
    assert result.json()['vaults_requiring_rotation']==[identifier]
    assert other.get('/api/me').status_code==401
    with app.state.store.connect() as c:
        assert not c.execute('SELECT 1 FROM devices WHERE user=?',(recipient['id'],)).fetchone()
        for kind in ('operations','jobs'):
            assert all(job['status']=='cancelled' for job in Store.all(c,workspace,kind))
    assert client.get('/api/team-vaults/'+identifier).json()['rotation_required']
    assert post(other,'/login',{'email':'reviewer@example.test','password':PASSWORD}).status_code==200
    assert other.get('/api/team-vaults').json()['vaults']==[]
    assert other.get('/api/vault?vault_id='+personal).json()['envelope']==envelope()


def test_offboarding_member_who_owns_vault_is_blocked_to_avoid_stranding_keys(system):
    app,client,_=system
    other=invited(app,client);recipient=setup_identity(other);create(other,recipient)
    result=post(client,'/members/'+recipient['id']+'/offboard',{'password':PASSWORD})
    assert result.status_code==409 and 'owns a shared vault' in result.text
    assert other.get('/api/me').status_code==200


def test_offboarded_inflight_ai_job_cannot_revive_or_publish_provider_response(system,monkeypatch):
    from backend import agents
    from test_platform import asset,scan,data
    app,client,_=system
    other=invited(app,client);user=other.get('/api/me').json()['id'];workspace=client.get('/api/me').json()['workspace']
    finding=scan(client,asset(client)['id'])['finding_ids'][0];identifier=uid()
    with app.state.store.connect(write=True) as c:
        Store.put(c,workspace,'jobs',{'id':identifier,'created_by':user,'status':'queued','finding_ids':[finding],'mode':'triage','permissions':{}})
    def offboard_during_request(*args):
        assert post(client,'/members/'+user+'/offboard',{'password':PASSWORD}).status_code==200
        return {'summary':'This cancelled provider response must never be published','recommendations':[]}
    monkeypatch.setattr(agents,'request_plan',offboard_during_request)
    agents.run_job(app.state.store,workspace,identifier,'fixture-provider-key','fixture-model')
    job=next(j for j in data(client)['jobs'] if j['id']==identifier)
    assert job['status']=='cancelled' and 'plan' not in job
