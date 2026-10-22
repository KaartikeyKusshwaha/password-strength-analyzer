import time
import pytest
from backend.store import Store
from backend import access_leases
from backend.security import digest as token_digest
import json
from test_platform import system,post,invited,PASSWORD
from test_handoffs import enable
from test_sharing import setup_identity,create,grant,payload
from test_extension_access import connect,headers
from test_credential_debt import shared_connection
from test_access_leases import run


def prepared(system):
    app,owner,_=system;who=setup_identity(owner);other=invited(app,owner);recipient=setup_identity(other)
    client=post(owner,'/clients',{'name':'Freelancer client'}).json()['id'];vaults=[]
    for _ in range(2):
        vault=create(owner,who);vaults.append(vault);assert post(owner,'/clients/'+client+'/vaults',{'vault_id':vault}).status_code==200
    codes=enable(owner);browser,pending,response=connect(app,owner);assert response.status_code==200;auth=headers(browser,pending)
    draft=browser.post('/api/companion/access/invitations',headers=auth,json={'client_id':client,'person_id':recipient['id'],'expires_at':int(time.time())+30*86400,'role':'editor'})
    assert draft.status_code==200,draft.text
    value=draft.json();signed=[]
    for vault in vaults:
        bearer=shared_connection(browser,owner,vault)['Authorization'][7:]
        context=browser.get('/api/companion/access/invitations/'+value['id']+'/vaults/'+vault,headers={**auth,'X-Sentinel-Vault-Token':bearer})
        assert context.status_code==200,context.text
        assert context.json()['recipient']['fingerprint']==recipient['fingerprint']
        signed.append({'vault_id':vault,'token':bearer,'grant':grant(who,recipient,vault,'editor')})
    body={'plan_digest':value['plan_digest'],'confirmed':True,'password':PASSWORD,'code':codes[0],'vaults':signed}
    return app,owner,other,who,recipient,vaults,codes,browser,auth,value,body


def test_multi_vault_invitation_and_expiry_are_atomic_and_revoke_after_acceptance(system,monkeypatch):
    app,owner,other,who,recipient,vaults,codes,browser,auth,draft,body=prepared(system)
    try:
        path='/api/companion/access/invitations/'+draft['id']+'/apply'
        response=browser.post(path,headers=auth,json=body);assert response.status_code==200,response.text
        assert browser.post(path,headers=auth,json=body).status_code==409
        for vault in vaults:assert post(other,'/team-vaults/'+vault+'/accept',{}).status_code==200
        lease=browser.get('/api/companion/access/leases',headers=auth).json()['leases'][0]
        assert lease['status']=='active' and len(lease['plan']['vaults'])==2
        assert PASSWORD not in str(lease) and body['vaults'][0]['token'] not in str(lease)
        due=draft['plan']['expires_at'];access_leases.tick(app.state.store,lambda:due+1)
        active=browser.get('/api/companion/access/leases',headers=auth).json()['leases'][0]
        run(app,owner.get('/api/me').json()['workspace'],active['workflow'],due+1,monkeypatch)
        assert all(other.get('/api/team-vaults/'+vault).status_code==404 for vault in vaults)
    finally:other.close()


@pytest.mark.parametrize('damage',['signature','token','recipient','role','factor','subset','stale','expired'])
def test_invalid_batch_grants_no_access_and_consumes_no_factor(system,damage):
    app,owner,other,who,recipient,vaults,codes,browser,auth,draft,body=prepared(system)
    try:
        if damage=='signature':body['vaults'][1]['grant']['signature']='A'*88
        elif damage=='token':body['vaults'][1]['token']='x'*54
        elif damage=='recipient':body['vaults'][1]['grant']=grant(who,who,vaults[1],'editor')
        elif damage=='role':body['vaults'][1]['grant']=grant(who,recipient,vaults[1],'viewer')
        elif damage=='expired':
            workspace=owner.get('/api/me').json()['workspace']
            with app.state.store.connect(write=True) as c:
                value=Store.get(c,workspace,'access_invitation_drafts',draft['id']);value['deadline']=0;Store.put(c,workspace,'access_invitation_drafts',value)
        elif damage=='factor':body['code']='invalid'
        elif damage=='subset':body['vaults']=body['vaults'][:1]
        else:assert post(owner,'/team-vaults/'+vaults[0]+'/save',{'revision':1,'payload':payload(vaults[0])}).status_code==200
        response=browser.post('/api/companion/access/invitations/'+draft['id']+'/apply',headers=auth,json=body)
        assert response.status_code in {401,403,409,422},response.text
        workspace=owner.get('/api/me').json()['workspace']
        with app.state.store.connect() as c:
            assert all(not c.execute('SELECT 1 FROM team_grants WHERE vault=? AND user=?',(vault,recipient['id'])).fetchone() for vault in vaults)
            assert not Store.all(c,workspace,access_leases.KIND)
            assert token_digest(codes[0]) in json.loads(c.execute('SELECT recovery FROM users WHERE id=?',(who['id'],)).fetchone()[0])
        assert not browser.get('/api/companion/access/leases',headers=auth).json()['leases']
    finally:other.close()


def test_invitation_audit_failure_rolls_back_grants_expiry_and_factor(system,monkeypatch):
    app,owner,other,who,recipient,vaults,codes,browser,auth,draft,body=prepared(system)
    try:
        original=Store.event
        def fail(c,workspace,actor,action,target):
            original(c,workspace,actor,action,target)
            if action=='access_invitation.applied':raise RuntimeError('synthetic commit interruption')
        with monkeypatch.context() as context:
            context.setattr(Store,'event',fail)
            with pytest.raises(RuntimeError):browser.post('/api/companion/access/invitations/'+draft['id']+'/apply',headers=auth,json=body)
        workspace=owner.get('/api/me').json()['workspace']
        with app.state.store.connect() as c:
            assert not Store.all(c,workspace,access_leases.KIND)
            assert all(not c.execute('SELECT 1 FROM team_grants WHERE vault=? AND user=?',(vault,recipient['id'])).fetchone() for vault in vaults)
            assert token_digest(codes[0]) in json.loads(c.execute('SELECT recovery FROM users WHERE id=?',(who['id'],)).fetchone()[0])
        assert browser.post('/api/companion/access/invitations/'+draft['id']+'/apply',headers=auth,json=body).status_code==200
    finally:other.close()


def test_invitation_context_cors_revocation_and_restore(system,tmp_path):
    from test_extension_connect import ORIGIN
    from backend.backups import init_key,create_backup,restore_backup
    app,owner,other,who,recipient,vaults,codes,browser,auth,draft,body=prepared(system)
    try:
        path='/api/companion/access/invitations/'+draft['id']+'/vaults/'+vaults[0]
        response=browser.options(path,headers={'Origin':ORIGIN,'Access-Control-Request-Method':'GET','Access-Control-Request-Headers':'authorization,x-sentinel-vault-token'})
        assert response.status_code==204 and 'x-sentinel-vault-token' in response.headers['access-control-allow-headers'].lower()
        assert browser.get(path,headers=auth).status_code==403
        key,archive,destination=tmp_path/'key',tmp_path/'draft.backup',tmp_path/'restored'
        init_key(key);create_backup(system[2],key,archive);restore_backup(archive,key,destination)
        with Store(destination/'sentinelops.db').connect() as c:
            assert Store.get(c,owner.get('/api/me').json()['workspace'],'access_invitation_drafts',draft['id'])['status']=='cancelled'
        assert browser.post('/api/companion/access/revoke',headers=auth,json={}).status_code==200
        assert browser.post('/api/companion/access/invitations/'+draft['id']+'/apply',headers=auth,json=body).status_code==401
    finally:other.close()

def test_short_expiry_remains_valid_after_time_spent_signing_the_draft(system,monkeypatch):
    app,owner,other,who,recipient,vaults,codes,browser,auth,draft,body=prepared(system)
    try:
        at=time.time()
        shorter=browser.post('/api/companion/access/invitations',headers=auth,json={'client_id':draft['plan']['client'],'person_id':recipient['id'],'expires_at':int(at)+3601,'role':'editor'})
        assert shorter.status_code==200,shorter.text
        pending=shorter.json();body['plan_digest']=pending['plan_digest']
        with monkeypatch.context() as context:
            context.setattr('time.time',lambda:at+120)
            response=browser.post('/api/companion/access/invitations/'+pending['id']+'/apply',headers=auth,json=body)
        assert response.status_code==200,response.text
    finally:other.close()
