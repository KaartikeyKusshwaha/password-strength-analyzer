"""Default production policy, rollout, bearer isolation and actual enrollment."""
import time
from unittest.mock import patch
import pytest
from fastapi.testclient import TestClient
from backend.app import Settings,create_app
from backend.security import totp,digest
from backend.store import Store,uid
from test_platform import PASSWORD,post,system,invited
from test_sharing import setup_identity,create,grant


@pytest.fixture
def protected(tmp_path):
    settings=Settings(data_dir=tmp_path,groq_key='')
    assert settings.admin_mfa_required is True
    app=create_app(settings)
    with TestClient(app) as client:
        response=post(client,'/setup',{'email':'owner@example.test','password':PASSWORD,'token':(tmp_path/'.bootstrap-token').read_text()})
        assert response.status_code==200,response.text
        yield app,client,tmp_path


def enroll(client):
    setup=post(client,'/mfa/setup',{'password':PASSWORD})
    assert setup.status_code==200,setup.text
    enabled=post(client,'/mfa/enable',{'code':totp(setup.json()['secret'],int(time.time()//30))})
    assert enabled.status_code==200,enabled.text
    return enabled.json()['recovery_codes']


def test_default_owner_gate_preserves_account_and_personal_vault_access(protected):
    app,client,_=protected
    me=client.get('/api/me').json()
    assert me['mfa_enrollment_required'] and me['admin_mfa_required'] and not me['mfa_enabled']
    for path in ('/api/workspace','/api/team-vaults','/api/clients/access-map','/api/extension-capabilities'):
        assert client.get(path).status_code==428,path
    assert post(client,'/invites',{'email':'member@example.test','role':'analyst'}).status_code==428
    assert client.get('/api/vaults').status_code==200
    created=post(client,'/vaults',{'name':'Personal access'})
    assert created.status_code==200,created.text
    assert client.get('/api/vault',params={'vault_id':created.json()['id']}).status_code==200
    assert client.get('/api/vault-activity/personal/'+created.json()['id']).status_code==200
    assert post(client,'/companions/revoke',{}).status_code==200
    assert client.get('/api/passkeys').status_code==200
    codes=enroll(client)
    assert len(codes)==8
    assert not client.get('/api/me').json()['mfa_enrollment_required']
    assert client.get('/api/workspace').status_code==200
    assert post(client,'/mfa/disable',{'password':PASSWORD,'code':codes[0]}).status_code==403
    assert client.get('/api/me').json()['recovery_remaining']==8
    assert post(client,'/logout',{}).status_code==200
    login=post(client,'/login',{'email':me['email'],'password':PASSWORD})
    assert login.json()['mfa_required'] is True


def test_stored_security_and_discovery_bearers_cannot_bypass_rollout_gate(protected):
    app,client,_=protected;me=client.get('/api/me').json();origin='chrome-extension://'+'a'*32
    from backend.extension_connect import SECURITY_SCOPE,SECURITY_KIND,DISCOVERY_SCOPE,DISCOVERY_KIND
    for scope,kind,path in ((SECURITY_SCOPE,SECURITY_KIND,'security'),(DISCOVERY_SCOPE,DISCOVERY_KIND,'discovery')):
        token=uid()+uid()
        with app.state.store.connect(write=True) as c:Store.put(c,scope,kind,{'id':digest(token),'user':me['id'],'workspace':me['workspace'],'origin':origin,'expires':time.time()+3600})
        response=client.get('/api/companion/'+path+'/context',headers={'Origin':origin,'Authorization':'Bearer '+token})
        assert response.status_code==428,response.text


def test_rollout_rechecks_live_shared_admin_roles_and_shared_bearers(system):
    app,client,_=system;owner=setup_identity(client);vault=create(client,owner)
    other=invited(app,client,role='analyst');person=setup_identity(other)
    assert post(client,'/team-vaults/'+vault+'/invite',grant(owner,person,vault,'admin')).status_code==200
    assert post(other,'/team-vaults/'+vault+'/accept',{}).status_code==200
    from test_shared_companions import pair
    headers=pair(other,vault)
    from test_device_connections import connect
    device=connect(client)
    app.state.store.admin_mfa_required=True
    worker=TestClient(app)
    assert worker.post('/api/device-agent/poll',json={},headers={'Authorization':'Bearer '+device['token']}).status_code==428
    worker.close()
    assert other.get('/api/me').json()['mfa_enrollment_required']
    assert other.get('/api/team-vaults').status_code==428
    assert other.get('/api/companion/vault',headers=headers).status_code==428
    with app.state.store.connect(write=True) as c:c.execute("UPDATE team_grants SET role='editor' WHERE user=?",(person['id'],))
    assert not other.get('/api/me').json()['mfa_enrollment_required']
    assert other.get('/api/workspace').status_code==200
    assert other.get('/api/companion/vault',headers=headers).status_code==200
    other.close()


@pytest.mark.parametrize('remove_role',[False,True])
def test_preexisting_admin_workers_do_not_execute_before_enrollment(protected,remove_role):
    app,client,_=protected;me=client.get('/api/me').json();store=app.state.store;identifier=uid()
    with store.connect(write=True) as c:
        assert not app.state.watch_service.permission(c,me['workspace'],me['id'])
        Store.put(c,me['workspace'],'jobs',{'id':identifier,'status':'queued','created_by':me['id'],'finding_ids':[]})
        if remove_role:c.execute("UPDATE members SET role='viewer' WHERE user=?",(me['id'],))
    from backend.agents import run_job
    with patch('backend.agents.request_plan') as external:
        run_job(store,me['workspace'],identifier,'not-a-real-key','fixture-model')
    external.assert_not_called()
    with store.connect() as c:assert ('permission' if remove_role else 'MFA') in Store.get(c,me['workspace'],'jobs',identifier)['error']


def test_worker_rechecks_mfa_after_planning_before_dispatch(protected,monkeypatch):
    app,client,_=protected;enroll(client);me=client.get('/api/me').json()
    from test_platform import asset,scan,queue_workflow,workflow_provider
    from backend.agents import run_job
    finding=scan(client,asset(client)['id'])['finding_ids'][0]
    job=queue_workflow(app,client,monkeypatch,finding,create_tasks=True,create_investigation=True)
    def lose_enrollment():
        with app.state.store.connect(write=True) as c:c.execute('UPDATE users SET mfa=NULL WHERE id=?',(me['id'],))
    run_job(app.state.store,me['workspace'],job['id'],'fixture-key','fixture-model',workflow_provider(lose_enrollment))
    with app.state.store.connect() as c:
        result=Store.get(c,me['workspace'],'jobs',job['id'])
        assert result['status']=='failed' and 'MFA' in result['error']
        assert not Store.all(c,me['workspace'],'tasks') and not Store.all(c,me['workspace'],'investigations')
