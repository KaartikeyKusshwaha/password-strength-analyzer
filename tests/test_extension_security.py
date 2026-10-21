from unittest.mock import patch
from fastapi.testclient import TestClient
from backend import scanner
from backend.app import OperationRequest
from backend.store import Store
from test_platform import system,post,invited,PASSWORD
from test_extension_connect import ORIGIN,PROOF

def connected(app,owner):
    client=TestClient(app)
    request=client.post('/api/companion/connect/start',json={**PROOF,'scope':'security'},headers={'Origin':ORIGIN}).json()
    workspace=owner.get('/api/me').json()['workspace']
    approved=post(owner,'/extension-connect/'+request['id']+'/approve',{'workspace_id':workspace,'confirmed_code':request['code']})
    assert approved.status_code==200,approved.text
    grant=client.post('/api/companion/connect/'+request['id']+'/poll',json=PROOF,headers={'Origin':ORIGIN}).json()
    assert grant['scope']=='security'
    return client,{'Origin':ORIGIN,'Authorization':'Bearer '+grant['token']}

def test_grants_are_separate_and_live_role_removal_blocks_access(system):
    app,owner,_=system;client,headers=connected(app,owner)
    response=client.get('/api/companion/security/context',headers=headers)
    assert response.status_code==200 and set(response.json())=={'workspace','scan_hosts','devices','ai_available','local_device'}
    assert client.get('/api/companion/vault',headers=headers).status_code==401
    assert client.get('/api/workspace',headers=headers).status_code==401
    assert client.get('/api/companion/security/context',headers={**headers,'Origin':'chrome-extension://'+'b'*32}).status_code==401
    me=owner.get('/api/me').json()
    with app.state.store.connect(write=True) as c:c.execute("UPDATE members SET role='viewer' WHERE workspace=? AND user=?",(me['workspace'],me['id']))
    assert client.get('/api/companion/security/context',headers=headers).status_code==403

def test_approved_operations_return_only_own_results_and_drafts(system,monkeypatch):
    app,owner,_=system;client,headers=connected(app,owner)
    app.state.settings.scan_hosts={'portal.example.test'}
    monkeypatch.setattr(app.state.executor,'submit',lambda *args:None)
    body={'action':'website','target':'portal.example.test','authorized':True}
    assert client.post('/api/companion/security/operations',json={**body,'authorized':False},headers=headers).status_code==422
    assert client.post('/api/companion/security/operations',json={**body,'target':'outside.example.test'},headers=headers).status_code==422
    response=client.post('/api/companion/security/operations',json=body,headers=headers)
    assert response.status_code==200,response.text
    operation=response.json();me=owner.get('/api/me').json()
    with patch.object(scanner,'scan_web',return_value=scanner.inspect_headers({},200)):
        app.state.run_operation(me['workspace'],me['id'],operation['id'],OperationRequest(**body))
    result=client.get('/api/companion/security/operations/'+operation['id'],headers=headers)
    assert result.status_code==200 and result.json()['status']=='complete'
    assert 'steps' not in result.json() and 'findings' not in result.json()
    with app.state.store.connect(write=True) as c:Store.put(c,me['workspace'],'operations',{'id':'e'*24,'created_by':'other-user','status':'complete','action':'website','target':'private.other'})
    assert client.get('/api/companion/security/operations/'+'e'*24,headers=headers).status_code==404

def test_cancel_and_control_room_revocation(system,monkeypatch):
    app,owner,_=system;client,headers=connected(app,owner)
    app.state.settings.scan_hosts={'portal.example.test'};monkeypatch.setattr(app.state.executor,'submit',lambda *args:None)
    operation=client.post('/api/companion/security/operations',json={'action':'website','target':'portal.example.test','authorized':True},headers=headers).json()
    assert client.post('/api/companion/security/operations/'+operation['id']+'/cancel',json={},headers=headers).status_code==200
    assert client.get('/api/companion/security/operations/'+operation['id'],headers=headers).json()['status']=='cancelled'
    grant=owner.get('/api/security-connections').json()['connections'][0]
    assert post(owner,'/security-connections/'+grant['id']+'/revoke',{}).status_code==200
    assert client.get('/api/companion/security/context',headers=headers).status_code==401

def test_offboarding_deletes_security_grants(system):
    app,owner,_=system;reviewer=invited(app,owner);client,headers=connected(app,reviewer)
    member=reviewer.get('/api/me').json()
    response=post(owner,'/members/'+member['id']+'/offboard',{'password':PASSWORD})
    assert response.status_code==200,response.text
    assert client.get('/api/companion/security/context',headers=headers).status_code in {401,403}
    with app.state.store.connect() as c:assert not any(grant['user']==member['id'] for grant in Store.all(c,'system:extension-security','security_connection'))
