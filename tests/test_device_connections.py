from unittest.mock import patch
import json
import pytest
from fastapi.testclient import TestClient
from companion import device_agent
from test_platform import PASSWORD, data, invited, post, system


def connect(client):
    response=post(client,'/device-connections',{'label':'Fixture computer','targets':['127.0.0.1'],'password':PASSWORD})
    assert response.status_code == 200, response.text
    return response.json()


def test_remote_device_jobs_are_scoped_leased_and_automatically_recorded(system):
    app,client,_=system
    grant=connect(client)
    worker=TestClient(app);headers={'Authorization':'Bearer '+grant['token']}
    assert worker.get('/api/workspace',headers=headers).status_code == 401
    assert worker.get('/api/companion/vault',headers=headers).status_code == 401
    operation=post(client,'/operations',{'action':'device','device_id':grant['id'],'target':'127.0.0.1','ports':[22,443],'authorized':True}).json()
    poll=worker.post('/api/device-agent/poll',json={},headers=headers).json()['operation']
    assert poll['id'] == operation['id']
    assert worker.post('/api/device-agent/poll',json={},headers=headers).json()['operation'] is None
    assert 'lease' not in data(client)['operations'][0]
    observations=[{'host':'127.0.0.1','port':22,'status':'open'},{'host':'127.0.0.1','port':443,'status':'closed'}]
    body={'operation_id':poll['id'],'lease':poll['lease'],'observations':observations}
    assert worker.post('/api/device-agent/result',json={**body,'lease':'wrong'},headers=headers).status_code == 409
    assert worker.post('/api/device-agent/result',json={**body,'observations':[{'host':'192.168.1.10','port':22,'status':'open'}]},headers=headers).status_code == 422
    result=worker.post('/api/device-agent/result',json=body,headers=headers)
    assert result.status_code == 200, result.text
    assert result.json()['status'] == 'complete'
    assert len(data(client)['scans']) == len(data(client)['findings']) == 1
    assert data(client)['findings'][0]['port'] == 22
    assert worker.post('/api/device-agent/result',json=body,headers=headers).status_code == 409
    assert data(client)['devices'][0]['seen']
    assert 'token' not in str(data(client)['devices'])


def test_device_scope_cancel_revocation_and_other_workspace_cannot_access_it(system):
    app,client,_=system
    assert post(client,'/device-connections',{'label':'Bad password','password':'wrong'}).status_code == 401
    grant=connect(client)
    assert post(client,'/operations',{'action':'device','device_id':grant['id'],'target':'192.168.1.10','authorized':True}).status_code == 422
    operation=post(client,'/operations',{'action':'device','device_id':grant['id'],'authorized':True}).json()
    assert post(client,'/operations/'+operation['id']+'/cancel',{}).status_code == 200
    worker=TestClient(app);headers={'Authorization':'Bearer '+grant['token']}
    assert worker.post('/api/device-agent/poll',json={},headers=headers).json()['operation'] is None
    assert post(client,'/device-connections/'+grant['id']+'/revoke',{}).status_code == 200
    assert worker.post('/api/device-agent/poll',json={},headers=headers).status_code == 401
    other=post(client,'/workspaces',{'name':'Other team'}).json()['id']
    post(client,'/workspaces/'+other+'/switch',{})
    assert data(client)['devices'] == []
    assert post(client,'/device-connections/'+grant['id']+'/revoke',{}).status_code == 404


def test_device_cli_never_accepts_scope_expansion_from_server(tmp_path):
    config={'server':'https://security.example.test','token':'fixture_'*7,'allowed_targets':['127.0.0.1']}
    path=tmp_path/'connection.json';path.write_text(json.dumps(config))
    assert device_agent.connection_file(path) == config
    malicious=lambda *args:{'operation':{'id':'fixture','target':'169.254.169.254','ports':[80],'lease':'lease-fixture-'*3}}
    with patch.object(device_agent.socket,'create_connection') as network:
        with pytest.raises(ValueError):
            device_agent.poll_once(config,malicious)
    network.assert_not_called()
    calls=[]
    def requester(config,path,body):
        calls.append((path,body))
        return {'operation':{'id':'fixture','target':'127.0.0.1','ports':[22],'lease':'lease-fixture-'*3}} if path.endswith('/poll') else {'ok':True}
    with patch.object(device_agent.socket,'create_connection',side_effect=ConnectionRefusedError):
        assert device_agent.poll_once(config,requester)
    assert calls[1][1]['observations'] == [{'host':'127.0.0.1','port':22,'status':'closed'}]
    config['server']='http://evil.example.test';path.write_text(json.dumps(config))
    with pytest.raises(ValueError):
        device_agent.connection_file(path)
