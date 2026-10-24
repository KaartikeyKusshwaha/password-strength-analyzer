import base64
from datetime import datetime, timezone
from unittest.mock import patch

from fastapi.testclient import TestClient

from companion import device_agent
from test_platform import PASSWORD, asset, data, invited, post, system


def envelope():
    return dict(version=1,salt=base64.b64encode(b's'*16).decode(),iv=base64.b64encode(b'i'*12).decode(),ciphertext=base64.b64encode(b'encrypted-fixture-envelope-opaque').decode())


def test_personal_vault_not_shared_with_workspace_or_agents(system):
    app,client,_=system
    reviewer=invited(app,client)
    assert client.get('/api/vault').json()=={'revision':0,'envelope':None}
    result=post(client,'/vault',{'revision':0,'envelope':envelope()})
    assert result.status_code==200,result.text
    assert reviewer.get('/api/vault').json()['envelope'] is None
    assert 'ciphertext' not in str(data(client))
    assert 'ciphertext' not in client.get('/api/report').text
    assert post(client,'/vault',{'revision':0,'envelope':envelope()}).status_code==409
    malformed=envelope();malformed['iv']='invalid'
    assert post(client,'/vault',{'revision':1,'envelope':malformed}).status_code==422


def test_scoped_pairing_and_cors_cannot_access_workspace(system):
    app,client,_=system
    assert post(client,'/companions',{'label':'Fixture browser','password':'incorrect'}).status_code==401
    pair=post(client,'/companions',{'label':'Fixture browser','password':PASSWORD}).json()
    extension=TestClient(app)
    headers={'Authorization':'Bearer '+pair['token'],'Origin':'chrome-extension://'+'a'*32}
    result=extension.get('/api/companion/vault',headers=headers)
    assert result.status_code==200 and result.headers['access-control-allow-origin']==headers['Origin']
    assert extension.get('/api/workspace',headers=headers).status_code==401
    result=extension.post('/api/companion/vault',json={'revision':0,'envelope':envelope()},headers=headers)
    assert result.status_code==200,result.text
    assert client.get('/api/vault').json()['revision']==1
    preflight=extension.options('/api/companion/vault',headers={'Origin':headers['Origin'],'Access-Control-Request-Method':'POST','Access-Control-Request-Headers':'authorization,content-type'})
    assert preflight.status_code==204
    assert extension.options('/api/companion/vault',headers={'Origin':'https://hostile.invalid'}).status_code==403
    assert extension.post('/api/companion/vault',json={'revision':1,'envelope':envelope()},headers={'Authorization':headers['Authorization'],'Origin':'https://hostile.invalid'}).status_code==403
    assert client.get('/api/companion/vault').status_code==401 # cookie alone never works
    post(client,'/companions/revoke',{})
    assert extension.get('/api/companion/vault',headers=headers).status_code==401


def test_device_agent_scope_and_no_upload():
    with patch.object(device_agent.socket,'create_connection',side_effect=ConnectionRefusedError) as connect:
        report=device_agent.assess()
    assert len(report['observations'])==30
    assert {p['host'] for p in report['observations']}=={'127.0.0.1','::1'}
    assert all(p['status']=='closed' for p in report['observations'])
    assert connect.call_count==30
    with patch.object(device_agent.socket,'create_connection',side_effect=TimeoutError):
        assert device_agent.check(('127.0.0.1',22))['status']=='unassessed'


def test_device_import_keeps_distinct_ports_and_partial_coverage(system):
    _,client,_=system
    identifier=asset(client)['id']
    report=dict(version=1,generated_at=datetime.now(timezone.utc).isoformat(),scope='fixed-loopback-tcp',observations=[dict(host='127.0.0.1',port=22,status='open'),dict(host='127.0.0.1',port=3306,status='open')])
    result=post(client,'/device-reports',{'asset_id':identifier,'report':report,'authorized':True})
    assert result.status_code==200,result.text
    assert result.json()['status']=='partial'
    findings=data(client)['findings']
    assert len(findings)==2 and len({f['fingerprint'] for f in findings})==2
    assert {f['port'] for f in findings}=={22,3306}
    assert all(f['severity']=='unknown' for f in findings)
    report['observations'][0]['host']='169.254.169.254'
    assert post(client,'/device-reports',{'asset_id':identifier,'report':report,'authorized':True}).status_code==422
