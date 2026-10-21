from fastapi.testclient import TestClient
from test_platform import system, post
from test_companions import envelope
from backend import extension_connect

ORIGIN='chrome-extension://'+'a'*32
PROOF={'proof':'test-only-proof-'+'x'*43}

def start(app):
    client=TestClient(app)
    response=client.post('/api/companion/connect/start',json=PROOF,headers={'Origin':ORIGIN})
    assert response.status_code==200,response.text
    return client,response.json()

def test_flow_grants_one_vault_without_exposing_tokens_to_approval_page(system):
    app,owner,_=system
    assert post(owner,'/vault',{'revision':0,'envelope':envelope()}).status_code==200
    vault=owner.get('/api/vaults').json()['vaults'][0]
    client,pending=start(app)
    path='/api/companion/connect/'+pending['id']
    assert client.post(path+'/poll',json=PROOF,headers={'Origin':ORIGIN}).json()=={'status':'pending'}
    assert client.get('/api/extension-connect/'+pending['id']).status_code==401
    detail=owner.get('/api/extension-connect/'+pending['id']).json()
    assert set(detail)=={'id','origin','code','expires','status','scope','workspace_id','workspace_name'}
    response=post(owner,'/extension-connect/'+pending['id']+'/approve',{'vault_id':vault['id'],'confirmed_code':pending['code']})
    assert response.status_code==200 and 'token' not in response.json()
    grant=client.post(path+'/poll',json=PROOF,headers={'Origin':ORIGIN}).json()
    headers={'Origin':ORIGIN,'Authorization':'Bearer '+grant['token']}
    assert client.get('/api/companion/vault',headers=headers).status_code==200
    assert client.get('/api/workspace',headers=headers).status_code==401
    assert client.post(path+'/poll',json=PROOF,headers={'Origin':ORIGIN}).json()==grant # lost reply can be retrieved
    assert client.post(path+'/ack',json=PROOF,headers={'Origin':ORIGIN}).status_code==200
    assert client.post(path+'/poll',json=PROOF,headers={'Origin':ORIGIN}).status_code==410

def test_requires_proof_origin_initialized_vault_and_one_approval(system):
    app,owner,_=system;client,pending=start(app);path='/api/companion/connect/'+pending['id']
    assert client.post(path+'/poll',json={'proof':'wrong'+'x'*43},headers={'Origin':ORIGIN}).status_code==403
    assert client.post(path+'/poll',json=PROOF,headers={'Origin':'chrome-extension://'+'b'*32}).status_code==403
    assert client.post('/api/companion/connect/start',json=PROOF,headers={'Origin':'https://hostile.test'}).status_code==403
    post(owner,'/vaults',{'name':'Browser test vault','is_default':True})
    vault=owner.get('/api/vaults').json()['vaults'][0]
    payload={'vault_id':vault['id'],'confirmed_code':pending['code']}
    assert post(owner,'/extension-connect/'+pending['id']+'/approve',payload).status_code==409
    post(owner,'/vault',{'revision':0,'envelope':envelope()})
    assert post(owner,'/extension-connect/'+pending['id']+'/approve',{**payload,'confirmed_code':'000000' if pending['code']!='000000' else '111111'}).status_code==403
    assert post(owner,'/extension-connect/'+pending['id']+'/approve',{**payload,'confirmed_code':'invalid'}).status_code==422
    assert post(owner,'/extension-connect/'+pending['id']+'/approve',payload).status_code==200
    assert post(owner,'/extension-connect/'+pending['id']+'/approve',payload).status_code==409
    post(owner,'/companions/revoke',{})
    assert client.post(path+'/poll',json=PROOF,headers={'Origin':ORIGIN}).status_code==410

def test_pending_expiry_and_recovery_clear_handshakes(system):
    app,owner,_=system;client,pending=start(app)
    with app.state.store.connect(write=True) as c:
        record=extension_connect.Store.get(c,extension_connect.SCOPE,extension_connect.KIND,pending['id'])
        record['expires']=0;extension_connect.Store.put(c,extension_connect.SCOPE,extension_connect.KIND,record)
    assert client.post('/api/companion/connect/'+pending['id']+'/poll',json=PROOF,headers={'Origin':ORIGIN}).status_code==410
    from backend.backups import suspend_authorizations
    with app.state.store.connect(write=True) as c:
        suspend_authorizations(c)
        assert c.execute("SELECT count(*) FROM entities WHERE workspace=? AND kind=?",(extension_connect.SCOPE,extension_connect.KIND)).fetchone()[0]==0

def test_cancelling_an_approved_request_revokes_its_unclaimed_grant(system):
    app,owner,_=system;post(owner,'/vault',{'revision':0,'envelope':envelope()})
    vault=owner.get('/api/vaults').json()['vaults'][0];client,pending=start(app)
    post(owner,'/extension-connect/'+pending['id']+'/approve',{'vault_id':vault['id'],'confirmed_code':pending['code']})
    path='/api/companion/connect/'+pending['id']
    grant=client.post(path+'/poll',json=PROOF,headers={'Origin':ORIGIN}).json()
    assert client.post(path+'/cancel',json=PROOF,headers={'Origin':ORIGIN}).status_code==200
    assert client.get('/api/companion/vault',headers={'Origin':ORIGIN,'Authorization':'Bearer '+grant['token']}).status_code==401

def test_approval_cannot_select_another_users_vault_or_skip_csrf(system):
    app,owner,_=system;client,pending=start(app)
    payload={'vault_id':'f'*24,'confirmed_code':pending['code']}
    assert owner.post('/api/extension-connect/'+pending['id']+'/approve',json=payload).status_code==403
    assert post(owner,'/extension-connect/'+pending['id']+'/approve',payload).status_code==409
