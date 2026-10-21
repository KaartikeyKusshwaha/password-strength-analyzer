import secrets
from fastapi.testclient import TestClient
from test_platform import system,post,PASSWORD
from test_extension_connect import ORIGIN,PROOF
from backend.store import Store
from backend.security import digest

def access(app,owner,allow=True):
    client=TestClient(app)
    request=client.post('/api/companion/connect/start',json={**PROOF,'scope':'security','device_pairing':allow},headers={'Origin':ORIGIN}).json()
    response=post(owner,'/extension-connect/'+request['id']+'/approve',{'workspace_id':owner.get('/api/me').json()['workspace'],'confirmed_code':request['code'],'device_pairing':allow})
    assert response.status_code==200,response.text
    grant=client.post('/api/companion/connect/'+request['id']+'/poll',json=PROOF,headers={'Origin':ORIGIN}).json()
    return client,{'Origin':ORIGIN,'Authorization':'Bearer '+grant['token']}

def request_helper(client):
    proof={'proof':secrets.token_urlsafe(32)}
    response=client.post('/api/device-pairing/start',json={**proof,'label':'Test Windows helper','allow_posture':True,'allow_updates':False})
    assert response.status_code==200,response.text
    return response.json(),proof

def test_pairing_is_proof_bound_reauthenticated_and_single_use(system):
    app,owner,_=system;client,headers=access(app,owner);request,proof=request_helper(client)
    code={'pairing_code':request['pairing_code']}
    detail=client.post('/api/companion/security/device-pairing/details',headers=headers,json=code)
    assert detail.status_code==200 and detail.json()['allowed_targets']==['127.0.0.1','::1']
    body={**code,'password':'wrong','allow_posture':True,'allow_updates':False}
    assert client.post('/api/companion/security/device-pairing/approve',headers=headers,json=body).status_code==401
    assert client.post('/api/companion/security/device-pairing/approve',headers=headers,json={**body,'password':PASSWORD,'allow_updates':True}).status_code==409
    approved=client.post('/api/companion/security/device-pairing/approve',headers=headers,json={**body,'password':PASSWORD})
    assert approved.status_code==200 and 'token' not in approved.json()
    assert client.post('/api/companion/security/device-pairing/approve',headers=headers,json={**body,'password':PASSWORD}).status_code==404
    assert client.post('/api/device-pairing/'+request['id']+'/poll',json=PROOF).status_code==403
    delivered=client.post('/api/device-pairing/'+request['id']+'/poll',json=proof).json()
    connection=delivered['connection'];assert connection['allow_posture'] is True and connection['allow_updates'] is False
    assert client.post('/api/device-agent/poll',json={'version':3,'posture_enabled':True,'updates_enabled':False},headers={'Authorization':'Bearer '+connection['token']}).status_code==200
    assert client.post('/api/device-pairing/'+request['id']+'/ack',json=proof).status_code==200
    assert client.post('/api/device-pairing/'+request['id']+'/poll',json=proof).status_code==410

def test_legacy_assessment_access_cannot_pair_and_cancellation_revokes(system):
    app,owner,_=system;client,headers=access(app,owner,False);request,proof=request_helper(client)
    code={'pairing_code':request['pairing_code']}
    assert client.post('/api/companion/security/device-pairing/details',headers=headers,json=code).status_code==403
    with app.state.store.connect(write=True) as c:
        grant=Store.get(c,'system:extension-security','security_connection',digest(headers['Authorization'][7:]));grant['device_pairing']=True;Store.put(c,'system:extension-security','security_connection',grant)
    approved=client.post('/api/companion/security/device-pairing/approve',headers=headers,json={**code,'password':PASSWORD,'allow_posture':True,'allow_updates':False})
    assert approved.status_code==200
    queued=client.post('/api/companion/security/operations',headers=headers,json={'action':'device','target':'127.0.0.1','device_id':approved.json()['id'],'authorized':True})
    assert queued.status_code==200
    token=client.post('/api/device-pairing/'+request['id']+'/poll',json=proof).json()['connection']['token']
    assert client.post('/api/device-pairing/'+request['id']+'/cancel',json=proof).status_code==200
    assert client.post('/api/device-agent/poll',json={'version':3},headers={'Authorization':'Bearer '+token}).status_code==401
    assert client.get('/api/companion/security/operations/'+queued.json()['id'],headers=headers).json()['status']=='interrupted'

def test_pairing_records_are_removed_on_restore(system):
    from backend.backups import suspend_authorizations
    app,owner,_=system;client=TestClient(app);request,proof=request_helper(client)
    with app.state.store.connect(write=True) as c:suspend_authorizations(c)
    assert client.post('/api/device-pairing/'+request['id']+'/poll',json=proof).status_code==410

def test_enabled_account_factor_is_required_and_cannot_be_reused(system):
    import time
    from backend.security import totp
    app,owner,_=system;client,headers=access(app,owner)
    secret='JBSWY3DPEHPK3PXP'
    with app.state.store.connect(write=True) as c:c.execute('UPDATE users SET mfa=?,mfa_step=-1',(app.state.cipher.encrypt(secret.encode()).decode(),))
    request,proof=request_helper(client)
    body={'pairing_code':request['pairing_code'],'password':PASSWORD,'allow_posture':True,'allow_updates':False}
    assert client.post('/api/companion/security/device-pairing/approve',headers=headers,json=body).status_code==401
    body['code']=totp(secret,int(time.time()//30))
    assert client.post('/api/companion/security/device-pairing/approve',headers=headers,json=body).status_code==200
    second,_=request_helper(client);body['pairing_code']=second['pairing_code']
    assert client.post('/api/companion/security/device-pairing/approve',headers=headers,json=body).status_code==401
