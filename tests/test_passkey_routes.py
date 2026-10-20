import json
import secrets

import pytest
from fastapi.testclient import TestClient

from backend.app import Settings, create_app
from backend.passkey_protocol import decode
from backend.security import digest, totp
from test_platform import PASSWORD
from test_passkey_protocol import authenticator, b64


@pytest.fixture
def web(tmp_path,authenticator):
    party=authenticator[0]
    app=create_app(Settings(data_dir=tmp_path,origin=party.origin,groq_key=''))
    with TestClient(app,base_url=party.origin) as client:
        response=client.post('/api/setup',json={'email':'owner@example.test','password':PASSWORD,'token':(tmp_path/'.bootstrap-token').read_text()},headers={'Origin':party.origin})
        assert response.status_code==200,response.text
        user=client.get('/api/me').json()['id']
        yield app,client,user,party


def send(web,path,body=None,request_id=None):
    app,client,user,party=web
    headers={'Origin':party.origin}
    me=client.get('/api/me')
    if me.status_code==200: headers['X-CSRF-Token']=me.json()['csrf']
    if request_id is not None: headers['X-Passkey-Request']=request_id
    return client.post('/api/passkeys/'+path,json=body or {},headers=headers)


def enroll(web,authenticator,code=''):
    result=send(web,'register/options',{'password':PASSWORD,'code':code})
    assert result.status_code==200,result.text
    options=result.json()
    response=authenticator[3]('create',decode(options['publicKey']['challenge']))
    finished=send(web,'register/finish',{'label':'Test device','credential':response},options['request_id'])
    assert finished.status_code==200,finished.text
    return finished.json()['id']


def login_proof(web,authenticator,**kwargs):
    options=send(web,'login/options',{'email':'owner@example.test'})
    assert options.status_code==200,options.text
    value=options.json()
    response=authenticator[3]('get',decode(value['publicKey']['challenge']),handle=web[2].encode(),**kwargs)
    return value,response


def test_real_registration_listing_login_and_cookie_controls(web,authenticator):
    app,client,user,party=web
    assert client.get('/api/passkeys/status').json()=={'available':True,'reason':None,'vault_unlock':False}
    identifier=enroll(web,authenticator)
    values=client.get('/api/passkeys').json()
    assert values['credentials'][0]['id']==identifier
    assert set(values['credentials'][0])=={'id','label','created_at','last_used','device_type','backed_up'}
    old=client.cookies.get('sentinel_session')
    options,proof=login_proof(web,authenticator)
    assert options['publicKey']['userVerification']=='required' and options['publicKey']['allowCredentials']==[]
    cookie=next(c for c in client.cookies.jar if c.name=='sentinel_passkey_binding')
    assert cookie.secure and cookie.path=='/api/passkeys' and cookie.has_nonstandard_attr('HttpOnly')
    result=send(web,'login/finish',{'credential':proof},options['request_id'])
    assert result.status_code==200,result.text
    assert result.json()['mfa_required'] is False
    assert client.cookies.get('sentinel_session')!=old and client.get('/api/me').json()['id']==user
    with app.state.store.connect() as c:
        assert c.execute('SELECT revision FROM passkey_credentials').fetchone()[0]==1
        assert not c.execute('SELECT 1 FROM sessions WHERE token=?',(digest(old),)).fetchone()
        assert any(e['action']=='auth.passkey_enrolled' for e in app.state.store.audit(c,'personal:'+user)['events'])


def test_signed_response_is_one_use_and_bad_proof_cannot_be_retried(web,authenticator):
    app,client,_,_=web;enroll(web,authenticator)
    options,proof=login_proof(web,authenticator)
    bad=json.loads(json.dumps(proof));bad['response']['signature']=b64(b'not-a-real-signature')
    assert send(web,'login/finish',{'credential':bad},options['request_id']).status_code==400
    assert send(web,'login/finish',{'credential':proof},options['request_id']).status_code==400
    options,proof=login_proof(web,authenticator)
    assert send(web,'login/finish',{'credential':proof},options['request_id']).status_code==200
    assert send(web,'login/finish',{'credential':proof},options['request_id']).status_code==400
    with app.state.store.connect() as c: assert c.execute('SELECT revision FROM passkey_credentials').fetchone()[0]==1


def test_invalid_json_consumes_claim_before_proof_parsing(web,authenticator):
    app,client,_,party=web;enroll(web,authenticator)
    options,proof=login_proof(web,authenticator)
    result=client.post('/api/passkeys/login/finish',content=b'{ invalid-json',headers={'Origin':party.origin,'X-Passkey-Request':options['request_id'],'Content-Type':'application/json'})
    assert result.status_code==400
    assert send(web,'login/finish',{'credential':proof},options['request_id']).status_code==400


def test_wrong_browser_binding_does_not_cancel_the_real_browser_request(web,authenticator):
    app,client,_,party=web;enroll(web,authenticator)
    options,proof=login_proof(web,authenticator)
    with TestClient(app,base_url=party.origin) as other:
        other.cookies.set('sentinel_passkey_binding',secrets.token_urlsafe(32),path='/api/passkeys')
        result=other.post('/api/passkeys/login/finish',json={'credential':proof},headers={'Origin':party.origin,'X-Passkey-Request':options['request_id']})
        assert result.status_code==400
    assert send(web,'login/finish',{'credential':proof},options['request_id']).status_code==200


def test_enrollment_requires_password_csrf_origin_and_unchanged_session(web,authenticator):
    app,client,_,party=web
    assert send(web,'register/options',{'password':'wrong-test-only'}).status_code==401
    assert client.post('/api/passkeys/register/options',json={'password':PASSWORD},headers={'Origin':party.origin}).status_code==403
    csrf=client.get('/api/me').json()['csrf']
    assert client.post('/api/passkeys/register/options',json={'password':PASSWORD},headers={'X-CSRF-Token':csrf}).status_code==403
    options=send(web,'register/options',{'password':PASSWORD}).json()
    response=authenticator[3]('create',decode(options['publicKey']['challenge']))
    client.post('/api/login',json={'email':'owner@example.test','password':PASSWORD},headers={'Origin':party.origin})
    assert send(web,'register/finish',{'label':'Device','credential':response},options['request_id']).status_code==400
    assert client.get('/api/passkeys').json()['credentials']==[]


def test_mfa_policy_is_preserved_for_enrollment_and_passkey_signin(web,authenticator):
    app,client,user,party=web
    def secured(path,body):
        return client.post('/api'+path,json=body,headers={'Origin':party.origin,'X-CSRF-Token':client.get('/api/me').json()['csrf']})
    started=secured('/mfa/setup',{'password':PASSWORD}).json()
    import time
    enabled=secured('/mfa/enable',{'code':totp(started['secret'],int(time.time()//30))})
    assert enabled.status_code==200,enabled.text
    recovery=enabled.json()['recovery_codes']
    assert send(web,'register/options',{'password':PASSWORD}).status_code==401
    enroll(web,authenticator,recovery[0])
    options,proof=login_proof(web,authenticator)
    result=send(web,'login/finish',{'credential':proof},options['request_id'])
    assert result.status_code==200 and result.json()['mfa_required']
    assert client.get('/api/me').status_code==401
    assert client.get('/api/passkeys').status_code==401
    factor=client.post('/api/login/factor',json={'code':recovery[1]},headers={'Origin':party.origin,'X-CSRF-Token':result.json()['csrf']})
    assert factor.status_code==200 and client.get('/api/me').json()['id']==user
    identifier=client.get('/api/passkeys').json()['credentials'][0]['id']
    assert send(web,identifier+'/remove',{'password':PASSWORD}).status_code==401
    assert send(web,identifier+'/remove',{'password':PASSWORD,'code':recovery[2]}).status_code==200


def test_removal_tombstones_key_revokes_other_sessions_and_pending_requests(web,authenticator):
    app,client,user,_=web;identifier=enroll(web,authenticator)
    options,proof=login_proof(web,authenticator)
    old=client.cookies.get('sentinel_session')
    result=send(web,identifier+'/remove',{'password':PASSWORD})
    assert result.status_code==200,result.text
    assert client.cookies.get('sentinel_session')!=old and client.get('/api/passkeys').json()['credentials']==[]
    assert send(web,'login/finish',{'credential':proof},options['request_id']).status_code==400
    options,proof=login_proof(web,authenticator)
    assert send(web,'login/finish',{'credential':proof},options['request_id']).status_code==400
    with app.state.store.connect() as c:
        assert c.execute('SELECT revoked_at FROM passkey_credentials').fetchone()[0] is not None
        assert c.execute('SELECT COUNT(*) FROM sessions WHERE user=?',(user,)).fetchone()[0]==1


@pytest.mark.parametrize('change',[{'origin':'https://evil.example.test'},{'rp_id':'other.example.test'},{'flags':0x01},{'handle':b'wrong-user'}])
def test_authenticator_proof_cannot_change_origin_rp_user_or_verification(web,authenticator,change):
    enroll(web,authenticator)
    options=send(web,'login/options',{'email':'owner@example.test'}).json()
    kwargs={'handle':web[2].encode(),**change}
    proof=authenticator[3]('get',decode(options['publicKey']['challenge']),**kwargs)
    assert send(web,'login/finish',{'credential':proof},options['request_id']).status_code==400


def test_discoverable_assertion_requires_a_user_handle(web,authenticator):
    enroll(web,authenticator)
    options=send(web,'login/options',{'email':'owner@example.test'}).json()
    proof=authenticator[3]('get',decode(options['publicKey']['challenge']))
    assert send(web,'login/finish',{'credential':proof},options['request_id']).status_code==400


def test_expired_challenge_and_cancelled_request_cannot_sign_in(web,authenticator):
    app,client,_,_=web;enroll(web,authenticator)
    options,proof=login_proof(web,authenticator)
    with app.state.store.connect(write=True) as c: c.execute('UPDATE passkey_ceremonies SET expires=0')
    assert send(web,'login/finish',{'credential':proof},options['request_id']).status_code==400
    options,proof=login_proof(web,authenticator)
    assert send(web,'cancel',request_id=options['request_id']).status_code==200
    assert send(web,'login/finish',{'credential':proof},options['request_id']).status_code==400


def test_another_account_cannot_reuse_credential_or_remove_it(web,authenticator):
    app,client,user,party=web;identifier=enroll(web,authenticator)
    with app.state.store.connect(write=True) as c:
        c.execute('INSERT INTO users(id,email,password) SELECT ?,?,password FROM users WHERE id=?',('b'*24,'other@example.test',user))
        workspace=c.execute('SELECT workspace FROM members WHERE user=?',(user,)).fetchone()[0]
        c.execute('INSERT INTO members VALUES(?,?,?)',(workspace,'b'*24,'analyst'))
    client.post('/api/login',json={'email':'other@example.test','password':PASSWORD},headers={'Origin':party.origin})
    assert send(web,identifier+'/remove',{'password':PASSWORD}).status_code==400
    options=send(web,'login/options',{'email':'other@example.test'}).json()
    proof=authenticator[3]('get',decode(options['publicKey']['challenge']),handle=user.encode())
    assert send(web,'login/finish',{'credential':proof},options['request_id']).status_code==400


def test_missing_membership_blocks_session_issuance_and_counter_commit(web,authenticator):
    app,client,user,_=web;enroll(web,authenticator)
    options,proof=login_proof(web,authenticator)
    with app.state.store.connect(write=True) as c: c.execute('DELETE FROM members WHERE user=?',(user,))
    assert send(web,'login/finish',{'credential':proof},options['request_id']).status_code==400
    with app.state.store.connect() as c: assert c.execute('SELECT revision FROM passkey_credentials').fetchone()[0]==0
    assert client.post('/api/login',json={'email':'owner@example.test','password':PASSWORD},headers={'Origin':web[3].origin}).status_code==401


def test_options_for_unknown_account_do_not_disclose_ids_or_account_existence(web):
    existing=send(web,'login/options',{'email':'owner@example.test'}).json()
    missing=send(web,'login/options',{'email':'missing@example.test'}).json()
    assert existing.keys()==missing.keys()
    assert existing['publicKey']['allowCredentials']==missing['publicKey']['allowCredentials']==[]
    assert set(existing['publicKey'])==set(missing['publicKey'])


def test_unsupported_ip_origin_remains_explicit_and_no_origin_is_changed(tmp_path):
    app=create_app(Settings(data_dir=tmp_path,origin='http://127.0.0.1:8110',groq_key=''))
    with TestClient(app) as client:
        assert client.get('/api/passkeys/status').json()['available'] is False
        assert client.post('/api/passkeys/login/options',json={'email':'owner@example.test'},headers={'Origin':'http://127.0.0.1:8110'}).status_code==409
    assert app.state.settings.origin=='http://127.0.0.1:8110'


def test_logout_cancels_pending_account_ceremonies_and_binding_cookie(web,authenticator):
    app,client,_,party=web;enroll(web,authenticator)
    options,proof=login_proof(web,authenticator)
    csrf=client.get('/api/me').json()['csrf']
    assert client.post('/api/logout',json={},headers={'Origin':party.origin,'X-CSRF-Token':csrf}).status_code==200
    assert not client.cookies.get('sentinel_passkey_binding')
    assert send(web,'login/finish',{'credential':proof},options['request_id']).status_code==400


def test_options_are_bounded_and_rate_limited(web):
    app,client,user,party=web
    for index in range(40):
        result=send(web,'login/options',{'email':f'unknown-{index}@example.test'})
        assert result.status_code in (200,400)
    assert send(web,'login/options',{'email':'another@example.test'}).status_code==429
    with app.state.store.connect() as c: assert c.execute('SELECT COUNT(*) FROM passkey_ceremonies').fetchone()[0]==5


def test_factor_use_rolls_back_when_a_ceremony_cannot_be_issued(web,authenticator):
    app,client,user,party=web
    # Fill this browser's bounded queue, then require a fresh recovery factor.
    for index in range(5): assert send(web,'login/options',{'email':f'unknown-{index}@example.test'}).status_code==200
    with app.state.store.connect(write=True) as c:
        c.execute('UPDATE users SET mfa=?,recovery=? WHERE id=?',
                  (app.state.cipher.encrypt(b'JBSWY3DPEHPK3PXP').decode(),json.dumps([digest('public-test-recovery')]),user))
    assert send(web,'register/options',{'password':PASSWORD,'code':'public-test-recovery'}).status_code==400
    with app.state.store.connect() as c: assert digest('public-test-recovery') in json.loads(c.execute('SELECT recovery FROM users WHERE id=?',(user,)).fetchone()[0])


def test_session_revocation_during_registration_verification_blocks_enrollment(web,authenticator,monkeypatch):
    app,client,user,party=web
    options=send(web,'register/options',{'password':PASSWORD}).json()
    response=authenticator[3]('create',decode(options['publicKey']['challenge']))
    original=type(party).register
    def racing_verifier(self,credential,challenge):
        verified=original(self,credential,challenge)
        with app.state.store.connect(write=True) as c: c.execute('DELETE FROM sessions WHERE user=?',(user,))
        return verified
    monkeypatch.setattr(type(party),'register',racing_verifier)
    assert send(web,'register/finish',{'label':'Test','credential':response},options['request_id']).status_code==401
    with app.state.store.connect() as c:
        assert c.execute('SELECT COUNT(*) FROM passkey_credentials').fetchone()[0]==0
        assert c.execute('SELECT COUNT(*) FROM passkey_ceremonies').fetchone()[0]==0


def test_pending_factor_cannot_restore_removed_workspace_membership(web,authenticator):
    app,client,user,party=web;enroll(web,authenticator)
    with app.state.store.connect(write=True) as c:
        c.execute('UPDATE users SET mfa=?,recovery=? WHERE id=?',
                  (app.state.cipher.encrypt(b'JBSWY3DPEHPK3PXP').decode(),json.dumps([digest('public-pending-factor')]),user))
    options,proof=login_proof(web,authenticator)
    pending=send(web,'login/finish',{'credential':proof},options['request_id']).json()
    assert pending['mfa_required']
    with app.state.store.connect(write=True) as c: c.execute('DELETE FROM members WHERE user=?',(user,))
    result=client.post('/api/login/factor',json={'code':'public-pending-factor'},headers={'Origin':party.origin,'X-CSRF-Token':pending['csrf']})
    assert result.status_code==403 and client.get('/api/me').status_code==401
    with app.state.store.connect() as c:
        assert digest('public-pending-factor') in json.loads(c.execute('SELECT recovery FROM users WHERE id=?',(user,)).fetchone()[0])
