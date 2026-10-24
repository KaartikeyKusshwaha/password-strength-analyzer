"""Signed synthetic authenticators, not mocked successful verification."""
import base64
import hashlib
import json
import secrets

import cbor2
import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec

from backend.passkey_protocol import RelyingParty,PasskeyError,decode


def b64(raw):return base64.urlsafe_b64encode(raw).decode().rstrip('=')


@pytest.fixture
def authenticator():
    key=ec.generate_private_key(ec.SECP256R1())
    numbers=key.public_key().public_numbers()
    public=cbor2.dumps({1:2,3:-7,-1:1,-2:numbers.x.to_bytes(32,'big'),-3:numbers.y.to_bytes(32,'big')})
    identifier=secrets.token_bytes(32)
    party=RelyingParty.from_origin('https://security.example.test')
    def response(kind,challenge,origin=party.origin,rp_id=party.rp_id,flags=None,counter=0,handle=None,**client_fields):
        client=json.dumps({'type':'webauthn.'+kind,'challenge':b64(challenge),'origin':origin,'crossOrigin':False,**client_fields}).encode()
        auth_data=hashlib.sha256(rp_id.encode()).digest()+bytes([flags if flags is not None else (0x45 if kind=='create' else 0x05)])+counter.to_bytes(4,'big')
        result={'id':b64(identifier),'rawId':b64(identifier),'type':'public-key','response':{'clientDataJSON':b64(client)}}
        if kind=='create':
            auth_data+=b'\0'*16+len(identifier).to_bytes(2,'big')+identifier+public
            result['response']['attestationObject']=b64(cbor2.dumps({'fmt':'none','attStmt':{},'authData':auth_data}))
        else:
            result['response'].update(authenticatorData=b64(auth_data),signature=b64(key.sign(auth_data+hashlib.sha256(client).digest(),ec.ECDSA(hashes.SHA256()))),userHandle=b64(handle) if handle is not None else None)
        return result
    return party,identifier,public,response


def test_registration_and_real_signature_authentication(authenticator):
    party,identifier,public,response=authenticator
    challenge=secrets.token_bytes(32)
    registered=party.register(response('create',challenge),challenge)
    assert registered.credential_id==identifier and registered.credential_public_key==public and registered.sign_count==0
    challenge=secrets.token_bytes(32)
    signed=response('get',challenge,counter=1,handle=b'opaque-user')
    checked=party.authenticate(signed,challenge,identifier,public,0,b'opaque-user')
    assert checked.new_sign_count==1 and checked.credential_id==identifier


@pytest.mark.parametrize('origin',['http://public.example.test','http://127.0.0.1:8110','https://127.0.0.1','https://[::1]','https://user@example.test','https://example.test/path','https://example.test?x=1','https://example.test#part','https://example.test/','https://EXAMPLE.test','https://example.test:443','https://example.test:0'])
def test_noncanonical_insecure_or_ip_origin_rejected(origin):
    with pytest.raises(PasskeyError):RelyingParty.from_origin(origin)


def test_options_require_user_verification_and_do_not_expand_rp_scope():
    party=RelyingParty.from_origin('http://localhost:8110')
    options=party.registration_options(b'opaque-user','fixture@example.test',[b'old-credential'])
    assert options['rp']['id']=='localhost' and options['user']['id']==b64(b'opaque-user')
    assert options['authenticatorSelection']['userVerification']=='required'
    assert options['authenticatorSelection']['residentKey']=='required'
    assert options['attestation']=='none' and len(decode(options['challenge']))>=32
    assert options['excludeCredentials'][0]['id']==b64(b'old-credential')
    assert party.authentication_options([b'old-credential'])['userVerification']=='required'
    assert party.authentication_options([])['allowCredentials']==[]
    with pytest.raises(PasskeyError):party.registration_options(b'','fixture@example.test')


@pytest.mark.parametrize('change',[
    {'origin':'https://evil.test'},{'rp_id':'other.example.test'},
    {'flags':0x41},{'flags':0x44},{'crossOrigin':True},{'crossOrigin':'false'},
    {'topOrigin':'https://security.example.test'},
])
def test_registration_rejects_scope_presence_verification_and_framing(authenticator,change):
    party,_,_,response=authenticator;challenge=secrets.token_bytes(32)
    with pytest.raises(PasskeyError):party.register(response('create',challenge,**change),challenge)


@pytest.mark.parametrize('change',[
    {'origin':'https://evil.test'},{'rp_id':'other.example.test'},{'flags':0x01},
    {'flags':0x04},{'crossOrigin':True},{'handle':b'another-user'},
])
def test_authentication_rejects_wrong_scope_flags_or_user(authenticator,change):
    party,identifier,public,response=authenticator;challenge=secrets.token_bytes(32)
    with pytest.raises(PasskeyError):party.authenticate(response('get',challenge,**change),challenge,identifier,public,0,b'opaque-user')


def test_challenge_signature_id_and_counter_binding(authenticator):
    party,identifier,public,response=authenticator;challenge=secrets.token_bytes(32)
    with pytest.raises(PasskeyError):party.register(response('create',challenge),secrets.token_bytes(32))
    signed=response('get',challenge,counter=1)
    for expected,ident,count in [(secrets.token_bytes(32),identifier,0),(challenge,b'other-credential',0),(challenge,identifier,1)]:
        with pytest.raises(PasskeyError):party.authenticate(signed,expected,ident,public,count,b'opaque-user')
    signed['response']['signature']=b64(b'not-a-signature')
    with pytest.raises(PasskeyError):party.authenticate(signed,challenge,identifier,public,0,b'opaque-user')


def test_zero_counter_sync_credential_is_valid_but_not_replay_protection(authenticator):
    party,identifier,public,response=authenticator;challenge=secrets.token_bytes(32)
    signed=response('get',challenge)
    assert party.authenticate(signed,challenge,identifier,public,0,b'opaque-user').new_sign_count==0
    # Protocol verification alone cannot consume a challenge. Route/storage
    # integration must make this proof single-use in a transaction.
    assert party.authenticate(signed,challenge,identifier,public,0,b'opaque-user').new_sign_count==0


@pytest.mark.parametrize('credential',[{},None,{'id':'bad/','response':{}},{'id':'a','response':{'clientDataJSON':'x'*10000}}])
def test_malformed_response_is_a_generic_error(authenticator,credential):
    party,identifier,public,_=authenticator
    with pytest.raises(PasskeyError):party.authenticate(credential,b'x'*32,identifier,public,0,b'opaque-user')
