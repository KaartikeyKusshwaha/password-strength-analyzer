"""Account WebAuthn routes. Vault unlock remains an independent local protocol."""
import base64
import re
import secrets
import time

from fastapi import Depends, HTTPException, Request, Response
from pydantic import BaseModel, ConfigDict, Field, SecretStr, field_validator

from .passkey_ceremonies import Ceremonies, Scope, valid_binding
from .passkey_protocol import PasskeyError, RelyingParty, decode
from . import passkey_credentials as credentials
from .security import digest, verify_password, consume_factor
from .store import Store, uid

COOKIE='sentinel_passkey_binding'
COOKIE_PATH='/api/passkeys'
INVALID='Passkey request could not be verified. Start again.'


class Reauthenticate(BaseModel):
    model_config=ConfigDict(extra='forbid')
    password: SecretStr = Field(max_length=128)
    code: str = Field(default='',max_length=80)


class SignInOptions(BaseModel):
    model_config=ConfigDict(extra='forbid',str_strip_whitespace=True)
    email: str = Field(min_length=3,max_length=254)

    @field_validator('email')
    @classmethod
    def email_valid(cls,value):
        if not re.fullmatch(r'[^\s@]+@[^\s@]+\.[^\s@]+',value):
            raise ValueError('Enter an email address.')
        return value.lower()


def install_routes(app,store,settings,cipher,auth,issue,throttle):
    ceremonies=Ceremonies(store)
    app.state.passkey_ceremonies=ceremonies
    try: configured_party=RelyingParty.from_origin(settings.origin)
    except PasskeyError: configured_party=None

    def party(request=None):
        if configured_party is None:
            raise HTTPException(409,'Passkeys need a configured HTTPS domain or localhost origin. The current app origin is unsupported.')
        if request is not None and request.headers.get('origin') != settings.origin:
            raise HTTPException(403,'Same-origin passkey request required.')
        return configured_party

    def binding(request,response):
        value=request.cookies.get(COOKIE,'')
        if not valid_binding(value): value=secrets.token_urlsafe(32)
        response.set_cookie(COOKIE,value,httponly=True,secure=settings.secure,samesite='strict',max_age=300,path=COOKIE_PATH)
        return value

    def live_account(c,session):
        row=c.execute('''SELECT u.* FROM sessions s JOIN users u ON u.id=s.user
            JOIN members m ON m.workspace=s.workspace AND m.user=s.user
            JOIN workspaces w ON w.id=m.workspace
            WHERE s.token=? AND s.pending=0 AND s.expires>? AND w.demo=0''',(session['token'],time.time())).fetchone()
        if not row: raise HTTPException(401,'Sign in required')
        return row

    def reauthenticate(c,session,body):
        user=live_account(c,session)
        if not verify_password(body.password.get_secret_value(),user['password']):
            raise HTTPException(401,'Current sign-in password required.')
        if user['mfa'] and not consume_factor(c,user,body.code,cipher):
            raise HTTPException(401,'Unused authenticator or recovery code required.')
        return user

    def options_response(options,pending):
        options['challenge']=base64.urlsafe_b64encode(pending.challenge).decode().rstrip('=')
        return {'request_id':pending.token,'publicKey':options,'expires_in':120}

    def rejected():
        return HTTPException(400,INVALID)

    async def proof_body(request,expected_keys):
        try:
            value=await request.json()
            if not isinstance(value,dict) or set(value)!=expected_keys: raise ValueError()
            return value
        except (ValueError,TypeError): raise rejected() from None

    @app.get('/api/passkeys/status')
    def status():
        return {'available':configured_party is not None,
                'reason':None if configured_party else 'Passkeys require a configured HTTPS domain or localhost origin.',
                'vault_unlock':False}

    @app.get('/api/passkeys')
    def listing(session=Depends(auth)):
        if configured_party is None: return {'available':False,'credentials':[]}
        with store.connect() as c:
            live_account(c,session)
            values=credentials.list_public(c,session['user'],configured_party)
        return {'available':True,'credentials':values}

    @app.post('/api/passkeys/register/options')
    def register_options(body: Reauthenticate,request: Request,response: Response,session=Depends(auth)):
        rp=party(request);throttle('passkey-enroll:'+session['user'],12)
        browser=binding(request,response)
        try:
            with store.connect(write=True) as c:
                user=reauthenticate(c,session,body)
                ids=credentials.active_ids(c,user['id'],rp)
                if len(ids)>=credentials.MAX_ACTIVE: raise PasskeyError('Too many active passkeys.')
                pending=ceremonies.begin_in_transaction(c,browser,Scope('registration',rp,user['id'],session['token']))
                options=rp.registration_options(user['id'].encode(),user['email'],ids)
            return options_response(options,pending)
        except PasskeyError: raise rejected() from None

    @app.post('/api/passkeys/register/finish')
    async def register_finish(request: Request,session=Depends(auth)):
        rp=party(request);throttle('passkey-enroll-finish:'+session['user'],15)
        try:
            challenge=ceremonies.consume(request.headers.get('X-Passkey-Request',''),request.cookies.get(COOKIE,''),
                                        Scope('registration',rp,session['user'],session['token']))
            # The claim is committed before JSON parsing or credential validation.
            body=await proof_body(request,{'label','credential'})
            verified=rp.register(body['credential'],challenge)
            with store.connect(write=True) as c:
                live_account(c,session)
                identifier=credentials.register(c,session['user'],rp,body['label'],verified)
                Store.event(c,'personal:'+session['user'],session['user'],'auth.passkey_enrolled',identifier)
            return {'id':identifier}
        except PasskeyError: raise rejected() from None

    @app.post('/api/passkeys/login/options')
    def login_options(body: SignInOptions,request: Request,response: Response):
        rp=party(request)
        throttle('passkey-login-ip:'+request.client.host,40)
        throttle('passkey-login-account:'+digest(body.email),20)
        browser=binding(request,response)
        try:
            with store.connect(write=True) as c:
                user=c.execute('SELECT id FROM users WHERE email=?',(body.email,)).fetchone()
                user_id=user['id'] if user else uid()
                pending=ceremonies.begin_in_transaction(c,browser,Scope('authentication',rp,user_id))
                # Discoverable enrollment is required. Do not disclose account
                # credential IDs/counts in unauthenticated options.
                options=rp.authentication_options([])
            return options_response(options,pending)
        except PasskeyError: raise rejected() from None

    @app.post('/api/passkeys/login/finish')
    async def login_finish(request: Request,response: Response):
        rp=party(request);throttle('passkey-login-finish:'+request.client.host,40)
        try:
            user_id,challenge=ceremonies.consume_authentication(request.headers.get('X-Passkey-Request',''),request.cookies.get(COOKIE,''),rp)
            body=await proof_body(request,{'credential'})
            if (not isinstance(body['credential'],dict) or not isinstance(body['credential'].get('response'),dict)
                    or body['credential']['response'].get('userHandle') is None):
                raise PasskeyError(INVALID)
            raw_id=decode(body['credential']['id'],1024) if isinstance(body['credential'],dict) and 'id' in body['credential'] else b''
            with store.connect() as c: observed=credentials.lookup(c,user_id,rp,raw_id)
            verified=rp.authenticate(body['credential'],challenge,observed.credential_id,observed.public_key,observed.sign_count,user_id.encode())
            with store.connect(write=True) as c:
                user=c.execute('SELECT * FROM users WHERE id=?',(user_id,)).fetchone()
                member=c.execute('''SELECT m.workspace FROM members m JOIN workspaces w ON w.id=m.workspace
                    WHERE m.user=? AND w.demo=0 ORDER BY m.rowid LIMIT 1''',(user_id,)).fetchone()
                if not user or not member: raise PasskeyError(INVALID)
                credentials.commit_authentication(c,observed,verified)
                prior=digest(request.cookies.get('sentinel_session',''))
                c.execute('DELETE FROM sessions WHERE token=?',(prior,))
                c.execute('DELETE FROM passkey_ceremonies WHERE session_hash=?',(prior,))
                result=issue(c,response,user_id,member['workspace'],bool(user['mfa']))
                Store.event(c,member['workspace'],user_id,'auth.passkey_factor_pending' if user['mfa'] else 'auth.passkey_signed_in',observed.id)
            return result
        except PasskeyError: raise rejected() from None

    @app.post('/api/passkeys/cancel')
    def cancel(request: Request):
        party(request);throttle('passkey-cancel:'+request.client.host,40)
        try:
            ceremonies.cancel(request.headers.get('X-Passkey-Request',''),request.cookies.get(COOKIE,''))
            return {'ok':True}
        except PasskeyError: raise rejected() from None

    @app.post('/api/passkeys/{identifier}/remove')
    def remove(identifier: str,body: Reauthenticate,request: Request,response: Response,session=Depends(auth)):
        rp=party(request);throttle('passkey-remove:'+session['user'],12)
        try:
            with store.connect(write=True) as c:
                reauthenticate(c,session,body)
                credentials.revoke(c,session['user'],rp,identifier)
                c.execute('DELETE FROM passkey_ceremonies WHERE account=?',(session['user'],))
                c.execute('DELETE FROM sessions WHERE user=?',(session['user'],))
                result=issue(c,response,session['user'],session['workspace'])
                Store.event(c,'personal:'+session['user'],session['user'],'auth.passkey_revoked',identifier)
            return result
        except PasskeyError: raise rejected() from None
