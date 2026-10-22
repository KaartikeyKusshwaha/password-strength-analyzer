"""Workspace sharing: public-key validation and authorization; no decryption keys."""
import base64
import hashlib
import json
from typing import Literal
from urllib.parse import urlsplit

from cryptography.exceptions import InvalidSignature, UnsupportedAlgorithm
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature
from fastapi import Depends, HTTPException
from pydantic import BaseModel, ConfigDict, Field, field_validator

from .store import Store, canonical, now
from .vault_activity import record_connection_revocations, record_action_cancellations, invalidate_ownership
from .browser_access import require_connection
from .admin_mfa import enforce as enforce_admin_mfa


class Body(BaseModel):
    model_config = ConfigDict(extra='forbid', str_strip_whitespace=True)


class PublicIdentity(Body):
    encryption: str = Field(max_length=1200)
    signing: str = Field(max_length=300)


class PrivateIdentity(Body):
    version: Literal[1]
    salt: str = Field(max_length=24)
    iv: str = Field(max_length=16)
    ciphertext: str = Field(min_length=100, max_length=16000)

    @field_validator('salt','iv','ciphertext')
    @classmethod
    def encoded(cls,value,info):
        try:
            data=base64.b64decode(value,validate=True)
        except ValueError:
            raise ValueError('Invalid encrypted identity')
        if info.field_name in {'salt','iv'} and len(data)!=(16 if info.field_name=='salt' else 12):
            raise ValueError('Invalid encryption parameters')
        return value


class IdentityCreate(Body):
    public: PublicIdentity
    encrypted: PrivateIdentity


class IdentityRewrap(Body):
    previous_digest: str = Field(pattern=r'^[a-f0-9]{64}$')
    encrypted: PrivateIdentity
    signature: str = Field(min_length=88,max_length=88)


class Grant(Body):
    version: Literal[1]
    vault_id: str = Field(pattern=r'^[a-f0-9]{24}$')
    recipient: str = Field(pattern=r'^[a-f0-9]{24}$')
    issuer: str = Field(pattern=r'^[a-f0-9]{24}$')
    epoch: int = Field(ge=1,le=1000000)
    role: Literal['owner','admin','editor','viewer']
    recipient_fingerprint: str = Field(pattern=r'^[a-f0-9]{64}$')
    issuer_fingerprint: str = Field(pattern=r'^[a-f0-9]{64}$')
    wrapped_key: str = Field(min_length=512,max_length=512)
    signature: str = Field(min_length=88,max_length=88)


class TeamPayload(Body):
    version: Literal[1]
    context: str = Field(pattern=r'^[a-f0-9]{24}$')
    epoch: int = Field(ge=1,le=1000000)
    iv: str = Field(max_length=16)
    ciphertext: str = Field(min_length=24,max_length=120000)

    @field_validator('iv','ciphertext')
    @classmethod
    def encoded(cls,value,info):
        try:
            raw=base64.b64decode(value,validate=True)
        except ValueError:
            raise ValueError('Invalid encrypted team payload')
        if (info.field_name=='iv' and len(raw)!=12) or (info.field_name=='ciphertext' and len(raw)<16):
            raise ValueError('Invalid team encryption parameters')
        return value


class TeamCreate(Body):
    id: str = Field(pattern=r'^[a-f0-9]{24}$')
    name: str = Field(min_length=2,max_length=70)
    manifest_signature: str = Field(min_length=88,max_length=88)
    payload: TeamPayload
    grant: Grant


class TeamWrite(Body):
    revision: int = Field(ge=1)
    payload: TeamPayload


class TeamRotate(TeamWrite):
    grants: list[Grant] = Field(min_length=1,max_length=20)


class TeamBrowserPolicy(Body):
    browser_enabled: bool = True
    browser_save: bool = True
    browser_fill: bool = True
    origins: list[str] = Field(default_factory=list,max_length=30)
    lock_seconds: int = Field(default=180,ge=30,le=900)

    @field_validator('origins')
    @classmethod
    def origins_valid(cls,values):
        result=[]
        for value in values:
            parsed=urlsplit(value)
            if parsed.scheme!='https' or not parsed.hostname or parsed.username or parsed.password or parsed.path not in {'','/'} or parsed.query or parsed.fragment:
                raise ValueError('Use exact HTTPS origins without credentials, paths or queries.')
            result.append(value.rstrip('/'))
        return list(dict.fromkeys(result))


def bad(condition,message='Sharing authorization failed',code=403):
    if not condition:
        raise HTTPException(code,message)


def revoke_access(c, workspace, actor, identifier, user):
    """Transactional revocation shared by interactive and approved workflows."""
    vault=c.execute("SELECT v.*,g.role FROM team_vaults v JOIN team_grants g ON g.vault=v.id JOIN members m ON m.workspace=v.workspace AND m.user=g.user WHERE v.id=? AND v.workspace=? AND g.user=? AND g.accepted=1 AND m.role!='viewer'",(identifier,workspace,actor)).fetchone()
    bad(vault,'Shared vault administration unavailable',404)
    recipient=c.execute('SELECT role FROM team_grants WHERE vault=? AND user=?',(identifier,user)).fetchone()
    bad(recipient,'Vault member not found',404)
    bad(user!=vault['owner'],'The vault owner cannot be offboarded through member revocation',409)
    bad(vault['role']=='owner' or vault['role']=='admin' and recipient['role'] not in {'owner','admin'},'Insufficient vault administration access')
    c.execute('DELETE FROM team_grants WHERE vault=? AND user=?',(identifier,user))
    record_connection_revocations(c,c.execute("SELECT * FROM companions WHERE kind='shared' AND vault_id=? AND user=?",(identifier,user)).fetchall(),actor)
    c.execute("DELETE FROM companions WHERE kind='shared' AND vault_id=? AND user=?",(identifier,user))
    record_action_cancellations(c,c.execute("SELECT id,workspace,user FROM credential_actions WHERE kind='shared' AND vault_id=? AND user=? AND status NOT IN ('complete','cancelled','expired')",(identifier,user)).fetchall(),actor)
    c.execute("UPDATE credential_actions SET status='cancelled',lease_hash=NULL,lease_connection=NULL,lease_expires=NULL WHERE kind='shared' AND vault_id=? AND user=? AND status NOT IN ('complete','cancelled','expired')",(identifier,user))
    c.execute('UPDATE team_vaults SET rotation_required=1 WHERE id=?',(identifier,))
    invalidate_ownership(c,workspace,identifier,actor,'access_revoked')
    Store.event(c,workspace,actor,'team_vault.access_revoked',identifier+':'+user)


def public_keys(public):
    try:
        encryption=serialization.load_der_public_key(base64.b64decode(public['encryption'],validate=True))
        signing=serialization.load_der_public_key(base64.b64decode(public['signing'],validate=True))
        if not isinstance(encryption,rsa.RSAPublicKey) or encryption.key_size!=3072 or encryption.public_numbers().e!=65537 or not isinstance(signing,ec.EllipticCurvePublicKey) or not isinstance(signing.curve,ec.SECP256R1):
            raise ValueError()
        fingerprint=hashlib.sha256(canonical(public).encode()).hexdigest()
        return fingerprint,signing
    except (ValueError,TypeError,KeyError,UnsupportedAlgorithm):
        raise HTTPException(422,'Invalid sharing public keys')


def verify(public,document,signature):
    try:
        _,key=public_keys(public)
        raw=base64.b64decode(signature,validate=True)
        if len(raw)!=64:
            raise ValueError()
        key.verify(encode_dss_signature(int.from_bytes(raw[:32],'big'),int.from_bytes(raw[32:],'big')),canonical(document).encode(),ec.ECDSA(hashes.SHA256()))
    except (InvalidSignature,ValueError):
        raise HTTPException(422,'Sharing signature verification failed')


def register(app,store,auth,writable,throttle):
    def identity(c,user):
        row=c.execute('SELECT * FROM sharing_identities WHERE user=?',(user,)).fetchone()
        bad(row,'Create a sharing identity first',409)
        return dict(row)

    def team(c,session,identifier,accepted=True):
        row=c.execute('SELECT v.*,g.role,g.accepted,g.envelope FROM team_vaults v JOIN team_grants g ON v.id=g.vault WHERE v.id=? AND v.workspace=? AND g.user=?',(identifier,session['workspace'],session['user'])).fetchone()
        bad(row,'Shared vault not found',404)
        bad(not accepted or row['accepted'],'Accept this vault invitation first',409)
        return dict(row)

    def validate_grant(c,grant,vault,issuer,owner_creation=False):
        value=grant.model_dump() if isinstance(grant,Grant) else grant
        bad(value['vault_id']==vault['id'] and value['epoch']==vault['epoch'] and value['issuer']==issuer,'Grant scope mismatch',422)
        recipient=identity(c,value['recipient']);sender=identity(c,issuer)
        bad(value['recipient_fingerprint']==recipient['fingerprint'] and value['issuer_fingerprint']==sender['fingerprint'],'Sharing fingerprint changed',409)
        member=c.execute('SELECT role FROM members WHERE workspace=? AND user=?',(vault['workspace'],value['recipient'])).fetchone()
        bad(member,'Recipient must belong to this workspace',422)
        bad(member['role']!='viewer' or value['role']=='viewer','Workspace viewers may receive view access only',422)
        if owner_creation:
            bad(value['role']=='owner' and value['recipient']==vault['owner'] and issuer==vault['owner'],'Owner grant required',422)
        else:
            bad(value['role']!='owner','Vault ownership cannot be reassigned by invitation',422)
            bad(value['role']!='admin' or issuer==vault['owner'],'Only the vault owner may delegate admin access')
        document={k:v for k,v in value.items() if k!='signature'}
        try:
            bad(len(base64.b64decode(value['wrapped_key'],validate=True))==384,'Invalid wrapped vault key',422)
        except ValueError:
            raise HTTPException(422,'Invalid wrapped vault key')
        verify(json.loads(sender['public']),document,value['signature'])
        proof=None
        if issuer!=vault['owner']:
            parent=c.execute('SELECT envelope FROM team_grants WHERE vault=? AND user=? AND accepted=1 AND role=?',(vault['id'],issuer,'admin')).fetchone()
            bad(parent,'Issuer no longer has admin access')
            proof=json.loads(parent['envelope'])
        return {**value,'issuer_public':json.loads(sender['public']),'issuer_grant':proof}

    @app.get('/api/sharing/identity')
    def own_identity(session=Depends(auth)):
        with store.connect() as c:
            row=c.execute('SELECT * FROM sharing_identities WHERE user=?',(session['user'],)).fetchone()
        return {'identity':{'public':json.loads(row['public']),'fingerprint':row['fingerprint'],'encrypted':json.loads(row['encrypted'])} if row else None,'user_id':session['user']}

    @app.post('/api/sharing/identity')
    def create_identity(body: IdentityCreate,session=Depends(auth)):
        throttle('sharing-identity:'+session['user'],5)
        public=body.public.model_dump();fingerprint,_=public_keys(public)
        with store.connect(write=True) as c:
            bad(not c.execute('SELECT 1 FROM sharing_identities WHERE user=?',(session['user'],)).fetchone(),'A sharing identity already exists; silent key replacement is disabled',409)
            c.execute('INSERT INTO sharing_identities VALUES(?,?,?,?,?)',(session['user'],canonical(public),fingerprint,canonical(body.encrypted.model_dump()),now()))
            Store.event(c,session['workspace'],session['user'],'sharing.identity_created',session['user'])
        return {'fingerprint':fingerprint}

    @app.post('/api/sharing/identity/passphrase')
    def rewrap_identity(body: IdentityRewrap,session=Depends(auth)):
        # Private identity maintenance is allowed for workspace viewers too.
        # The existing signing key proves possession; no passphrase is received.
        throttle('sharing-rewrap:'+session['user'],10)
        with store.connect(write=True) as c:
            row=identity(c,session['user'])
            previous=json.loads(row['encrypted'])
            previous_digest=hashlib.sha256(canonical(previous).encode()).hexdigest()
            bad(body.previous_digest==previous_digest,'Sharing protection changed; reload and unlock its current version before retrying',409)
            encrypted=body.encrypted.model_dump()
            bad(encrypted['salt']!=previous['salt'] and encrypted['iv']!=previous['iv'] and encrypted['ciphertext']!=previous['ciphertext'],'New sharing protection requires fresh encryption parameters',422)
            document={'action':'sharing.identity_rewrap.v1','user':session['user'],'fingerprint':row['fingerprint'],'previous_digest':previous_digest,'encrypted':encrypted}
            verify(json.loads(row['public']),document,body.signature)
            c.execute('UPDATE sharing_identities SET encrypted=? WHERE user=?',(canonical(encrypted),session['user']))
            from .ownership import cancel_identity_proposals
            cancel_identity_proposals(c,session['user'])
            record_connection_revocations(c,c.execute("SELECT * FROM companions WHERE kind='shared' AND user=?",(session['user'],)).fetchall(),session['user'])
            c.execute("DELETE FROM companions WHERE kind='shared' AND user=?",(session['user'],))
            record_action_cancellations(c,c.execute("SELECT id,workspace,user FROM credential_actions WHERE kind='shared' AND user=? AND status NOT IN ('complete','cancelled','expired')",(session['user'],)).fetchall(),session['user'])
            c.execute("UPDATE credential_actions SET status='cancelled',lease_hash=NULL,lease_connection=NULL,lease_expires=NULL WHERE kind='shared' AND user=? AND status NOT IN ('complete','cancelled','expired')",(session['user'],))
            for member in c.execute('SELECT workspace FROM members WHERE user=?',(session['user'],)).fetchall():
                Store.event(c,member['workspace'],session['user'],'sharing.passphrase_changed',session['user'])
        return {'fingerprint':row['fingerprint'],'shared_connections_revoked':True}

    @app.get('/api/sharing/directory')
    def directory(session=Depends(auth)):
        with store.connect() as c:
            return {'members':[{'id':r['id'],'email':r['email'],'role':r['role'],'public':json.loads(r['public']) if r['public'] else None,'fingerprint':r['fingerprint']} for r in c.execute('SELECT u.id,u.email,m.role,i.public,i.fingerprint FROM members m JOIN users u ON u.id=m.user LEFT JOIN sharing_identities i ON i.user=u.id WHERE m.workspace=?',(session['workspace'],))]}

    @app.get('/api/team-vaults')
    def list_teams(session=Depends(auth)):
        with store.connect() as c:
            from .ownership import incoming
            requests={row['vault_id'] for row in incoming(c,session['workspace'],session['user'])} if session['role']!='viewer' else set()
            return {'vaults':[{**{k:r[k] for k in r.keys() if k!='browser_policy'},'browser_enabled':json.loads(r['browser_policy'])['browser_enabled'],'ownership_pending':r['id'] in requests} for r in c.execute('SELECT v.id,v.name,v.owner,v.epoch,v.revision,v.rotation_required,v.browser_policy,g.role,g.accepted FROM team_vaults v JOIN team_grants g ON g.vault=v.id WHERE v.workspace=? AND g.user=? ORDER BY v.created_at',(session['workspace'],session['user']))]}

    @app.post('/api/team-vaults')
    def create_team(body: TeamCreate,session=Depends(auth)):
        writable(session);throttle('team-vault:'+session['user'],10)
        with store.connect(write=True) as c:
            sender=identity(c,session['user'])
            bad(not c.execute('SELECT 1 FROM team_vaults WHERE id=?',(body.id,)).fetchone(),'Vault id already exists',409)
            bad(c.execute('SELECT count(*) FROM team_vaults WHERE workspace=?',(session['workspace'],)).fetchone()[0]<20,'Workspace vault limit reached',409)
            vault={'id':body.id,'workspace':session['workspace'],'owner':session['user'],'epoch':1}
            manifest={**{k:vault[k] for k in ('id','workspace','owner')},'owner_fingerprint':sender['fingerprint']}
            verify(json.loads(sender['public']),manifest,body.manifest_signature)
            bad(body.payload.context==body.id and body.payload.epoch==1,'Team encryption context mismatch',422)
            grant=validate_grant(c,body.grant,vault,session['user'],True)
            c.execute('INSERT INTO team_vaults(id,workspace,owner,name,manifest,payload,epoch,revision,rotation_required,created_at) VALUES(?,?,?,?,?,?,?,?,?,?)',(body.id,session['workspace'],session['user'],body.name,canonical({'document':manifest,'signature':body.manifest_signature}),canonical(body.payload.model_dump()),1,1,0,now()))
            c.execute('INSERT INTO team_grants VALUES(?,?,?,?,?,?)',(body.id,session['user'],'owner',canonical(grant),1,now()))
            Store.event(c,session['workspace'],session['user'],'team_vault.created',body.id)
        return {'id':body.id}

    @app.get('/api/team-vaults/{identifier}')
    def read_team(identifier: str,session=Depends(auth)):
        with store.connect() as c:
            row=team(c,session,identifier,False)
            owner=identity(c,row['owner'])
            grants=[{'user_id':r['user'],'email':r['email'],'role':r['role'],'accepted':r['accepted'],'envelope':json.loads(r['envelope'])} for r in c.execute('SELECT g.*,u.email FROM team_grants g JOIN users u ON u.id=g.user WHERE g.vault=?',(identifier,))] if row['accepted'] else []
            return {'id':identifier,'name':row['name'],'workspace':row['workspace'],'owner':row['owner'],'owner_public':json.loads(owner['public']),'owner_fingerprint':owner['fingerprint'],'manifest':json.loads(row['manifest']),'epoch':row['epoch'],'revision':row['revision'],'rotation_required':bool(row['rotation_required']),'role':row['role'],'accepted':bool(row['accepted']),'grant':json.loads(row['envelope']),'grants':grants,'payload':json.loads(row['payload']) if row['accepted'] else None,'browser_policy':json.loads(row['browser_policy'])}

    @app.post('/api/team-vaults/{identifier}/browser-policy')
    def update_browser_policy(identifier: str,body: TeamBrowserPolicy,session=Depends(auth)):
        writable(session)
        with store.connect(write=True) as c:
            row=team(c,session,identifier)
            bad(row['role'] in {'owner','admin'},'Vault admin access required')
            c.execute('UPDATE team_vaults SET browser_policy=? WHERE id=?',(canonical(body.model_dump()),identifier))
            if canonical(body.model_dump())!=row['browser_policy']:
                invalidate_ownership(c,session['workspace'],identifier,session['user'],'browser_policy_updated')
            if not body.browser_enabled:
                record_connection_revocations(c,c.execute("SELECT * FROM companions WHERE kind='shared' AND vault_id=?",(identifier,)).fetchall(),session['user'])
                c.execute("DELETE FROM companions WHERE kind='shared' AND vault_id=?",(identifier,))
            Store.event(c,session['workspace'],session['user'],'team_vault.browser_policy_updated',identifier)
        return {'ok':True}

    @app.post('/api/team-vaults/{identifier}/accept')
    def accept_team(identifier: str,session=Depends(auth)):
        with store.connect(write=True) as c:
            row=team(c,session,identifier,False)
            bad(not row['rotation_required'],'Vault key rotation is required before accepting invitations',409)
            if not row['accepted']:
                c.execute('UPDATE team_grants SET accepted=1 WHERE vault=? AND user=?',(identifier,session['user']))
                invalidate_ownership(c,session['workspace'],identifier,session['user'],'grant_accepted')
                Store.event(c,session['workspace'],session['user'],'team_vault.invitation_accepted',identifier)
        return {'ok':True}

    @app.post('/api/team-vaults/{identifier}/invite')
    def invite_team(identifier: str,body: Grant,session=Depends(auth)):
        writable(session);throttle('team-invite:'+session['user'],30)
        with store.connect(write=True) as c:
            vault=team(c,session,identifier)
            bad(vault['role'] in {'owner','admin'},'Vault admin access required')
            bad(not vault['rotation_required'],'Rotate the vault key before issuing new access',409)
            bad(c.execute('SELECT count(*) FROM team_grants WHERE vault=?',(identifier,)).fetchone()[0]<20,'A team vault supports up to 20 members',409)
            bad(not c.execute('SELECT 1 FROM team_grants WHERE vault=? AND user=?',(identifier,body.recipient)).fetchone(),'Recipient already has an invitation or access',409)
            envelope=validate_grant(c,body,vault,session['user'])
            c.execute('INSERT INTO team_grants VALUES(?,?,?,?,?,?)',(identifier,body.recipient,body.role,canonical(envelope),0,now()))
            invalidate_ownership(c,session['workspace'],identifier,session['user'],'member_invited')
            Store.event(c,session['workspace'],session['user'],'team_vault.invited',identifier+':'+body.recipient)
        return {'ok':True}

    @app.post('/api/team-vaults/{identifier}/save')
    def save_team(identifier: str,body: TeamWrite,session=Depends(auth)):
        writable(session);throttle('team-write:'+session['user'],120)
        with store.connect(write=True) as c:
            vault=team(c,session,identifier)
            bad(vault['role'] in {'owner','admin','editor'},'Read-only vault access')
            bad(not vault['rotation_required'],'Rotate the vault key after offboarding before saving new credentials',409)
            bad(body.revision==vault['revision'],'Shared vault changed; reload before editing',409)
            bad(body.payload.context==identifier and body.payload.epoch==vault['epoch'],'Team encryption context mismatch',422)
            c.execute('UPDATE team_vaults SET payload=?,revision=revision+1 WHERE id=?',(canonical(body.payload.model_dump()),identifier))
            invalidate_ownership(c,session['workspace'],identifier,session['user'],'vault_saved')
            Store.event(c,session['workspace'],session['user'],'team_vault.saved',identifier)
        return {'revision':body.revision+1}

    @app.post('/api/team-vaults/{identifier}/revoke/{user}')
    def revoke_team(identifier: str,user: str,session=Depends(auth)):
        writable(session)
        with store.connect(write=True) as c:
            revoke_access(c,session['workspace'],session['user'],identifier,user)
        return {'ok':True,'rotation_required':True,'note':'Cached credentials cannot be erased. Rotate the vault key and affected website passwords.'}

    def apply_rotation(c,session,identifier,body):
        vault=team(c,session,identifier)
        bad(vault['role']=='owner','Only the vault owner may rotate and re-distribute the vault key')
        bad(body.revision==vault['revision'],'Shared vault changed; reload before rotating',409)
        bad(body.payload.context==identifier and body.payload.epoch==vault['epoch']+1,'Rotation requires the next key epoch',422)
        recipients={r['user']:dict(r) for r in c.execute('SELECT * FROM team_grants WHERE vault=?',(identifier,))}
        bad(len(body.grants)==len(recipients) and {g.recipient for g in body.grants}==set(recipients),'Rotation must cover exactly the remaining vault members',422)
        output=[]
        for grant in body.grants:
            bad(grant.role==recipients[grant.recipient]['role'],'Rotation cannot silently change a member role',422)
            output.append((grant.recipient,validate_grant(c,grant,{**vault,'epoch':vault['epoch']+1},session['user'],grant.recipient==vault['owner'])))
        for user,envelope in output:
            c.execute('UPDATE team_grants SET envelope=? WHERE vault=? AND user=?',(canonical(envelope),identifier,user))
        c.execute('UPDATE team_vaults SET payload=?,epoch=epoch+1,revision=revision+1,rotation_required=0 WHERE id=?',(canonical(body.payload.model_dump()),identifier))
        invalidate_ownership(c,session['workspace'],identifier,session['user'],'key_rotated')
        Store.event(c,session['workspace'],session['user'],'team_vault.key_rotated',identifier)
        return {'revision':body.revision+1,'epoch':body.payload.epoch}

    @app.post('/api/team-vaults/{identifier}/rotate')
    def rotate_team(identifier: str,body: TeamRotate,session=Depends(auth)):
        writable(session);throttle('team-rotate:'+session['user'],20)
        with store.connect(write=True) as c:return apply_rotation(c,session,identifier,body)

    def browser_context(c,connection):
        # Validate every use, including accepted grant, current membership and policy.
        require_connection(c,connection)
        enforce_admin_mfa(c,connection['user'],store)
        bad(connection.get('kind')=='shared','Shared browser connection required',401)
        member=c.execute('SELECT role FROM members WHERE workspace=? AND user=?',(connection['workspace'],connection['user'])).fetchone()
        bad(member,'Shared browser connection expired or revoked',401)
        row=team(c,connection,connection['vault_id'])
        policy=json.loads(row['browser_policy'])
        bad(policy['browser_enabled'],'Browser access to this shared vault is disabled',403)
        return row,policy,member

    def browser_metadata(c,session,identifier):
        row=team(c,session,identifier)
        bad(json.loads(row['browser_policy'])['browser_enabled'],'Enable browser access for this shared vault before connecting',409)
        identity(c,session['user'])
        return {'id':identifier,'name':row['name'],'kind':'shared'}

    def browser_read(connection):
        with store.connect() as c:
            row,policy,member=browser_context(c,connection);who=identity(c,connection['user']);owner=identity(c,row['owner'])
            shared={'id':row['id'],'workspace':row['workspace'],'owner':row['owner'],'owner_public':json.loads(owner['public']),'owner_fingerprint':owner['fingerprint'],'manifest':json.loads(row['manifest']),'epoch':row['epoch'],'revision':row['revision'],'role':row['role'],'accepted':True,'grant':json.loads(row['envelope']),'payload':json.loads(row['payload'])}
            metadata={'id':row['id'],'name':row['name'],'kind':'shared',**policy,'browser_save':policy['browser_save'] and not row['rotation_required'] and member['role']!='viewer' and row['role'] in {'owner','admin','editor'},'owner_fingerprint':owner['fingerprint'],'owner_is_self':row['owner']==connection['user'],'rotation_required':bool(row['rotation_required'])}
            return {'kind':'shared','revision':row['revision'],'envelope':shared['payload'],'vault':metadata,'sharing':{'user_id':connection['user'],'identity':{'public':json.loads(who['public']),'fingerprint':who['fingerprint'],'encrypted':json.loads(who['encrypted'])},'team':shared}}

    def browser_write(connection,revision,envelope):
        with store.connect(write=True) as c:
            row,policy,member=browser_context(c,connection)
            bad(policy['browser_save'] and member['role']!='viewer' and row['role'] in {'owner','admin','editor'},'Read-only browser vault access')
            bad(not row['rotation_required'],'Rotate the vault key after removing access before saving',409)
            bad(row['revision']==revision,'Shared vault changed; unlock again before saving',409)
            bad(envelope.context==row['id'] and envelope.epoch==row['epoch'],'Shared vault encryption context changed',422)
            c.execute('UPDATE team_vaults SET payload=?,revision=revision+1 WHERE id=?',(canonical(envelope.model_dump()),row['id']))
            invalidate_ownership(c,row['workspace'],row['id'],connection['user'],'browser_saved')
            Store.event(c,row['workspace'],connection['user'],'team_vault.browser_saved',row['id'])
        return {'revision':revision+1,'vault_id':row['id']}

    def workflow_rotation_context(c,connection):
        row,policy,member=browser_context(c,connection)
        bad(row['role']=='owner' and member['role']=='owner' and row['owner']==connection['user'],'Owner vault connection required')
        who=identity(c,connection['user'])
        grants=[{'user_id':r['user'],'role':r['role'],'accepted':r['accepted'],'envelope':json.loads(r['envelope'])} for r in c.execute('SELECT * FROM team_grants WHERE vault=?',(row['id'],))]
        directory=[]
        for recipient in grants:
            public=identity(c,recipient['user_id'])
            directory.append({'id':recipient['user_id'],'public':json.loads(public['public']),'fingerprint':public['fingerprint']})
        return {'team':{'id':row['id'],'workspace':row['workspace'],'owner':row['owner'],'owner_public':json.loads(who['public']),'owner_fingerprint':who['fingerprint'],'manifest':json.loads(row['manifest']),'epoch':row['epoch'],'revision':row['revision'],'role':row['role'],'accepted':True,'grant':json.loads(row['envelope']),'grants':grants,'payload':json.loads(row['payload'])},'directory':directory}

    def workflow_rotate(c,connection,body):
        row,policy,member=browser_context(c,connection)
        bad(row['role']=='owner' and member['role']=='owner' and row['owner']==connection['user'],'Owner vault connection required')
        return apply_rotation(c,{**connection,'role':member['role']},row['id'],body)

    from .ownership import register as register_ownership
    register_ownership(app,store,auth,writable,throttle,team,identity,validate_grant)
    return {'metadata':browser_metadata,'read':browser_read,'write':browser_write,'rotation_context':workflow_rotation_context,'rotate':workflow_rotate}
