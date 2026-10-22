"""Short-lived authorization for one encrypted vault or separate security operators."""
import hmac
import re
import secrets
import time
from typing import Literal

from fastapi import Depends, HTTPException, Request
from pydantic import BaseModel, Field, SecretStr, ConfigDict
from .security import digest
from .store import Store, uid

SCOPE='system:extension-connect'
KIND='extension_connect'
SECURITY_SCOPE='system:extension-security'
SECURITY_KIND='security_connection'
ACCESS_SCOPE='system:extension-access'
ACCESS_KIND='access_connection'
REMINDER_SCOPE='system:extension-reminders'
REMINDER_KIND='reminder_connection'
DISCOVERY_SCOPE='system:extension-discovery'
DISCOVERY_KIND='discovery_connection'

class Proof(BaseModel):
    model_config=ConfigDict(extra='forbid')
    proof: SecretStr = Field(min_length=43,max_length=100)
    scope: Literal['vault','security','access','discovery','reminders'] = 'vault'
    device_pairing: bool = False

class Approval(BaseModel):
    model_config=ConfigDict(extra='forbid')
    vault_id: str | None = Field(default=None,pattern=r'^[a-f0-9]{24}$')
    workspace_id: str | None = Field(default=None,pattern=r'^[a-f0-9]{24}$')
    confirmed_code: str = Field(pattern=r'^\d{6}$')
    device_pairing: bool = False
    vault_kind: Literal['personal','shared'] = 'personal'

def register(app,store,auth,throttle,cipher,settings,shared_metadata):
    def reject(condition,message,status=403):
        if not condition:raise HTTPException(status,message)
    def extension(request):
        origin=request.headers.get('origin','')
        reject(re.fullmatch(r'chrome-extension://[a-p]{32}',origin),'Extension origin required')
        return origin
    def lookup(c,identifier):
        reject(re.fullmatch(r'[a-f0-9]{24}',identifier),'Connection request unavailable',404)
        record=Store.get(c,SCOPE,KIND,identifier)
        reject(record and record['expires']>time.time(),'Connection request expired. Start again from the extension.',410)
        return record
    def verified(c,identifier,body,request):
        record=lookup(c,identifier)
        reject(record['origin']==extension(request) and hmac.compare_digest(record['proof_hash'],digest(body.proof.get_secret_value())),'Connection proof rejected')
        return record

    @app.post('/api/companion/connect/start')
    def start(body:Proof,request:Request):
        origin=extension(request);throttle('extension-start:'+request.client.host,20)
        with store.connect(write=True) as c:
            for old in Store.all(c,SCOPE,KIND):
                if old['expires']<=time.time():c.execute('DELETE FROM entities WHERE id=? AND workspace=? AND kind=?',(old['id'],SCOPE,KIND))
            reject(len(Store.all(c,SCOPE,KIND))<200,'Too many pending connections',429)
            record=dict(id=uid(),origin=origin,scope=body.scope,device_pairing=body.scope=='security' and body.device_pairing,proof_hash=digest(body.proof.get_secret_value()),code=f'{secrets.randbelow(1000000):06d}',expires=time.time()+300,status='pending')
            Store.put(c,SCOPE,KIND,record)
        return {'id':record['id'],'code':record['code'],'expires':record['expires'],'approval_url':settings.origin+'/#connect='+record['id']}

    @app.get('/api/extension-connect/{identifier}')
    def details(identifier:str,session=Depends(auth)):
        with store.connect() as c:record=lookup(c,identifier)
        result={key:record[key] for key in ('id','origin','code','expires','status')}
        result.update(scope=record.get('scope','vault'),device_pairing=record.get('device_pairing',False),workspace_id=session['workspace'])
        with store.connect() as c:result['workspace_name']=c.execute('SELECT name FROM workspaces WHERE id=?',(session['workspace'],)).fetchone()[0]
        return result

    @app.post('/api/extension-connect/{identifier}/approve')
    def approve(identifier:str,body:Approval,session=Depends(auth)):
        throttle('extension-approve:'+session['user'],20)
        with store.connect(write=True) as c:
            record=lookup(c,identifier)
            reject(record['status']=='pending','This request was already decided',409)
            reject(hmac.compare_digest(body.confirmed_code,record['code']),'Connection code does not match')
            if record.get('scope')=='reminders':
                reject(body.vault_id is None and body.workspace_id==session['workspace'] and not body.device_pairing and body.vault_kind=='personal','Reminder approval does not match',409)
                member=c.execute("SELECT u.mfa FROM users u JOIN members m ON m.user=u.id WHERE m.workspace=? AND m.user=? AND m.role='owner'",(session['workspace'],session['user'])).fetchone()
                reject(member and member['mfa'],'Current owner access and account MFA required')
                token=secrets.token_urlsafe(40)
                grant=dict(id=digest(token),user=session['user'],workspace=session['workspace'],origin=record['origin'],expires=time.time()+90*86400)
                Store.put(c,REMINDER_SCOPE,REMINDER_KIND,grant)
                record.update(status='approved',grant=cipher.encrypt(token.encode()).decode(),user=session['user'],workspace=session['workspace'])
                Store.put(c,SCOPE,KIND,record);Store.event(c,session['workspace'],session['user'],'extension.reminders_connected','read-only-90-days')
                return {'approved':True,'scope':'Read-only client-access expiry reminders for up to 90 days. No vault contents, grant, removal, scan, device or approval permission.'}
            if record.get('scope')=='discovery':
                reject(session['role'] in {'owner','analyst','reviewer'},'Reporting permission required')
                reject(body.vault_id is None and body.workspace_id==session['workspace'] and not body.device_pairing and body.vault_kind=='personal','Discovery approval does not match',409)
                token=secrets.token_urlsafe(40)
                grant=dict(id=digest(token),user=session['user'],workspace=session['workspace'],origin=record['origin'],expires=time.time()+30*86400)
                Store.put(c,DISCOVERY_SCOPE,DISCOVERY_KIND,grant)
                record.update(status='approved',grant=cipher.encrypt(token.encode()).decode(),user=session['user'],workspace=session['workspace'])
                Store.put(c,SCOPE,KIND,record)
                Store.event(c,session['workspace'],session['user'],'extension.discovery_connected','opt-in-account-metadata')
                return {'approved':True,'scope':'Your own domain and chosen account-label observations on explicitly enabled sites, for thirty days. No passwords, browsing history, vault access or removal permission.'}
            if record.get('scope')=='access':
                reject(body.vault_id is None and body.workspace_id==session['workspace'] and not body.device_pairing and body.vault_kind=='personal','Workflow approval does not match',409)
                user=c.execute('SELECT mfa FROM users WHERE id=?',(session['user'],)).fetchone()
                reject(session['role']=='owner' and user and user['mfa'],'Owner access and account MFA required')
                token=secrets.token_urlsafe(40)
                grant=dict(id=digest(token),user=session['user'],workspace=session['workspace'],origin=record['origin'],expires=time.time()+8*3600)
                Store.put(c,ACCESS_SCOPE,ACCESS_KIND,grant)
                record.update(status='approved',grant=cipher.encrypt(token.encode()).decode(),user=session['user'],workspace=session['workspace'])
                Store.put(c,SCOPE,KIND,record)
                Store.event(c,session['workspace'],session['user'],'extension.access_connected','workflow-only')
                return {'approved':True,'scope':'Client access metadata, handoffs and offboarding plans for eight hours. Offboarding execution requires fresh password and MFA approval. Signed invitations with approved expiry and ownership transfer additionally requires a separate exact-vault connection and local owner signatures; ownership transfer also requires successor acceptance. No vault contents without that separate connection, or scanning access.'}
            if record.get('scope')=='security':
                reject(body.vault_id is None and body.vault_kind=='personal' and body.workspace_id==session['workspace'],'Workspace approval does not match',409)
                reject(session['role'] in {'owner','analyst','reviewer'},'Assessment permission required')
                token=secrets.token_urlsafe(40)
                reject(not body.device_pairing or record.get('device_pairing') is True,'Device pairing was not requested',409)
                grant=dict(id=digest(token),user=session['user'],workspace=session['workspace'],origin=record['origin'],device_pairing=body.device_pairing,expires=time.time()+30*86400)
                Store.put(c,SECURITY_SCOPE,SECURITY_KIND,grant)
                record.update(status='approved',grant=cipher.encrypt(token.encode()).decode(),user=session['user'],workspace=session['workspace'])
                Store.put(c,SCOPE,KIND,record)
                Store.event(c,session['workspace'],session['user'],'extension.security_connected','scoped-operator-access')
                return {'approved':True,'scope':'Run explicitly approved assessments and read their results in this workspace. No vault access.'}
            reject(body.workspace_id is None,'Vault approval cannot change workspace',409)
            if body.vault_kind=='shared':
                vault=shared_metadata(c,session,body.vault_id)
            else:
                vault=c.execute('SELECT * FROM vault_spaces WHERE id=? AND user=?',(body.vault_id,session['user'])).fetchone()
                reject(vault and not vault['archived'] and vault['browser_enabled'] and vault['payload']!='null','Choose your initialized browser-enabled vault',409)
            token=secrets.token_urlsafe(40)
            workspace=session['workspace'] if body.vault_kind=='shared' else None
            c.execute('INSERT INTO companions(token,user,label,expires,vault_id,kind,workspace) VALUES(?,?,?,?,?,?,?)',(digest(token),session['user'],'Cloud extension',time.time()+30*86400,vault['id'],body.vault_kind,workspace))
            record.update(status='approved',grant=cipher.encrypt(token.encode()).decode(),user=session['user'],vault_id=vault['id'],vault_kind=body.vault_kind,workspace=workspace)
            Store.put(c,SCOPE,KIND,record)
            Store.event(c,workspace or 'personal:'+session['user'],session['user'],('team_vault.' if workspace else 'vault.')+'companion_connected',vault['id'])
            Store.event(c,session['workspace'],session['user'],'companion.token_created','encrypted-vault-only')
        return {'approved':True,'scope':'One encrypted shared vault and your encrypted sharing identity only; no general workspace or scan access.' if body.vault_kind=='shared' else 'One encrypted personal vault only; no workspace or scan access.'}

    @app.post('/api/companion/connect/{identifier}/poll')
    def poll(identifier:str,body:Proof,request:Request):
        throttle('extension-poll-ip:'+request.client.host,300)
        throttle('extension-poll:'+identifier+':'+digest(body.proof.get_secret_value()),120)
        with store.connect() as c:
            record=verified(c,identifier,body,request)
            if record['status']=='pending':return {'status':'pending'}
            token=cipher.decrypt(record['grant'].encode()).decode()
            if record.get('scope')=='security':
                grant=Store.get(c,SECURITY_SCOPE,SECURITY_KIND,digest(token))
                reject(grant and grant['expires']>time.time(),'Connection revoked. Start again.',410)
            elif record.get('scope')=='discovery':
                grant=Store.get(c,DISCOVERY_SCOPE,DISCOVERY_KIND,digest(token))
                reject(grant and grant['expires']>time.time(),'Connection revoked. Start again.',410)
            elif record.get('scope')=='reminders':
                grant=Store.get(c,REMINDER_SCOPE,REMINDER_KIND,digest(token))
                reject(grant and grant['expires']>time.time(),'Connection revoked. Start again.',410)
            elif record.get('scope')=='access':
                grant=Store.get(c,ACCESS_SCOPE,ACCESS_KIND,digest(token))
                reject(grant and grant['expires']>time.time(),'Connection revoked. Start again.',410)
            else:reject(c.execute('SELECT 1 FROM companions WHERE token=? AND expires>?',(digest(token),time.time())).fetchone(),'Connection revoked. Start again.',410)
        return {'status':'approved','token':token,'origin':settings.origin,'scope':record.get('scope','vault')}

    @app.post('/api/companion/connect/{identifier}/ack')
    def acknowledge(identifier:str,body:Proof,request:Request):
        with store.connect(write=True) as c:
            record=verified(c,identifier,body,request)
            reject(record['status']=='approved','Connection is not approved',409)
            c.execute('DELETE FROM entities WHERE id=? AND workspace=? AND kind=?',(identifier,SCOPE,KIND))
        return {'ok':True}

    @app.post('/api/companion/connect/{identifier}/cancel')
    def cancel(identifier:str,body:Proof,request:Request):
        with store.connect(write=True) as c:
            record=verified(c,identifier,body,request)
            if record['status']=='approved':
                token=cipher.decrypt(record['grant'].encode()).decode()
                if record.get('scope')=='security':
                    c.execute('DELETE FROM entities WHERE id=? AND workspace=? AND kind=?',(digest(token),SECURITY_SCOPE,SECURITY_KIND))
                    Store.event(c,record['workspace'],record['user'],'extension.security_revoked','cancelled-handoff')
                elif record.get('scope')=='discovery':
                    c.execute('DELETE FROM entities WHERE id=? AND workspace=? AND kind=?',(digest(token),DISCOVERY_SCOPE,DISCOVERY_KIND))
                    c.execute("DELETE FROM entities WHERE workspace=? AND kind='discovery_consents' AND json_extract(data,'$.connection')=?",(record['workspace'],digest(token)))
                    Store.event(c,record['workspace'],record['user'],'extension.discovery_revoked','cancelled-handoff')
                elif record.get('scope')=='reminders':
                    c.execute('DELETE FROM entities WHERE id=? AND workspace=? AND kind=?',(digest(token),REMINDER_SCOPE,REMINDER_KIND))
                    Store.event(c,record['workspace'],record['user'],'extension.reminders_revoked','cancelled-handoff')
                elif record.get('scope')=='access':
                    c.execute('DELETE FROM entities WHERE id=? AND workspace=? AND kind=?',(digest(token),ACCESS_SCOPE,ACCESS_KIND))
                    Store.event(c,record['workspace'],record['user'],'extension.access_revoked','cancelled-handoff')
                else:
                    c.execute('DELETE FROM companions WHERE token=?',(digest(token),))
                    Store.event(c,record.get('workspace') or 'personal:'+record['user'],record['user'],'companion.authorization_cancelled',record['vault_id'])
            c.execute('DELETE FROM entities WHERE id=? AND workspace=? AND kind=?',(identifier,SCOPE,KIND))
        return {'ok':True}
