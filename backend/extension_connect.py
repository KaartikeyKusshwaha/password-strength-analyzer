"""Short-lived browser authorization; grants one encrypted personal vault only."""
import hmac
import re
import secrets
import time

from fastapi import Depends, HTTPException, Request
from pydantic import BaseModel, Field, SecretStr, ConfigDict
from .security import digest
from .store import Store, uid

SCOPE='system:extension-connect'
KIND='extension_connect'

class Proof(BaseModel):
    model_config=ConfigDict(extra='forbid')
    proof: SecretStr = Field(min_length=43,max_length=100)

class Approval(BaseModel):
    model_config=ConfigDict(extra='forbid')
    vault_id: str = Field(pattern=r'^[a-f0-9]{24}$')
    confirmed_code: str = Field(pattern=r'^\d{6}$')

def register(app,store,auth,throttle,cipher,settings):
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
            record=dict(id=uid(),origin=origin,proof_hash=digest(body.proof.get_secret_value()),code=f'{secrets.randbelow(1000000):06d}',expires=time.time()+300,status='pending')
            Store.put(c,SCOPE,KIND,record)
        return {'id':record['id'],'code':record['code'],'expires':record['expires'],'approval_url':settings.origin+'/#connect='+record['id']}

    @app.get('/api/extension-connect/{identifier}')
    def details(identifier:str,session=Depends(auth)):
        with store.connect() as c:record=lookup(c,identifier)
        return {key:record[key] for key in ('id','origin','code','expires','status')}

    @app.post('/api/extension-connect/{identifier}/approve')
    def approve(identifier:str,body:Approval,session=Depends(auth)):
        throttle('extension-approve:'+session['user'],20)
        with store.connect(write=True) as c:
            record=lookup(c,identifier)
            reject(record['status']=='pending','This request was already decided',409)
            reject(hmac.compare_digest(body.confirmed_code,record['code']),'Connection code does not match')
            vault=c.execute('SELECT * FROM vault_spaces WHERE id=? AND user=?',(body.vault_id,session['user'])).fetchone()
            reject(vault and not vault['archived'] and vault['browser_enabled'] and vault['payload']!='null','Choose your initialized browser-enabled vault',409)
            token=secrets.token_urlsafe(40)
            c.execute('INSERT INTO companions(token,user,label,expires,vault_id,kind,workspace) VALUES(?,?,?,?,?,?,?)',(digest(token),session['user'],'Cloud extension',time.time()+30*86400,vault['id'],'personal',None))
            record.update(status='approved',grant=cipher.encrypt(token.encode()).decode(),user=session['user'],vault_id=vault['id'])
            Store.put(c,SCOPE,KIND,record)
            Store.event(c,'personal:'+session['user'],session['user'],'vault.companion_connected',vault['id'])
            Store.event(c,session['workspace'],session['user'],'companion.token_created','encrypted-vault-only')
        return {'approved':True,'scope':'One encrypted personal vault only; no workspace or scan access.'}

    @app.post('/api/companion/connect/{identifier}/poll')
    def poll(identifier:str,body:Proof,request:Request):
        throttle('extension-poll-ip:'+request.client.host,300)
        throttle('extension-poll:'+identifier+':'+digest(body.proof.get_secret_value()),120)
        with store.connect() as c:
            record=verified(c,identifier,body,request)
            if record['status']=='pending':return {'status':'pending'}
            token=cipher.decrypt(record['grant'].encode()).decode()
            reject(c.execute('SELECT 1 FROM companions WHERE token=? AND expires>?',(digest(token),time.time())).fetchone(),'Connection revoked. Start again.',410)
        return {'status':'approved','token':token,'origin':settings.origin}

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
                c.execute('DELETE FROM companions WHERE token=?',(digest(token),))
                Store.event(c,'personal:'+record['user'],record['user'],'companion.authorization_cancelled',record['vault_id'])
            c.execute('DELETE FROM entities WHERE id=? AND workspace=? AND kind=?',(identifier,SCOPE,KIND))
        return {'ok':True}
