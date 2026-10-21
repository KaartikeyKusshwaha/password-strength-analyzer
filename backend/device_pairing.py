"""Proof-bound helper handoff. Short codes identify a request, not a device token."""
import hmac
import re
import secrets
import time
from fastapi import Depends, HTTPException, Request
from pydantic import BaseModel, ConfigDict, Field, SecretStr
from .security import digest, verify_password, consume_factor
from .store import Store, uid, canonical, now

SCOPE='system:device-pairing'
KIND='device_pairing'
ALPHABET='ABCDEFGHJKLMNPQRSTUVWXYZ23456789'

class Proof(BaseModel):
    model_config=ConfigDict(extra='forbid')
    proof: SecretStr = Field(min_length=43,max_length=100)

class Start(Proof):
    label: str = Field(min_length=2,max_length=60,pattern=r'^[\w .()-]+$')
    allow_posture: bool = False
    allow_updates: bool = False

class Code(BaseModel):
    model_config=ConfigDict(extra='forbid')
    pairing_code: str = Field(pattern=r'^[A-HJ-NP-Z2-9]{8}$')

class Approve(Code):
    password: SecretStr = Field(min_length=1,max_length=128)
    code: str = Field(default='',max_length=128)
    allow_posture: bool
    allow_updates: bool

def register(app,store,settings,cipher,throttle,security_auth):
    def require(condition,message,status=403):
        if not condition:raise HTTPException(status,message)
    def available(c,identifier):
        require(re.fullmatch(r'[a-f0-9]{24}',identifier),'Pairing unavailable',404)
        record=Store.get(c,SCOPE,KIND,identifier)
        require(record and record['expires']>time.time(),'Pairing expired. Request a new code in the helper.',410)
        return record
    def proof_record(c,identifier,body):
        record=available(c,identifier)
        require(hmac.compare_digest(record['proof_hash'],digest(body.proof.get_secret_value())),'Pairing proof rejected')
        return record
    def code_record(c,body,session):
        grant=Store.get(c,'system:extension-security','security_connection',session['id'])
        require(grant and grant.get('device_pairing') is True and grant['expires']>time.time(),'Reconnect security agents and approve device pairing first')
        member=c.execute('SELECT role FROM members WHERE user=? AND workspace=?',(session['user'],session['workspace'])).fetchone()
        require(member and member['role'] in {'owner','analyst','reviewer'},'Assessment permission removed')
        rows=[r for r in Store.all(c,SCOPE,KIND) if r['code_hash']==digest(body.pairing_code) and r['expires']>time.time() and r['status']=='pending']
        require(len(rows)==1,'Pairing code unavailable',404)
        return rows[0]

    @app.post('/api/device-pairing/start')
    def start(body:Start,request:Request):
        throttle('helper-start:'+request.client.host,10)
        with store.connect(write=True) as c:
            for old in Store.all(c,SCOPE,KIND):
                if old['expires']<=time.time():c.execute('DELETE FROM entities WHERE id=? AND workspace=? AND kind=?',(old['id'],SCOPE,KIND))
            records=Store.all(c,SCOPE,KIND)
            require(len(records)<100,'Too many pending helpers',429)
            for _ in range(10):
                code=''.join(secrets.choice(ALPHABET) for _ in range(8))
                if all(r['code_hash']!=digest(code) for r in records):break
            else:raise HTTPException(503,'Try again later')
            record=dict(id=uid(),proof_hash=digest(body.proof.get_secret_value()),code_hash=digest(code),label=body.label,allow_posture=body.allow_posture,allow_updates=body.allow_updates,expires=time.time()+300,status='pending')
            Store.put(c,SCOPE,KIND,record)
        return {'id':record['id'],'pairing_code':code,'expires':record['expires'],'server':settings.origin}

    @app.post('/api/device-pairing/{identifier}/poll')
    def poll(identifier:str,body:Proof,request:Request):
        throttle('helper-poll:'+request.client.host,240)
        with store.connect() as c:
            record=proof_record(c,identifier,body)
            if record['status']=='pending':return {'status':'pending'}
            device=c.execute("SELECT d.* FROM devices d JOIN members m ON m.workspace=d.workspace AND m.user=d.user WHERE d.id=? AND d.expires>? AND m.role!='viewer'",(record['device_id'],time.time())).fetchone()
            require(device,'Device access removed',410)
            token=cipher.decrypt(record['grant'].encode()).decode()
        return {'status':'approved','connection':{'server':settings.origin,'token':token,'allowed_targets':['127.0.0.1','::1'],'allow_posture':record['allow_posture'],'allow_updates':record['allow_updates'],'id':record['device_id']}}

    @app.post('/api/device-pairing/{identifier}/ack')
    def ack(identifier:str,body:Proof):
        with store.connect(write=True) as c:
            record=proof_record(c,identifier,body)
            require(record['status']=='approved','Pairing not approved',409)
            c.execute('DELETE FROM entities WHERE id=? AND workspace=? AND kind=?',(identifier,SCOPE,KIND))
        return {'ok':True}

    @app.post('/api/device-pairing/{identifier}/cancel')
    def cancel(identifier:str,body:Proof):
        with store.connect(write=True) as c:
            record=proof_record(c,identifier,body)
            if record.get('device_id'):
                c.execute('DELETE FROM devices WHERE id=?',(record['device_id'],))
                for operation in Store.all(c,record['workspace'],'operations'):
                    if operation.get('device_id')==record['device_id'] and operation['status'] in {'queued','running'}:
                        operation.update(status='interrupted',error='Device pairing cancelled.',finished_at=now())
                        operation.pop('lease',None);Store.put(c,record['workspace'],'operations',operation)
                Store.event(c,record['workspace'],record['user'],'device.revoked',record['device_id'])
            c.execute('DELETE FROM entities WHERE id=? AND workspace=? AND kind=?',(identifier,SCOPE,KIND))
        return {'ok':True}

    @app.post('/api/companion/security/device-pairing/details')
    def details(body:Code,session=Depends(security_auth)):
        throttle('helper-code:'+session['user'],20)
        with store.connect() as c:record=code_record(c,body,session)
        return {**{key:record[key] for key in ('label','allow_posture','allow_updates','expires')},'allowed_targets':['127.0.0.1','::1']}

    @app.post('/api/companion/security/device-pairing/approve')
    def approve(body:Approve,session=Depends(security_auth)):
        # Throttle failed reauthentication as well as successful requests.
        throttle('helper-approve:'+session['user'],10)
        with store.connect(write=True) as c:
            record=code_record(c,body,session)
            require(body.allow_posture==record['allow_posture'] and body.allow_updates==record['allow_updates'],'Helper scope changed. Review the current request again.',409)
            user=c.execute('SELECT * FROM users WHERE id=?',(session['user'],)).fetchone()
            require(verify_password(body.password.get_secret_value(),user['password']),'Current sign-in password required',401)
            if user['mfa']:require(consume_factor(c,user,body.code,cipher),'Unused authenticator/recovery code required',401)
            require(c.execute('SELECT count(*) FROM devices WHERE workspace=? AND expires>?',(session['workspace'],time.time())).fetchone()[0]<20,'Device connection limit reached',409)
            identifier,token=uid(),secrets.token_urlsafe(40)
            c.execute('INSERT INTO devices(id,token,workspace,user,label,targets,expires,seen,allow_posture,allow_updates) VALUES(?,?,?,?,?,?,?,NULL,?,?)',(identifier,digest(token),session['workspace'],session['user'],record['label'],canonical(['127.0.0.1','::1']),time.time()+30*86400,int(record['allow_posture']),int(record['allow_updates'])))
            record.update(status='approved',device_id=identifier,user=session['user'],workspace=session['workspace'],grant=cipher.encrypt(token.encode()).decode())
            Store.put(c,SCOPE,KIND,record)
            Store.event(c,session['workspace'],session['user'],'device.connected',identifier)
        return {'id':identifier,'label':record['label'],'expires_days':30}
