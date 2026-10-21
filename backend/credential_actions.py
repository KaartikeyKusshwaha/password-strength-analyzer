"""Private encrypted account-action queue. No passwords or website forms on server."""
import base64
import hashlib
import hmac
import json
import secrets
import time
from typing import Literal

from fastapi import Depends,HTTPException,Request
from pydantic import BaseModel,ConfigDict,Field,field_validator

from .store import Store,canonical,now
from .browser_access import require_connection


class Body(BaseModel):
    model_config=ConfigDict(extra='forbid')


class ActionEnvelope(Body):
    version: Literal[1]
    iv: str=Field(max_length=16)
    ciphertext: str=Field(min_length=24,max_length=28000)

    @field_validator('iv','ciphertext')
    @classmethod
    def encoded(cls,value,info):
        try: raw=base64.b64decode(value,validate=True)
        except ValueError: raise ValueError('Invalid encrypted action')
        if info.field_name=='iv' and len(raw)!=12 or info.field_name=='ciphertext' and len(raw)<16:
            raise ValueError('Invalid encrypted action')
        return value


class CreateAction(Body):
    id: str=Field(pattern=r'^[a-f0-9]{24}$')
    vault_id: str=Field(pattern=r'^[a-f0-9]{24}$')
    kind: Literal['personal','shared']
    entry_count: int=Field(ge=1,le=20)
    expires_at: int
    envelope: ActionEnvelope


class Claim(Body):
    resume: bool=False


class Result(Body):
    lease: str=Field(min_length=40,max_length=100)
    index: int=Field(ge=0,le=19)
    state: Literal['prepared','needs_attention','confirmed_by_user','discarded']
    reason: Literal['','unsupported_form','cross_origin','requires_signin','tab_closed','site_confirmation_required']=''


def require(value,message='Account action not found',status=404):
    if not value: raise HTTPException(status,message)
    return value


def register(app,store,auth,companion_auth,throttle):
    def scope(c,user,kind,vault,workspace):
        if kind=='personal':
            row=c.execute('SELECT * FROM vault_spaces WHERE user=? AND id=?',(user,vault)).fetchone()
            require(row);require(not row['archived'] and row['browser_enabled'] and row['browser_save'] and row['browser_fill'],'This vault does not permit browser changes',403)
        else:
            row=c.execute('SELECT v.*,g.role,g.accepted,m.role AS member_role FROM team_vaults v JOIN team_grants g ON g.vault=v.id JOIN members m ON m.workspace=v.workspace AND m.user=g.user WHERE g.user=? AND v.id=? AND v.workspace=?',(user,vault,workspace)).fetchone()
            require(row);policy=json.loads(row['browser_policy'])
            require(row['accepted'] and row['role'] in {'owner','admin','editor'} and row['member_role']!='viewer','Edit access to an accepted vault is required',403)
            require(policy['browser_enabled'] and policy['browser_save'] and policy['browser_fill'] and not row['rotation_required'],'Browser saving/filling must be enabled and key rotation finished',409)

    def expire(c,user):
        at=time.time()
        expired=c.execute("SELECT id,workspace,user FROM credential_actions WHERE user=? AND expires_at<=? AND status NOT IN ('complete','cancelled','expired')",(user,at)).fetchall()
        c.execute("UPDATE credential_actions SET status='expired',lease_hash=NULL,lease_connection=NULL,lease_expires=NULL WHERE user=? AND expires_at<=? AND status NOT IN ('complete','cancelled','expired')",(user,at))
        for row in expired:
            Store.event(c,row['workspace'] or 'personal:'+row['user'],'system:expiry','credential_action.expired',row['id'])
        interrupted=c.execute("SELECT id,workspace,user FROM credential_actions WHERE user=? AND lease_expires<=? AND status IN ('running','awaiting_confirmation')",(user,at)).fetchall()
        c.execute("UPDATE credential_actions SET status='interrupted',lease_hash=NULL,lease_connection=NULL,lease_expires=NULL WHERE user=? AND lease_expires<=? AND status IN ('running','awaiting_confirmation')",(user,at))
        for row in interrupted:
            Store.event(c,row['workspace'] or 'personal:'+row['user'],'system:expiry','credential_action.interrupted',row['id'])

    def public(row):
        return {k:json.loads(row[k]) if k in {'manifest','items'} else row[k] for k in ('id','user','vault_id','kind','workspace','manifest','entry_count','status','items','created_at','expires_at')}

    def session_job(c,session,identifier):
        row=require(c.execute('SELECT * FROM credential_actions WHERE id=? AND user=?',(identifier,session['user'])).fetchone())
        require(row['kind']=='personal' or row['workspace']==session['workspace'])
        return row

    def browser_job(c,connection,identifier):
        require_connection(c,connection)
        row=require(c.execute('SELECT * FROM credential_actions WHERE id=? AND user=? AND vault_id=? AND kind=?',(identifier,connection['user'],connection['vault_id'],connection['kind'])).fetchone())
        require(row['kind']=='personal' or row['workspace']==connection['workspace'])
        scope(c,connection['user'],connection['kind'],connection['vault_id'],connection['workspace'])
        return row

    @app.get('/api/account-actions')
    def list_actions(session=Depends(auth)):
        with store.connect(write=True) as c:
            expire(c,session['user'])
            return {'actions':[public(row) for row in c.execute("SELECT * FROM credential_actions WHERE user=? AND (kind='personal' OR workspace=?) ORDER BY created_at DESC LIMIT 100",(session['user'],session['workspace']))]}

    def enqueue(body,session,connection=None):
        throttle('account-actions:'+session['user'],20)
        require(time.time()+60<=body.expires_at<=time.time()+3600,'Approve an action that expires within one hour',422)
        with store.connect(write=True) as c:
            if connection:require_connection(c,connection)
            scope(c,session['user'],body.kind,body.vault_id,session['workspace'])
            require(not c.execute('SELECT 1 FROM credential_actions WHERE id=?',(body.id,)).fetchone(),'Action id already exists',409)
            expire(c,session['user'])
            require(c.execute("SELECT count(*) FROM credential_actions WHERE user=? AND status NOT IN ('complete','cancelled','expired')",(session['user'],)).fetchone()[0]<10,'Finish or cancel existing account actions first',409)
            items=[{'state':'queued','reason':''} for _ in range(body.entry_count)]
            c.execute('INSERT INTO credential_actions VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)',(body.id,session['user'],body.vault_id,body.kind,session['workspace'] if body.kind=='shared' else None,canonical(body.envelope.model_dump()),body.entry_count,'queued',canonical(items),None,None,None,now(),body.expires_at))
            Store.event(c,session['workspace'] if body.kind=='shared' else 'personal:'+session['user'],session['user'],'credential_action.approved',body.id)
        return {'id':body.id,'status':'queued'}

    @app.post('/api/account-actions')
    def create_action(body:CreateAction,session=Depends(auth)):
        return enqueue(body,session)

    @app.post('/api/account-actions/{identifier}/cancel')
    def cancel_action(identifier: str,session=Depends(auth)):
        with store.connect(write=True) as c:
            row=session_job(c,session,identifier)
            require(row['status'] not in {'complete','cancelled','expired'},'This action has already stopped',409)
            c.execute("UPDATE credential_actions SET status='cancelled',lease_hash=NULL,lease_connection=NULL,lease_expires=NULL WHERE id=?",(identifier,))
            Store.event(c,row['workspace'] or 'personal:'+session['user'],session['user'],'credential_action.cancelled',identifier)
        return {'ok':True,'note':'Existing logins are retained. Discard staged passwords only if they were not used on the website.'}

    @app.get('/api/companion/actions')
    def browser_actions(request: Request):
        connection=companion_auth(request)
        with store.connect(write=True) as c:
            require_connection(c,connection)
            expire(c,connection['user']);scope(c,connection['user'],connection['kind'],connection['vault_id'],connection['workspace'])
            return {'actions':[public(row) for row in c.execute('SELECT * FROM credential_actions WHERE user=? AND kind=? AND vault_id=? ORDER BY created_at DESC LIMIT 50',(connection['user'],connection['kind'],connection['vault_id']))]}

    @app.get('/api/companion/actions/context')
    def browser_action_context(request:Request):
        connection=companion_auth(request)
        with store.connect() as c:
            require_connection(c,connection);scope(c,connection['user'],connection['kind'],connection['vault_id'],connection['workspace'])
        return {'actor':connection['user'],'vault_id':connection['vault_id'],'kind':connection['kind']}

    @app.post('/api/companion/actions')
    def browser_create_action(body:CreateAction,request:Request):
        connection=companion_auth(request)
        require(body.vault_id==connection['vault_id'] and body.kind==connection['kind'],'Approval belongs to a different vault',403)
        with store.connect() as c:require_connection(c,connection)
        # The same deterministic queue/policy checks as the signed-in control room.
        return enqueue(body,{'user':connection['user'],'workspace':connection['workspace']},connection)

    @app.post('/api/companion/actions/{identifier}/claim')
    def claim_action(identifier: str,body: Claim,request: Request):
        connection=companion_auth(request);throttle('account-claim:'+connection['user'],60)
        with store.connect(write=True) as c:
            expire(c,connection['user']);row=browser_job(c,connection,identifier)
            require(row['status']=='queued' or body.resume and row['status']=='interrupted','This action is active, stopped, or requires explicit resume',409)
            lease=secrets.token_urlsafe(40)
            c.execute("UPDATE credential_actions SET status='running',lease_hash=?,lease_connection=?,lease_expires=? WHERE id=?",(hashlib.sha256(lease.encode()).hexdigest(),connection['token'],min(row['expires_at'],time.time()+300),identifier))
            Store.event(c,row['workspace'] or 'personal:'+row['user'],row['user'],'credential_action.resumed' if row['status']=='interrupted' else 'credential_action.claimed',identifier)
        return {'lease':lease,'action':{**public(row),'status':'running'}}

    @app.post('/api/companion/actions/{identifier}/cancel')
    def browser_cancel_action(identifier:str,request:Request):
        connection=companion_auth(request)
        with store.connect(write=True) as c:
            expire(c,connection['user']);row=browser_job(c,connection,identifier)
            require(row['status'] not in {'complete','cancelled','expired'},'This action has already stopped',409)
            c.execute("UPDATE credential_actions SET status='cancelled',lease_hash=NULL,lease_connection=NULL,lease_expires=NULL WHERE id=?",(identifier,))
            Store.event(c,row['workspace'] or 'personal:'+row['user'],row['user'],'credential_action.cancelled',identifier)
        return {'ok':True,'note':'Plan stopped. Staged proposals remain encrypted; retain them if a website may already use one.'}

    @app.post('/api/companion/actions/{identifier}/result')
    def action_result(identifier: str,body: Result,request: Request):
        connection=companion_auth(request)
        with store.connect(write=True) as c:
            expire(c,connection['user']);row=browser_job(c,connection,identifier)
            require(row['status'] in {'running','awaiting_confirmation'} and row['lease_connection']==connection['token'] and hmac.compare_digest(row['lease_hash'] or '',hashlib.sha256(body.lease.encode()).hexdigest()),'Action lease expired or belongs to another browser',409)
            require(body.index<row['entry_count'],'Invalid action item',422)
            items=json.loads(row['items']);previous=items[body.index]['state']
            require(previous not in {'confirmed_by_user','discarded'} or previous==body.state,'This action item has already stopped',409)
            require(body.state not in {'confirmed_by_user','discarded'} or previous in {'prepared','needs_attention',body.state},'Prepare the change before recording its outcome',409)
            items[body.index]={'state':body.state,'reason':body.reason,'at':now()}
            state='complete' if all(i['state'] in {'confirmed_by_user','discarded'} for i in items) else 'running' if any(i['state']=='queued' for i in items) else 'awaiting_confirmation'
            c.execute('UPDATE credential_actions SET items=?,status=?,lease_expires=? WHERE id=?',(canonical(items),state,min(row['expires_at'],time.time()+300),identifier))
            Store.event(c,row['workspace'] or 'personal:'+row['user'],row['user'],'credential_action.'+body.state,identifier+':'+str(body.index))
        return {'status':state,'items':items,'verification':'User confirmation is not independent website verification.'}
