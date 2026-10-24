"""Owner-reported shared login debt linked to the existing encrypted operator."""
import json
import time
from typing import Literal
from fastapi import Depends,HTTPException
from pydantic import BaseModel,ConfigDict,Field
from .access_records import Record
from .store import Store,now,uid

def require(value,message,status=409):
    if not value:raise HTTPException(status,message)
    return value

class Create(Record):
    vault_id:str=Field(pattern=r'^[a-f0-9]{24}$')
    entry_ref:str=Field(pattern=r'^[a-f0-9]{64}$')
    platform:Literal['other','google_business','linkedin_pages','tiktok_business','shopify','wordpress','github','slack','meta']='other'
class Item(BaseModel):
    model_config=ConfigDict(extra='forbid')
    exposure_id:str=Field(pattern=r'^[a-f0-9]{24}$')
    index:int=Field(ge=0,le=19)
class Bind(BaseModel):
    model_config=ConfigDict(extra='forbid')
    action_id:str=Field(pattern=r'^[a-f0-9]{24}$')
    items:list[Item]=Field(min_length=1,max_length=20)
class Confirm(BaseModel):
    model_config=ConfigDict(extra='forbid')
    confirmed:bool=False
    delegated_access_confirmed:bool=False
    shared_login_retired:bool=False

def snapshot(c,workspace,client):
    active=c.execute("SELECT count(*) FROM credential_exposures WHERE workspace=? AND client=? AND state!='retired'",(workspace,client)).fetchone()[0]
    prior=[item['active'] for item in Store.all(c,workspace,'debt_snapshots') if item['client']==client]
    return {'active':active,'peak':max([active]+prior)}
def checkpoint(c,workspace,client):
    current=snapshot(c,workspace,client)
    Store.put(c,workspace,'debt_snapshots',dict(id=uid(),client=client,at=now(),**current))
def listing(c,workspace):
    rows=[dict(row) for row in c.execute('SELECT e.*,a.status AS action_status FROM credential_exposures e LEFT JOIN credential_actions a ON a.id=e.action_id WHERE e.workspace=? ORDER BY e.created_at,e.id',(workspace,))]
    return {'exposures':rows,'counts':{client['id']:snapshot(c,workspace,client['id']) for client in c.execute('SELECT id FROM clients WHERE workspace=?',(workspace,))},'verification':'Rotation and delegated-access checks are owner confirmations, not independent verification of an external service.'}
def update_from_action(c,action,index,state):
    if action['kind']!='shared':return
    for row in c.execute("SELECT * FROM credential_exposures WHERE workspace=? AND action_id=? AND action_index=? AND state!='retired'",(action['workspace'],action['id'],index)).fetchall():
        next_state='rotated' if state=='confirmed_by_user' else 'needed' if state=='discarded' else 'staged'
        if row['state']=='verified' and state=='confirmed_by_user':continue
        if row['state']==next_state:continue
        c.execute('UPDATE credential_exposures SET state=?,verified_at=NULL,updated_at=? WHERE id=?',(next_state,now(),row['id']))
        Store.event(c,row['workspace'],action['user'],'credential_debt.'+next_state,row['id'])

def register(app,store,auth,access_auth,throttle):
    def owner(c,session):
        require(c.execute("SELECT 1 FROM members WHERE workspace=? AND user=? AND role='owner'",(session['workspace'],session['user'])).fetchone(),'Workspace owner access required',403)
        if session.get('id'):
            from .extension_connect import ACCESS_SCOPE,ACCESS_KIND
            grant=Store.get(c,ACCESS_SCOPE,ACCESS_KIND,session['id'])
            require(grant and grant['expires']>time.time(),'Workflow connection expired or revoked',401)
            require(c.execute('SELECT mfa FROM users WHERE id=?',(session['user'],)).fetchone()['mfa'],'Owner MFA required',403)
    def writable(c,session,row):
        owner(c,session)
        require(c.execute('SELECT 1 FROM team_vaults v JOIN client_vaults l ON l.vault=v.id AND l.workspace=v.workspace WHERE v.id=? AND v.workspace=? AND v.owner=? AND l.client=?',(row['vault'],session['workspace'],session['user'],row['client'])).fetchone(),'A current client link and vault ownership are required',403)
    def get(c,session,identifier):return require(c.execute('SELECT * FROM credential_exposures WHERE id=? AND workspace=?',(identifier,session['workspace'])).fetchone(),'Shared login record not found',404)

    @app.get('/api/clients/debt')
    def history(session=Depends(auth)):
        with store.connect() as c:owner(c,session);return listing(c,session['workspace'])
    @app.get('/api/companion/access/debt')
    def read(session=Depends(access_auth)):
        with store.connect() as c:owner(c,session);return listing(c,session['workspace'])
    @app.post('/api/companion/access/debt')
    def create(body:Create,session=Depends(access_auth)):
        throttle('debt-create:'+session['workspace'],60)
        with store.connect(write=True) as c:
            writable(c,session,{'vault':body.vault_id,'client':body.client_id})
            row=c.execute('SELECT * FROM credential_exposures WHERE workspace=? AND client=? AND vault=? AND entry_ref=?',(session['workspace'],body.client_id,body.vault_id,body.entry_ref)).fetchone()
            if row:return {'id':row['id'],'state':row['state'],'created':False}
            require(c.execute('SELECT count(*) FROM credential_exposures WHERE workspace=?',(session['workspace'],)).fetchone()[0]<1000,'Shared login record limit reached')
            identifier=uid();at=now()
            c.execute('INSERT INTO credential_exposures VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)',(identifier,session['workspace'],body.client_id,body.vault_id,body.entry_ref,body.domain,body.account_label,body.platform,'needed',None,None,session['user'],at,at,None,None))
            Store.event(c,session['workspace'],session['user'],'credential_debt.recorded',identifier);checkpoint(c,session['workspace'],body.client_id)
        return {'id':identifier,'state':'needed','created':True}
    @app.post('/api/companion/access/debt/bind')
    def bind(body:Bind,session=Depends(access_auth)):
        with store.connect(write=True) as c:
            owner(c,session)
            action=require(c.execute("SELECT * FROM credential_actions WHERE id=? AND user=? AND workspace=? AND kind='shared'",(body.action_id,session['user'],session['workspace'])).fetchone(),'Matching encrypted action required',404)
            require(len(body.items)==action['entry_count'] and {item.index for item in body.items}==set(range(action['entry_count'])) and len({item.exposure_id for item in body.items})==len(body.items),'Bind exactly the distinct approved action items')
            require(action['expires_at']>time.time() and action['status'] not in {'cancelled','expired','interrupted'},'Action is no longer available')
            for item in body.items:
                row=get(c,session,item.exposure_id);writable(c,session,row)
                require(row['vault']==action['vault_id'] and row['state']!='retired','Wrong vault or retired debt')
                if row['action_id']==action['id']:
                    require(row['action_index']==item.index,'An existing binding cannot change its index');continue
                if row['action_id']:
                    old=c.execute('SELECT status FROM credential_actions WHERE id=?',(row['action_id'],)).fetchone()
                    require(not old or old['status'] in {'complete','cancelled','expired'},'Finish or cancel the earlier operator plan')
                c.execute("UPDATE credential_exposures SET action_id=?,action_index=?,state='needed',verified_at=NULL,updated_at=? WHERE id=?",(action['id'],item.index,now(),row['id']))
                Store.event(c,session['workspace'],session['user'],'credential_debt.action_bound',row['id'])
            for index,item in enumerate(json.loads(action['items'])):
                if item['state']!='queued':update_from_action(c,action,index,item['state'])
        return {'ok':True}
    @app.post('/api/companion/access/debt/{identifier}/verify')
    def verify(identifier:str,body:Confirm,session=Depends(access_auth)):
        with store.connect(write=True) as c:
            row=get(c,session,identifier);writable(c,session,row)
            require(body.confirmed and row['state'] in {'rotated','verified'},'Confirm a completed rotation after testing the new login yourself')
            if row['state']!='verified':
                c.execute("UPDATE credential_exposures SET state='verified',verified_at=?,updated_at=? WHERE id=?",(now(),now(),identifier));Store.event(c,session['workspace'],session['user'],'credential_debt.verified_by_owner',identifier)
        return {'ok':True,'verification':'Owner confirmation only; no independent website verification.'}
    @app.post('/api/companion/access/debt/{identifier}/retire')
    def retire(identifier:str,body:Confirm,session=Depends(access_auth)):
        with store.connect(write=True) as c:
            row=get(c,session,identifier);writable(c,session,row)
            require(body.confirmed and body.delegated_access_confirmed and body.shared_login_retired,'Confirm working delegated access and retirement of the shared login')
            require(row['state'] in {'verified','retired'},'Verify the replacement before retiring shared-login debt')
            if row['state']!='retired':
                c.execute("UPDATE credential_exposures SET state='retired',retired_at=?,updated_at=? WHERE id=?",(now(),now(),identifier));Store.event(c,session['workspace'],session['user'],'credential_debt.retired_by_owner',identifier);checkpoint(c,session['workspace'],row['client'])
        return {'ok':True,'verification':'Owner-confirmed retirement; no external permissions were changed by this request.'}

    @app.post('/api/companion/access/debt/{identifier}/reopen')
    def reopen(identifier:str,body:Confirm,session=Depends(access_auth)):
        throttle('debt-reopen:'+session['workspace'],60)
        with store.connect(write=True) as c:
            row=get(c,session,identifier);writable(c,session,row)
            require(body.confirmed and (row['state']=='retired' or row['state']=='needed' and not row['action_id']),'Only retired debt can be reopened; active rotation plans must be resolved separately')
            if row['state']=='retired':
                c.execute("UPDATE credential_exposures SET state='needed',action_id=NULL,action_index=NULL,verified_at=NULL,retired_at=NULL,updated_at=? WHERE id=?",(now(),identifier))
                Store.event(c,session['workspace'],session['user'],'credential_debt.reopened_by_owner',identifier);checkpoint(c,session['workspace'],row['client'])
        return {'ok':True,'note':'Shared login reported in use again. No external access was changed.'}
