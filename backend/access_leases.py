"""Bounded expiry policies; effects run only through the existing access runner."""
import hashlib
import json
import time
from typing import Literal
from fastapi import Depends,HTTPException
from pydantic import BaseModel,ConfigDict,Field
from .access_workflows import Approval,digest,owner,prepare,require
from .security import consume_factor,verify_password
from .store import Store,canonical,now,uid

KIND='access_leases'
TERMINAL={'complete','cancelled','blocked'}
LIMITS='Selected SentinelOps vault memberships only. No external accounts or cached copies are removed. Server access expires automatically under the stored approval; encryption-key rotation still needs local unlock. An initial membership or invitation must already exist; this policy does not issue a sharing key.'


class Request(BaseModel):
    model_config=ConfigDict(extra='forbid')
    client_id:str=Field(pattern=r'^[a-f0-9]{24}$')
    person_id:str=Field(pattern=r'^[a-f0-9]{24}$')
    expires_at:int
    mode:Literal['auto_revoke','scheduled_departure']='auto_revoke'


def initial_scope(c,workspace,client,person,actor):
    from .access_workflows import scope
    snapshots=scope(c,workspace,client,person,actor)
    values=[]
    for item in snapshots:
        grant=c.execute('SELECT envelope,accepted,role FROM team_grants WHERE vault=? AND user=?',(item['vault'],person)).fetchone()
        require(grant and grant['role']!='owner','Invite or grant non-owner membership before scheduling expiry.')
        envelope=json.loads(grant['envelope'])
        values.append({'vault':item['vault'],'recipient_fingerprint':envelope['recipient_fingerprint'],'role_at_plan':grant['role']})
    return values


def current_scope(c,workspace,record):
    """No broadening: inspect only the policy's original vaults and identity."""
    plan=record['plan'];actor=record['created_by'];snapshots=[]
    require(c.execute('SELECT 1 FROM clients WHERE id=? AND workspace=?',(plan['client'],workspace)).fetchone(),'Client unavailable.')
    target=c.execute('SELECT role FROM members WHERE workspace=? AND user=?',(workspace,plan['person'])).fetchone()
    require(not target or target['role']!='owner','Workspace owners cannot be expired by a policy.')
    identity=c.execute('SELECT fingerprint FROM sharing_identities WHERE user=?',(plan['person'],)).fetchone()
    for item in plan['vaults']:
        vault=c.execute('SELECT owner,epoch,revision,rotation_required FROM team_vaults WHERE id=? AND workspace=?',(item['vault'],workspace)).fetchone()
        linked=c.execute('SELECT 1 FROM client_vaults WHERE workspace=? AND client=? AND vault=?',(workspace,plan['client'],item['vault'])).fetchone()
        require(vault and vault['owner']==actor and linked,'Vault ownership or client link changed.')
        grant=c.execute('SELECT envelope,role FROM team_grants WHERE vault=? AND user=?',(item['vault'],plan['person'])).fetchone()
        if grant:
            value=json.loads(grant['envelope'])
            require(target and identity and identity['fingerprint']==item['recipient_fingerprint']==value['recipient_fingerprint'] and grant['role']!='owner','Recipient identity or protected role changed.')
        snapshots.append({'vault':item['vault'],'epoch':vault['epoch'],'revision':vault['revision'],'grant_digest':hashlib.sha256(grant['envelope'].encode()).hexdigest() if grant else hashlib.sha256(b'').hexdigest(),'absent_at_plan':not grant and not vault['rotation_required']})
    return snapshots


def valid_approval(record,at):
    approval=record.get('approval');plan=record['plan']
    return bool(plan.get('version')==1 and record['mode']==plan['mode'] and approval and approval.get('actor')==record['created_by'] and approval.get('digest')==record['plan_digest']==digest(plan) and approval.get('execute_before',0)>at and approval.get('expires_at')==plan['expires_at'])


def authorized_workflow(c,row,plan,approval,at):
    source=plan.get('source',{});record=Store.get(c,row['workspace'],KIND,source.get('id',''))
    if not record or record['mode']!='auto_revoke' or record['status'] not in {'executing','waiting_unlock'} or record.get('workflow')!=row['id'] or not valid_approval(record,at):return False
    bound=record['plan']
    if not (bound['expires_at']<=at and source.get('digest')==record['plan_digest'] and approval.get('lease_id')==record['id'] and approval.get('expires')==record['approval']['execute_before'] and row['created_by']==record['created_by'] and plan['client']==bound['client'] and plan['person']==bound['person'] and {item['vault'] for item in plan['vaults']}=={item['vault'] for item in bound['vaults']}):return False
    # A re-invited/different identity cannot be removed using an older approval.
    for item in bound['vaults']:
        grant=c.execute('SELECT envelope,role FROM team_grants WHERE vault=? AND user=?',(item['vault'],bound['person'])).fetchone()
        if grant and (grant['role']=='owner' or json.loads(grant['envelope'])['recipient_fingerprint']!=item['recipient_fingerprint']):return False
    return True


def display(c,workspace,record):
    client=c.execute('SELECT name FROM clients WHERE workspace=? AND id=?',(workspace,record['client'])).fetchone()
    person=c.execute('SELECT email FROM users WHERE id=?',(record['person'],)).fetchone()
    value={**record,'limitations':LIMITS,'client_name':client['name'] if client else None,'person_email':person['email'] if person else None}
    bound={item['vault'] for item in record['plan']['vaults']}
    value['uncovered_vaults']=[row['vault'] for row in c.execute('SELECT l.vault FROM client_vaults l JOIN team_grants g ON g.vault=l.vault AND g.user=? WHERE l.workspace=? AND l.client=? ORDER BY l.vault',(record['person'],workspace,record['client'])) if row['vault'] not in bound]
    if record.get('workflow'):
        row=c.execute('SELECT status FROM workflows WHERE workspace=? AND id=?',(workspace,record['workflow'])).fetchone()
        value['workflow_status']=row['status'] if row else 'unavailable'
    return value


def cancel(c,workspace,record,actor,reason='owner_cancelled'):
    record.update(status='cancelled',approval=None,updated_at=now(),reason=reason)
    Store.put(c,workspace,KIND,record)
    if record.get('workflow'):
        row=c.execute('SELECT status FROM workflows WHERE workspace=? AND id=?',(workspace,record['workflow'])).fetchone()
        if row and row['status'] not in {'complete','dry_run_complete','cancelled'}:
            c.execute("UPDATE workflows SET status='cancelled',approval=NULL,updated_at=? WHERE id=?",(now(),record['workflow']))
            c.execute("UPDATE workflow_steps SET status='cancelled' WHERE workflow=? AND status='pending'",(record['workflow'],))
            Store.event(c,workspace,actor,'access_workflow.cancelled',record['workflow'])
    Store.event(c,workspace,actor,'access_lease.cancelled',record['id'])


def tick(store,clock=time.time):
    # Called by the existing scheduler. Parent and derived plan commit together.
    with store.connect(write=True) as c:
        rows=c.execute("SELECT workspace,data FROM entities WHERE kind=? AND json_extract(data,'$.status') IN ('active','executing','waiting_unlock','ready_for_approval') ORDER BY COALESCE(json_extract(data,'$.last_checked'),0),rowid LIMIT 100",(KIND,)).fetchall()
        for saved in rows:
            workspace=saved['workspace'];record=json.loads(saved['data']);at=clock();record['last_checked']=at;plan=record['plan'];actor=owner(c,workspace,record['created_by'])
            if record['status']!='active':
                work=c.execute('SELECT status FROM workflows WHERE workspace=? AND id=?',(workspace,record.get('workflow'))).fetchone()
                state=work['status'] if work else 'unavailable'
                mapped='complete' if state=='complete' else 'waiting_unlock' if state=='waiting_unlock' else 'blocked' if state in {'blocked','cancelled','unavailable'} else 'ready_for_approval' if state=='awaiting_approval' else 'executing'
                if mapped!=record['status']:
                    record.update(status=mapped,updated_at=now());Store.put(c,workspace,KIND,record);Store.event(c,workspace,'system:access-expiry','access_lease.'+mapped,record['id'])
                Store.put(c,workspace,KIND,record)
                continue
            if not actor or not actor['mfa'] or not valid_approval(record,at):
                record.update(status='blocked',reason='Approval expired or preparing owner/MFA authority lost.',updated_at=now());Store.put(c,workspace,KIND,record);Store.event(c,workspace,'system:access-expiry','access_lease.blocked',record['id']);continue
            if at>=plan['remind_at'] and not record['reminder_sent']:
                record.update(reminder_sent=True,reminded_at=now());Store.event(c,workspace,'system:access-expiry','access_lease.expiry_reminder',record['id'])
            if at>=plan['expires_at']:
                try:
                    snapshots=current_scope(c,workspace,record)
                    if record['mode']=='scheduled_departure':
                        # Preparation may discover current grants; removal still requires fresh review.
                        work=prepare(c,workspace,plan['client'],plan['person'],record['created_by'],False,source={'kind':'scheduled_departure','id':record['id']})
                        record.update(workflow=work['id'],status='ready_for_approval')
                    else:
                        work=prepare(c,workspace,plan['client'],plan['person'],record['created_by'],False,snapshots=snapshots,source={'kind':'access_lease','id':record['id'],'digest':record['plan_digest']})
                        approval={'actor':record['created_by'],'at':now(),'expires':record['approval']['execute_before'],'digest':work['plan_digest'],'lease_id':record['id']}
                        c.execute("UPDATE workflows SET status='queued',approval=? WHERE id=?",(canonical(approval),work['id']))
                        record.update(workflow=work['id'],status='executing')
                    Store.event(c,workspace,'system:access-expiry','access_lease.due',record['id'])
                except HTTPException as error:
                    record.update(status='blocked',reason=error.detail);Store.event(c,workspace,'system:access-expiry','access_lease.blocked',record['id'])
            record['updated_at']=now();Store.put(c,workspace,KIND,record)


def register(app,store,auth,access_auth,throttle,cipher):
    def authorized(session):require(session['role']=='owner','Workspace owner access required',403)
    def get(c,session,identifier):return require(Store.get(c,session['workspace'],KIND,identifier),'Expiry policy unavailable',404)

    def listing(session):
        authorized(session)
        with store.connect() as c:
            rows=c.execute('SELECT data FROM entities WHERE workspace=? AND kind=? ORDER BY rowid DESC LIMIT 1000',(session['workspace'],KIND)).fetchall()
            return {'leases':[display(c,session['workspace'],json.loads(row[0])) for row in rows]}

    @app.get('/api/access-leases')
    def web_listing(session=Depends(auth)):return listing(session)
    @app.get('/api/companion/access/leases')
    def extension_listing(session=Depends(access_auth)):return listing(session)

    @app.post('/api/companion/access/leases')
    def create(body:Request,session=Depends(access_auth)):
        authorized(session);throttle('access-lease:'+session['user'],20)
        at=time.time();require(at+3600<=body.expires_at<=at+90*86400,'Choose an expiry between one hour and 90 days from now.',422)
        with store.connect(write=True) as c:
            actor=owner(c,session['workspace'],session['user']);require(actor and actor['mfa'],'Current owner access and MFA required',403)
            require(c.execute('SELECT count(*) FROM entities WHERE workspace=? AND kind=?',(session['workspace'],KIND)).fetchone()[0]<1000,'Expiry history limit reached.')
            require(c.execute("SELECT count(*) FROM entities WHERE workspace=? AND kind=? AND json_extract(data,'$.status') NOT IN ('complete','cancelled','blocked')",(session['workspace'],KIND)).fetchone()[0]<100,'Active expiry policy limit reached.')
            scope=initial_scope(c,session['workspace'],body.client_id,body.person_id,session['user'])
            for record in Store.all(c,session['workspace'],KIND):require(record['status'] in TERMINAL or record['plan']['client']!=body.client_id or record['plan']['person']!=body.person_id,'An active expiry policy already covers this client and person.')
            plan={'version':1,'client':body.client_id,'person':body.person_id,'vaults':scope,'mode':body.mode,'expires_at':body.expires_at,'remind_at':max(at,body.expires_at-3*86400)}
            record=dict(id=uid(),client=body.client_id,person=body.person_id,created_by=session['user'],mode=body.mode,status='awaiting_approval',plan=plan,plan_digest=digest(plan),approval=None,workflow=None,reminder_sent=False,created_at=now(),updated_at=now())
            Store.put(c,session['workspace'],KIND,record);Store.event(c,session['workspace'],session['user'],'access_lease.planned',record['id'])
            return display(c,session['workspace'],record)

    @app.post('/api/companion/access/leases/{identifier}/approve')
    def approve(identifier:str,body:Approval,session=Depends(access_auth)):
        authorized(session);throttle('access-approval:'+session['user'],8)
        with store.connect(write=True) as c:
            record=get(c,session,identifier);plan=record['plan'];at=time.time()
            require(record['status']=='awaiting_approval' and record['created_by']==session['user'] and body.approved and body.plan_digest==record['plan_digest']==digest(plan),'Policy cannot be approved.')
            require(at+3600<=plan['expires_at']<=at+90*86400,'Expiry is too near or has passed. Prepare a new policy.')
            require(initial_scope(c,session['workspace'],plan['client'],plan['person'],session['user'])==plan['vaults'],'Membership or client scope changed. Prepare a new policy.')
            actor=owner(c,session['workspace'],session['user']);require(actor and actor['mfa'],'Current owner access and MFA required',403)
            require(verify_password(body.password.get_secret_value(),actor['password']) and consume_factor(c,actor,body.code,cipher),'Current password and unused factor required',401)
            record.update(status='active',approval={'actor':session['user'],'at':now(),'digest':record['plan_digest'],'expires_at':plan['expires_at'],'execute_before':plan['expires_at']+7*86400},updated_at=now())
            Store.put(c,session['workspace'],KIND,record);Store.event(c,session['workspace'],session['user'],'access_lease.approved',identifier)
        return {'ok':True}

    @app.post('/api/companion/access/leases/{identifier}/cancel')
    def stop(identifier:str,session=Depends(access_auth)):
        authorized(session)
        with store.connect(write=True) as c:
            actor=owner(c,session['workspace'],session['user']);require(actor and actor['mfa'],'Current owner access and MFA required',403)
            record=get(c,session,identifier);require(record['status'] not in TERMINAL,'Policy cannot be cancelled.')
            cancel(c,session['workspace'],record,session['user'])
        return {'ok':True,'note':'Completed removals are not undone.'}
