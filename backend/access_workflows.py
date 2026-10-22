"""Durable local steps executed by reviews.Runner, never an LLM or new executor."""
import hashlib
import json
import time
from fastapi import Depends, HTTPException, Request
from pydantic import BaseModel, ConfigDict, Field, SecretStr
from .store import Store, canonical, now, uid
from .security import consume_factor, verify_password
from .sharing import revoke_access

ACTIVE={'queued','running','waiting_unlock'}


def require(value,message,status=409):
    if not value:raise HTTPException(status,message)
    return value


def digest(value):return hashlib.sha256(canonical(value).encode()).hexdigest()


class PlanRequest(BaseModel):
    model_config=ConfigDict(extra='forbid')
    client_id:str=Field(pattern=r'^[a-f0-9]{24}$')
    person_id:str=Field(pattern=r'^[a-f0-9]{24}$')
    dry_run:bool=True


class Approval(BaseModel):
    model_config=ConfigDict(extra='forbid')
    plan_digest:str=Field(pattern=r'^[a-f0-9]{64}$')
    approved:bool=False
    password:SecretStr=Field(max_length=256)
    code:str=Field(max_length=80)


def owner(c,workspace,actor):
    return c.execute("SELECT u.* FROM members m JOIN users u ON u.id=m.user WHERE m.workspace=? AND m.user=? AND m.role='owner'",(workspace,actor)).fetchone()


def scope(c,workspace,client,person,actor):
    require(c.execute('SELECT 1 FROM clients WHERE id=? AND workspace=?',(client,workspace)).fetchone(),'Client not found',404)
    member=require(c.execute('SELECT role FROM members WHERE user=? AND workspace=?',(person,workspace)).fetchone(),'Member not found',404)
    require(person!=actor and member['role']!='owner','Workspace owners cannot be offboarded by this plan.')
    rows=c.execute('SELECT v.id,v.owner,v.revision,v.epoch,g.role,g.envelope FROM client_vaults l JOIN team_vaults v ON v.id=l.vault AND v.workspace=l.workspace JOIN team_grants g ON g.vault=v.id WHERE l.client=? AND l.workspace=? AND g.user=? ORDER BY v.id',(client,workspace,person)).fetchall()
    require(0<len(rows)<=20,'Choose a client with 1–20 matching vault memberships.')
    require(all(row['owner']==actor and row['owner']!=person for row in rows),'Every selected vault must be owned by the approving owner; transfer ownership separately.')
    return [{'vault':row['id'],'epoch':row['epoch'],'revision':row['revision'],'grant_digest':hashlib.sha256(row['envelope'].encode()).hexdigest()} for row in rows]


def view(c,row):
    value=dict(row);value['plan']=json.loads(value['plan']);value['approval']=json.loads(value['approval']) if value['approval'] else None
    value['steps']=[dict(step) for step in c.execute('SELECT * FROM workflow_steps WHERE workflow=? ORDER BY position',(row['id'],))]
    value['rechecks']=[json.loads(item['data']) for item in c.execute("SELECT data FROM entities WHERE workspace=? AND kind='access_rechecks' AND json_extract(data,'$.workflow')=? ORDER BY json_extract(data,'$.due')",(row['workspace'],row['id']))]
    value['coverage']='Selected client vault memberships only. Cached credentials and website sessions are not erased; affected website-password rotation remains separate.'
    return value


def prepare(c,workspace,client,person,actor,dry_run=True,*,snapshots=None,source=None):
    """Create the existing durable plan; internal callers may bind a narrow scope."""
    limit=2000 if source and source.get('kind') in {'access_lease','scheduled_departure'} else 1000
    require(c.execute('SELECT count(*) FROM workflows WHERE workspace=?',(workspace,)).fetchone()[0]<limit,'Workflow limit reached.')
    snapshots=scope(c,workspace,client,person,actor) if snapshots is None else snapshots
    require(0<len(snapshots)<=20 and len({item['vault'] for item in snapshots})==len(snapshots),'Invalid workflow vault scope.')
    plan={'version':1,'client':client,'person':person,'dry_run':dry_run,'vaults':snapshots}
    if source:plan['source']=source
    identifier=uid();at=now()
    c.execute('INSERT INTO workflows VALUES(?,?,?,?,?,?,?,?,?,?,?)',(identifier,workspace,client,person,actor,'awaiting_approval',canonical(plan),digest(plan),None,at,at))
    for action in ('revoke','rotate_key','verify_absent'):
        for item in snapshots:
            index=c.execute('SELECT count(*) FROM workflow_steps WHERE workflow=?',(identifier,)).fetchone()[0]
            c.execute('INSERT INTO workflow_steps VALUES(?,?,?,?,?,?,?,?,?)',(uid(),identifier,index,item['vault'],action,'pending',0,None,None))
    Store.event(c,workspace,actor,'access_workflow.planned',identifier)
    return c.execute('SELECT * FROM workflows WHERE id=?',(identifier,)).fetchone()


def advance_one(store,workspace,identifier,clock=time.time):
    """One local effect and step completion commit together; no network calls here."""
    with store.connect(write=True) as c:
        row=c.execute('SELECT * FROM workflows WHERE id=? AND workspace=?',(identifier,workspace)).fetchone()
        if not row or row['status'] not in ACTIVE:return False
        approval=json.loads(row['approval']) if row['approval'] else None
        plan=json.loads(row['plan']);actor=row['created_by']
        user=owner(c,workspace,actor)
        valid=approval and approval.get('actor')==actor and approval.get('expires',0)>clock() and approval.get('digest')==row['plan_digest']==digest(plan) and user and user['mfa']
        if plan.get('source',{}).get('kind')=='access_lease':
            from .access_leases import authorized_workflow
            valid=valid and authorized_workflow(c,row,plan,approval,clock())
        stored_steps=c.execute('SELECT action,vault,status FROM workflow_steps WHERE workflow=? ORDER BY position',(identifier,)).fetchall()
        expected=[(action,item['vault']) for action in ('revoke','rotate_key','verify_absent') for item in plan['vaults']]
        done='simulated' if plan['dry_run'] else 'complete'
        valid=valid and plan['version']==1 and plan['client']==row['client'] and plan['person']==row['person'] and [(item['action'],item['vault']) for item in stored_steps]==expected and all(item['status'] in {'pending',done} for item in stored_steps)
        step=c.execute("SELECT * FROM workflow_steps WHERE workflow=? AND status='pending' ORDER BY position LIMIT 1",(identifier,)).fetchone()
        if not valid:
            c.execute("UPDATE workflows SET status='blocked',updated_at=? WHERE id=?",(now(),identifier));Store.event(c,workspace,actor,'access_workflow.approval_lost',identifier);return False
        if not step:
            c.execute('UPDATE workflows SET status=?,updated_at=? WHERE id=?',('dry_run_complete' if plan['dry_run'] else 'complete',now(),identifier))
            Store.event(c,workspace,actor,'access_workflow.finished',identifier)
            if not plan['dry_run']:
                from .access_evidence import schedule
                schedule(c,row,clock)
            return False
        snapshot=next((item for item in plan['vaults'] if item['vault']==step['vault']),None)
        vault=c.execute('SELECT * FROM team_vaults WHERE id=? AND workspace=?',(step['vault'],workspace)).fetchone()
        grant=c.execute('SELECT * FROM team_grants WHERE vault=? AND user=?',(step['vault'],row['person'])).fetchone()
        failure=None;outcome='simulated' if plan['dry_run'] else 'verified'
        target=c.execute('SELECT role FROM members WHERE workspace=? AND user=?',(workspace,row['person'])).fetchone()
        linked=c.execute('SELECT 1 FROM client_vaults WHERE workspace=? AND client=? AND vault=?',(workspace,row['client'],step['vault'])).fetchone()
        if not snapshot or not vault or vault['owner']!=actor or not linked or target and target['role']=='owner':failure='scope_changed'
        elif plan['dry_run']:pass
        elif step['action']=='revoke':
            if grant:
                if vault['epoch']!=snapshot['epoch'] or vault['revision']!=snapshot['revision'] or hashlib.sha256(grant['envelope'].encode()).hexdigest()!=snapshot['grant_digest']:failure='scope_changed'
                else:revoke_access(c,workspace,actor,step['vault'],row['person']);outcome='revoked'
            else:outcome='already_absent'
        elif grant:failure='access_reappeared'
        elif step['action']=='rotate_key' and (vault['rotation_required'] or vault['epoch']<snapshot['epoch'] or not snapshot.get('absent_at_plan') and vault['epoch']==snapshot['epoch']):
            c.execute("UPDATE workflows SET status='waiting_unlock',updated_at=? WHERE id=?",(now(),identifier));return False
        elif step['action'] not in {'rotate_key','verify_absent'}:failure='unsupported_step'
        if failure:
            c.execute('UPDATE workflow_steps SET outcome=? WHERE id=?',(failure,step['id']))
            c.execute("UPDATE workflows SET status='blocked',updated_at=? WHERE id=?",(now(),identifier));Store.event(c,workspace,actor,'access_workflow.'+failure,identifier);return False
        c.execute('UPDATE workflow_steps SET status=?,attempts=attempts+1,outcome=?,completed_at=? WHERE id=?',('simulated' if plan['dry_run'] else 'complete',outcome,now(),step['id']))
        c.execute("UPDATE workflows SET status='running',updated_at=? WHERE id=?",(now(),identifier))
        Store.event(c,workspace,actor,'access_workflow.step_completed',step['id'])
        return True


def register(app,store,auth,throttle,cipher,executor,shared_companions):
    def authorized(session):require(session['role']=='owner','Workspace owner access required',403)
    def get(c,session,identifier):return require(c.execute('SELECT * FROM workflows WHERE id=? AND workspace=?',(identifier,session['workspace'])).fetchone(),'Workflow not found',404)
    def dispatch(workspace,identifier):app.state.review_runner.enqueue_access(executor,workspace,identifier)

    @app.get('/api/access-workflows')
    def listing(session=Depends(auth)):
        authorized(session)
        with store.connect() as c:return {'workflows':[view(c,row) for row in c.execute('SELECT * FROM workflows WHERE workspace=? ORDER BY created_at DESC LIMIT 100',(session['workspace'],))]}

    @app.get('/api/access-workflows/{identifier}/report')
    def report(identifier:str,session=Depends(auth)):
        authorized(session)
        from .access_evidence import report as evidence
        with store.connect() as c:return evidence(c,get(c,session,identifier))

    @app.post('/api/access-workflows')
    def create(body:PlanRequest,session=Depends(auth)):
        authorized(session);throttle('access-plan:'+session['user'],20)
        with store.connect(write=True) as c:
            row=prepare(c,session['workspace'],body.client_id,body.person_id,session['user'],body.dry_run)
            return view(c,row)

    @app.post('/api/access-workflows/{identifier}/approve')
    def approve(identifier:str,body:Approval,session=Depends(auth)):
        authorized(session);throttle('access-approval:'+session['user'],8)
        with store.connect(write=True) as c:
            row=get(c,session,identifier);plan=json.loads(row['plan'])
            require(row['status']=='awaiting_approval' and body.approved and row['created_by']==session['user'],'This plan cannot be approved.')
            require(body.plan_digest==row['plan_digest']==digest(plan),'Plan changed; review again.')
            require(scope(c,session['workspace'],row['client'],row['person'],session['user'])==plan['vaults'],'Access changed; create a new plan.')
            user=owner(c,session['workspace'],session['user'])
            require(user and user['mfa'],'Enroll account MFA before approving access workflows.',403)
            require(verify_password(body.password.get_secret_value(),user['password']) and consume_factor(c,user,body.code,cipher),'Current password and unused factor required.',401)
            approval={'actor':session['user'],'at':now(),'expires':time.time()+86400,'digest':row['plan_digest']}
            c.execute("UPDATE workflows SET status='queued',approval=?,updated_at=? WHERE id=?",(canonical(approval),now(),identifier));Store.event(c,session['workspace'],session['user'],'access_workflow.approved',identifier)
        dispatch(session['workspace'],identifier)
        return {'ok':True}

    @app.post('/api/access-workflows/{identifier}/cancel')
    def cancel(identifier:str,session=Depends(auth)):
        authorized(session)
        with store.connect(write=True) as c:
            row=get(c,session,identifier);require(row['status'] not in {'complete','dry_run_complete','cancelled'},'Workflow already finished.')
            c.execute("UPDATE workflows SET status='cancelled',updated_at=? WHERE id=?",(now(),identifier))
            c.execute("UPDATE workflow_steps SET status='cancelled' WHERE workflow=? AND status='pending'",(identifier,));Store.event(c,session['workspace'],session['user'],'access_workflow.cancelled',identifier)
        return {'ok':True,'note':'Completed removals are not undone.'}

    # Narrow bearer routes reuse the very same planner, approver and canceller.
    from .extension_connect import ACCESS_SCOPE, ACCESS_KIND
    from .security import digest as token_digest
    from .client_access import snapshot
    import re
    def access_auth(request:Request):
        origin=request.headers.get('origin','')
        require(re.fullmatch(r'chrome-extension://[a-p]{32}',origin),'Extension origin required',403)
        bearer=request.headers.get('authorization','')
        require(bearer.startswith('Bearer '),'Workflow connection required',401)
        with store.connect() as c:
            grant=Store.get(c,ACCESS_SCOPE,ACCESS_KIND,token_digest(bearer[7:]))
            require(grant and grant['expires']>time.time() and grant['origin']==origin,'Workflow connection expired or revoked',401)
            user=owner(c,grant['workspace'],grant['user'])
            require(user and user['mfa'],'Owner access and account MFA required',403)
        return {**grant,'role':'owner'}

    app.state.access_auth=access_auth

    @app.get('/api/companion/access/context')
    def extension_context(session=Depends(access_auth)):
        return {**snapshot(store,session['workspace']),'expires':session['expires'],'actor_id':session['user']}

    @app.post('/api/companion/access/revoke')
    def extension_revoke(session=Depends(access_auth)):
        with store.connect(write=True) as c:
            c.execute('DELETE FROM entities WHERE id=? AND workspace=? AND kind=?',(session['id'],ACCESS_SCOPE,ACCESS_KIND))
            Store.event(c,session['workspace'],session['user'],'extension.access_revoked','owner-disconnected')
        return {'ok':True}

    @app.get('/api/companion/access/workflows')
    def extension_listing(session=Depends(access_auth)):return listing(session)

    @app.post('/api/companion/access/workflows')
    def extension_create(body:PlanRequest,session=Depends(access_auth)):return create(body,session)

    @app.post('/api/companion/access/workflows/{identifier}/approve')
    def extension_approve(identifier:str,body:Approval,session=Depends(access_auth)):return approve(identifier,body,session)

    @app.post('/api/companion/access/workflows/{identifier}/cancel')
    def extension_cancel(identifier:str,session=Depends(access_auth)):return cancel(identifier,session)

    @app.get('/api/companion/access/workflows/{identifier}/report')
    def extension_report(identifier:str,session=Depends(access_auth)):return report(identifier,session)

    from .sharing import TeamRotate
    def rotation_connection(c,session,identifier,vault,request):
        row=get(c,session,identifier);plan=json.loads(row['plan'])
        approval=json.loads(row['approval']) if row['approval'] else None
        require(row['status']=='waiting_unlock' and not plan['dry_run'] and row['created_by']==session['user'] and approval and approval.get('actor')==session['user'] and approval['expires']>time.time() and approval['digest']==row['plan_digest']==digest(plan),'Active approved workflow required')
        require(any(item['vault']==vault for item in plan['vaults']),'Vault is outside this plan',403)
        snapshot=next(item for item in plan['vaults'] if item['vault']==vault)
        current=c.execute('SELECT epoch,rotation_required FROM team_vaults WHERE id=? AND workspace=?',(vault,session['workspace'])).fetchone()
        require(current and current['rotation_required'] and current['epoch']==snapshot['epoch'],'This vault no longer needs the approved rotation')
        require(c.execute('SELECT 1 FROM client_vaults WHERE client=? AND vault=? AND workspace=?',(row['client'],vault,session['workspace'])).fetchone(),'Client vault link changed')
        require(owner(c,session['workspace'],session['user']),'Owner access required',403)
        grant=Store.get(c,ACCESS_SCOPE,ACCESS_KIND,session['id'])
        require(grant and grant['expires']>time.time(),'Workflow connection revoked',401)
        token=request.headers.get('x-sentinel-vault-token','')
        connection=c.execute('SELECT * FROM companions WHERE token=? AND expires>?',(token_digest(token),time.time())).fetchone()
        require(connection and connection['kind']=='shared' and connection['vault_id']==vault and connection['user']==session['user'] and connection['workspace']==session['workspace'],'A separate owner connection to this exact shared vault is required',403)
        require(not c.execute('SELECT 1 FROM team_grants WHERE vault=? AND user=?',(vault,row['person'])).fetchone(),'Access reappeared; rotation stopped')
        return dict(connection)

    @app.get('/api/companion/access/workflows/{identifier}/vaults/{vault}/rotation')
    def rotation_context(identifier:str,vault:str,request:Request,session=Depends(access_auth)):
        with store.connect() as c:
            connection=rotation_connection(c,session,identifier,vault,request)
            return shared_companions['rotation_context'](c,connection)

    @app.post('/api/companion/access/workflows/{identifier}/vaults/{vault}/rotation')
    def rotate(identifier:str,vault:str,body:TeamRotate,request:Request,session=Depends(access_auth)):
        throttle('team-rotate:'+session['user'],20)
        with store.connect(write=True) as c:
            connection=rotation_connection(c,session,identifier,vault,request)
            value=shared_companions['rotate'](c,connection,body)
        dispatch(session['workspace'],identifier)
        return value

    def tick():
        from .access_evidence import tick as check_access
        from .access_leases import tick as check_leases
        check_leases(store)
        check_access(store)
        with store.connect() as c:rows=c.execute("SELECT id,workspace FROM workflows WHERE status IN ('queued','running','waiting_unlock') ORDER BY updated_at LIMIT 100").fetchall()
        for row in rows:dispatch(row['workspace'],row['id'])
    app.state.access_workflow_tick=tick
