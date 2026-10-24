"""Opt-in weekly access reviews on the existing Runner, planner and task dispatcher."""
import json
import time
from fastapi import Depends,HTTPException
from pydantic import BaseModel,ConfigDict,Field,SecretStr
from . import agents,access_review_evidence as evidence
from .access_workflows import require,owner,digest
from .security import consume_factor,verify_password
from .store import Store,uid,now

POLICY='access_review_policy'
KIND='access_reviews'
WEEK=7*86400

class Consent(BaseModel):
    model_config=ConfigDict(extra='forbid')
    approved:bool=False
    password:SecretStr=Field(max_length=256)
    code:str=Field(max_length=80)

class Signoff(Consent):
    review_digest:str=Field(pattern=r'^[a-f0-9]{64}$')

def authority(c,workspace,actor):
    user=owner(c,workspace,actor)
    require(user and user['mfa'],'Current workspace owner and MFA required',403)
    return user

def policy(c,workspace):
    return next(iter(Store.all(c,workspace,POLICY)),None)

def review_digest(row,job):
    return digest({'id':row['id'],'evidence':row['evidence'],'job':job['id'] if job else None,'plan':job.get('plan') if job else None})

def display(c,workspace,row):
    job=Store.get(c,workspace,'jobs',row['job']) if row.get('job') else None
    state=row['status']
    if state=='planning':
        state='ready' if job and job['status']=='complete' else job['status'] if job else 'unavailable'
    return {**row,'status':state,'plan':job.get('plan') if job else None,'error':job.get('error') if job else row.get('error'),'review_digest':review_digest(row,job),'tasks':row.get('tasks',[]),'references':{evidence.finding(row,item)['id']:item for item in row['evidence']['items']},
      'coverage':'Recorded client-vault memberships, account reports and shared-password debt only. Stale reports do not prove inactivity. AI guidance is a draft. Sign-off creates follow-up tasks, never grants or removes access. At most 20 evidence items are planned; omitted items remain unreviewed.'}

def stop(c,workspace,row,actor):
    row.update(status='cancelled',finished_at=now());Store.put(c,workspace,KIND,row)
    if row.get('job'):
        job=Store.get(c,workspace,'jobs',row['job'])
        if job and job['status'] in {'queued','running'}:
            job.update(status='cancelled',finished_at=now());Store.put(c,workspace,'jobs',job)
    Store.event(c,workspace,actor,'access_review.cancelled',row['id'])

def queue(c,workspace,configuration,at):
    authority(c,workspace,configuration['created_by'])
    require(configuration['enabled'] and configuration['expires']>at,'Review consent expired or paused')
    require(not any(job['status'] in {'queued','running'} for job in Store.all(c,workspace,'jobs')),'Another agent run is active')
    active=c.execute("SELECT data FROM entities WHERE workspace=? AND kind=? AND json_extract(data,'$.status') IN ('planning','ready')",(workspace,KIND)).fetchall()
    for saved in active:
        prior=json.loads(saved[0]);job=Store.get(c,workspace,'jobs',prior['job']) if prior.get('job') else None
        if prior.get('expires',0)<=at:
            stop(c,workspace,prior,configuration['created_by']);continue
        require(not (prior['status']=='ready' or job and job['status'] in {'queued','running','complete'}),'Sign off or cancel the previous review first')
    require(c.execute('SELECT count(*) FROM entities WHERE workspace=? AND kind=?',(workspace,KIND)).fetchone()[0]<1000,'Review history limit reached')
    facts=evidence.collect(c,workspace,at-WEEK,at)
    covered=set()
    for previous in c.execute("SELECT data FROM entities WHERE workspace=? AND kind=? AND json_extract(data,'$.status')='signed_off' AND json_extract(data,'$.expires')>?",(workspace,KIND,at)):
        previous=json.loads(previous[0])
        if previous['evidence']['digest']==facts['digest']:
            covered.update(item['key'] for item in previous['evidence']['items'])
    if covered:facts=evidence.collect(c,workspace,at-WEEK,at,covered)
    row=dict(id=uid(),created_by=configuration['created_by'],policy=configuration['id'],created_at=now(),expires=at+WEEK,status='planning' if facts['items'] else 'ready',evidence=facts,job=None)
    findings=[evidence.finding(row,item) for item in facts['items']]
    for finding in findings:Store.put(c,workspace,'findings',finding)
    if findings:
        job=dict(id=uid(),mode='access_review',access_review=row['id'],finding_ids=[f['id'] for f in findings],status='queued',created_by=row['created_by'],created_at=now(),steps=[],permissions={'create_tasks':False,'create_investigation':False})
        Store.put(c,workspace,'jobs',job);row['job']=job['id'];Store.event(c,workspace,row['created_by'],'agent.queued',job['id'])
    Store.put(c,workspace,KIND,row)
    configuration.update(next_due=at+WEEK,last_checked=at,last_review=row['id']);Store.put(c,workspace,POLICY,configuration)
    Store.event(c,workspace,row['created_by'],'access_review.queued',row['id'])
    return row

def tick(store,dispatch,clock=time.time):
    # Reuses the existing scheduler thread and executor; one current week only.
    at=clock();queued=[]
    with store.connect(write=True) as c:
        rows=c.execute("SELECT workspace,data FROM entities WHERE kind=? AND json_extract(data,'$.enabled')=1 AND json_extract(data,'$.next_due')<=? ORDER BY COALESCE(json_extract(data,'$.last_checked'),0),id LIMIT 25",(POLICY,at)).fetchall()
        for saved in rows:
            config=json.loads(saved['data']);workspace=saved['workspace']
            try:
                authority(c,workspace,config['created_by'])
                require(config['expires']>at,'Review consent expired')
            except HTTPException:
                config.update(enabled=False,last_status='authority_or_consent_lost',last_checked=at);Store.put(c,workspace,POLICY,config);continue
            # Planning requires an actual provider; absence never creates a fake plan.
            try:
                row=queue(c,workspace,config,at)
                if row['job']:queued.append((workspace,row['id']))
            except (ValueError,HTTPException):
                config.update(last_checked=at,last_status='attention');Store.put(c,workspace,POLICY,config)
    for workspace,identifier in queued:dispatch(workspace,identifier)

def validate_job(c,workspace,job):
    row=Store.get(c,workspace,KIND,job['access_review'])
    require(row and row['status']=='planning' and row['job']==job['id'],'Access review is no longer active')
    require(row['expires']>time.time(),'Review expired. Compile a current review.')
    authority(c,workspace,job['created_by'])
    require(evidence.current(c,workspace,row),'Access metadata changed. Cancel this review and compile a new one.')
    config=policy(c,workspace)
    require(config and config['id']==row['policy'] and config['enabled'] and config['expires']>time.time(),'Review consent expired or paused')
    return row

def register(app,store,auth,access_auth,throttle,cipher,settings,executor):
    def dispatch(workspace,identifier):return app.state.review_runner.enqueue_access_review(executor,workspace,identifier,app.state.agent_transport)
    def scheduler():
        if settings.groq_key:tick(store,dispatch)
    app.state.access_review_tick=scheduler
    app.state.watch_service.additional_ticks.append(scheduler)

    def live(c,session):
        authority(c,session['workspace'],session['user'])
        if session.get('id'):
            from .extension_connect import ACCESS_SCOPE,ACCESS_KIND
            grant=Store.get(c,ACCESS_SCOPE,ACCESS_KIND,session['id'])
            require(grant and grant['expires']>time.time(),'Workflow connection revoked',401)
    @app.get('/api/companion/access/reviews')
    def listing(session=Depends(access_auth)):
        with store.connect() as c:
            live(c,session)
            rows=c.execute('SELECT data FROM entities WHERE workspace=? AND kind=? ORDER BY rowid DESC LIMIT 30',(session['workspace'],KIND)).fetchall()
            config=policy(c,session['workspace'])
            return {'policy':config,'reviews':[display(c,session['workspace'],json.loads(r[0])) for r in rows],'provider_ready':bool(settings.groq_key)}

    @app.post('/api/companion/access/reviews/enable')
    def enable(body:Consent,session=Depends(access_auth)):
        throttle('access-review-consent:'+session['user'],8)
        require(settings.groq_key,'Configure Groq before enabling access reviews',503)
        with store.connect(write=True) as c:
            live(c,session);user=authority(c,session['workspace'],session['user'])
            require(body.approved,'Approve weekly metadata-only planning',422)
            require(verify_password(body.password.get_secret_value(),user['password']) and consume_factor(c,user,body.code,cipher),'Current password and unused factor required',401)
            old=policy(c,session['workspace'])
            require(not old or not old['enabled'],'Pause the current policy before approving a new one')
            config=dict(id=old['id'] if old else uid(),enabled=True,created_by=session['user'],approved_at=now(),expires=time.time()+90*86400,next_due=time.time()+WEEK,last_checked=0)
            Store.put(c,session['workspace'],POLICY,config);Store.event(c,session['workspace'],session['user'],'access_review.enabled',config['id'])
        return config

    @app.post('/api/companion/access/reviews/pause')
    def pause(session=Depends(access_auth)):
        with store.connect(write=True) as c:
            live(c,session);config=require(policy(c,session['workspace']),'No review policy',404)
            config['enabled']=False;Store.put(c,session['workspace'],POLICY,config)
            for row in Store.all(c,session['workspace'],KIND):
                if row['status'] in {'planning','ready'}:stop(c,session['workspace'],row,session['user'])
            Store.event(c,session['workspace'],session['user'],'access_review.paused',config['id'])
        return {'ok':True,'note':'Existing follow-up tasks are not deleted. No access was changed.'}

    @app.post('/api/companion/access/reviews/run')
    def run(session=Depends(access_auth)):
        throttle('access-review-run:'+session['workspace'],8)
        require(settings.groq_key,'Configure Groq before planning',503)
        with store.connect(write=True) as c:
            live(c,session);config=require(policy(c,session['workspace']),'Enable reviews first',409)
            require(config['created_by']==session['user'],'Only the approving owner can compile under this consent',403)
            row=queue(c,session['workspace'],config,time.time())
        if row['job']:dispatch(session['workspace'],row['id'])
        return {'id':row['id']}

    @app.post('/api/companion/access/reviews/{identifier}/cancel')
    def cancel(identifier:str,session=Depends(access_auth)):
        with store.connect(write=True) as c:
            live(c,session);row=require(Store.get(c,session['workspace'],KIND,identifier),'Review unavailable',404)
            require(row['status'] in {'planning','ready'},'Review already finished')
            stop(c,session['workspace'],row,session['user'])
        return {'ok':True}

    @app.post('/api/companion/access/reviews/{identifier}/signoff')
    def signoff(identifier:str,body:Signoff,session=Depends(access_auth)):
        throttle('access-review-signoff:'+session['user'],8)
        with store.connect(write=True) as c:
            live(c,session);row=require(Store.get(c,session['workspace'],KIND,identifier),'Review unavailable',404)
            value=display(c,session['workspace'],row)
            require(value['status']=='ready' and row['expires']>time.time() and body.approved and body.review_digest==value['review_digest'],'Review is not ready, expired or changed')
            require(evidence.current(c,session['workspace'],row),'Access metadata changed. Compile a new review.')
            user=authority(c,session['workspace'],session['user'])
            require(verify_password(body.password.get_secret_value(),user['password']) and consume_factor(c,user,body.code,cipher),'Current password and unused factor required',401)
            tasks=[]
            if row['job']:
                job=require(Store.get(c,session['workspace'],'jobs',row['job']),'Plan unavailable')
                findings=[require(Store.get(c,session['workspace'],'findings',f),'Evidence unavailable') for f in job['finding_ids']]
                approved_job={**job,'created_by':session['user'],'permissions':{'create_tasks':True,'create_investigation':False}}
                output=agents.dispatch_work(c,session['workspace'],approved_job,findings,job['plan']);tasks=output['tasks']+output['reused_tasks']
            row.update(status='signed_off',signed_at=now(),signed_by=session['user'],signed_digest=value['review_digest'],tasks=tasks,partial=bool(row['evidence']['omitted']))
            Store.put(c,session['workspace'],KIND,row);Store.event(c,session['workspace'],session['user'],'access_review.signed_off',identifier)
        return {'ok':True,'tasks':tasks,'partial':row['partial'],'note':'Follow-up tasks only. No access was changed; omitted evidence remains unreviewed.'}
