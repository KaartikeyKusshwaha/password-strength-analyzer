"""Approved multi-check reviews. Raw submissions exist only in worker arguments."""
import time
import threading

from fastapi import Depends, HTTPException

from . import agents
from .store import Store, now, uid

KIND='security_reviews'
ACTIVE={'queued','running'}


def require(value,message,status=409):
    if not value:raise HTTPException(status,message)
    return value


def stop(c,workspace,review,actor,status='cancelled'):
    review.update(status=status,finished_at=now(),error='Review stopped. Start a new approved review to run remaining checks.')
    operations=Store.all(c,workspace,'operations')
    for step in review['checks']:
        completed=next((o for o in operations if o['id']==step.get('operation_id') and o.get('review_id')==review['id'] and o['status'] not in ACTIVE),None)
        if completed:step.update(status=completed['status'],scan_id=completed.get('scan_id'),finding_ids=completed.get('finding_ids',[]))
        elif step['status'] in {'pending','running'}:step['status']='interrupted' if status=='interrupted' else 'cancelled'
    review['finding_ids']=list(dict.fromkeys(f for step in review['checks'] for f in step.get('finding_ids',[])))
    for operation in operations:
        if operation.get('review_id')==review['id'] and operation['status'] in ACTIVE:
            operation.update(status='cancelled',finished_at=now(),error='Parent review stopped.')
            operation.pop('lease',None);operation.pop('lease_expires',None)
            Store.put(c,workspace,'operations',operation)
            Store.event(c,workspace,actor,'operation.cancelled',operation['id'])
    if review.get('agent_job'):
        job=Store.get(c,workspace,'jobs',review['agent_job'])
        if job and job['status'] in ACTIVE:
            job.update(status='cancelled',finished_at=now(),error='Parent review stopped.')
            Store.put(c,workspace,'jobs',job)
    Store.put(c,workspace,KIND,review)
    Store.event(c,workspace,actor,'security_review.'+status,review['id'])


class Runner:
    def __init__(self,store,settings,queue,execute):
        self.store,self.settings,self.queue,self.execute=store,settings,queue,execute
        self.wait_seconds=120
        self.pause=time.sleep
        self.access_pending=set();self.access_lock=threading.Lock()

    def run_access(self,workspace,identifier):
        from .access_workflows import advance_one
        # Bounded local steps, yielding as soon as client-side unlock is needed.
        try:
            for _ in range(61):
                if not advance_one(self.store,workspace,identifier):return
        except Exception:
            with self.store.connect(write=True) as c:
                row=c.execute("SELECT created_by FROM workflows WHERE id=? AND workspace=? AND status IN ('queued','running','waiting_unlock')",(identifier,workspace)).fetchone()
                if row:
                    c.execute("UPDATE workflows SET status='blocked',updated_at=? WHERE id=?",(now(),identifier))
                    Store.event(c,workspace,row['created_by'],'access_workflow.execution_failed',identifier)

    def enqueue_access(self,executor,workspace,identifier):
        key=(workspace,identifier)
        with self.access_lock:
            if key in self.access_pending:return
            self.access_pending.add(key)
        def work():
            try:self.run_access(workspace,identifier)
            finally:
                with self.access_lock:self.access_pending.discard(key)
        try:return executor.submit(work)
        except BaseException:
            with self.access_lock:self.access_pending.discard(key)
            raise

    def current(self,c,workspace,identifier,actor):
        review=Store.get(c,workspace,KIND,identifier)
        if not review or review['status'] not in ACTIVE:return None
        member=c.execute('SELECT role FROM members WHERE workspace=? AND user=?',(workspace,actor)).fetchone()
        if not member or member['role']=='viewer':raise PermissionError()
        return review

    def run(self,session,identifier,checks,transport=None):
        workspace,actor=session['workspace'],session['user']
        try:
            with self.store.connect(write=True) as c:
                review=self.current(c,workspace,identifier,actor)
                if not review or review['status']!='queued':return
                review.update(status='running',started_at=now());Store.put(c,workspace,KIND,review)
            for index,body in enumerate(checks):
                with self.store.connect(write=True) as c:
                    review=self.current(c,workspace,identifier,actor)
                    if not review:return
                    try:
                        operation=self.queue(c,body,session,identifier)
                    except HTTPException:
                        review['checks'][index].update(status='failed',error='The approved scope or connection is no longer available. No check was started.')
                        Store.put(c,workspace,KIND,review)
                        continue
                    review['checks'][index].update(status='running',operation_id=operation['id'])
                    Store.put(c,workspace,KIND,review)
                remote=body.action in {'device','posture','updates'} and body.device_id!='local'
                if not remote:self.execute(workspace,actor,operation['id'],body)
                deadline=time.monotonic()+self.wait_seconds
                while True:
                    with self.store.connect(write=True) as c:
                        review=self.current(c,workspace,identifier,actor)
                        if not review:return
                        completed=Store.get(c,workspace,'operations',operation['id'])
                        if completed['status'] not in ACTIVE:
                            review['checks'][index].update(status=completed['status'],scan_id=completed.get('scan_id'),finding_ids=completed.get('finding_ids',[]))
                            if completed.get('error'):review['checks'][index]['error']=completed['error']
                            Store.put(c,workspace,KIND,review)
                            break
                        if time.monotonic()>=deadline:
                            completed.update(status='cancelled',finished_at=now(),error='Review wait for the paired device expired. No complete assessment was inferred.')
                            completed.pop('lease',None);completed.pop('lease_expires',None)
                            Store.put(c,workspace,'operations',completed)
                            review['checks'][index].update(status='unassessed',error=completed['error'])
                            Store.put(c,workspace,KIND,review)
                            Store.event(c,workspace,actor,'operation.cancelled',completed['id'])
                            break
                    self.pause(.25)
            with self.store.connect(write=True) as c:
                review=self.current(c,workspace,identifier,actor)
                if not review:return
                ids=list(dict.fromkeys(f for step in review['checks'] for f in step.get('finding_ids',[])))
                review['finding_ids']=ids
                review['assessment_status']='complete' if all(step['status']=='complete' for step in review['checks']) else 'partial'
                review['triage_status']='not_requested'
                if review['ai_triage']:
                    review['triage_status']='no_findings' if not ids else 'queued'
                    if ids:
                        require(not any(j['status'] in ACTIVE for j in Store.all(c,workspace,'jobs')),'Another agent run is active')
                        job=dict(id=uid(),mode='remediation',finding_ids=ids[:20],status='queued',created_by=actor,created_at=now(),steps=[],permissions={'create_tasks':True,'create_investigation':False},review_id=identifier)
                        Store.put(c,workspace,'jobs',job);Store.event(c,workspace,actor,'agent.queued',job['id'])
                        review.update(agent_job=job['id'],triage_count=len(job['finding_ids']))
                Store.put(c,workspace,KIND,review)
            if review.get('agent_job'):
                agents.run_job(self.store,workspace,review['agent_job'],self.settings.groq_key,self.settings.model,transport)
            with self.store.connect(write=True) as c:
                review=self.current(c,workspace,identifier,actor)
                if not review:return
                if review.get('agent_job'):
                    job=Store.get(c,workspace,'jobs',review['agent_job'])
                    review['triage_status']=job['status']
                partial=review['assessment_status']!='complete' or review['triage_status'] not in {'not_requested','no_findings','complete'} or review.get('triage_count',len(review['finding_ids']))<len(review['finding_ids'])
                review.update(status='partial' if partial else 'complete',finished_at=now())
                Store.put(c,workspace,KIND,review);Store.event(c,workspace,actor,'security_review.finished',identifier)
        except Exception:
            with self.store.connect(write=True) as c:
                review=Store.get(c,workspace,KIND,identifier)
                if review and review['status'] in ACTIVE:stop(c,workspace,review,actor,'interrupted')


def register(app,store,auth,writable,throttle,settings,executor,validate,queue,execute,RequestModel):
    runner=Runner(store,settings,queue,execute);app.state.review_runner=runner

    @app.post('/api/security-reviews')
    def create(body:RequestModel,session=Depends(auth)):
        writable(session);throttle('security-review:'+session['workspace'],10)
        require(body.workspace_id==session['workspace'],'Workspace changed. Review the scope again before approving.')
        require(body.authorized,'Approve the complete review scope',422)
        require(not body.ai_triage or settings.groq_key,'Configure Groq before requesting AI triage',503)
        require(not any(check.ai_triage for check in body.checks),'Approve AI triage once for the whole review',422)
        try:submitted_bytes=sum(len(check.content.get_secret_value().encode('utf-8')) for check in body.checks)
        except UnicodeError:raise HTTPException(422,'Review submissions must be valid UTF-8')
        require(submitted_bytes<=1048576,'Combined review submissions exceed 1 MiB',422)
        for check in body.checks:validate(check,session)
        with store.connect(write=True) as c:
            member=c.execute('SELECT role FROM members WHERE workspace=? AND user=?',(session['workspace'],session['user'])).fetchone()
            require(member and member['role']!='viewer','Review permission removed',403)
            require(not any(item['status'] in ACTIVE for kind in (KIND,'operations','jobs') for item in Store.all(c,session['workspace'],kind)),'Another review, assessment or agent is active')
            value=dict(id=uid(),name=body.name,status='queued',created_by=session['user'],created_at=now(),ai_triage=body.ai_triage,finding_ids=[],checks=[dict(index=index,action=check.action,target=check.target,device_id=check.device_id,ports=sorted(set(check.ports)) if check.action=='device' else [],status='pending') for index,check in enumerate(body.checks)])
            Store.put(c,session['workspace'],KIND,value);Store.event(c,session['workspace'],session['user'],'security_review.approved',value['id'])
        executor.submit(runner.run,dict(session),value['id'],body.checks,app.state.agent_transport)
        return value

    @app.post('/api/security-reviews/{identifier}/cancel')
    def cancel(identifier:str,session=Depends(auth)):
        writable(session)
        with store.connect(write=True) as c:
            review=require(Store.get(c,session['workspace'],KIND,identifier),'Review not found',404)
            require(review['created_by']==session['user'] or session['role']=='owner','Only the requester or workspace owner may cancel',403)
            require(review['status'] in ACTIVE,'Review already finished')
            stop(c,session['workspace'],review,session['user'])
        return {'ok':True}
