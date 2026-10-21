"""Separately authorized extension operators. Vault tokens cannot use these routes."""
import re
import time
from fastapi import Depends, HTTPException, Request
from .security import digest
from .store import Store,now
from .extension_connect import SECURITY_SCOPE,SECURITY_KIND
from .scanner import RULES

def register(app,store,settings,throttle,executor,validate_operation,queue_operation,run_operation,OperationRequest,auth):
    def require(condition,message,status=403):
        if not condition:raise HTTPException(status,message)
    def security_auth(request:Request):
        origin=request.headers.get('origin','')
        require(re.fullmatch(r'chrome-extension://[a-p]{32}',origin),'Extension origin required')
        bearer=request.headers.get('authorization','')
        require(bearer.startswith('Bearer '),'Security connection required',401)
        with store.connect() as c:
            grant=Store.get(c,SECURITY_SCOPE,SECURITY_KIND,digest(bearer[7:]))
            require(grant and grant['expires']>time.time() and grant['origin']==origin,'Security connection expired or revoked',401)
            member=c.execute('SELECT u.email,m.role FROM members m JOIN users u ON u.id=m.user WHERE m.user=? AND m.workspace=?',(grant['user'],grant['workspace'])).fetchone()
            require(member and member['role'] in {'owner','analyst','reviewer'},'Assessment permission removed')
        return {**grant,'email':member['email'],'role':member['role']}

    @app.get('/api/companion/security/context')
    def context(session=Depends(security_auth)):
        with store.connect() as c:
            devices=[{key:row[key] for key in ('id','label','targets','allow_posture','allow_updates','seen')} for row in c.execute('SELECT * FROM devices WHERE workspace=? AND expires>?',(session['workspace'],time.time()))]
            import json
            for device in devices:device['targets']=json.loads(device['targets'])
            name=c.execute('SELECT name FROM workspaces WHERE id=?',(session['workspace'],)).fetchone()[0]
        return {'workspace':name,'scan_hosts':sorted(settings.scan_hosts),'devices':devices,'ai_available':bool(settings.groq_key),'local_device':not settings.secure and settings.host in {'localhost','127.0.0.1'}}

    @app.post('/api/companion/security/operations')
    def run(body:OperationRequest,session=Depends(security_auth)):
        throttle('operation:'+session['workspace'],30)
        validate_operation(body,session)
        with store.connect(write=True) as c:operation=queue_operation(c,body,session)
        if body.action not in {'device','posture','updates'} or body.device_id=='local':executor.submit(run_operation,session['workspace'],session['user'],operation['id'],body)
        return {'id':operation['id'],'status':operation['status']}

    @app.get('/api/companion/security/operations/{identifier}')
    def result(identifier:str,session=Depends(security_auth)):
        with store.connect() as c:
            operation=Store.get(c,session['workspace'],'operations',identifier)
            require(operation and operation['created_by']==session['user'],'Operation unavailable',404)
            output={key:operation[key] for key in ('id','action','target','status','error') if key in operation}
            scan=Store.get(c,session['workspace'],'scans',operation.get('scan_id',''))
            output['coverage']=scan.get('limits','') if scan else ''
            job=Store.get(c,session['workspace'],'jobs',operation.get('agent_job',''))
            output['ai_status']=job['status'] if job else None
            output['actions']=[{'title':recommendation['priority_reason'],'steps':recommendation['actions'],'verification':recommendation['verification']} for recommendation in (job or {}).get('plan',{}).get('recommendations',[])[:5]]
            output['summary']=(job or {}).get('plan',{}).get('summary','')
            if job and job['status']=='failed':output['ai_error']='The AI plan failed. No plan was accepted.'
            output['finding_count']=len(scan.get('finding_ids',[])) if scan else None
            ids=set(scan.get('finding_ids',[])) if scan else set()
            output['observations']=[{'title':finding['title'],'severity':finding['severity'],'guidance':RULES[finding['rule']][3]} for finding in Store.all(c,session['workspace'],'findings') if finding['id'] in ids and finding['rule'] in RULES][:5]
        return output

    @app.post('/api/companion/security/operations/{identifier}/cancel')
    def cancel(identifier:str,session=Depends(security_auth)):
        with store.connect(write=True) as c:
            operation=Store.get(c,session['workspace'],'operations',identifier)
            require(operation and operation['created_by']==session['user'],'Operation unavailable',404)
            if operation['status'] in {'queued','running'}:
                operation.update(status='cancelled',finished_at=now(),error='Cancelled from the extension. An in-flight device check may finish locally; its result will be rejected.')
                operation.pop('lease',None);Store.put(c,session['workspace'],'operations',operation)
            job=Store.get(c,session['workspace'],'jobs',operation.get('agent_job',''))
            if job and job['status'] in {'queued','running'}:
                job.update(status='cancelled',finished_at=now());Store.put(c,session['workspace'],'jobs',job)
            Store.event(c,session['workspace'],session['user'],'extension.operation_cancelled',identifier)
        return {'ok':True}

    @app.post('/api/companion/security/revoke')
    def disconnect(session=Depends(security_auth)):
        with store.connect(write=True) as c:
            c.execute('DELETE FROM entities WHERE id=? AND workspace=? AND kind=?',(session['id'],SECURITY_SCOPE,SECURITY_KIND))
            Store.event(c,session['workspace'],session['user'],'extension.security_revoked','extension-disconnect')
        return {'ok':True}

    @app.get('/api/security-connections')
    def connections(session=Depends(auth)):
        with store.connect() as c:return {'connections':[{'id':grant['id'],'expires':grant['expires'],'origin':grant['origin']} for grant in Store.all(c,SECURITY_SCOPE,SECURITY_KIND) if grant['user']==session['user'] and grant['workspace']==session['workspace'] and grant['expires']>time.time()]}

    @app.post('/api/security-connections/{identifier}/revoke')
    def revoke(identifier:str,session=Depends(auth)):
        with store.connect(write=True) as c:
            grant=Store.get(c,SECURITY_SCOPE,SECURITY_KIND,identifier)
            require(grant and grant['user']==session['user'] and grant['workspace']==session['workspace'],'Connection unavailable',404)
            c.execute('DELETE FROM entities WHERE id=? AND workspace=? AND kind=?',(identifier,SECURITY_SCOPE,SECURITY_KIND))
            Store.event(c,session['workspace'],session['user'],'extension.security_revoked','control-room')
        return {'ok':True}
