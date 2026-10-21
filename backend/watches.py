"""Opt-in exact dependency watches, serialized checks and durable in-app alerts."""
import json
import re
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from types import SimpleNamespace
from typing import Literal

from fastapi import Depends,HTTPException
from pydantic import BaseModel,ConfigDict,Field,SecretStr

from . import scanner
from .dependency_inventory import DependencyFormat,inventory,apply_coverage
from .store import Store,canonical,now,uid


class Body(BaseModel):
    model_config=ConfigDict(extra='forbid',str_strip_whitespace=True)


class Configuration(Body):
    name: str=Field(min_length=2,max_length=70)
    format: DependencyFormat
    dependency_selection: list[str] | None = Field(default=None,max_length=500)
    content: SecretStr
    interval_hours: Literal[6,12,24,72,168]=24
    enabled: bool=False
    create_tasks: bool=False
    consent: bool=False


class Toggle(Body):
    enabled: bool
    revision: int=Field(ge=1)
    consent: bool=False


class Update(Configuration):
    revision: int=Field(ge=1)


class Revision(Body):
    revision: int=Field(ge=1)


class ReadNotifications(Body):
    ids: list[str]=Field(min_length=1,max_length=100)


def require(value,message='Watch not found',status=404):
    if not value:raise HTTPException(status,message)
    return value


def scope_of(body):
    try:scope=inventory(body.content.get_secret_value(),body.format,body.dependency_selection)
    except ValueError as error:raise HTTPException(422,str(error))
    require(scope['packages'] and (not scope['skipped'] or body.dependency_selection is not None),'Preview and approve an exact subset when records are unsupported; at least one exact version is required.',422)
    require(body.format in {'requirements','package-json'} or body.dependency_selection is not None,'Preview the lockfile and approve its selected package versions first.',422)
    scope['packages']=sorted([dict(p,line=0) for p in scope['packages']],key=lambda p:(p['ecosystem'],p['name'],p['version']))
    return scope


class WatchService:
    def __init__(self,store,persist_scan):
        self.store=store;self.persist_scan=persist_scan;self.transport=None;self.clock=time.time
        self.executor=ThreadPoolExecutor(max_workers=1,thread_name_prefix='sentinel-watch')
        self.stop_event=threading.Event();self.thread=None;self.scheduler_error=False

    def notification(self,c,workspace,watch,run,kind,finding_ids=None,count=0):
        value={'id':uid(),'watch_id':watch['id'],'watch_name':watch['name'],'run_id':run,'kind':kind,'at':now(),'finding_ids':(finding_ids or [])[:20],'count':count}
        Store.put(c,workspace,'notifications',value)
        # Keep at most 500 workspace alerts; acknowledgement rows follow retention.
        for old in Store.all(c,workspace,'notifications')[500:]:
            c.execute("DELETE FROM entities WHERE workspace=? AND kind='notifications' AND id=?",(workspace,old['id']))
            c.execute('DELETE FROM notification_reads WHERE notification=?',(old['id'],))

    def permission(self,c,workspace,user):
        row=c.execute('SELECT role FROM members WHERE workspace=? AND user=?',(workspace,user)).fetchone()
        return row and row['role'] in {'owner','analyst','reviewer'}

    def stop_watch(self,c,workspace,watch,reason,status='interrupted'):
        if watch.get('active_run'):
            run=Store.get(c,workspace,'watch_runs',watch['active_run'])
            if run and run['status'] in {'queued','running'}:
                run.update(status=status,error=reason,finished_at=now());Store.put(c,workspace,'watch_runs',run)
        watch.update(enabled=False,next_due=None,active_run=None,revision=watch['revision']+1,last_status=status)
        Store.put(c,workspace,'watches',watch)

    def recover(self):
        with self.store.connect(write=True) as c:
            for row in c.execute("SELECT workspace,data FROM entities WHERE kind='watches'").fetchall():
                watch=json.loads(row['data'])
                if watch.get('active_run'):
                    self.stop_watch(c,row['workspace'],watch,'Server restarted during a watch. Resume explicitly; the interrupted request was not replayed.')
                    self.notification(c,row['workspace'],watch,None,'paused')

    def start(self):
        self.recover()
        def loop():
            while not self.stop_event.wait(30):
                try:self.tick();self.scheduler_error=False
                except Exception:self.scheduler_error=True
        self.thread=threading.Thread(target=loop,name='sentinel-watch-scheduler',daemon=True);self.thread.start()

    def stop(self):
        self.stop_event.set()
        if self.thread:self.thread.join(timeout=2)
        self.executor.shutdown(wait=True,cancel_futures=True)

    def queue_locked(self,c,workspace,watch,actor,scheduled):
        require(self.permission(c,workspace,actor),'Watch requester must remain a contributor',403)
        require(not watch.get('archived'),'Archived watches cannot run',409)
        require(not watch.get('active_run'),'This watch already has an active check',409)
        # One persisted active watch run across this installation, not one per click.
        require(not c.execute("SELECT 1 FROM entities WHERE kind='watch_runs' AND json_extract(data,'$.status') IN ('queued','running') LIMIT 1").fetchone(),'The watch worker is busy. Retry after the current check finishes.',409)
        identifier=uid();run={'id':identifier,'watch_id':watch['id'],'revision':watch['revision'],'actor':actor,'status':'queued','scheduled':scheduled,'created_at':now(),'lease_expires':self.clock()+300}
        watch.update(active_run=identifier,next_due=self.clock()+watch['interval_hours']*3600 if watch['enabled'] else None)
        Store.put(c,workspace,'watches',watch);Store.put(c,workspace,'watch_runs',run)
        Store.event(c,workspace,actor,'watch.check_queued',identifier)
        return identifier

    def tick(self):
        chosen=None
        with self.store.connect(write=True) as c:
            rows=c.execute("SELECT workspace,data FROM entities WHERE kind='watches'").fetchall()
            watches=[(row['workspace'],json.loads(row['data'])) for row in rows]
            for workspace,watch in watches:
                run=Store.get(c,workspace,'watch_runs',watch.get('active_run','')) if watch.get('active_run') else None
                if run and run['status'] in {'queued','running'} and run['lease_expires']<=self.clock():
                    self.stop_watch(c,workspace,watch,'Watch lease expired. Resume explicitly; no result was inferred.');self.notification(c,workspace,watch,None,'paused')
                if watch['enabled'] and not self.permission(c,workspace,watch['created_by']):
                    self.stop_watch(c,workspace,watch,'Watch owner access was removed. A workspace owner must take over explicitly.','cancelled');self.notification(c,workspace,watch,None,'paused')
            if c.execute("SELECT 1 FROM entities WHERE kind='watch_runs' AND json_extract(data,'$.status') IN ('queued','running') LIMIT 1").fetchone():return None
            due=sorted([(workspace,watch) for workspace,watch in watches if watch['enabled'] and not watch.get('active_run') and watch.get('next_due') is not None and watch['next_due']<=self.clock()],key=lambda pair:pair[1]['next_due'])
            if due:
                workspace,watch=due[0];chosen=(workspace,self.queue_locked(c,workspace,watch,watch['created_by'],True))
        if chosen:self.executor.submit(self.run,*chosen)
        return chosen

    def run(self,workspace,identifier):
        try:
            with self.store.connect(write=True) as c:
                run=Store.get(c,workspace,'watch_runs',identifier)
                if not run or run['status']!='queued':return
                watch=Store.get(c,workspace,'watches',run['watch_id'])
                if not watch or watch.get('active_run')!=identifier or watch['revision']!=run['revision']:
                    run.update(status='cancelled',finished_at=now());Store.put(c,workspace,'watch_runs',run);return
                if run['lease_expires']<=self.clock():
                    self.stop_watch(c,workspace,watch,'Watch lease expired before execution. Resume explicitly.');self.notification(c,workspace,watch,identifier,'paused');return
                if not self.permission(c,workspace,run['actor']) or not self.permission(c,workspace,watch['created_by']):
                    self.stop_watch(c,workspace,watch,'Watch permission removed; explicit owner takeover required.','cancelled');self.notification(c,workspace,watch,identifier,'paused');return
                run.update(status='running',started_at=now());Store.put(c,workspace,'watch_runs',run)
            result=scanner.scan_watch(watch['packages'],self.transport)
            if watch.get('dependency_inventory'):apply_coverage(result,{'coverage':watch['dependency_inventory'],'skipped':[]})
            with self.store.connect(write=True) as c:
                current=Store.get(c,workspace,'watches',watch['id']);run=Store.get(c,workspace,'watch_runs',identifier)
                if not current or current.get('active_run')!=identifier or current['revision']!=watch['revision'] or not run or run['status']!='running':return
                if run['lease_expires']<=self.clock() or not self.permission(c,workspace,run['actor']) or not self.permission(c,workspace,current['created_by']):
                    self.stop_watch(c,workspace,current,'Watch permission or lease expired. Resume explicitly.');self.notification(c,workspace,current,identifier,'paused');return
                asset=Store.get(c,workspace,'assets',current['asset_id']);require(asset,'Registered watch asset is unavailable',409)
                scan=self.persist_scan(c,workspace,run['actor'],asset,SimpleNamespace(kind='dependencies',label='Dependency watch '+current['id']),result)
                seen=set(current.get('observed',[]));found=set(scan['finding_ids']);fresh=found-seen
                if fresh:self.notification(c,workspace,current,identifier,'advisory',sorted(fresh),len(fresh))
                if scan['status']=='partial' and current.get('last_status')!='partial':self.notification(c,workspace,current,identifier,'coverage_lost')
                if scan['status']=='complete' and current.get('last_status') in {'partial','failed'}:self.notification(c,workspace,current,identifier,'coverage_restored')
                tasks=[]
                if current['create_tasks']:
                    existing={task['finding_id'] for task in Store.all(c,workspace,'tasks') if task['status']!='resolved'}
                    for finding_id in sorted(fresh-existing):
                        finding=Store.get(c,workspace,'findings',finding_id)
                        task={'id':uid(),'finding_id':finding_id,'assignee':current['created_by'],'due':'','title':finding['title'],'status':'open','created_by':run['actor'],'created_at':now(),'history':[],'watch_id':current['id']}
                        Store.put(c,workspace,'tasks',task);tasks.append(task['id']);Store.event(c,workspace,run['actor'],'watch.task_created',task['id'])
                current.update(active_run=None,last_status=scan['status'],last_checked=now(),last_scan=scan['id'],observed=sorted(found if scan['status']=='complete' else seen|found))
                run.update(status=scan['status'],finished_at=now(),scan_id=scan['id'],checked=len(scan['checked']),total=len(current['packages']),new_matches=len(fresh),tasks=tasks,error=scan.get('error'),advisory_details=scan.get('advisory_details'),dependency_inventory=scan.get('dependency_inventory'))
                Store.put(c,workspace,'watches',current);Store.put(c,workspace,'watch_runs',run);Store.event(c,workspace,run['actor'],'watch.check_finished',identifier)
                for old in [r for r in Store.all(c,workspace,'watch_runs') if r['watch_id']==current['id']][100:]:
                    c.execute("DELETE FROM entities WHERE id=? AND workspace=? AND kind='watch_runs'",(old['id'],workspace))
        except Exception:
            with self.store.connect(write=True) as c:
                run=Store.get(c,workspace,'watch_runs',identifier)
                if not run or run['status'] not in {'queued','running'}:return
                watch=Store.get(c,workspace,'watches',run['watch_id'])
                run.update(status='failed',finished_at=now(),error='OSV watch could not finish. No complete coverage was inferred. Check access and retry explicitly.');Store.put(c,workspace,'watch_runs',run)
                if watch and watch.get('active_run')==identifier:
                    if watch.get('last_status')!='failed':self.notification(c,workspace,watch,identifier,'coverage_lost')
                    watch.update(active_run=None,last_status='failed');Store.put(c,workspace,'watches',watch)


def register(app,store,auth,writable,throttle,persist_scan):
    service=WatchService(store,persist_scan)
    def managed(c,session,identifier):
        watch=require(Store.get(c,session['workspace'],'watches',identifier))
        require(session['role']=='owner' or watch['created_by']==session['user'],'Only its creator or workspace owner can manage this watch',403)
        return watch

    @app.get('/api/watches')
    def watches(session=Depends(auth)):
        with store.connect() as c:
            return {'watches':Store.all(c,session['workspace'],'watches'),'runs':Store.all(c,session['workspace'],'watch_runs')[:100],'scheduler_error':service.scheduler_error}

    @app.post('/api/watches')
    def create_watch(body: Configuration,session=Depends(auth)):
        writable(session);throttle('watch-config:'+session['user'],15)
        require(body.consent,'Approve storing package metadata and sending exact names/versions to OSV',422)
        scope=scope_of(body);packages=scope['packages']
        with store.connect(write=True) as c:
            require(sum(not w.get('archived') for w in Store.all(c,session['workspace'],'watches'))<20,'This workspace supports up to 20 active watches',409)
            identifier=uid();asset={'id':uid(),'name':body.name,'kind':'application','owner':session['email'],'environment':'development','criticality':'medium','hostname':'','authorized':True,'created_at':now(),'watch_id':identifier}
            Store.put(c,session['workspace'],'assets',asset)
            value={'id':identifier,'asset_id':asset['id'],'created_by':session['user'],'name':body.name,'format':body.format,'packages':packages,'dependency_inventory':scope['coverage'],'interval_hours':body.interval_hours,'enabled':body.enabled,'create_tasks':body.create_tasks,'revision':1,'next_due':service.clock()+body.interval_hours*3600 if body.enabled else None,'active_run':None,'last_status':'not_checked','observed':[],'created_at':now()}
            Store.put(c,session['workspace'],'watches',value);Store.event(c,session['workspace'],session['user'],'watch.created',identifier)
        return value

    @app.post('/api/watches/{identifier}/schedule')
    def schedule_watch(identifier: str,body: Toggle,session=Depends(auth)):
        writable(session)
        require(not body.enabled or body.consent,'Approve scheduled OSV checks before enabling',422)
        with store.connect(write=True) as c:
            watch=managed(c,session,identifier);require(watch['revision']==body.revision,'Watch changed; reload before editing',409)
            require(not watch.get('archived'),'Archived watches cannot be resumed',409)
            service.stop_watch(c,session['workspace'],watch,'Watch schedule changed; any active request result was cancelled.','cancelled')
            watch.update(enabled=body.enabled,created_by=session['user'],next_due=service.clock()+watch['interval_hours']*3600 if body.enabled else None,last_status='scheduled' if body.enabled else 'paused')
            Store.put(c,session['workspace'],'watches',watch);Store.event(c,session['workspace'],session['user'],'watch.schedule_updated',identifier)
        return watch

    @app.post('/api/watches/{identifier}/update')
    def update_watch(identifier: str,body: Update,session=Depends(auth)):
        writable(session);throttle('watch-config:'+session['user'],15)
        require(body.consent,'Approve storing package metadata and sending exact names/versions to OSV',422)
        scope=scope_of(body);packages=scope['packages']
        with store.connect(write=True) as c:
            watch=managed(c,session,identifier);require(watch['revision']==body.revision,'Watch changed; reload before editing',409)
            require(not watch.get('archived'),'Archived watches cannot be edited',409)
            service.stop_watch(c,session['workspace'],watch,'Watch configuration changed; the old result was cancelled.','cancelled')
            if packages!=watch['packages']:watch['observed']=[]
            watch.update(name=body.name,format=body.format,packages=packages,dependency_inventory=scope['coverage'],interval_hours=body.interval_hours,enabled=body.enabled,create_tasks=body.create_tasks,created_by=session['user'],next_due=service.clock()+body.interval_hours*3600 if body.enabled else None,last_status='not_checked')
            Store.put(c,session['workspace'],'watches',watch)
            asset=Store.get(c,session['workspace'],'assets',watch['asset_id'])
            if asset:asset['name']=body.name;Store.put(c,session['workspace'],'assets',asset)
            Store.event(c,session['workspace'],session['user'],'watch.updated',identifier)
        return watch

    @app.post('/api/watches/{identifier}/archive')
    def archive_watch(identifier: str,body: Revision,session=Depends(auth)):
        writable(session)
        with store.connect(write=True) as c:
            watch=managed(c,session,identifier);require(watch['revision']==body.revision,'Watch changed; reload before editing',409)
            service.stop_watch(c,session['workspace'],watch,'Watch archived; pending results cancelled.','cancelled')
            watch.update(archived=True,last_status='archived');Store.put(c,session['workspace'],'watches',watch)
            Store.event(c,session['workspace'],session['user'],'watch.archived',identifier)
        return watch

    @app.post('/api/watches/{identifier}/check')
    def check_watch(identifier: str,session=Depends(auth)):
        writable(session);throttle('watch-check:'+session['user'],10)
        with store.connect(write=True) as c:
            watch=managed(c,session,identifier);run=service.queue_locked(c,session['workspace'],watch,session['user'],False)
        service.executor.submit(service.run,session['workspace'],run)
        return {'id':run,'status':'queued'}

    @app.get('/api/notifications')
    def notifications(session=Depends(auth)):
        with store.connect() as c:
            read={row[0] for row in c.execute("SELECT r.notification FROM notification_reads r JOIN entities e ON e.id=r.notification WHERE r.user=? AND e.workspace=? AND e.kind='notifications'",(session['user'],session['workspace']))}
            values=[{**row,'read':row['id'] in read} for row in Store.all(c,session['workspace'],'notifications')]
        return {'notifications':values[:100],'unread':sum(not row['read'] for row in values)}

    @app.post('/api/notifications/read')
    def read_notifications(body: ReadNotifications,session=Depends(auth)):
        with store.connect(write=True) as c:
            for identifier in body.ids:
                require(Store.get(c,session['workspace'],'notifications',identifier),'Notification not found')
                c.execute('INSERT OR IGNORE INTO notification_reads VALUES(?,?,?)',(identifier,session['user'],now()))
        return {'ok':True}

    return service
