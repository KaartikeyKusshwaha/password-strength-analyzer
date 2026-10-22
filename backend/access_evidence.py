"""Read-only, vault-scoped verification. No external accounts or website scans."""
import json
import time
from .store import Store, now, uid

CHECKS=(('24h',86400),('7d',7*86400),('30d',30*86400))


def schedule(c,row,clock=time.time):
    existing=Store.all(c,row['workspace'],'access_rechecks')
    if any(item['workflow']==row['id'] for item in existing):return
    at=clock()
    for label,delay in CHECKS:
        Store.put(c,row['workspace'],'access_rechecks',dict(id=uid(),workflow=row['id'],label=label,due=at+delay,status='scheduled',created_at=now()))
    Store.event(c,row['workspace'],row['created_by'],'access_workflow.rechecks_scheduled',row['id'])


def tick(store,clock=time.time):
    # Same scheduler thread, one bounded read-only batch. Rechecks never remove access.
    with store.connect(write=True) as c:
        rows=c.execute("SELECT workspace,data FROM entities WHERE kind='access_rechecks' AND json_extract(data,'$.status')='scheduled' AND json_extract(data,'$.due')<=? ORDER BY json_extract(data,'$.due') LIMIT 100",(clock(),)).fetchall()
        for saved in rows:
            check=json.loads(saved['data']);workspace=saved['workspace']
            row=c.execute('SELECT * FROM workflows WHERE id=? AND workspace=?',(check['workflow'],workspace)).fetchone()
            if not row or row['status']!='complete':
                check.update(status='cancelled',checked_at=now());Store.put(c,workspace,'access_rechecks',check);continue
            plan=json.loads(row['plan']);observations=[]
            for item in plan['vaults']:
                vault=c.execute('SELECT workspace,epoch,rotation_required FROM team_vaults WHERE id=?',(item['vault'],)).fetchone()
                grant=c.execute('SELECT 1 FROM team_grants WHERE vault=? AND user=?',(item['vault'],row['person'])).fetchone() if vault and vault['workspace']==workspace else None
                state='unavailable' if not vault or vault['workspace']!=workspace else 'access_reappeared' if grant else 'rotation_pending' if vault['rotation_required'] or vault['epoch']<=item['epoch'] else 'absent'
                observations.append({'vault':item['vault'],'state':state})
            check.update(status='attention' if any(item['state']!='absent' for item in observations) else 'verified',checked_at=now(),observations=observations)
            Store.put(c,workspace,'access_rechecks',check)
            Store.event(c,workspace,'system:access-recheck','access_workflow.recheck_'+check['status'],row['id']+':'+check['label'])


def report(c,row):
    plan=json.loads(row['plan']);vaults=[]
    for item in plan['vaults']:
        vault=c.execute('SELECT id,name,epoch,rotation_required FROM team_vaults WHERE id=? AND workspace=?',(item['vault'],row['workspace'])).fetchone()
        grant=c.execute('SELECT role,accepted FROM team_grants WHERE vault=? AND user=?',(item['vault'],row['person'])).fetchone() if vault else None
        vaults.append({'id':item['vault'],'name':vault['name'] if vault else None,'current_access':bool(grant) if vault else None,'accepted':bool(grant['accepted']) if grant else None,'epoch':vault['epoch'] if vault else None,'rotation_required':bool(vault['rotation_required']) if vault else None})
    steps=[dict(item) for item in c.execute('SELECT id,position,vault,action,status,attempts,outcome,completed_at FROM workflow_steps WHERE workflow=? ORDER BY position',(row['id'],))]
    targets=[row['id']]+[item['id'] for item in steps]
    audit=[dict(item) for item in c.execute('SELECT seq,at,actor,action,target,digest FROM audit WHERE workspace=? ORDER BY seq',(row['workspace'],)) if item['target'] in targets or item['target'].startswith(row['id']+':')]
    chain=Store.audit(c,row['workspace'])
    integrity={key:chain[key] for key in ('valid','head')}
    return {'format':'sentinelops-vault-offboarding-v1','generated_at':now(),'workflow':row['id'],'client':row['client'],'person':row['person'],'status':row['status'],'dry_run':plan['dry_run'],'vaults':vaults,'steps':steps,'rechecks':sorted([item for item in Store.all(c,row['workspace'],'access_rechecks') if item['workflow']==row['id']],key=lambda item:item['due']),'events':audit,'audit':integrity,
            'limitations':'Evidence of selected SentinelOps vault memberships only. No assertion about website sessions, cached credentials, password changes, external MFA or device posture. Hash-chain integrity is not independent signing; a database administrator can rewrite the chain.'}
