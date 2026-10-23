"""Client-scoped report projection. Explicit allowlists exclude secrets and raw scans."""
import json
import time
from datetime import datetime
from .access_workflows import require,digest
from .store import Store

LIMITS='Point-in-time SentinelOps records and owner-selected check associations, not a security certification. External account access/MFA, copied credentials, website sessions, device return/wiping and actual remediation are not independently verified. Device posture is a helper self-report. A database administrator can rewrite the audit chain; its head and this report digest are not independent signatures.'

def bounded(c,sql,args=(),limit=1000):
    rows=c.execute(sql+' LIMIT '+str(limit+1),args).fetchall()
    require(len(rows)<=limit,'Report scope exceeds its bounded limit. No truncated Proof Pack was generated.')
    return [dict(row) for row in rows]

def collect(c,workspace,client_id,options):
    client=require(c.execute('SELECT id,name FROM clients WHERE id=? AND workspace=?',(client_id,workspace)).fetchone(),'Client unavailable',404)
    vaults=bounded(c,'SELECT v.id,v.name,v.epoch,v.rotation_required FROM client_vaults l JOIN team_vaults v ON v.id=l.vault AND v.workspace=l.workspace WHERE l.workspace=? AND l.client=? ORDER BY v.id',(workspace,client_id))
    access=bounded(c,'SELECT g.user AS person,g.vault,g.role,g.accepted,g.created_at FROM client_vaults l JOIN team_vaults v ON v.id=l.vault AND v.workspace=l.workspace JOIN team_grants g ON g.vault=v.id WHERE l.workspace=? AND l.client=? ORDER BY g.vault,g.user',(workspace,client_id))
    reports=bounded(c,"SELECT id,person,domain,account_label,role,source,state,updated_at FROM access_grants WHERE workspace=? AND client=? AND state!='retired' ORDER BY id",(workspace,client_id))
    workflows=bounded(c,'SELECT id,person,status,plan,created_at,updated_at FROM workflows WHERE workspace=? AND client=? ORDER BY created_at,id',(workspace,client_id),200)
    steps=[]
    for row in workflows:
        row['dry_run']=json.loads(row.pop('plan'))['dry_run']
        if options.include_posture:
            from .offboarding_posture import KIND
            row['posture_snapshot']=Store.get(c,workspace,KIND,row['id'])
        steps.extend({**step,'workflow':row['id']} for step in bounded(c,'SELECT id,vault,action,status,outcome,completed_at FROM workflow_steps WHERE workflow=? ORDER BY position',(row['id'],),60))
    require(len(steps)<=1500,'Too many offboarding steps for one report; no partial history was accepted.')
    people_ids={r['person'] for r in access+reports+workflows};people=[]
    for identifier in sorted(people_ids):
        row=c.execute('SELECT u.id,u.email,u.mfa,m.role FROM users u LEFT JOIN members m ON m.user=u.id AND m.workspace=? WHERE u.id=?',(workspace,identifier)).fetchone()
        people.append({'id':identifier,'email':row['email'] if row else 'Unavailable former account','workspace_role':row['role'] if row else None,'app_mfa_enrolled':bool(row and row['mfa'])})
    debt=bounded(c,'SELECT id,domain,state,updated_at,verified_at,retired_at FROM credential_exposures WHERE workspace=? AND client=? ORDER BY id',(workspace,client_id))
    from .handoffs import evidence as handoff_evidence
    handoffs=[]
    for saved in bounded(c,'SELECT * FROM handoff_records WHERE workspace=? AND client=? ORDER BY created_at,id',(workspace,client_id),200):
        receipt=json.loads(saved['receipt']) if saved['receipt'] else None
        current=handoff_evidence(c,saved)
        row={key:saved[key] for key in ('id','person','recipient','kind','status','updated_at')}
        row['signoff']={k:receipt[k] for k in ('at','actor','evidence_digest','external_access','device_return','device_wipe') if k in receipt} if receipt else None
        row['evidence_changed_since_signoff']=bool(receipt and receipt['evidence_digest']!=current['digest']);row['current_issues']=current['issues']
        handoffs.append(row)
    workflow_ids={row['id'] for row in workflows};rechecks=[]
    for row in c.execute("SELECT data FROM entities WHERE workspace=? AND kind='access_rechecks'",(workspace,)):
        item=json.loads(row[0])
        if item.get('workflow') in workflow_ids:rechecks.append({key:item.get(key) for key in ('id','workflow','label','due','status','checked_at','observations')})
    checks=[]
    for identifier in options.asset_ids:
        asset=require(Store.get(c,workspace,'assets',identifier),'Selected check system is unavailable',404)
        scans=c.execute("SELECT data FROM entities WHERE workspace=? AND kind='scans' AND json_extract(data,'$.asset_id')=? ORDER BY rowid DESC LIMIT 1",(workspace,identifier)).fetchall()
        scan=json.loads(scans[0][0]) if scans else None
        counts={}
        if scan:
            for finding_id in scan.get('finding_ids',[]):
                finding=Store.get(c,workspace,'findings',finding_id)
                if finding and finding.get('scan_id')==scan['id']:
                    severity=finding.get('severity','unknown');severity=severity if severity in {'critical','high','medium','low','info'} else 'unknown';counts[severity]=counts.get(severity,0)+1
        checks.append({'asset':identifier,'name':asset['name'],'association':'Owner-selected client association; not independently verified.','kind':scan['kind'] if scan else None,'scan':scan['id'] if scan else None,'at':scan['at'] if scan else None,'status':scan['status'] if scan else 'unassessed','finding_counts':counts})
    posture=[]
    if options.include_posture:
        for person in people:
            devices=bounded(c,'SELECT id,label,expires,seen FROM devices WHERE workspace=? AND user=? ORDER BY id',(workspace,person['id']),100)
            for device in devices:
                assets=c.execute("SELECT id FROM entities WHERE workspace=? AND kind='assets' AND json_extract(data,'$.device_id')=?",(workspace,device['id'])).fetchall()
                candidate=[]
                for asset in assets:
                    rows=c.execute("SELECT data FROM entities WHERE workspace=? AND kind='scans' AND json_extract(data,'$.asset_id')=? AND json_extract(data,'$.kind')='posture' ORDER BY rowid DESC LIMIT 1",(workspace,asset['id'])).fetchall()
                    if rows:candidate.append(json.loads(rows[0][0]))
                latest=max(candidate,key=lambda v:v['at']) if candidate else None
                raw=(latest or {}).get('posture',{})
                try:age=time.time()-datetime.fromisoformat(latest['at']).timestamp() if latest else None
                except (ValueError,TypeError):age=None
                posture.append({'person':person['id'],'device':device['id'],'label':device['label'],'connection_expired':device['expires']<=time.time(),'last_seen':device['seen'],'scan':latest['id'] if latest else None,'at':latest['at'] if latest else None,'freshness':'recorded_within_24h' if age is not None and 0<=age<=86400 else 'stale_or_unavailable','platform':raw.get('platform','unknown'),'checks':[{k:item.get(k) for k in ('id','state','reason')} for item in raw.get('checks',[]) if item.get('id') in {'firewall_domain','firewall_private','firewall_public','defender','system_disk','application_firewall','filevault','gatekeeper'}],'assessment':'Helper self-report; not independent attestation.'})
    require(len(posture)<=200,'Too many selected staff devices; no truncated posture summary was generated.')
    chain=Store.audit(c,workspace)
    targets={client_id}|{v['id'] for v in vaults}|{v['id'] for v in workflows+steps+handoffs}|{r['id'] for r in reports+debt}
    events=[{key:event[key] for key in ('seq','at','action','target','digest')} for event in chain['events'] if event['target'] in targets or any(event['target'].startswith(w['id']+':') for w in workflows)]
    require(len(events)<=3000,'Audit excerpt exceeds the report limit. No truncated report was generated.')
    value={'format':'sentinelops-client-proof-v1','brand':options.brand,'client':dict(client),'vaults':vaults,'access':access,'reported_accounts':reports,'people':people,'offboarding':workflows,'steps':steps,'rechecks':sorted(rechecks,key=lambda r:r['due']),'debt':debt,'handoffs':handoffs,'checks':checks,'posture':posture,'posture_included':options.include_posture,'audit':{'valid':chain['valid'],'head':chain['head'],'events':events,'scope':'Client-related excerpt; other-client events omitted. Chain verification is server-reported, not independently signed.'},'limitations':LIMITS}
    return value,digest(value)
