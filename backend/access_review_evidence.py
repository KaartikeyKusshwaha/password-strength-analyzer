"""Deterministic access metadata evidence; no vault payloads or external claims."""
import datetime
from .access_workflows import digest

RULES={
 'access_orphan':('high','Check access without a current workspace member','Review the recorded membership with the client owner. Prepare a separately approved removal if it is no longer needed.'),
 'access_rotation':('high','Finish pending shared-vault key rotation','Unlock the affected vault in the extension and finish the existing approved rotation. Revocation alone does not replace a cached key.'),
 'access_debt':('medium','Reduce a recorded shared-password exposure','Review delegated access, stage a supported password change and verify the result before retiring the recorded shared login.'),
 'access_stale':('low','Review a stale account report','Ask the account owner whether the reported access is still needed. No recent observation is not evidence of inactivity or removal.'),
 'access_new':('low','Review recently recorded access','Confirm the client, person and role. An invitation or account observation does not establish a successful external login.'),
}

def collect(c,workspace,since,at,exclude_keys=()):
    """Bind every source row, including omitted candidates, to one review digest."""
    queries={
      'members':("SELECT m.user,m.role FROM members m WHERE m.workspace=? ORDER BY m.user",),
      'clients':("SELECT id FROM clients WHERE workspace=? ORDER BY id",),
      'vaults':("SELECT l.client,v.id,v.owner,v.epoch,v.rotation_required FROM client_vaults l JOIN team_vaults v ON v.id=l.vault AND v.workspace=l.workspace WHERE l.workspace=? ORDER BY l.client,v.id",),
      'grants':("SELECT l.client,g.vault,g.user,g.role,g.accepted,g.created_at FROM client_vaults l JOIN team_vaults v ON v.id=l.vault AND v.workspace=l.workspace JOIN team_grants g ON g.vault=v.id WHERE l.workspace=? ORDER BY l.client,g.vault,g.user",),
      'reports':("SELECT id,client,person,source,state,role,created_at,updated_at FROM access_grants WHERE workspace=? ORDER BY id",),
      'debt':("SELECT id,client,vault,state,updated_at FROM credential_exposures WHERE workspace=? ORDER BY id",),
    }
    source={}
    for key,(sql,) in queries.items():
        rows=c.execute(sql+' LIMIT 10001',(workspace,)).fetchall()
        if len(rows)>10000:raise ValueError('Access review source exceeds its bounded limit. No partial review was accepted.')
        source[key]=[dict(row) for row in rows]
    members={row['user'] for row in source['members']};items=[]
    def add(rule,key,client,person=None,system=None,detail=None):
        items.append(dict(rule=rule,key=key,client=client,person=person,system=system,detail=detail))
    def timestamp(value):
        try:return datetime.datetime.fromisoformat(value).timestamp()
        except (TypeError,ValueError):return None
    for row in source['grants']:
        key='vault:'+row['client']+':'+row['vault']+':'+row['user']
        if row['user'] not in members:add('access_orphan',key,row['client'],row['user'],row['vault'],'Shared-vault membership; workspace member absent.')
        elif (timestamp(row['created_at']) or 0)>=since:add('access_new',key,row['client'],row['user'],row['vault'],'Accepted vault grant.' if row['accepted'] else 'Pending vault invitation.')
    for row in source['vaults']:
        if row['rotation_required']:add('access_rotation','rotation:'+row['client']+':'+row['id'],row['client'],system=row['id'],detail='Sharing key rotation is recorded as required.')
    for row in source['reports']:
        if row['state']=='retired':continue
        key='report:'+row['id']
        if row['person'] not in members:add('access_orphan',key,row['client'],row['person'],detail='Unverified account report; workspace member absent.')
        elif timestamp(row['updated_at']) is None or timestamp(row['updated_at'])<at-30*86400:add('access_stale',key,row['client'],row['person'],detail='No account observation or report update recorded in 30 days; actual usage is unknown.')
        elif (timestamp(row['created_at']) or 0)>=since:add('access_new',key,row['client'],row['person'],detail='New '+row['source']+' account report; external access is unverified.')
    for row in source['debt']:
        if row['state']!='retired':add('access_debt','debt:'+row['id'],row['client'],system=row['vault'],detail='Owner-reported shared login debt: '+row['state']+'.')
    rank={rule:index for index,rule in enumerate(RULES)}
    items.sort(key=lambda item:(rank[item['rule']],item['key']))
    remaining=[item for item in items if item['key'] not in exclude_keys]
    return {'digest':digest(source),'items':remaining[:20],'candidate_count':len(items),'reviewed_before':len(items)-len(remaining),'omitted':max(0,len(remaining)-20),'since':since,'at':at,'source_counts':{key:len(rows) for key,rows in source.items()}}

def current(c,workspace,review):
    return collect(c,workspace,review['evidence']['since'],review['evidence']['at'])['digest']==review['evidence']['digest']

def finding(review,item):
    severity,title,guidance=RULES[item['rule']]
    identifier=digest({'review':review['id'],'key':item['key']})[:24]
    return dict(id=identifier,rule=item['rule'],title=title,severity=severity,confidence='recorded_metadata',status='open',kind='access_review',label='Client access metadata',asset_id=None,scan_id=review['id'],fingerprint=digest(item),access_review=review['id'],access_item=item,created_at=review['created_at'],guidance=guidance)
