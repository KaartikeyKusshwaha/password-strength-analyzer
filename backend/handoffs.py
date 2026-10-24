"""Metadata handoff coordination; effects stay in existing offboarding/ownership flows."""
import json
import time
from typing import Literal
from fastapi import Depends,HTTPException
from pydantic import BaseModel,ConfigDict,Field,SecretStr
from .access_workflows import digest,owner
from .security import verify_password,consume_factor
from .store import Store,canonical,now,uid

ID=r'^[a-f0-9]{24}$'
LIMITS='Vault access and owner attestations only. External SaaS access, copied credentials, device return and wiping are not independently verified. No access is granted or revoked by a handoff record.'
TERMINAL={'complete','complete_with_exceptions','cancelled'}


def require(value,message,status=409):
    if not value:raise HTTPException(status,message)
    return value


class Draft(BaseModel):
    model_config=ConfigDict(extra='forbid')
    client_id:str=Field(pattern=ID)
    person_id:str=Field(pattern=ID)
    recipient_id:str=Field(pattern=ID)
    kind:Literal['person_handoff','client_offboard']='person_handoff'


class Confirm(BaseModel):
    model_config=ConfigDict(extra='forbid')
    digest:str=Field(pattern=r'^[a-f0-9]{64}$')
    confirmed:bool=False
    password:SecretStr=Field(max_length=256)
    code:str=Field(max_length=80)


class OwnerPromotion(BaseModel):
    model_config=ConfigDict(extra='forbid')
    confirmed:bool=False
    password:SecretStr=Field(max_length=256)
    code:str=Field(max_length=80)


class Signoff(Confirm):
    external_access:Literal['not_applicable','reviewed_unverified','unresolved']
    device_return:Literal['not_applicable','reported_complete','unresolved']
    device_wipe:Literal['not_applicable','reported_complete','unresolved']


class Link(BaseModel):
    model_config=ConfigDict(extra='forbid')
    workflow_id:str=Field(pattern=ID)


def scope(c,workspace,client,person,recipient,actor,kind):
    require(c.execute('SELECT 1 FROM clients WHERE id=? AND workspace=?',(client,workspace)).fetchone(),'Client unavailable',404)
    departing=require(c.execute('SELECT role FROM members WHERE workspace=? AND user=?',(workspace,person)).fetchone(),'Outgoing person unavailable',404)
    require(recipient!=person and recipient!=actor,'Choose a separate receiving owner.')
    require(owner(c,workspace,recipient),'Receiving workspace owner required.',403)
    if kind=='person_handoff':require(departing['role']!='owner' and person!=actor,'Transfer owner roles separately before a person handoff.')
    else:require(person==actor,'A client offboard must transfer the preparing vault owner out of access.')
    rows=c.execute('SELECT v.id,v.owner,v.epoch,v.rotation_required FROM client_vaults l JOIN team_vaults v ON v.id=l.vault AND v.workspace=l.workspace WHERE l.client=? AND l.workspace=? ORDER BY v.id',(client,workspace)).fetchall()
    require(0<len(rows)<=20,'Link 1–20 shared vaults before preparing a handoff.')
    require(all(v['owner']==actor for v in rows),'The preparing owner must own every linked vault. Complete any earlier ownership changes before planning.')
    return {'version':1,'client':client,'person':person,'recipient':recipient,'kind':kind,'vaults':[dict(v) for v in rows]}


def fresh_factor(c,session,body,cipher):
    user=require(owner(c,session['workspace'],session['user']),'Current owner access required.',403)
    require(user['mfa'],'Account MFA required.',403)
    require(verify_password(body.password.get_secret_value(),user['password']) and consume_factor(c,user,body.code,cipher),'Current password and unused MFA/recovery code required.',401)


def evidence(c,row):
    plan=json.loads(row['plan']);vaults=[];issues=[]
    linked=[r['vault'] for r in c.execute('SELECT vault FROM client_vaults WHERE workspace=? AND client=? ORDER BY vault',(row['workspace'],row['client']))]
    if linked!=[v['id'] for v in plan['vaults']]:issues.append('client_vault_scope_changed')
    for item in plan['vaults']:
        vault=c.execute('SELECT owner,epoch,rotation_required FROM team_vaults WHERE workspace=? AND id=?',(row['workspace'],item['id'])).fetchone()
        outgoing=c.execute('SELECT role,accepted FROM team_grants WHERE vault=? AND user=?',(item['id'],row['person'])).fetchone()
        incoming=c.execute('SELECT role,accepted FROM team_grants WHERE vault=? AND user=?',(item['id'],row['recipient'])).fetchone()
        observed={'id':item['id'],'exists':bool(vault),'outgoing_absent':not outgoing,'recipient_accepted':bool(incoming and incoming['accepted']),'recipient_owner':bool(vault and vault['owner']==row['recipient']),'key_rotated':bool(vault and vault['epoch']>item['epoch'] and not vault['rotation_required'])}
        if not all((observed['exists'],observed['outgoing_absent'],observed['recipient_accepted'],observed['key_rotated'])):issues.append('vault_handoff_incomplete:'+item['id'])
        if row['kind']=='client_offboard' and not observed['recipient_owner']:issues.append('ownership_transfer_incomplete:'+item['id'])
        vaults.append(observed)
    workflow=None
    if row['workflow']:
        found=c.execute('SELECT * FROM workflows WHERE workspace=? AND id=?',(row['workspace'],row['workflow'])).fetchone()
        if found:
            work=json.loads(found['plan']);workflow={'id':found['id'],'status':found['status'],'dry_run':work['dry_run']}
            if found['client']!=row['client'] or found['person']!=row['person'] or {v['vault'] for v in work['vaults']}!={v['id'] for v in plan['vaults']} or work['dry_run'] or found['status']!='complete':issues.append('linked_offboarding_incomplete')
        else:issues.append('linked_offboarding_missing')
    if row['kind']=='person_handoff' and not workflow:issues.append('completed_offboarding_required')
    reports=[dict(r) for r in c.execute("SELECT id,source,state,updated_at FROM access_grants WHERE workspace=? AND client=? AND person=? AND state!='retired' ORDER BY id",(row['workspace'],row['client'],row['person']))]
    debt=[dict(r) for r in c.execute("SELECT id,state,updated_at FROM credential_exposures WHERE workspace=? AND client=? AND state!='retired' ORDER BY id",(row['workspace'],row['client']))]
    value={'handoff':row['id'],'plan_digest':row['plan_digest'],'vaults':vaults,'workflow':workflow,'issues':issues,'reported_external_access':reports,'active_shared_password_debt':debt,'limitations':LIMITS}
    return {**value,'digest':digest(value)}


def view(c,row):
    result={key:row[key] for key in ('id','client','person','recipient','created_by','kind','status','workflow','created_at','updated_at','plan_digest')}
    result.update(plan=json.loads(row['plan']),approval=json.loads(row['approval']) if row['approval'] else None,receipt=json.loads(row['receipt']) if row['receipt'] else None,evidence=evidence(c,row))
    if result['receipt']:result['evidence_changed_since_signoff']=result['receipt']['evidence_digest']!=result['evidence']['digest']
    return result


def register(app,store,auth,access_auth,throttle,cipher):
    def authorized(session):require(session['role']=='owner','Workspace owner access required.',403)
    def get(c,session,identifier):return require(c.execute('SELECT * FROM handoff_records WHERE id=? AND workspace=?',(identifier,session['workspace'])).fetchone(),'Handoff unavailable.',404)

    def listing(session):
        authorized(session)
        with store.connect() as c:return {'handoffs':[view(c,row) for row in c.execute('SELECT * FROM handoff_records WHERE workspace=? ORDER BY created_at DESC LIMIT 100',(session['workspace'],))]}

    def create(body,session):
        authorized(session);throttle('handoff-plan:'+session['user'],20)
        with store.connect(write=True) as c:
            require(c.execute('SELECT count(*) FROM handoff_records WHERE workspace=?',(session['workspace'],)).fetchone()[0]<1000,'Handoff history limit reached.')
            plan=scope(c,session['workspace'],body.client_id,body.person_id,body.recipient_id,session['user'],body.kind);identifier=uid();at=now()
            c.execute('INSERT INTO handoff_records VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)',(identifier,session['workspace'],body.client_id,body.person_id,body.recipient_id,session['user'],body.kind,'awaiting_approval',canonical(plan),digest(plan),None,None,None,at,at))
            Store.event(c,session['workspace'],session['user'],'handoff.planned',identifier)
            return view(c,get(c,session,identifier))

    def approve(identifier,body,session):
        authorized(session);throttle('handoff-factor:'+session['user'],8)
        with store.connect(write=True) as c:
            row=get(c,session,identifier)
            require(row['created_by']==session['user'] and row['status']=='awaiting_approval' and body.confirmed,'Handoff cannot be approved.')
            current=scope(c,row['workspace'],row['client'],row['person'],row['recipient'],session['user'],row['kind'])
            require(body.digest==row['plan_digest']==digest(current),'Handoff scope changed; prepare a new record.')
            fresh_factor(c,session,body,cipher)
            c.execute("UPDATE handoff_records SET status='awaiting_signoff',approval=?,updated_at=? WHERE id=?",(canonical({'actor':session['user'],'at':now(),'expires':time.time()+7*86400,'digest':body.digest}),now(),identifier))
            Store.event(c,session['workspace'],session['user'],'handoff.approved',identifier)
        return {'ok':True,'note':'Coordinate the existing offboarding and signed ownership flows. This approval does not grant permission to change external accounts.'}

    def link(identifier,body,session):
        authorized(session)
        with store.connect(write=True) as c:
            row=get(c,session,identifier);require(row['created_by']==session['user'] and row['status']=='awaiting_signoff','Only the preparing owner can link active work.')
            work=require(c.execute('SELECT * FROM workflows WHERE workspace=? AND id=?',(row['workspace'],body.workflow_id)).fetchone(),'Workflow unavailable',404)
            require(work['client']==row['client'] and work['person']==row['person'],'Workflow scope differs.')
            c.execute('UPDATE handoff_records SET workflow=?,updated_at=? WHERE id=?',(body.workflow_id,now(),identifier));Store.event(c,session['workspace'],session['user'],'handoff.workflow_linked',identifier)
        return {'ok':True}

    def signoff(identifier,body,session):
        authorized(session);throttle('handoff-factor:'+session['user'],8)
        with store.connect(write=True) as c:
            row=get(c,session,identifier);approval=json.loads(row['approval']) if row['approval'] else None
            require(row['recipient']==session['user'] and row['status']=='awaiting_signoff' and body.confirmed,'Receiving owner sign-off required.',403)
            approving=owner(c,row['workspace'],row['created_by'])
            require(approval and approval['expires']>time.time() and approving and approving['mfa'] and approval['digest']==row['plan_digest']==digest(json.loads(row['plan'])),'Approval expired or lost. Prepare a new handoff.')
            current=evidence(c,row);require(body.digest==current['digest'],'Evidence changed. Review before signing off.')
            require(not current['issues'],'Vault or workflow steps remain incomplete.')
            require(not current['reported_external_access'] or body.external_access!='not_applicable','Reported external access requires an explicit unresolved or unverified acknowledgment.')
            fresh_factor(c,session,body,cipher)
            exceptions=bool(current['reported_external_access'] or current['active_shared_password_debt'] or body.external_access!='not_applicable' or body.device_return=='unresolved' or body.device_wipe=='unresolved')
            receipt={'actor':session['user'],'at':now(),'evidence_digest':body.digest,'external_access':body.external_access,'device_return':body.device_return,'device_wipe':body.device_wipe,'source':'owner_attestation','limitations':LIMITS}
            c.execute('UPDATE handoff_records SET status=?,receipt=?,updated_at=? WHERE id=?',('complete_with_exceptions' if exceptions else 'complete',canonical(receipt),now(),identifier));Store.event(c,session['workspace'],session['user'],'handoff.signed_off',identifier)
        return {'ok':True,'status':'complete_with_exceptions' if exceptions else 'complete'}

    def cancel(identifier,session):
        authorized(session)
        with store.connect(write=True) as c:
            row=get(c,session,identifier);require(session['user'] in {row['created_by'],row['recipient']} and row['status'] not in TERMINAL,'Handoff cannot be cancelled.')
            c.execute("UPDATE handoff_records SET status='cancelled',approval=NULL,updated_at=? WHERE id=?",(now(),identifier));Store.event(c,session['workspace'],session['user'],'handoff.cancelled',identifier)
        return {'ok':True,'note':'Linked offboarding runs must be cancelled separately; completed effects are not undone.'}

    @app.post('/api/members/{identifier}/promote-owner')
    def promote_owner(identifier:str,body:OwnerPromotion,session=Depends(auth)):
        authorized(session);throttle('handoff-factor:'+session['user'],8)
        with store.connect(write=True) as c:
            require(body.confirmed and identifier!=session['user'],'Explicit approval for a separate member required.')
            target=require(c.execute('SELECT u.mfa,m.role FROM users u JOIN members m ON m.user=u.id WHERE m.workspace=? AND u.id=?',(session['workspace'],identifier)).fetchone(),'Member unavailable.',404)
            require(target['role']!='owner' and target['mfa'],'The receiving member must enable account MFA before promotion.')
            fresh_factor(c,session,body,cipher)
            c.execute("UPDATE members SET role='owner' WHERE workspace=? AND user=?",(session['workspace'],identifier))
            Store.event(c,session['workspace'],session['user'],'member.promoted_owner',identifier)
        return {'ok':True}

    @app.get('/api/handoffs')
    def web_listing(session=Depends(auth)):return listing(session)
    @app.get('/api/companion/access/handoffs')
    def extension_listing(session=Depends(access_auth)):return listing(session)
    @app.post('/api/companion/access/handoffs')
    def extension_create(body:Draft,session=Depends(access_auth)):return create(body,session)
    @app.post('/api/companion/access/handoffs/{identifier}/approve')
    def extension_approve(identifier:str,body:Confirm,session=Depends(access_auth)):return approve(identifier,body,session)
    @app.post('/api/companion/access/handoffs/{identifier}/link')
    def extension_link(identifier:str,body:Link,session=Depends(access_auth)):return link(identifier,body,session)
    @app.post('/api/companion/access/handoffs/{identifier}/signoff')
    def extension_signoff(identifier:str,body:Signoff,session=Depends(access_auth)):return signoff(identifier,body,session)
    @app.post('/api/companion/access/handoffs/{identifier}/cancel')
    def extension_cancel(identifier:str,session=Depends(access_auth)):return cancel(identifier,session)
