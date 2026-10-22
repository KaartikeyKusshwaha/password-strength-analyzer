"""All-client-vault invitation + expiry, committed together using existing grants."""
import json
import time
from typing import Literal
from fastapi import Depends,Request
from pydantic import BaseModel,ConfigDict,Field,SecretStr
from .access_leases import Request as ExpiryRequest,create_policy,KIND as LEASE_KIND
from .access_workflows import owner,require,digest
from .extension_connect import ACCESS_SCOPE,ACCESS_KIND
from .security import consume_factor,verify_password
from .sharing import Grant
from .store import Store,canonical,now,uid

KIND='access_invitation_drafts'
ID=r'^[a-f0-9]{24}$'

class Draft(ExpiryRequest):
    mode:Literal['auto_revoke']='auto_revoke'
    role:Literal['viewer','editor','admin']='editor'

class SignedVault(BaseModel):
    model_config=ConfigDict(extra='forbid')
    vault_id:str=Field(pattern=ID)
    token:SecretStr=Field(min_length=40,max_length=100)
    grant:Grant

class Apply(BaseModel):
    model_config=ConfigDict(extra='forbid')
    plan_digest:str=Field(pattern=r'^[a-f0-9]{64}$')
    confirmed:bool=False
    password:SecretStr=Field(max_length=256)
    code:str=Field(max_length=80)
    vaults:list[SignedVault]=Field(min_length=1,max_length=20)


def scope(c,session,body):
    current=owner(c,session['workspace'],session['user']);require(current and current['mfa'],'Current owner access and MFA required',403)
    require(body.person_id!=session['user'],'Choose a separate contractor.')
    target=c.execute('SELECT u.id,u.email,m.role,i.public,i.fingerprint FROM members m JOIN users u ON u.id=m.user JOIN sharing_identities i ON i.user=u.id WHERE m.workspace=? AND m.user=?',(session['workspace'],body.person_id)).fetchone()
    require(target and target['role']!='owner','Choose a non-owner teammate with an initialized sharing identity.')
    require(target['role']!='viewer' or body.role=='viewer','Workspace viewers may receive view access only.')
    require(c.execute('SELECT 1 FROM clients WHERE workspace=? AND id=?',(session['workspace'],body.client_id)).fetchone(),'Client unavailable',404)
    vaults=c.execute('SELECT v.* FROM client_vaults l JOIN team_vaults v ON v.id=l.vault AND v.workspace=l.workspace WHERE l.workspace=? AND l.client=? ORDER BY v.id',(session['workspace'],body.client_id)).fetchall()
    require(0<len(vaults)<=20,'Link 1–20 client vaults before inviting a contractor.')
    result=[]
    for vault in vaults:
        require(vault['owner']==session['user'] and not vault['rotation_required'] and json.loads(vault['browser_policy'])['browser_enabled'],'Own, rotate and enable browser access for every client vault first.')
        require(not c.execute('SELECT 1 FROM team_grants WHERE vault=? AND user=?',(vault['id'],body.person_id)).fetchone(),'The teammate already has client-vault access. Use the existing-membership expiry flow.')
        require(c.execute('SELECT count(*) FROM team_grants WHERE vault=?',(vault['id'],)).fetchone()[0]<20,'A client vault is full.')
        from .ownership import state_digest
        result.append({'vault':vault['id'],'epoch':vault['epoch'],'revision':vault['revision'],'state_digest':state_digest(c,dict(vault))})
    return {'version':1,'client':body.client_id,'person':body.person_id,'role':body.role,'expires_at':body.expires_at,'recipient_fingerprint':target['fingerprint'],'vaults':result},dict(target)


def register(app,store,access_auth,throttle,cipher,shared):
    def get(c,session,identifier):
        value=require(Store.get(c,session['workspace'],KIND,identifier),'Invitation draft unavailable',404)
        require(value['created_by']==session['user'] and value['status']=='pending' and value['deadline']>time.time(),'Draft expired, stopped or already applied.')
        body=Draft(client_id=value['plan']['client'],person_id=value['plan']['person'],expires_at=value['plan']['expires_at'],role=value['plan']['role'])
        plan,target=scope(c,session,body)
        require(value['plan_digest']==digest(plan),'Client vaults or recipient changed. Prepare a new invitation draft.')
        return value,body,target

    def access(c,session):
        grant=Store.get(c,ACCESS_SCOPE,ACCESS_KIND,session['id'])
        require(grant and grant['expires']>time.time() and grant['user']==session['user'] and grant['workspace']==session['workspace'],'Workflow connection expired or revoked',401)

    @app.post('/api/companion/access/invitations')
    def draft(body:Draft,session=Depends(access_auth)):
        throttle('access-invitation:'+session['user'],20)
        at=time.time();require(at+3600<=body.expires_at<=at+90*86400,'Choose expiry between one hour and 90 days.',422)
        with store.connect(write=True) as c:
            access(c,session)
            require(c.execute('SELECT count(*) FROM entities WHERE workspace=? AND kind=?',(session['workspace'],KIND)).fetchone()[0]<1000,'Invitation draft history limit reached.')
            plan,target=scope(c,session,body)
            value=dict(id=uid(),created_by=session['user'],status='pending',deadline=at+900,plan=plan,plan_digest=digest(plan),created_at=now())
            Store.put(c,session['workspace'],KIND,value);Store.event(c,session['workspace'],session['user'],'access_invitation.planned',value['id'])
        return value

    @app.get('/api/companion/access/invitations/{identifier}/vaults/{vault}')
    def context(identifier:str,vault:str,request:Request,session=Depends(access_auth)):
        with store.connect() as c:
            c.execute('BEGIN');access(c,session);value,body,target=get(c,session,identifier)
            require(any(item['vault']==vault for item in value['plan']['vaults']),'Vault outside this draft',403)
            result=app.state.exact_vault_context(c,session,vault,request)
            return {**result,'recipient':{'id':target['id'],'email':target['email'],'role':target['role'],'public':json.loads(target['public']),'fingerprint':target['fingerprint']},'draft':value}

    @app.post('/api/companion/access/invitations/{identifier}/apply')
    def apply(identifier:str,body:Apply,request:Request,session=Depends(access_auth)):
        throttle('access-approval:'+session['user'],8)
        with store.connect(write=True) as c:
            access(c,session);value,expiry,target=get(c,session,identifier);plan=value['plan']
            require(body.confirmed and body.plan_digest==value['plan_digest'],'Review and approve the exact invitation and expiry scope.')
            require(len(body.vaults)==len(plan['vaults']) and {item.vault_id for item in body.vaults}=={item['vault'] for item in plan['vaults']},'Provide exactly one signed invitation for every client vault.')
            actor=owner(c,session['workspace'],session['user'])
            require(verify_password(body.password.get_secret_value(),actor['password']) and consume_factor(c,actor,body.code,cipher),'Current password and unused factor required',401)
            # Verify all bearer scopes and signatures under the same write lock.
            for item in body.vaults:
                headers=dict(request.headers);headers['x-sentinel-vault-token']=item.token.get_secret_value()
                from types import SimpleNamespace
                local=SimpleNamespace(headers=headers)
                app.state.exact_vault_context(c,session,item.vault_id,local)
                require(item.grant.recipient==plan['person'] and item.grant.role==plan['role'],'Invitation recipient or role differs from approval.')
                shared['invite'](c,item.vault_id,item.grant,session)
            lease=create_policy(c,expiry,session,minimum_lead=0)
            lease.pop('limitations',None);lease.pop('client_name',None);lease.pop('person_email',None);lease.pop('uncovered_vaults',None)
            lease.update(status='active',approval={'actor':session['user'],'at':now(),'digest':lease['plan_digest'],'expires_at':plan['expires_at'],'execute_before':plan['expires_at']+7*86400},updated_at=now())
            Store.put(c,session['workspace'],LEASE_KIND,lease);Store.event(c,session['workspace'],session['user'],'access_lease.approved',lease['id'])
            value.update(status='applied',lease_id=lease['id'],finished_at=now());Store.put(c,session['workspace'],KIND,value);Store.event(c,session['workspace'],session['user'],'access_invitation.applied',identifier)
        return {'ok':True,'lease_id':lease['id'],'note':'Invitations and approved expiry created together. The recipient must accept the invitations.'}
