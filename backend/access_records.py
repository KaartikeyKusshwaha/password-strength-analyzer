"""Explicit account metadata. Login attempts and manual reports are not verified grants."""
import re
import time
from typing import Literal
from fastapi import Depends,HTTPException,Request
from pydantic import BaseModel,ConfigDict,Field,field_validator
from .store import Store,now,uid
from .security import digest
from .admin_mfa import enforce as enforce_admin_mfa
from .extension_connect import DISCOVERY_SCOPE,DISCOVERY_KIND


def require(value,message,status=403):
    if not value:raise HTTPException(status,message)
    return value


class Record(BaseModel):
    model_config=ConfigDict(extra='forbid',str_strip_whitespace=True)
    client_id:str=Field(pattern=r'^[a-f0-9]{24}$')
    domain:str=Field(min_length=3,max_length=253)
    account_label:str=Field(min_length=1,max_length=100)

    @field_validator('domain')
    @classmethod
    def hostname(cls,value):
        try:value=value.encode('idna').decode('ascii').lower()
        except UnicodeError:raise ValueError('Use an exact hostname.') from None
        require(re.fullmatch(r'(?=.{3,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z](?:[a-z0-9-]{0,61}[a-z0-9])',value),'Use an exact hostname, without URL paths or credentials.',422)
        return value

    @field_validator('account_label')
    @classmethod
    def label(cls,value):
        if any(ord(char)<32 or ord(char)==127 for char in value):raise ValueError('Use a single-line account nickname.')
        return value


class Manual(Record):
    person_id:str=Field(pattern=r'^[a-f0-9]{24}$')
    role:Literal['owner','admin','editor','viewer','member']='member'


class Observation(BaseModel):
    model_config=ConfigDict(extra='forbid')
    consent_id:str=Field(pattern=r'^[a-f0-9]{24}$')


def available_clients(c,session):
    member=c.execute('SELECT role FROM members WHERE workspace=? AND user=?',(session['workspace'],session['user'])).fetchone()
    if not member or member['role']=='viewer':return []
    if member['role']=='owner':return [dict(row) for row in c.execute('SELECT id,name FROM clients WHERE workspace=? ORDER BY name,id',(session['workspace'],))]
    return [dict(row) for row in c.execute('SELECT DISTINCT p.id,p.name FROM clients p JOIN client_vaults l ON l.client=p.id AND l.workspace=p.workspace JOIN team_grants g ON g.vault=l.vault WHERE p.workspace=? AND g.user=? AND g.accepted=1 ORDER BY p.name,p.id',(session['workspace'],session['user']))]


def record(c,session,body,person,source):
    existing=c.execute('SELECT * FROM access_grants WHERE workspace=? AND client=? AND person=? AND domain=? AND account_label=? AND source=?',(session['workspace'],body.client_id,person,body.domain,body.account_label,source)).fetchone()
    state='observed' if source=='extension_discovery' else 'reported'
    if existing:
        role=getattr(body,'role',existing['role'])
        c.execute('UPDATE access_grants SET state=?,role=?,updated_at=? WHERE id=?',(state,role,now(),existing['id']))
        if existing['state']=='retired':Store.event(c,session['workspace'],session['user'],'access_metadata.reappeared',existing['id'])
        elif role!=existing['role']:Store.event(c,session['workspace'],session['user'],'access_metadata.updated',existing['id'])
        return {'id':existing['id'],'created':False,'state':state}
    require(c.execute('SELECT count(*) FROM access_grants WHERE workspace=?',(session['workspace'],)).fetchone()[0]<5000,'Reported access limit reached.',409)
    identifier=uid();at=now()
    c.execute('INSERT INTO access_grants VALUES(?,?,?,?,?,?,?,?,?,?,?,?)',(identifier,session['workspace'],body.client_id,person,body.domain,body.account_label,getattr(body,'role','member'),source,state,session['user'],at,at))
    Store.event(c,session['workspace'],session['user'],'access_metadata.recorded',identifier)
    return {'id':identifier,'created':True,'state':state}


def register(app,store,auth,throttle):
    def owner(session):require(session['role']=='owner','Workspace owner access required')
    def live(c,session):
        enforce_admin_mfa(c,session['user'],store)
        grant=Store.get(c,DISCOVERY_SCOPE,DISCOVERY_KIND,session['id'])
        require(grant and grant['expires']>time.time(),'Discovery connection expired or revoked',401)
        require(c.execute("SELECT 1 FROM members WHERE user=? AND workspace=? AND role IN ('owner','analyst','reviewer')",(session['user'],session['workspace'])).fetchone(),'Reporting permission removed')
    def valid_client(c,session,identifier):require(c.execute('SELECT 1 FROM clients WHERE id=? AND workspace=?',(identifier,session['workspace'])).fetchone(),'Client not found',404)

    @app.get('/api/extension-capabilities')
    def capabilities(session=Depends(auth)):
        from .extension_connect import ACCESS_SCOPE,ACCESS_KIND
        with store.connect() as c:
            values=[]
            for kind,scope,record_kind in (('access',ACCESS_SCOPE,ACCESS_KIND),('discovery',DISCOVERY_SCOPE,DISCOVERY_KIND)):
                for grant in Store.all(c,scope,record_kind):
                    if grant['user']==session['user'] and grant['workspace']==session['workspace'] and grant['expires']>time.time():values.append({key:grant[key] for key in ('id','origin','expires')}|{'kind':kind})
        return {'connections':values}

    @app.post('/api/extension-capabilities/{kind}/{identifier}/revoke')
    def revoke_capability(kind:Literal['access','discovery'],identifier:str,session=Depends(auth)):
        from .extension_connect import ACCESS_SCOPE,ACCESS_KIND
        scope,record_kind=(ACCESS_SCOPE,ACCESS_KIND) if kind=='access' else (DISCOVERY_SCOPE,DISCOVERY_KIND)
        with store.connect(write=True) as c:
            grant=require(Store.get(c,scope,record_kind,identifier),'Connection not found',404)
            require(grant['user']==session['user'] and grant['workspace']==session['workspace'],'Connection not found',404)
            c.execute('DELETE FROM entities WHERE workspace=? AND kind=? AND id=?',(scope,record_kind,identifier))
            if kind=='discovery':c.execute("DELETE FROM entities WHERE workspace=? AND kind='discovery_consents' AND json_extract(data,'$.connection')=?",(session['workspace'],identifier))
            Store.event(c,session['workspace'],session['user'],'extension.'+kind+'_revoked','account-settings')
        return {'ok':True,'note':'Approved workflows are separate and must be cancelled explicitly.'}

    @app.post('/api/clients/access-records')
    def manual(body:Manual,session=Depends(auth)):
        owner(session);throttle('access-record:'+session['workspace'],60)
        with store.connect(write=True) as c:
            require(c.execute("SELECT 1 FROM members WHERE user=? AND workspace=? AND role='owner'",(session['user'],session['workspace'])).fetchone(),'Workspace owner access required')
            valid_client(c,session,body.client_id)
            require(c.execute('SELECT 1 FROM members WHERE user=? AND workspace=?',(body.person_id,session['workspace'])).fetchone(),'Member not found',404)
            return record(c,session,body,body.person_id,'manual')

    @app.post('/api/clients/access-records/{identifier}/retire')
    def retire(identifier:str,session=Depends(auth)):
        owner(session)
        with store.connect(write=True) as c:
            require(c.execute("SELECT 1 FROM members WHERE user=? AND workspace=? AND role='owner'",(session['user'],session['workspace'])).fetchone(),'Workspace owner access required')
            row=require(c.execute('SELECT * FROM access_grants WHERE id=? AND workspace=?',(identifier,session['workspace'])).fetchone(),'Reported record not found',404)
            if row['state']!='retired':
                c.execute("UPDATE access_grants SET state='retired',updated_at=? WHERE id=?",(now(),identifier));Store.event(c,session['workspace'],session['user'],'access_metadata.retired',identifier)
        return {'ok':True,'note':'Metadata retired only. No external account access was revoked.'}

    def discovery_auth(request:Request):
        origin=request.headers.get('origin','')
        require(re.fullmatch(r'chrome-extension://[a-p]{32}',origin),'Extension origin required')
        bearer=request.headers.get('authorization','')
        require(bearer.startswith('Bearer '),'Discovery connection required',401)
        with store.connect() as c:
            grant=Store.get(c,DISCOVERY_SCOPE,DISCOVERY_KIND,digest(bearer[7:]))
            require(grant and grant['expires']>time.time() and grant['origin']==origin,'Discovery connection expired or revoked',401)
            member=c.execute('SELECT role FROM members WHERE user=? AND workspace=?',(grant['user'],grant['workspace'])).fetchone()
            require(member and member['role'] in {'owner','analyst','reviewer'},'Reporting permission removed')
            enforce_admin_mfa(c,grant['user'],store)
        return {**grant,'role':member['role']}

    @app.get('/api/companion/discovery/context')
    def context(session=Depends(discovery_auth)):
        with store.connect() as c:
            clients=available_clients(c,session)
            consents=[item for item in Store.all(c,session['workspace'],'discovery_consents') if item['connection']==session['id']]
        return {'clients':clients,'consents':consents,'expires':session['expires']}

    @app.post('/api/companion/discovery/consents')
    def consent(body:Record,session=Depends(discovery_auth)):
        throttle('discovery-consent:'+session['user'],60)
        with store.connect(write=True) as c:
            live(c,session)
            require(body.client_id in {item['id'] for item in available_clients(c,session)},'Choose a client you can currently access')
            existing=[item for item in Store.all(c,session['workspace'],'discovery_consents') if item['connection']==session['id']]
            match=next((item for item in existing if item['domain']==body.domain),None)
            require(match is not None or len(existing)<100,'Up to 100 chosen sites are supported.',409)
            value=dict(id=match['id'] if match else uid(),connection=session['id'],user=session['user'],**body.model_dump(),created_at=now())
            Store.put(c,session['workspace'],'discovery_consents',value);Store.event(c,session['workspace'],session['user'],'discovery.site_enabled',value['id'])
        return value

    @app.post('/api/companion/discovery/consents/{identifier}/disable')
    def disable(identifier:str,session=Depends(discovery_auth)):
        with store.connect(write=True) as c:
            live(c,session)
            value=require(Store.get(c,session['workspace'],'discovery_consents',identifier),'Consent not found',404)
            require(value['connection']==session['id'],'Consent not found',404)
            c.execute('DELETE FROM entities WHERE id=? AND workspace=? AND kind=?',(identifier,session['workspace'],'discovery_consents'));Store.event(c,session['workspace'],session['user'],'discovery.site_disabled',identifier)
        return {'ok':True,'note':'Collection stopped. Previously reported access metadata remains until retired.'}

    @app.post('/api/companion/discovery/observe')
    def observe(body:Observation,session=Depends(discovery_auth)):
        throttle('discovery-observe:'+session['id'],120)
        with store.connect(write=True) as c:
            live(c,session)
            consent=require(Store.get(c,session['workspace'],'discovery_consents',body.consent_id),'Site consent unavailable',404)
            require(consent['connection']==session['id'] and consent['user']==session['user'],'Site consent unavailable',404)
            require(consent['client_id'] in {item['id'] for item in available_clients(c,session)},'Client access removed')
            return record(c,session,Record(**{key:consent[key] for key in ('client_id','domain','account_label')}),session['user'],'extension_discovery')

    @app.post('/api/companion/discovery/revoke')
    def revoke(session=Depends(discovery_auth)):
        with store.connect(write=True) as c:
            live(c,session)
            c.execute('DELETE FROM entities WHERE id=? AND workspace=? AND kind=?',(session['id'],DISCOVERY_SCOPE,DISCOVERY_KIND))
            c.execute("DELETE FROM entities WHERE workspace=? AND kind='discovery_consents' AND json_extract(data,'$.connection')=?",(session['workspace'],session['id']))
            Store.event(c,session['workspace'],session['user'],'extension.discovery_revoked','owner-disconnected')
        return {'ok':True}
