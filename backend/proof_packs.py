"""Immutable encrypted metadata snapshots and explicitly approved, revocable links."""
import json
import re
import secrets
import time
from pathlib import Path
from typing import Literal
from fastapi import Depends,Request
from fastapi.responses import Response,FileResponse
from cryptography.fernet import InvalidToken
from reportlab.platypus.doctemplate import LayoutError
from pydantic import BaseModel,ConfigDict,Field,SecretStr,field_validator
from . import proof_evidence,proof_pdf
from .access_workflows import require,owner,digest
from .security import digest as token_digest,consume_factor,verify_password
from .store import Store,uid,now,canonical

KIND='client_proof_packs'
LINKS='client_proof_links'
ID=r'^[a-f0-9]{24}$'

class Options(BaseModel):
    model_config=ConfigDict(extra='forbid',str_strip_whitespace=True)
    client_id:str=Field(pattern=ID)
    brand:str=Field(default='Client access review',min_length=2,max_length=80)
    asset_ids:list[str]=Field(default_factory=list,max_length=20)
    include_posture:bool=False
    @field_validator('brand')
    @classmethod
    def label(cls,value):
        if any(ord(ch)<32 or ord(ch)==127 for ch in value):raise ValueError('Use a single-line report brand.')
        return value
    @field_validator('asset_ids')
    @classmethod
    def assets(cls,value):
        if len(set(value))!=len(value) or any(not re.fullmatch(ID,v) for v in value):raise ValueError('Choose distinct system IDs.')
        return sorted(value)

class Confirm(BaseModel):
    model_config=ConfigDict(extra='forbid')
    approved:bool=False
    password:SecretStr=Field(max_length=256)
    code:str=Field(max_length=80)

class Create(Options,Confirm):
    source_digest:str=Field(pattern=r'^[a-f0-9]{64}$')

class Share(Confirm):
    days:int=Field(default=7,ge=1,le=30)

class PublicRead(BaseModel):
    model_config=ConfigDict(extra='forbid')
    id:str=Field(pattern=ID)
    format:Literal['json','pdf']='json'

def register(app,store,auth,access_auth,throttle,cipher,settings):
    def live(c,session):
        user=owner(c,session['workspace'],session['user']);require(user and user['mfa'],'Current owner and MFA required',403)
        from .extension_connect import ACCESS_SCOPE,ACCESS_KIND
        if session.get('id'):
            grant=Store.get(c,ACCESS_SCOPE,ACCESS_KIND,session['id'])
            require(grant and grant['expires']>time.time(),'Workflow connection revoked',401)
        return user
    def factor(c,session,body):
        user=live(c,session)
        require(body.approved,'Approve this exact report operation',422)
        require(verify_password(body.password.get_secret_value(),user['password']) and consume_factor(c,user,body.code,cipher),'Current password and unused MFA/recovery code required',401)
    def get(c,session,identifier):
        return require(Store.get(c,session['workspace'],KIND,identifier),'Proof Pack unavailable',404)
    def content(record):
        try:
            value=json.loads(cipher.decrypt(record['encrypted'].encode()))
            expected=value.pop('digest');require(digest(value)==expected==record['digest'],'Proof Pack integrity check failed')
            return {**value,'digest':expected}
        except (ValueError,KeyError,InvalidToken):require(False,'Proof Pack could not be authenticated',409)
    def metadata(c,workspace,record):
        links=[{key:grant[key] for key in ('id','created_at','expires','revoked')} for grant in Store.all(c,workspace,LINKS) if grant['pack']==record['id']]
        return {key:record[key] for key in ('id','client','created_at','created_by','digest','revoked')}|{'links':links}
    @app.get('/api/companion/access/proof-packs/context')
    def context(session=Depends(access_auth)):
        with store.connect() as c:
            live(c,session)
            assets=[{'id':row['id'],'name':row['name']} for row in Store.all(c,session['workspace'],'assets')]
            return {'assets':assets[:500],'assets_omitted':max(0,len(assets)-500),'scope':'Only explicitly selected check systems are associated with this client snapshot. Device posture is optional and limited to the recorded client staff.'}
    @app.get('/api/companion/access/proof-packs')
    def listing(session=Depends(access_auth)):
        with store.connect() as c:
            live(c,session)
            return {'packs':[metadata(c,session['workspace'],row) for row in Store.all(c,session['workspace'],KIND)[:100]]}
    @app.get('/api/proof-packs')
    def web_listing(session=Depends(auth)):return listing(session)
    @app.post('/api/companion/access/proof-packs/preview')
    def preview(body:Options,session=Depends(access_auth)):
        throttle('proof-preview:'+session['workspace'],20)
        with store.connect() as c:
            c.execute('BEGIN') # one consistent read snapshot across every source
            live(c,session);value,source_digest=proof_evidence.collect(c,session['workspace'],body.client_id,body)
        return {'source_digest':source_digest,'snapshot':value,'note':'Preview only; not saved or shared. Generation rechecks this source and needs fresh owner approval.'}
    @app.post('/api/companion/access/proof-packs')
    def create(body:Create,session=Depends(access_auth)):
        throttle('proof-create:'+session['user'],8)
        with store.connect(write=True) as c:
            live(c,session)
            require(len(Store.all(c,session['workspace'],KIND))<500,'Proof Pack retention limit reached')
            value,source_digest=proof_evidence.collect(c,session['workspace'],body.client_id,body)
            require(source_digest==body.source_digest,'Source evidence changed. Preview and approve a new snapshot.')
            value.update(id=uid(),generated_at=now());value['digest']=digest(value)
            raw=canonical(value).encode();require(len(raw)<=2*1024*1024,'Snapshot exceeds 2 MiB; no partial report was generated')
            # Ensure it can render before consuming a factor or committing it.
            try:proof_pdf.render(value)
            except (ValueError,LayoutError):require(False,'Report cannot fit the bounded PDF layout; reduce the report scope.',422)
            factor(c,session,body)
            record=dict(id=value['id'],client=body.client_id,created_at=value['generated_at'],created_by=session['user'],digest=value['digest'],encrypted=cipher.encrypt(raw).decode(),revoked=False)
            Store.put(c,session['workspace'],KIND,record);Store.event(c,session['workspace'],session['user'],'proof_pack.created',record['id']+':'+record['digest'])
            return metadata(c,session['workspace'],record)
    @app.get('/api/companion/access/proof-packs/{identifier}/snapshot')
    def snapshot(identifier:str,session=Depends(access_auth)):
        with store.connect() as c:live(c,session);return content(get(c,session,identifier))
    @app.get('/api/companion/access/proof-packs/{identifier}/pdf')
    def pdf(identifier:str,session=Depends(access_auth)):
        throttle('proof-pdf:'+session['user'],20)
        with store.connect() as c:live(c,session);value=content(get(c,session,identifier))
        return Response(proof_pdf.render(value),media_type='application/pdf',headers={'Content-Disposition':'attachment; filename="client-proof-pack.pdf"'})
    @app.get('/api/proof-packs/{identifier}/snapshot')
    def web_snapshot(identifier:str,session=Depends(auth)):return snapshot(identifier,session)
    @app.get('/api/proof-packs/{identifier}/pdf')
    def web_pdf(identifier:str,session=Depends(auth)):return pdf(identifier,session)
    @app.post('/api/companion/access/proof-packs/{identifier}/share')
    def share(identifier:str,body:Share,session=Depends(access_auth)):
        throttle('proof-share:'+session['user'],8)
        with store.connect(write=True) as c:
            record=get(c,session,identifier);require(not record['revoked'],'This Proof Pack was revoked')
            require(len(Store.all(c,session['workspace'],LINKS))<1000,'Proof link retention limit reached')
            factor(c,session,body);token=secrets.token_urlsafe(40)
            link=dict(id=token_digest(token),pack=identifier,created_by=session['user'],created_at=now(),expires=time.time()+body.days*86400,revoked=False)
            Store.put(c,session['workspace'],LINKS,link);Store.event(c,session['workspace'],session['user'],'proof_pack.link_created',identifier)
        return {'url':settings.origin+'/proof#'+identifier+':'+token,'expires':link['expires'],'note':'Anyone with this link can read this immutable snapshot until expiry or revocation. Downloaded copies cannot be recalled. The secret stays in the URL fragment, not a server query string.'}
    @app.post('/api/companion/access/proof-packs/{identifier}/revoke')
    def revoke(identifier:str,session=Depends(access_auth)):
        with store.connect(write=True) as c:
            live(c,session);record=get(c,session,identifier);record['revoked']=True;Store.put(c,session['workspace'],KIND,record)
            for link in Store.all(c,session['workspace'],LINKS):
                if link['pack']==identifier:link['revoked']=True;Store.put(c,session['workspace'],LINKS,link)
            Store.event(c,session['workspace'],session['user'],'proof_pack.revoked',identifier)
        return {'ok':True,'note':'All links to this snapshot are revoked. Previously downloaded copies cannot be erased.'}
    @app.post('/api/public/proof-pack')
    def public(body:PublicRead,request:Request):
        throttle('proof-public:'+request.client.host,120)
        bearer=request.headers.get('authorization','');require(re.fullmatch(r'Bearer [A-Za-z0-9_-]{54}',bearer),'Proof link unavailable',404)
        with store.connect() as c:
            row=c.execute('SELECT workspace,data FROM entities WHERE kind=? AND id=?',(LINKS,token_digest(bearer[7:]))).fetchone()
            require(row,'Proof link unavailable',404);link=json.loads(row['data'])
            actor=owner(c,row['workspace'],link['created_by'])
            require(link['pack']==body.id and not link['revoked'] and link['expires']>time.time() and actor and actor['mfa'],'Proof link unavailable',404)
            record=Store.get(c,row['workspace'],KIND,body.id);require(record and not record['revoked'],'Proof link unavailable',404)
            value=content(record)
        if body.format=='pdf':return Response(proof_pdf.render(value),media_type='application/pdf')
        return value
    root=Path(__file__).parent/'public'
    @app.get('/proof')
    def viewer():return FileResponse(root/'proof.html')
    @app.get('/proof-view.js')
    def viewer_script():return FileResponse(root/'proof-view.js',media_type='text/javascript')
    @app.get('/proof-view.css')
    def viewer_style():return FileResponse(root/'proof-view.css',media_type='text/css')
