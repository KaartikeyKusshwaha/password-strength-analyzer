"""Extension adapters for the existing signed ownership protocol, not a new protocol."""
import time
from fastapi import Depends,Request
from .access_workflows import owner,require
from .extension_connect import ACCESS_SCOPE,ACCESS_KIND
from .ownership import Proposal,Acceptance
from .security import digest
from .store import Store


def register(app,store,access_auth,throttle,shared):
    operations=shared['ownership']

    def context(c,session,vault,request):
        # Revalidate both independent capabilities inside the effect transaction.
        access=Store.get(c,ACCESS_SCOPE,ACCESS_KIND,session['id'])
        require(access and access['expires']>time.time() and access['user']==session['user'] and access['workspace']==session['workspace'],'Workflow connection expired or revoked',401)
        current=owner(c,session['workspace'],session['user'])
        require(current and current['mfa'],'Current owner access and account MFA required',403)
        token=request.headers.get('x-sentinel-vault-token','')
        connection=c.execute('SELECT * FROM companions WHERE token=? AND expires>?',(digest(token),time.time())).fetchone()
        require(connection and connection['kind']=='shared' and connection['vault_id']==vault and connection['user']==session['user'] and connection['workspace']==session['workspace'],'A separate connection to this exact shared vault is required',403)
        return shared['ownership_context'](c,dict(connection))

    app.state.exact_vault_context=context

    @app.get('/api/companion/access/vaults/{vault}/ownership')
    def read(vault:str,request:Request,session=Depends(access_auth)):
        with store.connect() as c:
            c.execute('BEGIN')
            value=context(c,session,vault,request)
            return {**value,**operations['proposal'](c,vault,session)}

    @app.post('/api/companion/access/vaults/{vault}/ownership')
    def propose(vault:str,body:Proposal,request:Request,session=Depends(access_auth)):
        throttle('ownership:'+session['user'],20)
        with store.connect(write=True) as c:
            context(c,session,vault,request)
            return operations['propose'](c,vault,body,session)

    @app.post('/api/companion/access/vaults/{vault}/ownership/accept')
    def accept(vault:str,body:Acceptance,request:Request,session=Depends(access_auth)):
        throttle('ownership-accept:'+session['user'],20)
        with store.connect(write=True) as c:
            context(c,session,vault,request)
            return operations['accept'](c,vault,body,session)

    @app.post('/api/companion/access/vaults/{vault}/ownership/{proposal_id}/cancel')
    def cancel(vault:str,proposal_id:str,request:Request,session=Depends(access_auth)):
        throttle('ownership-cancel:'+session['user'],20)
        with store.connect(write=True) as c:
            context(c,session,vault,request)
            return operations['cancel'](c,vault,proposal_id,session)
