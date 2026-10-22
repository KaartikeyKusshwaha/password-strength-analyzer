import time
from unittest.mock import patch
from fastapi.testclient import TestClient
from backend import extension_connect
from backend.store import Store
from backend.security import digest
from test_platform import system, post, PASSWORD
from test_access_workflows import setup
from test_extension_connect import ORIGIN, PROOF
from test_sharing import payload,grant


def connect(app, owner, scope='access'):
    extension=TestClient(app)
    pending=extension.post('/api/companion/connect/start',json={**PROOF,'scope':scope},headers={'Origin':ORIGIN}).json()
    workspace=owner.get('/api/extension-connect/'+pending['id']).json()['workspace_id']
    result=post(owner,'/extension-connect/'+pending['id']+'/approve',{'workspace_id':workspace,'confirmed_code':pending['code']})
    return extension,pending,result


def headers(extension,pending):
    grant=extension.post('/api/companion/connect/'+pending['id']+'/poll',json=PROOF,headers={'Origin':ORIGIN}).json()
    return {'Origin':ORIGIN,'Authorization':'Bearer '+grant['token']}


def test_owner_workflow_connection_executes_only_freshly_approved_preview(system):
    app,owner,other,who,member,vaults,plan,code=setup(system,dry_run=True)
    try:
        extension,pending,result=connect(app,owner)
        assert result.status_code==200 and 'token' not in result.json()
        auth=headers(extension,pending)
        context=extension.get('/api/companion/access/context',headers=auth)
        assert context.status_code==200 and len(context.json()['clients'])==1
        assert context.json()['expires']<=time.time()+8*3600
        for path in ('vault','security/context'):
            assert extension.get('/api/companion/'+path,headers=auth).status_code==401
        assert extension.get('/api/clients/access-map',headers=auth).status_code==401
        path='/api/companion/access/workflows/'+plan['id']
        body={'approved':True,'plan_digest':plan['plan_digest'],'password':PASSWORD,'code':'wrong'}
        assert extension.post(path+'/approve',json=body,headers=auth).status_code==401
        with patch.object(app.state.executor,'submit'):
            assert extension.post(path+'/approve',json={**body,'code':code},headers=auth).status_code==200
        app.state.review_runner.run_access(plan['workspace'],plan['id'])
        result=extension.get('/api/companion/access/workflows',headers=auth).json()
        assert result['workflows'][0]['status']=='dry_run_complete'
        assert PASSWORD not in str(result) and code not in str(result)
        assert extension.get('/api/companion/access/context',headers={**auth,'Origin':'chrome-extension://'+'b'*32}).status_code==401
        assert extension.post('/api/companion/access/revoke',json={},headers=auth).status_code==200
        assert extension.get('/api/companion/access/context',headers=auth).status_code==401
    finally:other.close()


def test_security_grant_cannot_cross_into_access_and_expiry_cancel_restore_revoke(system):
    app,owner,other,who,member,vaults,plan,code=setup(system)
    try:
        extension,pending,result=connect(app,owner,'security')
        assert result.status_code==200
        assert extension.get('/api/companion/access/context',headers=headers(extension,pending)).status_code==401
        extension,pending,result=connect(app,owner)
        auth=headers(extension,pending)
        with app.state.store.connect(write=True) as c:
            grant=Store.get(c,extension_connect.ACCESS_SCOPE,extension_connect.ACCESS_KIND,digest(auth['Authorization'][7:]))
            grant['expires']=0;Store.put(c,extension_connect.ACCESS_SCOPE,extension_connect.ACCESS_KIND,grant)
        assert extension.get('/api/companion/access/context',headers=auth).status_code==401
        extension,pending,result=connect(app,owner);auth=headers(extension,pending)
        assert extension.post('/api/companion/connect/'+pending['id']+'/cancel',json=PROOF,headers={'Origin':ORIGIN}).status_code==200
        assert extension.get('/api/companion/access/context',headers=auth).status_code==401
        extension,pending,result=connect(app,owner);auth=headers(extension,pending)
        from backend.backups import suspend_authorizations
        with app.state.store.connect(write=True) as c:suspend_authorizations(c)
        assert extension.get('/api/companion/access/context',headers=auth).status_code==401
    finally:other.close()


def test_mfa_required_and_live_role_loss_blocks_workflow_access(system):
    app,owner,_=system
    extension,pending,result=connect(app,owner)
    assert result.status_code==403
    app,owner,other,who,member,vaults,plan,code=setup(system)
    try:
        extension,pending,result=connect(app,owner);auth=headers(extension,pending)
        response=extension.options('/api/companion/access/workflows',headers={'Origin':ORIGIN})
        assert response.status_code==204 and response.headers['access-control-allow-origin']==ORIGIN
        with app.state.store.connect(write=True) as c:
            c.execute("UPDATE members SET role='viewer' WHERE user=? AND workspace=?",(who['id'],plan['workspace']))
        assert extension.get('/api/companion/access/context',headers=auth).status_code==403
    finally:other.close()


def test_extension_rotation_requires_both_capabilities_and_only_approved_remaining_roster(system):
    app,owner,other,who,member,vaults,plan,code=setup(system,vault_count=1)
    try:
        vault=vaults[0]
        extension,pending,result=connect(app,owner);auth=headers(extension,pending)
        shared=extension.post('/api/companion/connect/start',json=PROOF,headers={'Origin':ORIGIN}).json()
        assert post(owner,'/extension-connect/'+shared['id']+'/approve',{'vault_id':vault,'vault_kind':'shared','confirmed_code':shared['code']}).status_code==200
        shared_auth=headers(extension,shared)
        path='/api/companion/access/workflows/'+plan['id']+'/vaults/'+vault+'/rotation'
        combined={**auth,'X-Sentinel-Vault-Token':shared_auth['Authorization'][7:]}
        assert extension.get(path,headers=combined).status_code==409 # No approved removal yet.
        with patch.object(app.state.executor,'submit'):
            assert extension.post('/api/companion/access/workflows/'+plan['id']+'/approve',json={'approved':True,'plan_digest':plan['plan_digest'],'password':PASSWORD,'code':code},headers=auth).status_code==200
        app.state.review_runner.run_access(plan['workspace'],plan['id'])
        assert extension.get(path,headers=auth).status_code==403
        assert extension.get(path,headers=shared_auth).status_code==401
        context=extension.get(path,headers=combined)
        assert context.status_code==200,context.text
        assert [item['user_id'] for item in context.json()['team']['grants']]==[who['id']]
        assert [item['id'] for item in context.json()['directory']]==[who['id']]
        body={'revision':1,'payload':payload(vault,2),'grants':[grant(who,who,vault,'owner',2),grant(who,member,vault,'editor',2)]}
        assert extension.post(path,json=body,headers=combined).status_code==422
        body['grants']=body['grants'][:1]
        with patch.object(app.state.executor,'submit'):
            response=extension.post(path,json=body,headers=combined)
        assert response.status_code==200,response.text
        assert extension.post(path,json=body,headers=combined).status_code==409
        app.state.review_runner.run_access(plan['workspace'],plan['id'])
        assert extension.get('/api/companion/access/workflows',headers=auth).json()['workflows'][0]['status']=='complete'
    finally:other.close()
