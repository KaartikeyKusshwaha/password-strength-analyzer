import json
import time
from unittest.mock import patch
from fastapi.testclient import TestClient
from backend.store import Store,uid,now
from backend.security import digest
from backend.proof_packs import KIND,LINKS
from test_platform import system,PASSWORD,post
from test_access_leases import prepared
from test_sharing import grant,payload
from test_access_workflows import approve

ROOT='/api/companion/access/proof-packs'

def preview(browser,headers,client,**kw):
    options={'client_id':client,'brand':'Northstar Agency','asset_ids':[],'include_posture':False,**kw}
    result=browser.post(ROOT+'/preview',headers=headers,json=options)
    assert result.status_code==200,result.text
    return options,result.json()

def generate(browser,headers,options,source,code):
    return browser.post(ROOT,headers=headers,json={**options,'source_digest':source['source_digest'],'approved':True,'password':PASSWORD,'code':code})

def share(browser,headers,identifier,code):
    return browser.post(ROOT+'/'+identifier+'/share',headers=headers,json={'approved':True,'password':PASSWORD,'code':code,'days':7})

def public(app,url,format='json',**kwargs):
    identifier,token=url.split('#')[1].split(':')
    return TestClient(app).post('/api/public/proof-pack',headers={'Authorization':'Bearer '+token},json={'id':identifier,'format':format},**kwargs)

def test_client_snapshot_pdf_real_removals_posture_redaction_and_private_then_shared(system,tmp_path):
    app,owner,other,who,member,vaults,codes,browser,headers,lease=prepared(system)
    try:
        workspace=owner.get('/api/me').json()['workspace']
        workflow=owner.get('/api/access-workflows').json()['workflows'][0]
        assert approve(app,owner,workflow,codes[0]).status_code==200
        app.state.review_runner.run_access(workspace,workflow['id'])
        for vault in vaults:
            assert post(owner,'/team-vaults/'+vault+'/rotate',{'revision':1,'payload':payload(vault,2),'grants':[grant(who,who,vault,'owner',2)]}).status_code==200
        app.state.review_runner.run_access(workspace,workflow['id'])
        device,asset,scan_id,finding_id,unknown_id=uid(),uid(),uid(),uid(),uid()
        with app.state.store.connect(write=True) as c:
            c.execute('INSERT INTO devices(id,token,workspace,user,label,targets,expires,seen,allow_posture) VALUES(?,?,?,?,?,?,?,?,?)',(device,digest('fixture-device'),workspace,member['id'],'Staff laptop','[]',time.time()+86400,time.time(),1))
            Store.put(c,workspace,'assets',dict(id=asset,name='Client portal checks',device_id=device,kind='device',owner='Recorded staff'))
            Store.put(c,workspace,'findings',dict(id=finding_id,scan_id=scan_id,severity='high',evidence='NEVER_EXPORT_RAW_SECRET'))
            Store.put(c,workspace,'findings',dict(id=unknown_id,scan_id=scan_id,severity='NEVER_EXPORT_RAW_SECRET',evidence='NEVER_EXPORT_RAW_SECRET'))
            Store.put(c,workspace,'scans',dict(id=scan_id,asset_id=asset,kind='posture',at=now(),status='partial',finding_ids=[finding_id,unknown_id],raw='NEVER_EXPORT_RAW_SECRET',posture={'platform':'windows','checks':[{'id':'system_disk','state':'unassessed','reason':'permission_denied'}]}))
            other_client=uid();c.execute('INSERT INTO clients VALUES(?,?,?,?)',(other_client,workspace,'OTHER_CLIENT_NAME_MUST_NOT_APPEAR',now()))
        options,source=preview(browser,headers,lease['client'],asset_ids=[asset],include_posture=True)
        body=source['snapshot'];assert body['offboarding'][0]['status']=='complete'
        assert len(body['rechecks'])==3 and all(r['status']=='scheduled' for r in body['rechecks'])
        assert any(step['action']=='revoke' and step['outcome']=='revoked' and step['completed_at'] for step in body['steps'])
        assert body['posture'][0]['checks'][0]['state']=='unassessed'
        assert body['checks'][0]['finding_counts']=={'high':1,'unknown':1}
        assert not next(p for p in body['people'] if p['id']==member['id'])['app_mfa_enrolled']
        result=generate(browser,headers,options,source,codes[1]);assert result.status_code==200,result.text
        identifier=result.json()['id'];assert not result.json()['links']
        snapshot=browser.get(ROOT+'/'+identifier+'/snapshot',headers=headers).json()
        serialized=json.dumps(snapshot)
        for secret in ('NEVER_EXPORT_RAW_SECRET','OTHER_CLIENT_NAME_MUST_NOT_APPEAR',PASSWORD,member['public']['encryption']):assert secret not in serialized
        pdf=browser.get(ROOT+'/'+identifier+'/pdf',headers=headers);assert pdf.status_code==200 and pdf.content.startswith(b'%PDF-')
        (tmp_path/'sample-proof.pdf').write_bytes(pdf.content);(tmp_path/'sample-proof.json').write_text(serialized,encoding='utf-8')
        assert owner.get('/api/proof-packs/'+identifier+'/pdf').status_code==200
        assert other.get('/api/proof-packs').status_code==403
        url=share(browser,headers,identifier,codes[2]).json()['url']
        assert '?token' not in url and '/proof#' in url
        shared=public(app,url);assert shared.status_code==200 and shared.json()==snapshot
        assert public(app,url,'pdf').content.startswith(b'%PDF-')
        with app.state.store.connect(write=True) as c:
            record=Store.get(c,workspace,KIND,identifier);assert 'Northstar' not in record['encrypted'] and 'owner@example.test' not in record['encrypted']
            c.execute("UPDATE clients SET name='Changed later' WHERE id=?",(lease['client'],))
        assert public(app,url).json()['client']['name']=='Offboarding client'
        assert browser.get(ROOT+'/'+identifier+'/snapshot',headers=headers).json()['digest']==snapshot['digest']
    finally:other.close()

def test_changed_preview_and_bad_factors_roll_back_without_consuming_unused_factor(system):
    app,owner,other,who,member,vaults,codes,browser,headers,lease=prepared(system)
    try:
        options,source=preview(browser,headers,lease['client'])
        assert generate(browser,headers,options,source,'wrong').status_code==401
        with app.state.store.connect(write=True) as c:c.execute('UPDATE clients SET name=? WHERE id=?',('Changed client',lease['client']))
        assert generate(browser,headers,options,source,codes[0]).status_code==409
        options,source=preview(browser,headers,lease['client'])
        result=generate(browser,headers,options,source,codes[0]);assert result.status_code==200,result.text
        assert generate(browser,headers,options,source,codes[0]).status_code==409 # creation audit changes the source head
        assert browser.post(ROOT+'/preview',headers=headers,json={**options,'asset_ids':[uid()]}).status_code==404
        assert browser.post(ROOT+'/preview',headers=headers,json={**options,'brand':'one\ntwo'}).status_code==422
        assert browser.post(ROOT+'/preview',headers=headers,json={**options,'asset_ids':[vaults[0],vaults[0]]}).status_code==422
        with app.state.store.connect() as c:assert len(Store.all(c,owner.get('/api/me').json()['workspace'],KIND))==1
    finally:other.close()

def test_share_capability_expiry_revocation_role_mfa_and_restore_fail_closed(system):
    from backend.backups import suspend_authorizations
    app,owner,other,who,member,vaults,codes,browser,headers,lease=prepared(system)
    try:
        workspace=owner.get('/api/me').json()['workspace'];options,source=preview(browser,headers,lease['client'])
        identifier=generate(browser,headers,options,source,codes[0]).json()['id'];url=share(browser,headers,identifier,codes[1]).json()['url']
        token=url.split(':')[-1]
        read=TestClient(app)
        assert read.get('/api/proof-packs/'+identifier+'/snapshot').status_code==401
        assert read.post('/api/public/proof-pack',json={'id':identifier}).status_code==404
        assert read.post('/api/public/proof-pack',headers={'Authorization':'Bearer '+token},json={'id':uid()}).status_code==404
        with app.state.store.connect(write=True) as c:
            link=Store.get(c,workspace,LINKS,digest(token));link['expires']=0;Store.put(c,workspace,LINKS,link)
        assert public(app,url).status_code==404
        url=share(browser,headers,identifier,codes[2]).json()['url']
        with app.state.store.connect(write=True) as c:c.execute("UPDATE members SET role='reviewer' WHERE workspace=? AND user=?",(workspace,who['id']))
        assert public(app,url).status_code==404
        with app.state.store.connect(write=True) as c:c.execute("UPDATE members SET role='owner' WHERE workspace=? AND user=?",(workspace,who['id']))
        assert public(app,url).status_code==200
        assert browser.post(ROOT+'/'+identifier+'/revoke',headers=headers,json={}).status_code==200
        assert public(app,url).status_code==404
        assert share(browser,headers,identifier,codes[3]).status_code==409
        options,source=preview(browser,headers,lease['client']);identifier2=generate(browser,headers,options,source,codes[3]).json()['id'];url2=share(browser,headers,identifier2,codes[4]).json()['url']
        with app.state.store.connect(write=True) as c:suspend_authorizations(c)
        assert public(app,url2).status_code==404
        with app.state.store.connect() as c:
            assert not Store.all(c,workspace,LINKS)
            assert len(Store.all(c,workspace,KIND))==2
    finally:other.close()

def test_snapshot_integrity_and_independent_capabilities_and_hosted_viewer(system):
    from test_extension_access import connect,headers as extension_headers
    app,owner,other,who,member,vaults,codes,browser,headers,lease=prepared(system)
    try:
        workspace=owner.get('/api/me').json()['workspace'];options,source=preview(browser,headers,lease['client'],brand='<Agency & Partners>')
        identifier=generate(browser,headers,options,source,codes[0]).json()['id']
        reminder,pending,result=connect(app,owner,'reminders')
        assert reminder.get(ROOT,headers=extension_headers(reminder,pending)).status_code==401
        cross={**headers,'Origin':'chrome-extension://'+'b'*32};assert browser.get(ROOT,headers=cross).status_code==401
        assert browser.options(ROOT+'/preview',headers={'Origin':headers['Origin'],'Access-Control-Request-Method':'POST','Access-Control-Request-Headers':'authorization, content-type'}).status_code==204
        assert browser.post('/api/public/proof-pack',headers={'Origin':'https://unrelated.example'},json={'id':identifier}).status_code==403
        assert TestClient(app).get('/proof').status_code==200
        script=TestClient(app).get('/proof-view.js').text
        assert 'innerHTML' not in script and 'credentials:\'omit\'' in script and 'history.replaceState' in script
        with app.state.store.connect(write=True) as c:
            record=Store.get(c,workspace,KIND,identifier);record['encrypted']='corrupted';Store.put(c,workspace,KIND,record)
        assert browser.get(ROOT+'/'+identifier+'/snapshot',headers=headers).status_code==409
    finally:other.close()

def test_mfa_reset_and_workspace_removal_permanently_delete_sharing_grants(system):
    from test_access_leases import enable
    from test_extension_access import connect,headers as extension_headers
    app,owner,other,who,member,vaults,codes,browser,headers,lease=prepared(system)
    try:
        workspace=owner.get('/api/me').json()['workspace'];options,source=preview(browser,headers,lease['client'])
        identifier=generate(browser,headers,options,source,codes[0]).json()['id'];url=share(browser,headers,identifier,codes[1]).json()['url']
        assert post(owner,'/mfa/disable',{'password':PASSWORD,'code':codes[2]}).status_code==200
        assert public(app,url).status_code==404
        new_codes=enable(owner)
        assert public(app,url).status_code==404 # re-enrollment must not resurrect the old link
        browser,pending,response=connect(app,owner);assert response.status_code==200;headers=extension_headers(browser,pending)
        assert share(browser,headers,identifier,new_codes[0]).status_code==200
        # Former owner grants cannot reappear if that account is later invited back.
        with app.state.store.connect(write=True) as c:
            Store.put(c,workspace,LINKS,dict(id=digest('former-owner-fixture'),pack=identifier,created_by=member['id'],created_at=now(),expires=time.time()+86400,revoked=False))
        assert post(owner,'/members/'+member['id']+'/offboard',{'password':PASSWORD,'code':new_codes[1]}).status_code==200
        with app.state.store.connect() as c:assert not Store.get(c,workspace,LINKS,digest('former-owner-fixture'))
    finally:other.close()

def test_proof_retains_real_independent_handoff_receipt_and_flags_later_changes(system):
    from test_handoffs import prepare,approve_handoff,listing,signoff
    app,owner,other,recipient,who,incoming,vault,work,codes,rcodes,browser,headers,receiver,iauth,row=prepare(system)
    try:
        assert approve_handoff(browser,headers,row,codes[1]).status_code==200
        assert approve(app,owner,work,codes[2]).status_code==200
        app.state.review_runner.run_access(work['workspace'],work['id'])
        assert post(owner,'/team-vaults/'+vault+'/rotate',{'revision':1,'payload':payload(vault,2),'grants':[grant(who,who,vault,'owner',2),grant(who,incoming,vault,'editor',2)]}).status_code==200
        app.state.review_runner.run_access(work['workspace'],work['id'])
        assert browser.post('/api/companion/access/handoffs/'+row['id']+'/link',headers=headers,json={'workflow_id':work['id']}).status_code==200
        assert signoff(receiver,iauth,listing(receiver,iauth),rcodes[0]).status_code==200
        _,source=preview(browser,headers,work['client']);receipt=source['snapshot']['handoffs'][0]
        assert receipt['signoff']['actor']==incoming['id'] and receipt['signoff']['at']
        assert not receipt['evidence_changed_since_signoff']
        assert post(owner,'/team-vaults/'+vault+'/invite',grant(who,who['departing'],vault,'editor',2)).status_code==200
        _,changed=preview(browser,headers,work['client'])
        assert changed['snapshot']['handoffs'][0]['evidence_changed_since_signoff']
        assert any('vault_handoff_incomplete' in issue for issue in changed['snapshot']['handoffs'][0]['current_issues'])
    finally:other.close();recipient.close()
