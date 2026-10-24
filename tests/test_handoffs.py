import json
import time
from unittest.mock import patch
import pytest
from backend.security import totp
from backend.store import Store,canonical
from backend.backups import init_key,create_backup,restore_backup
from test_platform import system,PASSWORD,post,invited
from test_access_workflows import setup,approve
from test_extension_access import connect,headers
from test_sharing import setup_identity,grant,payload


def enable(client):
    secret=post(client,'/mfa/setup',{'password':PASSWORD}).json()['secret']
    result=post(client,'/mfa/enable',{'code':totp(secret,int(time.time()//30))})
    assert result.status_code==200,result.text
    return result.json()['recovery_codes']


def prepare(system,kind='person_handoff'):
    app,owner,other,who,departing,vaults,workflow,_=setup(system,mfa=False,vault_count=1)
    who['departing']=departing
    recipient=invited(app,owner,email='receiving@example.test');identity=setup_identity(recipient)
    rcodes=enable(recipient);codes=enable(owner)
    promotion=post(owner,'/members/'+identity['id']+'/promote-owner',{'confirmed':True,'password':PASSWORD,'code':codes[0]})
    assert promotion.status_code==200,promotion.text
    vault=vaults[0]
    assert post(owner,f'/team-vaults/{vault}/invite',grant(who,identity,vault,'editor')).status_code==200
    assert post(recipient,f'/team-vaults/{vault}/accept',{}).status_code==200
    browser,pending,result=connect(app,owner);assert result.status_code==200
    auth=headers(browser,pending)
    incoming,request,result=connect(app,recipient);assert result.status_code==200
    iauth=headers(incoming,request)
    response=browser.post('/api/companion/access/handoffs',json={'client_id':workflow['client'],'person_id':who['id'] if kind=='client_offboard' else departing['id'],'recipient_id':identity['id'],'kind':kind},headers=auth)
    assert response.status_code==200,response.text
    return app,owner,other,recipient,who,identity,vault,workflow,codes,rcodes,browser,auth,incoming,iauth,response.json()


def approve_handoff(browser,auth,row,code):
    return browser.post('/api/companion/access/handoffs/'+row['id']+'/approve',headers=auth,json={'confirmed':True,'digest':row['plan_digest'],'password':PASSWORD,'code':code})


def listing(browser,auth):return browser.get('/api/companion/access/handoffs',headers=auth).json()['handoffs'][0]


def signoff(browser,auth,row,code,**changes):
    return browser.post('/api/companion/access/handoffs/'+row['id']+'/signoff',headers=auth,json={'confirmed':True,'digest':row['evidence']['digest'],'password':PASSWORD,'code':code,'external_access':'not_applicable','device_return':'not_applicable','device_wipe':'not_applicable',**changes})


def test_handoff_requires_real_removal_rotation_and_independent_fresh_signoff(system):
    app,owner,other,recipient,who,incoming,vault,work,codes,rcodes,browser,auth,receiver,iauth,row=prepare(system)
    try:
        assert approve_handoff(browser,auth,row,codes[1]).status_code==200
        assert signoff(receiver,iauth,listing(receiver,iauth),rcodes[0]).status_code==409
        assert signoff(browser,auth,listing(browser,auth),codes[2]).status_code==403
        assert approve(app,owner,work,codes[2]).status_code==200
        app.state.review_runner.run_access(work['workspace'],work['id'])
        assert other.get('/api/team-vaults/'+vault).status_code==404
        assert post(owner,f'/team-vaults/{vault}/rotate',{'revision':1,'payload':payload(vault,2),'grants':[grant(who,who,vault,'owner',2),grant(who,incoming,vault,'editor',2)]}).status_code==200
        app.state.review_runner.run_access(work['workspace'],work['id'])
        path='/api/companion/access/handoffs/'+row['id']
        assert browser.post(path+'/link',headers=auth,json={'workflow_id':work['id']}).status_code==200
        current=listing(receiver,iauth);assert current['evidence']['issues']==[]
        assert signoff(receiver,iauth,current,'incorrect').status_code==401
        assert signoff(receiver,iauth,current,rcodes[0]).json()['status']=='complete'
        assert signoff(receiver,iauth,current,rcodes[1]).status_code==403
        final=listing(receiver,iauth)
        assert final['receipt']['actor']==incoming['id'] and not final['evidence_changed_since_signoff']
        assert PASSWORD not in str(final) and rcodes[0] not in str(final)
        assert post(owner,'/team-vaults/'+vault+'/invite',grant(who,who['departing'],vault,'editor',2)).status_code==200
        assert listing(receiver,iauth)['evidence_changed_since_signoff']
        with app.state.store.connect() as c:assert Store.audit(c,work['workspace'])['valid']
    finally:other.close();recipient.close()


def test_stale_scope_token_origin_and_expired_approval_fail_closed(system):
    app,owner,other,recipient,who,incoming,vault,work,codes,rcodes,browser,auth,receiver,iauth,row=prepare(system)
    try:
        path='/api/companion/access/handoffs/'+row['id']
        assert browser.get('/api/companion/access/handoffs',headers={**auth,'Origin':'chrome-extension://'+'b'*32}).status_code==401
        assert post(other,'/members/'+incoming['id']+'/promote-owner',{'confirmed':True,'password':PASSWORD,'code':codes[1]}).status_code==403
        with app.state.store.connect(write=True) as c:c.execute('UPDATE team_vaults SET rotation_required=1 WHERE id=?',(vault,))
        assert approve_handoff(browser,auth,row,codes[1]).status_code==409
        with app.state.store.connect(write=True) as c:c.execute('UPDATE team_vaults SET rotation_required=0 WHERE id=?',(vault,))
        assert approve_handoff(browser,auth,row,codes[1]).status_code==200
        with app.state.store.connect(write=True) as c:
            approval=json.loads(c.execute('SELECT approval FROM handoff_records WHERE id=?',(row['id'],)).fetchone()[0]);approval['expires']=0
            c.execute('UPDATE handoff_records SET approval=? WHERE id=?',(canonical(approval),row['id']))
        assert signoff(receiver,iauth,listing(receiver,iauth),rcodes[0]).status_code==409
        assert browser.post(path+'/cancel',headers=auth,json={}).status_code==200
        assert listing(browser,auth)['status']=='cancelled'
        assert owner.get('/api/access-workflows').json()['workflows'][0]['status']=='awaiting_approval'
        assert browser.post('/api/companion/access/revoke',headers=auth,json={}).status_code==200
        assert browser.get('/api/companion/access/handoffs',headers=auth).status_code==401
    finally:other.close();recipient.close()


def test_restore_cancels_handoff_approval_and_revokes_extension_grants(system,tmp_path):
    app,owner,other,recipient,who,incoming,vault,work,codes,rcodes,browser,auth,receiver,iauth,row=prepare(system)
    try:
        assert approve_handoff(browser,auth,row,codes[1]).status_code==200
        key,archive,destination=tmp_path/'key',tmp_path/'handoff.backup',tmp_path/'restored'
        init_key(key);create_backup(system[2],key,archive);restore_backup(archive,key,destination)
        with Store(destination/'sentinelops.db').connect() as c:
            restored=c.execute('SELECT * FROM handoff_records WHERE id=?',(row['id'],)).fetchone()
            assert restored['status']=='cancelled' and restored['approval'] is None
            assert not c.execute("SELECT 1 FROM entities WHERE kind='access_connection'").fetchone()
            assert Store.audit(c,work['workspace'])['valid']
    finally:other.close();recipient.close()


def test_audit_failure_rolls_back_handoff_approval(system,monkeypatch):
    app,owner,other,recipient,who,incoming,vault,work,codes,rcodes,browser,auth,receiver,iauth,row=prepare(system)
    try:
        original=Store.event
        def fail(c,workspace,actor,action,target):
            original(c,workspace,actor,action,target)
            if action=='handoff.approved':raise RuntimeError('synthetic audit failure')
        monkeypatch.setattr(Store,'event',fail)
        with pytest.raises(RuntimeError):approve_handoff(browser,auth,row,codes[1])
        assert listing(browser,auth)['status']=='awaiting_approval'
        monkeypatch.setattr(Store,'event',original)
        assert approve_handoff(browser,auth,row,codes[1]).status_code==200
    finally:other.close();recipient.close()

def test_client_offboard_requires_ownership_transfer(system):
    app,owner,other,recipient,who,incoming,vault,work,codes,rcodes,browser,auth,receiver,iauth,row=prepare(system,kind='client_offboard')
    try:
        assert approve_handoff(browser,auth,row,codes[1]).status_code==200
        assert approve(app,owner,work,codes[2]).status_code==200
        app.state.review_runner.run_access(work['workspace'],work['id'])
        assert post(owner,f'/team-vaults/{vault}/rotate',{'revision':1,'payload':payload(vault,2),'grants':[grant(who,who,vault,'owner',2),grant(who,incoming,vault,'editor',2)]}).status_code==200
        current=listing(receiver,iauth)
        assert 'ownership_transfer_incomplete:'+vault in current['evidence']['issues']
        assert signoff(receiver,iauth,current,rcodes[0]).status_code==409
    finally:other.close();recipient.close()


def test_signoff_records_external_exceptions_and_rejects_stale_digest(system):
    app,owner,other,recipient,who,incoming,vault,work,codes,rcodes,browser,auth,receiver,iauth,row=prepare(system)
    try:
        assert approve_handoff(browser,auth,row,codes[1]).status_code==200
        assert approve(app,owner,work,codes[2]).status_code==200
        app.state.review_runner.run_access(work['workspace'],work['id'])
        assert post(owner,f'/team-vaults/{vault}/rotate',{'revision':1,'payload':payload(vault,2),'grants':[grant(who,who,vault,'owner',2),grant(who,incoming,vault,'editor',2)]}).status_code==200
        app.state.review_runner.run_access(work['workspace'],work['id'])
        assert browser.post('/api/companion/access/handoffs/'+row['id']+'/link',headers=auth,json={'workflow_id':work['id']}).status_code==200
        previous=listing(receiver,iauth)
        assert post(owner,'/clients/access-records',{'client_id':work['client'],'person_id':who['departing']['id'],'domain':'example.test','account_label':'Unverified external grant'}).status_code==200
        assert signoff(receiver,iauth,previous,rcodes[0]).status_code==409
        current=listing(receiver,iauth)
        assert signoff(receiver,iauth,current,rcodes[0]).status_code==409
        assert signoff(receiver,iauth,current,rcodes[0],external_access='reviewed_unverified',device_return='unresolved').json()['status']=='complete_with_exceptions'
    finally:other.close();recipient.close()


def test_owner_promotion_requires_member_mfa_and_fresh_owner_factor(system):
    app,owner,_=system;other=invited(app,owner)
    try:
        identifier=other.get('/api/me').json()['id'];codes=enable(owner)
        body={'confirmed':True,'password':PASSWORD,'code':codes[0]}
        assert post(owner,'/members/'+identifier+'/promote-owner',body).status_code==409
        enable(other)
        assert post(owner,'/members/'+identifier+'/promote-owner',{**body,'confirmed':False}).status_code==409
        assert post(owner,'/members/'+identifier+'/promote-owner',{**body,'code':'invalid'}).status_code==401
        assert post(owner,'/members/'+identifier+'/promote-owner',body).status_code==200
        assert other.get('/api/me').json()['role']=='owner'
    finally:other.close()

def test_schema_fourteen_backup_upgrades_handoffs_without_changing_accounts(system,tmp_path):
    from backend.store import SCHEMA_VERSION
    app,owner,source=system
    with app.state.store.connect(write=True) as c:
        account=c.execute('SELECT id,email,password FROM users').fetchone()[:]
        c.execute('DROP TABLE handoff_records');c.execute('DELETE FROM schema_migrations WHERE version=15')
    key,archive,destination=tmp_path/'key',tmp_path/'schema14.backup',tmp_path/'upgraded'
    init_key(key);assert create_backup(source,key,archive)['schema']==14
    assert restore_backup(archive,key,destination)['schema']==SCHEMA_VERSION
    with Store(destination/'sentinelops.db').connect() as c:
        assert c.execute('SELECT id,email,password FROM users').fetchone()[:]==account
        assert c.execute('SELECT count(*) FROM handoff_records').fetchone()[0]==0


def test_handoff_migration_rejects_unmarked_or_partial_tables(tmp_path):
    path=tmp_path/'schema.db';store=Store(path)
    with store.connect(write=True) as c:c.execute('DELETE FROM schema_migrations WHERE version=15')
    with pytest.raises(ValueError,match='Unmarked'):Store(path)
    with store.connect(write=True) as c:
        c.execute("INSERT INTO schema_migrations VALUES(15,'fixture')")
        c.execute('ALTER TABLE handoff_records RENAME COLUMN receipt TO broken_receipt')
    with pytest.raises(ValueError,match='incomplete'):Store(path)
