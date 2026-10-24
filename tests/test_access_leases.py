import time
import json
from unittest.mock import patch
import pytest
from backend import access_leases,access_workflows,access_evidence
from backend.store import Store
from backend.backups import init_key,create_backup,restore_backup
from test_platform import system,post,PASSWORD
from test_access_workflows import setup,approve
from test_handoffs import enable
from test_extension_access import connect,headers
from test_sharing import grant,payload


def prepared(system,mode='auto_revoke'):
    app,owner,other,who,member,vaults,old,_=setup(system,mfa=False)
    codes=enable(owner);browser,pending,result=connect(app,owner);assert result.status_code==200
    auth=headers(browser,pending);due=int(time.time())+30*86400
    result=browser.post('/api/companion/access/leases',headers=auth,json={'client_id':old['client'],'person_id':member['id'],'expires_at':due,'mode':mode})
    assert result.status_code==200,result.text
    return app,owner,other,who,member,vaults,codes,browser,auth,result.json()


def activate(browser,auth,row,code):
    return browser.post('/api/companion/access/leases/'+row['id']+'/approve',headers=auth,json={'approved':True,'plan_digest':row['plan_digest'],'password':PASSWORD,'code':code})


def current(browser,auth):return browser.get('/api/companion/access/leases',headers=auth).json()['leases'][0]


def run(app,workspace,identifier,at,monkeypatch):
    original=access_workflows.advance_one
    with monkeypatch.context() as context:
        context.setattr(access_workflows,'advance_one',lambda *args:original(*args,clock=lambda:at))
        app.state.review_runner.run_access(workspace,identifier)


def test_thirty_day_policy_reminds_once_revokes_rotates_and_rechecks(system,monkeypatch):
    app,owner,other,who,member,vaults,codes,browser,auth,row=prepared(system)
    try:
        workspace=owner.get('/api/me').json()['workspace'];due=row['plan']['expires_at']
        access_leases.tick(app.state.store,lambda:due+1)
        assert current(browser,auth)['status']=='awaiting_approval' # no stored authority, no effect
        assert activate(browser,auth,row,codes[0]).status_code==200
        access_leases.tick(app.state.store,lambda:row['plan']['remind_at']-1)
        assert not current(browser,auth)['reminder_sent']
        for _ in range(2):access_leases.tick(app.state.store,lambda:row['plan']['remind_at'])
        assert current(browser,auth)['reminder_sent']
        with app.state.store.connect() as c:assert c.execute("SELECT count(*) FROM audit WHERE action='access_lease.expiry_reminder'").fetchone()[0]==1
        assert all(other.get('/api/team-vaults/'+vault).status_code==200 for vault in vaults)
        for _ in range(2):access_leases.tick(app.state.store,lambda:due+1)
        active=current(browser,auth);identifier=active['workflow'];assert active['status']=='executing'
        run(app,workspace,identifier,due+1,monkeypatch)
        assert all(other.get('/api/team-vaults/'+vault).status_code==404 for vault in vaults)
        access_leases.tick(app.state.store,lambda:due+2);assert current(browser,auth)['status']=='waiting_unlock'
        for vault in vaults:assert post(owner,'/team-vaults/'+vault+'/rotate',{'revision':1,'payload':payload(vault,2),'grants':[grant(who,who,vault,'owner',2)]}).status_code==200
        run(app,workspace,identifier,due+3,monkeypatch);access_leases.tick(app.state.store,lambda:due+4)
        assert current(browser,auth)['status']=='complete'
        with app.state.store.connect() as c:
            checks=Store.all(c,workspace,'access_rechecks');assert len(checks)==3 and min(item['due'] for item in checks)==due+3+86400
            assert Store.audit(c,workspace)['valid']
            assert c.execute("SELECT count(*) FROM workflows WHERE json_extract(plan,'$.source.id')=?",(row['id'],)).fetchone()[0]==1
        value=current(browser,auth);assert PASSWORD not in str(value) and codes[0] not in str(value)
    finally:other.close()


def test_ordinary_vault_changes_are_allowed_but_owner_identity_and_links_are_bound(system,monkeypatch):
    app,owner,other,who,member,vaults,codes,browser,auth,row=prepared(system)
    try:
        assert activate(browser,auth,row,codes[0]).status_code==200
        # A normal payload revision must not make a 30-day expiry approval useless.
        assert post(owner,'/team-vaults/'+vaults[0]+'/save',{'revision':1,'payload':payload(vaults[0])}).status_code==200
        due=row['plan']['expires_at'];access_leases.tick(app.state.store,lambda:due+1)
        active=current(browser,auth);workspace=owner.get('/api/me').json()['workspace']
        run(app,workspace,active['workflow'],due+1,monkeypatch)
        assert all(other.get('/api/team-vaults/'+vault).status_code==404 for vault in vaults)
    finally:other.close()


def test_cancel_after_enqueue_stops_the_original_runner_without_regranting(system,monkeypatch):
    app,owner,other,who,member,vaults,codes,browser,auth,row=prepared(system)
    try:
        assert activate(browser,auth,row,codes[0]).status_code==200
        due=row['plan']['expires_at'];access_leases.tick(app.state.store,lambda:due+1);active=current(browser,auth)
        assert browser.post('/api/companion/access/leases/'+row['id']+'/cancel',headers=auth,json={}).status_code==200
        run(app,owner.get('/api/me').json()['workspace'],active['workflow'],due+1,monkeypatch)
        assert all(other.get('/api/team-vaults/'+vault).status_code==200 for vault in vaults)
        assert current(browser,auth)['status']=='cancelled'
    finally:other.close()


def test_departure_schedule_only_prepares_a_fresh_approval_plan(system):
    app,owner,other,who,member,vaults,codes,browser,auth,row=prepared(system,'scheduled_departure')
    try:
        assert activate(browser,auth,row,codes[0]).status_code==200
        access_leases.tick(app.state.store,lambda:row['plan']['expires_at']+1);active=current(browser,auth)
        assert active['status']=='ready_for_approval' and active['workflow_status']=='awaiting_approval'
        workspace=owner.get('/api/me').json()['workspace'];app.state.review_runner.run_access(workspace,active['workflow'])
        assert all(other.get('/api/team-vaults/'+vault).status_code==200 for vault in vaults)
        plan=next(item for item in owner.get('/api/access-workflows').json()['workflows'] if item['id']==active['workflow'])
        assert approve(app,owner,plan,codes[1]).status_code==200
        app.state.review_runner.run_access(workspace,active['workflow'])
        assert all(other.get('/api/team-vaults/'+vault).status_code==404 for vault in vaults)
    finally:other.close()


@pytest.mark.parametrize('change',['owner_mfa','client_link','recipient_owner','late'])
def test_due_policy_blocks_on_lost_authority_changed_scope_or_late_execution(system,change):
    app,owner,other,who,member,vaults,codes,browser,auth,row=prepared(system)
    try:
        assert activate(browser,auth,row,codes[0]).status_code==200
        workspace=owner.get('/api/me').json()['workspace']
        with app.state.store.connect(write=True) as c:
            if change=='owner_mfa':c.execute('UPDATE users SET mfa=NULL WHERE id=?',(who['id'],))
            elif change=='client_link':c.execute('DELETE FROM client_vaults WHERE vault=?',(vaults[0],))
            elif change=='recipient_owner':c.execute("UPDATE members SET role='owner' WHERE user=? AND workspace=?",(member['id'],workspace))
        due=row['plan']['expires_at']+(8*86400 if change=='late' else 1)
        access_leases.tick(app.state.store,lambda:due)
        with app.state.store.connect() as c:
            actual=Store.get(c,workspace,access_leases.KIND,row['id']);assert actual['status']=='blocked'
            assert not actual['workflow']
            assert all(c.execute('SELECT 1 FROM team_grants WHERE vault=? AND user=?',(vault,member['id'])).fetchone() for vault in vaults)
    finally:other.close()


def test_restore_cancels_active_expiry_authority_and_parent_child(system,tmp_path):
    app,owner,other,who,member,vaults,codes,browser,auth,row=prepared(system)
    try:
        assert activate(browser,auth,row,codes[0]).status_code==200
        access_leases.tick(app.state.store,lambda:row['plan']['expires_at']+1);active=current(browser,auth)
        key,archive,destination=tmp_path/'key',tmp_path/'expiry.backup',tmp_path/'restored';init_key(key);create_backup(system[2],key,archive);restore_backup(archive,key,destination)
        with Store(destination/'sentinelops.db').connect() as c:
            saved=c.execute('SELECT workspace FROM workflows WHERE id=?',(active['workflow'],)).fetchone()
            restored=Store.get(c,saved['workspace'],access_leases.KIND,row['id'])
            assert restored['status']=='cancelled' and restored['approval'] is None
            assert c.execute('SELECT status,approval FROM workflows WHERE id=?',(active['workflow'],)).fetchone()[:]==('cancelled',None)
    finally:other.close()

def test_already_removed_and_rotated_grants_need_no_unnecessary_new_key(system,monkeypatch):
    app,owner,other,who,member,vaults,codes,browser,auth,row=prepared(system)
    try:
        assert activate(browser,auth,row,codes[0]).status_code==200
        for vault in vaults:
            assert post(owner,'/team-vaults/'+vault+'/revoke/'+member['id'],{}).status_code==200
            assert post(owner,'/team-vaults/'+vault+'/rotate',{'revision':1,'payload':payload(vault,2),'grants':[grant(who,who,vault,'owner',2)]}).status_code==200
        due=row['plan']['expires_at'];access_leases.tick(app.state.store,lambda:due+1);active=current(browser,auth)
        run(app,owner.get('/api/me').json()['workspace'],active['workflow'],due+1,monkeypatch);access_leases.tick(app.state.store,lambda:due+2)
        assert current(browser,auth)['status']=='complete'
        access_evidence.tick(app.state.store,lambda:due+1+86400)
        with app.state.store.connect() as c:assert any(item['status']=='verified' for item in Store.all(c,owner.get('/api/me').json()['workspace'],'access_rechecks'))
        with app.state.store.connect() as c:assert all(c.execute('SELECT epoch FROM team_vaults WHERE id=?',(vault,)).fetchone()[0]==2 for vault in vaults)
    finally:other.close()


def test_parent_approval_is_rechecked_after_enqueue(system,monkeypatch):
    app,owner,other,who,member,vaults,codes,browser,auth,row=prepared(system)
    try:
        assert activate(browser,auth,row,codes[0]).status_code==200
        due=row['plan']['expires_at'];access_leases.tick(app.state.store,lambda:due+1);active=current(browser,auth);workspace=owner.get('/api/me').json()['workspace']
        with app.state.store.connect(write=True) as c:
            record=Store.get(c,workspace,access_leases.KIND,row['id']);record['approval']=None;Store.put(c,workspace,access_leases.KIND,record)
        run(app,workspace,active['workflow'],due+1,monkeypatch)
        assert all(other.get('/api/team-vaults/'+vault).status_code==200 for vault in vaults)
        with app.state.store.connect() as c:assert c.execute('SELECT status FROM workflows WHERE id=?',(active['workflow'],)).fetchone()[0]=='blocked'
    finally:other.close()


def test_due_creation_rolls_back_on_audit_failure_and_restarts_once(system,monkeypatch):
    app,owner,other,who,member,vaults,codes,browser,auth,row=prepared(system)
    try:
        assert activate(browser,auth,row,codes[0]).status_code==200
        due=row['plan']['expires_at'];event=Store.event
        def fail(c,workspace,actor,action,target):
            event(c,workspace,actor,action,target)
            if action=='access_lease.due':raise RuntimeError('synthetic mid-commit crash')
        with monkeypatch.context() as context:
            context.setattr(Store,'event',fail)
            with pytest.raises(RuntimeError):access_leases.tick(app.state.store,lambda:due+1)
        assert current(browser,auth)['status']=='active' and not current(browser,auth)['workflow']
        access_leases.tick(app.state.store,lambda:due+1)
        assert current(browser,auth)['status']=='executing'
        with app.state.store.connect() as c:assert c.execute("SELECT count(*) FROM workflows WHERE json_extract(plan,'$.source.id')=?",(row['id'],)).fetchone()[0]==1
    finally:other.close()


def test_expiry_approval_binds_digest_factor_target_and_unique_policy(system):
    app,owner,other,who,member,vaults,codes,browser,auth,row=prepared(system)
    try:
        path='/api/companion/access/leases/'+row['id']+'/approve'
        assert browser.post(path,headers=auth,json={'approved':True,'plan_digest':'a'*64,'password':PASSWORD,'code':codes[0]}).status_code==409
        assert activate(browser,auth,row,'invalid-factor').status_code==401
        assert activate(browser,auth,row,codes[0]).status_code==200
        assert activate(browser,auth,row,codes[1]).status_code==409
        duplicate={'client_id':row['client'],'person_id':row['person'],'expires_at':row['plan']['expires_at']}
        assert browser.post('/api/companion/access/leases',headers=auth,json=duplicate).status_code==409
        assert browser.post('/api/companion/access/leases',headers=auth,json={**duplicate,'expires_at':int(time.time())-1}).status_code==422
        assert other.get('/api/access-leases').status_code==403
        assert browser.get('/api/companion/access/leases',headers={**auth,'Origin':'chrome-extension://'+'b'*32}).status_code==401
    finally:other.close()

def test_expiry_never_broadens_to_vaults_added_after_approval(system,monkeypatch):
    from test_sharing import create
    app,owner,other,who,member,vaults,codes,browser,auth,row=prepared(system)
    try:
        assert activate(browser,auth,row,codes[0]).status_code==200
        extra=create(owner,who);assert post(owner,'/clients/'+row['client']+'/vaults',{'vault_id':extra}).status_code==200
        assert post(owner,'/team-vaults/'+extra+'/invite',grant(who,member,extra,'editor')).status_code==200
        assert post(other,'/team-vaults/'+extra+'/accept',{}).status_code==200
        assert current(browser,auth)['uncovered_vaults']==[extra]
        due=row['plan']['expires_at'];access_leases.tick(app.state.store,lambda:due+1);active=current(browser,auth)
        run(app,owner.get('/api/me').json()['workspace'],active['workflow'],due+1,monkeypatch)
        assert all(other.get('/api/team-vaults/'+vault).status_code==404 for vault in vaults)
        assert other.get('/api/team-vaults/'+extra).status_code==200
    finally:other.close()


def test_valid_expiry_is_not_blocked_by_the_manual_workflow_history_limit(system):
    app,owner,other,who,member,vaults,codes,browser,auth,row=prepared(system)
    try:
        assert activate(browser,auth,row,codes[0]).status_code==200
        workspace=owner.get('/api/me').json()['workspace']
        with app.state.store.connect(write=True) as c:
            count=c.execute('SELECT count(*) FROM workflows WHERE workspace=?',(workspace,)).fetchone()[0]
            for index in range(count,1000):c.execute('INSERT INTO workflows VALUES(?,?,?,?,?,?,?,?,?,?,?)',(f'{index:024x}',workspace,row['client'],row['person'],who['id'],'complete','{}','fixture',None,'fixture','fixture'))
        access_leases.tick(app.state.store,lambda:row['plan']['expires_at']+1)
        assert current(browser,auth)['status']=='executing'
        with app.state.store.connect() as c:assert c.execute('SELECT count(*) FROM workflows WHERE workspace=?',(workspace,)).fetchone()[0]==1001
    finally:other.close()

def test_pending_invitation_expires_without_waiting_for_the_recipient_to_accept(system,monkeypatch):
    app,owner,other,who,member,vaults,codes,browser,auth,row=prepared(system)
    try:
        vault=vaults[0]
        assert post(owner,'/team-vaults/'+vault+'/revoke/'+member['id'],{}).status_code==200
        assert post(owner,'/team-vaults/'+vault+'/rotate',{'revision':1,'payload':payload(vault,2),'grants':[grant(who,who,vault,'owner',2)]}).status_code==200
        assert post(owner,'/team-vaults/'+vault+'/invite',grant(who,member,vault,'editor',2)).status_code==200
        assert other.get('/api/team-vaults/'+vault).json()['accepted'] is False
        assert activate(browser,auth,row,codes[0]).status_code==200
        due=row['plan']['expires_at'];access_leases.tick(app.state.store,lambda:due+1);active=current(browser,auth)
        run(app,owner.get('/api/me').json()['workspace'],active['workflow'],due+1,monkeypatch)
        assert other.get('/api/team-vaults/'+vault).status_code==404
    finally:other.close()

def test_another_current_workspace_owner_can_cancel_an_expiry_policy(system):
    from test_platform import invited
    app,owner,other,who,member,vaults,codes,browser,auth,row=prepared(system)
    receiving=invited(app,owner,email='expiry-operator@example.test')
    try:
        assert activate(browser,auth,row,codes[0]).status_code==200
        enable(receiving);identifier=receiving.get('/api/me').json()['id']
        assert post(owner,'/members/'+identifier+'/promote-owner',{'confirmed':True,'password':PASSWORD,'code':codes[1]}).status_code==200
        alternate,pending,response=connect(app,receiving);assert response.status_code==200
        assert alternate.post('/api/companion/access/leases/'+row['id']+'/cancel',headers=headers(alternate,pending),json={}).status_code==200
        assert current(browser,auth)['status']=='cancelled'
    finally:receiving.close();other.close()

def test_scheduler_rotates_bounded_batches_without_starving_later_policies(system):
    from backend.store import uid
    app,owner,other,who,member,vaults,codes,browser,auth,row=prepared(system)
    try:
        assert activate(browser,auth,row,codes[0]).status_code==200
        workspace=owner.get('/api/me').json()['workspace'];at=time.time()
        with app.state.store.connect(write=True) as c:
            original=Store.get(c,workspace,access_leases.KIND,row['id'])
            # Synthetic batch spans the scheduler's global 100-record limit;
            # production applies its separate per-workspace active-policy bound.
            for _ in range(100):Store.put(c,workspace,access_leases.KIND,{**original,'id':uid()})
        access_leases.tick(app.state.store,lambda:at)
        with app.state.store.connect() as c:assert sum('last_checked' in item for item in Store.all(c,workspace,access_leases.KIND))==100
        access_leases.tick(app.state.store,lambda:at+1)
        with app.state.store.connect() as c:assert all('last_checked' in item for item in Store.all(c,workspace,access_leases.KIND))
    finally:other.close()
