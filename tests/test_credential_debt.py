import hashlib
import pytest
from backend.store import Store,SCHEMA_VERSION
from backend import debt_migration
from test_platform import system,post
from test_access_workflows import setup
from test_extension_access import connect,headers
from test_extension_connect import ORIGIN,PROOF
from test_credential_actions import approval,claim,result

def shared_connection(browser,owner,vault):
    pending=browser.post('/api/companion/connect/start',json=PROOF,headers={'Origin':ORIGIN}).json()
    assert post(owner,'/extension-connect/'+pending['id']+'/approve',{'vault_id':vault,'vault_kind':'shared','confirmed_code':pending['code']}).status_code==200
    return headers(browser,pending)
def create(browser,auth,client,vault,index):
    body={'client_id':client,'vault_id':vault,'entry_ref':hashlib.sha256(str(index).encode()).hexdigest(),'domain':'github.com','account_label':'Shared fixture '+str(index),'platform':'github'}
    response=browser.post('/api/companion/access/debt',json=body,headers=auth)
    assert response.status_code==200,response.text
    return response.json(),body
def current(browser,auth):return browser.get('/api/companion/access/debt',headers=auth).json()

def test_ten_records_follow_existing_operator_then_retire_only_after_explicit_delegation(system):
    app,owner,other,who,member,vaults,plan,code=setup(system,vault_count=1)
    try:
        browser,pending,_=connect(app,owner);auth=headers(browser,pending);vault=vaults[0]
        rows=[create(browser,auth,plan['client'],vault,index)[0] for index in range(10)]
        assert current(browser,auth)['counts'][plan['client']]=={'peak':10,'active':10}
        identifier,body=approval(owner,vault,'shared',10)
        bound={'action_id':identifier,'items':[{'exposure_id':row['id'],'index':index} for index,row in enumerate(rows)]}
        assert browser.post('/api/companion/access/debt/bind',json=bound,headers=auth).status_code==200
        assert browser.post('/api/companion/access/debt/'+rows[0]['id']+'/verify',json={'confirmed':True},headers=auth).status_code==409
        vault_auth=shared_connection(browser,owner,vault)
        lease=claim(browser,vault_auth,identifier).json()['lease']
        for index in range(10):assert result(browser,vault_auth,identifier,lease,'needs_attention',index).status_code==200
        assert {row['state'] for row in current(browser,auth)['exposures']}=={'staged'}
        for index in range(10):assert result(browser,vault_auth,identifier,lease,'confirmed_by_user',index).status_code==200
        assert {row['state'] for row in current(browser,auth)['exposures']}=={'rotated'}
        for row in rows:assert browser.post('/api/companion/access/debt/'+row['id']+'/verify',json={'confirmed':True},headers=auth).status_code==200
        assert {row['state'] for row in current(browser,auth)['exposures']}=={'verified'}
        assert current(browser,auth)['counts'][plan['client']]['active']==10 # Rotation is not debt elimination.
        path='/api/companion/access/debt/'+rows[0]['id']+'/retire'
        assert browser.post(path,json={'confirmed':True},headers=auth).status_code==409
        confirmation={'confirmed':True,'delegated_access_confirmed':True,'shared_login_retired':True}
        assert browser.post(path,json=confirmation,headers=auth).status_code==200
        assert browser.post(path,json=confirmation,headers=auth).status_code==200
        assert current(browser,auth)['counts'][plan['client']]=={'peak':10,'active':9}
        assert owner.get('/api/clients/access-map').json()['debt']['counts'][plan['client']]['active']==9
        assert 'Owner' in browser.post(path,json=confirmation,headers=auth).json()['verification']
        reopen='/api/companion/access/debt/'+rows[0]['id']+'/reopen'
        assert browser.post(reopen,json={'confirmed':True},headers=auth).status_code==200
        assert browser.post(reopen,json={'confirmed':True},headers=auth).status_code==200
        assert current(browser,auth)['counts'][plan['client']]=={'peak':10,'active':10}
        with app.state.store.connect() as c:
            assert sum(event['action']=='credential_debt.retired_by_owner' for event in Store.audit(c,plan['workspace'])['events'])==1
    finally:other.close()

def test_binding_is_atomic_scoped_and_duplicate_domains_in_distinct_vaults_are_supported(system):
    app,owner,other,who,member,vaults,plan,code=setup(system)
    try:
        browser,pending,_=connect(app,owner);auth=headers(browser,pending)
        first,body=create(browser,auth,plan['client'],vaults[0],1)
        second,_=create(browser,auth,plan['client'],vaults[1],1)
        assert not browser.post('/api/companion/access/debt',json=body,headers=auth).json()['created']
        assert len(current(browser,auth)['exposures'])==2
        leaked=browser.post('/api/companion/access/debt',json={**body,'password':'never-store-debt-secret'},headers=auth)
        assert leaked.status_code==422 and 'never-store' not in leaked.text
        action,_=approval(owner,vaults[0],'shared',2)
        response=browser.post('/api/companion/access/debt/bind',json={'action_id':action,'items':[{'exposure_id':first['id'],'index':0},{'exposure_id':second['id'],'index':1}]},headers=auth)
        assert response.status_code==409
        assert all(row['action_id'] is None for row in current(browser,auth)['exposures'])
        _,security_pending,_=connect(app,owner,'security');security_auth=headers(browser,security_pending)
        assert browser.get('/api/companion/access/debt',headers=security_auth).status_code==401
        assert other.get('/api/clients/debt').status_code==403
        with app.state.store.connect() as c:assert 'never-store-debt-secret' not in '\n'.join(c.iterdump())
    finally:other.close()

def test_debt_migration_preserves_schema_thirteen_and_rolls_back_failure(tmp_path,monkeypatch):
    path=tmp_path/'legacy.db';store=Store(path)
    with store.connect(write=True) as c:
        c.execute('DROP TABLE credential_exposures');c.execute('DELETE FROM schema_migrations WHERE version=14')
        c.execute("INSERT INTO workspaces VALUES('legacy','Keep this workspace',0)")
    validate=debt_migration.validate_layout
    def fail(c):raise RuntimeError('interrupted migration')
    monkeypatch.setattr(debt_migration,'validate_layout',fail)
    with pytest.raises(RuntimeError):Store(path)
    with store.connect() as c:
        assert c.execute('SELECT max(version) FROM schema_migrations').fetchone()[0]==13
        assert not c.execute("SELECT 1 FROM sqlite_master WHERE name='credential_exposures'").fetchone()
    monkeypatch.setattr(debt_migration,'validate_layout',validate)
    with Store(path).connect() as c:
        assert c.execute('SELECT max(version) FROM schema_migrations').fetchone()[0]==SCHEMA_VERSION
        assert c.execute("SELECT name FROM workspaces WHERE id='legacy'").fetchone()[0]=='Keep this workspace'

def test_operator_outcome_and_debt_transition_rollback_together(system,monkeypatch):
    from backend import credential_debt
    app,owner,other,who,member,vaults,plan,code=setup(system,vault_count=1)
    try:
        browser,pending,_=connect(app,owner);auth=headers(browser,pending)
        row,_=create(browser,auth,plan['client'],vaults[0],1);action,_=approval(owner,vaults[0],'shared')
        assert browser.post('/api/companion/access/debt/bind',json={'action_id':action,'items':[{'exposure_id':row['id'],'index':0}]},headers=auth).status_code==200
        vault_auth=shared_connection(browser,owner,vaults[0]);lease=claim(browser,vault_auth,action).json()['lease']
        original=credential_debt.update_from_action
        def fail(*args):original(*args);raise RuntimeError('simulated interruption before commit')
        monkeypatch.setattr(credential_debt,'update_from_action',fail)
        with pytest.raises(RuntimeError):result(browser,vault_auth,action,lease,'needs_attention')
        assert current(browser,auth)['exposures'][0]['state']=='needed'
        with app.state.store.connect() as c:
            import json
            assert json.loads(c.execute('SELECT items FROM credential_actions WHERE id=?',(action,)).fetchone()[0])[0]['state']=='queued'
        monkeypatch.setattr(credential_debt,'update_from_action',original)
        assert result(browser,vault_auth,action,lease,'needs_attention').status_code==200
        assert current(browser,auth)['exposures'][0]['state']=='staged'
    finally:other.close()

def test_schema_thirteen_backup_preserves_reported_access_on_debt_upgrade(system,tmp_path):
    from backend.backups import init_key,create_backup,restore_backup
    app,owner,source=system;me=owner.get('/api/me').json()
    client=post(owner,'/clients',{'name':'Preserved metadata client'}).json()['id']
    assert post(owner,'/clients/access-records',{'client_id':client,'person_id':me['id'],'domain':'example.test','account_label':'Preserve this nickname'}).status_code==200
    with app.state.store.connect(write=True) as c:
        c.execute('DROP TABLE credential_exposures');c.execute('DELETE FROM schema_migrations WHERE version=14')
    key,archive,destination=tmp_path/'backup-key',tmp_path/'schema13.backup',tmp_path/'restored'
    init_key(key);assert create_backup(source,key,archive)['schema']==13
    recovered=restore_backup(archive,key,destination)
    assert recovered['source_schema']==13 and recovered['schema']==SCHEMA_VERSION
    with Store(destination/'sentinelops.db').connect() as c:
        assert c.execute('SELECT account_label FROM access_grants').fetchone()[0]=='Preserve this nickname'
        assert c.execute('SELECT count(*) FROM credential_exposures').fetchone()[0]==0
