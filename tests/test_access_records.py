import pytest
from fastapi.testclient import TestClient
from backend.store import Store,SCHEMA_VERSION
from backend import access_records_migration
from test_platform import system,post,invited
from test_extension_connect import ORIGIN,PROOF
from test_sharing import setup_identity,create,grant


def connection(app,user):
    browser=TestClient(app)
    pending=browser.post('/api/companion/connect/start',json={**PROOF,'scope':'discovery'},headers={'Origin':ORIGIN}).json()
    workspace=user.get('/api/me').json()['workspace']
    response=post(user,'/extension-connect/'+pending['id']+'/approve',{'workspace_id':workspace,'confirmed_code':pending['code']})
    assert response.status_code==200,response.text
    token=browser.post('/api/companion/connect/'+pending['id']+'/poll',json=PROOF,headers={'Origin':ORIGIN}).json()['token']
    return browser,{'Origin':ORIGIN,'Authorization':'Bearer '+token}


def customer(client):return post(client,'/clients',{'name':'Metadata client'}).json()['id']


def test_manual_metadata_is_explicit_workspace_bound_idempotent_and_retirable(system):
    app,owner,_=system;other=invited(app,owner)
    try:
        person=other.get('/api/me').json()['id'];client=customer(owner)
        body={'client_id':client,'person_id':person,'domain':'APP.Example.com','account_label':'Agency social','role':'editor'}
        response=post(owner,'/clients/access-records',body);assert response.status_code==200,response.text
        assert response.json()['created']
        assert not post(owner,'/clients/access-records',body).json()['created']
        mapped=owner.get('/api/clients/access-map').json();row=mapped['grants'][0]
        assert row['source']=='manual' and row['state']=='reported' and row['account_label']=='Agency social'
        assert mapped['systems'][0]['kind']=='reported_account' and mapped['systems'][0]['name']=='app.example.com'
        assert post(other,'/clients/access-records',body).status_code==403
        assert post(owner,'/clients/access-records',{**body,'person_id':'f'*24}).status_code==404
        assert post(owner,'/clients/access-records',{**body,'client_id':'f'*24}).status_code==404
        assert post(owner,'/clients/access-records',{**body,'domain':'https://host.test/path?token=do-not-store'}).status_code==422
        identifier=response.json()['id']
        assert post(owner,'/clients/access-records/'+identifier+'/retire',{}).status_code==200
        mapped=owner.get('/api/clients/access-map').json()
        assert not mapped['grants'] and mapped['retired_records'][0]['state']=='retired'
        assert not post(owner,'/clients/access-records',body).json()['created']
        with app.state.store.connect() as c:
            events=Store.audit(c,owner.get('/api/me').json()['workspace'])['events']
            assert sum(event['action']=='access_metadata.recorded' for event in events)==1
            assert sum(event['action']=='access_metadata.reappeared' for event in events)==1
    finally:other.close()


def test_discovery_records_only_consented_own_metadata_and_revokes_cleanly(system):
    app,owner,_=system;client=customer(owner);browser,headers=connection(app,owner)
    for path in ('vault','security/context','access/context'):
        assert browser.get('/api/companion/'+path,headers=headers).status_code==401
    assert browser.get('/api/clients/access-map',headers=headers).status_code==401
    assert browser.post('/api/companion/discovery/observe',json={'consent_id':'f'*24},headers=headers).status_code==404
    consent=browser.post('/api/companion/discovery/consents',json={'client_id':client,'domain':'example.test','account_label':'My client account'},headers=headers)
    assert consent.status_code==200,consent.text
    identifier=consent.json()['id']
    path='/api/companion/discovery/observe'
    rejected=browser.post(path,json={'consent_id':identifier,'password':'fixture-secret-never-store'},headers=headers)
    assert rejected.status_code==422 and 'fixture-secret' not in rejected.text
    assert browser.post(path,json={'consent_id':identifier},headers=headers).json()['created']
    assert not browser.post(path,json={'consent_id':identifier},headers=headers).json()['created']
    mapped=owner.get('/api/clients/access-map').json()
    assert len(mapped['grants'])==1 and mapped['grants'][0]['state']=='observed'
    assert mapped['grants'][0]['source']=='extension_discovery'
    assert mapped['grants'][0]['person_id']==owner.get('/api/me').json()['id']
    with app.state.store.connect() as c:assert 'fixture-secret' not in '\n'.join(c.iterdump())
    assert browser.post('/api/companion/discovery/consents/'+identifier+'/disable',json={},headers=headers).status_code==200
    assert browser.post(path,json={'consent_id':identifier},headers=headers).status_code==404
    assert owner.get('/api/clients/access-map').json()['grants'] # Stopping collection does not claim removal.
    capabilities=owner.get('/api/extension-capabilities').json()['connections']
    assert len(capabilities)==1 and 'token' not in capabilities[0]
    assert post(owner,'/extension-capabilities/discovery/'+capabilities[0]['id']+'/revoke',{}).status_code==200
    assert browser.get('/api/companion/discovery/context',headers=headers).status_code==401


def test_discovery_restore_and_live_role_loss_stop_observation_without_deleting_history(system):
    app,owner,_=system;client=customer(owner);browser,headers=connection(app,owner)
    body={'client_id':client,'domain':'example.test','account_label':'Own nickname'}
    consent=browser.post('/api/companion/discovery/consents',json=body,headers=headers).json()
    assert browser.post('/api/companion/discovery/observe',json={'consent_id':consent['id']},headers=headers).status_code==200
    me=owner.get('/api/me').json()
    with app.state.store.connect(write=True) as c:c.execute("UPDATE members SET role='viewer' WHERE workspace=? AND user=?",(me['workspace'],me['id']))
    assert browser.post('/api/companion/discovery/observe',json={'consent_id':consent['id']},headers=headers).status_code==403
    with app.state.store.connect(write=True) as c:
        c.execute("UPDATE members SET role='owner' WHERE workspace=? AND user=?",(me['workspace'],me['id']))
        from backend.backups import suspend_authorizations
        suspend_authorizations(c)
        assert c.execute('SELECT count(*) FROM access_grants').fetchone()[0]==1
        assert not Store.all(c,me['workspace'],'discovery_consents')
    assert browser.get('/api/companion/discovery/context',headers=headers).status_code==401


def test_staff_discovery_cannot_claim_another_client_or_person_and_loses_scope_on_vault_removal(system):
    app,owner,_=system;other=invited(app,owner)
    try:
        who,member=setup_identity(owner),setup_identity(other);vault=create(owner,who);client=customer(owner);secret_client=customer(owner)
        post(owner,'/clients/'+client+'/vaults',{'vault_id':vault})
        post(owner,'/team-vaults/'+vault+'/invite',grant(who,member,vault,'editor'))
        browser,headers=connection(app,other)
        assert not browser.get('/api/companion/discovery/context',headers=headers).json()['clients']
        assert post(other,'/team-vaults/'+vault+'/accept',{}).status_code==200
        assert [item['id'] for item in browser.get('/api/companion/discovery/context',headers=headers).json()['clients']]==[client]
        body={'client_id':client,'domain':'example.test','account_label':'Staff nickname'}
        assert browser.post('/api/companion/discovery/consents',json={**body,'client_id':secret_client},headers=headers).status_code==403
        assert browser.post('/api/companion/discovery/consents',json={**body,'person_id':who['id']},headers=headers).status_code==422
        consent=browser.post('/api/companion/discovery/consents',json=body,headers=headers).json()
        assert post(owner,'/team-vaults/'+vault+'/revoke/'+member['id'],{}).status_code==200
        assert browser.post('/api/companion/discovery/observe',json={'consent_id':consent['id']},headers=headers).status_code==403
        with app.state.store.connect(write=True) as c:c.execute('DELETE FROM members WHERE workspace=? AND user=?',(owner.get('/api/me').json()['workspace'],member['id']))
        assert browser.get('/api/companion/discovery/context',headers=headers).status_code==403
    finally:other.close()


def test_reported_access_migration_preserves_prior_data_and_rolls_back_failure(tmp_path,monkeypatch):
    path=tmp_path/'legacy.db';store=Store(path)
    with store.connect(write=True) as c:
        c.execute('DROP TABLE access_grants');c.execute('DROP TABLE credential_exposures');c.execute('DROP TABLE handoff_records');c.execute('DELETE FROM schema_migrations WHERE version>=13')
        c.execute("INSERT INTO workspaces VALUES('old','Retain this workspace',0)")
    original=access_records_migration.validate_layout
    monkeypatch.setattr(access_records_migration,'validate_layout',lambda c:(_ for _ in ()).throw(RuntimeError('interrupted')))
    with pytest.raises(RuntimeError):Store(path)
    with store.connect() as c:
        assert c.execute('SELECT max(version) FROM schema_migrations').fetchone()[0]==12
        assert not c.execute("SELECT 1 FROM sqlite_master WHERE name='access_grants'").fetchone()
    monkeypatch.setattr(access_records_migration,'validate_layout',original)
    for _ in range(2):
        with Store(path).connect() as c:
            assert c.execute("SELECT name FROM workspaces WHERE id='old'").fetchone()[0]=='Retain this workspace'
            assert c.execute('SELECT max(version) FROM schema_migrations').fetchone()[0]==SCHEMA_VERSION
