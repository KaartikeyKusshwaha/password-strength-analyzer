import time
from backend.store import Store
from backend.security import digest
from backend.extension_connect import REMINDER_SCOPE,REMINDER_KIND
from test_platform import system,post,PASSWORD
from test_access_leases import prepared,activate
from test_extension_access import connect,headers
from test_extension_connect import ORIGIN,PROOF
from backend import access_leases


def test_ninety_day_reminders_never_authorize_access_or_vault_apis(system):
    app,owner,other,who,member,vaults,codes,operator,auth,lease=prepared(system)
    try:
        assert activate(operator,auth,lease,codes[0]).status_code==200
        browser,pending,result=connect(app,owner,'reminders');assert result.status_code==200,result.text
        bearer=headers(browser,pending)
        assert browser.get('/api/companion/reminders/context',headers=auth).status_code==401
        initial=browser.get('/api/companion/reminders/context',headers=bearer)
        assert initial.status_code==200 and initial.json()['alerts']==[]
        assert time.time()+89*86400<initial.json()['expires']<=time.time()+90*86400
        for path in ('vault','access/context','security/context','discovery/context'):
            assert browser.get('/api/companion/'+path,headers=bearer).status_code in {401,403}
        access_leases.tick(app.state.store,lambda:lease['plan']['remind_at'])
        current=browser.get('/api/companion/reminders/context',headers=bearer).json()
        assert current['alerts']==[{'id':lease['id'],'client':'Offboarding client','state':'expiring','expires_at':lease['plan']['expires_at']}]
        assert PASSWORD not in str(current) and member['public']['encryption'] not in str(current)
        assert browser.get('/api/companion/reminders/context',headers={**bearer,'Origin':'chrome-extension://'+'b'*32}).status_code==401
        assert browser.post('/api/companion/reminders/revoke',headers=bearer,json={}).status_code==200
        assert browser.get('/api/companion/reminders/context',headers=bearer).status_code==401
        assert operator.get('/api/companion/access/context',headers=auth).status_code==200
    finally:other.close()


def test_live_owner_mfa_expiry_and_settings_revoke_are_enforced(system):
    app,owner,other,who,member,vaults,codes,operator,auth,lease=prepared(system)
    try:
        browser,pending,response=connect(app,owner,'reminders');assert response.status_code==200
        bearer=headers(browser,pending)
        with app.state.store.connect(write=True) as c:
            grant=Store.get(c,REMINDER_SCOPE,REMINDER_KIND,digest(bearer['Authorization'][7:]));grant['expires']=0;Store.put(c,REMINDER_SCOPE,REMINDER_KIND,grant)
        assert browser.get('/api/companion/reminders/context',headers=bearer).status_code==401
        browser,pending,response=connect(app,owner,'reminders');bearer=headers(browser,pending)
        assert post(owner,'/reminder-connections/revoke',{}).status_code==200
        assert browser.get('/api/companion/reminders/context',headers=bearer).status_code==401
        browser,pending,response=connect(app,owner,'reminders');bearer=headers(browser,pending)
        with app.state.store.connect(write=True) as c:c.execute('UPDATE users SET mfa=NULL WHERE id=?',(who['id'],))
        assert browser.get('/api/companion/reminders/context',headers=bearer).status_code==403
    finally:other.close()

def test_reminder_restore_and_pending_handoff_cancellation_revoke_the_read_only_grant(system,tmp_path):
    from backend.backups import init_key,create_backup,restore_backup
    app,owner,other,who,member,vaults,codes,operator,auth,lease=prepared(system)
    try:
        browser,pending,response=connect(app,owner,'reminders');assert response.status_code==200
        bearer=headers(browser,pending)
        key,archive,destination=tmp_path/'key',tmp_path/'reminders.backup',tmp_path/'restored';init_key(key);create_backup(system[2],key,archive);restore_backup(archive,key,destination)
        with Store(destination/'sentinelops.db').connect() as c:assert not c.execute("SELECT 1 FROM entities WHERE kind='reminder_connection'").fetchone()
        assert browser.post('/api/companion/connect/'+pending['id']+'/cancel',headers={'Origin':ORIGIN},json=PROOF).status_code==200
        assert browser.get('/api/companion/reminders/context',headers=bearer).status_code==401
    finally:other.close()


def test_reminders_require_owner_mfa_and_cannot_change_scope_in_approval(system):
    app,owner,other,who,member,vaults,codes,operator,auth,lease=prepared(system)
    try:
        browser,pending,response=connect(app,other,'reminders');assert response.status_code==403
        from fastapi.testclient import TestClient
        browser=TestClient(app)
        pending=browser.post('/api/companion/connect/start',headers={'Origin':ORIGIN},json={**PROOF,'scope':'reminders'}).json()
        workspace=owner.get('/api/me').json()['workspace']
        assert post(owner,'/extension-connect/'+pending['id']+'/approve',{'workspace_id':workspace,'confirmed_code':pending['code'],'vault_id':vaults[0]}).status_code==409
        assert post(owner,'/extension-connect/'+pending['id']+'/approve',{'workspace_id':workspace,'confirmed_code':pending['code']}).status_code==200
        bearer=headers(browser,pending)
        with app.state.store.connect(write=True) as c:c.execute("UPDATE members SET role='reviewer' WHERE user=? AND workspace=?",(who['id'],workspace))
        assert browser.get('/api/companion/reminders/context',headers=bearer).status_code==403
    finally:other.close()
