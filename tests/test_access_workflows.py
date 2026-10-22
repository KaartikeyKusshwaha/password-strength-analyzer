import time
from unittest.mock import patch

import pytest

from backend import access_workflows
from backend.reviews import Runner
from backend.store import Store
from backend.security import totp
from test_platform import PASSWORD, system, invited, post
from test_sharing import setup_identity, create, grant, payload


def setup(system, dry_run=False, mfa=True, vault_count=2):
    app, client, _ = system
    other = invited(app, client)
    who, member = setup_identity(client), setup_identity(other)
    customer = post(client, '/clients', {'name': 'Offboarding client'}).json()['id']
    vaults = []
    for _ in range(vault_count):
        vault = create(client, who);vaults.append(vault)
        assert post(client, f'/clients/{customer}/vaults', {'vault_id': vault}).status_code == 200
        assert post(client, f'/team-vaults/{vault}/invite', grant(who, member, vault, 'editor')).status_code == 200
        assert post(other, f'/team-vaults/{vault}/accept', {}).status_code == 200
    recovery = ''
    if mfa:
        secret = post(client, '/mfa/setup', {'password': PASSWORD}).json()['secret']
        response = post(client, '/mfa/enable', {'code': totp(secret, int(time.time()//30))})
        assert response.status_code == 200, response.text
        recovery = response.json()['recovery_codes'][0]
    response = post(client, '/access-workflows', {'client_id': customer, 'person_id': member['id'], 'dry_run': dry_run})
    assert response.status_code == 200, response.text
    return app, client, other, who, member, vaults, response.json(), recovery


def approve(app, client, plan, code):
    with patch.object(app.state.executor, 'submit'):
        return post(client, f'/access-workflows/{plan["id"]}/approve', {'approved': True, 'plan_digest': plan['plan_digest'], 'password': PASSWORD, 'code': code})


def current(client):return client.get('/api/access-workflows').json()['workflows'][0]


def test_unapproved_and_dry_run_plans_never_revoke(system):
    app, client, other, who, member, vaults, plan, code = setup(system, dry_run=True)
    try:
        app.state.review_runner.run_access(plan['workspace'], plan['id'])
        assert current(client)['status'] == 'awaiting_approval'
        assert all(other.get(f'/api/team-vaults/{vault}').status_code == 200 for vault in vaults)
        assert approve(app, client, plan, code).status_code == 200
        app.state.review_runner.run_access(plan['workspace'], plan['id'])
        value = current(client)
        assert value['status'] == 'dry_run_complete'
        assert all(step['status'] == 'simulated' for step in value['steps'])
        assert all(other.get(f'/api/team-vaults/{vault}').status_code == 200 for vault in vaults)
    finally:other.close()


def test_real_plan_removes_both_vaults_then_waits_for_client_rotation(system):
    app, client, other, who, member, vaults, plan, code = setup(system)
    try:
        assert approve(app, client, plan, code).status_code == 200
        app.state.review_runner.run_access(plan['workspace'], plan['id'])
        value = current(client)
        assert value['status'] == 'waiting_unlock'
        assert all(other.get(f'/api/team-vaults/{vault}').status_code == 404 for vault in vaults)
        assert [step['outcome'] for step in value['steps'][:2]] == ['revoked', 'revoked']
        for vault in vaults:
            assert post(client, f'/team-vaults/{vault}/rotate', {'revision': 1, 'payload': payload(vault, 2), 'grants': [grant(who, who, vault, 'owner', 2)]}).status_code == 200
        app.state.review_runner.run_access(plan['workspace'], plan['id'])
        value = current(client)
        assert value['status'] == 'complete'
        assert all(step['attempts'] == 1 for step in value['steps'])
        assert 'website' in value['coverage']
        assert PASSWORD not in str(value) and code not in str(value)
    finally:other.close()


def test_crash_after_committed_step_resumes_without_repeating_removal(system,monkeypatch):
    app, client, other, who, member, vaults, plan, code = setup(system)
    try:
        assert approve(app, client, plan, code).status_code == 200
        actual = access_workflows.advance_one
        def crash(*args):
            actual(*args)
            raise SystemExit('simulated process crash after commit')
        monkeypatch.setattr(access_workflows, 'advance_one', crash)
        with pytest.raises(SystemExit):app.state.review_runner.run_access(plan['workspace'], plan['id'])
        monkeypatch.setattr(access_workflows, 'advance_one', actual)
        reopened = Store(app.state.store.path)
        restarted = Runner(reopened, app.state.settings, None, None)
        restarted.run_access(plan['workspace'], plan['id'])
        value = current(client)
        assert value['status'] == 'waiting_unlock'
        assert all(step['attempts'] == 1 for step in value['steps'][:2])
        with reopened.connect() as c:
            events = Store.audit(c, plan['workspace'])
            assert events['valid']
            assert sum(row['action'] == 'team_vault.access_revoked' for row in events['events']) == 2
    finally:other.close()


def test_mfa_stale_scope_and_last_owner_guards(system):
    app, client, other, who, member, vaults, plan, code = setup(system, mfa=False)
    try:
        assert approve(app, client, plan, '').status_code == 403
        response = post(client, '/access-workflows', {'client_id': plan['client'], 'person_id': who['id'], 'dry_run': False})
        assert response.status_code == 409
        assert other.get('/api/access-workflows').status_code == 403
        assert post(other, f'/access-workflows/{plan["id"]}/cancel', {}).status_code == 403
    finally:other.close()


def test_cancel_keeps_completed_removals_and_prevents_later_steps(system):
    app, client, other, who, member, vaults, plan, code = setup(system)
    try:
        assert approve(app, client, plan, code).status_code == 200
        access_workflows.advance_one(app.state.store, plan['workspace'], plan['id'])
        assert post(client, f'/access-workflows/{plan["id"]}/cancel', {}).status_code == 200
        app.state.review_runner.run_access(plan['workspace'], plan['id'])
        value = current(client)
        assert value['status'] == 'cancelled'
        assert value['steps'][0]['status'] == 'complete'
        assert all(step['status'] == 'cancelled' for step in value['steps'][1:])
        assert sum(other.get(f'/api/team-vaults/{vault}').status_code == 404 for vault in vaults) == 1
    finally:other.close()


def test_expired_approval_blocks_without_effect(system):
    app, client, other, who, member, vaults, plan, code = setup(system)
    try:
        assert approve(app, client, plan, code).status_code == 200
        access_workflows.advance_one(app.state.store, plan['workspace'], plan['id'], clock=lambda: time.time()+90000)
        assert current(client)['status'] == 'blocked'
        assert all(other.get(f'/api/team-vaults/{vault}').status_code == 200 for vault in vaults)
    finally:other.close()


def test_crash_inside_effect_rolls_back_removal_and_step_together(system,monkeypatch):
    app, client, other, who, member, vaults, plan, code = setup(system)
    try:
        assert approve(app, client, plan, code).status_code == 200
        original = access_workflows.revoke_access
        def crash(*args):
            original(*args)
            raise SystemExit('simulated crash before commit')
        monkeypatch.setattr(access_workflows, 'revoke_access', crash)
        with pytest.raises(SystemExit):access_workflows.advance_one(app.state.store, plan['workspace'], plan['id'])
        assert current(client)['steps'][0]['status'] == 'pending'
        assert all(other.get(f'/api/team-vaults/{vault}').status_code == 200 for vault in vaults)
        monkeypatch.setattr(access_workflows, 'revoke_access', original)
        app.state.review_runner.run_access(plan['workspace'], plan['id'])
        assert current(client)['status'] == 'waiting_unlock'
        with app.state.store.connect() as c:
            assert sum(e['action']=='team_vault.access_revoked' for e in Store.audit(c,plan['workspace'])['events'])==2
    finally:other.close()


def test_plan_scope_changes_require_new_approval(system):
    app, client, other, who, member, vaults, plan, code = setup(system)
    try:
        assert post(client,f'/team-vaults/{vaults[0]}/save',{'revision':1,'payload':payload(vaults[0])}).status_code==200
        assert approve(app, client, plan, code).status_code == 409
        assert current(client)['status']=='awaiting_approval'
        assert all(other.get(f'/api/team-vaults/{vault}').status_code==200 for vault in vaults)
    finally:other.close()


def test_reappeared_access_blocks_instead_of_reusing_old_approval(system):
    app, client, other, who, member, vaults, plan, code = setup(system)
    try:
        assert approve(app, client, plan, code).status_code==200
        app.state.review_runner.run_access(plan['workspace'], plan['id'])
        first=current(client)['steps'][0]['vault']
        assert post(client,f'/team-vaults/{first}/rotate',{'revision':1,'payload':payload(first,2),'grants':[grant(who,who,first,'owner',2)]}).status_code==200
        assert post(client,f'/team-vaults/{first}/invite',grant(who,member,first,'editor',2)).status_code==200
        app.state.review_runner.run_access(plan['workspace'], plan['id'])
        assert current(client)['status']=='blocked'
        assert any(step['outcome']=='access_reappeared' for step in current(client)['steps'])
    finally:other.close()


def test_restored_backup_drops_workflow_approval(system,tmp_path):
    from backend.backups import create_backup, init_key, restore_backup
    app, client, other, who, member, vaults, plan, code = setup(system)
    try:
        assert approve(app, client, plan, code).status_code==200
        key,archive,destination=tmp_path/'key',tmp_path/'backup.sentinelbackup',tmp_path/'restore'
        init_key(key);create_backup(system[2],key,archive);restore_backup(archive,key,destination)
        with Store(destination/'sentinelops.db').connect() as c:
            row=c.execute('SELECT status,approval FROM workflows WHERE id=?',(plan['id'],)).fetchone()
            assert tuple(row)==('cancelled',None)
            assert all(r[0]=='cancelled' for r in c.execute('SELECT status FROM workflow_steps WHERE workflow=?',(plan['id'],)))
            assert Store.audit(c,plan['workspace'])['valid']
    finally:other.close()


@pytest.mark.parametrize('damage',['delete','invalid_status'])
def test_incomplete_step_manifest_cannot_report_completion_or_mutate(system,damage):
    app, client, other, who, member, vaults, plan, code = setup(system)
    try:
        assert approve(app,client,plan,code).status_code==200
        with app.state.store.connect(write=True) as c:
            if damage=='delete':c.execute('DELETE FROM workflow_steps WHERE workflow=?',(plan['id'],))
            else:c.execute("UPDATE workflow_steps SET status='unknown' WHERE workflow=?",(plan['id'],))
        app.state.review_runner.run_access(plan['workspace'],plan['id'])
        assert current(client)['status']=='blocked'
        assert all(other.get(f'/api/team-vaults/{vault}').status_code==200 for vault in vaults)
    finally:other.close()


def test_workflow_migration_rolls_back_new_tables_on_failure(tmp_path,monkeypatch):
    from backend import workflow_migration
    path=tmp_path/'old-schema.db';store=Store(path)
    with store.connect(write=True) as c:
        c.execute('DROP TABLE workflow_steps');c.execute('DROP TABLE workflows');c.execute('DROP TABLE access_grants');c.execute('DROP TABLE credential_exposures');c.execute('DROP TABLE handoff_records')
        c.execute('DELETE FROM schema_migrations WHERE version>=12')
        c.execute("INSERT INTO workspaces VALUES('fixture','Keep this client space',0)")
    def fail(c):raise RuntimeError('simulated schema validation failure')
    monkeypatch.setattr(workflow_migration,'validate_layout',fail)
    with pytest.raises(RuntimeError):Store(path)
    with store.connect() as c:
        assert c.execute('SELECT max(version) FROM schema_migrations').fetchone()[0]==11
        assert not c.execute("SELECT 1 FROM sqlite_master WHERE name IN ('workflow_steps','workflows')").fetchone()
        assert c.execute("SELECT name FROM workspaces WHERE id='fixture'").fetchone()[0]=='Keep this client space'
