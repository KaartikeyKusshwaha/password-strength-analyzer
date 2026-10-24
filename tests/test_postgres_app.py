import pytest
from fastapi.testclient import TestClient
from backend.app import Settings,create_app
from backend.store import Store
from test_platform import PASSWORD,post
from test_postgres_schema import postgres_schema
from test_postgres_store import store_for
import test_access_workflows as workflows
import test_client_access as client_access
import test_proof_packs as proof_packs
import test_handoffs as handoffs
import test_extension_ownership as extension_ownership
import test_access_reviews as access_reviews
import test_access_leases as access_leases
import test_vault_activity as vault_activity


@pytest.fixture
def pg_system(postgres_schema,tmp_path,monkeypatch):
    _,_,_,schema=postgres_schema
    store=store_for(schema)
    class StoreFactory(Store):
        def __new__(cls,path):return store
    monkeypatch.setattr('backend.app.Store',StoreFactory)
    app=create_app(Settings(data_dir=tmp_path,groq_key='',admin_mfa_required=False))
    with TestClient(app) as client:
        response=post(client,'/setup',dict(email='owner@example.test',password=PASSWORD,token=(tmp_path/'.bootstrap-token').read_text()))
        assert response.status_code==200,response.text
        yield app,client,tmp_path


def test_postgres_login_bootstrap_and_scope_survive_reopen(pg_system):
    app,client,_=pg_system
    before=client.get('/api/me').json()
    assert post(client,'/logout',{}).status_code==200
    assert post(client,'/login',dict(email='owner@example.test',password=PASSWORD)).status_code==200
    assert client.get('/api/me').json()['id']==before['id']
    assert client.get('/api/workspace').status_code==200
    assert post(client,'/setup',dict(email='other@example.test',password=PASSWORD,token='invalid')).status_code==409
    with app.state.store.connect() as c:assert Store.audit(c,before['workspace'])['valid']


@pytest.mark.parametrize('case',[
    workflows.test_unapproved_and_dry_run_plans_never_revoke,
    workflows.test_real_plan_removes_both_vaults_then_waits_for_client_rotation,
    workflows.test_mfa_stale_scope_and_last_owner_guards,
    workflows.test_cancel_keeps_completed_removals_and_prevents_later_steps,
    client_access.test_live_map_tracks_invites_revocation_and_rotation_without_payloads,
],ids=lambda case:case.__name__)
def test_existing_offboarding_cases_on_postgres(pg_system,case):
    case(pg_system)


@pytest.mark.parametrize('case',[
    vault_activity.test_personal_lifecycle_is_private_vault_scoped_and_contains_no_ciphertext,
    vault_activity.test_keyset_pagination_is_bounded_and_stable_while_new_events_arrive,
    vault_activity.test_shared_activity_requires_current_membership_accepted_grant_and_workspace,
],ids=lambda case:case.__name__)
def test_existing_vault_activity_cases_on_postgres(pg_system,case):
    case(pg_system)


def test_existing_proof_pack_generation_on_postgres(pg_system,tmp_path):
    proof_packs.test_client_snapshot_pdf_real_removals_posture_redaction_and_private_then_shared(pg_system,tmp_path)


@pytest.mark.parametrize('case',[
    handoffs.test_handoff_requires_real_removal_rotation_and_independent_fresh_signoff,
    extension_ownership.test_extension_transfer_uses_signed_protocol_and_completes_real_handoff,
    access_reviews.test_weekly_pipeline_requires_consent_drafts_then_fresh_signoff_and_no_access_effects,
],ids=lambda case:case.__name__)
def test_existing_extension_workflows_on_postgres(pg_system,case):
    case(pg_system)


def test_freelancer_expiry_removal_rotation_and_rechecks_on_postgres(pg_system,monkeypatch):
    access_leases.test_thirty_day_policy_reminds_once_revokes_rotates_and_rechecks(pg_system,monkeypatch)


def test_hosted_startup_requires_persistent_key_before_database_access(tmp_path,monkeypatch):
    monkeypatch.delenv('APP_ENCRYPTION_KEY',raising=False)
    with pytest.raises(ValueError,match='APP_ENCRYPTION_KEY'):
        create_app(Settings(data_dir=tmp_path,groq_key='',database_url='postgresql://never-connect.invalid/app?sslmode=verify-full'))
    assert not (tmp_path/'.encryption-key').exists()


def test_hosted_bootstrap_restart_retains_account_and_mfa_key(postgres_schema,tmp_path,monkeypatch):
    from cryptography.fernet import Fernet
    _,_,_,schema=postgres_schema;store=store_for(schema)
    monkeypatch.setattr('backend.postgres.PostgresStore',lambda url:store)
    key=Fernet.generate_key();monkeypatch.setenv('APP_ENCRYPTION_KEY',key.decode())
    bootstrap='Disposable-bootstrap-only-'+('x'*32)
    monkeypatch.setenv('BOOTSTRAP_TOKEN',bootstrap)
    settings=Settings(data_dir=tmp_path,groq_key='',admin_mfa_required=False,database_url='postgresql://fixture')
    first=create_app(settings)
    ciphertext=first.state.cipher.encrypt(b'disposable MFA fixture')
    with TestClient(first) as client:
        assert post(client,'/setup',dict(email='owner@example.test',password=PASSWORD,token=bootstrap)).status_code==200
    assert not (tmp_path/'.encryption-key').exists()
    second=create_app(settings)
    with TestClient(second) as client:
        assert not client.get('/api/status').json()['setup_required']
        assert not (tmp_path/'.bootstrap-token').exists()
        assert second.state.cipher.decrypt(ciphertext)==b'disposable MFA fixture'
        assert post(client,'/login',dict(email='owner@example.test',password=PASSWORD)).status_code==200


def test_missing_postgres_table_is_not_recreated_on_start(postgres_schema):
    c,_,_,schema=postgres_schema
    c.execute('DROP TABLE handoff_records')
    with pytest.raises(ValueError,match='incomplete or incompatible'):store_for(schema)


def test_missing_postgres_permission_constraint_is_rejected(postgres_schema):
    c,_,_,schema=postgres_schema
    c.execute('ALTER TABLE devices DROP CONSTRAINT devices__allow_updates__boolean')
    with pytest.raises(ValueError,match='permission constraints'):store_for(schema)
