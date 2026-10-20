"""Credential persistence, real signatures and race tests in disposable stores."""
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
import secrets
from threading import Barrier

import pytest

from backend import passkey_credentials as credentials
from backend.passkey_protocol import PasskeyError, RelyingParty
from backend.passkey_ceremonies import Ceremonies, Scope, install_schema as install_ceremonies
from backend.store import Store
from test_passkey_protocol import authenticator

USER, OTHER = 'a' * 24, 'b' * 24


@pytest.fixture
def store(tmp_path):
    value = Store(tmp_path / 'credential-fixture.db')
    with value.connect(write=True) as c:
        credentials.install_schema(c)
        install_ceremonies(c)
        c.executemany('INSERT INTO users(id,email,password) VALUES(?,?,?)',
                      [(USER,'fixture@example.test','not-an-authentication-fixture'),
                       (OTHER,'other@example.test','not-an-authentication-fixture')])
    return value


def register(store, authenticator, user=USER, flags=None, counter=0):
    party, identifier, _, response = authenticator
    challenge = secrets.token_bytes(32)
    verified = party.register(response('create',challenge,flags=flags,counter=counter),challenge)
    with store.connect(write=True) as c:
        key = credentials.register(c,user,party,' Test device ',verified,clock=lambda:1000)
    return key, verified


def snapshot(store, authenticator, user=USER):
    party, identifier, _, _ = authenticator
    with store.connect() as c:
        return credentials.lookup(c,user,party,identifier)


def proof(authenticator, observed, counter=1, flags=None):
    party, _, _, response = authenticator
    challenge = secrets.token_bytes(32)
    return party.authenticate(response('get',challenge,counter=counter,flags=flags,handle=observed.user.encode()),
                              challenge,observed.credential_id,observed.public_key,observed.sign_count,observed.user.encode())


def test_real_registration_signature_persistence_and_safe_public_listing(store, authenticator):
    identifier, verified = register(store,authenticator)
    observed = snapshot(store,authenticator)
    assert observed.id == identifier and observed.sign_count == 0 and observed.revision == 0
    assert observed.public_key == verified.credential_public_key
    with store.connect(write=True) as c:
        assert credentials.commit_authentication(c,observed,proof(authenticator,observed),clock=lambda:1001) == USER
    # Reopen the actual file: the counter and revision are durable.
    reopened = Store(store.path)
    current = snapshot(reopened,authenticator)
    assert current.sign_count == 1 and current.revision == 1
    with reopened.connect() as c:
        public = credentials.list_public(c,USER,observed.party)
        assert public[0]['label'] == 'Test device' and public[0]['last_used'] == 1001
        assert set(public[0]) == {'id','label','created_at','last_used','device_type','backed_up'}
        assert credentials.active_ids(c,USER,observed.party) == [verified.credential_id]
        assert credentials.list_public(c,OTHER,observed.party) == []
    assert observed.credential_id.hex() not in repr(observed) and observed.public_key.hex() not in repr(observed)


def test_same_id_cannot_be_claimed_by_another_account_or_revived_after_revocation(store, authenticator):
    identifier, verified = register(store,authenticator)
    party = authenticator[0]
    for user in (USER, OTHER):
        with pytest.raises(PasskeyError):
            with store.connect(write=True) as c: credentials.register(c,user,party,'Another device',verified)
    with store.connect(write=True) as c: credentials.revoke(c,USER,party,identifier)
    with pytest.raises(PasskeyError):
        with store.connect(write=True) as c: credentials.register(c,USER,party,'Revive',verified)
    with store.connect() as c:
        assert credentials.active_ids(c,USER,party) == []
        assert credentials.list_public(c,USER,party) == []


def test_credentials_and_removal_are_bound_to_account_and_exact_origin(store, authenticator):
    identifier, _ = register(store,authenticator)
    party, raw_id, _, _ = authenticator
    for user, wrong_party in [(OTHER,party),(USER,RelyingParty.from_origin('https://other.example.test')),
                              (USER,RelyingParty.from_origin('https://security.example.test:8443'))]:
        with pytest.raises(PasskeyError):
            with store.connect() as c: credentials.lookup(c,user,wrong_party,raw_id)
        with pytest.raises(PasskeyError):
            with store.connect(write=True) as c: credentials.revoke(c,user,wrong_party,identifier)
    assert snapshot(store,authenticator).id == identifier


def test_removal_wins_against_an_already_verified_inflight_assertion(store, authenticator):
    identifier, _ = register(store,authenticator)
    observed = snapshot(store,authenticator)
    verified = proof(authenticator,observed)
    with store.connect(write=True) as c: credentials.revoke(c,USER,observed.party,identifier)
    with pytest.raises(PasskeyError):
        with store.connect(write=True) as c: credentials.commit_authentication(c,observed,verified)
    with pytest.raises(PasskeyError): snapshot(store,authenticator)


@pytest.mark.parametrize('counter',[0,1])
def test_concurrent_proofs_from_same_revision_have_one_winner_even_for_zero_counters(store, authenticator, counter):
    register(store,authenticator)
    observed = snapshot(store,authenticator)
    proofs = [proof(authenticator,observed,counter=counter) for _ in range(2)]
    barrier = Barrier(2)
    def commit(verified):
        barrier.wait()
        try:
            with store.connect(write=True) as c: credentials.commit_authentication(c,observed,verified)
            return True
        except PasskeyError: return False
    with ThreadPoolExecutor(max_workers=2) as executor:
        results = list(executor.map(commit,proofs))
    assert sorted(results) == [False,True]
    assert snapshot(store,authenticator).revision == 1


def test_authentication_and_session_insert_roll_back_together(store, authenticator):
    register(store,authenticator)
    observed = snapshot(store,authenticator)
    verified = proof(authenticator,observed)
    with pytest.raises(RuntimeError):
        with store.connect(write=True) as c:
            user = credentials.commit_authentication(c,observed,verified)
            c.execute('INSERT INTO sessions VALUES(?,?,?,?,?,?)',('test-only-session',user,'fixture','test-only-csrf',2000,0))
            raise RuntimeError('simulated session policy failure')
    assert snapshot(store,authenticator).revision == 0
    with store.connect() as c: assert c.execute('SELECT COUNT(*) FROM sessions').fetchone()[0] == 0


def test_both_counter_rollback_and_changed_backup_eligibility_are_rejected(store, authenticator):
    register(store,authenticator,counter=3)
    observed = snapshot(store,authenticator)
    with pytest.raises(PasskeyError): proof(authenticator,observed,counter=3)
    with pytest.raises(PasskeyError):
        with store.connect(write=True) as c:
            credentials.commit_authentication(c,observed,proof(authenticator,observed,counter=4,flags=0x1d))
    assert snapshot(store,authenticator).revision == 0


def test_synchronized_passkey_may_change_backup_state_but_not_eligibility(store, authenticator):
    register(store,authenticator,flags=0x4d)
    observed = snapshot(store,authenticator)
    with store.connect(write=True) as c:
        credentials.commit_authentication(c,observed,proof(authenticator,observed,counter=0,flags=0x1d))
    with store.connect() as c:
        assert credentials.list_public(c,USER,observed.party)[0]['backed_up'] == 1


@pytest.mark.parametrize('label',['',' ' * 10,'a' * 61,'Device\nname','Device\x00name'])
def test_invalid_labels_do_not_write_credentials(store, authenticator, label):
    party, _, _, response = authenticator
    challenge = secrets.token_bytes(32)
    verified = party.register(response('create',challenge),challenge)
    with pytest.raises(PasskeyError):
        with store.connect(write=True) as c: credentials.register(c,USER,party,label,verified)
    with store.connect() as c: assert credentials.list_public(c,USER,party) == []


def test_unverified_mapping_or_credential_for_missing_account_is_rejected(store, authenticator):
    party, _, _, response = authenticator
    challenge = secrets.token_bytes(32)
    verified = party.register(response('create',challenge),challenge)
    for user, proof_value in [(USER,{}),('f' * 24,verified),(USER,replace(verified,user_verified=False)),
                               (USER,replace(verified,credential_device_type='single_device'))]:
        with pytest.raises(PasskeyError):
            with store.connect(write=True) as c: credentials.register(c,user,party,'Device',proof_value)


def test_deleted_account_cannot_complete_authentication(store, authenticator):
    register(store,authenticator)
    observed = snapshot(store,authenticator)
    verified = proof(authenticator,observed)
    with store.connect(write=True) as c: c.execute('DELETE FROM users WHERE id=?',(USER,))
    with pytest.raises(PasskeyError):
        with store.connect(write=True) as c: credentials.commit_authentication(c,observed,verified)


def test_active_limit_is_atomic_and_revoked_keys_do_not_use_active_slots(store, authenticator, monkeypatch):
    monkeypatch.setattr(credentials,'MAX_ACTIVE',1)
    identifier, _ = register(store,authenticator)
    second = globals()['authenticator'].__wrapped__()
    with pytest.raises(PasskeyError): register(store,second)
    with store.connect(write=True) as c: credentials.revoke(c,USER,authenticator[0],identifier)
    register(store,second)
    with store.connect() as c: assert len(credentials.active_ids(c,USER,second[0])) == 1


def test_concurrent_registrations_cannot_exceed_the_account_limit(store, monkeypatch):
    monkeypatch.setattr(credentials,'MAX_ACTIVE',1)
    verified_values=[]
    for _ in range(2):
        party, _, _, response=globals()['authenticator'].__wrapped__()
        challenge=secrets.token_bytes(32)
        verified_values.append((party,party.register(response('create',challenge),challenge)))
    barrier=Barrier(2)
    def attempt(value):
        party,verified=value
        barrier.wait()
        try:
            with store.connect(write=True) as c: credentials.register(c,USER,party,'Concurrent device',verified)
            return True
        except PasskeyError: return False
    with ThreadPoolExecutor(max_workers=2) as executor:
        assert sorted(executor.map(attempt,verified_values)) == [False,True]
    with store.connect() as c: assert len(credentials.active_ids(c,USER,verified_values[0][0])) == 1


def test_writes_require_explicit_transaction_and_schema_install_rolls_back(store, authenticator, tmp_path):
    party, _, _, response = authenticator
    challenge = secrets.token_bytes(32)
    verified = party.register(response('create',challenge),challenge)
    with store.connect() as c:
        with pytest.raises(RuntimeError): credentials.register(c,USER,party,'Device',verified)
    clean = Store(tmp_path/'ddl-rollback.db')
    with pytest.raises(RuntimeError):
        with clean.connect(write=True) as c:
            credentials.install_schema(c)
            raise RuntimeError('migration failed')
    with clean.connect() as c:
        assert not c.execute("SELECT 1 FROM sqlite_master WHERE name='passkey_credentials'").fetchone()


def test_ceremony_claim_real_signature_and_atomic_credential_commit_work_together(store, authenticator):
    register(store,authenticator)
    service = Ceremonies(store)
    party, _, _, response = authenticator
    scope = Scope('authentication',party,USER)
    binding = secrets.token_urlsafe(32)
    pending = service.begin(binding,scope)
    signed = response('get',pending.challenge,counter=0,handle=USER.encode())
    challenge = service.consume(pending.token,binding,scope)
    observed = snapshot(store,authenticator)
    verified = party.authenticate(signed,challenge,observed.credential_id,observed.public_key,observed.sign_count,USER.encode())
    with store.connect(write=True) as c: assert credentials.commit_authentication(c,observed,verified) == USER
    with pytest.raises(PasskeyError): service.consume(pending.token,binding,scope)
    assert snapshot(store,authenticator).revision == 1
