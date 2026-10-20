"""Real SQLite concurrency and signed-response replay tests in disposable stores."""
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
import secrets
from threading import Barrier

import pytest

from backend.passkey_ceremonies import Ceremonies, Scope, install_schema, PER_BROWSER
from backend.passkey_protocol import PasskeyError, RelyingParty
from backend.store import Store
from backend import passkey_ceremonies
from test_passkey_protocol import authenticator


@pytest.fixture
def service(tmp_path):
    store = Store(tmp_path / 'ceremony-fixture.db')
    with store.connect(write=True) as c:
        install_schema(c)
    clock = [1000.0]
    return Ceremonies(store, lambda: clock[0]), clock


def scope():
    return Scope('authentication', RelyingParty.from_origin('https://security.example.test'))


def registration():
    return Scope('registration', scope().party, 'a' * 24, 'b' * 64)


def test_challenge_is_random_short_lived_and_tokens_and_browser_bindings_are_hashed(service):
    service, clock = service
    binding = secrets.token_urlsafe(32)
    first, second = service.begin(binding, scope()), service.begin(binding, scope())
    assert len(first.challenge) == 32 and first.challenge != second.challenge
    assert first.token != second.token and first.expires_at == clock[0] + 120
    with service.store.connect() as c:
        rows = c.execute('SELECT * FROM passkey_ceremonies').fetchall()
    assert len(rows) == 2
    assert all(binding not in str(tuple(row)) and first.token not in str(tuple(row)) for row in rows)
    assert first.token not in repr(first) and first.challenge.hex() not in repr(first)
    assert service.consume(first.token, binding, scope()) == first.challenge
    with pytest.raises(PasskeyError): service.consume(first.token, binding, scope())


def test_another_browser_cannot_claim_or_cancel_a_challenge(service):
    service, _ = service
    binding = secrets.token_urlsafe(32)
    pending = service.begin(binding, scope())
    with pytest.raises(PasskeyError): service.consume(pending.token, secrets.token_urlsafe(32), scope())
    assert service.consume(pending.token, binding, scope()) == pending.challenge


@pytest.mark.parametrize('wrong', [
    registration(),
    Scope('authentication', RelyingParty.from_origin('https://other.example.test')),
    Scope('authentication', scope().party, 'f' * 24),
])
def test_wrong_context_is_consumed_permanently(service, wrong):
    service, _ = service
    binding = secrets.token_urlsafe(32)
    pending = service.begin(binding, scope())
    with pytest.raises(PasskeyError): service.consume(pending.token, binding, wrong)
    with pytest.raises(PasskeyError): service.consume(pending.token, binding, scope())


def test_registration_requires_same_account_and_same_authenticated_session(service):
    service, _ = service
    binding = secrets.token_urlsafe(32)
    for changed in [replace(registration(), account='c' * 24), replace(registration(), session_hash='d' * 64)]:
        pending = service.begin(binding, registration())
        with pytest.raises(PasskeyError): service.consume(pending.token, binding, changed)
        with pytest.raises(PasskeyError): service.consume(pending.token, binding, registration())


def test_expiry_is_enforced_at_the_boundary_and_expired_rows_do_not_exhaust_limits(service):
    service, clock = service
    binding = secrets.token_urlsafe(32)
    pending = service.begin(binding, scope())
    clock[0] = pending.expires_at
    with pytest.raises(PasskeyError): service.consume(pending.token, binding, scope())
    for _ in range(PER_BROWSER): service.begin(binding, scope())
    with pytest.raises(PasskeyError): service.begin(binding, scope())
    clock[0] += 120
    service.begin(binding, scope())
    with service.store.connect() as c:
        assert c.execute('SELECT COUNT(*) FROM passkey_ceremonies').fetchone()[0] == 1


def test_account_limit_cannot_be_bypassed_by_many_browser_bindings(service):
    service, _ = service
    for _ in range(5): service.begin(secrets.token_urlsafe(32), registration())
    with pytest.raises(PasskeyError): service.begin(secrets.token_urlsafe(32), registration())
    service.begin(secrets.token_urlsafe(32), replace(registration(), account='f' * 24))


def test_global_capacity_rejects_without_evicting_another_browser(service, monkeypatch):
    service, _ = service
    monkeypatch.setattr(passkey_ceremonies, 'TOTAL', 2)
    first_binding, second_binding = secrets.token_urlsafe(32), secrets.token_urlsafe(32)
    first, second = service.begin(first_binding, scope()), service.begin(second_binding, scope())
    with pytest.raises(PasskeyError): service.begin(secrets.token_urlsafe(32), scope())
    assert service.consume(first.token, first_binding, scope()) == first.challenge
    assert service.consume(second.token, second_binding, scope()) == second.challenge


def test_browser_limit_is_shared_across_purposes_and_does_not_evict_requests(service):
    service, _ = service
    binding = secrets.token_urlsafe(32)
    pending = service.begin(binding, registration())
    for _ in range(PER_BROWSER - 1): service.begin(binding, scope())
    with pytest.raises(PasskeyError): service.begin(binding, registration())
    assert service.consume(pending.token, binding, registration()) == pending.challenge


def test_concurrent_verifiers_cannot_both_claim_the_same_request(service):
    service, _ = service
    binding = secrets.token_urlsafe(32)
    pending = service.begin(binding, scope())
    barrier = Barrier(2)
    def claim():
        barrier.wait(timeout=5)
        try: return service.consume(pending.token, binding, scope())
        except PasskeyError: return None
    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(lambda _: claim(), range(2)))
    assert results.count(pending.challenge) == 1 and results.count(None) == 1


def test_claim_does_not_roll_back_when_signature_verification_fails(service, authenticator):
    service, _ = service
    party, identifier, public, response = authenticator
    binding = secrets.token_urlsafe(32)
    pending = service.begin(binding, scope())
    signed = response('get', pending.challenge, origin='https://evil.test')
    challenge = service.consume(pending.token, binding, scope())
    with pytest.raises(PasskeyError): party.authenticate(signed, challenge, identifier, public, 0, b'user')
    with pytest.raises(PasskeyError): service.consume(pending.token, binding, scope())


def test_zero_counter_signed_response_cannot_be_replayed_with_consumed_or_fresh_request(service, authenticator):
    service, _ = service
    party, identifier, public, response = authenticator
    binding = secrets.token_urlsafe(32)
    pending = service.begin(binding, scope())
    signed = response('get', pending.challenge, counter=0)
    challenge = service.consume(pending.token, binding, scope())
    assert party.authenticate(signed, challenge, identifier, public, 0, b'user').new_sign_count == 0
    with pytest.raises(PasskeyError): service.consume(pending.token, binding, scope())
    fresh = service.begin(binding, scope())
    fresh_challenge = service.consume(fresh.token, binding, scope())
    with pytest.raises(PasskeyError): party.authenticate(signed, fresh_challenge, identifier, public, 0, b'user')


def test_session_and_account_invalidation_are_scoped(service):
    service, _ = service
    binding = secrets.token_urlsafe(32)
    first = service.begin(binding, registration())
    other_scope = replace(registration(), account='c' * 24, session_hash='d' * 64)
    other = service.begin(binding, other_scope)
    service.invalidate_session(registration().session_hash)
    with pytest.raises(PasskeyError): service.consume(first.token, binding, registration())
    assert service.consume(other.token, binding, other_scope) == other.challenge
    first = service.begin(binding, registration())
    remaining = service.begin(binding, other_scope)
    service.invalidate_account(registration().account)
    with pytest.raises(PasskeyError): service.consume(first.token, binding, registration())
    assert service.consume(remaining.token, binding, other_scope) == remaining.challenge


def test_claim_remains_consumed_after_reopening_store(service):
    service, _ = service
    binding = secrets.token_urlsafe(32)
    pending = service.begin(binding, scope())
    service.consume(pending.token, binding, scope())
    reopened = Ceremonies(Store(service.store.path), service.clock)
    with pytest.raises(PasskeyError): reopened.consume(pending.token, binding, scope())


def test_schema_install_respects_migration_transaction_and_does_not_change_version(tmp_path):
    store = Store(tmp_path / 'migration-fixture.db')
    with pytest.raises(RuntimeError):
        with store.connect(write=True) as c:
            install_schema(c)
            raise RuntimeError('simulate later migration failure')
    with store.connect() as c:
        assert not c.execute("SELECT 1 FROM sqlite_master WHERE name='passkey_ceremonies'").fetchone()
        assert c.execute('SELECT MAX(version) FROM schema_migrations').fetchone()[0] == 8


@pytest.mark.parametrize('token,binding', [('', 'a' * 43), ('a' * 43, ''), ('!' * 43, 'a' * 43), (None, None)])
def test_malformed_claim_values_are_generic_and_do_not_cancel_other_requests(service, token, binding):
    service, _ = service
    good_binding = secrets.token_urlsafe(32)
    pending = service.begin(good_binding, scope())
    with pytest.raises(PasskeyError, match='Start again'): service.consume(token, binding, scope())
    assert service.consume(pending.token, good_binding, scope()) == pending.challenge


def test_configuration_and_input_bounds_fail_before_creating_rows(service):
    service, _ = service
    for bad in ['', 'x' * 42, 'x' * 129, '!' * 43, None]:
        with pytest.raises(PasskeyError): service.begin(bad, scope())
    for kwargs in [dict(purpose='other', party=scope().party), dict(purpose='registration', party=scope().party), dict(purpose='authentication', party=scope().party, session_hash='b' * 64)]:
        with pytest.raises(ValueError): Scope(**kwargs)
    with pytest.raises(ValueError): Scope('authentication', RelyingParty('https://security.example.test', 'example.test'))
    with service.store.connect() as c:
        assert c.execute('SELECT COUNT(*) FROM passkey_ceremonies').fetchone()[0] == 0
