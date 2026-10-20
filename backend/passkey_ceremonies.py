"""Single-use WebAuthn challenge storage for account authentication routes.

install_schema is included in store migration 9.
Consuming commits before signature checking:
verification failure must never roll the claim back and make it reusable.
"""
from dataclasses import dataclass, field
import hmac
import re
import secrets
import time

from .passkey_protocol import PasskeyError, RelyingParty
from .security import digest

LIFETIME = 120
PER_BROWSER = 5
PER_ACCOUNT = 5
TOTAL = 4096
INVALID = 'Passkey request expired or could not be verified. Start again.'


def install_schema(connection):
    # Separate statements preserve the caller's migration transaction.
    connection.execute('''CREATE TABLE IF NOT EXISTS passkey_ceremonies(
        token_hash TEXT PRIMARY KEY,binding_hash TEXT NOT NULL,
        challenge BLOB NOT NULL,purpose TEXT NOT NULL,origin TEXT NOT NULL,
        rp_id TEXT NOT NULL,account TEXT,session_hash TEXT,expires REAL NOT NULL)''')
    connection.execute('CREATE INDEX IF NOT EXISTS passkey_ceremony_expiry ON passkey_ceremonies(expires)')
    connection.execute('CREATE INDEX IF NOT EXISTS passkey_ceremony_binding ON passkey_ceremonies(binding_hash)')
    connection.execute('CREATE INDEX IF NOT EXISTS passkey_ceremony_account ON passkey_ceremonies(account)')


@dataclass(frozen=True)
class Scope:
    purpose: str
    party: RelyingParty
    account: str | None = None
    session_hash: str | None = field(default=None, repr=False)

    def __post_init__(self):
        if self.purpose not in {'registration', 'authentication'}:
            raise ValueError('Invalid ceremony purpose.')
        if not isinstance(self.party, RelyingParty) or RelyingParty.from_origin(self.party.origin) != self.party:
            raise ValueError('Invalid ceremony relying party.')
        if self.account is not None and not re.fullmatch(r'[a-f0-9]{24}', self.account):
            raise ValueError('Invalid ceremony account.')
        if self.purpose == 'registration':
            if self.account is None or not isinstance(self.session_hash, str) or not re.fullmatch(r'[a-f0-9]{64}', self.session_hash):
                raise ValueError('Registration requires an authenticated account and session.')
        elif self.session_hash is not None:
            raise ValueError('Authentication must not inherit an authenticated session.')


@dataclass(frozen=True)
class Pending:
    token: str = field(repr=False)
    challenge: bytes = field(repr=False)
    expires_at: float


def valid_binding(value):
    return isinstance(value, str) and re.fullmatch(r'[A-Za-z0-9_-]{43,128}', value) is not None


class Ceremonies:
    def __init__(self, store, clock=time.time):
        self.store, self.clock = store, clock

    def begin(self, browser_binding, scope):
        with self.store.connect(write=True) as c:
            return self.begin_in_transaction(c,browser_binding,scope)

    def begin_in_transaction(self, c, browser_binding, scope):
        if not c.in_transaction:
            raise RuntimeError('Ceremony creation requires a write transaction.')
        if not valid_binding(browser_binding) or not isinstance(scope, Scope):
            raise PasskeyError(INVALID)
        at = self.clock()
        token, challenge = secrets.token_urlsafe(32), secrets.token_bytes(32)
        binding_hash = digest(browser_binding)
        c.execute('DELETE FROM passkey_ceremonies WHERE expires<=?', (at,))
        # Denial does not evict another browser's pending request.
        browser_count = c.execute('SELECT COUNT(*) FROM passkey_ceremonies WHERE binding_hash=?', (binding_hash,)).fetchone()[0]
        account_count = c.execute('SELECT COUNT(*) FROM passkey_ceremonies WHERE account=?', (scope.account,)).fetchone()[0] if scope.account else 0
        if browser_count >= PER_BROWSER or account_count >= PER_ACCOUNT or c.execute('SELECT COUNT(*) FROM passkey_ceremonies').fetchone()[0] >= TOTAL:
            raise PasskeyError('Too many pending passkey requests. Wait two minutes and try again.')
        c.execute('INSERT INTO passkey_ceremonies VALUES(?,?,?,?,?,?,?,?,?)',
                  (digest(token), binding_hash, challenge, scope.purpose, scope.party.origin,
                   scope.party.rp_id, scope.account, scope.session_hash, at + LIFETIME))
        return Pending(token, challenge, at + LIFETIME)

    def _claim(self, token, browser_binding):
        if not valid_binding(token) or not valid_binding(browser_binding):
            raise PasskeyError(INVALID)
        # Binding is checked before deletion, so knowledge of a public ceremony
        # ID alone cannot cancel a different browser's request.
        with self.store.connect(write=True) as c:
            row = c.execute('SELECT * FROM passkey_ceremonies WHERE token_hash=? AND binding_hash=?',
                            (digest(token), digest(browser_binding))).fetchone()
            if row:
                c.execute('DELETE FROM passkey_ceremonies WHERE token_hash=?', (digest(token),))
        # This check deliberately lives AFTER commit, including wrong purpose,
        # changed origin/account/session and subsequent invalid signatures.
        if not row or row['expires'] <= self.clock():
            raise PasskeyError(INVALID)
        return row

    def consume(self, token, browser_binding, scope):
        if not isinstance(scope,Scope):
            raise PasskeyError(INVALID)
        row=self._claim(token,browser_binding)
        expected = (scope.purpose, scope.party.origin, scope.party.rp_id, scope.account, scope.session_hash)
        actual = (row['purpose'], row['origin'], row['rp_id'], row['account'], row['session_hash'])
        if not hmac.compare_digest(repr(expected), repr(actual)):
            raise PasskeyError(INVALID)
        return bytes(row['challenge'])

    def consume_authentication(self, token, browser_binding, party):
        # Account is bound by the original server-created ceremony, not by
        # untrusted proof fields or a new account identifier at finish time.
        row=self._claim(token,browser_binding)
        try:
            expected=Scope('authentication',party,row['account'])
            if expected.account is None or (row['purpose'],row['origin'],row['rp_id'],row['session_hash']) != ('authentication',party.origin,party.rp_id,None):
                raise ValueError()
        except (ValueError,TypeError):
            raise PasskeyError(INVALID) from None
        return row['account'],bytes(row['challenge'])

    def cancel(self, token, browser_binding):
        self._claim(token,browser_binding)

    def invalidate_session(self, session_hash):
        if not isinstance(session_hash, str) or not re.fullmatch(r'[a-f0-9]{64}', session_hash):
            raise ValueError('Invalid session scope.')
        with self.store.connect(write=True) as c:
            c.execute('DELETE FROM passkey_ceremonies WHERE session_hash=?', (session_hash,))

    def invalidate_account(self, account):
        if not isinstance(account, str) or not re.fullmatch(r'[a-f0-9]{24}', account):
            raise ValueError('Invalid account scope.')
        with self.store.connect(write=True) as c:
            c.execute('DELETE FROM passkey_ceremonies WHERE account=?', (account,))
