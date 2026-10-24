"""Transaction-bound passkey credential storage for account routes.

Only trusted code may pass verifier results here. Caller owns reauthentication,
single-use ceremony consumption and current session/membership policy. Successful
authentication and session issuance must share the caller's write transaction.
"""
from dataclasses import dataclass, field
import math
import re
import sqlite3
import time

from webauthn.authentication.verify_authentication_response import VerifiedAuthentication
from webauthn.registration.verify_registration_response import VerifiedRegistration
from webauthn.helpers.structs import CredentialDeviceType

from .passkey_protocol import PasskeyError, RelyingParty
from .store import uid

MAX_ACTIVE = 10
INVALID = 'Passkey could not be verified. Start again.'


def install_schema(c):
    # Explicit migration candidate: no app import, automatic migration or commit.
    c.execute('''CREATE TABLE IF NOT EXISTS passkey_credentials(
        id TEXT PRIMARY KEY,user TEXT NOT NULL,origin TEXT NOT NULL,rp_id TEXT NOT NULL,
        credential_id BLOB NOT NULL UNIQUE,public_key BLOB NOT NULL,sign_count INTEGER NOT NULL,
        device_type TEXT NOT NULL,backed_up INTEGER NOT NULL,label TEXT NOT NULL,
        created_at REAL NOT NULL,last_used REAL,revoked_at REAL,revision INTEGER NOT NULL DEFAULT 0)''')
    c.execute('CREATE INDEX IF NOT EXISTS passkey_credentials_owner ON passkey_credentials(user,origin,revoked_at)')


def account(value):
    if not isinstance(value, str) or not re.fullmatch(r'[a-f0-9]{24}', value):
        raise PasskeyError(INVALID)
    return value


def party_valid(party):
    if not isinstance(party, RelyingParty) or RelyingParty.from_origin(party.origin) != party:
        raise PasskeyError(INVALID)


def writing(c):
    if not c.in_transaction:
        raise RuntimeError('Passkey writes require the caller transaction.')


def clock_value(clock):
    value = clock()
    if type(value) not in (float, int) or not math.isfinite(value) or value < 0:
        raise ValueError('Invalid passkey timestamp.')
    return value


def count_valid(value):
    return type(value) is int and 0 <= value <= 0xffffffff


def device_valid(value):
    return isinstance(value, CredentialDeviceType) and value in (CredentialDeviceType.SINGLE_DEVICE, CredentialDeviceType.MULTI_DEVICE)


@dataclass(frozen=True)
class Credential:
    id: str
    user: str
    party: RelyingParty
    credential_id: bytes = field(repr=False)
    public_key: bytes = field(repr=False)
    sign_count: int
    device_type: str
    revision: int


def register(c, user, party, label, verified, clock=time.time):
    writing(c)
    account(user)
    party_valid(party)
    if (not isinstance(label, str) or not 1 <= len(label.strip()) <= 60
            or not label.strip().isprintable()):
        raise PasskeyError('Use a passkey name with 1–60 printable characters.')
    if (not isinstance(verified, VerifiedRegistration) or verified.user_verified is not True
            or not isinstance(verified.credential_id, bytes) or not 1 <= len(verified.credential_id) <= 1024
            or not isinstance(verified.credential_public_key, bytes) or not 1 <= len(verified.credential_public_key) <= 4096
            or not count_valid(verified.sign_count) or not device_valid(verified.credential_device_type)
            or type(verified.credential_backed_up) is not bool
            or (verified.credential_backed_up and verified.credential_device_type == CredentialDeviceType.SINGLE_DEVICE)):
        raise PasskeyError(INVALID)
    if not c.execute('SELECT 1 FROM users WHERE id=?', (user,)).fetchone():
        raise PasskeyError(INVALID)
    if c.execute('SELECT COUNT(*) FROM passkey_credentials WHERE user=? AND revoked_at IS NULL', (user,)).fetchone()[0] >= MAX_ACTIVE:
        raise PasskeyError('This account already has ten active passkeys. Remove one before adding another.')
    identifier, at = uid(), clock_value(clock)
    try:
        c.execute('''INSERT INTO passkey_credentials
            (id,user,origin,rp_id,credential_id,public_key,sign_count,device_type,backed_up,label,created_at)
            VALUES(?,?,?,?,?,?,?,?,?,?,?)''',
            (identifier,user,party.origin,party.rp_id,verified.credential_id,verified.credential_public_key,
             verified.sign_count,verified.credential_device_type.value,int(verified.credential_backed_up),label.strip(),at))
    except sqlite3.IntegrityError:
        # Includes revoked IDs: a previously revoked credential must not revive.
        raise PasskeyError('This passkey cannot be registered. Create a new passkey.') from None
    return identifier


def lookup(c, user, party, credential_id):
    account(user)
    party_valid(party)
    if not isinstance(credential_id, bytes) or not 1 <= len(credential_id) <= 1024:
        raise PasskeyError(INVALID)
    row = c.execute('''SELECT p.* FROM passkey_credentials p JOIN users u ON u.id=p.user
        WHERE p.user=? AND p.origin=? AND p.rp_id=? AND p.credential_id=? AND p.revoked_at IS NULL''',
        (user,party.origin,party.rp_id,credential_id)).fetchone()
    if not row:
        raise PasskeyError(INVALID)
    return Credential(row['id'],row['user'],party,bytes(row['credential_id']),bytes(row['public_key']),
                      row['sign_count'],row['device_type'],row['revision'])


def commit_authentication(c, observed, verified, clock=time.time):
    writing(c)
    if (not isinstance(observed, Credential) or not isinstance(verified, VerifiedAuthentication)
            or verified.user_verified is not True or verified.credential_id != observed.credential_id
            or not count_valid(verified.new_sign_count) or not device_valid(verified.credential_device_type)
            or verified.credential_device_type.value != observed.device_type
            or type(verified.credential_backed_up) is not bool
            or (verified.credential_backed_up and verified.credential_device_type == CredentialDeviceType.SINGLE_DEVICE)
            or ((observed.sign_count > 0 or verified.new_sign_count > 0) and verified.new_sign_count <= observed.sign_count)):
        raise PasskeyError(INVALID)
    account(observed.user)
    party_valid(observed.party)
    # Revision increments even for zero-counter synchronized credentials. A
    # concurrent proof verified against a stale snapshot must restart, and a
    # revocation while the cryptographic verifier was running must win.
    changed = c.execute('''UPDATE passkey_credentials SET sign_count=?,backed_up=?,last_used=?,revision=revision+1
        WHERE id=? AND user=? AND origin=? AND rp_id=? AND credential_id=? AND public_key=?
        AND sign_count=? AND device_type=? AND revision=? AND revoked_at IS NULL
        AND EXISTS(SELECT 1 FROM users WHERE id=passkey_credentials.user)''',
        (verified.new_sign_count,int(verified.credential_backed_up),clock_value(clock),observed.id,observed.user,
         observed.party.origin,observed.party.rp_id,observed.credential_id,observed.public_key,observed.sign_count,
         observed.device_type,observed.revision)).rowcount
    if changed != 1:
        raise PasskeyError(INVALID)
    return observed.user


def revoke(c, user, party, identifier, clock=time.time):
    writing(c)
    account(user)
    party_valid(party)
    if not isinstance(identifier, str) or not re.fullmatch(r'[a-f0-9]{24}', identifier):
        raise PasskeyError(INVALID)
    changed = c.execute('''UPDATE passkey_credentials SET revoked_at=?,revision=revision+1
        WHERE id=? AND user=? AND origin=? AND rp_id=? AND revoked_at IS NULL''',
        (clock_value(clock),identifier,user,party.origin,party.rp_id)).rowcount
    if changed != 1:
        raise PasskeyError(INVALID)


def active_ids(c, user, party):
    account(user)
    party_valid(party)
    return [bytes(row[0]) for row in c.execute('''SELECT credential_id FROM passkey_credentials
        WHERE user=? AND origin=? AND rp_id=? AND revoked_at IS NULL ORDER BY created_at,id''',
        (user,party.origin,party.rp_id))]


def list_public(c, user, party):
    account(user)
    party_valid(party)
    return [dict(row) for row in c.execute('''SELECT id,label,created_at,last_used,device_type,backed_up
        FROM passkey_credentials WHERE user=? AND origin=? AND rp_id=? AND revoked_at IS NULL
        ORDER BY created_at,id''', (user,party.origin,party.rp_id))]
