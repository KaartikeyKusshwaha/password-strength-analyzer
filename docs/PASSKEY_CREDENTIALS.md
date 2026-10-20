# Passkey credential persistence — integration candidate

Status: implemented and tested in disposable SQLite databases; not imported by
the running application. No owner-store migration, account endpoint, session
issuance, credential-management UI or live authenticator enrollment is provided
by this module. It does not decrypt vaults or enable passkeys on other services.

`backend/passkey_credentials.py` complements the existing cryptographic protocol
and single-use ceremony store. Its schema installer does not commit or migrate
the app implicitly. Each write requires the caller's explicit transaction.

## Storage contract

- Each record has a random app identifier, owning account, exact configured
  origin/RP ID, globally unique authenticator credential ID, public key,
  signature count, backup eligibility/state, a bounded device label, timestamps
  and a revision. No authenticator private key or raw attestation is stored.
- Registration accepts the pinned verifier's typed result, requires user
  verification and an existing account, and allows at most ten active passkeys
  per account. The caller must first consume the current session-bound
  enrollment ceremony and complete existing password/MFA authorization.
- Lookup requires the exact account, origin and credential ID. No user-supplied
  account/origin/key/counter is a trusted expected value. Public list output
  omits credential IDs, public keys, counters and revision internals.
- Authentication verifies the real signature outside the write transaction,
  then conditionally updates the exact observed record/revision/key/counter.
  A concurrent commit or revocation makes that observation stale. Revisions
  advance even when a synchronized credential reports a zero signature count.
  Zero counters still need the single-use ceremony store to prevent replay.
- Backup eligibility must stay consistent with enrollment; backup state may
  change for an eligible synchronized passkey. Positive signature counters must
  advance. A missing account or revoked credential cannot complete the update.
- Revocation is a retained tombstone, not a delete/reinsert cycle. The same
  credential ID cannot be rebound to another account or revived after removal.
  Creating another passkey uses a fresh authenticator enrollment. Cached device
  private keys cannot be erased by the server.

The typed result is an internal API contract, not an independent authorization
boundary: trusted code can construct dataclasses. Future routes must call the
actual verifier and must never deserialize a request into a trusted result.

## Session and migration requirements still open

1. Add credentials/ceremonies through a versioned migration with encrypted backup
   and restore validation. A restored old backup can contain old credentials;
   define explicit authorization-reset policy without claiming rollback defense.
2. Issue the browser binding cookie, throttle endpoints and consume challenges
   before proof verification. Enrollment uses fresh app-password/MFA checks.
3. In the same write transaction as commit_authentication, check the current
   account/workspace policy, consume any required MFA and issue the appropriate
   full/pending session. A successful credential update alone is not a session.
   A later policy error must roll back that update and session together, while
   the already-committed ceremony remains spent.
4. Listing/removal require the signed-in owner and fresh removal authorization;
   invalidate pending account ceremonies and apply session-revocation policy.
   Add scoped enrollment/removal audit records and bounded endpoint rates.
5. Add user-gesture WebAuthn UI, cancellation/unsupported states and actual
   authenticator testing. Current 127.0.0.1 origin remains unsupported by the
   protocol configuration; do not silently switch the existing app origin.

## Verification on 20 October 2026

All 74 protocol, ceremony and credential tests passed. New credential cases
use real generated ECDSA keys, CBOR authenticator data and signatures. They cover
durable reopen, safe public metadata, account/origin isolation, duplicate IDs,
revoked-ID rebinding, in-flight revocation, actual concurrent registration
capacity, stale positive/zero-counter commits, eligibility/state handling,
session-insert rollback, invalid labels, missing accounts, explicit transaction
requirements and DDL rollback. A combined ceremony/signature/credential case
spends a real zero-counter assertion once. These are not hardware acceptance or
an independent security review.

A read-only check of the real owner store confirmed schema 8 and zero
passkey_credentials tables. The running app and installed companion were not
restarted or changed by this candidate.

The full backend regression also passed: 280 tests, one existing Starlette/httpx
TestClient deprecation warning. The local ignored JUnit report is
data/backend-regression-20261020-passkeys03.xml. The separate focused suite was
74 passed; neither result represents live WebAuthn enrollment or route acceptance.
