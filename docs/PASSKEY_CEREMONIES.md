# Passkey ceremony storage — isolated integration candidate

`backend/passkey_ceremonies.py` addresses single-use challenge lifecycle required
by the existing WebAuthn protocol helper. No sign-in, enrollment or credential
removal route has been added. Nothing was imported into the app, the server was
not restarted, and the real owner database still has schema 8 with no ceremony
table. Browser companion remains built as 0.12.4; its autofill acceptance is
still pending the user's popup action.

## Implemented contract

- Server-generated 32-byte random challenges and opaque request handles, with
  a 120-second deadline. Only hashes of the handle and browser binding are stored.
- Exact canonical RP origin/host, purpose, optional account, and for enrollment
  the authenticated account plus session hash are recorded with the challenge.
- A wrong browser binding cannot read or delete another browser's challenge.
  Once the binding matches, the claim is deleted in a BEGIN IMMEDIATE transaction
  and committed before purpose/context/expiry and signature verification. A bad
  signature or changed context cannot roll the deletion back.
- At most five pending requests per browser, five per scoped account, and 4,096
  globally. Requests at capacity are rejected without evicting somebody else's
  pending work. Expired records are pruned when beginning a new request.
- Registration ceremonies can be invalidated by session or account. Anonymous
  discoverable authentication ceremonies do not yet identify an account;
  credential revocation/current membership must still be checked after claiming.
- An explicit schema installer preserves its caller's migration transaction;
  there is no implicit migration or separate production sidecar store.

All scope values must be derived by trusted route code. A caller must not build
the expected RP, session or account from a submitted response. The browser binding
must be issued through the planned HttpOnly/SameSite cookie flow. This module
does not replace route rate limits, CSRF checks, fresh password/MFA enrollment
authorization, credential storage/counters, pending MFA, or session issuance.

## Evidence

On 2026-10-20, the protocol and ceremony suites passed **54 tests** using
temporary SQLite stores and real synthetic ECDSA authenticator responses.
Coverage includes concurrent claims (one winner), committed claim persistence
after reopen, invalid-signature failure, zero-counter signed-response replay,
fresh-challenge mismatch, wrong browser/purpose/origin/account/session, expiry
boundaries, scoped invalidation, bounded queues, malformed requests, and schema
installation rollback. No claim of hardware/browser acceptance or independent
security review is made.

## Integration still required

1. Versioned schema migration for credentials and ceremonies with backup schema
   validation/restore invalidation, and a migration test before owner-store use.
2. Origin-checked, throttled HTTP routes with browser-cookie and session binding.
   Consume before parsing/verifying any submitted authenticator proof.
3. Unique credential/account registration and atomic counter update, current
   membership and revocation checks, existing pending-MFA and session policy.
4. Reauthenticated enrollment/removal UI, cancellation and unsupported states;
   explicit user handoff for enrollment and actual authenticator testing.

Protocol reference already inspected:
[py_webauthn authentication](https://duo-labs.github.io/py_webauthn/authentication.html).
The installed pinned 3.0.1 library is authoritative for the signatures used by
the protocol helper; the online documentation labels itself 2.2.0.
