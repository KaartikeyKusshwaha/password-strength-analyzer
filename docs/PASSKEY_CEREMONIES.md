# Passkey ceremony storage

`backend/passkey_ceremonies.py` addresses single-use challenge lifecycle required
by the existing WebAuthn protocol helper. No sign-in, enrollment or credential
removal route was present at the initial candidate stage. Startup schema-9,
backup/recovery and account routes/UI now exist. A controlled, backed-up restart
upgraded the owner store to schema 9 without changing protected records. Native
Edge enrollment passed; remaining lifecycle acceptance is pending. See PASSKEY_HTTP.md. At the candidate's
initial verification the browser companion was 0.12.4.
It has since been built as 0.12.5; installed autofill acceptance remains pending.

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
- Registration ceremonies can be invalidated by session or account. The account
  sign-in route also binds its server-selected account before returning options;
  unknown accounts receive an opaque placeholder. Credential revocation/current
  membership are checked again after claiming.
- An explicit schema installer preserves its caller's migration transaction;
  there is no implicit migration or separate production sidecar store.

All scope values must be derived by trusted route code. A caller must not build
the expected RP, session or account from a submitted response. The browser binding
is issued by the HTTP routes through an HttpOnly/SameSite cookie. This module
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

## Current integration and remaining acceptance

The schema-9 startup/backup contract and controlled owner migration are complete.
Origin-checked, throttled HTTP routes bind the browser cookie and session, and
consume before parsing submitted authenticator proofs. Credential registration,
counter updates, membership/revocation checks and pending MFA/session issuance
are connected. Reauthenticated enrollment/removal UI includes cancellation and
unsupported states. See PASSKEY_HTTP.md for the route contract and current tests.

User-confirmed native Edge enrollment passed in the isolated localhost app.
Passkey sign-in and native cancellation/removal acceptance remain open;
synthetic proofs do not establish those remaining device results.

Protocol reference already inspected:
[py_webauthn authentication](https://duo-labs.github.io/py_webauthn/authentication.html).
The installed pinned 3.0.1 library is authoritative for the signatures used by
the protocol helper; the online documentation labels itself 2.2.0.
