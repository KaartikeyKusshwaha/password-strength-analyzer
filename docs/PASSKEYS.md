# Account passkeys — development implementation

Status: account routes, session/MFA integration and UI are implemented in app
0.13.0. The backed-up local owner store has been upgraded to schema 9 without
changing protected account/vault/sharing/connection records. User-confirmed
native Edge enrollment and sign-in passed in the isolated localhost acceptance app.
Remaining device lifecycle checks are **not yet accepted**. The current
127.0.0.1 origin is explicitly unsupported; the UI does not offer fake success
or silently change the app/companion origin. See PASSKEY_HTTP.md for the API,
tests and live upgrade evidence.

## Implemented

`backend/passkey_protocol.py` uses pinned `webauthn==3.0.1` for WebAuthn option
generation and cryptographic verification. Registration requests discoverable
credentials and required user verification, with attestation preference none.
The verifier requires user presence and verification, exact configured origin
and RP-ID hash, and a server-provided challenge of at least 32 bytes. Algorithm
support is explicitly ES256/RS256. Authentication additionally binds the selected
credential ID, checks a returned user handle against the server's account ID,
and applies the library's signature-counter validation. Framed/related-origin
ceremonies are rejected, including a claimed topOrigin. Malformed responses and
verification errors produce generic messages without echoing response data.

Configuration accepts only canonical HTTPS domain origins or HTTP localhost
with its exact port. The RP ID is the exact host; no parent-domain expansion.
IP addresses and noncanonical variants are refused. The current local app runs
at 127.0.0.1 and must not silently change origin during private browser testing.
A deliberate future transition to configured localhost, or an HTTPS deployment
domain, needs cookie/session, CSRF, companion and browser verification.

There is no custom public-key verification algorithm or secret in this module.
An authenticator's private key stays outside the service. Server public-key
records will still be account metadata requiring access control and backup.

## Integrated account workflow

`backend/passkey_ceremonies.py` supplies the challenge lifecycle. Its explicit
schema installer now participates in startup migration 9 and backup/recovery.
The real owner process now runs schema 9. See the
[ceremony evidence](PASSKEY_CEREMONIES.md) and
[migration/restore evidence](PASSKEY_MIGRATION.md).

- Enrollment requires current account password, an unused enrolled MFA factor,
  CSRF and exact Origin. The challenge is bound to that full session. Current
  session/membership is checked again after cryptographic verification.
- Sign-in starts with the entered email and requests a discoverable credential
  without exposing an account's credential IDs/count. The original server
  challenge fixes the expected account; it cannot be changed in the proof.
  A matching user handle is mandatory for this flow.
- A separate HttpOnly/SameSite cookie binds the browser. Claims are consumed
  before proof JSON parsing/verification, including malformed or invalid proofs.
  Exact RP/origin, UV, bounded queues, throttles and revision/counter guards apply.
- Session issuance shares a transaction with credential updates and current
  membership policy. Enrolled MFA still produces a pending session; the normal
  factor endpoint must complete before protected access is available.
- Team & security lists only the current user's passkeys. Removal requires fresh
  password/MFA, tombstones the key, cancels pending account ceremonies, signs
  out other account sessions and rotates the current session/CSRF.
- Backup restore clears challenges and revokes restored active passkeys. It
  cannot erase device keys or provide independent rollback protection.
- Explicit UI actions invoke the browser authenticator. Cancellation closes the
  pending request; uncertain finish outcomes are not retried automatically.

Before claiming browser acceptance, configure a deliberate supported origin and
verify enrollment, cancellation, sign-in, MFA, removal, restart and restore using
actual authenticators. Origin changes need session/cookie, CSRF and companion
verification. Do not alter the current origin merely to make a green status.

Passkeys here are for **SentinelOps account authentication**. They do not enable
passkeys on Google or another site, replace provider enrollment, decrypt a vault,
recover a lost master passphrase or give an LLM access to credentials. Vault
unlock/recovery needs a separately reviewed protocol and user-owned key material.

## Verification

33 protocol tests passed using independently constructed CBOR authenticator data
and real ECDSA signatures. They exercise registration/authentication, origin/RP
binding, challenges, UP/UV, crossOrigin/topOrigin, user handles, credential IDs,
signature failure, counter rollback, zero counters and malformed responses.
The zero-counter test explicitly demonstrates that the helper alone accepts the
same valid response twice. The additional SQLite ceremony candidate tests now
reject replay after a committed claim, including with real zero-counter signed
responses. Real-signed HTTP tests now cover session/MFA integration, revocation,
bad proofs/JSON, wrong account/browser/origin/RP, pending factors, throttles,
cancellation and session races. Frontend tests cover native buffer conversion,
proof allowlisting, explicit gestures, MFA transition, cancellation and ambiguous
outcomes. These are not a hardware/browser test or independent audit.

Sources inspected:
- https://www.w3.org/TR/webauthn-3/#rp-id
- https://www.w3.org/TR/webauthn-3/#discoverable-credential
- https://duo-labs.github.io/py_webauthn/registration.html
- https://duo-labs.github.io/py_webauthn/authentication.html
- Pinned 3.0.1 installed library source and PyPI package metadata. The online
  overview labels itself 2.2.0, so actual 3.0.1 signatures/exceptions were checked.
