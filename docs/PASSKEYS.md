# Passkey account sign-in — protocol foundation

Status: **in development, no sign-in/enrollment routes or UI yet**. An isolated
single-use ceremony-storage candidate is now tested alongside the protocol.
Transaction-bound credential persistence is also tested in isolated databases;
see [the credential storage contract](PASSKEY_CREDENTIALS.md). Schema-9 migration
and encrypted backup/recovery now pass an isolated actual-data restore drill;
see [the migration evidence](PASSKEY_MIGRATION.md).
The running
application, account sessions, vaults and origin have not been changed. Do not
present this helper as available sign-in, recovery or vault unlocking.

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

## Required before integration can be called usable

`backend/passkey_ceremonies.py` supplies the challenge lifecycle. Its explicit
schema installer now participates in startup migration 9 and backup/recovery.
The real owner process has not been restarted, so it still runs schema 8 and
does not expose ceremony routes. See [the ceremony evidence](PASSKEY_CEREMONIES.md)
and [the isolated migration/restore drill](PASSKEY_MIGRATION.md).

- Apply the tested schema-9 migration to the owner store at a controlled restart
  when routes are ready. Store no authenticator private keys. Credentials and
  short-lived ceremonies now have versioned schemas and backup/recovery handling.
- Registration requires current app-password reauthentication and the enrolled
  app MFA factor. Bind the enrollment challenge to that authenticated session.
- Bind sign-in challenges to a fresh HttpOnly/SameSite browser ceremony cookie,
  account, purpose, exact RP configuration and expiration. Throttle both routes
  and cap outstanding ceremonies. Do not trust expected values from a request.
- Claim/consume a challenge once atomically, including invalid attempts; update
  credential counters atomically. Zero-counter synced credentials cannot supply
  replay protection; the single-use server ceremony must do that job.
- Issue sessions only after successful verification, current membership checks
  and existing MFA policy. Preserve the normal pending-factor state and CSRF
  controls. A helper verification result by itself is not authorization.
- Add credential listing/removal with reauthentication, enrollment/deletion
  audit events, global credential-ID uniqueness, bounded names/records, session
  revocation policy, and enrollment race/replay protections.
- Update backup schema validation and restore invalidation of ceremonies.
  Define handling of revoked credentials in old backups; do not imply rollback
  protection. Exercise migration/recovery before updating a real user store.
- Integrate explicit browser user gestures, cancellation and unsupported states;
  offer no simulated passkey success. Require user interaction for registration.
- Test actual Windows Hello/security-key enrollment and sign-in, plus wrong
  origin, expired/replayed ceremonies, MFA, removal, membership and restore flows.

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
responses. Route/session integration remains unimplemented. These tests are not a hardware/browser test or
independent audit. `pip check` also passed after dependency installation.

Sources inspected:
- https://www.w3.org/TR/webauthn-3/#rp-id
- https://duo-labs.github.io/py_webauthn/registration.html
- https://duo-labs.github.io/py_webauthn/authentication.html
- Pinned 3.0.1 installed library source and PyPI package metadata. The online
  overview labels itself 2.2.0, so actual 3.0.1 signatures/exceptions were checked.
