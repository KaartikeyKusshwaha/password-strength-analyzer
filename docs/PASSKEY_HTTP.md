# Account passkeys in app 0.13.0

Account passkey enrollment, sign-in, management and session/MFA integration are
implemented. Live owner data runs schema 9 after an encrypted backup and a
controlled restart. **Native Edge enrollment and sign-in passed; the remaining
authenticator lifecycle checks are pending.**
The main local origin remains http://127.0.0.1:8110 and explicitly reports
passkeys unavailable. No origin, owner password, vault passphrase or companion
grant was changed to manufacture an accepted result.

## HTTP contract

| Endpoint | Boundary |
| --- | --- |
| GET /api/passkeys/status | Public availability only; no account/key metadata. |
| GET /api/passkeys | Current full account session; own active key labels/timestamps only. |
| POST /api/passkeys/register/options | Exact Origin, session/CSRF, password and unused enrolled MFA; bounded session-bound ceremony. |
| POST /api/passkeys/register/finish | Exact Origin, same full session/CSRF and browser binding; claim before JSON/proof parsing; current session/membership rechecked before insert. |
| POST /api/passkeys/login/options | Exact Origin, IP/account throttles, email-scoped server challenge; no credential IDs/count in the options. |
| POST /api/passkeys/login/finish | Exact Origin, browser-bound one-time header handle, mandatory matching user handle, real signature/UV and current membership; counter/revision and session issuance share a transaction. |
| POST /api/passkeys/cancel | Exact Origin and the requesting browser's opaque handle/binding; no proof or session granted. |
| POST /api/passkeys/{id}/remove | Exact Origin, own full session/CSRF, fresh password and enrolled MFA; tombstone, pending-ceremony cancellation and session rotation/revocation together. |

The request handle is carried in X-Passkey-Request, never a URL. A separate
HttpOnly/SameSite=Strict cookie is scoped to /api/passkeys and is Secure on
HTTPS. The challenge lasts two minutes. Queue caps and persistent rate limits
apply. Invalid JSON/proofs consume a valid bound claim; a different browser or
an Origin/CSRF failure cannot cancel another browser's request.

Registration's factor use and ceremony creation share a transaction, so a full
queue does not burn a recovery code. Authentication requires the original
server-selected account, exact origin/RP, presence/verification, active key,
unchanged backup eligibility and valid count/revision. A required enrolled MFA
factor still produces the existing pending-session state. Removing membership
prevents both password sign-in and pending-factor completion; removal does not
restore access or consume the rejected factor.

Discoverable enrollment is required. Authentication uses an empty allowCredentials
list for browser selection, while the server independently enforces the entered
account and returned user handle. See the
[W3C discoverable-credential definition](https://www.w3.org/TR/webauthn-3/#discoverable-credential).
The protocol helper supports explicit allowlists too; the account route uses
the discoverable flow and requires a user handle.

## UI and native boundary

The sign-in form offers a separate passkey button using the email only. A
pending-factor result opens the normal MFA form. Team & security lists keys,
requires reauthentication for enrollment/removal, invokes the browser only after
a deliberate user action, and exposes cancellation before the finish request.
Native buffers are converted to canonical base64url; only explicit public
credential-response fields are sent. The reauthentication password is sent only
to enrollment options/removal, not in the proof. Private authenticator keys
remain outside the app and AI workers.

Sign-in explains the requesting/device/verifying phases. The account fields
remain fixed while a request is active, and cancellation restores normal sign-in.

Cancel/abort invalidates the pending server request. A client deadline also bounds
the native wait to the returned lifetime (at most 120 seconds). Cancellation and
expiry settle independently of a native promise that ignores abort; a late
credential cannot reach the finish endpoint. A missing finish response
is treated as unknown: the client asks for an account/list refresh and never
retries a credential mutation automatically. User/device confirmation is required
for real enrollment; no synthetic UI success substitutes for it. This is account
authentication only, not vault encryption, recovery or third-party enrollment.

## Evidence on 21 October 2026

- Full backend run: 313 passed. Final authentication follow-up after current
  membership guards: 43 passed (22 passkey HTTP cases plus platform cases).
  Real ECDSA proofs exercise enrollment/sign-in, MFA, bad proofs/JSON, replay,
  expiry, browser/account/origin/RP isolation, revocation, unknown accounts,
  capacity/throttling, recovery-code rollback, cancellation and session races.
- Full frontend suite: 176 passed / 41 files. Final client/component follow-up:
  14 passed after request-handle/error-state adjustments. Production build passed.
  Existing strength-chunk and TestClient deprecation diagnostics remain.
- The owner upgrade's ignored baseline/result files are
  data/upgrade-0.13.0-baseline.json and data/upgrade-0.13.0-result.json.
  An encrypted pre-upgrade archive was created with the existing separate key.
  SQLite integrity passed; users, vault spaces, sharing identities, shared vaults,
  grants, companions, devices and server encryption key matched before/after.
  Both new passkey tables were empty. No active jobs/watches were interrupted.
- The served index matched the build. Edge retained the existing owner session,
  displayed the actual unsupported-IP-origin state and app 0.13.0, decrypted the
  disposable Browser acceptance vault with its one entry, and relocked it.
- Local ignored screenshots: data/browser-acceptance-0.13.0/
  passkey-origin-state.png and test-vault-after-upgrade.png.

## Native enrollment/sign-in passed; remaining lifecycle acceptance open

A separate loopback-only app at http://localhost:8111 uses disposable data in
data/passkey-browser-acceptance-20261021. No production user data was copied.
Its workspace is named Passkey browser acceptance. The existing disposable
account was signed in through the actual Edge UI; the passkey sign-in button
was available. The management form was prepared with a name and existing test
account reauthentication password. The user completed the creation/device prompt.
The actual Edge page then displayed "Passkey enrolled for this SentinelOps
account" and the active "Edge acceptance key" with "Not used yet". Screenshot:
data/browser-acceptance-0.13.0/passkey-enrolled-edge.png. Credential creation and
native confirmation were performed by the user, not simulated by test code.

The ignored launcher and logs are in data/. The test app has no AI key, valuable
vault data, or external email/registration integration. It does not change the
main app's origin, sessions or companion pairing. A real sign-in using the
passkey completed after user/device confirmation. Edge displayed the signed-in
account and "Last used 21/10/2026, 1:11:29 am" for the key. The ignored screenshot
is passkey-signin-success-edge.png in the same evidence directory. A read-only
store check confirmed the updated last_used and credential revision; this is a
real zero-counter authenticator, so revision advances provide concurrency checks.
The first native cancellation attempt did not visibly settle. The bounded client
was then loaded and a fresh request expired in actual Edge with "Passkey request
expired. Start again." Normal sign-in controls became available again. A read-only
store check found zero pending ceremonies and unchanged key revision/last_used,
so no late authentication was recorded. Screenshot: passkey-expiry-edge.png.
The page-level Cancel click remains unverified while native UI is active; mocked
late-native tests establish the client guard, not OS interaction. Keep the
lifecycle gate open for explicit cancellation, MFA, removal and device cleanup. Stop the
isolated service after the run. Actual extension 0.12.5 autofill acceptance is a
separate pending gate; these passkey tests do not establish that it works.

After expiry, ordinary password sign-in to the disposable account also passed.
The user completed the prepared test-key removal form. Their screenshot confirms
"Passkey removed" and "No passkeys enrolled". A subsequent read-only store check
confirmed the retained key tombstone (revision 2, revoked_at set) and zero pending
ceremonies. Enrollment, real sign-in, expiry and service-side removal now have
native Edge evidence. Explicit cancellation during native UI, enrolled-MFA device
acceptance and device-side key cleanup remain open. The main owner account and
vaults were not changed. The test service remains available for remaining checks.
