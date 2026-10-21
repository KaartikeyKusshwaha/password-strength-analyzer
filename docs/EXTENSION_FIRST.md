# Extension-first transition

The extension is the intended primary product. The website is the control room
for vault administration, saved results, connections and account/team settings.
Normal credential and assessment workflows must return their result inside the
extension. A dashboard shortcut is not equivalent to this requirement.

## Implemented first increment

Companion 0.14.0 adds a public-site header check directly in the popup. Access is
requested on an explicit click for the active exact origin, not all websites.
The extension rechecks that origin after permission approval. It sends one HEAD
request to the origin root without cookies, referrer, query/path, request body,
redirect following, page text or credentials. HTTP pages receive an address-only
warning without a network request. Browser-internal URLs, numeric IPs, localhost,
local-name targets and nonstandard ports are excluded from this operator.

Results show bounded header observations and plain actions in the popup.
Missing headers are not proof of exploitability. Failed/redirected requests have
no safety verdict. Site header repair requires the site's owner; this version
does not offer a fake automated repair or declare arbitrary websites safe.
No cloud account, vault unlock, Groq call or website allowlist is needed for this
browser-local check. Device checks still require the existing scoped helper.

The web sidebar exposes its four primary destinations and puts the existing
operational panels under a collapsed Advanced section. The web landing opens
vault management. Legacy task routes remain available under Advanced while
their replacement extension workflows are implemented.

## Remaining implementation and acceptance

1. Proactive exact-origin login assistance, TOTP form handling and post-login save
   offers, with explicit secret-use controls and navigation/iframe protections.
2. A unified assistant in the popup for approved cloud/device/code/dependency
   operations, short progress and actionable output; no arbitrary LLM commands.
3. Optional background header rechecks for explicitly opted-in origins and
   privacy-preserving local vault health checks; no browsing-history upload.
4. One-time cloud authorization without manual tokens. Vault-only connection
   credentials must not silently gain workspace or scanner permissions.
5. A reviewed device-helper installer/native-messaging flow with short-code
   pairing, exact scope and revocation. No hidden installation or broad port scan.
6. Complete all remaining normal tasks inside the extension, simplify the web
   landing, and finish cloud personal/shared multi-vault and helper acceptance.
7. Independent security review. Automated tests and an author review do not
   replace an external audit.

Passkey vault unlocking is optional future work. Phishing detection is excluded.
The local 0.14.0 build alone is not evidence that an installed browser extension
has reloaded or that native permission prompts and actual-site checks have passed.

## Verification, 21 October 2026

The first full frontend run passed 259 tests and exposed one initial-context
message regression. That message was changed from an error to a normal status
hint; the affected popup regression passed afterward. The final focused run
passed 22 tests, including exact-origin permission, denied access, navigation,
cookie/referrer exclusion, unavailable checks, HTTP-only warnings, reconnect and
vault-first navigation. Python packaging/status/deployment checks passed 24 with
one native Windows symlink fixture skipped. React and companion builds passed.

The hosted UI was updated with hash-verified archives after an encrypted backup.
Prior frontend/package files were retained. Public HTML references the new
vault-landing bundle. Browser control became disabled before rendered acceptance;
the installed 0.14.0 popup and its real-site permission flow remain unverified.

## Proactive login invitation, companion 0.14.1

Focusing a supported, visible, single-password HTTPS sign-in form offers an
in-page invitation to choose a saved login. The invitation reads no password or
vault entries and sends no credential metadata to the page. A trusted click asks
the worker to open the extension-owned popup. The worker requires the top frame,
the active sender tab, its original window and unchanged origin. Unlocking and
explicit exact-origin fill continue through the existing companion flow. Failed
popup opening is reported, with no website submission or credential write.

Chrome 127+ is required because this is the first version with general
`action.openPopup` availability. This is an invitation, not automatic unlock,
automatic credential filling, a post-login-success detector or TOTP autofill.
The focused invitation/autofill regression run passed 31 tests; the companion
production build passed. Installed native popup acceptance remains pending.

## Explicit authenticator filling, companion 0.14.2

The unlocked popup can bind an authenticator entry to an exact HTTPS origin,
replace that link with explicit confirmation, or remove it. This optional
`autofill_origin` is inside the encrypted entry and is validated on vault unlock
and write. Origin changes receive encrypted details-history events. Existing
authenticator entries have no inferred link; issuer/title strings are not used.

An explicit Fill verification code action preflights the current top-frame
receiver and its version, refreshes vault policy/revocation state, generates the
code locally, checks the active tab/origin again, and sends only the code to one
visible, editable `autocomplete=one-time-code` field. Ambiguous/split fields,
cross-origin forms, changed tabs and near-expiring codes fail without a retry.
Forms are not submitted. The user can disable filling without deleting the TOTP
secret. Secret keys never leave the extension or encrypted vault.

Focusing an explicit code field offers an invitation to open the companion.
No code is generated or filled by that invitation. Unattended TOTP filling,
post-login save detection and in-extension TOTP enrollment remain pending.

Regression testing caught a real transition bug: a login invitation could stop
the generation assistant from replacing it when a dynamic form became signup.
The panel reuse condition was corrected and the transition tests passed.

## Cloud sign-in authorization, companion 0.15.0

An unpaired popup now offers Sign in and connect against the pilot cloud origin.
An exact app-origin host grant is requested, a random 256-bit proof remains in
extension storage, and a five-minute approval request opens in a normal sign-in
tab. Only its random request ID appears in the URL. The user compares the six
digit code and explicitly approves one initialized, active, browser-enabled
personal vault. Neither the proof nor the resulting bearer token is displayed
on the approval page. No master passphrase is requested there.

Reopening the popup automatically finishes an approved connection; Finish
connection is also available. The vault response is verified through the
existing connection path before saving it. Existing local/multiple connections
are retained. Encrypted grant delivery is repeatable until acknowledged so a
lost network reply does not require re-approval. Pending handoffs expire, are
bound to the originating extension and proof, and are removed during backup
restore. Cancelling the request revokes its grant if approval had already
occurred. Normal connection revocation continues to apply.

The grant lasts up to thirty days and gives encrypted personal-vault access
only. It does not grant scanner/workspace access, connect all vaults silently,
unlock a vault, replace shared-vault trust verification, or install a device
helper. Shared-vault/local pairing remains in Advanced. Real browser approval
and popup acceptance remain pending; this is not a claim of independent audit.

Verification: all 274 frontend tests passed, React/companion production builds
passed, and 48 backend connection/platform/shared-companion/backup tests passed.
The hash-verified 0.15.0 runtime update was deployed after an encrypted backup.
Account, workspace, membership, vault, connection/device rows and the server key
were unchanged across the update. Public HTTPS checks returned start=200,
pending poll, unsigned approval=401, cancel=200, post-cancel poll=410 and healthy
owner setup state. This probe created no real vault grant. The post-update
encrypted backup completed successfully. Installed native/browser acceptance
and the separate shared-vault/device-helper onboarding remain open.


## Unified security controls, companion 0.16.0

The popup now wraps the existing assessment and AI-planning pipeline in one
security-assistant surface. It starts approved cloud website checks or checks
through an already paired device helper, shows short progress, limited
observations and up to five action drafts, and can cancel a pending run. It
never substitutes the cloud host for the user's computer. Device ports,
Windows posture and cached update checks clearly require the device helper.
The existing browser-only site check stays available without cloud access.

Security-agent access uses a separate, explicit sign-in approval for one
workspace, not a vault token. A thirty-day grant can request approved
assessments and read the requester's own operation results. Current membership,
role, expiry and extension origin are checked on each request. The grant cannot
unlock vaults, call general workspace APIs or approve repairs. Offboarding and
backup restore remove these grants. The control-room Connections page and the
extension both support revocation. Website allowlists and helper scope/policy
checks remain enforced by the existing deterministic operators.

Verification: 278 frontend tests passed, followed by six focused tests including
an additional separate-grant storage test. Forty-five backend tests covering
connections, operations, shared companions and backups passed. React and both
companion production builds passed. These are automated results, not installed
extension acceptance. One-click helper installation/pairing, in-popup file
checks, post-login save detection, background monitoring, shared-vault sign-in
onboarding and independent security review remain outstanding.


Deployment verification: companion 0.16.0 and its backend/control-room changes
were deployed to the free Oracle pilot from revision
55123cc35d5b773d120ff52371dd6cc64b325269. The release archive SHA-256 was
ba72bb4f21d5e1617964293ed32dbb6dc5c410f08983b0357edcc3dca684c5b0;
archive inventory and every payload hash were validated before installation.
Encrypted backups completed before and after the update. Accounts, membership,
workspaces, personal vault rows, existing companions/devices and the encryption
key matched their pre-update snapshots. HTTPS status returned 200 with owner
setup complete. Unauthorized security access and unsigned approval returned
401; a disposable pending security handoff could be started and cancelled,
after which polling returned 410. No real user grant was created by the probe.
SentinelOps and Caddy remained active. Browser inventory still returned
"Local browser use is disabled in Work settings"; no native acceptance is
claimed for this version.


## Popup file checks, companion 0.16.1

Advanced in the security assistant accepts a pasted or dropped UTF-8 text file
up to 64 KiB. Python AST checks and exact dependency checks run through the
existing assessment pipeline, with results and optional AI action drafts in
the same popup. No website visit is needed for these normal checks after
security access has been approved. Source is not written to extension storage
or retained in operation records and is never executed. Sending source to the
connected service requires explicit disclosure consent.

Dependency manifests support requirements.txt, package.json, package-lock v2/v3,
uv.lock and exact inventories. Preview uses the service parser without OSV
requests, then the user selects public package/version pairs and separately
consents to their OSV disclosure. Changing source, format or selection resets
the applicable approvals. Private package names can be excluded. Unsupported
and excluded record counts are visible, alongside scanner coverage limits.
Results include line numbers, package/advisory identities and fixed guidance
links, without exposing arbitrary workspace notes or submitted source.

All 283 frontend tests and 38 focused backend tests passed. Both companion
production builds passed. Tests cover explicit consent, stale selections,
file drop, size bounds, no preview-time OSV transmission, operation source
non-retention and separately scoped authorization. Actual installed extension
acceptance remains pending browser-control access. This does not complete
helper onboarding, background monitoring, post-login save offers, shared-vault
onboarding or independent security review.
