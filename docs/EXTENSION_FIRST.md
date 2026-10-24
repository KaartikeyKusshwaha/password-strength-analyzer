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
The current requirement-by-requirement state is maintained in
[EXTENSION_ACCEPTANCE.md](EXTENSION_ACCEPTANCE.md); the list above records the
original transition scope and is not a claim that later increments are missing.
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


Deployment: 0.16.1 was installed on the Oracle pilot from revision
d77f9042c3a7c6f07451b591bd7bd567655e9420 after verifying archive SHA-256
ca3c85f608ee59a32e9f4db17be8a8ee7eea532dc511fd1cc2f48ef8b9cc6225 and
all payload hashes. The installed package manifest reports 0.16.1. Account,
membership, workspace, personal/shared vault, companion and device rows and
the encryption key were unchanged across deployment. Encrypted backups passed
before and after the update. Public HTTPS remained healthy with owner setup
complete. Unauthenticated inventory preview returned 401, extension-origin
preflight returned 204 and an unrelated website origin was rejected with 403.
No real user access grant was created by verification. Native popup, file-drop
and cloud grant acceptance still require browser verification.


## Optional Windows helper setup, companion 0.17.0

The extension offers a bundled per-user Windows helper download and short-code
pairing. No Python installation, copied bearer token or terminal command is
required. The helper's visible Install and get pairing code action installs in
Local AppData, adds a Start menu shortcut and Windows uninstall entry, and
requests a five-minute code. It does not add a startup service or elevate.
The extension reviews exact scope and requires account password and MFA when
enabled. Pairing is an explicit additional capability in new security-access
approvals; existing assessment-only grants remain unable to pair devices.

The helper receives its device-only token via a random proof held only in
process memory, validates exact origin and scope, and persists the token with
current-user Windows DPAPI. Default targets are this computer's IPv4/IPv6
loopback only. Posture and cached-update access remain separate native and
server consents. Closing the helper stops polling. Cancelling an unacknowledged
handoff revokes its device and interrupts pending operations. Expiry, live role
checks, offboarding, ordinary device revocation and backup restore still apply.
The extension refreshes the device list and reuses its existing check/results
surface. The installer version, digest and unsigned status are shown honestly.

Verification: all 285 frontend tests passed, along with 83 focused backend
storage/pairing/device/operations/backup/release tests. Nine final pairing and
release tests also passed after adding cancellation and incomplete-artifact
coverage. Both web/extension production builds passed. The actual compiled
Windows helper exited zero in its headless self-test, importing the device
operator and completing a real DPAPI round trip, without installing or pairing
on the user's computer. Artifact and source hashes matched the build manifest.
The helper is an unsigned pilot; GUI install/shortcut/uninstall and actual
browser-to-helper acceptance remain unverified while browser control is
unavailable. This is not an independent security audit. See DEVICE_HELPER.md.


Deployment verification: companion 0.17.0 / helper 0.1.0 was deployed from
c0cae00bb808b4119a6a08c8f80e29fe92897b13. Release SHA-256:
e52588f5decbcc5bd2924c03884a57df21e246abd30159c2e89e02f5d85c2c5b.
The archive inventory and each payload digest were checked before installation.
Existing account, membership, workspace, personal/shared vault, companion and
device rows and the server encryption key remained unchanged. Encrypted
backups completed before and after the update. HTTPS status returned 200 with
owner setup complete. The public installer download was 12,629,618 bytes and
matched SHA-256 8b57c38b285e067d0641aa8ccf68aa6add27ca02b25a17a2ee9bd71f3be880d7.
The real helper client successfully started, polled and cancelled a disposable
pending request against the cloud. Unsigned extension approval returned 401;
post-cancellation polling returned 410. This created no real device grant and
did not install the helper. GUI installation and actual extension pairing/
scanning/uninstall acceptance remain pending.


## Quiet site checks, companion 0.18.0

The popup can opt the current exact HTTPS origin into quiet browser-local
header checks. No cloud/AI access or unlocked vault is required. The worker
stores only chosen origins and their latest header-check result/time, not
page paths, queries, credentials or browsing logs. It never requests an
unopted origin. Explicit host permission is checked before and after requests;
removal prunes the entry. Disabling during a request cannot re-enable it.

Visits reuse a twelve-hour check; browser alarms recheck due origins in batches
of five, with a fifty-origin bound. Failed checks remain unassessed and retry
on later wakes. A per-tab !/? badge surfaces observations/failures, while pending
secure-save badges take priority. Manual rechecks update the same result/badge.
The popup shows plain header guidance and opt-out controls. Browser sleep and
lifecycle constraints can delay scheduled work; no exact SLA is promised.

Verification: the full frontend run passed 292 tests. Eight focused tests passed
after the final bounded-concurrency change. Twenty-one package/status tests
passed with one Windows symlink fixture skipped. Content, popup and background
production builds passed. The actual bundled worker also booted against isolated
API fixtures and verified exact-origin cookie-free requests and opt-out cleanup.
Packaging refuses an unbundled monitoring worker. Installed browser acceptance
remains pending; this does not implement breach monitoring or post-login save
offers, nor replace independent security review. See QUIET_SITE_CHECKS.md.


Deployment: companion 0.18.0 was atomically published on Oracle from revision
da3542b2548f34ede206ab58e4d08fd7b63ecde4. Release archive SHA-256:
3a70260e70495b980146e11c0e77e417985eddfc9fe136bf984781ed24bc23a7;
installed companion ZIP SHA-256:
8142f25eb897f33809f5edc049f194779676eea4640a7e9060a7018fdfaaa973.
The archive inventory and payload hashes were validated, along with the ZIP
manifest, bundled-monitor protocol and ZIP integrity. Accounts, workspace and
membership, personal/shared vaults, companions/devices and server key remained
unchanged. Encrypted backups passed before/after; no app restart was needed.
Public HTTPS status returned 200 with owner setup complete. No real sites were
opted into monitoring. Browser inventory again reported Local browser use is
disabled in Work settings; native permission, alarm and badge acceptance is
unverified.


## In-extension account protection, companion 0.20.0

The unlocked popup now automatically estimates weak/repeated saved passwords
locally. An explicitly approved breach lookup uses the public Pwned Passwords
range API, padded responses, cookie omission and only a five-character SHA-1
prefix. It sends no account names, website names, complete hashes or passwords.
The provider sees the prefix and client IP. Runs are limited to twenty logins
and deduplicate repeated passwords. Current vault policy and synchronization
are checked before each query. Lock aborts external work and stale completions
are rejected. No vault-health output goes to AI or persistent extension storage.
Failed, skipped and unsupported checks stay unassessed. This is on-demand
password-dataset checking, not email/account breach monitoring or a guarantee
that an account is safe. Provider attribution is visible beside results.

Selected account-change plans can now be approved in the unlocked popup and
queued through the existing encrypted action pipeline without a website visit.
The new companion creation/context routes are bound to the current connection's
vault, user and kind. They reuse existing save/fill policies, shared-vault role
checks, transaction-time token validation, encrypted manifests and queue limits.
Passwords and selected origins remain inside the encrypted approval. The normal
operator still stages recoverable replacements, prepares supported exact-origin
forms and waits for human website submission/confirmation. A companion stop
route cancels a plan without deleting potentially used staged replacements.

Authenticator setup keys and TOTP URIs can now be added inside the extension,
with duplicate-key detection, explicit website binding and scoped saving policy.
Only ciphertext is synchronized. The user must confirm the first generated code
in the external service to enable its factor. The extension does not enroll
arbitrary accounts through a universal API or manage SMS/push as TOTP.

The website's primary labels are Vaults, Security results, Connections and
Settings; run/add-asset buttons are hidden on these primary control-room pages.
Device/project controls in the popup are collapsed behind a single entry and
the old three-tool website-launch menu is replaced by one control-room link.
This does not claim all remaining acceptance-ledger items are complete.

Verification: all 307 frontend tests passed, with a focused assistant UI test
passing after collapsing its controls. Production web, content, popup and worker
builds passed. Targeted backend account/vault/shared-connection regressions
passed 21 tests. The actual bundled worker fixture passed. A live prefix lookup
used only the public example password "password" and returned a valid match;
no saved user credential was used. Full backend-suite results and deployment
verification are recorded separately after completion. Browser acceptance and
independent review remain required.


Final regression run: all 459 backend tests passed with one native Windows
symlink fixture skipped; the run completed in 223.86 seconds and its JUnit
report is stored locally under ignored data/release020-backend-results.xml.
All 307 frontend tests passed. No independent audit or live-browser acceptance
is inferred from these results.


## Account protection deployment, companion 0.20.0

Deployed revision 14e1e04e58825c302a903a3f82f014a21d628d9c after an
archive SHA-256 check (84fa09f11d8bf528dcf5602d792bff902ff305891040aced0c46525ff31e0b18).
Accounts, workspace memberships, personal/shared vaults, device/browser
connections, credential-action records and the server encryption key were
unchanged. Encrypted backups passed before and after. Public HTTPS returned
200 with owner setup complete and the expected frontend bundle. Unsigned
companion context returned 401; extension preflight returned 204 and an
untrusted web-origin preflight returned 403.

Edge browser control connected successfully. The signed-in cloud interface
rendered Vaults, Security results, Connections and Settings. No cloud vault
exists in this account yet, so no unlocked cloud-vault acceptance is claimed.
The practice tab interrupted browser control; a fresh Edge cloud tab restored
control and rendered Settings. These observations do not verify an installed
0.20.0 extension, native permissions or helper installation.

## Login save offers and shared sign-in, companion 0.21.0

The popup can explicitly opt into login save offers per HTTPS origin (up to
50). Before this opt-in, login submissions are not read for this feature.
Only a trusted top-frame standard same-origin POST login with a single current
password and username creates a draft. The worker rechecks the origin, site
access and preference, bounds the entry and keeps at most ten tab-bound drafts
in memory. It never writes their passwords to extension storage, a server or
AI. Drafts expire after three minutes and are inaccessible after expiry,
worker restart, leaving the origin, dismissal or tab closure. Removing host
permissions clears drafts. Timers are best effort while the browser runs;
JavaScript memory is not guaranteed to be physically zeroed.

When the password form disappears, the page can offer private saving. The
prompt explicitly requires the user to confirm that login succeeded. It cannot
universally infer success or compare an encrypted locked vault. Clicking opens
the existing dedicated extension window; its exact window/tab binding, unlock,
policy checks, conflict handling and encrypted-write confirmation remain in
force. Cross-origin and unusual/SPA forms may not be supported. Nothing is
saved automatically.

Cloud connection approval now offers accepted, browser-enabled shared vaults
alongside initialized personal vaults. Each approval grants exactly one vault;
shared grants also expose only that user's encrypted sharing identity. Current
roles and browser policy remain enforced, and policy removal/offboarding revoke
access. Changing the selected vault clears the code-confirmation checkbox.
The extension's existing connection verifier reads the actual vault kind rather
than trusting new token metadata. Shared owner fingerprint verification remains
mandatory on unlock. Manual tokens remain available as an advanced option.

Connections now directs normal device onboarding to the Windows helper and
short-code pairing inside the extension. Python/manual connection forms and the
old dashboard operator are collapsed under Advanced.

Verification: 314 frontend tests passed across 71 files. Targeted cloud-handoff
regressions passed seven tests; shared companion/security suites passed their
existing cases. Production web/content/popup/worker builds passed. The actual
bundled worker fixture exercised opt-in draft creation, opening the bound
private window, reading only from that receiver, confirmation cleanup and no
plaintext storage. Native installed-extension and helper acceptance, periodic
breach monitoring and an independent audit remain outstanding.


### 0.21.0 deployment and live Edge verification

Deployed revision 64a88627ab459c0ba9ecbfe9ef3407c9be712084. Archive
SHA-256 a123d1ee062dfb1bf223776d1abca0166dc742a34e8be225e9bd2a8d04c51dd3;
companion ZIP SHA-256 d0b06cb532a484e9fc8ba83fbf8f311df47ecab0ef6102eb2a776a8842684ae5.
Inventory and every archive payload hash were checked. Protected account,
vault, sharing, device/companion and credential-action tables and the server
key were unchanged; encrypted backups passed before and after. An initial
health probe omitted the configured Host header and triggered rollback; the
corrected probe passed on the retry without weakening host validation.

The live signed-in Edge account rendered version 0.21.0, the four primary
navigation items and the new device-helper instructions with manual/Python
setup collapsed. The actual signed-in companion download reached the browser's
Downloads folder; its ZIP integrity, version and checksum matched the local
release. Unauthenticated download correctly returned 401. Public HTTPS status
returned 200 with setup complete and the expected frontend bundle. A screenshot
and structured verification record are stored under ignored data/oracle-deployment.

The browser security policy rejected navigation to edge://extensions/ and
explicitly prohibits alternate automation workarounds. Installed-extension
reload and native popup acceptance require the user's click. No new cloud
vault or scoped security connection exists in this account yet, so unlocked
cloud-vault, shared multi-user and helper pairing acceptance are not claimed.
Final focused capture/offer regressions passed 17 tests, targeted backend
handoff/shared/security/package tests passed 30 with one native skip, and five
deployment packaging tests passed. Independent audit and periodic breach
monitoring remain outside this verified increment.


## Recurring unlocked-vault review and retirement cleanup, 0.22.0

The popup now offers recurring Pwned Passwords checks, off by default and
scoped to an exact service, personal/shared kind and verified vault ID. Explicit
consent covers current and future eligible logins. Enabling does not immediately
query: on the next unlock, a due batch checks at most twenty eligible logins;
success waits at least 24 hours and rotates the next batch. Larger vaults are
not claimed to be fully checked each day. The popup must remain unlocked;
no worker holds decryption material or runs these queries while locked. There
is no guaranteed background SLA and no email/account breach monitor.

Recurring work uses the existing bounded, padded five-character-prefix client,
with per-entry revocation/policy refresh, lock abort and response validation.
The browser's existing provider permission is checked without prompting during
automatic runs; granting it requires the explicit enable click. There are no
queries as users type. Full passwords, hashes, names, site names and results are
not written to preferences or sent to AI. Stored scheduling metadata includes
the vault/service binding, opaque consent generation, last completed date,
retry date and batch cursor. Results remain ephemeral in the unlocked popup.

Consent and progress use separate local-storage keys. Late completions cannot
write the consent key, and a new opt-in gets a fresh generation. Stale progress
is ignored. Consent changes in another extension window abort the current
lookup; every next entry also rechecks the current generation. Errors and
aborts do not advance the completed date or cursor and can defer a retry for an
hour. A lookup already sent cannot be recalled from its provider.

The unused email-detection function, MIME parser module, MAIL rules and their
retired feature tests were removed. Existing API rejection regressions remain:
email scan, operation and combined-review requests are rejected before queuing
or persisting raw input. New assets no longer offer the inbox category. Older
persisted records remain readable; their history is not erased. Repository
integration documentation no longer advertises phishing triage. Python scan
coverage was corrected to list all eight PY rules rather than the first eight
entries in a mixed host/update/Python rule dictionary.

Verification: 431 backend tests passed with one native symlink skip in the full
suite (231.79 seconds). All 320 frontend tests then present passed; the final
recurrence failure case and related app/schedule regressions passed in a
subsequent focused run of 22 tests. Web, content, popup and bundled worker builds
passed, including the actual bundled-worker private-save fixture. Native
installed popup, cloud-vault and helper acceptance and independent audit remain
required. Live 0.21.0 practice-page inspection found no field invitation after
trusted focus, so installed version/profile/site-access diagnosis is pending;
no successful 0.22.0 native flow is inferred from tests.

Provider protocol checked against the official documentation:
https://haveibeenpwned.com/API/V3 and https://haveibeenpwned.com/scalar/.


### 0.22.0 deployment and installed-browser evidence

Deployed revision 5624b375cde924601d19880ca68647d9581a81b8. Archive
SHA-256 d04b43fcaf2e81e4e0cff756dd81c3b8797fcf5b0f5e31b769726b2c620e90c0;
ZIP SHA-256 03f5c6c460cf56b03918db93ec29aaa849bb281128be2261c96878eec170bf27.
All 57 archive files and manifest hashes were checked. Account/vault/sharing,
companion/device and credential-action records and the server key were
preserved during deployment; backups passed before and after. The retired mail
module was moved out of the current installation into its rollback directory.
Public HTTPS returned 200, setup remained complete and the expected 0.22
frontend bundle loaded. Signed-in Edge showed the 0.22 footer and four-section
navigation.

The user reported a 0.22 popup. Direct screenshots verified the installed login
invitation and proactive signup assistant, without entering or submitting any
credential. The signup overlay itself reported content 0.21.0: the local build
changed after the user's prior reload, leaving mixed cached/bundled versions.
The product is not considered to have passed an installed 0.22 end-to-end run.
Browser management also confirmed a duplicate practice tab was in the background;
its active-tab popup guard correctly refused launch. The invitation still failed
to launch the toolbar popup from the already-active original tab, so programmatic
popup compatibility remains unresolved. Manual toolbar opening works by user
report. The temporary duplicate practice/signup tabs were closed; the original
practice tab was retained.

The cloud account initially had no vault. An empty default Personal vault space
was created through its normal UI and the backend response rendered the master
passphrase/confirmation form. No passphrase was entered and no encrypted payload
or browser/security grant was created. This intentional setup action occurred
after the deployment's protected-state comparison. The next credential step
requires the user to choose the passphrase in the app. Edge then disconnected;
fresh inventory had no Edge browser and the supported reopen call reported it
unavailable. Native site-check results and cloud/helper acceptance remain
pending. Evidence screenshots/JSON and test reports remain under ignored data/.


## Queued popup diagnostics and version guard (source only)

The current 0.22 installed directory and downloadable ZIP are intentionally
unchanged while native acceptance is pending. The source now reads the browser's
registered manifest version for its popup header. If this differs from the file
bundle's version (or the extension context is invalid), it pauses vault/setup
controls before connection reads or unlocking and explains one reload plus a
website refresh. Matching versions retain ordinary setup. This addresses the
misleading popup/file version display observed during unpacked updates; it is
not a claim that the underlying Edge popup-opening failure is fixed.

The worker now classifies inactive/stale tabs, missing URL/site access,
unavailable popup APIs, browser-focus/user-gesture rejections and other launch
failures. Only fixed codes reach the content invitation; native exception text
is not returned or persisted. Existing top-frame, HTTPS, current-origin and
window checks are unchanged. The in-page invitation maps these codes to concrete
next steps rather than the previous generic failure.

Nineteen focused popup/capture/version tests passed, including matching-version
setup, mismatched/invalid contexts with no vault reads, preserved origin/frame
checks and exception redaction. Production content/popup/worker bundles were
built only under ignored data/qa-popup-20261022T0332. The actual isolated bundled
worker passed its private-save, monitor and popup-diagnostic fixture. Hashes of
every file in the installed companion/extension/dist directory were compared
before and after and remained identical. No new extension release or deployment
of this source patch has occurred. Rebuild/version the release deliberately after
native acceptance resumes; do not silently replace the frozen installed files.


Final queued-patch regression: all 327 frontend tests passed across 73 files.
The first full run exposed three old browser mocks missing runtime.getManifest;
the mocks were updated to the actual browser API shape, keeping production's
version guard fail-closed. Existing personal/shared autofill and reconnect
regressions passed again. The installed 0.22 ZIP retained SHA-256
03f5c6c460cf56b03918db93ec29aaa849bb281128be2261c96878eec170bf27.
A limited credential-pattern review scanned 728 new reachable Git blobs across
53 commits relative to the local origin/main reference, finding no Groq-key,
GitHub-token, private-key or AWS-access-ID patterns. No data/.env/key paths were
tracked. This is not a comprehensive secret scan, live-key validation or external
security audit. The ignored report records its exact scope and scanned head.
