# Extension-first acceptance ledger

This ledger separates implemented behavior from release acceptance. A checked
unit test or deployed archive does not prove an installed extension workflow.

| Requirement | Current implementation | Remaining evidence / work |
| --- | --- | --- |
| Site check starts and finishes in extension | Browser-only exact-origin header operator, plain guidance; user screenshot confirms HTTP 200 and three header observations on practice.expandtesting.com | Manual popup result passed; permission-prompt lifecycle and quiet-check badge acceptance remain |
| Device checks in extension | Scoped helper operator, progress, results, cancellation | Installed helper pairing and complete cloud scan |
| Python and dependency file checks | Popup paste/drop, inventory preview, selected OSV disclosure, results | Native popup file-drop acceptance |
| One assistant surface | Internal pipeline hidden; device/project controls collapsed in popup | Product usability review with real users |
| Signup/password-change suggestions | Trusted-focus local generation and explicit secure save | Login/signup invitations directly observed on practice site; content 0.21 versus popup 0.22 mismatch needs reload synchronization |
| Login and TOTP assistance | Exact-origin login choice, explicit linked TOTP fill, no submit; installed login invitation observed | Installed cloud multi-vault acceptance; unattended TOTP is not implemented |
| Post-login save offer | Per-site opt-in, trusted standard login submission, ephemeral worker draft, explicit private save | Native navigation/expiry acceptance; no universal success detection or locked-vault duplicate detection |
| In-page popup launch | Toolbar popup works by user report; invitation is visible | Programmatic popup launch still fails in active Edge practice tab; diagnose native error before calling complete |
| Quiet background site checks | Per-origin opt-in, alarms, local results, badges, opt-out | Real Chrome/Edge alarm lifecycle |
| Password health in popup | Local weak/reuse estimates; on-demand and opt-in daily-on-unlock padded HIBP prefix checks | Installed host-permission/lock cancellation acceptance; no always-on checking while locked |
| Approve account fixes without website | Popup selection creates encrypted plan; existing operator stages/prepares forms; stop action available | Native popup claim, form preparation and resume acceptance |
| Add authenticator without website | Parse setup key/URI locally, policy checks, ciphertext write; code shown in popup | External service must confirm first code; native popup acceptance |
| Control-room website | Vaults, Security results, Connections, Settings; advanced panels collapsed; primary run/add buttons removed | Four destinations and current onboarding copy rendered in signed-in Edge 0.21; subsequent native acceptance still needed |
| Cloud sign-in connection | Proof-bound code comparison and scoped approval, no token copying | Real cloud grant + popup acceptance |
| Multiple and shared vaults | Existing per-vault encrypted data, scoped tokens and shared trust checks | Personal/shared token-free handoff implemented; complete multi-vault browser run |
| Device onboarding | Bundled per-user Windows helper with short-code pairing and account reauthentication | GUI install, shortcut, uninstall and live extension pairing |
| No phishing feature | Email operator, MIME module and MAIL rules removed; new inbox assets excluded | Rejection regressions and independent audit of exposed entry points |
| Independent review | Threat-model/security docs and automated authorization tests exist | An external security audit has not occurred |

No universal password-change API, arbitrary-command agent, unattended website
submission, automatic OS repair, passkey-to-vault unlock, or email breach
monitor is claimed. A browser cannot inspect device ports without the helper.
The helper remains an unsigned pilot. These limits must remain visible rather
than being hidden behind a success status or a completion percentage.

### Queued HTTP-response correction

Source review found that error responses carrying the expected security headers
could produce an empty action list. The queued checker now requires a 2xx
response before interpreting headers. Access-denied, unsupported HEAD,
rate-limited and unavailable responses remain unassessed. A real-checker monitor
regression verifies that a 503 with all expected headers retains the unknown
badge. All 29 site-check/operator/UI/monitor tests passed. This correction is
source-only; the installed 0.22 directory and archive remain frozen.

Edge reconnected as browser 4. The practice login invitation appeared after
trusted focus; evidence is saved under ignored data/oracle-deployment as
edge-reconnected-login-invitation.png. The Personal cloud vault remains at its
initialization form, with no passphrase entered. Native popup site-check
acceptance still awaits the user's click.

### Manual site-check acceptance — 22 October 2026

The user supplied codex-clipboard-bbcfdf01-636b-458d-957d-a34d1214cdd5.png
showing the installed extension's result for https://practice.expandtesting.com:
HTTP 200, "3 things to review", the root HEAD/cookie-free coverage description,
and guidance for HSTS, CSP and content-type guessing. This proves the manual
popup site-check path returned and rendered its result. It does not prove
quiet-check scheduling, permission revocation, automatic remediation, cloud
vault handoff or device scanning. The observations describe the response's
header presence, not whether the website is safe or exploitable. No screenshot
claim is made about a permission prompt that is not pictured. The queued
non-2xx correction is not part of this installed result.

### Companion 0.22.1 release — 22 October 2026

After the manual popup site-check acceptance, the installed local directory and
cloud download were deliberately advanced to 0.22.1 in one build. This releases
the registered-version guard, fixed-code popup diagnostics and non-2xx unknown
result behavior described above. All 336 frontend tests across 73 files passed;
content, popup and worker production builds and the actual bundled-worker
fixture passed. The package SHA-256 is
48242862fc70edf4dd9ffbb64fb1913996eb539df8ba23caebdd22834a27798b.

The Oracle deployment replaced only the downloadable companion ZIP atomically,
retaining the prior ZIP for rollback. The encrypted backup passed, the service
remained active and no database/config/frontend/backend change was performed.
The website remains app version 0.22.0; the companion is 0.22.1. The registered
Edge extension still needs one user reload and practice-page refresh before
native acceptance of this patch. Diagnostics are not a claim that programmatic
Edge popup launch has been repaired. No credentials or permissions were added.

### Cloud download and vault initialization acceptance

The signed-in Edge control room downloaded companion 0.22.1 through the public
application download link. The downloaded ZIP passed integrity checks, its
manifest version was 0.22.1 and its SHA-256 matched the release exactly:
48242862fc70edf4dd9ffbb64fb1913996eb539df8ba23caebdd22834a27798b.
The connection panel also rendered Downloadable companion: 0.22.1.

After the user initialized the disposable Personal cloud vault, its supplied
public test passphrase successfully unlocked it through the UI. The page showed
Personal vault unlocked with zero entries. Evidence screenshot:
data/oracle-deployment/cloud-personal-unlocked.png. No real credentials were
saved. Extension-to-cloud scoped connection is still pending the native popup
sign-in action. This does not establish cloud autofill or multi-vault acceptance.

The helper endpoint returned HTTP 200 and 12,629,618 bytes from the server.
Edge did not report a completed native download during the observed timeout.
No browser warning was bypassed and no helper executable was run or installed.

### Cloud personal-vault authorization — 22 October 2026

After the previous request expired, the user started a new proof-bound connection
and completed its comparison-code approval. The actual Connections page now
lists Cloud extension, Personal vault, expiring 21 November 2026. A fresh UI
refresh still reports no successful vault contact and no reported version.
This proves scoped authorization exists, not that the native popup exchanged its
proof or read/unlocked the vault. The next step is reopening the popup to finish
handoff. Evidence: data/oracle-deployment/cloud-vault-connection-approved.png.
No security-agent grant is listed and no scan permission is inferred from this
vault authorization. No operator-side token copying or direct grant insertion
was used.

### First installed cloud companion contact

A fresh Connections UI refresh showed Last vault contact: 22 October 2026,
04:17:51 Asia/Calcutta, and Client reports version 0.22.1, matching the
downloadable build. This verifies the installed extension finished the cloud
handoff and performed an authorized encrypted-vault read. It does not prove
local decryption, a saved item, autofill, shared-vault access or security-agent
permissions. Evidence: data/oracle-deployment/cloud-companion-first-contact-0.22.1.png.

### Approved cloud demo entry saved; autofill pending

The user explicitly approved saving the public practice.expandtesting.com demo
login in the Personal cloud test vault. Through the normal control-room UI,
the existing vault was unlocked and Practice cloud acceptance was encrypted and
saved. The UI showed one entry with the exact HTTPS origin and public username.
This is a control-room save, not installed extension secure-save acceptance.
Evidence: data/oracle-deployment/cloud-demo-login-saved.png.
The practice username and password fields were then cleared through UI controls;
no login form was submitted. Native companion retrieval/fill awaits the user's
popup click, after which both field values can be verified without exposing
real credentials. The public test vault must not store valuable credentials.

### Queued proactive username invitation

Source now offers the login invitation when the user focuses the recognized
username/email field of an unambiguous supported login form, in addition to its
password field. It reuses the exact login-target resolution, excludes unrelated
email forms, explicit signup fields, cross-origin forms and frames, and reads no
credential values to construct the invitation. Twenty login invitation/form
regressions passed. This is source-only; installed companion 0.22.1 remains
unchanged while cloud native autofill acceptance proceeds.

### Cloud autofill mismatch investigation

After the user reported clicking fill, read-only DOM comparisons showed both
practice form fields nonempty but neither matching the approved public demo
entry. The page remained /login and no submission was performed. No field values
were copied into the test report. The selected vault/entry or possible browser
password-manager contribution needs clarification; this is not a successful
cloud exact-entry autofill acceptance. The current source's full frontend suite,
including the queued username-focus invitation, passed 338 tests in 73 files.
The installed 0.22.1 build remains unchanged.

### Correction: redacted comparisons do not establish mismatched credentials

Direct visual inspection after the user's cloud entry selection shows the
practice username field contains practice and the password field is populated.
Both fields were independently observed empty before the user's fill action.
The user confirmed selecting cloud Personal / Practice cloud acceptance.
The prior DOM comparison returned false even for the visibly matching username;
credential redaction makes that comparison unsuitable as exact-value evidence.
The previous mismatch inference is withdrawn. Visual evidence verifies both
fields populated with the expected visible username; the masked password's
exact value and successful website authentication remain unverified. No Login
submission was made. Screenshot: data/oracle-deployment/cloud-autofill-visible.png.
Do not read or expose the masked password to work around tool redaction.


### Render owner initialization and administrator MFA — 24 October 2026

User-created owner account and SentinelOps Test Lab workspace are visible on
the new Render/Neon installation. Read-only Settings inspection confirmed
Authenticator protection **Enabled**, eight recovery codes remaining and MFA
disable unavailable while the account holds an owner role. No code/seed was
used by the agent. This is app MFA setup evidence, not companion TOTP acceptance.

Through ordinary vault UI, created the empty **Browser acceptance** personal
vault space, default three-minute lock and existing browser save/fill policy.
It has no encrypted envelope yet. Master-passphrase entry, confirmation and
Create vault submission were handed to the user; no vault unlock, payload save,
companion pairing or autofill is claimed at this checkpoint. Evidence:
`data/render-browser-acceptance-vault-ready.png` (private operator screenshot).
The test browser is the in-app browser; installed Edge companion acceptance
remains separate. The current Render source remains c62da24, app/companion0.25.0.


### Render personal vault save/lock/reload — 24 October 2026

The user initialized Browser acceptance and explicitly approved storing the
public practice.expandtesting.com demo login in that vault and testing fill
without website submission. Through the actual in-app browser control-room UI,
unlocked the vault with its existing disposable test passphrase, saved Practice
cloud acceptance and observed its entry with no error. Explicit Lock hid the
entry and displayed the unlock form. Full page reload followed by a fresh
unlock restored the entry with no error. Screenshot:
`data/render-demo-login-reopened.png`.

This verifies a control-room encrypted save, lock concealment and cloud-backed
retrieval/decryption after reload. It does not establish installed-extension
secure-save, autofill, TOTP or shared-vault acceptance. No practice website login
was submitted. Opened a fresh Edge cloud tab and signed in using the authorized
test account; it reached One more check. The current authenticator entry was
handed to the user. Edge companion pairing/fill remains pending that sign-in.


### Authenticated Render companion download — 24 October 2026

Downloaded the actual companion through the signed-in in-app Connections link,
without extracting/replaying a session cookie. ZIP version 0.25.0, 13 files,
SHA-256 `7e7520e65023aa68573572576cb75cdfb2bcca831632efe4b913b73d9f4d9ec7`.
Manifest has storage/activeTab/alarms permissions; bundled JavaScript contains
the Render pilot origin and no old Oracle origin. This is the hosted Linux
artifact, not the earlier Windows local ZIP; its independently recorded checksum
is not assumed equal across builders. Download does not prove installed behavior.

The user's Edge MFA sign-in completed and the Browser acceptance cloud vault is
visible there, locked. A fresh Edge practice login tab is open with empty fields.
Starting native companion comparison-code pairing was handed to the user because
the popup is outside browser controls. No new vault connection or scan grant has
yet been approved or inferred.

Connections also offered a Windows helper link when its build is absent in the
Render image. Source fix 3ed486d adds validated helper availability to the
session-authenticated companion metadata and hides the missing download/install
steps. Available builds display version and SHA-256. Focused validation passed
23 backend helper/security tests, two frontend cases and production web build.
This source fix is not yet deployed; native binaries remain undistributed.


### Helper availability fix deployed — 24 October 2026

Render deployment `dep-dbds3qrncjis73dajevg` at source `3ad19c8` completed Live
in 59.9 seconds. After reloading the authenticated in-app Connections page,
the session remained valid, downloadable companion remained 0.25.0, the missing
Windows download link was absent, and the explicit deployment-unavailable/helper
requirement message was visible. Screenshot:
`data/render-helper-unavailable-confirmed.png`.
CI run 40018301276 passed five built-extension browser cases, 73 PostgreSQL and
backup checks (one platform skip), 42 helper/release checks and container startup.
Local helper/security tests passed 23, frontend availability cases two, web build
passed. This fixes missing-download guidance; it does not distribute a helper.
Installed Edge cloud comparison-code pairing still awaits the native-popup step.

### Render pairing reached the vault API — 24 October 2026

The user completed a new comparison-code approval in Edge. The actual approval
page displayed “Approved. Return to the extension and choose Finish connection.”
The authenticated Connections report subsequently recorded successful vault
contact at 03:40:42 IST from companion version 0.25.1. This confirms an approved
Render vault connection and an authenticated vault API request, not an independently
observed successful unlock or autofill. An older approved connection still has no
recorded vault contact. Neither connection was revoked during this observation.
Screenshot: `data/render-edge-contact-0251-20261024.png`.

The locally built companion is 0.25.1; the currently deployed Render download is
still 0.25.0. The control-room version warning reflects that difference and does
not invalidate the successful contact. Commit 527ba79 improves unreachable-server
errors and warns about ambiguous timed-out writes without automatically replaying
them or silently changing a vault's server. Its 12 targeted tests and root build
passed. CI run 40024857918 passed five isolated extension cases, 73 PostgreSQL
checks (one skipped), 42 helper/release checks and container startup.

A fresh Edge practice login page was opened with both fields empty. The subsequent
read-only check still found both empty; the installed-extension Fill action is
awaiting the user's native-popup click. No website login was submitted. Cloud
secure-save, TOTP and the two-account shared-vault removal test remain unverified
in the installed browser; isolated CI cases do not substitute for those gates.

Later observation: both practice login fields became nonempty, and the screenshot
visibly shows username `practice` with a masked password. The browser-control
DOM adapter substitutes `<redacted>` for both populated credential values.
Consequently, comparisons against the demo username/password returned false but
cannot establish a mismatch; that intermediate interpretation was withdrawn.
No attempt was made to bypass masking or submit the website login. Whether
SentinelOps or the browser's own manager performed this fill awaits the user's
confirmation. Screenshot: `data/render-edge-autofill-populated-20261024.png`.
The existing cloud test passphrase also unlocked Browser acceptance through the
control-room UI, which displayed its single Practice cloud acceptance entry;
the vault was explicitly locked afterward. This does not prove popup unlock.

The user subsequently confirmed explicitly: “Yes, I clicked SentinelOps Fill
this login.” Together with the before/after empty-to-populated fields and the
visible `practice` username, this verifies a user-initiated installed Edge fill
from the connected Render test vault. The password stayed masked and the website
Login button was not submitted, so this is a form-fill acceptance result, not a
website authentication success or a byte-for-byte password comparison. Secure-save,
TOTP and multi-account sharing/revocation remain separate unverified live gates.

### Hosted vault activity repaired — 24 October 2026

After a fresh owner/MFA sign-in, opening the live vault activity panel produced
an unexpected-response error. The PostgreSQL translator supported positional
binds but left named SQLite binds untranslated, even quoting the `:user` bind
name as an identifier. Commit 4f10b16 adds driver-bound named placeholders while
preserving quoted literals and PostgreSQL casts. The regression failed before
the fix and passed afterward. Local validation passed 17 tests; four real-PG
cases skipped without the isolated fixture. The initial local activity run hit
an inaccessible Windows pytest temp directory; a fresh dedicated test directory
resolved that setup problem without modifying application data.

CI run 40080397334 passed 77 PostgreSQL checks (one skipped), including real
personal/shared activity isolation and keyset pagination, 42 helper/release
checks, five extension cases and container startup. Render Free deployment
`dep-dbe79jom7kps73ct5d80` of 4f10b16 completed Live in 49.2 seconds. The existing
authenticated app session survived reload. The same activity panel then loaded
real initialization, save and browser-connection events without the error.
Screenshot: `data/render-vault-activity-fixed-4f10b16.png`.

The observed events include the earlier control-room encrypted save and two
browser connections, but no companion save. Installed-extension secure-save
remains pending, not inferred from the repaired service log. This deployment
also packages companion 0.25.1; no paid service or permission expansion occurred.

### Installed cloud unlock screenshot — 24 October 2026, 17:47 IST

User-supplied screenshots `Screenshot 2026-10-24 174709.png` and
`Screenshot 2026-10-24 174741.png` show companion 0.25.1, the selected
`Browser acceptance · sentinelops-pilot.onrender.com` connection, and
`Unlocked · this popup only`. This supplies direct visual evidence of installed
cloud vault unlock, beyond the earlier API-contact record. The third screenshot
shows the current website is the SentinelOps app itself, with no saved login
for that exact origin; the public practice entry belongs to a different origin.
That message is expected and does not establish data loss or failed pairing.
Cloud secure-save and TOTP remain pending separate installed-browser tests.
