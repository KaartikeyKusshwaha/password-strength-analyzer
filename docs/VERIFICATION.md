# Development verification — 0.16.0


## Offline recovery kits — 0.16.0

Full Python suite: 416 passed. Six focused recovery API cases passed including
mid-transaction rollback, scoped queued/leased-work cancellation and unrelated
vault preservation. Full frontend: 225 tests across 49 files plus production
build passed; 12 focused UI cases and the final build passed after scope-wording
corrections. The committed native vector also passed its independent Python
reproduction check (`tests/recovery_vector.py`). Cryptographic tests include an independent native Python vector,
subsequent encrypted writes, current-data recovery, fresh key rotation, explicit
snapshot selection and tampered/wrong-context/key rejection. Lifecycle tests
exclude secrets from requests and discard hidden/cancelled late results.

The actual app received a fresh encrypted backup and passed 15 startup checks
without schema or protected-data changes. No recovery key/kit was activated for
an actual vault. Edge was not connected; the real in-app browser sign-in screen
opened and is waiting for owner sign-in. Visual recovery setup/download/use and
independent security review remain open. See VAULT_RECOVERY_KITS.md. Ignored
startup evidence: `data/upgrade-0.16.0-*`; UI handoff screenshot:
`data/browser-acceptance-0.16.0/sign-in-handoff.png`.


## Windows Update observations — 0.15.0

The final complete Python suite (`tests` plus `test_analyzer.py`) passed 411
checks. A legacy migration test fixture was corrected to construct schema 8
without leaving the new version-10 marker behind. Focused crypto/migration/update
regressions passed 57 tests. React: 215 tests across 47 files passed, then 17
focused UI tests passed after a final finding-count label/scope-text correction.
The final production build passed. Existing TestClient/Vite warnings remain.

A live fixed Windows collector and actual Edge operation both reported zero
cached pending updates and no update-related restart; cache freshness remained
unverified. The real operation completed, its typed result rendered, no finding
or AI job was fabricated, and the audit chain remained valid. No updates were
installed or machine settings changed. New paired permission/lease paths have
API/client tests, not a claim of real remote-device acceptance.

The actual schema-9 backup restored to a separate schema-10 directory with 11
checks passing. The live upgrade passed 16 preservation/default-denial checks.
See WINDOWS_UPDATES.md and BACKUP_RECOVERY.md. Ignored screenshot and result:
`data/browser-acceptance-0.15.0/`.


## Message triage — 0.14.1

Bounded explicit RFC 822/MIME parsing, sanitized evidence, message-specific
finding/recheck scope and UI controls are implemented. The full Python run
passed 394 tests before the final agent scope change; 48 targeted platform/agent
and message regression tests passed after that adjustment. Frontend: 211 tests across
46 files and production build passed. See MESSAGE_TRIAGE.md for exact scope,
privacy boundaries, test coverage, upgrade checks and the actual Edge format
selection screenshot. No trained classifier or live inbox integration is claimed.


## Combined reviews — 21 October 2026

The full backend suite passed 360 tests; the final frontend suite passed 208
across 45 files and the production build passed. A focused 58-test backend run
also passed after report/version changes. Vite retains its existing large
strength-library chunk warning.

A fresh encrypted backup preceded the main 0.14.0 upgrade. Schema 9 integrity,
owner setup, ten compared record groups and the server encryption key were
preserved before the subsequent authorized browser workflow.

An isolated live Groq review completed two checks, three findings, one AI job
and three tasks. In actual Edge, the owner signed in normally and approved a
real localhost:8110 port check plus fixed Windows posture and AI follow-up.
Both coverage tables rendered: one open port, firewall/Defender enabled and
BitLocker permission denied. The review stayed partial; Groq planned its one
finding and created one open task. Agent-worker completion and task dispatch
were visibly verified. No setting was changed or repair claimed.

Ignored screenshot: data/browser-acceptance-0.14.0/combined-review.png.
See SECURITY_REVIEWS.md for scope, cancellation and remaining limitations.

## Live Groq activation — 21 October 2026

The supplied key authenticated at Groq's model-list endpoint. The existing
llama-3.3-70b-versatile configuration was unavailable to this account; the
operator explicitly set available openai/gpt-oss-120b in ignored `.env`.
No automatic substitute-model behavior was added. A synthetic plan passed
the production request/schema/citation validation code. An isolated synthetic
API operation then passed actual assessment, live Groq planning, task creation
and progress: one finding, one task, five completed workers, valid audit and
awaiting_recheck. No owner source, email or vault data was used in the probe.

After a fresh encrypted backup and inactive-job check, the main app was
restarted with the configuration. All ten compared record groups and its
server encryption key matched; integrity and owner setup passed. Ignored
evidence is recorded in REPOSITORY_INTEGRATION.md. Actual main-owner browser
AI-run acceptance subsequently passed in the combined review below. The full cross-module autonomous
loop and assign-3 classifier integration remain unfinished.

## Actual Edge autofill observation — 21 October 2026

The user reported Username and password filled after the requested 0.12.8
reload. The driver observed both practice fields populated and screenshot
username practice; it did not write either field. Browser-tool redaction means
the initial DOM equality checks cannot establish their exact plaintext values.
The evidence JSON explicitly records this limitation. A subsequent public-demo
Login submission timed out at /authenticate; server acceptance is unverified,
and no POST retry was made. See the before/after screenshots and result under
data/browser-acceptance-0.13.3/. Other sites, shared fills and installed negative
cases remain outside this single successful population observation.

## Edge fill feedback — companion 0.12.8 — 21 October 2026

Actual Edge website control returned. The stopped local app was started again;
its signed-out UI rendered. The unused blank tab, two duplicate app tabs and
the Add-ons tab were closed on request. Both live practice inputs remain blank;
their observed attributes and same-origin submit destination match the supported
form fixture. A read-only local check of only the Browser acceptance test vault
verified its master and public demo login. No owner password was retrieved.

The user reports that Fill does nothing. The installed toolbar popup is outside
the browser controls, so no exact popup outcome has yet been observed. Companion
0.12.8 adds entry-local progress/errors, a changing disabled busy button and
five-second page acknowledgements. A late preflight cannot use a newly unlocked
session, an unanswered preflight does not release credentials, and an uncertain
fill is never resent. The response may already have arrived; the UI says so.

All 203 frontend tests across 44 files passed and both companion builds passed.
Fourteen focused client cases also passed after strengthening the lock-during-
fetch fixture. The 12-file ZIP matches every build byte, retains the same
permissions and has no web-accessible private pages. SHA-256:
3a45956f56c8e08038d3da9f87aab1e11ee5f34ceb9cf2ed998916864c63767f.
No backend or app build changed; the live app remains 0.13.3. The existing
pairing/vault was retained. Installed 0.12.8 reload, exact popup feedback and
actual field-retention acceptance remain pending. See
companion-0.12.8-fill-feedback.md and BROWSER_ACCEPTANCE.md.

## Sourced dependency severity — 21 October 2026

Manual checks and registered watches now share bounded batch matching, alias
details and CVSS base calculations from OSV records. Each finding retains
version/vector/source provenance, partial/unavailable states and distinct
ratings. Missing ratings remain unknown. Severity-only changes preserve finding
and task identity. See ADVISORY_SEVERITY.md for exact scope.

Full regression: 352 backend tests passed (one existing TestClient warning),
198 frontend tests across 43 files passed, production build and pip check
passed. The initial focused run encountered the system pytest temp directory's
access-denied error; rerunning with a fresh repository-local basetemp passed
81 cases. The full run used a separate fresh basetemp and JUnit evidence in
data/backend-regression-cvss-20261021-01.xml.

A read-only live API check of the previously approved public lodash 4.17.20
fixture assessed one exact pin, fetched 5/5 advisory records and calculated
usable ratings for all five groups, including CVSS 3.1 and 4.0. The separate
public cvss 3.6 package query returned no OSV matches at check time; this is not
a safety certification. No owner inventory or findings were altered by either
probe. Ignored evidence: data/osv-cvss-live-20261021.json.

After a fresh encrypted backup, the local app restarted as 0.13.3. Integrity,
schema 9, ten compared record groups and encryption key matched. Served index
and script bytes match the build, which carries the new version. Owner setup
and unauthenticated scan rejection passed. Evidence is in
data/upgrade-0.13.3-baseline.json and data/upgrade-0.13.3-result.json. Actual Edge
autofill and the new severity UI remain visually unverified because local
browser control is disabled; HTTP and component checks do not replace them.

## Individual connection revocation — 21 October 2026

Browser & devices now prepares a named one-connection disconnection with a Keep
option. Account session/CSRF, account isolation, retained other grants/data and
transactional report/lease cleanup are implemented. Vault/action operations
recheck a current scoped bearer in their use transaction. Forty focused backend
and eight focused UI/operator cases passed, including actual personal/shared
route interleavings and rollback after a forced token-deletion failure. This
does not retract previously delivered plaintext. See COMPANION_CONNECTION_REPORTS.md.

Full regression: 327 backend tests passed (one existing TestClient warning),
194 frontend tests across 42 files passed, and production build passed. After
a fresh encrypted backup, the local app was restarted as 0.13.2. Integrity,
schema 9, ten compared record groups and encryption key matched; contact-report
entities are excluded from the comparison. The served index matches the build
and the live revoke endpoint rejects unauthenticated requests. No owner
connection was revoked for this smoke check. Actual visual acceptance is pending.

## Browser connection reports — 21 October 2026

Account-private contact/version diagnostics are integrated in Browser & devices
and companion 0.12.7. Reports do not expose token hashes or vault/website content
and cannot authorize an action. Full backend: 319 passed (one existing warning).
Full frontend: 192 passed / 42 files. App/companion builds and ZIP comparisons
passed. The backed-up owner app was restarted with all nine compared record
groups and its key unchanged; live schema remains 9 and the new header preflight
works. Native passkey test port 8111 was stopped with data retained. Installed
client/visual acceptance remains pending. See COMPANION_CONNECTION_REPORTS.md.

## Companion autofill receipts — 21 October 2026

Companion 0.12.6 rechecks field identity/form eligibility between credential
writes and observes field retention before reporting success. A website's
replacement/reset is reported without retry or submission; password-only steps
have a distinct message. All 189 frontend tests across 41 files and both
companion builds passed. The 12-file package matches its build. Actual installed
Edge acceptance remains pending because the latest browser inventory reports
local browser use disabled and exposes no apps/browsers. See
companion-0.12.6-autofill-receipts.md for exact evidence and scope.

## Account passkey integration and live upgrade — 21 October 2026

- Enrollment, one-time browser-bound sign-in, pending MFA, own-key management,
  reauthenticated removal, cancellation and session/audit policy are integrated.
  Proofs cannot substitute for a current account/workspace authorization check.
- Backend: 313-test full run passed; final authentication suite passed 43 tests
  after membership guards. Frontend: 176 tests across 41 files passed; a final
  14-test focused follow-up and production build also passed.
- A fresh encrypted backup preceded a process-chain-verified restart with no
  active jobs or enabled watches. The owner store is now schema 9. Integrity
  and protected account/vault/sharing/connection/key comparisons passed.
- Live Edge kept its owner session, showed 0.13.0 and the unsupported-IP-origin
  passkey state, and unlocked/relocked the unchanged disposable one-entry vault.
- A separate disposable localhost app was signed into through Edge. The user
  completed native enrollment; the actual page confirmed "Edge acceptance key"
  enrolled and not used yet. Real sign-in then reached the authenticated account
  and updated Last used after user/device confirmation. Remaining native lifecycle tests and actual companion autofill
  remain separate gates. See PASSKEY_HTTP.md.
- The existing approved public lodash@4.17.20 dependency watch completed in
  actual Edge: 1/1 exact pins assessed, 5/5 advisory records checked, no overlapping
  reports grouped and zero new matches. The schedule stayed off; no new tasks or
  duplicate alert were created. Zero new matches is not a clean vulnerability result.
- Browser testing exposed stale shared finding data after a watch completed.
  Navigation now refreshes the workspace snapshot. The frozen-snapshot regression
  and an actual Edge watch -> findings -> expanded-alias flow passed; the new
  last-seen time was visible without a second page reload.
- Native request waiting could remain busy during the cancellation check. The
  client now races the prompt against explicit abort and a server-lifetime cap,
  discarding late native proofs. The full frontend suite passed 180 tests across
  41 files. A final prompt-status/field-locking follow-up passed 25 focused tests;
  the production build passed. Tests include
  a native promise that ignores abort and then returns a late credential; no
  finish request is sent. In actual Edge the bounded new-build request expired,
  re-enabled sign-in and left zero pending ceremonies with unchanged last-use
  metadata. Explicit Cancel interaction during native UI remains unverified.

## Passkey schema migration and encrypted recovery — 20 October 2026

- New Store instances now apply schema 9 transactionally and reject future,
  gapped or malformed histories. Existing applied markers with missing passkey
  tables fail closed; migration does not silently recreate credential records.
- Backup supports source schemas 8/9, validates layout and manifest agreement,
  upgrades only isolated old restores, clears ceremonies and revokes restored
  active passkeys. Already revoked IDs remain tombstoned.
- Full backend regression: **290 passed**, one existing TestClient deprecation
  warning. The final malformed-metadata guard and its two additional cases were
  rechecked with the **12-test migration suite passing**.
- An actual encrypted owner-data backup restored successfully into a new local
  directory, upgraded to schema 9, preserved compared account/vault/sharing data
  and cleared its bearer grants/challenges. The live owner database remains
  schema 8 with no passkey tables and unchanged compared protected records.
  No restored server or owner migration was launched. See PASSKEY_MIGRATION.md.
- Account routes, sessions/MFA, enrollment/removal UI and real authenticator
  acceptance remain unfinished; this migration is not usable passkey sign-in.

## Passkey credential persistence candidate — 20 October 2026

- Added an explicit transaction-bound credential schema/repository with unique
  credential IDs, scoped lookup, bounded active registrations, revocation
  tombstones, revision/counter checks and atomic session-write compatibility.
  It is not imported by the app or installed in the owner store.
- Focused real-signature protocol/ceremony/credential suite: **74 passed**.
  Full backend regression: **280 passed**, one existing TestClient deprecation
  warning. The JUnit result is retained as ignored runtime evidence.
- Real owner-store read-only check: schema 8, no passkey credential table.
  The existing server listener remained active. No new account authentication
  routes or UI are exposed. See PASSKEY_CREDENTIALS.md for the remaining gates.

## Live backend recovery and truthful connection status — 20 October 2026

- The app backend was confirmed stopped, backed up encrypted, and restarted.
  Actual test-vault decryption succeeded afterward; SQLite integrity was ok,
  schema stayed 8, and the disposable public login remained intact. A live
  hash-prefix breach lookup reported 1,763 occurrences; the vault was relocked.
- The unconditional connected header was replaced with latest-request state
  and a read-only Retry. Actual Edge request blocking, failure, retry and
  activity recovery passed, including the visible 390-pixel mobile warning.
  Network and viewport overrides were restored.
- Full frontend suite: **165 passed / 39 files**. Production dashboard build
  passed. The responsive-only follow-up was rebuilt and visually verified.
- Strict installed-Python audit: 57 packages, zero known advisories after the
  project virtual environment's pip update to 26.2.1. pip check passed. This is
  advisory coverage, not an independent review or production-readiness claim.
- Installed companion still shows an older unversioned assistant. The 0.12.5
  build and 162-test baseline are recorded separately; actual installed autofill
  is not accepted. See browser-backend-recovery-2026-10-20.md.

## Live vault check and companion 0.12.1 diagnostic — 20 October 2026

- Edge reconnected. Saved app sign-in succeeded without extracting password
  values. The disposable Browser acceptance vault rejected a wrong passphrase,
  then unlocked with its established test passphrase and showed zero entries.
  The Personal default vault was not unlocked.
- User explicitly authorized and created a 30-day companion grant. Displayed
  scope verified as Browser acceptance only. Token was hidden; it is not in
  evidence files. Public practice-site demo login saving/autofill was authorized.
- In the installed companion, Save securely opened a visually blank private
  panel twice. No website submission or encrypted save success was observed.
  The installed version and cause remain unverified; this may involve a stale
  installed build or a frame-start/rendering problem. Do not claim root cause
  fixed or current 0.12.1 browser acceptance passed.
- Companion 0.12.1 adds a worker-mediated readiness acknowledgement to frame 0,
  bound to the pending capture ID, with no credential data in that message.
  An eight-second missing acknowledgement removes the blank panel and shows an
  explicit load error. Closing the assistant removes the listener/timer.
- Full frontend suite: **135 passed / 32 files**. Content and popup/frame
  builds passed; archive byte-matches dist and manifest 0.12.1. Dashboard build
  passed with the existing strength-size warning. No Python/schema/session-key
  changes were made in this diagnostic step. User reload/pairing and resumed
  saving, reopening, autofill and scoped revocation remain pending.

## Unwired passkey protocol foundation — 20 October 2026

- 33 protocol tests passed with real signed synthetic authenticator responses;
  no mocked-success verifier. Package integrity/dependency consistency check
  (`pip check`) passed. Added pinned webauthn 3.0.1 without replacing existing
  cryptography 50.0.2. Running service remains unchanged.
- Account routes, session-bound single-use ceremonies, migration/backup handling,
  enrollment UI and hardware/browser acceptance remain unimplemented. The helper
  is not exposed by any route. See PASSKEYS.md for the integration contract and
  explicit zero-counter replay limitation before ceremony persistence is added.

## Staged dependency-watch grouping — 20 October 2026

- Full Python suite: **206 passed**. A subsequent bounded streaming-chunk change
  and stronger cross-watch isolation assertion were rechecked with all **11
  advisory tests passing**. Known Starlette/httpx deprecation warning remains.
- App, Watches and advisory-coverage frontend suites: **10 passed**. Isolated
  production build succeeded under `data/candidate-advisory/frontend`; existing
  strength bundle size warning remains. The running frontend was not replaced.
- A read-only live OSV probe for public npm lodash 4.17.20 assessed one exact
  package and retrieved five valid detail records. All five matches remained
  separate; their CVE aliases were retained. No application database write.
- New grouping behavior is not yet deployed or browser-certified. The current
  running app remains the live-browser-checked 0.12.0 build while private vault
  setup is pending. See ADVISORY_GROUPING.md and the staged verification record
  in `data/candidate-advisory/verification.json` for exact source/build hashes.

## Live Edge check and frontend corrections — 20 October 2026

Browser access succeeded. Started the existing local server after confirming
there was no live Python/listener. A real local port-8110 operation completed;
the public dependency watch rerun completed without duplicate alerts. Selected
desktop/mobile screens rendered. Corrected and rechecked stale companion version
guidance, closed-mobile-sidebar accessibility, expanded state and Escape focus
restoration. Seven focused App/Companions tests passed; production build passed.
The installed companion visibly opened its assistant on an empty public
registration password field. No credentials entered, generated, saved or submitted;
installed extension version was not independently verified. Private vault and
shared acceptance remain pending. Full evidence/limits/build hashes are in
`browser-candidate-0.12.0-browser-check.json`.

## Shared-vault ownership handoff — 20 October 2026

- Full Python suite: **195 passed**, including 28 ownership-protocol cases. They
  check old/new-owner signatures, exact scope/fingerprints, snapshot changes,
  expiration, decline/cancel/replay, wrong workspace/user, CSRF/anonymous access,
  approved former-owner roles, pending other members, malformed grants/root/epoch,
  transaction preservation on failure and browser/action revocation scope.
  Inbox requests are addressed to the accepted successor only. Policy reversal
  cannot revive invalidated approval. Handoff permits later offboarding of a
  non-owner workspace teammate who previously owned a vault. The pending/viewer
  fixture was then strengthened to isolate each predicate and passed its focused
  recheck. Existing backup coverage also proves pending handoffs are cancelled.
- Full frontend suite: **131 passed in 30 files**. A Python-generated canonical
  snapshot vector matches JavaScript. Native WebCrypto tests transfer real fixture
  ciphertext to a new owner/key, preserve account history and staged passwords,
  reject wrong recipients/modified/expired proposals and prove the old data key
  cannot decrypt the next epoch. Component tests require explicit retained roles
  and successor acknowledgement, support decline, exclude viewers, reject stale
  responses and suppress late mutation after locking during proposal/acceptance
  crypto. Dashboard routing opens shared-vault review without auto-accepting.
  A duplicate React sibling key exposed by accepted-vault tests was corrected.
  The new dashboard integration wait initially exceeded the default 1-second
  bound under concurrent workers; bounded integration waits were corrected and
  the full rerun passed. This is not a production performance measurement.
- React production and both companion builds passed. Companion **0.12.0** archive
  matches dist. An encrypted pre-update snapshot was created; active worker and
  browser-lease counts were zero before restart. User/vault/identity/grant/session/
  device/companion records plus workspace/member/entity state matched exact
  pre-update fingerprints afterward. No real vault was unlocked or transferred.
  The live frontend matches dist; setup remains initialized; ownership read,
  proposal and acceptance APIs reject anonymous access with 401.
- Current candidate fingerprints and pending browser cases are recorded in
  browser-candidate-0.12.0.json. Private setup and browser control remain deferred
  per user instructions. This protocol still requires live browser acceptance
  and independent security/cryptographic review. See OWNERSHIP_TRANSFER.md.

## Vault activity timeline — 20 October 2026

- Full Python suite: **167 passed**, including 14 scoped activity/lifecycle cases
  and an additional private-audit corruption backup case. Coverage includes exact
  ownership, cross-workspace personal access, legacy metadata scoping, accepted
  shared grants/current membership, revoked/offboarded access, anonymous/bearer
  rejection, bounded stable keyset pagination with concurrent new events, private
  action associations, real saves/rewraps/default/archive/connection events and
  once-only expiry/interruption/resume processing records. Private ciphertext,
  manifests, account fields and browser credentials are absent from activity output.
- The final frontend suite passed **119 tests in 29 files**. Activity cases verify
  requests only on demand, no private fields in requests, paginated service data,
  refresh, private observations disappearing on lock, stale-response cancellation
  on close/scope switch, revoked-read errors and honest unknown history. After
  changing the page merge to a linear Map, all seven activity cases passed again.
  A further local-pagination case verifies all 56 retained observations can be
  displayed without additional service requests. The final rerun initially hit
  two cold-transform timeouts in App integration tests. Preparing the real lazy
  control-center module in beforeAll separates Vite module preparation from the
  interaction timeout without mocking the UI or changing production behavior;
  the complete 119-test rerun then passed.
- React and both companion production builds passed. Companion archive 0.11.0
  matches dist. A new encrypted pre-update backup and separate unserved restore
  drill preserved vault/identity/grant ciphertext, passed integrity checking and
  produced one recovery event per recovered personal/shared vault. Aggregate
  private evidence is in `data/activity-restore-drill.json`; backup validation now
  covers every stored audit scope, including personal ones.
- Before restarting, active-work count was zero. After restart, fingerprints for
  users, vaults, identities, grants, sessions, companions and devices were identical.
  The live index matches the current build, owner setup remains initialized and
  both personal/shared activity endpoints reject anonymous requests with 401.
  No original vault was decrypted or changed for this verification.
- No browser attempt was made during this phase, respecting the user's request
  to finish independent work first. The latest earlier Edge attempt was disabled.
  Browser acceptance remains unproven for the current build; see
  browser-candidate-0.11.0.json, BROWSER_ACCEPTANCE.md and VAULT_ACTIVITY.md.

## Sharing identity maintenance — 20 October 2026

- Full Python suite: **152 passed**, including 11 new identity-maintenance cases.
  Tests use native ECDSA signatures and exercise proof binding, ciphertext/signature
  alteration, wrong user, unchanged parameters, forbidden extra/plaintext fields,
  stale competing changes, CSRF, anonymous access and viewer self-maintenance.
  Shared key/fingerprint/grant/ciphertext preservation and cross-workspace
  revocation/cancellation scope are checked against actual database records.
- The frontend suite passed **110 tests in 28 files**. One further lifecycle case
  was then added; all eight TeamVaults component cases passed. Crypto tests use an
  independently generated Python identity/vault fixture: rewrapping keeps the
  original shared vault readable, preserves the public fingerprint and rejects
  old/wrong passphrases, context substitution and altered identity records.
  Signed authorization and previous-envelope hash are independently verified.
  UI cases clear form values before work, reject confirmation mismatches, never
  send passphrases, cancel pending crypto after locking, avoid late publication,
  lock on another session's protection change and fetch current protection on a
  later unlock after a late response. One polling-test timer setup and a lazy-panel
  wait bound were corrected; these were test harness issues, not claimed UI fixes.
- React production and both extension builds passed. Companion package **0.10.0**
  matches dist byte-for-byte. Before restarting the local server, an encrypted
  snapshot was created and active-job count verified zero. After restart, exact
  record fingerprints for users, personal/shared vaults, identities, grants,
  sessions and companion/device connections matched. No existing vault was
  decrypted, reset or re-encrypted. The current index is served at port 8110;
  owner setup remains initialized and anonymous private API/mutation access is 401.
- Edge remains unavailable on the latest attempts. No browser acceptance is
  claimed for the new passphrase flow or current package. Historical 0.9.2
  observations are retained separately; see browser-candidate-0.10.0.json.
  Private user entry is deferred. See SHARING_PASSPHRASE.md for the workflow and
  explicit cache/backup/key-compromise boundaries.

## Backup/recovery addition — 20 October 2026

- Full Python suite: **141 passed** (130 existing + 11 backup cases). After
  tightening the snapshot size guard and adding shared-envelope/action-lease
  assertions, all 11 backup tests passed again. Frontend behavior was unchanged.
- Tests exercise committed WAL snapshot consistency, wrong keys, authenticated
  tamper rejection, truncated/header-altered archives, no overwrite, missing or
  mismatched server keys, invalid audit links, unsupported schema, size bounds,
  credential-free CLI output, and sign-in to an isolated recovered application.
- A live local SQLite backup and separate-directory restore drill passed all
  15 aggregate checks. Personal/shared vault ciphertext, sharing identities and
  grants, membership, account authentication records and the server key matched.
  Restored sessions/invites/companion/device grants were absent, schedules paused,
  unfinished work interrupted, SQLite integrity and audit chains valid. Private
  operator evidence: `data/restore-drill-20261019T185049Z.json` (UTC timestamp).
  No original vault was decrypted or live database replaced; the restored copy
  was not served or promoted. Backups/keys remain on the same disk; offsite and
  recurring operations are not configured. See BACKUP_RECOVERY.md for limits.
- A fresh Edge connection attempt returned **Local browser use is disabled in
  Work settings**. The earlier browser observations below remain historical;
  additional browser acceptance is currently unavailable. User-directed private
  vault setup is deferred until independent work is complete.

Browser acceptance procedure: [BROWSER_ACCEPTANCE.md](BROWSER_ACCEPTANCE.md).
Live browser acceptance was partially exercised in Edge for 0.9.2. The candidate
records distinguish historical observations from the unverified current build.

Verified locally on Windows, 19 October 2026:

- Backend baseline from 0.9.0: 130 Python tests passed, including shared-vault identity isolation, pending
  invitations, signed grant tampering, role restrictions, conflict detection,
  offboarding, next-epoch distribution and cancelled in-flight AI responses.
  Shared companion tests cover accepted-grant scope, private identity isolation,
  view/edit roles, live browser policy, per-vault revocation, reinvitation without
  token revival, key rotation and v4-to-v5 schema migration.
  Account-action API tests cover encrypted/private approval scope, browser-bound
  leases, explicit resume after expiry, preparation-before-confirmation, cancelled
  work, shared access removal, bounded bodies and extension-only CORS routes.
  Host-posture tests cover fixed read-only commands, missing/unknown provider
  states, passive Defender mode, extra-field rejection, OS/timestamp checks,
  local/connection consent, old-client capability rejection, scoped leases,
  unique firewall-profile findings and ports-only permission preservation.
- 103 frontend tests passed, including independently generated native Python
  Argon2id/RSA-OAEP/ECDSA/AES-GCM interoperability, wrong-passphrase rejection,
  cross-recipient isolation and inability of old keys to decrypt rotated data.
  Companion session and React component tests use synthetic native-crypto fixtures
  to exercise shared unlock, explicit login filling, current policy restrictions,
  encrypted replacement confirmation, cancellation and scope substitution checks.
  Account-operator tests exercise approval decryption, durable encrypted staging,
  popup recovery without regenerating secrets, exact-origin preparation, unsupported
  forms and user-confirmed promotion/discard. Form tests check no submit/click,
  account mismatch, hidden/ambiguous fields and website password constraints.
  Vault lifecycle tests reject late unlock/save responses after locking.
  Host-posture UI tests retain permission-denied/passive states, dispatch to the
  selected remote agent and exclude ports-only connections from host checks.
- Dependency-watch tests cover exact-pin/consent validation, provider batching,
  pagination and malformed data, no severity invention, transport failures,
  serialized schedule claims, stale-edit cancellation, revision conflicts,
  explicit restart recovery, expired leases, optional task dispatch, repeated
  advisory suppression, partial coverage retention, restored-coverage alerts,
  role restrictions and independent member read states. React tests cover
  default-off permissions, explicit resumption, revisioned editing and viewer
  acknowledgements. The final backend change was rechecked with all 12 watch tests.
- A live public OSV probe for npm lodash@4.17.20 assessed one pin and returned
  five advisory identifiers with no request error. No user's manifest or secrets
  were sent. Overlapping IDs may represent the same issue.
- Account-review tests cover selected preview/approval, stale-plan invalidation,
  viewer restrictions, failed persistence, unknown/due/future review dates,
  exact-login duplicates, atomic archive/restore, staged-password protection,
  bounded encrypted history and rejection of injected fields/timestamps. Personal
  ciphertext round-trips preserve history without exposing it. Native shared
  crypto/companion tests prove archival is persisted, direct fill is denied,
  and a fresh capture cannot silently revive the archive. Direct archived TOTP
  reveals are denied. The prior proposal-discard test now also verifies its
  recorded encrypted events while proving the original login is unchanged.
- Six additional vault-lifecycle tests reproduced late encrypted writes after
  locking during master rewrap, legacy upgrade and destination encryption, then
  verified the fix. Backup restoration cannot enter a newer unlock session;
  successful master changes and destination-scoped copies still work. Plaintext
  form values are cleared before asynchronous work and are absent from API bodies.
  Generation/material checks occur before mutation dispatch and UI publication.
  Locking cannot undo a request already accepted by the server; a subsequent
  unlock fetches current state rather than assuming a timed-out update failed.
- React production build and both companion builds succeeded. Companion archive
  manifest is 0.9.2 and contains no local connection/credential configuration or
  synthetic private-key test vectors.
- Python dependency check passed. Git whitespace check found no errors.
- Local dashboard and status returned HTTP 200. Anonymous requests for sharing
  identity and shared vaults returned HTTP 401.
- SQLite snapshot created before migration 8. Existing personal/shared vault
  ciphertext, epochs/revisions and encrypted sharing identity fingerprints were
  identical after restart. No private vault was
  unlocked or decrypted during this verification. The watch-upgrade snapshot is
  `data/before-dependency-watches-upgrade-20261019.db`; preservation fingerprints
  are in `data/dependency-watches-upgrade-check.json`. Personal/shared ciphertext,
  identities, grants and companion/device connections matched after restart.
  Private watch/notification endpoints returned HTTP 401 anonymously. No watches
  or recurring provider requests were created on the owner's behalf.
- The final native Windows probe ran read-only without elevation: firewall domain,
  private and public profile status plus Defender status were enabled; the
  system-drive BitLocker status query returned permission denied and remained
  unassessed. No settings or recovery keys were accessed. These observations do
  not establish overall protection, patch currency or absence of compromise.

Browser inspection was initially blocked: the browser tool returned **Local browser use
is disabled in Work settings**. Reinstalling the browser extension did not alter
that session-level denial. A later user-requested manual-control check opened
Chrome, but Computer Use stopped because it could not determine the current
browser URL with enough confidence to enforce policy. That stop was obeyed;
no browser acceptance case was completed in that attempt and no policy bypass was attempted.
The later Edge connection succeeded through the supported browser tool. Desktop
and 390×844 responsive views were inspected. The coverage view had document and
client width 375 CSS pixels (the scrollbar accounts for the viewport difference),
with no horizontal overflow; mobile menu navigation worked. Keyboard-only,
all-page and all-browser coverage remain unproven.

A real browser-triggered local TCP check assessed 127.0.0.1 ports 22, 443 and
8110. Port 8110 was open, while 22/443 were unassessed. A PORT001 finding with
unknown severity and low confidence was recorded; the operation remained
partial rather than claiming complete coverage. Browser inspection found the
missing per-port display and stale 0.3 footer. Version 0.9.2 adds the typed
coverage table and reads the footer version from package metadata. Two new
tests retain unassessed/unsupported states and do not invent absent coverage.
Watch control styling and an integer-zero artifact on the locked vault page
were also corrected and rechecked visually.

A one-off browser watch for the public npm lodash@4.17.20 fixture assessed 1/1
pins and recorded five advisory IDs, an in-app alert and a separate user read
acknowledgement. Recurrence and task creation stayed off. No real user manifest
or vault secret was submitted. The clearly labelled public-fixture watch,
its asset/evidence, and the real local-port finding remain in the workspace.
Vault acceptance is waiting for user-created private master/passphrase entry
in the prepared separate Browser acceptance vault form; the existing Personal
vault was not unlocked or reset. Screenshots are under
`data/browser-acceptance-0.9.2/`, with case scope in the candidate JSON.

The external registration page was subsequently exercised without registration
submission or saving. A real focus event opened the SentinelOps password dialog;
the disposable weak test input produced “Very guessable.” Generator activation
filled both masked fields, reported “Harder to guess,” and left the URL on
`/register`. Both test values were cleared afterward. The closed shadow DOM
does not appear in the ordinary DOM snapshot; screenshots verified the actual
dialog. Password-value redaction prevents independent length/equality assertions
through read-only evaluation, so masked-value comparisons were not accepted as
proof. Actual installed companion version, save/pairing and all-site compatibility
remain unverified. An initial AX-index interaction on the ad-supported practice
site redirected to an advertisement; navigation returned immediately, and a
fresh semantic label locator correctly focused the password field. No account
was created or modified and no real user's secret was entered.

Installed SentinelOps companion copies need a user-triggered reload to 0.9.2;
this is separate from the browser-access extension used by Codex.
The 0.9 account-review restart needed no new schema migration. Snapshot
`data/before-account-review-upgrade-20261019.db` and fingerprints in
`data/account-review-upgrade-check.json` confirm existing personal/shared vaults,
sharing identities/grants and browser/device connections were unchanged. The
served React index and main bundle matched the new build byte-for-byte; private
vault/watch/notification/sharing APIs rejected anonymous access. No real owner's
entries were unlocked, archived or otherwise edited during verification.
The Windows posture feature uses the Python device operator; a remote client
also needs a newly opted-in connection and agent 0.7+ with `--allow-posture`.

For 0.9.1, the previous local app process was confirmed absent and port 8110
refused connections before starting it again. Snapshot
`data/before-vault-lifecycle-fix-20261019.db` and fingerprints in
`data/vault-lifecycle-fix-check.json` confirm private vault/identity/grant and
connection records were preserved. Schema stays at 8. The served React index
and main bundle match the new build; archive files match companion dist.
`browser-candidate-0.9.1.json` supersedes the unexecuted 0.9.0 candidate record.
Backend behavior was unchanged by this patch apart from product version metadata;
the 0.9.1 changes and six new regression cases are in the React vault lifecycle.

Known non-failing diagnostics: password-estimator bundle size warning and Starlette's
httpx TestClient deprecation warning. These do not establish production readiness.

Tests establish the stated functional boundaries; they are not independent
cryptographic review, browser/site compatibility certification, a deployment
restore drill, or completion of the remaining product plan.

Protocol references: [Web Cryptography API](https://www.w3.org/TR/webcrypto/),
[Argon2 RFC 9106](https://www.rfc-editor.org/rfc/rfc9106.html). The current KDF
uses one lane; it is not claimed to match RFC 9106's four-lane recommended profile.
