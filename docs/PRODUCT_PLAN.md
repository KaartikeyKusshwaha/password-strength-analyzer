# SentinelOps product direction and completion ledger

The first audience is **small teams and agencies managing client accounts**.
The product is a connected security control center. Users choose an outcome;
scoped browser/device operators execute it and record evidence. A chatbot,
fictional workspace, manual asset form or uploaded report is not the primary
workflow. Developer checks are available as connected secondary workflows.

## Implemented in the current development branch

| Capability | Evidence / boundary |
| --- | --- |
| Central control center | `ControlCenter.jsx`, `/api/operations`; target -> asset -> check -> findings -> optional authorized AI task dispatch. |
| Real device checks | Local operator and paired polling device client, private-IP allowlists, 64-port bound, job leases, cancel/revoke. Reported observations are not proven vulnerabilities. |
| Windows host posture | Explicit local/connection consent, protocol-v2 capability heartbeat, fixed read-only firewall/Defender/BitLocker status tools, bounded typed reports, per-check permission/unsupported states, findings and dashboard coverage table. No recovery keys, arbitrary commands, OS changes or patch assessment. |
| In-page password assistant | Extension `content.js`, dedicated private window `vault-frame.jsx`; recognized signup/change forms get local suggestions, generation and explicit encrypted saving. One disposable login saved/synchronized/reopened in actual Edge. The 0.12.7 dynamic-form checks and field-retention receipts still need installed-browser acceptance. |
| Multiple personal vaults | Per-vault ciphertext, revisions, names/purposes/colors, lock settings, archive, browser access/save/fill switches and optional exact-origin scope. |
| Scoped browser connections | Bound to a vault; extension can remember multiple connections and switch, locking the old one. Individual revocation preserves other connections and interrupts only its leased work with explicit resume required. Private contact/version diagnostics compare with the downloadable package; they do not certify installation or fill success. |
| Duplicate sites and cross-vault copies | Independent entries allowed; destination unlocked and re-encrypted locally, original preserved. |
| Shared workspace vaults (preview) | Argon2id-encrypted sharing identities, RSA-OAEP recipient key wraps, signed grants, trusted-channel fingerprint verification, invitation acceptance, owner/admin/editor/viewer access, conflict checks and next-epoch key rotation. Accepted vaults connect to the popup and in-page save panel with current role/policy checks. |
| Workspace offboarding | Owner reauthentication/MFA removes membership, sessions, device grants and shared keys; cancels active work and requires affected vault key rotation. Personal vaults remain accessible. Shared-vault owners must transfer their vaults to an accepted teammate before offboarding; workspace ownership is separate. |
| Local password review | Weakness and reuse checks after unlocking; no standalone password-lab navigation. |
| Account change launch | Exact-origin `/.well-known/change-password` discovery link; support varies. No universal or verified autonomous rotation claim. |
| Private account-change queue | Explicit encrypted approval for up to 20 logins, browser-specific leases, staged recoverable passwords, exact-origin form preparation and separate user-confirmed outcomes. No submit or external success verification. |
| Encrypted TOTP | Local code generation; actual provider enrollment still required. |
| Agent workflow | One AI planner + deterministic evidence/reference/dispatch/progress workers. Per-run write scope and independent review required. |
| Source/dependency/email/website checks | Bounded checks with explicit partial/failure states. OSV uses exact pins only. |
| App authentication and team roles | Session/CSRF controls, scrypt, TOTP replay controls, workspace isolation, independent task reviewer. |
| Audit and envelope migration | Linked audit records and legacy single-vault migration preserving ciphertext/revisions, backed up before updating the local owner store. Not independent signing or production Postgres. |

## Foundation: required before private team pilots with valuable credentials

- [x] Versioned Argon2id client KDF/envelope with bounded costs and tests for
  v1 compatibility, context binding, tampering and nonextractable keys. External
  review remains a separate release gate.
- [x] Random vault data keys wrapped by unlock keys. Master changes preserve
  encrypted item data and revoke browser tokens. Review the hierarchy before sharing.
- [x] Explicit no-recovery decision for personal master and sharing passphrases.
  Recovery-key enrollment and revocation remain future work. A sign-in password
  reset cannot decrypt either encrypted store.
- [x] Offline encrypted SQLite backups with consistent WAL snapshots, separate
  backup-key files and restore into a new directory. Recovery revokes active
  connections, interrupts queued work and pauses schedules; see BACKUP_RECOVERY.md.
  This does not configure offsite copies or unattended recurring backups.
- [ ] Postgres adapter with proper migrations and production deployment tests.
  SQLite remains the current local development store.
- [ ] Threat-model review, independent crypto/client audit, security reporting
  contact, signed releases and bug-bounty process.

## Adoption and launch workflows

- [x] Local CSV login import for Chrome, Bitwarden, 1Password and LastPass,
  preview, skipped-record reasons and ciphertext-only storage. Other item types,
  notes/custom fields and vendor-specific exports need additional coverage.
- [ ] Encrypted export exists; add explicit approved plaintext export only if
  needed for interoperability and explain the resulting file's sensitivity.
- [x] Optional HIBP hash-prefix password checks integrated in the account view.
  The existing local library implements padded k-anonymity lookups; there is
  not yet recurring breach monitoring or verified-email account monitoring.
- [ ] Chrome/Edge/Firefox store releases with reproducible packages and
  browser end-to-end tests; mobile Android/iOS autofill apps and integrations.
- [ ] Passkey account sign-in and a separately designed vault-unlock mechanism.
  Ordinary WebAuthn authentication does not automatically provide a vault key.
  A pinned-library protocol, isolated single-use ceremony store and transactional
  credential persistence have 74 tests.
  Migration/backup integration and an isolated actual-data restore drill now
  pass; the backed-up local store now runs schema 9. Account/session/MFA routes
  and enrollment/removal UI are implemented. Real signed HTTP proofs and UI
  tests pass. Native Edge enrollment and sign-in passed in a separate disposable
  localhost app; remaining lifecycle acceptance is pending. The current
  127.0.0.1 origin is explicitly unsupported. Vault unlocking is still a separate
  unimplemented passkey protocol. See PASSKEYS.md; keep this release gate open.
- [x] Local strength/reuse and account-review summary with explicit assessment
  limits, unknown history and no invented overall security score. Archived
  entries are excluded from active review and companion operations.

## Team/agency differentiators

- [x] Development implementation of encrypted sharing roles, invite acceptance,
  per-member key distribution, audit and owner-authorized workspace offboarding.
  Independently generated Python/WebCrypto interoperability tests cover the
  protocol; this is not an independent audit. See threat-model limitations.
- [x] Shared-vault browser connections scoped to one accepted grant, user and
  workspace; shared local unlock/session logic in popup and private save frame.
  Read-only fill, editable encrypted saves, exact-origin policy and replacement
  confirmation have API, crypto and component tests. Real browser checks pending.
- [x] Sharing identity passphrase change: local re-encryption of existing private
  keys, signed authorization bound to the prior envelope, conflict rejection,
  shared companion revocation and unfinished shared-action cancellation across
  workspaces. Fingerprints, grant wraps and vault ciphertext remain unchanged.
  Existing unlocked clients/old backup copies cannot be erased; keys do not rotate.
- [x] Shared-vault ownership handoff: signed expiring owner proposal, explicit
  successor acceptance, snapshot/replay protections, new key epoch/root/grants,
  approved former-owner access, preserved other roles/acceptance states and
  revocation/cancellation of this vault's connections/plans. Addressed requests
  appear on the central dashboard. Independent protocol review remains required.
- [ ] Identity recovery, signed payload authorship and rollback anchors.
  Current view/edit permissions are enforced by the service, not by encryption.
- [ ] Domain adapters for supported account changes, bulk proposals, explicit
  approval, per-site success verification and accurate unsupported states.
- [x] Generic preparation workflow: encrypted bulk approval, deterministic local
  operator, staged-password recovery, no-submit field preparation and truthful
  queued/prepared/confirmed/interrupted states. Per-site adapters and independent
  confirmation are still unimplemented; the generic path is not a fallback AI.
- [ ] Account discovery only from explicit browser/account sources the user
  authorizes. No covert browsing-history or inbox collection.
- [x] Account-review operator: exact-login duplicate observations, configurable
  review-due intervals, unknown history, selected plan preview/approval,
  encrypted archival/restoration and pending-password recovery protection.
  No external account closure, automatic expiry/deletion or inactivity claim.
- [x] Windows firewall profiles, Defender and system-drive BitLocker protection
  status through fixed read-only tools, separate connection/local opt-in, strict
  report validation and honest unsupported/permission states. A live local probe
  verified four enabled states and one permission-denied disk check.
- [ ] OS update/patch coverage, full disk/other antivirus assessment and macOS/Linux
  posture collectors. Current observations do not establish overall protection.
- [x] Registered exact PyPI/npm dependency watches, opt-in schedules, durable
  in-app alerts and optional assigned remediation tasks. Revision-bound jobs,
  restart interruption, per-member reads and explicit partial coverage tested.
- [x] Development implementation of bounded OSV alias lookup/grouping for
  dependency watches, separate detail-coverage reporting and stable finding/task
  identity within the exact package and scan scope. Tested with automated cases
  and a read-only live API probe. Live Edge reran the approved public-package
  watch and displayed 1/1 assessed pins, 5/5 advisory details, no overlapping
  reports grouped and zero new matches. Historical
  overlapping work is retained; partial detail coverage can still overlap.
- [x] Sourced CVSS base severity for manual dependency checks and watches, with
  record/version/vector provenance, package scope and explicit partial/unknown
  coverage. Ratings prioritize advisory matches; they do not prove local
  exploitability. See ADVISORY_SEVERITY.md for bounds and remaining acceptance.
- [ ] Installed-software discovery, dependency graph discovery and externally
  delivered notifications.
- [x] Encrypted per-account history for local saves, proposals, user-confirmed
  changes, reviews and archive/restore actions. Latest eight events, no previous
  password values and no claim of independent or tamper-evident verification.
- [x] Per-vault activity timeline: scoped paginated service records, current
  accepted shared-grant checks, recorded save/access/action lifecycle events,
  and separately labelled encrypted account observations after unlock. Earlier
  unrecorded events, local fills/reveals and trimmed/deleted account history
  cannot be reconstructed. This filtered log is not independent audit proof.
- [ ] Recovery and emergency-access protocol.

## Later enterprise work

SSO/SCIM, separate admin console, policy enforcement, compliance exports and
developer CLI/API. Each needs its own authorization model, tests and release
gate; user-facing capability labels must follow actual verified behavior.

## References used for design

- [1Password vault organization and sharing](https://support.1password.com/create-share-vaults/)
- [1Password Travel Mode and its boundaries](https://support.1password.com/travel-mode/)
- [Bitwarden organizations and collections](https://bitwarden.com/help/getting-started-organizations/)
- [NIST SP 800-63B-4 password guidance](https://pages.nist.gov/800-63-4/sp800-63b.html)
- [W3C change-password discovery draft](https://www.w3.org/TR/change-password-url/)

These references inform product requirements. They do not certify SentinelOps or
imply identical cryptography, permissions, recovery or deployment guarantees.
