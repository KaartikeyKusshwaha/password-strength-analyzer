# SentinelOps threat model (development build)

Status: implementation review document, **not an independent security audit**.

## Dependency watch boundary (0.8)

Watches store exact package names/versions as workspace metadata. Registration
requires explicit consent to send those names/versions to the fixed OSV batch
endpoint. The original manifest is not retained. No source code, login, vault
content or access token is sent. Provider results are bounded, IDs validated,
and redirects disabled. Batch responses supply advisory IDs; no severity or
exploitability is invented. Pagination, unsupported data, limits and network
failures remain incomplete coverage. Advisory IDs can refer to overlapping issues.

One separate worker serializes checks across this single-process installation.
Persisted revision/lease/permission checks precede execution and publication.
Changing, pausing, archiving or offboarding cancels pending results. Interrupted
active jobs disable their schedule until explicit resumption. Enabled idle
schedules become eligible once when overdue; missed intervals are not replayed.
A scheduler error is exposed on the watch page. This is not a distributed
scheduler or a guarantee of delivery while the computer is off.

Contributor-created tasks require separate approval at watch configuration and
retain normal evidence/review requirements. Alerts are workspace-scoped metadata,
with separate per-user read states. Retention is 500 alerts per workspace and
100 runs per watch; the UI shows the latest 100 alerts/runs. No external email or
messaging is enabled. Archiving retains evidence and does not resolve findings.
First product audience: small teams and agencies handling multiple client
accounts, with developers and small startups as an adjacent audience.

## Assets and trust boundaries

### Account lifecycle metadata (0.9)

Optional version-1 entry history lives within the existing encrypted personal
or shared data payload; it is never sent as a separate API field, notification
or model input. The client validates fixed timestamp fields, eight bounded
kind/time events and no arbitrary history properties. Original password values,
actor emails and browsing history are not recorded there. Old entries retain
unknown dates. A saved credential is not proof it works at a website; only a
user's explicit confirmation records a reported accepted change. Account review
dates are user reports, not account activity or an automatic rotation policy.

The local review operator snapshots an exact selection for a two-minute plan,
requires confirmation, and relies on the existing encrypted revision check for
publication. A changed vault invalidates the plan. Archiving refuses entries
with a pending replacement; it never deletes the old or staged secret. Restore
requires separate selection and approval. Shared viewers have no mutation
controls and server roles remain authoritative for encrypted writes.

Updated companion clients exclude archived logins/TOTP from UI and direct
fill/code/action calls. An archived login is not silently overwritten by a
new capture; a new active entry is independent. All installed companion copies
must be reloaded to 0.9.0 for this behavior. Old clients, malicious clients,
previous exports and cached credentials cannot be constrained or wiped by an
encrypted metadata flag. Archiving does not revoke provider sessions or close
accounts, and archived entries retain their encrypted-storage quota.

History is client-reported, editable by a holder of the data key, truncated to
eight events, and included in encrypted backups. It is not a signed audit log,
proof of authorship, rollback protection or a complete per-vault timeline.

### Pending local operations (0.9.1)

Personal vault master rewrap, legacy upgrade, cross-vault copy and backup restore
are bound to the unlock generation and current key-material handle. Locking,
unmounting or starting another unlock invalidates pending local work. Checks
after asynchronous reads/derivation/encryption prevent a cancelled operation
from submitting a later encrypted write or publishing a stale UI result. Form
values are cleared before the operation begins. WebCrypto/KDF work may finish
in memory and immutable JavaScript strings cannot be guaranteed zeroized.

The server's revision check remains authoritative. A request dispatched before
locking may already have committed and cannot be rolled back by a client-side
generation check. Errors do not assert that a protection update failed to commit;
the user must unlock again to fetch current encrypted state. Tests cover both
cancelled operations and successful protection/copy paths with disposable data.

- Vault contents: login passwords and TOTP seeds. New v2 vaults use a random
  AES-256 data key. Argon2id (64 MiB, 3 passes, one lane) derives an unlock key
  that wraps the data key with AES-256-GCM. Distinct AAD binds key wrapping and
  item encryption to the vault ID. KDF parameters and envelope lengths are
  bounded and validated by both client and server. Data keys are nonextractable
  after import; temporary raw key arrays are zeroed on a best-effort basis.
- Legacy v1 envelopes remain readable with PBKDF2-SHA256 (600,000 iterations).
  Upgrading is explicit and re-encrypts existing entries locally. v2 master
  changes re-wrap the data key without changing encrypted item data. All browser
  tokens for that vault are revoked; previous backups and already-unwrapped
  keys are not retroactively erased. The server rejects context substitution
  and v2-to-v1 downgrade writes.
- Account credentials: the app sign-in password is sent to the authenticated app
  server and stored as a scrypt verifier. It is separate from vault unlock.
  This is not a claim that all account authentication is zero knowledge.
- Vault master passphrases, unwrapped keys, credentials and TOTP values remain
  outside the LLM. Server APIs receive ciphertext and authenticated metadata.
- Vault names, purpose, color, timers, browser policy, timestamps, and restricted
  website origins are metadata stored in plaintext on the backend. Do not put
  sensitive passwords, recovery keys or client secrets in those fields.
- Browser connection tokens are long random bearer credentials, stored hashed
  on the server and persisted in extension-local storage. Each token is bound
  to one user and one vault. A default-vault change cannot broaden its scope.
- Device tokens authorize a narrow private-target TCP-check protocol, not vault
  access, a shell, arbitrary code, OS configuration changes or broad scanning.
- Team findings, assets, tasks and audit events are workspace-scoped. Private
  vault envelopes are not included in team reports or model inputs.

## Adversaries and current controls

### Malicious website or lookalike domain

Password assistance runs in an isolated content script. A closed shadow root
provides UI containment, **not a security guarantee against the embedding page**.
The master-passphrase form and vault cryptography run in an extension-origin
frame. Same-origin policy keeps its DOM and keys out of the website.

Captures require a real user click in content-script UI, exact current origin,
top-level sender frame, bounded values and a tab-bound random request ID. They
live only in the service worker's memory for up to three minutes. Reloads or
worker termination may discard them. Nothing captures a password on submission.

Fill actions require one visible supported login field on the exact HTTPS
origin and a same-origin form destination. No wildcard subdomains, automatic
submission, cross-origin frames or TOTP injection. The current vault policy is
checked before filling. Master-key handling is not delegated to a model.

An embedding page can remove, cover or imitate UI. Users must recognize the
installed extension and its unlock flow. Independent review must include
clickjacking, hostile-page UI spoofing and Content Security Policy compatibility.

### Stolen database or account session

Vault ciphertext alone does not reveal credentials, but enables offline
master-passphrase guessing. A weak master passphrase remains a risk. The
Argon2id format and key hierarchy require independent review before team sharing.
Authenticated sessions expose vault metadata and ciphertext; sign-in MFA,
HttpOnly/SameSite cookies, CSRF and origin checks limit session abuse.

The SQLite file and the app MFA-encryption key must be protected and backed up.
Database access can rewrite audit events and metadata. Hash-linked audit events
detect some edits relative to an externally retained head; they do not provide
independent signatures or protection from a malicious administrator.

### Compromised server or extension

A malicious app server can serve modified frontend code that steals future
master-passphrase input. An extension or update compromise can defeat client
encryption. End-to-end encryption alone does not protect against a malicious
client update. Release signing, dependency review, CSP, reproducible builds,
store review and an independently audited client are required before launch.

### Malicious model output or prompt injection

Provider input contains only allowlisted finding identifiers, fixed rule
guidance, severity and confidence. Raw submissions and vault material are not
sent. Model output is structured, bounded and must cover supplied IDs exactly.
Only fixed deterministic tools create tasks or investigation briefs under
per-run authorization. They recheck current evidence and contributor access.
Instructions are not executed as commands or treated as authorization.

### Unauthorized device scans and forged reports

Local checks require an authenticated contributor and explicit target authority.
Hosted installations cannot substitute the hosting server for the user's PC.
Paired devices have explicit target allowlists, expiry, scoped tokens, job leases,
exact target/port result matching and revocation. Clients independently reject
scope expansion, metadata addresses, public addresses and redirects that could
forward bearer tokens. At most 64 selected TCP ports on one private IP are
accepted; there is no exploit execution or arbitrary shell.

A compromised paired device can fabricate observations. Reports are not remote
attestation and open ports are not proof of vulnerabilities or Internet exposure.
Network/firewall permission errors are unassessed, never silently clean.

### Read-only Windows host posture

Host posture is a separate operation on the selected operator computer only;
loopback targets identify that scope. LAN targets are rejected for host checks.
Hosted installations still require a paired device and never assess the cloud
server as if it were the user's computer. Existing device tokens default to
ports-only. Host collection needs both an opted-in token and `--allow-posture`
on the local client. Protocol-v2 heartbeats report the local capability; an old
or unconsented agent fails the operation without dispatching host tools.

The standalone agent uses only three fixed PowerShell status scripts on Windows,
with an absolute system executable, `-NoProfile`, `-NonInteractive`, `shell=False`,
hidden windows and a 15-second timeout per tool. Job text, target addresses and
provider/model output never enter these scripts or executable arguments. The
scripts query Windows firewall profiles, Defender status, and the system-drive
BitLocker `GetProtectionStatus` CIM method; they do not query key protectors,
recovery passwords, processes, software inventories or arbitrary files. They do
not elevate, alter configuration or run remotely against a LAN device.

Only raw command outputs up to 12 KB are accepted after capture and are discarded
after normalization. The timeout and size check do not sandbox a replaced local
module; a compromised collector can consume resources or fabricate output. The server
accepts exactly five known checks with bounded state/reason enums and a recent
timestamp; extra keys, duplicate/missing checks, arbitrary error text and
platform-inconsistent healthy states are rejected. Non-Windows reports are
explicitly unsupported. Missing modules, timeouts and denied privileges remain
unassessed; their absence never implies protection. A passive Defender mode is
reported separately because another antivirus may be active. Firewall status is
profile configuration, not proof of an active protection path. BitLocker status
covers only protection on the system drive, not every volume, recovery readiness
or the entire device's security. No installed-update/patch checks are implemented.

These remain self-reports. A compromised device or replaced local PowerShell
module can fabricate observations. The server checks the current scoped lease,
permission, requested operation kind and empty port list before accepting host
results. Port jobs cannot smuggle posture output. Disabled protection states
create separately scoped review findings; unassessed checks make the run partial.
Allowlisted rule guidance may enter existing optional AI triage, but raw command
output and device-specific fields do not enter model input.

## Multi-vault guarantees and limits

- Credential identity is scoped to a vault. Two vaults can contain the same
  website and username with the same or different passwords.
- Switching vaults unmounts the old unlock view and drops key references.
- Copying requires unlocking the destination and re-encrypting its complete
  collection with its own key. Source data is retained; copies are independent.
- Lock timers and hidden-tab locking clear local references; JavaScript cannot
  guarantee physical memory zeroization.
- Disabling browser access or archiving revokes that vault's tokens. Existing
  unlocked windows may retain local plaintext until closed or timed out.
- Archive is reversible and preserves ciphertext. It is not travel-mode secure
  erasure, emergency recovery, or removal from another device's backups.
- Browser website restrictions are enforced by the extension, not by decrypting
  opaque envelopes on the server. A compromised client can bypass client policy.
- Personal and shared workspace vaults use different key envelopes. The browser
  companion supports both with separately scoped tokens and local unlock paths.
  Emergency access and master-key recovery are not implemented.

## Shared vault protocol preview

Each user creates one sharing identity locally: RSA-OAEP 3072/SHA256 for key
distribution and ECDSA P-256/SHA256 for grant signatures. Private PKCS8 keys are
encrypted together using AES-256-GCM and an Argon2id-derived key (fixed 64 MiB,
three passes, one lane). User ID is bound in identity AAD. The server stores
public keys, their SHA256 canonical-JSON fingerprint and opaque encrypted private
keys. Private keys are re-imported as nonextractable after creation/unlock.
Identity replacement and recovery are not implemented. Passphrase changes
re-encrypt the same private-key bundle with a new Argon2id salt/AES-GCM IV.
The client verifies the old bundle matches the unchanged public keys before
encrypting it. An existing-key ECDSA signature binds the action version, user,
fingerprint, previous-envelope SHA256 and complete new encrypted envelope.
The server checks proof and previous-envelope equality in one write transaction;
it cannot check the passphrase's strength or decrypt the replacement bundle.
A faulty or malicious authorized client can still encrypt the wrong contents.

Passphrase change revokes that user's shared companion tokens and cancels
unfinished shared credential actions across all workspaces, recording an event
in each current workspace. Personal tokens, other users, grant wraps, public
fingerprints and vault epochs/ciphertext remain unchanged. The initiating UI
locks after commit; other unlocked dashboard identities poll every eight seconds
when idle and lock when their encrypted record changes. A compromised client can
ignore this. Previously decrypted keys, credentials, cached encrypted identities
and old backups cannot be recalled. This is wrapper maintenance, not key rotation
after key compromise or master-passphrase recovery. Old snapshots require their
old passphrase; external rollback protection is not implemented.

Each shared vault has a random AES-256 data key and a key epoch. The key is
wrapped separately for every recipient using RSA-OAEP with vault ID, epoch and
recipient in its label. AES-GCM data AAD binds the vault and epoch. Signed grants
bind sender/recipient identity fingerprints, role, vault, epoch and wrapped key.
The owner signs a root manifest and can delegate admin access. Admins can issue
editor/viewer grants with an owner-signed admin proof; further delegation is
rejected. Fingerprints must be compared through an independent trusted channel
before accepting an unfamiliar owner or sending access to a teammate. They are
not authenticated merely by displaying the server's directory. Current UI trust
is session-local and asks again after switching/locking; persistent pinning and
key transparency remain future work.

Invitations are pending until accepted. The server withholds data ciphertext
until acceptance, but the invitation already contains a wrapped key; acceptance
is a service authorization boundary, not a separate cryptographic barrier.
Owner/admin/editor/viewer permissions are enforced by the service. Readers have
the symmetric data key and can retain plaintext or manufacture ciphertext if the
service is compromised. There is no signed payload authorship protocol yet.

Revocation removes the recipient grant and blocks new saves/invitations until
the owner decrypts locally, generates a fresh data key, re-encrypts contents and
wraps it for exactly the remaining members. Signatures and existing recipient
fingerprints are checked before rotation. Transactional revisions/epochs reject
stale writes and incorrect member sets. A removed member's old key cannot read
new ciphertext, but does not erase old passwords or backups. Rotate known website
passwords separately. No independently anchored rollback protection exists; a
malicious server can replay an older valid snapshot to a fresh client.

Workspace offboarding requires owner password and MFA when enabled. It removes
workspace sessions, membership, paired devices and shared grants, cancels active
jobs, and marks affected shared vaults for rotation. In-flight model responses
cannot revive cancelled jobs. Personal vaults and other workspace memberships
remain with the account. Removing a shared-vault owner is blocked to avoid
stranding the encryption keys until the owner completes the separate two-party
vault handoff. Workspace ownership is unchanged by that handoff.
Unlocked clients poll every eight seconds and lock when the tab is hidden or
after three minutes of inactivity. Revocation cannot remotely wipe cached data.

Ownership handoff uses an old-owner signature over an expiring proposal, identity
fingerprints, approved former-owner role and a complete vault-state digest. The
accepted successor signs the new manifest, exact member grants and next-epoch
ciphertext. Content/access/policy changes durably invalidate pending approvals,
so reverting a policy cannot revive one. Acceptance rotates the client data key,
revokes that vault's browser tokens and cancels unfinished plans, preserving
encrypted staged values. Backups and identity rewraps cancel pending handoffs.
The service cannot verify plaintext preservation or client randomness. Remaining
members verify the new root through a trusted channel. Old decrypted copies and
backups cannot be erased, and workspace ownership is separate. The protocol is a
development preview requiring independent review; see OWNERSHIP_TRANSFER.md.

The protocol has functional, tampering, authorization, rotation and independent
Python/WebCrypto interoperability tests. It has not received an independent
cryptographic audit and is not approved for valuable production credentials.

### Shared vault browser connections

A shared companion bearer is bound to one vault, user and workspace. It retrieves
only that accepted grant and data ciphertext, the owner's public verification
keys, and the user's encrypted private sharing identity. The extra identity
ciphertext exposure is an explicit part of the pairing scope; it permits offline
guessing if the bearer leaks. It does not grant access to the identity directory,
other vaults, invitations, workspace records or plaintext. Personal tokens remain
personal during schema migration and cannot be broadened with query parameters.

Every broker request checks current workspace membership, accepted grant and
browser-enabled policy. Saves additionally check the member's current workspace
and vault role, save permission, key epoch, revision and rotation-required flag.
Grant revocation, workspace offboarding or disabling shared browser access deletes
the relevant bearer records. Re-enabling access or inviting the user again does
not revive deleted tokens. Remaining members can unlock a newly rotated key
using the fresh signed grant returned for their existing scoped connection.

The popup and private frame use one SaveSession implementation. Sharing private
keys are unlocked only inside the extension, never persisted in storage or sent
to the website/LLM. Non-owner unlock requires an independently checked owner
fingerprint; server-provided ownership metadata cannot bypass cryptographic
verification. A cached fingerprint from the server is a candidate, not a trust
anchor. Pairing stores only connection metadata and bearer tokens, not private
identity ciphertext or unlock keys.

Live policy and revision checks precede login fills, code reveals and saves;
duplicate-account updates require confirmation. Exact-origin restrictions apply
to login saving/filling. TOTP entries have no origin, so the browser-fill switch
controls their reveal but origin lists cannot constrain which service they are
used for. Closing/locking/switching invalidates in-flight unlocks and aborts
requests; a request already committed by the server cannot be rolled back by
closing a window. Pending writes use revision checks and are never blindly
retried. Popup polling detects later access/content changes within eight seconds;
cached plaintext cannot be remotely erased. Compatibility with actual external
websites, CSP and browser extension lifecycles still needs live verification.

## Account-change workflow

### Account-change approvals and staged secrets

Account-action manifests use AES-GCM under the current vault data key, with
distinct AAD binding the action ID, vault ID, actor and personal/shared scope.
They contain exact origins and entry IDs, not passwords. The server stores
ciphertext and private user-scoped status/count/expiry metadata. Personal action
events are excluded from team audit/report streams. Shared action events reveal
only IDs and bounded outcome labels, never website names or credentials.

Browser leases are random, stored hashed on the server, bound to the initiating
bearer and expire within five minutes or the approval deadline. Extension
session storage may retain the raw action lease and ID to survive popup closing;
they cannot access another action or vault. No plaintext manifest, password or
key is persisted there. Every broker call rechecks current vault ownership or
accepted editable shared access, browser save/fill policy and rotation status.
Removed shared membership/grants cancel pending approvals and revoke bearers.
Encrypted manifests are authenticated locally; invalid scope/count/expiry,
modified ciphertext or unavailable entry IDs stop execution. A database operator
can still rewrite status metadata; outcomes are not independent attestations.
Approval manifests use a symmetric vault key rather than a separate per-user
signature. Shared recipients already holding that key could forge another user's
manifest if they also compromise the service or that user's authenticated API
access. This preview does not provide cryptographic non-repudiation of shared
approval authorship. A signed approval protocol remains a production gate.

Before navigation or form preparation, a generated replacement is staged inside
the encrypted login entry while the old password remains the saved credential.
Only explicit user confirmation promotes it. Unused proposals can be discarded;
cancelled/expired jobs do not delete them. Pending data is included in encrypted
backups and recoverable in the dashboard. It is excluded from cross-vault copies.
Readers of a shared vault can see staged secrets because they already have its
data key. Staging increases the amount of secret material in an unlocked client;
locking/unmounting clears references and invalidates late unlock/save responses.

The browser form worker is a typed, top-frame-only preparation tool. It verifies
exact HTTPS origin and same-origin form action, requires unambiguous visible
new/current/confirmation fields, checks account hints and password constraints,
and never submits. Secrets sent to an approved website can be read by that site,
including compromised scripts. Site-supplied fields are not evidence that the
account is correct or the password changed. Same-origin single sign-on routes,
unusual forms, passkeys, MFA and CAPTCHA need user participation or reviewed
site adapters. The well-known URL is discovery and may return an error.

Cancellation and permission checks precede each tool call; they cannot retract a
request already committed or a value already written to an approved page.
`confirmed_by_user` is a user report. No live login attempt or external success
verification is performed, and no workflow state is marketed as autonomous
verified password rotation.

## Recovery decision

### Vault activity metadata

The per-vault timeline returns an allowlisted, paginated subset of service events
after checking exact personal ownership or current membership plus accepted
shared grant. Credential-action associations use stored vault IDs and action
scope, not encrypted manifests or title/username guesses. Personal metadata
events now use private audit scopes; older owner-attributed workspace metadata
can be shown only for the exact owned vault. Current shared member emails can
label actors; former actors are not resolved outside the current workspace.

Service action types, actor IDs and timestamps are metadata, not zero-knowledge
credential contents. This filtered view does not verify a whole hash chain or
establish external success. Browser outcome messages remain self-reported.
Local account observations and titles are derived only from decrypted entries,
are never sent with timeline requests and disappear from the UI on lock. Local
fills, reveals and unlocks have no server telemetry. Missing historical records,
trimmed account events and deleted entries cannot be reconstructed. Old clients
or compromised browsers can retain copied data and cannot be remotely erased.
All stored audit scopes are checked during SQLite backup validation; this is
still not an independent audit or rollback authority. See VAULT_ACTIVITY.md.

Personal version-2 vaults now offer advance offline-kit recovery (0.16.0).
The service never holds a recovery secret or decryptable key escrow. Without
usable material prepared before the loss, neither account sign-in/reset nor TOTP
can decrypt a vault. Shared identities still have no recovery. Full recovery-kit
scope, lifecycle and historical-access limits appear below and in
VAULT_RECOVERY_KITS.md; native acceptance and independent review remain open.

## Release gates

Account passkeys in 0.13.0 use exact configured RP/origin, required user
verification, a separate HttpOnly browser binding and one-use server challenges.
Enrollment requires a full session plus fresh password/enrolled MFA. Proofs
are consumed before parsing/verification; keys/counters/revisions, membership
and session issuance are checked transactionally. Existing enrolled MFA remains
required after passkey sign-in. Account removal revokes sessions/challenges and
keeps a tombstone; backup restore revokes every restored active key.

Public keys, device labels and authentication times are server metadata.
Authenticator private keys never enter the vault, backend or AI context. A
passkey is not a vault encryption/recovery key. Current IP-origin UI is disabled;
the separately prepared localhost acceptance account has disposable data only.
Native enrollment/sign-in, Windows Hello/security-key behavior and site/store
compatibility are not accepted from unit/component/synthetic-signature tests.
Migration/origin changes and cached device credentials need deliberate review;
rollback freshness and erasure of authenticator copies are not provided.

Independent review of the Argon2id + wrapped-key implementation; sharing/revocation protocol; production
Postgres migrations and restore drills; CSV/breach-check browser interoperability;
passkeys; per-site account-change adapters; signed clients and extension
store publication; mobile autofill; external penetration/crypto review; bug
bounty intake and remediation process. None is implied by green unit tests.


## Uploaded message triage (0.14.1)

RFC 822 parsing is local and bounded by input size, MIME part/depth and link
counts. Content is never rendered, followed or executed. Attachment filenames
are inspected for fixed executable suffixes; content is excluded. Decode or
structure problems produce explicit partial coverage, never a safe inference.
Uploaded Authentication-Results is untrusted and never proves SPF/DKIM/DMARC.
Reply-domain/link-host differences can be legitimate and require verification.
The model provider receives only allowlisted rule summaries. Raw message bodies,
headers, addresses, filenames and destinations are not retained or sent to AI.
A SHA-256 message scope prevents unrelated messages replacing findings or being
counted as rechecks; it leaks equality and permits guesses of known content.
There is no trained classifier, inbox connector, antivirus attachment engine,
quarantine or deletion action. See MESSAGE_TRIAGE.md for the exact boundaries.


## Windows Update cache/reboot observations (0.15.0)

Update status is separate from posture permission. Schema-10 migration defaults
existing connections to denied; protocol-3 capability and the client flag must
also consent. Fixed local COM calls use an offline WUA search and update-reboot
boolean. Counts and errors are typed/bounded, not raw OS inventory. Sender/job
text cannot supply commands. The old posture allowlist never runs update tools.
Cached zero and successful execution do not establish patch coverage, and paired
results remain untrusted self-reports rather than independent attestation. The
app performs no online refresh, download, installation, reboot or settings
change. Updates form a separate scan scope and cannot resolve port/protection
findings. See WINDOWS_UPDATES.md for permissions, protocol and limitations.


## Offline personal recovery kits (0.16.0)

Recovery material is prepared locally before a master is lost. A separate random
256-bit code wraps a fresh data key with AES-GCM and context/kit/date associated
data. The kit is an encrypted snapshot plus wrapper; neither it, the code nor
plaintext is uploaded. Only an owner/context/revision-bound replacement envelope
and fixed intent reach the service. Successful activation, use or invalidation
rotates actual key bytes in the client and atomically revokes the selected
vault's browser tokens and unfinished account plans. Server code cannot prove
hidden-key rotation or correct plaintext preservation; it validates metadata and
transaction scope. A malicious client/session can already overwrite ciphertext.

Kit snapshots and older app backups remain accessible with their historical
keys; changing a master wrap alone does not revoke them. Current recovery never
silently selects old data. Snapshot restoration explicitly overwrites current
entries and can lose later changes. Losing both master and previously saved
usable material remains unrecoverable. Closing UI cannot retract an already
sent HTTP commit; no automatic retry is made. Shared recovery, trusted contacts,
hardened memory, native credential/download acceptance and independent protocol
review remain unfinished. See VAULT_RECOVERY_KITS.md for exact limits.
