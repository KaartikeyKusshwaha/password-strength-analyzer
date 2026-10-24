# Client handoff coordination

Handoffs are prepared, approved, linked to existing offboarding, cancelled and
signed off from the extension's Client access section. Workflows in the website
retains a read-only history. A handoff record never changes permissions itself.
The existing offboarding runner and signed vault ownership protocol perform the
actual effects; there is no second executor.

## Scope and approval

Schema 15 adds `handoff_records`: workspace/client/person/receiving owner,
canonical vault snapshot and digest, approval, linked workflow and receipt.
The preparing workspace owner must own every client-linked vault (1–20).
A separate receiving workspace owner is required. Settings can promote an
existing MFA-enrolled member with explicit full-owner consent, current owner
password and an unused MFA/recovery factor. Promotion does not grant vault keys.

`person_handoff` excludes departing workspace owners. Sign-off requires a real,
completed existing offboarding run with the same client, person and exact vault
set. Every outgoing grant must be absent, the recipient must have accepted vault
access and every vault must have a newer fully rotated key epoch.

`client_offboard` transfers the preparing vault owner out of the client vaults.
It requires the recipient to own every vault, the outgoing owner to have no
remaining vault grant and a new key epoch. The extension now prepares, reviews,
accepts and cancels the existing mutually signed ownership protocol. Each party
selects and unlocks the exact shared vault in their own extension; the receiving
owner accepts explicitly. Acceptance rotates the key, revokes the old browser
connections and cancels unfinished shared password-action plans. Reconnect and
verify the new owner before reopening. See EXTENSION_OWNERSHIP.md. The handoff UI
cannot bypass the transfer or certify it prematurely.

Preparing-owner approval binds the exact current scope and expires after seven
days. Sign-off requires the separate receiving owner's current password and an
unused factor, plus the current evidence digest. Live owner/MFA loss, stale
scope/evidence, incomplete/dry-run offboarding and unrotated keys fail closed.
The extension uses the existing expiring owner access capability, exact origin
checks and CSRF-free bearer CORS allowlist; handoff access grants no vault read
capability. Passwords and factor values are not persisted in handoff records.

## Honest receipts

External account reports and active shared-password debt remain visible in the
evidence. External reports require an explicit unresolved or reviewed-unverified
acknowledgment and produce `complete_with_exceptions`. Device return/wipe answers
are owner attestations, never remotely verified facts. Unresolved device steps
also produce exceptions. A completed receipt records its evidence digest; later
changed evidence is highlighted without rewriting the original receipt.

Cancelling a handoff does not cancel its linked offboarding run or undo removals.
Backup restore cancels nonterminal handoffs, clears their approvals and revokes
extension grants. Supported older backups migrate through schema 15. The audit
log remains a local hash chain, not an independent certification.

## Validation

API integration covers real revoke/rotation effects, independent sign-off,
current-factor failures, replay, stale scope/evidence, external exceptions,
ownership requirements, cancellation, token/origin restrictions, encrypted
backup restore and audit rollback. UI tests cover transient credentials,
disabled premature sign-off, changed-evidence warnings and exact route limits.
Native extension/two-account browser acceptance remains pending the consolidated
final pass. No hosted migration or release is implied by source tests.
