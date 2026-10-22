# Signed vault ownership in the extension

The extension's Client access section now includes **Transfer a client vault**.
Both participants need current workspace owner/MFA authority, their own accepted
connection to the exact shared vault, and an unlocked local sharing identity.
The current owner loads the vault, selects an accepted successor, chooses their
retained role (removed by default), and explicitly signs. The successor loads the
same vault in their own extension, reviews the proposal and explicitly accepts.
No routine website step is required. Creating vaults, initial sharing grants and
workspace role administration remain control-room settings.

This reuses the existing cryptographic functions and server ownership protocol.
The protocol core is shared by web and extension adapters, with no altered key
format, new runner or server decryption key. The extension adapter rechecks both
expiring capabilities, current workspace ownership/MFA, accepted vault membership
and browser policy inside the mutation transaction. The signed state digest,
revision, key epoch, identities, recipients and exact permitted member roles
retain their existing checks. Context reads require both capabilities too.

The extension compares fresh server state with the reviewed snapshot, verifies
the trusted owner/grant locally and refuses local concurrent activity or changed
entries/revisions before uploading signatures. Acceptance generates a fresh key
locally, encrypts current entries and their staged password history, signs the
new grants, and submits only encrypted payloads and signatures. Both sides'
existing vault connections are revoked and unfinished shared account-action
plans cancelled by the same existing transaction. Workspace workflow tokens
remain independent; handoff receipts can still be reviewed and signed off.

On an acceptance attempt, lock after the guarded task completes. If the response
is lost or cancellation makes completion uncertain, lock anyway and report
uncertainty. Do not retry blindly or show success; check the handoff and reconnect
if the server revoked the connection. Stale proposals can be reloaded, cancelled
or declined. Copies decrypted before removal cannot be erased.

## Tests and limitations

The existing ownership protocol regression passed after extracting its core.
Adapter tests exercise a complete real client-offboard handoff, matching state
digests, exact-vault/token/origin restrictions, revocation, stale scope and atomic
rollback on audit failure. CORS preflight includes the separate vault header.
A real-crypto two-session extension test preserves entries in a new-owner payload
and rejects decrypting it with the old owner's key; request bodies contain no
plaintext credentials. Operator/UI tests cover stale/local races, lock lifecycle,
uncertain outcomes, consent and late responses after locking.

These are automated acceptance evidence, not the required real two-profile cloud
browser test or an independent security audit. The new source is unreleased;
installed companion files and hosted services have not been replaced.
