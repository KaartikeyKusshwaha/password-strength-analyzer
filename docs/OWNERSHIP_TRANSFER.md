# Shared-vault ownership handoff

Development build 0.12.0 adds a two-party handoff for one shared vault. This is
separate from workspace ownership. A workspace owner still cannot offboard
themselves through the member-removal endpoint.

## Product workflow

1. The current vault owner unlocks their sharing identity, verifies/opens the
   vault and opens **Vault ownership and handoff**. They choose an existing
   accepted teammate whose workspace role permits writes, and explicitly choose
   their own subsequent access: removed, viewer, editor or admin.
2. The browser checks the selected identity against the signed current grant and
   signs a proposal locally. No private keys, passphrases or credential fields
   are submitted. The proposal lasts 15 minutes. It does not change ownership,
   grant roles, encrypted data or browser connections.
3. The addressed successor sees a request on their control center, opens shared
   vault review, unlocks their own identity and verifies the current owner through
   the existing fingerprint process. They can decline, or explicitly acknowledge
   the member-access and connection consequences before accepting.
4. On acceptance the browser decrypts locally, generates a new random vault data
   key, preserves all entries/history/staged password proposals, encrypts under
   the next epoch, and wraps the new key for exactly the approved members. The
   successor signs a new owner manifest, each grant and the acceptance payload.
5. The service atomically validates both parties' signatures and the exact member
   set, commits the new root/key epoch/revision, revokes all shared companion
   tokens for that vault and cancels its unfinished credential-action leases.
   Personal/unrelated vaults and connections remain unaffected. Remaining member
   roles and invitation-acceptance states stay the same; only the two roles named
   in the proposal change. The initiating UI locks and reloads its vault list.

Remaining members must verify the new owner fingerprint when reopening and pair
fresh browser connections. Staged website passwords remain inside the rotated
encrypted vault and can be reconciled with the existing account recovery controls.
Cancelled plans do not prove that a website password was unchanged. An old owner
whose access is removed has no next-epoch grant; one explicitly retained as
viewer/editor/admin receives the corresponding next-epoch grant.

After transferring every vault they own, a non-owner workspace teammate can be
offboarded normally. An administrator cannot bypass a vault owner's handoff by
simply deleting that owner, which would strand the key distribution.

## Protocol binding

The old owner's `team_vault.ownership.v1` signature binds proposal ID, vault,
workspace, current owner and recipient IDs/fingerprints, revision, epoch, expiry,
former-owner role and a SHA256 snapshot digest. The canonical snapshot covers
the current encrypted payload, signed manifest, browser policy, rotation flag and
the full sorted grant roster including roles, envelopes and acceptance states.
Member emails are display metadata and are not used as cryptographic identity.

The new owner's `team_vault.ownership_accept.v1` signature binds proposal ID,
snapshot digest, revision, complete next-epoch payload, manifest signature and
every new grant. The server verifies the successor's root manifest and all key
wrap signatures independently. It rejects missing/extra/duplicate recipients,
unapproved role changes, wrong context/epoch, stale state, expired/stopped
proposals, wrong users and wrong workspaces. The server cannot decrypt or prove
the integrity of the client's plaintext transformation or key randomness; the
client implementation and its independent review must establish those properties.

Content saves, grant changes, browser-policy changes, revocation, offboarding
and key rotation durably invalidate pending proposals in the same transaction.
Changing a policy back cannot revive old approval. The final snapshot check also
guards changes racing with local encryption. A fresh proposal is required after
invalidation. Repeating an already accepted invitation is idempotent and does not
invalidate a handoff. Sharing-passphrase maintenance cancels pending proposals
sent or received by that identity. Application-backup recovery cancels pending
handoffs rather than reviving old approvals.

Current owners and addressed successors can cancel/decline. A proposal is not
reserved ownership and does not freeze normal vault edits. At most one current
pending proposal is allowed per vault. Pending records plus the latest 100
terminal receipts per workspace are retained; service timeline events remain
subject to normal audit retention. Expiry is evaluated against service time;
this is not a scheduler promising an action precisely at its deadline.

## Boundaries and verification

- Existing decrypted credentials, exported copies and old backups cannot be
  recalled. Rotation protects future ciphertext from the removed key holder; it
  does not erase already known website passwords. Rotate those at the provider.
- Transfer affects vault ownership only. It does not change workspace roles,
  external website account ownership, app sign-in credentials or identity keys.
- Remaining members explicitly verify the new root identity; the server's
  directory alone is not an independent trusted channel. There is no external
  rollback authority or independent payload-authorship guarantee.
- Lock/hide/unmount generation checks prevent late local work from submitting or
  publishing into a newer UI session. Locking cannot retract a committed request.
- Automated native-crypto, API and UI checks cover this development protocol.
  Live browser acceptance and independent cryptographic/security review remain
  unfinished release gates. This is not a claim of an audited password manager.
