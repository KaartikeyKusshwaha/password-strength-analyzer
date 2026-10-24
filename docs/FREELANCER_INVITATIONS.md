# Freelancer invitations with an expiry

The extension now provides an initial contractor invitation flow, covering every
vault linked to one client (1–20). The contractor must already be a non-owner
workspace teammate with an initialized sharing identity. An existing account and
identity are account setup requirements; no SaaS intake or credential harvesting
is added. Existing client-vault memberships use the separate expiry-only flow.

1. Select client, teammate, vault role and expiry (30 days by default).
2. The server prepares a 15-minute metadata draft binding the exact vault set,
   current vault state digests, recipient fingerprint, role and expiry.
3. Select and unlock each required shared vault in the extension. Its owner key
   locally signs the ordinary wrapped-key invitation. Switching vaults locks the
   previous vault. Wrapped invitations and their scoped bearer references stay
   only in popup memory; no grant is sent to the server yet.
4. Review all signed vaults and approve both access and automatic expiry with
   current account password and an unused MFA/recovery factor.
5. The server rechecks the owner workflow capability, each independent exact-vault
   capability, MFA/owner authority, client links, unchanged vault snapshots,
   recipient identity and exact role/signature/roster. All invitations and one
   active expiry policy commit together, or everything rolls back, including
   factor consumption and audit effects.
6. The teammate explicitly accepts their invitations. The expiry engine revokes
   pending invitations too; failure to accept cannot keep an invitation alive.

This uses the existing grant-signing, wrapping, signature verification and invite
core. The crypto protocol and encrypted payload format are unchanged. The access
connection by itself cannot fetch a vault or grant access. Every vault requires
its separate accepted owner connection. All current client vaults must belong to
the preparing owner, have browser access enabled, have capacity and require no
pending rotation. Workspace viewers can receive only viewer grants; workspace
owners are protected from this contractor flow. Roles are explicit: viewer,
editor or admin (admin permits managing other members). No credentials enter an
AI model.

Any vault content, role, policy, identity or client-link change invalidates the
draft before applying it; prepare and sign again. Draft expiry, replay, missing
vaults and mismatched tokens fail closed. Pending drafts are cancelled on backup
restore. Signing alone changes nothing. Discarding the local draft removes its
local wrapped invitations; the metadata draft expires on the server. If the
final response is interrupted, refresh expiry policies to inspect the result
before starting another batch. Atomicity prevents an invitation without its
expiry, but a lost network response is not proof that nothing happened.

The API accepts an expiry at least one hour ahead when preparing the draft.
Time spent signing within its 15-minute deadline does not impose a second full
hour of lead time. UI supports 1–90 days. The stored expiry approval remains
narrowly bound to these vaults and the verified recipient. Rotation at removal
still needs local unlock; old decrypted copies and external website access are
not erased. Day-27 background reminder polling is now available through its separate
read-only approval; see ACCESS_REMINDERS.md for delivery delays and limits.

Automated tests cover real two-vault issuance/acceptance/expiry, invalid signatures,
wrong capabilities/recipient/role, stale snapshots, subset/replay failures,
transaction/audit/factor rollback, restore, preflight and short-expiry boundaries.
A real-crypto client test proves the contractor can open the wrapped key while
requests contain no plaintext entries. UI/operator tests retain transient
credentials, explicit final consent, exact snapshot checks and local lock/race
protection. Live cloud/two-profile browser acceptance and independent security
review remain separate pending gates.

Final invitation regression: 12 passed after adding expired-draft, exact-role,
short-expiry, audit/factor rollback and restore checks. Initial combined backend
regression: 51 passed. Frontend: 397 passed in 89 files, plus one subsequent
real-crypto invitation test. Web and extension builds passed. Existing TestClient
deprecation and large strength-dictionary bundle warnings remain unchanged.
