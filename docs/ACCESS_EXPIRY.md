# Freelancer expiry and scheduled departures

The extension's Client access section can prepare and approve a time limit for a
contractor's existing client-vault memberships or invitations. Default: 30 days;
UI range: 1–90 days. The API accepts an absolute expiry at least one hour and at
most 90 days ahead. A reminder is recorded three days before expiry (immediately
for shorter policies). These are real workspace records, not training data.

## Authority and execution

A preparing workspace owner must own all 1–20 vaults in the initial client/person
scope. Approval requires the exact plan digest, current account password and an
unused MFA/recovery factor. It binds the person, verified recipient identity,
fixed vault IDs, behavior and deadline. Later non-owner role/key/payload changes
within that identity are explicitly included in auto-expiry consent. Ordinary
vault edits do not invalidate a month-long approval. New vault memberships are
outside the approval, shown as uncovered, and never silently added to removal.
Changing a selected vault's owner, client link or recipient identity blocks the
policy. Workspace owners cannot be offboarded this way.

`auto_revoke` creates one derived offboarding plan when due and executes it under
the stored narrow policy approval. The existing `reviews.Runner`, executor,
step journal, cancellation and scheduler perform the effects. The parent policy
and derived plan commit in one transaction; a crash rolls back or resumes the
same plan, without creating duplicate effects. Parent authority is rechecked
before every step. A 30-second scheduler interval is not an exact-time guarantee:
server downtime, executor backlog and failures can delay work. Bounded policy
batches rotate by least-recently-checked record so waiting unlocks cannot keep
later policies permanently out of the scan. Processing more
than seven days late blocks for fresh intervention instead of silently using an
indefinitely old approval.

Server memberships and their scoped browser connections are revoked first.
Encryption-key rotation needs the owner's locally unlocked vault; no passphrase
or decryption key is stored on the server to bypass that step. The normal
extension offboarding run provides the rotation controls. Previously absent,
already-rotated access can be verified without an unnecessary new key. A pending
rotation remains pending. Completion schedules the existing +24h/+7d/+30d
read-only rechecks. Copies decrypted earlier and external website access are not
erased by this policy.

`scheduled_departure` only prepares a current offboarding plan at the deadline.
It does not authorize removal: the owner must review that new scope and supply a
fresh password/factor approval in the extension. This is the scheduled-last-day
trigger; no Google or GitHub connector trigger is claimed.

Any current workspace owner with MFA can cancel a policy and its unfinished
linked steps. Completed removals are never undone or regranted. Backup restore
cancels active policies and derived authorizations. Records use the existing
workspace-scoped entity store; no encryption-format/schema migration is needed.
There are at most 100 nonterminal policies and 1,000 policy-history records per
workspace. Derived runs have bounded additional capacity beyond the ordinary
manual-workflow history limit so an already approved expiry is not blocked by a
full manual history.

## UI and remaining work

Prepare, approve, cancel and inspect progress in the extension. The website's
Workflows view retains read-only expiry history. Approval credentials are cleared
immediately after submission and never enter policy data or an AI planner.

**Not finished:** creating the initial signed vault invitation from this same
expiry flow, and durable background extension reminder delivery. Initial
membership/invitation must currently be created using existing vault settings.
The day-27 event is stored and visible when the extension refreshes; it is not an
email, push notification or guaranteed background badge. Workflow connections
expire after eight hours, so they cannot honestly be treated as a month-long
notification channel. A separately approved read-only reminder channel remains
to be implemented; destructive operator-token lifetime must not be extended
silently. This checkpoint is the expiry engine and extension controls, not a
claim that every freelancer onboarding requirement is complete.

Tests cover real two-vault expiry/rotation/rechecks, pending invitations,
pre-approval inactivity, scheduled departures, cancellation, lost authority,
late processing, parent revalidation, crash rollback, scoped membership changes,
capacity and encrypted restore. Native browser acceptance and production rollout
remain deferred with the rest of the implementation.
