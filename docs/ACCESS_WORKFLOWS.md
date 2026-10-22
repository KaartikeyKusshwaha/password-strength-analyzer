# Durable client-vault offboarding foundation

Unreleased schema 12 implementation. No browser testing or production migration
was performed. This is the local vault connector's first workflow path, not a
completed agency service or Google/GitHub connector.

## Scope and approval

`POST /api/access-workflows` takes client_id, person_id and dry_run (default true).
Only a current workspace owner can create a plan. Plans cover 1–20 linked shared
vault memberships. The actor must own every vault; the target cannot be self or
a workspace/vault owner. Ownership handoff remains its separate signed protocol.

The plan freezes vault IDs, revisions, key epochs and grant digests. No passwords,
keys, encrypted vault payloads or authenticator seeds enter workflow records.
The server computes the plan digest; a provider cannot select executable actions.

`POST /api/access-workflows/{id}/approve` requires explicit approved=true, that
digest, the creator's current sign-in password and an unused MFA factor. Owner
MFA enrollment is mandatory for this path. A changed scope needs a new plan.
Approvals last at most 24 hours and are rechecked against current owner/MFA
state before each step. This is not yet global mandatory-owner-MFA enforcement.

## Steps and execution

1. Revoke the target from every approved vault before pausing for rotation.
2. Wait for the approving owner to unlock each connected shared vault in the
   extension and rotate its key using the existing browser crypto. No raw key or unlock passphrase is retained on the backend.
3. Verify the target remains absent and the next epoch is present without a
   rotation-required flag. Reappearing access blocks the run, rather than using
   the old approval to revoke newly granted access.

The existing `reviews.Runner` executes these steps through the application's
existing single executor. The existing watch scheduler submits eligible work;
startup also requeues eligible records. No second queue, runner process or
scheduler thread was introduced. A process-local pending set bounds duplicate
submissions; database state and a write transaction provide durable correctness.

Each local membership effect, token/action cancellation, audit event and step
completion share one SQLite transaction. A crash before commit rolls everything
back; a crash after commit resumes at the next pending step. This establishes
local atomic/idempotent effects only, not exactly-once external API execution.
Remote leases, reconciliation, retry/backoff and connector failure states remain
required before external connectors are attached.

Dry-run steps are simulated and do not revoke access or require real rotation.
Cancelled runs retain completed removals and mark remaining steps cancelled.
Execution failures become blocked with a fixed audit event, not raw exceptions.
Unknown actions and lost approval cannot authorize a mutation. Backups retain
historical results but recovery cancels pending runs and clears their approvals.

`GET /api/access-workflows` is owner/workspace scoped. It returns up to 100 plans,
their per-step status and coverage. The app session API is also used by the
read-only Offboarding history inside Clients & Access. Execution starts and is
approved in the extension, using a separately approved eight-hour `access`
connection. Its comparison-code handoff requires a current owner with MFA.
The bearer routes under `/api/companion/access` reuse these same handlers and
runner. They cannot read vault payloads or use scanner/device routes; existing
vault and security grants cannot call them. Role/MFA loss is checked on each use;
disconnect, handoff cancellation, member offboarding, MFA disabling and backup
restore revoke the capability. Passwords and factors are cleared from the popup
form immediately on submission and are never written into extension storage.
An approved workflow remains independently authorized until its 24-hour expiry
or explicit plan cancellation; disconnecting the extension does not undo it.

## What a completed run means

Completion establishes selected local shared-vault membership removal and
subsequent key rotation. It does not erase cached passwords, revoke website
sessions, rotate website credentials, suspend a Workspace account or prove MFA
on a third-party platform. The returned coverage states these exclusions.
Server-side validation can observe the current signed grant protocol/epoch; the
independent crypto tests separately verify honest-client rotation creates a new
data key. A compromised vault owner cannot be certified by backend metadata.

## Evidence

The initial focused workflow/backup suite passed 23 tests. It covers unapproved and
dry-run no-effects, two-vault removal before unlock, complete verified local
scope after rotation, crash before/after commit, no duplicate revocation audit,
cancel preservation, MFA/owner checks, stale plans, expiry, reappearing access
and restored-approval cancellation. Sharing/client/migration regression passed
47 tests. The full backend snapshot passed 462 tests with one skipped and one
Starlette TestClient deprecation warning. After that snapshot, manifest/state
validation and migration-failure regressions were extended. The final focused
workflow suite passed 13 tests; the workflow/review/watch suite passed 32 tests
before the final extra invalid-state case. These are automated results, not
installed browser acceptance or proof of external connector effects.

## Evidence and scheduled local checks

Real completed workflows schedule three read-only rechecks at +24h, +7d and
+30d in the existing watch scheduler. A due check records absent, reappeared,
rotation-pending or unavailable vault scope. It never automatically revokes a
new invitation. Dry runs schedule no checks. Restored pending checks are
cancelled so a restored database is not represented as fresh evidence.

Owner-scoped report APIs at `/api/access-workflows/{id}/report` and the matching
extension route return current selected-vault access, step outcomes/timestamps,
rechecks, relevant audit events and whole-workspace chain verification. The
extension can inspect this report; the control room also exports JSON. Reports
are not independently signed or security certifications. A white-label client
PDF/share link, external connector evidence and device posture integration are
still unfinished.

Shared-key rotation is now available within the extension workflow surface.
Its rotation endpoints require BOTH the live workflow bearer and a separate,
currently accepted owner companion for the exact vault and actor. The workflow
must be approved, unexpired, waiting for rotation, with its target still absent,
client link intact and original epoch pending. Neither bearer alone can fetch
the context or submit rotation. Context exposes only that vault's encrypted
payload/grants and remaining recipients' public keys; the existing client crypto
creates the next payload/key distribution. The same server rotation validator
used by interactive vault controls commits it, covering exactly the remaining
roster. Repeated or changed-scope rotations are rejected. The extension locks
its previous vault session afterward.

Next implementation: discovery/debt,
manual/external connector sources, handoffs, expiry and the rest of the master
plan. External connector expansion remains behind the agency-validation gate.
All browser acceptance is deferred until implementation is finished, as the
user requested.

Final verification of this increment: backend 471 passed, one skipped; frontend
348 passed across 76 files. Web and content/popup/background extension builds
passed. No live browser verification or production deployment was performed.
