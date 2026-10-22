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
2. Wait for each remaining owner to rotate its key using the existing browser
   crypto. No raw key or unlock passphrase is retained on the backend.
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
their per-step status and coverage. The current API uses the authenticated app
session. A separately approved extension workflow capability and popup UI are
still needed; existing scan-only or vault tokens are not broadened implicitly.

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

Next implementation: extension-specific approval scope and action/progress UI,
Workflows control-room history, client-side rotation queue, stronger lifecycle
and migration-failure regressions, and the rest of the agency master plan.
