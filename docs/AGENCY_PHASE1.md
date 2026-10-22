# Client access and durable offboarding implementation

This branch contains unreleased implementation. Oracle remains on the previously
verified hosted app 0.22.0 and companion download 0.22.1. GitHub companion 0.23.0
is the prior prerelease, not these new source changes. No production migrations
or browser tests were performed for this work. The user explicitly deferred
browser testing until implementation is finished.

## Access map

Schema 11 adds client records and explicit shared-vault links. The owner-only
Clients & Access page reads original accepted/pending membership tables live,
filters by client/person and displays key-rotation requirements. Unlinking only
changes metadata; it does not revoke access. Credential payloads are never read
by the map.

Schema 13 adds `access_grants` for explicit manual reports and opt-in extension
discovery. These are not materialized copies of vault memberships. Manual
reports identify existing workspace members and retain owner-reported roles.
Extension observations identify the signed-in person and a chosen account
nickname, with domain-only site metadata. A login attempt is not proof of
successful sign-in. The map labels each source; retiring a report does not claim
external revocation. Users without a connector are not represented as verified
platform grants. External people and real SaaS connector sources remain pending.

## Extension offboarding

Schema 12 persists immutable approval-bound plans and local workflow steps. The
existing review Runner, executor and watch scheduler execute and resume them;
there is no second runner. A real or dry-run plan selects 1–20 explicitly linked
vault memberships. Fresh creator password/MFA approval binds a plan digest, and
all removals commit before waiting for key rotation. Actor/MFA loss, expiry,
stale scope, reappearing access or invalid step manifests stop execution.

Each effect, scoped token/action cancellation, audit event and step completion
shares one SQLite transaction. Crash-before-commit rolls back; crash-after-commit
resumes at the next pending step. This is local atomicity, not exactly-once
external API execution. Cancelled plans retain completed removals. Backup restore
cancels pending workflow approvals.

An eight-hour owner/MFA extension capability supports plan creation, fresh
approval, cancellation, progress and evidence. Existing vault/scanner tokens do
not gain workflow authority. Shared-key rotation requires BOTH this capability
and a separately connected, unlocked owner companion for the exact vault. The
existing browser crypto generates the next payload and remaining-member key
distribution; the original server rotation validator commits it. Repeated or
changed-scope rotations are rejected, then the old local vault session locks.

## Rechecks, history and discovery control

Real completed local workflows schedule read-only +24h/+7d/+30d vault checks.
Reappearing access or unavailable scope raises attention, not another automatic
removal. Reports include step outcomes/timestamps, selected current access,
rechecks, relevant audit events and chain validity/head. Unrelated workspace
history is omitted. The control room offers read-only workflow history and JSON
export. A final white-label PDF/share link Proof Pack is still pending.

Discovery uses its own comparison-code connection, with no vault, scanner or
removal permission. Staff can choose only currently assigned clients; owners
can choose their workspace clients. Viewers cannot submit observations. Each
site needs browser host permission plus explicit client/nickname consent. The
worker sends only a consent ID on a top-level login-form attempt; the server
binds person/client/domain/label to stored consent. Permission removal pauses
local collection until explicitly enabled again. Discovery can be revoked in
the extension or Connections; offboarding and restore revoke it too. See
[the full protocol](ACCESS_DISCOVERY.md).

## Verification and remaining scope

The prior offboarding increment passed backend 471 tests (one skipped) and
frontend 348 tests. New discovery/map/migration verification is recorded below.
Current web and content/popup/background builds compile without replacing the
installed extension. Isolated build artifacts are under data/discovery-validation.

Shared-password debt now extends the existing encrypted operator; see
[its scope and recovery limits](SHARED_PASSWORD_DEBT.md). Schema 14 adds only
metadata and preserves schemas 8–13 as backup inputs. The extension can register,
approve, follow progress, verify, archive/retire and reopen shared-login debt.
Owner confirmations are not independent external verification.

Remaining implementation includes expired/orphaned proposal recovery UX, external connector leases/reconciliation/retries, departure triggers,
freelancer expiry, weekly reviews, full handoffs and the final Proof Pack.
Mandatory owner/admin MFA is currently enforced only for workflow access and
approval. Advanced-UI flag conversion and archived phishing cleanup remain.

Browser acceptance, agency interviews/design partners, an independent security
review, store/helper signing and recurring off-server backups remain genuine
gates. Connector Phase 4 is not authorized by the master plan until at least
three agencies report the stated pain; no such interviews have been conducted.

Final discovery regression: backend 476 passed, one skipped, one existing
Starlette TestClient deprecation warning. Final frontend suite: 359 passed across
78 files, including worker/popup checks for exact-site permission and the final
offline-stop UI adjustment. Web and content/popup/worker
builds passed into isolated validation directories. No installed browser files
or live Oracle services were replaced.

Debt verification snapshot: backend 480 passed, one skipped, before the final
reopen assertion and schema-13 backup test extension. The final focused debt
suite passed five tests. Frontend final rerun passed 366 tests across 80 files.
Web and content/popup/background builds passed into data/debt-validation.
Final complete backend rerun: 481 passed, one skipped, with the existing
Starlette TestClient deprecation warning. Browser testing remains deferred.
