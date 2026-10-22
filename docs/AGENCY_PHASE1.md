# Phase 1 implementation ledger

This is unreleased source work. The Oracle app has not received schema 11 or
the new frontend. The two-account browser gate and agency-validation gate remain
open. Browser tests are deferred until implementation is finished, at the user's
latest instruction. Automated tests continue during implementation.

## Client access map: first source

- Explicit client records and links to existing shared vaults, in schema 11.
  No client data is fabricated from vault names or imported credential plaintext.
- Workspace-owner-only API: create clients, bind/unbind metadata, read the map.
  Existing accepted vault roles and pending invitations are read live from their
  original tables, not duplicated into a stale materialized grant list.
- Revoking a member removes that membership from the next map read immediately.
  The affected vault still displays rotation_required. This distinguishes access
  removal from completing encryption and website-password rotation.
- Owner-only Clients & Access control-room page supports client/person filters,
  current role/provenance, pending invites, rotation notices and link management.
- Metadata unlink is explicitly not credential revocation; the original vault,
  grants, tokens and ciphertext remain untouched.
- Data is labelled shared_vault provenance. A vault is not evidence of actual
  non-Google platform membership, active sessions, staff MFA or device compliance.
  Platform systems, manual/external people/grants, connectors and extension
  discovery remain to be implemented, rather than inferred from this one source.
- New writes share their transaction with the existing linked audit events.
  Duplicate link requests are idempotent and do not duplicate audit events.

## Migration and recovery

Schema 11 creates clients/client_vaults without changing vault keys or payloads.
Unmarked or incomplete layouts fail closed. Old version-9/10 migration fixtures
now explicitly omit later client tables when simulating historic stores.
Backup validation checks the new layout; schema-10 archives remain supported.
Restore tests verify client links survive encrypted recovery and historic account
records survive schema-10-to-11 upgrade. No production migration has been run.

## Verification

- Full frontend suite: 340 tests passed across 74 files; production build passed.
- Full backend snapshot: 451 passed, one skipped, before the final additional
  backup-layout guard and old-schema backup regression were added.
- Final focused access/backup suite: 16 passed; migration/device/passkey suite:
  31 passed. A new browser run has not been attempted.
- A previous frontend navigation regression expected four destinations. It was
  changed to verify the additional owner-only Clients & Access destination;
  Advanced remains collapsed and the old checks were not duplicated here.

## Runner reuse review

`backend/reviews.py::Runner` already coordinates operation IDs, progress, current
membership checks and cancellation using the application's single executor.
`backend/agents.py` validates provider plans and dispatches tasks transactionally.
`backend/app.py` marks prior running operations/reviews interrupted on restart,
and `backend/watches.py` owns existing scheduling. Durable offboarding needs to
extend these paths with persisted step scope/approval, leases, reconciliation and
retries. The current interrupted-on-restart behavior is not resumability.
No second queue/executor or claim of exactly-once external effects was introduced.

Not yet implemented: durable access workflows/steps, vault connector orchestration,
one-tap popup offboarding approval/progress, external connectors/triggers,
discovery/debt, expiry, proof packs, reviews or handoffs. Refer to the master plan
for their complete gates; this first map source does not complete Phase 1.

## Subsequent workflow foundation (schema 12)

The initial statement that durable local workflow steps were absent is now
superseded by ACCESS_WORKFLOWS.md. Approval-bound client-vault plans and atomic
revocation/rotation-verification steps now extend the existing Runner and watch
scheduler. Dry-run, MFA, scope freshness, crash resume, cancellation and restore
approval invalidation have focused coverage. The extension workflow permission,
popup approval/progress, external connectors and remaining phases are still
unfinished. Schema 11 remains a supported backup source. Production is unchanged
and browser testing stays deferred under the user's latest instruction.

The complete backend snapshot with the workflow foundation passed 462 tests,
one skipped, before the final manifest/state guard extensions. The final focused
workflow suite passed 13 tests; workflow/review/watch regressions passed 32.
No browser sessions were operated during this implementation turn. No production
schema upgrade, token expansion or connector authorization was performed.


## Extension workflow and evidence increment

Separate eight-hour owner/MFA workflow capabilities and popup plan creation,
fresh approval, cancellation, progress and evidence views now reuse the existing
runner. Scanner and vault grants retain their previous scope. The Clients &
Access page includes read-only workflow history; ordinary execution starts in
the extension. Real completed local workflows schedule read-only +24h/+7d/+30d
checks and report reappearing access without a second removal. JSON evidence
includes explicit limitations; this is not yet the final PDF Client Proof Pack.
Shared-key rotation subsequently gained an extension workflow action using the
existing crypto and a separately connected, unlocked owner vault. Both scoped
authorizations are required; the rotation API covers exactly the remaining roster. No browser testing or production deployment was
performed. The full frontend snapshot passed 346 tests across 75 files before
the final history component; final verification is recorded below.


Final extension-workflow verification (22 October 2026): 348 frontend tests
passed across 76 files, including a wait for sharing-poll registration that
removed a timing-dependent test race. Web and all three extension production
builds passed. The installed extension directory and live Oracle deployment
were deliberately left unchanged. Validation artifacts are under
D:/sentinelops-validation-20261022 because C: ran out of space during disposable
SQLite test creation. Only explicitly named generated test directories from
this work were removed; production databases and backups were preserved.
The focused workflow/evidence/backup/sharing-companion suite passed 37 tests;
the final scope suite passed 19 and CORS/status/workflow regression passed 14.

Final clean backend rerun: 471 passed, one skipped, one existing Starlette
TestClient deprecation warning. The prior CORS regression is resolved. Full
JUnit report: D:/sentinelops-validation-20261022/backend-final-results.xml.
Browser testing remains deferred; this does not complete the full master plan.
