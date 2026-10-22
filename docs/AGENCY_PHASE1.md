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
