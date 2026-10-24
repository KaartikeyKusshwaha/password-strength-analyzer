# Retired email history: offline archival

Email detection is not an active product capability. Its scanner, MIME parser,
submission schemas and options were already removed; rejection regressions stay
to prevent those entry points from returning. The remaining mail-coverage renderer,
icons and legacy agent snapshot grouping have now been removed. Unsupported old
finding rules produce unavailable progress rather than matching unrelated scans.

`python -m backend.mail_retirement` is an offline maintenance command, not an
application API or extension feature. It never downloads mail or reads an inbox.
It operates on one explicitly chosen workspace and existing assessment history.

1. Stop affected workers. Preview the exact record set:

   ```powershell
   python -m backend.mail_retirement --data-dir <data-folder> --workspace <workspace-id>
   ```

   Output contains IDs, kinds, hashes, linked-history counts and a plan digest.
   It excludes record contents, labels, subjects, account emails and keys. Plans
   are bounded to 10,000 active entities and the existing 128-MiB backup budget.
   If `records` is empty, stop: nothing needs archival or a new archive backup.
2. Review the IDs and linked history. The component includes linked findings,
   tasks, jobs, reviews and operations so those records do not become dangling
   active work. An ordinary application asset and unrelated scans on that asset
   remain active. A retired inbox asset participates in the archive component.
   Mixed reviews can pull non-email history into the component. The command
   refuses linked history unless explicitly selected with the flag below.
   References from unrecognized record kinds and running/queued work block apply.
   Other workspaces are not traversed or altered.
3. Use the existing encrypted-backup key workflow. Keep the key and resulting
   backup in protected operator storage, outside disposable cleanup folders.
   Approve only the exact preview digest:

   ```powershell
   python -m backend.mail_retirement --data-dir <data-folder> --workspace <workspace-id> --apply --approve-digest <reviewed-digest> --backup-key <private-key-file> --backup-output <new-backup-file>
   ```

   Add `--allow-linked-history` only when the linked records were also reviewed
   and authorized. A new exclusive backup filename is required on retry if a prior
   attempt already created it. Nothing overwrites an existing backup or key.
4. The command creates the existing encrypted full-database/server-key backup,
   authenticates it, validates schema/integrity/audit, and confirms it contains
   the exact approved history. It rechecks the source under a write transaction
   and verifies the backup file has not changed before archival. Plan drift,
   backup/key failure or an audit-write failure causes no partial archival.

Records keep their original IDs but move to the internal `retired_mail_records`
kind, which is excluded from active workspace APIs. Each wrapper retains the exact
original JSON, its kind/hash, the approved plan digest and the authenticated
backup checksum. Audit rows are not erased or rewritten; a new event records the
retirement. This archives data; it does not purge physical database pages or
reclaim disk space. No schema or vault-encryption format changes are required.

Recover through `python -m backend.backups restore` into a new offline directory,
using the retained pre-archive backup and key. The existing restore path resets
active authorizations rather than replaying approvals. Review that isolated copy
before any separate recovery operation. A subsequent normal backup also retains
the archive wrappers. The archive command never removes its recovery material.

The shared authenticated-backup reader validates snapshots in memory. Its
in-memory copy uses SQLite's documented rollback-header adjustment for WAL
deserialization; stored backups and bytes restored to disk are unchanged.
[SQLite deserialize guidance](https://www.sqlite.org/c3ref/deserialize.html).

Local read-only preflight on 22 October 2026 found one workspace and zero legacy
records, so no local history was mutated and no real archive backup was needed.
The Oracle SSH connection timed out; hosted history remains unverified. No Oracle
deployment or browser acceptance is claimed by this implementation.

Verification completed on 23 October 2026:

- 73 focused backend integration checks passed across archival, backups, access
  workflows, debt, passkey migrations and platform behavior.
- The final 13 retirement/API regressions passed after the resource guard and
  linked-history cases were added. They cover preview redaction, tenant isolation,
  unrelated checks, explicit mixed-review scope, recoverable backups, stale plans,
  changed backup files, rollback, active work, opaque references, bounded record
  counts and unavailable progress for retired rules.
- All 373 frontend tests across 81 files and the web production build passed.
  The removed renderer's positive feature tests were removed with it; a regression
  now ensures old coverage payloads do not mount that UI.
- One existing Starlette TestClient deprecation warning remains. Test datasets,
  test-only keys/backups and validation builds are disposable and were created
  under the user's single cleanup folder, not the real backup directories.
