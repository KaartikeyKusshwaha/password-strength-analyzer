# Schema-nine passkey migration and recovery

Source integration is implemented. New Store instances install the ceremony
and credential tables through migration 9. On 21 October the owner process was
restarted after an encrypted backup and upgraded to schema 9 with unchanged
protected account/vault/sharing/connection records. Account endpoints,
session/MFA integration and management UI now exist. Actual authenticator
acceptance remains pending; see PASSKEY_HTTP.md. The earlier schema-8 restore
drill below is retained as historical evidence.

## Migration behavior

The store rejects future or gapped schema histories before creating tables.
Migration 9 and its marker share the caller's transaction; installer failure
rolls back both tables and marker. Reopening is idempotent. The migration checks
table layouts, primary keys and the global (not partial or owner-scoped)
credential-ID uniqueness constraint. A missing table under an existing version-9
marker is an error; silently recreating it would hide lost credential data.

This migration adds storage, not authentication grants. It does not decrypt or
rewrite vault ciphertext, rotate master/sharing keys, change account passwords,
or change the configured browser origin. Back up schema 8 before the updated
service is restarted. There is no automatic deployment/restart in this step.

## Backup and restore behavior

Backup creation supports exact contiguous schema histories 1–8 and 1–9 and
records the snapshot's actual version in its encrypted manifest. Recovery checks
that manifest against the authenticated database and validates the original
schema before upgrading an older store in the new destination.

Recovery clears all pending ceremonies and tombstones every active restored
passkey, preserving its metadata/public key and increasing the revision. Keys
already revoked keep their tombstone. This deliberately requires fresh passkey
enrollment after sign-in with the restored password/MFA; it avoids reviving an
old passkey from a snapshot. Other account/role/password/MFA rollback limits
remain as documented in BACKUP_RECOVERY.md. No freshness/rollback defense or
ability to erase authenticator private keys is claimed.

## Verification

Focused migration/backup/ceremony/credential tests initially passed 61 cases.
Additional cases exercise partial uniqueness and an authenticated archive with
a mismatched schema manifest. Coverage includes migration idempotence and
transaction rollback, protected ciphertext/revision preservation, refusal to
repair missing version-9 tables, schema-8 restore into a new directory, active
key/challenge invalidation, retained revoked keys, and source preservation.

The full backend run passed 290 tests with one existing Starlette/httpx
TestClient deprecation warning. A final integer-type guard for malformed schema
metadata was then verified with the complete 12-test migration suite, including
two new malformed-history cases. The full run's ignored JUnit report is
data/backend-regression-20261020-migration09.xml. These automated results do not
establish browser passkey sign-in or authentication-route acceptance.

An actual owner-data restore drill succeeded on 2026-10-20:

- Backup: data/encrypted-backups/before-passkey-migration-20261020T161525Z-a2dff3.sentinelbackup.
- Isolated destination: data/passkey-restore-drill-20261020T161525Z-a2dff3.
- Report: data/passkey-migration-drill-20261020T161525Z-a2dff3.json.
- The original store remained schema 8 with no passkey credential table.
- The restored store passed SQLite quick_check and became schema 9.
- Selected account-protection fields, all personal vault records, sharing
  identities, shared vaults and shared grants matched before/after and the
  live protected records remained unchanged.
- Restored sessions, invites, companion/device grants and ceremonies were empty.

These are ignored private runtime artifacts. No key, plaintext credential or
record content was printed. No restored server was launched; this drill does
not establish production failover, offsite recovery or passkey sign-in success.
