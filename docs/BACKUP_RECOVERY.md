# SQLite operator backup and recovery

The offline tool `python -m backend.backups` supports schema-8 and schema-9
SQLite application databases. It uses SQLite's online backup API to include committed WAL
pages while the app runs. It encrypts the database and server MFA-encryption
key together with AES-256-GCM, a fresh 96-bit nonce and a version-bound header.
It checks SQLite integrity, schema compatibility, MFA-key compatibility when
encrypted MFA records exist, and all stored audit scopes before accepting data.
There is a 128 MiB development limit and a 30-second snapshot budget.

New Store initialization applies the transactional schema-9 passkey migration.
Back up an existing schema-8 store before restarting the updated app. The
local owner store was migrated on 21 October after an encrypted backup and
isolated restore drill. Account routes/UI are implemented; the current IP origin
is unsupported. Native enrollment/sign-in/expiry/removal passed in a separate
disposable localhost app; remaining lifecycle acceptance is pending. The later
0.13.1 restart also had a fresh encrypted backup and unchanged protected records.

This is separate from the personal-vault export in the app. A full-app backup
contains sensitive account hashes, workspace metadata and server MFA secrets as
well as client-encrypted vaults. Possession of both backup and backup key gives
access to server-held information. Personal and sharing master passphrases are
never collected by this tool; restoring cannot recover a forgotten passphrase.

## Create a backup

Run from the repository using its Python environment. Create directories first;
use unique output names. These example paths are intentionally separate:

```powershell
.venv\Scripts\python.exe -m backend.backups init-key --key-file C:\PrivateKeys\sentinel-backup.key
.venv\Scripts\python.exe -m backend.backups create --data-dir .\data --key-file C:\PrivateKeys\sentinel-backup.key --output D:\Backups\sentinel-2026-10-19.sentinelbackup
```

The key is generated into an exclusively created binary file; no key value is
printed or accepted as a command-line argument. Existing key/output files are
never overwritten. Keep the key separately from backups and restrict both with
OS access controls. File modes are requested on creation; on Windows these are
not a substitute for reviewing inherited NTFS ACLs. Keep an offline/off-device
copy. Local same-disk copies alone do not cover disk loss or ransomware.

Only the database and `.encryption-key` are included. Environment files, logs,
bootstrap tokens, extension/device connection files and backup keys are not.
Configure deployment environment variables separately after recovery. The
snapshot and encryption use memory; a running operator process still has access
to that memory. This does not protect a compromised computer or administrator.

## Restore and verify in isolation

```powershell
.venv\Scripts\python.exe -m backend.backups restore --input D:\Backups\sentinel-2026-10-19.sentinelbackup --key-file C:\PrivateKeys\sentinel-backup.key --destination .\data-restored
```

The destination **must not already exist**, including an empty directory or
symlink. The tool authenticates before writing any plaintext. It stages fixed
filenames in a temporary directory next to the destination, validates the
database, applies the recovery policy, then renames it into place. No arbitrary
archive paths are extracted. Plaintext staging exists briefly on disk; normal
cleanup is not secure erasure and a machine crash can leave staging behind.
Use an encrypted disk, private parent directory and inspect it after failures.

A schema-8 archive is validated in its original form, then upgraded to schema 9
only in the new destination. The encrypted manifest must match the actual
database version. Schema-9 backups additionally require both passkey tables,
their expected layout and global credential-ID uniqueness constraint. Missing,
gapped and future schema histories fail closed.

Recovery preserves account password hashes, enrolled MFA, vault ciphertext and
revisions, sharing identities/grants, assets, findings, tasks and audit history.
It deliberately changes active authorization and execution state:

- Deletes sessions, invites, browser connections and device bearer grants.
- Deletes pending passkey ceremonies and revokes every active restored passkey.
  Revoked IDs remain tombstoned. This prevents an older backup from silently
  reactivating passkeys removed after its snapshot. Sign in with the restored
  app password/MFA and enroll fresh passkeys when account passkey UI is available.
- Clears unfinished MFA enrollment; preserves already enrolled MFA and its
  replay/recovery-code state as of the snapshot.
- Cancels unfinished credential actions and clears their leases. Encrypted
  staged credential values remain in their vault for deliberate reconciliation.
- Interrupts queued/running device, AI and watch runs. Pauses all watch schedules
  and increments their revisions. Completed historical results remain.
- Cancels pending vault-ownership handoffs; old signed approvals are not revived.
- Adds a `backup.restored` event to each workspace's linked audit history,
  per-vault recovery events and cancellation records for unfinished account work.

Sign in again, re-pair companions/devices and explicitly resume schedules only
after checking the recovered environment. Do not immediately run the restored
server against the live server's devices or expose it publicly. Use an isolated
port and matching APP_ORIGIN if starting it for a drill.

A backup is a point-in-time copy: users removed after the snapshot and old
password/MFA/recovery-code state can return. Review membership and credential
changes since that date before promotion. The tool does not merge newer data,
prove freshness, supply independent rollback protection, rotate shared-vault
keys, deploy the restored service, or switch the live DATA_DIR automatically.
The independent crypto/security review and production database/deployment gates
remain open. No recurring backup scheduler or offsite transfer is configured.

On 20 October 2026 an actual schema-8 encrypted backup was restored into an
isolated ignored data directory and migrated to schema 9. Account protection,
personal/shared ciphertext, sharing identities and grants matched the source;
restored bearer grants/challenges were cleared. The live store stayed on schema
8 with unchanged protected records. No recovered service was launched or
promoted. See PASSKEY_MIGRATION.md for exact evidence and limits.

## Implementation references

- [Python SQLite Connection.backup](https://docs.python.org/3.13/library/sqlite3.html#sqlite3.Connection.backup)
- [SQLite online backup consistency](https://sqlite.org/backup.html)
- [Cryptography AESGCM and authenticated decryption](https://cryptography.io/en/stable/hazmat/primitives/aead/#cryptography.hazmat.primitives.ciphers.aead.AESGCM)
