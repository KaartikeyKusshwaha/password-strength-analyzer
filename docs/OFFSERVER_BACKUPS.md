# Encrypted off-server pilot backups

The operator PC can pull an encrypted snapshot from the existing Oracle VM.
This uses existing SSH and local disk, with no new hosting or storage service.
It is not activated by installing the app or merely having these scripts.
The PC must be on, signed in and able to reach SSH. Keep an additional protected
offline copy for loss/ransomware affecting this PC. A task failure needs operator
attention; no email or third-party notification is sent.

## Server preparation

Use the previously verified SSH host key and your existing administrative access.
Do not disable host-key checks or copy private keys into the repository. Before
running these commands, review the release and verify its manifest. On the VM:

```bash
cd /opt/sentinelops/current
sudo install -d -m 0700 -o root -g root /var/backups/sentinelops
sudo /opt/sentinelops/current/.venv/bin/python -m backend.backups init-key --key-file /etc/sentinelops/backup.key
sudo install -m 0700 -o root -g root /opt/sentinelops/current/deploy/oracle/backup-export.sh /usr/local/sbin/sentinelops-backup-export
```

Run the key initialization **only if the key does not exist**; the tool refuses
replacement. Preserve the existing key when updating code. Work from the release
directory so Python imports resolve. The exporter also sets its own fixed cwd.
Copy the backup key to a separately protected local key file through your private
administrative channel; never print it in chat, terminal logs or a shared shell
history. It must stay separate from archives. Do not copy the server MFA key by
itself. Restrict parent directory and NTFS ACL access on the PC to your account.

The SSH account must already be able to invoke the exact exporter with
`sudo -n`. The fixed root-owned script accepts no arguments and produces only
encrypted bytes on stdout. This procedure does not install new sudo rules or
grant new SSH administration permissions. Do not grant broader sudo access just
to make a backup task work. A dedicated restricted backup identity may replace
the existing administrative identity after operator review.

The exporter creates a unique private encrypted temporary snapshot on the VM,
streams it and removes it on normal exit/failure. A killed process/host crash can
leave an encrypted temporary directory; inspect it deliberately. It never
creates a plaintext SQLite dump. Archive authentication still takes place on
the receiving PC before a retained copy is accepted.

## Private operator configuration

Create an empty private backup folder and a JSON configuration outside Git.
Use absolute paths. Example placeholders must be replaced locally:

```json
{
  "host": "192.0.2.1",
  "user": "ubuntu",
  "ssh_executable": "C:/Program Files/Git/usr/bin/ssh.exe",
  "ssh_key_file": "C:/PrivateKeys/sentinelops-ssh",
  "known_hosts_file": "C:/PrivateKeys/sentinelops-known-hosts",
  "backup_key_file": "C:/PrivateKeys/sentinelops-backup.key",
  "destination": "C:/PrivateBackups/SentinelOps"
}
```

The exact host key must be verified independently, not learned automatically by
this tool. The SSH executable is an explicitly trusted local program. Ambient
SSH config, agent identities, forwarding and interactive prompts are disabled.
Configuration rejects shell-shaped hosts/users and unknown fields. Quote/newline
characters in operator file paths are unsupported. Encryption/SSH keys cannot
reside under the archive destination. Do not put the destination in a public,
shared or source-control folder. Local file modes do not replace NTFS ACL review.

From the checkout, using its existing Python environment:

```powershell
.venv\Scripts\python.exe deploy\offserver_backup.py --config C:\PrivateKeys\sentinelops-backup.json
```

The transfer has a three-minute limit, checks size while receiving, and refuses
an archive above the existing 128 MiB backup bound. At least 256 MiB free space
is required. Encrypted temporary staging is removed after success or failure;
a machine crash can leave staging. Archive validation authenticates AES-GCM,
SQLite integrity, supported schema, MFA-key compatibility and audit chains in
memory. Freshness requires a timezone-aware timestamp no older than 24 hours
and no more than five minutes ahead; clock correctness is still operator-owned.
The tool does not independently attest the server's clock or prevent a malicious
administrator from creating misleading source records.

Only after validation does the tool exclusively create a timestamp/hash-named
`.sentinelbackup` and adjacent `.receipt.json`. It never replaces an earlier
archive, restores data or deletes retained backups. The receipt records its
hash, schema and validation times, with no keys or database contents. A failed
receipt write can leave a valid archive but still returns failure. Receipts are
operator records, not independent signatures. Monitor destination capacity and
choose retention deliberately; full disk causes failure rather than deletion.

## Register the daily Windows task

```powershell
.\deploy\Install-BackupTask.ps1 -Python "$PWD\.venv\Scripts\python.exe" -Config C:\PrivateKeys\sentinelops-backup.json
```

The installer performs one real authenticated pull first. Only success registers
the 04:00 local-time task, with start-when-available, no overlapping runs, a
ten-minute execution limit and the current user's interactive, limited token.
It stores no Windows password and refuses an existing task name. An offline or
signed-out PC cannot provide continuous backup coverage. Inspect execution:

```powershell
Get-ScheduledTaskInfo -TaskName 'SentinelOps encrypted off-server backup'
Get-ChildItem C:\PrivateBackups\SentinelOps -Filter '*.receipt.json'
```

An exit result of zero plus a newly validated archive/receipt establishes that
run, not future operation. Do a separate isolated restore drill with
`python -m backend.backups restore`; verify data and revoked authorization before
any disaster promotion. Neither task registration nor file transfer is a restore
test. See BACKUP_RECOVERY.md for membership rollback and credential limits.

## Current verification limits

Synthetic encrypted archive transfer/restore, tampering/wrong-key/stale rejection,
timeout/partial failure, host/configuration rejection, native Windows SSH argument
parsing and release allowlisting have automated checks. PowerShell task syntax
and exporter shell syntax are checked. No scheduled task is registered and no
server exporter/key is installed by these tests. Live SSH currently times out;
real off-server transfer, recurring execution and hosted restore acceptance are
still required. Do not describe this as an active backup service until verified.


## Neon Free pilot backup — 24 October 2026

The reachable source is now Neon, using `deploy/postgres_backup_pull.py` and
full TLS certificate/hostname validation. Oracle SSH and old archives remain
untouched. Private connection/MFA/backup keys are separate from the encrypted
archive directory and excluded from Git; their NTFS ACL grants only the current
operator account. No keys are printed in receipts or command arguments.

A real Neon export authenticated successfully at 2026-10-23T18:53:07Z (24 October
in India), schema 15, SHA-256
`5cc2283e95c76e0945bb011ca708e729cd35d5d730f38c8e8c9f5e0e78efa3ac`.
It restored into an isolated SQLite directory (integrity `ok`) and a fresh local
PostgreSQL schema, preserving the 15 migration markers and clearing bearer
state. The drill database was stopped afterward; the live source was never
imported into or changed. The snapshot contained **zero users and zero vaults**:
this proves the new installation's archive transport/schema recovery only,
not recovery of populated accounts or the old Oracle vaults.

The installer completed a second real authenticated export before registering
`SentinelOps Neon encrypted off-server backup`, daily at 04:00 local time,
interactive current user, limited token, start when available, ten-minute limit
and no overlapping runs. No Windows password, paid service or retention deletion
is configured. Actual scheduled execution must be recorded separately; task
registration alone does not prove recurring coverage. This PC must be on and
signed in with connectivity and sufficient storage.


A manually started execution through **Windows Task Scheduler** completed on
24 October at 00:25:54 IST: task state `Ready`, `LastTaskResult: 0`, and a new
authenticated receipt/archive
`20261023T185554Z-1448681d69153982.sentinelbackup` appeared. This verifies the
registered task action and current-user access, rather than just direct CLI
execution. The first **timed** daily run is due at 04:00 IST on 24 October and
has not yet been observed. It must be checked before claiming unattended daily
coverage. Existing archives are never replaced or automatically deleted.


## First real owner-account recovery drill — 24 October 2026

After user owner setup, a fresh Neon export at 2026-10-23T19:53:21Z contained
one user, one workspace and one live session (no personal/shared vaults yet).
Archive SHA-256:
`f706d4457c24ed1ac0a1cf242b07036b82fa13a4707b8f6c2d0188342b0c6116`.
Isolated SQLite restore passed integrity and exact account-ID/email/password-hash,
MFA-value and membership preservation comparisons. A separate local PostgreSQL
restore imported 22 rows at schema 15, preserved those same account/membership
fields, retained a valid audit chain, revoked the saved session and cleared the
pending MFA draft. No private account values were printed. The live source was
not modified and the local PostgreSQL drill server was stopped afterward.

The first PostgreSQL comparison incorrectly used SELECT * for members, including
its adapter-only ordering column; the corrected comparison used the declared
application columns and passed. This was a drill-assertion issue, not evidence
of lost membership or a production change.

This archive predates MFA confirmation. Subsequent browser inspection confirmed
Authenticator protection Enabled, but enrolled-MFA and saved-vault recovery need
a later snapshot/drill. The first timed 04:00 task run remains unobserved.
