# Oracle pilot deployment (no Docker)

Target: a dedicated Ubuntu 24.04 Oracle Compute VM with persistent boot storage.
The Python API serves the React build and runs one worker process; Caddy terminates
HTTPS. SQLite and the server encryption key live outside the release directory.
This is a pilot deployment, not an independently audited production release.

## Account and VM

Use the existing OCI tenancy and home region. Check remaining Always Free compute,
memory and boot-volume allowances in the account before provisioning; do not
assume a shape is free from its name alone. Choose only resources shown eligible
within the remaining free allowance. Free capacity can be unavailable and idle
VMs may be reclaimed. A paid shape or account upgrade needs a separate user choice.

Use a dedicated SSH key and restrict SSH ingress to the operator's public IP.
Permit inbound TCP 80 and 443 in the OCI VCN/security rules and host firewall.
Do not expose TCP 8110 or database ports. Point a controlled DNS hostname to the
public VM address before requesting HTTPS. No domain purchase is included.

## Build locally, stage, inspect, then install

1. Run the React and companion build/package commands from the main README.
2. Run `.venv\Scripts\python.exe deploy/build_release.py` from the repository root.
   This writes `data/deploy/sentinelops-release.tar.gz` and prints its SHA-256.
   The selected payload includes Python modules, built frontend, packaged
   companion and deployment templates. It excludes local .env, SQLite databases,
   keys, browser/device connections, tests and working data.
3. Transfer the archive and `deploy/oracle/install.sh` to the VM over SSH/SCP.
   Compare the archive SHA-256 on both machines. Inspect release-manifest.json.
4. On a fresh VM run:
   `sudo bash install.sh /home/ubuntu/sentinelops-release.tar.gz security.your-domain.com`
   The script refuses an existing SentinelOps deployment and an active Caddy
   installation. It installs Ubuntu packages and Python dependencies, sets up an
   unprivileged systemd service, and configures HTTPS. It does not modify OCI
   ingress rules, purchase a domain, migrate local accounts or configure AI keys.
5. Verify `systemctl status sentinelops caddy`, HTTPS certificate validity and
   the owner bootstrap screen. Privately read `/var/lib/sentinelops/.bootstrap-token`
   through SSH and create the owner in the browser. Never publish the token.
6. Set the Groq key privately in `/etc/sentinelops/app.env` and restart only the
   SentinelOps service. Configure exact SCAN_HOSTS only for authorized websites.
   Source keys and local data are not automatically uploaded by this bundle.

The service binds 127.0.0.1:8110 and trusts proxy headers only from loopback.
APP_ORIGIN must match the public HTTPS hostname for secure cookies and origin
checks. DATA_DIR is /var/lib/sentinelops with private permissions. Exactly one
worker is deliberate: the current SQLite/scheduler architecture is single-process.
Users' devices need paired agents; the cloud host is not scanned in their place.

## Data, backup and release limits

This fresh install creates a new cloud owner and empty database. Moving existing
accounts requires an explicitly planned encrypted backup/restore, preserving the
server encryption key and accounting for connection/session revocation. Do not
copy a live SQLite file. See ../../docs/BACKUP_RECOVERY.md.

Before valuable data is stored, configure encrypted backups with a separate key,
off-device copies and a restore drill. The optional `backup.sh`,
`sentinelops-backup.service` and `sentinelops-backup.timer` templates create an
encrypted online snapshot daily at 02:30 UTC (with up to ten minutes of jitter).
Install the script as `/usr/local/sbin/sentinelops-backup`, install the units in
`/etc/systemd/system`, create a root-only `/var/backups/sentinelops` directory,
and generate `/etc/sentinelops/backup.key` with the backup CLI before enabling
the timer. Keep a protected copy of that key off the VM. The fresh installer
does not enable these optional units automatically.

Snapshots remain on the VM until an operator copies them elsewhere. A timer
alone does not protect against VM/disk loss. The release now includes the
optional fixed `backup-export.sh` command; ../../docs/OFFSERVER_BACKUPS.md covers
the authenticated PC pull and verification-first daily Windows task. Neither is
activated by the fresh installer. No automatic retention deletion is configured;
monitor storage and arrange retention deliberately.
Database migration, recurring offsite retention and independent security review
remain deployment gates. Update/rollback is also a separate
procedure requiring a pre-update backup; rerunning this fresh installer refuses
to overwrite an existing deployment.

Current preparation has automated archive tests and shell syntax validation.
Only an actual VM install, HTTPS check, persistent-data/restart checks and browser
acceptance can establish successful hosting. No such hosting result is implied by
the presence of these files.
