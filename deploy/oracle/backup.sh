#!/usr/bin/env bash
# Invoked by the optional pilot backup timer. Never writes plaintext snapshots.
set -euo pipefail
umask 077
cd /opt/sentinelops/current
output="/var/backups/sentinelops/$(date -u +%Y%m%dT%H%M%SZ).sentinelbackup"
exec .venv/bin/python -m backend.backups create \
  --data-dir /var/lib/sentinelops \
  --key-file /etc/sentinelops/backup.key \
  --output "$output"
