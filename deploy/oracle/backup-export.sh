#!/usr/bin/env bash
# Fixed root-owned command invoked over pinned SSH. stdout is ciphertext only.
set -euo pipefail
umask 077
if [[ $EUID -ne 0 || $# -ne 0 ]]; then
  echo 'This fixed backup exporter requires root and accepts no arguments.' >&2
  exit 2
fi
cd /opt/sentinelops/current
temporary=$(mktemp -d /var/backups/sentinelops/.export-XXXXXXXX)
output="$temporary/snapshot.sentinelbackup"
cleanup() { rm -f -- "$output"; rmdir -- "$temporary"; }
trap cleanup EXIT
.venv/bin/python -m backend.backups create \
  --data-dir /var/lib/sentinelops \
  --key-file /etc/sentinelops/backup.key \
  --output "$output" >/dev/null
cat -- "$output"
