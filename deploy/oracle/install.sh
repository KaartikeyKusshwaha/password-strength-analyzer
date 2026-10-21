#!/usr/bin/env bash
# Fresh Ubuntu 24.04 VM only. Run as root after reviewing the staged release.
set -euo pipefail
umask 077
if [[ $EUID -ne 0 || $# -ne 2 ]]; then
  echo 'Usage: sudo bash install.sh /absolute/release.tar.gz security.your-domain.com' >&2
  exit 2
fi
bundle=$(realpath -- "$1")
domain=$2
if [[ ! $domain =~ ^([a-z0-9]([a-z0-9-]*[a-z0-9])?\.)+[a-z]{2,63}$ || ${#domain} -gt 253 ]]; then
  echo 'Provide an exact lowercase DNS hostname, without scheme, path or port.' >&2
  exit 2
fi
if [[ -e /opt/sentinelops/current || -e /etc/sentinelops/app.env || -e /var/lib/sentinelops/sentinelops.db ]]; then
  echo 'Existing installation detected. Refusing to replace its code, configuration or data.' >&2
  exit 2
fi
source /etc/os-release
if [[ $ID != ubuntu || $VERSION_ID != 24.04 ]]; then
  echo 'This installer targets Ubuntu 24.04. Review dependencies for other images.' >&2
  exit 2
fi
if [[ -s /etc/caddy/Caddyfile ]] && systemctl is-active --quiet caddy; then
  echo 'An active Caddy service already exists; review its sites before continuing.' >&2
  exit 2
fi
apt-get update
DEBIAN_FRONTEND=noninteractive apt-get install -y python3-venv python3-pip caddy
id sentinelops >/dev/null 2>&1 || useradd --system --home-dir /var/lib/sentinelops --shell /usr/sbin/nologin sentinelops
install -d -m 0755 /opt/sentinelops/current
install -d -m 0700 -o sentinelops -g sentinelops /var/lib/sentinelops
install -d -m 0750 -o root -g sentinelops /etc/sentinelops
# Python's data filter rejects escaping paths, links, devices and unsafe modes.
python3 - "$bundle" <<'PY'
import hashlib, json, sys, tarfile
with tarfile.open(sys.argv[1], 'r:gz') as archive:
    members = archive.getmembers()
    names = [member.name for member in members]
    if len(names) != len(set(names)) or any(not member.isfile() for member in members):
        raise SystemExit('Release contains unexpected non-file entries.')
    manifest = json.load(archive.extractfile('release-manifest.json'))
    if set(names) != set(manifest['files']) | {'release-manifest.json'}:
        raise SystemExit('Release file inventory differs from manifest.')
    for name, digest in manifest['files'].items():
        if hashlib.sha256(archive.extractfile(name).read()).hexdigest() != digest:
            raise SystemExit('Release file checksum mismatch.')
    archive.extractall('/opt/sentinelops/current', filter='data')
PY
python3 -m venv /opt/sentinelops/current/.venv
/opt/sentinelops/current/.venv/bin/python -m pip install -r /opt/sentinelops/current/requirements.txt
chown -R root:root /opt/sentinelops/current
chmod -R go-w /opt/sentinelops/current
printf 'APP_ORIGIN=https://%s\nDATA_DIR=/var/lib/sentinelops\nSCAN_HOSTS=\nGROQ_API_KEY=\nGROQ_MODEL=openai/gpt-oss-120b\n' "$domain" > /etc/sentinelops/app.env
chown root:sentinelops /etc/sentinelops/app.env
chmod 0640 /etc/sentinelops/app.env
install -m 0644 /opt/sentinelops/current/deploy/oracle/sentinelops.service /etc/systemd/system/sentinelops.service
systemctl daemon-reload
systemctl enable --now sentinelops
printf '%s {\n    encode zstd gzip\n    reverse_proxy 127.0.0.1:8110\n}\n' "$domain" > /etc/caddy/Caddyfile
caddy validate --config /etc/caddy/Caddyfile
systemctl enable --now caddy
systemctl reload caddy
echo 'Services started. Verify HTTPS, create the owner account privately, then configure AI and backups.'
echo 'Bootstrap token file: /var/lib/sentinelops/.bootstrap-token (read only over your SSH session).'
echo 'Keep TCP 8110 private. Permit public TCP 80/443 and restrict SSH to your IP in OCI and the OS firewall.'
