"""Package a deployment without local accounts, credentials, data or test fixtures."""
import gzip
import hashlib
import io
import json
import subprocess
import tarfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def build_release(root=ROOT, output=None):
    root = Path(root).resolve()
    output = Path(output or root / 'data' / 'deploy' / 'sentinelops-release.tar.gz')
    fixed = ['requirements.txt', 'run.py', 'backend/public/proof.html',
             'backend/public/proof-view.js', 'backend/public/proof-view.css',
             'companion/__init__.py', 'companion/device_agent.py',
             'companion/extension/sentinelops-companion.zip', 'frontend/dist/index.html',
             'deploy/oracle/sentinelops.service', 'deploy/oracle/install.sh',
             'deploy/oracle/app.env.example', 'deploy/oracle/Caddyfile.example']
    files = [root / name for name in fixed]
    files += sorted((root / 'backend').glob('*.py'))
    helper_files=[root/'companion/helper-dist'/name for name in ('SentinelOpsDeviceHelper.exe','helper-manifest.json')]
    if any(path.exists() for path in helper_files):
        if not all(path.is_file() for path in helper_files):raise ValueError('Incomplete Windows helper build.')
        files+=helper_files
    files += sorted(path for path in (root / 'frontend/dist/assets').glob('*') if path.suffix in {'.js', '.css', '.wasm'})
    if not (root / 'backend/app.py').is_file() or not (root / 'frontend/dist/assets').is_dir():
        raise ValueError('Build the application before packaging its deployment.')
    payload = {}
    for file in files:
        if not file.is_file() or file.is_symlink() or not file.resolve().is_relative_to(root):
            raise ValueError('Required deployment file is missing or linked outside the project.')
        name = file.relative_to(root).as_posix()
        content = file.read_bytes()
        # Windows checkout settings must not make shell/configuration files fail on Linux.
        if name.startswith('deploy/oracle/'):
            content = content.replace(b'\r\n', b'\n')
        payload[name] = content
    if not any(name.startswith('frontend/dist/assets/') for name in payload):
        raise ValueError('No frontend assets found.')
    try:
        revision = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=root, text=True).strip()
    except (OSError, subprocess.CalledProcessError):
        raise ValueError('A Git revision is required for deployment provenance.') from None
    manifest = {'revision':revision, 'files':{name:hashlib.sha256(content).hexdigest() for name,content in sorted(payload.items())}}
    payload['release-manifest.json'] = (json.dumps(manifest, indent=2)+'\n').encode()
    output.parent.mkdir(parents=True, exist_ok=True)
    buffer = io.BytesIO()
    with gzip.GzipFile(fileobj=buffer, mode='wb', mtime=0, filename='') as compressed:
        with tarfile.open(fileobj=compressed, mode='w') as archive:
            for name, content in sorted(payload.items()):
                info = tarfile.TarInfo(name)
                info.size, info.mode, info.mtime = len(content), 0o644, 0
                archive.addfile(info, io.BytesIO(content))
    value = buffer.getvalue()
    temporary = output.with_suffix(output.suffix + '.tmp')
    try:
        temporary.write_bytes(value)
        temporary.replace(output)
    finally:
        temporary.unlink(missing_ok=True)
    return {'revision':revision, 'sha256':hashlib.sha256(value).hexdigest(), 'files':len(payload), 'bytes':len(value)}


if __name__ == '__main__':
    print(json.dumps(build_release(), indent=2))
