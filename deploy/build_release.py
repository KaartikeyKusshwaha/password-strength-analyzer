"""Package a deployment without local accounts, credentials, data or test fixtures."""
import gzip
import hashlib
import io
import json
import tarfile
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:sys.path.insert(0,str(ROOT))
from deploy.build_provenance import verify


def build_release(root=ROOT, output=None, *, build_root=None):
    root = Path(root).resolve()
    build_root=Path(build_root or root).resolve()
    output = Path(output or root / 'data' / 'deploy' / 'sentinelops-release.tar.gz')
    fixed = ['requirements.txt', 'run.py', 'backend/postgres_layout.json', 'backend/public/proof.html',
             'backend/public/proof-view.js', 'backend/public/proof-view.css',
             'companion/__init__.py', 'companion/device_agent.py',
             'companion/extension/sentinelops-companion.zip', 'frontend/dist/index.html',
             'deploy/oracle/sentinelops.service', 'deploy/oracle/install.sh',
             'deploy/oracle/app.env.example', 'deploy/oracle/Caddyfile.example',
             'deploy/oracle/backup.sh', 'deploy/oracle/backup-export.sh',
             'deploy/oracle/sentinelops-backup.service', 'deploy/oracle/sentinelops-backup.timer']
    files = [(build_root if name.startswith(('frontend/dist/','companion/extension/sentinelops-companion.zip')) else root) / name for name in fixed]
    files += sorted((root / 'backend').glob('*.py'))
    helper_files=[root/'companion/helper-dist'/name for name in ('SentinelOpsDeviceHelper.exe','helper-manifest.json')]
    if any(path.exists() for path in helper_files):
        if not all(path.is_file() for path in helper_files):raise ValueError('Incomplete Windows helper build.')
        from backend.helper_status import status
        if not status(helper_files[0].parent)['available']:raise ValueError('Incomplete or unverified Windows helper build.')
        files+=helper_files
    mac_root=root/'companion/helper-macos-dist'
    if mac_root.exists():
        from backend.helper_status import macos_status
        metadata=macos_status(mac_root)
        if not metadata['available']:raise ValueError('Incomplete or unverified macOS helper build.')
        files+=[mac_root/'helper-manifest.json',mac_root/metadata['filename']]
    files += sorted(path for path in (build_root / 'frontend/dist/assets').glob('*') if path.suffix in {'.js', '.css', '.wasm'})
    if not (root / 'backend/app.py').is_file() or not (build_root / 'frontend/dist/assets').is_dir():
        raise ValueError('Build the application before packaging its deployment.')
    payload = {}
    for file in files:
        base=build_root if file.is_relative_to(build_root) and (file.is_relative_to(build_root/'frontend/dist') or file==build_root/'companion/extension/sentinelops-companion.zip') else root
        if not file.is_file() or file.is_symlink() or not file.resolve().is_relative_to(base):
            raise ValueError('Required deployment file is missing or linked outside the project.')
        name = file.relative_to(base).as_posix()
        content = file.read_bytes()
        # Windows checkout settings must not make shell/configuration files fail on Linux.
        if name.startswith('deploy/oracle/'):
            content = content.replace(b'\r\n', b'\n')
        payload[name] = content
    # Recheck the bytes already read, so a helper replaced after its status check
    # cannot be packaged with a checksum belonging to a different binary.
    for platform_root,artifact_name in (('companion/helper-dist','SentinelOpsDeviceHelper.exe'),('companion/helper-macos-dist',None)):
        metadata_bytes=payload.get(platform_root+'/helper-manifest.json')
        if metadata_bytes is None:continue
        metadata=json.loads(metadata_bytes)
        name=artifact_name or 'SentinelOpsDeviceHelper-'+metadata['platform']+'.zip'
        artifact=payload.get(platform_root+'/'+name,b'')
        if len(artifact)!=metadata['bytes'] or hashlib.sha256(artifact).hexdigest()!=metadata['sha256']:
            raise ValueError('Helper build changed during release packaging.')
    if not any(name.startswith('frontend/dist/assets/') for name in payload):
        raise ValueError('No frontend assets found.')
    provenance=verify(root,build_root)
    # Compare the bytes already read into this archive, not just a second view of
    # the output files, so concurrent output changes cannot produce a mixed pack.
    if any(hashlib.sha256(payload.get(name,b'')).hexdigest()!=checksum for name,checksum in provenance['outputs'].items()):
        raise ValueError('Build outputs changed during release packaging.')
    revision=provenance['revision']
    payload['build-provenance.json']=(json.dumps(provenance,sort_keys=True,indent=2)+'\n').encode()
    manifest = {'revision':revision, 'source_digest':provenance['source_digest'], 'files':{name:hashlib.sha256(content).hexdigest() for name,content in sorted(payload.items())}}
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
