"""Build a deterministic companion ZIP from a validated, already-built directory."""
import hashlib
import json
import re
import tempfile
from pathlib import Path
from zipfile import ZipFile, ZipInfo, ZIP_DEFLATED

ROOT = Path(__file__).resolve().parent / 'extension'
REQUIRED = {'manifest.json', 'content.js', 'background.js', 'popup.html', 'vault-frame.html'}
ASSET_SUFFIXES = {'.js', '.css', '.wasm'}
SECRET_MARKERS = re.compile(rb'gsk_[A-Za-z0-9]{24,}|-----BEGIN (?:RSA |EC |OPENSSH |ENCRYPTED )?PRIVATE KEY-----')


def linked(path):
    return path.is_symlink() or getattr(path, 'is_junction', lambda: False)()


def package_extension(dist=ROOT / 'dist', output=ROOT / 'sentinelops-companion.zip', source_manifest=ROOT / 'public' / 'manifest.json'):
    dist, output, source_manifest = Path(dist), Path(output), Path(source_manifest)
    if linked(dist) or not dist.is_dir():
        raise ValueError('Build both content and popup bundles before packaging.')
    if output.resolve().is_relative_to(dist.resolve()):
        raise ValueError('Package output must be outside the build directory.')
    payload = {}
    for file in sorted(dist.rglob('*')):
        if linked(file):
            raise ValueError('Symlinks and junctions are not permitted in an extension package.')
        if file.is_dir():
            continue
        name = file.relative_to(dist).as_posix()
        if name not in REQUIRED and not (len(file.relative_to(dist).parts) == 2 and name.startswith('assets/') and file.suffix in ASSET_SUFFIXES and not file.name.startswith('.')):
            raise ValueError('Unexpected build file; only extension entry points and bundled assets are permitted.')
        size = file.stat().st_size
        if size > 16 * 1024 * 1024:
            raise ValueError('Extension file exceeds the package size bound.')
        if len(payload) >= 100 or sum(map(len, payload.values())) + size > 32 * 1024 * 1024:
            raise ValueError('Extension package exceeds the file count or size bound.')
        content = file.read_bytes()
        if SECRET_MARKERS.search(content):
            raise ValueError('Credential-like content detected; package not written. Review the local build privately.')
        payload[name] = content
    if not REQUIRED.issubset(payload):
        raise ValueError('Build both content and popup bundles before packaging.')
    if len(payload) > 100 or sum(map(len, payload.values())) > 32 * 1024 * 1024:
        raise ValueError('Extension package exceeds the file count or size bound.')
    try:
        manifest = json.loads(payload['manifest.json'])
        source = json.loads(source_manifest.read_text(encoding='utf-8'))
    except (ValueError, UnicodeError, OSError) as error:
        raise ValueError('The built and source manifests must be readable JSON.') from error
    if not isinstance(manifest, dict) or not isinstance(source, dict):
        raise ValueError('Extension manifests must be JSON objects.')
    if manifest != source:
        raise ValueError('Built manifest differs from source; rebuild before packaging.')
    if 'alarms' in manifest.get('permissions',[]) and b'sentinel-site-monitor/v1' not in payload['background.js']:
        raise ValueError('Build the monitoring background bundle before packaging.')
    if manifest.get('manifest_version') != 3 or not re.fullmatch(r'\d+\.\d+\.\d+(?:\.\d+)?', str(manifest.get('version', ''))):
        raise ValueError('A versioned Manifest V3 build is required.')
    # Fixed order, timestamps, permissions and compression omit machine metadata.
    # Build reproducibility still depends on the pinned sources and toolchain.
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(dir=output.parent, suffix='.tmp', delete=False) as handle:
            temporary = Path(handle.name)
        with ZipFile(temporary, 'w', compression=ZIP_DEFLATED, compresslevel=9) as archive:
            for name, content in sorted(payload.items()):
                info = ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
                info.create_system = 3
                info.external_attr = 0o100644 << 16
                info.compress_type = ZIP_DEFLATED
                archive.writestr(info, content, compresslevel=9)
        digest = hashlib.sha256(temporary.read_bytes()).hexdigest()
        temporary.replace(output)
    finally:
        if temporary and temporary.exists():
            temporary.unlink()
    return {'version':manifest['version'], 'sha256':digest,
            'files':{name:hashlib.sha256(content).hexdigest() for name,content in sorted(payload.items())},
            'uncompressed_bytes':sum(map(len,payload.values()))}


if __name__ == '__main__':
    try:
        report = package_extension()
    except (ValueError, OSError) as error:
        raise SystemExit(str(error)) from None
    print(json.dumps(report, indent=2))
