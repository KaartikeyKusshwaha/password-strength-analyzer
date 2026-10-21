import json
import os
from pathlib import Path
from zipfile import ZipFile

import pytest
from companion.package_extension import package_extension, REQUIRED


def build(tmp_path):
    dist = tmp_path / 'dist'
    dist.mkdir()
    manifest = {'manifest_version':3, 'version':'0.13.0', 'permissions':['storage','activeTab']}
    source = tmp_path / 'source-manifest.json'
    source.write_text(json.dumps(manifest), encoding='utf-8')
    for name in REQUIRED:
        (dist / name).write_text(json.dumps(manifest) if name == 'manifest.json' else 'public fixture', encoding='utf-8')
    (dist / 'assets').mkdir()
    (dist / 'assets' / 'popup.js').write_text('public bundled fixture', encoding='utf-8')
    return dist, tmp_path / 'extension.zip', source


def test_same_payload_has_identical_archive_despite_file_timestamps(tmp_path):
    dist, output, source = build(tmp_path)
    first = package_extension(dist, output, source)
    archive_bytes = output.read_bytes()
    for file in dist.rglob('*'):
        os.utime(file, (1_700_000_000, 1_700_000_000))
    assert package_extension(dist, output, source) == first
    assert output.read_bytes() == archive_bytes
    with ZipFile(output) as archive:
        assert archive.namelist() == sorted(first['files'])
        assert archive.testzip() is None
        assert all(info.date_time == (1980, 1, 1, 0, 0, 0) for info in archive.infolist())

def test_monitoring_requires_the_built_worker_not_the_public_source_copy(tmp_path):
    dist,output,source=build(tmp_path)
    manifest=json.loads(source.read_text(encoding='utf-8'));manifest['permissions'].append('alarms')
    source.write_text(json.dumps(manifest),encoding='utf-8');(dist/'manifest.json').write_text(json.dumps(manifest),encoding='utf-8')
    with pytest.raises(ValueError,match='monitoring background bundle'):package_extension(dist,output,source)
    (dist/'background.js').write_text("globalThis.sentinelMonitorProtocol='sentinel-site-monitor/v1';",encoding='utf-8')
    assert package_extension(dist,output,source)['version']=='0.13.0'


@pytest.mark.parametrize('extra', ['.env', 'token.json', 'assets/source.js.map', 'assets/keys.json', 'assets/.private.js'])
def test_unexpected_files_fail_without_overwriting_previous_package(tmp_path, extra):
    dist, output, source = build(tmp_path)
    package_extension(dist, output, source)
    original = output.read_bytes()
    (dist / extra).write_text('private fixture', encoding='utf-8')
    with pytest.raises(ValueError, match='Unexpected build file'):
        package_extension(dist, output, source)
    assert output.read_bytes() == original


def test_missing_entry_stale_manifest_and_detectable_secret_fail_closed(tmp_path):
    dist, output, source = build(tmp_path)
    (dist / 'popup.html').unlink()
    with pytest.raises(ValueError, match='Build both'):
        package_extension(dist, output, source)
    (dist / 'popup.html').write_text('public fixture', encoding='utf-8')
    source.write_text('{"manifest_version":3,"version":"9.0.0"}', encoding='utf-8')
    with pytest.raises(ValueError, match='differs from source'):
        package_extension(dist, output, source)
    source.write_bytes((dist / 'manifest.json').read_bytes())
    (dist / 'assets' / 'popup.js').write_text('gsk_' + 'x' * 32, encoding='utf-8')
    with pytest.raises(ValueError, match='Credential-like content'):
        package_extension(dist, output, source)
    assert not output.exists()


def test_output_must_not_be_an_input_and_symlinks_are_rejected(tmp_path):
    dist, output, source = build(tmp_path)
    with pytest.raises(ValueError, match='outside'):
        package_extension(dist, dist / 'extension.zip', source)
    try:
        (dist / 'assets' / 'linked.js').symlink_to(source)
    except OSError:
        pytest.skip('This machine cannot create unprivileged symlinks.')
    with pytest.raises(ValueError, match='Symlinks'):
        package_extension(dist, output, source)


def test_symlink_rejection_without_os_privileges(tmp_path, monkeypatch):
    dist, output, source = build(tmp_path)
    candidate = dist / 'assets' / 'popup.js'
    original = Path.is_symlink
    monkeypatch.setattr(Path, 'is_symlink', lambda file: file == candidate or original(file))
    with pytest.raises(ValueError, match='Symlinks'):
        package_extension(dist, output, source)
    assert not output.exists()


def test_non_object_manifest_has_explicit_error(tmp_path):
    dist, output, source = build(tmp_path)
    (dist / 'manifest.json').write_text('[]', encoding='utf-8')
    source.write_text('[]', encoding='utf-8')
    with pytest.raises(ValueError, match='JSON objects'):
        package_extension(dist, output, source)


def test_interrupted_zip_write_preserves_previous_package_and_cleans_temporary_file(tmp_path, monkeypatch):
    dist, output, source = build(tmp_path)
    package_extension(dist, output, source)
    original = output.read_bytes()
    def failed_write(*args, **kwargs):
        raise OSError('fixture disk write failure')
    monkeypatch.setattr(ZipFile, 'writestr', failed_write)
    with pytest.raises(OSError, match='fixture disk write failure'):
        package_extension(dist, output, source)
    assert output.read_bytes() == original
    assert not list(tmp_path.glob('*.tmp'))
