"""Bind helper build metadata to the exact source shipped with the server.

This detects stale builds; it is not a publisher signature or an independent
attestation that a binary was built from those sources.
"""
import hashlib
from pathlib import Path

SOURCE_ROOT = Path(__file__).resolve().parent
COMMON = ('device_agent.py', 'helper_client.py', 'helper_desktop.py',
          'macos_posture.py', 'helper_artifacts.py')
WINDOWS = COMMON + ('helper_windows.py', 'build_helper.py', 'helper-build-requirements.txt')
MACOS = COMMON + ('helper_macos.py', 'macos_keychain.py', 'build_helper_macos.py',
                  'helper-macos-build-requirements.txt')


def source_inventory(platform, root=None):
    root = Path(root or SOURCE_ROOT)
    if platform == 'windows-x64':
        names = WINDOWS
    elif platform in {'macos-arm64', 'macos-x86_64'}:
        names = MACOS
    else:
        raise ValueError('Unsupported helper platform.')
    result = {}
    for name in names:
        path = root / name
        if path.is_symlink() or path.is_junction() or not path.is_file():
            raise ValueError('Helper source is missing or linked.')
        # Git checkouts on Windows can use CRLF while the Linux server uses LF.
        # These text sources must compare across native builders and hosts.
        result[name] = hashlib.sha256(path.read_bytes().replace(b'\r\n', b'\n')).hexdigest()
    return result
