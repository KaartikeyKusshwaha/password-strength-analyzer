"""Public build metadata; no device identity or bearer credentials."""
import json
import re
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]/'companion/helper-dist'

def status(root=ROOT):
    root=Path(root)
    try:
        value=json.loads((root/'helper-manifest.json').read_text(encoding='utf-8'))
        artifact=root/'SentinelOpsDeviceHelper.exe'
        if artifact.is_symlink() or not artifact.is_file() or not re.fullmatch(r'\d+\.\d+\.\d+',value['version']) or not re.fullmatch(r'[a-f0-9]{64}',value['sha256']) or value['bytes']!=artifact.stat().st_size or not 1_000_000<=value['bytes']<=40_000_000 or value['signed'] is not False:raise ValueError()
        return {'available':True,'version':value['version'],'sha256':value['sha256'],'bytes':value['bytes'],'signed':False,'platform':'windows-x64'}
    except (OSError,ValueError,KeyError,TypeError):return {'available':False}
