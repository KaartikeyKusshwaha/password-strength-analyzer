"""Public build metadata; no device identity or bearer credentials."""
import json
import re
import hashlib
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]/'companion/helper-dist'

def status(root=ROOT):
    root=Path(root)
    try:
        manifest=root/'helper-manifest.json'
        if manifest.is_symlink() or not manifest.is_file() or manifest.stat().st_size>16_384:raise ValueError()
        value=json.loads(manifest.read_text(encoding='utf-8'))
        artifact=root/'SentinelOpsDeviceHelper.exe'
        if artifact.is_symlink() or not artifact.is_file() or value['platform']!='windows-x64' or not re.fullmatch(r'\d+\.\d+\.\d+',value['version']) or not re.fullmatch(r'[a-f0-9]{64}',value['sha256']) or type(value['bytes']) is not int or value['bytes']!=artifact.stat().st_size or not 1_000_000<=value['bytes']<=40_000_000 or value['signed'] is not False:raise ValueError()
        with artifact.open('rb') as handle:
            if hashlib.file_digest(handle,'sha256').hexdigest()!=value['sha256']:raise ValueError()
        return {'available':True,'version':value['version'],'sha256':value['sha256'],'bytes':value['bytes'],'signed':False,'platform':'windows-x64'}
    except (OSError,ValueError,KeyError,TypeError):return {'available':False}

def macos_status(root=None):
    root=Path(root or ROOT.parent/'helper-macos-dist')
    try:
        value=json.loads((root/'helper-manifest.json').read_text(encoding='utf-8'))
        platform=value['platform']
        if platform not in {'macos-arm64','macos-x86_64'}:raise ValueError()
        name='SentinelOpsDeviceHelper-'+platform+'.zip';artifact=root/name
        if artifact.is_symlink() or not artifact.is_file() or not re.fullmatch(r'\d+\.\d+\.\d+',value['version']) or not re.fullmatch(r'[a-f0-9]{64}',value['sha256']) or value['bytes']!=artifact.stat().st_size or not 1_000_000<=value['bytes']<=150_000_000 or value['signed'] is not False or value['notarized'] is not False:raise ValueError()
        with artifact.open('rb') as handle:
            if hashlib.file_digest(handle,'sha256').hexdigest()!=value['sha256']:raise ValueError()
        return {key:value[key] for key in ('version','platform','sha256','bytes','signed','notarized')}|{'available':True,'filename':name}
    except (OSError,ValueError,KeyError,TypeError):return {'available':False}
