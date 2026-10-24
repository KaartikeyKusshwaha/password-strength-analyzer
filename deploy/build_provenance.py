"""Bind local release output bytes to a source inventory and Git revision.

This is a stale-build guard, not a publisher signature or independent attestation.
"""
import hashlib
import json
from pathlib import Path
import re
import subprocess

def hashed(path, root):
    if path.is_symlink() or getattr(path,'is_junction',lambda:False)() or not path.is_file() or not path.resolve().is_relative_to(root.resolve()):
        raise ValueError('Release provenance refuses missing or linked files.')
    with path.open('rb') as handle:return hashlib.file_digest(handle,'sha256').hexdigest()


def source_digest(root):
    root=Path(root)
    files=set()
    for name in ('requirements.txt','run.py','backend/postgres_layout.json','Dockerfile','render.yaml','.dockerignore','frontend/index.html','frontend/package.json','frontend/package-lock.json','frontend/vite.config.js'):
        path=root/name
        if path.exists():files.add(path)
    for name in ('backend','frontend/src','companion','deploy'):
        directory=root/name
        for path in directory.rglob('*'):
            relative=path.relative_to(directory)
            if any(part in {'node_modules','dist','__pycache__','helper-dist','helper-macos-dist'} for part in relative.parts):continue
            if name=='frontend/src' and path.is_file() or path.suffix in {'.py','.js','.jsx','.css','.html','.sh','.ps1','.service','.timer','.example'} or name=='companion' and path.as_posix().endswith('/extension/public/manifest.json'):
                if path.is_file():files.add(path)
    inventory={path.relative_to(root).as_posix():hashed(path,root) for path in sorted(files)}
    if not inventory:raise ValueError('No release source inventory found.')
    return hashlib.sha256(json.dumps(inventory,sort_keys=True,separators=(',',':')).encode()).hexdigest()


def revision(root):
    try:value=subprocess.check_output(['git','rev-parse','HEAD'],cwd=root,text=True).strip()
    except (OSError,subprocess.CalledProcessError):raise ValueError('A Git revision is required for release provenance.') from None
    if not re.fullmatch(r'[a-f0-9]{40,64}',value):raise ValueError('Invalid Git revision.')
    return value


def outputs(build_root):
    build_root=Path(build_root)
    files=[build_root/'frontend/dist/index.html',build_root/'companion/extension/sentinelops-companion.zip']
    files+=sorted(path for path in (build_root/'frontend/dist/assets').glob('*') if path.suffix in {'.js','.css','.wasm'})
    if len(files)<3:raise ValueError('No frontend assets found.')
    return {file.relative_to(build_root).as_posix():hashed(file,build_root) for file in files}


def stamp(root,build_root,expected_source):
    if source_digest(root)!=expected_source:raise ValueError('Sources changed during build; prepare a new candidate.')
    value={'format':1,'revision':revision(root),'source_digest':expected_source,'outputs':outputs(build_root)}
    path=Path(build_root)/'build-provenance.json'
    with path.open('x',encoding='utf-8') as handle:json.dump(value,handle,sort_keys=True,indent=2);handle.write('\n')
    return value


def verify(root,build_root):
    path=Path(build_root)/'build-provenance.json'
    try:
        if path.is_symlink() or path.stat().st_size>128*1024:raise ValueError()
        value=json.loads(path.read_text(encoding='utf-8'))
        if set(value)!={'format','revision','source_digest','outputs'} or value['format']!=1 or value['revision']!=revision(root) or value['source_digest']!=source_digest(root) or value['outputs']!=outputs(build_root):raise ValueError()
    except (OSError,ValueError,TypeError,KeyError):
        raise ValueError('Missing, changed or stale release build provenance; prepare a new candidate.') from None
    return value
