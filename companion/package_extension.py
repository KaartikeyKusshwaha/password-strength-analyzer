from pathlib import Path
from zipfile import ZipFile, ZIP_DEFLATED

root = Path(__file__).resolve().parent / 'extension'
dist = root / 'dist'
required = ['manifest.json','content.js','background.js','popup.html','vault-frame.html']
if not all((dist / name).is_file() for name in required):
    raise SystemExit('Build both content and popup bundles before packaging.')
with ZipFile(root / 'sentinelops-companion.zip', 'w', ZIP_DEFLATED) as archive:
    for file in sorted(dist.rglob('*')):
        if file.is_file():
            archive.write(file, file.relative_to(dist))
print('Packaged SentinelOps companion without credentials or local configuration.')
