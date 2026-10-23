"""Native macOS pilot app build; no Developer ID/notarization or paid services."""
import hashlib
import importlib.metadata
import json
import platform
import subprocess
import sys
from pathlib import Path
from companion.helper_client import VERSION
from companion.helper_macos import APP,BUNDLE,checked_bundle

ROOT=Path(__file__).resolve().parents[1]

def build(output=None,work=None):
    if platform.system()!='Darwin':raise ValueError('A native macOS builder is required; no cross-built app was produced.')
    arch=platform.machine()
    if arch not in {'arm64','x86_64'}:raise ValueError('Unsupported Mac builder architecture.')
    for package,version in [('pyinstaller','6.22.3'),('pyobjc-core','12.2.2'),('pyobjc-framework-Security','12.2.2')]:
        if importlib.metadata.version(package)!=version:raise ValueError('Use the pinned macOS helper build requirements.')
    output=Path(output or ROOT/'companion/helper-macos-dist').resolve();work=Path(work or ROOT/'data/helper-macos-build').resolve()
    output.mkdir(parents=True,exist_ok=True);work.mkdir(parents=True,exist_ok=True)
    license_file=next((p for p in [Path(sys.base_prefix)/'LICENSE.txt',Path(sys.base_prefix)/'lib'/('python'+str(sys.version_info.major)+'.'+str(sys.version_info.minor))/'LICENSE.txt'] if p.is_file()),None)
    if license_file is None:raise ValueError('The native Python distribution must include its LICENSE.txt before bundling.')
    pyinstaller_license=Path(importlib.metadata.distribution('pyinstaller').locate_file('pyinstaller-6.22.3.dist-info/licenses/COPYING.txt'))
    if not pyinstaller_license.is_file():raise ValueError('PyInstaller license must be included.')
    command=[sys.executable,'-m','PyInstaller','--onedir','--windowed','--noconfirm','--clean','--name','SentinelOpsDeviceHelper','--osx-bundle-identifier',BUNDLE,'--target-architecture',arch,'--paths',str(ROOT),'--distpath',str(output),'--workpath',str(work/'work'),'--specpath',str(work),'--hidden-import','Security','--add-data',str(license_file)+':licenses/python','--add-data',str(pyinstaller_license)+':licenses/pyinstaller',str(ROOT/'companion/helper_macos.py')]
    for package in ('pyobjc-core','pyobjc-framework-Security','pyobjc-framework-Cocoa','certifi'):
        distribution=importlib.metadata.distribution(package)
        licenses=[Path(distribution.locate_file(name)) for name in distribution.files or [] if name.name.lower() in {'license','license.txt','license.rst','copying'}]
        if not licenses:
            fallback=ROOT/'companion/licenses'/(package+'-'+distribution.version+'-LICENSE.txt')
            metadata=json.loads((ROOT/'companion/licenses/source-manifest.json').read_text(encoding='utf-8'))
            if not fallback.is_file() or hashlib.sha256(fallback.read_bytes()).hexdigest()!=metadata.get(fallback.name,{}).get('license_sha256'):raise ValueError('Dependency license is missing: '+package)
            licenses=[fallback]
        for license in licenses:command[3:3]=['--add-data',str(license)+':licenses/'+package]
    subprocess.run(command,cwd=ROOT,check=True)
    app=checked_bundle(output/APP)
    artifact=output/('SentinelOpsDeviceHelper-macos-'+arch+'.zip')
    subprocess.run(['/usr/bin/ditto','-c','-k','--sequesterRsrc','--keepParent',str(app),str(artifact)],stdin=subprocess.DEVNULL,check=True,timeout=120)
    sources=['device_agent.py','helper_client.py','helper_desktop.py','helper_macos.py','macos_keychain.py','macos_posture.py','build_helper_macos.py']
    metadata={'version':VERSION,'platform':'macos-'+arch,'sha256':hashlib.sha256(artifact.read_bytes()).hexdigest(),'bytes':artifact.stat().st_size,'signed':False,'signature':'PyInstaller ad-hoc only; no trusted Developer ID','notarized':False,'builder':'PyInstaller 6.22.3','sources':{name:hashlib.sha256((ROOT/'companion'/name).read_bytes()).hexdigest() for name in sources}}
    (output/'helper-manifest.json').write_text(json.dumps(metadata,indent=2)+'\n',encoding='utf-8')
    return metadata

if __name__=='__main__':print(json.dumps(build(),indent=2))
