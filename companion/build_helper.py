"""Build the unsigned Windows pilot helper without requiring Python on user devices."""
import hashlib
import importlib.metadata
import json
import os
from pathlib import Path
import subprocess
import sys
from companion.helper_client import VERSION
from companion.helper_artifacts import source_inventory

ROOT=Path(__file__).resolve().parents[1]

def build(output=None,work=None):
    if os.name!='nt':raise ValueError('Build the Windows helper on Windows.')
    if importlib.metadata.version('pyinstaller')!='6.22.3':raise ValueError('Use the pinned helper build requirements.')
    output=Path(output or ROOT/'companion/helper-dist').resolve();work=Path(work or ROOT/'data/helper-build').resolve()
    output.mkdir(parents=True,exist_ok=True);work.mkdir(parents=True,exist_ok=True)
    command=[sys.executable,'-m','PyInstaller','--onefile','--windowed','--noconfirm','--clean','--name','SentinelOpsDeviceHelper','--paths',str(ROOT),'--distpath',str(output),'--workpath',str(work/'work'),'--specpath',str(work)]
    license_file=Path(sys.base_prefix)/'LICENSE.txt'
    if not license_file.is_file():raise ValueError('Python license must be included in the helper bundle.')
    pyinstaller_license=Path(importlib.metadata.distribution('pyinstaller').locate_file('pyinstaller-6.22.3.dist-info/licenses/COPYING.txt'))
    if not pyinstaller_license.is_file():raise ValueError('PyInstaller license must be included.')
    command+=['--add-data',str(license_file)+os.pathsep+'licenses/python','--add-data',str(pyinstaller_license)+os.pathsep+'licenses/pyinstaller',str(ROOT/'companion/helper_windows.py')]
    source_before=source_inventory('windows-x64')
    subprocess.run(command,cwd=ROOT,check=True)
    if source_inventory('windows-x64')!=source_before:raise ValueError('Helper source changed during build; rebuild before publishing.')
    artifact=output/'SentinelOpsDeviceHelper.exe'
    metadata={'version':VERSION,'sha256':hashlib.sha256(artifact.read_bytes()).hexdigest(),'bytes':artifact.stat().st_size,'platform':'windows-x64','signed':False,'builder':'PyInstaller 6.22.3','sources':source_before}
    (output/'helper-manifest.json').write_text(json.dumps(metadata,indent=2)+'\n',encoding='utf-8')
    return metadata

if __name__=='__main__':print(json.dumps(build(),indent=2))
