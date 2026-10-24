"""Per-user Windows helper installer and visible, revocable polling app."""
import hashlib
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path
from companion.helper_client import VERSION,protect,data_directory,load_connection,save_connection
from companion.device_agent import poll_once

APP='SentinelOpsDeviceHelper.exe'
UNINSTALL=r'''$ErrorActionPreference='Stop'
Add-Type -AssemblyName PresentationFramework
if([System.Windows.MessageBox]::Show('Remove SentinelOps Device Helper and its local connection? Revoke its cloud connection in SentinelOps too.','Uninstall SentinelOps','YesNo') -ne 'Yes'){exit}
$base=[IO.Path]::GetFullPath([Environment]::GetFolderPath('LocalApplicationData')).TrimEnd('\')
$target=[IO.Path]::GetFullPath((Join-Path $base 'SentinelOpsDeviceHelper'))
if([IO.Directory]::GetParent($target).FullName -ne $base -or [IO.Path]::GetFileName($target) -ne 'SentinelOpsDeviceHelper'){throw 'Invalid folder'}
if((Get-Item -LiteralPath $target).Attributes -band [IO.FileAttributes]::ReparsePoint){throw 'Linked folders unsupported'}
try { Remove-Item -LiteralPath (Join-Path $target 'SentinelOpsDeviceHelper.exe') -ErrorAction Stop } catch { [System.Windows.MessageBox]::Show('Close the helper, then run uninstall again.');exit 1 }
foreach($name in @('connection.dpapi','connection.new','uninstall.ps1')){Remove-Item -LiteralPath (Join-Path $target $name) -ErrorAction SilentlyContinue}
Remove-Item -LiteralPath (Join-Path ([Environment]::GetFolderPath('Programs')) 'SentinelOps Device Helper.lnk') -ErrorAction SilentlyContinue
Remove-Item -LiteralPath 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\SentinelOpsDeviceHelper' -ErrorAction SilentlyContinue
Remove-Item -LiteralPath $target -ErrorAction SilentlyContinue
'''

def install():
    if os.name!='nt' or not getattr(sys,'frozen',False):raise ValueError('Use the packaged Windows helper installer.')
    import winreg
    folder=data_directory();folder.mkdir(parents=True,exist_ok=True)
    target=folder/APP;source=Path(sys.executable)
    if target.is_symlink():raise ValueError('Linked application files unsupported.')
    if source.resolve()!=target.resolve() and (not target.exists() or hashlib.sha256(source.read_bytes()).digest()!=hashlib.sha256(target.read_bytes()).digest()):shutil.copyfile(source,target)
    (folder/'uninstall.ps1').write_text(UNINSTALL,encoding='utf-8-sig')
    powershell=Path(os.environ.get('SystemRoot',r'C:\Windows'))/'System32/WindowsPowerShell/v1.0/powershell.exe'
    shortcut="$ErrorActionPreference='Stop';$folder=[Environment]::GetFolderPath('Programs');$shell=New-Object -ComObject WScript.Shell;$link=$shell.CreateShortcut((Join-Path $folder 'SentinelOps Device Helper.lnk'));$link.TargetPath=Join-Path $env:LOCALAPPDATA 'SentinelOpsDeviceHelper\\SentinelOpsDeviceHelper.exe';$link.Save()"
    subprocess.run([str(powershell),'-NoLogo','-NoProfile','-NonInteractive','-Command',shortcut],stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=15,check=True,creationflags=getattr(subprocess,'CREATE_NO_WINDOW',0))
    with winreg.CreateKey(winreg.HKEY_CURRENT_USER,r'Software\Microsoft\Windows\CurrentVersion\Uninstall\SentinelOpsDeviceHelper') as key:
        for name,value in {'DisplayName':'SentinelOps Device Helper','DisplayVersion':VERSION,'Publisher':'SentinelOps community pilot','InstallLocation':str(folder),'UninstallString':f'"{powershell}" -NoProfile -File "{folder / "uninstall.ps1"}"'}.items():winreg.SetValueEx(key,name,0,winreg.REG_SZ,value)
    return folder

class WindowsAdapter:
    platform_name='Windows'
    supports_updates=True
    posture_label='Allow read-only firewall, Defender and drive-encryption status'
    updates_label='Allow cached Windows Update / restart status (no installation)'
    initial_status='Install for this Windows user and connect from the browser extension.'
    storage_note='Installed per user under Local AppData with a Start menu shortcut. The device token is protected by Windows for this user. Revoke access in SentinelOps Connections. Uninstall using Windows Installed apps.'
    def install(self):return install()
    def load(self):
        path=data_directory()/'connection.dpapi'
        return load_connection(path) if path.exists() else None
    def save(self,config):save_connection(data_directory()/'connection.dpapi',config)
    def forget(self):
        path=data_directory()/'connection.dpapi'
        if path.is_symlink():raise ValueError('Linked connection files are unsupported.')
        path.unlink(missing_ok=True)


def main():
    if len(sys.argv)==3 and sys.argv[1]=='--self-test':
        value=b'SentinelOps helper self-test; not a credential'
        assert protect(protect(value),decrypt=True)==value
        Path(sys.argv[2]).write_text(json.dumps({'version':VERSION,'dpapi_roundtrip':True,'device_operator_imported':True}),encoding='utf-8');return
    from companion.helper_desktop import HelperApp
    HelperApp(WindowsAdapter()).run()

if __name__=='__main__':main()
