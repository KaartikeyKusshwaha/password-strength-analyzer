"""Per-user Windows helper installer and visible, revocable polling app."""
import hashlib
import json
import os
import queue
import shutil
import subprocess
import sys
import threading
import time
import urllib.error
from pathlib import Path
from companion.helper_client import VERSION,Pairing,protect,data_directory,load_connection,save_connection
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

class HelperApp:
    def __init__(self):
        import tkinter as tk
        from tkinter import ttk
        self.tk=tk;self.root=tk.Tk();self.root.title('SentinelOps Device Helper');self.root.geometry('590x590');self.root.minsize(560,530)
        self.events=queue.Queue();self.stop=threading.Event();self.worker=None;self.pairing=None;self.config=None
        box=ttk.Frame(self.root,padding=24);box.pack(fill='both',expand=True)
        ttk.Label(box,text='Connect this computer',font=('Segoe UI',20,'bold')).pack(anchor='w')
        ttk.Label(box,text='Optional Windows helper · '+VERSION).pack(anchor='w',pady=(3,16))
        ttk.Label(box,text='Only approved checks of this computer. No administrator rights,\nstartup service, arbitrary commands, password access or automatic repairs.\nClosing this window stops polling.',wraplength=530).pack(anchor='w')
        self.posture=tk.BooleanVar();self.updates=tk.BooleanVar()
        self.posture_button=ttk.Checkbutton(box,text='Allow read-only firewall, Defender and drive-encryption status',variable=self.posture);self.posture_button.pack(anchor='w',pady=(16,5))
        self.updates_button=ttk.Checkbutton(box,text='Allow cached Windows Update / restart status (no installation)',variable=self.updates);self.updates_button.pack(anchor='w')
        ttk.Label(box,text='TCP scope: 127.0.0.1 and ::1 only. No LAN or public-host scanning.').pack(anchor='w',pady=(12,4))
        self.status=tk.StringVar(value='Install for this Windows user and connect from the browser extension.')
        ttk.Label(box,textvariable=self.status,wraplength=525).pack(anchor='w',pady=12)
        self.code=tk.StringVar();ttk.Label(box,textvariable=self.code,font=('Consolas',28,'bold')).pack(anchor='w')
        self.connect_button=ttk.Button(box,text='Install and get pairing code',command=self.connect);self.connect_button.pack(anchor='w',pady=10)
        self.disconnect_button=ttk.Button(box,text='Stop helper',command=self.close);self.disconnect_button.pack(anchor='w')
        ttk.Label(box,text='Installed per user under Local AppData with a Start menu shortcut.\nThe device token is protected by Windows for this user. Revoke access\nin SentinelOps Connections. Uninstall using Windows Installed apps.',wraplength=525).pack(anchor='w',pady=15)
        self.root.protocol('WM_DELETE_WINDOW',self.close);self.root.after(150,self.drain)
        try:
            path=data_directory()/'connection.dpapi'
            if path.exists():
                self.config=load_connection(path);self.posture.set(self.config.get('allow_posture',False));self.updates.set(self.config.get('allow_updates',False));self.lock_options();self.begin_polling()
        except Exception:self.status.set('The saved connection could not be opened. Reconnect this helper; no scans have run.')
    def lock_options(self):
        self.posture_button.state(['disabled']);self.updates_button.state(['disabled']);self.connect_button.state(['disabled'])
    def connect(self):
        if self.worker and self.worker.is_alive():return
        options=(self.posture.get(),self.updates.get());self.lock_options();self.status.set('Installing the helper for your Windows user…')
        def task():
            try:
                folder=install();pairing=Pairing('Windows device helper',*options);self.pairing=pairing
                pending=pairing.start();self.events.put(('code',pending['pairing_code']))
                while not self.stop.wait(5):
                    config=pairing.poll()
                    if config:
                        if self.stop.is_set():
                            try:pairing.cancel()
                            except Exception:pass
                            return
                        save_connection(folder/'connection.dpapi',config)
                        try:pairing.acknowledge()
                        except Exception:pass # Persisted grant works; proof delivery expires server-side.
                        self.events.put(('connected',config));return
                try:pairing.cancel()
                except Exception:pass
            except Exception:self.events.put(('error','Pairing could not finish or expired. Check your connection and request a new code.'))
        self.worker=threading.Thread(target=task,daemon=True);self.worker.start()
    def begin_polling(self):
        self.status.set('Connected. Approve a device check in your extension. Keep this window open.');self.code.set('')
        def task():
            while not self.stop.is_set():
                try:
                    completed=poll_once(self.config,allow_posture=self.config.get('allow_posture',False),allow_updates=self.config.get('allow_updates',False))
                    self.events.put(('status','Check synchronized. Ready for the next approved check.' if completed else 'Connected. Waiting for a check approved in your extension.'))
                except urllib.error.HTTPError as error:
                    if error.code==401:
                        self.events.put(('error','Device connection expired or was revoked. Request a new pairing code to reconnect.'));return
                    self.events.put(('status','The service rejected this request. No substitute results were recorded.'))
                except Exception:self.events.put(('status','Connection unavailable. No substitute results were recorded. Retrying while this window stays open.'))
                self.stop.wait(5)
        self.worker=threading.Thread(target=task,daemon=True);self.worker.start()
    def drain(self):
        try:
            while True:
                kind,value=self.events.get_nowait()
                if kind=='code':self.code.set(value[:4]+'-'+value[4:]);self.status.set('In the SentinelOps extension, choose Connect device helper. Enter this code, review the scope and approve with your account password/MFA. Code expires in five minutes.')
                elif kind=='connected':self.config=value;self.begin_polling()
                elif kind=='status':self.status.set(value)
                elif kind=='error':self.status.set(value);self.code.set('');self.connect_button.state(['!disabled']);self.posture_button.state(['!disabled']);self.updates_button.state(['!disabled'])
        except queue.Empty:pass
        self.root.after(150,self.drain)
    def close(self):
        self.stop.set();self.root.destroy()
    def run(self):self.root.mainloop()

def main():
    if len(sys.argv)==3 and sys.argv[1]=='--self-test':
        value=b'SentinelOps helper self-test; not a credential'
        assert protect(protect(value),decrypt=True)==value
        Path(sys.argv[2]).write_text(json.dumps({'version':VERSION,'dpapi_roundtrip':True,'device_operator_imported':True}),encoding='utf-8');return
    HelperApp().run()

if __name__=='__main__':main()
