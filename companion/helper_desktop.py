"""Visible desktop pairing UI shared by platform-specific secure-storage adapters."""
import queue
import threading
import urllib.error
from companion.helper_client import VERSION,Pairing
from companion.device_agent import poll_once

class HelperApp:
    def __init__(self,adapter):
        self.adapter=adapter
        import tkinter as tk
        from tkinter import ttk
        self.tk=tk;self.root=tk.Tk();self.root.title('SentinelOps Device Helper');self.root.geometry('590x590');self.root.minsize(560,530)
        self.events=queue.Queue();self.stop=threading.Event();self.worker=None;self.pairing=None;self.config=None
        box=ttk.Frame(self.root,padding=24);box.pack(fill='both',expand=True)
        ttk.Label(box,text='Connect this computer',font=('Segoe UI',20,'bold')).pack(anchor='w')
        ttk.Label(box,text='Optional '+adapter.platform_name+' helper · '+VERSION).pack(anchor='w',pady=(3,16))
        ttk.Label(box,text='Only approved checks of this computer. No administrator rights,\nstartup service, arbitrary commands, password access or automatic repairs.\nClosing this window stops polling.',wraplength=530).pack(anchor='w')
        self.posture=tk.BooleanVar();self.updates=tk.BooleanVar()
        self.posture_button=ttk.Checkbutton(box,text=adapter.posture_label,variable=self.posture);self.posture_button.pack(anchor='w',pady=(16,5))
        self.updates_button=ttk.Checkbutton(box,text=adapter.updates_label,variable=self.updates);self.updates_button.pack(anchor='w')
        if not adapter.supports_updates:self.updates_button.state(['disabled'])
        ttk.Label(box,text='TCP scope: 127.0.0.1 and ::1 only. No LAN or public-host scanning.').pack(anchor='w',pady=(12,4))
        self.status=tk.StringVar(value=adapter.initial_status)
        ttk.Label(box,textvariable=self.status,wraplength=525).pack(anchor='w',pady=12)
        self.code=tk.StringVar();ttk.Label(box,textvariable=self.code,font=('Consolas',28,'bold')).pack(anchor='w')
        self.connect_button=ttk.Button(box,text='Install and get pairing code',command=self.connect);self.connect_button.pack(anchor='w',pady=10)
        self.disconnect_button=ttk.Button(box,text='Stop helper',command=self.close);self.disconnect_button.pack(anchor='w')
        self.forget_button=ttk.Button(box,text='Stop and forget local connection',command=self.forget);self.forget_button.pack(anchor='w',pady=5)
        ttk.Label(box,text=adapter.storage_note,wraplength=525).pack(anchor='w',pady=15)
        self.root.protocol('WM_DELETE_WINDOW',self.close);self.root.after(150,self.drain)
        try:
            saved=adapter.load()
            if saved:
                self.config=saved;self.posture.set(self.config.get('allow_posture',False));self.updates.set(self.config.get('allow_updates',False));self.lock_options();self.begin_polling()
        except Exception:self.status.set('The saved connection could not be opened. Reconnect this helper; no scans have run.')
    def lock_options(self):
        self.posture_button.state(['disabled']);self.updates_button.state(['disabled']);self.connect_button.state(['disabled'])
    def connect(self):
        if self.worker and self.worker.is_alive():return
        self.stop.clear()
        options=(self.posture.get(),self.updates.get() and self.adapter.supports_updates);self.lock_options();self.status.set('Installing the helper for this user…')
        def task():
            try:
                self.adapter.install();pairing=Pairing(self.adapter.platform_name+' device helper',*options);self.pairing=pairing
                pending=pairing.start();self.events.put(('code',pending['pairing_code']))
                while not self.stop.wait(5):
                    config=pairing.poll()
                    if config:
                        if self.stop.is_set():
                            try:pairing.cancel()
                            except Exception:pass
                            return
                        self.adapter.save(config)
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
                elif kind=='error':self.status.set(value);self.code.set('');self.connect_button.state(['!disabled']);self.posture_button.state(['!disabled']);self.updates_button.state(['!disabled'] if self.adapter.supports_updates else ['disabled']);self.forget_button.state(['!disabled'])
                elif kind=='forgotten':
                    self.config=None;self.code.set('');self.status.set('Local connection removed. Revoke the cloud device connection in the extension too. Connect again only when ready.');self.connect_button.state(['!disabled']);self.posture_button.state(['!disabled']);self.updates_button.state(['!disabled'] if self.adapter.supports_updates else ['disabled']);self.forget_button.state(['!disabled'])
        except queue.Empty:pass
        self.root.after(150,self.drain)
    def close(self):
        self.stop.set();self.root.destroy()
    def forget(self):
        from tkinter import messagebox
        if not messagebox.askyesno('Forget device connection','Stop this helper and remove only its local protected connection? Revoke the cloud connection in SentinelOps too.'):return
        self.stop.set();self.lock_options();self.forget_button.state(['disabled']);self.status.set('Stopping in-flight read-only work before removing the local connection. Keep this window open.')
        worker=self.worker
        def task():
            if worker:worker.join(timeout=65)
            if worker and worker.is_alive():self.events.put(('error','A read-only check is still finishing. Keep the helper stopped and retry forgetting after it finishes.'));return
            try:self.adapter.forget();self.events.put(('forgotten',None))
            except Exception:self.events.put(('error','Local protected storage could not be removed. Revoke the cloud connection in the extension.'))
        threading.Thread(target=task,daemon=True).start()
    def run(self):self.root.mainloop()
