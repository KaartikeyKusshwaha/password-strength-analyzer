"""Read-only alert projection; bearer never authorizes workflow execution."""
import json
import re
import time
from fastapi import Depends,Request
from .access_workflows import owner,require
from .extension_connect import REMINDER_SCOPE,REMINDER_KIND
from .security import digest
from .store import Store,now


def register(app,store,auth,throttle):
    def reminder_auth(request:Request):
        origin=request.headers.get('origin','');bearer=request.headers.get('authorization','')
        require(re.fullmatch(r'chrome-extension://[a-p]{32}',origin),'Extension origin required',403)
        require(bearer.startswith('Bearer '),'Reminder connection required',401)
        with store.connect() as c:
            grant=Store.get(c,REMINDER_SCOPE,REMINDER_KIND,digest(bearer[7:]))
            require(grant and grant['expires']>time.time() and grant['origin']==origin,'Reminder connection expired or revoked',401)
            actor=owner(c,grant['workspace'],grant['user']);require(actor and actor['mfa'],'Current owner access and MFA required',403)
        return grant

    @app.get('/api/companion/reminders/context')
    def context(session=Depends(reminder_auth)):
        throttle('access-reminders:'+session['id'],120)
        with store.connect() as c:
            rows=c.execute("SELECT data FROM entities WHERE workspace=? AND kind='access_leases' AND json_extract(data,'$.status') NOT IN ('complete','cancelled','awaiting_approval') ORDER BY json_extract(data,'$.plan.expires_at') LIMIT 1000",(session['workspace'],)).fetchall()
            alerts=[]
            for row in rows:
                lease=json.loads(row[0]);state=lease['status']
                if state=='active' and not lease.get('reminder_sent'):continue
                client=c.execute('SELECT name FROM clients WHERE workspace=? AND id=?',(session['workspace'],lease['client'])).fetchone()
                alerts.append({'id':lease['id'],'client':client['name'] if client else 'Former client','state':'expiring' if state=='active' else state,'expires_at':lease['plan']['expires_at']})
            return {'alerts':alerts,'expires':session['expires'],'checked_at':now(),'coverage':'Expiry reminders and execution status only. Read-only; no vault contents, passwords, access changes or external account assertions.'}

    @app.post('/api/companion/reminders/revoke')
    def revoke(session=Depends(reminder_auth)):
        with store.connect(write=True) as c:
            c.execute('DELETE FROM entities WHERE workspace=? AND kind=? AND id=?',(REMINDER_SCOPE,REMINDER_KIND,session['id']))
            Store.event(c,session['workspace'],session['user'],'extension.reminders_revoked','owner-disconnected')
        return {'ok':True}

    @app.post('/api/reminder-connections/revoke')
    def revoke_all(session=Depends(auth)):
        require(session['role']=='owner','Workspace owner required',403)
        with store.connect(write=True) as c:
            c.execute("DELETE FROM entities WHERE workspace=? AND kind=? AND json_extract(data,'$.workspace')=? AND json_extract(data,'$.user')=?",(REMINDER_SCOPE,REMINDER_KIND,session['workspace'],session['user']))
            Store.event(c,session['workspace'],session['user'],'extension.reminders_revoked','all-own-connections')
        return {'ok':True}
