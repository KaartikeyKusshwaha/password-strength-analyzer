import {serviceOrigin} from './policy';
export const REMINDER_ALARM='sentinelops-access-reminders';
export async function reminderRequest(connection,path='context',fetcher=(...args)=>globalThis.fetch(...args)){
 if(connection?.kind!=='reminders'||!/^[A-Za-z0-9_-]{40,100}$/.test(connection.token||'')||!['context','revoke'].includes(path))throw new Error('Connect read-only reminders first.');
 const response=await fetcher(serviceOrigin(connection.origin)+'/api/companion/reminders/'+path,{method:path==='revoke'?'POST':'GET',credentials:'omit',redirect:'error',headers:{Authorization:'Bearer '+connection.token,...(path==='revoke'?{'Content-Type':'application/json'}:{})},...(path==='revoke'?{body:'{}'}:{}),signal:AbortSignal.timeout(10000)});
 if(!response.ok)throw Object.assign(new Error([401,403].includes(response.status)?'Reminder connection expired, revoked or lost owner/MFA authority. Reconnect.':'Reminder check unavailable.'),{terminal:[401,403].includes(response.status)});
 const result=await response.json();
 if(path==='context'&&(!Array.isArray(result.alerts)||result.alerts.length>1000||!Number.isFinite(result.expires)))throw new Error('Unexpected reminder response.');
 return result;
}
export function createReminderMonitor(browser,{request=reminderRequest,clock=()=>Date.now()}={}){
 let inflight=null;
 async function same(connection){const current=(await browser.storage.local.get('reminderConnection')).reminderConnection;return current?.token===connection?.token&&current?.origin===connection?.origin;}
 async function badge(text){if(globalThis.sentinelCaptureActive)return;await browser.action.setBadgeText({text});if(text)await browser.action.setBadgeBackgroundColor({color:'#a86b22'});}
 async function check(){
  if(inflight)return inflight;
  inflight=(async()=>{
   const connection=(await browser.storage.local.get('reminderConnection')).reminderConnection;
   if(!connection){await browser.alarms.clear(REMINDER_ALARM);await browser.storage.local.remove('reminderStatus');await badge('');return;}
   try{
    const origin=serviceOrigin(connection.origin);
    if(!await browser.permissions.contains({origins:[origin+'/*']}))throw Object.assign(new Error('Host permission missing'),{terminal:true});
    const result=await request(connection);if(!await same(connection))return;
    await browser.storage.local.set({reminderStatus:{connectionId:connection.id,state:'current',count:result.alerts.length,checkedAt:clock(),expires:result.expires}});
    if(await same(connection))await badge(result.alerts.length?'R':'');
   }catch(error){if(!await same(connection))return;await browser.storage.local.set({reminderStatus:{connectionId:connection.id,state:error.terminal?'reconnect':'unavailable',checkedAt:clock()}});if(await same(connection)){await badge('?');if(error.terminal)await browser.alarms.clear(REMINDER_ALARM);}}
  })().finally(()=>{inflight=null;});return inflight;
 }
 async function schedule(){const value=(await browser.storage.local.get('reminderConnection')).reminderConnection;if(value)await browser.alarms.create(REMINDER_ALARM,{periodInMinutes:15});else await browser.alarms.clear(REMINDER_ALARM);}
 function install(){
  browser.alarms.onAlarm.addListener(alarm=>{if(alarm.name===REMINDER_ALARM)check().catch(()=>{});});
  browser.storage.onChanged?.addListener((changes,area)=>{if(area==='local'&&changes.reminderConnection)schedule().then(check).catch(()=>{});});
  browser.runtime.onStartup?.addListener(()=>schedule().then(check).catch(()=>{}));
  schedule().then(check).catch(()=>{});
 }
 async function restoreBadge(){const value=await browser.storage.local.get(['reminderStatus','reminderConnection']);const saved=value.reminderConnection&&value.reminderStatus?.connectionId===value.reminderConnection.id?value.reminderStatus:null;await badge(saved?.state==='current'?(saved.count?'R':''):saved?'?':'');}
 return {check,install,restoreBadge};
}
