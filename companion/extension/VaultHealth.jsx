import React,{useEffect,useRef,useState} from 'react';
import {accountHealth} from '../../frontend/src/account-health';
import {isArchived} from '../../frontend/src/entry-history';
import {checkBreach} from '../../frontend/src/lab';
import {scheduleKey,loadSchedule,enableSchedule,disableSchedule,advanceSchedule,scheduleDue,scheduleBatch} from './breach-schedule';
const ENDPOINT='https://api.pwnedpasswords.com/*';

export default function VaultHealth({entries,session,browser,checkPassword,onApproved}){
  const [health,setHealth]=useState(null),[localError,setLocalError]=useState(''),[results,setResults]=useState([]),[approved,setApproved]=useState(false),[running,setRunning]=useState(false),[error,setError]=useState('');
  const epoch=useRef(0),request=useRef(null);
  const [selection,setSelection]=useState([]),[approving,setApproving]=useState(false),[notice,setNotice]=useState('');
  const [schedule,setSchedule]=useState(null),[scheduleBusy,setScheduleBusy]=useState(false),[scheduleError,setScheduleError]=useState('');
  const runLock=useRef(false),autoAttempt=useRef(false),scheduleIdentity=useRef(null);
  useEffect(()=>{
    let live=true,key;try{key=scheduleKey(session);}catch{return;}
    scheduleIdentity.current=key;autoAttempt.current=false;
    if(browser.storage?.local)loadSchedule(browser,key).then(value=>{if(live)setSchedule(value);}).catch(()=>{if(live)setScheduleError('Recurring-check preferences could not load. No automatic lookup was started.');});
    const changed=(changes,area)=>{if(area==='local'&&changes[key]){request.current?.abort();autoAttempt.current=true;loadSchedule(browser,key).then(value=>{if(live)setSchedule(value);}).catch(()=>{});}};
    browser.storage?.onChanged?.addListener(changed);
    return()=>{live=false;scheduleIdentity.current=null;browser.storage?.onChanged?.removeListener(changed);};
  },[session,session.policy?.id,session.config?.origin]);
  useEffect(()=>{
    const current=++epoch.current;request.current?.abort();setResults([]);setApproved(false);setRunning(false);setHealth(null);setLocalError('');setError('');setSelection([]);setNotice('');
    (async()=>{try{let check=checkPassword;if(!check){const {estimator}=await import('../../frontend/src/strength');check=password=>estimator.check(password);}const value=accountHealth(entries,check);if(current===epoch.current)setHealth(value);}catch{if(current===epoch.current)setLocalError('Local password estimates could not load; no health verdict was produced.');}})();
    return()=>{epoch.current++;request.current?.abort();};
  },[entries]);
  const logins=entries.filter(entry=>entry.type==='login'&&!isArchived(entry));
  const eligible=logins.filter(entry=>{if(!entry.password)return false;try{session.permitted('fill',entry.origin);return true;}catch{return false;}});
  const pending=[...eligible.filter(entry=>!results.some(result=>result.id===entry.id)),...eligible.filter(entry=>results.some(result=>result.id===entry.id&&result.status==='unassessed'))].slice(0,20);
  const actions=logins.map(entry=>({entry,local:health?.find(item=>item.id===entry.id),breach:results.find(item=>item.id===entry.id)})).filter(item=>item.local?.weak||item.local?.reused||item.breach?.count>0);
  useEffect(()=>{
    if(!schedule||!scheduleDue(schedule)||autoAttempt.current||runLock.current||!eligible.length)return;
    autoAttempt.current=true;breachRun({automatic:true,batch:scheduleBatch(eligible,schedule)});
  },[schedule,entries]);
  async function breachRun({automatic=false,batch=pending}={}){
    if(runLock.current)return;runLock.current=true;
    const current=epoch.current,controller=new AbortController();request.current=controller;setRunning(true);setError('');
    const live=()=>current===epoch.current&&!controller.signal.aborted;
    const key=scheduleIdentity.current;let complete=true;
    try{
      const access=automatic?await browser.permissions.contains({origins:[ENDPOINT]}):await browser.permissions.request({origins:[ENDPOINT]});
      if(!access)throw Object.assign(new Error(),{code:'DECLINED'});
      if(!live())return;
      await session.external(async({signal,active})=>{
        const combined=AbortSignal.any([signal,controller.signal]),cache=new Map();
        for(const entry of batch){
          combined.throwIfAborted();active();await session.refresh();active();session.permitted('fill',entry.origin);
          if(automatic){const consent=await loadSchedule(browser,key);if(!consent.enabled||consent.generation!==schedule.generation)throw new Error('Recurring permission changed.');}
          let status='unassessed',count=null;
          try{
            if(!cache.has(entry.password))cache.set(entry.password,await checkBreach(entry.password,(url,options)=>{combined.throwIfAborted();active();session.permitted('fill',entry.origin);return globalThis.fetch(url,options);},{signal:combined}));
            active();count=cache.get(entry.password);status=count>0?'found':'not_found';
          }catch{complete=false;if(combined.aborted)break;active();}
          if(live())setResults(previous=>[...previous.filter(row=>row.id!==entry.id),{id:entry.id,status,count}]);
        }
      });
      if(automatic&&live()&&complete&&key&&scheduleIdentity.current===key){
        const currentSchedule=await loadSchedule(browser,key);
        if(currentSchedule.enabled&&currentSchedule.generation===schedule.generation&&live())setSchedule(await advanceSchedule(browser,key,{...currentSchedule,checkedAt:Date.now(),retryAt:0,offset:(currentSchedule.offset+batch.length)%eligible.length}));
      }
    }catch(error){complete=false;if(live())setError(error.code==='DECLINED'?'Breach-service access was declined. No lookup was sent.':'Checks stopped or access could not be verified. Check the vault connection and try again; remaining passwords are unassessed.');}
    finally{
      if(automatic&&key&&scheduleIdentity.current===key&&(!complete||!live())){
        // A failed/aborted run never advances the completed date or cursor.
        try{const value=await loadSchedule(browser,key);if(value.enabled&&value.generation===schedule.generation)await advanceSchedule(browser,key,{...value,retryAt:Date.now()+60*60*1000});}catch{/* Storage failure never becomes success. */}
      }
      runLock.current=false;if(request.current===controller){if(current===epoch.current){setRunning(false);setApproved(false);}request.current=null;}
    }
  }
  async function openChange(entry){setError('');try{const generation=session.generation;await session.refresh();session.active(generation);session.permitted('fill',entry.origin);session.permitted('save',entry.origin);const response=await browser.runtime.sendMessage({type:'open-account-change',origin:entry.origin});if(!response?.ok)throw new Error();}catch{setError('The security page could not open or this vault does not permit the action. No website or password was changed.');}}
  return <section aria-label="Vault account health"><strong>{actions.length?`${actions.length} saved logins need review`:health===null?(localError?'Local password estimates unavailable':'Checking saved passwords locally…'):'No listed weak or reused passwords in this vault'}</strong>
    <p className="fine">Local estimates for this unlocked vault only. Secrets and health results are never sent to AI. Passwords over 128 characters are not strength-scored. No result certifies an account is safe.</p>
    {results.length>0&&<p className="fine">Password exposure data: <a href="https://haveibeenpwned.com/Passwords" target="_blank" rel="noreferrer">Have I Been Pwned · Pwned Passwords</a>.</p>}
    {actions.slice(0,5).map(({entry,local,breach})=><article key={entry.id}><h3>{entry.title}</h3><p>{local?.weak?'Choose a less predictable password. ':''}{local?.reused?'This password appears in multiple saved logins. ':''}{breach?.count>0?'This password appears in the breach dataset. Replace it; this is not proof that this account was breached.':''}</p><button className="secondary" disabled={running} onClick={()=>openChange(entry)}>Open password-change page</button></article>)}
    {actions.length>5&&<p>{actions.length-5} more saved logins need review. Review details below.</p>}
    <details><summary>Fix selected passwords with the account operator</summary><p>Select up to 20 logins. Approve one encrypted plan to generate recoverable replacements and prepare supported website forms. Passwords remain local/encrypted; the operator never submits a website form or claims it changed an arbitrary service automatically.</p>
      {logins.map(entry=><label key={entry.id}><input type="checkbox" checked={selection.includes(entry.id)} disabled={running||approving||!!entry.pending_change} onChange={event=>{setSelection(event.target.checked?[...selection,entry.id]:selection.filter(id=>id!==entry.id));setNotice('');}}/>{entry.title}{entry.pending_change?' · existing change must be resolved':''}</label>)}
      <button disabled={running||approving||!selection.length||selection.length>20} onClick={async()=>{setApproving(true);setError('');try{const job=await session.approveChanges(selection);setSelection([]);setNotice('Encrypted action plan approved. Continue in Approved account actions below.');onApproved?.(job.id);}catch(e){setError(e.message);}finally{setApproving(false);}}}>{approving?'Approving locally…':`Approve password changes for ${selection.length} selected logins`}</button>
      {notice&&<p role="status">{notice}</p>}
    </details>
    <details><summary>Advanced · password review and breach lookup</summary>
      <p><a href="https://haveibeenpwned.com/Passwords" target="_blank" rel="noreferrer">Have I Been Pwned · Pwned Passwords</a> lookups send only a five-character SHA-1 prefix with response padding. The service can observe your IP and queried prefix. Full passwords, full hashes, usernames and website names are not sent.</p>
      <p>Checks run only while this popup and vault remain unlocked. Up to 20 saved logins per run; repeated passwords within a run share one lookup. Closing/locking stops further work. Nothing is checked as you type or while locked.</p>
      <p className="fine">Only logins allowed by this vault’s current browser-filling policy are eligible. Empty passwords are excluded. Policy is rechecked before each lookup.</p>
      <label><input type="checkbox" checked={approved} disabled={running} onChange={event=>setApproved(event.target.checked)}/>Allow hash-prefix lookups for the next {pending.length} saved logins in this vault.</label>
      <button className="secondary" disabled={!approved||running||!pending.length} onClick={()=>breachRun()}>{running?'Checking saved passwords…':'Check saved passwords for known exposure'}</button>
      {running&&<button className="secondary" onClick={()=>{request.current?.abort();setRunning(false);setApproved(false);}}>Stop breach checks</button>}
      <p className="fine">“Not found” means no match in this dataset, not safe. Errors and skipped records remain unassessed. This is not email/account breach monitoring.</p>
      {logins.map(entry=>{const local=health?.find(row=>row.id===entry.id),breach=results.find(row=>row.id===entry.id);return <p key={entry.id}><strong>{entry.title}</strong> · {local?(local.assessed?(local.weak?'weak estimate':'not flagged by strength estimate'):'strength unassessed'):'estimating'}{local?.reused?' · repeated password':''} · {breach?(breach.status==='found'?'found in password dataset':breach.status==='not_found'?'not found in password dataset':'breach lookup unassessed'):'breach lookup not run'}</p>;})}
    </details>{localError&&<p role="alert" className="error">{localError}</p>}{error&&<p role="alert" className="error">{error}</p>}
    {!schedule&&scheduleError&&<p role="alert" className="error">{scheduleError}</p>}
    {schedule&&<details><summary>Recurring password checks {schedule.enabled?'· enabled for this vault':''}</summary>
      <p>Opt in for this vault, including future saved logins. Starting on your next unlock, check up to 20 eligible logins when due, then wait at least 24 hours. Larger vaults rotate through batches. The browser must be open and this vault unlocked; there is no checking while locked or a guaranteed background schedule.</p>
      <p><a href="https://haveibeenpwned.com/Passwords" target="_blank" rel="noreferrer">Pwned Passwords</a> sees your IP and five-character hash prefixes. No full hashes, passwords, usernames or websites are sent. Only consent, last completed time, retry time and a batch position are stored locally. Results stay in this popup; they are not retained while locked or sent to AI.</p>
      {schedule.checkedAt>0&&<p>Last completed batch: {new Date(schedule.checkedAt).toLocaleString()}</p>}
      <button className="secondary" disabled={scheduleBusy} onClick={async()=>{
        const key=scheduleIdentity.current;if(!key)return;setScheduleBusy(true);setScheduleError('');
        try{
          if(schedule.enabled){request.current?.abort();autoAttempt.current=true;setSchedule(await disableSchedule(browser,key));}
          else{
            if(!await browser.permissions.request({origins:[ENDPOINT]}))throw new Error('Service access declined. Recurring checks stay off.');
            if(key!==scheduleIdentity.current)throw new Error('The vault changed. Reopen its controls.');
            autoAttempt.current=true;setSchedule(await enableSchedule(browser,key));
          }
        }catch(error){setScheduleError(error.message);}finally{setScheduleBusy(false);}
      }}>{schedule.enabled?'Disable recurring password checks':'Allow daily checks on unlock for this vault'}</button>
      {scheduleError&&<p role="alert" className="error">{scheduleError}</p>}
    </details>}
  </section>;
}
