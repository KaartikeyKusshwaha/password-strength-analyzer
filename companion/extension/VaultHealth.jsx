import React,{useEffect,useRef,useState} from 'react';
import {accountHealth} from '../../frontend/src/account-health';
import {isArchived} from '../../frontend/src/entry-history';
import {checkBreach} from '../../frontend/src/lab';
const ENDPOINT='https://api.pwnedpasswords.com/*';

export default function VaultHealth({entries,session,browser,checkPassword,onApproved}){
  const [health,setHealth]=useState(null),[localError,setLocalError]=useState(''),[results,setResults]=useState([]),[approved,setApproved]=useState(false),[running,setRunning]=useState(false),[error,setError]=useState('');
  const epoch=useRef(0),request=useRef(null);
  const [selection,setSelection]=useState([]),[approving,setApproving]=useState(false),[notice,setNotice]=useState('');
  useEffect(()=>{
    const current=++epoch.current;request.current?.abort();setResults([]);setApproved(false);setRunning(false);setHealth(null);setLocalError('');setError('');setSelection([]);setNotice('');
    (async()=>{try{let check=checkPassword;if(!check){const {estimator}=await import('../../frontend/src/strength');check=password=>estimator.check(password);}const value=accountHealth(entries,check);if(current===epoch.current)setHealth(value);}catch{if(current===epoch.current)setLocalError('Local password estimates could not load; no health verdict was produced.');}})();
    return()=>{epoch.current++;request.current?.abort();};
  },[entries]);
  const logins=entries.filter(entry=>entry.type==='login'&&!isArchived(entry));
  const eligible=logins.filter(entry=>{if(!entry.password)return false;try{session.permitted('fill',entry.origin);return true;}catch{return false;}});
  const pending=[...eligible.filter(entry=>!results.some(result=>result.id===entry.id)),...eligible.filter(entry=>results.some(result=>result.id===entry.id&&result.status==='unassessed'))].slice(0,20);
  const actions=logins.map(entry=>({entry,local:health?.find(item=>item.id===entry.id),breach:results.find(item=>item.id===entry.id)})).filter(item=>item.local?.weak||item.local?.reused||item.breach?.count>0);
  async function breachRun(){
    const current=epoch.current,controller=new AbortController();request.current=controller;setRunning(true);setError('');
    const live=()=>current===epoch.current&&!controller.signal.aborted;
    try{
      if(!await browser.permissions.request({origins:[ENDPOINT]}))throw Object.assign(new Error(),{code:'DECLINED'});
      if(!live())return;
      await session.external(async({signal,active})=>{
        const combined=AbortSignal.any([signal,controller.signal]),cache=new Map();
        for(const entry of pending){
          combined.throwIfAborted();active();await session.refresh();active();session.permitted('fill',entry.origin);
          let status='unassessed',count=null;
          try{
            if(!cache.has(entry.password))cache.set(entry.password,await checkBreach(entry.password,(url,options)=>{combined.throwIfAborted();active();session.permitted('fill',entry.origin);return globalThis.fetch(url,options);},{signal:combined}));
            active();count=cache.get(entry.password);status=count>0?'found':'not_found';
          }catch{if(combined.aborted)break;active();}
          if(live())setResults(previous=>[...previous.filter(row=>row.id!==entry.id),{id:entry.id,status,count}]);
        }
      });
    }catch(error){if(live())setError(error.code==='DECLINED'?'Breach-service access was declined. No lookup was sent.':'Checks stopped or access could not be verified. Check the vault connection and try again; remaining passwords are unassessed.');}
    finally{if(request.current===controller){if(current===epoch.current){setRunning(false);setApproved(false);}request.current=null;}}
  }
  async function openChange(entry){setError('');try{const generation=session.generation;await session.refresh();session.active(generation);session.permitted('fill',entry.origin);session.permitted('save',entry.origin);const response=await browser.runtime.sendMessage({type:'open-account-change',origin:entry.origin});if(!response?.ok)throw new Error();}catch{setError('The security page could not open or this vault does not permit the action. No website or password was changed.');}}
  return <section aria-label="Vault account health"><strong>{actions.length?`${actions.length} saved logins need review`:health===null?(localError?'Local password estimates unavailable':'Checking saved passwords locally…'):'No listed weak or reused passwords in this vault'}</strong>
    <p className="fine">Local estimates for this unlocked vault only. Secrets and health results are never sent to AI. Passwords over 128 characters are not strength-scored. No result certifies an account is safe.</p>
    {results.length>0&&<p className="fine">Password exposure data: <a href="https://haveibeenpwned.com/Passwords" target="_blank" rel="noreferrer">Have I Been Pwned · Pwned Passwords</a>.</p>}
    {actions.slice(0,5).map(({entry,local,breach})=><article key={entry.id}><h3>{entry.title}</h3><p>{local?.weak?'Choose a less predictable password. ':''}{local?.reused?'This password appears in multiple saved logins. ':''}{breach?.count>0?'This password appears in the breach dataset. Replace it; this is not proof that this account was breached.':''}</p><button className="secondary" disabled={running} onClick={()=>openChange(entry)}>Open password-change page</button></article>)}
    {actions.length>5&&<p>{actions.length-5} more saved logins need review. Review details below.</p>}
    <details><summary>Fix selected passwords with the account operator</summary><p>Select up to 20 logins. Approve one encrypted plan to generate recoverable replacements and prepare supported website forms. Passwords remain local/encrypted; the operator never submits a website form or claims it changed an arbitrary service automatically.</p>
      {logins.map(entry=><label key={entry.id}><input type="checkbox" checked={selection.includes(entry.id)} disabled={running||approving||!!entry.pending_change} onChange={event=>{setSelection(event.target.checked?[...selection,entry.id]:selection.filter(id=>id!==entry.id));setNotice('');}}/>{entry.title}{entry.pending_change?' · existing change must be resolved':''}</label>)}
      <button disabled={running||approving||!selection.length||selection.length>20} onClick={async()=>{setApproving(true);setError('');try{await session.approveChanges(selection);setSelection([]);setNotice('Encrypted action plan approved. Continue in Approved account actions below.');onApproved?.();}catch(e){setError(e.message);}finally{setApproving(false);}}}>{approving?'Approving locally…':`Approve password changes for ${selection.length} selected logins`}</button>
      {notice&&<p role="status">{notice}</p>}
    </details>
    <details><summary>Advanced · password review and breach lookup</summary>
      <p><a href="https://haveibeenpwned.com/Passwords" target="_blank" rel="noreferrer">Have I Been Pwned · Pwned Passwords</a> lookups send only a five-character SHA-1 prefix with response padding. The service can observe your IP and queried prefix. Full passwords, full hashes, usernames and website names are not sent.</p>
      <p>Checks run only while this popup and vault remain unlocked. Up to 20 saved logins per run; repeated passwords within a run share one lookup. Closing/locking stops further work. Nothing is checked as you type or while locked.</p>
      <p className="fine">Only logins allowed by this vault’s current browser-filling policy are eligible. Empty passwords are excluded. Policy is rechecked before each lookup.</p>
      <label><input type="checkbox" checked={approved} disabled={running} onChange={event=>setApproved(event.target.checked)}/>Allow hash-prefix lookups for the next {pending.length} saved logins in this vault.</label>
      <button className="secondary" disabled={!approved||running||!pending.length} onClick={breachRun}>{running?'Checking saved passwords…':'Check saved passwords for known exposure'}</button>
      {running&&<button className="secondary" onClick={()=>{request.current?.abort();setRunning(false);setApproved(false);}}>Stop breach checks</button>}
      <p className="fine">“Not found” means no match in this dataset, not safe. Errors and skipped records remain unassessed. This is not email/account breach monitoring.</p>
      {logins.map(entry=>{const local=health?.find(row=>row.id===entry.id),breach=results.find(row=>row.id===entry.id);return <p key={entry.id}><strong>{entry.title}</strong> · {local?(local.assessed?(local.weak?'weak estimate':'not flagged by strength estimate'):'strength unassessed'):'estimating'}{local?.reused?' · repeated password':''} · {breach?(breach.status==='found'?'found in password dataset':breach.status==='not_found'?'not found in password dataset':'breach lookup unassessed'):'breach lookup not run'}</p>;})}
    </details>{localError&&<p role="alert" className="error">{localError}</p>}{error&&<p role="alert" className="error">{error}</p>}
  </section>;
}
