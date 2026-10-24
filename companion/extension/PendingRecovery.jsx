import React,{useEffect,useRef,useState} from 'react';
import {PendingRecovery} from './pending-recovery';
import {isArchived} from '../../frontend/src/entry-history';

export default function PendingRecoveryPanel({session,jobs,onStop,onResolved,onChange,onBusy}){
  const pending=session.entries.filter(entry=>entry.type==='login'&&entry.pending_change&&!isArchived(entry));
  const [statuses,setStatuses]=useState([]),[busy,setBusy]=useState(false),[error,setError]=useState(''),[notice,setNotice]=useState(''),[reveal,setReveal]=useState(null);
  const alive=useRef(true),epoch=useRef(0),recovery=useRef(new PendingRecovery(session));
  async function inspect(){const mark=++epoch.current;try{const value=await recovery.current.inspect();if(alive.current&&mark===epoch.current)setStatuses(value);}catch(e){if(alive.current&&mark===epoch.current)setError(e.message);}}
  useEffect(()=>{alive.current=true;return()=>{alive.current=false;epoch.current++;};},[]);
  useEffect(()=>{setReveal(null);if(pending.length)inspect();},[session.entries,jobs]);
  useEffect(()=>{if(!reveal)return;const timer=setTimeout(()=>setReveal(null),10000),hide=()=>{if(document.hidden)setReveal(null);};document.addEventListener('visibilitychange',hide);return()=>{clearTimeout(timer);document.removeEventListener('visibilitychange',hide);};},[reveal]);
  async function run(work){setBusy(true);onBusy?.(true);setReveal(null);setError('');setNotice('');try{await work();}catch(e){if(alive.current)setError(e.message);}finally{if(alive.current){setBusy(false);onBusy?.(false);onChange?.();}}}
  if(!pending.length)return <>{notice&&<p role="status">{notice}</p>}{error&&<p role="alert" className="error">{error}</p>}</>;
  return <details><summary>Recover staged password changes</summary><p>A stopped or expired plan does not erase its encrypted proposal. Resolve the vault entry here only after checking the website. Recovery preserves an archived copy of the unused password; it does not restart the old plan or verify website acceptance.</p>
    <button className="secondary" disabled={busy} onClick={()=>run(inspect)}>Refresh recovery status</button>
    {pending.map(entry=>{const status=statuses.find(item=>item.id===entry.id&&item.action===entry.pending_change.action_id);return <article key={entry.id}><h3>{entry.title}</h3><p>{entry.origin} · {status?.status.replaceAll('_',' ')||'Checking plan status…'}</p>
      {status?.status==='untracked'&&<p className="fine">This connection cannot locate the plan. Coordinate any other account work before recovery. This is not proof that no other work is active.</p>}
      {status?.job&&!status.canRecover&&<button className="secondary" disabled={busy} onClick={()=>run(async()=>{await onStop(status.job);await inspect();})}>Stop matching plan before recovery</button>}
      <button className="secondary" disabled={busy||!status} onClick={()=>run(async()=>{const value=await recovery.current.reveal(entry.id,entry.pending_change.action_id);if(alive.current)setReveal({id:entry.id,...value});})}>Show staged password for 10 seconds</button>
      {reveal?.id===entry.id&&reveal.generation===session.generation&&<code className="fingerprint">{reveal.password}</code>}
      {status?.canRecover&&<><form onSubmit={event=>{event.preventDefault();run(async()=>{await recovery.current.resolve(entry.id,entry.pending_change.action_id,true);if(alive.current)setNotice('Replacement saved in the vault. The previous password is retained in an encrypted archived recovery copy. Old queue/debt status is unchanged.');await onResolved?.();});}}><label><input type="checkbox" required/>I checked the website and it accepts this staged password.</label><button disabled={busy}>Keep replacement and archive previous password</button></form>
      <form onSubmit={event=>{event.preventDefault();run(async()=>{await recovery.current.resolve(entry.id,entry.pending_change.action_id,false);if(alive.current)setNotice('Original login retained. The unused proposal is preserved in an encrypted archived recovery copy. Old queue/debt status is unchanged.');await onResolved?.();});}}><label><input type="checkbox" required/>I checked that the website does not use this proposal.</label><button className="secondary" disabled={busy}>Keep original and archive unused proposal</button></form></>}
    </article>;})}
    {notice&&<p role="status">{notice}</p>}{error&&<p role="alert" className="error">{error}</p>}
  </details>;
}
