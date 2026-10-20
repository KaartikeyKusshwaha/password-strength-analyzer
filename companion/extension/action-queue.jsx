import React,{useEffect,useRef,useState} from 'react';
import {AccountOperator} from './action-operator';

export function ActionQueue({session,browser,onChange}) {
  const operator=useRef(new AccountOperator(session,browser)),alive=useRef(true);
  const [jobs,setJobs]=useState(null),[selected,setSelected]=useState(null),[busy,setBusy]=useState(false),[error,setError]=useState(''),[notice,setNotice]=useState('');
  useEffect(()=>()=>{alive.current=false;operator.current=null;},[]);
  async function run(action) {setBusy(true);setError('');try{await action();}catch(e){if(alive.current)setError(e.message);}finally{if(alive.current){setBusy(false);onChange?.();}}}
  async function load() {
    const value=await session.actions();if(!alive.current)return;setJobs(value);
    if(await operator.current.restore(value) && alive.current)setSelected(operator.current.action);
  }
  function update() {if(alive.current)setSelected({...operator.current.action});}
  return <section><h2>Approved account actions</h2><p className="fine">Encrypted plans come from your dashboard approval. The operator stages a recoverable password and prepares supported exact-origin forms. Submit each website yourself. Sign-in, MFA and unsupported forms require your input.</p>
    {error && <p className="error">{error}</p>}{notice && <p className="notice">{notice}</p>}
    <button className="secondary" disabled={busy} onClick={()=>run(load)}>Load approved account actions</button>
    {jobs?.length===0 && <p>No approved work for this vault.</p>}
    {jobs?.map(job=><div key={job.id}><strong>{job.entry_count} account(s) · {job.status.replaceAll('_',' ')}</strong><p className="fine">Approval {job.id.slice(0,8)}</p>{['queued','interrupted'].includes(job.status) && <button disabled={busy} onClick={()=>run(async()=>{await operator.current.select(job,job.status==='interrupted');update();setNotice('Approval decrypted and claimed. Open each security page below. Original saved logins are retained until you confirm a change.');})}>{job.status==='interrupted'?'Resume interrupted approval':'Review and run approved plan'}</button>}{['running','awaiting_confirmation'].includes(job.status) && selected?.id!==job.id && <p className="fine">Another popup holds this action lease. Reopen it, or explicitly resume after its five-minute lease expires.</p>}</div>)}
    {selected && operator.current?.plan?.items.map((item,index)=>{
      const entry=session.entries.find(e=>e.id===item.entry_id),state=selected.items[index]?.state,done=['confirmed_by_user','discarded'].includes(state);
      return <article key={item.entry_id}><h3>{entry?.title || 'Approved login'}</h3><p>{item.origin}</p><p>{entry?.username} · {state?.replaceAll('_',' ')}</p>
        {!done && <><button disabled={busy} onClick={()=>run(async()=>{await operator.current.open(index);update();})}>Stage password and open security page</button>
        <button className="secondary" disabled={busy} onClick={()=>run(async()=>{const [tab]=await browser.tabs.query({active:true,currentWindow:true});await operator.current.prepare(index,tab);update();setNotice('Prepared supported password fields. Nothing was submitted. Review and finish the website before confirming below.');})}>Prepare this tab’s change form</button>
        <p className="fine">The staged password remains encrypted beside the original login. It can be recovered in the dashboard even if this popup closes or the approval expires.</p>
        {['prepared','needs_attention'].includes(state) && <><button disabled={busy} onClick={()=>run(async()=>{await operator.current.finish(index,true);update();setNotice('Saved the replacement after your confirmation. This is not independent website verification.');})}>Website accepted it — update vault</button><button className="secondary" disabled={busy} onClick={()=>run(async()=>{await operator.current.finish(index,false);update();setNotice('Unused proposal discarded. Original login retained.');})}>Not used — discard proposal</button></>}
        </>}
      </article>;
    })}
    {session.entries.some(e=>e.pending_change) && <p className="notice">You have staged password changes. Resolve them here or in the dashboard before replacing those saved logins manually.</p>}
  </section>;
}
