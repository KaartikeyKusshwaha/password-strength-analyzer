import {useEffect,useRef,useState} from 'react';
import {api} from './api';
import {validateAction} from './action-crypto';
import {finishChange} from './credential-changes';
import {isArchived} from './entry-history';

export function ActionFeed({vaultId='',go}) {
  const [actions,setActions]=useState([]),[error,setError]=useState('');
  useEffect(()=>{let active=true;const load=()=>api('/account-actions').then(v=>{if(active)setActions((v.actions || []).filter(a=>!vaultId || a.vault_id===vaultId));}).catch(e=>{if(active)setError(e.message);});load();const timer=setInterval(load,8000);return()=>{active=false;clearInterval(timer);};},[vaultId]);
  return <div className="spaced"><h3>Private account-action queue</h3>{error && <p role="alert">{error}</p>}{!actions.length?<p className="fine">No approved account actions yet. Unlock a vault, select logins and approve a browser preparation plan.</p>:actions.slice(0,8).map(action=><article key={action.id} className="operation-record"><strong>{action.entry_count} account change{action.entry_count===1?'':'s'} · {action.status.replaceAll('_',' ')}</strong><p className="fine">{action.kind} vault · {action.id.slice(0,8)} · expires {new Date(action.expires_at*1000).toLocaleTimeString()}</p><p className="fine">{action.items.filter(i=>i.state==='confirmed_by_user').length} confirmed by you. Website names and entry selections remain encrypted.</p>{!['complete','expired','cancelled'].includes(action.status) && <button className="button secondary" onClick={async()=>{try{await api('/account-actions/'+action.id+'/cancel',{});setActions(list=>list.map(a=>a.id===action.id?{...a,status:'cancelled'}:a));}catch(e){setError(e.message);}}}>Cancel remaining work</button>}</article>)}{go && <button className="button secondary" onClick={()=>go('vault')}>Unlock accounts and approve work</button>}<p className="fine">Prepared forms and your confirmation are recorded separately. A queued or prepared action does not prove a website password changed. Cancelled work never deletes staged passwords.</p></div>;
}

export default function AccountActions({entries,vaultId,kind,actor,seal,canPrepare=true,canEdit=true,onSave}) {
  const [selected,setSelected]=useState([]),[busy,setBusy]=useState(false),[error,setError]=useState(''),[notice,setNotice]=useState(''),[reveal,setReveal]=useState(null);
  const alive=useRef(true);
  useEffect(()=>{alive.current=true;return()=>{alive.current=false;};},[]);
  useEffect(()=>{if(!reveal)return;const timer=setTimeout(()=>setReveal(null),10000);return()=>clearTimeout(timer);},[reveal]);
  async function run(action) {setBusy(true);setError('');setNotice('');try{await action();}catch(e){if(alive.current)setError(e.message);}finally{if(alive.current)setBusy(false);}}
  const logins=entries.filter(e=>e.type==='login' && !isArchived(e));
  return <section className="panel spaced"><span className="eyebrow">ACCOUNT CHANGE OPERATOR</span><h3>Approve a browser preparation plan</h3><p>Select up to 20 accounts. The companion will open each exact website's change-password URL, stage a generated replacement in the encrypted vault and prepare a supported form when you choose to continue. Review and submit each website yourself; confirm its outcome before the saved login is replaced.</p>
    {error && <p className="notice error" role="alert">{error}</p>}{notice && <p className="notice" role="status">{notice}</p>}
    <form onSubmit={event=>{event.preventDefault();run(async()=>{
      if(!actor || !canPrepare || !selected.length)throw new Error('Select editable logins in an unlocked vault.');
      const approved_at=Math.floor(Date.now()/1000),id=[...crypto.getRandomValues(new Uint8Array(12))].map(b=>b.toString(16).padStart(2,'0')).join('');
      const manifest=validateAction({version:1,id,vault_id:vaultId,actor,kind,approved_at,expires_at:approved_at+1800,items:logins.filter(e=>selected.includes(e.id)).map(e=>({entry_id:e.id,origin:e.origin}))});
      const envelope=await seal(manifest);if(!alive.current)return;
      await api('/account-actions',{id,vault_id:vaultId,kind,entry_count:manifest.items.length,expires_at:manifest.expires_at,envelope});
      if(alive.current){setSelected([]);setNotice('Encrypted plan approved for 30 minutes. Open the connected companion, unlock this vault and choose Approved account actions. No website has been changed yet.');}
    });}}>
      {logins.map(entry=><label className="check" key={entry.id}><input type="checkbox" disabled={!canPrepare || busy || !!entry.pending_change} checked={selected.includes(entry.id)} onChange={event=>setSelected(list=>event.target.checked?[...list,entry.id].slice(0,20):list.filter(id=>id!==entry.id))}/>{entry.title} · {entry.origin} · {entry.username}{entry.pending_change?' · pending change':''}</label>)}
      {!logins.length && <p>Add a login before preparing account changes.</p>}
      <label className="check"><input type="checkbox" name="approval" required disabled={!canPrepare || busy}/>I approve preparation for the selected accounts. The operator may open their security pages and fill supported change forms, but will not submit them.</label><button className="button" disabled={busy || !canPrepare || !selected.length}>{busy?'Encrypting approval…':'Approve selected account preparation'}</button>
    </form>
    {logins.filter(e=>e.pending_change).map(entry=><div className="notice spaced" key={entry.id}><h4>Pending replacement · {entry.title}</h4><p>{entry.origin} · {entry.username}</p><p className="fine">The original saved login is still active in the vault. A proposed replacement is encrypted alongside it, so a closed popup or interrupted action does not lose the password. Confirm only after the website accepted it; discard only if it was not used.</p>{reveal===entry.id && <code className="fingerprint">{entry.pending_change.password}</code>}<button className="button secondary" onClick={()=>setReveal(reveal===entry.id?null:entry.id)}>Show staged password for 10 seconds</button>{onSave && <><button className="button" disabled={busy || !canEdit} onClick={()=>run(async()=>{await onSave(finishChange(entries,entry.id,entry.pending_change.action_id,true));if(alive.current)setNotice('Saved the staged password after your confirmation. This records your report, not independent website verification.');})}>Website accepted it — use staged password</button><button className="button secondary" disabled={busy || !canEdit} onClick={()=>run(async()=>{await onSave(finishChange(entries,entry.id,entry.pending_change.action_id,false));if(alive.current)setNotice('Proposal discarded; original login retained.');})}>Not used — discard proposal</button></>}</div>)}
    <ActionFeed vaultId={vaultId}/>
  </section>;
}
