import {useEffect,useMemo,useRef,useState} from 'react';
import {api} from './api';
import {validateHistory} from './entry-history';

const descriptions={
  'vault.created':'Vault space created','vault.properties_updated':'Vault properties updated',
  'vault.default_changed':'Default-vault selection changed','vault.archived':'Vault archived',
  'vault.restored':'Vault restored from archive','vault.initialized':'Encrypted vault initialized',
  'vault.saved':'Encrypted vault saved','vault.browser_saved':'Encrypted vault saved by a browser',
  'vault.protection_changed':'Vault protection changed','vault.companion_connected':'Browser connection created',
  'vault.companions_revoked':'Browser connections revoked','vault.recovery_restored':'Vault recovered from an application backup',
  'team_vault.created':'Shared vault created','team_vault.browser_policy_updated':'Shared browser permissions updated',
  'team_vault.invitation_accepted':'Shared invitation accepted','team_vault.invited':'Shared access invited',
  'team_vault.saved':'Encrypted shared vault saved','team_vault.access_revoked':'Shared access removed',
  'team_vault.key_rotated':'Shared vault encryption key rotated','team_vault.browser_saved':'Shared vault saved by a browser',
  'team_vault.companion_connected':'Shared browser connection created','team_vault.companions_revoked':'Shared browser connections revoked',
  'team_vault.recovery_restored':'Shared vault recovered from an application backup',
  'team_vault.ownership_proposed':'Vault ownership transfer proposed','team_vault.ownership_cancelled':'Ownership transfer cancelled',
  'team_vault.ownership_declined':'Ownership transfer declined','team_vault.ownership_transferred':'Vault ownership transferred with a new encryption key',
  'team_vault.ownership_invalidated':'Ownership proposal invalidated by a vault change',
  'credential_action.approved':'Private account-action plan approved','credential_action.cancelled':'Private account-action plan cancelled',
  'credential_action.claimed':'Account-action plan claimed by a browser','credential_action.resumed':'Account-action plan resumed',
  'credential_action.expired':'Account-action approval expired','credential_action.interrupted':'Account-action lease interrupted',
  'credential_action.prepared':'Account-change form reported prepared','credential_action.needs_attention':'Account action needs attention',
  'credential_action.confirmed_by_user':'Website change reported by the user','credential_action.discarded':'Staged proposal reported discarded',
};
const localDescriptions={saved:'Account saved locally',credential_saved:'Credential saved locally',details_saved:'Account details saved locally',proposal_staged:'Replacement password staged',proposal_discarded:'Staged password discarded',change_confirmed_by_user:'Website change reported by the user',reviewed:'Account marked reviewed',archived:'Account archived',restored:'Account restored from archive'};
function Timestamp({value}) {
  return Number.isFinite(Date.parse(value))?<time dateTime={value}>{new Date(value).toLocaleString()}</time>:<span>Unknown time</span>;
}
export default function VaultActivity({kind,vaultId,entries=null}) {
  const scope=kind+'/'+vaultId;
  const [open,setOpen]=useState(false),[result,setResult]=useState(null),[loading,setLoading]=useState(false),[error,setError]=useState(''),[localLimit,setLocalLimit]=useState(50);
  const generation=useRef(0),currentScope=useRef(scope);
  useEffect(()=>{
    currentScope.current=scope;generation.current++;setResult(null);setOpen(false);setLoading(false);setError('');setLocalLimit(50);
    return ()=>{generation.current++;};
  },[scope]);
  const local=useMemo(()=>{
    const events=[];let unknown=0;
    for(const entry of entries || []){
      try{validateHistory(entry.history);}catch{unknown++;continue;}
      if(!entry.history?.events?.length){unknown++;continue;}
      entry.history.events.forEach((event,index)=>events.push({key:entry.id+':'+index,at:event.at,label:localDescriptions[event.kind],title:entry.title}));
    }
    events.sort((a,b)=>Date.parse(b.at)-Date.parse(a.at));
    return {events,unknown};
  },[entries]);
  async function load(reset=false) {
    if(loading || !vaultId)return;
    const before=reset?null:result?.next_before,mark=++generation.current,captured=scope;
    setLoading(true);setError('');
    try{
      const value=await api('/vault-activity/'+encodeURIComponent(kind)+'/'+encodeURIComponent(vaultId)+(before?'?before='+before:''));
      if(mark!==generation.current || currentScope.current!==captured)return;
      if(!Array.isArray(value.events))throw new Error('Vault activity is unavailable. Retry to load the recorded events.');
      setResult(old=>{
        const merged=new Map((!reset && old?.scope===captured?old.events:[]).map(event=>[event.id,event]));
        for(const event of value.events)if(!merged.has(event.id))merged.set(event.id,event);
        return {scope:captured,events:[...merged.values()],next_before:value.next_before};
      });
    }catch(e){if(mark===generation.current && currentScope.current===captured){setResult(null);setError(e.message);}}
    finally{if(mark===generation.current && currentScope.current===captured)setLoading(false);}
  }
  if(!vaultId)return null;
  const visible=result?.scope===scope?result:null;
  return <section className="panel spaced vault-activity" aria-label="Vault activity timeline">
    <div className="section-heading"><div><span className="eyebrow">VAULT ACTIVITY</span><h3>Follow what changed.</h3></div>
      <button type="button" className="button secondary" aria-expanded={open} onClick={()=>{
        if(open){generation.current++;setOpen(false);setLoading(false);setResult(null);setError('');}
        else{setOpen(true);load(true);}
      }}>{open?'Hide vault activity':'Show vault activity'}</button>
    </div>
    {open && <>
      <h4>Service-recorded events</h4><p className="fine">Vault saves, recorded access changes and reported account-action states. This filtered service log is not an independently verified audit. A saved password or user report does not prove a website accepted a change. Earlier unrecorded activity is unavailable.</p>
      <button type="button" className="button secondary" disabled={loading} onClick={()=>load(true)}>Refresh vault activity</button>
      {error && <p className="notice error" role="alert">{error}</p>}
      {loading && <p role="status">Loading recorded vault activity…</p>}
      {visible && !visible.events.length && <p>No service events have been recorded for this vault. This does not establish that no activity occurred.</p>}
      {visible?.events.length>0 && <ol className="vault-activity-list">{visible.events.map(event=><li key={event.id}><div><strong>{descriptions[event.action] || 'Recorded vault event'}</strong><small>{event.actor_label || 'Unavailable actor'}</small></div><Timestamp value={event.at}/></li>)}</ol>}
      {visible?.next_before && <button type="button" className="button secondary" disabled={loading} onClick={()=>load(false)}>Load older vault events</button>}
      <h4 className="spaced">Encrypted account observations</h4>
      {entries===null?<p>Unlock this vault to see its private account observations.</p>:<>
        <p className="fine">Client-reported history retained inside the encrypted vault: latest eight observations per current account, including archived accounts. This is not a complete or independently verified account history. Removed entries and older trimmed events are unavailable.</p>
        {local.unknown>0 && <p>{local.unknown} account(s) have no supported recorded history.</p>}
        {!local.events.length && <p>No encrypted account observations are available.</p>}
        {!!local.events.length && <ol className="vault-activity-list">{local.events.slice(0,localLimit).map(event=><li key={event.key}><div><strong>{event.label}</strong><small>{event.title}</small></div><Timestamp value={event.at}/></li>)}</ol>}
        {localLimit<local.events.length && <button type="button" className="button secondary" onClick={()=>setLocalLimit(value=>value+50)}>Show older account observations</button>}
      </>}
    </>}
  </section>;
}
