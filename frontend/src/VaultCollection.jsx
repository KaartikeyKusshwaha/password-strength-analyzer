import { useEffect, useState } from 'react';
import { api } from './api';
import Vault from './Vault';
import TeamVaults from './TeamVaults';

function Properties({ value, onSave, busy }) {
  return <form className="operator-form" onSubmit={async event=>{event.preventDefault();const fields=new FormData(event.currentTarget);await onSave({name:fields.get('name'),purpose:fields.get('purpose'),color:fields.get('color'),lock_seconds:Number(fields.get('lock_seconds')),browser_enabled:fields.has('browser_enabled'),browser_save:fields.has('browser_save'),browser_fill:fields.has('browser_fill'),origins:fields.get('origins').split(',').map(v=>v.trim()).filter(Boolean),archived:fields.has('archived'),is_default:value?.is_default || fields.has('is_default')});}}>
    <label>Vault name<input name="name" defaultValue={value?.name || ''} placeholder="Personal, work, project or recovery" minLength={2} maxLength={60} required/></label>
    <div className="form-grid"><label>Purpose<select name="purpose" defaultValue={value?.purpose || 'personal'}><option value="personal">Personal</option><option value="work">Work accounts</option><option value="project">Project / client</option><option value="recovery">Recovery / offline use</option></select></label><label>Color<select name="color" defaultValue={value?.color || 'moss'}><option value="moss">Moss</option><option value="blue">Blue</option><option value="purple">Purple</option><option value="amber">Amber</option></select></label></div>
    <label>Lock after inactivity<select name="lock_seconds" defaultValue={value?.lock_seconds || 180}><option value={30}>30 seconds</option><option value={60}>1 minute</option><option value={180}>3 minutes</option><option value={300}>5 minutes</option><option value={900}>15 minutes</option></select></label>
    <label className="check"><input name="browser_enabled" type="checkbox" defaultChecked={value ? !!value.browser_enabled : true}/>Allow browser connections to this vault</label>
    <label className="check"><input name="browser_save" type="checkbox" defaultChecked={value ? !!value.browser_save : true}/>Allow browser assistant to save or update logins</label>
    <label className="check"><input name="browser_fill" type="checkbox" defaultChecked={value ? !!value.browser_fill : true}/>Allow filling selected logins from the browser companion</label>
    <label>Browser website scope (optional)<textarea name="origins" rows={2} defaultValue={value?.origins.join(', ') || ''} placeholder="https://accounts.example.com, https://app.example.com"/></label><p className="fine">Leave blank for any exact HTTPS website. These rules restrict the companion’s save and fill actions; they do not inspect encrypted entries on the server. Turning off browser access revokes that vault’s tokens. Already-unlocked windows must be closed to clear their local contents.</p>
    <label className="check"><input name="is_default" type="checkbox" defaultChecked={!!value?.is_default} disabled={!!value?.is_default}/>Use as the default vault</label>
    {value && !value.is_default && <label className="check"><input name="archived" type="checkbox" defaultChecked={!!value.archived}/>Archive this vault and revoke its browser connections</label>}
    <button className="button" disabled={busy}>{busy?'Saving…':value?'Save vault properties':'Create vault space'}</button>
  </form>;
}
export default function VaultCollection({me,initialMode='personal'}) {
  const [vaults,setVaults]=useState(null),[selected,setSelected]=useState(''),[creating,setCreating]=useState(false),[editing,setEditing]=useState(false),[busy,setBusy]=useState(false),[error,setError]=useState(''),[mode,setMode]=useState(initialMode);
  async function load(preferred) {const value=await api('/vaults');setVaults(value.vaults);setSelected(preferred || value.vaults.find(v=>v.is_default)?.id || value.vaults[0]?.id || '');}
  useEffect(()=>{load().catch(e=>setError(e.message));},[]);
  const active=vaults?.find(v=>v.id===selected);
  async function save(value) {setBusy(true);setError('');try{const result=await api(creating?'/vaults':'/vaults/'+selected,value);await load(result.id);setCreating(false);setEditing(false);}catch(e){setError(e.message);}finally{setBusy(false);}}
  return <>
    {me && <div className="inline spaced"><button className={'button '+(mode==='personal'?'':'secondary')} onClick={()=>setMode('personal')}>Personal vaults</button><button className={'button '+(mode==='team'?'':'secondary')} onClick={()=>setMode('team')}>Shared workspace vaults</button></div>}
    {mode==='team'?<TeamVaults key={me.workspace} me={me}/>:<>
    {error && <p className="notice error" role="alert">{error}</p>}
    <section className="panel vault-switcher"><div><span className="eyebrow">YOUR VAULT COLLECTION</span><h2>Separate contexts. One control center.</h2><p className="muted">Each vault has its own encrypted contents and master passphrase. The same website or account can exist in several vaults without overwriting another vault’s login.</p></div><div className="inline">{vaults?.length>0 && <label>Active vault<select value={selected} onChange={event=>{setSelected(event.target.value);setCreating(false);setEditing(false);}}>{vaults.map(v=><option key={v.id} value={v.id}>{v.name}{v.is_default?' · default':''}{v.archived?' · archived':''}</option>)}</select></label>}<button className="button" onClick={()=>{setCreating(!creating);setEditing(false);}}>New vault</button>{active && <button className="button secondary" onClick={()=>{setEditing(!editing);setCreating(false);}}>Vault properties</button>}</div></section>
    {(creating || editing) && <section className="panel spaced"><h2>{creating?'Create a vault':'Vault properties'}</h2><Properties key={creating?'new':active.id+active.updated_at} value={creating?null:active} onSave={save} busy={busy}/></section>}
    {vaults === null ? <p>Loading your vaults…</p> : !vaults.length && !creating ? <section className="panel spaced"><h2>Create your first vault</h2><p>Choose its name and browser permissions, then set the master passphrase locally. Only encrypted credentials are stored on the backend.</p><button className="button" onClick={()=>setCreating(true)}>Create my vault</button></section> : active && !creating && !editing ? <Vault key={active.id+active.updated_at} space={active} me={me} otherVaults={vaults.filter(v=>v.id!==active.id && !v.archived)}/> : null}
    </>}
  </>;
}
