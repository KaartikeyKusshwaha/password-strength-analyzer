import React,{useEffect,useRef,useState} from 'react';
import {api} from './api';
import WorkflowHistory from './WorkflowHistory';

export default function ClientAccess(){
  const [map,setMap]=useState(null),[error,setError]=useState(''),[busy,setBusy]=useState(false);
  const [client,setClient]=useState(''),[person,setPerson]=useState('');
  const live=useRef(true);
  async function load(){const value=await api('/clients/access-map');if(live.current)setMap(value);}
  useEffect(()=>{live.current=true;load().catch(e=>{if(live.current)setError(e.message);});return()=>{live.current=false;};},[]);
  async function run(action){setBusy(true);setError('');try{await action();await load();}catch(e){if(live.current)setError(e.message);}finally{if(live.current)setBusy(false);}}
  const people=[...new Map((map?.grants||[]).map(row=>[row.person_id,row.email])).entries()];
  const rows=(map?.grants||[]).filter(row=>(!client||row.client===client)&&(!person||row.person_id===person));
  const clientName=id=>map.clients.find(item=>item.id===id)?.name||'Unavailable client';
  const vaultName=id=>map.systems.find(item=>item.id===id)?.name||'Unavailable vault';
  return <section aria-label="Client access map">
    {error&&<p role="alert" className="notice error">{error}</p>}
    <div className="panel"><h2>Who can touch each client?</h2>
      <p>Link existing shared vaults to clients. Memberships below are read live; credential contents are never loaded by this map.</p>
      <button className="button secondary" disabled={busy} onClick={()=>run(async()=>{})}>Refresh access map</button>
      {!map&&!error&&<p role="status">Loading access metadata…</p>}
      {map&&<><p className="notice">{map.coverage}</p>
        {!map.clients.length&&<p>No clients yet. Create a client record, then link an existing shared vault.</p>}
        <div className="inline"><label>Client<select value={client} onChange={e=>setClient(e.target.value)}><option value="">All clients</option>{map.clients.map(item=><option key={item.id} value={item.id}>{item.name}</option>)}</select></label>
          <label>Person<select value={person} onChange={e=>setPerson(e.target.value)}><option value="">All people</option>{people.map(([id,email])=><option key={id} value={id}>{email}</option>)}</select></label></div>
        {map.systems.filter(item=>(!client||item.client===client)&&item.rotation_required).map(item=><p className="notice" key={item.client+item.id}>Key rotation required: {clientName(item.client)} / {item.name}. Removed members may retain old credentials; new access is not fully secured until rotation and affected website password changes are completed.</p>)}
        <table><caption>Vault-derived client access</caption><thead><tr><th>Client</th><th>Person</th><th>Vault source</th><th>Role</th><th>Evidence</th></tr></thead>
          <tbody>{rows.map(row=><tr key={row.client+row.person_id+row.system_id}><td>{clientName(row.client)}</td><td>{row.email}</td><td>{vaultName(row.system_id)}</td><td>{row.role}</td><td>{row.state==='accepted'?'Accepted vault membership':'Invitation pending · not accepted access'}</td></tr>)}</tbody></table>
        {!rows.length&&<p>No matching memberships. This is not proof that no external account access exists.</p>}
      </>}
    </div>
    <div className="panel"><h2>Manage client links</h2><p>These links organize metadata. Unlinking does not revoke anyone’s access.</p>
      <form onSubmit={e=>{e.preventDefault();const form=e.currentTarget,name=new FormData(form).get('name');run(async()=>{await api('/clients',{name});if(live.current)form.reset();});}}>
        <label>Client name<input name="name" required minLength={2} maxLength={100}/></label><button className="button" disabled={busy}>Create client record</button>
      </form>
      {map?.clients.length>0&&<form onSubmit={e=>{e.preventDefault();const fields=new FormData(e.currentTarget);run(()=>api('/clients/'+fields.get('client')+'/vaults',{vault_id:fields.get('vault')}));}}>
        <label>Client to link<select name="client" required>{map.clients.map(item=><option key={item.id} value={item.id}>{item.name}</option>)}</select></label>
        <label>Existing shared vault<select name="vault" required>{!map.available_vaults.length&&<option value="">No shared vaults available</option>}{map.available_vaults.map(item=><option key={item.id} value={item.id}>{item.name}</option>)}</select></label>
        <button className="button" disabled={busy||!map.available_vaults.length}>Link shared vault</button>
      </form>}
      {map?.systems.map(item=><div className="member-row" key={item.client+item.id}><p>{clientName(item.client)} / {item.name}</p><button className="button secondary" disabled={busy} onClick={()=>run(()=>api('/clients/'+item.client+'/vaults/'+item.id+'/unlink',{}))}>Unlink metadata: {item.name}</button></div>)}
    </div>
    {map&&<WorkflowHistory/>}
  </section>;
}
