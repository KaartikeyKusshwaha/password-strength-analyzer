import ProofPacks from './ProofPacks';
import AccessReviews from './AccessReviews';
import FreelancerInvite from './FreelancerInvite';
import AccessLeases from './AccessLeases';
import VaultOwnership from './VaultOwnership';
import React,{useEffect,useState} from 'react';
import CredentialDebt from './CredentialDebt';
import ClientHandoffs from './ClientHandoffs';
import CloudConnect from './CloudConnect';
import {accessRequest} from './access-client';
import {rotateConnectedVault} from './workflow-rotation';

const terminal=new Set(['complete','dry_run_complete','cancelled','blocked']);
const labels={awaiting_approval:'Review and approve',queued:'Queued',running:'Removing selected access',waiting_unlock:'Access removed; vault key rotation needed',complete:'Selected vault steps verified',dry_run_complete:'Preview complete; no access changed',cancelled:'Cancelled',blocked:'Stopped; review required'};

export default function AccessWorkflows({browser=chrome,request=accessRequest,vaultSession=null,selectedVault=null,vaultUnlocked=false,onRotated=()=>{},onTransferred=onRotated,onApproved=()=>{},onVaultChanged=()=>{}}){
  const [connection,setConnection]=useState(null),[ready,setReady]=useState(false),[map,setMap]=useState(null),[runs,setRuns]=useState([]),[client,setClient]=useState(''),[person,setPerson]=useState(''),[preview,setPreview]=useState(true),[busy,setBusy]=useState(false),[error,setError]=useState(''),[notice,setNotice]=useState(''),[report,setReport]=useState(null);
  async function refresh(value=connection){
    const [context,result]=await Promise.all([request(value,'context'),request(value,'workflows')]);setMap(context);setRuns(result.workflows);
  }
  useEffect(()=>{let live=true;browser.storage.local.get('accessConnection').then(async saved=>{if(!live)return;if(saved.accessConnection){setConnection(saved.accessConnection);try{await refresh(saved.accessConnection);}catch(e){if(live)setError(e.message);}}if(live)setReady(true);});return()=>{live=false;};},[]);
  useEffect(()=>{if(!connection||!runs.some(run=>!terminal.has(run.status)&&run.status!=='awaiting_approval')&&!map?.debt?.exposures.some(item=>['queued','running','awaiting_confirmation'].includes(item.action_status)))return;const timer=setInterval(()=>refresh().catch(e=>setError(e.message)),5000);return()=>clearInterval(timer);},[connection,runs]);
  const people=[...new Map((map?.grants||[]).filter(grant=>grant.client===client).map(grant=>[grant.person_id,grant])).values()];
  async function action(work,reload=true){setBusy(true);setError('');setNotice('');try{await work();if(reload)await refresh();}catch(e){setError(e.message);}finally{setBusy(false);}}
  return <details><summary>Client access · offboarding workflows</summary><p>Remove selected client vault memberships with one approved plan. Website sessions and copied passwords require separate follow-up.</p>
    {!ready?<p>Loading workflow connection…</p>:!connection?<CloudConnect browser={browser} scope="access" onConnected={value=>{setConnection(value);refresh(value).catch(e=>setError(e.message));}}/>:<>
      <button className="secondary" disabled={busy} onClick={()=>action(async()=>{})}>Refresh workflows</button>
      <button className="secondary" disabled={busy} onClick={()=>action(async()=>{await request(connection,'revoke',{});await browser.storage.local.remove('accessConnection');setConnection(null);setMap(null);setRuns([]);},false)}>Disconnect workflows</button>
      {map&&<form onSubmit={event=>{event.preventDefault();action(async()=>{await request(connection,'workflows',{client_id:client,person_id:person,dry_run:preview});setNotice('Plan prepared. Review its vaults before approving.');});}}>
        <label>Client<select required value={client} onChange={event=>{setClient(event.target.value);setPerson('');}}><option value="">Choose client</option>{map.clients.map(item=><option key={item.id} value={item.id}>{item.name}</option>)}</select></label>
        <label>Person<select required value={person} onChange={event=>setPerson(event.target.value)}><option value="">Choose person</option>{people.map(item=><option key={item.person_id} value={item.person_id}>{item.email}</option>)}</select></label>
        <label><input type="checkbox" checked={preview} onChange={event=>setPreview(event.target.checked)}/>Preview only; make no changes</label>
        <button disabled={busy||!person||!client}>Prepare offboarding plan</button>
        {!map.clients.length&&<p>Link client vaults in the control room before preparing your first plan.</p>}
      </form>}
      {map&&<CredentialDebt connection={connection} map={map} session={vaultSession} unlocked={vaultUnlocked} request={request} refresh={refresh} onApproved={onApproved} onVaultChanged={onVaultChanged}/>}
      <VaultOwnership connection={connection} session={vaultSession} selectedVault={selectedVault} unlocked={vaultUnlocked} request={request} onTransferred={onTransferred}/>
      {map&&<FreelancerInvite connection={connection} map={map} session={vaultSession} selectedVault={selectedVault} unlocked={vaultUnlocked} request={request} onChanged={refresh}/>}
      {map&&<ProofPacks connection={connection} map={map} request={request}/>}
      {map&&<AccessReviews connection={connection} map={map} request={request}/>}
      {map&&<AccessLeases connection={connection} map={map} request={request} onChanged={refresh}/>}
      {map&&<ClientHandoffs connection={connection} map={map} runs={runs} request={request}/>}
      {runs.map(run=><section key={run.id} aria-label="Offboarding plan"><h3>{labels[run.status]||run.status}</h3><p>{map?.clients.find(item=>item.id===run.client)?.name||'Client'} · {map?.grants.find(item=>item.person_id===run.person)?.email||'Selected member'}</p><p>{run.plan.dry_run?'Preview only.':'Real access removal.'} {run.plan.vaults.length} vault(s). {run.steps.filter(step=>['complete','simulated'].includes(step.status)).length}/{run.steps.length} steps.</p>
        <ul>{run.plan.vaults.map(item=><li key={item.vault}>{map?.systems.find(system=>system.id===item.vault)?.name||item.vault}</li>)}</ul>
        <p className="fine">{run.coverage}</p>
        {run.rechecks?.some(check=>check.status==='attention')&&<p role="alert">A scheduled vault recheck needs attention. Access may have reappeared or the vault could not be verified. Review the evidence report; nothing was automatically removed.</p>}
        {run.status==='waiting_unlock'&&<><p>Select and unlock each affected shared vault below. Rotation runs locally in this extension and distributes a new key only to remaining members. Website passwords still need changing separately.</p>{run.plan.vaults.filter(item=>map?.systems.some(system=>system.id===item.vault&&system.rotation_required)).map(item=><div key={item.vault}>{selectedVault?.vaultId===item.vault&&vaultUnlocked?<button disabled={busy} onClick={()=>action(async()=>{await rotateConnectedVault(connection,vaultSession,run.id,item.vault,request);onRotated();setNotice('Vault key rotated. The workflow will verify remaining access. Unlock again before further vault actions.');})}>Rotate connected vault key</button>:<p className="fine">Connect and unlock: {map?.systems.find(system=>system.id===item.vault)?.name||item.vault}</p>}</div>)}</>}
        {run.status==='awaiting_approval'&&<form onSubmit={event=>{event.preventDefault();const form=event.currentTarget;const password=form.elements.password.value,code=form.elements.code.value;form.reset();action(async()=>{await request(connection,'workflows/'+run.id+'/approve',{plan_digest:run.plan_digest,approved:true,password,code});});}}>
          <label>Current account password<input name="password" type="password" autoComplete="current-password" required maxLength={256}/></label>
          <label>Unused MFA or recovery code<input name="code" autoComplete="one-time-code" required maxLength={80}/></label>
          <label><input type="checkbox" required/>I approve this exact {run.plan.dry_run?'preview':'access removal'} plan.</label><button disabled={busy}>Approve plan</button>
        </form>}
        {!['complete','dry_run_complete','cancelled'].includes(run.status)&&<button className="secondary" disabled={busy} onClick={()=>action(async()=>{await request(connection,'workflows/'+run.id+'/cancel',{});setNotice('Cancelled. Completed removals are not undone.');})}>Cancel plan</button>}
        <button className="secondary" disabled={busy} onClick={()=>action(async()=>setReport(await request(connection,'workflows/'+run.id+'/report')))}>View evidence report</button><details><summary>Step history</summary><ol>{run.steps.map(step=><li key={step.id}>{step.action}: {step.status}{step.outcome?' · '+step.outcome:''}</li>)}</ol></details>
      </section>)}
      {report&&<section><h3>Vault offboarding evidence</h3><p>{report.limitations}</p><p>Audit chain: {report.audit.valid?'valid at generation':'validation failed'}. This is not an independent audit.</p><textarea readOnly aria-label="Offboarding evidence JSON" value={JSON.stringify(report,null,2)} rows={12}/><button className="secondary" onClick={()=>setReport(null)}>Close report</button></section>}
    </>}{notice&&<p role="status">{notice}</p>}{error&&<><p role="alert" className="error">{error}</p>{connection&&<button className="secondary" disabled={busy} onClick={async()=>{await browser.storage.local.remove('accessConnection');setConnection(null);setMap(null);setRuns([]);setError('');setReport(null);setNotice('Local workflow connection forgotten. An unreachable server grant may remain valid until expiry; forgetting does not cancel approved plans.');}}>Forget local workflow connection</button>}</>}
  </details>;
}
