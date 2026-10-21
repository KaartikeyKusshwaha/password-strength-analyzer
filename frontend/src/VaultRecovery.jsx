import {useEffect,useRef,useState} from 'react';
import {api} from './api';
import {parseRecoveryKit,prepareRecoveryKit,recoverWithKit,rotateProtectedVault} from './vault-v2';

function downloadKit(kit) {
  const url=URL.createObjectURL(new Blob([JSON.stringify(kit,null,2)],{type:'application/json'}));
  const link=document.createElement('a');link.href=url;link.download='sentinelops-recovery-'+kit.vault_id+'-'+kit.recovery_id+'.json';link.click();
  setTimeout(()=>URL.revokeObjectURL(url),1000);
}
export default function VaultRecovery({space,vaultPath,unlocked,disabled,onReplaced}) {
  const [mode,setMode]=useState(''),[busy,setBusy]=useState(false),[error,setError]=useState(''),[prepared,setPrepared]=useState(null),[requested,setRequested]=useState(false),[confirmed,setConfirmed]=useState(''),[stored,setStored]=useState(false),[source,setSource]=useState('current'),[kitInfo,setKitInfo]=useState(null);
  const generation=useRef(0),forms=useRef(null);
  function clear() {generation.current++;setMode('');setPrepared(null);setConfirmed('');setStored(false);setRequested(false);setKitInfo(null);setBusy(false);setError('');forms.current?.querySelectorAll('form').forEach(form=>form.reset());}
  useEffect(()=>{const hidden=()=>{if(document.hidden)clear();};document.addEventListener('visibilitychange',hidden);return()=>{generation.current++;document.removeEventListener('visibilitychange',hidden);};},[]);
  useEffect(()=>{if(!unlocked)clear();},[unlocked]);
  useEffect(()=>{if(!mode)return;let timer;const schedule=()=>{clearTimeout(timer);timer=setTimeout(clear,(space.lock_seconds||180)*1000);};schedule();document.addEventListener('pointerdown',schedule);document.addEventListener('keydown',schedule);return()=>{clearTimeout(timer);document.removeEventListener('pointerdown',schedule);document.removeEventListener('keydown',schedule);};},[mode,space.lock_seconds]);
  const active=mark=>mark===generation.current;
  async function prepare(event) {
    event.preventDefault();if(disabled||busy||!unlocked)return;const form=event.currentTarget,master=new FormData(form).get('master'),mark=++generation.current;form.reset();setBusy(true);setError('');
    try {
      const latest=await api(vaultPath);if(!active(mark))return;
      const result=await prepareRecoveryKit(latest.envelope,master);if(!active(mark))return;
      // Verify the encrypted kit locally before presenting it for activation.
      await recoverWithKit(result.kit,result.secret,master,{context:space.id,currentEnvelope:result.envelope,source:'current'});if(!active(mark))return;
      setPrepared({...result,revision:latest.revision});setRequested(false);setStored(false);setConfirmed('');
    }catch(e){if(active(mark))setError(e.message);}finally{if(active(mark))setBusy(false);}
  }
  async function activate() {
    if(disabled||!prepared||!requested||!stored||confirmed.trim().toUpperCase()!==prepared.secret||busy)return;
    const mark=++generation.current,captured=prepared;setBusy(true);setError('');
    try {
      const response=await api(vaultPath,{revision:captured.revision,envelope:captured.envelope,rotation_reason:'recovery-kit'});
      if(!active(mark))return;
      clear();onReplaced(captured.envelope,response.revision,'Recovery kit activated. Keep the downloaded kit and its recovery key separately. Older kits no longer unlock future data; reconnect browsers for this vault.');
    }catch(e){if(active(mark))setError('Activation was not confirmed. Keep the kit and key and check the vault before retrying. '+e.message);}finally{if(active(mark))setBusy(false);}
  }
  async function recover(event) {
    event.preventDefault();if(disabled||busy)return;const form=event.currentTarget,fields=new FormData(form),file=form.elements.kit.files[0],selected=source,mark=++generation.current;
    const key=fields.get('recovery_key'),password=fields.get('new_master');form.reset();setBusy(true);setError('');
    try {
      if(password!==fields.get('confirm'))throw new Error('New master passphrases must match.');
      const {estimator}=await import('./strength');if(!active(mark))return;
      if(password.length<15||password.length>128||estimator.check(password).score<3)throw new Error('Choose a less predictable master passphrase (15–128 characters).');
      if(!file||file.size>150000)throw new Error('Choose the original recovery-kit JSON under 150 KB.');
      const kit=parseRecoveryKit(await file.text());if(!active(mark))return;
      const latest=await api(vaultPath);if(!active(mark))return;
      const replacement=await recoverWithKit(kit,key,password,{context:space.id,currentEnvelope:latest.envelope,source:selected});if(!active(mark))return;
      const response=await api(vaultPath,{revision:latest.revision,envelope:replacement,rotation_reason:'recovery-'+selected});if(!active(mark))return;
      clear();onReplaced(replacement,response.revision,'Vault recovered and locked with a fresh data key. Unlock using your new master passphrase. Previous kits cannot unlock future data; create a new kit and reconnect browsers.');
    }catch(e){if(active(mark))setError('Recovery was not confirmed. Check the latest vault before retrying. '+e.message);}finally{if(active(mark))setBusy(false);}
  }
  async function invalidate(event) {
    event.preventDefault();if(disabled||busy||!unlocked)return;const form=event.currentTarget,master=new FormData(form).get('master'),mark=++generation.current;form.reset();setBusy(true);setError('');
    try {
      const latest=await api(vaultPath);if(!active(mark))return;
      const replacement=await rotateProtectedVault(latest.envelope,master);if(!active(mark))return;
      const response=await api(vaultPath,{revision:latest.revision,envelope:replacement,rotation_reason:'invalidate-recovery-kits'});if(!active(mark))return;
      clear();onReplaced(replacement,response.revision,'Vault data key rotated. Older recovery kits no longer unlock future data. Historical copies remain decryptable. Unlock with the same master passphrase and reconnect browsers.');
    }catch(e){if(active(mark))setError('Key rotation was not confirmed. Check the vault before retrying. '+e.message);}finally{if(active(mark))setBusy(false);}
  }
  return <section className="panel spaced" ref={forms}><h2>Offline vault recovery</h2><p>Prepare a kit while you still know the master passphrase. Keep its encrypted file and separate random recovery key offline. Your sign-in account, the matching kit and key are required to recover current server data. Neither secret nor decrypted contents are sent to the server or AI.</p><p className="fine">Each activation or recovery rotates the data key, revokes this vault’s browser connections and cancels its private account-action queues. Previously staged passwords remain in encrypted entries. Master-passphrase changes alone do not invalidate kits. Old kits and keys can still open historical snapshots; this cannot erase copies. Restoring an old application backup can restore old key access; rotate again before storing new secrets.</p>
    <div className="inline"><button className="button secondary" disabled={disabled||busy||!unlocked} onClick={()=>{clear();setMode('prepare');}}>Prepare recovery kit</button><button className="button secondary" disabled={disabled||busy} onClick={()=>{clear();setMode('recover');setSource('current');}}>Recover with a kit</button><button className="text-button" disabled={disabled||busy||!unlocked} onClick={()=>{clear();setMode('invalidate');}}>Invalidate older kits for future data</button></div>
    {!unlocked&&<p className="fine">Unlock to prepare or invalidate kits. Recovery works while locked, but cannot be added retroactively after losing the master passphrase.</p>}{error&&<p role="alert" className="notice error">{error}</p>}
    {mode==='prepare'&&!prepared&&<form onSubmit={prepare}><label>Master passphrase for recovery setup<input name="master" type="password" autoComplete="off" required minLength={15} maxLength={256}/></label><button className="button" disabled={busy||disabled}>{busy?'Preparing locally…':'Prepare encrypted kit locally'}</button></form>}
    {prepared&&<div className="notice"><h3>Prepared, not activated</h3><p>The current vault has not changed yet. Download and verify the file, store this key separately, then activate. Closing, hiding or idle-locking this panel discards its unsaved state.</p><label>New recovery key<textarea readOnly rows={3} value={prepared.secret}/></label><button className="button secondary" disabled={busy} onClick={()=>{downloadKit(prepared.kit);setRequested(true);}}>Download encrypted recovery kit</button>{requested&&<p>Download requested. Verify that the JSON file was saved before continuing.</p>}<label>Retype or paste the saved recovery key<input type="password" value={confirmed} onChange={event=>setConfirmed(event.target.value)} autoComplete="off" maxLength={100}/></label><label className="check"><input type="checkbox" checked={stored} onChange={event=>setStored(event.target.checked)}/>I verified the kit file was saved and stored its key separately. Activate this new vault key and revoke this vault’s browser connections and account-action queues.</label><button className="button" disabled={busy||disabled||!requested||!stored||confirmed.trim().toUpperCase()!==prepared.secret} onClick={activate}>Activate recovery kit</button></div>}
    {mode==='recover'&&<form onSubmit={recover}><label>Recovery-kit JSON<input name="kit" type="file" accept="application/json,.json" required onChange={async event=>{const file=event.target.files[0],mark=generation.current;setError('');setKitInfo(null);try{if(!file||file.size>150000)throw new Error('Choose a recovery kit under 150 KB.');const kit=parseRecoveryKit(await file.text());if(active(mark))setKitInfo({created_at:kit.created_at,vault_id:kit.vault_id});}catch(e){if(active(mark))setError(e.message);}}}/></label>{kitInfo&&<p>Kit snapshot: {new Date(kitInfo.created_at).toLocaleString()}. {kitInfo.vault_id===space.id?'Matches this vault identifier.':'This kit belongs to a different vault.'}</p>}<label>Saved recovery key<input type="password" name="recovery_key" autoComplete="off" required maxLength={100}/></label><label>Recovery source<select disabled={busy||disabled} value={source} onChange={event=>setSource(event.target.value)}><option value="current">Current encrypted server vault</option><option value="snapshot">Explicitly restore the kit snapshot</option></select></label>{source==='snapshot'&&<label className="check"><input type="checkbox" required/>Replace current entries with the kit’s older snapshot. Changes after its date will be overwritten; export the current encrypted backup first.</label>}<label>Recovery new master passphrase<input name="new_master" type="password" autoComplete="new-password" required minLength={15} maxLength={128}/></label><label>Confirm recovery new master passphrase<input name="confirm" type="password" autoComplete="new-password" required minLength={15} maxLength={128}/></label><label className="check"><input type="checkbox" required/>Recover the selected source with a new data key, revoke this vault’s browser connections and cancel its private account-action queues.</label><button className="button" disabled={busy||disabled}>{busy?'Recovering locally…':'Recover selected source'}</button></form>}
    {mode==='invalidate'&&<form onSubmit={invalidate}><p>This rotates the actual data key without changing the master passphrase. Older kits stop opening future vault data; their historical snapshots remain accessible.</p><label>Master passphrase for key rotation<input name="master" type="password" autoComplete="off" required minLength={15} maxLength={256}/></label><label className="check"><input type="checkbox" required/>Rotate the vault key and revoke this vault’s browser connections and private account-action queues.</label><button className="button" disabled={busy||disabled}>Rotate data key without a kit</button></form>}
    {mode&&<button className="text-button" onClick={clear}>Close recovery panel and clear local secrets</button>}
  </section>;
}
