import React, { useEffect, useRef, useState } from 'react';
import { createRoot } from 'react-dom/client';
import { SaveSession } from './vault-session';
import './popup.css';
document.body.classList.add('vault-frame');

export function Frame() {
  const session = useRef(new SaveSession(chrome));
  const [capture,setCapture]=useState(null), [ready,setReady]=useState(false), [unlocked,setUnlocked]=useState(false),
    [busy,setBusy]=useState(false), [error,setError]=useState(''), [saved,setSaved]=useState(false), [update,setUpdate]=useState(false), [connections,setConnections]=useState([]),[selection,setSelection]=useState('');
  const [seconds,setSeconds]=useState(null),[expired,setExpired]=useState(false);
  useEffect(() => {
    chrome.storage.local.get(['connections','connection']).then(value=>{const list=value.connections || (value.connection?[value.connection]:[]);setConnections(list);setSelection(list.findIndex(c=>c.token===value.connection?.token));});
    chrome.runtime.sendMessage({type:'frame-capture', id:location.hash.slice(1)})
      .then(value => {if(!value?.entry) throw new Error('No current save request for this tab. Close this panel and choose Save again.'); setCapture(value.entry);})
      .catch(e=>setError(e.message)).finally(()=>setReady(true));
    const hidden=()=>{if(document.hidden){session.current.lock();setUnlocked(false);setUpdate(false);}};document.addEventListener('visibilitychange',hidden);
    return ()=>{document.removeEventListener('visibilitychange',hidden);session.current.lock();};
  },[]);
  useEffect(()=>{
    if(!capture || saved)return;
    let ended=false;
    const expire=()=>{if(ended)return;ended=true;session.current.lock();setUnlocked(false);setUpdate(false);setCapture(null);setExpired(true);setSeconds(0);};
    const tick=()=>{const left=Math.ceil((capture.expires-Date.now())/1000);setSeconds(Math.max(0,left));if(!Number.isFinite(left) || left<=0)expire();};
    tick();
    const deadline=setTimeout(expire,Number.isFinite(capture.expires)?Math.max(0,Math.min(180000,capture.expires-Date.now())):0);
    const interval=setInterval(tick,1000);
    return()=>{ended=true;clearTimeout(deadline);clearInterval(interval);};
  },[capture,saved]);
  useEffect(()=>{
    if(!unlocked)return;
    const timer=setTimeout(()=>{session.current.lock();setUnlocked(false);},(session.current.policy?.lock_seconds || 180)*1000);
    return()=>clearTimeout(timer);
  },[unlocked]);
  return <main><header><span className="logo">S</span><div><h1>SentinelOps</h1><small>PRIVATE VAULT CONNECTION</small></div></header>
    {!ready ? <p>Opening secure save…</p> : saved ? <><h2>Encrypted and saved</h2><p>Your login is synchronized with the selected vault in your dashboard.</p><p>Saving here does not confirm that the website accepted this password. Finish signup or the password change on the website.</p></> : expired ? <>
      <h2>Save request expired</h2>
      <p>Close this window. On the website, focus the password field and choose Save securely again. Then unlock and confirm saving within three minutes.</p>
      <p className="fine">This window has locked and discarded its captured login. If saving was already in progress, check your dashboard before retrying.</p>
      <button onClick={()=>window.close()}>Close this window</button>
    </> : <>
      <h2>{unlocked ? 'Confirm save to '+(session.current.policy?.name || 'your vault') : 'Unlock to save securely'}</h2>
      {capture && <><p><strong>{capture.origin}</strong></p><p>{capture.username || 'No username detected. Add it on the website before saving if required.'}</p></>}
      {capture && seconds!==null && <p className="notice">Save request expires in {seconds}s. Complete both unlock and saving before then.</p>}
      <p className="fine">This panel belongs to the browser extension. The website cannot read your master passphrase. No passwords are sent to AI.</p>
      {connections.length>0 && <label>Save in vault<select value={selection} disabled={busy} onChange={async event=>{const index=Number(event.target.value);session.current.lock();setUnlocked(false);setUpdate(false);setError('');setSelection(index);await chrome.storage.local.set({connection:connections[index]});}}>{connections.map((value,index)=><option key={index} value={index}>{value.vaultName || 'Vault name not verified'} · {new URL(value.origin).host}</option>)}</select></label>}
      {error && <p role="alert" className="error">{error}</p>}
      {!unlocked ? <form onSubmit={async e=>{e.preventDefault();setBusy(true);setError('');const form=e.currentTarget;const master=form.elements.master.value, fingerprint=form.elements.fingerprint?.value || '';form.reset();try{await session.current.unlock(master,fingerprint,connections[Number(selection)] || null);setUnlocked(true);}catch(e){setError(e instanceof TypeError ? 'Could not reach SentinelOps. Keep your local app running.' : e.message);}finally{setBusy(false);}}}>
        <label>{connections[Number(selection)]?.vaultKind==='shared'?'Sharing passphrase':'Master passphrase'}<input name="master" type="password" required minLength={15} maxLength={256} autoComplete="off"/></label>
        {connections[Number(selection)]?.vaultKind==='shared' && !connections[Number(selection)].ownerIsSelf && <><p className="fine">Compare the vault owner's fingerprint through a trusted channel before opening this vault.</p><code className="fingerprint">{connections[Number(selection)].ownerFingerprint}</code><label>Verified owner fingerprint<input name="fingerprint" pattern="[a-fA-F0-9]{64}" autoComplete="off" maxLength={64} required/></label></>}
        <button disabled={busy || !capture}>{busy?'Unlocking locally…':'Unlock'}</button>
      </form> : <>{session.current.policy && !session.current.policy.browser_save && <p className="notice">This vault currently allows viewing only in the companion. Choose a vault with save access, or ask its owner to review your access and any pending key rotation.</p>}{update && <p className="notice">This account is already saved. Confirm the website accepted the new password before replacing your saved login.</p>}<button disabled={busy || session.current.policy?.browser_save===false} onClick={async()=>{setBusy(true);setError('');try{const result=await session.current.save(capture,update);if(result.needsConfirmation){setUpdate(true);return;}setSaved(true);session.current.lock();setCapture(null);await chrome.runtime.sendMessage({type:'capture-saved',id:location.hash.slice(1)});}catch(e){setError(e.message);if(/changed elsewhere|revoked|locked/.test(e.message)){session.current.lock();setUnlocked(false);}}finally{setBusy(false);}}}>{busy?'Encrypting…':update?'Website accepted it — update saved login':'Encrypt and save login'}</button></>}
    </>}
  </main>;
}
const root=document.getElementById('root');
if(root)createRoot(root).render(<Frame/>);
