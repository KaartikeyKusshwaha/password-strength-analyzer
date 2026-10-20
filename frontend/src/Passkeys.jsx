import {useEffect,useRef,useState} from 'react';
import {api} from './api';
import {supportedPasskeys,performPasskey} from './passkey-client';

export function PasskeySignIn({disabled,onClick}){
  const [status,setStatus]=useState(null);
  useEffect(()=>{let alive=true;api('/passkeys/status').then(value=>{if(alive)setStatus(value);}).catch(()=>{if(alive)setStatus({available:false,reason:'Passkeys are unavailable on this server.'});});return()=>{alive=false;};},[]);
  const ready=status?.available && supportedPasskeys();
  return <div className="passkey-signin"><button type="button" className="button secondary" disabled={disabled || !ready} onClick={onClick}>Sign in with a passkey</button><p className="fine">{!status?'Checking passkey availability…':!status.available?(status.reason || 'Passkeys are unavailable on this server.'):!supportedPasskeys()?'This browser or context does not support passkeys.':'Enter your account email, then choose its passkey. Your vault master passphrase stays separate.'}</p></div>;
}

export default function Passkeys({mfaEnabled,onSessionChanged}){
  const [data,setData]=useState(null),[error,setError]=useState(''),[notice,setNotice]=useState(''),[busy,setBusy]=useState(false),[phase,setPhase]=useState(''),[selected,setSelected]=useState(null);
  const controller=useRef(null),mounted=useRef(true);
  async function load(){const value=await api('/passkeys');if(mounted.current)setData(value);}
  useEffect(()=>{mounted.current=true;load().catch(e=>{if(mounted.current)setError(e.message);});return()=>{mounted.current=false;controller.current?.abort();};},[]);
  async function submit(event){
    event.preventDefault();const fields=Object.fromEntries(new FormData(event.currentTarget));event.currentTarget.reset();
    setBusy(true);setError('');setNotice('');
    try {
      if(selected){await api('/passkeys/'+selected.id+'/remove',{password:fields.password,code:fields.code||''});if(mounted.current){setSelected(null);setNotice('Passkey removed. Other account sessions and pending passkey requests were revoked.');}await onSessionChanged?.();}
      else {const abort=new AbortController();controller.current=abort;await performPasskey('register',{...fields,signal:abort.signal,onPhase:next=>{if(mounted.current)setPhase(next);}});if(mounted.current)setNotice('Passkey enrolled for this SentinelOps account.');}
      await load();
    }catch(e){if(mounted.current)setError(e.message);}
    finally{controller.current=null;if(mounted.current){setBusy(false);setPhase('');}}
  }
  return <section className="panel" aria-label="Account passkeys"><h2>Passkeys for your account</h2><p className="muted">Sign into SentinelOps with your device or security key. An enabled authenticator factor is still required. Passkeys do not unlock your vaults or enroll other websites.</p>
    {error && <p className="notice error" role="alert">{error}</p>}{notice && <p className="notice" role="status">{notice}</p>}
    <button className="text-button" disabled={busy} onClick={()=>{setError('');load().catch(e=>setError(e.message));}}>Refresh passkeys</button>
    {!data?<p>{error?'Account passkeys could not be loaded. Use Refresh passkeys to retry.':'Loading account passkeys…'}</p>:!data.available?<p className="notice">Passkeys require an app configured at an HTTPS domain or localhost. This origin is unsupported; existing passwords and vault connections keep their current origin.</p>:<>
      {data.credentials.length?<ul className="passkey-list">{data.credentials.map(item=><li key={item.id}><strong>{item.label}</strong><p className="fine">Added {new Date(item.created_at*1000).toLocaleDateString()} · {item.last_used?'Last used '+new Date(item.last_used*1000).toLocaleString():'Not used yet'}</p><button className="text-button" disabled={busy} onClick={()=>{setSelected(item);setNotice('');setError('');}}>Remove {item.label}</button></li>)}</ul>:<p>No passkeys enrolled.</p>}
      {!supportedPasskeys() && !selected?<p className="notice">Enrollment is unavailable in this browser or context. You can still manage existing passkeys after reauthentication.</p>:null}
      <form className="passkey-form" onSubmit={submit} key={selected?.id || 'enroll'}><h3>{selected?'Remove '+selected.label:'Add a passkey'}</h3>
        {selected?<p className="fine">This removes its SentinelOps access and signs out your other account sessions. The device may keep a local copy that no longer works here.</p>:<label>Passkey name<input name="label" required maxLength={60} placeholder="Work laptop or security key" disabled={busy}/></label>}
        <label>Current account password<input name="password" type="password" autoComplete="current-password" required maxLength={128} disabled={busy}/></label>
        {mfaEnabled && <label>Unused authenticator or recovery code<input name="code" autoComplete="one-time-code" required maxLength={80} disabled={busy}/></label>}
        <button className="button secondary" type="submit" disabled={busy || (!selected && (!supportedPasskeys() || data.credentials.length>=10))}>{busy?(phase==='finishing'?'Saving passkey…':phase==='authenticator'?'Complete the device prompt…':'Verifying…'):selected?'Remove this passkey':'Create account passkey'}</button>
        {selected && <button type="button" className="text-button" disabled={busy} onClick={()=>setSelected(null)}>Keep this passkey</button>}
        {busy && !selected && phase!=='finishing' && <button type="button" className="text-button" onClick={()=>controller.current?.abort()}>Cancel passkey request</button>}
      </form><p className="fine">Up to ten active passkeys. No account-recovery or vault-unlock mechanism is added by enrolling one.</p>
    </>}
  </section>;
}
