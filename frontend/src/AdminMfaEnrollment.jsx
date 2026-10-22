import React,{lazy,Suspense,useState} from 'react';
import {api} from './api';
import SetupQr from './SetupQr';
const PersonalVaults=lazy(()=>import('./VaultCollection'));

export default function AdminMfaEnrollment({onDone,onSignOut}){
  const [setup,setSetup]=useState(null),[codes,setCodes]=useState(null),[busy,setBusy]=useState(false),[error,setError]=useState(''),[personal,setPersonal]=useState(false);
  async function run(work){setBusy(true);setError('');try{await work();}catch(e){setError(e.message);}finally{setBusy(false);}}
  return <main className="panel"><h1>Protect your administrator account</h1>
    <p>Workspace owners and shared-vault administrators must enable an authenticator before using administrative tools. Your existing account and encrypted personal vaults are retained.</p>
    {error&&<p role="alert" className="notice error">{error}</p>}
    {!setup&&!codes&&<form onSubmit={event=>{event.preventDefault();const form=event.currentTarget,password=new FormData(form).get('password');form.reset();run(async()=>setSetup(await api('/mfa/setup',{password})));}}>
      <label>Current account password<input name="password" type="password" autoComplete="current-password" required maxLength={256}/></label><button className="button" disabled={busy}>Set up administrator MFA</button>
    </form>}
    {setup&&!codes&&<><p>Add this account to your authenticator app. The setup expires in ten minutes. Keep its key private.</p><SetupQr uri={setup.uri}/><label>Private setup key<input readOnly value={setup.secret}/></label>
      <form onSubmit={event=>{event.preventDefault();const form=event.currentTarget,code=new FormData(form).get('code');form.reset();run(async()=>{const result=await api('/mfa/enable',{code});setSetup(null);setCodes(result.recovery_codes);});}}><label>Authenticator code<input name="code" autoComplete="one-time-code" inputMode="numeric" required maxLength={80}/></label><button className="button" disabled={busy}>Confirm and enable MFA</button></form>
      <button className="button secondary" disabled={busy} onClick={()=>setSetup(null)}>Restart setup</button></>}
    {codes&&<><p role="status">Authenticator enabled. Save these single-use recovery codes privately before continuing. They will not be shown again.</p><textarea aria-label="Private recovery codes" readOnly rows={9} value={codes.join('\n')}/>
      <form onSubmit={event=>{event.preventDefault();run(onDone);}}><label><input type="checkbox" required/>I saved my recovery codes privately.</label><button className="button" disabled={busy}>Continue to workspace</button></form></>}
    <div className="inline spaced"><button className="button secondary" disabled={busy} onClick={()=>setPersonal(!personal)}>{personal?'Close personal vaults':'Open personal vaults'}</button><button className="button secondary" disabled={busy} onClick={()=>run(onSignOut)}>Sign out</button></div>
    {personal&&<Suspense fallback={<p>Opening personal vaults…</p>}><PersonalVaults/></Suspense>}
  </main>;
}
