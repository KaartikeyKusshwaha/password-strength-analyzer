import React,{useState} from 'react';
export default function AuthenticatorSetup({session,active,onUpdated,disabled}){
  const [busy,setBusy]=useState(false),[error,setError]=useState(''),[saved,setSaved]=useState(false);
  return <details><summary>Add an authenticator account</summary>
    <p>Enable an authenticator app in the other service’s security settings. Paste its setup key or TOTP URI below. SentinelOps encrypts it locally before storage; no key is sent to AI.</p>
    <form onSubmit={async event=>{event.preventDefault();const form=event.currentTarget,title=form.elements.title.value,setup=form.elements.setup.value,origin=form.elements.origin.value.trim();form.reset();setBusy(true);setSaved(false);setError('');try{await session.addAuthenticator(title,setup,origin);onUpdated();setSaved(true);}catch(e){setError(e.message);}finally{setBusy(false);}}}>
      <label>Authenticator account name<input name="title" required maxLength={100} autoComplete="off" disabled={disabled||busy}/></label>
      <label>Setup key or TOTP URI<input name="setup" type="password" required maxLength={4096} autoComplete="off" disabled={disabled||busy}/></label>
      <label>Exact HTTPS site for code filling (optional)<input name="origin" type="url" defaultValue={active?.origin||''} autoComplete="off" disabled={disabled||busy}/></label>
      <p className="fine">A code can be filled only after linking this exact origin. For a vault restricted to particular websites, this field is required. SMS, push prompts and passkeys cannot be imported as TOTP.</p>
      <button disabled={disabled||busy}>{busy?'Encrypting…':'Encrypt and add authenticator'}</button>
    </form>
    {saved&&<p role="status">Authenticator saved. Use Show code below, then enter the first code in the other service to complete its enrollment. Saving the key alone does not enable 2FA there.</p>}
    {error&&<p role="alert" className="error">{error}</p>}
  </details>;
}
