import React,{useState} from 'react';
import {securityRequest} from './security-client';
import {serviceOrigin} from './policy';

export default function DevicePairing({connection,enabled,running,onConnected,browser=chrome,helper,macHelper}){
  const [code,setCode]=useState(''),[scope,setScope]=useState(null),[busy,setBusy]=useState(false),[error,setError]=useState(''),[done,setDone]=useState(false);
  return <details><summary>Connect device helper</summary>
    <p>Needs device helper · Install the optional app for your platform, then enter its short code here. No device tokens or terminal commands. Windows may ask you to confirm this unsigned pilot download. Closing the helper stops device checks.</p>
    {helper?.available?<><button className="secondary" disabled={running||busy} onClick={async()=>{try{await browser.tabs.create({url:serviceOrigin(connection.origin)+'/api/device-helper/windows'});}catch{setError('The helper download could not open.');}}}>Download Windows helper {helper.version}</button><details><summary>Download verification</summary><p className="fingerprint">SHA-256: {helper.sha256}</p><p>Install only the helper you requested. Do not disable Windows security protections to run it.</p></details></>:<p>The Windows helper installer is not available on this service yet.</p>}
    {macHelper?.available?<><button className="secondary" disabled={running||busy} onClick={async()=>{try{await browser.tabs.create({url:serviceOrigin(connection.origin)+'/api/device-helper/macos'});}catch{setError('The Mac helper download could not open.');}}}>Download macOS helper {macHelper.version} · {macHelper.platform}</button><p>SHA-256: {macHelper.sha256}. Pilot app: no trusted Developer ID or notarization. Do not disable macOS security protections. Choose the build matching your Mac architecture.</p></>:<p>The macOS app package is not available from this service yet.</p>}
    {!enabled?<p>Reconnect security agents and approve device pairing to use this flow. Existing assessment-only access cannot create device connections.</p>:done?<p role="status">Approved. Keep the helper open; it will connect automatically. Device checks stay in this extension.</p>:<>
      <label>Helper pairing code<input disabled={running||busy} value={code} autoComplete="off" spellCheck={false} placeholder="ABCD-EF23" onChange={event=>{setCode(event.target.value.toUpperCase().replace(/[^A-Z2-9]/g,'').slice(0,8));setScope(null);setError('');}}/></label>
      <button className="secondary" disabled={running||busy||!/^[A-HJ-NP-Z2-9]{8}$/.test(code)} onClick={async()=>{setBusy(true);setError('');try{setScope(await securityRequest(connection,'/device-pairing/details',{pairing_code:code}));}catch(e){setError(e.message);}finally{setBusy(false);}}}>Review helper scope</button>
      {scope&&<form onSubmit={async event=>{event.preventDefault();const form=event.currentTarget;const password=form.elements.password.value,factor=form.elements.factor.value;form.reset();setBusy(true);setError('');try{await securityRequest(connection,'/device-pairing/approve',{pairing_code:code,password,code:factor,allow_posture:scope.allow_posture,allow_updates:scope.allow_updates});setDone(true);await onConnected();}catch(e){setError(e.message);}finally{setBusy(false);}}}>
        <p><strong>{scope.label}</strong> · Connect for up to 30 days. Compare the code with the helper on your own computer.</p>
        <p>Scope: this computer’s loopback TCP ports{scope.allow_posture?', supported host-protection status (Windows or macOS)':''}{scope.allow_updates?', cached Windows Update/restart status':''}. No network ranges, arbitrary commands or automatic fixes.</p>
        <label>Current SentinelOps account password<input disabled={busy} type="password" name="password" autoComplete="off" required maxLength={128}/></label>
        <label>Account MFA or recovery code, if enabled<input disabled={busy} name="factor" autoComplete="off" maxLength={128}/></label>
        <button disabled={busy||running}>{busy?'Approving…':'Approve this helper connection'}</button>
      </form>}
    </>}{error&&<p role="alert" className="error">{error}</p>}
  </details>;
}
