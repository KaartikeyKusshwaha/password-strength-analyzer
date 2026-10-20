import {api} from './api';

export function supportedPasskeys(){return !!(window.isSecureContext && window.PublicKeyCredential && navigator.credentials?.create && navigator.credentials?.get);}

export function decodePasskey(value){
  if(typeof value!=='string' || !value || value.length>140000 || !/^[A-Za-z0-9_-]+$/.test(value))throw new Error('Invalid passkey options.');
  const binary=atob(value.replaceAll('-','+').replaceAll('_','/')+'='.repeat((4-value.length%4)%4));
  const bytes=Uint8Array.from(binary,c=>c.charCodeAt(0));
  if(encodePasskey(bytes)!==value)throw new Error('Invalid passkey options.');
  return bytes;
}
export function encodePasskey(value){
  if(!(value instanceof ArrayBuffer) && !ArrayBuffer.isView(value))throw new Error('Invalid passkey response.');
  const bytes=new Uint8Array(value);
  if(bytes.length>100000)throw new Error('Passkey response exceeds the supported size.');
  let binary='';for(const byte of bytes)binary+=String.fromCharCode(byte);
  return btoa(binary).replaceAll('+','-').replaceAll('/','_').replaceAll('=','');
}
function nativeOptions(mode,options){
  const challenge=decodePasskey(options.challenge);
  if(challenge.length<32 || challenge.length>128)throw new Error('Invalid passkey options.');
  const rpId=mode==='register'?options.rp?.id:options.rpId;
  if(rpId!==location.hostname || (mode==='login'?options.userVerification!=='required':options.authenticatorSelection?.userVerification!=='required' || options.authenticatorSelection?.residentKey!=='required'))throw new Error('Passkey options do not match this website.');
  if(mode==='register')return {...options,challenge,user:{...options.user,id:decodePasskey(options.user.id)},excludeCredentials:(options.excludeCredentials||[]).map(item=>({...item,id:decodePasskey(item.id)}))};
  return {...options,challenge,allowCredentials:(options.allowCredentials||[]).map(item=>({...item,id:decodePasskey(item.id)}))};
}
function serialize(mode,credential){
  if(!credential || credential.type!=='public-key')throw new Error('No passkey was returned.');
  const response={clientDataJSON:encodePasskey(credential.response.clientDataJSON)};
  if(mode==='register')response.attestationObject=encodePasskey(credential.response.attestationObject);
  else Object.assign(response,{authenticatorData:encodePasskey(credential.response.authenticatorData),signature:encodePasskey(credential.response.signature),userHandle:credential.response.userHandle?encodePasskey(credential.response.userHandle):null});
  return {id:credential.id,rawId:encodePasskey(credential.rawId),type:'public-key',response};
}
function aborted(signal){if(signal?.aborted)throw new DOMException('Cancelled','AbortError');}
async function waitForAuthenticator(mode,publicKey,signal,expiresIn){
  if(!Number.isInteger(expiresIn) || expiresIn<1 || expiresIn>120)throw new Error('Invalid passkey options.');
  const native=new AbortController();let expired=false,rejectCancellation;
  const cancellation=new Promise((_,reject)=>{rejectCancellation=reject;});
  const cancel=()=>{native.abort();rejectCancellation(new DOMException('Cancelled','AbortError'));};
  signal?.addEventListener('abort',cancel,{once:true});
  const deadline=setTimeout(()=>{expired=true;cancel();},expiresIn*1000);
  try {
    aborted(signal);
    // Do not depend on a native prompt settling promptly after AbortSignal.
    // A late credential is discarded, and can never reach the finish endpoint.
    return await Promise.race([navigator.credentials[mode==='register'?'create':'get']({publicKey,signal:native.signal}),cancellation]);
  }catch(error){
    if(expired && error.name==='AbortError')throw new Error('Passkey request expired. Start again.');
    throw error;
  }finally{clearTimeout(deadline);signal?.removeEventListener('abort',cancel);}
}
export async function performPasskey(mode,{email,password,code='',label,signal,onPhase=()=>{}}){
  if(!supportedPasskeys())throw new Error('Passkeys are unavailable in this browser or context.');
  if(!['login','register'].includes(mode))throw new Error('Unsupported passkey operation.');
  let requestId,finishing=false;
  try {
    aborted(signal);onPhase('requesting');
    const pending=await api('/passkeys/'+mode+'/options',mode==='login'?{email}:{password,code});
    if(typeof pending.request_id!=='string' || !/^[A-Za-z0-9_-]{43,128}$/.test(pending.request_id))throw new Error('Invalid passkey request.');
    requestId=pending.request_id;aborted(signal);
    const publicKey=nativeOptions(mode,pending.publicKey);
    onPhase('authenticator');
    const credential=await waitForAuthenticator(mode,publicKey,signal,pending.expires_in??120);
    aborted(signal);
    const body={credential:serialize(mode,credential),...(mode==='register'?{label}:{})};
    onPhase('finishing');finishing=true;
    return await api('/passkeys/'+mode+'/finish',body,{requestId});
  } catch(error) {
    if(requestId)await api('/passkeys/cancel',{}, {requestId}).catch(()=>{});
    if(finishing && !error.status)throw new Error('The server did not confirm the result. Refresh your account or passkey list before retrying.');
    if(['AbortError','NotAllowedError'].includes(error.name))throw new Error('Passkey request cancelled or not approved.');
    if(error.name==='InvalidStateError')throw new Error('This authenticator already has a matching passkey. Use another authenticator.');
    if(error.name==='SecurityError')throw new Error('Passkeys are unavailable for this website origin.');
    if(error.name==='NotSupportedError')throw new Error('This authenticator does not support the required passkey options.');
    throw error;
  }
}
