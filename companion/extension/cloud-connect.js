import {serviceOrigin} from './policy';
import {prepareConnection} from './connection';
export const CLOUD_ORIGIN='https://sentinelops.129-225-76-232.sslip.io';
async function request(origin,path,proof,fetcher,extra={}){
  const response=await fetcher(origin+'/api/companion/connect/'+path,{method:'POST',credentials:'omit',redirect:'error',headers:{'Content-Type':'application/json'},body:JSON.stringify({proof,...extra}),signal:AbortSignal.timeout(10000)});
  if(!response.ok)throw new Error('The connection request failed or expired. Start again from the extension.');
  return response.json();
}
export async function startCloudConnection(browser,origin=CLOUD_ORIGIN,fetcher=(...args)=>globalThis.fetch(...args),scope='vault'){
  origin=serviceOrigin(origin);
  const granted=await browser.permissions.request({origins:[origin+'/*']});
  if(!granted)throw new Error('App access was declined. Nothing was connected.');
  const previous=await browser.storage.local.get('cloudConnect');
  if(previous.cloudConnect&&previous.cloudConnect.expires*1000>Date.now())throw new Error('Finish or cancel the existing connection request before starting another.');
  const proof=btoa(String.fromCharCode(...crypto.getRandomValues(new Uint8Array(32)))).replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/,'');
  if(!['vault','security','access','discovery'].includes(scope))throw new Error('Unsupported connection scope.');
  const result=await request(origin,'start',proof,fetcher,{scope,device_pairing:scope==='security'});
  if(!/^[a-f0-9]{24}$/.test(result.id)||!/^\d{6}$/.test(result.code)||!Number.isFinite(result.expires)||result.approval_url!==origin+'/#connect='+result.id)throw new Error('Unexpected connection response. Nothing was connected.');
  const pending={origin,id:result.id,proof,code:result.code,expires:result.expires,scope};
  await browser.storage.local.set({cloudConnect:pending});
  await browser.tabs.create({url:result.approval_url});
  return pending;
}
export async function finishCloudConnection(browser,fetcher=(...args)=>globalThis.fetch(...args)){
  const {cloudConnect:pending}=await browser.storage.local.get('cloudConnect');
  if(!pending||pending.expires*1000<=Date.now())throw new Error('Connection request expired. Start again.');
  const origin=serviceOrigin(pending.origin);
  if(!/^[a-f0-9]{24}$/.test(pending.id))throw new Error('Invalid pending request.');
  const result=await request(origin,pending.id+'/poll',pending.proof,fetcher);
  if(result.status==='pending')return null;
  if(result.status!=='approved'||result.origin!==origin)throw new Error('Unexpected connection response.');
  if((pending.scope||'vault')!==(result.scope||'vault'))throw new Error('Connection scope changed. Start again.');
  if(pending.scope==='discovery'){
    if(!/^[A-Za-z0-9_-]{40,100}$/.test(result.token))throw new Error('Invalid discovery connection.');
    const connection={origin,token:result.token,kind:'discovery'};
    const check=await fetcher(origin+'/api/companion/discovery/context',{credentials:'omit',redirect:'error',headers:{Authorization:'Bearer '+result.token},signal:AbortSignal.timeout(10000)});
    if(!check.ok)throw new Error('Discovery access could not be verified.');
    await browser.storage.local.set({discoveryConnection:connection,discoverySites:[]});await browser.storage.local.remove('cloudConnect');
    try{await request(origin,pending.id+'/ack',pending.proof,fetcher);}catch{}
    return connection;
  }
  if(pending.scope==='access'){
    if(!/^[A-Za-z0-9_-]{40,100}$/.test(result.token))throw new Error('Invalid workflow connection.');
    const connection={origin,token:result.token,kind:'access'};
    const check=await fetcher(origin+'/api/companion/access/context',{credentials:'omit',redirect:'error',headers:{Authorization:'Bearer '+result.token},signal:AbortSignal.timeout(10000)});
    if(!check.ok)throw new Error('Workflow access could not be verified.');
    await browser.storage.local.set({accessConnection:connection});await browser.storage.local.remove('cloudConnect');
    try{await request(origin,pending.id+'/ack',pending.proof,fetcher);}catch{}
    return connection;
  }
  if(pending.scope==='security'){
    if(!/^[A-Za-z0-9_-]{40,100}$/.test(result.token))throw new Error('Invalid security connection.');
    const connection={origin,token:result.token,kind:'security'};
    const check=await fetcher(origin+'/api/companion/security/context',{credentials:'omit',redirect:'error',headers:{Authorization:'Bearer '+result.token},signal:AbortSignal.timeout(10000)});
    if(!check.ok)throw new Error('Security access could not be verified.');
    await browser.storage.local.set({securityConnection:connection});await browser.storage.local.remove('cloudConnect');
    try{await request(origin,pending.id+'/ack',pending.proof,fetcher);}catch{}
    return connection;
  }
  const connection=await prepareConnection(browser,origin,result.token,fetcher);
  if(!connection.connection)throw new Error('App access is missing. Allow access and retry.');
  await browser.storage.local.remove('cloudConnect');
  try{await request(origin,pending.id+'/ack',pending.proof,fetcher);}catch{/* Saved grant remains valid; proof handoff expires server-side. */}
  return connection.connection;
}
export async function cancelCloudConnection(browser,fetcher=(...args)=>globalThis.fetch(...args)){
  const {cloudConnect:pending}=await browser.storage.local.get('cloudConnect');
  if(pending&&pending.expires*1000>Date.now())await request(serviceOrigin(pending.origin),pending.id+'/cancel',pending.proof,fetcher);
  await browser.storage.local.remove('cloudConnect');
}
