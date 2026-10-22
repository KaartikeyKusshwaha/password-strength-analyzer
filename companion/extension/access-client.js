import {serviceOrigin} from './policy';

export async function accessRequest(connection,path='',body,fetcher=(...args)=>globalThis.fetch(...args),options={}){
  if(connection?.kind!=='access'||!/^([A-Za-z0-9_-]{40,100})$/.test(connection.token||''))throw new Error('Connect access workflows first.');
  if(!/^(context|revoke|handoffs(?:\/[a-f0-9]{24}\/(?:approve|link|signoff|cancel))?|debt(?:\/bind|\/[a-f0-9]{24}\/(?:verify|retire|reopen))?|workflows(?:\/[a-f0-9]{24}\/(?:approve|cancel|report|vaults\/[a-f0-9]{24}\/rotation))?)$/.test(path))throw new Error('Unsupported workflow action.');
  if(options.vaultToken&&!path.endsWith('/rotation'))throw new Error('Vault authorization is limited to rotation.');
  const response=await fetcher(serviceOrigin(connection.origin)+'/api/companion/access/'+path,{
    method:body===undefined?'GET':'POST',credentials:'omit',redirect:'error',signal:options.signal?AbortSignal.any([options.signal,AbortSignal.timeout(15000)]):AbortSignal.timeout(15000),
    headers:{Authorization:'Bearer '+connection.token,...(options.vaultToken?{'X-Sentinel-Vault-Token':options.vaultToken}:{}),...(body===undefined?{}:{'Content-Type':'application/json'})},
    ...(body===undefined?{}:{body:JSON.stringify(body)})
  });
  if(!response.ok){
    let detail;try{detail=(await response.json()).detail;}catch{}
    throw new Error(typeof detail==='string'?detail:response.status===401?'Workflow connection expired or revoked. Reconnect.':'Workflow request failed. Refresh before retrying.');
  }
  return response.json();
}
