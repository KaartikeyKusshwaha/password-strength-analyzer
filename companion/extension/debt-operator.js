import {accessRequest} from './access-client';
import {isArchived,recordHistory} from '../../frontend/src/entry-history';
const KEY='debtPendingBinding';
export async function debtReference(vault,entry){
  return Array.from(new Uint8Array(await crypto.subtle.digest('SHA-256',new TextEncoder().encode('sentinelops-debt/v1:'+vault+':'+entry))),byte=>byte.toString(16).padStart(2,'0')).join('');
}
function scope(session,connection){if(session?.material?.kind!=='shared'||!session.entries||session.config?.origin!==connection.origin)throw new Error('Select and unlock a shared vault on this service first.');}
export async function registerSharedLogins(session,connection,client,ids,platform,request=accessRequest){
  scope(session,connection);
  if(!ids.length||ids.length>20||new Set(ids).size!==ids.length)throw new Error('Select 1–20 distinct logins.');
  return session.external(async({active})=>{
    for(const id of ids){
      const entry=session.entries.find(item=>item.id===id&&item.type==='login'&&!isArchived(item));if(!entry)throw new Error('A selected login is unavailable.');
      const url=new URL(entry.origin);if(url.protocol!=='https:'||url.username||url.password)throw new Error('Choose an HTTPS login.');
      const entry_ref=await debtReference(session.policy.id,id);active();
      await request(connection,'debt',{client_id:client,vault_id:session.policy.id,entry_ref,domain:url.hostname,account_label:(entry.title?.trim()||url.hostname).slice(0,100),platform});active();
    }
  });
}
export async function recoverDebtBinding(session,connection,request=accessRequest){
  const pending=(await session.browser.storage.local.get(KEY))[KEY];
  if(!pending)return false;
  if(pending.origin!==connection.origin)throw new Error('Finish the pending debt link on its original service.');
  await request(connection,'debt/bind',pending.body);
  await session.browser.storage.local.remove(KEY);return pending.body.action_id;
}
export async function approveDebtRotation(session,connection,rows,request=accessRequest){
  scope(session,connection);
  if(!rows.length||rows.length>20||rows.some(row=>row.vault!==session.policy.id||row.state==='retired'))throw new Error('Select up to 20 active debt records for the unlocked vault.');
  const pending=(await session.browser.storage.local.get(KEY))[KEY];
  if(pending)throw new Error('Retry the pending rotation link before creating another plan.');
  return session.external(async({active})=>{
    const local=new Map();
    for(const entry of session.entries.filter(item=>item.type==='login'&&!isArchived(item)))local.set(await debtReference(session.policy.id,entry.id),entry.id);
    active();const ids=rows.map(row=>local.get(row.entry_ref));
    if(ids.some(id=>!id)||new Set(ids).size!==ids.length)throw new Error('Selected debt records do not match distinct logins in this vault.');
    const job=await session.approveChanges(ids);active();
    const body={action_id:job.id,items:rows.map((row,index)=>({exposure_id:row.id,index}))};
    await session.browser.storage.local.set({[KEY]:{origin:connection.origin,vault:session.policy.id,body}});active();
    await recoverDebtBinding(session,connection,request);return job;
  });
}
async function localEntry(session,row){
  for(const entry of session.entries.filter(item=>item.type==='login'))if(await debtReference(session.policy.id,entry.id)===row.entry_ref)return entry;
  throw new Error('The reported shared login is no longer in this vault.');
}
export async function retireSharedLogin(session,connection,row,request=accessRequest,onVaultChanged=()=>{}){
  scope(session,connection);
  if(row.vault!==session.policy.id||!['verified','retired'].includes(row.state))throw new Error('Unlock the matching verified vault login before retirement.');
  return session.external(async({active})=>{
    await session.refresh();active();const entry=await localEntry(session,row);active();
    if(entry.pending_change||entry.change_receipt?.action_id!==row.action_id)throw new Error('The local rotation receipt changed. Review the current login before retirement.');
    if(!isArchived(entry)){
      const at=new Date().toISOString();await session.persist(session.entries.map(item=>item.id===entry.id?recordHistory(item,'archived',at,{archived_at:at}):item));active();onVaultChanged();
    }
    try{return await request(connection,'debt/'+row.id+'/retire',{confirmed:true,delegated_access_confirmed:true,shared_login_retired:true});}
    catch(error){throw new Error('Login archived locally, but debt retirement was not confirmed. Retry after reconnecting. '+error.message);}
  });
}
export async function restoreDebtLogin(session,connection,row,onVaultChanged=()=>{}){
  scope(session,connection);
  if(row.vault!==session.policy.id||row.state!=='needed')throw new Error('Reopen debt and select its matching shared vault first.');
  return session.external(async({active})=>{
    await session.refresh();active();const entry=await localEntry(session,row);active();
    if(!isArchived(entry))throw new Error('The login is already active in this vault.');
    await session.persist(session.entries.map(item=>item.id===entry.id?recordHistory(item,'restored',new Date().toISOString(),{archived_at:undefined}):item));active();onVaultChanged();
  });
}
