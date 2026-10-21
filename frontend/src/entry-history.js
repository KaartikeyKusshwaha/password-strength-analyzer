// Encrypted, client-reported observations only. Never sent separately to an API.
export const HISTORY_KINDS=Object.freeze(['saved','credential_saved','details_saved','proposal_staged','proposal_discarded','change_confirmed_by_user','reviewed','archived','restored']);
const fields=new Set(['version','saved_at','reviewed_at','archived_at','events']);
export function validTime(value){return typeof value==='string' && /^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z$/.test(value) && Number.isFinite(Date.parse(value)) && new Date(value).toISOString()===value;}
export function validateHistory(history){
  if(history===undefined)return;
  if(!history || history.version!==1 || Object.keys(history).some(k=>!fields.has(k)) || !Array.isArray(history.events) || history.events.length>8 || ['saved_at','reviewed_at','archived_at'].some(k=>history[k]!==undefined && !validTime(history[k])) || history.events.some(e=>!e || Object.keys(e).sort().join(',')!=='at,kind' || !HISTORY_KINDS.includes(e.kind) || !validTime(e.at)))throw new Error('Unsupported encrypted account history.');
}
export function isArchived(entry){return !!entry.history?.archived_at;}
export function recordHistory(entry,kind,at=new Date().toISOString(),updates={}){
  validateHistory(entry.history);
  if(!HISTORY_KINDS.includes(kind) || !validTime(at))throw new Error('Unsupported account observation.');
  const history={version:1,...entry.history,...updates,events:[...(entry.history?.events||[]),{kind,at}].slice(-8)};
  for(const field of Object.keys(history))if(history[field]===undefined)delete history[field];
  validateHistory(history);return {...entry,history};
}
export function trackChanges(previous,next,at=new Date().toISOString()){
  const byId=new Map(previous.map(e=>[e.id,e]));
  return next.map(value=>{
    const old=byId.get(value.id);let entry=value;
    if(!old)return value.history?value:recordHistory(value,'saved',at,{saved_at:at});
    // Older clients may omit new metadata when replacing a login. Preserve it.
    if(old.history && !entry.history)entry={...entry,history:old.history};
    let kind;
    if(entry.change_receipt && entry.change_receipt.action_id!==old.change_receipt?.action_id)kind='change_confirmed_by_user';
    else if(old.type===entry.type && (old.password!==entry.password || old.secret!==entry.secret || old.algorithm!==entry.algorithm || old.digits!==entry.digits || old.period!==entry.period))kind='credential_saved';
    else if(!old.pending_change && entry.pending_change)kind='proposal_staged';
    else if(old.pending_change && !entry.pending_change)kind='proposal_discarded';
    else if(old.title!==entry.title || old.origin!==entry.origin || old.username!==entry.username || old.autofill_origin!==entry.autofill_origin)kind='details_saved';
    return kind?recordHistory(entry,kind,at):entry;
  });
}
