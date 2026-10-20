import {from64,to64,validOrigin} from './vault-crypto';
const encoder=new TextEncoder(),decoder=new TextDecoder();
function requireValue(value) {if(!value)throw new Error('Invalid or expired account action approval.');}
function id(value) {return typeof value==='string' && /^[a-f0-9]{24}$/.test(value);}
function descriptor(value) {
  const actor=value.actor || value.user;
  requireValue(id(value.id) && id(value.vault_id) && id(actor) && ['personal','shared'].includes(value.kind));
  return {id:value.id,vault_id:value.vault_id,actor,kind:value.kind};
}
function aad(value) {const scope=descriptor(value);return encoder.encode('SentinelOps account action v1:'+scope.id+':'+scope.vault_id+':'+scope.actor+':'+scope.kind);}
export function validateAction(value) {
  descriptor(value);
  requireValue(Object.keys(value).sort().join(',')==='actor,approved_at,expires_at,id,items,kind,vault_id,version' && value.version===1 && Number.isInteger(value.approved_at) && Number.isInteger(value.expires_at) && value.approved_at<=Date.now()/1000+300 && value.expires_at> Date.now()/1000 && value.expires_at>value.approved_at && value.expires_at<=value.approved_at+3600 && Array.isArray(value.items) && value.items.length>0 && value.items.length<=20);
  const seen=new Set();
  for(const item of value.items) {
    requireValue(item && Object.keys(item).sort().join(',')==='entry_id,origin' && /^[A-Za-z0-9_-]{1,80}$/.test(item.entry_id) && !seen.has(item.entry_id) && item.origin.length<=300 && validOrigin(item.origin)===item.origin);seen.add(item.entry_id);
  }
  return value;
}
export async function sealAction(manifest,key) {
  validateAction(manifest);const iv=crypto.getRandomValues(new Uint8Array(12)),plain=encoder.encode(JSON.stringify(manifest));
  try{return {version:1,iv:to64(iv),ciphertext:to64(new Uint8Array(await crypto.subtle.encrypt({name:'AES-GCM',iv,additionalData:aad(manifest)},key,plain)))};}finally{plain.fill(0);}
}
export async function openAction(envelope,key,job) {
  requireValue(envelope?.version===1 && typeof envelope.iv==='string' && envelope.iv.length===16 && from64(envelope.iv).length===12 && typeof envelope.ciphertext==='string' && envelope.ciphertext.length<=28000);
  const plain=new Uint8Array(await crypto.subtle.decrypt({name:'AES-GCM',iv:from64(envelope.iv),additionalData:aad(job)},key,from64(envelope.ciphertext)));
  try{
    const manifest=validateAction(JSON.parse(decoder.decode(plain)));
    requireValue(JSON.stringify(descriptor(manifest))===JSON.stringify(descriptor(job)) && manifest.items.length===job.entry_count && manifest.expires_at===job.expires_at);
    return manifest;
  }finally{plain.fill(0);}
}
