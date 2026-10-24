// Client-only key hierarchy. No provider calls, automatic persistence or raw vault-data-key exports.
import { from64, to64, validateEntries } from './vault-crypto';
const encoder = new TextEncoder();
export const ARGON2 = Object.freeze({algorithm:'argon2id',memory_kib:65536,iterations:3,parallelism:1});
const aad = (context, purpose) => encoder.encode('SentinelOps vault v2 '+purpose+':'+context);
function checkPassword(password) {if(typeof password!=='string' || [...password].length<15 || password.length>256)throw new Error('Use a separate master passphrase of 15–256 characters.');}
function validate(envelope) {
  if(envelope?.version!==2 || !/^[a-f0-9]{24}$/.test(envelope.context) || envelope.kdf?.algorithm!=='argon2id' || envelope.kdf.memory_kib!==65536 || envelope.kdf.iterations!==3 || envelope.kdf.parallelism!==1 || typeof envelope.salt!=='string' || envelope.salt.length!==24 || typeof envelope.wrap_iv!=='string' || envelope.wrap_iv.length!==16 || typeof envelope.wrapped_key!=='string' || envelope.wrapped_key.length!==64 || from64(envelope.salt).length!==16 || from64(envelope.wrap_iv).length!==12 || from64(envelope.wrapped_key).length!==48) throw new Error('Unsupported vault protection parameters.');
}
export async function deriveUnlockKey(password,salt) {
  checkPassword(password);
  if(typeof salt!=='string' || salt.length!==24 || from64(salt).length!==16)throw new Error('Invalid unlock salt.');
  const {argon2id}=await import('hash-wasm');
  const raw=await argon2id({password,salt:from64(salt),memorySize:ARGON2.memory_kib,iterations:ARGON2.iterations,parallelism:ARGON2.parallelism,hashLength:32,outputType:'binary'});
  try{return await crypto.subtle.importKey('raw',raw,{name:'AES-GCM'},false,['encrypt','decrypt']);}finally{raw.fill(0);}
}
const wrappingKey=deriveUnlockKey;
async function wrapRaw(raw,password,context) {
  const salt=to64(crypto.getRandomValues(new Uint8Array(16))), iv=crypto.getRandomValues(new Uint8Array(12)), key=await wrappingKey(password,salt);
  const wrapped=await crypto.subtle.encrypt({name:'AES-GCM',iv,additionalData:aad(context,'wrap')},key,raw);
  return {version:2,context,kdf:{...ARGON2},salt,wrap_iv:to64(iv),wrapped_key:to64(new Uint8Array(wrapped))};
}
async function unwrapRaw(envelope,password) {
  validate(envelope);
  const key=await wrappingKey(password,envelope.salt);
  return new Uint8Array(await crypto.subtle.decrypt({name:'AES-GCM',iv:from64(envelope.wrap_iv),additionalData:aad(envelope.context,'wrap')},key,from64(envelope.wrapped_key)));
}
export async function createProtectedVault(entries,password,context) {
  if(!/^[a-f0-9]{24}$/.test(context))throw new Error('Create a vault space before choosing its master passphrase.');
  const raw=crypto.getRandomValues(new Uint8Array(32));
  try{
    const protection=await wrapRaw(raw,password,context), key=await crypto.subtle.importKey('raw',raw,{name:'AES-GCM'},false,['encrypt','decrypt']);
    return {key,salt:protection,envelope:await encryptProtected(entries,key,protection)};
  }finally{raw.fill(0);}
}
export async function encryptProtected(entries,key,protection) {
  validate(protection);validateEntries(entries);
  const plaintext=encoder.encode(JSON.stringify({entries}));
  if(plaintext.length>85000)throw new Error('Vault exceeds the current encrypted storage limit.');
  const iv=crypto.getRandomValues(new Uint8Array(12));
  const cipher=new Uint8Array(await crypto.subtle.encrypt({name:'AES-GCM',iv,additionalData:aad(protection.context,'data')},key,plaintext));
  let binary='';for(let offset=0;offset<cipher.length;offset+=8192)binary+=String.fromCharCode(...cipher.subarray(offset,offset+8192));
  return {...protection,iv:to64(iv),ciphertext:btoa(binary)};
}
export async function decryptProtected(envelope,key,protection) {
  validate(envelope);
  if(envelope.context!==protection.context || envelope.wrapped_key!==protection.wrapped_key || envelope.salt!==protection.salt || typeof envelope.ciphertext!=='string' || envelope.ciphertext.length>125000 || from64(envelope.iv).length!==12)throw new Error('Vault encryption changed. Lock and unlock again.');
  const plaintext=await crypto.subtle.decrypt({name:'AES-GCM',iv:from64(envelope.iv),additionalData:aad(envelope.context,'data')},key,from64(envelope.ciphertext));
  return validateEntries(JSON.parse(new TextDecoder().decode(plaintext)).entries);
}
function protectionOf(envelope) {const {iv,ciphertext,...protection}=envelope;return protection;}
export async function unlockProtected(envelope,password) {
  let raw;
  try{
    raw=await unwrapRaw(envelope,password);
    const key=await crypto.subtle.importKey('raw',raw,{name:'AES-GCM'},false,['encrypt','decrypt']), protection=protectionOf(envelope);
    return {key,salt:protection,entries:await decryptProtected(envelope,key,protection)};
  }catch{throw new Error('Could not unlock. Check the master passphrase and encrypted vault integrity.');}finally{raw?.fill(0);}
}
export async function changeMasterPassphrase(envelope,currentPassword,newPassword) {
  let raw;
  try{
    raw=await unwrapRaw(envelope,currentPassword);
    const key=await crypto.subtle.importKey('raw',raw,{name:'AES-GCM'},false,['encrypt','decrypt']);
    await decryptProtected(envelope,key,protectionOf(envelope));
    const protection=await wrapRaw(raw,newPassword,envelope.context);
    return {...protection,iv:envelope.iv,ciphertext:envelope.ciphertext};
  }finally{raw?.fill(0);}
}

// Offline recovery. The kit is encrypted; the independent 256-bit code stays local.
const recoveryAAD = kit => encoder.encode('SentinelOps recovery kit v1:'+kit.vault_id+':'+kit.recovery_id+':'+kit.created_at);
const hex = bytes => [...bytes].map(value=>value.toString(16).padStart(2,'0')).join('');
function recoveryCode(raw) {return 'SRK1-'+hex(raw).toUpperCase().match(/.{8}/g).join('-');}
function codeBytes(code) {
  if(typeof code!=='string'||!/^SRK1-(?:[0-9A-F]{8}-){7}[0-9A-F]{8}$/.test(code.trim().toUpperCase()))throw new Error('Use the complete SRK1 recovery key.');
  return Uint8Array.from(code.trim().slice(5).replaceAll('-','').match(/../g),value=>parseInt(value,16));
}
function exactKeys(value,keys) {return value&&typeof value==='object'&&!Array.isArray(value)&&Object.keys(value).sort().join(',')===keys.sort().join(',');}
export function parseRecoveryKit(value) {
  try {
    if(typeof value==='string') {
      if(new TextEncoder().encode(value).length>150000)throw new Error();
      value=JSON.parse(value);
    }
    if(!exactKeys(value,['format','version','vault_id','recovery_id','created_at','key_wrap','snapshot'])||value.format!=='sentinelops-recovery-kit'||value.version!==1||!/^[a-f0-9]{24}$/.test(value.vault_id)||!/^[a-f0-9]{24}$/.test(value.recovery_id)||typeof value.created_at!=='string'||value.created_at.length>30||new Date(value.created_at).toISOString()!==value.created_at)throw new Error();
    if(!exactKeys(value.key_wrap,['iv','wrapped_key'])||typeof value.key_wrap.iv!=='string'||value.key_wrap.iv.length!==16||from64(value.key_wrap.iv).length!==12||typeof value.key_wrap.wrapped_key!=='string'||value.key_wrap.wrapped_key.length!==64||from64(value.key_wrap.wrapped_key).length!==48)throw new Error();
    const snapshot=value.snapshot;
    if(!exactKeys(snapshot,['version','context','kdf','salt','wrap_iv','wrapped_key','iv','ciphertext'])||snapshot.context!==value.vault_id||!exactKeys(snapshot.kdf,['algorithm','memory_kib','iterations','parallelism'])||typeof snapshot.iv!=='string'||snapshot.iv.length!==16||from64(snapshot.iv).length!==12||typeof snapshot.ciphertext!=='string'||snapshot.ciphertext.length>125000||snapshot.ciphertext.length<24)throw new Error();
    validate(snapshot);
    return value;
  }catch {throw new Error('Unsupported or damaged recovery kit. Choose its original JSON file.');}
}
export async function rotateProtectedVault(envelope,currentPassword) {
  const unlocked=await unlockProtected(envelope,currentPassword);
  return (await createProtectedVault(unlocked.entries,currentPassword,envelope.context)).envelope;
}
export async function prepareRecoveryKit(envelope,currentPassword) {
  let oldRaw,raw,secretRaw;
  try {
    oldRaw=await unwrapRaw(envelope,currentPassword);
    const oldKey=await crypto.subtle.importKey('raw',oldRaw,{name:'AES-GCM'},false,['decrypt']);
    const entries=await decryptProtected(envelope,oldKey,protectionOf(envelope));
    raw=crypto.getRandomValues(new Uint8Array(32));
    const protection=await wrapRaw(raw,currentPassword,envelope.context), key=await crypto.subtle.importKey('raw',raw,{name:'AES-GCM'},false,['encrypt','decrypt']);
    const replacement=await encryptProtected(entries,key,protection);
    secretRaw=crypto.getRandomValues(new Uint8Array(32));
    const secret=recoveryCode(secretRaw),recoveryKey=await crypto.subtle.importKey('raw',secretRaw,{name:'AES-GCM'},false,['encrypt']);
    const kit={format:'sentinelops-recovery-kit',version:1,vault_id:envelope.context,recovery_id:hex(crypto.getRandomValues(new Uint8Array(12))),created_at:new Date().toISOString(),key_wrap:null,snapshot:replacement};
    const iv=crypto.getRandomValues(new Uint8Array(12)),wrapped=await crypto.subtle.encrypt({name:'AES-GCM',iv,additionalData:recoveryAAD(kit)},recoveryKey,raw);
    kit.key_wrap={iv:to64(iv),wrapped_key:to64(new Uint8Array(wrapped))};
    return {envelope:replacement,kit,secret};
  }catch {throw new Error("Recovery setup could not unlock this vault. Check the current master passphrase and vault integrity.");}
  finally {oldRaw?.fill(0);raw?.fill(0);secretRaw?.fill(0);}
}
export async function recoverWithKit(value,code,newPassword,{context,currentEnvelope,source}={}) {
  const kit=parseRecoveryKit(value);
  if(kit.vault_id!==context||!['current','snapshot'].includes(source))throw new Error('Choose the matching personal vault and an explicit recovery source.');
  const selected=source==='snapshot'?kit.snapshot:currentEnvelope;
  if(selected?.version!==2||selected.context!==context)throw new Error('The selected recovery source does not match this vault.');
  let secretRaw,raw;
  try {
    secretRaw=codeBytes(code);
    const recoveryKey=await crypto.subtle.importKey('raw',secretRaw,{name:'AES-GCM'},false,['decrypt']);
    raw=new Uint8Array(await crypto.subtle.decrypt({name:'AES-GCM',iv:from64(kit.key_wrap.iv),additionalData:recoveryAAD(kit)},recoveryKey,from64(kit.key_wrap.wrapped_key)));
    const key=await crypto.subtle.importKey('raw',raw,{name:'AES-GCM'},false,['decrypt']);
    const entries=await decryptProtected(selected,key,protectionOf(selected));
    return (await createProtectedVault(entries,newPassword,context)).envelope;
  }catch {throw new Error('Recovery did not decrypt the selected data. Check the key, kit and source. An older snapshot is never selected automatically.');}
  finally {secretRaw?.fill(0);raw?.fill(0);}
}
