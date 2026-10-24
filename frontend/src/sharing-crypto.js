// Local sharing cryptography. Network requests and UI policy live outside this module.
import { from64, to64, validateEntries } from './vault-crypto';
import { deriveUnlockKey } from './vault-v2';
import {sealAction,openAction} from './action-crypto';
const encoder=new TextEncoder(), decoder=new TextDecoder();
const rsa={name:'RSA-OAEP',hash:'SHA-256'}, ec={name:'ECDSA',namedCurve:'P-256'}, sig={name:'ECDSA',hash:'SHA-256'};
const grantFields=['version','vault_id','recipient','issuer','epoch','role','recipient_fingerprint','issuer_fingerprint','wrapped_key'];
const roles=['owner','admin','editor','viewer'];
export function canonical(value) {
  if(Array.isArray(value))return '['+value.map(canonical).join(',')+']';
  if(value && typeof value==='object')return '{'+Object.keys(value).sort().map(k=>JSON.stringify(k)+':'+canonical(value[k])).join(',')+'}';
  return JSON.stringify(value);
}
function requireValue(value,message='Invalid sharing envelope.') {if(!value)throw new Error(message);}
function identifier(value) {return typeof value==='string' && /^[a-f0-9]{24}$/.test(value);}
function bytes(value,maximum) {requireValue(typeof value==='string' && value.length<=maximum);return from64(value);}
async function digest(value) {return [...new Uint8Array(await crypto.subtle.digest('SHA-256',encoder.encode(canonical(value))))].map(b=>b.toString(16).padStart(2,'0')).join('');}
export async function inspectPublic(value) {
  requireValue(value && Object.keys(value).sort().join(',')==='encryption,signing');
  const encryption=await crypto.subtle.importKey('spki',bytes(value.encryption,1200),rsa,false,['encrypt']);
  const signing=await crypto.subtle.importKey('spki',bytes(value.signing,300),ec,false,['verify']);
  requireValue(encryption.algorithm.modulusLength===3072 && [...encryption.algorithm.publicExponent].join(',')==='1,0,1');
  return {encryption,signing,fingerprint:await digest(value)};
}
async function sign(privateKey,value) {return to64(new Uint8Array(await crypto.subtle.sign(sig,privateKey,encoder.encode(canonical(value)))));}
async function verify(publicKey,value,signature) {requireValue(await crypto.subtle.verify(sig,publicKey,bytes(signature,88),encoder.encode(canonical(value))),'Sharing signature failed. Do not use this vault.');}
function identityAAD(user) {requireValue(identifier(user));return encoder.encode('SentinelOps sharing identity v1:'+user);}
function label(grant) {return encoder.encode('SentinelOps team grant v1:'+grant.vault_id+':'+grant.epoch+':'+grant.recipient);}
function dataAAD(context,epoch) {return encoder.encode('SentinelOps team vault v1:'+context+':'+epoch);}
function identityHandle(user,publicValue,fingerprint,decryption,signing) {
  return {user,public:publicValue,fingerprint,
    sign:document=>sign(signing,document),
    unwrap:grant=>crypto.subtle.decrypt({...rsa,label:label(grant)},decryption,bytes(grant.wrapped_key,512)),
  };
}
export async function createSharingIdentity(user,password) {
  const salt=to64(crypto.getRandomValues(new Uint8Array(16))), wrapping=await deriveUnlockKey(password,salt);
  const encryption=await crypto.subtle.generateKey({...rsa,modulusLength:3072,publicExponent:new Uint8Array([1,0,1])},true,['encrypt','decrypt']);
  const signing=await crypto.subtle.generateKey(ec,true,['sign','verify']);
  const publicValue={encryption:to64(new Uint8Array(await crypto.subtle.exportKey('spki',encryption.publicKey))),signing:to64(new Uint8Array(await crypto.subtle.exportKey('spki',signing.publicKey)))};
  const privateRSA=new Uint8Array(await crypto.subtle.exportKey('pkcs8',encryption.privateKey)), privateEC=new Uint8Array(await crypto.subtle.exportKey('pkcs8',signing.privateKey));
  let plaintext;
  try {
    plaintext=encoder.encode(JSON.stringify({encryption:to64(privateRSA),signing:to64(privateEC)}));
    const iv=crypto.getRandomValues(new Uint8Array(12)), ciphertext=await crypto.subtle.encrypt({name:'AES-GCM',iv,additionalData:identityAAD(user)},wrapping,plaintext);
    const encrypted={version:1,salt,iv:to64(iv),ciphertext:to64(new Uint8Array(ciphertext))};
    // Re-import private keys as nonextractable; no raw key leaves this module.
    return {record:{public:publicValue,encrypted},identity:await importIdentity(user,publicValue,privateRSA,privateEC)};
  }finally{privateRSA.fill(0);privateEC.fill(0);plaintext?.fill(0);}
}
async function importIdentity(user,publicValue,privateRSA,privateEC) {
  const {fingerprint,encryption:publicRSA,signing:publicEC}=await inspectPublic(publicValue);
  const decryption=await crypto.subtle.importKey('pkcs8',privateRSA,rsa,false,['decrypt']), signing=await crypto.subtle.importKey('pkcs8',privateEC,ec,false,['sign']);
  const challenge=crypto.getRandomValues(new Uint8Array(32)), wrapped=await crypto.subtle.encrypt(rsa,publicRSA,challenge);
  requireValue(to64(new Uint8Array(await crypto.subtle.decrypt(rsa,decryption,wrapped)))===to64(challenge),'Sharing keys do not match.');
  const proof=await sign(signing,{user});await verify(publicEC,{user},proof);
  return identityHandle(user,publicValue,fingerprint,decryption,signing);
}
async function useIdentityMaterial(user,record,password,action) {
  let plain, privateRSA, privateEC;
  try {
    let identity;
    try {
      const value=record?.encrypted;requireValue(value?.version===1 && bytes(value.iv,16).length===12 && typeof value.ciphertext==='string' && value.ciphertext.length<=16000);
      const key=await deriveUnlockKey(password,value.salt);
      plain=new Uint8Array(await crypto.subtle.decrypt({name:'AES-GCM',iv:from64(value.iv),additionalData:identityAAD(user)},key,from64(value.ciphertext)));
      const parsed=JSON.parse(decoder.decode(plain));privateRSA=bytes(parsed.encryption,8000);privateEC=bytes(parsed.signing,1000);
      identity=await importIdentity(user,record.public,privateRSA,privateEC);
      requireValue(identity.fingerprint===record.fingerprint,'Sharing identity fingerprint changed.');
    }catch{throw new Error('Could not unlock the sharing identity. Check its passphrase and integrity.');}
    return await action(identity,plain);
  }finally{plain?.fill(0);privateRSA?.fill(0);privateEC?.fill(0);}
}
export async function unlockSharingIdentity(user,record,password) {
  return useIdentityMaterial(user,record,password,identity=>identity);
}
export async function prepareSharingPassphraseChange(user,record,currentPassword,newPassword) {
  requireValue(currentPassword!==newPassword,'Choose a different sharing passphrase.');
  return useIdentityMaterial(user,record,currentPassword,async(identity,plain)=>{
    const salt=to64(crypto.getRandomValues(new Uint8Array(16))),iv=crypto.getRandomValues(new Uint8Array(12));
    const wrapping=await deriveUnlockKey(newPassword,salt);
    const ciphertext=await crypto.subtle.encrypt({name:'AES-GCM',iv,additionalData:identityAAD(user)},wrapping,plain);
    const encrypted={version:1,salt,iv:to64(iv),ciphertext:to64(new Uint8Array(ciphertext))};
    const previous_digest=await digest(record.encrypted);
    const document={action:'sharing.identity_rewrap.v1',user,fingerprint:identity.fingerprint,previous_digest,encrypted};
    return {previous_digest,encrypted,signature:await identity.sign(document)};
  });
}
function grantDocument(grant) {return Object.fromEntries(grantFields.map(k=>[k,grant[k]]));}
async function verifyGrant(grant,team,ownerKeys,depth=0) {
  requireValue(grant?.version===1 && grant.vault_id===team.id && grant.epoch===team.epoch && identifier(grant.recipient) && identifier(grant.issuer) && roles.includes(grant.role));
  const issuer=await inspectPublic(grant.issuer_public);
  requireValue(issuer.fingerprint===grant.issuer_fingerprint);
  if(grant.issuer===team.owner) {
    requireValue(issuer.fingerprint===ownerKeys.fingerprint);
    requireValue((grant.role==='owner')===(grant.recipient===team.owner));
  } else {
    requireValue(depth===0 && ['editor','viewer'].includes(grant.role),'Unsupported delegation chain.');
    const parent=grant.issuer_grant;
    requireValue(parent?.issuer===team.owner && parent.recipient===grant.issuer && parent.role==='admin' && parent.recipient_fingerprint===issuer.fingerprint);
    await verifyGrant(parent,team,ownerKeys,depth+1);
  }
  await verify(issuer.signing,grantDocument(grant),grant.signature);
}
export async function verifyTeam(team,identity,trustedOwnerFingerprint) {
  requireValue(identifier(team.id) && identifier(team.workspace) && identifier(team.owner) && Number.isInteger(team.epoch) && team.epoch>0 && team.epoch<=1000000);
  const owner=await inspectPublic(team.owner_public);
  requireValue(owner.fingerprint===trustedOwnerFingerprint && owner.fingerprint===team.owner_fingerprint,'Verify the vault owner fingerprint through a trusted channel first.');
  const manifest={id:team.id,workspace:team.workspace,owner:team.owner,owner_fingerprint:owner.fingerprint};
  requireValue(canonical(team.manifest.document)===canonical(manifest));await verify(owner.signing,manifest,team.manifest.signature);
  requireValue(team.grant?.recipient===identity.user && team.grant.recipient_fingerprint===identity.fingerprint);
  requireValue(team.grant.role===team.role);await verifyGrant(team.grant,team,owner);
  return owner;
}
async function grantFor(raw,identity,recipient,team,role) {
  requireValue(identifier(recipient.id) && roles.includes(role));
  const keys=await inspectPublic(recipient.public);requireValue(keys.fingerprint===recipient.fingerprint,'Recipient fingerprint changed.');
  const document={version:1,vault_id:team.id,recipient:recipient.id,issuer:identity.user,epoch:team.epoch,role,recipient_fingerprint:keys.fingerprint,issuer_fingerprint:identity.fingerprint};
  document.wrapped_key=to64(new Uint8Array(await crypto.subtle.encrypt({...rsa,label:label(document)},keys.encryption,raw)));
  return {...document,signature:await identity.sign(document)};
}
async function encryptData(entries,key,team) {
  validateEntries(entries);const plain=encoder.encode(JSON.stringify({entries}));requireValue(plain.length<=85000,'Team vault storage limit reached.');
  try {
    const iv=crypto.getRandomValues(new Uint8Array(12)), cipher=new Uint8Array(await crypto.subtle.encrypt({name:'AES-GCM',iv,additionalData:dataAAD(team.id,team.epoch)},key,plain));
    return {version:1,context:team.id,epoch:team.epoch,iv:to64(iv),ciphertext:to64(cipher)};
  }finally{plain.fill(0);}
}
async function decryptData(payload,key,team) {
  requireValue(payload?.version===1 && payload.context===team.id && payload.epoch===team.epoch && bytes(payload.iv,16).length===12 && typeof payload.ciphertext==='string' && payload.ciphertext.length<=120000);
  const plain=new Uint8Array(await crypto.subtle.decrypt({name:'AES-GCM',iv:from64(payload.iv),additionalData:dataAAD(team.id,team.epoch)},key,from64(payload.ciphertext)));
  try{return validateEntries(JSON.parse(decoder.decode(plain)).entries);}finally{plain.fill(0);}
}
async function vaultHandle(raw,team,identity) {
  requireValue(raw.length===32);const key=await crypto.subtle.importKey('raw',raw,{name:'AES-GCM'},false,['encrypt','decrypt']);let closed=false;
  const active=()=>requireValue(!closed,'Unlock the shared vault again.');
  return {close(){closed=true;raw.fill(0);},
    async sealAction(manifest){active();return sealAction(manifest,key);},
    async openAction(job){active();return openAction(job.manifest,key,job);},
    async decrypt(payload){active();return decryptData(payload,key,team);},
    async encrypt(entries){active();return encryptData(entries,key,team);},
    async invite(recipient,role){active();requireValue(team.role==='owner' || team.role==='admin');requireValue(role!=='owner' && (role!=='admin' || team.role==='owner'));return grantFor(raw,identity,recipient,team,role);},
  };
}
export async function createTeamVault(identity,workspace,name,id) {
  requireValue(identifier(id) && identifier(workspace));
  const team={id,workspace,owner:identity.user,epoch:1,role:'owner'}, raw=crypto.getRandomValues(new Uint8Array(32));
  try{
    const grant=await grantFor(raw,identity,{id:identity.user,public:identity.public,fingerprint:identity.fingerprint},team,'owner');
    const manifest={id,workspace,owner:identity.user,owner_fingerprint:identity.fingerprint};
    const key=await crypto.subtle.importKey('raw',raw,{name:'AES-GCM'},false,['encrypt','decrypt']);
    return {id,name,manifest_signature:await identity.sign(manifest),grant,payload:await encryptData([],key,team)};
  }finally{raw.fill(0);}
}
export async function openTeamVault(team,identity,trustedFingerprint) {
  await verifyTeam(team,identity,trustedFingerprint);requireValue(team.accepted,'Accept the verified invitation first.');
  const raw=new Uint8Array(await identity.unwrap(team.grant));let handle;
  try{handle=await vaultHandle(raw,team,identity);return {handle,entries:await handle.decrypt(team.payload)};}catch(error){raw.fill(0);handle?.close();throw error;}
}
export async function rotateTeamVault(team,identity,trustedFingerprint,directory) {
  requireValue(team.owner===identity.user && team.role==='owner');const owner=await verifyTeam(team,identity,trustedFingerprint);
  const opened=await openTeamVault(team,identity,trustedFingerprint), next={...team,epoch:team.epoch+1}, raw=crypto.getRandomValues(new Uint8Array(32));
  try {
    const grants=[];
    for(const member of team.grants) {
      await verifyGrant(member.envelope,team,owner);requireValue(member.role===member.envelope.role && member.user_id===member.envelope.recipient);
      const recipient=directory.find(v=>v.id===member.user_id);requireValue(recipient && recipient.fingerprint===member.envelope.recipient_fingerprint,'Member identity changed. Re-verify access before rotating.');
      grants.push(await grantFor(raw,identity,recipient,next,member.role));
    }
    const key=await crypto.subtle.importKey('raw',raw,{name:'AES-GCM'},false,['encrypt','decrypt']);
    return {revision:team.revision,grants,payload:await encryptData(opened.entries,key,next)};
  }finally{raw.fill(0);opened.handle.close();}
}

const ownershipFields=['action','version','id','vault_id','workspace','owner','recipient','owner_fingerprint','recipient_fingerprint','state_digest','revision','epoch','former_owner_role','expires_at'];
const formerRoles=['removed','viewer','editor','admin'];
export async function ownershipStateDigest(team) {
  requireValue(team.browser_policy && Array.isArray(team.grants) && team.grants.length>0 && team.grants.length<=20,'Load the complete current shared vault first.');
  const grants=team.grants.map(member=>({user_id:member.user_id,role:member.role,accepted:!!member.accepted,envelope:member.envelope})).sort((a,b)=>a.user_id<b.user_id?-1:a.user_id>b.user_id?1:0);
  return digest({id:team.id,workspace:team.workspace,owner:team.owner,owner_fingerprint:team.owner_fingerprint,epoch:team.epoch,revision:team.revision,rotation_required:!!team.rotation_required,browser_policy:team.browser_policy,manifest:team.manifest,payload:team.payload,grants});
}
async function verifyRoster(team,owner) {
  requireValue(Array.isArray(team.grants) && team.grants.length>0 && team.grants.length<=20 && new Set(team.grants.map(m=>m.user_id)).size===team.grants.length,'Invalid shared member roster.');
  for(const member of team.grants){
    await verifyGrant(member.envelope,team,owner);
    requireValue(member.user_id===member.envelope.recipient && member.role===member.envelope.role,'Member access changed. Reload before transferring.');
  }
}
export async function prepareOwnershipProposal(team,identity,recipient,formerRole) {
  requireValue(team.owner===identity.user && team.role==='owner' && team.accepted && !team.rotation_required && team.epoch<1000000,'Open a current vault you own before proposing a transfer.');
  requireValue(formerRoles.includes(formerRole) && recipient.id!==identity.user && recipient.role!=='viewer','Choose an eligible teammate and your access after transfer.');
  const owner=await verifyTeam(team,identity,identity.fingerprint);await verifyRoster(team,owner);
  const member=team.grants.find(m=>m.user_id===recipient.id);
  requireValue(member?.accepted && member.envelope.recipient_fingerprint===recipient.fingerprint,'The intended owner must have accepted access with the verified identity.');
  const keys=await inspectPublic(recipient.public);requireValue(keys.fingerprint===recipient.fingerprint,'Recipient identity changed.');
  const id=[...crypto.getRandomValues(new Uint8Array(12))].map(v=>v.toString(16).padStart(2,'0')).join('');
  const document={action:'team_vault.ownership.v1',version:1,id,vault_id:team.id,workspace:team.workspace,owner:identity.user,recipient:recipient.id,owner_fingerprint:identity.fingerprint,recipient_fingerprint:recipient.fingerprint,state_digest:await ownershipStateDigest(team),revision:team.revision,epoch:team.epoch,former_owner_role:formerRole,expires_at:Math.floor(Date.now()/1000)+900};
  return {document,signature:await identity.sign(document)};
}
export async function verifyOwnershipProposal(team,identity,trustedOwnerFingerprint,proposal) {
  const value=proposal?.document;
  requireValue(proposal?.status==='pending' && value && Object.keys(value).sort().join(',')===[...ownershipFields].sort().join(','),'Load a pending ownership proposal first.');
  requireValue(value.action==='team_vault.ownership.v1' && value.version===1 && identifier(value.id) && value.vault_id===team.id && value.workspace===team.workspace && value.owner===team.owner && value.recipient===identity.user && value.recipient_fingerprint===identity.fingerprint && formerRoles.includes(value.former_owner_role),'Ownership proposal scope or recipient mismatch.');
  requireValue(Number.isInteger(value.expires_at) && value.expires_at>Math.floor(Date.now()/1000) && value.epoch===team.epoch && value.revision===team.revision && !team.rotation_required && team.epoch<1000000,'Ownership proposal expired or the vault changed.');
  const owner=await verifyTeam(team,identity,trustedOwnerFingerprint);await verifyRoster(team,owner);
  requireValue(value.owner_fingerprint===owner.fingerprint && value.state_digest===await ownershipStateDigest(team),'Vault contents or access changed. Ask for a new proposal.');
  await verify(owner.signing,value,proposal.signature);return value;
}
export async function acceptOwnershipTransfer(team,identity,trustedOwnerFingerprint,proposal,directory) {
  const document=await verifyOwnershipProposal(team,identity,trustedOwnerFingerprint,proposal);
  const opened=await openTeamVault(team,identity,trustedOwnerFingerprint),raw=crypto.getRandomValues(new Uint8Array(32));
  const next={...team,owner:identity.user,epoch:team.epoch+1,role:'owner'};
  try{
    const grants=[];
    for(const member of team.grants){
      if(member.user_id===team.owner && document.former_owner_role==='removed')continue;
      const recipient=directory.find(person=>person.id===member.user_id);
      requireValue(recipient && recipient.fingerprint===member.envelope.recipient_fingerprint,'A member identity changed. Reload and verify access again.');
      const role=member.user_id===identity.user?'owner':member.user_id===team.owner?document.former_owner_role:member.role;
      grants.push(await grantFor(raw,identity,recipient,next,role));
    }
    const key=await crypto.subtle.importKey('raw',raw,{name:'AES-GCM'},false,['encrypt','decrypt']);
    const manifest={id:team.id,workspace:team.workspace,owner:identity.user,owner_fingerprint:identity.fingerprint};
    const body={proposal_id:document.id,revision:team.revision,manifest_signature:await identity.sign(manifest),payload:await encryptData(opened.entries,key,next),grants};
    return {...body,signature:await identity.sign({action:'team_vault.ownership_accept.v1',state_digest:document.state_digest,...body})};
  }finally{raw.fill(0);opened.handle.close();}
}
