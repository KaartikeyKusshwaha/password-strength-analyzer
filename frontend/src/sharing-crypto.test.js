import {beforeEach,expect,it,vi} from 'vitest';
import {webcrypto} from 'node:crypto';
import {canonical,createSharingIdentity,unlockSharingIdentity,prepareSharingPassphraseChange,createTeamVault,verifyTeam,openTeamVault,rotateTeamVault,ownershipStateDigest,prepareOwnershipProposal,verifyOwnershipProposal,acceptOwnershipTransfer} from './sharing-crypto';
import native from './fixtures/native-sharing.json';
import ownershipVector from './fixtures/native-ownership-state.json';
const ownerID='a'.repeat(24),readerID='b'.repeat(24),workspace='c'.repeat(24),vaultID='d'.repeat(24),master='Fixture-only!harbor-orchid-river-79';
const entry={id:'fixture-entry',type:'login',title:'Example',origin:'https://example.test',username:'fixture',password:'fixture-password-never-real'};
let owner,reader,created;
beforeEach(()=>{vi.stubGlobal('crypto',webcrypto);});
it('opens an independently generated Python Argon2id/RSA-OAEP/ECDSA/AES-GCM vector',async()=>{
  const who=await unlockSharingIdentity(native.user,native.identity,native.password);
  const opened=await openTeamVault(native.team,who,native.identity.fingerprint);
  expect(opened.entries).toEqual([native.entry]);opened.handle.close();
},15000);
async function fixture() {
  if(!created){owner=await createSharingIdentity(ownerID,master);reader=await createSharingIdentity(readerID,master);created=await createTeamVault(owner.identity,workspace,'Client',vaultID);}
  const root={document:{id:vaultID,workspace,owner:ownerID,owner_fingerprint:owner.identity.fingerprint},signature:created.manifest_signature};
  const grant={...created.grant,issuer_public:owner.record.public,issuer_grant:null};
  return {id:vaultID,workspace,owner:ownerID,owner_public:owner.record.public,owner_fingerprint:owner.identity.fingerprint,manifest:root,epoch:1,revision:1,rotation_required:false,role:'owner',accepted:true,grant,grants:[{user_id:ownerID,role:'owner',envelope:grant,accepted:true}],payload:created.payload};
}
it('encrypts private identity keys, rejects wrong passphrases and binds identity to user',async()=>{
  await fixture();const record={...owner.record,fingerprint:owner.identity.fingerprint};
  expect(JSON.stringify(record)).not.toContain(master);expect(JSON.stringify(record)).not.toContain('PRIVATE KEY');
  expect((await unlockSharingIdentity(ownerID,record,master)).fingerprint).toBe(owner.identity.fingerprint);
  await expect(unlockSharingIdentity(ownerID,record,'wrong-fixture-passphrase')).rejects.toThrow('Could not unlock');
  await expect(unlockSharingIdentity(readerID,record,master)).rejects.toThrow('Could not unlock');
},30000);
it('requires verified owner identity, rejects signed role tampering and isolates recipients',async()=>{
  const team=await fixture();const trusted=owner.identity.fingerprint;
  await expect(openTeamVault(team,owner.identity,'0'.repeat(64))).rejects.toThrow('Verify');
  await expect(openTeamVault({...team,role:'editor',grant:{...team.grant,role:'editor'}},owner.identity,trusted)).rejects.toThrow();
  const opened=await openTeamVault(team,owner.identity,trusted),payload=await opened.handle.encrypt([entry]);
  expect(JSON.stringify(payload)).not.toContain(entry.password);
  const invited=await opened.handle.invite({id:readerID,public:reader.record.public,fingerprint:reader.identity.fingerprint},'viewer');
  const shared={...team,role:'viewer',grant:{...invited,issuer_public:owner.record.public,issuer_grant:null},payload};
  const read=await openTeamVault(shared,reader.identity,trusted);expect(read.entries).toEqual([entry]);
  await expect(openTeamVault(shared,owner.identity,trusted)).rejects.toThrow();
  await expect(openTeamVault({...shared,payload:{...payload,context:'e'.repeat(24)}},reader.identity,trusted)).rejects.toThrow();
  await expect(read.handle.invite({id:ownerID,public:owner.record.public,fingerprint:trusted},'editor')).rejects.toThrow();
  read.handle.close();await expect(read.handle.decrypt(payload)).rejects.toThrow('Unlock');opened.handle.close();
},30000);
it('changes the data key on offboarding so a removed recipient cannot decrypt the next epoch',async()=>{
  const team=await fixture(),trusted=owner.identity.fingerprint,opened=await openTeamVault(team,owner.identity,trusted);
  const payload=await opened.handle.encrypt([entry]);
  const invited=await opened.handle.invite({id:readerID,public:reader.record.public,fingerprint:reader.identity.fingerprint},'editor');
  const removed=await openTeamVault({...team,role:'editor',grant:{...invited,issuer_public:owner.record.public,issuer_grant:null},payload},reader.identity,trusted);
  const rotated=await rotateTeamVault({...team,payload},owner.identity,trusted,[{id:ownerID,public:owner.record.public,fingerprint:trusted}]);
  expect(rotated.payload.epoch).toBe(2);expect(rotated.grants.map(g=>g.recipient)).toEqual([ownerID]);
  await expect(removed.handle.decrypt(rotated.payload)).rejects.toThrow();
  // Even bypassing epoch validation cannot make the previous AES key decrypt new ciphertext.
  await expect(removed.handle.decrypt({...rotated.payload,epoch:1})).rejects.toThrow();
  const next={...team,epoch:2,revision:2,grant:{...rotated.grants[0],issuer_public:owner.record.public,issuer_grant:null},payload:rotated.payload};
  expect((await openTeamVault(next,owner.identity,trusted)).entries).toEqual([entry]);removed.handle.close();opened.handle.close();
},30000);

it('changes only the encrypted identity wrapper and preserves independently generated shared keys and access',async()=>{
  const next='Fixture-only!a-new-cedar-harbor-79';
  const before=structuredClone(native.identity),team=structuredClone(native.team);
  const change=await prepareSharingPassphraseChange(native.user,native.identity,native.password,next);
  expect(Object.keys(change).sort()).toEqual(['encrypted','previous_digest','signature']);
  expect(change.encrypted.salt).not.toBe(before.encrypted.salt);
  expect(change.encrypted.iv).not.toBe(before.encrypted.iv);
  expect(change.encrypted.ciphertext).not.toBe(before.encrypted.ciphertext);
  expect(native.identity).toEqual(before);expect(native.team).toEqual(team);
  const current={...before,encrypted:change.encrypted};
  const who=await unlockSharingIdentity(native.user,current,next);
  expect(who.fingerprint).toBe(before.fingerprint);
  const opened=await openTeamVault(native.team,who,before.fingerprint);
  expect(opened.entries).toEqual([native.entry]);opened.handle.close();
  await expect(unlockSharingIdentity(native.user,current,native.password)).rejects.toThrow('Could not unlock');
  // The signed authorization binds the existing encryption revision, user and new envelope.
  const publicKey=await crypto.subtle.importKey('spki',Uint8Array.from(atob(before.public.signing),c=>c.charCodeAt(0)),{name:'ECDSA',namedCurve:'P-256'},false,['verify']);
  const document={action:'sharing.identity_rewrap.v1',user:native.user,fingerprint:before.fingerprint,previous_digest:change.previous_digest,encrypted:change.encrypted};
  expect(await crypto.subtle.verify({name:'ECDSA',hash:'SHA-256'},publicKey,Uint8Array.from(atob(change.signature),c=>c.charCodeAt(0)),new TextEncoder().encode(canonical(document)))).toBe(true);
  const expected=[...new Uint8Array(await crypto.subtle.digest('SHA-256',new TextEncoder().encode(canonical(before.encrypted))))].map(v=>v.toString(16).padStart(2,'0')).join('');
  expect(change.previous_digest).toBe(expected);
  expect(JSON.stringify(change)).not.toContain(next);
  expect(JSON.stringify(change)).not.toContain(native.password);
},30000);

it('refuses rewrapping with the wrong current passphrase, wrong user, altered identity or unchanged password',async()=>{
  const next='Fixture-only!another-sharing-password-79';
  await expect(prepareSharingPassphraseChange(native.user,native.identity,'wrong-current-fixture',next)).rejects.toThrow('Could not unlock');
  await expect(prepareSharingPassphraseChange('e'.repeat(24),native.identity,native.password,next)).rejects.toThrow('Could not unlock');
  await expect(prepareSharingPassphraseChange(native.user,{...native.identity,fingerprint:'0'.repeat(64)},native.password,next)).rejects.toThrow('Could not unlock');
  await expect(prepareSharingPassphraseChange(native.user,native.identity,native.password,native.password)).rejects.toThrow('different');
  await expect(prepareSharingPassphraseChange(native.user,native.identity,native.password,'short')).rejects.toThrow('15');
},30000);

it('matches the independently computed Python ownership snapshot digest',async()=>{
  expect(await ownershipStateDigest(ownershipVector.team)).toBe(ownershipVector.state_digest);
});
async function ownershipFixture() {
  const team=await fixture(),trusted=owner.identity.fingerprint,opened=await openTeamVault(team,owner.identity,trusted);
  const pendingEntry={...entry,pending_change:{action_id:'f'.repeat(24),created_at:'2026-10-19T00:00:00.000Z',password:'fixture-staged-replacement-never-real'},history:{version:1,events:[{kind:'saved',at:'2026-10-19T00:00:00.000Z'}]}};
  const payload=await opened.handle.encrypt([pendingEntry]);
  const invite=await opened.handle.invite({id:readerID,public:reader.record.public,fingerprint:reader.identity.fingerprint},'editor');
  const readerGrant={...invite,issuer_public:owner.record.public,issuer_grant:null};opened.handle.close();
  const complete={...team,payload,browser_policy:{browser_enabled:true,browser_save:true,browser_fill:true,origins:[],lock_seconds:180},grants:[...team.grants,{user_id:readerID,role:'editor',accepted:true,envelope:readerGrant}]};
  const directory=[{id:ownerID,public:owner.record.public,fingerprint:trusted,role:'analyst'},{id:readerID,public:reader.record.public,fingerprint:reader.identity.fingerprint,role:'reviewer'}];
  return {team:complete,view:{...complete,role:'editor',grant:readerGrant},directory,trusted,pendingEntry};
}
it('transfers through new-owner-signed grants and a fresh data key without losing encrypted account history',async()=>{
  const {team,view,directory,trusted,pendingEntry}=await ownershipFixture();
  const old=await openTeamVault(team,owner.identity,trusted);
  const proposal={...await prepareOwnershipProposal(team,owner.identity,directory[1],'removed'),status:'pending'};
  const body=await acceptOwnershipTransfer(view,reader.identity,trusted,proposal,directory);
  expect(body.payload.epoch).toBe(2);expect(body.grants.map(g=>g.recipient)).toEqual([readerID]);
  expect(JSON.stringify(body)).not.toContain(entry.password);expect(JSON.stringify(body)).not.toContain(entry.username);
  expect(JSON.stringify(body)).not.toContain(pendingEntry.pending_change.password);
  const manifest={id:vaultID,workspace,owner:readerID,owner_fingerprint:reader.identity.fingerprint};
  const next={...view,owner:readerID,owner_public:reader.record.public,owner_fingerprint:reader.identity.fingerprint,epoch:2,revision:2,role:'owner',manifest:{document:manifest,signature:body.manifest_signature},grant:{...body.grants[0],issuer_public:reader.record.public,issuer_grant:null},payload:body.payload};
  const opened=await openTeamVault(next,reader.identity,reader.identity.fingerprint);
  expect(opened.entries).toEqual([pendingEntry]);opened.handle.close();
  await expect(old.handle.decrypt({...body.payload,epoch:1})).rejects.toThrow();old.handle.close();
  await expect(openTeamVault(next,owner.identity,reader.identity.fingerprint)).rejects.toThrow();
},30000);
it('preserves only the approved former-owner role and refuses forged, changed or wrong-recipient proposals',async()=>{
  const {team,view,directory,trusted}=await ownershipFixture();
  const proposal={...await prepareOwnershipProposal(team,owner.identity,directory[1],'viewer'),status:'pending'};
  const body=await acceptOwnershipTransfer(view,reader.identity,trusted,proposal,directory);
  expect(body.grants.find(g=>g.recipient===ownerID).role).toBe('viewer');
  await expect(verifyOwnershipProposal(view,owner.identity,trusted,proposal)).rejects.toThrow('scope');
  await expect(verifyOwnershipProposal({...view,browser_policy:{...view.browser_policy,browser_fill:false}},reader.identity,trusted,proposal)).rejects.toThrow('changed');
  await expect(verifyOwnershipProposal(view,reader.identity,trusted,{...proposal,document:{...proposal.document,former_owner_role:'admin'}})).rejects.toThrow('signature');
  await expect(verifyOwnershipProposal(view,reader.identity,trusted,{...proposal,document:{...proposal.document,expires_at:1}})).rejects.toThrow('expired');
  await expect(verifyOwnershipProposal(view,reader.identity,trusted,{...proposal,status:'cancelled'})).rejects.toThrow('pending');
},30000);
