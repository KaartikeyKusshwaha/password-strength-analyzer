import {expect,it,vi} from 'vitest';
import {webcrypto} from 'node:crypto';
import {prepareRecoveryKit,recoverWithKit,parseRecoveryKit,rotateProtectedVault,createProtectedVault,changeMasterPassphrase} from './vault-v2';
import {unlockVault,encryptVault} from './vault-crypto';
import nativeKit from './recovery-native.fixture.json';
vi.stubGlobal('crypto',webcrypto);
const master='Fixture-only!harbor-river-orbit-79',next='Fixture-only!mountain-lantern-harbor-94',context='a'.repeat(24);
const entry={id:'fixture-account',type:'login',title:'Fixture',origin:'https://example.test',username:'private-fixture-user',password:'private-fixture-password'};
const nativeCode='SRK1-00010203-04050607-08090A0B-0C0D0E0F-10111213-14151617-18191A1B-1C1D1E1F';
it('recovers an independent Python Argon2id/AES-GCM vector without the original master',async()=>{
  const result=await recoverWithKit(nativeKit,nativeCode,next,{context:nativeKit.vault_id,currentEnvelope:nativeKit.snapshot,source:'current'});
  expect((await unlockVault(result,next)).entries).toEqual([]);
  expect(result.ciphertext).not.toBe(nativeKit.snapshot.ciphertext);
},20000);
it('creates an encrypted kit with a separate 256-bit code and recovers later server writes locally',async()=>{
  const fetcher=vi.fn();vi.stubGlobal('fetch',fetcher);
  const original=await createProtectedVault([entry],master,context),prepared=await prepareRecoveryKit(original.envelope,master);
  expect(prepared.secret).toMatch(/^SRK1-(?:[A-F0-9]{8}-){7}[A-F0-9]{8}$/);
  expect(prepared.envelope.ciphertext).not.toBe(original.envelope.ciphertext);
  expect(JSON.stringify(prepared.kit)).not.toContain(prepared.secret);
  expect(JSON.stringify(prepared.kit)).not.toContain(entry.password);
  expect(JSON.stringify(prepared.kit)).not.toContain(master);
  const unlocked=await unlockVault(prepared.envelope,master);
  const latest=await encryptVault([{...entry,password:'latest-fixture-value'}],unlocked.key,unlocked.salt);
  const recovered=await recoverWithKit(prepared.kit,prepared.secret,next,{context,currentEnvelope:latest,source:'current'});
  expect((await unlockVault(recovered,next)).entries[0].password).toBe('latest-fixture-value');
  await expect(recoverWithKit(prepared.kit,prepared.secret,next,{context,currentEnvelope:recovered,source:'current'})).rejects.toThrow('never selected automatically');
  expect(fetcher).not.toHaveBeenCalled();
},25000);
it('never substitutes a kit snapshot for unreadable current data and permits an explicitly chosen historical source',async()=>{
  const prepared=await prepareRecoveryKit((await createProtectedVault([entry],master,context)).envelope,master);
  const rotated=await rotateProtectedVault(prepared.envelope,master);
  await expect(recoverWithKit(prepared.kit,prepared.secret,next,{context,currentEnvelope:rotated,source:'current'})).rejects.toThrow('never selected automatically');
  const historical=await recoverWithKit(prepared.kit,prepared.secret,next,{context,currentEnvelope:rotated,source:'snapshot'});
  expect((await unlockVault(historical,next)).entries).toEqual([entry]);
  await expect(recoverWithKit(prepared.kit,prepared.secret,next,{context,currentEnvelope:rotated})).rejects.toThrow('explicit recovery source');
},25000);
it('binds wrapping to vault, kit identifier and date and rejects wrong keys and damaged payloads',async()=>{
  const prepared=await prepareRecoveryKit((await createProtectedVault([entry],master,context)).envelope,master);
  const options={context,currentEnvelope:prepared.envelope,source:'current'};
  for(const changed of [{...prepared.kit,recovery_id:'b'.repeat(24)},{...prepared.kit,created_at:'2026-01-01T00:00:00.000Z'},{...prepared.kit,key_wrap:{...prepared.kit.key_wrap,wrapped_key:'A'.repeat(64)}}])await expect(recoverWithKit(changed,prepared.secret,next,options)).rejects.toThrow('Recovery did not decrypt');
  const wrong=prepared.secret.slice(0,-1)+(prepared.secret.endsWith('0')?'1':'0');
  await expect(recoverWithKit(prepared.kit,wrong,next,options)).rejects.toThrow('Recovery did not decrypt');
  await expect(recoverWithKit(prepared.kit,prepared.secret,next,{...options,context:'b'.repeat(24)})).rejects.toThrow('matching personal vault');
  await expect(recoverWithKit(prepared.kit,prepared.secret,next,{...options,currentEnvelope:{...prepared.envelope,ciphertext:'A'.repeat(64)}})).rejects.toThrow('Recovery did not decrypt');
},25000);
it('documents that a master rewrap alone preserves kit access and rejects invalid or oversized files',async()=>{
  const prepared=await prepareRecoveryKit((await createProtectedVault([],master,context)).envelope,master);
  const changed=await changeMasterPassphrase(prepared.envelope,master,next);
  expect((await unlockVault(await recoverWithKit(prepared.kit,prepared.secret,master,{context,currentEnvelope:changed,source:'current'}),master)).entries).toEqual([]);
  for(const value of ['x'.repeat(150001),'{bad', {...nativeKit,version:2},{...nativeKit,plaintext:'never allowed'},{...nativeKit,snapshot:{...nativeKit.snapshot,kdf:{...nativeKit.snapshot.kdf,memory_kib:2147483648}}}])expect(()=>parseRecoveryKit(value)).toThrow('Unsupported or damaged');
},25000);
