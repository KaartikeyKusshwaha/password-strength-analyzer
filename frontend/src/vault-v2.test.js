import { expect, it, vi } from 'vitest';
import { webcrypto } from 'node:crypto';
import { createProtectedVault, changeMasterPassphrase } from './vault-v2';
import { encryptVault, unlockVault, decryptWithKey } from './vault-crypto';
const master='Fixture-only!harbor-river-orbit-79', nextMaster='Fixture-only!orchid-mountain-harbor-83', context='a'.repeat(24);
const entry={id:'fixture-login',type:'login',title:'Fixture',origin:'https://example.test',username:'fixture',password:'fixture-secret-password'};
vi.stubGlobal('crypto',webcrypto);
it('opens an independent native-cryptography Argon2id/AES-GCM test vector',async()=>{
  // Produced with Python cryptography Argon2id + AESGCM, not the JS wrappers.
  // Fixed salts/IVs exist only in this interoperability fixture.
  const vector={version:2,context:'cccccccccccccccccccccccc',kdf:{algorithm:'argon2id',memory_kib:65536,iterations:3,parallelism:1},salt:'AAECAwQFBgcICQoLDA0ODw==',wrap_iv:'d3d3d3d3d3d3d3d3',wrapped_key:'hHFn0vrSs48/S4MPc1wJ9GOLdt3+oE1424YFFA5y/LfSEumlWAFoU0iOKa7PcYw2',iv:'ZGRkZGRkZGRkZGRk',ciphertext:'nrrTpCm4gMNRkGTTnj5jbYudurlbgV+IL0y06zKv'};
  expect((await unlockVault(vector,'Fixture-only!native-argon-vector-79')).entries).toEqual([]);
},15000);
it('uses a random nonextractable data key with Argon2id and round-trips without network or plaintext persistence',async()=>{
  const fetcher=vi.fn();vi.stubGlobal('fetch',fetcher);
  const created=await createProtectedVault([entry],master,context);
  expect(created.key.extractable).toBe(false);expect(created.envelope.version).toBe(2);
  expect(created.envelope.kdf).toEqual({algorithm:'argon2id',memory_kib:65536,iterations:3,parallelism:1});
  expect(JSON.stringify(created.envelope)).not.toContain(entry.password);
  const opened=await unlockVault(created.envelope,master);expect(opened.entries).toEqual([entry]);
  const updated=await encryptVault([{...entry,password:'new-fixture-secret'}],opened.key,opened.salt);
  expect(updated.wrapped_key).toBe(created.envelope.wrapped_key);expect(updated.iv).not.toBe(created.envelope.iv);
  expect((await decryptWithKey(updated,opened.key,opened.salt))[0].password).toBe('new-fixture-secret');
  expect(fetcher).not.toHaveBeenCalled();
},15000);
it('changes the master wrapping key without changing encrypted item data',async()=>{
  const created=await createProtectedVault([entry],master,context);
  const changed=await changeMasterPassphrase(created.envelope,master,nextMaster);
  expect(changed.ciphertext).toBe(created.envelope.ciphertext);expect(changed.iv).toBe(created.envelope.iv);
  expect(changed.wrapped_key).not.toBe(created.envelope.wrapped_key);expect(changed.salt).not.toBe(created.envelope.salt);
  expect((await unlockVault(changed,nextMaster)).entries).toEqual([entry]);
  await expect(unlockVault(changed,master)).rejects.toThrow('Could not unlock');
},15000);
it('allows the same account in two independently encrypted vaults',async()=>{
  const a=await createProtectedVault([entry],master,context),b=await createProtectedVault([{...entry,password:'other-fixture-password'}],master,'b'.repeat(24));
  expect((await unlockVault(a.envelope,master)).entries[0].password).toBe(entry.password);
  expect((await unlockVault(b.envelope,master)).entries[0].password).toBe('other-fixture-password');
  expect(a.envelope.wrapped_key).not.toBe(b.envelope.wrapped_key);
  await expect(decryptWithKey(b.envelope,a.key,a.salt)).rejects.toThrow('encryption changed');
},15000);
it('rejects wrapped-key substitution, context changes and unbounded KDF parameters',async()=>{
  const created=await createProtectedVault([entry],master,context);
  await expect(unlockVault({...created.envelope,context:'b'.repeat(24)},master)).rejects.toThrow('Could not unlock');
  await expect(unlockVault({...created.envelope,kdf:{...created.envelope.kdf,memory_kib:2147483648}},master)).rejects.toThrow('Could not unlock');
  await expect(unlockVault({...created.envelope,wrapped_key:'A'.repeat(64)},master)).rejects.toThrow('Could not unlock');
  await expect(decryptWithKey({...created.envelope,wrapped_key:'A'.repeat(64)},created.key,created.salt)).rejects.toThrow('encryption changed');
},15000);
