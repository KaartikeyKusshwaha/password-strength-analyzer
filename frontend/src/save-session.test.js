import { expect, it, vi } from 'vitest';
import { webcrypto } from 'node:crypto';
import { deriveKey, encryptVault, unlockVault } from './vault-crypto';
import { SaveSession } from '../../companion/extension/vault-session';
import {applyReview} from './account-review';

it('blocks archived login fills and authenticator reveals even when a caller supplies their IDs directly',async()=>{
  const login={id:'login',type:'login',title:'Fixture',origin:'https://example.test',username:'fixture',password:'fixture-secret'},code={id:'otp',type:'totp',title:'Fixture code',secret:'JBSWY3DPEHPK3PXP',digits:6,period:30,algorithm:'SHA-1'};
  const session=new SaveSession({});session.entries=applyReview([login,code],['login','otp'],'archive');session.refresh=vi.fn(async()=>{});
  await expect(session.fill('login',login.origin)).rejects.toThrow('No selected login');
  await expect(session.code('otp')).rejects.toThrow('archived');
});

it('the in-page save sends only ciphertext and requires confirmation before replacing an existing account', async () => {
  vi.stubGlobal('crypto',webcrypto);
  const master='Fixture-only!orbit-harbor-river-79';
  const salt=crypto.getRandomValues(new Uint8Array(16)), key=await deriveKey(master,salt);
  const old={id:'old',type:'login',title:'Fixture',origin:'https://example.test',username:'fixture',password:'Old-fixture-secret-123'};
  let payload=await encryptVault([old],key,salt), revision=1;
  const fetcher=vi.fn(async (url, options)=>{
    expect(url).toBe('http://127.0.0.1:8110/api/companion/vault');
    expect(options.credentials).toBe('omit');expect(options.redirect).toBe('error');
    if(options.method==='POST'){
      expect(options.body).not.toContain('replacement-secret');expect(options.body).not.toContain(master);expect(options.body).not.toContain('https://example.test');
      const value=JSON.parse(options.body);expect(value.revision).toBe(revision);payload=value.envelope;revision++;
    }
    return {ok:true,status:200,json:async()=>({revision,envelope:payload})};
  });
  const browser={storage:{local:{get:async()=>({connection:{origin:'http://127.0.0.1:8110',token:'fixture-token-only'}})}}};
  const session=new SaveSession(browser,fetcher);
  await session.unlock(master);
  const capture={origin:'https://example.test',username:'fixture',password:'replacement-secret',expires:Date.now()+180000};
  expect(await session.save(capture)).toEqual({needsConfirmation:true});
  expect(fetcher.mock.calls.filter(([,options])=>options.method==='POST')).toHaveLength(0);
  expect(await session.save(capture,true)).toEqual({saved:true,updated:true});
  const decrypted=await unlockVault(payload,master);
  expect(decrypted.entries).toHaveLength(1);expect(decrypted.entries[0].password).toBe('replacement-secret');
  session.lock();await expect(session.save(capture,true)).rejects.toThrow('Unlock');
});
it('rejects expired captures, revoked tokens and stale vault writes', async () => {
  const session=new SaveSession({});
  session.material={};session.entries=[];
  await expect(session.save({expires:Date.now()-1})).rejects.toThrow('expired');
  session.config={origin:'https://example.test',token:'private'};
  session.fetcher=async()=>({status:401});await expect(session.request()).rejects.toThrow('revoked');
  session.fetcher=async()=>({status:409});await expect(session.request()).rejects.toThrow('nothing was overwritten');
  session.fetcher=async()=>({status:500});await expect(session.request()).rejects.toThrow('Could not synchronize');
});
it('enforces the selected vault browser policy before encrypting or sending a save',async()=>{
  const session=new SaveSession({}),fetcher=vi.fn();session.fetcher=fetcher;
  session.material={};session.entries=[];
  const capture={origin:'https://example.test',username:'fixture',password:'fixture',expires:Date.now()+10000};
  session.policy={browser_save:false,origins:[]};
  await expect(session.save(capture)).rejects.toThrow('does not permit');
  session.policy={browser_save:true,origins:['https://other.test']};
  await expect(session.save(capture)).rejects.toThrow('does not permit');
  expect(fetcher).not.toHaveBeenCalled();
});
