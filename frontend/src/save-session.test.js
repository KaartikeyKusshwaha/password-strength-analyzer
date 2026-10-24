import { expect, it, vi } from 'vitest';
import { webcrypto } from 'node:crypto';
import { deriveKey, encryptVault, unlockVault } from './vault-crypto';
import { SaveSession } from '../../companion/extension/vault-session';
import {applyReview} from './account-review';
import {openAction} from './action-crypto';

it('aborts external password checks on lock and rejects a stale completion',async()=>{
  const session=new SaveSession({});session.material={};session.entries=[];let finish,signal;
  const operation=session.external(context=>{signal=context.signal;return new Promise(resolve=>finish=resolve);});
  expect(session.pending.size).toBe(1);session.lock();expect(signal.aborted).toBe(true);finish('stale result');
  await expect(operation).rejects.toThrow('Vault locked');expect(session.pending.size).toBe(0);
});

it('approves a selected encrypted account plan inside the extension without transmitting login details',async()=>{
  vi.stubGlobal('crypto',webcrypto);
  const salt=crypto.getRandomValues(new Uint8Array(16)),key=await deriveKey('Fixture-only!orbit-harbor-river-79',salt);
  const session=new SaveSession({});session.entries=[{id:'login',type:'login',title:'Private account',origin:'https://example.test',username:'private-user',password:'original-private-secret'}];session.material={kind:'personal',key,salt};session.policy={id:'a'.repeat(24),browser_enabled:true,browser_save:true,browser_fill:true,origins:[]};session.refresh=vi.fn(async()=>{});
  let queued;
  session.request=vi.fn(async(body,path)=>{if(path==='/actions/context')return {actor:'b'.repeat(24),vault_id:session.policy.id,kind:'personal'};queued=body;return {id:body.id,status:'queued'};});
  const response=await session.approveChanges(['login']);expect(response.status).toBe('queued');
  for(const value of ['Private account','example.test','private-user','original-private-secret'])expect(JSON.stringify(queued)).not.toContain(value);
  const opened=await openAction(queued.envelope,key,{...queued,user:'b'.repeat(24)});expect(opened.items).toEqual([{entry_id:'login',origin:'https://example.test'}]);
  session.entries[0].pending_change={action_id:'c'.repeat(24),password:'staged',created_at:new Date().toISOString()};
  await expect(session.approveChanges(['login'])).rejects.toThrow('staged');
});

it('adds authenticator keys through ciphertext-only writes and rejects duplicates and scope violations',async()=>{
  vi.stubGlobal('crypto',webcrypto);
  const master='Fixture-only!orbit-harbor-river-79',secret='JBSWY3DPEHPK3PXP';
  const salt=crypto.getRandomValues(new Uint8Array(16)),key=await deriveKey(master,salt);
  let envelope=await encryptVault([],key,salt),revision=0;
  const policy={id:'a'.repeat(24),browser_enabled:true,browser_fill:true,browser_save:true,origins:['https://example.test']};
  const fetcher=vi.fn(async(url,options)=>{if(options.method==='POST'){expect(options.body).not.toContain(secret);expect(options.body).not.toContain(master);const body=JSON.parse(options.body);envelope=body.envelope;revision++;}return {ok:true,status:200,json:async()=>({envelope,revision,vault:policy})};});
  const session=new SaveSession({},fetcher);await session.unlock(master,'',{origin:'http://127.0.0.1:8110',token:'fixture',vaultId:policy.id});
  await expect(session.addAuthenticator('Example',secret)).rejects.toThrow('allowed website');
  await expect(session.addAuthenticator('Example',secret,'https://outside.test')).rejects.toThrow('permit');
  const id=await session.addAuthenticator('Example',secret,'https://example.test');
  const opened=await unlockVault(envelope,master);expect(opened.entries[0]).toMatchObject({id,type:'totp',secret,autofill_origin:'https://example.test'});
  await expect(session.addAuthenticator('Duplicate',secret,'https://example.test')).rejects.toThrow('already saved');
  expect(fetcher.mock.calls.filter(([,options])=>options.method==='POST')).toHaveLength(1);
});

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
