import {beforeEach,expect,it,vi} from 'vitest';
import {webcrypto} from 'node:crypto';
import {SaveSession} from '../../companion/extension/vault-session';
import {openTeamVault,unlockSharingIdentity,rotateTeamVault,createSharingIdentity} from './sharing-crypto';
import native from './fixtures/native-sharing.json';
import {applyReview} from './account-review';

const origin='http://127.0.0.1:8110';
beforeEach(()=>vi.stubGlobal('crypto',webcrypto));
function system() {
  const config={origin,token:'fixture-private-token-only',vaultId:native.team.id,vaultKind:'shared'};
  let value={kind:'shared',revision:1,envelope:native.team.payload,vault:{id:native.team.id,name:'Client fixture',kind:'shared',browser_save:true,browser_fill:true,origins:[],lock_seconds:30},sharing:{user_id:native.user,identity:native.identity,team:structuredClone(native.team)}};
  const fetcher=vi.fn(async(url,options)=>{
    expect(url).toBe(origin+'/api/companion/vault');expect(options.credentials).toBe('omit');expect(options.redirect).toBe('error');
    if(options.method==='POST'){
      expect(options.body).not.toContain(native.password);expect(options.body).not.toContain('https://example.test');expect(options.body).not.toContain('replacement-fixture-password');
      const body=JSON.parse(options.body);expect(body.revision).toBe(value.revision);
      value={...value,revision:value.revision+1,envelope:body.envelope,sharing:{...value.sharing,team:{...value.sharing.team,revision:value.revision+1,payload:body.envelope}}};
    }
    return {ok:true,status:200,json:async()=>value};
  });
  const browser={storage:{local:{get:vi.fn(async()=>({connection:config})),set:vi.fn()}}};
  return {session:new SaveSession(browser,fetcher),fetcher,browser,config,get value(){return value;},set value(next){value=next;}};
}
it('persists encrypted shared archival, denies companion use, and creates a fresh login without reviving an archive',async()=>{
  const s=system();await s.session.unlock(native.password);
  await s.session.persist(applyReview(s.session.entries,[native.entry.id],'archive'));
  await expect(s.session.fill(native.entry.id,native.entry.origin)).rejects.toThrow('No selected login');
  const who=await unlockSharingIdentity(native.user,native.identity,native.password),opened=await openTeamVault(s.value.sharing.team,who,native.identity.fingerprint);
  expect(opened.entries[0].password).toBe(native.entry.password);expect(opened.entries[0].history.archived_at).toBeTruthy();opened.handle.close();
  for(const [,options] of s.fetcher.mock.calls)if(options.body){expect(options.body).not.toContain('archived_at');expect(options.body).not.toContain(native.entry.password);}
  await s.session.save({origin:native.entry.origin,username:native.entry.username,password:'replacement-fixture-password',expires:Date.now()+180000});
  expect(s.session.entries).toHaveLength(2);expect(s.session.entries.find(e=>e.id===native.entry.id).history.archived_at).toBeTruthy();
  const active=s.session.entries.find(e=>e.id!==native.entry.id);expect(active.history.events[0].kind).toBe('saved');
  expect(await s.session.fill(active.id,native.entry.origin)).toMatchObject({password:'replacement-fixture-password'});s.session.lock();
},15000);
it('uses the same encrypted shared vault in the companion and dashboard without persisting private keys',async()=>{
  const s=system();await s.session.unlock(native.password);
  expect(s.session.entries).toEqual([native.entry]);
  expect(await s.session.fill(native.entry.id,native.entry.origin)).toMatchObject({username:'fixture',password:native.entry.password});
  await expect(s.session.fill(native.entry.id,'https://example.test.evil.test')).rejects.toThrow('exact HTTPS origin');
  const capture={origin:native.entry.origin,username:native.entry.username,password:'replacement-fixture-password',expires:Date.now()+180000};
  expect(await s.session.save(capture)).toEqual({needsConfirmation:true});
  expect(s.fetcher.mock.calls.filter(([,v])=>v.method==='POST')).toHaveLength(0);
  expect(await s.session.save(capture,true)).toEqual({saved:true,updated:true});
  const who=await unlockSharingIdentity(native.user,native.identity,native.password),opened=await openTeamVault(s.value.sharing.team,who,native.identity.fingerprint);
  expect(opened.entries[0].password).toBe('replacement-fixture-password');opened.handle.close();
  expect(s.browser.storage.local.set).not.toHaveBeenCalled();s.session.lock();expect(s.session.material).toBeNull();
},15000);
it('rechecks live policy for saves, login fills and authenticator reveals',async()=>{
  const s=system();await s.session.unlock(native.password);
  s.value={...s.value,vault:{...s.value.vault,browser_save:false,browser_fill:false}};
  await expect(s.session.fill(native.entry.id,native.entry.origin)).rejects.toThrow('does not permit');
  await expect(s.session.code('not-disclosed')).rejects.toThrow('does not permit');
  await expect(s.session.save({origin:native.entry.origin,username:'new',password:'replacement-fixture-password',expires:Date.now()+10000})).rejects.toThrow('does not permit');
  expect(s.fetcher.mock.calls.filter(([,v])=>v.method==='POST')).toHaveLength(0);
},15000);
it('refuses stale entries after shared key rotation and requires another local unlock',async()=>{
  const s=system();await s.session.unlock(native.password);
  const who=await unlockSharingIdentity(native.user,native.identity,native.password);
  const changed=await rotateTeamVault(native.team,who,native.identity.fingerprint,[{id:native.user,public:native.identity.public,fingerprint:native.identity.fingerprint}]);
  s.value={...s.value,revision:2,envelope:changed.payload,sharing:{...s.value.sharing,team:{...s.value.sharing.team,epoch:2,revision:2,payload:changed.payload,grant:{...changed.grants[0],issuer_public:native.identity.public,issuer_grant:null}}}};
  await expect(s.session.fill(native.entry.id,native.entry.origin)).rejects.toThrow('changed elsewhere');
  await s.session.unlock(native.password);expect(s.session.entries).toEqual([native.entry]);s.session.lock();
},15000);
it('cannot revive an unlock that was cancelled while its request was in flight',async()=>{
  const s=system();let resolveRequest;
  s.fetcher.mockImplementationOnce(()=>new Promise(resolve=>{resolveRequest=resolve;}));
  const opening=s.session.unlock(native.password,'',s.config);
  await vi.waitFor(()=>expect(resolveRequest).toBeTypeOf('function'));
  s.session.lock();resolveRequest({ok:true,status:200,json:async()=>s.value});
  await expect(opening).rejects.toThrow('Vault locked');expect(s.session.material).toBeNull();expect(s.session.entries).toBeNull();
});
it('refuses a connection whose selected vault ID or kind was substituted',async()=>{
  const s=system();await expect(s.session.unlock(native.password,'',{...s.config,vaultId:'e'.repeat(24)})).rejects.toThrow('different vault');
  await expect(s.session.unlock(native.password,'',{...s.config,vaultKind:'personal'})).rejects.toThrow('scope changed');
});
it('requires independent owner verification for a recipient even if connection metadata claims ownership',async()=>{
  const s=system(),reader=await createSharingIdentity('f'.repeat(24),'Fixture-only!reader-sharing-passphrase-79');
  const who=await unlockSharingIdentity(native.user,native.identity,native.password),opened=await openTeamVault(native.team,who,native.identity.fingerprint);
  const grant=await opened.handle.invite({id:reader.identity.user,public:reader.record.public,fingerprint:reader.identity.fingerprint},'viewer');opened.handle.close();
  s.value={...s.value,sharing:{user_id:reader.identity.user,identity:{...reader.record,fingerprint:reader.identity.fingerprint},team:{...native.team,role:'viewer',grant:{...grant,issuer_public:native.identity.public,issuer_grant:null}}}};
  await expect(s.session.unlock('Fixture-only!reader-sharing-passphrase-79','',{...s.config,ownerIsSelf:true})).rejects.toThrow('Verify');
  await s.session.unlock('Fixture-only!reader-sharing-passphrase-79',native.identity.fingerprint);
  expect(s.session.entries).toEqual([native.entry]);s.session.lock();
},15000);
