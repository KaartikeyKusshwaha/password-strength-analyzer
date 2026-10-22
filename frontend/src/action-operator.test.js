import {beforeEach,expect,it,vi} from 'vitest';
import {webcrypto} from 'node:crypto';
import {SaveSession} from '../../companion/extension/vault-session';
import {AccountOperator} from '../../companion/extension/action-operator';
import {PendingRecovery} from '../../companion/extension/pending-recovery';
import {unlockSharingIdentity,openTeamVault} from './sharing-crypto';
import native from './fixtures/native-sharing.json';
beforeEach(()=>vi.stubGlobal('crypto',webcrypto));

it('automatically stages only an approved plan without opening or submitting a website',async()=>{
  const s=await system();await s.operator.stageApproved(s.job);
  expect(s.session.entries[0].pending_change.password).toHaveLength(24);
  expect(s.session.entries[0].password).toBe(native.entry.password);
  expect(s.browser.runtime.sendMessage).not.toHaveBeenCalled();
  expect(s.browser.tabs.sendMessage).not.toHaveBeenCalled();s.session.lock();
},20000);

it('recovers a stopped proposal into encrypted archived storage without restarting its plan',async()=>{
  const s=await system();await s.operator.stageApproved(s.job);
  const proposal=s.session.entries[0].pending_change.password,recovery=new PendingRecovery(s.session);
  await expect(recovery.resolve(native.entry.id,s.job.id,true)).rejects.toThrow('Stop the matching');
  s.job={...s.job,status:'expired'};s.fetcher.mockClear();
  await recovery.resolve(native.entry.id,s.job.id,true);
  expect(s.session.entries[0].password).toBe(proposal);
  expect(s.session.entries[0].pending_change).toBeUndefined();
  expect(s.session.entries[1].password).toBe(native.entry.password);
  expect(s.session.entries[1].history.archived_at).toBeTruthy();
  for(const [url,options] of s.fetcher.mock.calls){expect(url).not.toMatch(/\/(claim|result)$/);if(options.body){expect(options.body).not.toContain(proposal);expect(options.body).not.toContain(native.entry.password);}}
  s.session.lock();const reopened=new SaveSession(s.browser,s.fetcher);await reopened.unlock(native.password);
  expect(reopened.entries).toHaveLength(2);expect(reopened.entries[0].password).toBe(proposal);reopened.lock();
},20000);

async function system() {
  const who=await unlockSharingIdentity(native.user,native.identity,native.password),opened=await openTeamVault(native.team,who,native.identity.fingerprint);
  const at=Math.floor(Date.now()/1000),manifest={version:1,id:'4'.repeat(24),actor:native.user,vault_id:native.team.id,kind:'shared',approved_at:at,expires_at:at+1800,items:[{entry_id:native.entry.id,origin:native.entry.origin}]};
  let job={id:manifest.id,user:native.user,vault_id:native.team.id,kind:'shared',workspace:native.team.workspace,entry_count:1,expires_at:manifest.expires_at,status:'queued',items:[{state:'queued',reason:''}],manifest:await opened.handle.sealAction(manifest)};opened.handle.close();
  let value={kind:'shared',revision:1,envelope:native.team.payload,vault:{id:native.team.id,name:'Client',browser_save:true,browser_fill:true,origins:[],lock_seconds:180},sharing:{user_id:native.user,identity:native.identity,team:structuredClone(native.team)}};
  const temporary={},config={origin:'http://127.0.0.1:8110',token:'fixture-private-browser-bearer',vaultId:native.team.id,vaultKind:'shared'},lease='fixture_'.repeat(7);
  const browser={storage:{local:{get:vi.fn(async()=>({connection:config})),set:vi.fn()},session:{get:vi.fn(async()=>temporary),set:vi.fn(async values=>Object.assign(temporary,values))}},runtime:{sendMessage:vi.fn(async()=>({ok:true}))},tabs:{sendMessage:vi.fn(async()=>({ok:true,submitted:false}))}};
  const fetcher=vi.fn(async(url,options)=>{
    let response;
    if(url.endsWith('/vault')) {
      if(options.method==='POST') {const body=JSON.parse(options.body);expect(body.revision).toBe(value.revision);value={...value,revision:value.revision+1,envelope:body.envelope,sharing:{...value.sharing,team:{...value.sharing.team,revision:value.revision+1,payload:body.envelope}}};}
      response=value;
    } else if(url.endsWith('/claim')) {job={...job,status:'running'};response={lease,action:structuredClone(job)};}
    else if(url.endsWith('/result')) {const body=JSON.parse(options.body);expect(body.lease).toBe(lease);job={...job,status:['confirmed_by_user','discarded'].includes(body.state)?'complete':'awaiting_confirmation',items:[{state:body.state,reason:body.reason}]};response={status:job.status,items:job.items};}
    else response={actions:[structuredClone(job)]};
    return {ok:true,status:200,json:async()=>structuredClone(response)};
  });
  const session=new SaveSession(browser,fetcher);await session.unlock(native.password);
  return {browser,fetcher,session,operator:new AccountOperator(session,browser),get job(){return job;},set job(next){job=next;},get value(){return value;},config};
}
it('runs the approved encrypted plan through staging, page opening, preparation and explicit confirmation',async()=>{
  const s=await system();await s.operator.select(s.job);await s.operator.open(0);
  const staged=s.session.entries[0].pending_change.password;
  expect(s.session.entries[0].password).toBe(native.entry.password);expect(staged.length).toBe(24);
  expect(s.browser.runtime.sendMessage).toHaveBeenCalledWith({type:'open-account-change',origin:native.entry.origin});
  expect(s.browser.tabs.sendMessage).not.toHaveBeenCalled();
  expect(await s.operator.prepare(0,{id:7,url:native.entry.origin+'/change'})).toEqual({prepared:true,submitted:false});
  expect(s.browser.tabs.sendMessage).toHaveBeenCalledWith(7,{type:'prepare-password-change',origin:native.entry.origin,current:native.entry.password,replacement:staged,username:native.entry.username},{frameId:0});
  expect(s.session.entries[0].password).toBe(native.entry.password);
  await s.operator.finish(0,true);expect(s.session.entries[0].password).toBe(staged);expect(s.session.entries[0].pending_change).toBeUndefined();expect(s.job.status).toBe('complete');
  for(const [,options] of s.fetcher.mock.calls)if(options.body){expect(options.body).not.toContain(staged);expect(options.body).not.toContain(native.entry.password);expect(options.body).not.toContain(native.entry.origin);expect(options.body).not.toContain(native.password);}
  expect(JSON.stringify(s.browser.storage.session.set.mock.calls)).not.toContain(staged);expect(s.browser.storage.local.set).not.toHaveBeenCalled();s.session.lock();
},20000);
it('restores a closed popup without generating another password and retains old login for unsupported forms',async()=>{
  const s=await system();await s.operator.select(s.job);await s.operator.open(0);const staged=s.session.entries[0].pending_change.password;s.session.lock();
  const next=new SaveSession(s.browser,s.fetcher);await next.unlock(native.password);const operator=new AccountOperator(next,s.browser);
  expect(await operator.restore([s.job])).toBe(true);
  s.browser.tabs.sendMessage.mockResolvedValue({ok:false,reason:'unsupported_form'});
  await expect(operator.prepare(0,{id:7,url:native.entry.origin+'/change'})).rejects.toThrow('supported password-change form');
  expect(next.entries[0].pending_change.password).toBe(staged);expect(next.entries[0].password).toBe(native.entry.password);expect(s.job.items[0].reason).toBe('unsupported_form');
  await operator.finish(0,false);const {history,...original}=next.entries[0];expect(original).toEqual(native.entry);expect(history.events.map(e=>e.kind)).toEqual(['proposal_staged','proposal_discarded']);next.lock();
},20000);
it('never sends secrets to a lookalike tab and stops cancelled work before page navigation',async()=>{
  const s=await system();await s.operator.select(s.job);
  await expect(s.operator.prepare(0,{id:7,url:'https://example.test.evil.test/change'})).rejects.toThrow('approved exact HTTPS');
  expect(s.browser.tabs.sendMessage).not.toHaveBeenCalled();s.job={...s.job,status:'cancelled'};
  await expect(s.operator.open(0)).rejects.toThrow('action stopped');expect(s.browser.runtime.sendMessage).not.toHaveBeenCalled();
  expect(s.session.entries[0].password).toBe(native.entry.password);expect(s.session.entries[0].pending_change).toBeDefined();s.session.lock();
},20000);
