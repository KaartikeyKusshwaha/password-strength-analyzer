import {afterEach,beforeEach,expect,it,vi} from 'vitest';
import {createLoginOffers} from '../../companion/extension/login-offers';
let browser,saved,handlers,save,manager,now,allowed;
const origin='https://fixture.example.test';
const popup={id:'fixture',url:'chrome-extension://fixture/popup.html'};
const sender={id:'fixture',url:origin+'/login',frameId:0,tab:{id:1,windowId:7}};
const entry={origin,username:'public-demo-user',password:'public-fixture-password'};
beforeEach(()=>{
  vi.useFakeTimers();saved={};handlers={};now=1000;allowed=true;save=vi.fn(async()=>{});
  browser={runtime:{id:'fixture',getURL:path=>'chrome-extension://fixture/'+path,onMessage:{addListener:fn=>handlers.message=fn}},storage:{local:{get:async()=>structuredClone(saved),set:async value=>Object.assign(saved,structuredClone(value))}},permissions:{contains:async()=>allowed,onRemoved:{addListener:fn=>handlers.permission=fn}},tabs:{get:async()=>({id:1,windowId:7,url:origin+'/account'}),query:async()=>[{id:1,windowId:7,url:origin+'/login'}],sendMessage:async()=>{},onRemoved:{addListener:fn=>handlers.removed=fn},onUpdated:{addListener:fn=>handlers.updated=fn}}};
  manager=createLoginOffers(browser,{save,clock:()=>now});manager.install();
});
afterEach(()=>{vi.clearAllTimers();vi.useRealTimers();});
const send=(type,extra={},who=sender)=>manager.message({type,...extra},who);
const enable=()=>send('login-offer-enable',{origin},popup);
it('is off by default and never stores or returns a draft password',async()=>{
  expect(await send('login-offer-submit',{entry})).toMatchObject({available:false,enabled:false});
  await enable();await send('login-offer-submit',{entry});
  const offer=await send('login-offer-check');expect(offer).toMatchObject({available:true,enabled:true});
  expect(JSON.stringify(offer)+JSON.stringify(saved)).not.toContain(entry.password);
  expect(saved).toEqual({loginSaveSites:[origin]});
  await send('login-offer-save',{id:offer.id});expect(save).toHaveBeenCalledWith(entry,sender,181000);
  await send('login-offer-save',{id:offer.id});expect(save).toHaveBeenCalledTimes(1);
});
it('requires a popup opt-in and rejects frames, other tabs and cross-origin entries',async()=>{
  await expect(send('login-offer-enable',{origin})).rejects.toThrow();
  await enable();
  await expect(send('login-offer-submit',{entry},{...sender,frameId:1})).rejects.toThrow();
  await expect(send('login-offer-submit',{entry:{...entry,origin:'https://other.test'}})).rejects.toThrow();
  await send('login-offer-submit',{entry});
  expect(await send('login-offer-check',{}, {...sender,tab:{id:2,windowId:7}})).toMatchObject({available:false});
  expect(save).not.toHaveBeenCalled();
});
it('drops expired, dismissed, disabled, permission-removed and navigated drafts',async()=>{
  await enable();await send('login-offer-submit',{entry});let offer=await send('login-offer-check');
  now+=180001;expect(await send('login-offer-save',{id:offer.id})).toMatchObject({available:false});
  await send('login-offer-submit',{entry});offer=await send('login-offer-check');
  await send('login-offer-dismiss',{id:offer.id});expect((await send('login-offer-check')).available).toBe(false);
  await send('login-offer-submit',{entry});await send('login-offer-disable',{origin},popup);
  expect((await send('login-offer-check')).available).toBe(false);
  await enable();await send('login-offer-submit',{entry});handlers.updated(1,{url:'https://other.test/'});
  expect((await send('login-offer-check')).available).toBe(false);
  await send('login-offer-submit',{entry});handlers.permission();allowed=false;
  expect((await send('login-offer-check')).available).toBe(false);expect(save).not.toHaveBeenCalled();
});
it('cannot recover drafts after worker restart or tab closure',async()=>{
  await enable();await send('login-offer-submit',{entry});
  const restarted=createLoginOffers(browser,{save,clock:()=>now});
  expect((await restarted.message({type:'login-offer-check'},sender)).available).toBe(false);
  handlers.removed(1);expect((await send('login-offer-check')).available).toBe(false);
});
