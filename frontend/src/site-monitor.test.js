import {expect,it,vi} from 'vitest';
import {createSiteMonitor} from '../../companion/extension/site-monitor';
import {checkWebsite} from '../../companion/extension/site-check';
function fixture(){
  const saved={},tabs=[{id:1,windowId:7,url:'https://example.test/private?secret=redacted',active:true}];let allowed=true,now=1000;
  const browser={runtime:{id:'fixture',getURL:path=>'chrome-extension://fixture/'+path,onMessage:{addListener:vi.fn()},onStartup:{addListener:vi.fn()},onInstalled:{addListener:vi.fn()}},permissions:{contains:vi.fn(async()=>allowed),onRemoved:{addListener:vi.fn()}},storage:{local:{get:vi.fn(async()=>structuredClone(saved)),set:vi.fn(async value=>Object.assign(saved,structuredClone(value)))}},tabs:{query:vi.fn(async()=>tabs),get:vi.fn(async()=>tabs[0]),onUpdated:{addListener:vi.fn()}},action:{setBadgeText:vi.fn(async()=>{}),setBadgeBackgroundColor:vi.fn(async()=>{})},alarms:{create:vi.fn(async()=>{}),clear:vi.fn(async()=>{}),onAlarm:{addListener:vi.fn()}}};
  const checker=vi.fn(async scope=>({origin:scope.origin,actions:[{id:'csp',title:'Review header policy',detail:'Header missing.'}],coverage:'Header presence only'}));
  const monitor=createSiteMonitor(browser,{checker,clock:()=>now});
  const popup={id:'fixture',url:'chrome-extension://fixture/popup.html'},content={id:'fixture',frameId:0,url:tabs[0].url,tab:{id:1,windowId:7}};
  return {browser,monitor,checker,saved,tabs,popup,content,enable:()=>monitor.message({type:'site-monitor-enable',origin:'https://example.test'},popup),allow:value=>allowed=value,advance:ms=>now+=ms};
}
it('sends nothing without opt-in and never stores visited paths or query strings',async()=>{
  const f=fixture();await f.monitor.message({type:'site-monitor-visit'},f.content);expect(f.checker).not.toHaveBeenCalled();
  await f.enable();expect(f.checker).toHaveBeenCalledWith({origin:'https://example.test',https:true,permission:'https://example.test/*'});
  expect(JSON.stringify(f.saved)).not.toContain('private');expect(JSON.stringify(f.saved)).not.toContain('secret=');
  expect(f.browser.action.setBadgeText).toHaveBeenCalledWith({tabId:1,text:'!'});
  await f.monitor.message({type:'site-monitor-visit'},f.content);expect(f.checker).toHaveBeenCalledTimes(1);
  f.advance(12*60*60*1000);await f.monitor.scheduled();expect(f.checker).toHaveBeenCalledTimes(2);
});
it('rejects page-side enable attempts and missing origin permission',async()=>{
  const f=fixture();await expect(f.monitor.message({type:'site-monitor-enable',origin:'https://example.test'},f.content)).rejects.toThrow('controls');
  f.allow(false);await expect(f.enable()).rejects.toThrow('permission');expect(f.checker).not.toHaveBeenCalled();
  expect(await f.monitor.message({type:'site-monitor-visit'},{...f.content,frameId:1})).toEqual({ok:false});
});
it('does not restore an opt-in disabled during an in-flight check',async()=>{
  const f=fixture();let finish;f.checker.mockImplementation(()=>new Promise(resolve=>finish=resolve));
  const running=f.enable();await vi.waitFor(()=>expect(finish).toBeTypeOf('function'));
  await f.monitor.message({type:'site-monitor-disable',origin:'https://example.test'},f.popup);
  finish({origin:'https://example.test',actions:[]});await running;
  expect(f.saved.siteMonitor).toEqual([]);expect(f.browser.alarms.clear).toHaveBeenCalled();
});
it('fails unknown, checks permission on recheck and does not label a different tab origin',async()=>{
  const f=fixture();f.checker.mockRejectedValue(new Error('unavailable'));await f.enable();
  expect(f.saved.siteMonitor[0].state).toBe('unassessed');expect(f.browser.action.setBadgeText).toHaveBeenLastCalledWith({tabId:1,text:'?'});
  f.allow(false);f.advance(16*60*1000);await f.monitor.check('https://example.test');expect(f.saved.siteMonitor).toEqual([]);expect(f.checker).toHaveBeenCalledTimes(1);
  f.allow(true);f.tabs[0].url='https://elsewhere.test/';await expect(f.enable()).rejects.toThrow('active site');
});
it('keeps a blocked or unavailable website unknown instead of clearing its badge',async()=>{
  const f=fixture();
  f.checker.mockImplementation(scope=>checkWebsite(scope,async()=>new Response(null,{status:503,headers:{'strict-transport-security':'max-age=31536000','content-security-policy':"default-src 'self'",'x-content-type-options':'nosniff'}})));
  await f.enable();
  expect(f.saved.siteMonitor[0]).toMatchObject({state:'unassessed',result:null});
  expect(f.browser.action.setBadgeText).toHaveBeenLastCalledWith({tabId:1,text:'?'});
});
it('keeps pending secure-save badges ahead of monitoring warnings',async()=>{
  const f=fixture();await f.enable();f.monitor.setCapture(1,true);
  await vi.waitFor(()=>expect(f.browser.action.setBadgeText).toHaveBeenLastCalledWith({tabId:1,text:'1'}));
  f.monitor.setCapture(1,false);await vi.waitFor(()=>expect(f.browser.action.setBadgeText).toHaveBeenLastCalledWith({tabId:1,text:'!'}));
});
it('prunes removed permission immediately and lets explicit rechecks update cached badges',async()=>{
  const f=fixture();f.monitor.install();await f.enable();
  f.checker.mockResolvedValue({origin:'https://example.test',actions:[],coverage:'Header presence only'});
  await f.monitor.message({type:'site-monitor-recheck',origin:'https://example.test'},f.popup);
  expect(f.checker).toHaveBeenCalledTimes(2);expect(f.saved.siteMonitor[0].state).toBe('clear');
  expect(f.browser.action.setBadgeText).toHaveBeenLastCalledWith({tabId:1,text:''});
  f.allow(false);f.browser.permissions.onRemoved.addListener.mock.calls[0][0]();
  await vi.waitFor(()=>expect(f.saved.siteMonitor).toEqual([]));expect(f.checker).toHaveBeenCalledTimes(2);
});
it('rechecks every due chosen site with at most five parallel requests',async()=>{
  const f=fixture();f.saved.siteMonitor=Array.from({length:8},(_,index)=>({origin:`https://h${index}.example.test`,generation:String(index),at:0,state:'unassessed',result:null}));
  let active=0,peak=0;
  f.checker.mockImplementation(async scope=>{active++;peak=Math.max(peak,active);await new Promise(resolve=>setTimeout(resolve,5));active--;return {origin:scope.origin,actions:[]};});
  await f.monitor.scheduled();expect(f.checker).toHaveBeenCalledTimes(8);expect(peak).toBeLessThanOrEqual(5);expect(peak).toBeGreaterThan(1);
  expect(f.saved.siteMonitor.every(site=>site.state==='clear')).toBe(true);
});
