// Boot the actual bundled worker against isolated API fixtures; no real browser.
const {readFileSync}=require('node:fs');
const {resolve}=require('node:path');
const {runInNewContext}=require('node:vm');
const {webcrypto}=require('node:crypto');
const assert=require('node:assert/strict');
const saved={},badges=[],requests=[];let clear=false;
const event=()=>({addListener:()=>{}});
const tab={id:1,windowId:7,url:'https://fixture.example.test/private?not-sent=1',active:true};
const chrome={runtime:{id:'fixture',getURL:path=>'chrome-extension://fixture/'+path,onMessage:event(),onStartup:event(),onInstalled:event()},storage:{local:{get:async()=>structuredClone(saved),set:async value=>Object.assign(saved,structuredClone(value))}},permissions:{contains:async()=>true,onRemoved:event()},tabs:{query:async()=>[tab],get:async()=>tab,onUpdated:event()},windows:{onRemoved:event()},action:{setBadgeText:async value=>badges.push(value),setBadgeBackgroundColor:async()=>{}},alarms:{onAlarm:event(),create:async()=>{},clear:async()=>{clear=true;}}};
const context={chrome,URL,AbortController,setTimeout,clearTimeout,crypto:webcrypto,fetch:async(url,options)=>{requests.push({url,options});return {status:200,headers:{get:()=>null}};}};
runInNewContext(readFileSync(resolve(__dirname,'extension/dist/background.js'),'utf8'),context);
(async()=>{
  assert.equal(context.sentinelMonitorProtocol,'sentinel-site-monitor/v1');
  const popup={id:'fixture',url:'chrome-extension://fixture/popup.html'};
  await context.sentinelMonitor.message({type:'site-monitor-enable',origin:'https://fixture.example.test'},popup);
  assert.equal(requests.length,1);assert.equal(requests[0].url,'https://fixture.example.test/');
  assert.equal(requests[0].options.method,'HEAD');assert.equal(requests[0].options.credentials,'omit');assert.equal(requests[0].options.redirect,'error');
  assert.equal(saved.siteMonitor.length,1);assert.equal(saved.siteMonitor[0].state,'issues');
  assert.ok(!JSON.stringify(saved).includes('private'));assert.ok(!JSON.stringify(saved).includes('not-sent'));
  assert.ok(badges.some(value=>value.tabId===1&&value.text==='!'));
  await context.sentinelMonitor.message({type:'site-monitor-disable',origin:'https://fixture.example.test'},popup);
  assert.equal(saved.siteMonitor.length,0);assert.ok(clear);
  process.stdout.write(JSON.stringify({bundled_worker_boot:true,exact_origin_only:true,cookie_free:true,opt_out_clears_state:true})+'\n');
})().catch(error=>{process.stderr.write(error.stack+'\n');process.exitCode=1;});
