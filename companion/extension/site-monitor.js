import {websiteScope,checkWebsite} from './site-check';
const KEY='siteMonitor',ALARM='sentinelops-site-monitor',MAX=50;
const INTERVAL=12*60*60*1000,RETRY=15*60*1000;
export function createSiteMonitor(browser,{checker=checkWebsite,clock=()=>Date.now()}={}){
  let changes=Promise.resolve();const inflight=new Map(),captures=new Set();
  const serial=fn=>{const next=changes.catch(()=>{}).then(fn);changes=next;return next;};
  async function read(){const saved=await browser.storage.local.get(KEY);return Array.isArray(saved[KEY])?saved[KEY].slice(0,MAX).filter(site=>{try{return websiteScope(site.origin).https&&websiteScope(site.origin).origin===site.origin;}catch{return false;}}):[];}
  const write=sites=>browser.storage.local.set({[KEY]:sites});
  const permission=origin=>browser.permissions.contains({origins:[origin+'/*']});
  async function badges(origin,site){
    const tabs=await browser.tabs.query({});
    await Promise.all(tabs.map(async tab=>{try{
      if(new URL(tab.url).origin!==origin)return;
      const text=captures.has(tab.id)?'1':site?.state==='issues'?'!':site?.state==='unassessed'?'?':'';
      await browser.action.setBadgeText({tabId:tab.id,text});
      if(text)await browser.action.setBadgeBackgroundColor({tabId:tab.id,color:captures.has(tab.id)?'#28684c':'#a86b22'});
    }catch{/* Closed or inaccessible tab. */}}));
  }
  async function alarm(){const sites=await serial(read);if(sites.length)await browser.alarms.create(ALARM,{periodInMinutes:30});else await browser.alarms.clear(ALARM);}
  async function check(origin,force=false){
    if(inflight.has(origin))return inflight.get(origin);
    const task=(async()=>{
      const site=await serial(async()=>{
        const sites=await read(),site=sites.find(item=>item.origin===origin);
        if(!site)return null;
        if(!await permission(origin)){await write(sites.filter(item=>item.origin!==origin));return null;}
        if(!force&&site.at&&clock()-site.at<(site.state==='unassessed'?RETRY:INTERVAL))return {...site,cached:true};
        site.at=clock();site.state='unassessed';site.result=null;await write(sites);return {...site};
      });
      if(!site){await badges(origin,null);return null;}
      if(site.cached){await badges(origin,site);return site;}
      let result=null;
      try{result=await checker(websiteScope(origin));}catch{/* Failed requests never produce an all-clear. */}
      const updated=await serial(async()=>{
        const sites=await read(),current=sites.find(item=>item.origin===origin);
        if(!current||current.generation!==site.generation)return null;
        if(!await permission(origin)){await write(sites.filter(item=>item.origin!==origin));return null;}
        current.result=result;current.at=clock();current.state=result?(result.actions.length?'issues':'clear'):'unassessed';await write(sites);return current;
      });
      await badges(origin,updated);return updated;
    })().finally(()=>inflight.delete(origin));
    inflight.set(origin,task);return task;
  }
  async function message(message,sender){
    if(sender.id!==browser.runtime.id)throw new Error('Companion request required.');
    if(message.type==='site-monitor-visit'){
      if(sender.frameId!==0||!sender.tab)return {ok:false};
      const scope=websiteScope(sender.url),tab=await browser.tabs.get(sender.tab.id);
      if(!scope.https||new URL(tab.url).origin!==scope.origin||tab.windowId!==sender.tab.windowId)return {ok:false};
      await check(scope.origin);return {ok:true};
    }
    if(sender.url!==browser.runtime.getURL('popup.html'))throw new Error('Open monitoring controls in the companion.');
    if(message.type==='site-monitor-status')return {ok:true,sites:await serial(read)};
    const scope=websiteScope(message.origin);if(!scope.https)throw new Error('Quiet checks require HTTPS.');
    if(['site-monitor-enable','site-monitor-recheck'].includes(message.type)){
      const tabs=await browser.tabs.query({active:true,currentWindow:true});
      if(new URL(tabs[0]?.url).origin!==scope.origin||!await permission(scope.origin))throw new Error('The active site changed or permission was declined.');
      if(message.type==='site-monitor-recheck'){await check(scope.origin,true);return {ok:true,sites:await serial(read)};}
      await serial(async()=>{const sites=await read();if(!sites.some(site=>site.origin===scope.origin)){if(sites.length>=MAX)throw new Error('Quiet checks support up to 50 explicitly chosen sites.');sites.push({origin:scope.origin,generation:crypto.randomUUID(),at:0,state:'unassessed',result:null});await write(sites);}});
      await alarm();await check(scope.origin);return {ok:true,sites:await serial(read)};
    }
    if(message.type==='site-monitor-disable'){
      await serial(async()=>write((await read()).filter(site=>site.origin!==scope.origin)));await badges(scope.origin,null);await alarm();return {ok:true,sites:await serial(read)};
    }
    throw new Error('Unsupported monitoring request.');
  }
  async function scheduled(){
    const sites=await serial(read);
    const due=sites.filter(site=>!site.at||clock()-site.at>=(site.state==='unassessed'?RETRY:INTERVAL)).sort((a,b)=>a.at-b.at);
    for(let offset=0;offset<due.length;offset+=5)await Promise.all(due.slice(offset,offset+5).map(site=>check(site.origin)));
    await alarm();
  }
  async function prune(){
    const removed=await serial(async()=>{const sites=await read(),keep=[],removed=[];for(const site of sites)(await permission(site.origin)?keep:removed).push(site);await write(keep);return removed;});
    for(const site of removed)await badges(site.origin,null);
    await alarm();
  }
  function install(){
    browser.runtime.onMessage.addListener((value,sender,reply)=>{
      if(!value?.type?.startsWith('site-monitor-'))return;
      message(value,sender).then(reply,error=>reply({ok:false,error:error.message}));return true;
    });
    browser.alarms.onAlarm.addListener(value=>{if(value.name===ALARM)scheduled().catch(()=>{});});
    browser.runtime.onStartup.addListener(()=>alarm().catch(()=>{}));
    browser.runtime.onInstalled.addListener(()=>alarm().catch(()=>{}));
    browser.tabs.onUpdated.addListener((tabId,change)=>{if(change.status==='loading')browser.action.setBadgeText({tabId,text:''}).catch(()=>{});});
    browser.permissions.onRemoved.addListener(()=>prune().catch(()=>{}));
  }
  return {install,message,scheduled,check,setCapture(tabId,value){value?captures.add(tabId):captures.delete(tabId);browser.tabs.get(tabId).then(async tab=>{const origin=new URL(tab.url).origin;const site=(await serial(read)).find(item=>item.origin===origin);await badges(origin,site);}).catch(()=>{});}};
}
