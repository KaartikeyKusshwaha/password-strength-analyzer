import {createLoginOffers} from '../login-offers';
// Plaintext captures are tab-bound, in worker memory, and expire after 3 minutes.
// They are never written to extension storage or returned to a website.
const captures = new Map();
function releaseCapture(id){const value=captures.get(id);captures.delete(id);if(value)globalThis.sentinelMonitor?.setCapture(value.tab,false);}
function sweep() { for(const [id,value] of captures) if(value.expires<=Date.now()) releaseCapture(id); }
function captureEntry(entry,sender,deadline=Date.now()+180000){
  const origin=new URL(sender.url).origin;
  if(!sender.tab || sender.frameId!==0 || !origin.startsWith('https://') || origin!==entry?.origin || typeof entry.password!=='string' || !entry.password.length || entry.password.length>256 || typeof entry.username!=='string' || entry.username.length>254)throw new Error('Invalid save entry.');
  for(const [id,value] of captures)if(value.tab===sender.tab.id)releaseCapture(id);
  if(captures.size>=10)releaseCapture(captures.keys().next().value);
  const id=crypto.randomUUID();
  const expires=Math.min(deadline,Date.now()+180000);
  if(!Number.isFinite(expires)||expires<=Date.now())throw new Error('Save entry expired.');
  captures.set(id,{origin,username:entry.username,password:entry.password,tab:sender.tab.id,expires});
  globalThis.sentinelMonitor?.setCapture(sender.tab.id,true);
  chrome.action.setBadgeText({text:'1'});chrome.action.setBadgeBackgroundColor({color:'#28684c'});
  setTimeout(()=>{sweep();if(!captures.size)chrome.action.setBadgeText({text:''});},expires-Date.now());
  return id;
}
async function openPrivateSave(id,value){
  if(value.windowReady)throw new Error('Save window already opened.');
  value.windowReady=chrome.windows.create({url:chrome.runtime.getURL('vault-frame.html')+'#'+id,type:'popup',width:470,height:740,focused:true}).then(window=>{
    if(!Number.isInteger(window?.id) || !Number.isInteger(window.tabs?.[0]?.id))throw new Error('Private save window unavailable.');
    return window;
  });
  try{const window=await value.windowReady;value.windowId=window.id;}catch(error){releaseCapture(id);throw error;}
}
createLoginOffers(chrome,{save:async(entry,sender,expires)=>{const id=captureEntry(entry,sender,expires);await openPrivateSave(id,captures.get(id));}}).install();
async function privateReceiver(value,sender) {
  if(!value?.windowReady || sender.frameId!==0)return false;
  const window=await value.windowReady;
  return sender.tab?.id===window.tabs?.[0]?.id && sender.tab?.windowId===window.id;
}
chrome.windows.onRemoved.addListener(windowId=>{
  for(const [id,value] of captures)if(value.windowId===windowId)releaseCapture(id);
  if(!captures.size)chrome.action.setBadgeText({text:''});
});
chrome.runtime.onMessage.addListener((message,sender,reply)=>{
  if(sender.id!==chrome.runtime.id)return;
  sweep();
  if(message?.type==='open-login-companion'){
    if(!sender.tab||sender.frameId!==0){reply({ok:false,reason:'invalid_source'});return;}
    try{
      const page=new URL(sender.url);
      if(page.protocol!=='https:'||page.username||page.password){reply({ok:false,reason:'invalid_page'});return;}
      chrome.tabs.get(sender.tab.id).then(async tab=>{
        if(!tab.active)return {ok:false,reason:'inactive_tab'};
        if(tab.windowId!==sender.tab.windowId)return {ok:false,reason:'changed_tab'};
        if(!tab.url)return {ok:false,reason:'site_access'};
        try{if(new URL(tab.url).origin!==page.origin)return {ok:false,reason:'changed_tab'};}catch{return {ok:false,reason:'changed_tab'};}
        if(typeof chrome.action?.openPopup!=='function')return {ok:false,reason:'popup_api'};
        try{await chrome.action.openPopup({windowId:tab.windowId});return {ok:true};}
        catch(error){
          const message=String(error?.message||'');
          return {ok:false,reason:/focus|active window/i.test(message)?'browser_focus':/user (?:gesture|activation)/i.test(message)?'user_gesture':'popup_unavailable'};
        }
      }).then(reply,()=>reply({ok:false,reason:'tab_unavailable'}));
      return true;
    }catch{reply({ok:false,reason:'invalid_page'});return;}
  }
  if(message?.type==='open-account-change' && sender.url===chrome.runtime.getURL('popup.html')){
    try {
      const origin=new URL(message.origin);
      if(origin.protocol!=='https:' || origin.origin!==message.origin || origin.username || origin.password)throw new Error();
      chrome.tabs.create({url:origin.origin+'/.well-known/change-password',active:true}).then(()=>reply({ok:true})).catch(()=>reply({ok:false}));
      return true;
    }catch{reply({ok:false});return;}
  }
  if(message?.type==='capture'){
    if(!sender.tab || sender.frameId!==0)return;
    try {
      const id=captureEntry(message.entry,sender);
      reply({ok:true,id});
    }catch{reply({ok:false});}
  }
  if(message?.type==='open-private-save' && sender.tab && sender.frameId===0){
    const value=captures.get(message.id);
    if(!value || value.tab!==sender.tab.id || new URL(sender.url).origin!==value.origin){reply({ok:false});return;}
    openPrivateSave(message.id,value).then(()=>reply({ok:true})).catch(()=>reply({ok:false}));
    return true;
  }
  const frame=sender.tab && sender.url?.split('#')[0]===chrome.runtime.getURL('vault-frame.html');
  if(message?.type==='frame-capture' && frame){
    const value=captures.get(message.id);
    privateReceiver(value,sender).then(allowed=>{
      if(!allowed || captures.get(message.id)!==value || value.expires<=Date.now()){reply({entry:null});return;}
      chrome.tabs.sendMessage(value.tab,{type:'private-save-ready',id:message.id},{frameId:0}).catch(()=>{});
      const {origin,username,password,expires}=value;reply({entry:{origin,username,password,expires}});
    }).catch(()=>reply({entry:null}));
    return true;
  }
  if(message?.type==='capture-saved' && frame){
    const value=captures.get(message.id);
    privateReceiver(value,sender).then(allowed=>{
      if(!allowed){reply({ok:false});return;}
      releaseCapture(message.id);if(!captures.size)chrome.action.setBadgeText({text:''});reply({ok:true});
    }).catch(()=>reply({ok:false}));
    return true;
  }
});
