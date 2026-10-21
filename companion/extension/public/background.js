// Plaintext captures are tab-bound, in worker memory, and expire after 3 minutes.
// They are never written to extension storage or returned to a website.
const captures = new Map();
function sweep() { for(const [id,value] of captures) if(value.expires<=Date.now()) captures.delete(id); }
async function privateReceiver(value,sender) {
  if(!value?.windowReady || sender.frameId!==0)return false;
  const window=await value.windowReady;
  return sender.tab?.id===window.tabs?.[0]?.id && sender.tab?.windowId===window.id;
}
chrome.windows.onRemoved.addListener(windowId=>{
  for(const [id,value] of captures)if(value.windowId===windowId)captures.delete(id);
  if(!captures.size)chrome.action.setBadgeText({text:''});
});
chrome.runtime.onMessage.addListener((message,sender,reply)=>{
  if(sender.id!==chrome.runtime.id)return;
  sweep();
  if(message?.type==='open-login-companion' && sender.tab && sender.frameId===0){
    try{
      const page=new URL(sender.url);
      if(page.protocol!=='https:')return;
      chrome.tabs.get(sender.tab.id).then(tab=>{
        if(!tab.active || new URL(tab.url).origin!==page.origin || tab.windowId!==sender.tab.windowId)throw new Error();
        return chrome.action.openPopup({windowId:tab.windowId});
      }).then(()=>reply({ok:true})).catch(()=>reply({ok:false}));
      return true;
    }catch{reply({ok:false});return;}
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
      const origin=new URL(sender.url).origin, entry=message.entry;
      if(!origin.startsWith('https://') || origin!==entry?.origin || typeof entry.password!=='string' || !entry.password.length || entry.password.length>256 || typeof entry.username!=='string' || entry.username.length>254)throw new Error();
      for(const [id,value] of captures)if(value.tab===sender.tab.id)captures.delete(id);
      if(captures.size>=10)captures.delete(captures.keys().next().value);
      const id=crypto.randomUUID();
      captures.set(id,{origin,username:entry.username,password:entry.password,tab:sender.tab.id,expires:Date.now()+180000});
      chrome.action.setBadgeText({text:'1'});chrome.action.setBadgeBackgroundColor({color:'#28684c'});
      setTimeout(()=>{sweep();if(!captures.size)chrome.action.setBadgeText({text:''});},180000);
      reply({ok:true,id});
    }catch{reply({ok:false});}
  }
  if(message?.type==='open-private-save' && sender.tab && sender.frameId===0){
    const value=captures.get(message.id);
    if(!value || value.tab!==sender.tab.id || new URL(sender.url).origin!==value.origin){reply({ok:false});return;}
    if(value.windowReady){reply({ok:false});return;}
    value.windowReady=chrome.windows.create({url:chrome.runtime.getURL('vault-frame.html')+'#'+message.id,type:'popup',width:470,height:740,focused:true}).then(window=>{
      if(!Number.isInteger(window?.id) || !Number.isInteger(window.tabs?.[0]?.id))throw new Error('Private save window unavailable.');
      return window;
    });
    value.windowReady.then(window=>{value.windowId=window.id;reply({ok:true});}).catch(()=>{captures.delete(message.id);reply({ok:false});});
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
      captures.delete(message.id);if(!captures.size)chrome.action.setBadgeText({text:''});reply({ok:true});
    }).catch(()=>reply({ok:false}));
    return true;
  }
});
