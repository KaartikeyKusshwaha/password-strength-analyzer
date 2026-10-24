// Opt-in login-attempt drafts live only in this worker, never in storage.
const KEY='loginSaveSites',TTL=180000;
export function createLoginOffers(browser,{save,clock=()=>Date.now()}={}){
  const drafts=new Map();let changes=Promise.resolve();
  const serial=fn=>{const result=changes.catch(()=>{}).then(fn);changes=result;return result;};
  const originOf=url=>{const u=new URL(url);if(u.protocol!=='https:'||u.username||u.password)throw new Error('HTTPS site required.');return u.origin;};
  async function sites(){const data=await browser.storage.local.get(KEY);return [...new Set((Array.isArray(data[KEY])?data[KEY]:[]).filter(value=>{try{return originOf(value)===value;}catch{return false;}}))].slice(0,50);}
  function sweep(){for(const [tab,draft] of drafts)if(draft.expires<=clock())drafts.delete(tab);}
  async function page(sender){if(sender.id!==browser.runtime.id||sender.frameId!==0||!sender.tab)throw new Error('Top-level companion page required.');const origin=originOf(sender.url),tab=await browser.tabs.get(sender.tab.id);if(originOf(tab.url)!==origin||tab.windowId!==sender.tab.windowId)throw new Error('The active site changed.');return origin;}
  async function message(message,sender){
    sweep();
    if(sender.id!==browser.runtime.id)throw new Error('Companion request required.');
    if(sender.url===browser.runtime.getURL('popup.html')){
      if(message.type==='login-offer-status')return {ok:true,sites:await sites()};
      if(!['login-offer-enable','login-offer-disable'].includes(message.type))throw new Error('Unsupported request.');
      const origin=originOf(message.origin);if(origin!==message.origin)throw new Error('Exact origin required.');
      return serial(async()=>{
        const existing=await sites();
        if(message.type==='login-offer-enable'){
          const tabs=await browser.tabs.query({active:true,currentWindow:true});
          if(originOf(tabs[0]?.url)!==origin||!await browser.permissions.contains({origins:[origin+'/*']}))throw new Error('The site changed or permission was declined.');
          if(!existing.includes(origin)){if(existing.length>=50)throw new Error('Up to 50 chosen sites are supported.');existing.push(origin);}
        }else{for(const [tab,draft] of drafts)if(draft.origin===origin)drafts.delete(tab);}
        const next=message.type==='login-offer-enable'?existing:existing.filter(site=>site!==origin);
        await browser.storage.local.set({[KEY]:next});
        for(const tab of await browser.tabs.query({})){try{if(originOf(tab.url)===origin)browser.tabs.sendMessage?.(tab.id,{type:'login-offer-permission',enabled:next.includes(origin)},{frameId:0}).catch(()=>{});}catch{}}
        return {ok:true,sites:next};
      });
    }
    if(!['login-offer-submit','login-offer-check','login-offer-save','login-offer-dismiss'].includes(message.type))throw new Error('Open save-offer controls in the companion.');
    const origin=await page(sender),tab=sender.tab.id;
    return serial(async()=>{
    if(!await browser.permissions.contains({origins:[origin+'/*']})||!(await sites()).includes(origin)){drafts.delete(tab);return {ok:true,enabled:false,available:false};}
    if(message.type==='login-offer-submit'){
      const entry=message.entry;
      if(entry?.origin!==origin||typeof entry.username!=='string'||!entry.username||entry.username.length>254||typeof entry.password!=='string'||!entry.password||entry.password.length>256)throw new Error('A bounded login entry is required.');
      if(drafts.size>=10&&!drafts.has(tab))drafts.delete(drafts.keys().next().value);
      const id=crypto.randomUUID();drafts.set(tab,{origin,username:entry.username,password:entry.password,id,expires:clock()+TTL});
      setTimeout(()=>{if(drafts.get(tab)?.id===id)drafts.delete(tab);},TTL);
      return {ok:true};
    }
    const draft=drafts.get(tab);
    if(!draft||draft.origin!==origin)return {ok:true,enabled:true,available:false};
    if(message.type==='login-offer-check')return {ok:true,enabled:true,available:true,id:draft.id};
    if(message.id!==draft.id)return {ok:false};
    if(message.type==='login-offer-dismiss'){drafts.delete(tab);return {ok:true};}
    if(message.type==='login-offer-save'){
      // Clear before opening; replaying a click cannot create another window.
      drafts.delete(tab);await save({origin:draft.origin,username:draft.username,password:draft.password},sender,draft.expires);return {ok:true};
    }
    throw new Error('Unsupported login offer.');
    });
  }
  function install(){
    browser.runtime.onMessage.addListener((m,s,reply)=>{if(!m?.type?.startsWith('login-offer-'))return;message(m,s).then(reply,()=>reply({ok:false,error:'The login offer expired or is unavailable. Submit again after enabling save offers.'}));return true;});
    browser.tabs.onRemoved?.addListener(id=>drafts.delete(id));
    browser.tabs.onUpdated.addListener((id,change)=>{if(!change.url)return;try{if(drafts.get(id)?.origin!==originOf(change.url))drafts.delete(id);}catch{drafts.delete(id);}});
    browser.permissions.onRemoved.addListener(()=>{drafts.clear();});
  }
  return {message,install};
}
