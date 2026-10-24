import {discoveryRequest} from './discovery-client';

const KEY='discoverySites';
function site(url){const value=new URL(url);if(value.protocol!=='https:'||value.username||value.password||value.port)throw new Error('A default-port HTTPS website is required.');return {origin:value.origin,domain:value.hostname};}

export function createAccessDiscovery(browser,{request=discoveryRequest,clock=()=>Date.now()}={}){
  const sent=new Map();let serial=Promise.resolve();
  function change(task){const result=serial.catch(()=>{}).then(task);serial=result;return result;}
  async function state(){const saved=await browser.storage.local.get(['discoveryConnection',KEY]);return {connection:saved.discoveryConnection,sites:Array.isArray(saved[KEY])?saved[KEY]:[]};}
  async function message(message,sender){
    if(sender.id!==browser.runtime.id)throw new Error('Companion request required.');
    const popup=sender.url===browser.runtime.getURL('popup.html');
    if(popup)return change(async()=>{
      const {connection,sites}=await state();
      if(message.type==='discovery-status')return {ok:true,connection:!!connection,sites,context:connection?await request(connection,'context'):null};
      if(!connection)throw new Error('Connect account discovery first.');
      if(message.type==='discovery-disconnect'){
        try{await request(connection,'revoke',{});}finally{await browser.storage.local.remove('discoveryConnection');await browser.storage.local.set({[KEY]:[]});sent.clear();}
        return {ok:true};
      }
      if(message.type==='discovery-disable'){
        const chosen=sites.find(item=>item.id===message.id);if(!chosen)throw new Error('Enabled site not found.');
        await browser.storage.local.set({[KEY]:sites.filter(item=>item.id!==message.id)});sent.clear();
        await request(connection,'consents/'+chosen.id+'/disable',{});return {ok:true};
      }
      if(message.type!=='discovery-enable')throw new Error('Unsupported discovery action.');
      const tabs=await browser.tabs.query({active:true,currentWindow:true}),current=site(tabs[0]?.url);
      if(current.origin!==message.origin)throw new Error('The active website changed.');
      if(!await browser.permissions.contains({origins:[current.origin+'/*']}))throw new Error('Allow this exact website before enabling discovery.');
      const consent=await request(connection,'consents',{client_id:message.client,domain:current.domain,account_label:message.label});
      if(consent.domain!==current.domain||consent.client_id!==message.client||!/^[a-f0-9]{24}$/.test(consent.id))throw new Error('Unexpected discovery consent.');
      await browser.storage.local.set({[KEY]:[...sites.filter(item=>item.domain!==current.domain),{id:consent.id,domain:current.domain,origin:current.origin,client_id:message.client,account_label:consent.account_label}]});
      sent.clear();return {ok:true};
    });
    if(message.type!=='discovery-observe'||Object.keys(message).length!==1||sender.frameId!==0||!sender.tab)throw new Error('Top-level login activity required.');
    return change(async()=>{
      const current=site(sender.url),{connection,sites}=await state(),consent=sites.find(item=>item.origin===current.origin&&item.domain===current.domain);
      if(!connection||!consent)return {ok:true,recorded:false};
      if(!await browser.permissions.contains({origins:[current.origin+'/*']}))return {ok:true,recorded:false};
      const tab=await browser.tabs.get(sender.tab.id);
      if(site(tab.url).origin!==current.origin||tab.windowId!==sender.tab.windowId)throw new Error('The website changed.');
      const key=sender.tab.id+':'+consent.id,last=sent.get(key);
      if(last!==undefined&&clock()-last<60000)return {ok:true,recorded:false};
      await request(connection,'observe',{consent_id:consent.id});sent.set(key,clock());
      if(sent.size>200)sent.delete(sent.keys().next().value);
      return {ok:true,recorded:true};
    });
  }
  function install(){
    browser.runtime.onMessage.addListener((m,s,reply)=>{if(!m?.type?.startsWith('discovery-'))return;message(m,s).then(reply,error=>reply({ok:false,error:error.message}));return true;});
    browser.permissions.onRemoved.addListener(()=>{change(async()=>{await browser.storage.local.set({[KEY]:[]});sent.clear();}).catch(()=>{});});
  }
  return {message,install};
}
