import {isLoginFocusField} from './login-form';
import {inspectOtp} from './otp-form';

// This invitation contains no credential metadata. Unlock remains extension-owned.
export function offerLogin(document,pageUrl,field,browser,{isTop=true,kind='login'}={}) {
  const origin=new URL(pageUrl).origin;
  const supported=()=>kind==='otp'?inspectOtp(document,pageUrl,origin).ok:isLoginFocusField(document,pageUrl,field);
  if(!isTop || !supported())return null;
  const host=document.createElement('div');
  host.style.cssText='position:fixed;right:18px;bottom:18px;z-index:2147483647';
  const shadow=host.attachShadow({mode:'closed'}),panel=document.createElement('section');
  const style=document.createElement('style');
  style.textContent='section{font:14px/1.5 system-ui;background:#f6f8f1;color:#25392d;border:1px solid #c8d9be;border-radius:12px;padding:18px;width:300px;max-width:calc(100vw - 48px);box-shadow:0 10px 35px #10291c40}button{font:inherit;border:1px solid #b9ceb6;border-radius:6px;padding:8px;margin:5px;background:#28684c;color:white}small{display:block;overflow-wrap:anywhere}';
  panel.setAttribute('role','dialog');panel.setAttribute('aria-label','SentinelOps login assistant');
  const title=document.createElement('strong');title.textContent=kind==='otp'?'Use your SentinelOps authenticator':'Sign in with SentinelOps';
  const site=document.createElement('small');site.textContent=origin;
  const text=document.createElement('p');text.textContent=kind==='otp'?'Unlock your vault in the companion and choose an authenticator explicitly linked to this website.':'Unlock your vault in the companion to choose a matching login. Nothing is filled until you choose it.';
  const open=document.createElement('button');open.textContent=kind==='otp'?'Choose authenticator':'Choose saved login';
  const dismiss=document.createElement('button');dismiss.textContent='Dismiss';
  dismiss.onclick=event=>{if(event.isTrusted)host.remove();};
  open.onclick=async event=>{
    if(!event.isTrusted || !field.isConnected || !supported())return;
    open.disabled=true;
    try{
      const result=await browser.runtime.sendMessage({type:'open-login-companion'});
      if(!result?.ok){
        const messages={inactive_tab:'This website is in a background tab. Select its tab, then try again.',changed_tab:'The tab or website changed. Refresh this website before trying again.',site_access:'The browser has not exposed this tab to SentinelOps. Open the toolbar icon on this website once, then retry.',popup_api:'This browser does not expose automatic popup opening. Use the SentinelOps toolbar icon.',browser_focus:'The browser window is not focused. Bring it to the front, then try again or use the toolbar icon.',user_gesture:'This browser requires its toolbar click to open the companion. Click the SentinelOps toolbar icon.',tab_unavailable:'This tab is no longer available. Reopen the website and use the toolbar icon.',invalid_source:'Open SentinelOps from the top-level website or its toolbar icon.',invalid_page:'This invitation requires an exact HTTPS website.'};
        text.textContent=messages[result?.reason]||'The browser could not open the companion automatically. Use the SentinelOps toolbar icon. No login was filled.';return;
      }
      text.textContent='Choose and unlock your vault in the SentinelOps popup.';
    }
    catch{text.textContent='Open the SentinelOps toolbar icon to choose your login. The popup could not be opened.';}
    finally{open.disabled=false;}
  };
  panel.append(title,site,text,open,dismiss);shadow.append(style,panel);document.documentElement.append(host);
  return host;
}
