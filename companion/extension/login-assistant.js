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
  const text=document.createElement('p');text.textContent=kind==='otp'?'Open the SentinelOps toolbar icon, unlock your vault and choose an authenticator explicitly linked to this website.':'Open the SentinelOps toolbar icon, unlock your vault and choose a matching login. Nothing is filled until you choose it.';
  const dismiss=document.createElement('button');dismiss.textContent='Dismiss';
  dismiss.onclick=event=>{if(event.isTrusted)host.remove();};
  panel.append(title,site,text,dismiss);shadow.append(style,panel);document.documentElement.append(host);
  return host;
}
