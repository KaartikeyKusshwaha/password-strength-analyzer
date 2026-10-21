import { ZxcvbnFactory } from '@zxcvbn-ts/core';
import * as common from '@zxcvbn-ts/language-common';
import * as en from '@zxcvbn-ts/language-en';
import { generatePassword } from '../../frontend/src/lab';
import { isNewPassword, formOriginAllowed, setPasswordFields } from './form-policy';
import {preparePasswordChange} from './change-form';
import {watchPrivateFrame} from './frame-status';
import {fillLoginForm,inspectLoginForm} from './login-form';
import manifest from './public/manifest.json';
import {offerLogin} from './login-assistant';

const estimator = new ZxcvbnFactory({ translations: en.translations, graphs: common.adjacencyGraphs, dictionary: {...common.dictionary, ...en.dictionary} });
const labels = ['Very guessable','Guessable','Somewhat guessable','Less guessable','Harder to guess'];
let panel = null, current = null, renderEstimate = null, stopFrameWatch = null;
const attached = new WeakSet();
const style = `:host{all:initial}*{box-sizing:border-box}section{font:14px/1.6 system-ui;color:#25392d;background:#f6f8f1;border:1px solid #c8d9be;border-radius:14px;box-shadow:0 15px 55px #10291c40;padding:22px;width:365px;max-width:calc(100vw - 24px)}header{display:flex;justify-content:space-between;align-items:center;margin-bottom:10px}h2{font-size:20px;line-height:1.3;margin:8px 0}p{margin:10px 0}small{display:block;font-size:11px;color:#5b6c58}button{font:13px system-ui;cursor:pointer;border:1px solid #b9ceb6;border-radius:6px;padding:9px 12px;background:#fff;color:#23543c;margin:4px 6px 4px 0}button.primary{background:#28684c;color:white}button:disabled{opacity:.5;cursor:wait}meter{width:100%;height:9px}iframe{display:block;border:0;width:100%;height:470px;background:#f6f8f1;border-radius:8px}a{color:#28684c}`;
function close() { stopFrameWatch?.();stopFrameWatch=null;panel?.remove(); panel=null; current=null; renderEstimate=null; }
function assistant(field) {
  if (current === field && panel?.isConnected) return;
  close(); current=field;
  const host=document.createElement('div');
  host.style.cssText='position:fixed;right:18px;bottom:18px;z-index:2147483647;max-height:calc(100vh - 36px);overflow:auto';
  const shadow=host.attachShadow({mode:'closed'}), css=document.createElement('style');css.textContent=style;
  const section=document.createElement('section');section.setAttribute('role','dialog');section.setAttribute('aria-label','SentinelOps password assistant');
  const header=document.createElement('header'),brand=document.createElement('strong');brand.textContent='SentinelOps · password assistant';
  const dismiss=document.createElement('button');dismiss.textContent='×';dismiss.setAttribute('aria-label','Close password assistant');dismiss.onclick=event=>{if(event.isTrusted)close();};header.append(brand,dismiss);
  const title=document.createElement('h2');title.textContent='A stronger password, right here.';
  const origin=document.createElement('small');origin.textContent=location.origin+' · Companion '+manifest.version;
  const estimate=document.createElement('p'),meter=document.createElement('meter');meter.min=0;meter.max=4;
  const help=document.createElement('small');
  const generate=document.createElement('button');generate.className='primary';generate.textContent='Use a strong password';
  const save=document.createElement('button');save.textContent='Save securely';
  const status=document.createElement('p');status.setAttribute('role','status');
  const fine=document.createElement('small');fine.textContent='Strength checks and generation run locally. Saving encrypts your login to your connected vault. Nothing is sent to AI. Website forms are never submitted automatically.';
  renderEstimate=()=>{const value=field.value;save.disabled=!value;const result=value && value.length<=128?estimator.check(value):null;estimate.textContent=result?labels[result.score]+' · local estimate':value?'Too long to assess (128 characters max)':'Create a unique password for this account.';meter.value=result?.score||0;help.textContent=result?.feedback?.warning||'';};
  generate.onclick=event=>{if(!event.isTrusted || !field.isConnected || !isNewPassword(field) || !formOriginAllowed(location.href,field.form?.action))return;setPasswordFields(field,generatePassword());renderEstimate();status.textContent='Filled the password and matching confirmation field. Review the website before continuing.';};
  save.onclick=async event=>{
    if(!event.isTrusted || !field.isConnected || !field.value)return;
    if(!formOriginAllowed(location.href,field.form?.action)){status.textContent='Cross-origin form destinations are not supported.';return;}
    const username=field.form?.querySelector('input[autocomplete="username"],input[type="email"],input[name="username"],input[name="email"]')?.value||'';
    save.disabled=true;
    try {
      const result=await chrome.runtime.sendMessage({type:'capture',entry:{origin:location.origin,username,password:field.value}});
      if(!result?.ok)throw new Error('Could not prepare the private save. Reload the browser companion and try again.');
      stopFrameWatch=watchPrivateFrame(chrome,result.id,()=>{
        status.textContent='The private save window did not start. No login was saved. Reload SentinelOps in your browser extensions, refresh this website, and choose Save again.';
      });
      const opened=await chrome.runtime.sendMessage({type:'open-private-save',id:result.id});
      if(!opened?.ok){stopFrameWatch?.();throw new Error('Could not open the private save window. No login was saved. Try again from the website.');}
      for(const element of [title,estimate,meter,help,generate,save,fine])element.remove();
      status.textContent='Finish saving in the SentinelOps extension window. Unlock there, review the website and username, then confirm encrypted saving. Nothing has been saved yet.';
      renderEstimate=null;
    }catch(e){status.textContent=e.message;save.disabled=false;}
  };
  section.append(header,origin,title,estimate,meter,help,generate,save,status,fine);shadow.append(css,section);document.documentElement.append(host);panel=host;renderEstimate();
}
function attach(field) {
  if(attached.has(field))return;
  attached.add(field);
  field.addEventListener('focus',event=>{
    if(!event.isTrusted || window.top!==window || !field.getClientRects().length || !formOriginAllowed(location.href,field.form?.action))return;
    if(isNewPassword(field))assistant(field);
    else {close();current=field;panel=offerLogin(document,location.href,field,chrome);}
  });
  let timer;
  field.addEventListener('input',()=>{if(current!==field || !renderEstimate)return;clearTimeout(timer);timer=setTimeout(()=>renderEstimate?.(),150);});
}
function inspect(){document.querySelectorAll('input[type="password"]').forEach(attach);if(current && (!current.isConnected || !formOriginAllowed(location.href,current.form?.action) || (renderEstimate && !isNewPassword(current))))close();}
inspect();let scanTimer;
new MutationObserver(()=>{clearTimeout(scanTimer);scanTimer=setTimeout(inspect,250);}).observe(document.documentElement,{subtree:true,childList:true,attributes:true,attributeFilter:['type','name','id','autocomplete','disabled','readonly','hidden','action']});
document.addEventListener('keydown',event=>{if(event.isTrusted && event.key==='Escape')close();});
chrome.runtime.onMessage.addListener((message,sender,reply)=>{
  if(sender.id===chrome.runtime.id && message?.type==='inspect-login'){
    reply({...((window.top===window)?inspectLoginForm(document,location.href,message.origin):{ok:false,reason:'frame'}),version:manifest.version});return;
  }
  if(sender.id===chrome.runtime.id && message?.type==='prepare-password-change'){
    if(window.top!==window){reply({ok:false,reason:'cross_origin'});return;}
    reply(preparePasswordChange(document,location.href,message));return;
  }
  if(sender.id!==chrome.runtime.id || message?.type!=='fill-login')return;
  if(window.top!==window){reply({ok:false});return;}
  fillLoginForm(document,location.href,message.entry).then(reply,()=>reply({ok:false,reason:'value_rejected'}));
  return true;
});
