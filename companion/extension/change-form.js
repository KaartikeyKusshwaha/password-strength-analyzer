import {formOriginAllowed} from './form-policy';

export function preparePasswordChange(document,pageUrl,message,visible=field=>!!field.getClientRects().length) {
  let page;
  try{page=new URL(pageUrl);}catch{return {ok:false,reason:'cross_origin'};}
  if(page.protocol!=='https:' || page.origin!==message.origin || typeof message.current!=='string' || typeof message.replacement!=='string' || message.current.length>256 || message.replacement.length<15 || message.replacement.length>128)return {ok:false,reason:'cross_origin'};
  const editable=field=>field.type==='password' && !field.disabled && !field.readOnly && visible(field);
  const candidates=[];
  for(const form of document.querySelectorAll('form')) {
    const fields=[...form.querySelectorAll('input[type="password"]')].filter(editable);
    const next=fields.filter(field=>!/confirm|repeat|retype/i.test(field.name+' '+field.id) && (field.autocomplete==='new-password' || /new[_-]?(pass|password)|password[_-]?new/i.test(field.name+' '+field.id)));
    if(next.length!==1)continue;
    if(!formOriginAllowed(pageUrl,form.action))return {ok:false,reason:'cross_origin'};
    const old=fields.filter(field=>field.autocomplete==='current-password' || /current|old/i.test(field.name+' '+field.id));
    const confirm=fields.filter(field=>/confirm|repeat|retype/i.test(field.name+' '+field.id));
    const user=form.querySelector('input[autocomplete="username"],input[type="email"],input[name="username"]');
    if(old.length>1 || confirm.length>1 || fields.some(field=>field!==next[0] && !old.includes(field) && !confirm.includes(field)) || user?.value && user.value!==message.username)continue;
    candidates.push({next:next[0],old:old[0],confirm:confirm[0]});
  }
  if(candidates.length!==1)return {ok:false,reason:'unsupported_form'};
  const {next,old,confirm}=candidates[0];
  for(const field of [next,confirm].filter(Boolean)) {
    if(field.maxLength>=0 && message.replacement.length>field.maxLength || field.minLength>message.replacement.length)return {ok:false,reason:'unsupported_form'};
    const probe=field.cloneNode(false);probe.value=message.replacement;
    if(probe.validity?.patternMismatch)return {ok:false,reason:'unsupported_form'};
  }
  // No submit/click/navigation. Field selection finishes before any credential is written.
  const setter=Object.getOwnPropertyDescriptor(document.defaultView.HTMLInputElement.prototype,'value').set;
  for(const [field,value] of [[old,message.current],[next,message.replacement],[confirm,message.replacement]])if(field){setter.call(field,value);field.dispatchEvent(new document.defaultView.Event('input',{bubbles:true}));field.dispatchEvent(new document.defaultView.Event('change',{bubbles:true}));}
  if(next.value!==message.replacement || confirm && confirm.value!==message.replacement || old && old.value!==message.current)return {ok:false,reason:'unsupported_form'};
  return {ok:true,submitted:false};
}
