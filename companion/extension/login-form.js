import {mayFill} from './policy';
import {isNewPassword} from './form-policy';

export function fillLoginForm(document,pageUrl,entry) {
  if(typeof entry?.username!=='string' || entry.username.length>254 || typeof entry?.password!=='string' || !entry.password || entry.password.length>256 || !mayFill(entry.origin,pageUrl))return {ok:false};
  const visible=field=>field.getClientRects().length && !field.disabled && !field.readOnly;
  const fields=[...document.querySelectorAll('input[type="password"]')].filter(field=>!isNewPassword(field,pageUrl) && !/confirm|repeat|retype/i.test(field.name+' '+field.id) && visible(field));
  if(fields.length!==1)return {ok:false};
  const field=fields[0],form=field.form;
  if(!mayFill(entry.origin,pageUrl,form?.action))return {ok:false};
  const usernames=[...(form?.querySelectorAll('input[autocomplete="username"],input[type="email"],input[name="username"],input[name="email"]') || [])].filter(visible);
  if(usernames.length>1)return {ok:false};
  const setter=Object.getOwnPropertyDescriptor(HTMLInputElement.prototype,'value').set;
  for(const [input,value] of [[usernames[0],entry.username],[field,entry.password]])if(input){setter.call(input,value);input.dispatchEvent(new Event('input',{bubbles:true}));input.dispatchEvent(new Event('change',{bubbles:true}));}
  return {ok:true};
}
