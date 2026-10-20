import {mayFill} from './policy';
import {isNewPassword} from './form-policy';

function loginTarget(document,pageUrl,origin) {
  if(!mayFill(origin,pageUrl))return {ok:false,reason:'origin'};
  const visible=field=>field.getClientRects().length && !field.disabled && !field.readOnly;
  const fields=[...document.querySelectorAll('input[type="password"]')].filter(field=>!isNewPassword(field,pageUrl) && !/confirm|repeat|retype/i.test(field.name+' '+field.id) && visible(field));
  if(fields.length!==1)return {ok:false,reason:'password_field'};
  const field=fields[0],form=field.form;
  if(!mayFill(origin,pageUrl,form?.action))return {ok:false,reason:'form_action'};
  const usernames=[...(form?.querySelectorAll('input[autocomplete="username"],input[type="email"],input[name="username"],input[name="email"]') || [])].filter(visible);
  if(usernames.length>1)return {ok:false,reason:'username_field'};
  return {ok:true,field,username:usernames[0]};
}
export function inspectLoginForm(document,pageUrl,origin) {
  const {ok,reason}=loginTarget(document,pageUrl,origin);
  return ok?{ok:true}:{ok:false,reason};
}
export function fillLoginForm(document,pageUrl,entry) {
  if(typeof entry?.username!=='string' || entry.username.length>254 || typeof entry?.password!=='string' || !entry.password || entry.password.length>256)return {ok:false,reason:'entry'};
  const target=loginTarget(document,pageUrl,entry.origin);
  if(!target.ok)return target;
  const {field,username}=target;
  const setter=Object.getOwnPropertyDescriptor(HTMLInputElement.prototype,'value').set;
  for(const [input,value] of [[username,entry.username],[field,entry.password]])if(input){setter.call(input,value);input.dispatchEvent(new Event('input',{bubbles:true}));input.dispatchEvent(new Event('change',{bubbles:true}));}
  return {ok:true};
}
