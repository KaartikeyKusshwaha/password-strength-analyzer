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
export async function fillLoginForm(document,pageUrl,entry) {
  if(typeof entry?.username!=='string' || entry.username.length>254 || typeof entry?.password!=='string' || !entry.password || entry.password.length>256)return {ok:false,reason:'entry'};
  const target=loginTarget(document,pageUrl,entry.origin);
  if(!target.ok)return target;
  const {field,username}=target;
  const setter=Object.getOwnPropertyDescriptor(HTMLInputElement.prototype,'value').set;
  function current(){
    const next=loginTarget(document,pageUrl,entry.origin);
    return next.ok && next.field===field && next.username===username && field.isConnected && (!username || username.isConnected);
  }
  for(const [input,value] of [[username,entry.username],[field,entry.password]])if(input){
    // A site's input handlers can replace fields or change a form destination.
    // Recheck between writes so the password never follows a changed target.
    if(!current())return {ok:false,reason:'form_changed'};
    setter.call(input,value);
    input.dispatchEvent(new Event('input',{bubbles:true}));
    if(!current())return {ok:false,reason:'form_changed'};
    input.dispatchEvent(new Event('change',{bubbles:true}));
  }
  // Frameworks may restore a controlled value after the input/change events.
  // Observe once after their queued updates; never retry a credential write.
  await new Promise(resolve=>setTimeout(resolve,150));
  if(!current())return {ok:false,reason:'form_changed'};
  if(field.value!==entry.password || (username && username.value!==entry.username))return {ok:false,reason:'value_rejected'};
  return {ok:true,filled:username?'login':'password'};
}
