import {mayFill} from './policy';
function target(document,pageUrl,origin){
  if(!mayFill(origin,pageUrl))return {ok:false,reason:'origin'};
  const fields=[...document.querySelectorAll('input[autocomplete="one-time-code"]')].filter(field=>['text','tel','number','password'].includes(field.type)&&!field.disabled&&!field.readOnly&&field.getClientRects().length);
  if(fields.length!==1)return {ok:false,reason:'otp_field'};
  const field=fields[0];
  if(!mayFill(origin,pageUrl,field.form?.action))return {ok:false,reason:'form_action'};
  return {ok:true,field};
}
export function inspectOtp(document,pageUrl,origin){const {ok,reason}=target(document,pageUrl,origin);return ok?{ok:true}:{ok:false,reason};}
export function fillOtp(document,pageUrl,{origin,code}){
  if(typeof code!=='string'||!/^\d{6}(?:\d{2})?$/.test(code))return {ok:false,reason:'code'};
  const selected=target(document,pageUrl,origin);if(!selected.ok)return selected;
  const field=selected.field;
  if(field.maxLength>0&&field.maxLength<code.length)return {ok:false,reason:'otp_field'};
  Object.getOwnPropertyDescriptor(HTMLInputElement.prototype,'value').set.call(field,code);
  field.dispatchEvent(new Event('input',{bubbles:true}));
  const next=target(document,pageUrl,origin);
  if(!next.ok||next.field!==field||!field.isConnected)return {ok:false,reason:'form_changed'};
  field.dispatchEvent(new Event('change',{bubbles:true}));
  return field.value===code?{ok:true}:{ok:false,reason:'value_rejected'};
}
