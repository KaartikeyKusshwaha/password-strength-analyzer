import {formOriginAllowed,isNewPassword} from './form-policy';
export function loginSubmission(form,url){
  if(!form||form.tagName!=='FORM'||form.method.toLowerCase()!=='post'||!formOriginAllowed(url,form.action))return null;
  const passwords=[...form.querySelectorAll('input[type="password"]')].filter(input=>!input.disabled&&!input.readOnly&&input.getClientRects().length);
  if(passwords.length!==1||isNewPassword(passwords[0],url))return null;
  const username=form.querySelector('input[autocomplete="username"],input[type="email"],input[name="username"],input[name="email"]')?.value||'';
  const password=passwords[0].value;
  if(!username||username.length>254||!password||password.length>256)return null;
  return {origin:new URL(url).origin,username,password};
}
