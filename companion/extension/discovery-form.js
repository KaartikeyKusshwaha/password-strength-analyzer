import {formOriginAllowed,isNewPassword} from './form-policy';
export function isDiscoveryLoginForm(form,url){
  if(form?.tagName!=='FORM'||!formOriginAllowed(url,form.action))return false;
  return [...form.querySelectorAll('input[type="password"]')].some(field=>!field.disabled&&!field.readOnly&&!isNewPassword(field,url));
}
