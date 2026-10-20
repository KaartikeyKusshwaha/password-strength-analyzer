export function autofillError(reason) {
  return ({
    origin:'The selected login does not match this HTTPS website. Nothing was filled.',
    password_field:'No single supported sign-in password field was found. Signup, reset and ambiguous forms are not filled.',
    form_action:'This form sends to another origin. SentinelOps did not fill it.',
    username_field:'Several username fields were found. SentinelOps did not choose one.',
    frame:'Autofill is available only in the main website page.',
    entry:'The selected login cannot be filled. Check its details in your vault.',
    form_changed:'The website changed its sign-in form while filling. Review the fields and try again from the current page. Nothing was submitted.',
    value_rejected:'The website did not keep the filled values. Review its fields; SentinelOps did not submit or retry the login.',
  })[reason] || 'The website did not confirm autofill. Nothing was submitted.';
}

export async function fillSavedLogin(browser,session,entryId,active,version) {
  // Establish the page/version before decrypting an entry for transmission.
  // Never include native messaging errors, URLs or credential values in diagnostics.
  let check;
  try {check=await browser.tabs.sendMessage(active.id,{type:'inspect-login',origin:active.origin},{frameId:0});}
  catch {throw new Error('The website companion is unavailable. Reload SentinelOps in Extensions, then refresh this website and reopen the companion.');}
  if(check?.version!==version)throw new Error('The website is using an older companion. Refresh this website, then reopen SentinelOps and try again.');
  if(!check.ok)throw new Error(autofillError(check.reason));
  const generation=session.generation,selected=await session.fill(entryId,active.origin);
  session.active(generation);
  let result;
  try {result=await browser.tabs.sendMessage(active.id,{type:'fill-login',entry:selected},{frameId:0});}
  catch {throw new Error('The website companion disconnected. Refresh the website and try again. Nothing was submitted.');}
  if(!result?.ok)throw new Error(autofillError(result?.reason));
  if(!['login','password'].includes(result.filled))throw new Error('The website companion did not confirm the filled fields. Refresh the website and try again. Nothing was submitted.');
  return result.filled;
}
