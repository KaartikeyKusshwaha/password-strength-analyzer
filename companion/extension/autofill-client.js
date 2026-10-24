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

async function messageWithDeadline(browser,tab,message) {
  let timer;
  try {
    return await Promise.race([
      browser.tabs.sendMessage(tab,message,{frameId:0}),
      new Promise((_,reject)=>{timer=setTimeout(()=>reject(new Error('No page acknowledgement')),5000);}),
    ]);
  } finally {clearTimeout(timer);}
}

export async function fillSavedLogin(browser,session,entryId,active,version,progress=()=>{}) {
  // Establish the page/version before decrypting an entry for transmission.
  // Never include native messaging errors, URLs or credential values in diagnostics.
  const generation=session.generation;
  let check;
  progress('Checking this sign-in form…');
  try {check=await messageWithDeadline(browser,active.id,{type:'inspect-login',origin:active.origin});}
  catch {throw new Error('The website companion did not answer. Reload SentinelOps in Extensions, then refresh this website and reopen the companion. No saved credentials were sent.');}
  if(check?.version!==version)throw new Error('The website is using an older companion. Refresh this website, then reopen SentinelOps and try again.');
  if(!check.ok)throw new Error(autofillError(check.reason));
  session.active(generation);
  progress('Checking current vault access…');
  const selected=await session.fill(entryId,active.origin);
  session.active(generation);
  progress('Filling the selected login; waiting for the website…');
  let result;
  try {result=await messageWithDeadline(browser,active.id,{type:'fill-login',entry:selected});}
  catch {throw new Error('The website did not acknowledge filling. Check its fields before retrying: the message may have arrived. Nothing was submitted and SentinelOps did not retry.');}
  if(!result?.ok)throw new Error(autofillError(result?.reason));
  if(!['login','password'].includes(result.filled))throw new Error('The website companion did not confirm the filled fields. Refresh the website and try again. Nothing was submitted.');
  return result.filled;
}

export async function fillSavedCode(browser,session,entryId,active,version){
  const generation=session.generation;
  const check=await messageWithDeadline(browser,active.id,{type:'inspect-otp',origin:active.origin});
  if(!check?.ok||check.version!==version)throw new Error('No current, single supported verification-code field was found. Refresh the site if the companion was updated.');
  session.active(generation);
  const code=await session.codeFor(entryId,active.origin);session.active(generation);
  const tabs=await browser.tabs.query({active:true,currentWindow:true});
  if(tabs[0]?.id!==active.id||new URL(tabs[0].url).origin!==active.origin)throw new Error('Website changed. No code was sent.');
  const result=await messageWithDeadline(browser,active.id,{type:'fill-otp',origin:active.origin,code});
  if(!result?.ok)throw new Error('The website did not confirm code filling. Review the field before trying again. Nothing was submitted.');
  return true;
}
