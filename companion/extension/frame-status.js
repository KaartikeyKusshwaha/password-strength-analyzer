// Readiness travels through the extension worker, never website postMessage.
// The acknowledgement contains no captured entry, token or unlock material.
export function watchPrivateFrame(chrome, id, failed, timeoutMs=8000) {
  let active=true;
  function stop(){if(!active)return;active=false;clearTimeout(timer);chrome.runtime.onMessage.removeListener(ready);}
  function ready(message,sender){
    if(sender?.id===chrome.runtime.id && message?.type==='private-save-ready' && message.id===id)stop();
  }
  const timer=setTimeout(()=>{if(!active)return;stop();failed();},timeoutMs);
  chrome.runtime.onMessage.addListener(ready);
  return stop;
}
