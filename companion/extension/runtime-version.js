// Unpacked updates can change popup files before registered content scripts or
// the worker are reloaded. Display the browser's loaded version, not just files.
export function runtimeVersion(browser,bundled){
  try{
    const loaded=browser.runtime.getManifest().version;
    if(!/^\d+\.\d+\.\d+(?:\.\d+)?$/.test(loaded))throw new Error();
    return {loaded,bundled,matches:loaded===bundled};
  }catch{return {loaded:null,bundled,matches:false};}
}
