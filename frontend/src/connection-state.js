let state='unknown';
const listeners=new Set();
export const connectionSnapshot=()=>state;
export function subscribeConnection(listener){listeners.add(listener);return()=>listeners.delete(listener);}
export function reportConnection(next){
  if(state===next)return;
  state=next;
  for(const listener of listeners)listener();
}
