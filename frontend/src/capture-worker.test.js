import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { runInNewContext } from 'node:vm';
import { expect, it, vi } from 'vitest';

function worker() {
  let handler,removed; let current=10000;
  const badge=vi.fn(),storage=vi.fn();
  const chrome={runtime:{id:'fixture-extension',getURL:path=>'chrome-extension://fixture-extension/'+path,onMessage:{addListener:fn=>{handler=fn;}}},action:{setBadgeText:badge,setBadgeBackgroundColor:vi.fn()},storage:{local:{set:storage}},tabs:{create:vi.fn(async()=>({id:5})),sendMessage:vi.fn(async()=>{})},windows:{create:vi.fn(async()=>({id:50,tabs:[{id:51}]})),onRemoved:{addListener:fn=>{removed=fn;}}}};
  const workerSource = readFileSync(resolve(process.cwd(), '../companion/extension/public/background.js'),'utf8');
  runInNewContext(workerSource,{chrome,Date:{now:()=>current},crypto:{randomUUID:()=>Math.random().toString(36)},setTimeout:()=>{},URL});
  return {message:(message,sender)=>new Promise(resolve=>{if(handler(message,sender,resolve)!==true)resolve(undefined);}),advance:()=>{current+=180001;},remove:id=>removed(id),storage,open:chrome.tabs.create,window:chrome.windows.create,ready:chrome.tabs.sendMessage};
}
const content={id:'fixture-extension',frameId:0,tab:{id:1},url:'https://example.test/register'};
const entry={origin:'https://example.test',username:'fixture',password:'fixture-secret'};
const frame={id:'fixture-extension',frameId:0,tab:{id:51,windowId:50},url:'chrome-extension://fixture-extension/vault-frame.html'};
async function captureAndOpen(w){const capture=await w.message({type:'capture',entry},content);expect((await w.message({type:'open-private-save',id:capture.id},content)).ok).toBe(true);return capture;}
it('exposes captures only to the exact dedicated extension window and never persists plaintext',async()=>{
  const w=worker(),capture=await captureAndOpen(w);
  expect(w.window).toHaveBeenCalledWith({url:'chrome-extension://fixture-extension/vault-frame.html#'+capture.id,type:'popup',width:470,height:740,focused:true});
  for(const sender of [{...frame,tab:{id:52,windowId:50}},{...frame,tab:{id:51,windowId:99}},{...frame,frameId:1},{...frame,tab:undefined}]) {
    const result=await w.message({type:'frame-capture',id:capture.id},sender);
    expect(result?.entry || null).toBeNull();
  }
  expect(await w.message({type:'frame-capture',id:capture.id},content)).toBeUndefined();
  const result=await w.message({type:'frame-capture',id:capture.id},frame);
  expect(result.entry).toEqual({...entry,expires:190000});
  expect(w.ready).toHaveBeenLastCalledWith(1,{type:'private-save-ready',id:capture.id},{frameId:0});
  expect(JSON.stringify(w.ready.mock.calls)).not.toContain('fixture-secret');
  expect(JSON.stringify(w.window.mock.calls)).not.toContain('fixture-secret');
  expect(w.storage).not.toHaveBeenCalled();
  w.advance();expect((await w.message({type:'frame-capture',id:capture.id},frame)).entry).toBeNull();
});
it('rejects untrusted senders, subframes, mismatched origins and opening a capture from another tab',async()=>{
  const w=worker();
  expect(await w.message({type:'capture',entry},{...content,id:'other-extension'})).toBeUndefined();
  expect(await w.message({type:'capture',entry},{...content,frameId:1})).toBeUndefined();
  expect((await w.message({type:'capture',entry:{...entry,origin:'https://other.test'}},content)).ok).toBe(false);
  const capture=await w.message({type:'capture',entry},content);
  for(const sender of [{...content,tab:{id:2}},{...content,url:'https://other.test'},{...content,frameId:1}])await w.message({type:'open-private-save',id:capture.id},sender);
  expect(w.window).not.toHaveBeenCalled();
  expect((await w.message({type:'frame-capture',id:capture.id},frame)).entry).toBeNull();
});
it('drops saved requests, supersedes older captures, and rejects deletion from an unrelated window',async()=>{
  const w=worker(),old=await captureAndOpen(w),latest=await captureAndOpen(w);
  expect((await w.message({type:'frame-capture',id:old.id},frame)).entry).toBeNull();
  expect((await w.message({type:'capture-saved',id:latest.id},{...frame,tab:{id:52,windowId:50}})).ok).toBe(false);
  expect((await w.message({type:'frame-capture',id:latest.id},frame)).entry.password).toBe(entry.password);
  await w.message({type:'capture-saved',id:latest.id},frame);
  expect((await w.message({type:'frame-capture',id:latest.id},frame)).entry).toBeNull();
});
it('clears a closed window and removes a failed window request without claiming success',async()=>{
  const w=worker(),capture=await captureAndOpen(w);
  expect((await w.message({type:'open-private-save',id:capture.id},content)).ok).toBe(false);
  expect(w.window).toHaveBeenCalledTimes(1);
  w.remove(50);expect((await w.message({type:'frame-capture',id:capture.id},frame)).entry).toBeNull();
  w.window.mockRejectedValueOnce(new Error('window unavailable'));
  const failed=await w.message({type:'capture',entry},content);
  expect((await w.message({type:'open-private-save',id:failed.id},content)).ok).toBe(false);
  expect((await w.message({type:'frame-capture',id:failed.id},frame)).entry).toBeNull();
});
it('waits for exact window binding when the private page starts before windows.create resolves',async()=>{
  const w=worker();let finish;
  w.window.mockImplementationOnce(()=>new Promise(resolve=>{finish=resolve;}));
  const capture=await w.message({type:'capture',entry},content);
  const opening=w.message({type:'open-private-save',id:capture.id},content);
  let delivered=false;
  const reading=w.message({type:'frame-capture',id:capture.id},frame).then(result=>{delivered=true;return result;});
  await Promise.resolve();expect(delivered).toBe(false);
  finish({id:50,tabs:[{id:51}]});
  expect((await opening).ok).toBe(true);expect((await reading).entry.password).toBe(entry.password);
});
it('does not release captures through the old unscoped popup request',async()=>{
  const w=worker();await captureAndOpen(w);
  expect(await w.message({type:'get-capture'},{id:'fixture-extension',url:'chrome-extension://fixture-extension/popup.html'})).toBeUndefined();
});
it('fails closed if a created window has no verifiable browser tab binding',async()=>{
  const w=worker();w.window.mockResolvedValueOnce({id:50,tabs:[]});
  const capture=await w.message({type:'capture',entry},content);
  expect((await w.message({type:'open-private-save',id:capture.id},content)).ok).toBe(false);
  expect((await w.message({type:'frame-capture',id:capture.id},frame)).entry).toBeNull();
});
it('opens only an exact HTTPS change-password path requested by the private popup',async()=>{
  const w=worker(),popup={id:'fixture-extension',url:'chrome-extension://fixture-extension/popup.html'};
  await w.message({type:'open-account-change',origin:'https://example.test'},content);expect(w.open).not.toHaveBeenCalled();
  for(const origin of ['http://example.test','https://example.test/path','https://user:pass@example.test','javascript:alert(1)'])await w.message({type:'open-account-change',origin},popup);
  expect(w.open).not.toHaveBeenCalled();
  await w.message({type:'open-account-change',origin:'https://example.test'},popup);
  expect(w.open).toHaveBeenCalledWith({url:'https://example.test/.well-known/change-password',active:true});expect(w.storage).not.toHaveBeenCalled();
});
