import {expect,it,vi} from 'vitest';
import {createAccessDiscovery} from '../../companion/extension/access-discovery';
import {discoveryRequest} from '../../companion/extension/discovery-client';
import {isDiscoveryLoginForm} from '../../companion/extension/discovery-form';

const origin='https://app.example.test',client='a'.repeat(24),id='c'.repeat(24);
function fixture(){
  const saved={discoveryConnection:{kind:'discovery',origin:'http://127.0.0.1:8110',token:'t'.repeat(54)},discoverySites:[]};
  const tab={id:5,windowId:2,url:origin+'/dashboard?session=never-record-this'};
  const browser={runtime:{id:'fixture-extension',getURL:path=>'chrome-extension://fixture/'+path,onMessage:{addListener:vi.fn()}},storage:{local:{get:vi.fn(async()=>({...saved})),set:vi.fn(async data=>Object.assign(saved,data)),remove:vi.fn(async key=>{delete saved[key];})}},tabs:{query:vi.fn(async()=>[tab]),get:vi.fn(async()=>tab)},permissions:{contains:vi.fn(async()=>true),onRemoved:{addListener:vi.fn()}}};
  const request=vi.fn(async(_,path,body)=>path==='consents'?{id,domain:body.domain,client_id:body.client_id,account_label:body.account_label}:path==='context'?{clients:[{id:client,name:'Client'}],consents:[]}:{ok:true});
  return {saved,browser,tab,request,popup:{id:browser.runtime.id,url:browser.runtime.getURL('popup.html')},page:{id:browser.runtime.id,url:tab.url,frameId:0,tab:{id:5,windowId:2}}};
}

it('does nothing on unchosen sites, then sends only the consent id for a selected login attempt',async()=>{
  const f=fixture(),agent=createAccessDiscovery(f.browser,{request:f.request,clock:()=>0});
  expect(await agent.message({type:'discovery-observe'},f.page)).toEqual({ok:true,recorded:false});
  expect(f.request).not.toHaveBeenCalled();
  await agent.message({type:'discovery-enable',origin,client,label:'Client nickname'},f.popup);
  expect(f.saved.discoverySites).toEqual([{id,domain:'app.example.test',origin,client_id:client,account_label:'Client nickname'}]);
  expect(await agent.message({type:'discovery-observe'},f.page)).toEqual({ok:true,recorded:true});
  const observation=f.request.mock.calls.at(-1);
  expect(observation.slice(1)).toEqual(['observe',{consent_id:id}]);
  expect(JSON.stringify(f.request.mock.calls)).not.toContain('never-record-this');
  expect((await agent.message({type:'discovery-observe'},f.page)).recorded).toBe(false);
  expect(f.request.mock.calls.filter(([,path])=>path==='observe')).toHaveLength(1);
});

it('requires popup/site permission and rejects subframes, extra values and navigation changes',async()=>{
  const f=fixture(),agent=createAccessDiscovery(f.browser,{request:f.request});
  f.browser.permissions.contains.mockResolvedValue(false);
  await expect(agent.message({type:'discovery-enable',origin,client,label:'Nickname'},f.popup)).rejects.toThrow('Allow this exact');
  expect(f.request).not.toHaveBeenCalled();
  f.browser.permissions.contains.mockResolvedValue(true);
  await agent.message({type:'discovery-enable',origin,client,label:'Nickname'},f.popup);
  await expect(agent.message({type:'discovery-observe',password:'do-not-store'},f.page)).rejects.toThrow('Top-level');
  await expect(agent.message({type:'discovery-observe'},{...f.page,frameId:1})).rejects.toThrow('Top-level');
  f.tab.url='https://other.example.test/';
  await expect(agent.message({type:'discovery-observe'},f.page)).rejects.toThrow('website changed');
  expect(f.request.mock.calls.filter(([,path])=>path==='observe')).toHaveLength(0);
});

it('stops locally even when disabling cannot reach the server and does not silently restore site consent',async()=>{
  const f=fixture(),agent=createAccessDiscovery(f.browser,{request:f.request});
  await agent.message({type:'discovery-enable',origin,client,label:'Nickname'},f.popup);
  f.request.mockRejectedValueOnce(new Error('offline'));
  await expect(agent.message({type:'discovery-disable',id},f.popup)).rejects.toThrow('offline');
  expect(f.saved.discoverySites).toEqual([]);
  expect((await agent.message({type:'discovery-observe'},f.page)).recorded).toBe(false);
  await agent.message({type:'discovery-status'},f.popup);
  expect(f.saved.discoverySites).toEqual([]);
});

it('host permission removal pauses collection until a fresh explicit enable',async()=>{
  const f=fixture(),agent=createAccessDiscovery(f.browser,{request:f.request});
  await agent.message({type:'discovery-enable',origin,client,label:'Nickname'},f.popup);
  agent.install();f.browser.permissions.onRemoved.addListener.mock.calls[0][0]({origins:[origin+'/*']});
  await agent.message({type:'discovery-status'},f.popup);
  expect(f.saved.discoverySites).toEqual([]);
  expect((await agent.message({type:'discovery-observe'},f.page)).recorded).toBe(false);
});

it('rejects workflow/vault credentials and paths outside the discovery capability',async()=>{
  const fetcher=vi.fn(),connection={kind:'discovery',origin:'http://127.0.0.1:8110',token:'t'.repeat(54)};
  await expect(discoveryRequest({...connection,kind:'access'},'context',undefined,fetcher)).rejects.toThrow('Connect account discovery');
  await expect(discoveryRequest(connection,'../vault',undefined,fetcher)).rejects.toThrow('Unsupported');
  expect(fetcher).not.toHaveBeenCalled();
});

it('recognizes login form structure without reading a password and ignores signup or cross-origin forms',()=>{
  const form=document.createElement('form');form.action=origin+'/login';
  form.innerHTML='<input type="password" name="password" autocomplete="current-password">';
  Object.defineProperty(form.elements[0],'value',{get:()=>{throw new Error('Password values must not be read');}});
  expect(isDiscoveryLoginForm(form,origin+'/login')).toBe(true);
  form.action='https://other.example.test/login';expect(isDiscoveryLoginForm(form,origin+'/login')).toBe(false);
  form.action=origin+'/signup';form.innerHTML='<input type="password" name="new_password" autocomplete="new-password">';
  expect(isDiscoveryLoginForm(form,origin+'/signup')).toBe(false);
});
