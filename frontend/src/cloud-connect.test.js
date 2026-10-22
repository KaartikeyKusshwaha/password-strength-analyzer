import {expect,it,vi} from 'vitest';
import {startCloudConnection,finishCloudConnection,CLOUD_ORIGIN} from '../../companion/extension/cloud-connect';
function browser(){const saved={connections:[{origin:'http://127.0.0.1:8110',token:'legacy-test-only',vaultId:'legacy'}]};return {saved,permissions:{request:vi.fn(async()=>true),contains:vi.fn(async()=>true)},tabs:{create:vi.fn(async()=>{})},storage:{local:{get:vi.fn(async()=>({...saved})),set:vi.fn(async value=>Object.assign(saved,value)),remove:vi.fn(async key=>{delete saved[key];})}}};}
function transport(){return vi.fn(async(url)=>({ok:true,status:200,json:async()=>url.endsWith('/start')?{id:'a'.repeat(24),code:'123456',expires:Date.now()/1000+300,approval_url:CLOUD_ORIGIN+'/#connect='+'a'.repeat(24)}:url.endsWith('/poll')?{status:'approved',origin:CLOUD_ORIGIN,token:'x'.repeat(54)}:url.endsWith('/vault')?{revision:1,envelope:{version:1},vault:{id:'new-vault',name:'Work'}}:{ok:true}}));}
it('keeps discovery separate and requires fresh per-site opt-in after connecting',async()=>{
  const b=browser();b.saved.discoverySites=[{domain:'old.test'}];
  const fetcher=vi.fn(async url=>({ok:true,json:async()=>url.endsWith('/start')?{id:'a'.repeat(24),code:'123456',expires:Date.now()/1000+300,approval_url:CLOUD_ORIGIN+'/#connect='+'a'.repeat(24)}:url.endsWith('/poll')?{status:'approved',scope:'discovery',origin:CLOUD_ORIGIN,token:'x'.repeat(54)}:{clients:[]}}));
  await startCloudConnection(b,CLOUD_ORIGIN,fetcher,'discovery');
  const connection=await finishCloudConnection(b,fetcher);
  expect(connection.kind).toBe('discovery');expect(b.saved.discoveryConnection).toEqual(connection);
  expect(b.saved.discoverySites).toEqual([]);expect(b.saved.connections).toHaveLength(1);
  expect(fetcher.mock.calls.some(([url])=>url.endsWith('/discovery/context'))).toBe(true);
  expect(fetcher.mock.calls.some(([url])=>url.endsWith('/vault'))).toBe(false);
});
it('stores workflow access separately and verifies its narrow context before acknowledgement',async()=>{
  const b=browser();
  const fetcher=vi.fn(async url=>({ok:true,json:async()=>url.endsWith('/start')?{id:'a'.repeat(24),code:'123456',expires:Date.now()/1000+300,approval_url:CLOUD_ORIGIN+'/#connect='+'a'.repeat(24)}:url.endsWith('/poll')?{status:'approved',scope:'access',origin:CLOUD_ORIGIN,token:'x'.repeat(54)}:{ok:true}}));
  await startCloudConnection(b,CLOUD_ORIGIN,fetcher,'access');
  const connection=await finishCloudConnection(b,fetcher);
  expect(b.saved.accessConnection).toEqual({...connection,kind:'access'});
  expect(b.saved.connections).toHaveLength(1);expect(b.saved.securityConnection).toBeUndefined();
  expect(fetcher.mock.calls.some(([url])=>url.endsWith('/access/context'))).toBe(true);
  expect(fetcher.mock.calls.some(([url])=>url.endsWith('/vault')||url.endsWith('/security/context'))).toBe(false);
});
it('uses sign-in approval without placing proof or bearer tokens in a URL',async()=>{
  const b=browser(),fetcher=transport();const pending=await startCloudConnection(b,CLOUD_ORIGIN,fetcher);
  expect(pending.proof.length).toBe(43);
  expect(b.saved.cloudConnect).toEqual(pending);
  const url=b.tabs.create.mock.calls[0][0].url;expect(url).not.toContain(pending.proof);expect(url).toBe(CLOUD_ORIGIN+'/#connect='+'a'.repeat(24));
  const connection=await finishCloudConnection(b,fetcher);
  expect(connection.vaultId).toBe('new-vault');expect(b.saved.connections).toHaveLength(2);
  expect(b.saved.cloudConnect).toBeUndefined();
  expect(fetcher.mock.calls.at(-1)[0]).toContain('/ack');
});
it('does not start after permission denial or accept an approval URL on another origin',async()=>{
  const b=browser(),fetcher=transport();b.permissions.request.mockResolvedValue(false);
  await expect(startCloudConnection(b,CLOUD_ORIGIN,fetcher)).rejects.toThrow('declined');expect(fetcher).not.toHaveBeenCalled();
  b.permissions.request.mockResolvedValue(true);
  const wrong=async()=>({ok:true,json:async()=>({id:'a'.repeat(24),code:'123456',expires:Date.now()/1000+300,approval_url:'https://other.example/'})});
  await expect(startCloudConnection(b,CLOUD_ORIGIN,wrong)).rejects.toThrow('Unexpected');expect(b.tabs.create).not.toHaveBeenCalled();
});
it('keeps pending proof when approval is not yet granted and rejects expiry',async()=>{
  const b=browser();b.saved.cloudConnect={origin:CLOUD_ORIGIN,id:'a'.repeat(24),proof:'x'.repeat(43),expires:Date.now()/1000+300};
  expect(await finishCloudConnection(b,async()=>({ok:true,json:async()=>({status:'pending'})}))).toBeNull();
  expect(b.saved.cloudConnect).toBeDefined();b.saved.cloudConnect.expires=0;
  await expect(finishCloudConnection(b,transport())).rejects.toThrow('expired');
});
it('does not turn a vault approval into a workspace security grant',async()=>{
  const b=browser();b.saved.cloudConnect={origin:CLOUD_ORIGIN,id:'a'.repeat(24),proof:'x'.repeat(43),expires:Date.now()/1000+300,scope:'vault'};
  const changed=async()=>({ok:true,json:async()=>({status:'approved',scope:'security',origin:CLOUD_ORIGIN,token:'x'.repeat(54)})});
  await expect(finishCloudConnection(b,changed)).rejects.toThrow('scope changed');expect(b.saved.securityConnection).toBeUndefined();
});

it('stores security access separately after verifying it and retains existing vaults',async()=>{
  const b=browser();
  const fetcher=vi.fn(async url=>({ok:true,json:async()=>url.endsWith('/start')?{id:'a'.repeat(24),code:'123456',expires:Date.now()/1000+300,approval_url:CLOUD_ORIGIN+'/#connect='+'a'.repeat(24)}:url.endsWith('/poll')?{status:'approved',scope:'security',origin:CLOUD_ORIGIN,token:'x'.repeat(54)}:{ok:true}}));
  await startCloudConnection(b,CLOUD_ORIGIN,fetcher,'security');
  const connection=await finishCloudConnection(b,fetcher);
  expect(connection.kind).toBe('security');expect(b.saved.securityConnection).toEqual(connection);
  expect(b.saved.connections).toHaveLength(1);expect(b.saved.cloudConnect).toBeUndefined();
  expect(fetcher.mock.calls.some(([url])=>url.endsWith('/security/context'))).toBe(true);
  expect(fetcher.mock.calls.some(([url])=>url.endsWith('/vault'))).toBe(false);
});

it('approves read-only reminders separately without storing an operator capability',async()=>{
 const b=browser();
 const fetcher=vi.fn(async url=>({ok:true,json:async()=>url.endsWith('/start')?{id:'a'.repeat(24),code:'123456',expires:Date.now()/1000+300,approval_url:CLOUD_ORIGIN+'/#connect='+'a'.repeat(24)}:url.endsWith('/poll')?{status:'approved',scope:'reminders',origin:CLOUD_ORIGIN,token:'x'.repeat(54)}:{alerts:[],expires:Date.now()/1000+90*86400}}));
 await startCloudConnection(b,CLOUD_ORIGIN,fetcher,'reminders');const value=await finishCloudConnection(b,fetcher);expect(value.kind).toBe('reminders');expect(value.id).toBeTruthy();expect(b.saved.reminderConnection).toEqual(value);expect(b.saved.accessConnection).toBeUndefined();expect(fetcher.mock.calls.some(([url])=>url.endsWith('/reminders/context'))).toBe(true);expect(fetcher.mock.calls.some(([url])=>url.endsWith('/vault')||url.endsWith('/access/context'))).toBe(false);
});
