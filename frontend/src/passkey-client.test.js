import {afterEach,beforeEach,expect,it,vi} from 'vitest';
import {api} from './api';
import {performPasskey,encodePasskey,decodePasskey} from './passkey-client';
vi.mock('./api',()=>({api:vi.fn()}));
const raw=()=>new Uint8Array([1,2,3]).buffer;
let browser;
function options(mode){return {request_id:'r'.repeat(43),publicKey:{challenge:encodePasskey(new Uint8Array(32).fill(1)),timeout:120000,...(mode==='register'?{rp:{id:'security.example.test'},user:{id:encodePasskey(new Uint8Array(24).fill(2)),name:'fixture@example.test'},authenticatorSelection:{residentKey:'required',userVerification:'required'},excludeCredentials:[]}:{rpId:'security.example.test',userVerification:'required',allowCredentials:[]})}};}
beforeEach(()=>{
  vi.mocked(api).mockReset();
  vi.stubGlobal('isSecureContext',true);vi.stubGlobal('PublicKeyCredential',class {});
  vi.stubGlobal('location',{hostname:'security.example.test'});
  const credential={id:encodePasskey(raw()),rawId:raw(),type:'public-key',response:{clientDataJSON:raw(),attestationObject:raw(),authenticatorData:raw(),signature:raw(),userHandle:raw()},privateKey:'never-serialize-this-fixture'};
  browser={create:vi.fn(async()=>credential),get:vi.fn(async()=>credential)};
  vi.stubGlobal('navigator',{credentials:browser});
});
afterEach(()=>{vi.useRealTimers();});
it('converts native buffers, sends only explicit proof fields and carries the opaque request in a header option',async()=>{
  vi.mocked(api).mockResolvedValueOnce(options('register')).mockResolvedValueOnce({id:'new-fixture'});
  await expect(performPasskey('register',{password:'public-test-only',label:'Device'})).resolves.toEqual({id:'new-fixture'});
  expect(browser.create.mock.calls[0][0].publicKey.challenge).toBeInstanceOf(Uint8Array);
  const [path,body,header]=vi.mocked(api).mock.calls[1];
  expect(path).toBe('/passkeys/register/finish');expect(header).toEqual({requestId:'r'.repeat(43)});
  expect(body).toMatchObject({label:'Device',credential:{id:'AQID',rawId:'AQID',type:'public-key',response:{clientDataJSON:'AQID',attestationObject:'AQID'}}});
  expect(JSON.stringify(body)).not.toContain('public-test-only');expect(JSON.stringify(body)).not.toContain('never-serialize');
});
it('preserves the pending-factor result for sign-in instead of treating it as full access',async()=>{
  vi.mocked(api).mockResolvedValueOnce(options('login')).mockResolvedValueOnce({mfa_required:true,csrf:'fixture'});
  await expect(performPasskey('login',{email:'fixture@example.test'})).resolves.toEqual({mfa_required:true,csrf:'fixture'});
  expect(api).toHaveBeenNthCalledWith(1,'/passkeys/login/options',{email:'fixture@example.test'});
  expect(JSON.stringify(vi.mocked(api).mock.calls[1])).not.toContain('attestationObject');
});
it('cancels a native rejection without submitting a proof',async()=>{
  vi.mocked(api).mockResolvedValueOnce(options('login')).mockResolvedValue({ok:true});browser.get.mockRejectedValue(new DOMException('Native private detail','NotAllowedError'));
  await expect(performPasskey('login',{email:'fixture@example.test'})).rejects.toThrow('cancelled or not approved');
  expect(api).toHaveBeenLastCalledWith('/passkeys/cancel',{}, {requestId:'r'.repeat(43)});
  expect(vi.mocked(api).mock.calls.some(([path])=>path.endsWith('/finish'))).toBe(false);
});
it('cancels if the component aborts while options are loading',async()=>{
  const controller=new AbortController();vi.mocked(api).mockImplementationOnce(async()=>{controller.abort();return options('login');}).mockResolvedValue({ok:true});
  await expect(performPasskey('login',{email:'fixture@example.test',signal:controller.signal})).rejects.toThrow('cancelled');
  expect(browser.get).not.toHaveBeenCalled();expect(api).toHaveBeenLastCalledWith('/passkeys/cancel',{}, {requestId:'r'.repeat(43)});
});
it('cancels even when the native promise ignores abort and discards its late proof',async()=>{
  const controller=new AbortController();let release;
  const credential=await browser.get();
  browser.get.mockImplementation(()=>new Promise(resolve=>{release=resolve;}));
  vi.mocked(api).mockResolvedValueOnce(options('login')).mockResolvedValue({ok:true});
  const operation=performPasskey('login',{email:'fixture@example.test',signal:controller.signal});
  const result=expect(operation).rejects.toThrow('cancelled');
  await vi.waitFor(()=>expect(release).toBeTypeOf('function'));
  controller.abort();await result;
  expect(browser.get.mock.calls.at(-1)[0].signal.aborted).toBe(true);
  expect(api).toHaveBeenLastCalledWith('/passkeys/cancel',{}, {requestId:'r'.repeat(43)});
  release(credential);await Promise.resolve();
  expect(vi.mocked(api).mock.calls.some(([path])=>path.endsWith('/finish'))).toBe(false);
});
it('bounds a native prompt by the server lifetime and never submits a late credential',async()=>{
  vi.useFakeTimers();let release;
  const credential=await browser.get();browser.get.mockImplementation(()=>new Promise(resolve=>{release=resolve;}));
  vi.mocked(api).mockResolvedValueOnce({...options('login'),expires_in:2}).mockResolvedValue({ok:true});
  const operation=performPasskey('login',{email:'fixture@example.test'});
  const result=expect(operation).rejects.toThrow('expired');
  await vi.advanceTimersByTimeAsync(2000);await result;
  expect(browser.get.mock.calls.at(-1)[0].signal.aborted).toBe(true);
  release(credential);await Promise.resolve();
  expect(vi.mocked(api).mock.calls.some(([path])=>path.endsWith('/finish'))).toBe(false);
  expect(vi.getTimerCount()).toBe(0);
});
it('rejects an unbounded lifetime before opening a native prompt',async()=>{
  vi.mocked(api).mockResolvedValueOnce({...options('login'),expires_in:121}).mockResolvedValue({ok:true});
  await expect(performPasskey('login',{email:'fixture@example.test'})).rejects.toThrow('Invalid passkey options');
  expect(browser.get).not.toHaveBeenCalled();
});
it('does not invoke the authenticator for a wrong RP or weakened verification options',async()=>{
  const pending=options('login');pending.publicKey.rpId='other.example.test';vi.mocked(api).mockResolvedValueOnce(pending).mockResolvedValue({ok:true});
  await expect(performPasskey('login',{email:'fixture@example.test'})).rejects.toThrow('do not match');expect(browser.get).not.toHaveBeenCalled();
});
it('reports an ambiguous finish result without automatically retrying the action',async()=>{
  vi.mocked(api).mockResolvedValueOnce(options('register')).mockRejectedValueOnce(new Error('Cannot reach service')).mockResolvedValue({ok:true});
  await expect(performPasskey('register',{password:'public-fixture',label:'Device'})).rejects.toThrow('server did not confirm');
  expect(vi.mocked(api).mock.calls.filter(([path])=>path.endsWith('/finish'))).toHaveLength(1);
});
it('uses canonical base64url and refuses missing native buffers',()=>{
  expect(decodePasskey(encodePasskey(raw()))).toEqual(new Uint8Array([1,2,3]));
  expect(()=>decodePasskey('AQID=')).toThrow();expect(()=>decodePasskey('AB')).toThrow();expect(()=>encodePasskey(undefined)).toThrow();
});
