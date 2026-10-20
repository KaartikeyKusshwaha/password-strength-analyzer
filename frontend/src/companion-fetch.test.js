import {afterEach,expect,it,vi} from 'vitest';
import {SaveSession} from '../../companion/extension/vault-session';
import manifest from '../../companion/extension/public/manifest.json';

afterEach(()=>vi.unstubAllGlobals());

it('calls browser fetch with its global receiver rather than the vault session',async()=>{
  const fetch=vi.fn(function(url,options){
    if(this!==globalThis)throw new TypeError("Failed to execute 'fetch' on 'Window': Illegal invocation");
    expect(url).toBe('http://127.0.0.1:8110/api/companion/vault');
    expect(options.credentials).toBe('omit');
    expect(options.redirect).toBe('error');
    expect(options.headers['X-Sentinel-Companion-Version']).toBe(manifest.version);
    return Promise.resolve({ok:true,status:200,json:async()=>({revision:2})});
  });
  vi.stubGlobal('fetch',fetch);
  const session=new SaveSession({});
  session.config={origin:'http://127.0.0.1:8110',token:'test-only'};
  await expect(session.request()).resolves.toEqual({revision:2});
  expect(fetch).toHaveBeenCalledTimes(1);
  expect(session.pending.size).toBe(0);
});

it('does not bind an injected transport to the vault session',async()=>{
  const transport=vi.fn(function(){
    expect(this).toBeUndefined();
    return Promise.resolve({ok:false,status:401});
  });
  const session=new SaveSession({},transport);
  session.config={origin:'http://127.0.0.1:8110',token:'test-only'};
  await expect(session.request()).rejects.toThrow('expired or was revoked');
  expect(session.pending.size).toBe(0);
});
