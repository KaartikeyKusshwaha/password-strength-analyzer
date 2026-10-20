import { expect, it, vi } from 'vitest';
import { allowConnection, prepareConnection, restoreConnection, verifyConnection } from '../../companion/extension/connection';

const origin = 'http://127.0.0.1:8110';
const token = 'fixture_'.repeat(7);
const valid = async () => ({ ok: true, status: 200, json: async () => ({ revision: 1, envelope: { version: 1 } }) });
function browser(granted = false) {
  const values = {};
  return { values,
    storage: { local: {
      get: vi.fn(async () => ({ ...values })),
      set: vi.fn(async data => Object.assign(values, data)),
      remove: vi.fn(async key => { delete values[key]; }),
    } },
    permissions: {
      contains: vi.fn(async () => granted),
      request: vi.fn(async () => { granted = true; return true; }),
    },
  };
}
it('persists pending pairing before requesting any permission', async () => {
  const b = browser();
  const result = await prepareConnection(b, ' ' + origin + '/ ', ' ' + token + ' ', valid);
  expect(result).toEqual({ connection: null, pending: { origin, token } });
  expect(b.values.pendingConnection).toEqual({ origin, token });
  expect(b.permissions.request).not.toHaveBeenCalled();
});
it('recovers when popup closes during permission approval', async () => {
  const b = browser();
  await prepareConnection(b, origin, token, valid);
  await b.permissions.request({ origins: ['http://127.0.0.1/*'] });
  const fetcher = vi.fn(valid);
  const result = await restoreConnection(b, fetcher);
  expect(result.connection).toEqual({ origin, token });
  expect(b.values.pendingConnection).toBeUndefined();
  expect(fetcher.mock.calls[0][1]).toMatchObject({ credentials: 'omit', redirect: 'error', headers: { Authorization: 'Bearer ' + token } });
  expect((await restoreConnection(b, fetcher)).connection).toEqual({ origin, token });
  expect(fetcher).toHaveBeenCalledTimes(1);
});
it('requests permission synchronously on the allow click and validates before connecting', async () => {
  const b = browser();
  const pending = (await prepareConnection(b, origin, token, valid)).pending;
  const promise = allowConnection(b, pending, valid);
  expect(b.permissions.request).toHaveBeenCalledTimes(1);
  expect((await promise).connection).toEqual(pending);
});
it('retains pending state when access is denied or the server is offline', async () => {
  const b = browser();
  const pending = (await prepareConnection(b, origin, token, valid)).pending;
  b.permissions.request.mockResolvedValue(false);
  await expect(allowConnection(b, pending, valid)).rejects.toThrow('declined');
  b.permissions.contains.mockResolvedValue(true);
  await expect(restoreConnection(b, async () => { throw new TypeError('offline'); })).rejects.toThrow('Could not reach');
  expect(b.values.connection).toBeUndefined();
  expect(b.values.pendingConnection).toEqual(pending);
});
it('never saves an active connection for a rejected token or unexpected server response', async () => {
  for (const fetcher of [
    async () => ({ status: 401 }),
    async () => ({ status: 200, ok: true, json: async () => ({}) }),
    async () => ({ status: 200, ok: true, json: async () => ({ revision: 0, envelope: null }) }),
  ]) {
    const b = browser(true);
    await expect(prepareConnection(b, origin, token, fetcher)).rejects.toThrow();
    expect(b.values.connection).toBeUndefined();
    expect(b.values.pendingConnection).toBeTruthy();
  }
});
it('reports storage failures without claiming a connection and can recover the pending record', async () => {
  const b = browser();
  await prepareConnection(b, origin, token, valid);
  b.permissions.contains.mockResolvedValue(true);
  b.storage.local.set.mockRejectedValueOnce(new Error('Storage unavailable'));
  await expect(restoreConnection(b, valid)).rejects.toThrow('Storage unavailable');
  expect(b.values.connection).toBeUndefined();
  expect((await restoreConnection(b, valid)).connection).toEqual({ origin, token });
});
it('rejects a sign-in password as token before storing or contacting anything', async () => {
  const b = browser(true), fetcher = vi.fn(valid);
  await expect(prepareConnection(b, origin, 'not-a-companion-token', fetcher)).rejects.toThrow('complete companion token');
  expect(b.storage.local.set).not.toHaveBeenCalled();
  expect(fetcher).not.toHaveBeenCalled();
});
it('does not include a token in a connection error', async () => {
  await expect(verifyConnection({ origin, token }, async () => ({ status: 401 }))).rejects.toThrow('expired, revoked or incorrect');
});
it('keeps different vault connections and replaces only the renewed connection for the same vault',async()=>{
  const b=browser(true);
  const response=vault=>async()=>({ok:true,status:200,json:async()=>({revision:1,envelope:{version:1},vault})});
  await prepareConnection(b,origin,token,response({id:'personal',name:'Personal'}));
  await prepareConnection(b,origin,token+'x',response({id:'work',name:'Work'}));
  expect(b.values.connections).toHaveLength(2);
  expect(b.values.connection.vaultId).toBe('work');
  await prepareConnection(b,origin,token+'y',response({id:'work',name:'Work'}));
  expect(b.values.connections).toHaveLength(2);
  expect(b.values.connections.find(c=>c.vaultId==='personal').token).toBe(token);
  expect(b.values.connections.find(c=>c.vaultId==='work').token).toBe(token+'y');
});
it('remembers a shared vault scope without treating the server fingerprint as verified trust',async()=>{
  const b=browser(true),fingerprint='a'.repeat(64);
  const fetcher=async()=>({ok:true,status:200,json:async()=>({kind:'shared',revision:1,envelope:{version:1},vault:{kind:'shared',id:'shared',name:'Client',owner_fingerprint:fingerprint,owner_is_self:false},sharing:{identity:{encrypted:{ciphertext:'opaque'}},team:{accepted:true}}})});
  const result=await prepareConnection(b,origin,token,fetcher);
  expect(result.connection).toMatchObject({vaultId:'shared',vaultKind:'shared',ownerFingerprint:fingerprint,ownerIsSelf:false});
  expect(JSON.stringify(b.values)).not.toContain('opaque');expect(result.connection.trustedFingerprint).toBeUndefined();
});
