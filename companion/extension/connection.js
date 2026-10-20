import { serviceOrigin } from './policy';
import manifest from './public/manifest.json';

export function normalizeConnection(origin, token) {
  const connection = { origin: serviceOrigin(origin.trim()), token: token.trim() };
  if (!/^[A-Za-z0-9_-]{40,100}$/.test(connection.token)) {
    throw new Error('Copy the complete companion token from Browser & devices. Do not use your sign-in password or master passphrase.');
  }
  return connection;
}

export function hostPermission(connection) {
  const url = new URL(connection.origin);
  return { origins: [url.protocol + '//' + url.hostname + '/*'] };
}

export async function verifyConnection(connection, fetcher = fetch) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 8000);
  try {
    const response = await fetcher(connection.origin + '/api/companion/vault', {
      method: 'GET', credentials: 'omit', redirect: 'error',
      headers: { Authorization: 'Bearer ' + connection.token, 'X-Sentinel-Companion-Version':manifest.version },
      signal: controller.signal,
    });
    if (response.status === 401) throw new Error('This companion token is expired, revoked or incorrect. Create a fresh token in Browser & devices.');
    if (!response.ok) throw new Error('SentinelOps rejected the connection. Check that the app origin is correct and try again.');
    const value = await response.json();
    if (!Number.isInteger(value.revision) || value.revision < 0 || !('envelope' in value)) throw new Error('This address did not return a SentinelOps vault response. Check the app origin.');
    if (!value.envelope) throw new Error('Create your personal vault in the SentinelOps dashboard, then return and verify the connection.');
    if(value.kind==='shared' && (!value.sharing?.identity?.encrypted || !value.sharing?.team?.accepted))throw new Error('Accept the shared vault invitation and create your sharing identity in the dashboard first.');
    return value.vault || null;
  } catch (error) {
    if (error.name === 'AbortError' || error instanceof TypeError) throw new Error('Could not reach SentinelOps. Keep the local app running, check the origin, and allow the requested app access. Your pending pairing is retained.');
    throw error;
  } finally { clearTimeout(timer); }
}

// A pending token is durable before any permission prompt opens. Reopening the
// popup can finish a granted connection without asking the user to paste again.
export async function restoreConnection(browser, fetcher = fetch) {
  const saved = await browser.storage.local.get(['connection', 'pendingConnection', 'connections']);
  if (!saved.pendingConnection) return { connection: saved.connection || null, pending: null };
  const pending = normalizeConnection(saved.pendingConnection.origin, saved.pendingConnection.token);
  if (!await browser.permissions.contains(hostPermission(pending))) return { connection: null, pending };
  const vault = await verifyConnection(pending, fetcher);
  const connection = {...pending, ...(vault ? {vaultId:vault.id,vaultName:vault.name,...(vault.kind==='shared'?{vaultKind:'shared',ownerFingerprint:vault.owner_fingerprint,ownerIsSelf:vault.owner_is_self}: {})} : {})};
  // Set active state before removing pending state. Either durable state can
  // recover if the popup closes between these two writes.
  const previous = saved.connections || (saved.connection ? [saved.connection] : []);
  const connections = [...previous.filter(item => !(item.origin === connection.origin && (connection.vaultId ? item.vaultId === connection.vaultId && (item.vaultKind || 'personal')===(connection.vaultKind || 'personal') : item.token === connection.token))), connection];
  await browser.storage.local.set({ connection, connections });
  await browser.storage.local.remove('pendingConnection');
  return { connection, pending: null };
}

export async function prepareConnection(browser, origin, token, fetcher = fetch) {
  const pending = normalizeConnection(origin, token);
  await browser.storage.local.set({ pendingConnection: pending });
  return restoreConnection(browser, fetcher);
}

export async function allowConnection(browser, pending, fetcher = fetch) {
  // Must be invoked directly from the user click; no await before request().
  const granted = await browser.permissions.request(hostPermission(pending));
  if (!granted) throw new Error('App access was declined. Pairing details are retained. Choose Allow app access to try again.');
  return restoreConnection(browser, fetcher);
}
