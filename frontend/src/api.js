import {reportConnection} from './connection-state';
let csrf = "";
export function setCsrf(value) {
  csrf = value || "";
}
export async function api(path, body, {requestId} = {}) {
  let response;
  try { response = await fetch("/api" + path, {
    credentials: "same-origin",
    method: body === undefined ? "GET" : "POST",
    headers:
      body === undefined
        ? {}
        : { "Content-Type": "application/json", "X-CSRF-Token": csrf, ...(requestId?{'X-Passkey-Request':requestId}:{}) },
    ...(body === undefined ? {} : { body: JSON.stringify(body) }),
  }); } catch { reportConnection('unavailable');throw new Error('Cannot reach SentinelOps. Keep the local app running, then retry.'); }
  let value;
  try {value=await response.json();}
  catch {reportConnection('error');throw new Error('SentinelOps returned an unexpected response. Retry when the service is available.');}
  reportConnection(response.status>=500?'error':'available');
  if (!response.ok) {
    const error = new Error(
      typeof value.detail === "string" ? value.detail : "Request failed",
    );
    error.status = response.status;
    throw error;
  }
  if (value.csrf) setCsrf(value.csrf);
  return value;
}
