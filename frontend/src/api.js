let csrf = "";
export function setCsrf(value) {
  csrf = value || "";
}
export async function api(path, body) {
  let response;
  try { response = await fetch("/api" + path, {
    credentials: "same-origin",
    method: body === undefined ? "GET" : "POST",
    headers:
      body === undefined
        ? {}
        : { "Content-Type": "application/json", "X-CSRF-Token": csrf },
    ...(body === undefined ? {} : { body: JSON.stringify(body) }),
  }); } catch { throw new Error('Cannot reach SentinelOps. Keep the local app running, then retry.'); }
  const value = await response.json();
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
