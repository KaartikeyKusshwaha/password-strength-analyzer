export function generatePassword(length = 24) {
  if (!Number.isInteger(length) || length < 15 || length > 128)
    throw new Error("Choose 15–128 characters.");
  const alphabet =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%&*_-+";
  const cutoff = Math.floor(256 / alphabet.length) * alphabet.length;
  let result = "";
  while (result.length < length) {
    const bytes = crypto.getRandomValues(new Uint8Array(128));
    for (const byte of bytes)
      if (byte < cutoff && result.length < length)
        result += alphabet[byte % alphabet.length];
  }
  return result;
}

export async function checkBreach(password, fetcher = (...args)=>globalThis.fetch(...args), options = {}) {
  if(typeof password!=='string'||!password.length||password.length>256)throw new Error('Unsupported password. Password was not checked.');
  const signal=AbortSignal.any([AbortSignal.timeout(10000),...(options.signal?[options.signal]:[])]);
  signal.throwIfAborted();
  const hash = await crypto.subtle.digest(
    "SHA-1",
    new TextEncoder().encode(password),
  );
  const hex = Array.from(new Uint8Array(hash), (byte) =>
    byte.toString(16).padStart(2, "0"),
  )
    .join("")
    .toUpperCase();
  signal.throwIfAborted();
  const response = await fetcher(
    "https://api.pwnedpasswords.com/range/" + hex.slice(0, 5),
    {
      headers: { "Add-Padding": "true" },
      credentials: "omit",
      referrerPolicy: "no-referrer",
      redirect: "error",
      cache: "no-store",
      signal,
    },
  );
  if (!response.ok)
    throw new Error("Breach service unavailable. Password was not checked.");
  let text;
  if(response.body?.getReader){
    const reader=response.body.getReader(),decoder=new TextDecoder();let size=0;text='';
    try{while(true){signal.throwIfAborted();const chunk=await reader.read();if(chunk.done)break;size+=chunk.value.byteLength;if(size>2000000)throw new Error('Unsupported breach response. Password was not checked.');text+=decoder.decode(chunk.value,{stream:true});}text+=decoder.decode();}
    catch(error){await reader.cancel().catch(()=>{});throw error;}finally{reader.releaseLock();}
  }else text=await response.text();
  signal.throwIfAborted();
  if (text.length > 2000000)
    throw new Error("Unsupported breach response. Password was not checked.");
  const rows = text.trim().split(/\r?\n/);
  if (!rows.length || rows.some((row) => !/^[0-9A-F]{35}:\d+$/.test(row)||!Number.isSafeInteger(Number(row.split(':')[1]))))
    throw new Error("Invalid breach response. Password was not checked.");
  if(new Set(rows.map(row=>row.split(':')[0])).size!==rows.length)throw new Error('Ambiguous breach response. Password was not checked.');
  const match = rows.find((row) => row.split(":")[0] === hex.slice(5));
  return match ? Number(match.split(":")[1]) : 0;
}
