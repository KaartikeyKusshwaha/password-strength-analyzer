// Shared by the dashboard and browser companion. No network calls in this module.
import {validateHistory} from './entry-history';
const encoder = new TextEncoder();
const aad = encoder.encode("SentinelOps personal vault v1");
export const ITERATIONS = 600000;
export function to64(bytes) {
  return btoa(String.fromCharCode(...bytes));
}
export function from64(value) {
  return Uint8Array.from(atob(value), (c) => c.charCodeAt(0));
}
export function validOrigin(value) {
  const url = new URL(value);
  if (url.protocol !== "https:" || url.username || url.password)
    throw new Error("Use an HTTPS website origin.");
  return url.origin;
}
export async function deriveKey(password, salt) {
  if ([...password].length < 15 || password.length > 256)
    throw new Error("Use a separate master passphrase of 15–256 characters.");
  const material = await crypto.subtle.importKey(
    "raw",
    encoder.encode(password),
    "PBKDF2",
    false,
    ["deriveKey"],
  );
  return crypto.subtle.deriveKey(
    { name: "PBKDF2", salt, iterations: ITERATIONS, hash: "SHA-256" },
    material,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"],
  );
}
export function validateEntries(entries) {
  if (!Array.isArray(entries) || entries.length > 200)
    throw new Error("Vault supports at most 200 entries.");
  const ids = new Set();
  for (const item of entries) {
    if (
      !item ||
      typeof item.id !== "string" ||
      ids.has(item.id) ||
      !["login", "totp"].includes(item.type) ||
      typeof item.title !== "string" ||
      item.title.length > 100
    )
      throw new Error("Unsupported vault entry.");
    ids.add(item.id);
    validateHistory(item.history);
    if (item.type === "login") {
      validOrigin(item.origin);
      if (
        typeof item.username !== "string" ||
        item.username.length > 254 ||
        typeof item.password !== "string" ||
        item.password.length > 256
      )
        throw new Error("Invalid login entry.");
      if(item.pending_change!==undefined) {
        const pending=item.pending_change;
        if(!pending || Object.keys(pending).sort().join(',')!=='action_id,created_at,password' || !/^[a-f0-9]{24}$/.test(pending.action_id) || typeof pending.password!=='string' || !pending.password.length || pending.password.length>256 || typeof pending.created_at!=='string' || pending.created_at.length>40 || !Number.isFinite(Date.parse(pending.created_at)))throw new Error('Invalid pending password change.');
      }
      if(item.change_receipt!==undefined) {
        const receipt=item.change_receipt;
        if(!receipt || Object.keys(receipt).sort().join(',')!=='action_id,confirmed_at' || !/^[a-f0-9]{24}$/.test(receipt.action_id) || typeof receipt.confirmed_at!=='string' || receipt.confirmed_at.length>40 || !Number.isFinite(Date.parse(receipt.confirmed_at)))throw new Error('Invalid password change receipt.');
      }
    } else {
      decodeBase32(item.secret);
      if (
        ![6, 8].includes(item.digits) ||
        ![30, 60].includes(item.period) ||
        !["SHA-1", "SHA-256", "SHA-512"].includes(item.algorithm)
      )
        throw new Error("Unsupported TOTP parameters.");
    }
  }
  return entries;
}
export async function encryptVault(entries, key, salt) {
  if (salt?.version === 2) return (await import('./vault-v2')).encryptProtected(entries,key,salt);
  validateEntries(entries);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const plaintext = encoder.encode(JSON.stringify({ entries }));
  if (plaintext.length > 85000)
    throw new Error(
      "Vault is too large for this pilot. Export a backup before removing entries.",
    );
  const ciphertext = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv, additionalData: aad },
    key,
    plaintext,
  );
  const bytes = new Uint8Array(ciphertext);
  // Chunked encoding avoids argument-count limits for larger encrypted vaults.
  let binary = "";
  for (let offset = 0; offset < bytes.length; offset += 8192)
    binary += String.fromCharCode(...bytes.subarray(offset, offset + 8192));
  return {
    version: 1,
    salt: to64(salt),
    iv: to64(iv),
    ciphertext: btoa(binary),
  };
}
export async function unlockVault(envelope, password) {
  if (envelope?.version === 2) return (await import('./vault-v2')).unlockProtected(envelope,password);
  if (
    !envelope ||
    envelope.version !== 1 ||
    typeof envelope.ciphertext !== "string" ||
    envelope.ciphertext.length > 125000
  )
    throw new Error("Unsupported encrypted vault.");
  try {
    const salt = from64(envelope.salt),
      iv = from64(envelope.iv);
    if (salt.length !== 16 || iv.length !== 12) throw new Error();
    const key = await deriveKey(password, salt);
    const decrypted = await crypto.subtle.decrypt(
      { name: "AES-GCM", iv, additionalData: aad },
      key,
      from64(envelope.ciphertext),
    );
    const entries = validateEntries(
      JSON.parse(new TextDecoder().decode(decrypted)).entries,
    );
    return { key, salt, entries };
  } catch {
    throw new Error(
      "Could not unlock. Check the master passphrase and encrypted backup integrity.",
    );
  }
}
export async function decryptWithKey(envelope, key, salt) {
  if (envelope?.version === 2) return (await import('./vault-v2')).decryptProtected(envelope,key,salt);
  if (!envelope || envelope.version !== 1 || envelope.salt !== to64(salt) || typeof envelope.ciphertext !== 'string' || envelope.ciphertext.length > 125000) throw new Error('Vault encryption changed. Lock and unlock again.');
  const iv = from64(envelope.iv);
  if (iv.length !== 12) throw new Error('Invalid vault envelope.');
  const plain = await crypto.subtle.decrypt({name:'AES-GCM',iv,additionalData:aad},key,from64(envelope.ciphertext));
  return validateEntries(JSON.parse(new TextDecoder().decode(plain)).entries);
}
export function decodeBase32(value) {
  if (typeof value !== "string") throw new Error("Enter a Base32 setup key.");
  const cleaned = value.replace(/\s/g, "").replace(/=+$/, "").toUpperCase();
  if (!/^[A-Z2-7]{16,128}$/.test(cleaned))
    throw new Error("Enter a valid Base32 setup key (16–128 characters).");
  let bits = 0,
    buffer = 0;
  const bytes = [];
  for (const c of cleaned) {
    buffer = (buffer << 5) | "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567".indexOf(c);
    bits += 5;
    if (bits >= 8) {
      bits -= 8;
      bytes.push((buffer >> bits) & 255);
    }
  }
  return new Uint8Array(bytes);
}
export function parseOtpAuth(value) {
  if (!value.startsWith("otpauth://"))
    return {
      secret: value.replace(/\s/g, "").replace(/=+$/, "").toUpperCase(),
      digits: 6,
      period: 30,
      algorithm: "SHA-1",
    };
  const url = new URL(value);
  if (url.hostname !== "totp")
    throw new Error(
      "Only time-based TOTP accounts are supported; HOTP is not supported.",
    );
  const algorithm = (url.searchParams.get("algorithm") || "SHA1")
    .toUpperCase()
    .replace("SHA", "SHA-");
  const result = {
    secret: (url.searchParams.get("secret") || "")
      .replace(/=+$/, "")
      .toUpperCase(),
    digits: Number(url.searchParams.get("digits") || 6),
    period: Number(url.searchParams.get("period") || 30),
    algorithm,
  };
  decodeBase32(result.secret);
  if (
    ![6, 8].includes(result.digits) ||
    ![30, 60].includes(result.period) ||
    !["SHA-1", "SHA-256", "SHA-512"].includes(algorithm)
  )
    throw new Error(
      "Supported: SHA1/256/512, 6 or 8 digits, 30 or 60 second periods.",
    );
  return result;
}
export async function generateTotp(item, at = Date.now()) {
  const bytes = new Uint8Array(8);
  let count = BigInt(Math.floor(at / 1000 / item.period));
  for (let i = 7; i >= 0; i--) {
    bytes[i] = Number(count & 255n);
    count >>= 8n;
  }
  const key = await crypto.subtle.importKey(
    "raw",
    decodeBase32(item.secret),
    { name: "HMAC", hash: item.algorithm },
    false,
    ["sign"],
  );
  const mac = new Uint8Array(await crypto.subtle.sign("HMAC", key, bytes));
  const offset = mac.at(-1) & 15;
  const number =
    ((mac[offset] & 127) * 2 ** 24 +
      (mac[offset + 1] << 16) +
      (mac[offset + 2] << 8) +
      mac[offset + 3]) %
    10 ** item.digits;
  return String(number).padStart(item.digits, "0");
}
