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

export async function checkBreach(password, fetcher = fetch) {
  const hash = await crypto.subtle.digest(
    "SHA-1",
    new TextEncoder().encode(password),
  );
  const hex = Array.from(new Uint8Array(hash), (byte) =>
    byte.toString(16).padStart(2, "0"),
  )
    .join("")
    .toUpperCase();
  const response = await fetcher(
    "https://api.pwnedpasswords.com/range/" + hex.slice(0, 5),
    {
      headers: { "Add-Padding": "true" },
      credentials: "omit",
      referrerPolicy: "no-referrer",
    },
  );
  if (!response.ok)
    throw new Error("Breach service unavailable. Password was not checked.");
  const text = await response.text();
  if (text.length > 2000000)
    throw new Error("Unsupported breach response. Password was not checked.");
  const rows = text.trim().split(/\r?\n/);
  if (!rows.length || rows.some((row) => !/^[0-9A-F]{35}:\d+$/.test(row)))
    throw new Error("Invalid breach response. Password was not checked.");
  const match = rows.find((row) => row.split(":")[0] === hex.slice(5));
  return match ? Number(match.split(":")[1]) : 0;
}
