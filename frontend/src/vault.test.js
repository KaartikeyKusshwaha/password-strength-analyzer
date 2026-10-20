import { beforeEach, describe, expect, it, vi } from "vitest";
import { webcrypto } from "node:crypto";
import {
  deriveKey,
  encryptVault,
  unlockVault,
  parseOtpAuth,
  generateTotp,
  validOrigin,
  validateEntries,
  decryptWithKey,
} from "./vault-crypto";
beforeEach(() => vi.stubGlobal("crypto", webcrypto));
const master = "Fixture-only!sunlight-harbor-72";
const entry = {
  id: "fixture-login",
  type: "login",
  title: "Fixture account",
  origin: "https://accounts.example.test",
  username: "fixture-user",
  password: "Fixture-only-password-secret",
};
describe("encrypted personal vault", () => {
  it('refreshes data saved by a companion with the existing local key and rejects a replacement vault', async () => {
    const salt=webcrypto.getRandomValues(new Uint8Array(16)), key=await deriveKey(master,salt);
    const updated=await encryptVault([entry],key,salt);
    expect(await decryptWithKey(updated,key,salt)).toEqual([entry]);
    await expect(decryptWithKey(updated,key,webcrypto.getRandomValues(new Uint8Array(16)))).rejects.toThrow('encryption changed');
  });
  it("round trips with a nonextractable key and randomized authenticated encryption", async () => {
    const salt = webcrypto.getRandomValues(new Uint8Array(16)),
      key = await deriveKey(master, salt);
    expect(key.extractable).toBe(false);
    const first = await encryptVault([entry], key, salt),
      second = await encryptVault([entry], key, salt);
    expect(first.iv).not.toBe(second.iv);
    expect(first.ciphertext).not.toBe(second.ciphertext);
    expect(JSON.stringify(first)).not.toContain(entry.password);
    expect(JSON.stringify(first)).not.toContain(entry.username);
    const result = await unlockVault(first, master);
    expect(result.entries).toEqual([entry]);
    await expect(
      unlockVault(first, "Wrong-master-fixture-only-123"),
    ).rejects.toThrow("Could not unlock");
    const changed = {
      ...first,
      ciphertext:
        (first.ciphertext[0] === "A" ? "B" : "A") + first.ciphertext.slice(1),
    };
    await expect(unlockVault(changed, master)).rejects.toThrow(
      "Could not unlock",
    );
  });
  it("rejects unsupported entries and non-HTTPS origins", () => {
    expect(() => validOrigin("http://example.test")).toThrow();
    expect(() => validOrigin("https://user:pass@example.test")).toThrow();
    expect(
      validOrigin("https://accounts.example.test/login?secret=omitted"),
    ).toBe("https://accounts.example.test");
    expect(() => validateEntries([entry, entry])).toThrow();
    expect(() => validateEntries([{ ...entry, password: [] }])).toThrow();
    expect(() =>
      validateEntries([
        {
          id: "id",
          type: "totp",
          title: "Invalid",
          secret: "short",
          digits: 6,
          period: 30,
          algorithm: "SHA-1",
        },
      ]),
    ).toThrow();
  });
});
describe("external account TOTP compatibility", () => {
  it("matches RFC 6238 at the standard test timestamp", async () => {
    const entry = {
      secret: "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ",
      algorithm: "SHA-1",
      digits: 8,
      period: 30,
    };
    expect(await generateTotp(entry, 59000)).toBe("94287082");
    expect(await generateTotp({ ...entry, digits: 6 }, 59000)).toBe("287082");
  });
  it("parses standard enrollment URIs and rejects unsupported HOTP", () => {
    const item = parseOtpAuth(
      "otpauth://totp/Example:fixture?secret=JBSWY3DPEHPK3PXP&issuer=Example&algorithm=SHA256&digits=8&period=60",
    );
    expect(item).toEqual({
      secret: "JBSWY3DPEHPK3PXP",
      algorithm: "SHA-256",
      digits: 8,
      period: 60,
    });
    expect(() =>
      parseOtpAuth("otpauth://hotp/Example?secret=JBSWY3DPEHPK3PXP&counter=1"),
    ).toThrow();
    expect(() =>
      parseOtpAuth("otpauth://totp/Example?secret=JBSWY3DPEHPK3PXP&period=5"),
    ).toThrow();
  });
});
