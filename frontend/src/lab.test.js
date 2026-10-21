import { describe, expect, it, vi } from "vitest";
import { webcrypto } from "node:crypto";
import { checkBreach, generatePassword } from "./lab";

describe("private password tools", () => {
  it("generates the requested length with cryptographic browser randomness", () => {
    vi.stubGlobal("crypto", webcrypto);
    expect(generatePassword()).toHaveLength(24);
    expect(generatePassword(64)).toHaveLength(64);
    expect(() => generatePassword(2)).toThrow();
    expect(generatePassword()).not.toBe(generatePassword());
  });
  it("only sends a five character prefix and requests padded anonymous responses", async () => {
    vi.stubGlobal("crypto", webcrypto);
    const password = "password";
    // SHA1(password)=5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8
    const fetcher = vi.fn(async () => ({
      ok: true,
      text: async () =>
        "1E4C9B93F3F0682250B6CF8331B7EE68FD8:42\r\n" + "0".repeat(35) + ":0",
    }));
    expect(await checkBreach(password, fetcher)).toBe(42);
    expect(fetcher).toHaveBeenCalledOnce();
    const [url, options] = fetcher.mock.calls[0];
    expect(url).toBe("https://api.pwnedpasswords.com/range/5BAA6");
    expect(options.headers["Add-Padding"]).toBe("true");
    expect(options.credentials).toBe("omit");
    expect(JSON.stringify(options)).not.toContain(password);
    expect(new URL(url).search).toBe("");
    expect(JSON.stringify(fetcher.mock.calls)).not.toContain("1E4C9B93");
  });
  it("treats failed and malformed lookups as not checked", async () => {
    vi.stubGlobal("crypto", webcrypto);
    await expect(
      checkBreach("fixture", async () => ({ ok: false })),
    ).rejects.toThrow("not checked");
    await expect(
      checkBreach("fixture", async () => ({
        ok: true,
        text: async () => "<html>service error</html>",
      })),
    ).rejects.toThrow("not checked");
  });
  it("does not treat padding count zero as a breach", async () => {
    vi.stubGlobal("crypto", webcrypto);
    expect(
      await checkBreach("password", async () => ({
        ok: true,
        text: async () => "1E4C9B93F3F0682250B6CF8331B7EE68FD8:0",
      })),
    ).toBe(0);
  });
  it('does not send an aborted prefix request or accept invalid counts',async()=>{
    vi.stubGlobal('crypto',webcrypto);const controller=new AbortController();controller.abort();const fetcher=vi.fn();
    await expect(checkBreach('password',fetcher,{signal:controller.signal})).rejects.toThrow();expect(fetcher).not.toHaveBeenCalled();
    await expect(checkBreach('password',async()=>({ok:true,text:async()=> '1E4C9B93F3F0682250B6CF8331B7EE68FD8:999999999999999999999'}))).rejects.toThrow('not checked');
  });
  it('rejects conflicting rows instead of trusting the first count',async()=>{
    vi.stubGlobal('crypto',webcrypto);
    await expect(checkBreach('password',async()=>({ok:true,text:async()=> '1E4C9B93F3F0682250B6CF8331B7EE68FD8:0\n1E4C9B93F3F0682250B6CF8331B7EE68FD8:42'}))).rejects.toThrow('not checked');
  });
  it('cancels an oversized streamed response before accepting a verdict',async()=>{
    vi.stubGlobal('crypto',webcrypto);const reader={read:vi.fn(async()=>({done:false,value:new Uint8Array(2000001)})),cancel:vi.fn(async()=>{}),releaseLock:vi.fn()};
    await expect(checkBreach('password',async()=>({ok:true,body:{getReader:()=>reader}}))).rejects.toThrow('not checked');
    expect(reader.cancel).toHaveBeenCalled();expect(reader.releaseLock).toHaveBeenCalled();
  });
});
