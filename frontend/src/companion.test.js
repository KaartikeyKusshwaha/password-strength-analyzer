import { expect, it } from "vitest";
import { mayFill, serviceOrigin } from "../../companion/extension/policy";

it("never fills related subdomains, HTTP pages or cross-origin form destinations", () => {
  const origin = "https://accounts.example.test";
  expect(mayFill(origin, origin + "/login", "/session")).toBe(true);
  expect(mayFill(origin, "https://evil.accounts.example.test/login")).toBe(
    false,
  );
  expect(mayFill(origin, "https://accounts.example.test.evil.test/login")).toBe(
    false,
  );
  expect(mayFill(origin, "http://accounts.example.test/login")).toBe(false);
  expect(mayFill(origin, origin + "/login", "https://evil.test/collect")).toBe(
    false,
  );
  expect(mayFill(origin, origin + "/login", "javascript:alert(1)")).toBe(false);
});
it("pairs only with explicit HTTPS app origins or local loopback origins", () => {
  expect(serviceOrigin("http://127.0.0.1:8110")).toBe("http://127.0.0.1:8110");
  expect(serviceOrigin("https://security.example.test")).toBe(
    "https://security.example.test",
  );
  for (const value of [
    "http://example.test",
    "https://user:pass@example.test",
    "https://example.test/steal",
    "https://example.test?key=secret",
    "file:///tmp/vault",
  ])
    expect(() => serviceOrigin(value)).toThrow();
});
