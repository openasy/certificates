import { describe, expect, it } from "vitest";
import { fetchChain, isPrivate, resolvePublic, validHost } from "./probe.ts";

describe("isPrivate", () => {
  it("knows addresses the server must not connect to", () => {
    for (const a of [
      "127.0.0.1",
      "10.1.2.3",
      "172.16.0.1",
      "172.31.255.255",
      "192.168.1.1",
      "169.254.169.254",
      "100.64.0.1",
      "0.0.0.0",
      "::1",
      "fd00::1",
      "fe80::1",
      "::ffff:10.0.0.1",
      "224.0.0.1",
    ])
      expect(isPrivate(a), a).toBe(true);
    for (const a of ["8.8.8.8", "172.32.0.1", "93.184.216.34", "2606:4700:4700::1111"]) expect(isPrivate(a), a).toBe(false);
  });
});

describe("validHost", () => {
  it("takes names and addresses, and nothing that could be something else", () => {
    for (const h of ["example.com", "a-b.example.co.uk", "203.0.113.5", "2606:4700:4700::1111", "localhost"]) expect(validHost(h), h).toBe(true);
    for (const h of ["", "bad host", "a_b.example.com", "-a.example.com", "http://example.com", "example.com/path", "12345", "a".repeat(64) + ".com"])
      expect(validHost(h), h).toBe(false);
  });
});

describe("resolvePublic and fetchChain", () => {
  it("refuses private addresses without connecting, even when a name mixes them in", async () => {
    await expect(resolvePublic("127.0.0.1")).rejects.toThrow(/private address/);
    await expect(resolvePublic("x.example.com", { resolve: async () => ["8.8.8.8", "10.0.0.1"] })).rejects.toThrow(/private address/);
    await expect(resolvePublic("x.example.com", { resolve: async () => [] })).rejects.toThrow(/does not resolve/);
    await expect(fetchChain("169.254.169.254", 443)).rejects.toThrow(/private address/);
    await expect(fetchChain("localhost", 1)).rejects.toThrow(/private address/);
  });
  it("lets a test reach loopback only by asking for it", async () => {
    await expect(resolvePublic("127.0.0.1", { allowPrivate: true })).resolves.toBe("127.0.0.1");
  });
});
