import { describe, expect, it } from "vitest";
import { parseCertificate, parsePem, PemError, signatureAlgorithm } from "./x509.ts";
import { inDays, keys, makeCert, privateKeyPem } from "./testcert.ts";

describe("parseCertificate", () => {
  it("reads names, dates, key and signature", () => {
    const c = makeCert({ cn: "shop.example.com", sans: ["shop.example.com", "www.shop.example.com"], ips: ["203.0.113.7"], notBefore: inDays(-10), notAfter: inDays(80), serial: 4096 });
    const p = parseCertificate(c.pem);
    expect(p).toMatchObject({ subjectCn: "shop.example.com", issuerCn: "shop.example.com", keyType: "rsa", keyBits: 2048, signature: "sha256WithRSAEncryption", isCa: false, selfSigned: true, serial: "1000" });
    expect(p.sans).toEqual(["DNS:shop.example.com", "DNS:www.shop.example.com", "IP:203.0.113.7"]);
    expect(p.id).toMatch(/^[0-9a-f]{64}$/);
    expect(Date.parse(p.notAfter) - Date.parse(p.notBefore)).toBeCloseTo(90 * 86_400_000, -4);
    expect(p.pem).toContain("BEGIN CERTIFICATE");
  });

  it("knows other key and signature kinds", () => {
    expect(parseCertificate(makeCert({ cn: "ec.example.com", keyKind: "ec" }).pem)).toMatchObject({ keyType: "ec", keyBits: 256, signature: "ecdsa-with-SHA256" });
    expect(parseCertificate(makeCert({ cn: "ed.example.com", keyKind: "ed25519" }).pem)).toMatchObject({ keyType: "ed25519", signature: "Ed25519" });
    expect(parseCertificate(makeCert({ cn: "old.example.com", hash: "sha1" }).pem).signature).toBe("sha1WithRSAEncryption");
    expect(signatureAlgorithm(makeCert({ cn: "x" }).der)).toBe("sha256WithRSAEncryption");
  });

  it("tells a certificate signed by another from a self-signed one", () => {
    const ca = makeCert({ cn: "Example Root CA", ca: true, keyKind: "rsa2048b" });
    const leaf = makeCert({ cn: "app.example.com", sans: ["app.example.com"], issuer: { cn: "Example Root CA", privateKey: ca.privateKey } });
    expect(parseCertificate(leaf.pem)).toMatchObject({ selfSigned: false, isCa: false, issuerCn: "Example Root CA" });
    expect(parseCertificate(ca.pem)).toMatchObject({ selfSigned: true, isCa: true });
  });

  it("warns about what is weak or unusual, and only for leaves where that applies", () => {
    const w = (o: Parameters<typeof makeCert>[0]) => parseCertificate(makeCert(o).pem).warnings;
    const ca = makeCert({ cn: "Example Root CA", ca: true, keyKind: "rsa2048b" });
    const signed = { issuer: { cn: "Example Root CA", privateKey: ca.privateKey } };
    expect(w({ cn: "a.example.com", ...signed })).toEqual([]);
    expect(w({ cn: "a.example.com", keyKind: "rsa1024", ...signed })).toEqual(["weak-key"]);
    expect(w({ cn: "a.example.com", hash: "sha1", ...signed })).toEqual(["weak-signature"]);
    expect(w({ cn: "*.example.com", sans: ["*.example.com"], ...signed })).toEqual(["wildcard"]);
    expect(w({ cn: "a.example.com", notAfter: inDays(500), ...signed })).toEqual(["long-lifetime"]);
    expect(w({ cn: "a.example.com" })).toEqual(["self-signed"]);
    // A root is self-signed and long-lived by nature.
    expect(w({ cn: "Example Root CA", ca: true, notAfter: inDays(3650) })).toEqual([]);
  });
});

describe("parsePem", () => {
  it("reads a chain in order", () => {
    const ca = makeCert({ cn: "Example Root CA", ca: true, keyKind: "rsa2048b" });
    const leaf = makeCert({ cn: "app.example.com", issuer: { cn: "Example Root CA", privateKey: ca.privateKey } });
    expect(parsePem(`${leaf.pem}\n${ca.pem}`).map((c) => c.subjectCn)).toEqual(["app.example.com", "Example Root CA"]);
  });

  it("refuses a private key before reading anything, whatever the kind, and never repeats it", () => {
    const cert = makeCert({ cn: "a.example.com" }).pem;
    for (const kind of ["rsa2048", "ec", "ed25519"] as const) {
      const key = privateKeyPem(kind);
      let message = "";
      try {
        parsePem(`${cert}\n${key}`);
      } catch (err) {
        expect(err).toBeInstanceOf(PemError);
        message = (err as Error).message;
      }
      expect(message).toMatch(/private key/);
      expect(message).not.toContain(key.split("\n")[1]!);
    }
    expect(() => parsePem("-----BEGIN RSA PRIVATE KEY-----\nAAAA\n-----END RSA PRIVATE KEY-----")).toThrow(/private key/);
    expect(() => parsePem("-----BEGIN ENCRYPTED PRIVATE KEY-----\nAAAA\n-----END ENCRYPTED PRIVATE KEY-----")).toThrow(/private key/);
  });

  it("refuses what is not a certificate", () => {
    expect(() => parsePem("hello")).toThrow(/No certificate/);
    expect(() => parsePem("-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----")).toThrow(/Certificate 1 could not be read/);
    expect(keys("rsa1024")).toBeDefined();
  });
});
