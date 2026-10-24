import { createServer as tlsServer, type Server as TlsServer } from "node:tls";
import type { AddressInfo } from "node:net";
import { gzipSync } from "node:zlib";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { fileId, parseEndpoints } from "./endpoints.ts";
import { startApp } from "./test-app.ts";
import { inDays, makeCert, privateKeyPem } from "./testcert.ts";

let app: Awaited<ReturnType<typeof startApp>>;
beforeAll(async () => {
  app = await startApp({ version: "0.1.0" });
});
afterAll(() => app.close());

const json = async (res: Response) => (await res.json()) as any;
const ca = makeCert({ cn: "Example Root CA", ca: true, keyKind: "rsa2048b", notAfter: inDays(3000) });
const signed = { issuer: { cn: "Example Root CA", privateKey: ca.privateKey } };
const shop = makeCert({ cn: "shop.example.com", sans: ["shop.example.com", "www.shop.example.com"], notAfter: inDays(80), ...signed });
const names = async (query = "") => (await json(await app.admin(`/api/v1/certificates${query}`))).certificates.map((c: { commonName: string }) => c.commonName);

describe("sending certificates", () => {
  it("takes PEM text and keeps what is public about it", async () => {
    const res = await app.send(shop.pem, "web-1:443");
    expect(res.status).toBe(201);
    const { certificates, added } = await json(res);
    expect(added).toBe(1);
    expect(certificates[0]).toMatchObject({
      commonName: "shop.example.com",
      names: ["DNS:shop.example.com", "DNS:www.shop.example.com"],
      issuerCommonName: "Example Root CA",
      state: "valid",
      daysLeft: expect.any(Number),
      keyType: "rsa",
      keyBits: 2048,
      signature: "sha256WithRSAEncryption",
      ca: false,
      selfSigned: false,
      warnings: [],
      sources: [{ source: "web-1:443", position: 0, lastSeen: expect.any(String) }],
    });
    expect(certificates[0].daysLeft).toBeGreaterThanOrEqual(79);
  });

  it("knows a certificate it has seen, and adds the new place", async () => {
    const again = await json(await app.send(shop.pem, "/etc/ssl/shop.pem"));
    expect(again.added).toBe(0);
    expect(again.certificates[0].sources.map((s: { source: string }) => s.source).sort()).toEqual(["/etc/ssl/shop.pem", "web-1:443"]);
    expect(await names()).toEqual(["shop.example.com"]);
  });

  it("takes JSON with a source, gzip, and a chain with the position of each", async () => {
    const leaf = makeCert({ cn: "api.example.com", sans: ["api.example.com"], notAfter: inDays(60), ...signed });
    const res = await app.ingest("/api/v1/certificates", {
      method: "POST",
      body: gzipSync(JSON.stringify({ pem: `${leaf.pem}\n${ca.pem}`, source: "lb-1:443" })),
      headers: { "content-encoding": "gzip" },
    });
    const body = await json(res);
    expect(body.added).toBe(2);
    expect(body.certificates.map((c: any) => [c.commonName, c.sources[0].position, c.ca])).toEqual([
      ["api.example.com", 0, false],
      ["Example Root CA", 1, true],
    ]);
    const detail = await json(await app.admin(`/api/v1/certificates/${body.certificates[0].id}`));
    expect(detail.pem).toContain("BEGIN CERTIFICATE");
    expect(detail.chain.map((c: any) => c.commonName)).toEqual(["Example Root CA"]);
  });

  it("refuses a body with a private key, whatever else it holds, and keeps nothing of it", async () => {
    const before = await names();
    const key = privateKeyPem();
    const fresh = makeCert({ cn: "never.example.com", ...signed });
    for (const body of [`${fresh.pem}\n${key}`, JSON.stringify({ pem: `${fresh.pem}\n${key}`, source: "x" }), key]) {
      const res = await app.ingest("/api/v1/certificates", { method: "POST", body });
      expect(res.status).toBe(422);
      const text = await res.text();
      expect(text).toContain('"code":"private-key"');
      expect(text).not.toContain(key.split("\n")[1]!);
    }
    expect(await names()).toEqual(before);
    const dump = JSON.stringify([...app.db.prepare("SELECT * FROM certificates").all(), ...app.db.prepare("SELECT * FROM sources").all()]);
    expect(dump).not.toContain("PRIVATE KEY");
    expect(dump).not.toContain(key.split("\n")[1]!);
  });

  it("refuses what is not a certificate", async () => {
    const problem = async (res: Response, status: number, code: string) => (expect(res.status).toBe(status), expect(await json(res)).toMatchObject({ code }));
    await problem(await app.send("hello"), 422, "invalid-pem");
    await problem(await app.send("-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----"), 422, "invalid-pem");
    await problem(await app.send(shop.pem, "bad\u0000source"), 422, "invalid-body");
    await problem(await app.ingest("/api/v1/certificates", { method: "POST", body: "{nope" }), 400, "invalid-json");
    await problem(await app.ingest("/api/v1/certificates", { method: "POST", body: JSON.stringify({ pem: 5 }) }), 422, "invalid-body");
    await problem(await app.ingest("/api/v1/certificates", { method: "POST", body: shop.pem, headers: { "content-encoding": "br" } }), 400, "invalid-body");
    await problem(await app.ingest("/api/v1/certificates", { method: "POST", body: "x".repeat(1024 * 1024 + 1) }), 413, "payload-too-large");
  });
});

describe("states and warnings", () => {
  it("tells valid, expiring, critical, expired and not yet valid apart", async () => {
    const make = (cn: string, from: number, to: number, extra = {}) => makeCert({ cn, notBefore: inDays(from), notAfter: inDays(to), ...signed, ...extra }).pem;
    await app.send(
      [
        make("expired.example.com", -100, -2),
        make("early.example.com", 5, 95),
        make("critical.example.com", -80, 3),
        make("expiring.example.com", -70, 20),
      ].join("\n"),
      "scan",
    );
    const state = async (cn: string) => (await json(await app.admin(`/api/v1/certificates?q=${cn}`))).certificates[0].state;
    expect(await state("expired.example.com")).toBe("expired");
    expect(await state("early.example.com")).toBe("not-yet-valid");
    expect(await state("critical.example.com")).toBe("critical");
    expect(await state("expiring.example.com")).toBe("expiring");
    expect(await state("shop.example.com")).toBe("valid");
    for (const [s, cn] of [
      ["expired", "expired.example.com"],
      ["not-yet-valid", "early.example.com"],
      ["critical", "critical.example.com"],
      ["expiring", "expiring.example.com"],
    ] as const) {
      expect(await names(`?state=${s}`), s).toEqual([cn]);
    }
    expect(await names("?state=valid")).toEqual(expect.arrayContaining(["shop.example.com", "api.example.com"]));
    expect(await names("?state=valid")).not.toContain("expired.example.com");
  });

  it("sorts by expiry, soonest first, or by name", async () => {
    expect((await names()).slice(0, 3)).toEqual(["expired.example.com", "critical.example.com", "expiring.example.com"]);
    const byName = await names("?sort=name");
    expect(byName).toEqual([...byName].sort((a, b) => a.localeCompare(b, "en", { sensitivity: "base" })));
  });

  it("warns about weak keys and signatures, wildcards, self-signed leaves and long lifetimes", async () => {
    await app.send(
      [
        makeCert({ cn: "weak.example.com", keyKind: "rsa1024", ...signed }).pem,
        makeCert({ cn: "sha1.example.com", hash: "sha1", ...signed }).pem,
        makeCert({ cn: "*.example.org", sans: ["*.example.org"], ...signed }).pem,
        makeCert({ cn: "self.example.com", keyKind: "ec" }).pem,
        makeCert({ cn: "long.example.com", notAfter: inDays(700), ...signed }).pem,
      ].join("\n"),
      "scan",
    );
    expect(await names("?warning=weak-key")).toEqual(["weak.example.com"]);
    expect(await names("?warning=weak-signature")).toEqual(["sha1.example.com"]);
    expect(await names("?warning=wildcard")).toEqual(["*.example.org"]);
    expect(await names("?warning=self-signed")).toEqual(["self.example.com"]);
    expect(await names("?warning=long-lifetime")).toEqual(["long.example.com"]);
    expect(await names("?ca=true")).toEqual(["Example Root CA"]);
    expect(await names("?q=web-1")).toEqual(["shop.example.com"]);
    expect(await names("?q=%25")).toEqual([]);
  });

  it("summarizes the inventory", async () => {
    const s = await json(await app.admin("/api/v1/summary"));
    expect(s).toMatchObject({ states: { expired: 1, critical: 1, expiring: 1, "not-yet-valid": 1 }, withWarnings: 5, warnDays: [30, 14, 7, 1], endpoints: 0 });
    expect(s.certificates).toBe(Object.values(s.states as Record<string, number>).reduce((a, b) => a + b, 0));
    expect(s.nextExpiry).toMatchObject({ commonName: "critical.example.com" });
    const metrics = await (await fetch(`${app.base}/metrics`)).text();
    expect(metrics).toContain('openasy_build_info{product="certificates",version="0.1.0"} 1');
    expect(metrics).toContain('openasy_certificates_expiring{state="critical"} 1');
    expect(metrics).toContain('openasy_certificates_expiring{state="expired"} 1');
  });

  it("filters and pages with clear refusals", async () => {
    const page = await json(await app.admin("/api/v1/certificates?limit=2"));
    expect(page.certificates).toHaveLength(2);
    expect((await json(await app.admin(`/api/v1/certificates?limit=2&cursor=${page.nextCursor}`))).certificates.length).toBeGreaterThan(0);
    for (const q of ["state=old", "warning=big", "sort=size", "ca=maybe", "limit=0", "cursor=junk"])
      expect((await app.admin(`/api/v1/certificates?${q}`)).status, q).toBe(422);
  });
});

describe("crossing a threshold", () => {
  it("reports the tightest threshold once, as a certificate gets closer", async () => {
    const own = await startApp({ version: "0.1.0" });
    const c = makeCert({ cn: "slow.example.com", notBefore: inDays(-50), notAfter: inDays(20), ...signed });
    await own.send(c.pem, "x");
    const crossings = async () => (await json(await own.admin("/api/v1/expiring?since=2000-01-01T00:00:00Z"))).crossings.map((x: any) => x.threshold);
    expect(await crossings()).toEqual([30]);
    // Asking again reports nothing new.
    expect(await crossings()).toEqual([30]);
    const move = (days: number) => own.db.prepare("UPDATE certificates SET not_after = ?").run(inDays(days).toISOString());
    move(5);
    expect(await crossings()).toEqual([7, 30]);
    move(0.5);
    move(-1);
    expect(await crossings()).toEqual([0, 7, 30]);
    // Only what crossed after a time.
    expect((await json(await own.admin(`/api/v1/expiring?since=${new Date(Date.now() + 60_000).toISOString()}`))).crossings).toEqual([]);
    expect((await own.admin("/api/v1/expiring?since=yesterday")).status).toBe(422);
    await own.close();
  });

  it("follows the thresholds it is given", async () => {
    const own = await startApp({ version: "0.1.0", warnDays: [10, 2] });
    await own.send(makeCert({ cn: "a.example.com", notBefore: inDays(-5), notAfter: inDays(15), ...signed }).pem);
    await own.send(makeCert({ cn: "b.example.com", notBefore: inDays(-5), notAfter: inDays(9), ...signed }).pem);
    const x = (await json(await own.admin("/api/v1/expiring"))).crossings;
    expect(x.map((c: any) => [c.certificate.commonName, c.threshold])).toEqual([["b.example.com", 10]]);
    expect((await json(await own.admin("/api/v1/certificates?state=expiring"))).certificates.map((c: any) => c.commonName)).toEqual(["b.example.com"]);
    await own.close();
  });
});

describe("endpoints", () => {
  const tls = async (chain: string[], key: string) => {
    const server: TlsServer = tlsServer({ key, cert: chain.join("\n") }, (s) => s.on("error", () => {}).end());
    await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
    return { server, port: (server.address() as AddressInfo).port };
  };

  // Endpoints come from the endpoints file only (ADR 0052): the tests give it one entry.
  const fromFile = (own: Awaited<ReturnType<typeof startApp>>, url: string) =>
    own.certs.syncFile(parseEndpoints(`endpoints:\n  - { name: Local, url: '${url}' }`));

  it("has no route that adds an endpoint", async () => {
    expect((await app.admin("/api/v1/endpoints", { method: "POST", body: JSON.stringify({ host: "shop.example.com" }) })).status).toBe(404);
  });

  it("refuses private and loopback addresses by default, at every probe", async () => {
    for (const host of ["localhost", "127.0.0.1", "10.0.0.5", "169.254.169.254", "192.168.1.1"]) {
      fromFile(app, `tls://${host}:443`);
      const probed = await json(await app.admin(`/api/v1/endpoints/${fileId("Local")}/probe`, { method: "POST" }));
      expect(probed.lastError, host).toMatch(/private address|does not resolve/);
    }
    app.certs.syncFile([]);
  });

  it("refuses a public name that answers with a private address", async () => {
    const own = await startApp({ version: "0.1.0", probe: { resolve: async () => ["203.0.113.9", "10.0.0.1"] } });
    fromFile(own, "https://sneaky.example.com");
    expect((await json(await own.admin(`/api/v1/endpoints/${fileId("Local")}/probe`, { method: "POST" }))).lastError).toMatch(/private address/);
    await own.close();
  });

  it("reads the chain a server presents, and says apart whether it is trusted", async () => {
    const leaf = makeCert({ cn: "localhost", sans: ["localhost"], notAfter: inDays(25), ...signed });
    const { server, port } = await tls([leaf.pem, ca.pem], leaf.privateKey.export({ type: "pkcs8", format: "pem" }) as string);
    // Loopback is allowed here through the test hook only; the product has no setting for it.
    const own = await startApp({ version: "0.1.0", probe: { allowPrivate: true, resolve: async () => ["127.0.0.1"] } });
    try {
      fromFile(own, `tls://localhost:${port}`);
      const created = (await json(await own.admin("/api/v1/endpoints"))).endpoints[0];
      expect(created).toMatchObject({ host: "localhost", port, source: "file", lastProbeAt: null, certificate: null });

      const probed = await json(await own.admin(`/api/v1/endpoints/${created.id}/probe`, { method: "POST" }));
      expect(probed).toMatchObject({
        lastError: null,
        chainValid: false,
        chainError: expect.any(String),
        certificate: { commonName: "localhost", state: "expiring" },
      });
      const list = (await json(await own.admin("/api/v1/certificates"))).certificates;
      expect(list.map((c: any) => [c.commonName, c.sources[0].source, c.sources[0].position])).toEqual([
        ["localhost", `localhost:${port}`, 0],
        ["Example Root CA", `localhost:${port}`, 1],
      ]);
      expect((await json(await own.admin("/api/v1/summary"))).endpoints).toBe(1);
    } finally {
      server.close();
      await own.close();
    }
  });

  it("keeps the failure of a probe, and the last good certificate", async () => {
    const own = await startApp({ version: "0.1.0", probe: { allowPrivate: true, resolve: async () => ["127.0.0.1"], timeoutMs: 500 } });
    const closed = await tls([shop.pem], shop.privateKey.export({ type: "pkcs8", format: "pem" }) as string);
    fromFile(own, `tls://localhost:${closed.port}`);
    const created = (await json(await own.admin("/api/v1/endpoints"))).endpoints[0];
    closed.server.close();
    const failed = await json(await own.admin(`/api/v1/endpoints/${created.id}/probe`, { method: "POST" }));
    expect(failed).toMatchObject({
      lastError: expect.stringContaining(String(closed.port)),
      chainValid: null,
      certificate: null,
      lastProbeAt: expect.any(String),
    });
    expect((await json(await own.admin("/api/v1/summary"))).failingEndpoints).toBe(1);
    expect((await own.admin("/api/v1/endpoints/missing/probe", { method: "POST" })).status).toBe(404);
    expect((await own.admin(`/api/v1/endpoints/${created.id}`, { method: "DELETE" })).status).toBe(409);
    own.db.prepare("INSERT INTO endpoints (id, host, port, created_at) VALUES ('ui-1', 'shop.example.com', 443, '2026-10-01T00:00:00Z')").run();
    expect((await own.admin("/api/v1/endpoints/ui-1", { method: "DELETE" })).status).toBe(204);
    expect((await own.admin("/api/v1/endpoints/ui-1", { method: "DELETE" })).status).toBe(404);
    await own.close();
  });
});

describe("deleting and access", () => {
  it("deletes a certificate with its places", async () => {
    const id = (await json(await app.admin("/api/v1/certificates?q=weak.example.com"))).certificates[0].id;
    expect((await app.admin(`/api/v1/certificates/${id}`, { method: "DELETE" })).status).toBe(204);
    expect((await app.admin(`/api/v1/certificates/${id}`)).status).toBe(404);
    expect(app.db.prepare("SELECT COUNT(*) AS n FROM sources WHERE cert_id = ?").get(id)).toEqual({ n: 0 });
    expect((await app.admin("/api/v1/certificates/missing", { method: "DELETE" })).status).toBe(404);
  });

  it("forgets certificates nobody has reported for the retention period", async () => {
    app.db.prepare("UPDATE certificates SET last_seen = '2000-01-01T00:00:00.000Z' WHERE subject_cn = 'sha1.example.com'").run();
    app.certs.purge();
    expect(await names("?q=sha1.example.com")).toEqual([]);
  });

  it("asks for the ingest token or an editor, and keeps the rest to people", async () => {
    const anon = (path: string, init: RequestInit = {}) => fetch(app.base + path, init);
    expect((await anon("/api/v1/certificates", { method: "POST", body: shop.pem })).status).toBe(401);
    expect((await anon("/api/v1/certificates", { method: "POST", body: shop.pem, headers: { authorization: "Bearer nope" } })).status).toBe(401);
    expect((await anon("/api/v1/certificates")).status).toBe(401);
    expect((await app.ingest("/api/v1/certificates")).status).toBe(401);
    expect((await app.ingest("/api/v1/endpoints")).status).toBe(401);
    expect((await app.ingest("/api/v1/endpoints/x/probe", { method: "POST" })).status).toBe(401);
    const closed = await startApp({ version: "0.1.0", ingestToken: undefined, adminToken: undefined });
    expect((await fetch(`${closed.base}/api/v1/certificates`, { method: "POST", body: shop.pem })).status).toBe(503);
    await closed.close();
    expect(await json(await fetch(`${app.base}/api/v1/version`))).toEqual({ product: "certificates", version: "0.1.0" });
  });
});
