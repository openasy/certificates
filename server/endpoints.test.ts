import { readFileSync } from "node:fs";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { parseWarnDays } from "./certs.ts";
import { fileId, parseEndpoints } from "./endpoints.ts";
import { startApp } from "./test-app.ts";

// The same file as in Uptime (ADR 0052): both products read the same entries.
const FIXTURE = readFileSync(new URL("./testdata/endpoints.yaml", import.meta.url), "utf8");
const json = async (res: Response) => (await res.json()) as any;

describe("the endpoints file", () => {
  it("reads the same entries as Uptime does", () => {
    expect(parseEndpoints(FIXTURE).map((e) => `${e.name}: ${e.kind} ${e.host}:${e.port} ${e.server ?? "-"}`)).toEqual([
      "Website: http www.example.com:443 web-1",
      "API: http api.example.com:8443 web-1",
      "Mail: tls mail.example.com:465 -",
      "Database: tcp db.example.com:5432 db-1",
      "Resolver: dns example.com:null -",
      "Old site: http old.example.com:80 -",
    ]);
    expect(() => parseEndpoints("endpoints:\n  - { name: A, url: 'tcp://db.example.com' }")).toThrow(/needs a port/);
  });
});

describe("endpoints from the file", () => {
  let app: Awaited<ReturnType<typeof startApp>>;
  beforeAll(async () => {
    // No network in tests: every name answers with a private address, which a probe refuses at once.
    app = await startApp({ version: "0.1.0", probe: { resolve: async () => ["10.0.0.5"] } });
  });
  afterAll(() => app.close());

  const endpoints = async () => (await json(await app.admin("/api/v1/endpoints"))).endpoints as Array<Record<string, any>>;

  it("are its https:// and tls:// entries, beside the ones added here", async () => {
    app.db.prepare("INSERT INTO endpoints (id, host, port, created_at) VALUES ('ui-1', 'shop.example.com', 443, '2026-10-01T00:00:00Z')").run();
    expect(app.certs.syncFile(parseEndpoints(FIXTURE))).toEqual([]);
    const list = await endpoints();
    expect(list.map((e) => `${e.host}:${e.port} ${e.source} ${e.name ?? "-"} ${e.server ?? "-"}`)).toEqual([
      "api.example.com:8443 file API web-1",
      "mail.example.com:465 file Mail -",
      "shop.example.com:443 ui - -",
      "www.example.com:443 file Website web-1",
    ]);
    expect(list.find((e) => e.name === "Website")).toMatchObject({ id: fileId("Website"), lastProbeAt: null });
  });

  it("are removed in the file only, and one on a private address is kept with the probe's answer", async () => {
    const res = await app.admin(`/api/v1/endpoints/${fileId("Website")}`, { method: "DELETE" });
    expect(res.status).toBe(409);
    expect((await json(res)).detail).toMatch(/endpoints file/);
    const probed = await app.admin(`/api/v1/endpoints/${fileId("Website")}/probe`, { method: "POST" });
    expect(probed.status).toBe(200);
    expect((await json(probed)).lastError).toMatch(/private address.*collector/);
  });

  it("follow the file, forget what was read at an old address, and take over one added here at the same address", async () => {
    app.db.prepare("UPDATE endpoints SET last_probe_at = '2026-10-01T00:00:00Z', last_error = 'x' WHERE id = ?").run(fileId("Mail"));
    const warnings = app.certs.syncFile(
      parseEndpoints(
        "endpoints:\n  - { name: Mail, url: 'tls://mail.example.com:993', server: mail-1 }\n  - { name: Mail again, url: 'tls://mail.example.com:993' }\n  - { name: Shop, url: https://shop.example.com }\n  - { name: Resolver, url: 'dns://example.com' }\n",
      ),
    );
    expect(warnings).toEqual([]);
    const list = await endpoints();
    expect(list.map((e) => `${e.host}:${e.port} ${e.source} ${e.server ?? "-"}`)).toEqual(["mail.example.com:993 file mail-1", "shop.example.com:443 file -"]);
    expect(list[0]).toMatchObject({ lastProbeAt: null, lastError: null });
    // The one added here is the file's now, under the file's name, and keeps when it was added.
    expect(list[1]).toMatchObject({ id: fileId("Shop"), name: "Shop", createdAt: "2026-10-01T00:00:00Z" });
  });

  it("refuse a whole file with a bad address", async () => {
    const before = await endpoints();
    expect(() => app.certs.syncFile([{ ...parseEndpoints("endpoints:\n  - { name: X, url: 'tls://x.example.com' }")[0]!, host: "bad host" }])).toThrow(
      /X: bad host is not a host name/,
    );
    expect(await endpoints()).toEqual(before);
  });
});

describe("the summary", () => {
  it("says where the file stands, or null without one", async () => {
    const without = await startApp({ version: "0.1.0" });
    const state = { path: "/config/endpoints.yaml", appliedAt: "2026-10-01T00:00:00.000Z", entries: 6, error: null, warnings: ["x"] };
    const withFile = await startApp({ version: "0.1.0", endpointsFile: () => state });
    try {
      expect((await json(await without.admin("/api/v1/summary"))).endpointsFile).toBeNull();
      expect((await json(await withFile.admin("/api/v1/summary"))).endpointsFile).toEqual(state);
    } finally {
      await without.close();
      await withFile.close();
    }
  });

  it("names the shared variable when the days are wrong", () => {
    expect(() => parseWarnDays("30,0")).toThrow(/OPENASY_CERT_WARN_DAYS/);
  });
});
