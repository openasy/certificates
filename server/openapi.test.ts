import { mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Ajv2020 } from "ajv/dist/2020.js";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { ADMIN_TOKEN, INGEST_TOKEN, startApp } from "./test-app.ts";
import { inDays, makeCert, privateKeyPem } from "./testcert.ts";

// Contract tests (ADR 0024): every response the API sends must match openapi.json.

type Spec = {
  info: { version: string };
  paths: Record<string, Record<string, { responses: Record<string, { $ref?: string; content?: Record<string, { schema: object }> }> }>>;
  components: { responses: Record<string, { content: Record<string, { schema: object }> }> };
};

const spec = JSON.parse(readFileSync(new URL("../openapi.json", import.meta.url), "utf8")) as Spec;
const { version } = JSON.parse(readFileSync(new URL("../package.json", import.meta.url), "utf8")) as { version: string };

const ajv = new Ajv2020({ strict: false, validateFormats: false });
ajv.addSchema(spec, "openapi");

const docsDir = mkdtempSync(join(tmpdir(), "certificates-docs-"));
writeFileSync(join(docsDir, "index.html"), "<!doctype html><title>API</title>");

let app: Awaited<ReturnType<typeof startApp>>;
let base: string;
const covered = new Set<string>();

beforeAll(async () => {
  app = await startApp({ version, openapi: spec, docsDir, probe: { resolve: async () => ["203.0.113.9"], timeoutMs: 300 } });
  base = app.base;
});

afterAll(() => app.close());

/** Calls the API and checks status, content type and body against the description. */
async function call(method: string, path: string, init: RequestInit = {}, concrete = path) {
  const res = await fetch(base + concrete, { ...init, method });
  const operation = spec.paths[path]?.[method.toLowerCase()];
  expect(operation, `${method} ${path} is not in openapi.json`).toBeDefined();
  covered.add(`${method} ${path}`);

  const declared = operation!.responses[String(res.status)];
  expect(declared, `${method} ${concrete} answered ${res.status}, which openapi.json does not list`).toBeDefined();
  // A response is either inline or a $ref to components/responses; build the JSON pointer to its schema either way.
  const shared = declared!.$ref?.split("/").pop();
  const response = shared ? spec.components.responses[shared]! : declared!;
  const at = shared
    ? `openapi#/components/responses/${shared}`
    : `openapi#/paths/${path.replaceAll("/", "~1")}/${method.toLowerCase()}/responses/${res.status}`;

  if (!response.content) {
    expect(res.headers.get("content-length") ?? "0", `${method} ${path} ${res.status} should have no body`).toBe("0");
    return { res, body: undefined };
  }
  const type = res.headers.get("content-type")!.split(";")[0]!;
  expect(response.content?.[type], `${method} ${path} ${res.status} sent ${type}, which openapi.json does not list`).toBeDefined();

  const body = type.endsWith("json") ? await res.json() : await res.text();
  const schema = `${at}/content/${type.replace("/", "~1")}/schema`;
  const validate = ajv.getSchema(schema)!;
  expect(validate(body), JSON.stringify(validate.errors)).toBe(true);
  return { res, body };
}

const auth = (token: string, body?: string, type = "application/json") => ({
  headers: { authorization: `Bearer ${token}`, "content-type": type },
  ...(body !== undefined && { body }),
});
const admin = (body?: unknown) => auth(ADMIN_TOKEN, body === undefined ? undefined : typeof body === "string" ? body : JSON.stringify(body));

describe("openapi.json", () => {
  it("has the version of this release", () => {
    expect(spec.info.version).toBe(version);
  });

  it("is served with the running version", async () => {
    const served = (await (await fetch(`${base}/api/openapi.json`)).json()) as Spec;
    expect(served.info.version).toBe(version);
    // certificates's own operations, then sign-in from @openasy/auth (tested against its description in that package).
    expect(Object.keys(served.paths).filter((p) => !p.startsWith("/api/v1/auth/"))).toEqual(Object.keys(spec.paths));
    expect(served.paths["/api/v1/auth/login"]).toBeDefined();
  });

  it("serves the API reference at /api/docs/", async () => {
    expect((await fetch(`${base}/api/docs`, { redirect: "manual" })).headers.get("location")).toBe("/api/docs/");
    const res = await fetch(`${base}/api/docs/`);
    expect(res.headers.get("content-type")).toContain("text/html");
    expect((await fetch(`${base}/api/docs/../../package.json`)).status).not.toBe(200);
  });
});

describe("responses match openapi.json", () => {
  let id = "";
  let endpoint = "";
  const ca = makeCert({ cn: "Example Root CA", ca: true, keyKind: "rsa2048b", notAfter: inDays(3000) });
  const leaf = makeCert({
    cn: "shop.example.com",
    sans: ["shop.example.com"],
    notAfter: inDays(5),
    issuer: { cn: "Example Root CA", privateKey: ca.privateKey },
  });
  const send = (body: string, token = INGEST_TOKEN) => auth(token, body, "text/plain");

  it("product and health", async () => {
    await call("GET", "/api/v1/version");
    await call("GET", "/api/v1/products", admin());
    await call("GET", "/api/v1/products", {});
    await call("GET", "/healthz");
    await call("GET", "/readyz");
    await call("GET", "/metrics");
  });

  it("certificates in, and every refusal", async () => {
    const received = (await call("POST", "/api/v1/certificates", send(`${leaf.pem}\n${ca.pem}`), "/api/v1/certificates?source=web-1:443")).body as {
      certificates: Array<{ id: string }>;
    };
    id = received.certificates[0]!.id;
    await call("POST", "/api/v1/certificates", send(leaf.pem));
    await call("POST", "/api/v1/certificates", auth(INGEST_TOKEN, JSON.stringify({ pem: leaf.pem, source: "cron" })));
    await call("POST", "/api/v1/certificates", send(`${leaf.pem}\n${privateKeyPem()}`));
    await call("POST", "/api/v1/certificates", send("hello"));
    await call("POST", "/api/v1/certificates", auth(INGEST_TOKEN, "{nope"));
    await call("POST", "/api/v1/certificates", auth(INGEST_TOKEN, JSON.stringify({ pem: 5 })));
    await call("POST", "/api/v1/certificates", send("x".repeat(1024 * 1024 + 1)));
    await call("POST", "/api/v1/certificates", send(leaf.pem), "/api/v1/certificates?source=%00");
    await call("POST", "/api/v1/certificates", send(leaf.pem, "wrong"));
    await call("POST", "/api/v1/certificates", { method: "POST" });
  });

  it("the inventory", async () => {
    const { body } = await call("GET", "/api/v1/certificates", admin());
    expect((body as { certificates: unknown[] }).certificates).toHaveLength(2);
    await call("GET", "/api/v1/certificates", admin(), "/api/v1/certificates?state=critical&warning=wildcard&ca=false&q=shop&sort=name&limit=1");
    await call("GET", "/api/v1/certificates", admin(), "/api/v1/certificates?limit=1");
    await call("GET", "/api/v1/certificates", admin(), "/api/v1/certificates?state=old");
    await call("GET", "/api/v1/certificates", {});
    await call("GET", "/api/v1/certificates/{id}", admin(), `/api/v1/certificates/${id}`);
    await call("GET", "/api/v1/certificates/{id}", admin(), "/api/v1/certificates/missing");
    await call("GET", "/api/v1/certificates/{id}", {}, `/api/v1/certificates/${id}`);
    await call("GET", "/api/v1/expiring", admin());
    await call("GET", "/api/v1/expiring", admin(), "/api/v1/expiring?since=2000-01-01T00:00:00Z&limit=5");
    await call("GET", "/api/v1/expiring", admin(), "/api/v1/expiring?since=yesterday");
    await call("GET", "/api/v1/expiring", {});
    await call("GET", "/api/v1/summary", admin());
    await call("GET", "/api/v1/overview", admin());
    await call("GET", "/api/v1/summary", {});
  });

  it("endpoints", async () => {
    await call("GET", "/api/v1/endpoints", admin());
    app.db.prepare("INSERT INTO endpoints (id, host, port, created_at) VALUES ('ui-1', 'api.example.com', 8443, '2026-10-01T00:00:00Z')").run();
    endpoint = "ui-1";
    await call("POST", "/api/v1/endpoints/{id}/probe", admin(), `/api/v1/endpoints/${endpoint}/probe`);
    await call("POST", "/api/v1/endpoints/{id}/probe", admin(), "/api/v1/endpoints/missing/probe");
    await call("POST", "/api/v1/endpoints/{id}/probe", { method: "POST" }, `/api/v1/endpoints/${endpoint}/probe`);
    await call("GET", "/api/v1/endpoints", {});
    await call("DELETE", "/api/v1/endpoints/{id}", admin(), `/api/v1/endpoints/${endpoint}`);
    await call("DELETE", "/api/v1/endpoints/{id}", admin(), `/api/v1/endpoints/${endpoint}`);
    await call("DELETE", "/api/v1/endpoints/{id}", { method: "DELETE" }, "/api/v1/endpoints/x");
  });

  it("deletes a certificate", async () => {
    await call("DELETE", "/api/v1/certificates/{id}", admin(), `/api/v1/certificates/${id}`);
    await call("DELETE", "/api/v1/certificates/{id}", admin(), `/api/v1/certificates/${id}`);
    await call("DELETE", "/api/v1/certificates/{id}", { method: "DELETE" }, "/api/v1/certificates/x");
  });

  it("covers every operation in openapi.json", () => {
    const all = Object.entries(spec.paths).flatMap(([path, ops]) => Object.keys(ops).map((m) => `${m.toUpperCase()} ${path}`));
    expect([...covered].sort()).toEqual(all.sort());
  });
});
