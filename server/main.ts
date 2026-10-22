import { existsSync, readFileSync } from "node:fs";
import { createServer } from "node:http";
import { createAuth, oidcFromEnv, readSecretsKey } from "@openasy/auth";
import { createApp, createMetricsHandler } from "./app.ts";
import { openDb } from "./db.ts";
import { log } from "./log.ts";
import { parseProducts } from "./products.ts";
import { createCerts, parseWarnDays } from "./certs.ts";

const { version } = JSON.parse(readFileSync(new URL("../package.json", import.meta.url), "utf8")) as { version: string };
const port = Number(process.env.PORT ?? 8080);
const dbPath = process.env.CERTIFICATES_DB ?? "/data/certificates.db";
const retentionDays = Number(process.env.CERTIFICATES_RETENTION_DAYS ?? 365);
const probeHours = Number(process.env.CERTIFICATES_PROBE_HOURS ?? 6);
const warnDays = parseWarnDays(process.env.CERTIFICATES_WARN_DAYS);
const webDir = new URL("../dist/web", import.meta.url).pathname;
const docsDir = new URL("../dist/docs", import.meta.url).pathname;
const openapi = JSON.parse(readFileSync(new URL("../openapi.json", import.meta.url), "utf8")) as Record<string, unknown>;
const headless = process.env.CERTIFICATES_HEADLESS === "true";
// Set it to keep /metrics off the port that is published or behind an ingress (ADR 0026).
const metricsPort = process.env.CERTIFICATES_METRICS_PORT ? Number(process.env.CERTIFICATES_METRICS_PORT) : undefined;

if (!Number.isFinite(probeHours) || probeHours < 0) throw new Error("CERTIFICATES_PROBE_HOURS must be 0 (off) or a number of hours");
if (!Number.isFinite(retentionDays) || retentionDays < 1) throw new Error("CERTIFICATES_RETENTION_DAYS must be a number of days, 1 or more");

const db = openDb(dbPath);
// The address people open certificates at, behind the TLS proxy (ADR 0026). Cookies, passkeys and OIDC redirects use it.
const publicUrl = (process.env.CERTIFICATES_PUBLIC_URL ?? `http://localhost:${port}`).replace(/\/$/, "");
const secretsKeyFile = process.env.CERTIFICATES_SECRETS_KEY_FILE ?? "/run/secrets/openasy-kek";
const auth = createAuth({
  db,
  product: "certificates",
  productName: "OpenAsy Certificates",
  origin: publicUrl,
  // Locally the same certificates is often opened as 127.0.0.1 too.
  trustedOrigins: publicUrl.startsWith("http://localhost:") ? [publicUrl.replace("localhost", "127.0.0.1")] : [],
  passwords: process.env.CERTIFICATES_PASSWORD_SIGN_IN !== "false",
  oidc: oidcFromEnv(process.env, "CERTIFICATES_"),
  secretsKey: readSecretsKey(secretsKeyFile),
  // Audit log (ADR 0013): every sign-in, failure and change to members and tokens.
  onEvent: (event) => log(event.type === "sign-in-failed" ? "warn" : "info", "auth", { event }),
});
const certs = createCerts(db, { retentionDays, warnDays });
const products = parseProducts(process.env.OPENASY_PRODUCTS);
if (products.invalid.length) log("warn", "OPENASY_PRODUCTS: left out entries that are not id=https://address", { entries: products.invalid });
const server = createServer(
  createApp({
    db,
    certs,
    version,
    auth,
    ingestToken: process.env.CERTIFICATES_INGEST_TOKEN,
    webDir: !headless && existsSync(webDir) ? webDir : undefined,
    docsDir: existsSync(docsDir) ? docsDir : undefined,
    openapi,
    serveMetrics: metricsPort === undefined,
    products: products.products,
  }),
);
const metricsServer = metricsPort !== undefined ? createServer(createMetricsHandler(certs, version)) : undefined;
metricsServer?.listen(metricsPort, () => log("info", "metrics on their own port", { port: metricsPort }));

server.listen(port, () => log("info", "certificates started", { version, port, db: dbPath, headless, retentionDays, warnDays, probeHours }));
if (!process.env.CERTIFICATES_INGEST_TOKEN) log("warn", "CERTIFICATES_INGEST_TOKEN is not set; a collector needs an API token with the editor role (Settings, API tokens) to send certificates");
if (!publicUrl.startsWith("https://") && !/^http:\/\/(localhost|127\.0\.0\.1)(:|$)/.test(publicUrl)) {
  log("warn", "CERTIFICATES_PUBLIC_URL is not https: browsers will not keep secure cookies or allow passkeys. Put certificates behind TLS (ADR 0026)", { url: publicUrl });
}
if (auth.secretsInClear) log("warn", "no secrets key: TOTP secrets are stored unencrypted. Mount a 32-byte key (openssl rand -hex 32)", { file: secretsKeyFile });
const setup = auth.setupLink();
// No default password (ADR 0013): the first person to open this link becomes the owner.
if (setup) log("info", "no owner yet: open this link once to create the owner account", { url: setup });

certs.purge();
const timers: NodeJS.Timeout[] = [setInterval(() => auth.purge(), 5 * 60_000), setInterval(() => certs.purge(), 24 * 3_600_000), setInterval(() => certs.checkExpiry(), 3_600_000)];
if (probeHours > 0) {
  // Connects only to endpoints an admin added, on public addresses, one after another (ADR 0046).
  const probe = () => certs.probeAll().catch((err) => log("warn", "probe round failed", { error: String(err) }));
  void probe();
  timers.push(setInterval(probe, probeHours * 3_600_000));
} else {
  log("info", "endpoint probes are off; send certificates with POST /api/v1/certificates");
}

function shutdown(signal: string) {
  log("info", "shutting down", { signal });
  for (const t of timers) clearInterval(t);
  metricsServer?.close();
  server.close(() => {
    db.close();
    process.exit(0);
  });
  setTimeout(() => process.exit(1), 10_000).unref();
}
process.on("SIGTERM", () => shutdown("SIGTERM"));
process.on("SIGINT", () => shutdown("SIGINT"));
