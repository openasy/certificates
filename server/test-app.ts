// Starts the app on a random port for tests.
import { createServer, type RequestListener, type Server } from "node:http";
import { createAuth } from "@openasy/auth";
import type { AddressInfo } from "node:net";
import { createApp, type AppOptions } from "./app.ts";
import { openDb } from "./db.ts";
import { createCerts } from "./certs.ts";
import type { ProbeOptions } from "./probe.ts";

export const INGEST_TOKEN = "test-ingest-token";
export const ADMIN_TOKEN = "test-admin-token";

export async function startApp(opts: Partial<AppOptions> & { version: string; probe?: ProbeOptions; warnDays?: number[] }) {
  const db = openDb(":memory:");
  const certs = createCerts(db, { probe: opts.probe, warnDays: opts.warnDays });
  // The origin is known once the port is, so the handler is set after listening.
  let handler: RequestListener = (_req, res) => res.writeHead(503).end();
  const server: Server = createServer((req, res) => handler(req, res));
  await new Promise<void>((resolve) => server.listen(0, resolve));
  const base = `http://localhost:${(server.address() as AddressInfo).port}`;
  const auth = createAuth({ db, product: "certificates", productName: "OpenAsy Certificates", origin: base });
  const { probe: _probe, warnDays: _warnDays, ...rest } = opts;
  handler = createApp({ db, certs, auth, ingestToken: INGEST_TOKEN, adminToken: ADMIN_TOKEN, ...rest });
  const as = (token: string) => (path: string, init: RequestInit = {}) => fetch(base + path, { ...init, headers: { authorization: `Bearer ${token}`, "content-type": "application/json", ...init.headers } });
  const admin = as(ADMIN_TOKEN);
  const ingest = as(INGEST_TOKEN);
  /** Sends PEM text the way a cron job does. */
  const send = (pem: string, source?: string) => ingest(`/api/v1/certificates${source ? `?${new URLSearchParams({ source })}` : ""}`, { method: "POST", body: pem, headers: { "content-type": "text/plain" } });
  const close = () => new Promise<void>((resolve) => server.close(() => resolve()));
  return { db, certs, auth, base, admin, ingest, send, close };
}
