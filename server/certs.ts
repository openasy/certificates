import { X509Certificate } from "node:crypto";
import type { DatabaseSync, SQLInputValue } from "node:sqlite";
import { fileId, type Endpoint } from "./endpoints.ts";
import { fetchChain, validHost, type ProbeOptions } from "./probe.ts";
import { parsePem, PemError, type Parsed } from "./x509.ts";

export type ProblemCode =
  | "invalid-token"
  | "invalid-json"
  | "invalid-body"
  | "invalid-pem"
  | "private-key"
  | "not-found"
  | "conflict"
  | "not-configured"
  | "payload-too-large"
  | "internal-error";

export class CertsError extends Error {
  readonly status: number;
  readonly code: ProblemCode;
  constructor(status: number, code: ProblemCode, detail: string) {
    super(detail);
    this.status = status;
    this.code = code;
  }
}

export type State = "valid" | "expiring" | "critical" | "expired" | "not-yet-valid";
export const STATES: State[] = ["valid", "expiring", "critical", "expired", "not-yet-valid"];
export const WARNINGS = ["weak-key", "weak-signature", "wildcard", "self-signed", "long-lifetime"] as const;

const DAY = 86_400_000;
const SOURCE = /^[\x20-\x7e]{1,255}$/;

const now = () => new Date().toISOString();
const bad = (detail: string) => new CertsError(422, "invalid-body", detail);
const notFound = (what: string) => new CertsError(404, "not-found", `${what} does not exist.`);

export interface Page<T> {
  items: T[];
  /** Opaque; pass it back as `cursor` for the next page. Absent on the last page (ADR 0024). */
  nextCursor?: string;
}

const encodeCursor = (offset: number) => Buffer.from(JSON.stringify({ o: offset })).toString("base64url");
function decodeCursor(cursor: string | undefined): number {
  if (!cursor) return 0;
  try {
    const o = (JSON.parse(Buffer.from(cursor, "base64url").toString("utf8")) as { o?: unknown }).o;
    if (typeof o === "number" && Number.isSafeInteger(o) && o >= 0) return o;
  } catch {
    // fall through
  }
  throw bad("cursor is not one this API returned.");
}

export function parseLimit(value: string | null, max = 500, fallback = 100): number {
  if (value === null) return fallback;
  const n = Number(value);
  if (!Number.isInteger(n) || n < 1 || n > max) throw bad(`limit must be between 1 and ${max}.`);
  return n;
}

/** "30,14,7,1" as a list of days, largest first. */
export function parseWarnDays(value: string | undefined): number[] {
  const days = (value ?? "30,14,7,1").split(",").map((d) => Number(d.trim()));
  if (!days.length || days.some((d) => !Number.isInteger(d) || d < 1 || d > 365))
    throw new Error("OPENASY_CERT_WARN_DAYS is a comma-separated list of days, 1 to 365, such as 30,14,7,1");
  return [...new Set(days)].sort((a, b) => b - a);
}

export interface CertsOptions {
  /** Certificates nobody has reported for this long are deleted (ADR 0015). */
  retentionDays?: number;
  /** Days before expiry at which a certificate is reported, largest first. The largest is also where it becomes "expiring". */
  warnDays?: number[];
  probe?: ProbeOptions;
}

export interface CertFilter {
  state?: State;
  warning?: string;
  q?: string;
  ca?: boolean;
  sort: "expiry" | "name";
}

interface CertRow {
  id: string;
  subject: string;
  subject_cn: string | null;
  sans: string;
  issuer: string;
  issuer_cn: string | null;
  serial: string;
  not_before: string;
  not_after: string;
  key_type: string;
  key_bits: number | null;
  signature: string;
  is_ca: number;
  self_signed: number;
  warnings: string;
  pem: string;
  first_seen: string;
  last_seen: string;
}

export function createCerts(db: DatabaseSync, { retentionDays = 365, warnDays = [30, 14, 7, 1], probe = {} }: CertsOptions = {}) {
  const expiringDays = Math.max(...warnDays);
  // "Critical" is the last week, or the tightest threshold when that is wider.
  const criticalDays = Math.min(7, expiringDays);

  function stateOf(row: Pick<CertRow, "not_before" | "not_after">, at = Date.now()): State {
    const left = Date.parse(row.not_after) - at;
    if (left < 0) return "expired";
    if (Date.parse(row.not_before) > at) return "not-yet-valid";
    return left < criticalDays * DAY ? "critical" : left < expiringDays * DAY ? "expiring" : "valid";
  }
  const daysLeft = (row: Pick<CertRow, "not_after">, at = Date.now()) => Math.floor((Date.parse(row.not_after) - at) / DAY);

  const sourcesOf = (id: string) =>
    (
      db.prepare("SELECT source, position, last_seen FROM sources WHERE cert_id = ? ORDER BY last_seen DESC, source").all(id) as Array<{
        source: string;
        position: number;
        last_seen: string;
      }>
    ).map((s) => ({
      source: s.source,
      position: s.position,
      lastSeen: s.last_seen,
    }));

  function present(r: CertRow) {
    return {
      id: r.id,
      subject: r.subject,
      commonName: r.subject_cn,
      names: JSON.parse(r.sans) as string[],
      issuer: r.issuer,
      issuerCommonName: r.issuer_cn,
      serial: r.serial,
      notBefore: r.not_before,
      notAfter: r.not_after,
      daysLeft: daysLeft(r),
      state: stateOf(r),
      keyType: r.key_type,
      keyBits: r.key_bits,
      signature: r.signature,
      ca: r.is_ca === 1,
      selfSigned: r.self_signed === 1,
      warnings: JSON.parse(r.warnings) as string[],
      sources: sourcesOf(r.id),
      firstSeen: r.first_seen,
      lastSeen: r.last_seen,
    };
  }

  const row = (id: string) => {
    const r = db.prepare("SELECT * FROM certificates WHERE id = ?").get(id) as CertRow | undefined;
    if (!r) throw notFound("The certificate");
    return r;
  };

  /** The certificates in the inventory that signed this one, nearest first. */
  function chainOf(r: CertRow) {
    const out: CertRow[] = [];
    let current = new X509Certificate(r.pem);
    let issuerName = r.issuer;
    for (let depth = 0; depth < 8; depth++) {
      const candidates = db
        .prepare("SELECT * FROM certificates WHERE subject = ? AND id <> ?")
        .all(issuerName, new X509Certificate(r.pem).fingerprint256.replace(/:/g, "").toLowerCase()) as unknown as CertRow[];
      const next = candidates.find((c) => {
        try {
          return !out.some((o) => o.id === c.id) && current.checkIssued(new X509Certificate(c.pem));
        } catch {
          return false;
        }
      });
      if (!next || next.id === r.id) break;
      out.push(next);
      if (next.self_signed === 1) break;
      current = new X509Certificate(next.pem);
      issuerName = next.issuer;
    }
    return out;
  }

  function store(p: Parsed, source: string, position: number, at: string): boolean {
    const known = db.prepare("SELECT 1 FROM certificates WHERE id = ?").get(p.id);
    db.prepare(
      `INSERT INTO certificates (id, subject, subject_cn, sans, issuer, issuer_cn, serial, not_before, not_after, key_type, key_bits, signature, is_ca, self_signed, warnings, pem, first_seen, last_seen)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
       ON CONFLICT (id) DO UPDATE SET last_seen = excluded.last_seen`,
    ).run(
      p.id,
      p.subject,
      p.subjectCn,
      JSON.stringify(p.sans),
      p.issuer,
      p.issuerCn,
      p.serial,
      p.notBefore,
      p.notAfter,
      p.keyType,
      p.keyBits,
      p.signature,
      p.isCa ? 1 : 0,
      p.selfSigned ? 1 : 0,
      JSON.stringify(p.warnings),
      p.pem,
      at,
      at,
    );
    db.prepare(
      "INSERT INTO sources (cert_id, source, position, last_seen) VALUES (?, ?, ?, ?) ON CONFLICT (cert_id, source) DO UPDATE SET position = excluded.position, last_seen = excluded.last_seen",
    ).run(p.id, source, position, at);
    return !known;
  }

  /**
   * Writes the tightest threshold each certificate has now crossed, once. A certificate that goes from 30 to 7 days
   * left is reported when it crosses 7, not again for 14 and 30 (ADR 0046).
   */
  function checkExpiry(at = Date.now()) {
    const marks = db.prepare("SELECT cert_id, MIN(threshold) AS t FROM expiry_marks GROUP BY cert_id").all() as Array<{ cert_id: string; t: number }>;
    const tightest = new Map(marks.map((m) => [m.cert_id, m.t]));
    const insert = db.prepare("INSERT OR IGNORE INTO expiry_marks (cert_id, threshold, crossed_at) VALUES (?, ?, ?)");
    let crossed = 0;
    for (const c of db.prepare("SELECT id, not_after FROM certificates").all() as Array<{ id: string; not_after: string }>) {
      const left = Date.parse(c.not_after) - at;
      const threshold = left < 0 ? 0 : (warnDays.filter((d) => left < d * DAY).at(-1) ?? null);
      if (threshold === null) continue;
      const seen = tightest.get(c.id);
      if (seen !== undefined && seen <= threshold) continue;
      insert.run(c.id, threshold, new Date(at).toISOString());
      crossed++;
    }
    return crossed;
  }

  function ingestParsed(parsed: Parsed[], source: string) {
    const at = now();
    let added = 0;
    db.exec("BEGIN IMMEDIATE");
    try {
      parsed.forEach((p, i) => {
        if (store(p, source, i, at)) added++;
      });
      db.exec("COMMIT");
    } catch (err) {
      db.exec("ROLLBACK");
      throw err;
    }
    checkExpiry();
    return { certificates: parsed.map((p) => present(row(p.id))), added };
  }

  function listQuery(filter: CertFilter, cursor: string | undefined, limit: number) {
    const where: string[] = [];
    const args: SQLInputValue[] = [];
    const t = Date.now();
    const iso = (days: number) => new Date(t + days * DAY).toISOString();
    const at = new Date(t).toISOString();
    if (filter.state === "expired") (where.push("not_after < ?"), args.push(at));
    else if (filter.state === "not-yet-valid") (where.push("not_after >= ? AND not_before > ?"), args.push(at, at));
    else if (filter.state === "critical") (where.push("not_after >= ? AND not_before <= ? AND not_after < ?"), args.push(at, at, iso(criticalDays)));
    else if (filter.state === "expiring")
      (where.push("not_before <= ? AND not_after >= ? AND not_after < ?"), args.push(at, iso(criticalDays), iso(expiringDays)));
    else if (filter.state === "valid") (where.push("not_before <= ? AND not_after >= ?"), args.push(at, iso(expiringDays)));
    if (filter.warning) (where.push("warnings LIKE ?"), args.push(`%"${filter.warning}"%`));
    if (filter.ca !== undefined) (where.push("is_ca = ?"), args.push(filter.ca ? 1 : 0));
    if (filter.q) {
      const like = `%${filter.q.replace(/[\\%_]/g, "\\$&")}%`;
      where.push(
        "(subject LIKE ? ESCAPE '\\' OR sans LIKE ? ESCAPE '\\' OR issuer LIKE ? ESCAPE '\\' OR id LIKE ? ESCAPE '\\' OR id IN (SELECT cert_id FROM sources WHERE source LIKE ? ESCAPE '\\'))",
      );
      args.push(like, like, like, like, like);
    }
    const offset = decodeCursor(cursor);
    const order = filter.sort === "name" ? "COALESCE(subject_cn, subject) COLLATE NOCASE, not_after" : "not_after, id";
    const rows = db
      .prepare(`SELECT * FROM certificates ${where.length ? `WHERE ${where.join(" AND ")}` : ""} ORDER BY ${order} LIMIT ? OFFSET ?`)
      .all(...args, limit + 1, offset) as unknown as CertRow[];
    return { items: rows.slice(0, limit).map(present), ...(rows.length > limit && { nextCursor: encodeCursor(offset + limit) }) } satisfies Page<unknown>;
  }

  function presentEndpoint(e: Record<string, any>) {
    const cert = e.cert_id ? (db.prepare("SELECT * FROM certificates WHERE id = ?").get(e.cert_id) as CertRow | undefined) : undefined;
    return {
      id: e.id as string,
      host: e.host as string,
      port: e.port as number,
      name: (e.name as string | null) ?? null,
      source: e.source as "ui" | "file",
      server: (e.server as string | null) ?? null,
      lastProbeAt: (e.last_probe_at as string | null) ?? null,
      lastError: (e.last_error as string | null) ?? null,
      chainValid: e.chain_valid === null ? null : e.chain_valid === 1,
      chainError: (e.chain_error as string | null) ?? null,
      certificate: cert ? { id: cert.id, commonName: cert.subject_cn, notAfter: cert.not_after, daysLeft: daysLeft(cert), state: stateOf(cert) } : null,
      createdAt: e.created_at as string,
    };
  }
  const endpointRow = (id: string) => {
    const e = db.prepare("SELECT * FROM endpoints WHERE id = ?").get(id) as Record<string, any> | undefined;
    if (!e) throw notFound("The endpoint");
    return e;
  };

  async function probeEndpoint(id: string) {
    const e = endpointRow(id);
    try {
      const { chain, authorized, error } = await fetchChain(e.host, e.port, probe);
      const parsed = chain.map((der) => parsePem(`-----BEGIN CERTIFICATE-----\n${der.toString("base64")}\n-----END CERTIFICATE-----`)[0]!);
      if (!parsed.length) throw new Error(`${e.host}:${e.port} sent no certificate.`);
      ingestParsed(parsed, `${e.host}:${e.port}`);
      db.prepare("UPDATE endpoints SET last_probe_at = ?, last_error = NULL, chain_valid = ?, chain_error = ?, cert_id = ? WHERE id = ?").run(
        now(),
        authorized ? 1 : 0,
        error,
        parsed[0]!.id,
        id,
      );
    } catch (err) {
      db.prepare("UPDATE endpoints SET last_probe_at = ?, last_error = ? WHERE id = ?").run(now(), (err as Error).message.slice(0, 500), id);
    }
    return presentEndpoint(endpointRow(id));
  }

  /** Certificates that expire in each of the next 13 weeks, counted from now. */
  const expiryWeeks = () => {
    const from = Date.now();
    const weeks = Array.from({ length: 13 }, (_, i) => ({ start: new Date(from + i * 7 * DAY).toISOString(), certificates: 0 }));
    const until = new Date(from + 13 * 7 * DAY).toISOString();
    for (const r of db.prepare("SELECT not_after FROM certificates WHERE not_after >= ? AND not_after < ?").all(weeks[0]!.start, until) as Array<{
      not_after: string;
    }>)
      weeks[Math.floor((Date.parse(r.not_after) - from) / (7 * DAY))]!.certificates++;
    return weeks;
  };

  const countStates = () => {
    const out = Object.fromEntries(STATES.map((s) => [s, 0])) as Record<State, number>;
    const at = Date.now();
    for (const r of db.prepare("SELECT not_before, not_after FROM certificates").all() as Array<Pick<CertRow, "not_before" | "not_after">>)
      out[stateOf(r, at)]++;
    return out;
  };

  return {
    warnDays,

    /** Takes PEM text from CI, a collector or a person. A private key in it refuses the whole body. */
    ingest(text: string, source: string | null | undefined) {
      const from = source ?? "upload";
      if (!SOURCE.test(from)) throw bad("source is printable text of up to 255 characters, such as host:443 or a file path.");
      let parsed: Parsed[];
      try {
        parsed = parsePem(text);
      } catch (err) {
        if (!(err instanceof PemError)) throw err;
        throw new CertsError(422, /private key/.test(err.message) ? "private-key" : "invalid-pem", err.message);
      }
      return ingestParsed(parsed, from);
    },

    list: (filter: CertFilter, cursor: string | undefined, limit: number) => listQuery(filter, cursor, limit),

    certificate(id: string) {
      const r = row(id);
      return {
        ...present(r),
        pem: r.pem,
        chain: chainOf(r).map((c) => ({
          id: c.id,
          commonName: c.subject_cn,
          subject: c.subject,
          notAfter: c.not_after,
          state: stateOf(c),
          ca: c.is_ca === 1,
          selfSigned: c.self_signed === 1,
        })),
      };
    },

    deleteCertificate(id: string) {
      if (db.prepare("DELETE FROM certificates WHERE id = ?").run(id).changes === 0) throw notFound("The certificate");
    },

    /** Certificates that crossed a threshold since a time, tightest crossings first. */
    expiring(since: string, limit: number) {
      checkExpiry();
      const rows = db
        .prepare(
          "SELECT m.threshold, m.crossed_at, c.* FROM expiry_marks m JOIN certificates c ON c.id = m.cert_id WHERE m.crossed_at >= ? ORDER BY m.threshold, c.not_after LIMIT ?",
        )
        .all(since, limit) as unknown as Array<CertRow & { threshold: number; crossed_at: string }>;
      return rows.map((r) => ({ threshold: r.threshold, crossedAt: r.crossed_at, certificate: present(r) }));
    },
    checkExpiry,

    // Endpoints.
    listEndpoints: () => (db.prepare("SELECT * FROM endpoints ORDER BY host, port").all() as Array<Record<string, any>>).map(presentEndpoint),
    endpoint: (id: string) => presentEndpoint(endpointRow(id)),
    deleteEndpoint(id: string) {
      if (endpointRow(id).source === "file")
        throw new CertsError(409, "conflict", "This endpoint comes from the endpoints file (OPENASY_ENDPOINTS). Remove it there.");
      // Only endpoints added here before the file was the way in (ADR 0052) can be removed here.
      db.prepare("DELETE FROM endpoints WHERE id = ?").run(id);
    },

    /**
     * Makes the endpoints match the endpoints file (ADR 0052): the https:// and tls:// entries, by host and port. An
     * endpoint added here before, at an address the file names, becomes the file's and keeps what was read. The addresses are checked again at every probe, so a name on a private
     * address is kept with the error the probe gives it rather than refusing the file. Returns what to fix that did not
     * stop it.
     */
    syncFile(endpoints: Endpoint[]): string[] {
      const wanted = endpoints.filter((e) => e.kind === "tls" || e.url.startsWith("https://"));
      for (const e of wanted) if (!validHost(e.host)) throw new Error(`${e.name}: ${e.host} is not a host name or an address.`);
      const warnings: string[] = [];
      const kept: string[] = [];
      db.exec("BEGIN IMMEDIATE");
      try {
        for (const e of wanted) {
          const id = fileId(e.name);
          const host = e.host.toLowerCase();
          const same = db.prepare("SELECT id, source FROM endpoints WHERE host = ? AND port = ?").get(host, e.port) as
            { id: string; source: string } | undefined;
          if (same && same.id !== id) {
            // Two entries for one address, such as https:// and tls://, are one endpoint.
            if (same.source !== "ui" || db.prepare("SELECT 1 FROM endpoints WHERE id = ?").get(id)) continue;
            db.prepare("UPDATE endpoints SET id = ?, source = 'file', name = ?, server = ? WHERE id = ?").run(id, e.name, e.server, same.id);
          }
          kept.push(id);
          const current = db.prepare("SELECT host, port FROM endpoints WHERE id = ?").get(id) as { host: string; port: number } | undefined;
          if (!current) {
            db.prepare("INSERT INTO endpoints (id, host, port, created_at, source, name, server) VALUES (?, ?, ?, ?, 'file', ?, ?)").run(
              id,
              host,
              e.port,
              now(),
              e.name,
              e.server,
            );
          } else if (current.host !== host || current.port !== e.port) {
            // Another address is another endpoint: what was probed at the old one is not its.
            db.prepare(
              "UPDATE endpoints SET host = ?, port = ?, name = ?, server = ?, last_probe_at = NULL, last_error = NULL, chain_valid = NULL, chain_error = NULL, cert_id = NULL WHERE id = ?",
            ).run(host, e.port, e.name, e.server, id);
          } else {
            db.prepare("UPDATE endpoints SET name = ?, server = ? WHERE id = ?").run(e.name, e.server, id);
          }
        }
        const gone = (db.prepare("SELECT id FROM endpoints WHERE source = 'file'").all() as Array<{ id: string }>).filter((r) => !kept.includes(r.id));
        for (const r of gone) db.prepare("DELETE FROM endpoints WHERE id = ?").run(r.id);
        db.exec("COMMIT");
      } catch (err) {
        db.exec("ROLLBACK");
        throw err;
      }
      return warnings;
    },

    /** Endpoints never probed yet, such as the ones a file just added, so they do not wait for the next round. */
    async probeNew() {
      for (const e of db.prepare("SELECT id FROM endpoints WHERE last_probe_at IS NULL ORDER BY created_at").all() as Array<{ id: string }>)
        await probeEndpoint(e.id);
    },
    probeEndpoint,
    /** Every endpoint, one after another: a probe is a connection to someone else's server. */
    async probeAll() {
      for (const e of db.prepare("SELECT id FROM endpoints ORDER BY last_probe_at").all() as Array<{ id: string }>) await probeEndpoint(e.id);
    },

    summary() {
      const states = countStates();
      const certificates = Object.values(states).reduce((a, b) => a + b, 0);
      const withWarnings = (db.prepare("SELECT COUNT(*) AS n FROM certificates WHERE warnings <> '[]'").get() as { n: number }).n;
      const endpoints = (db.prepare("SELECT COUNT(*) AS n FROM endpoints").get() as { n: number }).n;
      const failing = (db.prepare("SELECT COUNT(*) AS n FROM endpoints WHERE last_error IS NOT NULL").get() as { n: number }).n;
      const next = db.prepare("SELECT * FROM certificates WHERE not_after >= ? ORDER BY not_after LIMIT 1").get(now()) as CertRow | undefined;
      return {
        certificates,
        states,
        withWarnings,
        endpoints,
        failingEndpoints: failing,
        warnDays,
        nextExpiry: next ? { id: next.id, commonName: next.subject_cn, notAfter: next.not_after, daysLeft: daysLeft(next) } : null,
        expiryWeeks: expiryWeeks(),
      };
    },

    countStates,

    purge() {
      const before = new Date(Date.now() - retentionDays * DAY).toISOString();
      db.prepare("DELETE FROM certificates WHERE last_seen < ? AND id NOT IN (SELECT cert_id FROM endpoints WHERE cert_id IS NOT NULL)").run(before);
    },
  };
}

export type Certs = ReturnType<typeof createCerts>;
