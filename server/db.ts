import { mkdirSync } from "node:fs";
import { dirname } from "node:path";
import { DatabaseSync } from "node:sqlite";

// Forward-only migrations (ADR 0010): append new entries, never edit or remove old ones.
const MIGRATIONS = [
  `CREATE TABLE settings (key TEXT PRIMARY KEY, value TEXT NOT NULL);
   -- A certificate is found again by the sha256 of its DER encoding. Only public certificates are kept: a body
   -- with a private key is refused before anything is parsed (ADR 0046).
   CREATE TABLE certificates (
     id TEXT PRIMARY KEY,
     subject TEXT NOT NULL,
     subject_cn TEXT,
     sans TEXT NOT NULL,
     issuer TEXT NOT NULL,
     issuer_cn TEXT,
     serial TEXT NOT NULL,
     not_before TEXT NOT NULL,
     not_after TEXT NOT NULL,
     key_type TEXT NOT NULL,
     key_bits INTEGER,
     signature TEXT NOT NULL,
     is_ca INTEGER NOT NULL,
     self_signed INTEGER NOT NULL,
     warnings TEXT NOT NULL,
     pem TEXT NOT NULL,
     first_seen TEXT NOT NULL,
     last_seen TEXT NOT NULL
   );
   CREATE INDEX certificates_expiry ON certificates (not_after);
   -- Where a certificate was seen, and at which place of the chain that was sent (0 is the leaf).
   CREATE TABLE sources (
     cert_id TEXT NOT NULL REFERENCES certificates (id) ON DELETE CASCADE,
     source TEXT NOT NULL,
     position INTEGER NOT NULL,
     last_seen TEXT NOT NULL,
     PRIMARY KEY (cert_id, source)
   );
   -- An address the server connects to itself, on public addresses only.
   CREATE TABLE endpoints (
     id TEXT PRIMARY KEY,
     host TEXT NOT NULL,
     port INTEGER NOT NULL,
     created_at TEXT NOT NULL,
     last_probe_at TEXT,
     last_error TEXT,
     chain_valid INTEGER,
     chain_error TEXT,
     cert_id TEXT REFERENCES certificates (id) ON DELETE SET NULL,
     UNIQUE (host, port)
   );
   -- The tightest threshold a certificate has crossed, written once, so each crossing is reported once.
   CREATE TABLE expiry_marks (
     cert_id TEXT NOT NULL REFERENCES certificates (id) ON DELETE CASCADE,
     threshold INTEGER NOT NULL,
     crossed_at TEXT NOT NULL,
     PRIMARY KEY (cert_id, threshold)
   )`,
  `-- Endpoints from the endpoints file (OPENASY_ENDPOINTS, ADR 0052) are changed there, not here. name is the entry's
   -- name in the file; server names the server the endpoint runs on, from the hosts file.
   ALTER TABLE endpoints ADD COLUMN source TEXT NOT NULL DEFAULT 'ui' CHECK (source IN ('ui', 'file'));
   ALTER TABLE endpoints ADD COLUMN name TEXT;
   ALTER TABLE endpoints ADD COLUMN server TEXT`,
];

/** Opens the product's single SQLite file in WAL mode (ADR 0011) and migrates it forward. */
export function openDb(path: string): DatabaseSync {
  if (path !== ":memory:") mkdirSync(dirname(path), { recursive: true });
  const db = new DatabaseSync(path);
  db.exec("PRAGMA journal_mode = WAL; PRAGMA foreign_keys = ON; PRAGMA busy_timeout = 5000;");
  db.exec("CREATE TABLE IF NOT EXISTS schema_migrations (version INTEGER PRIMARY KEY, applied_at TEXT NOT NULL)");
  const row = db.prepare("SELECT COALESCE(MAX(version), 0) AS v FROM schema_migrations").get() as { v: number };
  for (let v = row.v; v < MIGRATIONS.length; v++) {
    db.exec("BEGIN");
    try {
      db.exec(MIGRATIONS[v]!);
      db.prepare("INSERT INTO schema_migrations (version, applied_at) VALUES (?, ?)").run(v + 1, new Date().toISOString());
      db.exec("COMMIT");
    } catch (err) {
      db.exec("ROLLBACK");
      throw err;
    }
  }
  return db;
}
