import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { openDb } from "./db.ts";

describe("openDb", () => {
  it("uses WAL and migrates once", () => {
    const path = join(mkdtempSync(join(tmpdir(), "certificates-")), "nested", "certificates.db");
    const first = openDb(path);
    expect(first.prepare("PRAGMA journal_mode").get()).toEqual({ journal_mode: "wal" });
    first.close();

    const second = openDb(path);
    expect(second.prepare("SELECT COUNT(*) AS n FROM schema_migrations").get()).toEqual({ n: 2 });
    second.close();
  });

  it("keeps no private key and no column for one", () => {
    const db = openDb(":memory:");
    const columns = (t: string) => (db.prepare(`PRAGMA table_info(${t})`).all() as Array<{ name: string }>).map((c) => c.name);
    for (const table of ["certificates", "sources", "endpoints", "expiry_marks"]) expect(columns(table).join(" "), table).not.toMatch(/key_pem|private|secret/);
  });

  it("deletes a certificate's places and marks with it, and forgets it on an endpoint", () => {
    const db = openDb(":memory:");
    db.exec(`INSERT INTO certificates VALUES ('c', 's', NULL, '[]', 'i', NULL, '1', 'a', 'b', 'rsa', 2048, 'x', 0, 0, '[]', 'pem', 'now', 'now');
      INSERT INTO sources VALUES ('c', 'host:443', 0, 'now');
      INSERT INTO expiry_marks VALUES ('c', 30, 'now');
      INSERT INTO endpoints (id, host, port, created_at, cert_id) VALUES ('e', 'x.example.com', 443, 'now', 'c');
      DELETE FROM certificates`);
    expect(db.prepare("SELECT (SELECT COUNT(*) FROM sources) + (SELECT COUNT(*) FROM expiry_marks) AS n").get()).toEqual({ n: 0 });
    expect(db.prepare("SELECT cert_id FROM endpoints").get()).toEqual({ cert_id: null });
  });
});
