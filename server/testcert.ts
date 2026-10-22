// Real X.509 certificates for tests, built here because node:crypto reads them but cannot make them, and the dates
// must be ours to choose. DER by hand; signed with node:crypto.
import { createPrivateKey, generateKeyPairSync, sign, type KeyObject } from "node:crypto";

const length = (n: number) => (n < 128 ? Buffer.from([n]) : n < 256 ? Buffer.from([0x81, n]) : Buffer.from([0x82, n >> 8, n & 255]));
const tlv = (tag: number, ...parts: Buffer[]) => {
  const body = Buffer.concat(parts);
  return Buffer.concat([Buffer.from([tag]), length(body.length), body]);
};
const seq = (...p: Buffer[]) => tlv(0x30, ...p);
const set = (...p: Buffer[]) => tlv(0x31, ...p);
const int = (n: number | Buffer) => {
  const b = typeof n === "number" ? Buffer.from(n.toString(16).padStart(n.toString(16).length % 2 ? n.toString(16).length + 1 : n.toString(16).length, "0"), "hex") : n;
  return tlv(0x02, b[0]! & 0x80 ? Buffer.concat([Buffer.from([0]), b]) : b);
};
const oid = (dotted: string) => {
  const p = dotted.split(".").map(Number);
  const out = [p[0]! * 40 + p[1]!];
  for (const n of p.slice(2)) {
    const chunk = [n & 0x7f];
    for (let v = n >> 7; v > 0; v >>= 7) chunk.unshift((v & 0x7f) | 0x80);
    out.push(...chunk);
  }
  return tlv(0x06, Buffer.from(out));
};
const utf8 = (s: string) => tlv(0x0c, Buffer.from(s));
const bits = (b: Buffer) => tlv(0x03, Buffer.concat([Buffer.from([0]), b]));
const octets = (b: Buffer) => tlv(0x04, b);
const bool = (v: boolean) => tlv(0x01, Buffer.from([v ? 0xff : 0]));
const pad = (n: number) => String(n).padStart(2, "0");
const time = (d: Date) => {
  const y = d.getUTCFullYear();
  const rest = `${pad(d.getUTCMonth() + 1)}${pad(d.getUTCDate())}${pad(d.getUTCHours())}${pad(d.getUTCMinutes())}${pad(d.getUTCSeconds())}Z`;
  return y < 2050 ? tlv(0x17, Buffer.from(`${pad(y % 100)}${rest}`)) : tlv(0x18, Buffer.from(`${y}${rest}`));
};
const name = (cn: string) => seq(set(seq(oid("2.5.4.3"), utf8(cn))));

export type SignatureHash = "sha256" | "sha1";
const ALGORITHMS = {
  rsa: { sha256: seq(oid("1.2.840.113549.1.1.11"), tlv(0x05, Buffer.alloc(0))), sha1: seq(oid("1.2.840.113549.1.1.5"), tlv(0x05, Buffer.alloc(0))) },
  ec: { sha256: seq(oid("1.2.840.10045.4.3.2")), sha1: seq(oid("1.2.840.10045.4.1")) },
  ed25519: { sha256: seq(oid("1.3.101.112")), sha1: seq(oid("1.3.101.112")) },
} as const;

export interface KeyPair {
  privateKey: KeyObject;
  publicKey: KeyObject;
}

const cache = new Map<string, KeyPair>();
/** Key pairs are slow to make and tests need only a few kinds, so they are made once. */
export function keys(kind: "rsa2048" | "rsa1024" | "ec" | "ed25519" | "rsa2048b" = "rsa2048"): KeyPair {
  let k = cache.get(kind);
  if (!k) {
    k =
      kind === "ec"
        ? generateKeyPairSync("ec", { namedCurve: "prime256v1" })
        : kind === "ed25519"
          ? generateKeyPairSync("ed25519")
          : generateKeyPairSync("rsa", { modulusLength: kind === "rsa1024" ? 1024 : 2048 });
    cache.set(kind, k);
  }
  return k;
}

const DAY = 86_400_000;
/** A date this many days from now. */
export const inDays = (n: number) => new Date(Date.now() + n * DAY);

export interface CertOptions {
  cn: string;
  sans?: string[];
  ips?: string[];
  notBefore?: Date;
  notAfter?: Date;
  ca?: boolean;
  keyKind?: Parameters<typeof keys>[0];
  hash?: SignatureHash;
  /** Signed by this certificate's key; without it the certificate signs itself. */
  issuer?: { cn: string; privateKey: KeyObject };
  serial?: number;
}

export function makeCert(o: CertOptions) {
  const pair = keys(o.keyKind ?? "rsa2048");
  const signer = o.issuer ? o.issuer.privateKey : pair.privateKey;
  const type = pair.publicKey.asymmetricKeyType as "rsa" | "ec" | "ed25519";
  const signerType = signer.asymmetricKeyType as "rsa" | "ec" | "ed25519";
  const hash = o.hash ?? "sha256";
  const algorithm = ALGORITHMS[signerType][hash];
  const general = [
    ...(o.sans ?? []).map((s) => tlv(0x82, Buffer.from(s))),
    ...(o.ips ?? []).map((ip) => tlv(0x87, Buffer.from(ip.split(".").map(Number)))),
  ];
  const extensions = [
    seq(oid("2.5.29.19"), bool(true), octets(seq(...(o.ca ? [bool(true)] : [])))),
    ...(general.length ? [seq(oid("2.5.29.17"), octets(seq(...general)))] : []),
  ];
  const tbs = seq(
    tlv(0xa0, int(2)),
    int(o.serial ?? 1000 + Math.floor(Math.random() * 1_000_000)),
    algorithm,
    name(o.issuer ? o.issuer.cn : o.cn),
    seq(time(o.notBefore ?? inDays(-1)), time(o.notAfter ?? inDays(90))),
    name(o.cn),
    pair.publicKey.export({ type: "spki", format: "der" }) as Buffer,
    tlv(0xa3, seq(...extensions)),
  );
  const signature = signerType === "ed25519" ? sign(null, tbs, signer) : sign(hash, tbs, signer);
  const der = seq(tbs, algorithm, bits(signature));
  const pem = `-----BEGIN CERTIFICATE-----\n${der.toString("base64").replace(/(.{64})/g, "$1\n").trim()}\n-----END CERTIFICATE-----\n`;
  void type;
  return { pem, der, ...pair };
}

/** A private key in PEM, for tests that must prove a key is refused. */
export const privateKeyPem = (kind: Parameters<typeof keys>[0] = "rsa2048") => keys(kind).privateKey.export({ type: "pkcs8", format: "pem" }) as string;
export { createPrivateKey };
