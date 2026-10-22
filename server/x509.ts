import { X509Certificate } from "node:crypto";

export class PemError extends Error {}

export interface Parsed {
  id: string;
  subject: string;
  subjectCn: string | null;
  sans: string[];
  issuer: string;
  issuerCn: string | null;
  serial: string;
  notBefore: string;
  notAfter: string;
  keyType: string;
  keyBits: number | null;
  signature: string;
  isCa: boolean;
  selfSigned: boolean;
  warnings: string[];
  pem: string;
}

/** Most certificates one upload may hold, and the largest body: a chain is a few KB. */
export const MAX_CERTIFICATES = 100;
export const PEM_LIMIT = 1024 * 1024;

const BLOCK = /-----BEGIN CERTIFICATE-----[\s\S]+?-----END CERTIFICATE-----/g;
/** Every kind of private key block: RSA, EC, PKCS#8, encrypted. */
const PRIVATE_KEY = /-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----/;

const SIGNATURES: Record<string, string> = {
  "1.2.840.113549.1.1.4": "md5WithRSAEncryption",
  "1.2.840.113549.1.1.5": "sha1WithRSAEncryption",
  "1.2.840.113549.1.1.10": "rsassa-pss",
  "1.2.840.113549.1.1.11": "sha256WithRSAEncryption",
  "1.2.840.113549.1.1.12": "sha384WithRSAEncryption",
  "1.2.840.113549.1.1.13": "sha512WithRSAEncryption",
  "1.2.840.10045.4.1": "ecdsa-with-SHA1",
  "1.2.840.10045.4.3.2": "ecdsa-with-SHA256",
  "1.2.840.10045.4.3.3": "ecdsa-with-SHA384",
  "1.2.840.10045.4.3.4": "ecdsa-with-SHA512",
  "1.3.101.112": "Ed25519",
  "1.3.101.113": "Ed448",
};
const WEAK_SIGNATURES = new Set(["md5WithRSAEncryption", "sha1WithRSAEncryption", "ecdsa-with-SHA1"]);

/** Reads one DER element at offset: its tag, where its content starts and ends. */
function element(der: Buffer, at: number) {
  const tag = der[at]!;
  let length = der[at + 1]!;
  let start = at + 2;
  if (length & 0x80) {
    const n = length & 0x7f;
    if (n < 1 || n > 4) throw new PemError("not a certificate");
    length = 0;
    for (let i = 0; i < n; i++) length = length * 256 + der[at + 2 + i]!;
    start = at + 2 + n;
  }
  if (start + length > der.length) throw new PemError("not a certificate");
  return { tag, start, end: start + length };
}

/** The signature algorithm is the second element of the certificate; node:crypto does not expose it. */
export function signatureAlgorithm(der: Buffer): string {
  const outer = element(der, 0);
  const tbs = element(der, outer.start);
  const algorithm = element(der, tbs.end);
  const oid = element(der, algorithm.start);
  if (oid.tag !== 0x06) throw new PemError("not a certificate");
  const bytes = der.subarray(oid.start, oid.end);
  const parts: number[] = [Math.floor(bytes[0]! / 40), bytes[0]! % 40];
  let value = 0;
  for (const b of bytes.subarray(1)) {
    value = value * 128 + (b & 0x7f);
    if (!(b & 0x80)) (parts.push(value), (value = 0));
  }
  const dotted = parts.join(".");
  return SIGNATURES[dotted] ?? dotted;
}

const field = (dn: string, key: string) => dn.split("\n").find((l) => l.startsWith(`${key}=`))?.slice(key.length + 1) ?? null;

/** DNS:a.example.com, IP Address:10.0.0.1 and the like, without the quoting node adds to odd values. */
function names(san: string | undefined): string[] {
  if (!san) return [];
  return [...san.matchAll(/(DNS|IP Address|email|URI):("(?:[^"\\]|\\.)*"|[^,]+)/g)].map((m) => `${m[1] === "IP Address" ? "IP" : m[1]}:${m[2]!.replace(/^"|"$/g, "").trim()}`);
}

const DAY = 86_400_000;

/** Parses one certificate and finds what is worth a warning (ADR 0046). */
export function parseCertificate(pem: string): Parsed {
  let x: X509Certificate;
  try {
    x = new X509Certificate(pem);
  } catch {
    throw new PemError("not a certificate");
  }
  const key = x.publicKey;
  const details = key.asymmetricKeyDetails ?? {};
  const keyType = key.asymmetricKeyType ?? "unknown";
  const keyBits = typeof details.modulusLength === "number" ? details.modulusLength : keyType === "ec" ? curveBits(details.namedCurve) : keyType === "ed25519" ? 256 : null;
  const signature = signatureAlgorithm(x.raw);
  let selfSigned = false;
  if (x.subject === x.issuer) {
    try {
      selfSigned = x.verify(key);
    } catch {
      selfSigned = false;
    }
  }
  const sans = names(x.subjectAltName);
  const notBefore = x.validFromDate.toISOString();
  const notAfter = x.validToDate.toISOString();
  const subjectCn = field(x.subject, "CN");
  const warnings: string[] = [];
  if (keyType === "rsa" && keyBits !== null && keyBits < 2048) warnings.push("weak-key");
  if (WEAK_SIGNATURES.has(signature)) warnings.push("weak-signature");
  if ([subjectCn ?? "", ...sans.map((s) => s.slice(s.indexOf(":") + 1))].some((n) => n.startsWith("*."))) warnings.push("wildcard");
  if (!x.ca) {
    if (selfSigned) warnings.push("self-signed");
    if ((x.validToDate.getTime() - x.validFromDate.getTime()) / DAY > 398) warnings.push("long-lifetime");
  }
  return {
    id: x.fingerprint256.replace(/:/g, "").toLowerCase(),
    subject: x.subject.replace(/\n/g, ", "),
    subjectCn,
    sans,
    issuer: x.issuer.replace(/\n/g, ", "),
    issuerCn: field(x.issuer, "CN"),
    serial: x.serialNumber.toLowerCase(),
    notBefore,
    notAfter,
    keyType,
    keyBits,
    signature,
    isCa: x.ca,
    selfSigned,
    warnings,
    pem: x.toString().trim() + "\n",
  };
}

function curveBits(curve: string | undefined): number | null {
  const m = curve?.match(/(\d{3})/);
  return m ? Number(m[1]) : curve === "prime256v1" ? 256 : null;
}

/**
 * The certificates in a body of PEM text. A body that holds any private key is refused whole, before it is parsed
 * and without echoing any of it (ADR 0046).
 */
export function parsePem(text: string): Parsed[] {
  if (PRIVATE_KEY.test(text)) throw new PemError("The body contains a private key. Send certificates only; the key stays where it is.");
  const blocks = text.match(BLOCK) ?? [];
  if (!blocks.length) throw new PemError("No certificate found: send PEM text with -----BEGIN CERTIFICATE----- blocks.");
  if (blocks.length > MAX_CERTIFICATES) throw new PemError(`A body may hold at most ${MAX_CERTIFICATES} certificates.`);
  return blocks.map((b, i) => {
    try {
      return parseCertificate(b);
    } catch {
      throw new PemError(`Certificate ${i + 1} could not be read.`);
    }
  });
}
