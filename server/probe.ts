import { lookup } from "node:dns/promises";
import { isIP } from "node:net";
import { connect } from "node:tls";

/** Addresses the server may not connect to: it must not be turned on its own network or on a cloud's metadata service. */
export function isPrivate(address: string): boolean {
  const a = address.toLowerCase().replace(/^\[|\]$/g, "");
  if (a.startsWith("::ffff:")) return isPrivate(a.slice(7));
  if (isIP(a) === 4) {
    const [p, q] = a.split(".").map(Number) as [number, number];
    return p === 0 || p === 10 || p === 127 || (p === 100 && q >= 64 && q <= 127) || (p === 169 && q === 254) || (p === 172 && q >= 16 && q <= 31) || (p === 192 && q === 168) || (p === 192 && q === 0) || p >= 224;
  }
  return a === "::" || a === "::1" || a.startsWith("fc") || a.startsWith("fd") || /^fe[89ab]/.test(a);
}

export interface ProbeOptions {
  /** Resolves a name to addresses. Tests replace it. */
  resolve?: (host: string) => Promise<string[]>;
  /** Lets the probe reach loopback and private addresses. Only tests set it; there is no setting for it (ADR 0046). */
  allowPrivate?: boolean;
  timeoutMs?: number;
}

export interface Chain {
  /** DER of the certificates the server sent, leaf first. */
  chain: Buffer[];
  /** Whether the chain is trusted by the system's roots and fits the name. Read apart from the chain itself. */
  authorized: boolean;
  error: string | null;
}

const HOST = /^(?=.{1,253}$)([A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)*[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?$/;

export const validHost = (host: string) => (isIP(host) !== 0 || HOST.test(host)) && !/^\d+$/.test(host);

const system = async (host: string) => (await lookup(host, { all: true })).map((a) => a.address);

/** One public address for a host, or an error saying why not. Every address must be public, so no answer can mix in a private one. */
export async function resolvePublic(host: string, { resolve = system, allowPrivate = false }: ProbeOptions = {}): Promise<string> {
  const addresses = isIP(host) ? [host] : await resolve(host).catch(() => []);
  if (!addresses.length) throw new Error(`${host} does not resolve.`);
  if (!allowPrivate && addresses.some(isPrivate)) throw new Error(`${host} is on a private address. Certificates on private networks are reported by a collector in that network; the server itself only connects to public addresses.`);
  return addresses[0]!;
}

/**
 * Reads the certificates a server presents. The connection goes to the address that was checked, not to the name, so a
 * name that changes its answer in between gets nothing. Verification is off only so the chain can be read from servers
 * whose certificate is wrong; whether it is right is reported separately.
 */
export async function fetchChain(host: string, port: number, options: ProbeOptions = {}): Promise<Chain> {
  const address = await resolvePublic(host, options);
  return new Promise((resolve, reject) => {
    const socket = connect({ host: address, port, servername: isIP(host) ? undefined : host, rejectUnauthorized: false, timeout: options.timeoutMs ?? 5000 });
    const fail = (message: string) => (socket.destroy(), reject(new Error(message)));
    socket.once("timeout", () => fail(`${host}:${port} did not answer within ${(options.timeoutMs ?? 5000) / 1000} s.`));
    socket.once("error", (err) => fail(`${host}:${port}: ${err.message}`));
    socket.once("secureConnect", () => {
      const chain: Buffer[] = [];
      let cert = socket.getPeerCertificate(true);
      while (cert?.raw && chain.length < 10 && !chain.some((c) => c.equals(cert.raw))) {
        chain.push(cert.raw);
        cert = cert.issuerCertificate;
      }
      const result = { chain, authorized: socket.authorized, error: socket.authorized ? null : String(socket.authorizationError ?? "not trusted") };
      socket.end();
      resolve(result);
    });
  });
}
