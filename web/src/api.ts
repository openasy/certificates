// The UI is an ordinary client of the public API (ADR 0014, 0018). Types follow openapi.json.

export type State = "valid" | "expiring" | "critical" | "expired" | "not-yet-valid";
export type Warning = "weak-key" | "weak-signature" | "wildcard" | "self-signed" | "long-lifetime";

/** Another OpenAsy product of this install, from OPENASY_PRODUCTS. */
export interface ProductLink {
  id: string;
  url: string;
}

export interface Source {
  source: string;
  position: number;
  lastSeen: string;
}

export interface Certificate {
  id: string;
  subject: string;
  commonName: string | null;
  names: string[];
  issuer: string;
  issuerCommonName: string | null;
  serial: string;
  notBefore: string;
  notAfter: string;
  daysLeft: number;
  state: State;
  keyType: string;
  keyBits: number | null;
  signature: string;
  ca: boolean;
  selfSigned: boolean;
  warnings: Warning[];
  sources: Source[];
  firstSeen: string;
  lastSeen: string;
}

export interface CertificateDetail extends Certificate {
  pem: string;
  chain: Array<{ id: string; commonName: string | null; subject: string; notAfter: string; state: State; ca: boolean; selfSigned: boolean }>;
}

export interface Endpoint {
  id: string;
  host: string;
  port: number;
  /** The entry's name in the endpoints file; null for endpoints added here. */
  name: string | null;
  /** file: from the endpoints file (OPENASY_ENDPOINTS); removed there, not here. */
  source: "ui" | "file";
  /** The server it runs on, by its name in the hosts file. */
  server: string | null;
  lastProbeAt: string | null;
  lastError: string | null;
  chainValid: boolean | null;
  chainError: string | null;
  certificate: { id: string; commonName: string | null; notAfter: string; daysLeft: number; state: State } | null;
  createdAt: string;
}

export interface Summary {
  certificates: number;
  states: Record<State, number>;
  withWarnings: number;
  endpoints: number;
  failingEndpoints: number;
  warnDays: number[];
  nextExpiry: { id: string; commonName: string | null; notAfter: string; daysLeft: number } | null;
  endpointsFile: EndpointsFile | null;
  /** Certificates that expire in each of the next 13 weeks, counted from now, soonest first. */
  expiryWeeks: Array<{ start: string; certificates: number }>;
}

/** The endpoints file (ADR 0052), shared with Uptime: a file that cannot be applied leaves its last good version. */
export interface EndpointsFile {
  path: string;
  appliedAt: string | null;
  entries: number;
  error: string | null;
  warnings: string[];
}

export class Unauthorized extends Error {}
/** The signed-in owner or admin has no second factor yet; the sign-in gate asks for one. */
export class MfaSetupRequired extends Error {}
export class ApiError extends Error {}

// The session is an HttpOnly cookie set by sign-in (@openasy/auth); the browser sends it, nothing is stored here.
export async function api<T>(path: string, init: RequestInit = {}): Promise<T> {
  const res = await fetch(path, {
    ...init,
    credentials: "same-origin",
    headers: { ...(init.body ? { "content-type": "application/json" } : {}), ...init.headers },
  });
  if (!res.ok) {
    const problem = (await res.json().catch(() => ({}))) as { code?: string; detail?: string };
    if (res.status === 401) throw new Unauthorized(problem.detail);
    if (problem.code === "mfa-setup-required") throw new MfaSetupRequired(problem.detail);
    throw new ApiError(problem.detail ?? `${path}: ${res.status}`);
  }
  return (res.status === 204 ? undefined : await res.json()) as T;
}

/** What the overview draws besides the summary (GET /api/v1/overview). Counts are of certificates still valid. */
export interface Overview {
  byIssuer: Array<{ issuer: string; certificates: number }>;
  byKey: Array<{ key: string; certificates: number }>;
  warnings: Record<Warning, number>;
  /** The next eight to end. */
  soonest: Array<{ id: string; commonName: string | null; issuer: string; notAfter: string; daysLeft: number }>;
}
