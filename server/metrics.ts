// Prometheus text exposition, written by hand: a few lines, no client library needed.
const requests = new Map<string, number>();

export function countRequest(method: string, route: string, status: number) {
  const key = `method="${method}",route="${route}",status="${status}"`;
  requests.set(key, (requests.get(key) ?? 0) + 1);
}

export interface Gauges {
  /** Every certificate by state. */
  states: Record<string, number>;
  withWarnings: number;
  endpoints: number;
  failingEndpoints: number;
}

export function renderMetrics(version: string, g: Gauges): string {
  const lines = [
    "# HELP openasy_build_info Build information.",
    "# TYPE openasy_build_info gauge",
    `openasy_build_info{product="certificates",version="${version}"} 1`,
    "# HELP openasy_http_requests_total HTTP requests handled.",
    "# TYPE openasy_http_requests_total counter",
    ...[...requests].map(([labels, n]) => `openasy_http_requests_total{${labels}} ${n}`),
    "# HELP openasy_certificates_total Certificates in the inventory by state.",
    "# TYPE openasy_certificates_total gauge",
    ...Object.entries(g.states).map(([s, n]) => `openasy_certificates_total{state="${s}"} ${n}`),
    "# HELP openasy_certificates_expiring Certificates that are expiring, critical or expired, to alert on.",
    "# TYPE openasy_certificates_expiring gauge",
    ...["expiring", "critical", "expired"].map((s) => `openasy_certificates_expiring{state="${s}"} ${g.states[s] ?? 0}`),
    "# HELP openasy_certificates_with_warnings Certificates with a weak key or signature, a wildcard, a self-signed leaf or a long lifetime.",
    "# TYPE openasy_certificates_with_warnings gauge",
    `openasy_certificates_with_warnings ${g.withWarnings}`,
    "# HELP openasy_certificates_endpoints Endpoints the server probes.",
    "# TYPE openasy_certificates_endpoints gauge",
    `openasy_certificates_endpoints ${g.endpoints}`,
    "# HELP openasy_certificates_endpoints_failing Endpoints whose last probe failed.",
    "# TYPE openasy_certificates_endpoints_failing gauge",
    `openasy_certificates_endpoints_failing ${g.failingEndpoints}`,
    "# HELP process_uptime_seconds Seconds since the process started.",
    "# TYPE process_uptime_seconds gauge",
    `process_uptime_seconds ${process.uptime().toFixed(0)}`,
  ];
  return lines.join("\n") + "\n";
}
