// What the search window (Cmd+K) finds in Certificates: certificates by name, issuer or place, from the API, and
// endpoints by host or name.
import type { SearchFn, SearchResult } from "@openasy/ui";
import { BadgeCheck, Radar } from "lucide-react";
import type { Certificate, Endpoint } from "./api.ts";
import type { T } from "./i18n.ts";

type Call = <R>(path: string, init?: RequestInit) => Promise<R>;
const query = (q: string) => new URLSearchParams({ q, limit: "8" });

export function search(call: Call, t: T): SearchFn {
  return async (q, signal) => {
    const [found, endpoints] = await Promise.all([
      call<{ certificates: Certificate[] }>(`/api/v1/certificates?${query(q)}`, { signal }),
      call<{ endpoints: Endpoint[] }>("/api/v1/endpoints", { signal }),
    ]);
    const certificates: SearchResult[] = found.certificates.map((c) => ({
      id: `certificate:${c.id}`,
      label: c.commonName ?? c.subject,
      detail: t("search.certificateDetail", { issuer: c.issuerCommonName ?? c.issuer, days: c.daysLeft }),
      kind: t("search.certificate"),
      icon: BadgeCheck,
      severity: c.state === "expired" ? "critical" : c.state === "critical" ? "high" : c.state === "expiring" ? "medium" : undefined,
      mono: true,
      href: `/certificates/${encodeURIComponent(c.id)}`,
    }));
    const named: SearchResult[] = endpoints.endpoints
      .filter((e) => `${e.host}:${e.port} ${e.name ?? ""}`.toLowerCase().includes(q))
      .slice(0, 6)
      .map((e) => ({
        id: `endpoint:${e.id}`,
        label: `${e.host}:${e.port}`,
        detail: e.lastError ?? e.certificate?.commonName ?? e.name ?? "",
        kind: t("search.endpoint"),
        icon: Radar,
        mono: true,
        href: "/endpoints",
      }));
    return [...certificates, ...named];
  };
}
