import {
  AppShell,
  Badge,
  BrandProvider,
  Button,
  Callout,
  DataTable,
  Dialog,
  EmptyState,
  FacetFilter,
  FilterBar,
  IconButton,
  KpiCard,
  KpiGrid,
  navigate,
  PageHeader,
  Panel,
  PRODUCT_IDS,
  SearchInput,
  SegmentedControl,
  StatusBadge,
  TextField,
  usePath,
  type Column,
  type ProductId,
  useThemePreference,
  useAgo,
} from "@openasy/ui";
import { AccountSettings, AuthGate, MembersSettings, SignInSettings, TokensSettings, useAuth, useInstallBrand } from "@openasy/auth/react";
import colophon from "virtual:openasy-colophon";
import { BadgeCheck, KeyRound, LogIn, LogOut, Plus, Radar, RefreshCw, Settings2, Trash2, UserRound, Users } from "lucide-react";
import { useCallback, useEffect, useState, type FormEvent, type ReactNode } from "react";
import {
  api,
  MfaSetupRequired,
  Unauthorized,
  type Certificate,
  type CertificateDetail,
  type Endpoint,
  type ProductLink,
  type State,
  type Summary,
  type Warning,
} from "./api.ts";
import { useT, type T } from "./i18n.ts";

const PAGES = ["endpoints", "setup", "account", "members", "signin", "tokens", "about"] as const;
type Route = { page: "certificates" | (typeof PAGES)[number] } | { page: "certificate"; id: string };
/** The first path segments that are pages of this UI, for followLinks. */
export const PATHS = ["certificates", ...PAGES];
function parseRoute(path: string): Route {
  const [page, id] = path.replace(/^\//, "").split("/");
  if (page === "certificates" && id) return { page: "certificate", id: decodeURIComponent(id) };
  if ((PAGES as readonly string[]).includes(page ?? "")) return { page: page as (typeof PAGES)[number] };
  return { page: "certificates" };
}

/** Data loading with the session; when it ends, the sign-in screen comes back. */
function useApi() {
  const { expired, refresh } = useAuth();
  return useCallback(
    async <T,>(path: string, init?: RequestInit): Promise<T> => {
      try {
        return await api<T>(path, init);
      } catch (err) {
        if (err instanceof Unauthorized) expired();
        if (err instanceof MfaSetupRequired) void refresh();
        throw err;
      }
    },
    [expired, refresh],
  );
}
type Call = ReturnType<typeof useApi>;

const STATES = (t: T): Array<{ value: State; label: string }> => [
  { value: "expired", label: t("states.expired") },
  { value: "critical", label: t("states.criticalUnder7Days") },
  { value: "expiring", label: t("states.expiring") },
  { value: "not-yet-valid", label: t("states.notYetValid") },
  { value: "valid", label: t("states.valid") },
];
const WARNINGS = (t: T): Array<{ value: Warning; label: string; hint: string }> => [
  { value: "weak-key", label: t("warnings.weakKey"), hint: t("warnings.rsaUnder2048Bits") },
  { value: "weak-signature", label: t("warnings.weakSignature"), hint: t("warnings.sha1OrMd5") },
  { value: "wildcard", label: t("warnings.wildcard"), hint: t("warnings.oneKeyForEverySubdomain") },
  { value: "self-signed", label: t("warnings.selfSigned"), hint: t("warnings.aLeafThatSignedItself") },
  { value: "long-lifetime", label: t("warnings.longLifetime"), hint: t("warnings.aLeafValidForOver") },
];

const TONE = { valid: "success", expiring: "warning", critical: "danger", expired: "danger", "not-yet-valid": "info" } as const;

function StateBadge({ state }: { state: State }) {
  const t = useT();
  return (
    <StatusBadge tone={TONE[state]}>
      {STATES(t)
        .find((s) => s.value === state)
        ?.label.split(",")[0] ?? state}
    </StatusBadge>
  );
}

function Left({ days, state }: { days: number; state: State }) {
  const t = useT();
  if (state === "not-yet-valid") return <span className="text-xs text-fg-muted">{t("left.notYet")}</span>;
  return <span className="text-xs whitespace-nowrap">{days < 0 ? t("left.dAgo", { value: -days }) : `${days} d`}</span>;
}

function Code({ children }: { children: ReactNode }) {
  return <pre className="m-0 max-h-72 overflow-auto rounded-md bg-subtle px-2.5 py-2 font-mono text-xs text-fg">{children}</pre>;
}

function CertificatesPage({ call, summary }: { call: Call; summary?: Summary }) {
  const t = useT();
  const [state, setState] = useState<string[]>([]);
  const [warning, setWarning] = useState<string[]>([]);
  const [q, setQ] = useState("");
  const [onlyLeaves, setOnlyLeaves] = useState("all");
  const [rows, setRows] = useState<Certificate[]>();
  const [more, setMore] = useState<string>();

  const query = useCallback(
    (cursor?: string) => {
      const p = new URLSearchParams({ limit: "200" });
      if (state.length === 1) p.set("state", state[0]!);
      if (warning.length === 1) p.set("warning", warning[0]!);
      if (onlyLeaves !== "all") p.set("ca", onlyLeaves === "ca" ? "true" : "false");
      if (q.trim()) p.set("q", q.trim());
      if (cursor) p.set("cursor", cursor);
      return call<{ certificates: Certificate[]; nextCursor?: string }>(`/api/v1/certificates?${p}`);
    },
    [call, state, warning, q, onlyLeaves],
  );
  const load = useCallback(() => {
    query().then(
      (r) => (setRows(r.certificates), setMore(r.nextCursor)),
      () => setRows([]),
    );
  }, [query]);
  useEffect(load, [load]);
  const loadMore = () => more && query(more).then((r) => (setRows((x) => [...(x ?? []), ...r.certificates]), setMore(r.nextCursor)));
  // The API filters by one state or warning; picking several shows each of them here.
  const shown = (rows ?? []).filter(
    (c) => (state.length < 2 || state.includes(c.state)) && (warning.length < 2 || c.warnings.some((w) => warning.includes(w))),
  );

  const columns: Column<Certificate>[] = [
    { id: "state", header: t("certificatesPage.state"), width: "120px", sortValue: (c) => c.notAfter, cell: (c) => <StateBadge state={c.state} /> },
    {
      id: "name",
      header: t("certificatesPage.certificate"),
      width: "30%",
      sortValue: (c) => c.commonName ?? c.subject,
      cell: (c) => (
        <span className="flex min-w-0 flex-col">
          <a href={`/certificates/${c.id}`} className="certificates-wrap self-start text-sm font-medium">
            {c.commonName ?? c.subject}
          </a>
          <span className="certificates-clamp text-xs text-fg-muted" title={c.names.join(", ")}>
            {c.names.length ? c.names.map((n) => n.replace(/^DNS:/, "")).join(", ") : c.ca ? t("certificatesPage.certificateAuthority") : ""}
          </span>
        </span>
      ),
    },
    {
      id: "expires",
      header: t("certificatesPage.expires"),
      sortValue: (c) => c.notAfter,
      cell: (c) => <span className="text-xs whitespace-nowrap">{new Date(c.notAfter).toLocaleDateString()}</span>,
    },
    { id: "left", header: t("certificatesPage.left"), align: "right", sortValue: (c) => c.daysLeft, cell: (c) => <Left days={c.daysLeft} state={c.state} /> },
    { id: "issuer", header: t("certificatesPage.issuer"), cell: (c) => <span className="certificates-wrap text-xs">{c.issuerCommonName ?? c.issuer}</span> },
    {
      id: "warnings",
      header: t("certificatesPage.warnings"),
      cell: (c) => (
        <span className="flex flex-wrap gap-1">
          {c.warnings.map((w) => (
            <Badge key={w} tone="warning">
              {WARNINGS(t).find((x) => x.value === w)?.label ?? w}
            </Badge>
          ))}
        </span>
      ),
    },
    {
      id: "where",
      header: t("certificatesPage.seenAt"),
      cell: (c) => (
        <span className="certificates-wrap font-mono text-xs">
          {c.sources[0]?.source ?? ""}
          {c.sources.length > 1 ? ` +${c.sources.length - 1}` : ""}
        </span>
      ),
    },
  ];

  const s = summary;
  return (
    <>
      <PageHeader
        title={t("certificatesPage.certificates")}
        description={
          s
            ? t("certificatesPage.expiryWarningsAtDays", { plural: t("plurals.certificate", { count: s.certificates }), value: s.warnDays.join(", ") })
            : undefined
        }
        actions={<SearchInput label={t("certificatesPage.searchNameIssuerOrPlace")} className="w-64" value={q} onChange={(e) => setQ(e.target.value)} />}
      />
      {s && (
        <KpiGrid minWidth={150}>
          <KpiCard label={t("certificatesPage.expired")} value={s.states.expired} tone={s.states.expired ? "danger" : "success"} />
          <KpiCard
            label={t("certificatesPage.critical")}
            value={s.states.critical}
            tone={s.states.critical ? "danger" : "success"}
            footer={<span className="text-xs text-fg-muted">{t("certificatesPage.under7Days")}</span>}
          />
          <KpiCard label={t("certificatesPage.expiring")} value={s.states.expiring} tone={s.states.expiring ? "warning" : "success"} />
          <KpiCard label={t("certificatesPage.valid")} value={s.states.valid} tone="success" />
          <KpiCard label={t("certificatesPage.withWarnings")} value={s.withWarnings} tone={s.withWarnings ? "warning" : "success"} />
          <KpiCard
            label={t("certificatesPage.nextToExpire")}
            value={s.nextExpiry ? `${s.nextExpiry.daysLeft} d` : "–"}
            footer={<span className="certificates-clamp text-xs text-fg-muted">{s.nextExpiry?.commonName ?? ""}</span>}
          />
        </KpiGrid>
      )}
      <FilterBar onClear={() => (setState([]), setWarning([]), setQ(""), setOnlyLeaves("all"))}>
        <FacetFilter
          label={t("certificatesPage.state")}
          selected={state}
          onChange={setState}
          options={STATES(t).map((x) => ({ value: x.value, label: x.label.split(",")[0]!, count: s?.states[x.value] }))}
        />
        <FacetFilter
          label={t("certificatesPage.warning")}
          selected={warning}
          onChange={setWarning}
          options={WARNINGS(t).map((x) => ({ value: x.value, label: x.label }))}
        />
        <SegmentedControl
          label={t("certificatesPage.kind")}
          size="sm"
          value={onlyLeaves}
          onChange={setOnlyLeaves}
          options={[
            { value: "all", label: t("certificatesPage.all") },
            { value: "leaf", label: t("certificatesPage.leaves") },
            { value: "ca", label: "CAs" },
          ]}
        />
      </FilterBar>
      <Panel
        title={t("certificatesPage.soonestToExpireFirst")}
        flush
        footer={
          more ? (
            <Button size="sm" onClick={loadMore}>
              {t("certificatesPage.loadMore")}
            </Button>
          ) : undefined
        }
      >
        <DataTable
          label={t("certificatesPage.certificates")}
          columns={columns}
          rows={shown}
          loading={!rows}
          getRowId={(c) => c.id}
          minWidth={980}
          pageSize={50}
          empty={
            <EmptyState title={t("certificatesPage.noCertificates")}>
              {s && s.certificates === 0 ? (
                <>
                  {t("certificatesPage.sendSomeOrAddAn")} <a href="/setup">{t("certificatesPage.setup")}</a>.
                </>
              ) : (
                t("certificatesPage.nothingMatchesTheseFilters")
              )}
            </EmptyState>
          }
        />
      </Panel>
    </>
  );
}

function CertificatePage({ call, id, reload }: { call: Call; id: string; reload: () => void }) {
  const ago = useAgo();
  const t = useT();
  const { can } = useAuth();
  const [cert, setCert] = useState<CertificateDetail | null>();
  const [removing, setRemoving] = useState(false);
  const [error, setError] = useState<string>();
  useEffect(() => void call<CertificateDetail>(`/api/v1/certificates/${id}`).then(setCert, () => setCert(null)), [call, id]);
  const remove = () =>
    call(`/api/v1/certificates/${id}`, { method: "DELETE" }).then(
      () => {
        reload();
        navigate("/certificates");
      },
      (err: Error) => setError(err.message),
    );
  if (cert === null)
    return (
      <EmptyState title={t("certificatePage.certificateNotFound")}>
        {t("certificatePage.itMayHaveBeenDeleted")} <a href="/certificates">{t("certificatePage.backToCertificates")}</a>.
      </EmptyState>
    );
  const pairs: Array<[string, ReactNode]> = cert
    ? [
        [
          t("certificatePage.subject"),
          <span key="subject" className="certificates-wrap">
            {cert.subject}
          </span>,
        ],
        [
          t("certificatePage.issuer"),
          <span key="issuer" className="certificates-wrap">
            {cert.issuer}
          </span>,
        ],
        [t("certificatePage.validFrom"), new Date(cert.notBefore).toLocaleString()],
        [
          t("certificatePage.validUntil"),
          `${new Date(cert.notAfter).toLocaleString()} (${cert.daysLeft < 0 ? `${-cert.daysLeft} days ago` : `${cert.daysLeft} days left`})`,
        ],
        [t("certificatePage.key"), `${cert.keyType.toUpperCase()}${cert.keyBits ? ` ${cert.keyBits}` : ""}`],
        [t("certificatePage.signature"), cert.signature],
        [
          t("certificatePage.serial"),
          <span key="serial" className="font-mono text-xs">
            {cert.serial}
          </span>,
        ],
        [
          "SHA-256",
          <span key="sha256" className="certificates-wrap font-mono text-xs">
            {cert.id}
          </span>,
        ],
        [
          t("certificatePage.kind"),
          cert.ca ? t("certificatePage.certificateAuthority") : cert.selfSigned ? t("certificatePage.leafSelfSigned") : t("certificatePage.leaf"),
        ],
      ]
    : [];
  return (
    <>
      <PageHeader
        title={cert?.commonName ?? cert?.subject ?? t("certificatePage.certificate")}
        description={cert ? t("certificatePage.firstSeenLastSeen", { ago: ago(cert.firstSeen), ago2: ago(cert.lastSeen) }) : undefined}
        actions={
          cert && (
            <>
              <StateBadge state={cert.state} />
              {can("admin") && (
                <Button icon={<Trash2 />} onClick={() => setRemoving(true)}>
                  {t("certificatePage.delete")}
                </Button>
              )}
            </>
          )
        }
      />
      {cert && cert.warnings.length > 0 && (
        <Callout tone="warning" title={t("certificatePage.worthALook")}>
          <ul className="certificates-list">
            {cert.warnings.map((w) => (
              <li key={w}>
                {WARNINGS(t).find((x) => x.value === w)?.label}: {WARNINGS(t).find((x) => x.value === w)?.hint}
              </li>
            ))}
          </ul>
        </Callout>
      )}
      <div className="grid gap-2.5 xl:grid-cols-2">
        <Panel title={t("certificatePage.details")}>
          <dl className="certificates-pairs text-sm">
            {pairs.map(([k, v]) => (
              <div key={k} className="contents">
                <dt className="text-fg-muted">{k}</dt>
                <dd className="m-0">{v}</dd>
              </div>
            ))}
          </dl>
        </Panel>
        <div className="flex flex-col gap-2.5">
          <Panel title={t("certificatePage.names")} description={cert ? t("plurals.name", { count: cert.names.length }) : undefined}>
            <ul className="certificates-list flex flex-wrap gap-1">
              {(cert?.names ?? []).map((n) => (
                <li key={n}>
                  <Badge mono>{n}</Badge>
                </li>
              ))}
            </ul>
          </Panel>
          <Panel title={t("certificatePage.chain")} description={t("certificatePage.whatSignedItAmongThe")}>
            {cert && cert.chain.length === 0 ? (
              <p className="m-0 text-sm text-fg-muted">
                {cert.selfSigned ? t("certificatePage.itSignedItself") : t("certificatePage.theCertificateAboveItHas")}
              </p>
            ) : (
              <ul className="certificates-list flex flex-col gap-1 text-sm">
                {(cert?.chain ?? []).map((c) => (
                  <li key={c.id} className="flex items-center gap-2">
                    <a href={`/certificates/${c.id}`}>{c.commonName ?? c.subject}</a>
                    <StateBadge state={c.state} />
                    {c.selfSigned && <Badge>{t("certificatePage.root")}</Badge>}
                  </li>
                ))}
              </ul>
            )}
          </Panel>
        </div>
      </div>
      <Panel title={t("certificatePage.seenAt")} description={t("certificatePage.position0IsTheLeaf")} flush>
        <DataTable
          label={t("certificatePage.places")}
          columns={[
            {
              id: "source",
              header: t("certificatePage.where"),
              cell: (s: CertificateDetail["sources"][number]) => <span className="certificates-wrap font-mono text-xs">{s.source}</span>,
            },
            { id: "position", header: t("certificatePage.chainPosition"), align: "right", cell: (s) => s.position },
            { id: "seen", header: t("certificatePage.lastSeen"), cell: (s) => <span className="text-xs">{ago(s.lastSeen)}</span> },
          ]}
          rows={cert?.sources ?? []}
          loading={cert === undefined}
          getRowId={(s) => s.source}
          minWidth={520}
        />
      </Panel>
      <Panel title={t("certificatePage.certificate")} description={t("certificatePage.publicOnlyAPrivateKey")}>
        <Code>{cert?.pem ?? ""}</Code>
      </Panel>
      <Dialog
        open={removing}
        onOpenChange={setRemoving}
        title={t("certificatePage.deleteThisCertificate")}
        description={t("certificatePage.itLeavesTheInventoryWith")}
        footer={
          <>
            <Button type="button" onClick={() => setRemoving(false)}>
              {t("certificatePage.cancel")}
            </Button>
            <Button type="button" variant="primary" onClick={() => void remove()}>
              {t("certificatePage.delete")}
            </Button>
          </>
        }
      >
        {error ? <span className="text-xs text-danger">{error}</span> : <></>}
      </Dialog>
    </>
  );
}

function EndpointsPage({ call, summary, reload }: { call: Call; summary?: Summary; reload: () => void }) {
  const ago = useAgo();
  const t = useT();
  const { can } = useAuth();
  const [rows, setRows] = useState<Endpoint[]>();
  const [adding, setAdding] = useState(false);
  const [host, setHost] = useState("");
  const [port, setPort] = useState("443");
  const [error, setError] = useState<string>();
  const [busy, setBusy] = useState<string>();
  const load = useCallback(
    () =>
      void call<{ endpoints: Endpoint[] }>("/api/v1/endpoints").then(
        (r) => setRows(r.endpoints),
        () => setRows([]),
      ),
    [call],
  );
  useEffect(load, [load]);
  const close = () => (setAdding(false), setHost(""), setPort("443"), setError(undefined));

  const add = async (e: FormEvent) => {
    e.preventDefault();
    try {
      const created = await call<Endpoint>("/api/v1/endpoints", { method: "POST", body: JSON.stringify({ host: host.trim(), port: Number(port) }) });
      close();
      load();
      await call(`/api/v1/endpoints/${created.id}/probe`, { method: "POST" }).catch(() => {});
      load();
      reload();
    } catch (err) {
      setError((err as Error).message);
    }
  };
  const probe = async (id: string) => {
    setBusy(id);
    await call(`/api/v1/endpoints/${id}/probe`, { method: "POST" }).catch(() => {});
    setBusy(undefined);
    load();
    reload();
  };

  const columns: Column<Endpoint>[] = [
    {
      id: "host",
      header: t("endpointsPage.endpoint"),
      sortValue: (e) => e.host,
      cell: (e) => (
        <span className="flex min-w-0 flex-col gap-0.5">
          <span className="certificates-wrap font-mono text-xs">
            {e.host}:{e.port}
          </span>
          {(e.source === "file" || e.server) && (
            <span className="flex flex-wrap items-center gap-1.5">
              {e.source === "file" && <Badge tone="neutral">{e.name ? t("endpointsPage.fromFile", { name: e.name }) : t("endpointsPage.fromFile2")}</Badge>}
              {e.server && <Badge tone="neutral">{t("endpointsPage.on", { server: e.server })}</Badge>}
            </span>
          )}
        </span>
      ),
    },
    {
      id: "cert",
      header: t("endpointsPage.certificate"),
      cell: (e) =>
        e.certificate ? (
          <a href={`/certificates/${e.certificate.id}`}>{e.certificate.commonName ?? "certificate"}</a>
        ) : (
          <span className="text-xs text-fg-muted">{t("endpointsPage.noneYet")}</span>
        ),
    },
    {
      id: "state",
      header: t("endpointsPage.state"),
      cell: (e) =>
        e.certificate ? (
          <span className="flex items-center gap-1.5">
            <StateBadge state={e.certificate.state} />
            <Left days={e.certificate.daysLeft} state={e.certificate.state} />
          </span>
        ) : (
          "–"
        ),
    },
    {
      id: "chain",
      header: t("endpointsPage.chain"),
      description: t("endpointsPage.whetherTheSystemSRoots"),
      cell: (e) =>
        e.chainValid === null ? (
          "–"
        ) : e.chainValid ? (
          <StatusBadge tone="success">{t("endpointsPage.trusted")}</StatusBadge>
        ) : (
          <span title={e.chainError ?? undefined}>
            <StatusBadge tone="warning">{t("endpointsPage.notTrusted")}</StatusBadge>
          </span>
        ),
    },
    {
      id: "probe",
      header: t("endpointsPage.lastProbe"),
      cell: (e) =>
        e.lastError ? (
          <span className="certificates-clamp text-xs text-danger" title={e.lastError}>
            {e.lastError}
          </span>
        ) : (
          <span className="text-xs">{ago(e.lastProbeAt)}</span>
        ),
    },
    {
      id: "actions",
      header: <span className="sr-only">{t("endpointsPage.actions")}</span>,
      label: t("endpointsPage.actions"),
      align: "right",
      cell: (e) => (
        <span className="flex justify-end gap-1">
          {can("editor") && (
            <IconButton label={t("endpointsPage.probeNow", { host: e.host })} size="sm" onClick={() => void probe(e.id)} disabled={busy === e.id}>
              <RefreshCw />
            </IconButton>
          )}
          {can("admin") && e.source === "ui" && (
            <IconButton
              label={t("endpointsPage.remove", { host: e.host })}
              size="sm"
              onClick={() =>
                void call(`/api/v1/endpoints/${e.id}`, { method: "DELETE" }).then(
                  () => (load(), reload()),
                  () => {},
                )
              }
            >
              <Trash2 />
            </IconButton>
          )}
        </span>
      ),
    },
  ];
  return (
    <>
      <PageHeader
        title={t("endpointsPage.endpoints")}
        description={t("endpointsPage.addressesThisServerConnectsTo")}
        actions={
          can("admin") && (
            <Button variant="primary" icon={<Plus />} onClick={() => setAdding(true)}>
              {t("endpointsPage.addEndpoint")}
            </Button>
          )
        }
      />
      {summary?.endpointsFile?.error && (
        <Callout tone="danger" title={t("endpointsPage.theEndpointsFileIsNot")}>
          {t("endpointsPage.theEndpointsFromItsLast", { error: summary.endpointsFile.error, path: summary.endpointsFile.path })}
        </Callout>
      )}
      {!!summary?.endpointsFile?.warnings.length && (
        <Callout tone="warning" title={t("endpointsPage.theEndpointsFileHasSomething")}>
          {summary.endpointsFile.warnings.join(" ")}
        </Callout>
      )}
      <Panel flush>
        <DataTable
          label={t("endpointsPage.endpoints")}
          columns={columns}
          rows={rows ?? []}
          loading={!rows}
          getRowId={(e) => e.id}
          minWidth={900}
          empty={
            <EmptyState title={t("endpointsPage.noEndpoints")}>
              {can("admin") ? t("endpointsPage.addAHostToRead") : t("endpointsPage.anAdminAddsTheHosts")}
            </EmptyState>
          }
        />
      </Panel>
      <Dialog
        open={adding}
        onOpenChange={(open) => !open && close()}
        title={t("endpointsPage.addAnEndpoint")}
        description={t("endpointsPage.theServerConnectsToIt")}
        onSubmit={add}
        footer={
          <>
            <Button type="button" onClick={close}>
              {t("endpointsPage.cancel")}
            </Button>
            <Button type="submit" variant="primary" disabled={!host.trim()}>
              {t("endpointsPage.addAndRead")}
            </Button>
          </>
        }
      >
        <TextField
          label={t("endpointsPage.host")}
          value={host}
          onChange={(e) => setHost(e.target.value)}
          hint={t("endpointsPage.aNameSuchAsShop")}
          error={error}
        />
        <TextField label={t("endpointsPage.port")} value={port} onChange={(e) => setPort(e.target.value.replace(/\D/g, ""))} inputMode="numeric" />
      </Dialog>
    </>
  );
}

// ---------------------------------------------------------------- Setup

function SetupPage() {
  const t = useT();
  const origin = window.location.origin;
  return (
    <>
      <PageHeader title={t("setupPage.setup")} description={t("setupPage.twoWaysToKnowEvery")} />
      <Panel title={t("setupPage.sendCertificates")} description={t("setupPage.fromACronJobCi")}>
        <Code>{`# a file, or a chain
curl -sf -X POST -H "Authorization: Bearer $CERTIFICATES_INGEST_TOKEN" --data-binary @/etc/ssl/certs/shop.pem \\
  "${origin}/api/v1/certificates?source=web-1:/etc/ssl/certs/shop.pem"

# what a server presents
openssl s_client -connect shop.example.com:443 -showcerts </dev/null 2>/dev/null | curl -sf -X POST \\
  -H "Authorization: Bearer $CERTIFICATES_INGEST_TOKEN" --data-binary @- "${origin}/api/v1/certificates?source=shop.example.com:443"`}</Code>
        <p className="mt-2 mb-0 text-sm text-fg-muted">{t("setupPage.aBodyThatHoldsA")}</p>
      </Panel>
      <Panel title={t("setupPage.readEndpoints")} description={t("setupPage.underEndpointsAddAPublic")}>
        <ul className="certificates-list flex flex-col gap-1 text-sm text-fg-muted">
          <li>{t("setupPage.namesThatResolveToA")}</li>
          <li>{t("setupPage.certificatesOnPrivateNetworksAre")}</li>
          <li>{t("setupPage.warningsComeAtTheThresholds")}</li>
        </ul>
      </Panel>
    </>
  );
}

/** The first screen, until the first certificate arrives. The summary is polled, so it gives way by itself. */
function WelcomePage() {
  const t = useT();
  return (
    <>
      <PageHeader
        title={t("welcomePage.getStarted")}
        description={t("welcomePage.certificatesShowHereAsSoon")}
        actions={<StatusBadge tone="info">{t("welcomePage.waitingForTheFirstCertificate")}</StatusBadge>}
      />
      <SetupPage />
    </>
  );
}

// ---------------------------------------------------------------- Shell

/** Account, Members, Sign-in and API tokens: the screens come from @openasy/auth. */
function SettingsPage({ page }: { page: "account" | "members" | "signin" | "tokens" }) {
  const t = useT();
  const { signOut, can } = useAuth();
  if (page !== "account" && !can("admin")) return <EmptyState title={t("settingsPage.adminsOnly")}>{t("settingsPage.askAnAdminOfThis")}</EmptyState>;
  const titles = {
    account: ["Account", "Your profile, password, two-step verification and where you are signed in."],
    members: [
      "Members",
      "Who can sign in to this certificates, and with which role. Viewers see everything; editors also send certificates and probe endpoints now; admins also add and remove endpoints, delete certificates, and manage members and tokens.",
    ],
    signin: [
      "Sign-in",
      "Identity providers people can sign in with, such as OpenAsy Identity, Keycloak or Microsoft Entra ID, and which of their groups give which role.",
    ],
    tokens: ["API tokens", "For scripts, cron jobs and collectors. Each token has one role and an expiry; the secret is shown once."],
  } as const;
  return (
    <>
      <PageHeader
        title={titles[page][0]}
        description={titles[page][1]}
        actions={
          page === "account" && (
            <Button icon={<LogOut />} onClick={() => void signOut()}>
              {t("settingsPage.signOut")}
            </Button>
          )
        }
      />
      {page === "account" ? <AccountSettings /> : page === "members" ? <MembersSettings /> : page === "signin" ? <SignInSettings /> : <TokensSettings />}
    </>
  );
}

function Product() {
  const msg = useT();
  const [theme, setTheme] = useThemePreference();
  const { me, can } = useAuth();
  const route = parseRoute(usePath());
  const [summary, setSummary] = useState<Summary>();
  const [products, setProducts] = useState<Array<ProductLink & { id: ProductId }>>([]);
  const call = useApi();

  // The install's other products (OPENASY_PRODUCTS), for the switcher; ids this UI does not know are left out.
  useEffect(() => {
    void call<{ products: ProductLink[] }>("/api/v1/products").then(
      (r) =>
        setProducts(
          r.products.filter((p): p is ProductLink & { id: ProductId } => p.id !== "certificates" && (PRODUCT_IDS as readonly string[]).includes(p.id)),
        ),
      () => {},
    );
  }, [call]);

  const reload = useCallback(() => void call<Summary>("/api/v1/summary").then(setSummary, () => {}), [call]);
  useEffect(() => {
    reload();
    const t = setInterval(reload, 15_000);
    return () => clearInterval(t);
  }, [reload]);

  const nav = [
    { id: "certificates", label: msg("product.certificates"), icon: BadgeCheck, count: summary?.certificates },
    { id: "endpoints", label: msg("product.endpoints"), icon: Radar, count: summary?.failingEndpoints || undefined },
  ];
  const footerNav = [
    { id: "setup", label: msg("product.setup"), icon: Settings2 },
    ...(can("admin")
      ? [
          { id: "members", label: msg("product.members"), icon: Users },
          { id: "signin", label: msg("product.signIn"), icon: LogIn },
          { id: "tokens", label: msg("product.apiTokens"), icon: KeyRound },
        ]
      : []),
    { id: "account", label: msg("product.account"), icon: UserRound },
  ];
  const active = route.page === "certificate" ? "certificates" : route.page;
  const roleName = me.user.role.charAt(0).toUpperCase() + me.user.role.slice(1);

  return (
    <AppShell
      product="certificates"
      about={colophon}
      nav={nav}
      activeNav={active}
      onNavigate={(id) => navigate(`/${id}`)}
      connectedProducts={products.map((p) => p.id)}
      onSwitchProduct={(id) => {
        const to = products.find((p) => p.id === id);
        if (to) window.location.assign(to.url);
      }}
      footerNav={footerNav}
      user={{ name: me.user.name, role: roleName }}
      theme={theme}
      onThemeChange={setTheme}
    >
      {route.page === "certificates" && summary && summary.certificates === 0 && summary.endpoints === 0 ? (
        <WelcomePage />
      ) : route.page === "certificates" ? (
        <CertificatesPage call={call} summary={summary} />
      ) : route.page === "certificate" ? (
        <CertificatePage key={route.id} call={call} id={route.id} reload={reload} />
      ) : route.page === "endpoints" ? (
        <EndpointsPage call={call} summary={summary} reload={reload} />
      ) : route.page === "account" || route.page === "members" || route.page === "signin" || route.page === "tokens" ? (
        <SettingsPage page={route.page} />
      ) : (
        <SetupPage />
      )}
    </AppShell>
  );
}

export function App() {
  const installBrand = useInstallBrand();
  const [theme] = useThemePreference();
  return (
    // The install's brand from config/brand.env (ADR 0053); OpenAsy's own look where it sets none.
    <BrandProvider theme={theme} brand={{ name: "OpenAsy", organization: undefined, ...installBrand }} className="min-h-screen">
      <AuthGate product="OpenAsy Certificates">
        <Product />
      </AuthGate>
    </BrandProvider>
  );
}
