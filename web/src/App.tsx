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
} from "@openasy/ui";
import { AccountSettings, AuthGate, MembersSettings, SignInSettings, TokensSettings, useAuth } from "@openasy/auth/react";
import { BadgeCheck, KeyRound, LogIn, LogOut, Plus, Radar, RefreshCw, Settings2, Trash2, UserRound, Users } from "lucide-react";
import { useCallback, useEffect, useState, type FormEvent, type ReactNode } from "react";
import { api, MfaSetupRequired, Unauthorized, type Certificate, type CertificateDetail, type Endpoint, type ProductLink, type State, type Summary, type Warning } from "./api.ts";

function ago(iso: string | null | undefined): string {
  if (!iso) return "never";
  const s = Math.round((Date.now() - Date.parse(iso)) / 1000);
  if (s < 60) return "just now";
  if (s < 3600) return `${Math.round(s / 60)} min ago`;
  if (s < 86_400) return `${Math.round(s / 3600)} h ago`;
  return `${Math.round(s / 86_400)} d ago`;
}

const plural = (n: number, one: string, many = `${one}s`) => `${n} ${n === 1 ? one : many}`;

const PAGES = ["endpoints", "setup", "account", "members", "signin", "tokens"] as const;
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

const STATES: Array<{ value: State; label: string }> = [
  { value: "expired", label: "Expired" },
  { value: "critical", label: "Critical, under 7 days" },
  { value: "expiring", label: "Expiring" },
  { value: "not-yet-valid", label: "Not yet valid" },
  { value: "valid", label: "Valid" },
];
const WARNINGS: Array<{ value: Warning; label: string; hint: string }> = [
  { value: "weak-key", label: "Weak key", hint: "RSA under 2048 bits" },
  { value: "weak-signature", label: "Weak signature", hint: "SHA-1 or MD5" },
  { value: "wildcard", label: "Wildcard", hint: "One key for every subdomain" },
  { value: "self-signed", label: "Self-signed", hint: "A leaf that signed itself" },
  { value: "long-lifetime", label: "Long lifetime", hint: "A leaf valid for over 398 days" },
];

const TONE = { valid: "success", expiring: "warning", critical: "danger", expired: "danger", "not-yet-valid": "info" } as const;

function StateBadge({ state }: { state: State }) {
  return <StatusBadge tone={TONE[state]}>{STATES.find((s) => s.value === state)?.label.split(",")[0] ?? state}</StatusBadge>;
}

function Left({ days, state }: { days: number; state: State }) {
  if (state === "not-yet-valid") return <span className="text-xs text-fg-muted">not yet</span>;
  return <span className="text-xs whitespace-nowrap">{days < 0 ? `${-days} d ago` : `${days} d`}</span>;
}

function Code({ children }: { children: ReactNode }) {
  return <pre className="m-0 max-h-72 overflow-auto rounded-md bg-subtle px-2.5 py-2 font-mono text-xs text-fg">{children}</pre>;
}

function CertificatesPage({ call, summary }: { call: Call; summary?: Summary }) {
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
    query().then((r) => (setRows(r.certificates), setMore(r.nextCursor)), () => setRows([]));
  }, [query]);
  useEffect(load, [load]);
  const loadMore = () => more && query(more).then((r) => (setRows((x) => [...(x ?? []), ...r.certificates]), setMore(r.nextCursor)));
  // The API filters by one state or warning; picking several shows each of them here.
  const shown = (rows ?? []).filter((c) => (state.length < 2 || state.includes(c.state)) && (warning.length < 2 || c.warnings.some((w) => warning.includes(w))));

  const columns: Column<Certificate>[] = [
    { id: "state", header: "State", width: "120px", sortValue: (c) => c.notAfter, cell: (c) => <StateBadge state={c.state} /> },
    {
      id: "name",
      header: "Certificate",
      width: "30%",
      sortValue: (c) => c.commonName ?? c.subject,
      cell: (c) => (
        <span className="flex min-w-0 flex-col">
          <a href={`/certificates/${c.id}`} className="certificates-wrap self-start text-sm font-medium">
            {c.commonName ?? c.subject}
          </a>
          <span className="certificates-clamp text-xs text-fg-muted" title={c.names.join(", ")}>
            {c.names.length ? c.names.map((n) => n.replace(/^DNS:/, "")).join(", ") : c.ca ? "Certificate authority" : ""}
          </span>
        </span>
      ),
    },
    { id: "expires", header: "Expires", sortValue: (c) => c.notAfter, cell: (c) => <span className="text-xs whitespace-nowrap">{new Date(c.notAfter).toLocaleDateString()}</span> },
    { id: "left", header: "Left", align: "right", sortValue: (c) => c.daysLeft, cell: (c) => <Left days={c.daysLeft} state={c.state} /> },
    { id: "issuer", header: "Issuer", cell: (c) => <span className="certificates-wrap text-xs">{c.issuerCommonName ?? c.issuer}</span> },
    {
      id: "warnings",
      header: "Warnings",
      cell: (c) => (
        <span className="flex flex-wrap gap-1">
          {c.warnings.map((w) => (
            <Badge key={w} tone="warning">
              {WARNINGS.find((x) => x.value === w)?.label ?? w}
            </Badge>
          ))}
        </span>
      ),
    },
    { id: "where", header: "Seen at", cell: (c) => <span className="certificates-wrap font-mono text-xs">{c.sources[0]?.source ?? ""}{c.sources.length > 1 ? ` +${c.sources.length - 1}` : ""}</span> },
  ];

  const s = summary;
  return (
    <>
      <PageHeader title="Certificates" description={s ? `${plural(s.certificates, "certificate")} · expiry warnings at ${s.warnDays.join(", ")} days` : undefined} actions={<SearchInput label="Search name, issuer or place" className="w-64" value={q} onChange={(e) => setQ(e.target.value)} />} />
      {s && (
        <KpiGrid minWidth={150}>
          <KpiCard label="Expired" value={s.states.expired} tone={s.states.expired ? "danger" : "success"} />
          <KpiCard label="Critical" value={s.states.critical} tone={s.states.critical ? "danger" : "success"} footer={<span className="text-xs text-fg-muted">under 7 days</span>} />
          <KpiCard label="Expiring" value={s.states.expiring} tone={s.states.expiring ? "warning" : "success"} />
          <KpiCard label="Valid" value={s.states.valid} tone="success" />
          <KpiCard label="With warnings" value={s.withWarnings} tone={s.withWarnings ? "warning" : "success"} />
          <KpiCard label="Next to expire" value={s.nextExpiry ? `${s.nextExpiry.daysLeft} d` : "–"} footer={<span className="certificates-clamp text-xs text-fg-muted">{s.nextExpiry?.commonName ?? ""}</span>} />
        </KpiGrid>
      )}
      <FilterBar onClear={() => (setState([]), setWarning([]), setQ(""), setOnlyLeaves("all"))}>
        <FacetFilter label="State" selected={state} onChange={setState} options={STATES.map((x) => ({ value: x.value, label: x.label.split(",")[0]!, count: s?.states[x.value] }))} />
        <FacetFilter label="Warning" selected={warning} onChange={setWarning} options={WARNINGS.map((x) => ({ value: x.value, label: x.label }))} />
        <SegmentedControl
          label="Kind"
          size="sm"
          value={onlyLeaves}
          onChange={setOnlyLeaves}
          options={[
            { value: "all", label: "All" },
            { value: "leaf", label: "Leaves" },
            { value: "ca", label: "CAs" },
          ]}
        />
      </FilterBar>
      <Panel
        title="Soonest to expire first"
        flush
        footer={
          more ? (
            <Button size="sm" onClick={loadMore}>
              Load more
            </Button>
          ) : undefined
        }
      >
        <DataTable
          label="Certificates"
          columns={columns}
          rows={shown}
          loading={!rows}
          getRowId={(c) => c.id}
          minWidth={980}
          pageSize={50}
          empty={
            <EmptyState title="No certificates">
              {s && s.certificates === 0 ? (
                <>
                  Send some, or add an endpoint to read. See <a href="/setup">Setup</a>.
                </>
              ) : (
                "Nothing matches these filters."
              )}
            </EmptyState>
          }
        />
      </Panel>
    </>
  );
}

function CertificatePage({ call, id, reload }: { call: Call; id: string; reload: () => void }) {
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
      <EmptyState title="Certificate not found">
        It may have been deleted. <a href="/certificates">Back to certificates</a>.
      </EmptyState>
    );
  const pairs: Array<[string, ReactNode]> = cert
    ? [
        ["Subject", <span className="certificates-wrap">{cert.subject}</span>],
        ["Issuer", <span className="certificates-wrap">{cert.issuer}</span>],
        ["Valid from", new Date(cert.notBefore).toLocaleString()],
        ["Valid until", `${new Date(cert.notAfter).toLocaleString()} (${cert.daysLeft < 0 ? `${-cert.daysLeft} days ago` : `${cert.daysLeft} days left`})`],
        ["Key", `${cert.keyType.toUpperCase()}${cert.keyBits ? ` ${cert.keyBits}` : ""}`],
        ["Signature", cert.signature],
        ["Serial", <span className="font-mono text-xs">{cert.serial}</span>],
        ["SHA-256", <span className="certificates-wrap font-mono text-xs">{cert.id}</span>],
        ["Kind", cert.ca ? "Certificate authority" : cert.selfSigned ? "Leaf, self-signed" : "Leaf"],
      ]
    : [];
  return (
    <>
      <PageHeader
        title={cert?.commonName ?? cert?.subject ?? "Certificate"}
        description={cert ? `First seen ${ago(cert.firstSeen)} · last seen ${ago(cert.lastSeen)}` : undefined}
        actions={
          cert && (
            <>
              <StateBadge state={cert.state} />
              {can("admin") && (
                <Button icon={<Trash2 />} onClick={() => setRemoving(true)}>
                  Delete
                </Button>
              )}
            </>
          )
        }
      />
      {cert && cert.warnings.length > 0 && (
        <Callout tone="warning" title="Worth a look">
          <ul className="certificates-list">
            {cert.warnings.map((w) => (
              <li key={w}>
                {WARNINGS.find((x) => x.value === w)?.label}: {WARNINGS.find((x) => x.value === w)?.hint}
              </li>
            ))}
          </ul>
        </Callout>
      )}
      <div className="grid gap-2.5 xl:grid-cols-2">
        <Panel title="Details">
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
          <Panel title="Names" description={cert ? plural(cert.names.length, "name") : undefined}>
            <ul className="certificates-list flex flex-wrap gap-1">
              {(cert?.names ?? []).map((n) => (
                <li key={n}>
                  <Badge mono>{n}</Badge>
                </li>
              ))}
            </ul>
          </Panel>
          <Panel title="Chain" description="What signed it, among the certificates seen here">
            {cert && cert.chain.length === 0 ? (
              <p className="m-0 text-sm text-fg-muted">{cert.selfSigned ? "It signed itself." : "The certificate above it has not been seen."}</p>
            ) : (
              <ul className="certificates-list flex flex-col gap-1 text-sm">
                {(cert?.chain ?? []).map((c) => (
                  <li key={c.id} className="flex items-center gap-2">
                    <a href={`/certificates/${c.id}`}>{c.commonName ?? c.subject}</a>
                    <StateBadge state={c.state} />
                    {c.selfSigned && <Badge>Root</Badge>}
                  </li>
                ))}
              </ul>
            )}
          </Panel>
        </div>
      </div>
      <Panel title="Seen at" description="Position 0 is the leaf of a chain" flush>
        <DataTable
          label="Places"
          columns={[
            { id: "source", header: "Where", cell: (s: CertificateDetail["sources"][number]) => <span className="certificates-wrap font-mono text-xs">{s.source}</span> },
            { id: "position", header: "Chain position", align: "right", cell: (s) => s.position },
            { id: "seen", header: "Last seen", cell: (s) => <span className="text-xs">{ago(s.lastSeen)}</span> },
          ]}
          rows={cert?.sources ?? []}
          loading={cert === undefined}
          getRowId={(s) => s.source}
          minWidth={520}
        />
      </Panel>
      <Panel title="Certificate" description="Public only. A private key is never accepted.">
        <Code>{cert?.pem ?? ""}</Code>
      </Panel>
      <Dialog
        open={removing}
        onOpenChange={setRemoving}
        title="Delete this certificate?"
        description="It leaves the inventory with where it was seen. It comes back if it is sent or probed again."
        footer={
          <>
            <Button type="button" onClick={() => setRemoving(false)}>
              Cancel
            </Button>
            <Button type="button" variant="primary" onClick={() => void remove()}>
              Delete
            </Button>
          </>
        }
      >
        {error ? <span className="text-xs text-danger">{error}</span> : <></>}
      </Dialog>
    </>
  );
}

function EndpointsPage({ call, reload }: { call: Call; reload: () => void }) {
  const { can } = useAuth();
  const [rows, setRows] = useState<Endpoint[]>();
  const [adding, setAdding] = useState(false);
  const [host, setHost] = useState("");
  const [port, setPort] = useState("443");
  const [error, setError] = useState<string>();
  const [busy, setBusy] = useState<string>();
  const load = useCallback(() => void call<{ endpoints: Endpoint[] }>("/api/v1/endpoints").then((r) => setRows(r.endpoints), () => setRows([])), [call]);
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
    { id: "host", header: "Endpoint", sortValue: (e) => e.host, cell: (e) => <span className="certificates-wrap font-mono text-xs">{e.host}:{e.port}</span> },
    { id: "cert", header: "Certificate", cell: (e) => (e.certificate ? <a href={`/certificates/${e.certificate.id}`}>{e.certificate.commonName ?? "certificate"}</a> : <span className="text-xs text-fg-muted">none yet</span>) },
    { id: "state", header: "State", cell: (e) => (e.certificate ? <span className="flex items-center gap-1.5"><StateBadge state={e.certificate.state} /><Left days={e.certificate.daysLeft} state={e.certificate.state} /></span> : "–") },
    {
      id: "chain",
      header: "Chain",
      description: "Whether the system's roots trust the chain and it fits the name. The expiry above does not depend on it.",
      cell: (e) => (e.chainValid === null ? "–" : e.chainValid ? <StatusBadge tone="success">Trusted</StatusBadge> : <span title={e.chainError ?? undefined}><StatusBadge tone="warning">Not trusted</StatusBadge></span>),
    },
    {
      id: "probe",
      header: "Last probe",
      cell: (e) => (e.lastError ? <span className="certificates-clamp text-xs text-danger" title={e.lastError}>{e.lastError}</span> : <span className="text-xs">{ago(e.lastProbeAt)}</span>),
    },
    {
      id: "actions",
      header: <span className="sr-only">Actions</span>,
      label: "Actions",
      align: "right",
      cell: (e) => (
        <span className="flex justify-end gap-1">
          {can("editor") && (
            <IconButton label={`Probe ${e.host} now`} size="sm" onClick={() => void probe(e.id)} disabled={busy === e.id}>
              <RefreshCw />
            </IconButton>
          )}
          {can("admin") && (
            <IconButton label={`Remove ${e.host}`} size="sm" onClick={() => void call(`/api/v1/endpoints/${e.id}`, { method: "DELETE" }).then(() => (load(), reload()), () => {})}>
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
        title="Endpoints"
        description="Addresses this server connects to, with a TLS handshake, to read the certificates they present. Public addresses only; certificates on private networks are sent by a collector there."
        actions={
          can("admin") && (
            <Button variant="primary" icon={<Plus />} onClick={() => setAdding(true)}>
              Add endpoint
            </Button>
          )
        }
      />
      <Panel flush>
        <DataTable label="Endpoints" columns={columns} rows={rows ?? []} loading={!rows} getRowId={(e) => e.id} minWidth={900} empty={<EmptyState title="No endpoints">{can("admin") ? "Add a host to read its certificate every few hours." : "An admin adds the hosts to read."}</EmptyState>} />
      </Panel>
      <Dialog
        open={adding}
        onOpenChange={(open) => !open && close()}
        title="Add an endpoint"
        description="The server connects to it from here. A name that resolves to a private address is refused."
        onSubmit={add}
        footer={
          <>
            <Button type="button" onClick={close}>
              Cancel
            </Button>
            <Button type="submit" variant="primary" disabled={!host.trim()}>
              Add and read
            </Button>
          </>
        }
      >
        <TextField label="Host" value={host} onChange={(e) => setHost(e.target.value)} hint="A name such as shop.example.com, or a public address." error={error} />
        <TextField label="Port" value={port} onChange={(e) => setPort(e.target.value.replace(/\D/g, ""))} inputMode="numeric" />
      </Dialog>
    </>
  );
}

// ---------------------------------------------------------------- Setup

function SetupPage() {
  const origin = window.location.origin;
  return (
    <>
      <PageHeader title="Setup" description="Two ways to know every certificate you have: send them, or let this server read them." />
      <Panel title="Send certificates" description="From a cron job, CI or a collector. Use CERTIFICATES_INGEST_TOKEN, set where certificates runs, or an API token with the editor role from API tokens.">
        <Code>{`# a file, or a chain
curl -sf -X POST -H "Authorization: Bearer $CERTIFICATES_INGEST_TOKEN" --data-binary @/etc/ssl/certs/shop.pem \\
  "${origin}/api/v1/certificates?source=web-1:/etc/ssl/certs/shop.pem"

# what a server presents
openssl s_client -connect shop.example.com:443 -showcerts </dev/null 2>/dev/null | curl -sf -X POST \\
  -H "Authorization: Bearer $CERTIFICATES_INGEST_TOKEN" --data-binary @- "${origin}/api/v1/certificates?source=shop.example.com:443"`}</Code>
        <p className="mt-2 mb-0 text-sm text-fg-muted">A body that holds a private key of any kind is refused whole, and nothing of it is kept.</p>
      </Panel>
      <Panel title="Read endpoints" description="Under Endpoints, add a public host and port. The server connects with a TLS handshake every few hours, and reports apart whether the chain is trusted.">
        <ul className="certificates-list flex flex-col gap-1 text-sm text-fg-muted">
          <li>Names that resolve to a private, loopback or link-local address are refused, here and at every probe.</li>
          <li>Certificates on private networks are sent by a collector in that network.</li>
          <li>Warnings come at the thresholds in the header of Certificates, once per crossing: GET /api/v1/expiring lists them, and /metrics has openasy_certificates_expiring for alerts.</li>
        </ul>
      </Panel>
    </>
  );
}

/** The first screen, until the first certificate arrives. The summary is polled, so it gives way by itself. */
function WelcomePage() {
  return (
    <>
      <PageHeader title="Get started" description="Certificates show here as soon as the first one arrives." actions={<StatusBadge tone="info">Waiting for the first certificate</StatusBadge>} />
      <SetupPage />
    </>
  );
}

// ---------------------------------------------------------------- Shell

/** Account, Members, Sign-in and API tokens: the screens come from @openasy/auth. */
function SettingsPage({ page }: { page: "account" | "members" | "signin" | "tokens" }) {
  const { signOut, can } = useAuth();
  if (page !== "account" && !can("admin")) return <EmptyState title="Admins only">Ask an admin of this certificates for access.</EmptyState>;
  const titles = {
    account: ["Account", "Your profile, password, two-step verification and where you are signed in."],
    members: ["Members", "Who can sign in to this certificates, and with which role. Viewers see everything; editors also send certificates and probe endpoints now; admins also add and remove endpoints, delete certificates, and manage members and tokens."],
    signin: ["Sign-in", "Identity providers people can sign in with, such as OpenAsy Identity, Keycloak or Microsoft Entra ID, and which of their groups give which role."],
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
              Sign out
            </Button>
          )
        }
      />
      {page === "account" ? <AccountSettings /> : page === "members" ? <MembersSettings /> : page === "signin" ? <SignInSettings /> : <TokensSettings />}
    </>
  );
}

function Product() {
  const [theme, setTheme] = useThemePreference();
  const { me, can } = useAuth();
  const route = parseRoute(usePath());
  const [summary, setSummary] = useState<Summary>();
  const [products, setProducts] = useState<Array<ProductLink & { id: ProductId }>>([]);
  const call = useApi();

  // The install's other products (OPENASY_PRODUCTS), for the switcher; ids this UI does not know are left out.
  useEffect(() => {
    void call<{ products: ProductLink[] }>("/api/v1/products").then(
      (r) => setProducts(r.products.filter((p): p is ProductLink & { id: ProductId } => p.id !== "certificates" && (PRODUCT_IDS as readonly string[]).includes(p.id))),
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
    { id: "certificates", label: "Certificates", icon: BadgeCheck, count: summary?.certificates },
    { id: "endpoints", label: "Endpoints", icon: Radar, count: summary?.failingEndpoints || undefined },
  ];
  const footerNav = [
    { id: "setup", label: "Setup", icon: Settings2 },
    ...(can("admin")
      ? [
          { id: "members", label: "Members", icon: Users },
          { id: "signin", label: "Sign-in", icon: LogIn },
          { id: "tokens", label: "API tokens", icon: KeyRound },
        ]
      : []),
    { id: "account", label: "Account", icon: UserRound },
  ];
  const active = route.page === "certificate" ? "certificates" : route.page;
  const roleName = me.user.role.charAt(0).toUpperCase() + me.user.role.slice(1);

  return (
    <AppShell
      product="certificates"
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
        <EndpointsPage call={call} reload={reload} />
      ) : route.page === "account" || route.page === "members" || route.page === "signin" || route.page === "tokens" ? (
        <SettingsPage page={route.page} />
      ) : (
        <SetupPage />
      )}
    </AppShell>
  );
}

export function App() {
  const [theme] = useThemePreference();
  return (
    // No organization until branding is configurable (ADR 0004); the library's default is a placeholder.
    <BrandProvider theme={theme} brand={{ name: "OpenAsy", organization: undefined }} className="min-h-screen">
      <AuthGate product="OpenAsy Certificates">
        <Product />
      </AuthGate>
    </BrandProvider>
  );
}
