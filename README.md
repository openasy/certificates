# certificates

[![CI](https://github.com/openasy/certificates/actions/workflows/ci.yml/badge.svg)](https://github.com/openasy/certificates/actions/workflows/ci.yml)
[![Node.js 26 LTS](https://img.shields.io/badge/node-26%20LTS-339933?logo=nodedotjs&logoColor=white)](./.nvmrc)
[![License: AGPL-3.0](https://img.shields.io/badge/license-AGPL--3.0-blue)](./LICENSE)

The [OpenAsy](https://github.com/openasy) Certificates product: **every TLS certificate you have, when it expires and
what is wrong with it** (ADR 0046). Certificates arrive two ways: you send them, or the server reads them from public
endpoints with a TLS handshake. Private keys are never accepted.

```
cron, CI or a collector ──POST /api/v1/certificates (PEM)──▶  certificates  ──▶  inventory: state, warnings, chain, where seen
public endpoints ◀──TLS handshake every 6 hours──────────────       └── /api/v1/expiring and /metrics, to alert on
```

## Send certificates

```bash
# a file, or a chain
curl -sf -X POST -H "Authorization: Bearer $CERTIFICATES_INGEST_TOKEN" --data-binary @/etc/ssl/certs/shop.pem \
  "https://certs.example.com/api/v1/certificates?source=web-1:/etc/ssl/certs/shop.pem"

# what a server presents
openssl s_client -connect shop.example.com:443 -showcerts </dev/null 2>/dev/null | curl -sf -X POST \
  -H "Authorization: Bearer $CERTIFICATES_INGEST_TOKEN" --data-binary @- \
  "https://certs.example.com/api/v1/certificates?source=shop.example.com:443"
```

- **A body that holds a private key of any kind is refused whole** (`private-key`), before it is read and without
  repeating any of it. The key stays where it is.
- A certificate is known by its SHA-256 fingerprint, so the same one sent from many places is one certificate with each
  place it was seen (`source`) and its position in that chain.
- What signed a certificate is shown as its chain, among the certificates seen here.

## Endpoints

The endpoints come from the endpoints file (see below); the server connects to each every 6 hours (`CERTIFICATES_PROBE_HOURS`), reads the chain
it presents, and says apart whether the system's roots trust it and it fits the name. **Only public addresses**: a name
that resolves to a private, loopback or link-local address is refused at every probe, so the
server cannot be used to reach your internal network. Certificates on private networks are sent by a collector there.

### From a file

Endpoints come from a file the install keeps, the same file Uptime reads, and from nowhere else (ADR 0052): there is
no form and no API route that adds one. Mount it and set
`OPENASY_ENDPOINTS`; Certificates reads it at start and again within a minute of a change, and probes new endpoints at
once. Its `https://` and `tls://` entries are endpoints here; the others are Uptime's.

```yaml
endpoints:
  - name: Website
    url: https://www.example.com
    server: web-1                     # the server it runs on, by its name in the hosts file
  - name: Mail
    url: tls://mail.example.com:465
```

An endpoint is changed and removed in the file: the API answers 409 to a delete. Endpoints added in the UI before 0.5.0
keep working, and the Endpoints page shows the lines to copy into the file; once an entry has the same address, it takes
the endpoint over with what was read. A name on a
private address is kept with the probe's error rather than refusing the file. A file with a mistake is not applied at
all: the endpoints from its last good version stay, and the Endpoints page and the log say what to fix.

## State and warnings

| State | When |
| --- | --- |
| `expired` | past its end |
| `critical` | under 7 days left (or the smallest threshold, if lower) |
| `expiring` | under the largest threshold, 30 days by default |
| `not-yet-valid` | before its start |
| `valid` | otherwise |

Warnings: `weak-key` (RSA under 2048 bits), `weak-signature` (SHA-1 or MD5), `wildcard` (one key for every subdomain),
`self-signed` (a leaf that signed itself) and `long-lifetime` (a leaf valid for over 398 days).

**Expiry alerts.** Each certificate is reported once for the tightest threshold it has crossed (30, 14, 7 and 1 days
by default, and 0 for expired), not again for the wider ones. A scheduled alert asks `GET /api/v1/expiring?since=` with
the time of its last run.

## Run

```bash
openssl rand -hex 32 > openasy-kek
export CERTIFICATES_INGEST_TOKEN=$(openssl rand -hex 32)
docker compose up -d
docker compose logs certificates | grep 'no owner yet'
```

Open the link from the log once to create the owner account; there is no default password (ADR 0013). The UI and API
are on http://localhost:8080, the API reference at http://localhost:8080/api/docs/.

`openasy-kek` encrypts sign-in secrets in the database (ADR 0021). Keep it apart from the volume and with your backups.

| Variable | Default | |
| --- | --- | --- |
| `PORT` | `8080` | HTTP port |
| `CERTIFICATES_PUBLIC_URL` | `http://localhost:8080` | The address people open, with `https://` behind your TLS proxy |
| `OPENASY_PRODUCTS` | | The install's other OpenAsy products, for the product switcher. Give every product the same value |
| `CERTIFICATES_INGEST_TOKEN` | | Lets cron jobs, CI and collectors send certificates, and nothing else. An API token with the editor role works too |
| `OPENASY_CERT_WARN_DAYS` | `30,14,7,1` | Expiry thresholds in days, largest first. Uptime reads the same variable, so give both the same value: its TLS checks fail at the critical one. `CERTIFICATES_WARN_DAYS` is still read, for now |
| `OPENASY_ENDPOINTS` | | A YAML file of endpoints, shared with Uptime; see [From a file](#from-a-file) |
| `CERTIFICATES_PROBE_HOURS` | `6` | How often endpoints are read |
| `CERTIFICATES_SECRETS_KEY_FILE` | `/run/secrets/openasy-kek` | 32-byte key-encryption key |
| `CERTIFICATES_DB` | `/data/certificates.db` | SQLite file (WAL), on the `/data` volume |
| `CERTIFICATES_RETENTION_DAYS` | `365` | Certificates not seen for this long, and on no endpoint, are deleted |
| `CERTIFICATES_METRICS_PORT` | | Serve `/metrics` on this port only (ADR 0026) |
| `CERTIFICATES_HEADLESS` | `false` | `true` serves only the API |
| `CERTIFICATES_PASSWORD_SIGN_IN`, `OPENASY_OIDC_*` | | Sign-in, as in every OpenAsy product ([@openasy/auth](https://github.com/openasy/auth)) |

`/metrics` has `openasy_certificates_total{state}`, `openasy_certificates_expiring{state}`,
`openasy_certificates_with_warnings` and the endpoints, to alert on in your own Prometheus.

The container runs as non-root with a read-only root filesystem, no capabilities and `no-new-privileges`.

## Roles

Viewers see everything; editors also send certificates and probe endpoints now; admins also remove endpoints added before the file,
delete certificates, and manage members and API tokens (ADR 0003).

## Develop

```bash
npm install
npm test        # reading X.509, refusing private keys, states and thresholds, probing with private addresses refused, and every API response against openapi.json
npm run dev     # the UI, with the API on :8080
```

## Licence

AGPL-3.0 (ADR 0008).
