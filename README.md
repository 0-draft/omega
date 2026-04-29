# Omega

> SPIFFE-compatible Workload Identity + AuthZEN-compliant Authorization + OIDC Federation + AI Agent Identity, in a single binary. Apache-2.0. PQC ready from Day 1.

**Ω — the last letter, and the last identity platform you'll need to deploy.**

Workload identity has been three things at once for a decade: a private fork (Athenz / NToken / RDL), a half-finished standard (SPIFFE without authorization), and a proprietary cul-de-sac (Vault absorbed into IBM, BSL-licensed). Omega exists to end that. One binary, one operator, every piece swappable, every wire format an open standard.

**Status: pre-alpha (PoC v0.0.1 in progress).** Do not use in production. APIs will break.

## Why

Existing Athenz-style stacks ship 13+ repositories, a proprietary IDL (RDL), a proprietary token (NToken), and a 27-table MySQL schema. SPIFFE/SPIRE is the de-facto identity standard but punts on authorization. AuthZEN 1.0 just landed (OpenID Final, January 2026) but no one ships an end-to-end product around it. WIMSE is still in IETF draft. AI agent identity (MCP, A2A) is a green field.

Omega is the convergence point:

- **One binary** — `omega server`, `omega agent`, `omega <CRUD>`. No 13-repo zoo
- **SPIFFE-native** — X.509-SVID + JWT-SVID, Workload API over a Unix socket
- **AuthZEN 1.0** — Cedar by default, swap in OPA / OpenFGA / SpiceDB as external PDPs
- **OIDC Federation Hub** — AWS / GCP / Azure / GitHub Actions in-tree
- **K8s-native** — CRDs from day one, CSI driver for cert delivery
- **PQC-ready** — ML-DSA / ML-KEM selectable at issuance time
- **AI Agent Identity** — MCP server SVID + sender-constrained JWT-SVID, in-tree
- **Modular like SPIRE / OPA** — every component runs standalone or in-process
- **Apache-2.0**, no CLA, no BSL trap door

## Three subjects, one platform

| Subject       | Identity format       | Authorization model         | Primary protocol                |
| ------------- | --------------------- | --------------------------- | ------------------------------- |
| Service       | X.509-SVID, JWT-SVID  | RBAC + ABAC + ReBAC         | mTLS, AuthZEN PDP               |
| Human         | OIDC, SCIM-provisioned | RBAC + ABAC + ReBAC         | OIDC, AuthZEN PDP               |
| AI Agent      | JWT-SVID + MCP / A2A  | Delegation chain, scoped    | RFC 8693 token exchange + AuthZEN |

Every authorization decision lands in a tamper-evident log with the full delegation chain, regardless of subject type.

## Quickstart (PoC v0.0.1)

```bash
git clone https://github.com/kanywst/omega
cd omega
make demo
```

`make demo` boots the control plane, two node agents (giving the same OS user two distinct SPIFFE IDs over separate sockets), and the [`examples/hello-svid`](examples/hello-svid/) server + client. The client fetches its X.509-SVID over the SPIFFE Workload API, mTLS-handshakes the server, and prints the verified peer SPIFFE ID. End-to-end in a few seconds.

Authorization is exposed at the OpenID AuthZEN 1.0 PDP API endpoint:

```bash
curl -sS -X POST http://127.0.0.1:8080/access/v1/evaluation \
  -H 'Content-Type: application/json' \
  -d '{"subject":{"type":"Spiffe","id":"spiffe://omega.local/example/web"},
       "action":{"name":"GET"},
       "resource":{"type":"HttpPath","id":"/api/foo"}}'
# -> {"decision":true,"reasons":["policy0"]}   (or {"decision":false} when no policy permits)
```

Pass `--policy-dir DIR` to `omega server` to load `*.cedar` files at startup.

## Architecture

```text
+----------------------+        +------------------+
|  omega server        |  HTTP  |  omega agent     |    workload
|  (control plane)     |<------>|  (Workload API)  |<--- (uds, X509-SVID)
|  - SQLite / Postgres |        |  - peercred      |
|  - CA + SVID issuer  |        |  - cache         |
|  - AuthZEN PDP       |        +------------------+
|  - Federation Hub    |
|  - Audit log         |
+----------------------+
```

Components are independently runnable (`omega server identity`, `omega server policy`, `omega agent`) so deployments can scale or replace each piece without forklift upgrades.

## Endpoints (PoC v0.0.1)

| Method | Path                      | Purpose                                                   |
| ------ | ------------------------- | --------------------------------------------------------- |
| GET    | `/healthz`                | Liveness                                                  |
| POST   | `/v1/domains`             | Create a SPIFFE namespace (`{name, description}`)         |
| GET    | `/v1/domains`             | List domains                                              |
| GET    | `/v1/domains/{name}`      | Fetch a domain                                            |
| POST   | `/v1/svid`                | Issue an X.509-SVID from a CSR (`{spiffe_id, csr}`)       |
| GET    | `/v1/bundle`              | Trust bundle PEM (CA cert)                                |
| POST   | `/access/v1/evaluation`   | OpenID AuthZEN 1.0 PDP evaluation                         |

Workload API gRPC (SPIFFE) is served by `omega agent` over a Unix socket and speaks the standard `SpiffeWorkloadAPI` service: `FetchX509SVID` and `FetchX509Bundles`.

## Standards alignment

| Layer               | Standard                                                      |
| ------------------- | ------------------------------------------------------------- |
| Workload identity   | SPIFFE / SPIRE compatible (X.509-SVID, JWT-SVID, Workload API) |
| Multi-domain identity | IETF WIMSE                                                  |
| Authorization       | OpenID AuthZEN 1.0                                            |
| Federation          | OIDC, OAuth 2.1, RFC 8693 (token exchange)                    |
| Token binding       | RFC 8705 (mTLS-bound) / RFC 9449 (DPoP)                       |
| Provisioning        | SCIM 2.0                                                      |
| AI agent identity   | MCP (Anthropic), A2A (Google), GNAP                           |
| Cryptography        | NIST FIPS 203 / 204 / 205 (ML-KEM / ML-DSA / SLH-DSA)         |

## Roadmap

PoC scope and 4-week sprint plan: see [docs/poc/scope.md](docs/poc/scope.md).

| Version | Scope                                                                |
| ------- | -------------------------------------------------------------------- |
| v0.0.1  | Single binary, X.509-SVID issuance, Cedar PDP, demo                  |
| v0.0.2  | JWT-SVID, container image, Helm chart, GitHub Actions release        |
| v0.1    | K8s Operator + CRDs, CSI driver, Postgres + event sourcing           |
| v0.2    | OIDC Federation Hub (AWS / GCP / Azure / GitHub), tamper-evident log |
| v0.3    | PQC (ML-DSA), HSM (PKCS#11) + KMS plugins, Athenz ZMS importer       |
| v0.4    | AI Agent Identity (MCP server SVID, sender-constrained JWT)          |
| v1.0    | CNCF Sandbox proposal                                                |

## License

Apache-2.0. See [LICENSE](LICENSE).
