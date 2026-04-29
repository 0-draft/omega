# Raftel

> SPIFFE-compatible Workload Identity + AuthZEN-compliant Authorization + OIDC Federation + AI Agent Identity, in a single binary. Apache-2.0. PQC ready from Day 1.

Raftel is the destination only the Pirate King reaches — the truth at the end of the Grand Line.
This project is the destination of the Workload Identity / Authorization stack: one binary, one operator, no proprietary tokens, no proprietary IDLs.

**Status: pre-alpha (PoC v0.0.1 in progress).** Do not use in production. APIs will break.

## Why

Existing Athenz-style stacks ship 13+ repositories, a proprietary IDL (RDL), a proprietary token (NToken), and a 27-table MySQL schema. Vault has been BSL-licensed and absorbed into IBM. SPIFFE/SPIRE is the standard but punts on Authorization. AuthZEN 1.0 just landed but no one ships an end-to-end product around it.

Raftel is the answer:

- **One binary** — `raftel server`, `raftel agent`, `raftel <CRUD>`. No 13-repo zoo
- **SPIFFE-native** — X.509-SVID + JWT-SVID, Workload API on a Unix socket
- **AuthZEN 1.0** — Cedar by default, swap in OPA / OpenFGA / SpiceDB as external PDPs
- **OIDC Federation Hub** — AWS / GCP / Azure / GitHub Actions in-tree
- **K8s-native** — CRDs from day one, CSI driver for cert delivery
- **PQC-ready** — ML-DSA / ML-KEM selectable at issuance time
- **AI Agent Identity** — MCP server SVID + sender-constrained JWT-SVID, in-tree
- **Apache-2.0**, no CLA, no BSL trap door

## Quickstart (PoC v0.0.1)

```bash
git clone https://github.com/kanywst/raftel
cd raftel
make build
make demo
```

`make demo` brings up control plane + agent + a sample protected service, fetches a SVID, and shows Cedar-evaluated allow/deny. Should take 30 seconds.

## Status / Roadmap

PoC scope and 4-week sprint plan: see [docs/poc/scope.md](docs/poc/scope.md).

| Version | Scope                                                                |
| ------- | -------------------------------------------------------------------- |
| v0.0.1  | Single binary, X.509-SVID issuance, Cedar PDP, demo                  |
| v0.0.2  | JWT-SVID, container image, Helm chart, GitHub Actions release        |
| v0.1    | K8s Operator + CRDs, CSI driver, Postgres + event-sourcing           |
| v0.2    | OIDC Federation Hub (AWS / GCP / Azure / GitHub), tamper-evident log |
| v0.3    | PQC (ML-DSA), HSM (PKCS#11) + KMS plugins, Athenz ZMS importer       |
| v0.4    | AI Agent Identity (MCP server SVID, sender-constrained JWT)          |
| v1.0    | CNCF Sandbox proposal                                                |

## License

Apache-2.0. See [LICENSE](LICENSE).
