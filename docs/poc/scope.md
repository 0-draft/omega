# Raftel PoC v0.0.1 — Scope

> Detailed background lives in the kill-athenz-pj research notes. This file is the in-repo summary.

## Goal

> `raftel server` (control plane) + `raftel agent` (Workload API) + `raftel svid fetch` (CLI).
> A demo client picks up an X.509-SVID, calls a protected HTTP endpoint, and the request is
> allowed or denied by a Cedar policy. End-to-end demo in 30 seconds.

## In-scope (v0.0.1)

- Single binary `raftel` with subcommands: `server`, `agent`, `domain`, `policy`, `svid`.
- Self-signed CA on first boot. X.509-SVID, 30 minute validity. SPIFFE ID format
  `spiffe://raftel.local/<domain-path>/<service>`.
- SPIFFE Workload API on `/tmp/raftel-agent.sock`, UID-based attestation.
- Cedar engine embedded. AuthZEN 1.0 endpoint at `POST /access/v1/evaluation`.
- SQLite single-file storage (`<data-dir>/raftel.db`). 3 tables.
- `examples/hello-svid/` demo (server + client), wired up by `make demo`.

## Out-of-scope (defer)

JWT-SVID, K8s CRDs / Operator, OIDC federation, PQC, HSM/KMS plugins, Postgres /
event-sourcing, container image, Athenz ZMS importer, AI agent identity.
See [`05-proposal.md`](../../../kill-athenz-pj/notes/05-proposal.md) for the full roadmap.

## Definition of Done

1. `make build` cross-compiles for darwin/arm64 and linux/amd64.
2. `make demo` brings up server, agent, demo client and shows allow/deny.
3. `go test ./...` is green with `-race`.
4. README has a quickstart that fits on one screen.

## Sprint plan

| Week | Deliverable                                                  |
| ---- | ------------------------------------------------------------ |
| W1   | Repo bootstrap, cobra skeleton, SQLite, domain CRUD          |
| W2   | CA + X.509-SVID issuance, Workload API socket                |
| W3   | Cedar PDP, AuthZEN HTTP endpoint, demo app                   |
| W4   | README, asciinema, CI green, v0.0.1 tag, push public         |
