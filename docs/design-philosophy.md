# Design philosophy

This page is the rule used to decide whether a proposed feature
belongs in Omega. The five design principles in [scope.md](scope.md)
say *what* Omega is; this page says *how* the boundary between
"Omega ships it", "Omega defines an interface and ships one default",
and "Omega never ships it" is drawn.

The headline rule is unchanged: Omega is the workload + agent
identity and authorization control plane. Issuance, AuthZEN
evaluation, OIDC federation, audit. Anything outside that loop is
either a plugin seam or somebody else's job.

## Three layers

| Layer                                                                  | What lives here                                                                        | Examples                                                                                                                                                                                                                                                                      |
| ---------------------------------------------------------------------- | -------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Core (in-tree, mandatory)                                              | wire formats Omega produces or consumes; control-plane decisions Omega owns end-to-end | X.509-SVID / JWT-SVID issuance, AuthZEN 1.0 PDP, OIDC federation, tamper-evident audit log, K8s Operator + cert-manager external Issuer, admin UI                                                                                                                             |
| Plugin (in-tree interface + default, external implementations welcome) | upstream systems Omega depends on but does not own                                     | PDP engine (Cedar default; OPA / OpenFGA / SpiceDB / Cerbos via AuthZEN), CA upstream (self-signed default; Vault PKI / step-ca / AWS PCA / GCP CAS / Azure KeyVault), storage (SQLite default; Postgres), workload attestor (Kubernetes / EC2 / GCP IAM / Docker / Unix uid) |
| Out-of-tree (integrate only, never ship)                               | downstream consumers and adjacent products                                             | end-user login UX (Keycloak), secrets storage (Vault), mesh data plane (Istio / Linkerd / Envoy), SIEM analytics (Splunk / Loki), agent runtime (MCP servers / LangChain), CRL / OCSP responders                                                                              |

The Core layer is what shows up in the README's "what Omega *is*"
column. The Plugin layer is the answer to "this is what makes
Omega-as-platform different from Omega-as-monolith". The Out-of-tree
layer is enumerated in [non-goals.md](non-goals.md) with the
recommended replacement for each.

## Four rules for "when in doubt"

When a proposed feature isn't obviously in one layer, walk these in
order. The first one that fires gives the answer.

1. **Does Omega produce or consume the wire format?** If yes - Core.
   X.509-SVID and JWT-SVID encoding, AuthZEN 1.0 request and response
   shape, OIDC discovery document, SCIM 2.0 provisioning calls, and
   the audit-log hash-chain format are all examples. Omega cannot
   delegate these; getting them wrong breaks compatibility with the
   rest of the ecosystem.

2. **Is it a control-plane decision Omega owns?** If yes - Core.
   "Should this CSR be signed?", "Does this AuthZEN evaluation permit
   the action?", "Should this audit entry be appended?" - these are
   the decisions the control plane exists to make. They cannot be
   moved out without making Omega a thin proxy.

3. **Is it an upstream system Omega depends on but does not own?**
   If yes - Plugin. The CA that signs intermediate certificates, the
   PDP that evaluates Cedar (or doesn't), the database that holds
   policy state, the attestor that proves a workload is who it claims
   to be - Omega ships an interface and one good default for each so
   the single-binary quickstart works, and accepts external plugins
   for everything else. This is the SPIRE / OPA modularity model.

4. **Is it a downstream consumer or an adjacent product?** If yes,
   out-of-tree. Mesh data planes consume Omega's identity. SIEMs
   consume Omega's audit log. Agent runtimes consume Omega's
   delegation tokens. Secrets engines sit alongside Omega, not inside
   it. For each of these the right answer is an integration document,
   not a feature.

If none of the four rules fires, the feature is most likely
out-of-scope and should be discussed in a GitHub Discussion before a
PR lands.

## Worked examples

### CRL / OCSP / OCSP Stapling

Rule 4 fires first: certificate revocation infrastructure is a
downstream consumer pattern, and the rest of PKI has converged on
short-lived rotation as the replacement. SPIRE explicitly scoped
revocation out, the WebPKI ecosystem retired OCSP, and Omega's 30
minute X.509-SVID lifetime makes a deny-list mechanism arrive too
late to matter. Out-of-tree, full stop. See
[non-goals.md](non-goals.md#omega-is-not-a-crl--ocsp-responder).

### Postgres storage backend

Rule 3 fires: storage is an upstream Omega depends on but does not
own. SQLite stays as the in-process default for the quickstart;
Postgres ships as the production default. Both implement the same
storage interface. Other backends (e.g. an external KV) are accepted
as out-of-tree plugins.

### Event sourcing on top of Postgres

Rule 2 doesn't fire (the audit log is already tamper-evident through
hash-chaining; event sourcing would be a redundant durability
mechanism). Rule 3 doesn't fire (event sourcing isn't an upstream
system; it's an internal architectural choice). The cost - schema
evolution friction, query difficulty, and a learning curve on the
operator side - has no offsetting Core or Plugin requirement. Killed.

### Raft consensus inside the omega binary

Rule 3 fires partially (replication is an upstream concern), but the
"plugin" answer is the storage layer Postgres backend plus
advisory-lock leader election, not a self-implemented Raft. Vault
chose Raft because its data plane is stateful storage; Omega's
stateful surface is the CA private key plus policy, both of which
DB-side replication handles cleanly. Self-implemented Raft is
deferred indefinitely and only revisited if a deployment proves
DB-side HA insufficient.

### cert-manager external Issuer

Rule 1 fires: the wire format here is the Kubernetes
`CertificateRequest` resource and Omega is the signer. Because the
issuer-lib upstream library handles all the controller-runtime
plumbing, the in-tree implementation is a thin Sign / Check pair
calling the same CA path the HTTP `/v1/svid` endpoint uses. Core.

### MCP server SVID and A2A delegation

Rule 1 fires: the JWT-SVID issued to an agent and the RFC 8693
token-exchange chain that records "human → agent → tool" delegation
are wire formats Omega produces. Rule 2 fires: the AuthZEN evaluation
that gates each tool call is a control-plane decision. Both are Core.
What Omega does *not* ship - the LLM client, the tool registry, the
prompt template system - falls to Rule 4 and is Out-of-tree.

## How to use this page in a PR review

When a contribution arguably falls outside the Core layer, the
reviewer's job is to identify which of the four rules applies, link
to it, and indicate which layer the feature should live in. If the
contributor disagrees with the layer assignment, the right venue is a
GitHub Discussion proposing a scope amendment - the design principles
in [scope.md](scope.md) and the layer rules here are revisable,
but the bar is explicit.
