# ADR 0001: Cedar as the default PDP

## Status

Accepted (project inception).

## Context

Omega exposes an [OpenID AuthZEN 1.0](https://openid.net/specs/authorization-api-1_0.html)
PDP at `POST /access/v1/evaluation`. AuthZEN is a wire format, not
a policy engine; the project has to ship at least one default
engine so the single-binary quickstart works without an external
PDP.

Candidate engines as of project start (early 2026):

- **Cedar** (Apache-2.0, joined CNCF Sandbox 2025-10-08, AWS / Cloudflare / MongoDB / StrongDM / AWS Bedrock AgentCore production users). RBAC + ABAC + limited ReBAC. Formally analysable.
- **OPA / Rego** (Apache-2.0, CNCF Graduated). Mature, large policy ecosystem, ABAC-first.
- **OpenFGA** (Apache-2.0, CNCF Sandbox). ReBAC-first (Zanzibar lineage).
- **SpiceDB** (Apache-2.0). ReBAC, also Zanzibar lineage.
- **Cerbos** (Apache-2.0). RBAC + ABAC, simpler model than OPA.

Constraints driving the choice:

- The default PDP runs in-process with `omega server`. Network
  hops between Omega and a separate PDP are an acceptable Plugin
  configuration but not the default - the project's value
  proposition is "single binary".
- The default PDP needs to cover RBAC, ABAC, and at least the
  hierarchical-group flavour of ReBAC, because the README
  promises all three for every subject (Service / Human / AI).
- The default PDP must be Apache-2.0 with no CLA, matching the
  project's licence commitment.
- The default PDP must have a Go-native, in-process implementation
  - shelling out to a separate runtime defeats the
    single-binary goal.

Cedar is the only candidate that simultaneously hits all four
constraints. `cedar-go` is in-process, RBAC + ABAC + limited
ReBAC are first-class, the licence is Apache-2.0, and Cedar's
formal-analysis tooling is a net plus for an authorization
control plane.

OPA / Rego is the closest runner-up; it is Plugin-supported (an
operator can swap Cedar for OPA via the AuthZEN bridge), but the
default cost includes a heavier runtime and an ABAC-leaning
mental model that fits the "Service" subject worse than the
RBAC-first deployments we expect.

OpenFGA / SpiceDB are too narrow for the default - their value is
ReBAC graphs, which are an enhancement to Cedar's RBAC/ABAC
default rather than a replacement.

## Decision

Embed `cedar-go` as the default in-process PDP. Expose the
AuthZEN 1.0 wire format on `POST /access/v1/evaluation` so any
external AuthZEN-speaking PDP (OPA, OpenFGA, SpiceDB, Cerbos,
Aserto, Topaz, etc.) can be swapped in via a future bridge.

## Consequences

Easier:

- The single-binary quickstart works with zero PDP configuration
  - operators get a usable allow/deny path on the first
    `make demo`.
- AuthZEN compliance is one wire format we own end-to-end; no
  translation layer between the HTTP request and the engine.
- Cedar's analysis tooling is available to operators who care
  about formal verification of policy bundles.

Harder:

- Heavy ReBAC graphs (Zanzibar-style) are not a good fit for
  Cedar. Operators in that bucket have to run OpenFGA or SpiceDB
  behind the AuthZEN bridge.
- The AuthZEN bridge / adapter for non-Cedar engines is not
  built yet (tracked in `ROADMAP.md` and `gap-analysis.md`).
  Until it lands, Cedar is the only practical engine choice.

New obligations:

- Track Cedar releases and the `cedar-go` Go API for breaking
  changes; the engine is an upstream dependency we ship by
  default.
- Maintain example policies under `examples/` that exercise
  RBAC + ABAC + delegation patterns.

## Scope fit

Rule 3 in [design-philosophy.md](../design-philosophy.md):
*"Is it an upstream system Omega depends on but does not own?"*

Yes. The PDP engine is a Plugin layer concern: Omega defines the
AuthZEN wire interface, ships Cedar as the default, and accepts
external implementations.
