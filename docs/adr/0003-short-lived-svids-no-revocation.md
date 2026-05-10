# ADR 0003: Short-lived SVIDs instead of CRL / OCSP

## Status

Accepted (project inception).

## Context

A traditional X.509 CA ships either a Certificate Revocation
List (CRL) or an OCSP responder so consumers can check whether a
leaf certificate has been revoked since issuance. Both add a
parallel distribution path that must always be reachable, plus a
window during which a revoked credential is still trusted because
the deny list has not propagated.

Omega's defaults are X.509-SVID at 30 minutes and JWT-SVID at 5
minutes, both auto-rotated at the validity midpoint. The maximum
residual exposure of a compromised credential is therefore
bounded by *one rotation window* - independent of how fast a CRL
or OCSP response would have shipped.

The rest of the relevant ecosystem reached the same conclusion:

| Year | Decision |
| --- | --- |
| SPIRE | Leaf-SVID revocation, CRLs, JTI deny lists explicitly out of scope ([spire#1934](https://github.com/spiffe/spire/issues/1934)) |
| 2023 | CA/B Forum SC-063 made OCSP optional, CRL mandatory for WebPKI |
| 2024 | Apple, Microsoft, Mozilla rolling out CRLite-style local revocation in browsers |
| 2025 | Let's Encrypt shut down its OCSP service (340B requests/month retired) |

The reasons cited in those decisions - privacy leakage of
browsing patterns to the CA, operational cost of a separate
distribution plane, soft-fail OCSP being effectively a no-op
under partition - apply at least as much to a workload-identity
control plane as to public web PKI.

## Decision

Do not implement CRL, OCSP, OCSP Stapling, or a JTI deny list.
The compromise response model is rotation:

| Compromise type | Response |
| --- | --- |
| Leaf SVID | Stop renewing; the cert expires within one TTL (≤30 min default) |
| Workload key | Re-attest the workload; the agent issues a new SVID on next poll |
| Signing CA | Bundle rotation: prepare new CA → propagate via bundle → activate |
| Trust domain | Federation peer removal propagates through `/v1/bundle` |

Deployments that genuinely need longer-lived (multi-day) SVIDs
*and* a deny-list mechanism should encode revocation in the
**external PDP layer**: include a `revoked` attribute in the
AuthZEN context and let Cedar policy gate on it. This keeps
revocation in policy, where it can be audited and reasoned
about, rather than in a separate signing channel.

## Consequences

Easier:

- Operators do not need to deploy a CRL distribution point or an
  OCSP responder.
- The compromise response (rotation) exercises the issuance
  path, which is always-on. There is no separate path that has
  to be working at the moment of incident response.
- Privacy leakage to a CA over OCSP is a non-issue.

Harder:

- Long-lived SVIDs are not supported as a first-class
  configuration. Operators who try to extend the TTL into the
  multi-day range (e.g. for offline workloads) lose the
  rotation-as-revocation property and must bring their own
  policy-layer deny list.
- Auditors trained on traditional PKI mental models may ask for
  CRL / OCSP and have to be re-educated. The
  [`docs/non-goals.md`](../non-goals.md#omega-is-not-a-crl--ocsp-responder)
  page exists to make that conversation efficient.

New obligations:

- The 30-minute / 5-minute TTL defaults are part of the public
  API surface and must be honoured by future changes (or
  explicitly bumped via a new ADR + CHANGELOG entry).
- Auto-rotation at validity midpoint must remain the default
  agent behaviour.

## Scope fit

Rule 4 in [design-philosophy.md](../design-philosophy.md):
*"Is it a downstream consumer or an adjacent product?"*

Certificate revocation infrastructure is a downstream consumer
pattern, and the rest of PKI has converged on rotation as the
replacement. Out-of-tree, full stop. See
[`docs/non-goals.md`](../non-goals.md#omega-is-not-a-crl--ocsp-responder)
for the operator-facing version.
