# Envoy ext_authz × Omega AuthZEN PDP

A self-contained Docker Compose stack that puts an Envoy front proxy in
front of [`httpbin`](https://httpbin.org) and gates every request through
Omega's OpenID AuthZEN 1.0 PDP via Envoy's
[`ext_authz` HTTP filter](https://www.envoyproxy.io/docs/envoy/latest/configuration/http/http_filters/ext_authz_filter).
It is the canonical reference for using Omega as an authorization control
plane in an existing service mesh or API gateway.

## Wire diagram

```text
                  x-user: alice
       client ---------------------> envoy:8000
                                       |
                                       | ext_authz HTTP /authz<path>
                                       v
                                authzen-adapter:9000
                                       |
                                       | POST /access/v1/evaluation
                                       v
                                 omega-server:8080
                                  (Cedar PDP, --policy-dir)
                                       |
                                  decision: true|false
                                       |
                                       v
       upstream <----------------- envoy (200 / 403)
        httpbin
```

The `authzen-adapter` is a ~150-line Go service that translates each
ext_authz HTTP check into the AuthZEN evaluation shape
(`{subject, action, resource}`) and back to a 200 / 403. Real deployments
keep the adapter pattern but read the principal from a verified JWT or
the SAN URI of a client X.509-SVID instead of an `x-user` header.

## Run

```bash
cd examples/envoy-ext-authz
docker compose up --build
```

When the stack is up:

| Service     | URL                                           | Notes                       |
| ----------- | --------------------------------------------- | --------------------------- |
| Envoy       | <http://localhost:28000>                      | gated entry point           |
| Envoy admin | <http://localhost:29901>                      | stats, config_dump          |
| Omega       | <http://localhost:28080>                      | admin API + AuthZEN PDP     |
| PDP         | <http://localhost:28080/access/v1/evaluation> | direct PDP (bypasses envoy) |

Ports are intentionally non-default (`28000` / `28080` / `29901`) so this
example can run alongside the top-level quickstart and the observability
stack without colliding.

## Verify

```bash
# alice has @id("allow-alice-get") → GET allowed, POST denied
curl -i -H "x-user: alice" http://localhost:28000/get          # 200
curl -i -X POST -H "x-user: alice" http://localhost:28000/post # 403

# bob has no policy → everything denied
curl -i -H "x-user: bob" http://localhost:28000/get            # 403

# admin has @id("allow-admin-any") → any method, any path
curl -i -X POST -H "x-user: admin" http://localhost:28000/post # 200

# anonymous (no x-user header) → only /status/200 is permitted
curl -i http://localhost:28000/status/200                      # 200
curl -i http://localhost:28000/get                             # 403
```

Each decision lands in the adapter's structured slog output:

```json
{"level":"INFO","msg":"decision","decision":"allow",
 "subject":"alice","method":"GET","path":"/get",
 "reasons":["allow-alice-get"],"pdp_latency_ms":6}
```

The `reasons[]` field is the policy id (taken from the `@id("...")`
annotation in the matching `.cedar` file) so audit consumers can trace
every allow back to its source rule.

## What's included

| File                                 | Purpose                                          |
| ------------------------------------ | ------------------------------------------------ |
| `compose.yaml`                       | omega + adapter + envoy + httpbin                |
| `envoy.yaml`                         | listener, ext_authz filter, httpbin upstream     |
| `authzen-adapter/main.go`            | ext_authz HTTP ↔ AuthZEN bridge                  |
| `authzen-adapter/Dockerfile`         | distroless image for the bridge                  |
| `policies/allow-alice-get.cedar`     | per-subject + per-method permit                  |
| `policies/allow-admin-any.cedar`     | unscoped permit (operator / break-glass)         |
| `policies/allow-public-status.cedar` | resource-scoped permit (anonymous health probes) |

## How it composes

The Envoy filter is configured with `path_prefix: /authz`, so a request
to `GET /get` arrives at the adapter as `GET /authz/get`. The adapter
strips the prefix, reads `x-user` (allow-listed in the filter's
`authorization_request.allowed_headers`), and POSTs:

```json
{
  "subject":  {"type":"User","id":"alice"},
  "action":   {"name":"GET"},
  "resource": {"type":"HttpPath","id":"/get"}
}
```

Cedar evaluates this against the loaded policies. `allow-alice-get.cedar`
declares:

```cedar
@id("allow-alice-get")
permit (
  principal == User::"alice",
  action    == Action::"GET",
  resource
);
```

so `decision: true` comes back with `reasons: ["allow-alice-get"]`. The
adapter translates `true → 200, false → 403` for Envoy, and Envoy
forwards the original request to `httpbin` only on allow.

## Going to production

Three things this demo simplifies that you would change in a real deployment:

The principal source. `x-user` is convenient for a demo but trivially
forgeable end-to-end. In production, the adapter reads either a
JWT-SVID's `sub` claim (verified against the Omega trust bundle) or the
URI SAN of the downstream X.509-SVID surfaced by Envoy through the
`x-forwarded-client-cert` header. Cedar's `principal == Spiffe::"..."`
form is what `examples/hello-svid` already uses internally.

The PDP transport. The adapter makes a fresh HTTP/1.1 call to
`omega-server` per request. For high-RPS gateways, switch to keep-alive
with a connection pool, or keep the adapter as a sidecar and let it
stream-evaluate against an in-process Cedar engine via Omega's library
mode (planned).

The audit surface. Every Cedar evaluation already lands in the Omega
audit log; what's missing in this demo is forwarding to a SIEM. Wire the
audit log into your existing pipeline (OTLP / webhook export is planned)
so the `reasons[]` policy ids become searchable alongside the proxy's
access logs.

## Tear down

```bash
docker compose down -v
```
