# hello-svid

A minimal end-to-end demo of Omega's workload identity loop: two
processes running as the same OS user end up with two different SPIFFE
IDs, perform mTLS, and verify each other.

## Topology

```text
                ┌──────────────────────────┐
                │     omega server         │  control plane (HTTP :8080)
                │  CA + AuthZEN PDP        │
                └────────────┬─────────────┘
                             │ /v1/svid (CSR -> X.509-SVID)
              ┌──────────────┴──────────────┐
              │                             │
   ┌──────────▼──────────┐       ┌──────────▼──────────┐
   │ omega agent (svr)   │       │ omega agent (cli)   │
   │ uds: omega-server.. │       │ uds: omega-client.. │
   │ map uid=N → svr ID  │       │ map uid=N → cli ID  │
   └──────────┬──────────┘       └──────────┬──────────┘
              │ Workload API (X.509-SVID)   │
   ┌──────────▼──────────┐       ┌──────────▼──────────┐
   │ hello-svid/server   │  mTLS │ hello-svid/client   │
   │ spiffe://omega.local│◄──────┤ spiffe://omega.local│
   │   /hello/server     │       │   /hello/client     │
   └─────────────────────┘       └─────────────────────┘
```

Both agents run as the **same UID** but listen on different sockets, so
the workload's identity is determined by which socket it dials. This is
the simplest way to demo two distinct SPIFFE IDs on a single host
without creating real OS users; production deployments will use
attestor plugins (Kubernetes SAT, OIDC, process info) instead of the
demo's UID mapping.

## Run it

```bash
make demo
```

Expected output:

```text
[demo] starting omega server
[demo] starting omega agent for server identity (spiffe://omega.local/hello/server)
[demo] starting omega agent for client identity (spiffe://omega.local/hello/client)
[demo] starting hello-svid server
[demo] running hello-svid client
client SPIFFE ID: spiffe://omega.local/hello/client
hello from spiffe://omega.local/hello/server -> caller spiffe://omega.local/hello/client
[demo] success - mTLS hello-svid handshake completed
```

The `make demo` target tears every process down on exit and writes
per-process logs to `/tmp/omega-demo/`.

## What it proves

- The control plane signs valid X.509-SVIDs from CSRs.
- The agent attests local processes via UID and serves the
  Workload API gRPC contract that go-spiffe v2 understands.
- A workload can fetch its SVID + trust bundle and use it for mTLS
  without ever seeing a private key on disk.
- The peer SPIFFE ID is recoverable from the URI SAN on the
  client cert and matches the value the agent issued.
