# Observability example

A self-contained Docker Compose stack that runs `omega-server`, scrapes its
`/metrics` endpoint with Prometheus, renders a Grafana dashboard, and ships
distributed traces through an OpenTelemetry collector to Jaeger.

## Run

```bash
cd examples/observability
docker compose up --build
```

When the stack is up:

| Service    | URL                              | Notes                              |
| ---------- | -------------------------------- | ---------------------------------- |
| Omega      | <http://localhost:18080>         | admin API + AuthZEN PDP            |
| Metrics    | <http://localhost:18080/metrics> | raw Prometheus exposition          |
| Prometheus | <http://localhost:19090>         | UI, default scrape interval 5s     |
| Grafana    | <http://localhost:13001>         | anonymous Admin, dashboard "Omega" |
| Jaeger     | <http://localhost:16686>         | trace UI, service `omega-server`   |

Ports are intentionally non-default (`18080` / `19090` / `13001` / `16686`) so
this example can run side-by-side with the top-level `compose.yaml`
quickstart.

## Generate some load

In another terminal:

```bash
# create a domain
curl -s -X POST http://localhost:18080/v1/domains \
  -H 'content-type: application/json' \
  -d '{"name":"demo"}'

# evaluate access (no policies loaded → deny)
for i in $(seq 1 50); do
  curl -s -X POST http://localhost:18080/access/v1/evaluation \
    -H 'content-type: application/json' \
    -d '{"subject":{"id":"alice","type":"user"},"action":{"name":"read"},"resource":{"type":"doc","id":"doc1"}}' \
    > /dev/null
done
```

Within ~10 seconds the Grafana dashboard shows non-zero rates on
`omega_access_decisions_total` and `omega_audit_appended_total`. In Jaeger,
pick `omega-server` from the service dropdown and click **Find Traces**.
Each `POST /access/v1/evaluation` shows the parent HTTP span plus
`policy.Evaluate` and `audit.append` children, with the AuthZEN decision
attached as a span attribute.

## Tear down

```bash
docker compose down -v
```

## What's included

| File                                               | Purpose                                           |
| -------------------------------------------------- | ------------------------------------------------- |
| `compose.yaml`                                     | omega + prometheus + grafana + collector + jaeger |
| `prometheus.yml`                                   | scrape `omega-server:8080/metrics` every 5s       |
| `otel-collector.yaml`                              | OTLP receiver → batch → forward to jaeger         |
| `grafana/provisioning/datasources/prometheus.yaml` | Prometheus datasource auto-provisioning           |
| `grafana/provisioning/dashboards/omega.yaml`       | dashboard provider pointing to the JSON           |
| `grafana/dashboards/omega.json`                    | "Omega control plane" dashboard                   |

The dashboard panels cover build info, total counters (domains / SVIDs /
audit entries), HTTP request rate and latency (p50 / p95 / p99), access
decisions (allow vs deny rate, evaluation latency), SVID issuance by kind,
and audit appends by kind.

See `docs/observability.md` for the full metric reference, the trace
attribute schema, and how to wire this into an existing Prometheus /
Grafana / Jaeger installation.
