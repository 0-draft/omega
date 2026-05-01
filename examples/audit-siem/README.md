# Forwarding the audit chain to a SIEM

Every privileged operation an Omega control plane performs (X.509 SVID
issuance, JWT-SVID issuance, AuthZEN decision, policy reload) is
appended to a tamper-evident audit chain in the local SQLite store.
This example wires that chain to an external receiver over a signed
HTTP webhook so a SIEM, log pipeline, or custom collector can consume
it without touching the database.

## Topology

```text
                 +-----------------------+   AuthZEN evals    +-------------------------+
   curl -------> |  omega server         | -----------------> |   policy.Engine         |
                 |  :18098               |  ext_authz / API   |                         |
                 +-----------+-----------+                    +-------------------------+
                             |                                              |
                             v                                              v
                      audit_log (sqlite, hash-chained)               (decision, reasons)
                             |
                  +----------+-----------+
                  |  audit.Pump (200ms)  |  reads audit_forward_state.last_seq, then
                  |                      |  ListAudit(seq>last, batch=100)
                  +----------+-----------+
                             |
                             | POST /audit  { "events": [...] }
                             | X-Omega-Signature: sha256=<hmac>
                             v
                  +----------------------+
                  |  webhook receiver    |  verifies HMAC, appends each event
                  |  :18099              |  to events.jsonl
                  +----------------------+
```

The pump owns a per-forwarder watermark in the `audit_forward_state`
table. The watermark only advances after the receiver acknowledges the
batch with a 2xx, so a crashed sink (or a dropped network) replays the
same range on the next poll. Receivers should de-duplicate on the
event's stable `hash` field.

## Run it

```bash
make demo
```

The script:

1. builds and starts the receiver on `127.0.0.1:18099`
2. starts an Omega control plane on `127.0.0.1:18098` with
   `--audit-webhook-url http://127.0.0.1:18099/audit` and
   `--audit-webhook-secret demo-shared-secret`
3. POSTs three AuthZEN evaluations against `/access/v1/evaluation`
   (`alice/read` allow, `alice/write` deny, `bob/read` deny)
4. asserts that the receiver saw at least one `allow` and two `deny`
   events and that the HMAC signature was accepted on every batch

Expected tail of the output:

```text
[demo] events captured by receiver:
  {"seq":1,"ts":"...","kind":"access.evaluate","subject":"alice","decision":"allow","payload":{...}, ...}
  {"seq":2,"ts":"...","kind":"access.evaluate","subject":"alice","decision":"deny","payload":{...}, ...}
  {"seq":3,"ts":"...","kind":"access.evaluate","subject":"bob","decision":"deny","payload":{...}, ...}
[demo] allow=1 deny=2
[demo] success - signed audit batches delivered and verified
```

## Webhook contract

Every batch is a single POST to the configured URL with this shape:

```json
{
  "events": [
    {
      "seq": 42,
      "ts": "2026-04-30T12:34:56.789Z",
      "kind": "access.evaluate",
      "subject": "alice",
      "decision": "allow",
      "payload": { "...": "..." },
      "prev_hash": "...",
      "hash": "..."
    }
  ]
}
```

Headers set on every request:

| header                | value                                                                                         |
| --------------------- | --------------------------------------------------------------------------------------------- |
| `Content-Type`        | `application/json`                                                                            |
| `X-Omega-Event-Count` | number of events in the batch (lets a sink reject empty pings without parsing the body)       |
| `X-Omega-Signature`   | `sha256=<hex>` HMAC-SHA256 of the raw body, present only when `--audit-webhook-secret` is set |

The receiver MUST respond `2xx` to acknowledge the batch. Any other
response (including transport failures) leaves the watermark unchanged
and the same range is retried on the next poll.

## Configuration on the server

| flag                     | default                    | meaning                                           |
| ------------------------ | -------------------------- | ------------------------------------------------- |
| `--audit-webhook-url`    | empty (forwarder disabled) | POST audit batches to this URL                    |
| `--audit-webhook-secret` | empty (no signature)       | shared secret for `X-Omega-Signature`             |
| `--audit-batch-size`     | 100                        | max events per POST; clamped to 1000 by the store |
| `--audit-poll-interval`  | 1s                         | how often the pump asks the store for new rows    |

The forwarder runs as a background goroutine; the API path that writes
the audit row is unaffected when the sink is slow or down.

## What this example does NOT cover

The current build ships one forwarder (webhook). OTLP-Logs export is
the planned next step: the `audit.Forwarder` interface is shaped so the
OTLP path slots in without changing the pump or the storage surface,
and a server with both flags set will run two pumps with independent
watermarks (a slow OTLP collector cannot block webhook delivery and
vice versa).

## Files

| path                              | purpose                                                                                |
| --------------------------------- | -------------------------------------------------------------------------------------- |
| `receiver/main.go`                | minimal HMAC-validating webhook sink that appends every event to a JSONL file          |
| `policies/allow-alice-read.cedar` | one Cedar policy so the demo's AuthZEN evals produce a mix of allow + deny decisions   |
| `run-demo.sh`                     | spin server + receiver, drive evaluations, assert the receiver got the expected events |
| `Makefile`                        | `make demo` / `make down` wrappers                                                     |
