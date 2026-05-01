# Postgres-backed HA (advisory-lock leader election)

A two-replica Omega control plane sharing one Postgres database, with
write traffic gated on a Postgres advisory-lock leader. Reads stay
open on every replica; writes go through whichever replica currently
holds the lock. When the leader dies, the follower picks the lock up
on its next poll and starts accepting writes.

## What this exercises

| Concern                           | How HA mode handles it                                                                    |
| --------------------------------- | ----------------------------------------------------------------------------------------- |
| Single writer for the audit chain | `pg_try_advisory_lock(<key>)` on a dedicated session - only one replica holds it          |
| Follower rejects writes loudly    | `POST` returns `503 Service Unavailable` with `Retry-After: 1`                            |
| Follower still serves reads       | `GET /v1/domains`, `/v1/bundle`, `/v1/audit/...` work on every replica                    |
| Visible state                     | `GET /v1/leader` returns `{"is_leader": bool}` for ops dashboards                         |
| Fail-over                         | Leader process dies → Postgres releases the session lock → follower acquires on next poll |

## Run it

```bash
make demo
```

The demo:

1. Starts a transient `postgres:16-alpine` container.
2. Boots two omega servers (`a` on `:18101`, `b` on `:18102`) wired to the same DB.
3. Polls `GET /v1/leader` on both until exactly one replica claims leadership.
4. Sends a domain-create write to the leader (succeeds) and the follower (must 503 + `Retry-After: 1`).
5. Kills the leader process. Watches the follower promote.
6. Sends a write to the new leader and prints the resulting domain rows directly from Postgres.
7. Verifies `/v1/audit/verify` reports `valid: true` end-to-end.

## Server flags introduced

| Flag                            | Default          | Purpose                                                                                |
| ------------------------------- | ---------------- | -------------------------------------------------------------------------------------- |
| `--db <DSN>`                    | empty (= SQLite) | Set to a `postgres://...` DSN to enable HA.                                            |
| `--ha-leader-key <int>`         | reserved key     | Advisory-lock key. Override only when running multiple Omega clusters on one Postgres. |
| `--ha-poll-interval <duration>` | `1s`             | How often a follower retries to acquire the lock.                                      |

The election goroutine starts only when `--db` looks like a Postgres
DSN; SQLite stays single-writer-by-definition with no leader gate.

## Caveats

The advisory lock is held on a dedicated `*sql.Conn` so it follows the
session, not the transaction. If a network blip kills that one
connection (without killing the process), the leader bit flips to
`false` on the next ping and the leader stops accepting writes until
the lock is reacquired. Followers fill in within one poll interval.
