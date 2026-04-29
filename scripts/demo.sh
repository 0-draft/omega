#!/usr/bin/env bash
# scripts/demo.sh — end-to-end PoC demo of the Omega workload identity loop.
#
# Brings up:
#   1. omega server  (control plane on :8080)
#   2. omega agent   for the "server" workload identity (Workload API on /tmp/omega-server.sock)
#   3. omega agent   for the "client" workload identity (Workload API on /tmp/omega-client.sock)
#   4. examples/hello-svid/server  — mTLS HTTPS service on https://127.0.0.1:9443
#   5. examples/hello-svid/client  — mTLS request to (4), prints the result
#
# Both agents map the current UID to a different SPIFFE ID via separate
# sockets, so a single host can demo two-identity mTLS without touching
# real OS users. The demo exits 0 on success and tears every process down.

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BIN="${OMEGA_BIN:-${ROOT}/bin/omega}"
DATA_DIR="${OMEGA_DEMO_DIR:-/tmp/omega-demo}"
SERVER_ADDR="${OMEGA_DEMO_SERVER_ADDR:-127.0.0.1:8080}"
HELLO_ADDR="${OMEGA_DEMO_HELLO_ADDR:-127.0.0.1:9443}"
SERVER_SOCK="${DATA_DIR}/omega-server.sock"
CLIENT_SOCK="${DATA_DIR}/omega-client.sock"
SERVER_ID="spiffe://omega.local/hello/server"
CLIENT_ID="spiffe://omega.local/hello/client"
UID_NUM="$(id -u)"

PIDS=()
cleanup() {
  rc=$?
  # Tear down in reverse start order: workloads first so their
  # FetchX509SVID streams close before we ask the agent to GracefulStop.
  for (( i=${#PIDS[@]}-1; i>=0; i-- )); do
    pid="${PIDS[$i]}"
    if [[ -n "${pid:-}" ]] && kill -0 "$pid" 2>/dev/null; then
      kill "$pid" 2>/dev/null || true
      wait "$pid" 2>/dev/null || true
    fi
  done
  exit "$rc"
}
trap cleanup EXIT INT TERM

if [[ ! -x "$BIN" ]]; then
  echo "[demo] building omega binary at $BIN"
  (cd "$ROOT" && make build)
fi
echo "[demo] building hello-svid example binaries"
(cd "$ROOT" && go build -o bin/hello-svid-server ./examples/hello-svid/server)
(cd "$ROOT" && go build -o bin/hello-svid-client ./examples/hello-svid/client)
HELLO_SERVER="${ROOT}/bin/hello-svid-server"
HELLO_CLIENT="${ROOT}/bin/hello-svid-client"

rm -rf "$DATA_DIR"
mkdir -p "$DATA_DIR"

wait_for() {
  local what="$1" check="$2" tries=50
  while (( tries-- > 0 )); do
    if eval "$check" >/dev/null 2>&1; then
      return 0
    fi
    sleep 0.1
  done
  echo "[demo] timed out waiting for $what" >&2
  return 1
}

echo "[demo] starting omega server"
"$BIN" server --http-addr "$SERVER_ADDR" --data-dir "$DATA_DIR" >"$DATA_DIR/server.log" 2>&1 &
PIDS+=($!)
wait_for "control plane health" "curl -sf http://$SERVER_ADDR/healthz"

echo "[demo] starting omega agent for server identity ($SERVER_ID)"
"$BIN" agent --socket "$SERVER_SOCK" --server "http://$SERVER_ADDR" \
  --map "uid=${UID_NUM},id=${SERVER_ID}" \
  >"$DATA_DIR/agent-server.log" 2>&1 &
PIDS+=($!)
wait_for "server-side agent socket" "test -S $SERVER_SOCK"

echo "[demo] starting omega agent for client identity ($CLIENT_ID)"
"$BIN" agent --socket "$CLIENT_SOCK" --server "http://$SERVER_ADDR" \
  --map "uid=${UID_NUM},id=${CLIENT_ID}" \
  >"$DATA_DIR/agent-client.log" 2>&1 &
PIDS+=($!)
wait_for "client-side agent socket" "test -S $CLIENT_SOCK"

echo "[demo] starting hello-svid server"
"$HELLO_SERVER" --socket "$SERVER_SOCK" --addr "$HELLO_ADDR" \
  >"$DATA_DIR/hello-server.log" 2>&1 &
PIDS+=($!)
wait_for "hello-svid TLS port" "nc -z ${HELLO_ADDR%%:*} ${HELLO_ADDR##*:}"

echo "[demo] running hello-svid client"
"$HELLO_CLIENT" --socket "$CLIENT_SOCK" --url "https://$HELLO_ADDR/" --expect-server-id "$SERVER_ID"
echo "[demo] success — mTLS hello-svid handshake completed"
