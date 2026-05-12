#!/usr/bin/env bash
# run-demo.sh: prove that omega's GET /v1/spiffe-bundle endpoint
# emits a SPIFFE Trust Domain Format document that the upstream
# go-spiffe v2 SDK (spiffebundle.Read) can consume end-to-end. A
# regression that breaks the TDF shape would trip the SDK parse,
# not silently work against a permissive hand-rolled decoder.

set -euo pipefail

DEMO_DIR="${DEMO_DIR:-/tmp/omega-spiffe-bundle-tdf-demo}"
SERVER_PORT="${SERVER_PORT:-18690}"
TRUST_DOMAIN="${TRUST_DOMAIN:-omega.demo}"
REFRESH_HINT="${REFRESH_HINT:-180s}"

cleanup() {
	[[ -f "$DEMO_DIR/server.pid" ]] && kill "$(cat "$DEMO_DIR/server.pid")" 2>/dev/null || true
}
trap cleanup EXIT

wait_for_url() {
	local url="$1" log="$2"
	for _ in $(seq 1 50); do
		if curl -fsS "$url" >/dev/null 2>&1; then
			return 0
		fi
		sleep 0.1
	done
	echo "[demo] FAIL: $url did not become ready within 5s"
	[[ -f "$log" ]] && { echo "[demo] log tail ($log):"; tail -20 "$log" | sed 's/^/       /'; }
	exit 1
}

rm -rf "$DEMO_DIR"
mkdir -p "$DEMO_DIR"

EXAMPLE_DIR="$(cd "$(dirname "$0")" && pwd)"

echo "[demo] building consumer"
go -C "$EXAMPLE_DIR/cmd/consumer" build -o "$DEMO_DIR/consumer" .

echo "[demo] starting omega server on :$SERVER_PORT"
omega server \
	--http-addr "127.0.0.1:$SERVER_PORT" \
	--trust-domain "$TRUST_DOMAIN" \
	--data-dir "$DEMO_DIR/server" \
	--spiffe-bundle-refresh-hint "$REFRESH_HINT" \
	>"$DEMO_DIR/server.log" 2>&1 &
echo $! >"$DEMO_DIR/server.pid"
wait_for_url "http://127.0.0.1:$SERVER_PORT/healthz" "$DEMO_DIR/server.log"

# Save the raw response too so the demo output is self-explanatory if
# someone is reading it after the fact.
curl -fsS "http://127.0.0.1:$SERVER_PORT/v1/spiffe-bundle" >"$DEMO_DIR/spiffe-bundle.json"

"$DEMO_DIR/consumer" \
	--addr "http://127.0.0.1:$SERVER_PORT" \
	--trust-domain "$TRUST_DOMAIN"

echo "[demo] raw response (first 200 chars):"
head -c 200 "$DEMO_DIR/spiffe-bundle.json"
echo
