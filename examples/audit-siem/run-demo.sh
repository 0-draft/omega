#!/usr/bin/env bash
# run-demo.sh starts a webhook receiver, brings up an omega server
# wired to forward audit events to that receiver, drives a few AuthZEN
# evaluations, and asserts that the receiver saw both an `allow` and a
# `deny` decision (and that the HMAC signature was accepted).
set -euo pipefail

DEMO_DIR="${DEMO_DIR:-/tmp/omega-audit-siem-demo}"
SERVER_PORT="${SERVER_PORT:-18098}"
RECEIVER_PORT="${RECEIVER_PORT:-18099}"
SECRET="${SECRET:-demo-shared-secret}"

cleanup() {
	[[ -f "$DEMO_DIR/server.pid" ]] && kill "$(cat "$DEMO_DIR/server.pid")" 2>/dev/null || true
	[[ -f "$DEMO_DIR/receiver.pid" ]] && kill "$(cat "$DEMO_DIR/receiver.pid")" 2>/dev/null || true
}
trap cleanup EXIT

rm -rf "$DEMO_DIR"
mkdir -p "$DEMO_DIR"

EXAMPLE_DIR="$(cd "$(dirname "$0")" && pwd)"

echo "[demo] building receiver"
go -C "$EXAMPLE_DIR/receiver" build -o "$DEMO_DIR/receiver" .

echo "[demo] starting receiver on :$RECEIVER_PORT (signed)"
"$DEMO_DIR/receiver" \
	--addr "127.0.0.1:$RECEIVER_PORT" \
	--secret "$SECRET" \
	--out "$DEMO_DIR/events.jsonl" \
	>"$DEMO_DIR/receiver.log" 2>&1 &
echo $! >"$DEMO_DIR/receiver.pid"

# Wait for the receiver to bind.
for _ in $(seq 1 20); do
	if curl -fsS -o /dev/null "http://127.0.0.1:$RECEIVER_PORT/healthz" 2>/dev/null; then
		break
	fi
	sleep 0.1
done

echo "[demo] starting omega server on :$SERVER_PORT (audit -> http://127.0.0.1:$RECEIVER_PORT/audit)"
omega server \
	--http-addr "127.0.0.1:$SERVER_PORT" \
	--trust-domain omega.demo \
	--data-dir "$DEMO_DIR/server" \
	--policy-dir "$EXAMPLE_DIR/policies" \
	--audit-webhook-url "http://127.0.0.1:$RECEIVER_PORT/audit" \
	--audit-webhook-secret "$SECRET" \
	--audit-poll-interval 200ms \
	>"$DEMO_DIR/server.log" 2>&1 &
echo $! >"$DEMO_DIR/server.pid"

# Wait for the server.
for _ in $(seq 1 50); do
	if curl -fsS -o /dev/null "http://127.0.0.1:$SERVER_PORT/healthz" 2>/dev/null; then
		break
	fi
	sleep 0.1
done

evaluate() {
	local subject="$1" action="$2" resource_id="$3"
	curl -fsS -X POST "http://127.0.0.1:$SERVER_PORT/access/v1/evaluation" \
		-H "Content-Type: application/json" \
		-d "{\"subject\":{\"type\":\"User\",\"id\":\"$subject\"},\"action\":{\"name\":\"$action\"},\"resource\":{\"type\":\"Doc\",\"id\":\"$resource_id\"}}"
	echo
}

echo "[demo] driving AuthZEN evaluations"
evaluate alice read doc-1   # expect allow
evaluate alice write doc-1  # expect deny
evaluate bob   read doc-1   # expect deny

# Give the audit pump a couple of poll cycles to flush.
sleep 1

echo "[demo] events captured by receiver:"
sed 's/^/  /' "$DEMO_DIR/events.jsonl"

allow_count=$(grep -c '"decision":"allow"' "$DEMO_DIR/events.jsonl" || true)
deny_count=$(grep -c '"decision":"deny"' "$DEMO_DIR/events.jsonl" || true)

echo "[demo] allow=$allow_count deny=$deny_count"

if [[ "$allow_count" -lt 1 ]]; then
	echo "FAIL: expected at least 1 allow event" >&2
	exit 1
fi
if [[ "$deny_count" -lt 2 ]]; then
	echo "FAIL: expected at least 2 deny events" >&2
	exit 1
fi
if grep -q "bad signature" "$DEMO_DIR/receiver.log"; then
	echo "FAIL: receiver rejected a batch (bad signature)" >&2
	exit 1
fi

echo "[demo] success - signed audit batches delivered and verified"
