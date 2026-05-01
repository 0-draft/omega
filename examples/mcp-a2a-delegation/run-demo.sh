#!/usr/bin/env bash
# run-demo.sh stands up an Omega control plane with the token-exchange
# AuthZEN gate enabled, a tool-server (echo MCP) listening on a local
# port, and a client orchestrator that walks a 2-hop delegation chain
# (human -> coordinator agent -> sub-agent) and calls the tool with
# the resulting JWT-SVID.
#
# Asserts:
#   * hop 1 and hop 2 token exchanges return 200 with the expected
#     delegation_chain shape.
#   * the tool-server accepts the leaf token and echoes the chain.
#   * the audit log contains 2 token.exchange allow rows whose chain
#     starts with the human SPIFFE ID.
#   * the negative case (no human in the chain) is denied by Cedar.
set -euo pipefail

DEMO_DIR="${DEMO_DIR:-/tmp/omega-mcp-a2a-demo}"
SERVER_PORT="${SERVER_PORT:-18097}"
TOOL_PORT="${TOOL_PORT:-19000}"

cleanup() {
	[[ -f "$DEMO_DIR/server.pid" ]] && kill "$(cat "$DEMO_DIR/server.pid")" 2>/dev/null || true
	[[ -f "$DEMO_DIR/tool.pid" ]] && kill "$(cat "$DEMO_DIR/tool.pid")" 2>/dev/null || true
}
trap cleanup EXIT

rm -rf "$DEMO_DIR"
mkdir -p "$DEMO_DIR"

EXAMPLE_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$EXAMPLE_DIR/../.." && pwd)"

echo "[demo] building omega + demo binaries"
go -C "$REPO_ROOT" build -o "$DEMO_DIR/omega" ./cmd/omega
go -C "$REPO_ROOT" build -o "$DEMO_DIR/tool-server" ./examples/mcp-a2a-delegation/tool-server
go -C "$REPO_ROOT" build -o "$DEMO_DIR/client" ./examples/mcp-a2a-delegation/client

echo "[demo] starting omega server on :$SERVER_PORT (policy gate ON)"
"$DEMO_DIR/omega" server \
	--http-addr "127.0.0.1:$SERVER_PORT" \
	--trust-domain omega.local \
	--data-dir "$DEMO_DIR/server" \
	--policy-dir "$EXAMPLE_DIR/policies" \
	--enforce-token-exchange-policy \
	>"$DEMO_DIR/server.log" 2>&1 &
echo $! >"$DEMO_DIR/server.pid"

# Wait for the control plane.
for _ in $(seq 1 50); do
	if curl -fsS -o /dev/null "http://127.0.0.1:$SERVER_PORT/healthz" 2>/dev/null; then
		break
	fi
	sleep 0.1
done

echo "[demo] starting tool-server on :$TOOL_PORT"
"$DEMO_DIR/tool-server" \
	--addr "127.0.0.1:$TOOL_PORT" \
	--jwks-url "http://127.0.0.1:$SERVER_PORT/v1/jwt/bundle" \
	--audience "mcp://github-issue" \
	>"$DEMO_DIR/tool.log" 2>&1 &
echo $! >"$DEMO_DIR/tool.pid"

for _ in $(seq 1 50); do
	if curl -fsS -o /dev/null "http://127.0.0.1:$TOOL_PORT/healthz" 2>/dev/null; then
		break
	fi
	sleep 0.1
done

echo "[demo] running client (alice -> claude-code -> github-tool -> tool-server)"
"$DEMO_DIR/client" \
	--omega-url "http://127.0.0.1:$SERVER_PORT" \
	--tool-url  "http://127.0.0.1:$TOOL_PORT/tool/issues" \
	--human "spiffe://omega.local/humans/alice" \
	--coordinator "spiffe://omega.local/agents/claude-code" \
	--sub-agent "spiffe://omega.local/agents/claude-code/github-tool" \
	--tool-audience "mcp://github-issue" \
	| tee "$DEMO_DIR/client.out"

echo
echo "[demo] verifying the tool-server saw the full delegation chain"
expected_chain='"delegation_chain":["spiffe://omega.local/humans/alice","spiffe://omega.local/agents/claude-code","spiffe://omega.local/agents/claude-code/github-tool"]'
if ! grep -qF -- "$expected_chain" "$DEMO_DIR/client.out"; then
	echo "FAIL: tool-server response did not contain expected chain" >&2
	echo "want substring: $expected_chain" >&2
	exit 1
fi

echo
echo "[demo] verifying the audit log has 2 token.exchange allow rows rooted at alice"
audit=$(curl -fsS "http://127.0.0.1:$SERVER_PORT/v1/audit?since=0")
allow_count=$(printf '%s' "$audit" | grep -o '"kind":"token.exchange"[^}]*"decision":"allow"' | wc -l | tr -d ' ')
if [[ "$allow_count" -ne 2 ]]; then
	echo "FAIL: expected 2 token.exchange allow rows, got $allow_count" >&2
	echo "$audit" >&2
	exit 1
fi
if ! printf '%s' "$audit" | grep -q '"subject":"spiffe://omega.local/humans/alice"'; then
	echo "FAIL: no audit row carried alice as the chain root" >&2
	exit 1
fi

echo
echo "[demo] running negative case (service-only chain, no human root) -> expect 403"
svc="spiffe://omega.local/svc/web"
svc_tok=$(curl -fsS -X POST "http://127.0.0.1:$SERVER_PORT/v1/svid/jwt" \
	-H 'Content-Type: application/json' \
	-d "{\"spiffe_id\":\"$svc\",\"audience\":[\"omega-internal\"],\"ttl_seconds\":300}" \
	| sed -n 's/.*"token":"\([^"]*\)".*/\1/p')
deny_status=$(curl -s -o "$DEMO_DIR/deny.out" -w '%{http_code}' \
	-X POST "http://127.0.0.1:$SERVER_PORT/v1/token/exchange" \
	-H 'Content-Type: application/json' \
	-d "{\"grant_type\":\"urn:ietf:params:oauth:grant-type:token-exchange\",\
\"subject_token\":\"$svc_tok\",\"subject_token_type\":\"urn:ietf:params:oauth:token-type:jwt\",\
\"actor_token\":\"$svc_tok\",\"actor_token_type\":\"urn:ietf:params:oauth:token-type:jwt\",\
\"requested_spiffe_id\":\"$svc\",\"audience\":[\"omega-internal\"],\"ttl_seconds\":60}")
if [[ "$deny_status" != "403" ]]; then
	echo "FAIL: service-only exchange returned $deny_status, expected 403" >&2
	cat "$DEMO_DIR/deny.out" >&2
	exit 1
fi

echo
echo "[demo] success - 2-hop delegation reached the tool, policy gated the impostor"
