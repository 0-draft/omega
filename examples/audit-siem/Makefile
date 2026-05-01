.PHONY: demo down

DEMO_DIR := /tmp/omega-audit-siem-demo

# `make demo` boots a webhook receiver, an omega server wired to forward
# audit events to it, drives a few AuthZEN evaluations and verifies that
# both `allow` and `deny` decisions land at the receiver with a valid
# HMAC-SHA256 signature.
demo:
	@bash $(CURDIR)/run-demo.sh

down:
	@pkill -f 'omega server --http-addr 127.0.0.1:18098' 2>/dev/null || true
	@pkill -f '$(DEMO_DIR)/receiver' 2>/dev/null || true
	@rm -rf $(DEMO_DIR)
	@echo "[demo] torn down"
