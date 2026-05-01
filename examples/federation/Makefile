.PHONY: demo down

DEMO_DIR := /tmp/omega-federation-demo

# `make demo` brings up two federated Omega control planes (omega.alpha
# on :18088, omega.beta on :18089), one agent per side, and verifies that
# both agents serve the merged X.509 trust bundle map via the SPIFFE
# Workload API.
demo:
	@bash $(CURDIR)/run-demo.sh

down:
	@pkill -f 'omega server --http-addr 127.0.0.1:1808[89]' 2>/dev/null || true
	@pkill -f 'omega agent --socket $(DEMO_DIR)/' 2>/dev/null || true
	@rm -rf $(DEMO_DIR)
	@echo "[demo] torn down"
