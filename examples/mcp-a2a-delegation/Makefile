.PHONY: demo down

DEMO_DIR := /tmp/omega-mcp-a2a-demo

# `make demo` brings up an Omega control plane with the token-exchange
# AuthZEN gate enabled, a tool-server, and a client orchestrator that
# walks a 2-hop delegation chain (human -> coordinator -> sub-agent)
# and calls the tool. Asserts the chain reaches the tool and that a
# service-only exchange is denied by the Cedar policy.
demo:
	@bash $(CURDIR)/run-demo.sh

down:
	@pkill -f '$(DEMO_DIR)/omega' 2>/dev/null || true
	@pkill -f '$(DEMO_DIR)/tool-server' 2>/dev/null || true
	@rm -rf $(DEMO_DIR)
	@echo "[demo] torn down"
