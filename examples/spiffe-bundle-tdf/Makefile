.PHONY: demo down

DEMO_DIR := /tmp/omega-spiffe-bundle-tdf-demo

# `make demo` boots an omega server and runs a tiny go-spiffe v2
# consumer that fetches GET /v1/spiffe-bundle and parses it through
# `spiffebundle.Read`. Asserts the parsed bundle has both X.509 and
# JWT authorities and surfaces the sequence + refresh_hint envelope
# fields. Proves the TDF document is real SPIFFE-conformant material.
demo:
	@bash $(CURDIR)/run-demo.sh

down:
	@-[ -f $(DEMO_DIR)/server.pid ] && kill $$(cat $(DEMO_DIR)/server.pid) 2>/dev/null || true
	@rm -rf $(DEMO_DIR)
	@echo "[demo] torn down"
