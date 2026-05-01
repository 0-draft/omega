.PHONY: demo down

DEMO_DIR := /tmp/omega-postgres-ha-demo
PG_CONTAINER := omega-pg-ha-demo
A_PORT := 18101
B_PORT := 18102

# `make demo` boots Postgres + two omega replicas wired to the same
# advisory-lock key, kills the leader, and shows the follower
# promoting and accepting writes that the old leader was rejecting.
demo:
	@bash $(CURDIR)/run-demo.sh

down:
	@pkill -f 'omega server --http-addr 127.0.0.1:$(A_PORT)' 2>/dev/null || true
	@pkill -f 'omega server --http-addr 127.0.0.1:$(B_PORT)' 2>/dev/null || true
	@docker rm -f $(PG_CONTAINER) 2>/dev/null || true
	@rm -rf $(DEMO_DIR)
	@echo "[demo] torn down"
