.PHONY: demo down test-pg

DEMO_DIR := /tmp/omega-postgres-demo
PG_CONTAINER := omega-pg-demo
PG_PORT := 55433
PG_DSN := postgres://omega:omega@127.0.0.1:$(PG_PORT)/omega?sslmode=disable

# `make demo` starts a Postgres container, runs an Omega control plane
# wired to it, drives a couple of API calls, and shows the durable rows
# in audit_log so you can see the canonical chain landing in Postgres
# instead of SQLite.
demo:
	@bash $(CURDIR)/run-demo.sh

down:
	@pkill -f 'omega server --http-addr 127.0.0.1:18097' 2>/dev/null || true
	@docker rm -f $(PG_CONTAINER) 2>/dev/null || true
	@rm -rf $(DEMO_DIR)
	@echo "[demo] torn down"

# `make test-pg` runs the Postgres-backed unit tests against a transient
# container. CI uses the same env-var contract.
test-pg:
	@docker rm -f $(PG_CONTAINER) >/dev/null 2>&1 || true
	@docker run -d --name $(PG_CONTAINER) \
		-e POSTGRES_PASSWORD=omega -e POSTGRES_USER=omega -e POSTGRES_DB=omega \
		-p $(PG_PORT):5432 postgres:16-alpine >/dev/null
	@for i in $$(seq 1 60); do \
		if docker exec $(PG_CONTAINER) pg_isready -U omega -d omega 2>/dev/null | grep -q "accepting"; then break; fi; \
		sleep 0.5; \
	done
	@OMEGA_TEST_POSTGRES_DSN="$(PG_DSN)" \
		go -C $(CURDIR)/../.. test ./internal/server/storage/... -run Postgres -v
	@docker rm -f $(PG_CONTAINER) >/dev/null
