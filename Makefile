.PHONY: all build test lint tidy clean demo install run-server run-agent

BIN        := bin/raftel
PKG        := ./...
GOFLAGS    := -trimpath
LDFLAGS    := -s -w -X github.com/kanywst/raftel/internal/version.Version=$(shell git describe --tags --always --dirty 2>/dev/null || echo dev)

all: build

build:
	@mkdir -p bin
	go build $(GOFLAGS) -ldflags '$(LDFLAGS)' -o $(BIN) ./cmd/raftel

install:
	go install $(GOFLAGS) -ldflags '$(LDFLAGS)' ./cmd/raftel

test:
	go test -race -count=1 $(PKG)

lint:
	golangci-lint run

tidy:
	go mod tidy

clean:
	rm -rf bin dist .raftel *.db *.db-journal

run-server: build
	$(BIN) server --data-dir .raftel

run-agent: build
	$(BIN) agent --socket /tmp/raftel-agent.sock

# Bring up control plane + agent + demo client in tmux-style background.
demo: build
	@./scripts/demo.sh
