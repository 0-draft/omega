.PHONY: all build test lint tidy clean demo install run-server run-agent

BIN        := bin/omega
PKG        := ./...
GOFLAGS    := -trimpath
LDFLAGS    := -s -w -X github.com/kanywst/omega/internal/version.Version=$(shell git describe --tags --always --dirty 2>/dev/null || echo dev)

all: build

build:
	@mkdir -p bin
	go build $(GOFLAGS) -ldflags '$(LDFLAGS)' -o $(BIN) ./cmd/omega

install:
	go install $(GOFLAGS) -ldflags '$(LDFLAGS)' ./cmd/omega

test:
	go test -race -count=1 $(PKG)

lint:
	golangci-lint run

tidy:
	go mod tidy

clean:
	rm -rf bin dist .omega *.db *.db-journal

run-server: build
	$(BIN) server --data-dir .omega

run-agent: build
	$(BIN) agent --socket /tmp/omega-agent.sock

# Bring up control plane + agent + demo client in tmux-style background.
demo: build
	@./scripts/demo.sh
