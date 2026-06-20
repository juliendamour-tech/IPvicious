//go:build darwin

// Package icmpv6 – darwin.go provides user-mode ICMPv6 Echo Request / Reply
// communication on macOS via a raw socket.
//
// Requires root (sudo) because it opens a raw AF_INET6 socket.
//
// The ICMP echo identifier is derived from the process PID (masked to 16 bits)
// so that two agent processes on the same host produce distinct C2 keys.
package icmpv6

import (
	"fmt"
	"net"
	"os"
	"time"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv6"
)

// Sender sends ICMPv6 echo requests and receives the matching replies.
// Not safe for concurrent use from multiple goroutines.
type Sender struct {
	conn   *icmp.PacketConn
	echoID int // fixed for the lifetime of this Sender (PID & 0xFFFF)
	seq    int // incremented per send
}

// NewSender opens a raw ICMPv6 socket.
// Returns an error if the process lacks the required privilege.
func NewSender() (*Sender, error) {
	conn, err := icmp.ListenPacket("ip6:ipv6-icmp", "::")
	if err != nil {
		return nil, fmt.Errorf("open icmpv6 socket (requires root on macOS): %w", err)
	}
	return &Sender{
		conn:   conn,
		echoID: os.Getpid() & 0xFFFF,
	}, nil
}

// Close releases the ICMP socket.
func (s *Sender) Close() {
	s.conn.Close()
}

// SendRecv sends an ICMPv6 echo request to dstIP carrying payload, then blocks
// until the matching echo reply arrives or timeoutMs elapses.
// srcIP is ignored (the OS picks the source address from the routing table).
// Returns the reply payload, which has the same length as the request payload.
func (s *Sender) SendRecv(srcIP, dstIP net.IP, payload []byte, timeoutMs uint32) ([]byte, error) {
	s.seq = (s.seq + 1) & 0xFFFF

	msg := icmp.Message{
		Type: ipv6.ICMPTypeEchoRequest,
		Code: 0,
		Body: &icmp.Echo{
			ID:   s.echoID,
			Seq:  s.seq,
			Data: payload,
		},
	}
	// nil pseudo-header: the kernel fills in the checksum for raw IPv6 sockets.
	b, err := msg.Marshal(nil)
	if err != nil {
		return nil, fmt.Errorf("marshal echo request: %w", err)
	}

	// macOS raw IPv6 sockets require *net.IPAddr, not *net.UDPAddr.
	dst := &net.IPAddr{IP: dstIP}
	if _, err := s.conn.WriteTo(b, dst); err != nil {
		return nil, fmt.Errorf("send echo request: %w", err)
	}

	// Read replies until we find ours, or the deadline expires.
	deadline := time.Now().Add(time.Duration(timeoutMs) * time.Millisecond)
	if err := s.conn.SetReadDeadline(deadline); err != nil {
		return nil, fmt.Errorf("set read deadline: %w", err)
	}
	defer s.conn.SetReadDeadline(time.Time{}) // clear deadline on return

	buf := make([]byte, 4096)
	for {
		n, from, err := s.conn.ReadFrom(buf)
		if err != nil {
			return nil, fmt.Errorf("read echo reply: %w", err)
		}

		rmsg, err := icmp.ParseMessage(58, buf[:n]) // 58 = IPv6-ICMP
		if err != nil {
			continue
		}
		if rmsg.Type != ipv6.ICMPTypeEchoReply {
			continue
		}
		echo, ok := rmsg.Body.(*icmp.Echo)
		if !ok || echo.ID != s.echoID {
			continue // not our reply
		}
		if !addrMatchesIP(from, dstIP) {
			continue // reply from unexpected source
		}
		return echo.Data, nil
	}
}

// addrMatchesIP checks whether a net.Addr from ReadFrom corresponds to ip.
func addrMatchesIP(addr net.Addr, ip net.IP) bool {
	switch a := addr.(type) {
	case *net.UDPAddr:
		return a.IP.Equal(ip)
	case *net.IPAddr:
		return a.IP.Equal(ip)
	}
	return false
}
