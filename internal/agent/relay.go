//go:build windows

// Package agent – relay.go provides SOCKS5 stream relay between the tunnel and a TCP target.
//
// relayStream connects to the target, then bidirectionally pipes data between
// the TCP connection and the tunnel Stream buffers until either side closes.
package agent

import (
	"fmt"
	"io"
	"log"
	"net"

	"ipvicious/internal/protocol"
	"ipvicious/internal/tunnel"
)

// relayStream dials target, then forwards data between the TCP connection and
// the tunnel stream identified by streamID.
func (a *Agent) relayStream(streamID uint32, target string) {
	// Establish TCP connection to the IPv4 target (uses host routing = VPN).
	conn, err := net.Dial("tcp", target)
	if err != nil {
		log.Printf("[relay] stream %d dial %s failed: %v", streamID, target, err)
		a.tun.Streams().Remove(streamID) // clean up pre-allocated stream entry
		a.enqueue(protocol.TypeStreamClose, streamID, 0, nil)
		return
	}
	defer conn.Close()

	// Fetch the Stream from the table (pre-registered by ClientTunnel.dispatch).
	s := a.tun.Streams().Get(streamID)
	if s == nil {
		// The stream entry was never registered or was already removed.
		// Notify the server so it can release its own stream allocation.
		log.Printf("[relay] stream %d: no tunnel stream entry", streamID)
		a.enqueue(protocol.TypeStreamClose, streamID, 0, nil)
		return
	}
	defer func() {
		s.Close()
		a.tun.Streams().Remove(streamID)
		a.enqueue(protocol.TypeStreamClose, streamID, 0, nil)
	}()

	// tunnel → TCP (data arriving from C2 goes to the TCP target)
	go func() {
		for {
			select {
			case <-s.Closed:
				conn.Close()
				return
			case data := <-s.RecvBuf:
				if _, err := conn.Write(data); err != nil {
					return
				}
			}
		}
	}()

	// TCP → tunnel (data from the TCP target goes back to C2)
	buf := make([]byte, protocol.MaxData)
	for {
		n, readErr := conn.Read(buf)
		if n > 0 {
			chunk := make([]byte, n)
			copy(chunk, buf[:n])
			a.enqueue(protocol.TypeData, streamID, 0, chunk)
		}
		if readErr != nil {
			if readErr != io.EOF {
				log.Printf("[relay] stream %d read error: %v", streamID, readErr)
			}
			return
		}
		if s.IsClosed() {
			return
		}
	}
}

// resolveTarget converts a SOCKS5-style address (type + raw bytes + port) into
// a "host:port" string suitable for net.Dial.
func resolveTarget(addrType byte, addr []byte, port uint16) (string, error) {
	var host string
	switch addrType {
	case protocol.AddrIPv4:
		if len(addr) != 4 {
			return "", fmt.Errorf("IPv4 address must be 4 bytes, got %d", len(addr))
		}
		host = net.IP(addr).String()
	case protocol.AddrIPv6:
		if len(addr) != 16 {
			return "", fmt.Errorf("IPv6 address must be 16 bytes, got %d", len(addr))
		}
		host = fmt.Sprintf("[%s]", net.IP(addr).String())
	case protocol.AddrDomain:
		host = string(addr)
	default:
		return "", fmt.Errorf("unknown address type 0x%02X", addrType)
	}
	return fmt.Sprintf("%s:%d", host, port), nil
}

// Ensure StreamTable's channel-based helpers compile (import validation).
var _ = tunnel.StreamControl
