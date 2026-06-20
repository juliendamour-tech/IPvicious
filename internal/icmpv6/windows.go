//go:build windows

// Package icmpv6 provides user-mode ICMPv6 Echo Request / Reply
// communication on Windows via the IP Helper API (iphlpapi.dll).
// No administrator privileges are required.
package icmpv6

import (
	"fmt"
	"net"
	"syscall"
	"unsafe"

	"ipvicious/internal/crypto"
)

// Pre-encrypted API names (key {0xA7,0x3F,0x1E,0x92,0xC4,0x5D,0x8B,0x2A,0x6F,0xE3,0x47,0xB8,0xD1,0x09,0x7C,0x5E})
// "iphlpapi.dll"
var _eDLL = []byte{0xCE, 0x4F, 0x76, 0xFE, 0xB4, 0x3C, 0xFB, 0x43, 0x41, 0x87, 0x2B, 0xD4}

// "Icmp6CreateFile"
var _eCreate = []byte{0xEE, 0x5C, 0x73, 0xE2, 0xF2, 0x1E, 0xF9, 0x4F, 0x0E, 0x97, 0x22, 0xFE, 0xB8, 0x65, 0x19}

// "Icmp6SendEcho2"
var _eSend = []byte{0xEE, 0x5C, 0x73, 0xE2, 0xF2, 0x0E, 0xEE, 0x44, 0x0B, 0xA6, 0x24, 0xD0, 0xBE, 0x3B}

// "IcmpCloseHandle"
var _eClose = []byte{0xEE, 0x5C, 0x73, 0xE2, 0x87, 0x31, 0xE4, 0x59, 0x0A, 0xAB, 0x26, 0xD6, 0xB5, 0x65, 0x19}

// Lazy DLL / proc references - resolved at first use.
var (
	_modIPHLP *syscall.LazyDLL
	_pCreate  *syscall.LazyProc
	_pSend    *syscall.LazyProc
	_pClose   *syscall.LazyProc
)

func init() {
	_modIPHLP = syscall.NewLazyDLL(crypto.Dec(_eDLL))
	_pCreate = _modIPHLP.NewProc(crypto.Dec(_eCreate))
	_pSend = _modIPHLP.NewProc(crypto.Dec(_eSend))
	_pClose = _modIPHLP.NewProc(crypto.Dec(_eClose))
}

// sockAddrIn6 mirrors Windows sockaddr_in6 (28 bytes total).
type sockAddrIn6 struct {
	Family   uint16
	Port     uint16
	FlowInfo uint32
	Addr     [16]byte
	ScopeID  uint32
}

// ipv6AddressEx mirrors Windows IPV6_ADDRESS_EX (28 bytes).
type ipv6AddressEx struct {
	Port     uint16
	_        [2]byte
	FlowInfo uint32
	Addr     [8]uint16
	ScopeID  uint32
}

// icmpv6EchoReply mirrors Windows ICMPV6_ECHO_REPLY (36 bytes).
// Reply data immediately follows this structure in the reply buffer.
type icmpv6EchoReply struct {
	Address   ipv6AddressEx
	Status    uint32
	RoundTrip uint32
}

const replyHdrSize = int(unsafe.Sizeof(icmpv6EchoReply{}))

// ipToSockAddr converts a net.IP to sockAddrIn6.
func ipToSockAddr(ip net.IP) (sockAddrIn6, error) {
	ip6 := ip.To16()
	if ip6 == nil {
		return sockAddrIn6{}, fmt.Errorf("not a valid IPv6 address: %v", ip)
	}
	var s sockAddrIn6
	s.Family = 23 // AF_INET6
	copy(s.Addr[:], ip6)
	return s, nil
}

// Sender wraps a Windows ICMP handle.
// Do not use concurrently from multiple goroutines.
type Sender struct {
	handle uintptr
}

// NewSender opens a Windows ICMP handle (Icmp6CreateFile).
func NewSender() (*Sender, error) {
	h, _, err := _pCreate.Call()
	if h == 0 {
		return nil, fmt.Errorf("Icmp6CreateFile: %w", err)
	}
	return &Sender{handle: h}, nil
}

// Close releases the ICMP handle.
func (s *Sender) Close() {
	if s.handle != 0 {
		_pClose.Call(s.handle)
		s.handle = 0
	}
}

// SendRecv sends an ICMPv6 echo request to dstIP carrying payload and blocks
// until the echo reply arrives (or timeoutMs elapses).
// srcIP may be nil (OS picks source address from routing table).
// Returns the reply payload which has the same length as the request payload.
func (s *Sender) SendRecv(srcIP, dstIP net.IP, payload []byte, timeoutMs uint32) ([]byte, error) {
	if len(payload) == 0 {
		return nil, fmt.Errorf("payload must not be empty")
	}

	var srcAddr sockAddrIn6
	srcAddr.Family = 23 // AF_INET6 all-zeros = bind any
	if srcIP != nil {
		s6, err := ipToSockAddr(srcIP)
		if err != nil {
			return nil, err
		}
		srcAddr = s6
	}

	dstAddr, err := ipToSockAddr(dstIP)
	if err != nil {
		return nil, err
	}

	// Reply buffer: ICMPV6_ECHO_REPLY header + request payload + 8-byte guard
	replyBufLen := replyHdrSize + len(payload) + 8
	replyBuf := make([]byte, replyBufLen)

	ret, _, lerr := _pSend.Call(
		s.handle,
		0, // Event = NULL (synchronous call)
		0, // ApcRoutine = NULL
		0, // ApcContext = NULL
		uintptr(unsafe.Pointer(&srcAddr)),
		uintptr(unsafe.Pointer(&dstAddr)),
		uintptr(unsafe.Pointer(&payload[0])),
		uintptr(uint16(len(payload))),
		0, // RequestOptions = NULL
		uintptr(unsafe.Pointer(&replyBuf[0])),
		uintptr(replyBufLen),
		uintptr(timeoutMs),
	)

	if ret == 0 {
		return nil, fmt.Errorf("Icmp6SendEcho2: %w", lerr)
	}

	hdr := (*icmpv6EchoReply)(unsafe.Pointer(&replyBuf[0]))
	if hdr.Status != 0 {
		return nil, fmt.Errorf("ICMP reply status 0x%X", hdr.Status)
	}

	// Reply payload starts at offset replyHdrSize.
	// Its length equals len(payload) (same as the request).
	end := replyHdrSize + len(payload)
	if end > len(replyBuf) {
		return nil, fmt.Errorf("reply buffer underflow (hdr=%d payload=%d buf=%d)",
			replyHdrSize, len(payload), len(replyBuf))
	}
	out := make([]byte, len(payload))
	copy(out, replyBuf[replyHdrSize:end])
	return out, nil
}
