import sys

content = b'''\
//go:build windows

// Package icmpv6 provides user-mode ICMPv6 Echo Request / Reply
// communication on Windows via the IP Helper API (iphlpapi.dll).
// No administrator privileges are required.
package icmpv6

import (
\t"fmt"
\t"net"
\t"syscall"
\t"unsafe"

\t"ipvicious/internal/crypto"
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
\t_modIPHLP *syscall.LazyDLL
\t_pCreate  *syscall.LazyProc
\t_pSend    *syscall.LazyProc
\t_pClose   *syscall.LazyProc
)

func init() {
\t_modIPHLP = syscall.NewLazyDLL(crypto.Dec(_eDLL))
\t_pCreate  = _modIPHLP.NewProc(crypto.Dec(_eCreate))
\t_pSend    = _modIPHLP.NewProc(crypto.Dec(_eSend))
\t_pClose   = _modIPHLP.NewProc(crypto.Dec(_eClose))
}

// sockAddrIn6 mirrors Windows sockaddr_in6 (28 bytes total).
type sockAddrIn6 struct {
\tFamily   uint16
\tPort     uint16
\tFlowInfo uint32
\tAddr     [16]byte
\tScopeID  uint32
}

// ipv6AddressEx mirrors Windows IPV6_ADDRESS_EX (28 bytes).
type ipv6AddressEx struct {
\tPort     uint16
\t_        [2]byte
\tFlowInfo uint32
\tAddr     [8]uint16
\tScopeID  uint32
}

// icmpv6EchoReply mirrors Windows ICMPV6_ECHO_REPLY (36 bytes).
// Reply data immediately follows this structure in the reply buffer.
type icmpv6EchoReply struct {
\tAddress   ipv6AddressEx
\tStatus    uint32
\tRoundTrip uint32
}

const replyHdrSize = int(unsafe.Sizeof(icmpv6EchoReply{}))

// ipToSockAddr converts a net.IP to sockAddrIn6.
func ipToSockAddr(ip net.IP) (sockAddrIn6, error) {
\tip6 := ip.To16()
\tif ip6 == nil {
\t\treturn sockAddrIn6{}, fmt.Errorf("not a valid IPv6 address: %v", ip)
\t}
\tvar s sockAddrIn6
\ts.Family = 23 // AF_INET6
\tcopy(s.Addr[:], ip6)
\treturn s, nil
}

// Sender wraps a Windows ICMP handle.
// Do not use concurrently from multiple goroutines.
type Sender struct {
\thandle uintptr
}

// NewSender opens a Windows ICMP handle (Icmp6CreateFile).
func NewSender() (*Sender, error) {
\th, _, err := _pCreate.Call()
\tif h == 0 {
\t\treturn nil, fmt.Errorf("Icmp6CreateFile: %w", err)
\t}
\treturn &Sender{handle: h}, nil
}

// Close releases the ICMP handle.
func (s *Sender) Close() {
\tif s.handle != 0 {
\t\t_pClose.Call(s.handle)
\t\ts.handle = 0
\t}
}

// SendRecv sends an ICMPv6 echo request to dstIP carrying payload and blocks
// until the echo reply arrives (or timeoutMs elapses).
// srcIP may be nil (OS picks source address from routing table).
// Returns the reply payload which has the same length as the request payload.
func (s *Sender) SendRecv(srcIP, dstIP net.IP, payload []byte, timeoutMs uint32) ([]byte, error) {
\tif len(payload) == 0 {
\t\treturn nil, fmt.Errorf("payload must not be empty")
\t}

\tvar srcAddr sockAddrIn6
\tsrcAddr.Family = 23 // AF_INET6 all-zeros = bind any
\tif srcIP != nil {
\t\ts6, err := ipToSockAddr(srcIP)
\t\tif err != nil {
\t\t\treturn nil, err
\t\t}
\t\tsrcAddr = s6
\t}

\tdstAddr, err := ipToSockAddr(dstIP)
\tif err != nil {
\t\treturn nil, err
\t}

\t// Reply buffer: ICMPV6_ECHO_REPLY header + request payload + 8-byte guard
\treplyBufLen := replyHdrSize + len(payload) + 8
\treplyBuf := make([]byte, replyBufLen)

\tret, _, lerr := _pSend.Call(
\t\ts.handle,
\t\t0, // Event = NULL (synchronous call)
\t\t0, // ApcRoutine = NULL
\t\t0, // ApcContext = NULL
\t\tuintptr(unsafe.Pointer(&srcAddr)),
\t\tuintptr(unsafe.Pointer(&dstAddr)),
\t\tuintptr(unsafe.Pointer(&payload[0])),
\t\tuintptr(uint16(len(payload))),
\t\t0, // RequestOptions = NULL
\t\tuintptr(unsafe.Pointer(&replyBuf[0])),
\t\tuintptr(replyBufLen),
\t\tuintptr(timeoutMs),
\t)

\tif ret == 0 {
\t\treturn nil, fmt.Errorf("Icmp6SendEcho2: %w", lerr)
\t}

\thdr := (*icmpv6EchoReply)(unsafe.Pointer(&replyBuf[0]))
\tif hdr.Status != 0 {
\t\treturn nil, fmt.Errorf("ICMP reply status 0x%X", hdr.Status)
\t}

\t// Reply payload starts at offset replyHdrSize.
\t// Its length equals len(payload) (same as the request).
\tend := replyHdrSize + len(payload)
\tif end > len(replyBuf) {
\t\treturn nil, fmt.Errorf("reply buffer underflow (hdr=%d payload=%d buf=%d)",
\t\t\treplyHdrSize, len(payload), len(replyBuf))
\t}
\tout := make([]byte, len(payload))
\tcopy(out, replyBuf[replyHdrSize:end])
\treturn out, nil
}
'''

with open('/Users/julien/Documents/IPvicious/internal/icmpv6/windows.go', 'wb') as f:
    f.write(content)
print('written ok, lines:', content.count(b'\n'))
