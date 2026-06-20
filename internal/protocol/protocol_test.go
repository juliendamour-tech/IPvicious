// Package protocol: round-trip tests for Encode / Decode with compression and encryption.
package protocol

import (
	"bytes"
	"strings"
	"testing"
)

func makeFrame(typ byte, streamID, seqNo uint32, data []byte) *Frame {
	return &Frame{Type: typ, StreamID: streamID, SeqNo: seqNo, Data: data}
}

func TestRoundTrip(t *testing.T) {
	cases := []struct {
		name string
		data []byte
	}{
		{name: "empty", data: nil},
		{name: "small_below_threshold", data: []byte("hello")},
		{
			name: "text_compresses_well",
			data: []byte(strings.Repeat("GET / HTTP/1.1\r\nHost: target\r\n\r\n", 20)),
		},
		{
			name: "binary_incompressible",
			data: func() []byte {
				b := make([]byte, 512)
				for i := range b {
					b[i] = byte(i*31 + 7)
				}
				return b
			}(),
		},
		{name: "max_text_payload", data: []byte(strings.Repeat("A", MaxData))},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			original := makeFrame(TypeData, 42, 7, tc.data)
			encoded, err := Encode(original)
			if err != nil {
				t.Fatalf("Encode: %v", err)
			}
			if len(encoded) != PayloadSize {
				t.Fatalf("Encode: want %d bytes, got %d", PayloadSize, len(encoded))
			}
			decoded, err := Decode(encoded)
			if err != nil {
				t.Fatalf("Decode: %v", err)
			}
			if decoded.Type != original.Type {
				t.Errorf("Type mismatch")
			}
			if decoded.StreamID != original.StreamID {
				t.Errorf("StreamID mismatch")
			}
			if decoded.SeqNo != original.SeqNo {
				t.Errorf("SeqNo mismatch")
			}
			if !bytes.Equal(decoded.Data, original.Data) {
				t.Errorf("Data mismatch: want %d bytes, got %d bytes",
					len(original.Data), len(decoded.Data))
			}
			if decoded.Flags&FlagCompressed != 0 {
				t.Errorf("FlagCompressed not cleared by Decode")
			}
		})
	}
}

func TestCompressionFires(t *testing.T) {
	payload := []byte(strings.Repeat("AAAAAAAAAA", 50))
	encoded, err := Encode(makeFrame(TypeData, 1, 1, payload))
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	if encoded[9]&FlagCompressed == 0 {
		t.Error("FlagCompressed expected for compressible payload")
	}
	decoded, err := Decode(encoded)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if !bytes.Equal(decoded.Data, payload) {
		t.Error("round-trip data mismatch after compression")
	}
}

func TestIncompressibleNotExpanded(t *testing.T) {
	payload := make([]byte, 200)
	for i := range payload {
		payload[i] = byte(i)
	}
	encoded, err := Encode(makeFrame(TypeCmd, 0, 0, payload))
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	decoded, err := Decode(encoded)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if !bytes.Equal(decoded.Data, payload) {
		t.Error("data mismatch for incompressible payload")
	}
}

func TestBadMagic(t *testing.T) {
	buf := make([]byte, PayloadSize)
	buf[0] = 0xFF
	_, err := Decode(buf)
	if err != ErrBadMagic {
		t.Errorf("expected ErrBadMagic, got %v", err)
	}
}

// ─── encryption tests ─────────────────────────────────────────────────────────

func TestEncryptionRoundTrip(t *testing.T) {
	aead, err := NewAEAD("s3cr3t-psk")
	if err != nil {
		t.Fatalf("NewAEAD: %v", err)
	}

	cases := []struct {
		name string
		data []byte
	}{
		{name: "empty", data: nil},
		{name: "small", data: []byte("hello encrypted world")},
		{name: "compressible", data: []byte(strings.Repeat("AAAA", 200))},
		{name: "max_encrypted", data: make([]byte, EncMaxData)},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := makeFrame(TypeData, 1, 2, tc.data)
			encoded, err := Encode(f, aead)
			if err != nil {
				t.Fatalf("Encode: %v", err)
			}
			if len(encoded) != PayloadSize {
				t.Fatalf("want %d bytes, got %d", PayloadSize, len(encoded))
			}
			// FlagEncrypted must be set in the wire bytes (plaintext header).
			if len(tc.data) > 0 {
				if encoded[9]&FlagEncrypted == 0 {
					t.Error("FlagEncrypted not set in encoded header")
				}
			}
			decoded, err := Decode(encoded, aead)
			if err != nil {
				t.Fatalf("Decode: %v", err)
			}
			if decoded.Flags&FlagEncrypted != 0 {
				t.Error("FlagEncrypted not cleared by Decode")
			}
			if !bytes.Equal(decoded.Data, tc.data) {
				t.Errorf("data mismatch: want %d bytes, got %d bytes",
					len(tc.data), len(decoded.Data))
			}
		})
	}
}

func TestEncryptionWrongPSK(t *testing.T) {
	aeadSender, _ := NewAEAD("correct-psk")
	aeadWrong, _ := NewAEAD("wrong-psk")

	encoded, err := Encode(makeFrame(TypeCmd, 0, 1, []byte("whoami")), aeadSender)
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	_, err = Decode(encoded, aeadWrong)
	if err != ErrDecryptFailed {
		t.Errorf("expected ErrDecryptFailed, got %v", err)
	}
}

func TestEncryptionNoPSKOnEncryptedFrame(t *testing.T) {
	aead, _ := NewAEAD("some-psk")
	encoded, err := Encode(makeFrame(TypeCmd, 0, 1, []byte("whoami")), aead)
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	// Decode without PSK — must fail, not silently produce garbage.
	_, err = Decode(encoded)
	if err != ErrDecryptFailed {
		t.Errorf("expected ErrDecryptFailed when no PSK provided, got %v", err)
	}
}

func TestEncryptionNoncesAreDifferent(t *testing.T) {
	aead, _ := NewAEAD("nonce-test")
	f := makeFrame(TypeData, 1, 1, []byte("payload"))

	enc1, _ := Encode(f, aead)
	enc2, _ := Encode(f, aead)

	// Nonces are in the Data field starting at byte 20; they must differ.
	if bytes.Equal(enc1[20:32], enc2[20:32]) {
		t.Error("two Encode calls produced the same nonce — crypto/rand may be broken")
	}
}

func TestEncryptCompressThenEncrypt(t *testing.T) {
	// Compressible data: compression runs first, then encryption.
	// Both FlagCompressed and FlagEncrypted must be set in the wire header so
	// Decode knows to decrypt first, then decompress.
	aead, _ := NewAEAD("combo-test")
	compressible := []byte(strings.Repeat("AAAAAAAAAA", 50))

	encoded, err := Encode(makeFrame(TypeData, 1, 1, compressible), aead)
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	wireFlags := encoded[9]
	if wireFlags&FlagEncrypted == 0 {
		t.Error("FlagEncrypted should be set")
	}
	if wireFlags&FlagCompressed == 0 {
		t.Error("FlagCompressed should be set (signals Decode to decompress after decrypting)")
	}
	decoded, err := Decode(encoded, aead)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if decoded.Flags&FlagEncrypted != 0 {
		t.Error("FlagEncrypted not cleared by Decode")
	}
	if decoded.Flags&FlagCompressed != 0 {
		t.Error("FlagCompressed not cleared by Decode")
	}
	if !bytes.Equal(decoded.Data, compressible) {
		t.Error("round-trip data mismatch")
	}
}
