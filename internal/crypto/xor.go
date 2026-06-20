// Package crypto provides XOR-based compile-time string obfuscation.
//
// All sensitive string literals (DLL names, API names, default addresses, log
// messages) must be stored in the source as pre-encrypted byte slices and
// decoded at runtime via Dec(). This prevents a simple `strings` or Ghidra
// scan from exposing plaintext strings in the compiled binary.
//
// To generate the encrypted form of a new string, run:
//
//	go run ./tools/strenc "your string"
//
// The XOR key is deliberately fragmented across four variables so that no
// contiguous 16-byte key sequence appears in the .rodata section.
package crypto

// xk0..xk3 are the four 4-byte segments of the XOR key.
// Each is a package-level var (not const) so the compiler stores them
// separately in the data section rather than adjacent in .rodata.
var (
	xk0 = [4]byte{0xA7, 0x3F, 0x1E, 0x92}
	xk1 = [4]byte{0xC4, 0x5D, 0x8B, 0x2A}
	xk2 = [4]byte{0x6F, 0xE3, 0x47, 0xB8}
	xk3 = [4]byte{0xD1, 0x09, 0x7C, 0x5E}
)

// key is the assembled 16-byte XOR key, built at init time.
var key [16]byte

func init() {
	copy(key[0:4], xk0[:])
	copy(key[4:8], xk1[:])
	copy(key[8:12], xk2[:])
	copy(key[12:16], xk3[:])
}

// Dec decrypts a XOR-encrypted byte slice and returns the plaintext string.
// The input must have been produced by Enc or the strenc tool using the same key.
func Dec(encrypted []byte) string {
	out := make([]byte, len(encrypted))
	for i, b := range encrypted {
		out[i] = b ^ key[i&15] // i & 15 == i % 16 (power-of-two fast path)
	}
	return string(out)
}

// Enc encrypts a plaintext string and returns its XOR-encoded byte slice.
// The result can be pasted directly into Go source as a []byte literal.
// This function is mainly used by the strenc tool; prefer pre-computed
// encrypted literals in production code to avoid plaintext source strings.
func Enc(s string) []byte {
	out := make([]byte, len(s))
	for i, c := range []byte(s) {
		out[i] = c ^ key[i&15]
	}
	return out
}

// Key returns a copy of the assembled XOR key (used by the strenc helper).
func Key() [16]byte { return key }
