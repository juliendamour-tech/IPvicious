// Package protocol – encrypt.go provides AES-256-GCM authenticated encryption
// for the tunnel frame Data field.
//
// When a PSK is configured, Encode applies:
//  1. Compression  (if beneficial, FlagCompressed)
//  2. Encryption   (always, FlagEncrypted)
//
// Decode reverses that in order: decrypt → decompress.
//
// Wire layout of an encrypted Data field:
//
//	[  nonce (12 B)  ][  ciphertext  ][  auth tag (16 B)  ]
//
// The nonce is generated fresh from crypto/rand for every frame, so nonce
// reuse is not possible even if sequence counters wrap.
//
// Key derivation: HMAC-SHA256(key="ipvicious-v1", data=psk) → 32-byte AES-256.
// This isolates the AES key from the raw PSK string and avoids length-extension
// attacks that would be possible if sha256(psk) were used directly.
package protocol

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"io"
)

const (
	// FlagEncrypted is set in the Flags byte when the Data field is AES-256-GCM
	// authenticated-encrypted.  Encryption is applied after compression
	// (compress-then-encrypt ordering).
	FlagEncrypted = byte(0x02)

	encNonceSize = 12 // standard GCM nonce length
	encTagSize   = 16 // AES-GCM authentication tag length

	// EncOverhead is the extra bytes added to the Data field by encryption:
	//   12 (nonce) + 16 (auth tag) = 28 bytes per frame.
	EncOverhead = encNonceSize + encTagSize

	// EncMaxData is the maximum plaintext Data bytes per encrypted frame.
	// len(frame.Data) must not exceed EncMaxData when a PSK is active.
	EncMaxData = MaxData - EncOverhead // 1180 - 28 = 1152 bytes
)

// ErrDecryptFailed is returned when AES-GCM authentication/decryption fails.
// This indicates either a wrong PSK, frame corruption, or an active injection
// attempt.  The caller should drop the frame silently.
var ErrDecryptFailed = errors.New("protocol: decryption failed (wrong PSK or tampered frame)")

// NewAEAD derives an AES-256-GCM cipher from a PSK string.
//
// Key derivation uses HMAC-SHA256 with a fixed info label so that the raw PSK
// is never used as an AES key directly:
//
//	key = HMAC-SHA256(key="ipvicious-v1", data=psk)   → 32 bytes
func NewAEAD(psk string) (cipher.AEAD, error) {
	mac := hmac.New(sha256.New, []byte("ipvicious-v1"))
	mac.Write([]byte(psk))
	key := mac.Sum(nil) // 32 bytes → AES-256
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

// sealData encrypts plaintext with a fresh random nonce and returns
// nonce || ciphertext || auth_tag  (len = len(plaintext) + EncOverhead).
func sealData(aead cipher.AEAD, plaintext []byte) ([]byte, error) {
	nonce := make([]byte, encNonceSize)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	// Seal appends ciphertext+tag to nonce, so the result is nonce||ct||tag.
	return aead.Seal(nonce, nonce, plaintext, nil), nil
}

// openData decrypts nonce || ciphertext || tag produced by sealData.
// Returns ErrDecryptFailed on authentication failure (wrong key, tampered data).
func openData(aead cipher.AEAD, data []byte) ([]byte, error) {
	if len(data) < encNonceSize+encTagSize {
		return nil, ErrDecryptFailed
	}
	nonce := data[:encNonceSize]
	ct := data[encNonceSize:]
	pt, err := aead.Open(nil, nonce, ct, nil)
	if err != nil {
		return nil, ErrDecryptFailed
	}
	return pt, nil
}
