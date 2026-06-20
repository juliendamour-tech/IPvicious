// Package protocol – transparent payload compression helpers.
//
// Compression is applied inside Encode / Decode automatically:
//   - Encode tries zlib on any payload >= compressMinLen bytes; uses the
//     compressed form only when it is strictly smaller than the original.
//   - Decode detects the FlagCompressed bit and decompresses transparently.
//
// Using compress/zlib (RFC 1950 = deflate + 2-byte header + 4-byte Adler32)
// from the Go standard library — no extra dependency on either platform.
//
// Typical gains over a poll interval:
//   - HTTP / JSON responses:  40–70 % smaller payload
//   - Shell command output:   30–60 % smaller
//   - Binary files:           ~0 % (compression disabled when not beneficial)
package protocol

import (
	"bytes"
	"compress/zlib"
	"fmt"
	"io"
)

// FlagCompressed is set in the Flags byte of a frame when the Data field
// has been zlib-compressed by Encode.  Decode clears this bit after
// decompression so callers never observe it.
const FlagCompressed = byte(0x01)

// compressMinLen is the minimum uncompressed payload length (bytes) at which
// compression is attempted. Compressing tiny payloads costs more CPU than it
// saves in bandwidth.
const compressMinLen = 64

// decompressMaxBytes is the hard cap on how many bytes zlibDecompress will
// produce.  Any legitimate payload is at most MaxData bytes before
// compression, so anything beyond MaxData after decompression is malformed.
// This prevents a "zip bomb" (tiny compressed frame that expands to GB of RAM).
const decompressMaxBytes = MaxData

// zlibCompress returns the zlib-compressed form of data.
// Returns an error if compression fails; the caller falls back to plaintext.
func zlibCompress(data []byte) ([]byte, error) {
	var buf bytes.Buffer
	// zlib.BestSpeed trades a small amount of ratio for lower CPU cost —
	// important on the agent side which may be running alongside other work.
	w, err := zlib.NewWriterLevel(&buf, zlib.BestSpeed)
	if err != nil {
		return nil, err
	}
	if _, err := w.Write(data); err != nil {
		w.Close()
		return nil, err
	}
	if err := w.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// zlibDecompress inflates a zlib-compressed payload.
//
// The output is capped at decompressMaxBytes (= MaxData).  If the
// decompressed data would exceed this limit, an error is returned and
// no further memory is allocated.  This prevents zip-bomb attacks where
// a tiny compressed frame expands to an unbounded amount of data.
func zlibDecompress(data []byte) ([]byte, error) {
	r, err := zlib.NewReader(bytes.NewReader(data))
	if err != nil {
		return nil, fmt.Errorf("zlib open: %w", err)
	}
	defer r.Close()

	// LimitReader caps read at decompressMaxBytes+1.  If we read exactly
	// decompressMaxBytes+1 bytes, the payload exceeded the limit.
	limited := io.LimitReader(r, int64(decompressMaxBytes)+1)
	out, err := io.ReadAll(limited)
	if err != nil {
		return nil, fmt.Errorf("zlib read: %w", err)
	}
	if len(out) > decompressMaxBytes {
		return nil, fmt.Errorf("zlib: decompressed size exceeds %d bytes (zip bomb protection)",
			decompressMaxBytes)
	}
	return out, nil
}
