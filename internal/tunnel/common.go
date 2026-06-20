// Package tunnel implements a multiplexed stream layer on top of the ICMPv6
// ping tunnel. Every logical connection (SOCKS5 relay, command execution, file
// transfer) is represented as a Stream identified by a 32-bit StreamID.
//
// Stream IDs:
//
//	0                    – reserved (control channel, TypeHello/Noop)
//	1 – 0x7FFFFFFF       – SOCKS5 relay streams (allocated by the server)
//	0x80000000           – dedicated command-execution stream
//	0x80000001           – dedicated file-transfer stream
package tunnel

import (
	"sync"
	"sync/atomic"
)

// Reserved stream IDs for non-SOCKS5 traffic.
const (
	StreamControl = uint32(0x00000000)
	StreamCmd     = uint32(0x80000000)
	StreamFile    = uint32(0x80000001)
)

// Stream is a bidirectional, buffered logical channel multiplexed over the
// ICMPv6 tunnel. Send / Recv operations are non-blocking channel ops so that
// the polling loop is never stalled by a slow consumer.
type Stream struct {
	// ID uniquely identifies this stream within a session.
	ID uint32

	// SendBuf carries frames waiting to be written into the next outbound
	// ICMPv6 echo request (agent) or echo reply (C2).
	SendBuf chan []byte

	// RecvBuf carries frames received from the remote peer that have not yet
	// been consumed by the application goroutine.
	RecvBuf chan []byte

	// Closed is closed (via close()) when the stream is terminated.
	Closed chan struct{}

	once sync.Once
}

// newStream allocates and initialises a Stream with the given ID.
func newStream(id uint32) *Stream {
	return &Stream{
		ID:      id,
		SendBuf: make(chan []byte, 128),
		RecvBuf: make(chan []byte, 128),
		Closed:  make(chan struct{}),
	}
}

// Close marks the stream as terminated. Idempotent.
func (s *Stream) Close() {
	s.once.Do(func() { close(s.Closed) })
}

// IsClosed returns true if Close has been called.
func (s *Stream) IsClosed() bool {
	select {
	case <-s.Closed:
		return true
	default:
		return false
	}
}

// TrySend enqueues data into SendBuf without blocking.
// Returns false if the buffer is full (backpressure; caller may retry).
func (s *Stream) TrySend(data []byte) bool {
	select {
	case s.SendBuf <- data:
		return true
	default:
		return false
	}
}

// TryRecv dequeues data from RecvBuf without blocking.
// Returns nil if no data is available.
func (s *Stream) TryRecv() []byte {
	select {
	case d := <-s.RecvBuf:
		return d
	default:
		return nil
	}
}

// ─── StreamTable ──────────────────────────────────────────────────────────────

// StreamTable is a thread-safe registry of all active streams in a session.
type StreamTable struct {
	mu      sync.RWMutex
	streams map[uint32]*Stream
	nextID  uint32 // atomic; starts at 1
}

// NewStreamTable returns an empty StreamTable.
func NewStreamTable() *StreamTable {
	return &StreamTable{
		streams: make(map[uint32]*Stream),
		nextID:  0,
	}
}

// Alloc creates a new stream with an automatically-assigned ID.
// IDs are allocated from 1 upward; the caller is responsible for not
// confusing them with the reserved IDs (StreamCmd, StreamFile).
func (t *StreamTable) Alloc() *Stream {
	id := atomic.AddUint32(&t.nextID, 1)
	s := newStream(id)
	t.mu.Lock()
	t.streams[id] = s
	t.mu.Unlock()
	return s
}

// AllocWithID registers a stream with a specific ID supplied by the remote
// peer (e.g. when the C2 server opens a stream and the agent must mirror it).
// If a stream with that ID already exists it is returned unchanged.
func (t *StreamTable) AllocWithID(id uint32) *Stream {
	t.mu.Lock()
	defer t.mu.Unlock()
	if existing, ok := t.streams[id]; ok {
		return existing
	}
	s := newStream(id)
	t.streams[id] = s
	return s
}

// Get returns the stream with the given ID, or nil if not present.
func (t *StreamTable) Get(id uint32) *Stream {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.streams[id]
}

// Remove deletes a stream from the table. The stream is not closed here;
// callers should call s.Close() separately if needed.
func (t *StreamTable) Remove(id uint32) {
	t.mu.Lock()
	delete(t.streams, id)
	t.mu.Unlock()
}

// Len returns the number of currently registered streams.
func (t *StreamTable) Len() int {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return len(t.streams)
}

// ForEach calls fn for every stream currently in the table (under read lock).
// fn must not call any StreamTable methods (deadlock risk).
func (t *StreamTable) ForEach(fn func(*Stream)) {
	t.mu.RLock()
	defer t.mu.RUnlock()
	for _, s := range t.streams {
		fn(s)
	}
}
