# CLAUDE.md — AI Assistant Context for IPvicious

This file provides context, conventions, and guidance for AI coding assistants
working on this codebase.

---

## Project purpose

IPvicious is a **proof-of-concept** red-team tool demonstrating a split-tunnel
VPN bypass via ICMPv6. A Windows agent (user-mode, no admin) tunnels arbitrary
data through ICMPv6 Echo Request/Reply to a Linux C2 server. The C2 exposes a
SOCKS5 proxy and an interactive operator REPL.

This is a security research / PoC project. All strings should remain in English.
There must be no French comments, variable names, or log messages in Go source.

---

## Module and build

```
module: ipvicious          (go.mod)
Go:     1.21+
Deps:   golang.org/x/net v0.24.0   (icmp package)
        golang.org/x/sys v0.19.0   (indirect, syscall helpers)
```

### Cross-compilation targets

| Binary | GOOS | GOARCH | Entrypoint |
|--------|------|--------|------------|
| `dist/agent.exe` | `windows` | `amd64` | `cmd/client` |
| `dist/c2server`  | `linux`   | `amd64` | `cmd/server` |

Every package that is platform-specific uses a `//go:build` tag on line 1:
- `//go:build windows` — agent-side packages (`icmpv6/windows.go`, `tunnel/client.go`, `agent/`)
- `//go:build linux`   — server-side packages (`icmpv6/linux.go`, `tunnel/server.go`, `socks5/`, `cli/`)
- No build tag         — shared packages (`protocol/`, `crypto/`, `tunnel/common.go`)

### Build commands

```bash
# Development check (both targets)
GOOS=linux   GOARCH=amd64 go build ./...
GOOS=windows GOARCH=amd64 go build ./...

# Lint (must be zero warnings)
staticcheck -checks='all' ./...

# Tests (protocol package only — other packages are platform-gated)
go test ./internal/protocol/ -v

# Production build
make                                          # standard, both binaries
make client-baked server-baked C2=<ipv6> PSK=<key>   # baked-in defaults
./build.sh --garble --c2 <ipv6> --psk <key>  # garble obfuscation
```

### Compile-time ldflag variables

Both `cmd/client/main.go` and `cmd/server/main.go` expose these `var` declarations
that can be overridden at link time with `-X main.<name>=<value>`:

| Variable | Default | Description |
|----------|---------|-------------|
| `defaultC2` | `::1` | C2 IPv6 address (client only) |
| `defaultPollMs` | `50` | Poll interval ms (client only) |
| `defaultSocksBase` | `1080` | First TCP port for per-agent SOCKS5 proxies (server only) |
| `defaultPSK` | `` | AES-256-GCM pre-shared key (both) |

---

## Package map

```
internal/crypto/xor.go
    Enc(s string) []byte        — encrypt a plaintext string → []byte literal
    Dec(enc []byte) string      — decrypt at runtime
    Key() [16]byte              — assembled from xk0..xk3 [4]byte vars in init()
    !! XOR key is fragmented across 4 package-level var declarations to resist
       simple static analysis. Never consolidate them into one var.

internal/protocol/messages.go
    PayloadSize = 1200          — fixed ICMPv6 payload size (bytes)
    HeaderSize  = 20            — magic(8)+type(1)+flags(1)+streamID(4)+seqNo(4)+dataLen(2)
    MaxData     = 1180          — max unencrypted/uncompressed data per frame
    Encode(f *Frame, aead ...cipher.AEAD) ([]byte, error)
    Decode(payload []byte, aead ...cipher.AEAD) (*Frame, error)
    !! aead is variadic for backward compatibility; pass t.aead from both tunnels.
    !! Encode order:  compress → encrypt
    !! Decode order:  decrypt  → decompress

internal/protocol/compress.go
    FlagCompressed = 0x01
    zlibCompress / zlibDecompress
    !! decompressMaxBytes = MaxData — hard cap against zip bombs (LimitReader)

internal/protocol/encrypt.go
    FlagEncrypted  = 0x02
    EncOverhead    = 28         — nonce(12) + tag(16)
    EncMaxData     = 1152       — MaxData - EncOverhead
    NewAEAD(psk string) (cipher.AEAD, error)
        key = HMAC-SHA256("ipvicious-v1", psk)  → 32-byte AES-256
    !! ErrDecryptFailed must be dropped silently by the server (no reply = no fingerprint)

internal/protocol/protocol_test.go
    13 tests: round-trip (5), compression (2), bad-magic (1), encryption (5)
    Run with: go test ./internal/protocol/ -v

internal/icmpv6/windows.go   (//go:build windows)
    Sender.SendRecv(src, dst net.IP, payload []byte, timeoutMs uint32) ([]byte, error)
    Uses Icmp6SendEcho2 from iphlpapi.dll — no admin required
    !! DLL name and all proc names are stored as pre-encrypted []byte literals

internal/icmpv6/linux.go     (//go:build linux)
    Listener.Read() (*Request, error)
    Listener.Reply(req *Request, payload []byte) error
    Uses icmp.ListenPacket("ip6:ipv6-icmp", "::") + ICMPFilter (type 128 only)
    !! Requires root or CAP_NET_RAW

internal/tunnel/common.go
    Stream      — send/recv chan []byte (cap 128 each), sync.Once close
    StreamTable — sync.RWMutex, atomic uint32 ID counter
    Reserved IDs: StreamControl=0x00000000, StreamCmd=0x80000000, StreamFile=0x80000001

internal/tunnel/client.go    (//go:build windows)
    ClientTunnel.SetPSK(psk string) error   — call before Run
    ClientTunnel.Run(stop <-chan struct{})   — blocking poll loop
    setPollCh chan uint32 (cap 1)            — inter-goroutine poll-interval signal
    !! ticker is replaced atomically in the Run select loop on setPollCh receive

internal/tunnel/server.go    (//go:build linux)
    ServerTunnel.SetPSK(psk string) error   — call before Run
    ServerTunnel.Agent(key string) *AgentEntry — lookup by "<ipv6>#<echoID>" key
    AgentEntry.Key string                   — "<ipv6_addr>#<echoID>", immutable
    AgentEntry.EchoID int                   — ICMP echo identifier (unique per process)
    AgentEntry.Session() AgentSession       — snapshot; protected by AgentEntry.mu RWMutex
    AgentSession.LastPoll / NextPoll        — updated on every received frame
    findOrCreate(from net.Addr, echoID int) — key = fmt.Sprintf("%s#%d", addr, echoID)
    agentsMu sync.RWMutex                  — protects agents map[string]*AgentEntry
    !! AgentEntry.mu must be held for ALL reads/writes of session fields
    !! ErrBadMagic AND ErrDecryptFailed frames must be dropped silently
    !! Multiple agents on the same host are distinguished by echoID (per-process unique)

internal/agent/agent.go      (//go:build windows)
    Agent.New(tun) wires all ClientTunnel callbacks
    fileWriters map[uint32]*fileWriter      — multi-chunk download state
    !! cmd.exe and /C stored as _eCmdExe / _eFlagC encrypted []byte literals

internal/agent/relay.go      (//go:build windows)
    relayStream(a *Agent, streamID, addrType, addr, port)
    !! If streams.Get(streamID) == nil, MUST send TypeStreamClose before returning
       (stream leak prevention)

internal/socks5/socks5.go    (//go:build linux)
    Proxy.Listen(addr string) error
    NO_AUTH only (RFC 1928 method 0x00), CONNECT only
    Allocates a tunnel stream per connection, bidirectional relay

internal/cli/repl.go         (//go:build linux)
    REPL.Run()
    promptStr = colBold+colGreen+"IPvicious"+colReset+colBold+"> "+colReset  (no-agent default)
    currentPromptLocked() string — returns "IPvicious[N]>" when agent N is active (holds mu)
    agentOrder []string          — insertion-order list of agent keys
    agentStates map[string]*agentState — per-agent download state + proxy map
    activeKey string             — currently selected agent key
    nextSocksPort int            — next auto-allocated SOCKS5 port (advances past manual ports too)
    asyncPrintf / asyncWrite — thread-safe output under mu (clears + reprints prompt)
    !! All output to the terminal MUST go through asyncPrintf or asyncWrite,
       never fmt.Print directly, to avoid interleaving with the prompt line.
    !! OnFileData routes to ALL agents (not just activeKey) so in-flight downloads
       are never interrupted by the operator switching agents.
```

---

## Wire protocol constants

```
Magic   = [8]byte{0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE}
TypeHello       = 0x01    TypeData        = 0x02
TypeStreamOpen  = 0x03    TypeStreamClose = 0x04
TypeCmd         = 0x05    TypeCmdOut      = 0x06
TypeFileGet     = 0x07    TypeFilePut     = 0x08   (NOTE: ACK is 0x0B not 0x07)
TypeFileData    = 0x09    TypeFileEnd     = 0x0A
TypeAck         = 0x0B    TypeError       = 0x0C
TypeNoop        = 0x0D    TypeSetPoll     = 0x0E

FlagCompressed  = 0x01    (Flags byte bit 0)
FlagEncrypted   = 0x02    (Flags byte bit 1)
```

Frame layout (bytes):
```
[0:8]   Magic
[8]     Type
[9]     Flags
[10:14] StreamID (big-endian uint32)
[14:18] SeqNo    (big-endian uint32)
[18:20] DataLen  (big-endian uint16)
[20:]   Data (DataLen bytes) + zero padding to PayloadSize
```

---

## Security-sensitive invariants

These must never be broken:

1. **No reply on bad magic**: `server.go handleRequest` must silently drop frames
   where `err == protocol.ErrBadMagic` — replying fingerprints the C2 server.

2. **No reply on decrypt failure**: Same silent drop for `protocol.ErrDecryptFailed`.

3. **Zip-bomb cap**: `zlibDecompress` uses `io.LimitReader(r, MaxData+1)` and
   returns error if `len(output) > MaxData`. Never use `io.ReadAll` on zlib.

4. **Session mutex**: All reads/writes to `ServerTunnel.session` must hold
   `sessionMu` (RLock for reads, Lock for writes). Currently: `handleRequest`
   (Lock), `Session()` (RLock), `SetPollInterval()` (Lock).

5. **Stream leak**: Three paths in the agent must clean up pre-allocated stream entries:
   - `relay.go`: send `TypeStreamClose` when `streams.Get` returns nil.
   - `agent.go handleStreamOpen`: call `streams.Remove(streamID)` + send `TypeStreamClose`
     when `resolveTarget` fails (stream was pre-allocated by `AllocWithID` in `dispatch`).
   - `relay.go relayStream`: call `streams.Remove(streamID)` + send `TypeStreamClose`
     when `net.Dial` fails (same pre-allocation reason).

6. **XOR key fragmentation**: The 16-byte XOR key in `crypto/xor.go` must stay
   split across `xk0`, `xk1`, `xk2`, `xk3` — never merge into a single literal.

7. **Encrypted API names**: All DLL/proc names in `icmpv6/windows.go` must remain
   as pre-encrypted `[]byte` literals decoded via `crypto.Dec()` at call time.

---

## Code style conventions

- **No French** in any source file (comments, strings, identifiers, log messages).
- **Build tags** go on line 1 (`//go:build windows`), blank line, then package declaration.
- **Package comments** follow the form `// Package <name> – <description>.`
- **Constants**: use CamelCase (`PayloadSize`, not `PAYLOAD_SIZE`) per Go conventions.
- **Staticcheck**: must pass `staticcheck -checks='all' ./...` with zero warnings.
- **`go vet`**: must be clean on both GOOS targets before committing.
- Avoid `fmt.Print` in goroutines that share the terminal with the REPL — always
  use `r.asyncPrintf` / `r.infof` / `r.errf`.

---

## Adding a new message type

1. Add `TypeXxx = byte(0xNN)` constant to `internal/protocol/messages.go`.
2. Add encoder/decoder helpers if the payload has structure (see `EncodeSetPoll`).
3. Handle the new type in `ClientTunnel.dispatch()` (`tunnel/client.go`).
4. Handle the new type in `ServerTunnel.handleRequest()` (`tunnel/server.go`).
5. Add a public method to `ServerTunnel` to enqueue the frame (e.g. `SendXxx`).
6. Add the type to the message table in `README.md`.
7. Add a test in `protocol_test.go` if the payload has a non-trivial encoding.

---

## Adding a new REPL command

1. Add a `case "cmd_name":` branch in `REPL.dispatch()` in `cli/repl.go`.
2. Implement `(r *REPL) cmdXxx(...)` — use `r.infof` for output, `r.errf` for errors.
3. Add the command to the `help` string in `cmdHelp()`.
4. Document in the REPL section of `README.md`.

---

## Testing approach

Only `internal/protocol` has unit tests (platform-independent, pure Go).
Platform-specific packages (`icmpv6`, `tunnel`, `agent`, `socks5`, `cli`) require
a real Windows/Linux environment and a live ICMPv6 network, so they have no unit
tests.

To run the test suite:
```bash
go test ./internal/protocol/ -v         # 13 tests, must all pass
go test ./internal/protocol/ -race      # not supported (CGO needed for cross-compile)
staticcheck -checks='all' ./...         # 0 warnings expected
```

---

## File creation notes (for AI tools)

When creating or editing Go source files in this repo:
- Always verify with `go build ./...` on both GOOS targets after edits.
- Never use `io.ReadAll` on a compressed or untrusted `io.Reader` — use `io.LimitReader`.
- The `Encode`/`Decode` variadic `aead` parameter must be passed as `t.aead` from
  both `ClientTunnel.poll()` and `ServerTunnel.handleRequest()` / `sendNoop()`.
- When adding string literals that will appear in the binary (paths, API names,
  log prefixes), consider whether they should be XOR-encrypted. Use
  `go run ./tools/strenc "<string>"` to generate the encrypted literal.
