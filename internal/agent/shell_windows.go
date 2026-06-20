//go:build windows

// shell_windows.go provides the Windows-specific shell invocation for the
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

// "cmd.exe"
var _eCmdExe = []byte{0xC4, 0x52, 0x7A, 0xBC, 0xA1, 0x25, 0xEE}

// "/C"
var _eFlagC = []byte{0x88, 0x7C}

// runCommand executes cmd via cmd.exe /C and returns combined stdout+stderr.
func runCommand(cmd string) ([]byte, error) {
	shell := crypto.Dec(_eCmdExe) // "cmd.exe"
	flag := crypto.Dec(_eFlagC)   // "/C"

	c := exec.Command(shell, flag, cmd)
	var buf bytes.Buffer
	c.Stdout = &buf
	c.Stderr = &buf
	return buf.Bytes(), c.Run()
}
