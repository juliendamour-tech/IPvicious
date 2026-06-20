// strenc encrypts one or more strings with the same XOR key used by the
// crypto package and prints the resulting Go byte-slice literals.
//
// Usage:
//   go run ./tools/strenc "string1" "string2" ...
//
// The output can be pasted directly into Go source code.
package main

import (
	"fmt"
	"os"

	"ipvicious/internal/crypto"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: strenc <string> [string ...]")
		os.Exit(1)
	}
	for _, s := range os.Args[1:] {
		enc := crypto.Enc(s)
		fmt.Printf("// %q\n", s)
		fmt.Printf("var _ = []byte{")
		for i, b := range enc {
			if i > 0 { fmt.Print(", ") }
			fmt.Printf("0x%02X", b)
		}
		fmt.Println("}")
	}
}
