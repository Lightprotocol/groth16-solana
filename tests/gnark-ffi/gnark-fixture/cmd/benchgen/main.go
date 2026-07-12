// benchgen writes the deterministic Groth16 bench fixture sets into
// the directory given as the single argument. Invoked by
// tests/program/build.rs:
//
//	go run ./cmd/benchgen <out-dir>
package main

import (
	"fmt"
	"os"

	"github.com/lightprotocol/groth16-solana/tests/gnark-ffi/gnark-fixture/bench"
)

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: benchgen <out-dir>")
		os.Exit(2)
	}
	if err := bench.GenerateAll(os.Args[1]); err != nil {
		fmt.Fprintln(os.Stderr, "benchgen:", err)
		os.Exit(1)
	}
}
