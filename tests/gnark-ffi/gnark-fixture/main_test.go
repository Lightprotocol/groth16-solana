package main

// Smoke test: compile, set up, prove, and natively verify all three
// variants. This is the chain-of-trust anchor for the integration
// tests in the parent crate -- if gnark's own verifier rejects the
// proof here, no Rust port will succeed.
//
// Run with:  go test ./tests/gnark-ffi/gnark-fixture/

import (
	"fmt"
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr/hash_to_field"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
)

func TestVariantsCompileProveVerify(t *testing.T) {
	for _, v := range []int{1, 2, 3} {
		t.Run(fmt.Sprintf("variant_%d", v), func(t *testing.T) {
			runVariant(t, v)
		})
	}
}

func runVariant(t *testing.T, v int) {
	t.Helper()
	circuit, err := newCircuit(v)
	if err != nil {
		t.Fatalf("newCircuit: %v", err)
	}
	cs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, circuit)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}

	// Confirm task 1's empty-committed_wires invariant: every variant
	// must have exactly one commitment with no public-committed wires.
	commitments, ok := cs.GetCommitments().(constraint.Groth16Commitments)
	if !ok {
		t.Fatalf("unexpected commitment type %T", cs.GetCommitments())
	}
	if len(commitments) != 1 {
		t.Fatalf("expected 1 commitment, got %d: %+v", len(commitments), commitments)
	}
	if commitments[0].NbPublicCommitted != 0 {
		t.Fatalf("expected NbPublicCommitted == 0, got %d (PublicAndCommitmentCommitted=%v)",
			commitments[0].NbPublicCommitted, commitments[0].PublicAndCommitmentCommitted)
	}
	t.Logf("variant=%d nbConstraints=%d commitments=%+v", v, cs.GetNbConstraints(), commitments)

	pk, vk, err := groth16.Setup(cs)
	if err != nil {
		t.Fatalf("setup: %v", err)
	}
	x := big.NewInt(7)
	y := new(big.Int).Mul(x, x)
	assignment, err := newAssignment(v, x, y)
	if err != nil {
		t.Fatalf("newAssignment: %v", err)
	}
	w, err := frontend.NewWitness(assignment, ecc.BN254.ScalarField())
	if err != nil {
		t.Fatalf("witness: %v", err)
	}
	proof, err := groth16.Prove(cs, pk, w)
	if err != nil {
		t.Fatalf("prove: %v", err)
	}
	pubW, err := w.Public()
	if err != nil {
		t.Fatalf("pubW: %v", err)
	}
	if err := groth16.Verify(proof, vk, pubW); err != nil {
		t.Fatalf("native verify: %v", err)
	}
}

// The golden bytes for the lib-internal Rust unit tests
// (tests/gnark-ffi/test_fixtures.rs) come from the deterministic generator:
// `go run ./cmd/benchgen <dir>` (bsb22_1 fixture set), not from a
// test in this file — see the bench package for the seeding scheme.

// TestHashToFieldGoldenVectors prints the gnark BSB22 hash-to-field
// outputs for a few fixed messages so we can paste them into the
// Rust unit tests as golden vectors. The Rust impl in
// src/hash_to_field.rs must produce byte-identical output.
func TestHashToFieldGoldenVectors(t *testing.T) {
	cases := []struct {
		name string
		msg  []byte
	}{
		{"empty", []byte{}},
		{"abc", []byte("abc")},
		{"64-byte zero G1", make([]byte, 64)},
		{"64-byte sequential", func() []byte {
			b := make([]byte, 64)
			for i := range b {
				b[i] = byte(i)
			}
			return b
		}()},
	}
	for _, tc := range cases {
		h := hash_to_field.New([]byte("bsb22-commitment"))
		_, _ = h.Write(tc.msg)
		out := h.Sum(nil)
		t.Logf("hash_to_field bsb22-commitment(%s) = %x (len=%d)", tc.name, out, len(out))
	}
}
