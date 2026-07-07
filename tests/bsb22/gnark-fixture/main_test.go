package main

// Smoke test: compile, set up, prove, and natively verify all three
// variants. This is the chain-of-trust anchor for the integration
// tests in the parent crate -- if gnark's own verifier rejects the
// proof here, no Rust port will succeed.
//
// Run with:  go test ./tests/bsb22/gnark-fixture/

import (
	"fmt"
	"math/big"
	"os"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr/hash_to_field"
	"github.com/consensys/gnark/backend/groth16"
	groth16_bn254 "github.com/consensys/gnark/backend/groth16/bn254"
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

// castProofForFixture extracts (Ar, Bs, Krs, Commitments[0],
// CommitmentPok) raw bytes from a *groth16.Proof. Mirrors what
// main.go's Prove cgo entry does, but returns Go []byte slices for
// use in test logging.
func castProofForFixture(t *testing.T, proof groth16.Proof) [][]byte {
	t.Helper()
	bnProof, ok := proof.(*groth16_bn254.Proof)
	if !ok {
		t.Fatalf("unexpected proof type %T", proof)
	}
	if len(bnProof.Commitments) != 1 {
		t.Fatalf("expected 1 commitment, got %d", len(bnProof.Commitments))
	}
	ar := bnProof.Ar.RawBytes()
	bs := bnProof.Bs.RawBytes()
	krs := bnProof.Krs.RawBytes()
	cmt := bnProof.Commitments[0].RawBytes()
	pok := bnProof.CommitmentPok.RawBytes()
	return [][]byte{ar[:], bs[:128], krs[:], cmt[:], pok[:]}
}

// TestDumpFullFixture writes a matching (vk.bin, proof bytes,
// public input) tuple for variant 1 with X=7 so we can bake the
// triple into the lib-internal end-to-end unit test (task 8).
// gnark setup is non-deterministic so vk and proof MUST come from
// the same Setup call.
func TestDumpFullFixture(t *testing.T) {
	circuit, err := newCircuit(1)
	if err != nil {
		t.Fatal(err)
	}
	cs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, circuit)
	if err != nil {
		t.Fatal(err)
	}
	pk, vk, err := groth16.Setup(cs)
	if err != nil {
		t.Fatal(err)
	}

	dir := t.TempDir()
	if err := writeVerifyingKey(vk, dir+"/vk.bin"); err != nil {
		t.Fatal(err)
	}
	vkBytes, err := os.ReadFile(dir + "/vk.bin")
	if err != nil {
		t.Fatal(err)
	}

	x := big.NewInt(7)
	y := new(big.Int).Mul(x, x)
	assignment, err := newAssignment(1, x, y)
	if err != nil {
		t.Fatal(err)
	}
	w, err := frontend.NewWitness(assignment, ecc.BN254.ScalarField())
	if err != nil {
		t.Fatal(err)
	}
	proof, err := groth16.Prove(cs, pk, w)
	if err != nil {
		t.Fatal(err)
	}
	pubW, err := w.Public()
	if err != nil {
		t.Fatal(err)
	}
	if err := groth16.Verify(proof, vk, pubW); err != nil {
		t.Fatal(err)
	}

	// Cast to BN254 concrete type to access RawBytes() on each
	// element directly, the same way main.go's Prove cgo entry does.
	bnProof := castProofForFixture(t, proof)
	ar := bnProof[0]
	bs := bnProof[1]
	krs := bnProof[2]
	cmt := bnProof[3]
	pok := bnProof[4]
	xBytes := x.FillBytes(make([]byte, 32))

	t.Logf("VK_HEX            (%d bytes): %x", len(vkBytes), vkBytes)
	t.Logf("PROOF_A_HEX       (64 bytes): %x", ar)
	t.Logf("PROOF_B_HEX       (128 bytes): %x", bs)
	t.Logf("PROOF_C_HEX       (64 bytes): %x", krs)
	t.Logf("COMMITMENT_HEX    (64 bytes): %x", cmt)
	t.Logf("POK_HEX           (64 bytes): %x", pok)
	t.Logf("PUBLIC_INPUT_HEX  (32 bytes): %x", xBytes)
}

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
