// Package bench generates the Groth16 fixture sets consumed by the CU
// benchmark program in tests/program (see BENCHMARKS.md at the
// repo root).
//
// One circuit family, parameterized over the number of public inputs N
// and whether it forces a BSB22 commitment:
//
//   - N public inputs X[0..N)
//   - 1 private witness Y with the constraint sum(X_i * X_i) == Y
//   - withCommitment: one logderivlookup query at index Y (a private
//     wire), which makes gnark emit exactly ONE BSB22 commitment with
//     zero committed public wires — the same shape as LookupsCircuit
//     in the parent package
//
// DETERMINISM: gnark's Setup and Prove draw all randomness through
// the package-level `crypto/rand.Reader`. Before each variant we swap
// it for a ChaCha8 stream seeded from the variant name, so every run
// produces byte-identical keys and proofs. That lets the two
// independent cargo build graphs that consume these bytes — the SBF
// build of the bench program (bakes the vk) and the host build of its
// tests (embeds the proofs) — regenerate the same fixture set instead
// of sharing committed binaries. Determinism is asserted by
// TestGenerateIsDeterministic; if a gnark upgrade ever samples
// randomness concurrently the test fails.
//
// SECURITY NOTE: deterministic setup means PUBLICLY KNOWN toxic waste.
// These keys are for CU benchmarks only.
package bench

import (
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"io"
	"math/big"
	mathrand "math/rand/v2"
	"os"
	"path/filepath"
	"sync"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	groth16_bn254 "github.com/consensys/gnark/backend/groth16/bn254"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/std/lookup/logderivlookup"
)

// PublicInputCounts must stay in sync with the variants baked into
// tests/program (build.rs + src/lib.rs).
var PublicInputCounts = []int{1, 2, 4, 8}

// tableSize bounds the lookup index Y = sum(X_i^2). With X_i = i+1
// and N <= 8, Y <= 204 < 256.
const tableSize = 256

type BenchCircuit struct {
	withCommitment bool                // not a witness field (gnark ignores non-Variable fields)
	X              []frontend.Variable `gnark:",public"`
	Y              frontend.Variable
}

func (c *BenchCircuit) Define(api frontend.API) error {
	acc := frontend.Variable(0)
	for _, x := range c.X {
		acc = api.Add(acc, api.Mul(x, x))
	}
	api.AssertIsEqual(acc, c.Y)

	if c.withCommitment {
		table := logderivlookup.New(api)
		for i := 0; i < tableSize; i++ {
			table.Insert(i * i)
		}
		// Lookup over the PRIVATE wire Y so the commitment has no
		// committed public wires (NbPublicCommitted == 0), matching
		// the BSB22 shape the Rust verifier supports.
		results := table.Lookup(c.Y)
		api.AssertIsEqual(results[0], api.Mul(c.Y, c.Y))
	}
	return nil
}

// detReader is a mutex-guarded deterministic ChaCha8 byte stream that
// stands in for crypto/rand.Reader during Setup and Prove.
type detReader struct {
	mu  sync.Mutex
	rng *mathrand.ChaCha8
}

func newDetReader(label string) *detReader {
	seed := sha256.Sum256([]byte("groth16-solana bench fixture v1: " + label))
	return &detReader{rng: mathrand.NewChaCha8(seed)}
}

func (r *detReader) Read(p []byte) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.rng.Read(p)
}

// assignment fills X_i = i+1 and Y = sum(X_i^2).
func assignment(withCommitment bool, n int) (frontend.Circuit, []*big.Int) {
	xs := make([]frontend.Variable, n)
	pubs := make([]*big.Int, n)
	y := new(big.Int)
	for i := 0; i < n; i++ {
		x := big.NewInt(int64(i + 1))
		xs[i] = x
		pubs[i] = x
		y.Add(y, new(big.Int).Mul(x, x))
	}
	return &BenchCircuit{withCommitment: withCommitment, X: xs, Y: y}, pubs
}

// GenerateAll writes every fixture set into outDir:
//
//	{plain,bsb22}_{N}_vk.bin
//	{plain,bsb22}_{N}_proof_a.bin   (NOT negated; Rust tests negate A)
//	{plain,bsb22}_{N}_proof_b.bin
//	{plain,bsb22}_{N}_proof_c.bin
//	{plain,bsb22}_{N}_public_inputs.bin  (N*32 bytes, big-endian)
//	bsb22_{N}_commitment.bin, bsb22_{N}_pok.bin
func GenerateAll(outDir string) error {
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		return err
	}
	for _, withCommitment := range []bool{false, true} {
		for _, n := range PublicInputCounts {
			if err := generate(outDir, withCommitment, n); err != nil {
				return err
			}
		}
	}
	return nil
}

func generate(outDir string, withCommitment bool, n int) error {
	mode := "plain"
	if withCommitment {
		mode = "bsb22"
	}
	label := fmt.Sprintf("%s_%d", mode, n)

	// Per-variant deterministic randomness, independent of variant
	// iteration order. Restored on return so callers (tests) are not
	// left with a swapped global reader.
	prevReader := rand.Reader
	rand.Reader = newDetReader(label)
	defer func() { rand.Reader = prevReader }()

	shape := &BenchCircuit{withCommitment: withCommitment, X: make([]frontend.Variable, n)}
	cs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, shape)
	if err != nil {
		return fmt.Errorf("%s: compile: %w", label, err)
	}

	// Shape gates: plain has zero commitments; bsb22 has exactly one
	// with no committed public wires.
	commitments, ok := cs.GetCommitments().(constraint.Groth16Commitments)
	if !ok {
		return fmt.Errorf("%s: unexpected commitment type %T", label, cs.GetCommitments())
	}
	if withCommitment {
		if len(commitments) != 1 {
			return fmt.Errorf("%s: expected 1 commitment, got %d", label, len(commitments))
		}
		if commitments[0].NbPublicCommitted != 0 {
			return fmt.Errorf("%s: expected NbPublicCommitted == 0, got %d",
				label, commitments[0].NbPublicCommitted)
		}
	} else if len(commitments) != 0 {
		return fmt.Errorf("%s: expected 0 commitments, got %d", label, len(commitments))
	}

	// Deterministic setup: PUBLICLY KNOWN toxic waste, bench-only keys.
	pk, vk, err := groth16.Setup(cs)
	if err != nil {
		return fmt.Errorf("%s: setup: %w", label, err)
	}

	assign, pubs := assignment(withCommitment, n)
	w, err := frontend.NewWitness(assign, ecc.BN254.ScalarField())
	if err != nil {
		return fmt.Errorf("%s: witness: %w", label, err)
	}
	proof, err := groth16.Prove(cs, pk, w)
	if err != nil {
		return fmt.Errorf("%s: prove: %w", label, err)
	}
	pubW, err := w.Public()
	if err != nil {
		return fmt.Errorf("%s: public witness: %w", label, err)
	}
	if err := groth16.Verify(proof, vk, pubW); err != nil {
		return fmt.Errorf("%s: native verify: %w", label, err)
	}

	bnProof, ok := proof.(*groth16_bn254.Proof)
	if !ok {
		return fmt.Errorf("%s: unexpected proof type %T", label, proof)
	}
	vkBN, ok := vk.(*groth16_bn254.VerifyingKey)
	if !ok {
		return fmt.Errorf("%s: unexpected vk type %T", label, vk)
	}

	write := func(name string, data []byte) error {
		return os.WriteFile(filepath.Join(outDir, label+"_"+name+".bin"), data, 0o644)
	}

	vkFile, err := os.Create(filepath.Join(outDir, label+"_vk.bin"))
	if err != nil {
		return fmt.Errorf("%s: create vk: %w", label, err)
	}
	if _, err := vkBN.WriteRawTo(vkFile); err != nil {
		vkFile.Close()
		return fmt.Errorf("%s: write vk: %w", label, err)
	}
	if err := vkFile.Close(); err != nil {
		return fmt.Errorf("%s: close vk: %w", label, err)
	}

	ar := bnProof.Ar.RawBytes()
	bs := bnProof.Bs.RawBytes()
	krs := bnProof.Krs.RawBytes()
	if err := write("proof_a", ar[:]); err != nil {
		return err
	}
	if err := write("proof_b", bs[:128]); err != nil {
		return err
	}
	if err := write("proof_c", krs[:]); err != nil {
		return err
	}

	if withCommitment {
		if len(bnProof.Commitments) != 1 {
			return fmt.Errorf("%s: expected 1 proof commitment, got %d",
				label, len(bnProof.Commitments))
		}
		cmt := bnProof.Commitments[0].RawBytes()
		pok := bnProof.CommitmentPok.RawBytes()
		if err := write("commitment", cmt[:]); err != nil {
			return err
		}
		if err := write("pok", pok[:]); err != nil {
			return err
		}
	}

	pubBytes := make([]byte, 0, 32*n)
	for _, p := range pubs {
		pubBytes = append(pubBytes, p.FillBytes(make([]byte, 32))...)
	}
	return write("public_inputs", pubBytes)
}

// interface conformance for the crypto/rand.Reader swap
var _ io.Reader = (*detReader)(nil)
