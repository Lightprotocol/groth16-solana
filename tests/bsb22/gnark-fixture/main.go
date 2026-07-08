// Package main: gnark BN254 Groth16 fixture for the BSB22 commitment
// integration tests in the parent crate.
//
// Three circuit variants exercise 1, 2, and 3 logderivlookup queries.
// All three produce exactly ONE BSB22 commitment (gnark's multicommit
// package merges every deferred commit callback into a single
// api.Commit() at finalization), and ZERO committed_wires (the lookup
// queries are over the private witness Y, never the public input X).
// The on-chain verifier therefore needs to hash only the 64-byte
// commitment for the BSB22 hash-to-field step.
//
// SECURITY NOTE: gnark's groth16.Setup is unsafe -- fresh tau, no
// ceremony. The keys this fixture produces are sample bytes only and
// must not be used for anything that has value attached to it.
//
// C ABI:
//
//	Setup(variant, outDir)        -> nil | error string
//	Prove(variant, xDecimal, dir) -> *C_ProveResult (caller frees)
//	NativeVerify(variant, xDec, dir) -> nil | error string
//	FreeProveResult(p)
//	FreeString(s)
//
// The C_ProveResult struct contains every byte the on-chain BSB22
// verifier needs:
//
//	proof_a            G1 uncompressed BE         (64 bytes)  // NOT negated
//	proof_b            G2 uncompressed BE         (128 bytes)
//	proof_c            G1 uncompressed BE         (64 bytes)
//	commitment         G1 uncompressed BE         (64 bytes)  // proof.Commitments[0]
//	commitment_pok     G1 uncompressed BE         (64 bytes)  // proof.CommitmentPok
//	public_input       fr.Element BE              (32 bytes)  // X
package main

/*
#include <stdlib.h>
#include <string.h>

typedef struct {
    unsigned char proof_a[64];
    unsigned char proof_b[128];
    unsigned char proof_c[64];
    unsigned char commitment[64];
    unsigned char commitment_pok[64];
    unsigned char public_input[32];
    char *error;
} C_ProveResult;
*/
import "C"

import (
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"sync"
	"unsafe"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	groth16_bn254 "github.com/consensys/gnark/backend/groth16/bn254"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/std/lookup/logderivlookup"
)

// =============================================================================
// Circuits
// =============================================================================

// LookupsCircuit is a single parameterized circuit shape shared by all
// three variants. The variant is the field `nbLookups` (number of
// lookup queries); gnark's schema walker ignores non-Variable fields,
// so `nbLookups` is baked into the circuit at Compile time without
// becoming a witness:
//
//   - 1 user public input (X)
//   - 1 private witness (Y)
//   - 1 R1CS constraint (X*X == Y) so the circuit isn't degenerate
//   - A 64-entry logderivlookup table of squares (entry[i] = i*i)
//   - nbLookups independent lookups, each at index Y+k for k in
//     0..nbLookups-1, each bound by AssertIsEqual(result, (Y+k) * (Y+k))
//
// All three variants share the same public-input shape, so the same
// witness assignment (X = 7, Y = 49) works across them. With X = 7 the
// indices are 49, 50, 51 -- all in range for a 64-entry table.
//
// The lookup queries (Y + k) are computed from the PRIVATE witness Y,
// not from the public input X, so vk.PublicAndCommitmentCommitted[0]
// is empty for every variant. The BSB22 hash preimage on the verifier
// side is therefore just the 64-byte commitment.

const lookupTableSize = 64

func defineLookups(api frontend.API, X, Y frontend.Variable, nbLookups int) error {
	// Trivial constraint so the circuit is non-degenerate.
	api.AssertIsEqual(api.Mul(X, X), Y)

	// 64-entry table of squares: 0, 1, 4, 9, ..., 3969.
	table := logderivlookup.New(api)
	for i := 0; i < lookupTableSize; i++ {
		table.Insert(i * i)
	}

	// nbLookups independent lookups at indices Y, Y+1, ...,
	// Y+(nbLookups-1). Each result is asserted to equal idx*idx,
	// which both keeps the result wire allocated (so the optimizer
	// doesn't drop it) and gives the witness solver a unique value
	// to assign.
	for k := 0; k < nbLookups; k++ {
		var idx frontend.Variable
		if k == 0 {
			idx = Y
		} else {
			idx = api.Add(Y, k)
		}
		results := table.Lookup(idx)
		api.AssertIsEqual(results[0], api.Mul(idx, idx))
	}
	return nil
}

type LookupsCircuit struct {
	nbLookups int               // number of lookup queries; not a witness field (gnark ignores non-Variable fields)
	X         frontend.Variable `gnark:",public"`
	Y         frontend.Variable
}

func (c *LookupsCircuit) Define(api frontend.API) error {
	return defineLookups(api, c.X, c.Y, c.nbLookups)
}

func newCircuit(variant int) (frontend.Circuit, error) {
	if variant < 1 || variant > 3 {
		return nil, fmt.Errorf("unknown variant %d (must be 1, 2, or 3)", variant)
	}
	return &LookupsCircuit{nbLookups: variant}, nil
}

func newAssignment(variant int, x, y *big.Int) (frontend.Circuit, error) {
	if variant < 1 || variant > 3 {
		return nil, fmt.Errorf("unknown variant %d (must be 1, 2, or 3)", variant)
	}
	return &LookupsCircuit{nbLookups: variant, X: x, Y: y}, nil
}

// =============================================================================
// Constraint-system cache only. Compiling a circuit is deterministic
// and reusable across calls within the same process, so caching `cs`
// is safe and saves wall-clock. Proving keys and verifying keys are
// NOT cached: every Setup call writes fresh keys to a caller-provided
// directory, and every Prove / NativeVerify call loads them from
// disk. This keeps parallel Rust integration tests honest -- two
// tests using different tempdirs cannot accidentally cross-pollinate
// each other's keys via in-memory state.
// =============================================================================

var (
	csCacheMu sync.RWMutex
	csCache   = map[int]constraint.ConstraintSystem{}
)

func compile(variant int) (constraint.ConstraintSystem, error) {
	csCacheMu.RLock()
	if cs, ok := csCache[variant]; ok {
		csCacheMu.RUnlock()
		return cs, nil
	}
	csCacheMu.RUnlock()

	csCacheMu.Lock()
	defer csCacheMu.Unlock()
	if cs, ok := csCache[variant]; ok {
		return cs, nil
	}
	circuit, err := newCircuit(variant)
	if err != nil {
		return nil, err
	}
	cs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, circuit)
	if err != nil {
		return nil, fmt.Errorf("compile variant %d: %w", variant, err)
	}
	csCache[variant] = cs
	return cs, nil
}

func writeProvingKey(pk groth16.ProvingKey, path string) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	if _, err := pk.WriteTo(f); err != nil {
		return fmt.Errorf("pk WriteTo: %w", err)
	}
	return nil
}

func writeVerifyingKey(vk groth16.VerifyingKey, path string) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	vkBN, ok := vk.(*groth16_bn254.VerifyingKey)
	if !ok {
		return fmt.Errorf("unexpected vk type %T", vk)
	}
	if _, err := vkBN.WriteRawTo(f); err != nil {
		return fmt.Errorf("vk WriteRawTo: %w", err)
	}
	return nil
}

// loadKeys reads pk_{variant}.bin and vk_{variant}.bin from `dir` and
// returns them as fresh in-memory objects. No caching -- each call is
// independent so parallel tests cannot interfere.
func loadKeys(variant int, dir string) (groth16.ProvingKey, groth16.VerifyingKey, error) {
	pk := groth16.NewProvingKey(ecc.BN254)
	pkF, err := os.Open(filepath.Join(dir, fmt.Sprintf("pk_%d.bin", variant)))
	if err != nil {
		return nil, nil, fmt.Errorf("open pk: %w", err)
	}
	defer pkF.Close()
	if _, err := pk.ReadFrom(pkF); err != nil {
		return nil, nil, fmt.Errorf("read pk: %w", err)
	}

	vk := groth16.NewVerifyingKey(ecc.BN254)
	vkF, err := os.Open(filepath.Join(dir, fmt.Sprintf("vk_%d.bin", variant)))
	if err != nil {
		return nil, nil, fmt.Errorf("open vk: %w", err)
	}
	defer vkF.Close()
	if _, err := vk.ReadFrom(vkF); err != nil {
		return nil, nil, fmt.Errorf("read vk: %w", err)
	}
	return pk, vk, nil
}

// =============================================================================
// cgo exports
// =============================================================================

//export Setup
func Setup(variant C.int, outDir *C.char) *C.char {
	v := int(variant)
	dir := C.GoString(outDir)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return C.CString(fmt.Sprintf("mkdir %s: %v", dir, err))
	}
	cs, err := compile(v)
	if err != nil {
		return C.CString(err.Error())
	}

	// Print the CommitmentInfo so the Rust integration test (and
	// task 1's empty-committed_wires verification) can confirm
	// PublicAndCommitmentCommitted is empty for every variant.
	if commitments, ok := cs.GetCommitments().(constraint.Groth16Commitments); ok {
		fmt.Fprintf(os.Stderr, "gnark-fixture variant=%d commitments=%+v\n", v, commitments)
	}

	// SECURITY: gnark's UNSAFE Setup -- fresh tau, no ceremony.
	pk, vk, err := groth16.Setup(cs)
	if err != nil {
		return C.CString(fmt.Sprintf("setup: %v", err))
	}
	if err := writeProvingKey(pk, filepath.Join(dir, fmt.Sprintf("pk_%d.bin", v))); err != nil {
		return C.CString(err.Error())
	}
	if err := writeVerifyingKey(vk, filepath.Join(dir, fmt.Sprintf("vk_%d.bin", v))); err != nil {
		return C.CString(err.Error())
	}
	return nil
}

//export Prove
func Prove(variant C.int, xDecimal *C.char, dir *C.char) *C.C_ProveResult {
	v := int(variant)
	result := (*C.C_ProveResult)(C.malloc(C.sizeof_C_ProveResult))
	C.memset(unsafe.Pointer(result), 0, C.sizeof_C_ProveResult)

	xStr := C.GoString(xDecimal)
	xBI, ok := new(big.Int).SetString(xStr, 10)
	if !ok {
		result.error = C.CString(fmt.Sprintf("invalid X decimal %q", xStr))
		return result
	}
	yBI := new(big.Int).Mul(xBI, xBI)

	cs, err := compile(v)
	if err != nil {
		result.error = C.CString(err.Error())
		return result
	}

	pk, _, err := loadKeys(v, C.GoString(dir))
	if err != nil {
		result.error = C.CString(err.Error())
		return result
	}

	assignment, err := newAssignment(v, xBI, yBI)
	if err != nil {
		result.error = C.CString(err.Error())
		return result
	}
	w, err := frontend.NewWitness(assignment, ecc.BN254.ScalarField())
	if err != nil {
		result.error = C.CString(fmt.Sprintf("new witness: %v", err))
		return result
	}

	proof, err := groth16.Prove(cs, pk, w)
	if err != nil {
		result.error = C.CString(fmt.Sprintf("prove: %v", err))
		return result
	}
	proofBN := proof.(*groth16_bn254.Proof)

	if len(proofBN.Commitments) != 1 {
		result.error = C.CString(fmt.Sprintf(
			"expected exactly 1 commitment, got %d", len(proofBN.Commitments)))
		return result
	}

	arRaw := proofBN.Ar.RawBytes()
	bsRaw := proofBN.Bs.RawBytes()
	krsRaw := proofBN.Krs.RawBytes()
	cmtRaw := proofBN.Commitments[0].RawBytes()
	pokRaw := proofBN.CommitmentPok.RawBytes()

	if err := copyBytes(&result.proof_a[0], arRaw[:]); err != nil {
		result.error = C.CString(err.Error())
		return result
	}
	if err := copyBytes(&result.proof_b[0], bsRaw[:128]); err != nil {
		result.error = C.CString(err.Error())
		return result
	}
	if err := copyBytes(&result.proof_c[0], krsRaw[:]); err != nil {
		result.error = C.CString(err.Error())
		return result
	}
	if err := copyBytes(&result.commitment[0], cmtRaw[:]); err != nil {
		result.error = C.CString(err.Error())
		return result
	}
	if err := copyBytes(&result.commitment_pok[0], pokRaw[:]); err != nil {
		result.error = C.CString(err.Error())
		return result
	}
	pubBytes := xBI.FillBytes(make([]byte, 32))
	if err := copyBytes(&result.public_input[0], pubBytes); err != nil {
		result.error = C.CString(err.Error())
		return result
	}
	return result
}

//export NativeVerify
func NativeVerify(variant C.int, xDecimal *C.char, dir *C.char) *C.char {
	v := int(variant)
	cs, err := compile(v)
	if err != nil {
		return C.CString(err.Error())
	}
	pk, vk, err := loadKeys(v, C.GoString(dir))
	if err != nil {
		return C.CString(err.Error())
	}
	xBI, ok := new(big.Int).SetString(C.GoString(xDecimal), 10)
	if !ok {
		return C.CString("invalid X decimal")
	}
	yBI := new(big.Int).Mul(xBI, xBI)
	assignment, err := newAssignment(v, xBI, yBI)
	if err != nil {
		return C.CString(err.Error())
	}
	w, err := frontend.NewWitness(assignment, ecc.BN254.ScalarField())
	if err != nil {
		return C.CString(err.Error())
	}
	proof, err := groth16.Prove(cs, pk, w)
	if err != nil {
		return C.CString(err.Error())
	}
	pubW, err := w.Public()
	if err != nil {
		return C.CString(err.Error())
	}
	if err := groth16.Verify(proof, vk, pubW); err != nil {
		return C.CString(fmt.Sprintf("verify: %v", err))
	}
	return nil
}

//export FreeProveResult
func FreeProveResult(result *C.C_ProveResult) {
	if result == nil {
		return
	}
	if result.error != nil {
		C.free(unsafe.Pointer(result.error))
	}
	C.free(unsafe.Pointer(result))
}

//export FreeString
func FreeString(s *C.char) {
	if s != nil {
		C.free(unsafe.Pointer(s))
	}
}

func copyBytes(dst *C.uchar, src []byte) error {
	if dst == nil {
		return fmt.Errorf("nil dst")
	}
	dstSlice := unsafe.Slice((*byte)(unsafe.Pointer(dst)), len(src))
	copy(dstSlice, src)
	return nil
}

func main() {}
