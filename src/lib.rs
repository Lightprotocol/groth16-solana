//! Groth16 zero-knowledge proof verification with Solana alt_bn128 syscalls.
//!
//! A plain Groth16 verify costs 78,293–108,762 CU and a BSB22 verify
//! 144,138–174,621 CU, for 1 to 8 public inputs (see
//! [Benchmarks](#benchmarks)).
//!
//! The syscalls ship with Solana 1.18 onward and are active on mainnet-beta.
//!
//! Inputs are big-endian `u8` arrays.
//!
//! See the integration tests in `tests/program` for an example of how to use
//! this library.
//!
//! This crate is `no_std` and compatible with Groth16 proofs from circom and
//! gnark circuits.
//!
//! The verifying key can be generated from a snarkjs `verification_key.json`
//! or a gnark vk binary.
//!
//! Note: This open-source crate is provided "as-is" without warranties. Use
//! at your own risk.
//!
//! # Features
//!
//! - `bsb22` — verifies gnark proofs that include a single BSB22
//!   (Bowe-Sankaranarayanan-Bonneau 2022) Pedersen commitment, via
//!   `Groth16Verifier::new_with_commitment`. Every gnark circuit takes this
//!   shape once it uses `std/lookup/logderivlookup` or an emulated-field
//!   range check: gnark's `multicommit` merges the deferred commits into
//!   one `api.Commit()` at finalization (`std/multicommit/nativecommit.go:89`).
//! - `gnark-vk` — generates the `Groth16Verifyingkey` const from a gnark vk
//!   binary (`vk.WriteRawTo`) in `build.rs`; parses plain and BSB22 vks.
//!   [src/vk/gnark.rs](src/vk/gnark.rs)
//! - `circom-vk` — generates the `Groth16Verifyingkey` const from a snarkjs
//!   `verification_key.json`. [src/vk/circom.rs](src/vk/circom.rs)
//! - `circom` — converts circom-prover proofs to the verifier's byte format.
//!   [src/proof_parser.rs](src/proof_parser.rs)
//! - `bsb22-test` — re-exports the hash-to-field internals for the
//!   differential FFI tests. Test-only, not a stable API.
//!
//! # Benchmarks
//!
//! End-to-end verification cost (proof parsing, verifier construction,
//! `verify()`) in compute units:
//!
//! | Public inputs | Groth16 | Groth16-BSB22 |
//! |--------------:|--------:|--------------:|
//! | 1 | 78,293 | 144,138 |
//! | 2 | 82,704 | 148,581 |
//! | 4 | 91,448 | 157,300 |
//! | 8 | 108,762 | 174,621 |

#![no_std]

// The verification path (default and `bsb22` features on the
// Solana target) is heap-allocation-free; `alloc` is only needed by
// host-side tooling (vk parsers, proof parser) and tests. Gating the
// extern makes that a compile-time guarantee: any allocation
// reintroduced there fails to build for SBF.
#[cfg(any(not(target_os = "solana"), feature = "circom"))]
extern crate alloc;

// proptest (dev-dependency) expands to std-using code; the crate
// itself stays no_std, this only affects `cargo test` builds.
#[cfg(test)]
extern crate std;

pub mod decompression;
pub mod errors;
pub mod groth16;
pub(crate) mod syscalls;

#[cfg(feature = "circom")]
pub mod proof_parser;

#[cfg(feature = "bsb22")]
pub(crate) mod hash_to_field;

// Baked, reproducible BSB22 fixture bytes shared by the lib-internal
// unit tests (see the module docs for regeneration). Lives in
// tests/gnark-ffi/ next to the generator that produces it because it
// is test-only data, not crate source; the `#[path]` include is what
// lets `#[cfg(test)]` modules in src/ reach it as a crate-internal
// module.
#[cfg(all(test, feature = "gnark-vk"))]
#[path = "../tests/gnark-ffi/test_fixtures.rs"]
pub(crate) mod test_fixtures;

/// Test-only escape hatch (`bsb22-test` feature): the differential
/// proptests in `tests/gnark-ffi/` compare this against gnark-crypto's
/// `fr/hash_to_field` via FFI. Not a stable API surface.
#[cfg(feature = "bsb22-test")]
pub use hash_to_field::hash_to_field_bn254_fr;

/// Verifying-key parsers and Rust-const generators, one submodule per
/// proving stack: [`vk::circom`] for snarkjs JSON keys, [`vk::gnark`]
/// for gnark `WriteRawTo` binaries (incl. BSB22 commitment keys).
pub mod vk {
    #[cfg(feature = "circom-vk")]
    pub mod circom;

    // Host-only: the parser owns its IC column as a `Vec` and the
    // generator writes files; neither belongs in an SBF build, and
    // excluding them keeps that build free of `alloc`.
    #[cfg(all(feature = "gnark-vk", not(target_os = "solana")))]
    pub mod gnark;
}
