# groth16-solana

<!-- cargo-rdme start -->

Groth16 zero-knowledge proof verification with Solana alt_bn128 syscalls.

A plain Groth16 verify costs 78,324–108,789 CU. BSB22
`verify()` costs 134,795–165,258 CU; `verify_opt()` costs
119,286–150,085 CU. With both optional accelerators it costs
117,600–148,176 CU, for 1 to 8 public inputs (see
[Benchmarks](#benchmarks)).

The syscalls ship with Solana 1.18 onward and are active on mainnet-beta.

Inputs are big-endian `u8` arrays.

See the integration tests in `tests/program` for an example of how to use
this library.

This crate is `no_std` and compatible with Groth16 proofs from circom and
gnark circuits.

The verifying key can be generated from a snarkjs `verification_key.json`
or a gnark vk binary.

Note: This open-source crate is provided "as-is" without warranties. Use
at your own risk.

## Features

- `bsb22` — verifies gnark proofs that include a single BSB22
  (Belling-Soleimanian-Begassat 2022) Pedersen commitment, via
  `Groth16Verifier::new_with_commitment`. Every gnark circuit takes this
  shape once it uses `std/lookup/logderivlookup` or an emulated-field
  range check: gnark's `multicommit` merges the deferred commits into
  one `api.Commit()` at finalization (`std/multicommit/nativecommit.go:89`).
- `gnark-vk` — generates the `Groth16Verifyingkey` const from a gnark vk
  binary (`vk.WriteRawTo`) in `build.rs`; parses plain and BSB22 vks.
  [src/vk/gnark.rs](src/vk/gnark.rs)
- `circom-vk` — generates the `Groth16Verifyingkey` const from a snarkjs
  `verification_key.json`. [src/vk/circom.rs](src/vk/circom.rs)
- `circom` — converts circom-prover proofs to the verifier's byte format.
  [src/proof_parser.rs](src/proof_parser.rs)
- `bsb22-test` — re-exports the hash-to-field internals for the
  differential FFI tests. Test-only, not a stable API.

## Benchmarks

End-to-end verification cost (proof parsing, verifier construction, verification)
in compute units. Every column verifies one proof at a time.

| Public inputs | Groth16 | BSB22 | verify_opt | With hint | With cached key | With both |
|--------------:|--------:|------:|-----------:|----------:|----------------:|----------:|
| 1 | 78,324 | 134,795 | 119,286 | 118,244 | 118,641 | 117,600 |
| 2 | 82,732 | 139,201 | 123,739 | 122,700 | 123,063 | 122,022 |
| 4 | 91,472 | 147,939 | 132,574 | 131,537 | 131,833 | 130,795 |
| 8 | 108,789 | 165,258 | 150,085 | 149,045 | 149,216 | 148,176 |

`verify_opt()` uses the existing proof and instruction payload. For more
savings, `verify_opt_with_options()` accepts a checked reduction hint and/or
a pinned key digest. The hint appends 49 bytes: a 17-byte big-endian quotient
followed by a 32-byte canonical remainder for gnark's 48-byte SHA-256 XMD
expansion of the commitment with DST `bsb22-commitment`.

Generate the digest with `Groth16Verifyingkey::verify_opt_key_hash()` in a
build script and pin it alongside its matching key. It adds no instruction
data and must not be accepted from the prover. See `tests/program/build.rs`
and `tests/gnark-ffi/gnark-fixture/bench/bench.go` for complete examples.

`verify()` retains its separate pairing checks and error diagnostics.
The optimized path reports `ProofVerificationFailed` when its combined
pairing equation fails; malformed hints report `Bsb22InvalidHashHint`.

<!-- cargo-rdme end -->

## License

Licensed under [Apache License, Version 2.0](LICENSE).

### Contribution

Unless you explicitly state otherwise, any contribution intentionally
submitted for inclusion in the work by you, as defined in the Apache-2.0
license, shall be dual licensed as above, without any additional terms or
conditions.
