# groth16-solana

<!-- cargo-rdme start -->

Groth16 zero-knowledge proof verification with Solana alt_bn128 syscalls.

A plain Groth16 verify costs 78,293–108,762 CU and a BSB22 verify
144,138–174,621 CU, for 1 to 8 public inputs (see
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
  (Bowe-Sankaranarayanan-Bonneau 2022) Pedersen commitment, via
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

End-to-end verification cost (proof parsing, verifier construction,
`verify()`) in compute units:

| Public inputs | Groth16 | Groth16-BSB22 |
|--------------:|--------:|--------------:|
| 1 | 78,293 | 144,138 |
| 2 | 82,704 | 148,581 |
| 4 | 91,448 | 157,300 |
| 8 | 108,762 | 174,621 |

<!-- cargo-rdme end -->

## License

Licensed under [Apache License, Version 2.0](LICENSE).

### Contribution

Unless you explicitly state otherwise, any contribution intentionally
submitted for inclusion in the work by you, as defined in the Apache-2.0
license, shall be dual licensed as above, without any additional terms or
conditions.
