# CLAUDE.md

## Test coverage

`cargo test --workspace` runs the unit tests and the FFI differential
tests, but not the `circom-vk`-gated codegen tests: no workspace member
enables that feature as a normal dependency, so they need the explicit
`--features` invocation below. The mollusk suites need `cargo build-sbf`
first, and `tests/rust-vk` needs its npm build. CI runs `just ci` with
`PROPTEST_CASES=1000000`: lint (fmt check, clippy, the feature-matrix
compile, README sync via cargo-rdme), circuit build, workspace build
and tests, the all-features unit run, then BENCHMARKS.md regeneration
with a diff check.

### Unit and codegen tests (src/, tests/)

`cargo test -p groth16-solana --features "bsb22 gnark-vk circom-vk"`

1. `decompression::tests::apply_bitmask`
2. `groth16::tests::proof_verification_should_succeed`
3. `groth16::tests::proof_verification_with_compressed_inputs_should_succeed`
4. `groth16::tests::wrong_proof_verification_should_not_succeed`
5. `groth16::tests::public_input_greater_than_field_size_should_not_suceed`
6. `groth16::tests::test_is_less_than_bn254_field_size_be`
7. `groth16::tests::fr_modulus_constant_matches_ark` — pins
   `FR_MODULUS_BE` to `ark_bn254::Fr::MODULUS`
8. `groth16::tests::bsb22_e2e::bsb22_e2e_verifies` — deterministic
   gnark fixture, positive path
9. `groth16::tests::bsb22_e2e::bsb22_e2e_rejects_mutated_public_input`
10. `groth16::tests::bsb22_e2e::bsb22_e2e_rejects_public_input_greater_than_field_size`
11. `groth16::tests::bsb22_e2e::bsb22_e2e_rejects_substituted_on_curve_commitment`
12. `groth16::tests::bsb22_e2e::bsb22_e2e_rejects_substituted_on_curve_pok`
13. `groth16::tests::bsb22_e2e::bsb22_e2e_rejects_swapped_commitment_and_pok`
14. `groth16::tests::bsb22_e2e::bsb22_e2e_rejects_identity_commitment_and_pok`
15. `groth16::tests::bsb22_e2e::bsb22_e2e_rejects_not_on_curve_commitment`
16. `groth16::tests::bsb22_e2e::bsb22_e2e_rejects_not_on_curve_pok`
17. `groth16::tests::bsb22_e2e::bsb22_e2e_rejects_tampered_commitment_key`
18. `groth16::tests::bsb22_e2e::bsb22_e2e_new_rejects_bsb22_vk`
19. `groth16::tests::bsb22_e2e::bsb22_e2e_new_with_commitment_rejects_standard_vk`
20. `groth16::tests::bsb22_e2e::bsb22_e2e_new_with_commitment_rejects_short_vk_ic`
21. `hash_to_field::tests::matches_gnark_empty` — gnark-crypto golden
    vector
22. `hash_to_field::tests::matches_gnark_abc` — golden vector
23. `hash_to_field::tests::matches_gnark_zero_g1` — golden vector
24. `hash_to_field::tests::matches_gnark_sequential` — golden vector
25. `hash_to_field::tests::reference_matches_rfc9380_vectors` —
    validates the RustCrypto reference expander against all 10 RFC
    9380 CFRG vectors
26. `hash_to_field::tests::expander_matches_reference_grid` —
    deterministic msg/dst-length grid vs that reference at L = 48
27. `hash_to_field::tests::prop_expander_bsb22_shape` — proptest,
    64/16-byte shape (`PROPTEST_CASES`, default 1000)
28. `hash_to_field::tests::prop_expander_max_msg` — proptest,
    187/1-byte shape
29. `vk::gnark::tests::parse_bsb22_vk_shape`
30. `vk::gnark::tests::rejects_truncated_input`
31. `vk::gnark::tests::rejects_trailing_bytes`
32. `vk::gnark::tests::rejects_multi_commitment`
33. `vk::gnark::tests::rejects_multi_commitment_keys`
34. `vk::gnark::tests::rejects_lockstep_mismatch`
35. `vk::gnark::tests::rejects_committed_public_inputs`
36. `vk::gnark::tests::bsb22_vk_to_rust_const_roundtrip`
37. `vk::gnark::tests::generate_bsb22_vk_file_reports_io_error_for_missing_input`
38. `circom_vk_codegen::generates_const_with_vk_commitment_none`
39. `circom_vk_codegen::rejects_empty_ic`
40. `circom_vk_codegen::rejects_empty_point_coordinates`
41. `readme_benchmarks::crate_docs_cu_table_matches_benchmarks` — pins
    the CU table in the src/lib.rs crate docs (rendered into README.md
    by cargo-rdme) to the BENCHMARKS.md totals

### FFI differential tests (tests/gnark-ffi, requires Go)

`cargo test -p groth16-solana-gnark-ffi`, plus `go test ./...` in
`tests/gnark-ffi/gnark-fixture` for the Go side. Each Rust test
generates fresh proofs and confirms gnark's own verifier accepts them
first.

1. `tests::variant_1_verifies`
2. `tests::variant_2_verifies`
3. `tests::variant_3_verifies`
4. `tests::variant_1_rejects_mutated_public_input`
5. `tests::variant_2_rejects_mutated_commitment`
6. `tests::variant_3_rejects_mutated_pok`
7. `tests::variant_1_rejects_cross_proof_commitment_and_pok`
8. `bind::bindgen_test_layout_C_ProveResult` — bindgen-generated
   struct-layout check
9. `hash_to_field::matches_gnark_bsb22_shape` — 1M-case differential
   proptest vs gnark-crypto through cgo
10. `hash_to_field::matches_gnark_odd_offsets` — 1M-case differential
    proptest, non-block-aligned lengths
11. Go: `TestVariantsCompileProveVerify` — gnark-only
    compile/prove/verify smoke test
12. Go: `TestHashToFieldGoldenVectors` — prints the golden vectors
    baked into `src/hash_to_field.rs`
13. Go: `TestGenerateIsDeterministic` — bench-generator determinism

### Mollusk program tests (tests/program, requires Go + Solana toolchain)

Build the .so first; do not use `cargo test-sbf` for the bench, it
overwrites the profiled build:

```sh
cargo build-sbf --manifest-path tests/program/Cargo.toml -- --features profile-program
cargo test -p bsb22-integration-program --test failing
cargo test -p bsb22-integration-program --test bench_cu -- --ignored --nocapture
```

Each `failing.rs` test pins the exact `ProgramError` the client sees.

1. `rejects_unknown_selector`
2. `rejects_empty_instruction_data`
3. `rejects_wrong_payload_length` — one byte short and one byte long,
   all 8 variants
4. `rejects_cross_mode_payload` — BSB22 payload on a plain selector
   and vice versa
5. `rejects_mutated_public_input`
6. `rejects_non_negated_proof_a`
7. `rejects_off_curve_proof_point`
8. `rejects_public_input_ge_field_modulus`
9. `rejects_proof_for_different_vk`
10. `rejects_swapped_public_inputs`
11. `rejects_mutated_public_input_bsb22`
12. `rejects_substituted_on_curve_commitment`
13. `rejects_off_curve_commitment`
14. `rejects_mutated_pok`
15. `rejects_swapped_commitment_and_pok`
16. `offsets_match_program_layout` — guards the test-side offsets
    against instruction-format drift
17. `bench_cu` (`--ignored`) — executes all 8 variants successfully
    under mollusk and regenerates BENCHMARKS.md

### Circom end-to-end (tests/rust-vk, requires npm + circom)

`npm install && npm run build-all` in `tests/rust-vk`, then
`cargo test -p rust-vk-integration-test`.

1. `test_compressed_account_proof_with_groth16_solana` — builds a
   compressed-account Merkle-proof witness, proves with circom-prover,
   and verifies with the vk const generated by `vk::circom` in
   `build.rs`
