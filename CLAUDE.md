# CLAUDE.md

## Test coverage

`cargo test --workspace` runs the unit tests, the codegen tests and the
FFI differential tests. The `circom-vk`-gated codegen tests only run
there because `tests/rust-vk` enables `circom-vk` through a
dev-dependency; the all-features invocation below does not depend on
that. The mollusk suites need `cargo build-sbf` first, and
`tests/rust-vk` needs its npm build. CI runs `just ci` with
`PROPTEST_CASES=1000000`: lint (fmt check, clippy, the feature-matrix
compile, README sync via cargo-rdme), the no_std compile check
(`check-nostd`), circuit build, workspace build and tests, the
all-features unit run, then BENCHMARKS.md regeneration with a diff
check.

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
8. `groth16::tests::delta_equal_gamma_vk_accepts_forged_proof` — the
   test vk has delta == gamma (no phase-2 contribution), so
   `A = α, B = β, C = -L(x)` verifies for arbitrary inputs; the same
   forgery fails once delta differs
9. `groth16::tests::bsb22_e2e::bsb22_e2e_verifies` — deterministic
   gnark fixture, positive path
10. `groth16::tests::bsb22_e2e::bsb22_e2e_rejects_mutated_public_input`
11. `groth16::tests::bsb22_e2e::bsb22_e2e_rejects_public_input_greater_than_field_size`
12. `groth16::tests::bsb22_e2e::bsb22_e2e_rejects_substituted_on_curve_commitment`
13. `groth16::tests::bsb22_e2e::bsb22_e2e_rejects_substituted_on_curve_pok`
14. `groth16::tests::bsb22_e2e::bsb22_e2e_rejects_swapped_commitment_and_pok`
15. `groth16::tests::bsb22_e2e::bsb22_e2e_rejects_identity_commitment_and_pok`
16. `groth16::tests::bsb22_e2e::bsb22_e2e_rejects_not_on_curve_commitment`
17. `groth16::tests::bsb22_e2e::bsb22_e2e_rejects_not_on_curve_pok`
18. `groth16::tests::bsb22_e2e::bsb22_e2e_rejects_tampered_commitment_key`
19. `groth16::tests::bsb22_e2e::bsb22_e2e_new_rejects_bsb22_vk`
20. `groth16::tests::bsb22_e2e::bsb22_e2e_new_with_commitment_rejects_standard_vk`
21. `groth16::tests::bsb22_e2e::bsb22_e2e_new_with_commitment_rejects_short_vk_ic`
22. `hash_to_field::tests::matches_gnark_empty` — gnark-crypto golden
    vector
23. `hash_to_field::tests::matches_gnark_abc` — golden vector
24. `hash_to_field::tests::matches_gnark_zero_g1` — golden vector
25. `hash_to_field::tests::matches_gnark_sequential` — golden vector
26. `hash_to_field::tests::reference_matches_rfc9380_vectors` —
    validates the RustCrypto reference expander against all 10 RFC
    9380 CFRG vectors
27. `hash_to_field::tests::expander_matches_reference_grid` —
    deterministic msg/dst-length grid vs that reference at L = 48
28. `hash_to_field::tests::prop_expander_bsb22_shape` — proptest,
    64/16-byte shape (`PROPTEST_CASES`, default 1000)
29. `hash_to_field::tests::prop_expander_max_msg` — proptest,
    187/1-byte shape
30. `hash_to_field::tests::prop_reduce_be_l48_matches_single_buffer`
    — proptest, production halved reduction vs arkworks'
    whole-buffer reduction
31. `hash_to_field::tests::reduce_be_l48_matches_single_buffer_at_bounds`
32. `hash_to_field::tests::reduce_be_l48_wraps_on_final_add` — r,
    r + 1 and the largest multiple of r below 2^384, where the final
    add wraps past r
33. `vk::gnark::tests::parse_bsb22_vk_shape`
34. `vk::gnark::tests::rejects_truncated_input`
35. `vk::gnark::tests::rejects_trailing_bytes`
36. `vk::gnark::tests::rejects_oversized_nb_k_without_allocating`
37. `vk::gnark::tests::rejects_multi_commitment`
38. `vk::gnark::tests::rejects_multi_commitment_keys`
39. `vk::gnark::tests::rejects_lockstep_mismatch`
40. `vk::gnark::tests::rejects_committed_public_inputs`
41. `vk::gnark::tests::bsb22_vk_to_rust_const_roundtrip` — includes the
    insecure-test-setup header, consts and compile guard
42. `vk::gnark::tests::bsb22_vk_to_rust_const_production_has_no_guard`
43. `vk::gnark::tests::bsb22_vk_to_rust_const_rejects_production_vk_with_delta_equal_gamma`
44. `vk::gnark::tests::bsb22_vk_to_rust_const_accepts_insecure_test_vk_with_delta_equal_gamma`
45. `vk::gnark::tests::generate_bsb22_vk_file_pins_proving_key_sha256`
    — the SHA-256 of an "abc" proving key file appears in the
    generated const
46. `vk::gnark::tests::generate_bsb22_vk_file_reports_io_error_for_missing_proving_key`
47. `vk::gnark::tests::generate_bsb22_vk_file_reports_io_error_for_missing_input`
48. `vk::setup::tests::proving_key_sha256_matches_known_vector` — FIPS
    180-2 "abc"
49. `vk::setup::tests::proving_key_sha256_streams_across_chunks` —
    multi-chunk file vs one-shot SHA-256
50. `vk::setup::tests::proving_key_sha256_reports_missing_file`
51. `vk::setup::tests::metadata_marks_insecure_test_setup_with_compile_guard`
52. `vk::setup::tests::metadata_production_has_no_compile_guard`
53. `vk::setup::tests::metadata_export_name_depends_on_vk_source` —
    two vks with the same const name export different symbols
54. `vk::setup::tests::find_setup_txts_reads_markers_between_other_bytes`
55. `vk::setup::tests::find_setup_txts_returns_empty_without_markers`
56. `vk::setup::tests::find_setup_txts_rejects_unterminated_marker`
57. `vk::setup::tests::find_setup_txts_rejects_malformed_fields`
58. `circom_vk_codegen::generates_const_with_vk_commitment_none`
59. `circom_vk_codegen::insecure_test_setup_emits_flag_header_and_compile_guard`
60. `circom_vk_codegen::production_setup_emits_flag_without_compile_guard`
61. `circom_vk_codegen::rejects_production_vk_with_delta_equal_gamma`
62. `circom_vk_codegen::rejects_empty_ic`
63. `circom_vk_codegen::rejects_empty_point_coordinates`
64. `readme_benchmarks::crate_docs_cu_table_matches_benchmarks` — pins
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
13. Go: `TestGenerateIsDeterministic` — bench-generator determinism,
    proving keys included

### Mollusk program tests (tests/program, requires Go + Solana toolchain)

Build the .so first; do not use `cargo test-sbf` for the bench, it
overwrites the profiled build:

```sh
cargo build-sbf --manifest-path tests/program/Cargo.toml -- --features profile-program
cargo test -p bsb22-integration-program --test failing --test setup_txt
cargo test -p bsb22-integration-program --test bench_cu -- --ignored --nocapture
```

The baked vks come from a seeded gnark setup, so they are generated
as `SetupKind::InsecureTest` and the crate enables its
`insecure-test-setup` feature by default. Each `failing.rs` test pins
the exact `ProgramError` the client sees.

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
17. `setup_txt_readable_from_program_binary` (`setup_txt.rs`) — reads
    the exported `*_SETUP_TXT` markers back from the built .so: one
    per vk, all flagged insecure, each with the SHA-256 of its
    fixture pk.bin
18. `bench_cu` (`--ignored`) — executes all 8 variants successfully
    under mollusk and regenerates BENCHMARKS.md

Deploy tooling reads the same markers with
`vk::setup::find_setup_txts`, from a local build or a
`solana program dump`; `strings program.so | grep -A7 "BEGIN GROTH16 VK SETUP"`
shows them by hand.

### Circom end-to-end (tests/rust-vk, requires npm + circom)

`npm install && npm run build-all` in `tests/rust-vk`, then
`cargo test -p rust-vk-integration-test`.

1. `test_compressed_account_proof_with_groth16_solana` — checks the
   zkey's SHA-256 against `VERIFYINGKEY_PROVING_KEY_SHA256`, builds a
   compressed-account Merkle-proof witness, proves with circom-prover,
   and verifies with the vk const generated by `vk::circom` in
   `build.rs`
