//! Per-function CU profiling for every Groth16 verifier variant,
//! generating BENCHMARKS.md at the repo root. Mollusk executes the
//! PROFILED .so and light-program-profiler turns the profiler
//! syscalls into per-function CU tables (same harness pattern as
//! zolana's shielded-pool bench).
//!
//! Run (the profiled build is mandatory — `cargo test-sbf` would
//! overwrite it with an unprofiled one, so build first, then test):
//!
//!     cargo build-sbf --manifest-path tests/program/Cargo.toml -- --features profile-program
//!     cargo test -p bsb22-integration-program --test bench_cu -- --ignored --nocapture
//!
//! `#[ignore]` keeps the bench out of plain `cargo test` runs, which
//! do not build the profiled .so first.
//!
//! CU regression check: CI reruns this bench and fails on any
//! uncommitted BENCHMARKS.md diff, so cost changes must be
//! re-baselined by committing the regenerated file.

use bsb22_integration_program::bench_fixtures::{build_ix_data, fixtures, PROGRAM_ID_BYTES};
use light_program_profiler::{
    mollusk::{register_profiling_syscalls, take_profiling_entries},
    report::{CuBenchmark, ReadmeConfig},
};
use mollusk_solana_instruction::Instruction;
use mollusk_solana_pubkey::Pubkey;
use mollusk_svm::{program::loader_keys::LOADER_V3, result::Check, Mollusk};

const SBF_OUT_DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../target/deploy");
const OUTPUT_PATH: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../BENCHMARKS.md");

#[test]
#[ignore]
fn bench_cu() {
    std::env::set_var("SBF_OUT_DIR", SBF_OUT_DIR);

    let program_id = Pubkey::new_from_array(PROGRAM_ID_BYTES);
    let mut mollusk = Mollusk::default();
    register_profiling_syscalls(&mut mollusk);
    mollusk.add_program(&program_id, "bsb22_integration_program", &LOADER_V3);

    let mut bench = CuBenchmark::new(ReadmeConfig {
        title: "groth16-solana CU Benchmarks".into(),
        description: "Compute unit costs of Groth16 verification on Solana, measured with \
            [light-program-profiler](https://github.com/Lightprotocol/light-program-profiler) \
            under mollusk against the profiled build of `tests/program`. The matrix \
            covers plain Groth16 (`Groth16Verifier::new`) and BSB22 single-commitment proofs \
            (`Groth16Verifier::new_with_commitment`, gnark lookup circuits), each verified \
            with 1, 2, 4, and 8 public inputs. Proofs and verifying keys are regenerated \
            deterministically by build.rs (seeded gnark setup, see \
            tests/gnark-ffi/gnark-fixture/bench). `verify`/`verify_with_bsb22_commitment` is \
            proof parsing plus Groth16Verifier construction plus `verify()`."
            .into(),
        output_path: OUTPUT_PATH.into(),
        regenerate_command: Some(
            "cargo build-sbf --manifest-path tests/program/Cargo.toml -- --features profile-program \
             && cargo test -p bsb22-integration-program --test bench_cu -- --ignored --nocapture"
                .into(),
        ),
        ..Default::default()
    });

    for f in fixtures() {
        let plural = if f.nr_inputs == 1 { "" } else { "s" };
        let section = match f.commitment {
            None => format!("groth16 - {} public input{}", f.nr_inputs, plural),
            Some(_) => format!("groth16-bsb22 - {} public input{}", f.nr_inputs, plural),
        };

        let ix = Instruction {
            program_id,
            accounts: vec![],
            data: build_ix_data(&f),
        };
        mollusk.process_and_validate_instruction(&ix, &[], &[Check::success()]);

        let entries = take_profiling_entries();
        assert!(
            !entries.is_empty(),
            "no profiling entries for '{}'; rebuild the .so with \
             `cargo build-sbf --manifest-path tests/program/Cargo.toml -- --features profile-program`",
            f.label
        );
        bench.add_from_entries(&section, entries);
    }

    bench.generate().expect("write BENCHMARKS.md");
    eprintln!("wrote {}", OUTPUT_PATH);
}
