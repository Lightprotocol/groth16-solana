//! Empirical on-chain CU measurement for the Groth16 verifier
//! program, plus negative tests. Runs against the UNPROFILED build:
//!
//!     cargo build-sbf --manifest-path tests/program/Cargo.toml
//!     cargo test     --manifest-path tests/program/Cargo.toml -- --nocapture
//!
//! Or use the chained helper:
//!
//!     cargo test-sbf --manifest-path tests/program/Cargo.toml -- --nocapture
//!
//! Per-function CU profiling lives in tests/bench_cu.rs (mollusk +
//! light-program-profiler); this file is the litesvm sanity net that
//! keeps every variant verifying end to end and inside its CU
//! envelope. The fixtures are regenerated deterministically by
//! build.rs into OUT_DIR/bench-fixtures.

use bsb22_integration_program::bench_fixtures::{build_ix_data, fixtures, PROGRAM_ID_BYTES};
use litesvm::LiteSVM;
use solana_compute_budget::compute_budget::ComputeBudget;
use solana_instruction::Instruction;
use solana_keypair::Keypair;
use solana_pubkey::Pubkey;
use solana_signer::Signer;
use solana_transaction::Transaction;

fn program_id() -> Pubkey {
    Pubkey::new_from_array(PROGRAM_ID_BYTES)
}

fn setup_svm() -> (LiteSVM, Keypair) {
    let mut budget = ComputeBudget::new_with_defaults(false, false);
    budget.compute_unit_limit = 1_400_000;
    let mut svm = LiteSVM::new().with_compute_budget(budget);

    // The .so lives at target/deploy/<crate_name>.so after
    // `cargo build-sbf`. `cargo test-sbf` builds it automatically.
    let so_path = std::env::var("SBF_OUT_DIR")
        .map(|dir| format!("{}/bsb22_integration_program.so", dir))
        .unwrap_or_else(|_| "../../target/deploy/bsb22_integration_program.so".to_string());

    svm.add_program_from_file(program_id(), &so_path)
        .unwrap_or_else(|e| {
            panic!(
                "failed to load program from {}: {:?}\n\
                 did you run `cargo build-sbf --manifest-path tests/program/Cargo.toml` first?\n\
                 (a .so built with --features profile-program cannot run under litesvm)",
                so_path, e
            )
        });

    let payer = Keypair::new();
    svm.airdrop(&payer.pubkey(), 10_000_000_000).unwrap();

    (svm, payer)
}

fn send(svm: &mut LiteSVM, payer: &Keypair, data: Vec<u8>) -> Result<u64, String> {
    let ix = Instruction {
        program_id: program_id(),
        accounts: vec![],
        data,
    };
    let mut tx = Transaction::new_with_payer(&[ix], Some(&payer.pubkey()));
    tx.sign(&[payer], svm.latest_blockhash());
    svm.send_transaction(tx)
        .map(|meta| meta.compute_units_consumed)
        .map_err(|e| format!("{:?}", e.err))
}

#[test]
fn all_variants_verify_on_chain_within_cu_envelope() {
    let (mut svm, payer) = setup_svm();

    eprintln!("=== Groth16 on-chain verify CU (unprofiled build) ===");
    for f in fixtures() {
        let cu = send(&mut svm, &payer, build_ix_data(&f))
            .unwrap_or_else(|e| panic!("{} verify tx should succeed on chain: {}", f.label, e));
        eprintln!("  {:<8} compute_units_consumed = {}", f.label, cu);
        assert!(
            cu < f.max_cu,
            "{} exceeded CU budget: {} > {}",
            f.label,
            cu,
            f.max_cu
        );
    }
}

#[test]
fn rejects_wrong_instruction_length() {
    let (mut svm, payer) = setup_svm();

    // One byte short and one byte long: each variant accepts exactly
    // its fixed payload size and must reject both before touching the
    // proof.
    for f in fixtures() {
        let base = build_ix_data(&f);
        for delta in [-1i64, 1] {
            let mut data = base.clone();
            data.resize((base.len() as i64 + delta) as usize, 0);
            let result = send(&mut svm, &payer, data);
            assert!(
                result.is_err(),
                "{}: instruction data of len {} should be rejected",
                f.label,
                base.len() as i64 + delta
            );
        }
    }
}

#[test]
fn rejects_mutated_public_input() {
    let (mut svm, payer) = setup_svm();

    for f in fixtures() {
        let mut data = build_ix_data(&f);
        // Flip the last byte of the public input so the MSM yields a
        // different kSum and the final pairing check fails.
        *data.last_mut().unwrap() ^= 1;
        let result = send(&mut svm, &payer, data);
        assert!(
            result.is_err(),
            "{}: mutated public input should be rejected",
            f.label
        );
    }
}

#[test]
fn rejects_unknown_selector() {
    let (mut svm, payer) = setup_svm();

    let mut data = build_ix_data(&fixtures()[0]);
    *data.first_mut().unwrap() = 8; // first selector past the valid 0..=7 range
    let result = send(&mut svm, &payer, data);
    assert!(result.is_err(), "unknown selector should be rejected");
}

#[test]
fn rejects_commitment_variant_payload_on_plain_selector() {
    let (mut svm, payer) = setup_svm();

    // A bsb22_1 payload on the plain_1 selector: same proof points but
    // the trailing 160 bytes (commitment + pok + input) don't fit the
    // plain layout, so the length gate rejects it.
    let fixtures = fixtures();
    let bsb22_1 = &fixtures[4];
    assert_eq!(bsb22_1.label, "bsb22_1");
    let mut data = build_ix_data(bsb22_1);
    *data.first_mut().unwrap() = 0;
    let result = send(&mut svm, &payer, data);
    assert!(
        result.is_err(),
        "bsb22 payload on plain selector should be rejected"
    );
}
