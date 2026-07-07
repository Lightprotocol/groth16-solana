//! Empirical on-chain CU measurement for the BSB22 Groth16 verifier.
//!
//! This is the source of truth for the CU numbers documented in
//! `src/groth16.rs`. Run with:
//!
//!     cargo build-sbf --manifest-path tests/bsb22-program/Cargo.toml
//!     cargo test     --manifest-path tests/bsb22-program/Cargo.toml -- --nocapture
//!
//! Or use the chained helper:
//!
//!     cargo test-sbf --manifest-path tests/bsb22-program/Cargo.toml -- --nocapture
//!
//! The test deploys `bsb22_integration_program.so` into litesvm,
//! sends a verify transaction with a precomputed (vk, proof, public
//! input) snapshot, and asserts both that the tx succeeded AND that
//! the consumed CU is within the expected envelope.

use groth16_solana::groth16::negate_g1_be;
use litesvm::LiteSVM;
use solana_compute_budget::compute_budget::ComputeBudget;
use solana_instruction::Instruction;
use solana_keypair::Keypair;
use solana_pubkey::Pubkey;
use solana_signer::Signer;
use solana_transaction::Transaction;

const PROOF_A: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/proof_a.bin"));
const PROOF_B: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/proof_b.bin"));
const PROOF_C: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/proof_c.bin"));
const COMMITMENT: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/commitment.bin"));
const POK: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/pok.bin"));
const PUBLIC_INPUT: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/public_input.bin"));

fn build_ix_data() -> Vec<u8> {
    let proof_a_fixed: [u8; 64] = PROOF_A.try_into().expect("proof_a is 64 bytes");
    let proof_a_neg = negate_g1_be(&proof_a_fixed);
    let mut instruction_data = Vec::with_capacity(416);
    instruction_data.extend_from_slice(&proof_a_neg);
    instruction_data.extend_from_slice(PROOF_B);
    instruction_data.extend_from_slice(PROOF_C);
    instruction_data.extend_from_slice(COMMITMENT);
    instruction_data.extend_from_slice(POK);
    instruction_data.extend_from_slice(PUBLIC_INPUT);
    assert_eq!(instruction_data.len(), 416);
    instruction_data
}

fn program_id() -> Pubkey {
    Pubkey::new_from_array([
        0xb5, 0xb2, 0x20, 0x00, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab,
        0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89,
        0xab, 0xcd,
    ])
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
                 did you run `cargo build-sbf --manifest-path tests/bsb22-program/Cargo.toml` first?",
                so_path, e
            )
        });

    let payer = Keypair::new();
    svm.airdrop(&payer.pubkey(), 10_000_000_000).unwrap();

    (svm, payer)
}

#[test]
fn bsb22_verify_on_chain_succeeds_and_reports_cu() {
    let (mut svm, payer) = setup_svm();
    let instruction_data = build_ix_data();

    let ix = Instruction {
        program_id: program_id(),
        accounts: vec![],
        data: instruction_data,
    };
    let mut tx = Transaction::new_with_payer(&[ix], Some(&payer.pubkey()));
    tx.sign(&[&payer], svm.latest_blockhash());

    let meta = svm
        .send_transaction(tx)
        .expect("bsb22 verify tx should succeed on chain");

    eprintln!("=== BSB22 Groth16 on-chain verify ===");
    for log in &meta.logs {
        eprintln!("  {}", log);
    }
    eprintln!("compute_units_consumed = {}", meta.compute_units_consumed);

    // Sanity: the verifier must not exceed the documented soft
    // target. The measured cost at the time this test was added was
    // ~212k CU with solana-bn254 v3 and the sol_sha256 syscall for
    // BSB22 hash-to-field. Leave some margin for syscall-cost churn
    // across Solana runtime versions (+50% headroom).
    assert!(
        meta.compute_units_consumed < 350_000,
        "BSB22 verify exceeded CU budget: {} > 350_000",
        meta.compute_units_consumed
    );
}

#[test]
fn bsb22_verify_on_chain_rejects_mutated_public_input() {
    let (mut svm, payer) = setup_svm();
    let mut instruction_data = build_ix_data();
    // Flip the last byte of the public input so the extended MSM
    // yields a different kSum and the final pairing check fails.
    instruction_data[415] ^= 1;

    let ix = Instruction {
        program_id: program_id(),
        accounts: vec![],
        data: instruction_data,
    };
    let mut tx = Transaction::new_with_payer(&[ix], Some(&payer.pubkey()));
    tx.sign(&[&payer], svm.latest_blockhash());

    let send_result = svm.send_transaction(tx);
    assert!(
        send_result.is_err(),
        "mutated public input should be rejected"
    );
}
