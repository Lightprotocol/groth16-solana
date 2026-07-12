//! Negative tests for every Groth16 verifier variant, executed
//! on-chain under mollusk. Each test pins the exact error the client
//! would see: `ProgramError::InvalidInstructionData` from the parsing
//! gates, or `ProgramError::Custom(u32::from(Groth16Error::...))`
//! from the verifier.
//!
//! Registers the profiling syscalls, so the tests run against either
//! .so build (plain or --features profile-program). Run:
//!
//!     cargo build-sbf --manifest-path tests/program/Cargo.toml
//!     cargo test -p bsb22-integration-program --test failing

use bsb22_integration_program::bench_fixtures::{
    build_ix_data, fixtures, Fixture, PROGRAM_ID_BYTES,
};
use groth16_solana::{errors::Groth16Error, groth16::negate_g1_be};
use light_program_profiler::mollusk::register_profiling_syscalls;
use mollusk_solana_instruction::Instruction;
use mollusk_solana_program_error::ProgramError;
use mollusk_solana_pubkey::Pubkey;
use mollusk_svm::{program::loader_keys::LOADER_V3, result::Check, Mollusk};

const SBF_OUT_DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../target/deploy");

// Instruction-data offsets (selector at 0).
const PROOF_A: std::ops::Range<usize> = 1..65;
/// First byte after proof_c: public inputs (plain) or commitment (BSB22).
const TAIL: usize = 257;
const BSB22_COMMITMENT: std::ops::Range<usize> = 257..321;
const POK: std::ops::Range<usize> = 321..385;

/// BN254 G1 generator (x = 1, y = 2) as 64 uncompressed BE bytes — a
/// valid on-curve point unrelated to any fixture.
const G1_GENERATOR_BE: [u8; 64] = {
    let mut bytes = [0u8; 64];
    bytes[31] = 1;
    bytes[63] = 2;
    bytes
};

/// Deterministic off-curve encoding (x = 0, y = 1): y^2 = 1 but
/// x^3 + 3 = 3, so the alt_bn128 syscalls reject it.
const NOT_ON_CURVE_G1_BE: [u8; 64] = {
    let mut bytes = [0u8; 64];
    bytes[63] = 1;
    bytes
};

/// BN254 Fr modulus as 32 BE bytes — the smallest out-of-range
/// public input.
const FR_MODULUS_BE: [u8; 32] = [
    0x30, 0x64, 0x4e, 0x72, 0xe1, 0x31, 0xa0, 0x29, 0xb8, 0x50, 0x45, 0xb6, 0x81, 0x81, 0x58, 0x5d,
    0x28, 0x33, 0xe8, 0x48, 0x79, 0xb9, 0x70, 0x91, 0x43, 0xe1, 0xf5, 0x93, 0xf0, 0x00, 0x00, 0x01,
];

fn setup() -> (Mollusk, Pubkey) {
    std::env::set_var("SBF_OUT_DIR", SBF_OUT_DIR);
    let program_id = Pubkey::new_from_array(PROGRAM_ID_BYTES);
    let mut mollusk = Mollusk::default();
    // Registered unconditionally: no-op against the unprofiled .so,
    // required for the profile-program build.
    register_profiling_syscalls(&mut mollusk);
    mollusk.add_program(&program_id, "bsb22_integration_program", &LOADER_V3);
    (mollusk, program_id)
}

fn expect_err(mollusk: &Mollusk, program_id: Pubkey, data: Vec<u8>, expected: ProgramError) {
    let ix = Instruction {
        program_id,
        accounts: vec![],
        data,
    };
    mollusk.process_and_validate_instruction(&ix, &[], &[Check::err(expected)]);
}

fn custom(e: Groth16Error) -> ProgramError {
    ProgramError::Custom(u32::from(e))
}

fn fixture(label: &str) -> Fixture {
    fixtures()
        .into_iter()
        .find(|f| f.label == label)
        .unwrap_or_else(|| panic!("no fixture {label}"))
}

fn splice(data: &mut [u8], range: std::ops::Range<usize>, bytes: &[u8]) {
    data.get_mut(range)
        .expect("splice range in bounds")
        .copy_from_slice(bytes);
}

// =========================================================================
// Dispatch / parsing (shared)
// =========================================================================

#[test]
fn rejects_unknown_selector() {
    let (mollusk, program_id) = setup();
    let mut data = build_ix_data(&fixture("plain_1"));
    *data.first_mut().unwrap() = 8; // first selector past the valid 0..=7 range
    expect_err(
        &mollusk,
        program_id,
        data,
        ProgramError::InvalidInstructionData,
    );
}

#[test]
fn rejects_empty_instruction_data() {
    let (mollusk, program_id) = setup();
    expect_err(
        &mollusk,
        program_id,
        Vec::new(),
        ProgramError::InvalidInstructionData,
    );
}

#[test]
fn rejects_wrong_payload_length() {
    let (mollusk, program_id) = setup();
    // One byte short and one byte long: each variant accepts exactly
    // its fixed payload size and must reject both before touching the
    // proof.
    for f in fixtures() {
        let base = build_ix_data(&f);
        for delta in [-1i64, 1] {
            let mut data = base.clone();
            data.resize((base.len() as i64 + delta) as usize, 0);
            expect_err(
                &mollusk,
                program_id,
                data,
                ProgramError::InvalidInstructionData,
            );
        }
    }
}

#[test]
fn rejects_cross_mode_payload() {
    let (mollusk, program_id) = setup();

    // BSB22 payload on the same-N plain selector: 160 trailing bytes
    // (commitment + pok + input) don't fit the plain layout.
    let mut data = build_ix_data(&fixture("bsb22_1"));
    *data.first_mut().unwrap() = 0;
    expect_err(
        &mollusk,
        program_id,
        data,
        ProgramError::InvalidInstructionData,
    );

    // Plain payload on the same-N BSB22 selector: too short for
    // commitment + pok.
    let mut data = build_ix_data(&fixture("plain_1"));
    *data.first_mut().unwrap() = 4;
    expect_err(
        &mollusk,
        program_id,
        data,
        ProgramError::InvalidInstructionData,
    );
}

// =========================================================================
// Plain Groth16 (`verify`)
// =========================================================================

#[test]
fn rejects_mutated_public_input() {
    let (mollusk, program_id) = setup();
    let mut data = build_ix_data(&fixture("plain_1"));
    // Different input -> different kSum in the MSM -> pairing != 1.
    *data.last_mut().unwrap() ^= 1;
    expect_err(
        &mollusk,
        program_id,
        data,
        custom(Groth16Error::ProofVerificationFailed),
    );
}

#[test]
fn rejects_non_negated_proof_a() {
    let (mollusk, program_id) = setup();
    let f = fixture("plain_1");
    let mut data = build_ix_data(&f);
    // gnark's raw A instead of -A: a valid curve point that fails the
    // pairing equation.
    splice(&mut data, PROOF_A, f.proof_a);
    expect_err(
        &mollusk,
        program_id,
        data,
        custom(Groth16Error::ProofVerificationFailed),
    );
}

#[test]
fn rejects_off_curve_proof_point() {
    let (mollusk, program_id) = setup();
    let mut data = build_ix_data(&fixture("plain_1"));
    // proof_a only enters the pairing input; the syscall rejects the
    // off-curve encoding.
    splice(&mut data, PROOF_A, &NOT_ON_CURVE_G1_BE);
    expect_err(
        &mollusk,
        program_id,
        data,
        custom(Groth16Error::ProofVerificationFailed),
    );
}

#[test]
fn rejects_public_input_ge_field_modulus() {
    let (mollusk, program_id) = setup();
    let mut data = build_ix_data(&fixture("plain_1"));
    // Exercises the CHECK path in prepare_inputs before any syscall.
    splice(&mut data, TAIL..TAIL + 32, &FR_MODULUS_BE);
    expect_err(
        &mollusk,
        program_id,
        data,
        custom(Groth16Error::PublicInputGreaterThanFieldSize),
    );
}

#[test]
fn rejects_proof_for_different_vk() {
    let (mollusk, program_id) = setup();
    // bsb22_1's honestly-negated proof points and input on the plain_1
    // selector: same byte layout minus commitment/pok, so the length
    // gate passes and the pairing fails against the wrong vk.
    let donor = fixture("bsb22_1");
    let mut data = Vec::with_capacity(1 + 256 + 32);
    data.push(0); // plain_1 selector
    data.extend_from_slice(&negate_g1_be(donor.proof_a));
    data.extend_from_slice(donor.proof_b);
    data.extend_from_slice(donor.proof_c);
    data.extend_from_slice(donor.public_inputs);
    expect_err(
        &mollusk,
        program_id,
        data,
        custom(Groth16Error::ProofVerificationFailed),
    );
}

#[test]
fn rejects_swapped_public_inputs() {
    let (mollusk, program_id) = setup();
    let f = fixture("plain_2");
    let mut data = build_ix_data(&f);
    // Input order is binding: X = [1, 2] verified as [2, 1] fails.
    let first: [u8; 32] = f.public_inputs.get(..32).unwrap().try_into().unwrap();
    let second: [u8; 32] = f.public_inputs.get(32..64).unwrap().try_into().unwrap();
    assert_ne!(first, second, "swap test needs distinct inputs");
    splice(&mut data, TAIL..TAIL + 32, &second);
    splice(&mut data, TAIL + 32..TAIL + 64, &first);
    expect_err(
        &mollusk,
        program_id,
        data,
        custom(Groth16Error::ProofVerificationFailed),
    );
}

// =========================================================================
// BSB22 (`verify_with_bsb22_commitment`)
// =========================================================================

#[test]
fn rejects_mutated_public_input_bsb22() {
    let (mollusk, program_id) = setup();
    let mut data = build_ix_data(&fixture("bsb22_1"));
    *data.last_mut().unwrap() ^= 1;
    expect_err(
        &mollusk,
        program_id,
        data,
        custom(Groth16Error::ProofVerificationFailed),
    );
}

#[test]
fn rejects_substituted_on_curve_commitment() {
    let (mollusk, program_id) = setup();
    let mut data = build_ix_data(&fixture("bsb22_1"));
    // Valid point, wrong commitment: hash-to-field diverges, so the
    // main pairing fails before the PoK check runs.
    splice(&mut data, BSB22_COMMITMENT, &G1_GENERATOR_BE);
    expect_err(
        &mollusk,
        program_id,
        data,
        custom(Groth16Error::ProofVerificationFailed),
    );
}

#[test]
fn rejects_off_curve_commitment() {
    let (mollusk, program_id) = setup();
    let mut data = build_ix_data(&fixture("bsb22_1"));
    // The commitment is added to kSum as a raw G1 point; the syscall
    // rejection is mapped to the dedicated error.
    splice(&mut data, BSB22_COMMITMENT, &NOT_ON_CURVE_G1_BE);
    expect_err(
        &mollusk,
        program_id,
        data,
        custom(Groth16Error::Bsb22InvalidCommitmentPoint),
    );
}

#[test]
fn rejects_mutated_pok() {
    let (mollusk, program_id) = setup();
    let mut data = build_ix_data(&fixture("bsb22_1"));
    // The PoK does not enter kSum, so the main pairing still passes;
    // the knowledge-proof pairing e(commitment, gSigmaNeg) * e(pok, g)
    // is what fails.
    splice(&mut data, POK, &G1_GENERATOR_BE);
    expect_err(
        &mollusk,
        program_id,
        data,
        custom(Groth16Error::CommitmentPokVerificationFailed),
    );
}

#[test]
fn rejects_swapped_commitment_and_pok() {
    let (mollusk, program_id) = setup();
    let f = fixture("bsb22_1");
    let mut data = build_ix_data(&f);
    let (commitment, pok) = f.commitment.expect("bsb22 fixture has commitment");
    // hash-to-field runs over the PoK bytes -> wrong challenge ->
    // wrong kSum -> main pairing fails before the PoK check.
    splice(&mut data, BSB22_COMMITMENT, pok);
    splice(&mut data, POK, commitment);
    expect_err(
        &mollusk,
        program_id,
        data,
        custom(Groth16Error::ProofVerificationFailed),
    );
}

// Sanity: the offsets above must match the program's layout; guards
// against silent drift if the instruction format changes.
#[test]
fn offsets_match_program_layout() {
    use bsb22_integration_program::PROOF_LEN;
    assert_eq!(PROOF_A, 1..1 + 64);
    assert_eq!(TAIL, 1 + PROOF_LEN);
    assert_eq!(BSB22_COMMITMENT, 1 + PROOF_LEN..1 + PROOF_LEN + 64);
    assert_eq!(POK, 1 + PROOF_LEN + 64..1 + PROOF_LEN + 128);
}
