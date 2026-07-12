//! On-chain Groth16 verifier program covering every benchmark shape.
//!
//! The first instruction-data byte selects the variant; the payload is
//! a fixed-size byte blob for that variant:
//!
//!   selector 0..=3  plain Groth16, N = 1/2/4/8 public inputs
//!     proof_a        [  0..64)
//!     proof_b        [ 64..192)
//!     proof_c        [192..256)
//!     public_inputs  [256..256 + N*32)
//!
//!   selector 4..=7  BSB22 (one Pedersen commitment), N = 1/2/4/8
//!     proof_a        [  0..64)
//!     proof_b        [ 64..192)
//!     proof_c        [192..256)
//!     commitment     [256..320)
//!     pok            [320..384)
//!     public_inputs  [384..384 + N*32)
//!
//! The verifying keys are baked into `.rodata` via `build.rs`, which
//! regenerates the deterministic gnark fixtures and runs
//! `vk::gnark::generate_bsb22_vk_file` per variant.
//!
//! With the `profile-program` feature, `#[profile]` wraps the verify
//! functions in the profiler's custom syscalls; only the mollusk bench
//! harness (tests/bench_cu.rs) understands those. Default builds are
//! unprofiled and run everywhere.

use groth16_solana::groth16::{Groth16Verifier, Groth16Verifyingkey};
use light_program_profiler::profile;
use solana_program::{
    account_info::AccountInfo, entrypoint, entrypoint::ProgramResult, msg,
    program_error::ProgramError, pubkey::Pubkey,
};

// Baked verifying keys, one per benchmark variant (see build.rs).
// Each generated file carries its own `use` imports, so each gets a
// private module to avoid E0252 collisions.
macro_rules! include_vk {
    ($module:ident, $file:expr, $name:ident) => {
        mod $module {
            include!(concat!(env!("OUT_DIR"), $file));
        }
        use $module::$name;
    };
}

include_vk!(vk_plain_1, "/vk_plain_1.rs", VK_PLAIN_1);
include_vk!(vk_plain_2, "/vk_plain_2.rs", VK_PLAIN_2);
include_vk!(vk_plain_4, "/vk_plain_4.rs", VK_PLAIN_4);
include_vk!(vk_plain_8, "/vk_plain_8.rs", VK_PLAIN_8);
include_vk!(vk_bsb22_1, "/vk_bsb22_1.rs", VK_BSB22_1);
include_vk!(vk_bsb22_2, "/vk_bsb22_2.rs", VK_BSB22_2);
include_vk!(vk_bsb22_4, "/vk_bsb22_4.rs", VK_BSB22_4);
include_vk!(vk_bsb22_8, "/vk_bsb22_8.rs", VK_BSB22_8);

/// proof_a + proof_b + proof_c
pub const PROOF_LEN: usize = 64 + 128 + 64;
/// commitment + pok
pub const COMMITMENT_LEN: usize = 64 + 64;

/// Fixture table shared by the litesvm tests (tests/litesvm_cu.rs)
/// and the mollusk CU bench (tests/bench_cu.rs). Host-only so the
/// fixture bytes are not baked into the .so.
#[cfg(not(target_os = "solana"))]
pub mod bench_fixtures {
    use groth16_solana::groth16::negate_g1_be;

    /// The id the test harnesses deploy the program under.
    pub const PROGRAM_ID_BYTES: [u8; 32] = [
        0xb5, 0xb2, 0x20, 0x00, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab,
        0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89,
        0xab, 0xcd,
    ];

    pub struct Fixture {
        pub label: &'static str,
        pub selector: u8,
        pub nr_inputs: usize,
        pub proof_a: &'static [u8; 64],
        pub proof_b: &'static [u8],
        pub proof_c: &'static [u8],
        /// (commitment, pok) for the BSB22 variants
        pub commitment: Option<(&'static [u8], &'static [u8])>,
        pub public_inputs: &'static [u8],
        /// Soft CU target for the unprofiled build.
        pub max_cu: u64,
    }

    macro_rules! fixture {
        ($name:expr) => {
            include_bytes!(concat!(env!("OUT_DIR"), "/bench-fixtures/", $name))
        };
    }

    macro_rules! plain {
        ($label:expr, $selector:expr, $n:expr, $max_cu:expr) => {
            Fixture {
                label: $label,
                selector: $selector,
                nr_inputs: $n,
                proof_a: fixture!(concat!($label, "_proof_a.bin")),
                proof_b: fixture!(concat!($label, "_proof_b.bin")),
                proof_c: fixture!(concat!($label, "_proof_c.bin")),
                commitment: None,
                public_inputs: fixture!(concat!($label, "_public_inputs.bin")),
                max_cu: $max_cu,
            }
        };
    }
    macro_rules! bsb22 {
        ($label:expr, $selector:expr, $n:expr, $max_cu:expr) => {
            Fixture {
                label: $label,
                selector: $selector,
                nr_inputs: $n,
                proof_a: fixture!(concat!($label, "_proof_a.bin")),
                proof_b: fixture!(concat!($label, "_proof_b.bin")),
                proof_c: fixture!(concat!($label, "_proof_c.bin")),
                commitment: Some((
                    fixture!(concat!($label, "_commitment.bin")),
                    fixture!(concat!($label, "_pok.bin")),
                )),
                public_inputs: fixture!(concat!($label, "_public_inputs.bin")),
                max_cu: $max_cu,
            }
        };
    }

    // Per-variant CU envelopes: last measured (BENCHMARKS.md) plus
    // ~10% headroom for syscall-cost churn across runtime versions.
    // Each extra public input is one alt_bn128 G1 mul+add (~2.2k CU);
    // BSB22 adds hash-to-field + one extra MSM step + the 2-pair PoK
    // pairing (~133k CU) on top of the plain verify.
    pub fn fixtures() -> [Fixture; 8] {
        [
            plain!("plain_1", 0, 1, 87_000),  // measured 78,393
            plain!("plain_2", 1, 2, 92_000),  // measured 82,812
            plain!("plain_4", 2, 4, 101_000), // measured 91,550
            plain!("plain_8", 3, 8, 120_000), // measured 109,039
            bsb22!("bsb22_1", 4, 1, 233_000), // measured 211,563
            bsb22!("bsb22_2", 5, 2, 238_000), // measured 216,024
            bsb22!("bsb22_4", 6, 4, 248_000), // measured 224,786
            bsb22!("bsb22_8", 7, 8, 267_000), // measured 242,266
        ]
    }

    /// Full instruction data for a fixture: selector byte, negated
    /// proof_a, proof_b, proof_c, (commitment, pok) for BSB22, then
    /// the public inputs.
    pub fn build_ix_data(f: &Fixture) -> Vec<u8> {
        let proof_a_neg = negate_g1_be(f.proof_a);
        let payload_len = match f.commitment {
            Some(_) => super::bsb22_payload_len(f.nr_inputs),
            None => super::plain_payload_len(f.nr_inputs),
        };
        let mut data = Vec::with_capacity(1 + payload_len);
        data.push(f.selector);
        data.extend_from_slice(&proof_a_neg);
        data.extend_from_slice(f.proof_b);
        data.extend_from_slice(f.proof_c);
        if let Some((commitment, pok)) = f.commitment {
            data.extend_from_slice(commitment);
            data.extend_from_slice(pok);
        }
        data.extend_from_slice(f.public_inputs);
        assert_eq!(data.len(), 1 + payload_len);
        data
    }
}

/// Payload length (excluding the selector byte) for a plain variant.
pub const fn plain_payload_len(nr_inputs: usize) -> usize {
    PROOF_LEN + nr_inputs * 32
}

/// Payload length (excluding the selector byte) for a BSB22 variant.
pub const fn bsb22_payload_len(nr_inputs: usize) -> usize {
    PROOF_LEN + COMMITMENT_LEN + nr_inputs * 32
}

entrypoint!(process_instruction);

fn process_instruction(
    _program_id: &Pubkey,
    _accounts: &[AccountInfo],
    instruction_data: &[u8],
) -> ProgramResult {
    let (&selector, payload) = instruction_data
        .split_first()
        .ok_or(ProgramError::InvalidInstructionData)?;

    match selector {
        0 => verify::<1>(payload, &VK_PLAIN_1),
        1 => verify::<2>(payload, &VK_PLAIN_2),
        2 => verify::<4>(payload, &VK_PLAIN_4),
        3 => verify::<8>(payload, &VK_PLAIN_8),
        4 => verify_with_bsb22_commitment::<1>(payload, &VK_BSB22_1),
        5 => verify_with_bsb22_commitment::<2>(payload, &VK_BSB22_2),
        6 => verify_with_bsb22_commitment::<4>(payload, &VK_BSB22_4),
        7 => verify_with_bsb22_commitment::<8>(payload, &VK_BSB22_8),
        _ => {
            msg!("unknown variant selector: {}", selector);
            Err(ProgramError::InvalidInstructionData)
        }
    }
}

/// Split a fixed-size array off the front of `data`.
fn take<'a, const K: usize>(data: &mut &'a [u8]) -> Result<&'a [u8; K], ProgramError> {
    let (head, rest) = data
        .split_at_checked(K)
        .ok_or(ProgramError::InvalidInstructionData)?;
    *data = rest;
    head.try_into()
        .map_err(|_| ProgramError::InvalidInstructionData)
}

/// Parse exactly `N` 32-byte public inputs from the remaining payload.
fn parse_public_inputs<const N: usize>(data: &[u8]) -> Result<[[u8; 32]; N], ProgramError> {
    if data.len() != N * 32 {
        msg!(
            "invalid public input len: got {}, want {}",
            data.len(),
            N * 32
        );
        return Err(ProgramError::InvalidInstructionData);
    }
    let mut out = [[0u8; 32]; N];
    for (dst, src) in out.iter_mut().zip(data.chunks_exact(32)) {
        dst.copy_from_slice(src);
    }
    Ok(out)
}

#[profile]
fn verify<const N: usize>(mut payload: &[u8], vk: &Groth16Verifyingkey) -> ProgramResult {
    let proof_a: &[u8; 64] = take(&mut payload)?;
    let proof_b: &[u8; 128] = take(&mut payload)?;
    let proof_c: &[u8; 64] = take(&mut payload)?;
    let public_inputs: [[u8; 32]; N] = parse_public_inputs(payload)?;

    let mut verifier = Groth16Verifier::new(proof_a, proof_b, proof_c, &public_inputs, vk)
        .map_err(|e| {
            msg!("Groth16Verifier::new failed: {:?}", e);
            ProgramError::Custom(u32::from(e))
        })?;
    verifier.verify().map_err(|e| {
        msg!("verify failed: {:?}", e);
        ProgramError::Custom(u32::from(e))
    })
}

#[profile]
fn verify_with_bsb22_commitment<const N: usize>(
    mut payload: &[u8],
    vk: &Groth16Verifyingkey,
) -> ProgramResult {
    let proof_a: &[u8; 64] = take(&mut payload)?;
    let proof_b: &[u8; 128] = take(&mut payload)?;
    let proof_c: &[u8; 64] = take(&mut payload)?;
    let commitment: &[u8; 64] = take(&mut payload)?;
    let pok: &[u8; 64] = take(&mut payload)?;
    let public_inputs: [[u8; 32]; N] = parse_public_inputs(payload)?;

    let mut verifier = Groth16Verifier::new_with_commitment(
        proof_a,
        proof_b,
        proof_c,
        commitment,
        pok,
        &public_inputs,
        vk,
    )
    .map_err(|e| {
        msg!("new_with_commitment failed: {:?}", e);
        ProgramError::Custom(u32::from(e))
    })?;
    verifier.verify().map_err(|e| {
        msg!("verify failed: {:?}", e);
        ProgramError::Custom(u32::from(e))
    })
}
