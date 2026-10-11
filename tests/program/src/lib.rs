//! Groth16 verifier program covering every benchmark shape.
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
//!   selector 4..=7  BSB22 via verify(), N = 1/2/4/8
//!   selector 8..=11 BSB22 via verify_opt(), N = 1/2/4/8
//!   selector 12..=15 verify_opt with a checked hash hint
//!   selector 16..=19 verify_opt with a pinned key digest
//!   selector 20..=23 verify_opt with both accelerators
//!     all use one Pedersen commitment; hint modes append 49 bytes after inputs:
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

use groth16_solana::groth16::{
    Bsb22HashHint, Groth16Verifier, Groth16Verifyingkey, VerifyOptOptions,
};
use light_program_profiler::profile;
use solana_program::{
    account_info::AccountInfo, entrypoint, entrypoint::ProgramResult, msg,
    program_error::ProgramError, pubkey::Pubkey,
};

// Baked verifying keys, one per benchmark variant (see build.rs).
// Each generated file contains its own `use` imports, so each gets a
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

/// Fixture table for the mollusk CU bench (tests/bench_cu.rs).
/// Host-only so the fixture bytes are not baked into the .so.
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
        pub hash_hint: Option<&'static [u8]>,
        pub label: &'static str,
        pub selector: u8,
        pub nr_inputs: usize,
        pub proof_a: &'static [u8; 64],
        pub proof_b: &'static [u8],
        pub proof_c: &'static [u8],
        /// (commitment, pok) for the BSB22 variants
        pub commitment: Option<(&'static [u8], &'static [u8])>,
        pub public_inputs: &'static [u8],
    }

    macro_rules! fixture {
        ($name:expr) => {
            include_bytes!(concat!(env!("OUT_DIR"), "/bench-fixtures/", $name))
        };
    }

    macro_rules! plain {
        ($label:expr, $selector:expr, $n:expr) => {
            Fixture {
                label: $label,
                selector: $selector,
                nr_inputs: $n,
                proof_a: fixture!(concat!($label, "_proof_a.bin")),
                proof_b: fixture!(concat!($label, "_proof_b.bin")),
                proof_c: fixture!(concat!($label, "_proof_c.bin")),
                commitment: None,
                hash_hint: None,
                public_inputs: fixture!(concat!($label, "_public_inputs.bin")),
            }
        };
    }
    macro_rules! bsb22 {
        ($label:expr, $selector:expr, $n:expr) => {
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
                hash_hint: None,
            }
        };
    }

    // CU regression tracking: BENCHMARKS.md is regenerated by the
    // bench and committed; CI fails on any uncommitted diff, so cost
    // changes must be re-baselined.
    pub fn fixtures() -> [Fixture; 24] {
        [
            plain!("plain_1", 0, 1),
            plain!("plain_2", 1, 2),
            plain!("plain_4", 2, 4),
            plain!("plain_8", 3, 8),
            bsb22!("bsb22_1", 4, 1),
            bsb22!("bsb22_2", 5, 2),
            bsb22!("bsb22_4", 6, 4),
            bsb22!("bsb22_8", 7, 8),
            Fixture {
                label: "bsb22_opt_1",
                selector: 8,
                ..bsb22!("bsb22_1", 4, 1)
            },
            Fixture {
                label: "bsb22_opt_2",
                selector: 9,
                ..bsb22!("bsb22_2", 5, 2)
            },
            Fixture {
                label: "bsb22_opt_4",
                selector: 10,
                ..bsb22!("bsb22_4", 6, 4)
            },
            Fixture {
                label: "bsb22_opt_8",
                selector: 11,
                ..bsb22!("bsb22_8", 7, 8)
            },
            Fixture {
                label: "bsb22_hint_1",
                selector: 12,
                hash_hint: Some(fixture!("bsb22_1_hash_hint.bin")),
                ..bsb22!("bsb22_1", 4, 1)
            },
            Fixture {
                label: "bsb22_hint_2",
                selector: 13,
                hash_hint: Some(fixture!("bsb22_2_hash_hint.bin")),
                ..bsb22!("bsb22_2", 5, 2)
            },
            Fixture {
                label: "bsb22_hint_4",
                selector: 14,
                hash_hint: Some(fixture!("bsb22_4_hash_hint.bin")),
                ..bsb22!("bsb22_4", 6, 4)
            },
            Fixture {
                label: "bsb22_hint_8",
                selector: 15,
                hash_hint: Some(fixture!("bsb22_8_hash_hint.bin")),
                ..bsb22!("bsb22_8", 7, 8)
            },
            Fixture {
                label: "bsb22_cached_1",
                selector: 16,
                hash_hint: None,
                ..bsb22!("bsb22_1", 4, 1)
            },
            Fixture {
                label: "bsb22_cached_2",
                selector: 17,
                hash_hint: None,
                ..bsb22!("bsb22_2", 5, 2)
            },
            Fixture {
                label: "bsb22_cached_4",
                selector: 18,
                hash_hint: None,
                ..bsb22!("bsb22_4", 6, 4)
            },
            Fixture {
                label: "bsb22_cached_8",
                selector: 19,
                hash_hint: None,
                ..bsb22!("bsb22_8", 7, 8)
            },
            Fixture {
                label: "bsb22_hint_cached_1",
                selector: 20,
                hash_hint: Some(fixture!("bsb22_1_hash_hint.bin")),
                ..bsb22!("bsb22_1", 4, 1)
            },
            Fixture {
                label: "bsb22_hint_cached_2",
                selector: 21,
                hash_hint: Some(fixture!("bsb22_2_hash_hint.bin")),
                ..bsb22!("bsb22_2", 5, 2)
            },
            Fixture {
                label: "bsb22_hint_cached_4",
                selector: 22,
                hash_hint: Some(fixture!("bsb22_4_hash_hint.bin")),
                ..bsb22!("bsb22_4", 6, 4)
            },
            Fixture {
                label: "bsb22_hint_cached_8",
                selector: 23,
                hash_hint: Some(fixture!("bsb22_8_hash_hint.bin")),
                ..bsb22!("bsb22_8", 7, 8)
            },
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
        let payload_len = payload_len + f.hash_hint.map_or(0, |hint| hint.len());
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
        if let Some(hint) = f.hash_hint {
            data.extend_from_slice(hint);
        }
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
        4 => verify_with_bsb22_commitment::<1, 0>(
            payload,
            &VK_BSB22_1,
            &vk_bsb22_1::VK_BSB22_1_KEY_HASH,
        ),
        5 => verify_with_bsb22_commitment::<2, 0>(
            payload,
            &VK_BSB22_2,
            &vk_bsb22_2::VK_BSB22_2_KEY_HASH,
        ),
        6 => verify_with_bsb22_commitment::<4, 0>(
            payload,
            &VK_BSB22_4,
            &vk_bsb22_4::VK_BSB22_4_KEY_HASH,
        ),
        7 => verify_with_bsb22_commitment::<8, 0>(
            payload,
            &VK_BSB22_8,
            &vk_bsb22_8::VK_BSB22_8_KEY_HASH,
        ),
        8 => verify_with_bsb22_commitment::<1, 1>(
            payload,
            &VK_BSB22_1,
            &vk_bsb22_1::VK_BSB22_1_KEY_HASH,
        ),
        9 => verify_with_bsb22_commitment::<2, 1>(
            payload,
            &VK_BSB22_2,
            &vk_bsb22_2::VK_BSB22_2_KEY_HASH,
        ),
        10 => verify_with_bsb22_commitment::<4, 1>(
            payload,
            &VK_BSB22_4,
            &vk_bsb22_4::VK_BSB22_4_KEY_HASH,
        ),
        11 => verify_with_bsb22_commitment::<8, 1>(
            payload,
            &VK_BSB22_8,
            &vk_bsb22_8::VK_BSB22_8_KEY_HASH,
        ),
        12 => verify_with_bsb22_commitment::<1, 2>(
            payload,
            &VK_BSB22_1,
            &vk_bsb22_1::VK_BSB22_1_KEY_HASH,
        ),
        13 => verify_with_bsb22_commitment::<2, 2>(
            payload,
            &VK_BSB22_2,
            &vk_bsb22_2::VK_BSB22_2_KEY_HASH,
        ),
        14 => verify_with_bsb22_commitment::<4, 2>(
            payload,
            &VK_BSB22_4,
            &vk_bsb22_4::VK_BSB22_4_KEY_HASH,
        ),
        15 => verify_with_bsb22_commitment::<8, 2>(
            payload,
            &VK_BSB22_8,
            &vk_bsb22_8::VK_BSB22_8_KEY_HASH,
        ),
        16 => verify_with_bsb22_commitment::<1, 3>(
            payload,
            &VK_BSB22_1,
            &vk_bsb22_1::VK_BSB22_1_KEY_HASH,
        ),
        17 => verify_with_bsb22_commitment::<2, 3>(
            payload,
            &VK_BSB22_2,
            &vk_bsb22_2::VK_BSB22_2_KEY_HASH,
        ),
        18 => verify_with_bsb22_commitment::<4, 3>(
            payload,
            &VK_BSB22_4,
            &vk_bsb22_4::VK_BSB22_4_KEY_HASH,
        ),
        19 => verify_with_bsb22_commitment::<8, 3>(
            payload,
            &VK_BSB22_8,
            &vk_bsb22_8::VK_BSB22_8_KEY_HASH,
        ),
        20 => verify_with_bsb22_commitment::<1, 4>(
            payload,
            &VK_BSB22_1,
            &vk_bsb22_1::VK_BSB22_1_KEY_HASH,
        ),
        21 => verify_with_bsb22_commitment::<2, 4>(
            payload,
            &VK_BSB22_2,
            &vk_bsb22_2::VK_BSB22_2_KEY_HASH,
        ),
        22 => verify_with_bsb22_commitment::<4, 4>(
            payload,
            &VK_BSB22_4,
            &vk_bsb22_4::VK_BSB22_4_KEY_HASH,
        ),
        23 => verify_with_bsb22_commitment::<8, 4>(
            payload,
            &VK_BSB22_8,
            &vk_bsb22_8::VK_BSB22_8_KEY_HASH,
        ),
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
fn verify_with_bsb22_commitment<const N: usize, const MODE: u8>(
    mut payload: &[u8],
    vk: &Groth16Verifyingkey,
    key_hash: &[u8; 32],
) -> ProgramResult {
    let proof_a: &[u8; 64] = take(&mut payload)?;
    let proof_b: &[u8; 128] = take(&mut payload)?;
    let proof_c: &[u8; 64] = take(&mut payload)?;
    let commitment: &[u8; 64] = take(&mut payload)?;
    let pok: &[u8; 64] = take(&mut payload)?;
    let (public_bytes, mut hint_bytes) = payload
        .split_at_checked(N * 32)
        .ok_or(ProgramError::InvalidInstructionData)?;
    let public_inputs: [[u8; 32]; N] = parse_public_inputs(public_bytes)?;
    let hint = if MODE == 2 || MODE == 4 {
        Some(Bsb22HashHint {
            quotient: *take(&mut hint_bytes)?,
            remainder: *take(&mut hint_bytes)?,
        })
    } else {
        None
    };
    if !hint_bytes.is_empty() {
        return Err(ProgramError::InvalidInstructionData);
    }

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
    let result = if MODE == 0 {
        verifier.verify()
    } else {
        verifier.verify_opt_with_options(VerifyOptOptions {
            hash_hint: hint.as_ref(),
            key_hash: if MODE == 3 || MODE == 4 {
                Some(key_hash)
            } else {
                None
            },
        })
    };
    result.map_err(|e| {
        msg!("verify failed: {:?}", e);
        ProgramError::Custom(u32::from(e))
    })
}
