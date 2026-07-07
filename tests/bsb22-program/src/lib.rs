//! On-chain BSB22 Groth16 verifier program.
//!
//! The instruction data layout is a fixed-size byte blob:
//!
//!   proof_a       [ 0..64)
//!   proof_b       [64..192)
//!   proof_c      [192..256)
//!   commitment   [256..320)
//!   pok          [320..384)
//!   public_input [384..416)
//!
//! Total: 416 bytes. The verifying key is baked into `.rodata` via
//! `build.rs` → `vk::gnark::generate_bsb22_vk_file`.

use groth16_solana::groth16::Groth16Verifier;
use solana_program::{
    account_info::AccountInfo, entrypoint, entrypoint::ProgramResult, msg,
    program_error::ProgramError, pubkey::Pubkey,
};

// Baked BSB22 verifying key, generated at build time by
// groth16_solana::vk::gnark::generate_bsb22_vk_file from the
// committed tests/fixtures/bsb22/vk_variant_1.bin snapshot (see build.rs).
include!(concat!(env!("OUT_DIR"), "/verifying_key.rs"));

pub const IX_LEN: usize = 64 + 128 + 64 + 64 + 64 + 32;

entrypoint!(process_instruction);

fn process_instruction(
    _program_id: &Pubkey,
    _accounts: &[AccountInfo],
    instruction_data: &[u8],
) -> ProgramResult {
    if instruction_data.len() != IX_LEN {
        msg!(
            "invalid ix len: got {}, want {}",
            instruction_data.len(),
            IX_LEN
        );
        return Err(ProgramError::InvalidInstructionData);
    }

    let proof_a: &[u8; 64] = instruction_data[0..64].try_into().unwrap();
    let proof_b: &[u8; 128] = instruction_data[64..192].try_into().unwrap();
    let proof_c: &[u8; 64] = instruction_data[192..256].try_into().unwrap();
    let commitment: &[u8; 64] = instruction_data[256..320].try_into().unwrap();
    let pok: &[u8; 64] = instruction_data[320..384].try_into().unwrap();
    let public_input: [u8; 32] = instruction_data[384..416].try_into().unwrap();
    let public_inputs: [[u8; 32]; 1] = [public_input];

    let mut verifier = Groth16Verifier::new_with_commitment(
        proof_a,
        proof_b,
        proof_c,
        commitment,
        pok,
        &public_inputs,
        &VERIFYINGKEY,
    )
    .map_err(|e| {
        msg!("new_with_commitment failed: {:?}", e);
        ProgramError::Custom(u32::from(e))
    })?;

    verifier.verify().map_err(|e| {
        msg!("verify failed: {:?}", e);
        ProgramError::Custom(u32::from(e))
    })?;

    msg!("BSB22 Groth16 proof verified");
    Ok(())
}
