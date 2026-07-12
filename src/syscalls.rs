use crate::errors::Groth16Error;

#[cfg(target_os = "solana")]
mod inner {
    use super::Groth16Error;
    use pinocchio::syscalls::{sol_alt_bn128_compression, sol_alt_bn128_group_op};

    const G1_ADD_BE: u64 = 0;
    const G1_MUL_BE: u64 = 2;
    const PAIRING_BE: u64 = 3;
    const G1_DECOMPRESS_BE: u64 = 1;
    const G2_DECOMPRESS_BE: u64 = 3;

    pub fn g1_addition_be(input: &[u8; 128]) -> Result<[u8; 64], Groth16Error> {
        let mut result = [0u8; 64];
        let rc = unsafe {
            sol_alt_bn128_group_op(
                G1_ADD_BE,
                input.as_ptr(),
                input.len() as u64,
                result.as_mut_ptr(),
            )
        };
        if rc != 0 {
            return Err(Groth16Error::PreparingInputsG1AdditionFailed);
        }
        Ok(result)
    }

    pub fn g1_multiplication_be(input: &[u8; 96]) -> Result<[u8; 64], Groth16Error> {
        let mut result = [0u8; 64];
        let rc = unsafe {
            sol_alt_bn128_group_op(
                G1_MUL_BE,
                input.as_ptr(),
                input.len() as u64,
                result.as_mut_ptr(),
            )
        };
        if rc != 0 {
            return Err(Groth16Error::PreparingInputsG1MulFailed);
        }
        Ok(result)
    }

    pub fn pairing_be(input: &[u8]) -> Result<[u8; 32], Groth16Error> {
        let mut result = [0u8; 32];
        let rc = unsafe {
            sol_alt_bn128_group_op(
                PAIRING_BE,
                input.as_ptr(),
                input.len() as u64,
                result.as_mut_ptr(),
            )
        };
        if rc != 0 {
            return Err(Groth16Error::ProofVerificationFailed);
        }
        Ok(result)
    }

    pub fn g1_decompress_be(input: &[u8; 32]) -> Result<[u8; 64], Groth16Error> {
        let mut result = [0u8; 64];
        let rc = unsafe {
            sol_alt_bn128_compression(
                G1_DECOMPRESS_BE,
                input.as_ptr(),
                input.len() as u64,
                result.as_mut_ptr(),
            )
        };
        if rc != 0 {
            return Err(Groth16Error::DecompressingG1Failed);
        }
        Ok(result)
    }

    pub fn g2_decompress_be(input: &[u8; 64]) -> Result<[u8; 128], Groth16Error> {
        let mut result = [0u8; 128];
        let rc = unsafe {
            sol_alt_bn128_compression(
                G2_DECOMPRESS_BE,
                input.as_ptr(),
                input.len() as u64,
                result.as_mut_ptr(),
            )
        };
        if rc != 0 {
            return Err(Groth16Error::DecompressingG2Failed);
        }
        Ok(result)
    }

    /// Compute SHA-256 of `input` via the `sol_sha256` runtime syscall.
    ///
    /// Uses pinocchio's `define_syscall!`-bound `sol_sha256` rather than a bare
    /// `extern "C"` symbol: under the `static-syscalls` SBF ABI (platform-tools
    /// v1.54+) syscalls are dispatched by compile-time code, so a plain extern
    /// symbol does not resolve and silently leaves the output buffer zeroed.
    ///   fn sol_sha256(vals: *const u8, val_len: u64, hash_result: *mut u8) -> u64
    /// where `vals` is a pointer to an array of `(ptr, len)` pairs
    /// in the form of `&[&[u8]]`; `val_len` is the number of pairs.
    #[cfg(feature = "bsb22")]
    pub(crate) fn sha256(input: &[u8]) -> [u8; 32] {
        use pinocchio::syscalls::sol_sha256;

        let slices: [&[u8]; 1] = [input];
        let mut out = [0u8; 32];
        // SAFETY: `slices` lives until after the syscall returns;
        // `out` is a fixed-size 32-byte buffer matching the SHA-256
        // digest length the runtime writes.
        unsafe {
            sol_sha256(
                slices.as_ptr() as *const u8,
                slices.len() as u64,
                out.as_mut_ptr(),
            );
        }
        out
    }
}

#[cfg(not(target_os = "solana"))]
mod inner {
    use super::Groth16Error;
    use solana_bn254::compression::prelude::{
        alt_bn128_g1_decompress_be, alt_bn128_g2_decompress_be,
    };
    use solana_bn254::prelude::{
        alt_bn128_g1_addition_be as bn254_g1_add, alt_bn128_g1_multiplication_be as bn254_g1_mul,
        alt_bn128_pairing_be as bn254_pairing,
    };

    pub fn g1_addition_be(input: &[u8; 128]) -> Result<[u8; 64], Groth16Error> {
        let result =
            bn254_g1_add(input).map_err(|_| Groth16Error::PreparingInputsG1AdditionFailed)?;
        result
            .try_into()
            .map_err(|_| Groth16Error::PreparingInputsG1AdditionFailed)
    }

    pub fn g1_multiplication_be(input: &[u8; 96]) -> Result<[u8; 64], Groth16Error> {
        let result = bn254_g1_mul(input).map_err(|_| Groth16Error::PreparingInputsG1MulFailed)?;
        result
            .try_into()
            .map_err(|_| Groth16Error::PreparingInputsG1MulFailed)
    }

    pub fn pairing_be(input: &[u8]) -> Result<[u8; 32], Groth16Error> {
        let result = bn254_pairing(input).map_err(|_| Groth16Error::ProofVerificationFailed)?;
        result
            .try_into()
            .map_err(|_| Groth16Error::ProofVerificationFailed)
    }

    pub fn g1_decompress_be(input: &[u8; 32]) -> Result<[u8; 64], Groth16Error> {
        alt_bn128_g1_decompress_be(input).map_err(|_| Groth16Error::DecompressingG1Failed)
    }

    pub fn g2_decompress_be(input: &[u8; 64]) -> Result<[u8; 128], Groth16Error> {
        alt_bn128_g2_decompress_be(input).map_err(|_| Groth16Error::DecompressingG2Failed)
    }

    /// Compute SHA-256 of `input`. Host-side fallback for the
    /// `sol_sha256` syscall, backed by the pure-Rust `sha2` crate.
    #[cfg(feature = "bsb22")]
    pub(crate) fn sha256(input: &[u8]) -> [u8; 32] {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(input);
        hasher.finalize().into()
    }
}

pub use inner::*;
