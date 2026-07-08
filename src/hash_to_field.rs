//! BSB22 hash-to-field for the BN254 scalar field, byte-exact with
//! gnark-crypto's `ecc/bn254/fr/element.go::Hash` (which is what
//! gnark's BSB22 commitment verifier uses at
//! `backend/groth16/bn254/verify.go:84-95`).
//!
//! Algorithm:
//! 1. RFC 9380 `expand_message_xmd` over SHA-256 with `L = 48` bytes
//!    (16 + 32 — the BN254 Fr modulus is 254 bits, plus a 128-bit
//!    security margin).
//! 2. Interpret the 48-byte output as a big-endian integer and reduce
//!    mod r via `ark_bn254::Fr::from_be_bytes_mod_order`.
//!
//! gnark's `fr.Hash(msg, dst, 1)` returns the resulting field element
//! marshalled as 32 big-endian bytes; we return the same.
//!
//! The implementation is **allocation-free on the hot path**: the
//! three SHA-256 preimage buffers used inside `expand_message_xmd`
//! are stack-allocated `[u8; MAX_SCRATCH]` arrays, which keeps the
//! on-chain CU cost predictable and avoids BPF heap pressure.

use crate::errors::Groth16Error;
use ark_bn254::Fr;
use ark_ff::{BigInteger, PrimeField};

/// SHA-256 output size in bytes.
const B_IN_BYTES: usize = 32;
/// SHA-256 block size in bytes.
const R_IN_BYTES: usize = 64;
/// Per-element output length: 16-byte security margin + 32-byte modulus.
const L: usize = 48;
/// Upper bound on the `expand_message_xmd` preimage buffer size. Big
/// enough for any BSB22 call: `z_pad (64) + msg + l_i_b_str (2) +
/// 0x00 (1) + dst_prime (dst + 1)` with `msg <= ~150` bytes and `dst
/// <= ~30` bytes. The BSB22 caller uses msg=64 (one G1 point) and
/// dst="bsb22-commitment" (16 bytes), so the real usage is ~148.
const MAX_SCRATCH: usize = 256;

/// Compute SHA-256 of `input`.
///
/// On the Solana SBF target this calls the `sol_sha256` runtime
/// syscall directly via an inline `extern "C"` binding (the same
/// binding pinocchio uses internally — avoids pulling the
/// `solana-program` dep tree into `groth16-solana`). On host targets
/// (`cargo test`) it falls back to the pure-Rust `sha2` crate.
fn sha256(input: &[u8]) -> [u8; 32] {
    #[cfg(target_os = "solana")]
    {
        // Use pinocchio's `define_syscall!`-bound `sol_sha256` rather than a bare
        // `extern "C"` symbol: under the `static-syscalls` SBF ABI (platform-tools
        // v1.54+) syscalls are dispatched by compile-time code, so a plain extern
        // symbol does not resolve and silently leaves the output buffer zeroed.
        //   fn sol_sha256(vals: *const u8, val_len: u64, hash_result: *mut u8) -> u64
        // where `vals` is a pointer to an array of `(ptr, len)` pairs
        // in the form of `&[&[u8]]`; `val_len` is the number of pairs.
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
    #[cfg(not(target_os = "solana"))]
    {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(input);
        hasher.finalize().into()
    }
}

/// RFC 9380 `expand_message_xmd` with SHA-256, specialized to the one
/// output length this crate needs (`L = 48`, so `ell = 2`).
///
/// Mirrors `gnark-crypto/ecc/bn254/fr/element.go::Hash` (which calls
/// `hash.ExpandMsgXmd(msg, dst, lenInBytes)`) for the single
/// `lenInBytes == 48` case. This is **not** a general RFC 9380
/// implementation — if another output length is ever required,
/// re-generalize this function (restore the `len_in_bytes` parameter
/// and the `ell` computation) rather than duplicating it.
///
/// Returns `Err` only if the inputs are out-of-spec or would overflow
/// the stack scratch buffer: `dst` longer than 255 bytes, or the
/// preimage for any hash call exceeding [`MAX_SCRATCH`].
fn expand_message_xmd_sha256_l48(msg: &[u8], dst: &[u8]) -> Result<[u8; L], Groth16Error> {
    if dst.len() > 255 {
        return Err(Groth16Error::Bsb22HashToFieldFailed);
    }

    // DST_prime = dst || I2OSP(len(dst), 1)
    // Stack-allocate up to the spec-permitted 255+1 bytes.
    let mut dst_prime_buf = [0u8; 256];
    dst_prime_buf[..dst.len()].copy_from_slice(dst);
    dst_prime_buf[dst.len()] = dst.len() as u8;
    let dst_prime = &dst_prime_buf[..dst.len() + 1];

    // Single scratch buffer reused across all three SHA-256 calls.
    // Biggest preimage is b_0: 64 (z_pad) + msg + 2 (l_i_b_str) +
    // 1 (0x00) + dst_prime.len(). Bail if the caller gave us an
    // oversized message — BSB22 only ever hashes a 64-byte G1 point
    // so this is a defensive ceiling.
    let b0_len = R_IN_BYTES + msg.len() + 2 + 1 + dst_prime.len();
    if b0_len > MAX_SCRATCH {
        return Err(Groth16Error::Bsb22HashToFieldFailed);
    }
    let mut scratch = [0u8; MAX_SCRATCH];

    // b_0 = H(z_pad || msg || l_i_b_str || 0x00 || DST_prime)
    //   z_pad     = R_IN_BYTES zero bytes
    //   l_i_b_str = I2OSP(len_in_bytes, 2) = [0x00, 0x30] for len=48
    const L_I_B_STR: [u8; 2] = (L as u16).to_be_bytes();
    let mut offset = 0;
    // z_pad is already zero in the scratch buffer; just advance.
    offset += R_IN_BYTES;
    scratch[offset..offset + msg.len()].copy_from_slice(msg);
    offset += msg.len();
    scratch[offset..offset + 2].copy_from_slice(&L_I_B_STR);
    offset += 2;
    scratch[offset] = 0x00;
    offset += 1;
    scratch[offset..offset + dst_prime.len()].copy_from_slice(dst_prime);
    offset += dst_prime.len();
    debug_assert_eq!(offset, b0_len);
    let b0 = sha256(&scratch[..offset]);

    // b_1 = H(b_0 || I2OSP(1, 1) || DST_prime)
    let b1_len = B_IN_BYTES + 1 + dst_prime.len();
    // b1_len <= b0_len so no overflow possible, but stay defensive:
    debug_assert!(b1_len <= MAX_SCRATCH);
    let mut offset = 0;
    scratch[offset..offset + B_IN_BYTES].copy_from_slice(&b0);
    offset += B_IN_BYTES;
    scratch[offset] = 0x01;
    offset += 1;
    scratch[offset..offset + dst_prime.len()].copy_from_slice(dst_prime);
    offset += dst_prime.len();
    debug_assert_eq!(offset, b1_len);
    let b1 = sha256(&scratch[..offset]);

    // b_2 = H((b_0 XOR b_1) || I2OSP(2, 1) || DST_prime)
    let mut offset = 0;
    for j in 0..B_IN_BYTES {
        scratch[offset + j] = b0[j] ^ b1[j];
    }
    offset += B_IN_BYTES;
    scratch[offset] = 0x02;
    offset += 1;
    scratch[offset..offset + dst_prime.len()].copy_from_slice(dst_prime);
    offset += dst_prime.len();
    let b2 = sha256(&scratch[..offset]);

    // uniform_bytes = (b_1 || b_2)[..L]
    let mut out = [0u8; L];
    out[..B_IN_BYTES].copy_from_slice(&b1);
    out[B_IN_BYTES..L].copy_from_slice(&b2[..L - B_IN_BYTES]);
    Ok(out)
}

/// Compute gnark's `fr.Hash(msg, dst, 1)` over BN254 Fr and return the
/// resulting element as 32 big-endian bytes.
pub fn hash_to_field_bn254_fr(msg: &[u8], dst: &[u8]) -> Result<[u8; 32], Groth16Error> {
    let raw = expand_message_xmd_sha256_l48(msg, dst)?;
    let fr_elem = Fr::from_be_bytes_mod_order(&raw);
    let bi = fr_elem.into_bigint();
    let bytes = bi.to_bytes_be();
    let mut out = [0u8; 32];
    // Left-pad to 32 bytes (Fr always fits, but to_bytes_be may emit fewer
    // bytes for small values).
    out[32 - bytes.len()..].copy_from_slice(&bytes);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Golden vectors harvested from gnark-crypto v0.19.0 via the
    /// `TestHashToFieldGoldenVectors` Go test in
    /// `tests/bsb22/gnark-fixture/main_test.go`. Run that test and
    /// regenerate this list if you ever bump the gnark-crypto version.
    const DST: &[u8] = b"bsb22-commitment";

    #[test]
    fn matches_gnark_empty() {
        let got = hash_to_field_bn254_fr(b"", DST).unwrap();
        let want = hex_to_array("0cd710fca7c351e0f43221cbb4c4d2954de86c8e5bfd48f949cf791cec789074");
        assert_eq!(got, want);
    }

    #[test]
    fn matches_gnark_abc() {
        let got = hash_to_field_bn254_fr(b"abc", DST).unwrap();
        let want = hex_to_array("145f64e0f93255bfdd0c0edce7c545f5bc1c0c42dfc7f8963e921ba26ad82284");
        assert_eq!(got, want);
    }

    #[test]
    fn matches_gnark_zero_g1() {
        let msg = [0u8; 64];
        let got = hash_to_field_bn254_fr(&msg, DST).unwrap();
        let want = hex_to_array("1f1407ef745a0b1eae0567306b4560479d99b943b34072d983ad2ec6d37a1360");
        assert_eq!(got, want);
    }

    #[test]
    fn matches_gnark_sequential() {
        let mut msg = [0u8; 64];
        for (i, b) in msg.iter_mut().enumerate() {
            *b = i as u8;
        }
        let got = hash_to_field_bn254_fr(&msg, DST).unwrap();
        let want = hex_to_array("1db84f0dba489bb416bbfff0075b6a5912717f427be8d818d9a9a86375b9e91b");
        assert_eq!(got, want);
    }

    fn hex_to_array(s: &str) -> [u8; 32] {
        assert_eq!(s.len(), 64);
        let mut out = [0u8; 32];
        for i in 0..32 {
            out[i] = u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap();
        }
        out
    }
}
