//! Differential proptests for `hash_to_field_bn254_fr` against
//! gnark-crypto's `ecc/bn254/fr/hash_to_field` (the exact package
//! gnark's Groth16 verifier uses to derive the BSB22 commitment
//! challenge), called through the cgo fixture's `HashToField` export.
//!
//! The Rust implementation is const-generic over message and DST
//! length, so lengths cannot vary at runtime; instead each property
//! randomizes the *contents* at a fixed shape chosen to exercise a
//! distinct region of the scratch-buffer offset arithmetic in
//! `expand_message_xmd_sha256_l48`:
//!
//! - 64/16: the real BSB22 shape (one G1 point, "bsb22-commitment")
//! - 33/5:  odd, non-block-aligned offsets
//!
//! The complementary fixed golden vectors live in
//! `src/hash_to_field.rs`; these properties cover random contents.

use groth16_solana::hash_to_field_bn254_fr;
use groth16_solana_tests_bsb22::bind;
use proptest::prelude::*;
use std::ffi::CStr;
use std::os::raw::c_int;

/// Safe wrapper around the fixture's `HashToField` export. Panics on
/// a non-null error string (test fixtures shouldn't fail).
fn ffi_hash_to_field(msg: &[u8], dst: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    let err = unsafe {
        bind::HashToField(
            msg.as_ptr() as *mut _,
            msg.len() as c_int,
            dst.as_ptr() as *mut _,
            dst.len() as c_int,
            out.as_mut_ptr(),
        )
    };
    if !err.is_null() {
        let text = unsafe { CStr::from_ptr(err).to_string_lossy().into_owned() };
        unsafe { bind::FreeString(err) };
        panic!("HashToField failed: {}", text);
    }
    out
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(1_000_000))]

    /// The real BSB22 shape: a 64-byte G1 commitment preimage and a
    /// 16-byte DST (gnark uses b"bsb22-commitment").
    #[test]
    fn matches_gnark_bsb22_shape(msg in any::<[u8; 64]>(), dst in any::<[u8; 16]>()) {
        prop_assert_eq!(hash_to_field_bn254_fr(&msg, &dst), ffi_hash_to_field(&msg, &dst));
    }

    /// Non-block-aligned message and DST lengths hit different
    /// scratch-buffer offsets in every `expand_message_xmd` round.
    #[test]
    fn matches_gnark_odd_offsets(msg in any::<[u8; 33]>(), dst in any::<[u8; 5]>()) {
        prop_assert_eq!(hash_to_field_bn254_fr(&msg, &dst), ffi_hash_to_field(&msg, &dst));
    }
}
