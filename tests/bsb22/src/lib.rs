//! BSB22 commitment integration tests for `groth16-solana`.
//!
//! These tests live in their own workspace member because they have a
//! cgo dependency: the in-repo gnark fixture (`gnark-fixture/`) is
//! compiled to a C static archive at build time, bindgen generates
//! Rust FFI bindings, and each test calls `Setup` + `Prove` directly
//! to obtain real-world bytes for one of the three lookup variants.
//!
//! The chain of trust runs top-to-bottom: gnark's own
//! `groth16.Verify` is exercised inside `gnark-fixture/main_test.go`
//! (the smoke test that anchored task 2). If the in-repo verifier
//! disagrees with gnark on the same proof bytes, the bug is in our
//! port — not in the fixture.
//!
//! All tests are gated on the `bsb22` feature being enabled in the
//! parent crate (which the `Cargo.toml` here forces).

#[allow(
    non_camel_case_types,
    non_snake_case,
    non_upper_case_globals,
    dead_code
)]
mod bind {
    include!(concat!(env!("OUT_DIR"), "/bindings.rs"));
}

#[cfg(test)]
mod tests {
    use super::bind;
    use groth16_solana::errors::Groth16Error;
    use groth16_solana::gnark_vk_parser::parse_gnark_vk_bytes;
    use groth16_solana::groth16::{negate_g1_be, Groth16Verifier};
    use std::ffi::{CStr, CString};
    use std::os::raw::{c_char, c_int};
    use std::path::Path;
    use std::ptr;

    /// Run gnark Setup for a variant. The vk and pk get written to
    /// `dir/vk_{variant}.bin` and `dir/pk_{variant}.bin`. Panics on
    /// failure (test fixtures shouldn't fail).
    fn ffi_setup(variant: c_int, dir: &Path) {
        let dir_c = CString::new(dir.to_str().expect("path utf8")).unwrap();
        let err = unsafe { bind::Setup(variant, dir_c.as_ptr() as *mut c_char) };
        if !err.is_null() {
            let msg = unsafe { CStr::from_ptr(err).to_string_lossy().into_owned() };
            unsafe { bind::FreeString(err) };
            panic!("Setup variant={} failed: {}", variant, msg);
        }
    }

    /// Run gnark Prove for a variant with public input X. Returns the
    /// owned C struct for the caller to inspect; the caller must free
    /// via [`FfiProveResult::drop`].
    fn ffi_prove(variant: c_int, x: u64, dir: &Path) -> FfiProveResult {
        let dir_c = CString::new(dir.to_str().expect("path utf8")).unwrap();
        let x_c = CString::new(x.to_string()).unwrap();
        let raw = unsafe {
            bind::Prove(
                variant,
                x_c.as_ptr() as *mut c_char,
                dir_c.as_ptr() as *mut c_char,
            )
        };
        assert!(!raw.is_null(), "Prove returned NULL");
        FfiProveResult { raw }
    }

    /// Run gnark NativeVerify for a variant with public input X. Returns
    /// `Ok(())` if gnark's own verifier accepts the proof; this is the
    /// chain-of-trust anchor.
    fn ffi_native_verify(variant: c_int, x: u64, dir: &Path) -> Result<(), String> {
        let dir_c = CString::new(dir.to_str().expect("path utf8")).unwrap();
        let x_c = CString::new(x.to_string()).unwrap();
        let err = unsafe {
            bind::NativeVerify(
                variant,
                x_c.as_ptr() as *mut c_char,
                dir_c.as_ptr() as *mut c_char,
            )
        };
        if err.is_null() {
            Ok(())
        } else {
            let msg = unsafe { CStr::from_ptr(err).to_string_lossy().into_owned() };
            unsafe { bind::FreeString(err) };
            Err(msg)
        }
    }

    /// RAII wrapper around `*mut C_ProveResult`. Frees on drop.
    struct FfiProveResult {
        raw: *mut bind::C_ProveResult,
    }

    impl FfiProveResult {
        fn proof_a(&self) -> [u8; 64] {
            unsafe { (*self.raw).proof_a }
        }
        fn proof_b(&self) -> [u8; 128] {
            unsafe { (*self.raw).proof_b }
        }
        fn proof_c(&self) -> [u8; 64] {
            unsafe { (*self.raw).proof_c }
        }
        fn commitment(&self) -> [u8; 64] {
            unsafe { (*self.raw).commitment }
        }
        fn commitment_pok(&self) -> [u8; 64] {
            unsafe { (*self.raw).commitment_pok }
        }
        fn public_input(&self) -> [u8; 32] {
            unsafe { (*self.raw).public_input }
        }
        fn error(&self) -> Option<String> {
            let err = unsafe { (*self.raw).error };
            if err.is_null() {
                None
            } else {
                Some(unsafe { CStr::from_ptr(err).to_string_lossy().into_owned() })
            }
        }
    }

    impl Drop for FfiProveResult {
        fn drop(&mut self) {
            if !self.raw.is_null() {
                unsafe { bind::FreeProveResult(self.raw) };
                self.raw = ptr::null_mut();
            }
        }
    }

    // -------------------------------------------------------------------
    // Shared fixture: Setup + Prove + parse vk for one variant.
    // -------------------------------------------------------------------

    struct VariantFixture {
        vk_bytes: Vec<u8>,
        proof: FfiProveResult,
    }

    fn setup_variant(variant: c_int) -> (tempfile::TempDir, VariantFixture) {
        let dir = tempfile::tempdir().expect("tempdir");
        ffi_setup(variant, dir.path());
        let proof = ffi_prove(variant, 7, dir.path());
        if let Some(err) = proof.error() {
            panic!("Prove variant={} returned error: {}", variant, err);
        }
        // Native verify is the chain-of-trust anchor: if gnark
        // doesn't accept the proof, no port can.
        ffi_native_verify(variant, 7, dir.path()).expect("native verify");

        let vk_path = dir.path().join(format!("vk_{}.bin", variant));
        let vk_bytes = std::fs::read(&vk_path).expect("read vk.bin");

        let fixture = VariantFixture { vk_bytes, proof };
        (dir, fixture)
    }

    fn assert_verifies(variant: c_int) {
        let (_dir, fix) = setup_variant(variant);
        let vk = parse_gnark_vk_bytes(&fix.vk_bytes).expect("parse vk");
        assert!(
            vk.vk_commitment_g2.is_some(),
            "variant {} should be BSB22",
            variant
        );
        let borrowed = vk.as_borrowed();

        let proof_a = fix.proof.proof_a();
        let proof_b = fix.proof.proof_b();
        let proof_c = fix.proof.proof_c();
        let commitment = fix.proof.commitment();
        let pok = fix.proof.commitment_pok();
        let public_input = fix.proof.public_input();
        let public_inputs: [[u8; 32]; 1] = [public_input];

        // gnark emits proof.Ar in its non-negated form; the
        // on-chain verifier runs the standard 4-pair Groth16 check
        // which folds e(alpha, beta) onto the LHS, so it expects
        // -Ar. Mirror the negation the vanilla groth16-solana test
        // does, via the `negate_g1_be` public helper.
        let proof_a_neg = negate_g1_be(&proof_a);

        let mut verifier = Groth16Verifier::new_with_commitment(
            &proof_a_neg,
            &proof_b,
            &proof_c,
            &commitment,
            &pok,
            &public_inputs,
            &borrowed,
        )
        .expect("new_with_commitment");
        verifier.verify().expect("verify");
    }

    #[test]
    fn variant_1_verifies() {
        assert_verifies(1);
    }

    #[test]
    fn variant_2_verifies() {
        assert_verifies(2);
    }

    #[test]
    fn variant_3_verifies() {
        assert_verifies(3);
    }

    #[test]
    fn variant_1_rejects_mutated_public_input() {
        let (_dir, fix) = setup_variant(1);
        let vk = parse_gnark_vk_bytes(&fix.vk_bytes).expect("parse vk");
        let borrowed = vk.as_borrowed();

        let proof_a = negate_g1_be(&fix.proof.proof_a());
        let proof_b = fix.proof.proof_b();
        let proof_c = fix.proof.proof_c();
        let commitment = fix.proof.commitment();
        let pok = fix.proof.commitment_pok();
        let mut public_input = fix.proof.public_input();
        public_input[31] ^= 1; // flip a bit
        let public_inputs: [[u8; 32]; 1] = [public_input];

        let mut verifier = Groth16Verifier::new_with_commitment(
            &proof_a,
            &proof_b,
            &proof_c,
            &commitment,
            &pok,
            &public_inputs,
            &borrowed,
        )
        .expect("new_with_commitment");
        assert_eq!(
            verifier.verify(),
            Err(Groth16Error::ProofVerificationFailed)
        );
    }

    #[test]
    fn variant_2_rejects_mutated_commitment() {
        let (_dir, fix) = setup_variant(2);
        let vk = parse_gnark_vk_bytes(&fix.vk_bytes).expect("parse vk");
        let borrowed = vk.as_borrowed();

        let proof_a = negate_g1_be(&fix.proof.proof_a());
        let proof_b = fix.proof.proof_b();
        let proof_c = fix.proof.proof_c();
        let mut commitment = fix.proof.commitment();
        commitment[0] ^= 1; // flip a bit -> Pedersen PoK fails
        let pok = fix.proof.commitment_pok();
        let public_input = fix.proof.public_input();
        let public_inputs: [[u8; 32]; 1] = [public_input];

        let mut verifier = Groth16Verifier::new_with_commitment(
            &proof_a,
            &proof_b,
            &proof_c,
            &commitment,
            &pok,
            &public_inputs,
            &borrowed,
        )
        .expect("new_with_commitment");
        let err = verifier.verify().unwrap_err();
        // Bit-flipping the first byte of an uncompressed G1 BE point
        // either lands on an off-curve point (the syscall rejects with
        // PreparingInputsG1AdditionFailed when adding the commitment to
        // kSum) or — much rarer — yields a valid point that fails the
        // Pedersen PoK pairing or the main Groth16 pairing. All three
        // are valid rejections.
        assert!(
            matches!(
                err,
                Groth16Error::CommitmentPokVerificationFailed
                    | Groth16Error::ProofVerificationFailed
                    | Groth16Error::PreparingInputsG1AdditionFailed
                    | Groth16Error::PreparingInputsG1MulFailed
            ),
            "unexpected err: {:?}",
            err
        );
    }

    #[test]
    fn variant_3_rejects_mutated_pok() {
        let (_dir, fix) = setup_variant(3);
        let vk = parse_gnark_vk_bytes(&fix.vk_bytes).expect("parse vk");
        let borrowed = vk.as_borrowed();

        let proof_a = negate_g1_be(&fix.proof.proof_a());
        let proof_b = fix.proof.proof_b();
        let proof_c = fix.proof.proof_c();
        let commitment = fix.proof.commitment();
        let mut pok = fix.proof.commitment_pok();
        pok[0] ^= 1;
        let public_input = fix.proof.public_input();
        let public_inputs: [[u8; 32]; 1] = [public_input];

        let mut verifier = Groth16Verifier::new_with_commitment(
            &proof_a,
            &proof_b,
            &proof_c,
            &commitment,
            &pok,
            &public_inputs,
            &borrowed,
        )
        .expect("new_with_commitment");
        let err = verifier.verify().unwrap_err();
        assert_eq!(err, Groth16Error::CommitmentPokVerificationFailed);
    }
}
