//! BSB22 commitment integration tests for `groth16-solana`.
//!
//! These tests live in their own workspace member because they have a
//! cgo dependency: the in-repo gnark fixture (`gnark-fixture/`) is
//! compiled to a C static archive at build time, bindgen generates
//! Rust FFI bindings, and each test calls `Setup` + `Prove` directly
//! to obtain real-world bytes for one of the three lookup variants.
//!
//! The chain of trust runs top-to-bottom: gnark's own
//! `groth16.Verify` is exercised inside `gnark-fixture/main_test.go`.
//! If the in-repo verifier
//! disagrees with gnark on the same proof bytes, the bug is in our
//! port — not in the fixture.
//!
//! All tests are gated on the `bsb22` and `gnark-vk` features being
//! enabled in the parent crate (which the `Cargo.toml` here forces).

// `pub` so the integration tests under `tests/` (e.g. the
// hash-to-field differential proptests) can reuse the same bindings
// instead of re-including the bindgen output.
#[allow(
    non_camel_case_types,
    non_snake_case,
    non_upper_case_globals,
    dead_code
)]
pub mod bind {
    include!(concat!(env!("OUT_DIR"), "/bindings.rs"));
}

#[cfg(test)]
mod tests {
    use super::bind;
    use groth16_solana::errors::Groth16Error;
    use groth16_solana::vk::gnark::parse_gnark_vk_bytes;
    use groth16_solana::groth16::{negate_g1_be, Groth16Verifier, Groth16Verifyingkey};
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

    /// Proof material extracted from a [`VariantFixture`], ready for
    /// the in-repo verifier. Negative tests mutate one field and then
    /// assert on [`ProofFields::verify`].
    struct ProofFields {
        proof_a: [u8; 64], // already negated for the 4-pair check
        proof_b: [u8; 128],
        proof_c: [u8; 64],
        commitment: [u8; 64],
        pok: [u8; 64],
        public_input: [u8; 32],
    }

    impl ProofFields {
        fn from_fixture(fixture: &VariantFixture) -> Self {
            // gnark emits proof.Ar in its non-negated form; the
            // verifier runs the standard 4-pair Groth16 check, which
            // folds e(alpha, beta) onto the LHS, so it expects -Ar
            // (produced with the `negate_g1_be` public helper).
            Self {
                proof_a: negate_g1_be(&fixture.proof.proof_a()),
                proof_b: fixture.proof.proof_b(),
                proof_c: fixture.proof.proof_c(),
                commitment: fixture.proof.commitment(),
                pok: fixture.proof.commitment_pok(),
                public_input: fixture.proof.public_input(),
            }
        }

        fn verify(&self, vk: &Groth16Verifyingkey) -> Result<(), Groth16Error> {
            let public_inputs: [[u8; 32]; 1] = [self.public_input];
            let mut verifier = Groth16Verifier::new_with_commitment(
                &self.proof_a,
                &self.proof_b,
                &self.proof_c,
                &self.commitment,
                &self.pok,
                &public_inputs,
                vk,
            )
            .expect("new_with_commitment");
            verifier.verify()
        }
    }

    fn assert_verifies(variant: c_int) {
        let (_dir, fixture) = setup_variant(variant);
        let vk = parse_gnark_vk_bytes(&fixture.vk_bytes).expect("parse vk");
        assert!(
            vk.vk_commitment.is_some(),
            "variant {} should be BSB22",
            variant
        );
        let fields = ProofFields::from_fixture(&fixture);
        fields.verify(&vk.as_borrowed()).expect("verify");
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
        let (_dir, fixture) = setup_variant(1);
        let vk = parse_gnark_vk_bytes(&fixture.vk_bytes).expect("parse vk");
        let mut fields = ProofFields::from_fixture(&fixture);

        fields.public_input[31] ^= 1; // flip a bit

        assert_eq!(
            fields.verify(&vk.as_borrowed()),
            Err(Groth16Error::ProofVerificationFailed)
        );
    }

    #[test]
    fn variant_2_rejects_mutated_commitment() {
        let (_dir, fixture) = setup_variant(2);
        let vk = parse_gnark_vk_bytes(&fixture.vk_bytes).expect("parse vk");
        let mut fields = ProofFields::from_fixture(&fixture);

        fields.commitment[0] ^= 1; // flip a bit -> Pedersen PoK fails

        let err = fields.verify(&vk.as_borrowed()).unwrap_err();
        // Bit-flipping the first byte of an uncompressed G1 BE point
        // almost always lands on an off-curve point, rejected as
        // Bsb22InvalidCommitmentPoint when adding the commitment to
        // kSum. Much rarer: the flip yields a valid point that then
        // fails the main Groth16 pairing or the Pedersen PoK pairing.
        // All three are valid rejections.
        assert!(
            matches!(
                err,
                Groth16Error::Bsb22InvalidCommitmentPoint
                    | Groth16Error::ProofVerificationFailed
                    | Groth16Error::CommitmentPokVerificationFailed
            ),
            "unexpected err: {:?}",
            err
        );
    }

    #[test]
    fn variant_1_rejects_cross_proof_commitment_and_pok() {
        let (dir, fixture) = setup_variant(1);
        // Second proof under the same vk with X = 6 (Y = 36 keeps the
        // lookup indices inside the 64-entry table). Different
        // committed private wires give a different Pedersen
        // commitment; gnark's commitment is deterministic per
        // witness, so a second X = 7 proof would be vacuous here.
        let proof2 = ffi_prove(1, 6, dir.path());
        if let Some(err) = proof2.error() {
            panic!("Prove variant=1 x=6 returned error: {}", err);
        }
        let vk = parse_gnark_vk_bytes(&fixture.vk_bytes).expect("parse vk");
        let mut fields = ProofFields::from_fixture(&fixture);

        assert_ne!(
            fields.commitment,
            proof2.commitment(),
            "premise: the two proofs must not share a commitment"
        );

        // Proof 1's a/b/c and public input with proof 2's (D, pok).
        // The pair is self-consistent so the PoK pairing would pass,
        // but hashing the foreign commitment changes kSum and the
        // main pairing rejects first.
        fields.commitment = proof2.commitment();
        fields.pok = proof2.commitment_pok();

        assert_eq!(
            fields.verify(&vk.as_borrowed()),
            Err(Groth16Error::ProofVerificationFailed)
        );
    }

    #[test]
    fn variant_3_rejects_mutated_pok() {
        let (_dir, fixture) = setup_variant(3);
        let vk = parse_gnark_vk_bytes(&fixture.vk_bytes).expect("parse vk");
        let mut fields = ProofFields::from_fixture(&fixture);

        fields.pok[0] ^= 1;

        let err = fields.verify(&vk.as_borrowed()).unwrap_err();
        assert_eq!(err, Groth16Error::CommitmentPokVerificationFailed);
    }
}
