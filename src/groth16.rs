//! ```rust,ignore
//! let mut public_inputs_vec = Vec::new();
//! for input in PUBLIC_INPUTS.chunks(32) {
//!     public_inputs_vec.push(input);
//! }
//!
//! let proof_a: G1 =
//!     <G1 as FromBytes>::read(&*[&change_endianness(&PROOF[0..64])[..], &[0u8][..]].concat())?;
//! let mut proof_a_neg = [0u8; 65];
//! <G1 as ToBytes>::write(&proof_a.neg(), &mut proof_a_neg[..])?;
//!
//! let proof_a = change_endianness(&proof_a_neg[..64]).try_into()?;
//! let proof_b = PROOF[64..192].try_into()?;
//! let proof_c = PROOF[192..256].try_into()?;
//!
//! let mut verifier = Groth16Verifier::new(
//!     &proof_a,
//!     &proof_b,
//!     &proof_c,
//!     public_inputs_vec.as_slice(),
//!     &VERIFYING_KEY,
//! )?;
//! verifier.verify()?;
//! ```
//!
//! See functional test for a running example how to use this library.
//!
use crate::errors::Groth16Error;
use crate::syscalls::{g1_addition_be, g1_multiplication_be, pairing_be};

/// BSB22 Pedersen commitment verifying key.
/// `g2`             = pedersen.VerifyingKey.G
/// `g_sigma_neg_g2` = pedersen.VerifyingKey.GSigmaNeg
#[derive(PartialEq, Eq, Debug, Clone, Copy)]
pub struct CommitmentVerifyingKey {
    pub g2: [u8; 128],
    pub g_sigma_neg_g2: [u8; 128],
}

#[derive(PartialEq, Eq, Debug)]
pub struct Groth16Verifyingkey<'a> {
    pub nr_pubinputs: usize,
    pub vk_alpha_g1: [u8; 64],
    pub vk_beta_g2: [u8; 128],
    pub vk_gamma_g2: [u8; 128],
    pub vk_delta_g2: [u8; 128],
    pub vk_ic: &'a [[u8; 64]],

    /// BSB22 Pedersen commitment key — present only when the circuit
    /// uses lookups / `api.Commit`. Bundling both G2 points into one
    /// [`CommitmentVerifyingKey`] makes the type enforce that they are
    /// set together. For our supported circuits this is always exactly
    /// one commitment thanks to gnark's `multicommit` package merging
    /// deferred callbacks at finalization
    /// (`std/multicommit/nativecommit.go:89`).
    pub vk_commitment: Option<CommitmentVerifyingKey>,
}

#[derive(PartialEq, Eq, Debug)]
pub struct Groth16Verifier<'a, const NR_INPUTS: usize> {
    proof_a: &'a [u8; 64],
    proof_b: &'a [u8; 128],
    proof_c: &'a [u8; 64],
    public_inputs: &'a [[u8; 32]; NR_INPUTS],
    prepared_public_inputs: [u8; 64],
    verifyingkey: &'a Groth16Verifyingkey<'a>,

    /// `proof.Commitments[0]` — the single BSB22 Pedersen commitment.
    proof_commitment: Option<&'a [u8; 64]>,
    /// `proof.CommitmentPok` — the Pedersen knowledge proof.
    proof_commitment_pok: Option<&'a [u8; 64]>,
}

/// acc + point * scalar — the recurring MSM step in prepare_inputs.
/// Builds the 96-byte multiplication input (point || scalar), runs the
/// BN254 G1 scalar multiplication, then adds the result onto `acc`.
fn g1_mul_add(
    point: &[u8; 64],
    scalar: &[u8; 32],
    acc: &[u8; 64],
) -> Result<[u8; 64], Groth16Error> {
    let mut mul_input = [0u8; 96];
    mul_input[..64].copy_from_slice(point);
    mul_input[64..].copy_from_slice(scalar);
    let mul_res =
        g1_multiplication_be(&mul_input).map_err(|_| Groth16Error::PreparingInputsG1MulFailed)?;
    g1_add(&mul_res, acc)
}

/// acc + point for BN254 G1 points — builds the 128-byte addition
/// input (point || acc) and runs the syscall.
fn g1_add(point: &[u8; 64], acc: &[u8; 64]) -> Result<[u8; 64], Groth16Error> {
    let mut add_input = [0u8; 128];
    add_input[..64].copy_from_slice(point);
    add_input[64..].copy_from_slice(acc);
    g1_addition_be(&add_input).map_err(|_| Groth16Error::PreparingInputsG1AdditionFailed)
}

impl<const NR_INPUTS: usize> Groth16Verifier<'_, NR_INPUTS> {
    /// Constructor for standard Groth16 proofs (no BSB22 commitment).
    /// Rejects verifying keys that contain a commitment key; those
    /// proofs must use [`Groth16Verifier::new_with_commitment`].
    pub fn new<'a>(
        proof_a: &'a [u8; 64],
        proof_b: &'a [u8; 128],
        proof_c: &'a [u8; 64],
        public_inputs: &'a [[u8; 32]; NR_INPUTS],
        verifyingkey: &'a Groth16Verifyingkey<'a>,
    ) -> Result<Groth16Verifier<'a, NR_INPUTS>, Groth16Error> {
        // A vk with a Pedersen commitment key is a BSB22 vk and must
        // be paired with `new_with_commitment`. Checked before the
        // length check: a BSB22 vk has one extra vk_ic entry, so a
        // correctly sized call would otherwise fail with
        // InvalidPublicInputsLength and hide the real problem.
        if verifyingkey.vk_commitment.is_some() {
            return Err(Groth16Error::UnexpectedCommitmentKey);
        }

        if public_inputs.len() + 1 != verifyingkey.vk_ic.len() {
            return Err(Groth16Error::InvalidPublicInputsLength);
        }

        Ok(Groth16Verifier {
            proof_a,
            proof_b,
            proof_c,
            public_inputs,
            prepared_public_inputs: [0u8; 64],
            verifyingkey,
            proof_commitment: None,
            proof_commitment_pok: None,
        })
    }

    /// Constructor for BSB22 Groth16 proofs with one Pedersen
    /// commitment plus its knowledge proof. The verifying key must
    /// have its `vk_commitment` set, and `vk_ic.len()` must equal
    /// `public_inputs.len() + 2` (the trailing `vk_ic` slot is the K
    /// column gnark appends for the commitment-derived hash wire).
    /// Multi-commitment circuits are not supported; the vk parser
    /// rejects them at parse time with
    /// [`Groth16Error::Bsb22UnsupportedMultiCommitment`].
    #[cfg(feature = "bsb22")]
    pub fn new_with_commitment<'a>(
        proof_a: &'a [u8; 64],
        proof_b: &'a [u8; 128],
        proof_c: &'a [u8; 64],
        proof_commitment: &'a [u8; 64],
        proof_commitment_pok: &'a [u8; 64],
        public_inputs: &'a [[u8; 32]; NR_INPUTS],
        verifyingkey: &'a Groth16Verifyingkey<'a>,
    ) -> Result<Groth16Verifier<'a, NR_INPUTS>, Groth16Error> {
        // Checked before the length check: a standard-Groth16 vk fed
        // through this constructor should report MissingCommitmentKey,
        // not InvalidPublicInputsLength.
        if verifyingkey.vk_commitment.is_none() {
            return Err(Groth16Error::MissingCommitmentKey);
        }

        // BSB22 vks have one extra IC slot for the commitment-derived
        // hash wire that gnark appends to the public-witness vector.
        if public_inputs.len() + 2 != verifyingkey.vk_ic.len() {
            return Err(Groth16Error::InvalidPublicInputsLength);
        }

        Ok(Groth16Verifier {
            proof_a,
            proof_b,
            proof_c,
            public_inputs,
            prepared_public_inputs: [0u8; 64],
            verifyingkey,
            proof_commitment: Some(proof_commitment),
            proof_commitment_pok: Some(proof_commitment_pok),
        })
    }

    pub fn prepare_inputs<const CHECK: bool>(&mut self) -> Result<(), Groth16Error> {
        let mut prepared_public_inputs = self.verifyingkey.vk_ic[0];

        for (i, input) in self.public_inputs.iter().enumerate() {
            if CHECK && !is_less_than_bn254_field_size_be(input) {
                return Err(Groth16Error::PublicInputGreaterThanFieldSize);
            }
            prepared_public_inputs = g1_mul_add(
                &self.verifyingkey.vk_ic[i + 1],
                input,
                &prepared_public_inputs,
            )?;
        }

        // BSB22 extension: when the proof includes a Pedersen
        // commitment, gnark's verifier (verify.go:77-115) appends one
        // extra wire to publicWitness — the BSB22 hash of the
        // commitment bytes — and then adds the raw commitment G1
        // point to kSum after the MSM. We mirror that here.
        //
        // For our supported circuits (logderivlookup over private
        // wires), `vk.PublicAndCommitmentCommitted[0]` is empty
        // (verified against gnark r1cs.CommitmentInfo via the
        // `gnark-fixture` smoke test in `tests/bsb22/gnark-fixture/`),
        // so the BSB22 hash preimage is just the 64-byte commitment —
        // no public-witness concatenation needed.
        //
        // CU cost is measured by tests/bsb22-program/tests/litesvm_cu.rs (source of truth).
        #[cfg(feature = "bsb22")]
        {
            if self.verifyingkey.vk_commitment.is_some() != self.proof_commitment.is_some() {
                return Err(Groth16Error::Bsb22InconsistentCommitmentState);
            }

            if let Some(commitment) = self.proof_commitment {
                // 1. Hash the commitment to a field element using gnark's
                //    DST "bsb22-commitment" (constraint/commitment.go:7).
                let commitment_hash_fe =
                    crate::hash_to_field::hash_to_field_bn254_fr(commitment, b"bsb22-commitment");

                // 2. Multiply by the trailing K column (vk_ic[NR_INPUTS + 1])
                //    that gnark appended for the commitment-derived hash
                //    wire, and add to the running kSum.
                let commitment_hash_ic = self
                    .verifyingkey
                    .vk_ic
                    .get(NR_INPUTS + 1)
                    .ok_or(Groth16Error::InvalidPublicInputsLength)?;
                prepared_public_inputs = g1_mul_add(
                    commitment_hash_ic,
                    &commitment_hash_fe,
                    &prepared_public_inputs,
                )?;

                // 3. Add the raw commitment G1 point itself to kSum
                //    (verify.go:113-115). The commitment is prover-supplied
                //    bytes; a syscall rejection here means the point itself
                //    is invalid.
                prepared_public_inputs = g1_add(commitment, &prepared_public_inputs)
                    .map_err(|_| Groth16Error::Bsb22InvalidCommitmentPoint)?;
            }
        }
        self.prepared_public_inputs = prepared_public_inputs;

        Ok(())
    }

    /// Verifies the proof, and checks that public inputs are smaller than
    /// field size.
    pub fn verify(&mut self) -> Result<(), Groth16Error> {
        self.verify_common::<true>()
    }

    /// Verifies the proof, and does not check that public inputs are smaller
    /// than field size.
    pub fn verify_unchecked(&mut self) -> Result<(), Groth16Error> {
        self.verify_common::<false>()
    }

    fn verify_common<const CHECK: bool>(&mut self) -> Result<(), Groth16Error> {
        self.prepare_inputs::<CHECK>()?;

        // 4 pairing pairs: (proof_a, proof_b), (prepared, gamma), (proof_c, delta), (alpha, beta)
        let mut pairing_input = [0u8; 768];
        pairing_input[0..64].copy_from_slice(self.proof_a);
        pairing_input[64..192].copy_from_slice(self.proof_b);
        pairing_input[192..256].copy_from_slice(&self.prepared_public_inputs);
        pairing_input[256..384].copy_from_slice(&self.verifyingkey.vk_gamma_g2);
        pairing_input[384..448].copy_from_slice(self.proof_c);
        pairing_input[448..576].copy_from_slice(&self.verifyingkey.vk_delta_g2);
        pairing_input[576..640].copy_from_slice(&self.verifyingkey.vk_alpha_g1);
        pairing_input[640..768].copy_from_slice(&self.verifyingkey.vk_beta_g2);

        let pairing_res =
            pairing_be(&pairing_input).map_err(|_| Groth16Error::ProofVerificationFailed)?;

        if pairing_res[31] != 1 {
            return Err(Groth16Error::ProofVerificationFailed);
        }

        #[cfg(feature = "bsb22")]
        self.verify_commitment_pok()?;

        Ok(())
    }

    /// BSB22 Pedersen knowledge-proof check. For the
    /// single-commitment case the gnark fold collapses to
    /// identity (the G16-BSB22 challenge multiplies a 1-element
    /// MSM), so no Fiat-Shamir hash is needed and the check is a
    /// single 2-pair pairing equation:
    ///
    /// ```text
    /// e(commitment, gSigmaNeg) * e(pok, g) == 1
    /// ```
    ///
    /// Mirrors gnark-crypto pedersen.go:197-209 (the single-vk
    /// Verify form that BatchVerifyMultiVk collapses to when
    /// len(vk) == 1 && len(pok) == 1).
    ///
    /// Invariant: `proof_commitment`, `proof_commitment_pok`, and
    /// `vk_commitment` are all-Some (set together by
    /// `new_with_commitment`, which requires the vk commitment key) or
    /// all-None (from `new`, which rejects vks that contain one). The
    /// fields are private and the constructors are the only writers,
    /// but rather than trust that non-local invariant the match fails
    /// closed: a mixed state returns an error instead of silently
    /// skipping the PoK check.
    #[cfg(feature = "bsb22")]
    fn verify_commitment_pok(&self) -> Result<(), Groth16Error> {
        match (
            self.proof_commitment,
            self.proof_commitment_pok,
            self.verifyingkey.vk_commitment.as_ref(),
        ) {
            (Some(commitment), Some(pok), Some(commitment_key)) => {
                let mut pok_input = [0u8; 384];
                pok_input[0..64].copy_from_slice(commitment);
                pok_input[64..192].copy_from_slice(&commitment_key.g_sigma_neg_g2);
                pok_input[192..256].copy_from_slice(pok);
                pok_input[256..384].copy_from_slice(&commitment_key.g2);
                let pok_res = pairing_be(&pok_input)
                    .map_err(|_| Groth16Error::CommitmentPokVerificationFailed)?;
                if pok_res[31] != 1 {
                    return Err(Groth16Error::CommitmentPokVerificationFailed);
                }
                Ok(())
            }
            (None, None, None) => Ok(()),
            _ => Err(Groth16Error::Bsb22InconsistentCommitmentState),
        }
    }
}

/// BN254 scalar field (Fr) modulus as 32 big-endian bytes:
/// 21888242871839275222246405745257275088548364400416034343698204186575808495617
/// = 0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001.
/// Kept as a byte constant so the field-size check needs no arkworks
/// dependency; the `fr_modulus_constant_matches_ark` test pins it to
/// `ark_bn254::Fr::MODULUS`.
const FR_MODULUS_BE: [u8; 32] = [
    0x30, 0x64, 0x4e, 0x72, 0xe1, 0x31, 0xa0, 0x29, 0xb8, 0x50, 0x45, 0xb6, 0x81, 0x81, 0x58,
    0x5d, 0x28, 0x33, 0xe8, 0x48, 0x79, 0xb9, 0x70, 0x91, 0x43, 0xe1, 0xf5, 0x93, 0xf0, 0x00,
    0x00, 0x01,
];

pub fn is_less_than_bn254_field_size_be(bytes: &[u8; 32]) -> bool {
    // Fixed-width big-endian comparison is exactly lexicographic byte
    // order, which is what the array `Ord` impl provides.
    *bytes < FR_MODULUS_BE
}

/// Negate a BN254 G1 point serialized as 64 uncompressed big-endian
/// bytes (X || Y) and return the negated point in the same format.
/// For (x, y) the negation is (x, p - y) where p is the BN254 base
/// field (Fq) modulus.
///
/// Useful for preparing `proof.A` for a Groth16 verifier that expects
/// the LHS of the pairing equation to include `-A` (e.g. gnark emits
/// the non-negated form; the on-chain verifier folds `e(α, β)` onto
/// the LHS via the standard 4-pair check and therefore wants `-A`).
pub fn negate_g1_be(g1: &[u8; 64]) -> [u8; 64] {
    // Identity check: all zeros -> identity, negation is identity.
    if *g1 == [0u8; 64] {
        return [0u8; 64];
    }
    let mut result = [0u8; 64];
    // X coordinate is unchanged.
    result[..32].copy_from_slice(&g1[..32]);
    // BN254 Fq modulus (big-endian u64 limbs, most significant first).
    const FQ: [u64; 4] = [
        0x30644e72e131a029,
        0xb85045b68181585d,
        0x97816a916871ca8d,
        0x3c208c16d87cfd47,
    ];
    let y = [
        u64::from_be_bytes([
            g1[32], g1[33], g1[34], g1[35], g1[36], g1[37], g1[38], g1[39],
        ]),
        u64::from_be_bytes([
            g1[40], g1[41], g1[42], g1[43], g1[44], g1[45], g1[46], g1[47],
        ]),
        u64::from_be_bytes([
            g1[48], g1[49], g1[50], g1[51], g1[52], g1[53], g1[54], g1[55],
        ]),
        u64::from_be_bytes([
            g1[56], g1[57], g1[58], g1[59], g1[60], g1[61], g1[62], g1[63],
        ]),
    ];
    // Compute p - y with borrow (big-endian: limb[0] is most significant).
    let mut borrow: u64 = 0;
    let mut neg_y = [0u64; 4];
    for i in (0..4).rev() {
        let (diff, b1) = FQ[i].overflowing_sub(y[i]);
        let (diff, b2) = diff.overflowing_sub(borrow);
        neg_y[i] = diff;
        borrow = (b1 as u64) + (b2 as u64);
    }
    result[32..40].copy_from_slice(&neg_y[0].to_be_bytes());
    result[40..48].copy_from_slice(&neg_y[1].to_be_bytes());
    result[48..56].copy_from_slice(&neg_y[2].to_be_bytes());
    result[56..64].copy_from_slice(&neg_y[3].to_be_bytes());
    result
}

#[cfg(test)]
mod tests {
    extern crate alloc;
    use crate::decompression::{decompress_g1, decompress_g2};
    use alloc::vec::Vec;

    use super::*;
    use ark_bn254;
    use ark_ff::{BigInteger, PrimeField};
    use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, Compress, Validate};
    use core::ops::Neg;
    type G1 = ark_bn254::g1::G1Affine;
    type G2 = ark_bn254::g2::G2Affine;
    use solana_bn254::compression::prelude::convert_endianness;

    pub const VERIFYING_KEY: Groth16Verifyingkey = Groth16Verifyingkey {
        nr_pubinputs: 10,

        vk_alpha_g1: [
            45, 77, 154, 167, 227, 2, 217, 223, 65, 116, 157, 85, 7, 148, 157, 5, 219, 234, 51,
            251, 177, 108, 100, 59, 34, 245, 153, 162, 190, 109, 242, 226, 20, 190, 221, 80, 60,
            55, 206, 176, 97, 216, 236, 96, 32, 159, 227, 69, 206, 137, 131, 10, 25, 35, 3, 1, 240,
            118, 202, 255, 0, 77, 25, 38,
        ],

        vk_beta_g2: [
            9, 103, 3, 47, 203, 247, 118, 209, 175, 201, 133, 248, 136, 119, 241, 130, 211, 132,
            128, 166, 83, 242, 222, 202, 169, 121, 76, 188, 59, 243, 6, 12, 14, 24, 120, 71, 173,
            76, 121, 131, 116, 208, 214, 115, 43, 245, 1, 132, 125, 214, 139, 192, 224, 113, 36,
            30, 2, 19, 188, 127, 193, 61, 183, 171, 48, 76, 251, 209, 224, 138, 112, 74, 153, 245,
            232, 71, 217, 63, 140, 60, 170, 253, 222, 196, 107, 122, 13, 55, 157, 166, 154, 77, 17,
            35, 70, 167, 23, 57, 193, 177, 164, 87, 168, 199, 49, 49, 35, 210, 77, 47, 145, 146,
            248, 150, 183, 198, 62, 234, 5, 169, 213, 127, 6, 84, 122, 208, 206, 200,
        ],

        vk_gamma_g2: [
            25, 142, 147, 147, 146, 13, 72, 58, 114, 96, 191, 183, 49, 251, 93, 37, 241, 170, 73,
            51, 53, 169, 231, 18, 151, 228, 133, 183, 174, 243, 18, 194, 24, 0, 222, 239, 18, 31,
            30, 118, 66, 106, 0, 102, 94, 92, 68, 121, 103, 67, 34, 212, 247, 94, 218, 221, 70,
            222, 189, 92, 217, 146, 246, 237, 9, 6, 137, 208, 88, 95, 240, 117, 236, 158, 153, 173,
            105, 12, 51, 149, 188, 75, 49, 51, 112, 179, 142, 243, 85, 172, 218, 220, 209, 34, 151,
            91, 18, 200, 94, 165, 219, 140, 109, 235, 74, 171, 113, 128, 141, 203, 64, 143, 227,
            209, 231, 105, 12, 67, 211, 123, 76, 230, 204, 1, 102, 250, 125, 170,
        ],

        vk_delta_g2: [
            25, 142, 147, 147, 146, 13, 72, 58, 114, 96, 191, 183, 49, 251, 93, 37, 241, 170, 73,
            51, 53, 169, 231, 18, 151, 228, 133, 183, 174, 243, 18, 194, 24, 0, 222, 239, 18, 31,
            30, 118, 66, 106, 0, 102, 94, 92, 68, 121, 103, 67, 34, 212, 247, 94, 218, 221, 70,
            222, 189, 92, 217, 146, 246, 237, 9, 6, 137, 208, 88, 95, 240, 117, 236, 158, 153, 173,
            105, 12, 51, 149, 188, 75, 49, 51, 112, 179, 142, 243, 85, 172, 218, 220, 209, 34, 151,
            91, 18, 200, 94, 165, 219, 140, 109, 235, 74, 171, 113, 128, 141, 203, 64, 143, 227,
            209, 231, 105, 12, 67, 211, 123, 76, 230, 204, 1, 102, 250, 125, 170,
        ],

        vk_ic: &[
            [
                3, 183, 175, 189, 219, 73, 183, 28, 132, 200, 83, 8, 65, 22, 184, 81, 82, 36, 181,
                186, 25, 216, 234, 25, 151, 2, 235, 194, 13, 223, 32, 145, 15, 37, 113, 122, 93,
                59, 91, 25, 236, 104, 227, 238, 58, 154, 67, 250, 186, 91, 93, 141, 18, 241, 150,
                59, 202, 48, 179, 1, 53, 207, 155, 199,
            ],
            [
                46, 253, 85, 84, 166, 240, 71, 175, 111, 174, 244, 62, 87, 96, 235, 196, 208, 85,
                186, 47, 163, 237, 53, 204, 176, 190, 62, 201, 189, 216, 132, 71, 6, 91, 228, 97,
                74, 5, 0, 255, 147, 113, 161, 152, 238, 177, 78, 81, 111, 13, 142, 220, 24, 133,
                27, 149, 66, 115, 34, 87, 224, 237, 44, 162,
            ],
            [
                29, 157, 232, 254, 238, 178, 82, 15, 152, 205, 175, 129, 90, 108, 114, 60, 82, 162,
                37, 234, 115, 69, 191, 125, 212, 85, 176, 176, 113, 41, 23, 84, 8, 229, 196, 41,
                191, 243, 112, 105, 166, 75, 113, 160, 140, 34, 139, 179, 53, 180, 245, 195, 5, 24,
                42, 18, 82, 60, 173, 192, 67, 149, 211, 250,
            ],
            [
                18, 4, 92, 105, 55, 33, 222, 133, 144, 185, 99, 131, 167, 143, 52, 120, 44, 79,
                164, 63, 119, 223, 199, 154, 26, 86, 22, 208, 50, 53, 159, 65, 14, 171, 53, 159,
                255, 133, 91, 30, 162, 209, 152, 18, 251, 112, 105, 90, 65, 234, 44, 4, 42, 173,
                31, 230, 229, 137, 177, 112, 241, 142, 62, 176,
            ],
            [
                13, 117, 56, 250, 131, 38, 119, 205, 221, 228, 32, 185, 236, 82, 102, 29, 198, 53,
                117, 151, 19, 10, 255, 211, 41, 210, 72, 221, 79, 107, 251, 150, 35, 187, 30, 32,
                198, 17, 220, 4, 68, 10, 71, 51, 31, 169, 4, 174, 10, 38, 227, 229, 193, 129, 150,
                76, 94, 224, 182, 13, 166, 65, 175, 89,
            ],
            [
                21, 167, 160, 214, 213, 132, 208, 197, 115, 195, 129, 111, 129, 38, 56, 52, 41, 57,
                72, 249, 50, 187, 184, 49, 240, 228, 142, 147, 187, 96, 96, 102, 34, 163, 43, 218,
                199, 187, 250, 245, 119, 151, 237, 67, 231, 70, 236, 67, 157, 181, 216, 174, 25,
                82, 120, 255, 191, 89, 230, 165, 179, 241, 188, 218,
            ],
            [
                4, 136, 219, 130, 55, 89, 21, 224, 41, 30, 53, 234, 66, 160, 129, 174, 154, 139,
                151, 33, 163, 221, 150, 192, 171, 102, 241, 161, 48, 130, 31, 175, 6, 47, 176, 127,
                13, 8, 36, 228, 239, 219, 6, 158, 22, 31, 22, 162, 91, 196, 132, 188, 156, 228, 30,
                1, 178, 246, 197, 186, 236, 249, 236, 147,
            ],
            [
                9, 41, 120, 80, 67, 24, 240, 221, 136, 156, 137, 182, 168, 17, 176, 118, 119, 72,
                170, 188, 227, 31, 15, 22, 252, 37, 198, 154, 195, 163, 64, 125, 37, 211, 235, 67,
                249, 133, 45, 90, 162, 9, 173, 19, 80, 154, 208, 173, 221, 203, 206, 254, 81, 197,
                104, 26, 177, 78, 86, 210, 51, 116, 60, 87,
            ],
            [
                3, 41, 86, 208, 125, 147, 53, 187, 213, 220, 195, 141, 216, 40, 92, 137, 70, 210,
                168, 103, 105, 236, 85, 37, 165, 209, 246, 75, 122, 251, 75, 93, 28, 108, 154, 181,
                15, 16, 35, 88, 65, 211, 8, 11, 123, 84, 185, 187, 184, 1, 83, 141, 67, 46, 241,
                222, 232, 135, 59, 44, 152, 217, 237, 106,
            ],
            [
                34, 98, 189, 118, 119, 197, 102, 193, 36, 150, 200, 143, 226, 60, 0, 239, 21, 40,
                5, 156, 73, 7, 247, 14, 249, 157, 2, 241, 181, 208, 144, 0, 34, 45, 86, 133, 116,
                53, 235, 160, 107, 36, 195, 125, 122, 10, 206, 88, 85, 166, 62, 150, 65, 159, 130,
                7, 255, 224, 227, 229, 206, 138, 68, 71,
            ],
        ],

        // Standard Groth16 vk; no BSB22 commitment key.
        vk_commitment: None,
    };

    fn change_endianness(bytes: &[u8]) -> Vec<u8> {
        let mut vec = Vec::new();
        for b in bytes.chunks(32) {
            for byte in b.iter().rev() {
                vec.push(*byte);
            }
        }
        vec
    }

    pub const PUBLIC_INPUTS: [[u8; 32]; 9] = [
        [
            34, 238, 251, 182, 234, 248, 214, 189, 46, 67, 42, 25, 71, 58, 145, 58, 61, 28, 116,
            110, 60, 17, 82, 149, 178, 187, 160, 211, 37, 226, 174, 231,
        ],
        [
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 51,
            152, 17, 147,
        ],
        [
            4, 247, 199, 87, 230, 85, 103, 90, 28, 183, 95, 100, 200, 46, 3, 158, 247, 196, 173,
            146, 207, 167, 108, 33, 199, 18, 13, 204, 198, 101, 223, 186,
        ],
        [
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 7,
            49, 65, 41,
        ],
        [
            7, 130, 55, 65, 197, 232, 175, 217, 44, 151, 149, 225, 75, 86, 158, 105, 43, 229, 65,
            87, 51, 150, 168, 243, 176, 175, 11, 203, 180, 149, 72, 103,
        ],
        [
            46, 93, 177, 62, 42, 66, 223, 153, 51, 193, 146, 49, 154, 41, 69, 198, 224, 13, 87, 80,
            222, 171, 37, 141, 0, 1, 50, 172, 18, 28, 213, 213,
        ],
        [
            40, 141, 45, 3, 180, 200, 250, 112, 108, 94, 35, 143, 82, 63, 125, 9, 147, 37, 191, 75,
            62, 221, 138, 20, 166, 151, 219, 237, 254, 58, 230, 189,
        ],
        [
            33, 100, 143, 241, 11, 251, 73, 141, 229, 57, 129, 168, 83, 23, 235, 147, 138, 225,
            177, 250, 13, 97, 226, 162, 6, 232, 52, 95, 128, 84, 90, 202,
        ],
        [
            25, 178, 1, 208, 219, 169, 222, 123, 113, 202, 165, 77, 183, 98, 103, 237, 187, 93,
            178, 95, 169, 156, 38, 100, 125, 218, 104, 94, 104, 119, 13, 21,
        ],
    ];

    pub const PROOF: [u8; 256] = [
        45, 206, 255, 166, 152, 55, 128, 138, 79, 217, 145, 164, 25, 74, 120, 234, 234, 217, 68,
        149, 162, 44, 133, 120, 184, 205, 12, 44, 175, 98, 168, 172, 20, 24, 216, 15, 209, 175,
        106, 75, 147, 236, 90, 101, 123, 219, 245, 151, 209, 202, 218, 104, 148, 8, 32, 254, 243,
        191, 218, 122, 42, 81, 193, 84, 40, 57, 233, 205, 180, 46, 35, 111, 215, 5, 23, 93, 12, 71,
        118, 225, 7, 46, 247, 147, 47, 130, 106, 189, 184, 80, 146, 103, 141, 52, 242, 25, 0, 203,
        124, 176, 110, 34, 151, 212, 66, 180, 238, 151, 236, 189, 133, 209, 17, 137, 205, 183, 168,
        196, 92, 159, 75, 174, 81, 168, 18, 86, 176, 56, 16, 26, 210, 20, 18, 81, 122, 142, 104,
        62, 251, 169, 98, 141, 21, 253, 50, 130, 182, 15, 33, 109, 228, 31, 79, 183, 88, 147, 174,
        108, 4, 22, 14, 129, 168, 6, 80, 246, 254, 100, 218, 131, 94, 49, 247, 211, 3, 245, 22,
        200, 177, 91, 60, 144, 147, 174, 90, 17, 19, 189, 62, 147, 152, 18, 41, 139, 183, 208, 246,
        198, 118, 127, 89, 160, 9, 27, 61, 26, 123, 180, 221, 108, 17, 166, 47, 115, 82, 48, 132,
        139, 253, 65, 152, 92, 209, 53, 37, 25, 83, 61, 252, 42, 181, 243, 16, 21, 2, 199, 123, 96,
        218, 151, 253, 86, 69, 181, 202, 109, 64, 129, 124, 254, 192, 25, 177, 199, 26, 50,
    ];

    #[test]
    fn fr_modulus_constant_matches_ark() {
        assert_eq!(
            FR_MODULUS_BE.to_vec(),
            ark_bn254::Fr::MODULUS.to_bytes_be()
        );
    }

    #[test]
    fn test_is_less_than_bn254_field_size_be() {
        let bytes = [0u8; 32];
        assert!(is_less_than_bn254_field_size_be(&bytes));

        let modulus_le = ark_bn254::Fr::MODULUS.to_bytes_le();
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(&modulus_le);
        bytes.reverse();
        assert!(!is_less_than_bn254_field_size_be(&bytes));

        // modulus - 1 is the largest valid input.
        bytes[31] -= 1;
        assert!(is_less_than_bn254_field_size_be(&bytes));
    }

    #[test]
    fn proof_verification_should_succeed() {
        let proof_a: G1 = G1::deserialize_with_mode(
            &*[&change_endianness(&PROOF[0..64]), &[0u8][..]].concat(),
            Compress::No,
            Validate::Yes,
        )
        .unwrap();
        let mut proof_a_neg = [0u8; 65];
        proof_a
            .neg()
            .x
            .serialize_with_mode(&mut proof_a_neg[..32], Compress::No)
            .unwrap();
        proof_a
            .neg()
            .y
            .serialize_with_mode(&mut proof_a_neg[32..], Compress::No)
            .unwrap();

        let proof_a = change_endianness(&proof_a_neg[..64]).try_into().unwrap();
        let proof_b = PROOF[64..192].try_into().unwrap();
        let proof_c = PROOF[192..256].try_into().unwrap();

        let mut verifier =
            Groth16Verifier::new(&proof_a, &proof_b, &proof_c, &PUBLIC_INPUTS, &VERIFYING_KEY)
                .unwrap();
        verifier.verify().unwrap();
        verifier.verify_unchecked().unwrap();
    }

    fn compress_g1_be(g1: &[u8; 64]) -> [u8; 32] {
        let g1 = convert_endianness::<32, 64>(g1);
        let mut compressed = [0u8; 32];
        let g1 = G1::deserialize_with_mode(g1.as_slice(), Compress::No, Validate::Yes).unwrap();
        G1::serialize_with_mode(&g1, &mut compressed[..], Compress::Yes).unwrap();

        convert_endianness::<32, 32>(&compressed)
    }

    fn compress_g2_be(g2: &[u8; 128]) -> [u8; 64] {
        let g2: [u8; 128] = convert_endianness::<64, 128>(g2);

        let mut compressed = [0u8; 64];
        let g2 = G2::deserialize_with_mode(g2.as_slice(), Compress::No, Validate::Yes).unwrap();
        G2::serialize_with_mode(&g2, &mut compressed[..], Compress::Yes).unwrap();
        convert_endianness::<64, 64>(&compressed)
    }

    #[test]
    fn proof_verification_with_compressed_inputs_should_succeed() {
        let mut public_inputs_vec = Vec::new();
        for input in PUBLIC_INPUTS.chunks(32) {
            public_inputs_vec.push(input);
        }
        let compressed_proof_a = compress_g1_be(&PROOF[0..64].try_into().unwrap());
        let compressed_proof_b = compress_g2_be(&PROOF[64..192].try_into().unwrap());
        let compressed_proof_c = compress_g1_be(&PROOF[192..].try_into().unwrap());

        let proof_a = decompress_g1(&compressed_proof_a).unwrap();
        let proof_a: G1 = G1::deserialize_with_mode(
            &*[&change_endianness(&proof_a[0..64]), &[0u8][..]].concat(),
            Compress::No,
            Validate::Yes,
        )
        .unwrap();
        let mut proof_a_neg = [0u8; 65];
        proof_a
            .neg()
            .x
            .serialize_with_mode(&mut proof_a_neg[..32], Compress::No)
            .unwrap();
        proof_a
            .neg()
            .y
            .serialize_with_mode(&mut proof_a_neg[32..], Compress::No)
            .unwrap();

        let proof_a = change_endianness(&proof_a_neg[..64]).try_into().unwrap();
        let proof_b = decompress_g2(&compressed_proof_b).unwrap();
        let proof_c = decompress_g1(&compressed_proof_c).unwrap();
        let mut verifier =
            Groth16Verifier::new(&proof_a, &proof_b, &proof_c, &PUBLIC_INPUTS, &VERIFYING_KEY)
                .unwrap();
        verifier.verify().unwrap();
        verifier.verify_unchecked().unwrap();
    }

    #[test]
    fn wrong_proof_verification_should_not_succeed() {
        let proof_a = PROOF[0..64].try_into().unwrap();
        let proof_b = PROOF[64..192].try_into().unwrap();
        let proof_c = PROOF[192..256].try_into().unwrap();
        let mut verifier = Groth16Verifier::new(
            &proof_a, // using non negated proof a as test for wrong proof
            &proof_b,
            &proof_c,
            &PUBLIC_INPUTS,
            &VERIFYING_KEY,
        )
        .unwrap();
        assert_eq!(
            verifier.verify(),
            Err(Groth16Error::ProofVerificationFailed)
        );
        assert_eq!(
            verifier.verify_unchecked(),
            Err(Groth16Error::ProofVerificationFailed)
        );
    }

    #[test]
    fn public_input_greater_than_field_size_should_not_suceed() {
        let proof_a = PROOF[0..64].try_into().unwrap();
        let proof_b = PROOF[64..192].try_into().unwrap();
        let proof_c = PROOF[192..256].try_into().unwrap();
        let mut public_inputs = PUBLIC_INPUTS;
        public_inputs[0] = ark_bn254::Fr::MODULUS.to_bytes_be().try_into().unwrap();
        let mut verifier = Groth16Verifier::new(
            &proof_a, // using non negated proof a as test for wrong proof
            &proof_b,
            &proof_c,
            &public_inputs,
            &VERIFYING_KEY,
        )
        .unwrap();
        assert_eq!(
            verifier.verify_unchecked(),
            Err(Groth16Error::ProofVerificationFailed)
        );
        assert_eq!(
            verifier.verify(),
            Err(Groth16Error::PublicInputGreaterThanFieldSize)
        );
    }

    // -------------------------------------------------------------------
    // BSB22 end-to-end smoke test (lib-internal — does not depend on the
    // FFI test crate). Golden bytes harvested from the gnark-fixture
    // `TestDumpFullFixture` Go test for variant 1 with X=7. Setup is
    // non-deterministic so the vk and proof must come from the same
    // Setup call (the Go test prints them all together).
    //
    // The FFI test crate `tests/bsb22/` exercises the same path with
    // freshly-generated bytes per run; this test exists so a plain
    // `cargo test -p groth16-solana --features bsb22` covers the BSB22
    // verifier without the Go toolchain dep.
    // -------------------------------------------------------------------

    #[cfg(feature = "bsb22")]
    mod bsb22_e2e {
        use super::*;
        use crate::vk::gnark::parse_gnark_vk_bytes;

        // Committed binary fixtures — shared with the SBF program at
        // tests/bsb22-program/build.rs. All seven files are one
        // consistent snapshot from a single gnark `Setup` + `Prove`
        // for the variant-1 `LookupsCircuit` (one lookup) with X=7.
        // Regenerate all seven together
        // via `TestDumpFullFixture` in
        // `tests/bsb22/gnark-fixture/main_test.go` (gnark setup is
        // non-deterministic, so vk and proof must come from a single run).
        const VK_BYTES: &[u8] = include_bytes!("../tests/fixtures/bsb22/vk_variant_1.bin");
        const PROOF_A_BYTES: &[u8; 64] =
            include_bytes!("../tests/fixtures/bsb22/proof_a_variant_1.bin");
        const PROOF_B_BYTES: &[u8; 128] =
            include_bytes!("../tests/fixtures/bsb22/proof_b_variant_1.bin");
        const PROOF_C_BYTES: &[u8; 64] =
            include_bytes!("../tests/fixtures/bsb22/proof_c_variant_1.bin");
        const COMMITMENT_BYTES: &[u8; 64] =
            include_bytes!("../tests/fixtures/bsb22/commitment_variant_1.bin");
        const POK_BYTES: &[u8; 64] = include_bytes!("../tests/fixtures/bsb22/pok_variant_1.bin");
        const PUBLIC_INPUT_BYTES: &[u8; 32] =
            include_bytes!("../tests/fixtures/bsb22/public_input_variant_1.bin");

        /// BN254 G1 generator (x = 1, y = 2) as 64 uncompressed BE
        /// bytes — a valid on-curve point that is unrelated to the
        /// fixture's commitment and PoK.
        const G1_GENERATOR_BE: [u8; 64] = {
            let mut bytes = [0u8; 64];
            bytes[31] = 1;
            bytes[63] = 2;
            bytes
        };

        /// Deterministic off-curve encoding (x = 0, y = 1): y^2 = 1
        /// but x^3 + 3 = 3, so the alt_bn128 syscalls reject it.
        const NOT_ON_CURVE_G1_BE: [u8; 64] = {
            let mut bytes = [0u8; 64];
            bytes[63] = 1;
            bytes
        };

        /// Verify the fixture proof against `vk` with the commitment
        /// and PoK substituted; everything else stays honest, so
        /// negative tests isolate the commitment/PoK handling.
        fn verify_with_commitment_and_pok(
            commitment: &[u8; 64],
            pok: &[u8; 64],
            vk: &Groth16Verifyingkey,
        ) -> Result<(), Groth16Error> {
            let proof_a = negate_g1_be(PROOF_A_BYTES);
            let public_inputs: [[u8; 32]; 1] = [*PUBLIC_INPUT_BYTES];

            let mut verifier = Groth16Verifier::new_with_commitment(
                &proof_a,
                PROOF_B_BYTES,
                PROOF_C_BYTES,
                commitment,
                pok,
                &public_inputs,
                vk,
            )
            .expect("new_with_commitment");
            verifier.verify()
        }

        #[test]
        fn bsb22_e2e_verifies() {
            let vk_owned = parse_gnark_vk_bytes(VK_BYTES).unwrap();
            assert_eq!(vk_owned.nr_pubinputs, 1);
            assert!(vk_owned.vk_commitment.is_some());
            let vk = vk_owned.as_borrowed();

            let proof_a = negate_g1_be(PROOF_A_BYTES);
            let proof_b = *PROOF_B_BYTES;
            let proof_c = *PROOF_C_BYTES;
            let commitment = *COMMITMENT_BYTES;
            let pok = *POK_BYTES;
            let public_inputs: [[u8; 32]; 1] = [*PUBLIC_INPUT_BYTES];

            let mut verifier = Groth16Verifier::new_with_commitment(
                &proof_a,
                &proof_b,
                &proof_c,
                &commitment,
                &pok,
                &public_inputs,
                &vk,
            )
            .expect("new_with_commitment");
            verifier.verify().expect("verify");
        }

        #[test]
        fn bsb22_e2e_rejects_mutated_public_input() {
            let vk_owned = parse_gnark_vk_bytes(VK_BYTES).unwrap();
            let vk = vk_owned.as_borrowed();

            let proof_a = negate_g1_be(PROOF_A_BYTES);
            let proof_b = *PROOF_B_BYTES;
            let proof_c = *PROOF_C_BYTES;
            let commitment = *COMMITMENT_BYTES;
            let pok = *POK_BYTES;
            let mut public_input = *PUBLIC_INPUT_BYTES;
            public_input[31] ^= 1;
            let public_inputs: [[u8; 32]; 1] = [public_input];

            let mut verifier = Groth16Verifier::new_with_commitment(
                &proof_a,
                &proof_b,
                &proof_c,
                &commitment,
                &pok,
                &public_inputs,
                &vk,
            )
            .expect("new_with_commitment");
            assert_eq!(
                verifier.verify(),
                Err(Groth16Error::ProofVerificationFailed)
            );
        }

        #[test]
        fn bsb22_e2e_new_with_commitment_rejects_short_vk_ic() {
            // Construct a vk with one fewer ic entry than the constructor
            // expects (NR_INPUTS + 2 = 3, but we provide 2). Should be
            // rejected by `new_with_commitment` length check.
            let vk_owned = parse_gnark_vk_bytes(VK_BYTES).unwrap();
            let mut vk = vk_owned.as_borrowed();
            let truncated: Vec<[u8; 64]> = vk_owned.vk_ic[..vk_owned.vk_ic.len() - 1].to_vec();
            vk.vk_ic = &truncated;

            let proof_a = negate_g1_be(PROOF_A_BYTES);
            let proof_b = *PROOF_B_BYTES;
            let proof_c = *PROOF_C_BYTES;
            let commitment = *COMMITMENT_BYTES;
            let pok = *POK_BYTES;
            let public_inputs: [[u8; 32]; 1] = [*PUBLIC_INPUT_BYTES];

            let err = Groth16Verifier::new_with_commitment(
                &proof_a,
                &proof_b,
                &proof_c,
                &commitment,
                &pok,
                &public_inputs,
                &vk,
            )
            .unwrap_err();
            assert_eq!(err, Groth16Error::InvalidPublicInputsLength);
        }

        #[test]
        fn bsb22_e2e_rejects_substituted_on_curve_commitment() {
            let vk_owned = parse_gnark_vk_bytes(VK_BYTES).unwrap();
            let vk = vk_owned.as_borrowed();

            // The generator is on-curve, so prepare_inputs accepts it,
            // but its BSB22 hash differs from the honest commitment's:
            // kSum no longer matches what proof_c commits to and the
            // main pairing rejects before the PoK check runs.
            assert_eq!(
                verify_with_commitment_and_pok(&G1_GENERATOR_BE, POK_BYTES, &vk),
                Err(Groth16Error::ProofVerificationFailed)
            );
        }

        #[test]
        fn bsb22_e2e_rejects_substituted_on_curve_pok() {
            let vk_owned = parse_gnark_vk_bytes(VK_BYTES).unwrap();
            let vk = vk_owned.as_borrowed();

            // Honest commitment, so prepare_inputs and the main
            // pairing pass; the substituted PoK then fails the
            // Pedersen knowledge-proof pairing.
            assert_eq!(
                verify_with_commitment_and_pok(COMMITMENT_BYTES, &G1_GENERATOR_BE, &vk),
                Err(Groth16Error::CommitmentPokVerificationFailed)
            );
        }

        #[test]
        fn bsb22_e2e_rejects_swapped_commitment_and_pok() {
            let vk_owned = parse_gnark_vk_bytes(VK_BYTES).unwrap();
            let vk = vk_owned.as_borrowed();

            // Both are valid G1 points, but hashing the PoK bytes in
            // place of the commitment changes kSum, so the main
            // pairing rejects before the PoK check runs.
            assert_eq!(
                verify_with_commitment_and_pok(POK_BYTES, COMMITMENT_BYTES, &vk),
                Err(Groth16Error::ProofVerificationFailed)
            );
        }

        #[test]
        fn bsb22_e2e_rejects_identity_commitment_and_pok() {
            let vk_owned = parse_gnark_vk_bytes(VK_BYTES).unwrap();
            let vk = vk_owned.as_borrowed();

            // All-zero bytes encode the G1 identity, which the
            // syscalls accept, and e(0, gSigmaNeg) * e(0, g) == 1
            // would pass the PoK check trivially (matching gnark).
            // The proof still fails: hashing the zero commitment
            // yields a kSum that proof_c does not commit to, so the
            // main pairing rejects.
            assert_eq!(
                verify_with_commitment_and_pok(&[0u8; 64], &[0u8; 64], &vk),
                Err(Groth16Error::ProofVerificationFailed)
            );
        }

        #[test]
        fn bsb22_e2e_rejects_not_on_curve_commitment() {
            let vk_owned = parse_gnark_vk_bytes(VK_BYTES).unwrap();
            let vk = vk_owned.as_borrowed();

            // The G1 addition syscall rejects the off-curve point when
            // prepare_inputs adds the raw commitment to kSum.
            assert_eq!(
                verify_with_commitment_and_pok(&NOT_ON_CURVE_G1_BE, POK_BYTES, &vk),
                Err(Groth16Error::Bsb22InvalidCommitmentPoint)
            );
        }

        #[test]
        fn bsb22_e2e_rejects_not_on_curve_pok() {
            let vk_owned = parse_gnark_vk_bytes(VK_BYTES).unwrap();
            let vk = vk_owned.as_borrowed();

            // Honest commitment, so prepare_inputs and the main
            // pairing pass; the pairing syscall then rejects the
            // off-curve PoK point inside the knowledge-proof check.
            assert_eq!(
                verify_with_commitment_and_pok(COMMITMENT_BYTES, &NOT_ON_CURVE_G1_BE, &vk),
                Err(Groth16Error::CommitmentPokVerificationFailed)
            );
        }

        #[test]
        fn bsb22_e2e_rejects_public_input_greater_than_field_size() {
            let vk_owned = parse_gnark_vk_bytes(VK_BYTES).unwrap();
            let vk = vk_owned.as_borrowed();

            let proof_a = negate_g1_be(PROOF_A_BYTES);
            let public_inputs: [[u8; 32]; 1] =
                [ark_bn254::Fr::MODULUS.to_bytes_be().try_into().unwrap()];

            let mut verifier = Groth16Verifier::new_with_commitment(
                &proof_a,
                PROOF_B_BYTES,
                PROOF_C_BYTES,
                COMMITMENT_BYTES,
                POK_BYTES,
                &public_inputs,
                &vk,
            )
            .expect("new_with_commitment");
            assert_eq!(
                verifier.verify_unchecked(),
                Err(Groth16Error::ProofVerificationFailed)
            );
            assert_eq!(
                verifier.verify(),
                Err(Groth16Error::PublicInputGreaterThanFieldSize)
            );
        }

        #[test]
        fn bsb22_e2e_new_rejects_bsb22_vk() {
            let vk_owned = parse_gnark_vk_bytes(VK_BYTES).unwrap();
            let vk = vk_owned.as_borrowed();

            let proof_a = negate_g1_be(PROOF_A_BYTES);
            let public_inputs: [[u8; 32]; 1] = [*PUBLIC_INPUT_BYTES];

            let err =
                Groth16Verifier::new(&proof_a, PROOF_B_BYTES, PROOF_C_BYTES, &public_inputs, &vk)
                    .unwrap_err();
            assert_eq!(err, Groth16Error::UnexpectedCommitmentKey);
        }

        #[test]
        fn bsb22_e2e_new_with_commitment_rejects_standard_vk() {
            // The standard-Groth16 vk from the parent test module has
            // no commitment key; the commitment-key check runs before
            // the vk_ic length check, so the input count is irrelevant.
            let proof_a = negate_g1_be(PROOF_A_BYTES);
            let public_inputs: [[u8; 32]; 1] = [*PUBLIC_INPUT_BYTES];

            let err = Groth16Verifier::new_with_commitment(
                &proof_a,
                PROOF_B_BYTES,
                PROOF_C_BYTES,
                COMMITMENT_BYTES,
                POK_BYTES,
                &public_inputs,
                &VERIFYING_KEY,
            )
            .unwrap_err();
            assert_eq!(err, Groth16Error::MissingCommitmentKey);
        }

        #[test]
        fn bsb22_e2e_rejects_tampered_commitment_key() {
            let mut vk_owned = parse_gnark_vk_bytes(VK_BYTES).unwrap();
            let commitment_key = vk_owned.vk_commitment.as_mut().expect("commitment key");
            // Replace GSigmaNeg with G — still a valid G2 point, so
            // the pairing syscall accepts the input, but the Pedersen
            // knowledge-proof equation no longer holds. The main
            // pairing does not involve the commitment key and passes.
            commitment_key.g_sigma_neg_g2 = commitment_key.g2;
            let vk = vk_owned.as_borrowed();

            assert_eq!(
                verify_with_commitment_and_pok(COMMITMENT_BYTES, POK_BYTES, &vk),
                Err(Groth16Error::CommitmentPokVerificationFailed)
            );
        }
    }
}
