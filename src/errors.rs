#[cfg(feature = "circom")]
use alloc::string::{String, ToString};

use thiserror::Error;

#[derive(Debug, Error, PartialEq)]
pub enum Groth16Error {
    #[error("ProofVerificationFailed")]
    ProofVerificationFailed,
    #[error("PreparingInputsG1AdditionFailed")]
    PreparingInputsG1AdditionFailed,
    #[error("PreparingInputsG1MulFailed")]
    PreparingInputsG1MulFailed,
    #[error("InvalidPublicInputsLength")]
    InvalidPublicInputsLength,
    #[error("DecompressingG1Failed")]
    DecompressingG1Failed,
    #[error("DecompressingG2Failed")]
    DecompressingG2Failed,
    #[error("PublicInputGreaterThanFieldSize")]
    PublicInputGreaterThanFieldSize,
    #[cfg(feature = "circom")]
    #[error("Arkworks serialization error: {0}")]
    ArkworksSerializationError(String),
    #[cfg(feature = "circom")]
    #[error("Failed to convert proof component to byte array")]
    ProofConversionError,
    #[cfg(feature = "bsb22")]
    #[error("MissingCommitmentKey")]
    MissingCommitmentKey,
    #[cfg(feature = "bsb22")]
    #[error("CommitmentPokVerificationFailed")]
    CommitmentPokVerificationFailed,
    #[cfg(feature = "bsb22")]
    #[error("Bsb22HashToFieldFailed")]
    Bsb22HashToFieldFailed,
    #[cfg(feature = "bsb22")]
    #[error("Bsb22UnsupportedMultiCommitment")]
    Bsb22UnsupportedMultiCommitment,
    #[cfg(feature = "bsb22")]
    #[error("Bsb22InvalidVerifyingKeyBinary")]
    Bsb22InvalidVerifyingKeyBinary,
    /// The verifying key contains a BSB22 Pedersen commitment key but
    /// the standard constructor was used. Call
    /// `Groth16Verifier::new_with_commitment` instead. Not feature
    /// gated because standard builds must also refuse BSB22 vks.
    #[error("UnexpectedCommitmentKey")]
    UnexpectedCommitmentKey,
    /// The gnark circuit commits to public inputs
    /// (`PublicAndCommitmentCommitted` has a non-empty entry), which
    /// this verifier's BSB22 hash preimage does not support — only
    /// commitments over private wires (e.g. `logderivlookup`) work.
    #[cfg(feature = "bsb22")]
    #[error("Bsb22CommittedPublicInputsUnsupported")]
    Bsb22CommittedPublicInputsUnsupported,
    /// Reading the vk.bin or writing the generated Rust file failed in
    /// `generate_bsb22_vk_file` — a filesystem problem (wrong path,
    /// permissions), not a malformed verifying key.
    #[cfg(feature = "bsb22")]
    #[error("Bsb22VkFileIoFailed")]
    Bsb22VkFileIoFailed,
    /// The proof's BSB22 commitment bytes do not encode a valid BN254
    /// G1 point (the alt_bn128 syscall rejected them).
    #[cfg(feature = "bsb22")]
    #[error("Bsb22InvalidCommitmentPoint")]
    Bsb22InvalidCommitmentPoint,
}

#[cfg(feature = "circom")]
impl From<ark_serialize::SerializationError> for Groth16Error {
    fn from(e: ark_serialize::SerializationError) -> Self {
        Groth16Error::ArkworksSerializationError(e.to_string())
    }
}

impl From<Groth16Error> for u32 {
    fn from(error: Groth16Error) -> Self {
        // Codes 0, 4, and 5 belonged to variants that were never
        // constructed and were removed (IncompatibleVerifyingKeyWith-
        // NrPublicInputs, InvalidG1Length, InvalidG2Length); they stay
        // unassigned so historical error codes keep their meaning.
        match error {
            Groth16Error::ProofVerificationFailed => 1,
            Groth16Error::PreparingInputsG1AdditionFailed => 2,
            Groth16Error::PreparingInputsG1MulFailed => 3,
            Groth16Error::InvalidPublicInputsLength => 6,
            Groth16Error::DecompressingG1Failed => 7,
            Groth16Error::DecompressingG2Failed => 8,
            Groth16Error::PublicInputGreaterThanFieldSize => 9,
            #[cfg(feature = "circom")]
            Groth16Error::ArkworksSerializationError(_) => 10,
            #[cfg(feature = "circom")]
            Groth16Error::ProofConversionError => 11,
            #[cfg(feature = "bsb22")]
            Groth16Error::MissingCommitmentKey => 12,
            #[cfg(feature = "bsb22")]
            Groth16Error::CommitmentPokVerificationFailed => 13,
            #[cfg(feature = "bsb22")]
            Groth16Error::Bsb22HashToFieldFailed => 14,
            #[cfg(feature = "bsb22")]
            Groth16Error::Bsb22UnsupportedMultiCommitment => 15,
            #[cfg(feature = "bsb22")]
            Groth16Error::Bsb22InvalidVerifyingKeyBinary => 16,
            Groth16Error::UnexpectedCommitmentKey => 17,
            #[cfg(feature = "bsb22")]
            Groth16Error::Bsb22CommittedPublicInputsUnsupported => 18,
            #[cfg(feature = "bsb22")]
            Groth16Error::Bsb22VkFileIoFailed => 19,
            #[cfg(feature = "bsb22")]
            Groth16Error::Bsb22InvalidCommitmentPoint => 20,
        }
    }
}
