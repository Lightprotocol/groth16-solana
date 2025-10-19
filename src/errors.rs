use thiserror::Error;

#[derive(Debug, Error, PartialEq)]
pub enum Groth16Error {
    #[error("Incompatible Verifying Key with number of public inputs")]
    IncompatibleVerifyingKeyWithNrPublicInputs,
    #[error("ProofVerificationFailed")]
    ProofVerificationFailed,
    #[error("PreparingInputsG1AdditionFailed")]
    PreparingInputsG1AdditionFailed,
    #[error("PreparingInputsG1MulFailed")]
    PreparingInputsG1MulFailed,
    #[error("InvalidG1Length")]
    InvalidG1Length,
    #[error("InvalidG2Length")]
    InvalidG2Length,
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
}

#[cfg(feature = "circom")]
impl From<ark_serialize::SerializationError> for Groth16Error {
    fn from(e: ark_serialize::SerializationError) -> Self {
        Groth16Error::ArkworksSerializationError(e.to_string())
    }
}
