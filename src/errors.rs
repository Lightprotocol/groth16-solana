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

impl From<Groth16Error> for u32 {
    fn from(error: Groth16Error) -> Self {
        match error {
            Groth16Error::IncompatibleVerifyingKeyWithNrPublicInputs => 0,
            Groth16Error::ProofVerificationFailed => 1,
            Groth16Error::PreparingInputsG1AdditionFailed => 2,
            Groth16Error::PreparingInputsG1MulFailed => 3,
            Groth16Error::InvalidG1Length => 4,
            Groth16Error::InvalidG2Length => 5,
            Groth16Error::InvalidPublicInputsLength => 6,
            Groth16Error::DecompressingG1Failed => 7,
            Groth16Error::DecompressingG2Failed => 8,
            Groth16Error::PublicInputGreaterThanFieldSize => 9,
            #[cfg(feature = "circom")]
            Groth16Error::ArkworksSerializationError(_) => 10,
            #[cfg(feature = "circom")]
            Groth16Error::ProofConversionError => 11,
        }
    }
}
