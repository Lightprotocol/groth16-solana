pub mod compression;
// pub mod prelude {
//     pub use crate::alt_bn128::{consts::*, target_arch::*, AltBn128Error};
// }

use {
    bytemuck::{Pod, Zeroable},
    thiserror::Error,
};

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum AltBn128Error {
    #[error("The input data is invalid")]
    InvalidInputData,
    #[error("Invalid group data")]
    GroupError,
    #[error("Slice data is going out of input data bounds")]
    SliceOutOfBounds,
    #[error("Unexpected error")]
    UnexpectedError,
    #[error("Failed to convert a byte slice into a vector {0:?}")]
    TryIntoVecError(Vec<u8>),
    #[error("Failed to convert projective to affine g1")]
    ProjectiveToG1Failed,
}

impl From<u64> for AltBn128Error {
    fn from(v: u64) -> AltBn128Error {
        match v {
            1 => AltBn128Error::InvalidInputData,
            2 => AltBn128Error::GroupError,
            3 => AltBn128Error::SliceOutOfBounds,
            4 => AltBn128Error::TryIntoVecError(Vec::new()),
            5 => AltBn128Error::ProjectiveToG1Failed,
            _ => AltBn128Error::UnexpectedError,
        }
    }
}

impl From<AltBn128Error> for u64 {
    fn from(v: AltBn128Error) -> u64 {
        match v {
            AltBn128Error::InvalidInputData => 1,
            AltBn128Error::GroupError => 2,
            AltBn128Error::SliceOutOfBounds => 3,
            AltBn128Error::TryIntoVecError(_) => 4,
            AltBn128Error::ProjectiveToG1Failed => 5,
            AltBn128Error::UnexpectedError => 0,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Pod, Zeroable)]
#[repr(transparent)]
pub struct PodG1(pub [u8; 64]);

#[derive(Clone, Copy, Debug, PartialEq, Eq, Pod, Zeroable)]
#[repr(transparent)]
pub struct PodG2(pub [u8; 128]);
