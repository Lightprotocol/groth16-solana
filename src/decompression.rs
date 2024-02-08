use solana_program::alt_bn128::compression::prelude::{
    alt_bn128_g1_decompress, alt_bn128_g2_decompress,
};

use crate::errors::Groth16Error;

pub fn decompress_g1(g1_bytes: &[u8; 32]) -> Result<[u8; 64], Groth16Error> {
    let decompressed_g1 = alt_bn128_g1_decompress(g1_bytes)
        .map_err(|_| crate::errors::Groth16Error::DecompressingG1Failed {})?;
    Ok(decompressed_g1)
}

pub fn decompress_g2(g2_bytes: &[u8; 64]) -> Result<[u8; 128], Groth16Error> {
    let decompressed_g2 = alt_bn128_g2_decompress(g2_bytes)
        .map_err(|_| crate::errors::Groth16Error::DecompressingG2Failed {})?;
    Ok(decompressed_g2)
}

#[cfg(test)]
mod tests {

    use super::*;
    use ark_bn254;
    use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, Compress, Validate};

    use ark_serialize::Flags;
    type G1 = ark_bn254::g1::G1Affine;
    type G2 = ark_bn254::g2::G2Affine;

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
    fn apply_bitmask() {
        use solana_program::alt_bn128::compression::prelude::convert_endianness;

        let proof_a_le: G1 = G1::deserialize_with_mode(
            &convert_endianness::<32, 64>(&PROOF[0..64].try_into().unwrap())[..],
            Compress::No,
            Validate::Yes,
        )
        .unwrap();

        let index = 31;
        let mask = proof_a_le.to_flags().u8_bitmask();
        let mut new_proof_a_bytes =
            convert_endianness::<32, 64>(&PROOF[0..64].try_into().unwrap()).to_vec();
        new_proof_a_bytes[index] |= mask;
        let proof_a_compressed_be: [u8; 32] =
            convert_endianness::<32, 64>(&new_proof_a_bytes.try_into().unwrap())[0..32]
                .try_into()
                .unwrap();
        let proof_a_be = decompress_g1(&proof_a_compressed_be).unwrap();
        assert_eq!(proof_a_be.to_vec(), PROOF[0..64].to_vec());

        let index = 63;
        let le_proof_b_bytes = convert_endianness::<64, 128>(&PROOF[64..192].try_into().unwrap());
        let mut new_proof_b_bytes = le_proof_b_bytes[0..64].to_vec();
        let proof_b_uncompressed =
            G2::deserialize_with_mode(&le_proof_b_bytes[..], Compress::No, Validate::Yes).unwrap();
        let mask = proof_b_uncompressed.to_flags().u8_bitmask();

        new_proof_b_bytes[index] |= mask;

        let mut serialized_compressed = [0u8; 64];
        G2::serialize_compressed(&proof_b_uncompressed, serialized_compressed.as_mut()).unwrap();

        assert_eq!(
            serialized_compressed[0..32].to_vec(),
            le_proof_b_bytes[..32]
        );
        assert_eq!(
            serialized_compressed[32..64].to_vec(),
            le_proof_b_bytes[32..64]
        );
        assert_eq!(
            serialized_compressed[0..32].to_vec(),
            new_proof_b_bytes[..32]
        );
        assert_eq!(
            serialized_compressed[32..64].to_vec(),
            new_proof_b_bytes[32..64]
        );

        let proof_b = decompress_g2(&convert_endianness::<64, 64>(
            &new_proof_b_bytes.try_into().unwrap(),
        ))
        .unwrap();
        assert_eq!(proof_b.to_vec(), PROOF[64..192].to_vec());

        let index = 31;
        let proof_c_uncompressed = G1::deserialize_uncompressed(
            &convert_endianness::<32, 64>(&PROOF[192..].try_into().unwrap())[..],
        )
        .unwrap();

        let mask = proof_c_uncompressed.to_flags().u8_bitmask();
        let mut new_proof_c_bytes =
            convert_endianness::<32, 64>(&PROOF[192..].try_into().unwrap()).to_vec();
        new_proof_c_bytes[index] |= mask;
        let mut serialized_compressed = [0u8; 32];
        G1::serialize_compressed(&proof_c_uncompressed, serialized_compressed.as_mut()).unwrap();
        assert_eq!(serialized_compressed.to_vec(), new_proof_c_bytes[..32]);
        let proof_c = decompress_g1(
            &convert_endianness::<32, 32>(&new_proof_c_bytes[0..32].try_into().unwrap())
                .try_into()
                .unwrap(),
        )
        .unwrap();
        assert_eq!(proof_c.to_vec(), PROOF[192..].to_vec());
    }
}
