use std::ops::Neg;

use crate::errors::Groth16Error;
use ark_bn254;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, Compress};
use solana_program::alt_bn128::compression::prelude::{
    alt_bn128_g1_decompress, alt_bn128_g2_decompress,
};
type G1 = ark_bn254::g1::G1Affine;
type G2 = ark_bn254::g2::G2Affine;

pub fn decompress_g1(g1_bytes: &[u8], negate: bool) -> Result<[u8; 64], Groth16Error> {
    let decompressed_g1 = alt_bn128_g1_decompress(g1_bytes)
        .map_err(|_| crate::errors::Groth16Error::DecompressingG1Failed {})?;
    // let decompressed_g1 = if negate {
    //     G1::deserialize_compressed(g1_bytes).unwrap().neg()
    // } else {
    //     G1::deserialize_compressed(g1_bytes).unwrap()
    // };
    // let mut decompressed_g1_bytes = [0u8; 64];
    // decompressed_g1
    //     .x
    //     .serialize_with_mode(&mut decompressed_g1_bytes[..32], Compress::No)
    //     .map_err(|_| crate::errors::Groth16Error::DecompressingG2Failed)?;
    // decompressed_g1
    //     .y
    //     .serialize_with_mode(&mut decompressed_g1_bytes[32..], Compress::No)
    //     .map_err(|_| crate::errors::Groth16Error::DecompressingG2Failed)?;
    // let mut proof_a_neg = [0u8; 64];
    // proof_a_uncompreseed
    //     .neg()
    //     .x
    //     .serialize_with_mode(&mut proof_a_neg[..32], Compress::No)
    //     .unwrap();
    // proof_a_uncompreseed
    //     .neg()
    //     .y
    //     .serialize_with_mode(&mut proof_a_neg[32..], Compress::No)
    //     .unwrap();
    Ok(decompressed_g1)
}

pub fn decompress_g2(g2_bytes: &[u8]) -> Result<[u8; 128], Groth16Error> {
    let decompressed_g2 = alt_bn128_g2_decompress(g2_bytes)
        .map_err(|_| crate::errors::Groth16Error::DecompressingG2Failed {})?;
    // let decompressed_g2 = G2::deserialize_compressed(g2_bytes).unwrap();
    // let mut decompressed_g2_bytes = [0u8; 128];
    // decompressed_g2
    //     .x
    //     .serialize_with_mode(&mut decompressed_g2_bytes[..64], Compress::No)
    //     .map_err(|_| crate::errors::Groth16Error::DecompressingG2Failed)?;
    // decompressed_g2
    //     .y
    //     .serialize_with_mode(&mut decompressed_g2_bytes[64..128], Compress::No)
    //     .map_err(|_| crate::errors::Groth16Error::DecompressingG2Failed)?;
    Ok(decompressed_g2)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bn254;
    use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, Compress, Validate};

    // use ark_ff::bytes::{FromBytes, ToBytes};
    use ark_serialize::Flags;
    type G1 = ark_bn254::g1::G1Affine;
    type G2 = ark_bn254::g2::G2Affine;

    fn change_endianness(bytes: &[u8]) -> Vec<u8> {
        let mut vec = Vec::new();
        for b in bytes.chunks(32) {
            for byte in b.iter().rev() {
                vec.push(*byte);
            }
        }
        vec
    }

    fn convert_edianness_128(bytes: &[u8]) -> Vec<u8> {
        bytes
            .chunks(64)
            .flat_map(|b| b.iter().copied().rev().collect::<Vec<u8>>())
            .collect::<Vec<u8>>()
    }

    pub const PUBLIC_INPUTS: [u8; 9 * 32] = [
        34, 238, 251, 182, 234, 248, 214, 189, 46, 67, 42, 25, 71, 58, 145, 58, 61, 28, 116, 110,
        60, 17, 82, 149, 178, 187, 160, 211, 37, 226, 174, 231, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 51, 152, 17, 147, 4, 247, 199, 87, 230, 85,
        103, 90, 28, 183, 95, 100, 200, 46, 3, 158, 247, 196, 173, 146, 207, 167, 108, 33, 199, 18,
        13, 204, 198, 101, 223, 186, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 7, 49, 65, 41, 7, 130, 55, 65, 197, 232, 175, 217, 44, 151, 149, 225,
        75, 86, 158, 105, 43, 229, 65, 87, 51, 150, 168, 243, 176, 175, 11, 203, 180, 149, 72, 103,
        46, 93, 177, 62, 42, 66, 223, 153, 51, 193, 146, 49, 154, 41, 69, 198, 224, 13, 87, 80,
        222, 171, 37, 141, 0, 1, 50, 172, 18, 28, 213, 213, 40, 141, 45, 3, 180, 200, 250, 112,
        108, 94, 35, 143, 82, 63, 125, 9, 147, 37, 191, 75, 62, 221, 138, 20, 166, 151, 219, 237,
        254, 58, 230, 189, 33, 100, 143, 241, 11, 251, 73, 141, 229, 57, 129, 168, 83, 23, 235,
        147, 138, 225, 177, 250, 13, 97, 226, 162, 6, 232, 52, 95, 128, 84, 90, 202, 25, 178, 1,
        208, 219, 169, 222, 123, 113, 202, 165, 77, 183, 98, 103, 237, 187, 93, 178, 95, 169, 156,
        38, 100, 125, 218, 104, 94, 104, 119, 13, 21,
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
    fn compression() {
        let mut public_inputs_vec = Vec::new();
        for input in PUBLIC_INPUTS.chunks(32) {
            public_inputs_vec.push(input);
        }
        let proof_a: G1 = G1::deserialize_with_mode(
            &*[&change_endianness(&PROOF[0..64]), &[0u8][..]].concat(),
            Compress::No,
            Validate::Yes,
        )
        .unwrap();
        let mut res = [0u8; 32];
        G1::serialize_compressed(&proof_a, res.as_mut()).unwrap();

        assert_eq!(
            PROOF[0..32]
                .to_vec()
                .clone()
                .iter()
                .rev()
                .collect::<Vec<&u8>>(),
            res.iter().collect::<Vec<&u8>>(),
        );

        let proof_a_uncompreseed: G1 = G1::deserialize_compressed(
            &[&change_endianness(&PROOF[0..64]), &[0u8][..]].concat()[0..32],
        )
        .unwrap();
        println!(
            "proof_a_uncompressed: {:?}",
            proof_a_uncompreseed.to_flags()
        );

        let mut proof_a_neg = [0u8; 64];
        proof_a_uncompreseed
            .neg()
            .x
            .serialize_with_mode(&mut proof_a_neg[..32], Compress::No)
            .unwrap();
        proof_a_uncompreseed
            .neg()
            .y
            .serialize_with_mode(&mut proof_a_neg[32..], Compress::No)
            .unwrap();

        let proof_a = decompress_g1(&change_endianness(&PROOF[0..64])[0..32], true).unwrap();
        assert_eq!(proof_a, proof_a_neg);

        let index = 63;
        let le_proof_b_bytes = convert_edianness_128(&PROOF[64..192]);
        let mut new_proof_b_bytes = le_proof_b_bytes[0..64].to_vec();
        let proof_b_uncompressed =
            G2::deserialize_with_mode(&le_proof_b_bytes[..], Compress::No, Validate::Yes).unwrap();
        let mask = proof_b_uncompressed.to_flags().u8_bitmask();

        println!("proof_c {}", proof_b_uncompressed);
        println!("to_flags {:?}", proof_b_uncompressed.to_flags());
        new_proof_b_bytes[index] |= mask;
        println!("new_proof_b_bytes[index] {}", new_proof_b_bytes[index]);

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

        let proof_b = decompress_g2(&new_proof_b_bytes).unwrap();
        assert_eq!(
            proof_b.to_vec(),
            convert_edianness_128(&PROOF[64..192]).to_vec()
        );

        let index = 31;
        let proof_c_uncompressed =
            G1::deserialize_uncompressed(&change_endianness(&PROOF[192..])[..]).unwrap();

        let mask = proof_c_uncompressed.to_flags().u8_bitmask();
        let mut new_proof_c_bytes = change_endianness(&PROOF[192..])[0..32].to_vec();
        new_proof_c_bytes[index] |= mask;
        println!("new_proof_c_bytes[index] {}", new_proof_c_bytes[index]);
        let mut serialized_compressed = [0u8; 32];
        G1::serialize_compressed(&proof_c_uncompressed, serialized_compressed.as_mut()).unwrap();
        assert_eq!(serialized_compressed.to_vec(), new_proof_c_bytes);
        let proof_c = decompress_g1(&new_proof_c_bytes[0..32], false).unwrap();
        assert_eq!(proof_c.to_vec(), change_endianness(&PROOF[192..]).to_vec());
        println!(
            "proof_c_uncompressed: {:?}",
            proof_c_uncompressed.to_flags()
        );
    }
}
