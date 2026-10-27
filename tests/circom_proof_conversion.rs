#![cfg(feature = "circom")]

use circom_prover::prover::circom::{Proof, G1, G2};
use groth16_solana::{errors::Groth16Error, proof_parser::circom_prover::convert_proof};

fn generator_proof() -> Proof {
    // BN254 generators, expressed as circom-prover's integer coordinates.
    let g1 = G1 {
        x: 1u32.into(),
        y: 2u32.into(),
        z: 1u32.into(),
    };
    Proof {
        a: g1.clone(),
        b: G2 {
            x: [
                "10857046999023057135944570762232829481370756359578518086990519993285655852781"
                    .parse()
                    .unwrap(),
                "11559732032986387107991004021392285783925812861821192530917403151452391805634"
                    .parse()
                    .unwrap(),
            ],
            y: [
                "8495653923123431417604973247489272438418190587263600148770280649306958101930"
                    .parse()
                    .unwrap(),
                "4082367875863433681332203403145435568316851327593401208105741076214120093531"
                    .parse()
                    .unwrap(),
            ],
            z: [1u32.into(), 0u32.into()],
        },
        c: g1,
        protocol: "groth16".into(),
        curve: "bn128".into(),
    }
}

#[test]
fn converts_generators_to_expected_verifier_bytes() {
    // A is negated; G2 coordinates put c1 before c0; C is unchanged.
    let expected = (
        array_bytes::hex2array_unchecked::<_, 64>(
            "000000000000000000000000000000000000000000000000000000000000000130644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd45",
        ),
        array_bytes::hex2array_unchecked::<_, 128>(
            "198e9393920d483a7260bfb731fb5d25f1aa493335a9e71297e485b7aef312c21800deef121f1e76426a00665e5c4479674322d4f75edadd46debd5cd992f6ed090689d0585ff075ec9e99ad690c3395bc4b313370b38ef355acdadcd122975b12c85ea5db8c6deb4aab71808dcb408fe3d1e7690c43d37b4ce6cc0166fa7daa",
        ),
        array_bytes::hex2array_unchecked::<_, 64>(
            "00000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000002",
        ),
    );
    assert_eq!(convert_proof(&generator_proof()).unwrap(), expected);
}

#[test]
fn preserves_points_at_infinity() {
    // Arkworks encodes the infinity flag in the last coordinate's high byte.
    // A serializes its coordinates separately, so it carries no flag.
    let mut proof_b = [0u8; 128];
    proof_b[64] = 0x40;
    let mut proof_c = [0u8; 64];
    proof_c[32] = 0x40;
    assert_eq!(
        convert_proof(&Proof::default()).unwrap(),
        ([0u8; 64], proof_b, proof_c),
    );
}

#[test]
fn rejects_coordinate_larger_than_32_bytes() {
    let mut proof = generator_proof();
    proof.a.x <<= 256usize;
    assert_eq!(
        convert_proof(&proof),
        Err(Groth16Error::ProofConversionError)
    );
}

#[test]
fn rejects_coordinate_equal_to_base_field_modulus() {
    let mut proof = generator_proof();
    proof.a.x = "21888242871839275222246405745257275088696311157297823662689037894645226208583"
        .parse()
        .unwrap();
    assert!(matches!(
        convert_proof(&proof),
        Err(Groth16Error::ArkworksSerializationError(_))
    ));
}

#[test]
fn rejects_g1_point_off_curve() {
    let mut proof = generator_proof();
    proof.c.y = 3u32.into();
    assert!(matches!(
        convert_proof(&proof),
        Err(Groth16Error::ArkworksSerializationError(_))
    ));
}

#[test]
fn rejects_g2_point_off_curve() {
    let mut proof = generator_proof();
    proof.b.y = [1u32.into(), 0u32.into()];
    assert!(matches!(
        convert_proof(&proof),
        Err(Groth16Error::ArkworksSerializationError(_))
    ));
}
