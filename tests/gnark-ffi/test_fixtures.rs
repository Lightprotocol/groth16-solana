//! Baked BSB22 fixture bytes for the lib-internal unit tests
//! (`groth16::tests::bsb22_e2e` and `vk::gnark::tests`).
//!
//! One consistent (vk, proof, public input) snapshot from a single
//! gnark `Setup` + `Prove` of the `bsb22_1` bench circuit (one public
//! input, one `logderivlookup` query merged into one BSB22
//! commitment). The generator seeds gnark's randomness, so these
//! bytes are reproducible — regenerate and dump them with:
//!
//! ```sh
//! cd tests/gnark-ffi/gnark-fixture
//! go run ./cmd/benchgen /tmp/bench-fixtures
//! xxd -p -c 9999 /tmp/bench-fixtures/bsb22_1_<name>.bin
//! ```
//!
//! `proof_a` is gnark's raw (non-negated) A; tests negate it with
//! [`crate::groth16::negate_g1_be`] before verifying.

/// Compile-time hex decode; malformed input fails the build.
const fn hex<const N: usize>(s: &str) -> [u8; N] {
    const fn nibble(c: u8) -> u8 {
        match c {
            b'0'..=b'9' => c - b'0',
            b'a'..=b'f' => c - b'a' + 10,
            _ => panic!("invalid hex digit"),
        }
    }
    let bytes = s.as_bytes();
    assert!(bytes.len() == N * 2, "hex length mismatch");
    let mut out = [0u8; N];
    let mut i = 0;
    while i < N {
        out[i] = (nibble(bytes[i * 2]) << 4) | nibble(bytes[i * 2 + 1]);
        i += 1;
    }
    out
}

/// gnark `VerifyingKey.WriteRawTo` binary (incl. the BSB22
/// Pedersen commitment key sections).
pub(crate) const VK_BYTES: &[u8] = &hex::<1040>(
    "2832b3b107817b4b0767f9add86782a905485710c4a71b71de6a1ce2a362348f0157e947a6459c2559e90a2d7832281b9bb68ba448ac59600e3789dc6ff301b626443ee51bf45118c142670c96322bd7e3c931d4bbefee6f485ce8f61248669c14f14d69caf7f13138cdacf5820aabc3ab2fc940b6b1086d771d9991b69a13352e5867a8bb72e8c3c6ad04b012bf218142b8ec948f7392a13c22f14cf1ec8ae5243abfb66a82ffbec8bd308d3f4d971dc2fa37d074be8100ca7ee1b51d4a93aa119e9eaba672bbc9620ce0342f1aeb1164fef301aec6b0e4145b6e90102eb7e5303a60a108b0fdd8647c38e94c9375dada568791db4d763f6c0ecd331bf22eb617bff14f5e1c427e93758cdc923868103ea73b375f0deeeed39d24d96a5aa049040da2d6acdd758682e66beb9e5a0337d5c62133541bdb6e9530a0eaa4d2d18a1d6420e6a1ff281802ee8df161f4553c81f4648c2a83efa3652620a3d6fb454502949594678dda680f8043f39f13076724f74a8909cfa393c1281c12bf7d4179218c8f52dc7a231df1752dab04ec702204444ef66a9a003545fc064e7016ca41285b4da02e9a6b95b94903882f19f19d35a4fc5e248624ca538da61014c025260779a5c4348e3450f0daa98eb31d8c1e73e94313420a870d69a428bae63e68272f119218fb9b7a86a02dd78def56cc9f3ac1c320ca0120594c64e388819ac4c21adf3fec199c7cfcb977e3a878f6d353dfec5731d76240d23de3c46cd884829904c477d2c941158a38a8c75cfba2e893acbaf0cd44d5618cb88e888f0e7acc29000000032e27548f4c368316e4b8416ef0e47972a13d46cc38de3db4d832f9a9ea1a7d7b1a1c9fc4f37a6f0709d85472db0629ddd6aaf76aa8dda353e9e64742ee8413c80b56d2c354d201468dbb63f67e0951343b26b02550ca3e0d6099dc23adaaf05713e9a0d13c18faa7aa5d4a16b7e8ab34506e7e0be791489401b3de9917801be20e8cab57283209b616fb4ec703109866324e488f5038a0c1bb4acc023a265ed00a6327b0c5146f2fa229189c97b22aef77317ade40f705239cdb7242e4ce311e0000000100000000000000012bd6284973bba006e4e2d278659fa700c8fa4f5d37eaa83dff66ab1c609b99f71e21459bcecab9296cd8bf9ce41333203af61de460679617028443967dca125c1e77f19177c7fa2c5f3fbe8d20867a6d87a315308099307f8f5842a571e0e97700cffb185fb05829108ef0904320f76238e710ddfc44052db1a83ebb1e5f43461cf2826b36b05d5abaff685da0fc4c2f403ca98d7c474163889de19b0500f8c7126d7ddd567721b2bad43feb6725d15c4cfdedf4c9e7931cb9acb563077684690fe7d91fd6ab0ee5de49cf44d3c3a9dc3160c3615ea8958fc8cc3d86b6188db00f7007aea846f8007f8c930978ea572f0a45c048cf7dcbbecf41523d7c3486fc",
);

/// `proof.Ar` — G1 uncompressed BE, NOT negated.
pub(crate) const PROOF_A_BYTES: &[u8; 64] = &hex::<64>(
    "02eeb18e52f9121d135f8866bda4306b1c252857e8531b31b79bbf1f8edabad6139c2202691bed1fa22388d61da2fac95fa93d98b267a8827fdd8688170a0e6e",
);

/// `proof.Bs` — G2 uncompressed BE.
pub(crate) const PROOF_B_BYTES: &[u8; 128] = &hex::<128>(
    "104f3fdfcd3b6ff3594ac29cfe138cef177b4dc2fa0c5cd4e3d25813400547dc04f80804a13ac09d5113e237d7a4f533e3e2a9c3c3f53626ccd687409d6fc27d0bfb4caa91473e797e7481ee07dec577443e615240d93f816647d2f388cc6c92026598dd65008e4ca9d3e61a446b7d20579600898eebd30dd63035e14569d196",
);

/// `proof.Krs` — G1 uncompressed BE.
pub(crate) const PROOF_C_BYTES: &[u8; 64] = &hex::<64>(
    "05e4d1af086c06c514f108596853809f095aef380eb826a55f676970693c7b0a12ad50ed0f1d6ff86b63f137414b3e1fc1c26cb0fdc6fecedd90dfb7e7d6e107",
);

/// `proof.Commitments[0]` — the single BSB22 Pedersen commitment.
pub(crate) const COMMITMENT_BYTES: &[u8; 64] = &hex::<64>(
    "016dab9da4ed7bfaa3a55d4b37ddfe0ef8b570560cbfbe7336d0ba08591dc5fc2a22b326576e9aea18f2ddf1b93e9546fe34db9af34431c2aedfb7800b95cb2b",
);

/// `proof.CommitmentPok` — the Pedersen knowledge proof.
pub(crate) const POK_BYTES: &[u8; 64] = &hex::<64>(
    "224611505c18413e0871351fc322fee1c3c46e0d4905ea5588df0b5871b3c96207d8ace0738c0e416dc50b375c013fd30fae36585b65d3ef435037f1b5972c4b",
);

/// The single public input X = 1 as a BE field element.
pub(crate) const PUBLIC_INPUT_BYTES: &[u8; 32] =
    &hex::<32>("0000000000000000000000000000000000000000000000000000000000000001");
