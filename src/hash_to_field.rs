//! BSB22 hash-to-field for the BN254 scalar field, byte-exact with
//! gnark-crypto's `ecc/bn254/fr/element.go::Hash` (which is what
//! gnark's BSB22 commitment verifier uses at
//! `backend/groth16/bn254/verify.go:84-95`).
//!
//! Algorithm:
//! 1. RFC 9380 `expand_message_xmd` over SHA-256 with `L = 48` bytes
//!    (16 + 32 — the BN254 Fr modulus is 254 bits, plus a 128-bit
//!    security margin).
//! 2. Interpret the 48-byte output as a big-endian integer and reduce
//!    mod r via `ark_bn254::Fr::from_le_bytes_mod_order` (over the
//!    reversed buffer — the BE wrapper heap-allocates, the LE path
//!    does not).
//!
//! gnark's `fr.Hash(msg, dst, 1)` returns the resulting field element
//! marshalled as 32 big-endian bytes; we return the same.
//!
//! The implementation is **allocation-free**: the three SHA-256
//! preimage buffers used inside `expand_message_xmd` are
//! stack-allocated `[u8; MAX_SCRATCH]` arrays, the modular reduction
//! uses arkworks' non-allocating LE path, and the result is
//! serialized limb-by-limb into a stack array. This keeps the
//! on-chain CU cost predictable and avoids BPF heap pressure.
//!
//! `msg` and `dst` are const-generic fixed-size arrays, so the RFC
//! 9380 DST length limit and the scratch-buffer capacity are checked
//! at compile time and the functions are infallible.

use crate::syscalls::sha256;
use ark_bn254::Fr;
use ark_ff::PrimeField;

/// SHA-256 output size in bytes.
const B_IN_BYTES: usize = 32;
/// SHA-256 block size in bytes.
const R_IN_BYTES: usize = 64;
/// Per-element output length: 16-byte security margin + 32-byte modulus.
const L: usize = 48;
/// Upper bound on the `expand_message_xmd` preimage buffer size. Big
/// enough for any BSB22 call: `z_pad (64) + msg + l_i_b_str (2) +
/// 0x00 (1) + dst_prime (dst + 1)` with `msg <= ~150` bytes and `dst
/// <= ~30` bytes. The BSB22 caller uses msg=64 (one G1 point) and
/// dst="bsb22-commitment" (16 bytes), so the real usage is ~148.
/// A `const` assertion in `expand_message_xmd_sha256_l48` rejects any
/// instantiation whose preimage would exceed this, at compile time.
const MAX_SCRATCH: usize = 256;

/// RFC 9380 `expand_message_xmd` with SHA-256, specialized to the one
/// output length this crate needs (`L = 48`, so `ell = 2`).
///
/// Mirrors `gnark-crypto/ecc/bn254/fr/element.go::Hash` (which calls
/// `hash.ExpandMsgXmd(msg, dst, lenInBytes)`) for the single
/// `lenInBytes == 48` case. This is **not** a general RFC 9380
/// implementation — if another output length is ever required,
/// re-generalize this function (restore the `len_in_bytes` parameter
/// and the `ell` computation) rather than duplicating it.
///
/// `MSG_LEN` and `DST_LEN` are const generics, so the RFC 9380 DST
/// length limit (<= 255) and the scratch-buffer capacity are enforced
/// at compile time and no runtime error path exists.
fn expand_message_xmd_sha256_l48<const MSG_LEN: usize, const DST_LEN: usize>(
    msg: &[u8; MSG_LEN],
    dst: &[u8; DST_LEN],
) -> [u8; L] {
    // RFC 9380: len(DST) <= 255 so I2OSP(len(dst), 1) is well-defined.
    const { assert!(DST_LEN <= 255) };
    // Biggest preimage is b_0: z_pad (64) + msg + l_i_b_str (2) +
    // 0x00 (1) + dst_prime (DST_LEN + 1). Must fit the scratch buffer.
    const { assert!(R_IN_BYTES + MSG_LEN + 2 + 1 + DST_LEN + 1 <= MAX_SCRATCH) };

    // Single scratch buffer reused across all three SHA-256 calls.
    let mut scratch = [0u8; MAX_SCRATCH];

    // DST_prime = dst || I2OSP(len(dst), 1), appended to every preimage.
    let append_dst_prime = |scratch: &mut [u8; MAX_SCRATCH], offset: usize| -> usize {
        scratch[offset..offset + DST_LEN].copy_from_slice(dst);
        scratch[offset + DST_LEN] = DST_LEN as u8;
        offset + DST_LEN + 1
    };

    // b_0 = H(z_pad || msg || l_i_b_str || 0x00 || DST_prime)
    //   z_pad     = R_IN_BYTES zero bytes
    //   l_i_b_str = I2OSP(len_in_bytes, 2) = [0x00, 0x30] for len=48
    const L_I_B_STR: [u8; 2] = (L as u16).to_be_bytes();
    // z_pad is already zero in the scratch buffer; just advance.
    let mut offset = R_IN_BYTES;
    scratch[offset..offset + MSG_LEN].copy_from_slice(msg);
    offset += MSG_LEN;
    scratch[offset..offset + 2].copy_from_slice(&L_I_B_STR);
    offset += 2;
    scratch[offset] = 0x00;
    offset += 1;
    offset = append_dst_prime(&mut scratch, offset);
    let b0 = sha256(&scratch[..offset]);

    // b_1 = H(b_0 || I2OSP(1, 1) || DST_prime)
    let mut offset = 0;
    scratch[offset..offset + B_IN_BYTES].copy_from_slice(&b0);
    offset += B_IN_BYTES;
    scratch[offset] = 0x01;
    offset += 1;
    offset = append_dst_prime(&mut scratch, offset);
    let b1 = sha256(&scratch[..offset]);

    // b_2 = H((b_0 XOR b_1) || I2OSP(2, 1) || DST_prime)
    for (out_byte, (x, y)) in scratch
        .iter_mut()
        .zip(b0.iter().zip(b1.iter()))
        .take(B_IN_BYTES)
    {
        *out_byte = x ^ y;
    }
    let mut offset = B_IN_BYTES;
    scratch[offset] = 0x02;
    offset += 1;
    offset = append_dst_prime(&mut scratch, offset);
    let b2 = sha256(&scratch[..offset]);

    // uniform_bytes = (b_1 || b_2)[..L]
    let mut out = [0u8; L];
    out[..B_IN_BYTES].copy_from_slice(&b1);
    out[B_IN_BYTES..L].copy_from_slice(&b2[..L - B_IN_BYTES]);
    out
}

/// Compute gnark's `fr.Hash(msg, dst, 1)` over BN254 Fr and return the
/// resulting element as 32 big-endian bytes.
pub fn hash_to_field_bn254_fr<const MSG_LEN: usize, const DST_LEN: usize>(
    msg: &[u8; MSG_LEN],
    dst: &[u8; DST_LEN],
) -> [u8; 32] {
    let mut raw = expand_message_xmd_sha256_l48(msg, dst);
    // ark's `from_be_bytes_mod_order` copies its input to a heap Vec
    // just to reverse it; reverse the stack buffer in place and take
    // the LE path, which is allocation-free.
    raw.reverse();
    let fr_elem = Fr::from_le_bytes_mod_order(&raw);
    // `BigInt::to_bytes_be` returns a Vec; serialize the four
    // little-endian u64 limbs to big-endian bytes on the stack instead.
    let limbs = fr_elem.into_bigint().0;
    let mut out = [0u8; 32];
    for (chunk, limb) in out.chunks_exact_mut(8).zip(limbs.iter().rev()) {
        chunk.copy_from_slice(&limb.to_be_bytes());
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec::Vec;
    use proptest::prelude::*;

    /// Golden vectors harvested from gnark-crypto v0.19.0 via the
    /// `TestHashToFieldGoldenVectors` Go test in
    /// `tests/gnark-ffi/gnark-fixture/main_test.go`. Run that test and
    /// regenerate this list if you ever bump the gnark-crypto version.
    const DST: &[u8; 16] = b"bsb22-commitment";

    #[test]
    fn matches_gnark_empty() {
        let got = hash_to_field_bn254_fr(b"", DST);
        let want = hex_to_array("0cd710fca7c351e0f43221cbb4c4d2954de86c8e5bfd48f949cf791cec789074");
        assert_eq!(got, want);
    }

    #[test]
    fn matches_gnark_abc() {
        let got = hash_to_field_bn254_fr(b"abc", DST);
        let want = hex_to_array("145f64e0f93255bfdd0c0edce7c545f5bc1c0c42dfc7f8963e921ba26ad82284");
        assert_eq!(got, want);
    }

    #[test]
    fn matches_gnark_zero_g1() {
        let msg = [0u8; 64];
        let got = hash_to_field_bn254_fr(&msg, DST);
        let want = hex_to_array("1f1407ef745a0b1eae0567306b4560479d99b943b34072d983ad2ec6d37a1360");
        assert_eq!(got, want);
    }

    #[test]
    fn matches_gnark_sequential() {
        let mut msg = [0u8; 64];
        for (i, b) in msg.iter_mut().enumerate() {
            *b = i as u8;
        }
        let got = hash_to_field_bn254_fr(&msg, DST);
        let want = hex_to_array("1db84f0dba489bb416bbfff0075b6a5912717f427be8d818d9a9a86375b9e91b");
        assert_eq!(got, want);
    }

    /// RFC 9380 `expand_message_xmd` reference: RustCrypto's
    /// implementation from the `elliptic-curve` crate (dev-dependency),
    /// the same code the k256/p256 curve crates use for hash-to-curve.
    ///
    /// The production `expand_message_xmd_sha256_l48` is specialized to
    /// L = 48, a length the official CFRG vectors do not cover, so RFC
    /// conformance is established in two hops:
    /// 1. `reference_matches_rfc9380_vectors` checks this reference
    ///    (and our wiring of it) against all 10 official
    ///    expand_message_xmd(SHA-256) vectors (output lengths 32/128).
    /// 2. `expander_matches_reference_grid` checks the production
    ///    expander against this reference at L = 48 across a grid of
    ///    msg/dst lengths.
    fn expand_message_xmd_reference(msg: &[u8], dst: &[u8], len_in_bytes: usize) -> Vec<u8> {
        use elliptic_curve::hash2curve::{ExpandMsg, ExpandMsgXmd, Expander};
        use sha2::Sha256;

        let dsts = [dst];
        let mut expander = ExpandMsgXmd::<Sha256>::expand_message(&[msg], &dsts, len_in_bytes)
            .expect("valid expand_message_xmd parameters");
        let mut out = Vec::new();
        out.resize(len_in_bytes, 0u8);
        expander.fill_bytes(&mut out);
        out
    }

    /// All 10 official CFRG test vectors for expand_message_xmd with
    /// SHA-256 (RFC 9380 appendix K.1,
    /// DST = "QUUX-V01-CS02-with-expander-SHA256-128").
    #[test]
    fn reference_matches_rfc9380_vectors() {
        const RFC_DST: &[u8] = b"QUUX-V01-CS02-with-expander-SHA256-128";
        let mut q128 = b"q128_".to_vec();
        q128.extend([b'q'; 128]);
        let mut a512 = b"a512_".to_vec();
        a512.extend([b'a'; 512]);

        let cases: [(&[u8], usize, &str); 10] = [
            (b"", 32, "68a985b87eb6b46952128911f2a4412bbc302a9d759667f87f7a21d803f07235"),
            (b"abc", 32, "d8ccab23b5985ccea865c6c97b6e5b8350e794e603b4b97902f53a8a0d605615"),
            (b"abcdef0123456789", 32, "eff31487c770a893cfb36f912fbfcbff40d5661771ca4b2cb4eafe524333f5c1"),
            (&q128, 32, "b23a1d2b4d97b2ef7785562a7e8bac7eed54ed6e97e29aa51bfe3f12ddad1ff9"),
            (&a512, 32, "4623227bcc01293b8c130bf771da8c298dede7383243dc0993d2d94823958c4c"),
            (b"", 128, "af84c27ccfd45d41914fdff5df25293e221afc53d8ad2ac06d5e3e29485dadbee0d121587713a3e0dd4d5e69e93eb7cd4f5df4cd103e188cf60cb02edc3edf18eda8576c412b18ffb658e3dd6ec849469b979d444cf7b26911a08e63cf31f9dcc541708d3491184472c2c29bb749d4286b004ceb5ee6b9a7fa5b646c993f0ced"),
            (b"abc", 128, "abba86a6129e366fc877aab32fc4ffc70120d8996c88aee2fe4b32d6c7b6437a647e6c3163d40b76a73cf6a5674ef1d890f95b664ee0afa5359a5c4e07985635bbecbac65d747d3d2da7ec2b8221b17b0ca9dc8a1ac1c07ea6a1e60583e2cb00058e77b7b72a298425cd1b941ad4ec65e8afc50303a22c0f99b0509b4c895f40"),
            (b"abcdef0123456789", 128, "ef904a29bffc4cf9ee82832451c946ac3c8f8058ae97d8d629831a74c6572bd9ebd0df635cd1f208e2038e760c4994984ce73f0d55ea9f22af83ba4734569d4bc95e18350f740c07eef653cbb9f87910d833751825f0ebefa1abe5420bb52be14cf489b37fe1a72f7de2d10be453b2c9d9eb20c7e3f6edc5a60629178d9478df"),
            (&q128, 128, "80be107d0884f0d881bb460322f0443d38bd222db8bd0b0a5312a6fedb49c1bbd88fd75d8b9a09486c60123dfa1d73c1cc3169761b17476d3c6b7cbbd727acd0e2c942f4dd96ae3da5de368d26b32286e32de7e5a8cb2949f866a0b80c58116b29fa7fabb3ea7d520ee603e0c25bcaf0b9a5e92ec6a1fe4e0391d1cdbce8c68a"),
            (&a512, 128, "546aff5444b5b79aa6148bd81728704c32decb73a3ba76e9e75885cad9def1d06d6792f8a7d12794e90efed817d96920d728896a4510864370c207f99bd4a608ea121700ef01ed879745ee3e4ceef777eda6d9e5e38b90c86ea6fb0b36504ba4a45d22e86f6db5dd43d98a294bebb9125d5b794e9d2a81181066eb954966a487"),
        ];
        for (msg, len, want_hex) in cases {
            assert_eq!(
                expand_message_xmd_reference(msg, RFC_DST, len),
                hex_to_vec(want_hex),
                "msg_len={} len_in_bytes={}",
                msg.len(),
                len
            );
        }
    }

    /// Differential check of the production expander against the
    /// RFC-vector-validated reference at L = 48, across SHA-256 block
    /// boundaries (31/32/33, 63/64/65), L itself (47/48), and the
    /// extremes admitted by the compile-time scratch assert
    /// (64 + MSG + 3 + DST + 1 <= 256, i.e. MSG + DST <= 188).
    #[test]
    fn expander_matches_reference_grid() {
        macro_rules! diff_case {
            ($m:literal, $d:literal) => {{
                // Deterministic per-case byte patterns so no two cases
                // share a msg/dst prefix.
                let msg: [u8; $m] =
                    core::array::from_fn(|i| (i as u8).wrapping_mul(31).wrapping_add($m ^ $d));
                let dst: [u8; $d] =
                    core::array::from_fn(|i| (i as u8).wrapping_mul(17).wrapping_add($d));
                let got = expand_message_xmd_sha256_l48(&msg, &dst);
                let want = expand_message_xmd_reference(&msg, &dst, L);
                assert_eq!(
                    got.as_slice(),
                    want.as_slice(),
                    "MSG_LEN={} DST_LEN={}",
                    $m,
                    $d
                );
            }};
        }
        macro_rules! diff_msg_row {
            ($d:literal) => {{
                diff_case!(0, $d);
                diff_case!(1, $d);
                diff_case!(31, $d);
                diff_case!(32, $d);
                diff_case!(33, $d);
                diff_case!(47, $d);
                diff_case!(48, $d);
                diff_case!(63, $d);
                diff_case!(64, $d);
                diff_case!(65, $d);
                diff_case!(100, $d);
                diff_case!(120, $d);
            }};
        }
        diff_msg_row!(1);
        diff_msg_row!(15);
        diff_msg_row!(16);
        diff_msg_row!(17);
        diff_msg_row!(32);
        diff_msg_row!(64);
        diff_case!(187, 1);
        diff_case!(1, 187);
        diff_case!(120, 68);
    }

    /// Random-content property tests: the production expander must
    /// agree with the library reference for arbitrary msg/dst bytes.
    ///
    /// `expand_message_xmd_sha256_l48` is const-generic over lengths,
    /// so each shape is a separate monomorphization. Two shapes
    /// suffice: the real BSB22 call (msg = one uncompressed G1 point,
    /// dst_len = len("bsb22-commitment")) and the largest msg the
    /// compile-time scratch assert admits (b_0 preimage exactly fills
    /// MAX_SCRATCH). Content only flows through `copy_from_slice` and
    /// one XOR, so random bytes guard those; the length dimension is
    /// covered deterministically by `expander_matches_reference_grid`.
    /// Proptest case count: 1000 by default, overridable for deeper
    /// one-off soak runs, e.g. `PROPTEST_CASES=1000000 cargo test
    /// --release`. (The env var must be read manually here: proptest
    /// only honors it in `ProptestConfig::default()`, and an explicit
    /// `with_cases` would silently ignore it.)
    fn proptest_cases() -> u32 {
        std::env::var("PROPTEST_CASES")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(1000)
    }

    macro_rules! expander_shape_proptest {
        ($name:ident, $msg_len:literal, $dst_len:literal) => {
            proptest! {
                #![proptest_config(ProptestConfig::with_cases(proptest_cases()))]
                #[test]
                fn $name(
                    msg in any::<[u8; $msg_len]>(),
                    dst in any::<[u8; $dst_len]>(),
                ) {
                    let got = expand_message_xmd_sha256_l48(&msg, &dst);
                    let want = expand_message_xmd_reference(&msg, &dst, L);
                    prop_assert_eq!(
                        got.as_slice(),
                        want.as_slice(),
                        "expander mismatch for MSG_LEN={} DST_LEN={}",
                        $msg_len,
                        $dst_len
                    );
                }
            }
        };
    }

    expander_shape_proptest!(prop_expander_bsb22_shape, 64, 16);
    expander_shape_proptest!(prop_expander_max_msg, 187, 1);

    fn hex_to_vec(s: &str) -> Vec<u8> {
        assert!(s.len() % 2 == 0);
        s.as_bytes()
            .chunks(2)
            .map(|pair| u8::from_str_radix(core::str::from_utf8(pair).unwrap(), 16).unwrap())
            .collect()
    }

    fn hex_to_array(s: &str) -> [u8; 32] {
        assert_eq!(s.len(), 64);
        let mut out = [0u8; 32];
        for i in 0..32 {
            out[i] = u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap();
        }
        out
    }
}
