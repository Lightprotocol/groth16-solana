//! Integration tests for the circom/snarkjs vk codegen
//! (`groth16_solana::vk::circom`): the generated const must include the
//! un-gated `vk_commitment` field and the setup metadata consts,
//! malformed JSON must produce meaningful `VkParseError`s instead of
//! integer-underflow panics, and a forgeable vk must not be labelled
//! production.
#![cfg(feature = "circom-vk")]

use groth16_solana::groth16::Groth16Verifyingkey;
use groth16_solana::vk::circom::{parse_vk_json_to_rust_string, VkParseError};
use groth16_solana::vk::setup::{vk_sha256, SetupKind};

/// Minimal well-formed snarkjs-shaped JSON: projective points with a
/// trailing z component, one IC entry (constant K[0] only, so zero
/// public inputs). The coordinate values are dummies — the generator
/// does no curve validation, only byte formatting. Delta equals gamma,
/// like a zkey exported before any phase-2 contribution.
const MINIMAL_VK_JSON: &str = r#"{
    "vk_alpha_1": ["1", "2", "1"],
    "vk_beta_2": [["1", "2"], ["3", "4"], ["1", "0"]],
    "vk_gamma_2": [["1", "2"], ["3", "4"], ["1", "0"]],
    "vk_delta_2": [["1", "2"], ["3", "4"], ["1", "0"]],
    "IC": [["1", "2", "1"]]
}"#;

/// [`MINIMAL_VK_JSON`] with delta moved off gamma, as after a
/// phase-2 contribution.
fn contributed_vk_json() -> String {
    MINIMAL_VK_JSON.replace(
        r#""vk_delta_2": [["1", "2"], ["3", "4"], ["1", "0"]]"#,
        r#""vk_delta_2": [["5", "6"], ["7", "8"], ["1", "0"]]"#,
    )
}

#[test]
fn generates_const_with_vk_commitment_none() {
    let src = parse_vk_json_to_rust_string(MINIMAL_VK_JSON, SetupKind::InsecureTest).unwrap();
    assert!(src.contains("pub const VERIFYINGKEY: Groth16Verifyingkey"));
    assert!(src.contains("nr_pubinputs: 0,"));
    assert!(src.contains("vk_commitment: None,"));
}

#[test]
fn insecure_test_setup_emits_flag_header_and_compile_guard() {
    let src = parse_vk_json_to_rust_string(MINIMAL_VK_JSON, SetupKind::InsecureTest).unwrap();
    assert!(src.contains("// INSECURE TEST SETUP:"));
    assert!(src.contains("pub const VERIFYINGKEY_VK_SHA256: [u8; 32] = ["));
    assert!(src.contains("pub const VERIFYINGKEY_INSECURE_TEST_SETUP: bool = true;"));
    assert!(src.contains("#[cfg(not(feature = \"insecure-test-setup\"))]\ncompile_error!("));
}

#[test]
fn production_setup_emits_flag_without_compile_guard() {
    let src = parse_vk_json_to_rust_string(&contributed_vk_json(), SetupKind::Production).unwrap();
    assert!(src.contains("pub const VERIFYINGKEY_VK_SHA256: [u8; 32] = ["));
    assert!(src.contains("pub const VERIFYINGKEY_INSECURE_TEST_SETUP: bool = false;"));
    assert!(!src.contains("INSECURE TEST SETUP:"));
    assert!(!src.contains("compile_error!"));
}

/// 32-byte big-endian encoding of a small integer.
fn be32(v: u8) -> [u8; 32] {
    let mut out = [0u8; 32];
    out[31] = v;
    out
}

fn concat<const N: usize>(parts: &[[u8; 32]]) -> [u8; N] {
    parts.concat().try_into().unwrap()
}

#[test]
fn vk_sha256_const_matches_parsed_points() {
    // G1 (x, y) -> x || y; G2 ((x.c0, x.c1), (y.c0, y.c1)) ->
    // x.c1 || x.c0 || y.c1 || y.c0, the alt_bn128 syscall layout.
    let g2 = concat::<128>(&[be32(2), be32(1), be32(4), be32(3)]);
    let ic = [concat::<64>(&[be32(1), be32(2)])];
    let vk = Groth16Verifyingkey {
        nr_pubinputs: 0,
        vk_alpha_g1: concat(&[be32(1), be32(2)]),
        vk_beta_g2: g2,
        vk_gamma_g2: g2,
        vk_delta_g2: g2,
        vk_ic: &ic,
        vk_commitment: None,
    };
    let digest = vk_sha256(&vk)
        .iter()
        .map(|b| format!("{b}u8"))
        .collect::<Vec<_>>()
        .join(", ");
    let src = parse_vk_json_to_rust_string(MINIMAL_VK_JSON, SetupKind::InsecureTest).unwrap();
    assert!(src.contains(&format!(
        "pub const VERIFYINGKEY_VK_SHA256: [u8; 32] = [{digest}];"
    )));
}

#[test]
fn rejects_g1_point_with_extra_coordinate() {
    let json = MINIMAL_VK_JSON.replace(
        r#""vk_alpha_1": ["1", "2", "1"]"#,
        r#""vk_alpha_1": ["1", "2", "3", "1"]"#,
    );
    let err = parse_vk_json_to_rust_string(&json, SetupKind::InsecureTest).unwrap_err();
    let msg = format!("{}", err);
    assert!(
        msg.contains("vk_alpha_1 encodes to 96 bytes, expected 64"),
        "unexpected error: {}",
        msg
    );
}

#[test]
fn rejects_production_vk_with_delta_equal_gamma() {
    let err = parse_vk_json_to_rust_string(MINIMAL_VK_JSON, SetupKind::Production).unwrap_err();
    assert!(
        matches!(err, VkParseError::ForgeableProductionVk),
        "unexpected error: {}",
        err
    );
}

#[test]
fn rejects_empty_ic() {
    let json = MINIMAL_VK_JSON.replace(r#"[["1", "2", "1"]]"#, "[]");
    let err = parse_vk_json_to_rust_string(&json, SetupKind::InsecureTest).unwrap_err();
    let msg = format!("{}", err);
    assert!(msg.contains("IC is empty"), "unexpected error: {}", msg);
}

#[test]
fn rejects_empty_point_coordinates() {
    let json = MINIMAL_VK_JSON.replace(r#""vk_alpha_1": ["1", "2", "1"]"#, r#""vk_alpha_1": []"#);
    let err = parse_vk_json_to_rust_string(&json, SetupKind::InsecureTest).unwrap_err();
    let msg = format!("{}", err);
    assert!(
        msg.contains("vk_alpha_1 is empty"),
        "unexpected error: {}",
        msg
    );
}
