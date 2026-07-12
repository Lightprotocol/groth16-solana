//! Integration tests for the circom/snarkjs vk codegen
//! (`groth16_solana::vk::circom`): the generated const must include the
//! un-gated `vk_commitment` field, and malformed JSON must produce
//! meaningful `VkParseError`s instead of integer-underflow panics.
#![cfg(feature = "circom-vk")]

use groth16_solana::vk::circom::parse_vk_json_to_rust_string;

/// Minimal well-formed snarkjs-shaped JSON: projective points with a
/// trailing z component, one IC entry (constant K[0] only, so zero
/// public inputs). The coordinate values are dummies — the generator
/// does no curve validation, only byte formatting.
const MINIMAL_VK_JSON: &str = r#"{
    "vk_alpha_1": ["1", "2", "1"],
    "vk_beta_2": [["1", "2"], ["3", "4"], ["1", "0"]],
    "vk_gamma_2": [["1", "2"], ["3", "4"], ["1", "0"]],
    "vk_delta_2": [["1", "2"], ["3", "4"], ["1", "0"]],
    "IC": [["1", "2", "1"]]
}"#;

#[test]
fn generates_const_with_vk_commitment_none() {
    let src = parse_vk_json_to_rust_string(MINIMAL_VK_JSON).unwrap();
    assert!(src.contains("pub const VERIFYINGKEY: Groth16Verifyingkey"));
    assert!(src.contains("nr_pubinputs: 0,"));
    assert!(src.contains("vk_commitment: None,"));
}

#[test]
fn rejects_empty_ic() {
    let json = MINIMAL_VK_JSON.replace(r#"[["1", "2", "1"]]"#, "[]");
    let err = parse_vk_json_to_rust_string(&json).unwrap_err();
    let msg = format!("{}", err);
    assert!(msg.contains("IC is empty"), "unexpected error: {}", msg);
}

#[test]
fn rejects_empty_point_coordinates() {
    let json = MINIMAL_VK_JSON.replace(r#""vk_alpha_1": ["1", "2", "1"]"#, r#""vk_alpha_1": []"#);
    let err = parse_vk_json_to_rust_string(&json).unwrap_err();
    let msg = format!("{}", err);
    assert!(
        msg.contains("vk_alpha_1 is empty"),
        "unexpected error: {}",
        msg
    );
}
