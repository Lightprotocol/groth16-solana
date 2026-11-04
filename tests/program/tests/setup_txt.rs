//! The `*_SETUP_TXT` markers are present in the SBF binary: reading the
//! built .so (as a post-deployment check would read a
//! `solana program dump`) finds one marker per baked vk, each flagged
//! as an insecure test setup and containing the vk SHA-256 recomputed
//! from its fixture vk.bin. Requires the .so from `cargo build-sbf`
//! (plain or `--features profile-program`).

use groth16_solana::vk::gnark::parse_gnark_vk_bytes;
use groth16_solana::vk::setup::{find_setup_txts, vk_sha256};

const PROGRAM_SO: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../target/deploy/bsb22_integration_program.so"
);
const FIXTURE_DIR: &str = concat!(env!("OUT_DIR"), "/bench-fixtures");
const LABELS: [&str; 8] = [
    "plain_1", "plain_2", "plain_4", "plain_8", "bsb22_1", "bsb22_2", "bsb22_4", "bsb22_8",
];

#[test]
fn setup_txt_readable_from_program_binary() {
    let binary = std::fs::read(PROGRAM_SO)
        .unwrap_or_else(|e| panic!("read {PROGRAM_SO} (run cargo build-sbf first): {e}"));
    let mut found = find_setup_txts(&binary).unwrap();
    found.sort_by(|a, b| a.name.cmp(&b.name));

    let mut expected: Vec<(String, bool, [u8; 32])> = LABELS
        .iter()
        .map(|label| {
            let bytes = std::fs::read(format!("{FIXTURE_DIR}/{label}_vk.bin")).unwrap();
            let vk = parse_gnark_vk_bytes(&bytes).unwrap();
            (
                format!("VK_{}", label.to_uppercase()),
                true,
                vk_sha256(&vk.as_borrowed()),
            )
        })
        .collect();
    expected.sort();

    let found: Vec<(String, bool, [u8; 32])> = found
        .into_iter()
        .map(|s| (s.name, s.insecure_test_setup, s.vk_sha256))
        .collect();
    assert_eq!(found, expected);
}
