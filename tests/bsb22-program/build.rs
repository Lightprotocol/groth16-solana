// Read the committed BSB22 variant-1 fixture from
// `tests/fixtures/bsb22/` and copy every file into `OUT_DIR` so the
// litesvm test can pick them up with `include_bytes!`. Then drive
// `groth16_solana::gnark_vk_parser::generate_bsb22_vk_file` against
// the same vk.bin to emit a `pub const VERIFYINGKEY` source file
// that `src/lib.rs` includes at compile time.
//
// The fixture files are a single consistent snapshot from one gnark
// `Setup` + `Prove` call for `Lookups1Circuit` with X=7. gnark's
// setup is non-deterministic so all files must be regenerated
// together — see `TestDumpFullFixture` in
// `tests/bsb22/gnark-fixture/main_test.go`.

use groth16_solana::gnark_vk_parser::generate_bsb22_vk_file;
use std::path::PathBuf;

const FIXTURE_FILES: &[&str] = &[
    "vk_variant_1.bin",
    "proof_a_variant_1.bin",
    "proof_b_variant_1.bin",
    "proof_c_variant_1.bin",
    "commitment_variant_1.bin",
    "pok_variant_1.bin",
    "public_input_variant_1.bin",
];

fn main() {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let fixture_dir = manifest_dir
        .parent()
        .unwrap()
        .join("fixtures")
        .join("bsb22");
    let out_dir = PathBuf::from(std::env::var("OUT_DIR").unwrap());

    // Mirror committed fixtures into OUT_DIR with short names the
    // litesvm test `include_bytes!`es.
    let map = [
        ("vk_variant_1.bin", "vk.bin"),
        ("proof_a_variant_1.bin", "proof_a.bin"),
        ("proof_b_variant_1.bin", "proof_b.bin"),
        ("proof_c_variant_1.bin", "proof_c.bin"),
        ("commitment_variant_1.bin", "commitment.bin"),
        ("pok_variant_1.bin", "pok.bin"),
        ("public_input_variant_1.bin", "public_input.bin"),
    ];
    for (src, dst) in map.iter() {
        let bytes = std::fs::read(fixture_dir.join(src))
            .unwrap_or_else(|e| panic!("read fixture {}: {}", src, e));
        std::fs::write(out_dir.join(dst), &bytes).unwrap();
    }

    // Bake the vk as a `pub const VERIFYINGKEY` that src/lib.rs
    // `include!`s. The helper reads the vk.bin we just wrote.
    let vk_path = out_dir.join("vk.bin");
    generate_bsb22_vk_file(&vk_path, &out_dir, "verifying_key.rs", "VERIFYINGKEY")
        .expect("generate_bsb22_vk_file");

    println!("cargo:rerun-if-changed=build.rs");
    for name in FIXTURE_FILES {
        println!(
            "cargo:rerun-if-changed=../fixtures/bsb22/{}",
            name
        );
    }
}
