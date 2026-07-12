// Regenerate the benchmark fixture sets ({plain,bsb22} x {1,2,4,8}
// public inputs) into OUT_DIR by running the deterministic gnark
// generator, then bake each verifying key as a `pub const` source
// file that `src/lib.rs` includes at compile time.
//
// The generator seeds gnark's randomness (crypto/rand.Reader swap in
// tests/gnark-ffi/gnark-fixture/bench), so every build — the SBF build
// that bakes the vks and the host test build that embeds the matching
// proofs — reproduces byte-identical fixtures. No fixture files are
// committed; the only requirement is a Go toolchain, which
// tests/gnark-ffi already needs.

use groth16_solana::vk::gnark::generate_bsb22_vk_file;
use std::path::PathBuf;
use std::process::Command;

const MODES: [&str; 2] = ["plain", "bsb22"];
const PUBLIC_INPUT_COUNTS: [usize; 4] = [1, 2, 4, 8];

fn main() {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let gnark_dir = manifest_dir
        .parent()
        .unwrap()
        .join("gnark-ffi")
        .join("gnark-fixture");
    let out_dir = PathBuf::from(std::env::var("OUT_DIR").unwrap());
    let fixture_dir = out_dir.join("bench-fixtures");

    // Confirm the Go toolchain exists. Without it the build fails
    // loudly with a clear message instead of a confusing exec error.
    if Command::new("go").arg("version").status().is_err() {
        println!("cargo:warning=`go` not found in PATH; tests/program requires the Go toolchain");
        panic!("missing Go toolchain");
    }

    let status = Command::new("go")
        .current_dir(&gnark_dir)
        .args(["run", "./cmd/benchgen"])
        .arg(&fixture_dir)
        .status()
        .expect("run `go run ./cmd/benchgen`");
    assert!(status.success(), "benchgen failed with {status}");

    // Bake each vk as `pub const VK_<MODE>_<N>` that src/lib.rs
    // `include!`s. generate_bsb22_vk_file handles both vk shapes and
    // emits `vk_commitment: None` for the plain ones.
    for mode in MODES {
        for n in PUBLIC_INPUT_COUNTS {
            let label = format!("{mode}_{n}");
            let vk_path = fixture_dir.join(format!("{label}_vk.bin"));
            generate_bsb22_vk_file(
                &vk_path,
                &out_dir,
                &format!("vk_{label}.rs"),
                &format!("VK_{}", label.to_uppercase()),
            )
            .unwrap_or_else(|e| panic!("generate vk const for {label}: {e:?}"));
        }
    }

    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=../gnark-ffi/gnark-fixture/bench");
    println!("cargo:rerun-if-changed=../gnark-ffi/gnark-fixture/cmd/benchgen");
    println!("cargo:rerun-if-changed=../gnark-ffi/gnark-fixture/go.mod");
    println!("cargo:rerun-if-changed=../gnark-ffi/gnark-fixture/go.sum");
}
