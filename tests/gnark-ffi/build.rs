// Build the in-repo gnark fixture (`gnark-fixture/`) as a C static
// archive via cgo, then run bindgen over the generated header so the
// integration tests can call Setup / Prove / NativeVerify directly.

use std::{env, path::PathBuf, process::Command};

fn main() {
    println!("cargo:rerun-if-changed=gnark-fixture/main.go");
    println!("cargo:rerun-if-changed=gnark-fixture/main_test.go");
    println!("cargo:rerun-if-changed=gnark-fixture/go.mod");
    println!("cargo:rerun-if-changed=gnark-fixture/go.sum");

    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());
    let go_dir = manifest_dir.join("gnark-fixture");
    let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());
    let lib_out = out_dir.join("libgnark_fixture.a");

    // Confirm the Go toolchain exists. Without it the build fails
    // loudly with a clear message instead of a confusing linker error.
    if Command::new("go").arg("version").status().is_err() {
        println!("cargo:warning=`go` not found in PATH; tests/gnark-ffi requires the Go toolchain");
        panic!("missing Go toolchain");
    }

    // Build as C static archive. Go generates libgnark_fixture.h
    // alongside libgnark_fixture.a in OUT_DIR.
    let status = Command::new("go")
        .current_dir(&go_dir)
        .env("CGO_ENABLED", "1")
        .env("CC", "clang")
        .args([
            "build",
            "-buildmode=c-archive",
            "-o",
            lib_out.to_str().unwrap(),
            ".",
        ])
        .status()
        .expect("go build");
    assert!(status.success(), "go build -buildmode=c-archive failed");

    let header = out_dir.join("libgnark_fixture.h");
    let bindings = bindgen::Builder::default()
        .header(header.to_str().unwrap())
        .allowlist_function("Setup")
        .allowlist_function("Prove")
        .allowlist_function("NativeVerify")
        .allowlist_function("HashToField")
        .allowlist_function("FreeProveResult")
        .allowlist_function("FreeString")
        .allowlist_type("C_ProveResult")
        .generate()
        .expect("bindgen generate");
    bindings
        .write_to_file(out_dir.join("bindings.rs"))
        .expect("write bindings");

    println!("cargo:rustc-link-search=native={}", out_dir.display());
    println!("cargo:rustc-link-lib=static=gnark_fixture");

    if cfg!(target_os = "macos") {
        println!("cargo:rustc-link-lib=framework=CoreFoundation");
        println!("cargo:rustc-link-lib=framework=Security");
        println!("cargo:rustc-link-lib=resolv");
    }
}
