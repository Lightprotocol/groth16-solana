# groth16-solana workspace

export RUST_BACKTRACE := env_var_or_default("RUST_BACKTRACE", "0")

default:
    @just --list

# === Rust workspace ===

build:
    cargo build --workspace

build-release:
    cargo build --release --workspace

check:
    cargo check --workspace

check-all:
    cargo check --workspace --all-targets

# === CI ===

# The full CI sequence; CI sets PROPTEST_CASES=1000000 to soak the
# hash_to_field proptests (local default: 1000). The profiled .so must
# exist before test-workspace because the mollusk failing.rs tests
# load it.

# Everything CI runs after toolchain setup
ci: lint build-circuit build build-program-profiled test-workspace test-unit bench check-benchmarks

# Compile the rust-vk test circuit and generate its keys (requires npm + circom)
build-circuit:
    cd tests/rust-vk && npm install && npm run build-all

# Fail on uncommitted BENCHMARKS.md changes (bench regenerates it)
check-benchmarks:
    git diff --exit-code BENCHMARKS.md

# === Tests (per-suite test list in CLAUDE.md) ===

# The workspace run misses the `circom-vk`-gated codegen tests (no
# member enables that feature as a normal dependency), so `test` chains
# the all-features unit run, mirroring CI.

# Workspace tests plus the all-features unit run
test: test-workspace test-unit

test-workspace:
    cargo test --workspace

# Unit + codegen tests with every feature enabled
test-unit:
    cargo test -p groth16-solana --features "bsb22 gnark-vk circom-vk"

# FFI differential tests against gnark (requires Go)
test-ffi:
    cargo test -p groth16-solana-gnark-ffi

# Go-side fixture tests: gnark smoke test + generator determinism
test-go:
    cd tests/gnark-ffi/gnark-fixture && go test ./...

# Mollusk negative tests for every verifier variant
test-program: build-program
    cargo test -p bsb22-integration-program --test failing

# === SBF program (tests/program) ===

# build.rs regenerates the gnark fixtures, so both builds need the Go
# toolchain. The profiled .so runs only under mollusk with the
# profiling syscalls registered; do not deploy it.

# Plain SBF build of the verifier program into target/deploy
build-program:
    cargo build-sbf --manifest-path tests/program/Cargo.toml

# Profiled SBF build for the CU bench
build-program-profiled:
    cargo build-sbf --manifest-path tests/program/Cargo.toml -- --features profile-program

# === Bench ===

# Regenerate BENCHMARKS.md with the mollusk CU profiler
bench: build-program-profiled
    cargo test -p bsb22-integration-program --test bench_cu -- --ignored --nocapture

# === Formatting and linting ===

# Format check, clippy, feature-matrix compile, README sync
lint: fmt-check clippy check-features check-readme

format: fmt

fmt:
    cargo fmt --all

fmt-check:
    cargo fmt --all -- --check

clippy:
    cargo clippy --workspace --all-targets -- -D warnings

# Compile groth16-solana with no features, each feature alone, and all features
check-features:
    cargo check -p groth16-solana
    cargo check -p groth16-solana --features circom-vk
    cargo check -p groth16-solana --features gnark-vk
    cargo check -p groth16-solana --features circom
    cargo check -p groth16-solana --features bsb22
    cargo check -p groth16-solana --features bsb22-test
    cargo check -p groth16-solana --all-features

# === README generation (cargo-rdme) ===

# Regenerate README.md from the src/lib.rs crate docs
readme:
    cargo rdme --force

# Fail when README.md is out of sync with the src/lib.rs crate docs
check-readme:
    #!/usr/bin/env bash
    set -euo pipefail
    command -v cargo-rdme >/dev/null || cargo install cargo-rdme
    cargo rdme --check

# === Maintenance ===

clean:
    cargo clean
