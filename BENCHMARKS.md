# groth16-solana CU Benchmarks

Compute unit costs of on-chain Groth16 verification, measured with [light-program-profiler](https://github.com/Lightprotocol/light-program-profiler) under mollusk against the profiled build of `tests/program`. The matrix covers plain Groth16 (`Groth16Verifier::new`) and BSB22 single-commitment proofs (`Groth16Verifier::new_with_commitment`, gnark lookup circuits), each verified with 1, 2, 4, and 8 public inputs. Proofs and verifying keys are regenerated deterministically by build.rs (seeded gnark setup, see tests/gnark-ffi/gnark-fixture/bench). `verify`/`verify_with_bsb22_commitment` is proof parsing plus Groth16Verifier construction plus `verify()`.

Regenerate with `cargo build-sbf --manifest-path tests/program/Cargo.toml -- --features profile-program && cargo test -p bsb22-integration-program --test bench_cu -- --ignored --nocapture`.

## Definitions

- **Total CU**: Compute units consumed by the function including all children
- **Net CU**: Compute units consumed by the function itself (excluding children)

## Table of Contents

1. [Groth16 - 1 public input](#groth16---1-public-input)
2. [Groth16 - 2 public inputs](#groth16---2-public-inputs)
3. [Groth16 - 4 public inputs](#groth16---4-public-inputs)
4. [Groth16 - 8 public inputs](#groth16---8-public-inputs)
5. [Groth16-bsb22 - 1 public input](#groth16-bsb22---1-public-input)
6. [Groth16-bsb22 - 2 public inputs](#groth16-bsb22---2-public-inputs)
7. [Groth16-bsb22 - 4 public inputs](#groth16-bsb22---4-public-inputs)
8. [Groth16-bsb22 - 8 public inputs](#groth16-bsb22---8-public-inputs)

## 1. Groth16 - 1 public input

| Function                       |   Total CU |     Net CU |
| ------------------------------ | ---------- | ---------- |
| `verify`                       |     78,293 |     78,293 |

## 2. Groth16 - 2 public inputs

| Function                       |   Total CU |     Net CU |
| ------------------------------ | ---------- | ---------- |
| `verify`                       |     82,704 |     82,704 |

## 3. Groth16 - 4 public inputs

| Function                       |   Total CU |     Net CU |
| ------------------------------ | ---------- | ---------- |
| `verify`                       |     91,448 |     91,448 |

## 4. Groth16 - 8 public inputs

| Function                       |   Total CU |     Net CU |
| ------------------------------ | ---------- | ---------- |
| `verify`                       |    108,762 |    108,762 |

## 5. Groth16-bsb22 - 1 public input

| Function                       |   Total CU |     Net CU |
| ------------------------------ | ---------- | ---------- |
| `verify_with_bsb22_commitment` |    211,461 |    211,461 |

## 6. Groth16-bsb22 - 2 public inputs

| Function                       |   Total CU |     Net CU |
| ------------------------------ | ---------- | ---------- |
| `verify_with_bsb22_commitment` |    215,912 |    215,912 |

## 7. Groth16-bsb22 - 4 public inputs

| Function                       |   Total CU |     Net CU |
| ------------------------------ | ---------- | ---------- |
| `verify_with_bsb22_commitment` |    224,681 |    224,681 |

## 8. Groth16-bsb22 - 8 public inputs

| Function                       |   Total CU |     Net CU |
| ------------------------------ | ---------- | ---------- |
| `verify_with_bsb22_commitment` |    241,985 |    241,985 |

