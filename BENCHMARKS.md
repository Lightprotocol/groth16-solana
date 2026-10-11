# groth16-solana CU Benchmarks

Compute unit costs of Groth16 verification on Solana, measured with [light-program-profiler](https://github.com/Lightprotocol/light-program-profiler) under mollusk against the profiled build of `tests/program`. The matrix covers plain Groth16 (`Groth16Verifier::new`) and BSB22 single-commitment proofs (`Groth16Verifier::new_with_commitment`, gnark lookup circuits), each verified with 1, 2, 4, and 8 public inputs. BSB22 fixtures are checked using both `verify()` and the single-proof `verify_opt()` method, with all combinations of a checked 49-byte hash-reduction hint and a pinned key digest. Proofs and verifying keys are regenerated deterministically by build.rs (seeded gnark setup, see tests/gnark-ffi/gnark-fixture/bench). `verify`/`verify_with_bsb22_commitment` is proof parsing plus Groth16Verifier construction plus the selected verification method.

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
9. [Groth16-bsb22-opt - 1 public input](#groth16-bsb22-opt---1-public-input)
10. [Groth16-bsb22-opt - 2 public inputs](#groth16-bsb22-opt---2-public-inputs)
11. [Groth16-bsb22-opt - 4 public inputs](#groth16-bsb22-opt---4-public-inputs)
12. [Groth16-bsb22-opt - 8 public inputs](#groth16-bsb22-opt---8-public-inputs)
13. [Groth16-bsb22-opt-cached - 1 public input](#groth16-bsb22-opt-cached---1-public-input)
14. [Groth16-bsb22-opt-cached - 2 public inputs](#groth16-bsb22-opt-cached---2-public-inputs)
15. [Groth16-bsb22-opt-cached - 4 public inputs](#groth16-bsb22-opt-cached---4-public-inputs)
16. [Groth16-bsb22-opt-cached - 8 public inputs](#groth16-bsb22-opt-cached---8-public-inputs)
17. [Groth16-bsb22-opt-hint - 1 public input](#groth16-bsb22-opt-hint---1-public-input)
18. [Groth16-bsb22-opt-hint - 2 public inputs](#groth16-bsb22-opt-hint---2-public-inputs)
19. [Groth16-bsb22-opt-hint - 4 public inputs](#groth16-bsb22-opt-hint---4-public-inputs)
20. [Groth16-bsb22-opt-hint - 8 public inputs](#groth16-bsb22-opt-hint---8-public-inputs)
21. [Groth16-bsb22-opt-hint-cached - 1 public input](#groth16-bsb22-opt-hint-cached---1-public-input)
22. [Groth16-bsb22-opt-hint-cached - 2 public inputs](#groth16-bsb22-opt-hint-cached---2-public-inputs)
23. [Groth16-bsb22-opt-hint-cached - 4 public inputs](#groth16-bsb22-opt-hint-cached---4-public-inputs)
24. [Groth16-bsb22-opt-hint-cached - 8 public inputs](#groth16-bsb22-opt-hint-cached---8-public-inputs)

## 1. Groth16 - 1 public input

| Function                       |   Total CU |     Net CU |
| ------------------------------ | ---------- | ---------- |
| `verify`                       |     78,324 |     78,324 |

## 2. Groth16 - 2 public inputs

| Function                       |   Total CU |     Net CU |
| ------------------------------ | ---------- | ---------- |
| `verify`                       |     82,732 |     82,732 |

## 3. Groth16 - 4 public inputs

| Function                       |   Total CU |     Net CU |
| ------------------------------ | ---------- | ---------- |
| `verify`                       |     91,472 |     91,472 |

## 4. Groth16 - 8 public inputs

| Function                       |   Total CU |     Net CU |
| ------------------------------ | ---------- | ---------- |
| `verify`                       |    108,789 |    108,789 |

## 5. Groth16-bsb22 - 1 public input

| Function                       |   Total CU |     Net CU |
| ------------------------------ | ---------- | ---------- |
| `verify_with_bsb22_commitment` |    134,795 |    134,795 |

## 6. Groth16-bsb22 - 2 public inputs

| Function                       |   Total CU |     Net CU |
| ------------------------------ | ---------- | ---------- |
| `verify_with_bsb22_commitment` |    139,201 |    139,201 |

## 7. Groth16-bsb22 - 4 public inputs

| Function                       |   Total CU |     Net CU |
| ------------------------------ | ---------- | ---------- |
| `verify_with_bsb22_commitment` |    147,939 |    147,939 |

## 8. Groth16-bsb22 - 8 public inputs

| Function                       |   Total CU |     Net CU |
| ------------------------------ | ---------- | ---------- |
| `verify_with_bsb22_commitment` |    165,258 |    165,258 |

## 9. Groth16-bsb22-opt - 1 public input

| Function                       |   Total CU |     Net CU |
| ------------------------------ | ---------- | ---------- |
| `verify_with_bsb22_commitment` |    119,286 |    119,286 |

## 10. Groth16-bsb22-opt - 2 public inputs

| Function                       |   Total CU |     Net CU |
| ------------------------------ | ---------- | ---------- |
| `verify_with_bsb22_commitment` |    123,739 |    123,739 |

## 11. Groth16-bsb22-opt - 4 public inputs

| Function                       |   Total CU |     Net CU |
| ------------------------------ | ---------- | ---------- |
| `verify_with_bsb22_commitment` |    132,574 |    132,574 |

## 12. Groth16-bsb22-opt - 8 public inputs

| Function                       |   Total CU |     Net CU |
| ------------------------------ | ---------- | ---------- |
| `verify_with_bsb22_commitment` |    150,085 |    150,085 |

## 13. Groth16-bsb22-opt-cached - 1 public input

| Function                       |   Total CU |     Net CU |
| ------------------------------ | ---------- | ---------- |
| `verify_with_bsb22_commitment` |    118,641 |    118,641 |

## 14. Groth16-bsb22-opt-cached - 2 public inputs

| Function                       |   Total CU |     Net CU |
| ------------------------------ | ---------- | ---------- |
| `verify_with_bsb22_commitment` |    123,063 |    123,063 |

## 15. Groth16-bsb22-opt-cached - 4 public inputs

| Function                       |   Total CU |     Net CU |
| ------------------------------ | ---------- | ---------- |
| `verify_with_bsb22_commitment` |    131,833 |    131,833 |

## 16. Groth16-bsb22-opt-cached - 8 public inputs

| Function                       |   Total CU |     Net CU |
| ------------------------------ | ---------- | ---------- |
| `verify_with_bsb22_commitment` |    149,216 |    149,216 |

## 17. Groth16-bsb22-opt-hint - 1 public input

| Function                       |   Total CU |     Net CU |
| ------------------------------ | ---------- | ---------- |
| `verify_with_bsb22_commitment` |    118,244 |    118,244 |

## 18. Groth16-bsb22-opt-hint - 2 public inputs

| Function                       |   Total CU |     Net CU |
| ------------------------------ | ---------- | ---------- |
| `verify_with_bsb22_commitment` |    122,700 |    122,700 |

## 19. Groth16-bsb22-opt-hint - 4 public inputs

| Function                       |   Total CU |     Net CU |
| ------------------------------ | ---------- | ---------- |
| `verify_with_bsb22_commitment` |    131,537 |    131,537 |

## 20. Groth16-bsb22-opt-hint - 8 public inputs

| Function                       |   Total CU |     Net CU |
| ------------------------------ | ---------- | ---------- |
| `verify_with_bsb22_commitment` |    149,045 |    149,045 |

## 21. Groth16-bsb22-opt-hint-cached - 1 public input

| Function                       |   Total CU |     Net CU |
| ------------------------------ | ---------- | ---------- |
| `verify_with_bsb22_commitment` |    117,600 |    117,600 |

## 22. Groth16-bsb22-opt-hint-cached - 2 public inputs

| Function                       |   Total CU |     Net CU |
| ------------------------------ | ---------- | ---------- |
| `verify_with_bsb22_commitment` |    122,022 |    122,022 |

## 23. Groth16-bsb22-opt-hint-cached - 4 public inputs

| Function                       |   Total CU |     Net CU |
| ------------------------------ | ---------- | ---------- |
| `verify_with_bsb22_commitment` |    130,795 |    130,795 |

## 24. Groth16-bsb22-opt-hint-cached - 8 public inputs

| Function                       |   Total CU |     Net CU |
| ------------------------------ | ---------- | ---------- |
| `verify_with_bsb22_commitment` |    148,176 |    148,176 |

