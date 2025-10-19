# ZK Circom Circuit for Compressed Account Merkle Proof

This directory contains a circom circuit that verifies a Merkle proof of a compressed account on Solana.

## Circuit Overview

The `compressed_account_merkle_proof.circom` circuit combines two key components:

1. **Compressed Account Hash**: Computes the hash of a compressed account using Poseidon hash
   - Based on: https://github.com/ananas-block/compressed-account-circuit
   - Inputs: owner_hashed, leaf_index, merkle_tree_hashed, discriminator, data_hash

2. **Merkle Proof Verification**: Verifies the account exists in a Merkle tree
   - Based on: /Users/ananas/dev/light-protocol2/circuit-lib/circuit-lib.circom
   - Inputs: pathElements (26 levels), expectedRoot

## Setup

Run the setup script - it will handle dependencies, compilation, and key generation:

```bash
./scripts/setup.sh
```

To clean up build artifacts:

```bash
./scripts/clean.sh
```

## Testing

### Rust Test with Mopro

The circuit can be tested from Rust using the mopro library:

```bash
cargo test test_compressed_account_merkle_proof_circuit
```

This test:
1. Loads the compiled circuit and zkey
2. Generates a proof with sample inputs
3. Verifies the proof is valid

## Circuit Structure

```
CompressedAccountMerkleProof (main)
├── CompressedAccountHash
│   └── Poseidon(5) - Hashes account fields
└── MerkleProof(26)
    ├── Num2Bits - Converts leaf index to bits
    ├── Switcher[26] - Routes left/right based on path
    └── Poseidon(2)[26] - Hashes up the tree
```

## Public Inputs

The following inputs are public (visible in the proof):
- owner_hashed
- merkle_tree_hashed
- discriminator
- data_hash
- expectedRoot

Private inputs:
- leaf_index
- pathElements

## References

- Compressed Account Circuit: https://github.com/ananas-block/compressed-account-circuit
- Merkle Proof Implementation: /Users/ananas/dev/light-protocol2/circuit-lib/circuit-lib.circom
- Mopro ZK Library: https://github.com/zkmopro/mopro
- SnarkJS: https://github.com/iden3/snarkjs
