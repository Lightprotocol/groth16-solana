pragma circom 2.0.0;

include "../node_modules/circomlib/circuits/poseidon.circom";
include "../node_modules/circomlib/circuits/bitify.circom";
include "../node_modules/circomlib/circuits/switcher.circom";
include "../node_modules/circomlib/circuits/comparators.circom";

// Compressed Account Hash Template
// Computes the hash of a compressed account
template CompressedAccountHash() {
    signal input owner_hashed;
    signal input leaf_index;
    signal input merkle_tree_hashed;
    signal input discriminator;
    signal input data_hash;

    signal output hash;

    component poseidon = Poseidon(5);

    poseidon.inputs[0] <== owner_hashed;
    poseidon.inputs[1] <== leaf_index;
    poseidon.inputs[2] <== merkle_tree_hashed;
    poseidon.inputs[3] <== discriminator + 36893488147419103232; // + discriminator domain
    poseidon.inputs[4] <== data_hash;

    hash <== poseidon.out;
}

// Merkle Proof Verification Template
// Verifies that a leaf is in a Merkle tree with a given root
template MerkleProof(levels) {
    signal input leaf;
    signal input pathElements[levels];
    signal input leafIndex;
    signal output root;

    component switcher[levels];
    component hasher[levels];

    component indexBits = Num2Bits(levels);
    indexBits.in <== leafIndex;

    for (var i = 0; i < levels; i++) {
        switcher[i] = Switcher();
        switcher[i].L <== i == 0 ? leaf : hasher[i - 1].out;
        switcher[i].R <== pathElements[i];
        switcher[i].sel <== indexBits.out[i];

        hasher[i] = Poseidon(2);
        hasher[i].inputs[0] <== switcher[i].outL;
        hasher[i].inputs[1] <== switcher[i].outR;
    }

    root <== hasher[levels - 1].out;
}

// Main Circuit: Compressed Account Merkle Proof Verification
// Computes compressed account hash and verifies it exists in a Merkle tree
template CompressedAccountMerkleProof(levels) {
    // Compressed account inputs
    signal input owner_hashed;
    signal input leaf_index;
    signal input merkle_tree_hashed;
    signal input discriminator;
    signal input data_hash;

    // Merkle proof inputs
    signal input pathElements[levels];
    signal input expectedRoot;

    // Step 1: Compute compressed account hash
    component accountHasher = CompressedAccountHash();
    accountHasher.owner_hashed <== owner_hashed;
    accountHasher.leaf_index <== leaf_index;
    accountHasher.merkle_tree_hashed <== merkle_tree_hashed;
    accountHasher.discriminator <== discriminator;
    accountHasher.data_hash <== data_hash;

    // Step 2: Verify Merkle proof
    component merkleProof = MerkleProof(levels);
    merkleProof.leaf <== accountHasher.hash;
    merkleProof.pathElements <== pathElements;
    merkleProof.leafIndex <== leaf_index;

    // Step 3: CRITICAL CONSTRAINT - Enforce that computed root MUST equal expected root
    // This === operator adds a constraint that will fail witness generation if roots don't match
    merkleProof.root === expectedRoot;
}

// Main component with 26 levels (typical for Solana state trees)
component main {
    public [
        owner_hashed,
        merkle_tree_hashed,
        discriminator,
        data_hash,
        expectedRoot
    ]
} = CompressedAccountMerkleProof(26);
