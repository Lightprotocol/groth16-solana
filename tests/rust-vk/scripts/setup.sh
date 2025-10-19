#!/bin/bash

set -e

echo "Setting up groth16-solana integration test..."

# Create directories
mkdir -p pot build

# Download powers of tau if not exists
POT_FILE="pot/powersOfTau28_hez_final_16.ptau"
if [ ! -f "$POT_FILE" ]; then
    echo "Downloading powers of tau ceremony file..."
    curl -L https://storage.googleapis.com/zkevm/ptau/powersOfTau28_hez_final_16.ptau -o "$POT_FILE"
    echo "Powers of tau downloaded successfully"
else
    echo "Powers of tau file already exists, skipping download"
fi

# Install npm dependencies
echo "Installing npm dependencies..."
npm install

echo "Setup complete! Run 'npm run build-all' to compile the circuit and generate keys"
