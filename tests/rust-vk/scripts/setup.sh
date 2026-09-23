#!/bin/bash

set -e

echo "Setting up groth16-solana integration test..."

# Create directories
mkdir -p pot build

# PSE perpetual powers of tau, 2^16 powers, prepared for phase 2. The
# Hermez mirrors (storage.googleapis.com/zkevm, hermez.s3) now return
# 403 to anonymous callers.
POT_FILE="pot/ppot_0080_16.ptau"
POT_URL="https://pse-trusted-setup-ppot.s3.eu-central-1.amazonaws.com/pot28_0080/ppot_0080_16.ptau"
POT_SHA256="ed3622a7c79b0b49aadd134ebbc5b77df8c8c59bccebdfd0d9bf2c1a51561cf9"

sha256() {
    if command -v sha256sum >/dev/null; then
        sha256sum "$1" | cut -d' ' -f1
    else
        shasum -a 256 "$1" | cut -d' ' -f1
    fi
}

# Download powers of tau if not exists
if [ ! -f "$POT_FILE" ]; then
    echo "Downloading powers of tau ceremony file..."
    curl -fL "$POT_URL" -o "$POT_FILE"
else
    echo "Powers of tau file already exists, skipping download"
fi
if [ "$(sha256 "$POT_FILE")" != "$POT_SHA256" ]; then
    echo "Checksum mismatch for $POT_FILE; delete it and rerun" >&2
    exit 1
fi
echo "Powers of tau checksum ok"

# Install npm dependencies
echo "Installing npm dependencies..."
npm install

echo "Setup complete! Run 'npm run build-all' to compile the circuit and generate keys"
