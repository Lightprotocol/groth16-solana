//! Parser for gnark v0.14's `VerifyingKey.WriteRawTo` binary layout.
//!
//! This is the on-disk format produced by `vk.WriteRawTo(w)` in
//! gnark; it differs from the snarkjs JSON format that
//! [`crate::vk::circom`] handles. The light-protocol/xtask
//! `create_vkeyrs_from_gnark_key.rs` parses the same head-of-file
//! layout but stops at the K array — it does NOT read the trailing
//! BSB22 sections (`PublicAndCommitmentCommitted` and `CommitmentKeys`)
//! that gnark always emits, even for circuits without commitments. This module
//! reads everything and rejects multi-commitment vk's
//! ([`Groth16Error::Bsb22UnsupportedMultiCommitment`]).
//!
//! Layout — `gnark/backend/groth16/bn254/marshal.go::writeTo`:
//!
//! ```text
//! [α]1                              G1 64 BE
//! [β]1                              G1 64 BE   (unused by verifier)
//! [β]2                              G2 128 BE
//! [γ]2                              G2 128 BE
//! [δ]1                              G1 64 BE   (unused by verifier)
//! [δ]2                              G2 128 BE
//! nbK                               u32 BE
//! K[]                               nbK × G1 64 BE
//! PublicAndCommitmentCommitted: [][]uint64 encoded as
//!   outerLen                        u32 BE       -- ALWAYS PRESENT, may be 0
//!   for i in 0..outerLen:
//!     innerLen                      u32 BE
//!     innerLen × u64 BE
//! nbCommitmentKeys                  u32 BE       -- ALWAYS PRESENT, may be 0
//! for each commitmentKey:
//!   G                               G2 128 BE
//!   GSigmaNeg                       G2 128 BE
//! ```
//!
//! Multi-commitment circuits (`outerLen > 1` or `nbCommitmentKeys > 1`)
//! are rejected loudly. Commitment-free circuits parse cleanly and produce a
//! [`Groth16VerifyingkeyOwned`] with `vk_commitment` set to `None`.

#[cfg(not(target_os = "solana"))]
extern crate std;

use crate::errors::Groth16Error;
use crate::groth16::{CommitmentVerifyingKey, Groth16Verifyingkey};
#[cfg(not(target_os = "solana"))]
use alloc::format;
#[cfg(not(target_os = "solana"))]
use alloc::string::String;
use alloc::vec::Vec;

/// Owned counterpart of [`Groth16Verifyingkey`]. The borrowed form
/// holds `&'a [[u8; 64]]` slices, which makes it perfect for
/// embedding as a `pub const` in downstream programs but inconvenient
/// for runtime construction (e.g., the integration tests in
/// `tests/gnark-ffi/`). This struct owns its `vk_ic` vector and exposes
/// [`Self::as_borrowed`] to materialise a borrowed view that the
/// verifier consumes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Groth16VerifyingkeyOwned {
    pub nr_pubinputs: usize,
    pub vk_alpha_g1: [u8; 64],
    pub vk_beta_g2: [u8; 128],
    pub vk_gamma_g2: [u8; 128],
    pub vk_delta_g2: [u8; 128],
    pub vk_ic: Vec<[u8; 64]>,
    pub vk_commitment: Option<CommitmentVerifyingKey>,
}

impl Groth16VerifyingkeyOwned {
    /// Borrow this owned vk as a [`Groth16Verifyingkey`] suitable for
    /// constructing a [`crate::groth16::Groth16Verifier`]. The
    /// borrowed view shares the underlying `vk_ic` slice — the owned
    /// struct must outlive the borrow.
    pub fn as_borrowed(&self) -> Groth16Verifyingkey<'_> {
        Groth16Verifyingkey {
            nr_pubinputs: self.nr_pubinputs,
            vk_alpha_g1: self.vk_alpha_g1,
            vk_beta_g2: self.vk_beta_g2,
            vk_gamma_g2: self.vk_gamma_g2,
            vk_delta_g2: self.vk_delta_g2,
            vk_ic: &self.vk_ic,
            vk_commitment: self.vk_commitment,
        }
    }
}

/// Parse gnark's `WriteRawTo` binary into an owned vk struct.
///
/// Rejects:
/// - any input shorter than the fixed-head size, or with trailing
///   bytes, or `nbK == 0`, or mismatched `outerLen` /
///   `nbCommitmentKeys` (gnark emits both in lockstep — 0/0 or 1/1)
///   → [`Groth16Error::Bsb22InvalidVerifyingKeyBinary`].
/// - `outerLen > 1` or `nbCommitmentKeys > 1`
///   → [`Groth16Error::Bsb22UnsupportedMultiCommitment`].
/// - a non-empty committed-wires list (the circuit commits to public
///   inputs) → [`Groth16Error::Bsb22CommittedPublicInputsUnsupported`].
pub fn parse_gnark_vk_bytes(bytes: &[u8]) -> Result<Groth16VerifyingkeyOwned, Groth16Error> {
    let mut cursor = Cursor::new(bytes);

    let vk_alpha_g1 = cursor.take_64()?;
    cursor.skip(64)?; // beta_g1, unused by verifier
    let vk_beta_g2 = cursor.take_128()?;
    let vk_gamma_g2 = cursor.take_128()?;
    cursor.skip(64)?; // delta_g1, unused by verifier
    let vk_delta_g2 = cursor.take_128()?;

    let nb_k = cursor.u32()? as usize;
    if nb_k == 0 {
        return Err(Groth16Error::Bsb22InvalidVerifyingKeyBinary);
    }
    let mut vk_ic = Vec::with_capacity(nb_k);
    for _ in 0..nb_k {
        vk_ic.push(cursor.take_64()?);
    }

    // Trailing PublicAndCommitmentCommitted: [][]uint64
    let outer_len = cursor.u32()? as usize;
    if outer_len > 1 {
        return Err(Groth16Error::Bsb22UnsupportedMultiCommitment);
    }
    // Even though we only support outer_len in {0, 1} with empty
    // committed_wires, we must still consume the inner slice to keep
    // the cursor aligned for the commitment-key section.
    for _ in 0..outer_len {
        let inner_len = cursor.u32()? as usize;
        // committed_wires must be empty for our supported circuits
        // (logderivlookup over private wires). A non-empty list means
        // the circuit commits to public inputs, whose values would
        // have to be concatenated into the verifier's BSB22 hash
        // preimage — unsupported until someone threads those wire
        // indices through.
        if inner_len != 0 {
            return Err(Groth16Error::Bsb22CommittedPublicInputsUnsupported);
        }
    }

    let nb_commitments = cursor.u32()? as usize;
    if nb_commitments > 1 {
        return Err(Groth16Error::Bsb22UnsupportedMultiCommitment);
    }
    if nb_commitments != outer_len {
        // gnark writes outerLen and nbCommitmentKeys in lockstep:
        // both 0 (no commitment) or both 1 (BSB22). A mismatch is a
        // malformed binary, not a multi-commitment circuit.
        return Err(Groth16Error::Bsb22InvalidVerifyingKeyBinary);
    }

    let vk_commitment = if nb_commitments == 1 {
        let g2 = cursor.take_128()?;
        let g_sigma_neg_g2 = cursor.take_128()?;
        Some(CommitmentVerifyingKey { g2, g_sigma_neg_g2 })
    } else {
        None
    };

    // Reject trailing garbage: gnark's WriteRawTo output has a
    // known fixed structure and the cursor must land exactly at
    // the end. Anything else is a corrupted or malformed vk.bin.
    if cursor.pos != bytes.len() {
        return Err(Groth16Error::Bsb22InvalidVerifyingKeyBinary);
    }

    // gnark's `nbK` includes the constant K[0]; the verifier-facing
    // `nr_pubinputs` is K excluding K[0] minus the trailing K column
    // for the commitment hash wire (one extra K entry per commitment).
    //
    //   nr_pubinputs = nbK - 1 - nbCommitments
    //
    // For BSB22 single-commitment: nr_pubinputs = nbK - 2.
    // For standard Groth16:                 nr_pubinputs = nbK - 1.
    let nr_pubinputs = if vk_commitment.is_some() {
        if nb_k < 2 {
            return Err(Groth16Error::Bsb22InvalidVerifyingKeyBinary);
        }
        nb_k - 2
    } else {
        nb_k - 1
    };

    Ok(Groth16VerifyingkeyOwned {
        nr_pubinputs,
        vk_alpha_g1,
        vk_beta_g2,
        vk_gamma_g2,
        vk_delta_g2,
        vk_ic,
        vk_commitment,
    })
}

// =============================================================================
// Build-script helper: emit a Groth16Verifyingkey const from gnark vk.bin
// =============================================================================

#[cfg(not(target_os = "solana"))]
fn byte_list(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|b| format!("{}u8", b))
        .collect::<Vec<_>>()
        .join(", ")
}

/// Emit a Rust source string containing a `pub const VERIFYINGKEY:
/// Groth16Verifyingkey = …;` declaration built from a parsed
/// [`Groth16VerifyingkeyOwned`]. Used by downstream programs that
/// want to bake a gnark verifying key into their `.rodata` at build
/// time (the on-chain verifier reads a borrowed `&'static` vk that
/// way, avoiding any runtime allocation).
///
/// The generated source also includes the necessary `use
/// groth16_solana::groth16::…` import(s) so it can be `include!`d
/// directly into a downstream program's `src/verifying_key.rs`.
///
/// # Feature gating
///
/// The `vk_commitment` field is un-gated on `Groth16Verifyingkey`, so
/// the generated const compiles regardless of whether the `bsb22`
/// feature is enabled on the downstream runtime dependency. The
/// build-dependency on `groth16-solana` still needs
/// `features = ["bsb22"]` because this parser module itself lives
/// behind that feature.
#[cfg(not(target_os = "solana"))]
fn bsb22_vk_to_rust_const(vk: &Groth16VerifyingkeyOwned, const_name: &str) -> String {
    let mut out = String::new();
    out.push_str("// This file is generated by groth16_solana::vk::gnark.\n");
    out.push_str("// Do not edit by hand.\n\n");
    // Import `CommitmentVerifyingKey` only when the vk contains one;
    // otherwise a commitment-free vk would trip the unused-import lint.
    if vk.vk_commitment.is_some() {
        out.push_str(
            "use groth16_solana::groth16::{CommitmentVerifyingKey, Groth16Verifyingkey};\n\n",
        );
    } else {
        out.push_str("use groth16_solana::groth16::Groth16Verifyingkey;\n\n");
    }

    // The K-column slice needs a separate `static` binding because a
    // const can only borrow from another const / static with a
    // matching `'static` lifetime.
    out.push_str(&format!(
        "static {const_name}_VK_IC: &[[u8; 64]] = &[\n",
        const_name = const_name
    ));
    for row in &vk.vk_ic {
        out.push_str(&format!("    [{}],\n", byte_list(row)));
    }
    out.push_str("];\n\n");

    out.push_str(&format!(
        "pub const {}: Groth16Verifyingkey = Groth16Verifyingkey {{\n",
        const_name
    ));
    out.push_str(&format!("    nr_pubinputs: {},\n", vk.nr_pubinputs));

    out.push_str(&format!(
        "    vk_alpha_g1: [{}],\n",
        byte_list(&vk.vk_alpha_g1)
    ));
    out.push_str(&format!(
        "    vk_beta_g2: [{}],\n",
        byte_list(&vk.vk_beta_g2)
    ));
    out.push_str(&format!(
        "    vk_gamma_g2: [{}],\n",
        byte_list(&vk.vk_gamma_g2)
    ));
    out.push_str(&format!(
        "    vk_delta_g2: [{}],\n",
        byte_list(&vk.vk_delta_g2)
    ));
    out.push_str(&format!("    vk_ic: {}_VK_IC,\n", const_name));

    match &vk.vk_commitment {
        Some(ck) => {
            out.push_str("    vk_commitment: Some(CommitmentVerifyingKey {\n");
            out.push_str(&format!("        g2: [{}],\n", byte_list(&ck.g2)));
            out.push_str(&format!(
                "        g_sigma_neg_g2: [{}],\n",
                byte_list(&ck.g_sigma_neg_g2)
            ));
            out.push_str("    }),\n");
        }
        None => out.push_str("    vk_commitment: None,\n"),
    }

    out.push_str("};\n");
    out
}

/// Parse a gnark vk.bin file and write a Rust source file declaring
/// `pub const <const_name>: Groth16Verifyingkey` matching it. Typical
/// use is from a downstream program's `build.rs`:
///
/// ```rust,ignore
/// fn main() {
///     let out_dir = std::env::var("OUT_DIR").unwrap();
///     groth16_solana::vk::gnark::generate_bsb22_vk_file(
///         "fixtures/vk.bin",
///         &out_dir,
///         "verifying_key.rs",
///         "VERIFYINGKEY",
///     ).unwrap();
/// }
/// ```
///
/// The program source then picks up the generated file with:
///
/// ```rust,ignore
/// include!(concat!(env!("OUT_DIR"), "/verifying_key.rs"));
/// ```
#[cfg(not(target_os = "solana"))]
pub fn generate_bsb22_vk_file(
    input_path: impl AsRef<std::path::Path>,
    output_dir: impl AsRef<std::path::Path>,
    output_filename: &str,
    const_name: &str,
) -> Result<(), Groth16Error> {
    let bytes =
        std::fs::read(input_path.as_ref()).map_err(|_| Groth16Error::Bsb22VkFileIoFailed)?;
    let vk = parse_gnark_vk_bytes(&bytes)?;
    let rust = bsb22_vk_to_rust_const(&vk, const_name);
    std::fs::create_dir_all(output_dir.as_ref()).map_err(|_| Groth16Error::Bsb22VkFileIoFailed)?;
    let out_path = output_dir.as_ref().join(output_filename);
    std::fs::write(&out_path, rust).map_err(|_| Groth16Error::Bsb22VkFileIoFailed)?;
    Ok(())
}

// =============================================================================
// Cursor helper
// =============================================================================

struct Cursor<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }
    fn take(&mut self, n: usize) -> Result<&'a [u8], Groth16Error> {
        let end = self
            .pos
            .checked_add(n)
            .filter(|&end| end <= self.buf.len())
            .ok_or(Groth16Error::Bsb22InvalidVerifyingKeyBinary)?;
        let out = &self.buf[self.pos..end];
        self.pos = end;
        Ok(out)
    }
    fn skip(&mut self, n: usize) -> Result<(), Groth16Error> {
        self.take(n).map(|_| ())
    }
    fn take_64(&mut self) -> Result<[u8; 64], Groth16Error> {
        let s = self.take(64)?;
        let mut out = [0u8; 64];
        out.copy_from_slice(s);
        Ok(out)
    }
    fn take_128(&mut self) -> Result<[u8; 128], Groth16Error> {
        let s = self.take(128)?;
        let mut out = [0u8; 128];
        out.copy_from_slice(s);
        Ok(out)
    }
    fn u32(&mut self) -> Result<u32, Groth16Error> {
        let s = self.take(4)?;
        Ok(u32::from_be_bytes([s[0], s[1], s[2], s[3]]))
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    extern crate alloc;
    use super::*;
    use alloc::vec;

    /// Baked, reproducible `bsb22_1` vk snapshot shared with the
    /// `bsb22_e2e` tests in `src/groth16.rs` (see
    /// `crate::test_fixtures` for provenance and regeneration). The
    /// parser tests only assert the shape (K column count,
    /// commitment-key presence), not the actual coordinates.
    use crate::test_fixtures::VK_BYTES;

    #[test]
    fn parse_bsb22_vk_shape() {
        let bytes = VK_BYTES;
        assert_eq!(bytes.len(), 1040);
        let vk = parse_gnark_vk_bytes(bytes).expect("parse");

        // 1 user public input (X), 3 K columns (constant, X, commitment hash).
        assert_eq!(vk.nr_pubinputs, 1);
        assert_eq!(vk.vk_ic.len(), 3);

        // BSB22 commitment key is populated for the bsb22_1 fixture.
        assert!(vk.vk_commitment.is_some());

        // The borrowed view round-trips.
        let borrowed = vk.as_borrowed();
        assert_eq!(borrowed.nr_pubinputs, 1);
        assert_eq!(borrowed.vk_ic.len(), 3);
    }

    #[test]
    fn rejects_truncated_input() {
        let bytes = VK_BYTES;
        let err = parse_gnark_vk_bytes(&bytes[..bytes.len() - 8]).unwrap_err();
        assert_eq!(err, Groth16Error::Bsb22InvalidVerifyingKeyBinary);
    }

    #[test]
    fn rejects_trailing_bytes() {
        // Gnark emits a fixed-shape WriteRawTo blob; any bytes past
        // the last commitment key indicate corruption.
        let mut bytes = VK_BYTES.to_vec();
        bytes.push(0xab);
        let err = parse_gnark_vk_bytes(&bytes).unwrap_err();
        assert_eq!(err, Groth16Error::Bsb22InvalidVerifyingKeyBinary);
    }

    #[test]
    fn rejects_multi_commitment() {
        // Build a synthetic vk: fixed head + 1 K entry + outerLen=2.
        // The parser must reject before reading the second commitment.
        let mut bytes = vec![0u8; 576]; // alpha/beta/gamma/delta heads (zeroed)
        bytes.extend_from_slice(&1u32.to_be_bytes()); // nbK = 1
        bytes.extend_from_slice(&[0u8; 64]); // K[0]
        bytes.extend_from_slice(&2u32.to_be_bytes()); // outerLen = 2 -- REJECT
        let err = parse_gnark_vk_bytes(&bytes).unwrap_err();
        assert_eq!(err, Groth16Error::Bsb22UnsupportedMultiCommitment);
    }

    #[test]
    fn rejects_multi_commitment_keys() {
        let mut bytes = vec![0u8; 576];
        bytes.extend_from_slice(&1u32.to_be_bytes()); // nbK = 1
        bytes.extend_from_slice(&[0u8; 64]); // K[0]
        bytes.extend_from_slice(&0u32.to_be_bytes()); // outerLen = 0
        bytes.extend_from_slice(&2u32.to_be_bytes()); // nbCommitmentKeys = 2 -- REJECT
        let err = parse_gnark_vk_bytes(&bytes).unwrap_err();
        assert_eq!(err, Groth16Error::Bsb22UnsupportedMultiCommitment);
    }

    #[test]
    fn bsb22_vk_to_rust_const_roundtrip() {
        let bytes = VK_BYTES;
        let vk = parse_gnark_vk_bytes(bytes).unwrap();
        let src = bsb22_vk_to_rust_const(&vk, "VERIFYINGKEY");
        // Spot-check the shape without pinning exact whitespace: the
        // generated source must include the const declaration, the
        // nr_pubinputs value, and both commitment-key fields.
        assert!(src.contains(
            "use groth16_solana::groth16::{CommitmentVerifyingKey, Groth16Verifyingkey};"
        ));
        assert!(src.contains("pub const VERIFYINGKEY: Groth16Verifyingkey"));
        assert!(src.contains("nr_pubinputs: 1,"));
        assert!(src.contains("vk_ic: VERIFYINGKEY_VK_IC,"));
        assert!(src.contains("vk_commitment: Some(CommitmentVerifyingKey {"));
        // The bsb22_1 vk has 3 K-column entries.
        assert_eq!(src.matches("    [").count(), 3);
    }

    #[test]
    fn rejects_lockstep_mismatch() {
        // outerLen = 1 but nbCommitmentKeys = 0 -- gnark never emits
        // this, so it is a malformed binary.
        let mut bytes = vec![0u8; 576];
        bytes.extend_from_slice(&1u32.to_be_bytes()); // nbK = 1
        bytes.extend_from_slice(&[0u8; 64]); // K[0]
        bytes.extend_from_slice(&1u32.to_be_bytes()); // outerLen = 1
        bytes.extend_from_slice(&0u32.to_be_bytes()); // innerLen = 0
        bytes.extend_from_slice(&0u32.to_be_bytes()); // nbCommitmentKeys = 0 -- REJECT
        let err = parse_gnark_vk_bytes(&bytes).unwrap_err();
        assert_eq!(err, Groth16Error::Bsb22InvalidVerifyingKeyBinary);
    }

    #[test]
    fn rejects_committed_public_inputs() {
        // innerLen = 1: the circuit commits to a public input, which
        // this verifier's fixed 64-byte hash preimage cannot express.
        let mut bytes = vec![0u8; 576];
        bytes.extend_from_slice(&1u32.to_be_bytes()); // nbK = 1
        bytes.extend_from_slice(&[0u8; 64]); // K[0]
        bytes.extend_from_slice(&1u32.to_be_bytes()); // outerLen = 1
        bytes.extend_from_slice(&1u32.to_be_bytes()); // innerLen = 1 -- REJECT
        let err = parse_gnark_vk_bytes(&bytes).unwrap_err();
        assert_eq!(err, Groth16Error::Bsb22CommittedPublicInputsUnsupported);
    }

    #[test]
    fn generate_bsb22_vk_file_reports_io_error_for_missing_input() {
        let err = generate_bsb22_vk_file(
            "/nonexistent/vk.bin",
            std::env::temp_dir(),
            "verifying_key.rs",
            "VERIFYINGKEY",
        )
        .unwrap_err();
        assert_eq!(err, Groth16Error::Bsb22VkFileIoFailed);
    }
}
