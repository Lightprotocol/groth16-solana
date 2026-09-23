//! Setup metadata the vk generators write next to each verifying key.
//!
//! Both generators ([`crate::vk::circom`] and [`crate::vk::gnark`])
//! take a [`SetupKind`] and a [`ProvingKeySource`] and write, after
//! the `Groth16Verifyingkey` const:
//!
//! ```rust,ignore
//! /// SHA-256 of the proving key file this verifying key was generated with.
//! pub const VERIFYINGKEY_PROVING_KEY_SHA256: [u8; 32] = [..];
//! /// `true` for a test setup whose secret randomness is public or untrusted ...
//! pub const VERIFYINGKEY_INSECURE_TEST_SETUP: bool = false;
//! /// The two values above as a delimited string kept in the program binary.
//! #[unsafe(export_name = "groth16_solana_vk_setup_<hash>")]
//! pub static VERIFYINGKEY_SETUP_TXT: &str = "=======BEGIN GROTH16 VK SETUP V1=======\0..";
//! ```
//!
//! A prover compares [`proving_key_sha256`] of the proving key it is
//! about to load against `*_PROVING_KEY_SHA256`, so a stale or
//! mismatched key fails before proving starts.
//!
//! A [`SetupKind::InsecureTest`] vk also gets
//! `#[cfg(not(feature = "insecure-test-setup"))] compile_error!(..)`:
//! the crate that includes it must declare and enable an
//! `insecure-test-setup` feature. Deployable programs leave it off.
//!
//! # Checking a program binary
//!
//! `*_SETUP_TXT` follows Neodyme's `security.txt` layout: an exported
//! static (so neither the compiler nor the linker drops it although
//! nothing references it) holding `key\0value\0` pairs between
//! [`SETUP_TXT_BEGIN`] and [`SETUP_TXT_END`]. The program data account
//! stores the raw ELF, so [`find_setup_txts`] reads it from a local
//! `.so` or from `solana program dump <PROGRAM_ID> program.so` after
//! deployment. `strings program.so` shows the same fields.

extern crate std;

use sha2::{Digest, Sha256};
use std::fs::File;
use std::io::{self, Read};
use std::path::Path;

use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

/// Where the randomness of the Groth16 setup came from. Both generators
/// require it, so each build script has to state it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SetupKind {
    /// Test-only: the secret setup scalars (α, β, γ, δ, τ) are public or
    /// untrusted. A seeded gnark `groth16.Setup` makes them recomputable
    /// from the seed; a snarkjs zkey exported before any phase-2
    /// contribution leaves δ = γ; a throwaway local setup has nobody
    /// vouching that they were discarded. Whoever knows them can make
    /// the vk accept a proof for any public inputs without a valid
    /// witness; honest proofs still need one. Do not deploy it to devnet
    /// or mainnet.
    InsecureTest,
    /// The setup randomness was sampled from a secure source and
    /// discarded (a single-party random setup or an MPC ceremony).
    Production,
}

/// The proving key whose SHA-256 goes into the generated
/// `*_PROVING_KEY_SHA256` const.
#[derive(Debug, Clone, Copy)]
pub enum ProvingKeySource<'a> {
    /// Hash this file (streamed, so multi-GB keys are fine). Preferred:
    /// the digest is computed from the key next to the vk.
    File(&'a Path),
    /// A precomputed SHA-256, e.g. from a lockfile, for build scripts
    /// that do not have the proving key on disk.
    Sha256([u8; 32]),
}

impl ProvingKeySource<'_> {
    pub(crate) fn sha256(&self) -> io::Result<[u8; 32]> {
        match self {
            ProvingKeySource::File(path) => proving_key_sha256(path),
            ProvingKeySource::Sha256(digest) => Ok(*digest),
        }
    }
}

/// SHA-256 of the file at `path`, streamed in 64 KiB chunks. The
/// digest covers the file bytes as serialized: gnark `pk.WriteTo` and
/// `pk.WriteRawTo` of the same key hash differently.
pub fn proving_key_sha256(path: impl AsRef<Path>) -> io::Result<[u8; 32]> {
    let mut file = File::open(path.as_ref())?;
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 64 * 1024];
    loop {
        let n = file.read(&mut buf)?;
        if n == 0 {
            break;
        }
        let chunk = buf.get(..n).ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidData, "read returned too many bytes")
        })?;
        hasher.update(chunk);
    }
    Ok(hasher.finalize().into())
}

/// Whether `vk_delta_g2 == vk_gamma_g2`. snarkjs `groth16 setup`
/// (`zkey_new.js`) and gnark mpcsetup phase 2 (`phase2.go`) both start
/// delta at the G2 generator, which is also their gamma; only a
/// phase-2 contribution moves it. With gamma equal to delta,
/// `e(L, γ)·e(C, δ)` equals `e(L + C, δ)`, so the proof
/// `A = α, B = β, C = -L(x)` verifies for every public input `x`.
pub(crate) fn delta_equals_gamma(vk_gamma_g2: &[u8], vk_delta_g2: &[u8]) -> bool {
    vk_gamma_g2 == vk_delta_g2
}

/// Warning comment for the top of a generated file; empty for
/// [`SetupKind::Production`].
pub(crate) fn header_warning(setup: SetupKind) -> &'static str {
    match setup {
        SetupKind::InsecureTest => {
            "// INSECURE TEST SETUP: the secret setup randomness is public or\n\
             // untrusted. Whoever knows it can make this verifying key accept a\n\
             // proof for any public inputs without a valid witness. Do not deploy\n\
             // it to devnet or mainnet.\n\n"
        }
        SetupKind::Production => "",
    }
}

/// Opening delimiter of a `*_SETUP_TXT` string.
pub const SETUP_TXT_BEGIN: &str = "=======BEGIN GROTH16 VK SETUP V1=======\0";
/// Closing delimiter of a `*_SETUP_TXT` string.
pub const SETUP_TXT_END: &str = "=======END GROTH16 VK SETUP V1=======\0";

const FIELD_NAME: &str = "name";
const FIELD_INSECURE_TEST_SETUP: &str = "insecure_test_setup";
const FIELD_PROVING_KEY_SHA256: &str = "proving_key_sha256";

/// Setup metadata of one verifying key, read back from a binary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SetupTxt {
    /// The generated const's name, e.g. `VERIFYINGKEY`.
    pub name: String,
    pub insecure_test_setup: bool,
    pub proving_key_sha256: [u8; 32],
}

impl SetupTxt {
    fn to_marker(&self) -> String {
        format!(
            "{SETUP_TXT_BEGIN}{FIELD_NAME}\0{}\0{FIELD_INSECURE_TEST_SETUP}\0{}\0\
             {FIELD_PROVING_KEY_SHA256}\0{}\0{SETUP_TXT_END}",
            self.name,
            self.insecure_test_setup,
            to_hex(&self.proving_key_sha256)
        )
    }
}

/// A `*_SETUP_TXT` string in a binary that does not parse.
#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub enum SetupTxtError {
    #[error("setup.txt at byte {0} has no end delimiter")]
    Unterminated(usize),
    #[error("setup.txt at byte {offset} is malformed: {reason}")]
    Malformed { offset: usize, reason: String },
}

/// Every `*_SETUP_TXT` embedded in `binary` (a program `.so`, built
/// locally or fetched with `solana program dump`), in file order. One
/// entry per verifying key the program links.
pub fn find_setup_txts(binary: &[u8]) -> Result<Vec<SetupTxt>, SetupTxtError> {
    let begin = SETUP_TXT_BEGIN.as_bytes();
    let end = SETUP_TXT_END.as_bytes();
    let mut found = Vec::new();
    let mut pos = 0;
    while let Some(start) = find_bytes(binary.get(pos..).unwrap_or_default(), begin) {
        let offset = pos + start;
        let body_start = offset + begin.len();
        let body_rest = binary.get(body_start..).unwrap_or_default();
        let body_len = find_bytes(body_rest, end).ok_or(SetupTxtError::Unterminated(offset))?;
        let body = body_rest
            .get(..body_len)
            .ok_or(SetupTxtError::Unterminated(offset))?;
        found.push(parse_body(body, offset)?);
        pos = body_start + body_len + end.len();
    }
    Ok(found)
}

fn parse_body(body: &[u8], offset: usize) -> Result<SetupTxt, SetupTxtError> {
    let malformed = |reason: &str| SetupTxtError::Malformed {
        offset,
        reason: reason.to_string(),
    };
    let text = core::str::from_utf8(body).map_err(|_| malformed("not UTF-8"))?;
    // Every key and value is `\0`-terminated, so the last split is empty.
    let mut parts = text.split('\0');
    let mut field = |key: &str| -> Result<&str, SetupTxtError> {
        match (parts.next(), parts.next()) {
            (Some(k), Some(v)) if k == key => Ok(v),
            _ => Err(malformed(&format!("expected field `{key}`"))),
        }
    };
    let name = field(FIELD_NAME)?.to_string();
    let insecure_test_setup = match field(FIELD_INSECURE_TEST_SETUP)? {
        "true" => true,
        "false" => false,
        _ => return Err(malformed("insecure_test_setup is not true/false")),
    };
    let proving_key_sha256 = from_hex(field(FIELD_PROVING_KEY_SHA256)?)
        .ok_or_else(|| malformed("proving_key_sha256 is not 64 hex digits"))?;
    if parts.next() != Some("") || parts.next().is_some() {
        return Err(malformed("unexpected trailing fields"));
    }
    Ok(SetupTxt {
        name,
        insecure_test_setup,
        proving_key_sha256,
    })
}

fn find_bytes(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}

fn to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn from_hex(s: &str) -> Option<[u8; 32]> {
    let digits = s.as_bytes();
    if digits.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    for (byte, pair) in out.iter_mut().zip(digits.chunks_exact(2)) {
        let pair = core::str::from_utf8(pair).ok()?;
        *byte = u8::from_str_radix(pair, 16).ok()?;
    }
    Some(out)
}

/// Rust source for the `<const_name>_PROVING_KEY_SHA256`,
/// `<const_name>_INSECURE_TEST_SETUP` and `<const_name>_SETUP_TXT`
/// items, plus the compile guard for [`SetupKind::InsecureTest`].
/// `vk_source` is the generated vk code; hashing it into the export
/// name keeps the symbol unique when a program links several vks
/// that share a const name in different modules.
pub(crate) fn metadata_rust_source(
    vk_source: &str,
    const_name: &str,
    setup: SetupKind,
    proving_key_sha256: &[u8; 32],
) -> String {
    let digest = proving_key_sha256
        .iter()
        .map(|b| format!("{}u8", b))
        .collect::<Vec<_>>()
        .join(", ");
    let insecure = setup == SetupKind::InsecureTest;
    let marker = SetupTxt {
        name: const_name.to_string(),
        insecure_test_setup: insecure,
        proving_key_sha256: *proving_key_sha256,
    }
    .to_marker();
    let symbol_hash: [u8; 32] = Sha256::new()
        .chain_update(vk_source.as_bytes())
        .chain_update(marker.as_bytes())
        .finalize()
        .into();
    let symbol_hash = to_hex(&symbol_hash);
    let symbol = format!(
        "groth16_solana_vk_setup_{}",
        symbol_hash.get(..16).unwrap_or(&symbol_hash)
    );
    // `\x00`, not `\0`: a `\0` followed by a hex digit of the digest
    // reads like an octal escape (clippy `octal_escapes`).
    let marker_literal = marker.replace('\0', "\\x00");

    let mut out = String::new();
    out.push_str("\n/// SHA-256 of the proving key file this verifying key was generated with.\n");
    out.push_str("#[allow(dead_code)]\n#[rustfmt::skip]\n");
    out.push_str(&format!(
        "pub const {const_name}_PROVING_KEY_SHA256: [u8; 32] = [{digest}];\n"
    ));
    out.push_str(
        "\n/// `true` for a test setup whose secret randomness is public or untrusted:\n\
         /// whoever knows it can make this key accept a proof for any public\n\
         /// inputs without a valid witness. Must not be deployed to devnet or\n\
         /// mainnet.\n",
    );
    out.push_str("#[allow(dead_code)]\n");
    out.push_str(&format!(
        "pub const {const_name}_INSECURE_TEST_SETUP: bool = {insecure};\n"
    ));
    out.push_str(&format!(
        "\n/// The two consts above as a delimited string, exported so it stays in\n\
         /// the program binary; read it back with\n\
         /// `groth16_solana::vk::setup::find_setup_txts`.\n\
         #[unsafe(export_name = \"{symbol}\")]\n\
         #[rustfmt::skip]\n\
         pub static {const_name}_SETUP_TXT: &str = \"{marker_literal}\";\n"
    ));
    if insecure {
        out.push_str(&format!(
            "\n#[cfg(not(feature = \"insecure-test-setup\"))]\n\
             compile_error!(\"{const_name} comes from an insecure test setup: whoever knows its \
             setup randomness can make it accept a proof for any public inputs. Enable the \
             `insecure-test-setup` feature only in test builds, not for a devnet or mainnet \
             deployment.\");\n"
        ));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_file(name: &str, contents: &[u8]) -> std::path::PathBuf {
        let path = std::env::temp_dir().join(format!(
            "groth16-solana-setup-{}-{}",
            std::process::id(),
            name
        ));
        std::fs::write(&path, contents).unwrap();
        path
    }

    fn setup_txt(name: &str, insecure: bool, fill: u8) -> SetupTxt {
        SetupTxt {
            name: name.to_string(),
            insecure_test_setup: insecure,
            proving_key_sha256: [fill; 32],
        }
    }

    #[test]
    fn proving_key_sha256_matches_known_vector() {
        // FIPS 180-2 "abc" test vector.
        let path = temp_file("abc", b"abc");
        let digest = proving_key_sha256(&path).unwrap();
        std::fs::remove_file(&path).unwrap();
        let expected: [u8; 32] = [
            0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40, 0xde, 0x5d, 0xae,
            0x22, 0x23, 0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c, 0xb4, 0x10, 0xff, 0x61,
            0xf2, 0x00, 0x15, 0xad,
        ];
        assert_eq!(digest, expected);
    }

    #[test]
    fn proving_key_sha256_streams_across_chunks() {
        // 64 KiB chunks: 200_001 bytes spans four reads with a partial tail.
        let contents: Vec<u8> = (0..200_001u32).map(|i| (i % 251) as u8).collect();
        let path = temp_file("chunks", &contents);
        let digest = proving_key_sha256(&path).unwrap();
        std::fs::remove_file(&path).unwrap();
        let expected: [u8; 32] = Sha256::digest(&contents).into();
        assert_eq!(digest, expected);
    }

    #[test]
    fn proving_key_sha256_reports_missing_file() {
        let err = proving_key_sha256("/nonexistent/pk.bin").unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::NotFound);
    }

    #[test]
    fn metadata_marks_insecure_test_setup_with_compile_guard() {
        let src = metadata_rust_source("", "VK", SetupKind::InsecureTest, &[7u8; 32]);
        assert!(src.contains("pub const VK_PROVING_KEY_SHA256: [u8; 32] = [7u8, 7u8,"));
        assert!(src.contains("pub const VK_INSECURE_TEST_SETUP: bool = true;"));
        assert!(src.contains(
            "pub static VK_SETUP_TXT: &str = \"=======BEGIN GROTH16 VK SETUP V1=======\\x00name\\x00VK\\x00insecure_test_setup\\x00true\\x00proving_key_sha256\\x000707"
        ));
        assert!(src.contains("#[cfg(not(feature = \"insecure-test-setup\"))]\ncompile_error!("));
    }

    #[test]
    fn metadata_production_has_no_compile_guard() {
        let src = metadata_rust_source("", "VK", SetupKind::Production, &[7u8; 32]);
        assert!(src.contains("pub const VK_INSECURE_TEST_SETUP: bool = false;"));
        assert!(src.contains("\\x00insecure_test_setup\\x00false\\x00"));
        assert!(!src.contains("compile_error!"));
        assert_eq!(header_warning(SetupKind::Production), "");
    }

    #[test]
    fn metadata_export_name_depends_on_vk_source() {
        // Two vks named VERIFYINGKEY in different modules must not
        // export the same symbol.
        let export = |vk_source: &str| {
            let src = metadata_rust_source(vk_source, "VK", SetupKind::Production, &[7u8; 32]);
            let start = src.find("export_name = \"").unwrap();
            src.get(start..start + 60).unwrap().to_string()
        };
        assert_ne!(export("vk a"), export("vk b"));
        assert_eq!(export("vk a"), export("vk a"));
    }

    #[test]
    fn find_setup_txts_reads_markers_between_other_bytes() {
        let a = setup_txt("VK_A", true, 0xab);
        let b = setup_txt("VK_B", false, 0x01);
        let mut binary = b"\x7fELF junk".to_vec();
        binary.extend_from_slice(a.to_marker().as_bytes());
        binary.extend_from_slice(b"\0\0rodata");
        binary.extend_from_slice(b.to_marker().as_bytes());
        binary.extend_from_slice(b"tail");
        assert_eq!(find_setup_txts(&binary).unwrap(), [a, b]);
    }

    #[test]
    fn find_setup_txts_returns_empty_without_markers() {
        assert_eq!(find_setup_txts(b"\x7fELF no markers here").unwrap(), []);
    }

    #[test]
    fn find_setup_txts_rejects_unterminated_marker() {
        let marker = setup_txt("VK", true, 0).to_marker();
        let truncated = marker.get(..marker.len() - 4).unwrap();
        let mut binary = b"junk".to_vec();
        binary.extend_from_slice(truncated.as_bytes());
        assert_eq!(
            find_setup_txts(&binary).unwrap_err(),
            SetupTxtError::Unterminated(4)
        );
    }

    #[test]
    fn find_setup_txts_rejects_malformed_fields() {
        let good = setup_txt("VK", true, 0x11).to_marker();
        for bad in [
            good.replace("insecure_test_setup\0true", "insecure_test_setup\0yes"),
            good.replace("proving_key_sha256\0", "proving_key_sha256\0zz"),
            good.replace("name\0", "label\0"),
            good.replace(SETUP_TXT_END, &format!("extra\0field\0{SETUP_TXT_END}")),
        ] {
            let err = find_setup_txts(bad.as_bytes()).unwrap_err();
            assert!(
                matches!(err, SetupTxtError::Malformed { offset: 0, .. }),
                "unexpected result for {bad:?}: {err:?}"
            );
        }
    }
}
