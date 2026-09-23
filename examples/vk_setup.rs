//! Print the setup metadata of every verifying key baked into a Solana
//! program binary, from a local build or a deployed program:
//!
//! ```sh
//! solana program dump <PROGRAM_ID> program.so
//! cargo run -p groth16-solana --features gnark-vk --example vk_setup -- program.so
//! ```
//!
//! With `--deny-insecure` it exits with status 2 when any vk comes
//! from an insecure test setup, for use as a deploy gate.

use groth16_solana::vk::setup::find_setup_txts;
use std::process::ExitCode;

fn main() -> ExitCode {
    let mut deny_insecure = false;
    let mut path = None;
    for arg in std::env::args().skip(1) {
        match arg.as_str() {
            "--deny-insecure" => deny_insecure = true,
            _ if path.is_none() => path = Some(arg),
            _ => return usage(),
        }
    }
    let Some(path) = path else {
        return usage();
    };

    let binary = match std::fs::read(&path) {
        Ok(binary) => binary,
        Err(e) => {
            eprintln!("read {path}: {e}");
            return ExitCode::FAILURE;
        }
    };
    let setups = match find_setup_txts(&binary) {
        Ok(setups) => setups,
        Err(e) => {
            eprintln!("{path}: {e}");
            return ExitCode::FAILURE;
        }
    };
    if setups.is_empty() {
        println!("{path}: no groth16-solana vk setup metadata found");
    }
    for setup in &setups {
        let digest: String = setup
            .proving_key_sha256
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        let kind = if setup.insecure_test_setup {
            "INSECURE TEST SETUP"
        } else {
            "production"
        };
        println!("{}  {kind}  proving_key_sha256={digest}", setup.name);
    }
    if deny_insecure && setups.iter().any(|s| s.insecure_test_setup) {
        eprintln!("{path}: contains a verifying key from an insecure test setup");
        return ExitCode::from(2);
    }
    ExitCode::SUCCESS
}

fn usage() -> ExitCode {
    eprintln!("usage: vk_setup [--deny-insecure] <program.so>");
    ExitCode::FAILURE
}
