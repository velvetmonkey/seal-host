// SPDX-License-Identifier: Apache-2.0

use ed25519_dalek::SigningKey;
use seal_host_rs::reachability::{
    build_report, render_report, sign_report, verify_envelope, SignedEnvelope,
};
use seal_host_rs::{limits, secure_fs};
use std::path::Path;

fn usage() -> String {
    "usage:\n\
     seal-reachability-report issue --config <inventory.json> --signing-key-file <seed.hex> --out <report.json>\n\
     seal-reachability-report verify --report <report.json> --expected-pubkey <hex>\n\
     seal-reachability-report show --report <report.json> --expected-pubkey <hex>\n\
     seal-reachability-report public-key --signing-key-file <seed.hex>"
        .into()
}

fn value(args: &[String], flag: &str) -> Result<String, String> {
    let index = args
        .iter()
        .position(|arg| arg == flag)
        .ok_or_else(|| format!("{flag} required"))?;
    args.get(index + 1)
        .cloned()
        .ok_or_else(|| format!("{flag} requires a value"))
}

fn signing_key(path: &str) -> Result<SigningKey, String> {
    let key_path = Path::new(path);
    secure_fs::validate_private_file(key_path, "reachability signing key")?;
    let bytes = limits::read_file_bounded(key_path, 1024)
        .map_err(|e| format!("cannot read signing key file {path}: {e}"))?;
    let text =
        std::str::from_utf8(&bytes).map_err(|e| format!("signing key file is not UTF-8: {e}"))?;
    let bytes: [u8; 32] = hex::decode(text.trim())
        .map_err(|e| format!("bad signing key hex: {e}"))?
        .try_into()
        .map_err(|_| "signing key must be a 32-byte seed".to_string())?;
    Ok(SigningKey::from_bytes(&bytes))
}

fn envelope(path: &str) -> Result<SignedEnvelope, String> {
    let bytes =
        std::fs::read(path).map_err(|e| format!("cannot read signed report {path}: {e}"))?;
    serde_json::from_slice(&bytes).map_err(|e| format!("bad signed report envelope: {e}"))
}

fn now_ms() -> Result<u64, String> {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_millis() as u64)
        .map_err(|e| format!("system clock precedes Unix epoch: {e}"))
}

fn run() -> Result<(), String> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let command = args.first().ok_or_else(usage)?;
    match command.as_str() {
        "issue" => {
            let config = value(&args, "--config")?;
            let key_path = value(&args, "--signing-key-file")?;
            let out = value(&args, "--out")?;
            let inventory_bytes = std::fs::read(&config)
                .map_err(|e| format!("cannot read reachability inventory {config}: {e}"))?;
            let report = build_report(Path::new(&config), &inventory_bytes, now_ms()?)?;
            let signed = sign_report(&report, &signing_key(&key_path)?)?;
            let bytes = serde_json::to_string_pretty(&signed)
                .map_err(|e| format!("cannot serialize signed report: {e}"))?
                + "\n";
            std::fs::write(&out, bytes)
                .map_err(|e| format!("cannot write signed report {out}: {e}"))?;
            print!("{}", render_report(&report, &signed));
            println!("  artifact: {out}");
            Ok(())
        }
        "verify" | "show" => {
            let report_path = value(&args, "--report")?;
            let expected = value(&args, "--expected-pubkey")?;
            let signed = envelope(&report_path)?;
            let report = verify_envelope(&signed, Some(&expected))?;
            if command == "show" {
                print!("{}", render_report(&report, &signed));
            } else {
                println!("VERIFY OK: Ed25519 signature valid for exact payload bytes.");
                println!("kind: {}", signed.kind);
                println!("key_id: {}", signed.key_id);
                println!("payload_sha256: {}", signed.payload_sha256);
                println!("expected public key: MATCH");
            }
            Ok(())
        }
        "public-key" => {
            let key_path = value(&args, "--signing-key-file")?;
            println!(
                "{}",
                hex::encode(signing_key(&key_path)?.verifying_key().to_bytes())
            );
            Ok(())
        }
        _ => Err(usage()),
    }
}

fn main() {
    if let Err(error) = run() {
        eprintln!("seal-reachability-report: {error}");
        std::process::exit(2);
    }
}
