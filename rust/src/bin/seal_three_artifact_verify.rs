// SPDX-License-Identifier: Apache-2.0

use seal_host_rs::release::ReleaseStore;
use std::path::PathBuf;

fn run() -> Result<(), String> {
    let mut args = std::env::args_os().skip(1);
    let dir = PathBuf::from(
        args.next()
            .ok_or("usage: seal-three-artifact-verify RECEIPT_DIRECTORY RECEIPT_FILE")?,
    );
    let receipt = PathBuf::from(
        args.next()
            .ok_or("usage: seal-three-artifact-verify RECEIPT_DIRECTORY RECEIPT_FILE")?,
    );
    if args.next().is_some() {
        return Err("usage: seal-three-artifact-verify RECEIPT_DIRECTORY RECEIPT_FILE".into());
    }
    let store = ReleaseStore::open_existing(dir)?;
    store.read_verified(&receipt)?;
    println!("ACCEPTED {}", receipt.display());
    Ok(())
}

fn main() {
    if let Err(error) = run() {
        eprintln!("REFUSED: {error}");
        std::process::exit(1);
    }
}
