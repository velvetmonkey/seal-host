// SPDX-License-Identifier: Apache-2.0

use std::process::Command;

fn host(args: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_seal-host-rs"))
        .args(args)
        .output()
        .expect("run seal-host-rs")
}

#[test]
fn help_is_a_successful_standalone_discovery_path() {
    for flag in ["--help", "-h"] {
        let output = host(&[flag]);
        assert_eq!(output.status.code(), Some(0), "{flag}");
        assert!(output.stderr.is_empty(), "{flag}: {:?}", output.stderr);
        let stdout = String::from_utf8(output.stdout).unwrap();
        assert!(
            stdout.starts_with("usage: seal-host-rs "),
            "{flag}: {stdout}"
        );
        assert!(
            stdout.contains("--initialize-replay-store"),
            "{flag}: {stdout}"
        );
        assert!(
            stdout.contains("-- <server-cmd> <args...>"),
            "{flag}: {stdout}"
        );
        assert!(
            stdout.contains("docs/GETTING-STARTED.md"),
            "{flag}: {stdout}"
        );
    }
}

#[test]
fn help_does_not_relax_malformed_or_incomplete_invocations() {
    let combined = host(&["--help", "extra"]);
    assert_eq!(combined.status.code(), Some(2));
    assert!(String::from_utf8(combined.stderr)
        .unwrap()
        .contains("error: unknown arg: --help"));

    let empty = host(&[]);
    assert_eq!(empty.status.code(), Some(2));
    assert!(String::from_utf8(empty.stderr)
        .unwrap()
        .contains("error: server command required after --"));
}
