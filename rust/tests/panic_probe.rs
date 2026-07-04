// SPDX-License-Identifier: Apache-2.0
//! Empirical verification of the F1 fail-open fix.
//!
//! A compiled Lean `panic!` routes through `lean_panic_fn`, which — unless
//! told otherwise — prints and RETURNS THE TYPE'S DEFAULT VALUE. For
//! `seal_host_classify : UInt32` the default is 0 = passthrough, so an
//! unguarded panic would forward a hostile line unmediated.
//!
//! The host arms `lean_set_exit_on_panic` + `LEAN_ABORT_ON_PANIC` before the
//! runtime initialises. These probes drive the REAL binary's init path:
//!
//! * `--panic-probe` (production guard): the process must die inside the
//!   forced panic — it must NOT print `SURVIVED`.
//! * `--panic-probe-unguarded`: demonstrates the fail-open is real — the
//!   panic returns `lean_box(0)` (printed as `SURVIVED 1`, the boxed 0 that
//!   classify would map to passthrough).
//!
//! If the guarded probe ever starts SURVIVING (a toolchain changes panic
//! semantics), this test fails and the structural plan B applies: drop the
//! classify fast-path and route every line through the String-returning
//! `step`, whose panic default `""` already fails closed.

use std::process::Command;

fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_seal-host-rs")
}

#[test]
fn guarded_lean_panic_kills_the_process() {
    let out = Command::new(bin())
        .arg("--panic-probe")
        .output()
        .expect("spawn probe");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        !stdout.contains("SURVIVED"),
        "FAIL-OPEN: guarded Lean panic returned a routable default instead of \
         killing the process (stdout: {stdout:?}). Apply plan B: remove the \
         classify fast-path, route all lines through step."
    );
    assert!(
        !out.status.success(),
        "guarded panic probe exited 0 — panic did not terminate abnormally"
    );
    // 42 is the probe's own "survived" exit code; dying inside the panic
    // must produce anything but success or 42.
    assert_ne!(
        out.status.code(),
        Some(42),
        "probe reached its SURVIVED path"
    );
}

#[test]
fn unguarded_lean_panic_returns_the_fail_open_default() {
    let out = Command::new(bin())
        .arg("--panic-probe-unguarded")
        .env_remove("LEAN_ABORT_ON_PANIC")
        .output()
        .expect("spawn probe");
    let stdout = String::from_utf8_lossy(&out.stdout);
    // lean_box(0) == 1usize: the boxed scalar 0 — exactly the UInt32 default
    // classify would return, i.e. passthrough. This is the bug class the
    // guard closes; if THIS assertion fails the toolchain now aborts by
    // default and the guard is redundant (fine — keep it anyway).
    assert!(
        stdout.contains("SURVIVED 1"),
        "expected the unguarded panic to return the boxed default (stdout: {stdout:?})"
    );
}
