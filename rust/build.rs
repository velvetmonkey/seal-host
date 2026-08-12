// SPDX-License-Identifier: Apache-2.0
// Links the Lean verified core (libFfi.so, built by `lake build Ffi:shared`)
// and the Lean runtime (libleanshared.so from the active toolchain).
//
// Override with env vars:
//   SEAL_FFI_LIB_DIR   — directory containing libFfi.so
//   LEAN_LIB_DIR       — toolchain lib/lean directory

use std::path::PathBuf;
use std::process::Command;

fn main() {
    let manifest = PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap());
    let ffi_dir = std::env::var("SEAL_FFI_LIB_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| manifest.join("../.lake/build/lib"));

    let lean_dir = std::env::var("LEAN_LIB_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| {
            let out = Command::new("lean")
                .arg("--print-prefix")
                .output()
                .expect("lean --print-prefix (set LEAN_LIB_DIR to override)");
            PathBuf::from(String::from_utf8_lossy(&out.stdout).trim()).join("lib/lean")
        });

    for dir in [&ffi_dir, &lean_dir] {
        println!("cargo:rustc-link-search=native={}", dir.display());
    }
    if std::env::var_os("SEAL_REPRODUCIBLE_RELEASE").is_some() {
        println!("cargo:rustc-link-arg=-Wl,-rpath,$ORIGIN/../lib");
    } else {
        for dir in [&ffi_dir, &lean_dir] {
            println!("cargo:rustc-link-arg=-Wl,-rpath,{}", dir.display());
        }
    }
    // libleanshared.so bundles LLVM libunwind and exports _Unwind_* as global
    // text symbols. In DT_NEEDED order it precedes libgcc_s (which rustc adds
    // last), so it WINS the symbol tie and Rust's panic runtime ends up calling
    // Lean's unwinder. That unwinder fails phase-1 over Rust's frames
    // (_URC_FATAL_PHASE1_ERROR = "error 3") and the process ABORTS instead of
    // unwinding — so a single panicking test kills its whole binary without
    // naming itself, and with the default (fail-fast) scheduler cargo then
    // skips every test binary queued behind it (observed: 44 reported of 60).
    // Naming libgcc_s FIRST puts it ahead of libleanshared in DT_NEEDED so
    // libgcc's _Unwind_* win the tie and panics unwind and report normally.
    // Lean's own fail-closed panic policy (lean_set_exit_on_panic, see
    // tests/panic_probe.rs) is unaffected — it abort()s directly, not via
    // _Unwind_RaiseException.
    println!("cargo:rustc-link-lib=dylib=gcc_s");
    println!("cargo:rustc-link-lib=dylib=sealffi");
    println!("cargo:rustc-link-lib=dylib=leanshared");
    println!("cargo:rerun-if-env-changed=SEAL_FFI_LIB_DIR");
    println!("cargo:rerun-if-env-changed=LEAN_LIB_DIR");
    println!("cargo:rerun-if-env-changed=SEAL_REPRODUCIBLE_RELEASE");
}
