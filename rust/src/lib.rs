// SPDX-License-Identifier: Apache-2.0
//! Library surface of the seal-host Rust transport, exposed so the
//! conformance tests exercise the SAME routing code the binary runs
//! (no test-mirror differential). The binary entry point is `main.rs`.

pub mod a3;
pub mod lean;
pub mod providers;
pub mod receipt;
pub mod replay_store;
pub mod route;
