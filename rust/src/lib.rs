// SPDX-License-Identifier: Apache-2.0
//! Library surface of the seal-host Rust transport, exposed so the
//! conformance tests exercise the SAME routing code the binary runs
//! (no test-mirror differential). The binary entry point is `main.rs`.

pub mod a3;
pub mod adapter_revision;
pub mod authorization_decision;
pub mod crash_injection;
pub(crate) mod ed25519;
pub mod envelope_v23;
pub mod health;
pub mod lean;
pub mod limits;
pub mod output;
pub mod providers;
pub mod reachability;
pub mod receipt;
pub mod replay_store;
pub mod route;
pub mod secure_fs;
