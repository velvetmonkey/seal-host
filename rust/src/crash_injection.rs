// SPDX-License-Identifier: Apache-2.0
//! Test-only process crash injection.
//!
//! Production never sets [`CRASH_POINT_ENV`]. An armed point aborts the real
//! host process: there is no unwind and no in-process recovery substitute.

/// Names the single crash point armed for one test process.
pub const CRASH_POINT_ENV: &str = "SEAL_TEST_CRASH_POINT";

/// Abort the process when `point` is the exactly-armed crash point.
///
/// The marker is flushed through stderr before `abort`, so a harness can
/// distinguish reaching the intended point from any unrelated process exit.
pub fn abort_if_armed(point: &str) {
    if std::env::var_os(CRASH_POINT_ENV).as_deref() == Some(std::ffi::OsStr::new(point)) {
        eprintln!("{}", serde_json::json!({"seal_test_crash_point": point}));
        std::process::abort();
    }
}
