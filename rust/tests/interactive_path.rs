// SPDX-License-Identifier: Apache-2.0
//! Full-host-path tests for the INTERACTIVE approval channel — the first
//! coverage of the retry loop (main.rs interactive arm).
//!
//! The interactive provider reads the human's answer from `/dev/tty`, so the
//! host is spawned in a new session with a pseudo-terminal as its controlling
//! terminal while stdin/stdout stay pipes (the JSON-RPC transport). The test
//! plays the human by writing to the pty master.
//!
//! The blue test deliberately answers AFTER MAX_FUTURE_SKEW_MS (5 s): the
//! approval's issued_at is stamped at answer time, so filtering it with the
//! clock captured at line arrival dropped it as `future_issued_at` and the
//! call stayed blocked — the defect fixed alongside this test. A fast answer
//! cannot catch that regression; the slow one is the point.

use ed25519_dalek::{Signer, SigningKey};
use std::ffi::CString;
use std::io::{BufRead, BufReader, Write};
use std::os::unix::io::FromRawFd;
use std::os::unix::process::CommandExt;
use std::path::PathBuf;
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::mpsc::{channel, Receiver};
use std::time::Duration;

struct InteractiveHost {
    child: Child,
    stdin: ChildStdin,
    lines: Receiver<String>,
    stderr_lines: Receiver<String>,
    tty: std::fs::File,
    dir: PathBuf,
}

impl InteractiveHost {
    fn spawn(tag: &str) -> InteractiveHost {
        let dir = std::env::temp_dir().join(format!(
            "seal-host-interactive-{}-{}",
            std::process::id(),
            tag
        ));
        std::fs::create_dir_all(&dir).unwrap();

        // Same self-signed trusted config shape as the host_path oracle.
        let config_sk = SigningKey::from_bytes(&[7u8; 32]);
        let pk = hex::encode(config_sk.verifying_key().to_bytes());
        let payload = serde_json::json!({
            "epoch": 1,
            "safety": {
                "approval": {
                    "control_file": dir.join("approvals.ndjson").to_str().unwrap(),
                    "ttl_seconds": 120
                },
                "tools": [
                    {
                        "name": "db.execute",
                        "mode": "guarded",
                        "match": {"type": "contains_any_ci", "arg": "sql",
                                  "needles": ["drop", "delete", "truncate"]},
                        "target": [{"full_arguments": true}]
                    }
                ]
            }
        })
        .to_string();
        let sig = hex::encode(config_sk.sign(payload.as_bytes()).to_bytes());
        let envelope = serde_json::json!({"payload": payload, "signature": sig}).to_string();
        let config = dir.join("trusted.json");
        std::fs::write(&config, envelope).unwrap();

        // Pseudo-terminal: the master stays with the test (the "human"); the
        // host gets the slave as its CONTROLLING terminal, so its own open of
        // /dev/tty resolves to it. stdin/stdout remain pipes.
        let (master, slave_path) = unsafe {
            let master = libc::posix_openpt(libc::O_RDWR | libc::O_NOCTTY);
            assert!(master >= 0, "posix_openpt failed");
            assert_eq!(libc::grantpt(master), 0, "grantpt failed");
            assert_eq!(libc::unlockpt(master), 0, "unlockpt failed");
            let mut buf = [0u8; 128];
            assert_eq!(
                libc::ptsname_r(master, buf.as_mut_ptr().cast(), buf.len()),
                0,
                "ptsname_r failed"
            );
            let len = buf.iter().position(|&b| b == 0).unwrap();
            let path = CString::new(&buf[..len]).unwrap();
            (master, path)
        };

        let mut cmd = Command::new(env!("CARGO_BIN_EXE_seal-host-rs"));
        cmd.args([
            "--insecure-development-mode",
            "--config",
            config.to_str().unwrap(),
            "--pubkey",
            &pk,
            "--channel",
            "interactive",
            "--",
            "/bin/cat",
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
        unsafe {
            let slave_path = slave_path.clone();
            cmd.pre_exec(move || {
                // New session, then acquire the pty slave as controlling tty.
                if libc::setsid() < 0 {
                    return Err(std::io::Error::last_os_error());
                }
                let fd = libc::open(slave_path.as_ptr(), libc::O_RDWR);
                if fd < 0 {
                    return Err(std::io::Error::last_os_error());
                }
                if libc::ioctl(fd, libc::TIOCSCTTY, 0) < 0 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
        let mut child = cmd.spawn().expect("spawn seal-host-rs under pty");
        let stdin = child.stdin.take().unwrap();
        let stdout = child.stdout.take().unwrap();
        let stderr = child.stderr.take().unwrap();

        let (err_tx, stderr_lines) = channel::<String>();
        std::thread::spawn(move || {
            for line in BufReader::new(stderr).lines() {
                let Ok(line) = line else { break };
                if err_tx.send(line).is_err() {
                    break;
                }
            }
        });
        let (tx, lines) = channel::<String>();
        std::thread::spawn(move || {
            for line in BufReader::new(stdout).lines() {
                let Ok(line) = line else { break };
                if tx.send(line).is_err() {
                    break;
                }
            }
        });

        let tty = unsafe { std::fs::File::from_raw_fd(master) };
        InteractiveHost {
            child,
            stdin,
            lines,
            stderr_lines,
            tty,
            dir,
        }
    }

    fn send(&mut self, line: &str) {
        self.stdin
            .write_all(format!("{line}\n").as_bytes())
            .unwrap();
        self.stdin.flush().unwrap();
    }

    fn answer(&mut self, text: &str) {
        self.tty.write_all(text.as_bytes()).unwrap();
        self.tty.flush().unwrap();
    }

    fn expect_line(&mut self) -> String {
        match self.lines.recv_timeout(Duration::from_secs(30)) {
            Ok(line) => line,
            Err(e) => {
                let status = self.child.try_wait().ok().flatten();
                let stderr = self.drain_stderr(Duration::from_millis(50));
                panic!(
                    "host produced no output line in time: {e}; status={status:?}; stderr={stderr:?}"
                );
            }
        }
    }

    /// Block until the interactive prompt for an approval question shows up
    /// on the host's stderr (where the provider writes it).
    fn expect_prompt(&mut self) -> String {
        let deadline = std::time::Instant::now() + Duration::from_secs(20);
        let mut seen = Vec::new();
        while std::time::Instant::now() < deadline {
            if let Ok(line) = self.stderr_lines.recv_timeout(Duration::from_millis(200)) {
                if line.contains("approve target") {
                    return line;
                }
                seen.push(line);
            }
        }
        panic!("interactive prompt never appeared on stderr; saw: {seen:?}");
    }

    fn drain_stderr(&mut self, quiet_for: Duration) -> Vec<String> {
        let mut lines = Vec::new();
        while let Ok(line) = self.stderr_lines.recv_timeout(quiet_for) {
            lines.push(line);
        }
        lines
    }
}

impl Drop for InteractiveHost {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

fn guarded_call(id: u64, sql: &str) -> String {
    format!(
        r#"{{"jsonrpc":"2.0","id":{id},"method":"tools/call","params":{{"name":"db.execute","arguments":{{"database":"prod","sql":{}}}}}}}"#,
        serde_json::to_string(sql).unwrap()
    )
}

/// BLUE: a human "y" forwards the call even when the answer takes LONGER
/// than MAX_FUTURE_SKEW_MS (5 s). The delay is the test — the approval is
/// stamped at answer time, and a stale line-arrival clock in the retry
/// filter dropped it as future_issued_at, leaving the call blocked.
#[test]
fn interactive_yes_after_slow_human_answer_forwards() {
    let mut h = InteractiveHost::spawn("slow-yes");

    let call = guarded_call(1, "drop table accounts");
    h.send(&call);
    let prompt = h.expect_prompt();
    assert!(
        prompt.contains("[y/N]"),
        "prompt must ask the y/N question: {prompt}"
    );

    // The realistic human: reads the prompt, thinks, answers after >5 s.
    std::thread::sleep(Duration::from_millis(6_500));
    h.answer("y\n");

    let echoed = h.expect_line();
    assert_eq!(
        echoed, call,
        "a slow 'y' must still mint the approval and forward the call"
    );
    let stderr = h.drain_stderr(Duration::from_millis(200));
    assert!(
        !stderr.iter().any(|l| l.contains("future_issued_at")),
        "the human's think time must not be misread as clock skew: {stderr:?}"
    );
}

/// RED: a human "n" leaves the call blocked — no approval is minted, the
/// kernel's approval-required block is what the client sees, and the
/// session stays alive and mediating.
#[test]
fn interactive_no_keeps_call_blocked() {
    let mut h = InteractiveHost::spawn("no");

    let call = guarded_call(2, "drop table accounts");
    h.send(&call);
    h.expect_prompt();
    h.answer("n\n");

    let resp = h.expect_line();
    assert!(
        resp.contains("\"isError\":true") && resp.contains("approval required: "),
        "'n' must leave the call blocked: {resp}"
    );

    // Session survives: passthrough still works after the refusal.
    let init = r#"{"jsonrpc":"2.0","id":3,"method":"initialize"}"#;
    h.send(init);
    assert_eq!(h.expect_line(), init, "session must survive a blocked call");
}
