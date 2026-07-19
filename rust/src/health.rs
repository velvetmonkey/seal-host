// SPDX-License-Identifier: Apache-2.0
//! Minimal authenticated health/readiness HTTP surface.

use crate::limits::read_file_bounded;
use crate::secure_fs;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

const MAX_HEALTH_REQUEST_BYTES: usize = 8 * 1024;
const MAX_HEALTH_TOKEN_BYTES: usize = 1024;

pub struct HealthServer {
    stop: Arc<AtomicBool>,
    join: Option<std::thread::JoinHandle<()>>,
    addr: SocketAddr,
}

impl HealthServer {
    pub fn start(listen: &str, token_file: &Path, ready: Arc<AtomicBool>) -> Result<Self, String> {
        secure_fs::validate_private_file(token_file, "health auth token")?;
        let token_bytes = read_file_bounded(token_file, MAX_HEALTH_TOKEN_BYTES)
            .map_err(|e| format!("cannot read health auth token: {e}"))?;
        let token_text = std::str::from_utf8(&token_bytes)
            .map_err(|_| "health auth token must be UTF-8".to_string())?;
        let token = token_text.trim_end_matches(['\r', '\n']);
        if token.len() < 32 || token.contains(['\r', '\n']) {
            return Err("health auth token must be one line of at least 32 bytes".into());
        }
        let listener = TcpListener::bind(listen)
            .map_err(|e| format!("cannot bind authenticated health listener {listen}: {e}"))?;
        let addr = listener
            .local_addr()
            .map_err(|e| format!("cannot inspect health listener: {e}"))?;
        listener
            .set_nonblocking(true)
            .map_err(|e| format!("cannot configure health listener: {e}"))?;
        let expected = format!("Bearer {token}").into_bytes();
        let stop = Arc::new(AtomicBool::new(false));
        let thread_stop = stop.clone();
        let join = std::thread::spawn(move || {
            while !thread_stop.load(Ordering::Acquire) {
                match listener.accept() {
                    Ok((mut stream, _peer)) => {
                        let _ = stream.set_read_timeout(Some(Duration::from_secs(2)));
                        let _ = stream.set_write_timeout(Some(Duration::from_secs(2)));
                        serve_one(&mut stream, &expected, ready.load(Ordering::Acquire));
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        std::thread::sleep(Duration::from_millis(25));
                    }
                    Err(error) => {
                        eprintln!("health listener stopped: {error}");
                        break;
                    }
                }
            }
        });
        Ok(Self {
            stop,
            join: Some(join),
            addr,
        })
    }

    pub fn local_addr(&self) -> SocketAddr {
        self.addr
    }
}

impl Drop for HealthServer {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        if let Some(join) = self.join.take() {
            let _ = join.join();
        }
    }
}

fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    let mut difference = left.len() ^ right.len();
    let maximum = left.len().max(right.len());
    for index in 0..maximum {
        let a = left.get(index).copied().unwrap_or(0);
        let b = right.get(index).copied().unwrap_or(0);
        difference |= (a ^ b) as usize;
    }
    difference == 0
}

fn serve_one(stream: &mut TcpStream, expected_auth: &[u8], ready: bool) {
    let mut request = Vec::with_capacity(1024);
    let mut chunk = [0u8; 1024];
    loop {
        match stream.read(&mut chunk) {
            Ok(0) => break,
            Ok(count) => {
                if request.len().saturating_add(count) > MAX_HEALTH_REQUEST_BYTES {
                    write_response(stream, 413, "Payload Too Large", "refused\n");
                    return;
                }
                request.extend_from_slice(&chunk[..count]);
                if request.windows(4).any(|window| window == b"\r\n\r\n") {
                    break;
                }
            }
            Err(_) => return,
        }
    }
    let Ok(text) = std::str::from_utf8(&request) else {
        write_response(stream, 400, "Bad Request", "refused\n");
        return;
    };
    let mut lines = text.split("\r\n");
    let request_line = lines.next().unwrap_or("");
    let auth = lines.find_map(|line| {
        let (name, value) = line.split_once(':')?;
        name.eq_ignore_ascii_case("authorization")
            .then(|| value.trim().as_bytes())
    });
    if !auth
        .map(|provided| constant_time_eq(provided, expected_auth))
        .unwrap_or(false)
    {
        write_response(stream, 401, "Unauthorized", "unauthorized\n");
        return;
    }
    match request_line {
        "GET /healthz HTTP/1.1" | "GET /healthz HTTP/1.0" => {
            write_response(stream, 200, "OK", "ok\n")
        }
        "GET /readyz HTTP/1.1" | "GET /readyz HTTP/1.0" if ready => {
            write_response(stream, 200, "OK", "ready\n")
        }
        "GET /readyz HTTP/1.1" | "GET /readyz HTTP/1.0" => {
            write_response(stream, 503, "Service Unavailable", "not ready\n")
        }
        _ => write_response(stream, 404, "Not Found", "not found\n"),
    }
}

fn write_response(stream: &mut TcpStream, code: u16, reason: &str, body: &str) {
    let response = format!(
        "HTTP/1.1 {code} {reason}\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    let _ = stream.write_all(response.as_bytes());
    let _ = stream.flush();
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    fn request(addr: SocketAddr, token: &str, path: &str) -> String {
        let mut stream = TcpStream::connect(addr).unwrap();
        write!(
            stream,
            "GET {path} HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer {token}\r\n\r\n"
        )
        .unwrap();
        let mut response = String::new();
        stream.read_to_string(&mut response).unwrap();
        response
    }

    #[test]
    fn auth_and_readiness_are_enforced() {
        let dir = std::env::temp_dir().join(format!("seal-health-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        secure_fs::ensure_private_dir(&dir, "health test dir").unwrap();
        let token_path = dir.join("token");
        std::fs::write(&token_path, b"0123456789abcdef0123456789abcdef\n").unwrap();
        std::fs::set_permissions(&token_path, std::fs::Permissions::from_mode(0o600)).unwrap();
        let ready = Arc::new(AtomicBool::new(false));
        let server = HealthServer::start("127.0.0.1:0", &token_path, ready.clone()).unwrap();
        assert!(request(server.local_addr(), "wrong", "/healthz").starts_with("HTTP/1.1 401"));
        assert!(request(
            server.local_addr(),
            "0123456789abcdef0123456789abcdef",
            "/healthz"
        )
        .starts_with("HTTP/1.1 200"));
        assert!(request(
            server.local_addr(),
            "0123456789abcdef0123456789abcdef",
            "/readyz"
        )
        .starts_with("HTTP/1.1 503"));
        ready.store(true, Ordering::Release);
        assert!(request(
            server.local_addr(),
            "0123456789abcdef0123456789abcdef",
            "/readyz"
        )
        .starts_with("HTTP/1.1 200"));
        drop(server);
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
