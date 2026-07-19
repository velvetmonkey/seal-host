// SPDX-License-Identifier: Apache-2.0
//! Resource limits enforced before hostile bytes reach serde or Lean.

use std::io::{self, BufRead, Read};
use std::path::Path;

pub const MAX_WIRE_MESSAGE_BYTES: usize = 1024 * 1024;
pub const MAX_JSON_DEPTH: usize = 64;
pub const MAX_JSON_STRING_BYTES: usize = 256 * 1024;
pub const MAX_JSON_COLLECTION_ITEMS: usize = 4096;
pub const MAX_APPROVAL_LINE_BYTES: usize = 16 * 1024;
pub const MAX_TOKEN_FILE_BYTES: usize = 4 * 1024 * 1024;
pub const MAX_PENDING_APPROVALS: usize = 1024;
pub const MAX_AUXILIARY_FILE_BYTES: usize = 4 * 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FrameStatus {
    Eof,
    Complete,
    Oversized,
}

/// Read one newline-delimited frame without ever retaining more than `max`
/// bytes. An oversized frame is drained through its newline before returning,
/// so the next call starts on a fresh protocol boundary.
pub fn read_bounded_frame<R: BufRead>(
    reader: &mut R,
    out: &mut Vec<u8>,
    max: usize,
) -> io::Result<FrameStatus> {
    out.clear();
    let mut saw_any = false;
    let mut oversized = false;
    loop {
        let available = reader.fill_buf()?;
        if available.is_empty() {
            return Ok(if !saw_any {
                FrameStatus::Eof
            } else if oversized {
                FrameStatus::Oversized
            } else {
                FrameStatus::Complete
            });
        }
        saw_any = true;
        let take = available
            .iter()
            .position(|b| *b == b'\n')
            .map_or(available.len(), |position| position + 1);
        if !oversized {
            let room = max.saturating_sub(out.len());
            let retained = room.min(take);
            out.extend_from_slice(&available[..retained]);
            if retained < take {
                oversized = true;
            }
        }
        let terminated = available[take - 1] == b'\n';
        reader.consume(take);
        if terminated {
            return Ok(if oversized {
                FrameStatus::Oversized
            } else {
                FrameStatus::Complete
            });
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JsonLimit {
    Depth,
    StringBytes,
    CollectionItems,
}

impl JsonLimit {
    pub fn name(self) -> &'static str {
        match self {
            Self::Depth => "json_depth",
            Self::StringBytes => "json_string_bytes",
            Self::CollectionItems => "json_collection_items",
        }
    }

    pub fn maximum(self) -> usize {
        match self {
            Self::Depth => MAX_JSON_DEPTH,
            Self::StringBytes => MAX_JSON_STRING_BYTES,
            Self::CollectionItems => MAX_JSON_COLLECTION_ITEMS,
        }
    }
}

/// A conservative lexical JSON limit pass. It does not decide JSON validity;
/// the existing parser remains authoritative. It only rejects inputs whose
/// nesting, quoted-token extent, or per-container comma count exceeds a cap.
pub fn check_json_limits(bytes: &[u8]) -> Result<(), JsonLimit> {
    let mut stack: Vec<usize> = Vec::with_capacity(MAX_JSON_DEPTH);
    let mut in_string = false;
    let mut escaped = false;
    let mut string_bytes = 0usize;
    for &byte in bytes {
        if in_string {
            if escaped {
                escaped = false;
                string_bytes = string_bytes.saturating_add(1);
            } else {
                match byte {
                    b'\\' => {
                        escaped = true;
                        string_bytes = string_bytes.saturating_add(1);
                    }
                    b'"' => {
                        in_string = false;
                    }
                    _ => string_bytes = string_bytes.saturating_add(1),
                }
            }
            if string_bytes > MAX_JSON_STRING_BYTES {
                return Err(JsonLimit::StringBytes);
            }
            continue;
        }
        match byte {
            b'"' => {
                in_string = true;
                escaped = false;
                string_bytes = 0;
            }
            b'{' | b'[' => {
                if stack.len() >= MAX_JSON_DEPTH {
                    return Err(JsonLimit::Depth);
                }
                stack.push(1);
            }
            b',' => {
                if let Some(items) = stack.last_mut() {
                    *items = items.saturating_add(1);
                    if *items > MAX_JSON_COLLECTION_ITEMS {
                        return Err(JsonLimit::CollectionItems);
                    }
                }
            }
            b'}' | b']' => {
                stack.pop();
            }
            _ => {}
        }
    }
    Ok(())
}

pub fn read_file_bounded(path: &Path, max: usize) -> io::Result<Vec<u8>> {
    let file = std::fs::File::open(path)?;
    let mut bytes = Vec::with_capacity(max.min(64 * 1024));
    file.take((max as u64).saturating_add(1))
        .read_to_end(&mut bytes)?;
    if bytes.len() > max {
        return Err(io::Error::new(
            io::ErrorKind::FileTooLarge,
            format!("file exceeds {max} bytes"),
        ));
    }
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn oversized_frame_is_bounded_and_drained() {
        let input = format!("{}\nok\n", "x".repeat(10));
        let mut reader = Cursor::new(input.into_bytes());
        let mut frame = Vec::new();
        assert_eq!(
            read_bounded_frame(&mut reader, &mut frame, 4).unwrap(),
            FrameStatus::Oversized
        );
        assert_eq!(frame, b"xxxx");
        assert_eq!(
            read_bounded_frame(&mut reader, &mut frame, 4).unwrap(),
            FrameStatus::Complete
        );
        assert_eq!(frame, b"ok\n");
    }

    #[test]
    fn json_caps_are_named() {
        let deep = format!(
            "{}0{}",
            "[".repeat(MAX_JSON_DEPTH + 1),
            "]".repeat(MAX_JSON_DEPTH + 1)
        );
        assert_eq!(check_json_limits(deep.as_bytes()), Err(JsonLimit::Depth));
        let long = format!("\"{}\"", "a".repeat(MAX_JSON_STRING_BYTES + 1));
        assert_eq!(
            check_json_limits(long.as_bytes()),
            Err(JsonLimit::StringBytes)
        );
        let wide = format!("[{}]", vec!["0"; MAX_JSON_COLLECTION_ITEMS + 1].join(","));
        assert_eq!(
            check_json_limits(wide.as_bytes()),
            Err(JsonLimit::CollectionItems)
        );
    }
}
