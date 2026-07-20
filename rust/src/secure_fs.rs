// SPDX-License-Identifier: Apache-2.0
//! Unix ownership and mode checks for security-sensitive host state.

use std::fs::{File, OpenOptions};
use std::io::Write;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::Path;

fn current_uid() -> u32 {
    // SAFETY: geteuid has no preconditions and does not dereference pointers.
    unsafe { libc::geteuid() }
}

fn metadata_without_symlinks(path: &Path, label: &str) -> Result<std::fs::Metadata, String> {
    let metadata = std::fs::symlink_metadata(path)
        .map_err(|e| format!("cannot inspect {label} {}: {e}", path.display()))?;
    if metadata.file_type().is_symlink() {
        return Err(format!("{label} {} must not be a symlink", path.display()));
    }
    if metadata.uid() != current_uid() {
        return Err(format!(
            "{label} {} is owned by uid {}, expected uid {}",
            path.display(),
            metadata.uid(),
            current_uid()
        ));
    }
    Ok(metadata)
}

pub fn validate_private_dir(path: &Path, label: &str) -> Result<(), String> {
    let metadata = metadata_without_symlinks(path, label)?;
    if !metadata.is_dir() {
        return Err(format!("{label} {} is not a directory", path.display()));
    }
    let mode = metadata.mode() & 0o777;
    if mode != 0o700 {
        return Err(format!(
            "{label} {} has mode {mode:04o}, required 0700",
            path.display()
        ));
    }
    Ok(())
}

pub fn ensure_private_dir(path: &Path, label: &str) -> Result<(), String> {
    if !path.exists() {
        std::fs::create_dir_all(path)
            .map_err(|e| format!("cannot create {label} {}: {e}", path.display()))?;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))
            .map_err(|e| format!("cannot set {label} {} to 0700: {e}", path.display()))?;
    }
    validate_private_dir(path, label)
}

pub fn validate_private_file(path: &Path, label: &str) -> Result<(), String> {
    let metadata = metadata_without_symlinks(path, label)?;
    if !metadata.is_file() {
        return Err(format!("{label} {} is not a regular file", path.display()));
    }
    let mode = metadata.mode() & 0o777;
    if mode != 0o600 {
        return Err(format!(
            "{label} {} has mode {mode:04o}, required 0600",
            path.display()
        ));
    }
    Ok(())
}

pub fn open_private_new(path: &Path, label: &str) -> Result<File, String> {
    let file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .map_err(|e| format!("cannot create {label} {}: {e}", path.display()))?;
    validate_private_file(path, label)?;
    Ok(file)
}

pub fn ensure_private_file(path: &Path, label: &str) -> Result<(), String> {
    if path.exists() {
        return validate_private_file(path, label);
    }
    let mut file = open_private_new(path, label)?;
    file.flush()
        .and_then(|_| file.sync_all())
        .map_err(|e| format!("cannot sync {label} {}: {e}", path.display()))?;
    Ok(())
}

pub fn validate_private_parent(path: &Path, label: &str) -> Result<(), String> {
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    validate_private_dir(parent, label)
}

pub fn sync_dir(path: &Path, label: &str) -> Result<(), String> {
    File::open(path)
        .and_then(|dir| dir.sync_all())
        .map_err(|e| format!("cannot fsync {label} {}: {e}", path.display()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_path(tag: &str) -> std::path::PathBuf {
        std::env::temp_dir().join(format!(
            "seal-secure-fs-{tag}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ))
    }

    #[test]
    fn creates_exact_private_modes_and_rejects_unsafe_changes() {
        let dir = temp_path("modes");
        ensure_private_dir(&dir, "test dir").unwrap();
        let file = dir.join("state");
        ensure_private_file(&file, "test file").unwrap();
        assert_eq!(std::fs::metadata(&dir).unwrap().mode() & 0o777, 0o700);
        assert_eq!(std::fs::metadata(&file).unwrap().mode() & 0o777, 0o600);

        std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(validate_private_file(&file, "test file")
            .unwrap_err()
            .contains("required 0600"));
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
