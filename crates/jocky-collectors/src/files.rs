use cap_std::{ambient_authority, fs::Dir};
use serde_json::{json, Value};
use std::{
    io::Read,
    path::{Path, PathBuf},
    time::{Duration, Instant},
};

pub fn collect(args: &Value, approved_root: &Path) -> Result<(Vec<Value>, Vec<String>), String> {
    // Keep an open handle to the approved directory. Every subsequent open is
    // relative to that handle, so a path swap cannot redirect a read outside it.
    let approved =
        Dir::open_ambient_dir(approved_root, ambient_authority()).map_err(|e| e.to_string())?;
    let root_arg = Path::new(args["root"].as_str().unwrap_or("."));
    let root = approved
        .open_dir(root_arg)
        .map_err(|_| "Path is outside approved root or cannot be opened".to_string())?;
    let mut dirs = vec![(root, PathBuf::from(root_arg))];
    let limit = args["max_files"].as_u64().unwrap_or(100).min(1000) as usize;
    let mut rows = Vec::new();
    let mut warnings = Vec::new();
    let mut bytes = 0_u64;
    let start = Instant::now();

    while let Some((dir, relative)) = dirs.pop() {
        if start.elapsed() > Duration::from_secs(10) {
            warnings.push("Traversal timeout".into());
            break;
        }
        let entries = match dir.entries() {
            Ok(entries) => entries,
            Err(e) => {
                warnings.push(e.to_string());
                continue;
            }
        };
        for entry in entries {
            if rows.len() >= limit {
                warnings.push("File limit reached".into());
                break;
            }
            let entry = match entry {
                Ok(entry) => entry,
                Err(e) => {
                    warnings.push(e.to_string());
                    continue;
                }
            };
            let name = entry.file_name();
            let kind = match entry.file_type() {
                Ok(kind) => kind,
                Err(e) => {
                    warnings.push(e.to_string());
                    continue;
                }
            };
            if kind.is_symlink() {
                warnings.push("Skipped symbolic link".into());
                continue;
            }
            let path = relative.join(&name);
            if kind.is_dir() {
                if dirs.len() < 1000 {
                    match entry.open_dir() {
                        Ok(child) => dirs.push((child, path)),
                        Err(e) => warnings.push(e.to_string()),
                    }
                }
                continue;
            }
            if !kind.is_file() {
                continue;
            }
            let mut file = match entry.open() {
                Ok(file) => file,
                Err(e) => {
                    warnings.push(e.to_string());
                    continue;
                }
            };
            let before = match file.metadata() {
                Ok(md) if md.is_file() => md,
                Ok(_) => continue,
                Err(e) => {
                    warnings.push(e.to_string());
                    continue;
                }
            };
            let remaining = 10_485_760_u64.saturating_sub(bytes).min(1_048_576);
            if before.len() > remaining {
                warnings.push("Byte limit: file skipped".into());
                continue;
            }
            let mut data = Vec::new();
            if let Err(e) = file.by_ref().take(remaining + 1).read_to_end(&mut data) {
                warnings.push(e.to_string());
                continue;
            }
            if data.len() as u64 > remaining {
                warnings.push("Byte limit: file skipped".into());
                continue;
            }
            bytes += data.len() as u64;
            let changed = file
                .metadata()
                .map(|md| md.len() != before.len() || md.modified().ok() != before.modified().ok())
                .unwrap_or(true);
            rows.push(json!({"path": approved_root.join(&path).to_string_lossy(),
                "size": data.len(), "sha256": jocky_ir::hash(&data),
                "content_hex": hex::encode(&data), "changed_during_read": changed,
                "summary": name.to_string_lossy()}));
        }
        if rows.len() >= limit {
            break;
        }
    }
    Ok((rows, warnings))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn reads_regular_files_and_rejects_parent_paths() {
        let base = std::env::temp_dir().join(format!("jocky-files-{}", std::process::id()));
        let root = base.join("approved");
        fs::create_dir_all(root.join("nested")).unwrap();
        fs::write(root.join("nested/marker.txt"), b"approved").unwrap();
        let (rows, _) = collect(&json!({"root":"nested"}), &root).unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0]["content_hex"], hex::encode("approved"));
        assert!(collect(&json!({"root":".."}), &root).is_err());
        fs::remove_dir_all(base).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn skips_symlinks_to_files_outside_the_approved_root() {
        use std::os::unix::fs::symlink;
        let base = std::env::temp_dir().join(format!("jocky-link-{}", std::process::id()));
        let root = base.join("approved");
        fs::create_dir_all(&root).unwrap();
        fs::write(base.join("secret.txt"), b"outside").unwrap();
        symlink(base.join("secret.txt"), root.join("link.txt")).unwrap();
        let (rows, _) = collect(&json!({}), &root).unwrap();
        assert!(rows.is_empty());
        fs::remove_dir_all(base).unwrap();
    }
}
