//! Persistent workspace observations for native differential validation.
//!
//! Never follow output symlinks: dangling and external targets are data, not
//! authority to inspect another tree. This is final-state comparison, not a
//! syscall trace. Transient/external effects and the named exclusions are out
//! of scope. The caller must finish process cleanup before observing a tree.

use super::{MAX_ENTRIES, MAX_PATH_BYTES, MAX_PROJECT_BYTES, budget, open_regular, same_file_version};
use anyhow::{Context, Result, bail, ensure};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io::Read;
use std::os::unix::fs::MetadataExt;
use std::path::{Component, Path, PathBuf};
use std::time::Instant;

// Product receipts/state are not guest output and differ on native execution.
// Name this omission in every filesystem report; never call it full equivalence.
pub const EXCLUSIONS: &[&str] = &["**/.git", ".franken-node"];
const PREVIEW_LIMIT: usize = 20;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NodeKind { File, Directory, Symlink }

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NodeState {
    pub kind: NodeKind,
    pub mode: u32,
    pub length: u64,
    pub sha256: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ChangeKind { Created, Modified, Removed }

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Change {
    pub path: String,
    pub change: ChangeKind,
    pub after: Option<NodeState>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeltaSummary {
    pub sha256: String,
    pub changed_paths: usize,
    pub changes: Vec<Change>,
    pub details_truncated: bool,
}

pub type State = BTreeMap<String, NodeState>;

fn excluded(relative: &Path) -> bool {
    relative.components().any(|part| part.as_os_str() == ".git")
        || relative.components().next() == Some(Component::Normal(".franken-node".as_ref()))
}

/// Stream file hashes under a shared byte/deadline budget. Refuse unsupported
/// outputs instead of silently omitting them from a passing comparison.
pub fn observe(root: &Path, deadline: Instant) -> Result<State> {
    let mut state = State::new();
    let mut pending = vec![PathBuf::new()];
    let mut total_bytes = 0_usize;
    while let Some(relative) = pending.pop() {
        budget(deadline)?;
        if excluded(&relative) { continue; }
        ensure!(state.len() < MAX_ENTRIES, "workspace observation entry limit exceeded");
        let text = if relative.as_os_str().is_empty() { "." } else {
            relative.to_str().context("non-UTF-8 workspace output path refused")?
        };
        ensure!(text.len() <= MAX_PATH_BYTES, "workspace output path too long");
        let path = root.join(&relative);
        let metadata = fs::symlink_metadata(&path)?;
        let (kind, length, sha256) = if metadata.is_symlink() {
            ensure!(!relative.as_os_str().is_empty(), "workspace root was replaced by a symlink");
            let target = fs::read_link(&path)?;
            let bytes = target.as_os_str().as_encoded_bytes();
            ensure!(bytes.len() <= MAX_PATH_BYTES, "workspace link target too long");
            (NodeKind::Symlink, bytes.len() as u64, Some(hex::encode(Sha256::digest(bytes))))
        } else if metadata.is_dir() {
            for child in fs::read_dir(&path)? {
                budget(deadline)?;
                let child = child?;
                let child_relative = relative.join(child.file_name());
                if excluded(&child_relative) { continue; }
                ensure!(state.len() + pending.len() + 1 < MAX_ENTRIES,
                    "workspace observation entry limit exceeded");
                pending.push(child_relative);
            }
            (NodeKind::Directory, 0, None)
        } else if metadata.is_file() {
            ensure!(!relative.as_os_str().is_empty(), "workspace root is no longer a directory");
            ensure!(metadata.nlink() == 1, "hard-linked workspace outputs are not supported");
            let mut file = open_regular(&path)?;
            let before = file.metadata()?;
            ensure!(same_file_version(&metadata, &before), "workspace output changed before observation");
            let remaining = MAX_PROJECT_BYTES - total_bytes;
            ensure!(before.len() <= remaining as u64, "workspace output byte limit exceeded");
            let mut size = 0_usize;
            let mut hash = Sha256::new();
            let mut chunk = [0_u8; 65536];
            loop {
                budget(deadline)?;
                let request = chunk.len().min(remaining.saturating_sub(size).saturating_add(1));
                let count = file.read(&mut chunk[..request])?;
                if count == 0 { break; }
                ensure!(size + count <= remaining, "workspace output byte limit exceeded");
                size += count;
                hash.update(&chunk[..count]);
            }
            ensure!(same_file_version(&before, &file.metadata()?), "workspace output changed during observation");
            total_bytes += size;
            (NodeKind::File, size as u64, Some(hex::encode(hash.finalize())))
        } else {
            bail!("nonregular workspace output refused: {text}");
        };
        ensure!(same_file_version(&metadata, &fs::symlink_metadata(&path)?),
            "workspace output changed during observation");
        state.insert(text.to_owned(), NodeState { kind, mode: metadata.mode() & 0o7777, length, sha256 });
    }
    Ok(state)
}

/// Changes are relative to each leg's own input. Different rewritten sources
/// are not effects unless execution changes them. Removed bytes are not part
/// of a final-state effect, whereas the resulting bytes of a write are.
pub fn delta(before: &State, after: &State) -> Vec<Change> {
    let paths: BTreeSet<_> = before.keys().chain(after.keys()).collect();
    paths.into_iter().filter(|path| before.get(*path) != after.get(*path)).map(|path| Change {
        path: path.clone(),
        change: if !before.contains_key(path) { ChangeKind::Created }
            else if !after.contains_key(path) { ChangeKind::Removed } else { ChangeKind::Modified },
        after: after.get(path).cloned(),
    }).collect()
}

pub fn summarize(changes: &[Change]) -> Result<DeltaSummary> {
    let mut hash = Sha256::new();
    hash.update(b"franken-node/native-workspace-delta/v1\0");
    for change in changes {
        // Frame one bounded entry at a time, not one giant JSON allocation.
        let bytes = serde_json::to_vec(change)?;
        hash.update((bytes.len() as u64).to_le_bytes());
        hash.update(bytes);
    }
    Ok(DeltaSummary { sha256: hex::encode(hash.finalize()), changed_paths: changes.len(),
        changes: changes.iter().take(PREVIEW_LIMIT).cloned().collect(),
        details_truncated: changes.len() > PREVIEW_LIMIT })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::{PermissionsExt, symlink};
    use std::time::Duration;

    fn deadline() -> Instant { Instant::now() + Duration::from_secs(10) }

    #[test]
    fn captures_writes_deletions_permissions_and_root_changes_without_file_bytes() {
        let root = tempfile::tempdir().unwrap();
        fs::write(root.path().join("removed"), "private bytes").unwrap();
        fs::write(root.path().join("changed"), "before").unwrap();
        let before = observe(root.path(), deadline()).unwrap();
        fs::remove_file(root.path().join("removed")).unwrap();
        fs::write(root.path().join("changed"), "after-secret").unwrap();
        fs::set_permissions(root.path(), fs::Permissions::from_mode(0o750)).unwrap();
        let changes = delta(&before, &observe(root.path(), deadline()).unwrap());
        assert_eq!(changes.len(), 3);
        assert_eq!(changes[0].path, ".");
        assert_eq!(changes[0].after.as_ref().unwrap().mode, 0o750);
        assert_eq!(changes[2].change, ChangeKind::Removed);
        assert!(changes[2].after.is_none());
        let json = serde_json::to_string(&summarize(&changes).unwrap()).unwrap();
        assert!(!json.contains("after-secret"));
        assert!(!json.contains("private bytes"));
    }

    #[test]
    fn dangling_and_external_symlinks_are_compared_without_following_them() {
        let root = tempfile::tempdir().unwrap();
        symlink("absent", root.path().join("dangling")).unwrap();
        symlink("/unreadable/outside", root.path().join("external")).unwrap();
        let state = observe(root.path(), deadline()).unwrap();
        assert_eq!(state["dangling"].kind, NodeKind::Symlink);
        assert_eq!(state["external"].sha256, Some(hex::encode(Sha256::digest(b"/unreadable/outside"))));
    }

    #[test]
    fn permission_only_and_type_changes_are_observed() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("artifact");
        fs::write(&path, "bytes").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        let before = observe(root.path(), deadline()).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        assert_eq!(delta(&before, &observe(root.path(), deadline()).unwrap()).len(), 1);
        fs::remove_file(&path).unwrap();
        fs::create_dir(&path).unwrap();
        let changes = delta(&before, &observe(root.path(), deadline()).unwrap());
        assert_eq!(changes[0].after.as_ref().unwrap().kind, NodeKind::Directory);
    }

    #[test]
    fn named_exclusions_do_not_hide_similarly_named_guest_files() {
        let root = tempfile::tempdir().unwrap();
        fs::create_dir(root.path().join(".franken-node")).unwrap();
        symlink("/outside", root.path().join(".franken-node/receipt")).unwrap();
        fs::create_dir_all(root.path().join("pkg/.git")).unwrap();
        fs::write(root.path().join(".franken-node-result"), "guest").unwrap();
        fs::create_dir(root.path().join("pkg/.franken-node")).unwrap();
        let state = observe(root.path(), deadline()).unwrap();
        assert!(!state.contains_key(".franken-node"));
        assert!(!state.contains_key("pkg/.git"));
        assert!(state.contains_key(".franken-node-result"));
        assert!(state.contains_key("pkg/.franken-node"));
    }

    #[test]
    fn incomplete_observations_cannot_be_summaries() {
        let root = tempfile::tempdir().unwrap();
        assert!(observe(root.path(), Instant::now()).is_err());
        let output = root.path().join("oversized");
        fs::File::create(&output).unwrap().set_len(MAX_PROJECT_BYTES as u64 + 1).unwrap();
        assert!(observe(root.path(), deadline()).unwrap_err().to_string().contains("byte limit"));
    }

    #[test]
    fn hardlink_outputs_fail_closed() {
        let root = tempfile::tempdir().unwrap();
        fs::write(root.path().join("a"), "data").unwrap();
        fs::hard_link(root.path().join("a"), root.path().join("b")).unwrap();
        assert!(observe(root.path(), deadline()).unwrap_err().to_string().contains("hard-linked"));
    }

    #[test]
    fn a_replaced_workspace_root_is_not_followed() {
        let root = tempfile::tempdir().unwrap();
        let alias = root.path().join("alias");
        symlink(root.path(), &alias).unwrap();
        assert!(observe(&alias, deadline()).unwrap_err().to_string().contains("root"));
    }

    #[test]
    fn full_delta_hash_covers_changes_beyond_preview() {
        let changes: Vec<_> = (0..25).map(|i| Change {
            path: format!("file-{i:02}"), change: ChangeKind::Removed, after: None,
        }).collect();
        let first = summarize(&changes).unwrap();
        let mut changed = changes;
        changed[24].path = "different-last-path".into();
        let second = summarize(&changed).unwrap();
        assert_eq!(first.changed_paths, 25);
        assert!(first.details_truncated);
        assert_eq!(first.changes, second.changes);
        assert_ne!(first.sha256, second.sha256);
    }
}
