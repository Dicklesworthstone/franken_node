//! Decide when the product must remove the engine's live module-file authority.
//!
//! This is a bounded metadata-only admission check, not a filesystem snapshot.
//! An uncertain walk requires frozen capture; it never grants source authority.
//! Actual source capture independently refuses the reserved operator namespace.

use super::operator_control_component;
use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

const MAX_SCAN_ENTRIES: usize = 65_536;
const MAX_SCAN_DEPTH: usize = 64;

/// Whether a project must execute through the captured module resolver.
///
/// Initialized projects take the direct reserved-name fast path. Other roots
/// are inspected for nested operator state and symlink aliases without reading
/// file contents. Escaping or unresolved links and exhausted inspection bounds
/// conservatively require isolation. Pre-existing hardlink aliases are not
/// identified here: ordinary package-manager hardlinks retain their semantics.
///
/// Callers must repeat admission in the worker; concurrent host mutations are
/// outside this observation's guarantees. This does not replace either frozen
/// source admission or the live HostIo operator-state guard.
pub fn project_requires_operator_state_isolation(project: &Path) -> Result<bool, String> {
    inspect_project(project, MAX_SCAN_ENTRIES, MAX_SCAN_DEPTH)
}

fn contains_operator_component(path: &Path) -> bool {
    path.components().any(|component| {
        component
            .as_os_str()
            .to_str()
            .is_some_and(operator_control_component)
    })
}

fn inspection_error(error: impl std::fmt::Display) -> String {
    format!("Cannot inspect the project module boundary: {error}")
}

fn inspect_project(project: &Path, max_entries: usize, max_depth: usize) -> Result<bool, String> {
    if contains_operator_component(project) {
        return Ok(true);
    }
    let root = fs::canonicalize(project).map_err(inspection_error)?;
    if contains_operator_component(&root) {
        return Ok(true);
    }
    if !fs::metadata(&root).map_err(inspection_error)?.is_dir() {
        return Err("The project module boundary must be a directory".to_owned());
    }

    // Do not enumerate dependencies when ordinary initialization already
    // establishes an operator boundary. The walk below also catches mixed-case
    // names on a case-sensitive filesystem.
    for name in [".franken-node", "franken_node.toml"] {
        match fs::symlink_metadata(root.join(name)) {
            Ok(_) => return Ok(true),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(inspection_error(error)),
        }
    }

    let mut pending = vec![(root.clone(), 0_usize)];
    let mut visited = BTreeSet::<PathBuf>::new();
    let mut examined = 0_usize;
    while let Some((directory, depth)) = pending.pop() {
        let directory = match fs::canonicalize(directory) {
            Ok(directory) => directory,
            // A disappearing or retargeted directory cannot establish that
            // live module loading is free of operator state.
            Err(_) => return Ok(true),
        };
        if contains_operator_component(&directory) || !directory.starts_with(&root) {
            return Ok(true);
        }
        if !visited.insert(directory.clone()) {
            continue;
        }
        if depth > max_depth {
            return Ok(true);
        }
        // Finish this directory's entries before descending, so a reserved
        // sibling wins without inspecting the descendants of another sibling.
        for entry in fs::read_dir(&directory).map_err(inspection_error)? {
            let entry = entry.map_err(inspection_error)?;
            if examined >= max_entries {
                return Ok(true);
            }
            examined += 1;
            if entry
                .file_name()
                .to_str()
                .is_some_and(operator_control_component)
            {
                return Ok(true);
            }
            let kind = entry.file_type().map_err(inspection_error)?;
            if kind.is_dir() {
                pending.push((entry.path(), depth + 1));
            } else if kind.is_symlink() {
                let path = entry.path();
                let target = match fs::read_link(&path) {
                    Ok(target) => target,
                    Err(_) => return Ok(true),
                };
                if contains_operator_component(&target) {
                    return Ok(true);
                }
                let target = match fs::canonicalize(&path) {
                    Ok(target) => target,
                    Err(_) => return Ok(true),
                };
                if contains_operator_component(&target) || !target.starts_with(&root) {
                    return Ok(true);
                }
                match fs::metadata(&target) {
                    Ok(metadata) if metadata.is_dir() => pending.push((target, depth + 1)),
                    Ok(_) => {}
                    Err(_) => return Ok(true),
                }
            }
        }
    }
    Ok(false)
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::os::unix::fs::symlink;

    fn put(root: &Path, relative: &str) {
        let path = root.join(relative);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, b"private marker").unwrap();
    }

    #[test]
    fn operator_state_isolation_detects_default_nested_and_casefolded_names() {
        for name in [
            ".franken-node/keys/receipt.key",
            "franken_node.toml",
            "nested/.franken-node/remotecap/token.json",
            "nested/.FRANKEN-NODE/keys/receipt.key",
            "nested/FRANKEN_NODE.TOML",
        ] {
            let root = tempfile::tempdir().unwrap();
            put(root.path(), name);
            assert!(
                project_requires_operator_state_isolation(root.path()).unwrap(),
                "{name}"
            );
        }
    }

    #[test]
    fn operator_state_isolation_detects_narrowed_roots_and_ancestor_aliases() {
        let root = tempfile::tempdir().unwrap();
        put(root.path(), ".franken-node/runtime/entry.js");
        symlink(".franken-node", root.path().join("alias")).unwrap();
        for directory in [".franken-node/runtime", "alias/runtime"] {
            assert!(
                project_requires_operator_state_isolation(&root.path().join(directory)).unwrap(),
                "{directory}"
            );
        }
    }

    #[test]
    fn operator_state_isolation_preserves_ordinary_names_links_and_cycles() {
        let root = tempfile::tempdir().unwrap();
        for name in [
            "app.js",
            ".franken-node-data/value.json",
            "nested/.franken-node.json",
            "franken_node.toml.json",
        ] {
            put(root.path(), name);
        }
        fs::hard_link(root.path().join("app.js"), root.path().join("hardlink.js")).unwrap();
        symlink(".franken-node-data", root.path().join("ordinary-alias")).unwrap();
        symlink(".", root.path().join("cycle")).unwrap();
        assert!(!project_requires_operator_state_isolation(root.path()).unwrap());
    }

    #[test]
    fn operator_state_isolation_treats_escaping_and_unresolved_links_as_uncertain() {
        let outside = tempfile::tempdir().unwrap();
        put(outside.path(), "ordinary.js");
        let root = tempfile::tempdir().unwrap();
        symlink(outside.path(), root.path().join("outside")).unwrap();
        assert!(project_requires_operator_state_isolation(root.path()).unwrap());

        let dangling = tempfile::tempdir().unwrap();
        symlink("absent", dangling.path().join("unresolved")).unwrap();
        assert!(project_requires_operator_state_isolation(dangling.path()).unwrap());
    }

    #[test]
    fn operator_state_isolation_is_bounded_and_initialization_uses_the_fast_path() {
        let ordinary = tempfile::tempdir().unwrap();
        put(ordinary.path(), "nested/app.js");
        assert!(inspect_project(ordinary.path(), 0, MAX_SCAN_DEPTH).unwrap());
        assert!(inspect_project(ordinary.path(), MAX_SCAN_ENTRIES, 0).unwrap());
        assert!(!inspect_project(ordinary.path(), 2, 1).unwrap());

        let initialized = tempfile::tempdir().unwrap();
        put(initialized.path(), ".franken-node/keys/receipt.key");
        assert!(inspect_project(initialized.path(), 0, 0).unwrap());
    }
}
