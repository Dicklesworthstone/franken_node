//! Shared product executable discovery for embedded and standalone workflows.

use std::ffi::OsString;
use std::io;
use std::path::{Path, PathBuf};

/// Product workflows retain their current executable in ordinary builds.
/// Standalone hosts must find a separate product binary, never themselves.
pub(crate) fn resolve_for_current_executable(require_companion: bool) -> io::Result<PathBuf> {
    #[cfg(not(test))]
    if !require_companion {
        return std::env::current_exe();
    }

    let current = std::env::current_exe()?;
    resolve_from_host(&current, |key| std::env::var_os(key), require_companion)
}

fn candidate_executable(
    current: &Path,
    candidate: PathBuf,
    require_companion: bool,
) -> Option<PathBuf> {
    let metadata = std::fs::metadata(&candidate).ok()?;
    if !metadata.is_file() {
        return None;
    }
    if require_companion {
        // Reject both direct/symlink aliases and Unix hard links to this host.
        // A renamed migration tool is still not the product runtime.
        if candidate.canonicalize().ok()? == current.canonicalize().ok()? {
            return None;
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            let current_metadata = std::fs::metadata(current).ok()?;
            if metadata.dev() == current_metadata.dev() && metadata.ino() == current_metadata.ino()
            {
                return None;
            }
        }
    }
    Some(candidate)
}

fn resolve_from_host(
    current: &Path,
    mut environment: impl FnMut(&str) -> Option<OsString>,
    require_companion: bool,
) -> io::Result<PathBuf> {
    for key in ["FRANKEN_NODE_TEST_BIN", "CARGO_BIN_EXE_franken-node"] {
        if let Some(value) = environment(key)
            && let Some(candidate) =
                candidate_executable(current, PathBuf::from(value), require_companion)
        {
            return Ok(candidate);
        }
    }
    let is_lib_test_runner = current
        .file_stem()
        .and_then(std::ffi::OsStr::to_str)
        .is_some_and(|stem| stem.starts_with("frankenengine_node-"));
    if require_companion || is_lib_test_runner {
        for ancestor in current.ancestors().skip(1).take(6) {
            let candidate = ancestor.join(if cfg!(windows) {
                "franken-node.exe"
            } else {
                "franken-node"
            });
            if let Some(candidate) = candidate_executable(current, candidate, require_companion) {
                return Ok(candidate);
            }
        }
    }
    if require_companion {
        Err(io::Error::new(
            io::ErrorKind::NotFound,
            "could not locate a companion franken-node executable; select --native-bin for standalone migration commands",
        ))
    } else {
        Ok(current.to_path_buf())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture_file(path: &Path) {
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, b"executable identity fixture").unwrap();
    }

    fn product_name() -> &'static str {
        if cfg!(windows) {
            "franken-node.exe"
        } else {
            "franken-node"
        }
    }

    #[test]
    fn companion_discovery_finds_adjacent_and_cargo_profile_product() {
        for product_directory in ["target/debug/deps", "target/debug"] {
            let root = tempfile::tempdir().unwrap();
            let current = root
                .path()
                .join("target/debug/deps/franken_migration_suite-fixture");
            let product = root.path().join(product_directory).join(product_name());
            fixture_file(&current);
            fixture_file(&product);
            assert_eq!(
                resolve_from_host(&current, |_| None, true).unwrap(),
                product
            );
        }
    }

    #[test]
    fn companion_discovery_prefers_explicit_product_over_nearby_product() {
        for selected_key in ["FRANKEN_NODE_TEST_BIN", "CARGO_BIN_EXE_franken-node"] {
            let root = tempfile::tempdir().unwrap();
            let current = root.path().join("bin/franken-migration-suite");
            let nearby = root.path().join("bin").join(product_name());
            let selected = root.path().join("selected").join(product_name());
            fixture_file(&current);
            fixture_file(&nearby);
            fixture_file(&selected);
            let resolved = resolve_from_host(
                &current,
                |key| (key == selected_key).then(|| selected.clone().into_os_string()),
                true,
            )
            .unwrap();
            assert_eq!(resolved, selected);
        }
    }

    #[test]
    fn companion_discovery_never_falls_back_to_the_host() {
        let root = tempfile::tempdir().unwrap();
        // Keep all six discovery ancestors inside this fixture.
        let current = root
            .path()
            .join("one/two/three/four/five/six/franken-migration-suite");
        fixture_file(&current);
        let error = resolve_from_host(&current, |_| Some(current.clone().into_os_string()), true)
            .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::NotFound);
    }

    #[test]
    #[cfg(unix)]
    fn companion_discovery_refuses_symlink_and_hardlink_aliases_of_the_host() {
        let root = tempfile::tempdir().unwrap();
        let current = root.path().join("franken-migration-suite");
        let symlink = root.path().join("symlinked-product");
        let hardlink = root.path().join("hardlinked-product");
        fixture_file(&current);
        std::os::unix::fs::symlink(&current, &symlink).unwrap();
        std::fs::hard_link(&current, &hardlink).unwrap();
        assert!(candidate_executable(&current, symlink, true).is_none());
        assert!(candidate_executable(&current, hardlink, true).is_none());
    }

    #[test]
    fn product_test_discovery_retains_existing_fallback_and_profile_lookup() {
        let root = tempfile::tempdir().unwrap();
        let current = root
            .path()
            .join("target/debug/deps/frankenengine_node-fixture");
        fixture_file(&current);
        assert_eq!(
            resolve_from_host(&current, |_| None, false).unwrap(),
            current
        );
        let product = root.path().join("target/debug").join(product_name());
        fixture_file(&product);
        assert_eq!(
            resolve_from_host(&current, |_| None, false).unwrap(),
            product
        );
        let other_host = root.path().join("target/debug/deps/another-host");
        fixture_file(&other_host);
        assert_eq!(
            resolve_from_host(&other_host, |_| None, false).unwrap(),
            other_host
        );
    }
}
