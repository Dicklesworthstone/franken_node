//! Bounded selection of npm workspace manifests from the private capture.
//!
//! Selectors support literal components, `*` within a component and standalone
//! `**`. Unsupported glob dialects fail explicitly. No installed-package or
//! state-directory traversal, symlink following, package-manager execution or
//! fallback to trusting the lockfile's workspace projection.

use super::{
    Capture, DependencyAdmission, DependencyFinding, MAX_DEPTH, MAX_MANIFEST_BYTES,
    bounded_text, identity, name, relative, time_remaining,
};
use anyhow::{Context, Result, ensure};
use rustix::fs::{AtFlags, Dir, FileType, Mode, OFlags, openat, statat};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use std::fs::File;

const MAX_PATTERNS: usize = 64;
const MAX_MANIFESTS: usize = 1024;
const MAX_DIRECTORIES: usize = 4096;
const MAX_ENTRIES: usize = 50_000;
const EXCLUDED: &[&str] = &[
    "node_modules", ".git", ".beads", ".migrate-backup", ".franken-node", ".franken-rewrite",
];

pub(super) fn manifest_path(directory: &str) -> String {
    if directory.is_empty() { "package.json".into() }
    else { format!("{directory}/package.json") }
}

struct Pattern {
    parts: Vec<String>,
}

impl Pattern {
    fn parse(raw: &Value) -> Result<Self> {
        let raw = bounded_text(raw, "workspace selector")?;
        let raw = raw.strip_prefix("./").unwrap_or(raw);
        let raw = raw.strip_suffix('/').unwrap_or(raw);
        relative(raw)?;
        ensure!(!raw.contains(['!', '?', '[', ']', '{', '}', '(', ')', '|']),
            "unsupported workspace selector dialect; use literal components, * or **");
        let parts: Vec<_> = raw.split('/').map(str::to_owned).collect();
        ensure!(parts.len() <= MAX_DEPTH && parts.iter().all(|part|
            !EXCLUDED.contains(&part.as_str()) && (!part.contains("**") || part == "**")),
            "workspace selector is too deep, reserved or uses unsupported glob syntax");
        Ok(Self { parts })
    }

    fn closure(&self, state: &mut [bool]) {
        for (index, part) in self.parts.iter().enumerate() {
            if state[index] && part == "**" { state[index + 1] = true; }
        }
    }

    fn start(&self) -> Vec<bool> {
        let mut state = vec![false; self.parts.len() + 1];
        state[0] = true;
        self.closure(&mut state);
        state
    }

    fn step(&self, state: &[bool], component: &str) -> Vec<bool> {
        let mut next = vec![false; state.len()];
        for (index, part) in self.parts.iter().enumerate() {
            if !state[index] { continue; }
            if part == "**" {
                if !component.starts_with('.') { next[index] = true; }
            } else if component_matches(part, component) {
                next[index + 1] = true;
            }
        }
        self.closure(&mut next);
        next
    }
}

// Wildcards match bytes only between UTF-8 literals. No recursion/backtracking
// tree is allocated; directory components and patterns have explicit bounds.
fn component_matches(pattern: &str, text: &str) -> bool {
    if text.starts_with('.') && !pattern.starts_with('.') { return false; }
    let (pattern, text) = (pattern.as_bytes(), text.as_bytes());
    let (mut p, mut t, mut retry) = (0, 0, 0);
    let mut star = None;
    while t < text.len() {
        if p < pattern.len() && pattern[p] != b'*' && pattern[p] == text[t] {
            p += 1;
            t += 1;
        } else if p < pattern.len() && pattern[p] == b'*' {
            star = Some(p);
            p += 1;
            retry = t;
        } else if let Some(index) = star {
            retry += 1;
            t = retry;
            p = index + 1;
        } else { return false; }
    }
    while p < pattern.len() && pattern[p] == b'*' { p += 1; }
    p == pattern.len()
}

fn directory(root: &File, path: &str) -> Result<File> {
    let mut current = root.try_clone()?;
    if !path.is_empty() {
        relative(path)?;
        for component in path.split('/') {
            current = File::from(openat(&current, component,
                OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::empty())?);
        }
    }
    Ok(current)
}

/// The root and all selected manifests are read exactly once, even when
/// selectors overlap. Directory handles are reopened relative to the held root
/// instead of retaining one descriptor per queued directory.
pub(super) fn capture(capture: &mut Capture, root: Value) -> Result<BTreeMap<String, Value>> {
    let raw = match root.get("workspaces") {
        None => &[][..],
        Some(value) => value.as_array().context("workspaces must be an array of selectors")?.as_slice(),
    };
    ensure!(raw.len() <= MAX_PATTERNS, "workspace selector count exceeds limit");
    let patterns: Vec<_> = raw.iter().map(Pattern::parse).collect::<Result<_>>()?;
    let mut manifests = BTreeMap::from([(String::new(), root)]);
    if patterns.is_empty() { return Ok(manifests); }
    let mut names = BTreeSet::new();
    if let Some(value) = manifests[""].get("name") {
        names.insert(name(bounded_text(value, "root package name")?)?.to_owned());
    }
    let mut matched = vec![false; patterns.len()];
    let initial: Vec<_> = patterns.iter().map(Pattern::start).collect();
    let mut pending = vec![(String::new(), initial, 0_usize)];
    let (mut entries, mut directories) = (0_usize, 1_usize);
    while let Some((path, states, depth)) = pending.pop() {
        time_remaining(capture.deadline)?;
        let fd = directory(&capture.root, &path).with_context(|| format!("capture workspace directory {path}"))?;
        let before = fd.metadata()?;
        let selected = states.iter().any(|state| state.last() == Some(&true));
        if !path.is_empty() && selected {
            let source = manifest_path(&path);
            ensure!(manifests.len() < MAX_MANIFESTS, "workspace manifest count exceeds limit");
            if let Some(manifest) = capture.read(&source, MAX_MANIFEST_BYTES)? {
                let package = name(bounded_text(manifest.get("name").context("workspace package name missing")?, "workspace package name")?)?;
                ensure!(names.insert(package.to_owned()), "duplicate workspace/root package name");
                // Nested project managers are not silently treated as part of
                // the root's npm resolution contract.
                ensure!(manifest.get("workspaces").is_none(), "nested workspace configuration requires separate assessment");
                for (seen, state) in matched.iter_mut().zip(&states) {
                    *seen |= state.last() == Some(&true);
                }
                manifests.insert(path.clone(), manifest);
            }
        }
        let descend = states.iter().any(|state| state[..state.len() - 1].iter().any(|active| *active));
        if !descend { continue; }
        let mut children = BTreeMap::new();
        for entry in Dir::read_from(&fd)? {
            time_remaining(capture.deadline)?;
            let entry = entry?;
            let bytes = entry.file_name().to_bytes();
            if bytes == b"." || bytes == b".." { continue; }
            entries += 1;
            ensure!(entries <= MAX_ENTRIES, "workspace directory entry count exceeds limit");
            let component = entry.file_name().to_str().context("workspace directory entry must be UTF-8")?;
            if EXCLUDED.contains(&component) { continue; }
            let next: Vec<_> = patterns.iter().zip(&states).map(|(pattern, state)| pattern.step(state, component)).collect();
            if !next.iter().any(|state| state.iter().any(|active| *active)) { continue; }
            let stat = statat(&fd, entry.file_name(), AtFlags::SYMLINK_NOFOLLOW)?;
            let kind = FileType::from_raw_mode(stat.st_mode);
            ensure!(kind != FileType::Symlink, "workspace selector may traverse a symlink; inventory refused");
            if kind != FileType::Directory { continue; }
            ensure!(depth < MAX_DEPTH, "workspace traversal depth exceeds limit");
            directories += 1;
            ensure!(directories <= MAX_DIRECTORIES, "workspace directory count exceeds limit");
            let child = if path.is_empty() { component.into() } else { format!("{path}/{component}") };
            relative(&child)?;
            ensure!(children.insert(child, next).is_none(), "workspace directory changed during enumeration");
        }
        ensure!(identity(&before) == identity(&fd.metadata()?), "workspace directory changed during enumeration");
        pending.extend(children.into_iter().rev().map(|(path, state)| (path, state, depth + 1)));
    }
    ensure!(matched.iter().all(|seen| *seen), "workspace selector matched no package manifests; incomplete inventory refused");
    Ok(manifests)
}

pub(super) fn manifest_findings(report: &mut DependencyAdmission, manifest: &Value, source: &str) -> Result<()> {
    let Some(scripts) = manifest.get("scripts") else { return Ok(()); };
    let scripts = scripts.as_object().context("package scripts must be an object")?;
    for (script, command) in scripts {
        let command = command.as_str().context("package script command must be a string")?;
        if ["preinstall", "install", "postinstall", "prepare"].contains(&script.as_str()) && !command.trim().is_empty() {
            report.finding(DependencyFinding {
                code: "install_script".into(), source: format!("{source}#scripts.{script}"),
                package: manifest.get("name").and_then(Value::as_str).unwrap_or_default().into(),
                installed_as: String::new(), package_path: None, version: None,
                detail: "Captured package declares install/prepare lifecycle code; explicit review required".into(),
            })?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::inspect;
    use serde_json::json;
    use std::fs;
    use std::path::Path;
    use std::time::{Duration, Instant};

    fn deadline() -> Instant { Instant::now() + Duration::from_secs(5) }
    fn fixture(package: Value, lock: Option<Value>) -> tempfile::TempDir {
        let root = tempfile::tempdir().unwrap();
        fs::write(root.path().join("package.json"), serde_json::to_vec(&package).unwrap()).unwrap();
        if let Some(lock) = lock {
            fs::write(root.path().join("package-lock.json"), serde_json::to_vec(&lock).unwrap()).unwrap();
        }
        root
    }
    fn modern_fixture(packages: Value) -> Value { json!({"lockfileVersion":3,"packages":packages}) }
    fn codes(report: &DependencyAdmission) -> Vec<&str> {
        report.findings.iter().map(|finding| finding.code.as_str()).collect()
    }

    fn write(root: &Path, directory: &str, manifest: Value) {
        fs::create_dir_all(root.join(directory)).unwrap();
        fs::write(root.join(manifest_path(directory)), serde_json::to_vec(&manifest).unwrap()).unwrap();
    }

    #[test]
    fn overlapping_star_and_globstar_selectors_capture_once_and_bind_real_bytes() {
        let root = fixture(json!({"workspaces":["./packages/*/", "packages/**", "packages/a"]}), None);
        write(root.path(), "packages/a", json!({"name":"a","dependencies":{"sharp":"^1"}}));
        write(root.path(), "packages/group/b", json!({"name":"b","peerDependencies":{"peer":"^2"}}));
        let report = inspect(root.path(), deadline()).unwrap();
        assert_eq!(report.manifests_scanned, 3);
        assert_eq!(report.inputs.len(), 3);
        assert!(report.findings.iter().any(|f| f.source == "packages/a/package.json#dependencies" && f.code == "native_addon"));
        assert!(report.findings.iter().any(|f| f.source == "packages/group/b/package.json#peerDependencies" && f.code == "unresolved_declaration"));
        use sha2::{Digest, Sha256};
        for input in &report.inputs {
            assert_eq!(input.sha256, hex::encode(Sha256::digest(fs::read(root.path().join(&input.path)).unwrap())));
        }
        assert_eq!(report, inspect(root.path(), deadline()).unwrap());
    }

    #[test]
    fn private_and_hoisted_identities_are_used_without_double_counting_packages() {
        let root = fixture(json!({"workspaces":["packages/*"]}), Some(modern_fixture(json!({
            "node_modules/dep":{"version":"1.0.0"},
            "packages/a/node_modules/private":{"version":"2.0.0"}
        }))));
        write(root.path(), "packages/a", json!({"name":"a","dependencies":{"dep":"^1","private":"^2"}}));
        write(root.path(), "packages/b", json!({"name":"b","dependencies":{"dep":"^1"}}));
        let report = inspect(root.path(), deadline()).unwrap();
        assert_eq!(report.packages_scanned, 2);
        assert_eq!(codes(&report), ["workspace_review", "workspace_review"]);
    }

    #[test]
    fn a_private_wrong_identity_is_not_rescued_by_a_matching_root_record() {
        let root = fixture(json!({"workspaces":["packages/a"]}), Some(modern_fixture(json!({
            "node_modules/dep":{"version":"1.0.0"},
            "packages/a/node_modules/dep":{"name":"other","version":"1.0.0"}
        }))));
        write(root.path(), "packages/a", json!({"name":"a","dependencies":{"dep":"^1"}}));
        let report = inspect(root.path(), deadline()).unwrap();
        assert!(report.findings.iter().any(|f| f.source == "packages/a/package.json#dependencies" && f.code == "unresolved_declaration"));
    }

    #[test]
    fn captured_workspace_lifecycle_is_not_hidden_by_a_clean_lock_projection() {
        let root = fixture(json!({"workspaces":["packages/a"]}), None);
        write(root.path(), "packages/a", json!({"name":"a","scripts":{"prepare":"node build.js"}}));
        let report = inspect(root.path(), deadline()).unwrap();
        assert!(report.findings.iter().any(|f| f.source == "packages/a/package.json#scripts.prepare" && f.code == "install_script"));
        assert!(!root.path().join("build.js").exists());
    }

    #[test]
    fn unknown_glob_dialects_and_reserved_or_missing_selections_fail_explicitly() {
        for selector in ["../outside", "/outside", "packages/{a,b}", "packages/[ab]", "!packages/a", "packages/a?", "node_modules/*", ".git/*", "packages/a**b", "missing/*"] {
            let root = fixture(json!({"workspaces":[selector]}), None);
            assert!(inspect(root.path(), deadline()).is_err(), "{selector}");
        }
        for workspaces in [Value::Null, json!("packages/*"), json!({"packages":["packages/*"]})] {
            let root = fixture(json!({"workspaces":workspaces}), None);
            assert!(inspect(root.path(), deadline()).is_err());
        }
        let root = fixture(json!({"workspaces":[]}), None);
        assert!(!inspect(root.path(), deadline()).unwrap().requires_review());
    }

    #[test]
    fn malformed_missing_duplicate_and_nested_workspace_manifests_fail_closed() {
        for manifest in [json!({}), json!({"name":"root"}), json!({"name":"a","workspaces":[]}), json!({"name":"a","scripts":{"prepare":false}})] {
            let root = fixture(json!({"name":"root","workspaces":["packages/a"]}), None);
            write(root.path(), "packages/a", manifest);
            assert!(inspect(root.path(), deadline()).is_err());
        }
        let root = fixture(json!({"workspaces":["packages/*"]}), None);
        write(root.path(), "packages/a", json!({"name":"duplicate"}));
        write(root.path(), "packages/b", json!({"name":"duplicate"}));
        assert!(inspect(root.path(), deadline()).is_err());
        fs::write(root.path().join("packages/b/package.json"), r#"{"name":"b","name":"c"}"#).unwrap();
        assert!(inspect(root.path(), deadline()).is_err());
    }

    #[test]
    fn selectors_never_follow_directory_or_manifest_symlinks() {
        use std::os::unix::fs::symlink;
        let outside = tempfile::tempdir().unwrap();
        fs::write(outside.path().join("package.json"), r#"{"name":"outside"}"#).unwrap();
        for wildcard in [false, true] {
            let root = fixture(json!({"workspaces":[if wildcard {"packages/*"} else {"packages/a"}]}), None);
            fs::create_dir(root.path().join("packages")).unwrap();
            symlink(outside.path(), root.path().join("packages/a")).unwrap();
            assert!(inspect(root.path(), deadline()).is_err());
        }
        let root = fixture(json!({"workspaces":["packages/a"]}), None);
        fs::create_dir_all(root.path().join("packages/a")).unwrap();
        symlink(outside.path().join("package.json"), root.path().join("packages/a/package.json")).unwrap();
        assert!(inspect(root.path(), deadline()).is_err());
    }

    #[test]
    fn reserved_subtrees_are_not_read_and_dot_directories_require_explicit_selection() {
        let root = fixture(json!({"workspaces":["packages/**"]}), None);
        write(root.path(), "packages/a", json!({"name":"a"}));
        for path in ["packages/node_modules/bad", "packages/.git/bad", "packages/.hidden"] {
            fs::create_dir_all(root.path().join(path)).unwrap();
            fs::write(root.path().join(path).join("package.json"), "invalid").unwrap();
        }
        let report = inspect(root.path(), deadline()).unwrap();
        assert_eq!(report.manifests_scanned, 2);
        assert_eq!(report.inputs.len(), 2);
    }

    #[test]
    fn selector_count_and_manifest_bytes_have_non_truncating_limits() {
        let root = fixture(json!({"workspaces":vec!["packages/a"; MAX_PATTERNS + 1]}), None);
        assert!(inspect(root.path(), deadline()).is_err());
        let root = fixture(json!({"workspaces":["packages/a"]}), None);
        fs::create_dir_all(root.path().join("packages/a")).unwrap();
        fs::write(root.path().join("packages/a/package.json"), vec![b' '; MAX_MANIFEST_BYTES + 1]).unwrap();
        assert!(inspect(root.path(), deadline()).is_err());
    }

    #[test]
    fn star_matcher_handles_utf8_suffixes_and_does_not_match_path_separators() {
        assert!(component_matches("π*-app", "π工具-app"));
        assert!(component_matches("a*b*c", "axbybc"));
        assert!(!component_matches("a*b*c", "axbybd"));
        assert!(!component_matches("*", ".hidden"));
        assert!(component_matches(".hidden*", ".hidden-name"));
        let pattern = Pattern::parse(&json!("packages/*")).unwrap();
        let s = pattern.step(&pattern.start(), "packages");
        let s = pattern.step(&s, "a");
        assert_eq!(s.last(), Some(&true));
        assert!(!pattern.step(&s, "b").iter().any(|active| *active));
    }
}
