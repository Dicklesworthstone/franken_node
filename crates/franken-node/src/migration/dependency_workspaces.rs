//! Bounded selection of npm workspace manifests from the private capture.
//!
//! Selectors support literal components, `*` within a component and standalone
//! `**`. Unsupported glob dialects fail explicitly. No installed-package or
//! state-directory traversal, symlink following, package-manager execution or
//! fallback to trusting the lockfile's workspace projection.

use super::{
    Capture, DependencyAdmission, DependencyFinding, LockedPackage, MAX_DEPTH,
    MAX_LOCK_BYTES, MAX_MANIFEST_BYTES, SECTIONS, bounded_text, flag, identity,
    name, relative, time_remaining,
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

fn workspace_finding(report: &mut DependencyAdmission, manifest: &Value, directory: &str, code: &str, detail: &str) -> Result<()> {
    let package = manifest.get("name").and_then(Value::as_str).unwrap_or_default();
    report.finding(DependencyFinding {
        code: code.into(), source: manifest_path(directory), package: package.into(),
        installed_as: package.into(), package_path: Some(directory.into()),
        version: manifest.get("version").and_then(Value::as_str).map(str::to_owned),
        detail: detail.into(),
    })
}

fn dependency_metadata_matches(manifest: &Value, recorded: &Value) -> bool {
    // Missing and empty declaration maps are equivalent. Do not conflate null
    // or another type with an empty map, or silently discard peer metadata.
    SECTIONS.iter().copied().chain(["peerDependenciesMeta"]).all(|field| {
        let empty = serde_json::Map::new();
        let left = match manifest.get(field) {
            None => Some(&empty),
            Some(value) => value.as_object(),
        };
        let right = match recorded.get(field) {
            None => Some(&empty),
            Some(value) => value.as_object(),
        };
        left.is_some() && left == right
    })
}

/// Only the canonical root installation of an explicitly selected workspace
/// may clear local-link review. Its target, name, version and dependency maps
/// must agree with the captured manifest. Arbitrary links and lockfile-only
/// workspace descriptors never gain this authorization.
pub(super) fn bind_links(
    capture: &mut Capture,
    manifests: &BTreeMap<String, Value>,
    lock: Option<&Value>,
    packages: &BTreeMap<String, LockedPackage>,
    report: &mut DependencyAdmission,
) -> Result<BTreeSet<String>> {
    let recorded = lock.and_then(|lock| lock.get("packages")).and_then(Value::as_object);
    let mut admitted = BTreeSet::new();
    for (path, manifest) in manifests {
        time_remaining(capture.deadline)?;
        let fd = directory(&capture.root, path)?;
        let has_binding = match statat(&fd, "binding.gyp", AtFlags::SYMLINK_NOFOLLOW) {
            Ok(_) => true,
            Err(rustix::io::Errno::NOENT) => false,
            Err(error) => return Err(error).context("inspect captured native-build marker"),
        };
        let gypfile = flag(manifest.as_object().context("captured manifest must be an object")?, "gypfile")?;
        if has_binding || gypfile {
            workspace_finding(report, manifest, path, "native_build",
                "Captured package has a binding.gyp marker or declares gypfile; native-build review required")?;
        }
        if path.is_empty() { continue; }
        for filename in ["package-lock.json", "npm-shrinkwrap.json"] {
            if capture.read(&format!("{path}/{filename}"), MAX_LOCK_BYTES)?.is_some() {
                workspace_finding(report, manifest, path, "workspace_lockfile",
                    "Workspace has an independent lockfile; assess it as a separate project instead of mixing lock authorities")?;
            }
        }
        let package = name(bounded_text(manifest.get("name").context("workspace name missing")?, "workspace name")?)?;
        let version = manifest.get("version").map(|value| bounded_text(value, "workspace version")).transpose()?;
        let location = format!("node_modules/{package}");
        let record = recorded.and_then(|records| records.get(path));
        let link = recorded.and_then(|records| records.get(&location));
        let matched = match (version, record, link, packages.get(&location)) {
            (Some(version), Some(record), Some(link), Some(locked)) => {
                locked.linked && !locked.unresolved && locked.name == package
                    && locked.installed_as == package
                    && locked.version.as_deref() == Some(version)
                    && link.get("resolved").and_then(Value::as_str) == Some(path.as_str())
                    && record.get("version").and_then(Value::as_str) == Some(version)
                    && record.get("name").is_none_or(|value| value.as_str() == Some(package))
                    && dependency_metadata_matches(manifest, record)
            }
            _ => false,
        };
        if matched {
            admitted.insert(location);
        } else {
            workspace_finding(report, manifest, path, "workspace_review",
                "Workspace root link, target identity, version or dependency metadata does not match the captured manifest")?;
        }
    }
    Ok(admitted)
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

    fn linked_fixture() -> tempfile::TempDir {
        let root = fixture(json!({"name":"root","workspaces":["packages/*"],"dependencies":{"a":"^1"}}),
            Some(modern_fixture(json!({
                "node_modules/a":{"link":true,"resolved":"packages/a"},
                "packages/a":{"name":"a","version":"1.0.0","dependencies":{"dep":"^1"}},
                "node_modules/dep":{"version":"1.2.3"}
            }))));
        write(root.path(), "packages/a", json!({"name":"a","version":"1.0.0","dependencies":{"dep":"^1"}}));
        root
    }

    #[test]
    fn captured_workspace_link_and_hoisted_dependency_can_pass_metadata_admission() {
        let root = linked_fixture();
        let report = inspect(root.path(), deadline()).unwrap();
        assert!(!report.requires_review(), "{report:#?}");
        assert_eq!(report.packages_scanned, 2);
        assert_eq!(report.manifests_scanned, 2);
        assert_eq!(report.inputs.iter().map(|input| input.path.as_str()).collect::<Vec<_>>(),
            ["package-lock.json", "package.json", "packages/a/package.json"]);
        // Metadata inspection neither installs a link nor runs the project.
        assert!(!root.path().join("node_modules").exists());
        assert_eq!(report, inspect(root.path(), deadline()).unwrap());
    }

    #[test]
    fn inter_workspace_cycles_and_scoped_names_resolve_without_recursing_through_links() {
        let root = fixture(json!({"workspaces":["packages/*"]}), Some(modern_fixture(json!({
            "node_modules/@team/a":{"link":true,"resolved":"packages/a"},
            "node_modules/b":{"link":true,"resolved":"packages/b"},
            "packages/a":{"name":"@team/a","version":"1.0.0","dependencies":{"b":"^1"}},
            "packages/b":{"name":"b","version":"1.0.0","dependencies":{"@team/a":"^1"}}
        }))));
        write(root.path(), "packages/a", json!({"name":"@team/a","version":"1.0.0","dependencies":{"b":"^1"}}));
        write(root.path(), "packages/b", json!({"name":"b","version":"1.0.0","dependencies":{"@team/a":"^1"}}));
        let report = inspect(root.path(), deadline()).unwrap();
        assert!(!report.requires_review(), "{report:#?}");
        assert_eq!(report.packages_scanned, 2);
        assert_eq!(report.manifests_scanned, 3);
    }

    #[test]
    fn changed_workspace_name_version_or_declaration_maps_cannot_clear_link_review() {
        for changed in [
            json!({"name":"other","version":"1.0.0","dependencies":{"dep":"^1"}}),
            json!({"name":"a","version":"2.0.0","dependencies":{"dep":"^1"}}),
            json!({"name":"a","dependencies":{"dep":"^1"}}),
            json!({"name":"a","version":"1.0.0","dependencies":{"dep":"^2"}}),
            json!({"name":"a","version":"1.0.0","dependencies":{"dep":"^1"},"peerDependenciesMeta":{"dep":{"optional":true}}}),
        ] {
            let root = linked_fixture();
            write(root.path(), "packages/a", changed);
            let report = inspect(root.path(), deadline()).unwrap();
            assert!(codes(&report).contains(&"workspace_review"), "{report:#?}");
            assert!(codes(&report).contains(&"local_link"), "{report:#?}");
        }
    }

    #[test]
    fn selected_manifest_cannot_authorize_unselected_or_nested_local_links() {
        for (location, target, descriptor) in [
            ("node_modules/extra", "unselected", json!({"name":"extra","version":"1.0.0"})),
            ("packages/a/node_modules/a", "packages/a", json!({"name":"a","version":"1.0.0","dependencies":{"dep":"^1"}})),
        ] {
            let root = linked_fixture();
            let path = root.path().join("package-lock.json");
            let mut lock: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
            lock["packages"][location] = json!({"link":true,"resolved":target});
            lock["packages"][target] = descriptor;
            fs::write(path, serde_json::to_vec(&lock).unwrap()).unwrap();
            let report = inspect(root.path(), deadline()).unwrap();
            assert!(report.findings.iter().any(|finding| finding.code == "local_link"
                && finding.package_path.as_deref() == Some(location)), "{report:#?}");
        }
    }

    #[test]
    fn wrong_root_link_target_or_missing_target_descriptor_never_passes() {
        for missing in [false, true] {
            let root = linked_fixture();
            let path = root.path().join("package-lock.json");
            let mut lock: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
            if missing {
                lock["packages"].as_object_mut().unwrap().remove("packages/a");
            } else {
                lock["packages"]["node_modules/a"]["resolved"] = json!("packages/other");
                lock["packages"]["packages/other"] = json!({"name":"a","version":"1.0.0","dependencies":{"dep":"^1"}});
            }
            fs::write(path, serde_json::to_vec(&lock).unwrap()).unwrap();
            let report = inspect(root.path(), deadline()).unwrap();
            assert!(codes(&report).contains(&"workspace_review"), "{report:#?}");
        }
    }

    #[test]
    fn captured_lifecycle_and_native_build_markers_remain_blockers_after_link_binding() {
        for kind in ["script", "gypfile", "binding"] {
            let root = linked_fixture();
            let mut manifest = json!({"name":"a","version":"1.0.0","dependencies":{"dep":"^1"}});
            match kind {
                "script" => manifest["scripts"] = json!({"prepare":"touch MUST_NOT_EXIST"}),
                "gypfile" => manifest["gypfile"] = json!(true),
                _ => fs::write(root.path().join("packages/a/binding.gyp"), "{}").unwrap(),
            }
            write(root.path(), "packages/a", manifest);
            let report = inspect(root.path(), deadline()).unwrap();
            let expected = if kind == "script" { "install_script" } else { "native_build" };
            assert!(codes(&report).contains(&expected), "{report:#?}");
            assert!(!codes(&report).contains(&"workspace_review"));
            assert!(!codes(&report).contains(&"local_link"));
            assert!(!root.path().join("packages/a/MUST_NOT_EXIST").exists());
        }
    }

    #[test]
    fn independent_workspace_lock_authorities_remain_review_items() {
        for filename in ["package-lock.json", "npm-shrinkwrap.json"] {
            let root = linked_fixture();
            fs::write(root.path().join("packages/a").join(filename), r#"{"lockfileVersion":3,"packages":{}}"#).unwrap();
            let report = inspect(root.path(), deadline()).unwrap();
            assert!(codes(&report).contains(&"workspace_lockfile"), "{report:#?}");
            assert!(report.inputs.iter().any(|input| input.path == format!("packages/a/{filename}")));
        }
    }

    #[test]
    fn symlinked_or_malformed_nested_lockfiles_are_errors_not_unobserved_approval() {
        use std::os::unix::fs::symlink;
        let root = linked_fixture();
        symlink("../../package-lock.json", root.path().join("packages/a/package-lock.json")).unwrap();
        assert!(inspect(root.path(), deadline()).is_err());
        let root = linked_fixture();
        fs::write(root.path().join("packages/a/package-lock.json"), "invalid").unwrap();
        assert!(inspect(root.path(), deadline()).is_err());
    }

    #[test]
    fn external_or_alias_requests_are_not_substituted_with_same_named_workspaces() {
        for request in ["npm:a@1", "file:../external", "https://example.invalid/a.tgz", "owner/repo"] {
            let root = linked_fixture();
            fs::write(root.path().join("package.json"), serde_json::to_vec(&json!({
                "name":"root","workspaces":["packages/*"],"dependencies":{"a":request}
            })).unwrap()).unwrap();
            let report = inspect(root.path(), deadline()).unwrap();
            assert!(report.findings.iter().any(|finding| finding.source == "package.json#dependencies"
                && finding.code == "unresolved_declaration"), "{request}: {report:#?}");
        }
    }

    #[test]
    fn stale_locked_workspace_projection_cannot_hide_a_new_native_dependency() {
        let root = linked_fixture();
        write(root.path(), "packages/a", json!({"name":"a","version":"1.0.0","dependencies":{"image":"npm:sharp@^1"}}));
        let report = inspect(root.path(), deadline()).unwrap();
        assert!(report.findings.iter().any(|finding| finding.source == "packages/a/package.json#dependencies"
            && finding.package == "sharp" && finding.code == "native_addon"));
        assert!(codes(&report).contains(&"workspace_review"));
    }
}
