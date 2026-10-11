//! Bind checked migration to its private captured npm installation.
//!
//! Lockfile integrity describes an archive, not an installed directory. These
//! checks deliberately do not equate a package.json hash with archive SRI.
//! The caller owns an immutable staged tree; no package manager, lifecycle
//! command, guest code, registry request, or symlink traversal happens here.
//! Ordinary npm packages and the already-admitted root workspace links are
//! supported. Other installed links require review, rather than being followed.

use super::{
    Capture, DependencyAdmission, DependencyFinding, LockedPackage, MAX_DEPTH,
    MAX_LOCK_BYTES, MAX_MANIFEST_BYTES, MAX_PACKAGES, SECTIONS, alias, bounded_text,
    flag, graph, identity, name, nearest_package, relative, time_remaining, workspaces,
};
use anyhow::{Context, Result, ensure};
use rustix::fs::{AtFlags, Dir, FileType, Mode, OFlags, openat, readlinkat, statat};
use serde_json::{Map, Value};
use std::collections::BTreeMap;
use std::fs::File;
use std::path::Path;
use std::time::Instant;

const MAX_TREE_ENTRIES: usize = 100_000;
const MAX_TREE_DIRECTORIES: usize = 20_000;
const MAX_TREE_PATH_BYTES: usize = 8 * 1024 * 1024;
const MAX_EDGES: usize = 200_000;
const INSTALLED_SCOPE: &str = "captured npm metadata, installed manifest identity, required dependency routes and native/lifecycle markers; not registry-content authentication, archive SRI verification, npm override resolution, a sandbox or runtime compatibility proof";

#[derive(Default)]
struct TreeBudget {
    entries: usize,
    directories: usize,
    path_bytes: usize,
}

impl TreeBudget {
    fn entry(&mut self, path: &str) -> Result<()> {
        self.entries += 1;
        self.path_bytes = self.path_bytes.checked_add(path.len())
            .context("installed inventory path byte count overflow")?;
        ensure!(self.entries <= MAX_TREE_ENTRIES && self.path_bytes <= MAX_TREE_PATH_BYTES,
            "installed dependency tree inventory exceeds its entry/path budget");
        Ok(())
    }

    fn directory(&mut self, depth: usize) -> Result<()> {
        self.directories += 1;
        ensure!(self.directories <= MAX_TREE_DIRECTORIES && depth <= MAX_DEPTH,
            "installed dependency tree inventory exceeds its directory/depth budget");
        Ok(())
    }
}

fn directory(root: &File, path: &str) -> Result<File> {
    let mut fd = root.try_clone()?;
    if !path.is_empty() {
        relative(path)?;
        for component in path.split('/') {
            fd = File::from(openat(&fd, component,
                OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::empty())?);
        }
    }
    Ok(fd)
}

fn module_container(path: &str) -> bool {
    path == "node_modules" || path.ends_with("/node_modules")
}

fn scope_container(path: &str) -> bool {
    path.rsplit_once('/').is_some_and(|(parent, leaf)|
        module_container(parent) && leaf.starts_with('@'))
}

fn installation_name(path: &str) -> Result<Option<String>> {
    let Some((parent, leaf)) = path.rsplit_once('/') else { return Ok(None); };
    if module_container(parent) && !leaf.starts_with('@') {
        return Ok(Some(name(leaf)?.to_owned()));
    }
    if scope_container(parent) {
        let scope = parent.rsplit('/').next().context("missing npm scope")?;
        return Ok(Some(name(&format!("{scope}/{leaf}"))?.to_owned()));
    }
    Ok(None)
}

fn section<'a>(value: &'a Value, field: &str, empty: &'a Map<String, Value>) -> Result<&'a Map<String, Value>> {
    match value.get(field) {
        None => Ok(empty),
        Some(value) => value.as_object().with_context(|| format!("installed {field} must be an object")),
    }
}

/// Resolve only npm's relative workspace-link shape: leading parent steps,
/// then ordinary components. A normal/../ sequence could traverse a symlink
/// before the parent step; lexical normalization would not prove its target.
fn workspace_target(location: &str, target: &str) -> Result<String> {
    ensure!(!target.is_empty() && target.len() <= 4096 && !target.starts_with('/')
        && !target.contains(['\\', ':']) && !target.chars().any(char::is_control),
        "workspace link target must be bounded and relative");
    let parent = location.rsplit_once('/').context("workspace link parent missing")?.0;
    let mut parts: Vec<_> = parent.split('/').collect();
    let mut descended = false;
    for part in target.split('/') {
        match part {
            "" | "." => anyhow::bail!("noncanonical workspace link target"),
            ".." => {
                ensure!(!descended && parts.pop().is_some(), "workspace link escapes or has ambiguous parent traversal");
            }
            _ => { descended = true; parts.push(part); }
        }
    }
    let result = parts.join("/");
    relative(&result)?;
    Ok(result)
}

fn lock_record<'a>(lock: Option<&'a Value>, path: &str) -> Option<&'a Value> {
    let lock = lock?;
    if lock.get("lockfileVersion").and_then(Value::as_u64) != Some(1) {
        return lock.get("packages")?.get(path);
    }
    let mut record = lock;
    for component in path.strip_prefix("node_modules/")?.split("/node_modules/") {
        record = record.get("dependencies")?.get(component)?;
    }
    Some(record)
}

fn declaration_maps_match(manifest: &Value, recorded: &Value, legacy: bool) -> Result<bool> {
    let empty = Map::new();
    if legacy {
        // v1 stores the union of production and optional edges in `requires`.
        // It contains no peer map; peers are still checked against the actual
        // installed graph below, not claimed to match nonexistent v1 evidence.
        let mut requires = section(manifest, "dependencies", &empty)?.clone();
        requires.extend(section(manifest, "optionalDependencies", &empty)?.clone());
        return Ok(&requires == section(recorded, "requires", &empty)?);
    }
    for field in ["dependencies", "optionalDependencies", "peerDependencies", "peerDependenciesMeta"] {
        if section(manifest, field, &empty)? != section(recorded, field, &empty)? {
            return Ok(false);
        }
    }
    Ok(true)
}

struct Inspector<'a> {
    capture: &'a mut Capture,
    locked: &'a BTreeMap<String, LockedPackage>,
    projects: &'a BTreeMap<String, Value>,
    lock: Option<&'a Value>,
    report: &'a mut DependencyAdmission,
    actual: BTreeMap<String, LockedPackage>,
    manifests: BTreeMap<String, Value>,
}

impl Inspector<'_> {
    fn finding(&mut self, path: &str, code: &str, detail: &str) -> Result<()> {
        let locked = self.locked.get(path);
        self.report.finding(DependencyFinding {
            code: code.into(), source: workspaces::manifest_path(path),
            package: locked.map_or_else(String::new, |package| package.name.clone()),
            installed_as: installation_name(path)?.unwrap_or_default(),
            package_path: Some(path.into()),
            version: locked.and_then(|package| package.version.clone()),
            detail: detail.into(),
        })
    }

    fn bind_manifest(&mut self, path: &str, installed_as: &str, manifest: Value, linked: bool) -> Result<()> {
        let Some(package_name) = manifest.get("name") else {
            return self.finding(path, "installed_identity_missing", "Installed package manifest has no name");
        };
        let package_name = name(bounded_text(package_name, "installed package name")?)?.to_owned();
        let Some(version) = manifest.get("version") else {
            return self.finding(path, "installed_identity_missing", "Installed package manifest has no version");
        };
        let version = bounded_text(version, "installed package version")?.to_owned();
        if graph::version_review(Some(&version), Some(&version)).is_some() {
            self.finding(path, "installed_version_invalid", "Installed package version is not a supported concrete npm version")?;
        }
        let matched = self.locked.get(path).is_some_and(|package|
            package.name == package_name && package.version.as_deref() == Some(version.as_str())
                && package.linked == linked);
        if !matched {
            self.finding(path, "installed_identity_mismatch", "Installed package name, exact version or link kind differs from the recorded installation")?;
        }
        if !linked && let Some(recorded) = lock_record(self.lock, path) {
            let legacy = self.lock.and_then(|lock| lock.get("lockfileVersion")).and_then(Value::as_u64) == Some(1);
            if !declaration_maps_match(&manifest, recorded, legacy)? {
                self.finding(path, "installed_dependency_metadata_mismatch", "Installed runtime dependency declarations differ from the lockfile; stale or hidden edges require review")?;
            }
        }
        if !linked {
            // Selected workspace lifecycle/gyp findings were already assessed
            // from this exact manifest by the metadata phase.
            let start = self.report.findings.len();
            workspaces::manifest_findings(self.report, &manifest, &workspaces::manifest_path(path))?;
            for finding in &mut self.report.findings[start..] {
                finding.installed_as = installed_as.into();
                finding.package_path = Some(path.into());
                finding.version = Some(version.clone());
            }
            if flag(manifest.as_object().context("installed manifest must be an object")?, "gypfile")? {
                self.finding(path, "native_build", "Installed package declares gypfile; native-build review required")?;
            }
        }
        ensure!(self.actual.len() < MAX_PACKAGES, "installed package count exceeds limit");
        ensure!(self.actual.insert(path.into(), LockedPackage {
            name: package_name, installed_as: installed_as.into(), version: Some(version),
            path: path.into(), install: false, linked, unresolved: false,
        }).is_none(), "duplicate installed package identity");
        self.manifests.insert(path.into(), manifest);
        Ok(())
    }

    fn ordinary_package(&mut self, path: &str, installed_as: &str) -> Result<()> {
        self.report.installed_packages_scanned += 1;
        if !self.locked.contains_key(path) {
            self.finding(path, "unrecorded_installed_package", "Installed package location is absent from the selected lockfile")?;
        }
        let Some(manifest) = self.capture.read(&workspaces::manifest_path(path), MAX_MANIFEST_BYTES)? else {
            return self.finding(path, "installed_manifest_missing", "Installed package directory has no regular package.json");
        };
        self.report.manifests_scanned += 1;
        self.bind_manifest(path, installed_as, manifest, false)
    }

    fn workspace_link(&mut self, path: &str, installed_as: &str, parent: &File, leaf: &str) -> Result<()> {
        self.report.installed_packages_scanned += 1;
        let expected = lock_record(self.lock, path)
            .filter(|_| self.locked.get(path).is_some_and(|package| package.linked))
            .and_then(|record| record.get("resolved")).and_then(Value::as_str)
            .filter(|target| self.projects.contains_key(*target))
            .map(str::to_owned);
        let Some(expected) = expected else {
            return self.finding(path, "installed_package_link", "Only an independently selected and metadata-bound root workspace link is supported");
        };
        let target = readlinkat(parent, leaf, Vec::new())?;
        let target = target.to_str().context("workspace link must be UTF-8")?;
        ensure!(workspace_target(path, target)? == expected, "installed workspace link differs from its captured target");
        // Verify every physical target parent without following the link.
        let _target = directory(&self.capture.root, &expected)?;
        ensure!(readlinkat(parent, leaf, Vec::new())?.to_str()? == target,
            "workspace link changed during inspection");
        let manifest = self.projects[&expected].clone();
        self.bind_manifest(path, installed_as, manifest, true)
    }

    fn walk(&mut self) -> Result<()> {
        let mut budget = TreeBudget::default();
        budget.directory(0)?;
        let mut pending = vec![(String::new(), None::<String>, 0_usize)];
        let mut directories = BTreeMap::new();
        while let Some((path, mut owner, depth)) = pending.pop() {
            time_remaining(self.capture.deadline)?;
            let fd = directory(&self.capture.root, &path)?;
            let before = fd.metadata()?;
            if !path.is_empty() && self.projects.contains_key(&path) { owner = Some(path.clone()); }
            if let Some(installed_as) = installation_name(&path)? {
                self.ordinary_package(&path, &installed_as)?;
                owner = Some(path.clone());
            }
            let mut children = BTreeMap::new();
            for entry in Dir::read_from(&fd)? {
                time_remaining(self.capture.deadline)?;
                let entry = entry?;
                let bytes = entry.file_name().to_bytes();
                if bytes == b"." || bytes == b".." || bytes == b".git" { continue; }
                let leaf = entry.file_name().to_str().context("installed inventory path must be UTF-8")?;
                let child = if path.is_empty() { leaf.into() } else { format!("{path}/{leaf}") };
                relative(&child)?;
                budget.entry(&child)?;
                let stat = statat(&fd, entry.file_name(), AtFlags::SYMLINK_NOFOLLOW)?;
                let kind = FileType::from_raw_mode(stat.st_mode);
                ensure!(children.insert(child, (leaf.to_owned(), kind)).is_none(),
                    "installed dependency directory changed during enumeration");
            }
            ensure!(identity(&before) == identity(&fd.metadata()?), "installed dependency directory changed during enumeration");
            directories.insert(path.clone(), identity(&before));
            for (child, (leaf, kind)) in children.into_iter().rev() {
                // npm's executable shims and hidden lockfile are not package
                // installations. Neither is executed or treated as authority.
                if module_container(&path) && ((leaf == ".bin" && kind == FileType::Directory)
                    || (leaf == ".package-lock.json" && kind == FileType::RegularFile)) { continue; }
                if kind == FileType::Directory {
                    budget.directory(depth + 1)?;
                    pending.push((child, owner.clone(), depth + 1));
                    continue;
                }
                if let Some(installed_as) = installation_name(&child)? {
                    if kind == FileType::Symlink {
                        self.workspace_link(&child, &installed_as, &fd, &leaf)?;
                    } else {
                        self.report.installed_packages_scanned += 1;
                        self.finding(&child, "installed_package_not_directory", "npm installation position is neither a regular directory nor an admitted workspace link")?;
                    }
                    continue;
                }
                if module_container(&child) || scope_container(&child) {
                    self.finding(&child, "installed_tree_link", "npm installation/scope container must be an ordinary directory")?;
                } else if let Some(owner) = &owner {
                    if leaf.ends_with(".node") || (leaf == "binding.gyp" && owner == &path) {
                        self.finding(owner, "native_payload", &format!("Captured installed package contains a native payload/build marker at {child}; explicit review required"))?;
                    }
                    if kind == FileType::Symlink {
                        self.finding(owner, "installed_content_link", "Installed package contains an unverified content link; it was not followed")?;
                    } else if kind != FileType::RegularFile {
                        self.finding(owner, "installed_content_special", "Installed package contains a nonregular payload; it was not opened")?;
                    }
                }
            }
        }
        // Detect ordinary directory replacement/rename while collecting the
        // inventory. Handles are reopened component-by-component, not through
        // named symlink ancestors, and descriptor use stays constant.
        for (path, before) in directories {
            time_remaining(self.capture.deadline)?;
            ensure!(identity(&directory(&self.capture.root, &path)?.metadata()?) == before,
                "installed dependency tree changed during inspection");
        }
        Ok(())
    }
}

/// Check physical presence AND the locked nearest location. A missing private
/// pin must not silently fall through to a compatible but different hoisted
/// copy. Optional absence is allowed; a present wrong optional copy is not.
fn routes(
    manifests: &BTreeMap<String, Value>,
    project: bool,
    actual: &BTreeMap<String, LockedPackage>,
    locked: &BTreeMap<String, LockedPackage>,
    report: &mut DependencyAdmission,
    deadline: Instant,
    edges: &mut usize,
) -> Result<()> {
    for (consumer, manifest) in manifests {
        time_remaining(deadline)?;
        if !project && actual.get(consumer).is_some_and(|package| package.linked) { continue; }
        let empty = Map::new();
        let deps = section(manifest, "dependencies", &empty)?;
        let optional = section(manifest, "optionalDependencies", &empty)?;
        let dev = section(manifest, "devDependencies", &empty)?;
        let peer_meta = section(manifest, "peerDependenciesMeta", &empty)?;
        let source = workspaces::manifest_path(consumer);
        for field in SECTIONS {
            if *field == "devDependencies" && !project { continue; }
            for (installed_as, request) in section(manifest, field, &empty)? {
                time_remaining(deadline)?;
                *edges += 1;
                ensure!(*edges <= MAX_EDGES, "installed dependency edge count exceeds limit");
                name(installed_as)?;
                let request = bounded_text(request, "installed dependency request")?;
                let (package, _) = alias(installed_as, Some(request))?;
                if (*field != "optionalDependencies" && optional.contains_key(installed_as))
                    || (*field == "devDependencies" && deps.contains_key(installed_as))
                    || (*field == "peerDependencies" && (deps.contains_key(installed_as)
                        || (project && dev.contains_key(installed_as)))) { continue; }
                let optional_peer = peer_meta.get(installed_as)
                    .map(|value| flag(value.as_object().context("installed peer metadata must be an object")?, "optional"))
                    .transpose()?.unwrap_or(false);
                let selected = nearest_package(actual, &source, installed_as);
                if selected.is_none() && (*field == "optionalDependencies" || (*field == "peerDependencies" && optional_peer)) { continue; }
                let expected = nearest_package(locked, &source, installed_as);
                let code = if selected.is_none() { Some("missing_installed_dependency") }
                    else if selected.map(|p| &p.path) != expected.map(|p| &p.path) { Some("installed_dependency_route_mismatch") }
                    else { None };
                if let Some(code) = code {
                    report.finding(DependencyFinding {
                        code: code.into(), source: format!("{source}#{field}"), package: package.into(),
                        installed_as: installed_as.clone(), version: Some(request.into()),
                        package_path: expected.map(|package| package.path.clone()),
                        detail: "Required staged dependency is missing or resolves at a different location than the locked nearest installation".into(),
                    })?;
                }
            }
        }
    }
    Ok(())
}

pub(super) fn inspect(
    capture: &mut Capture,
    locked: &BTreeMap<String, LockedPackage>,
    projects: &BTreeMap<String, Value>,
    lock: Option<&Value>,
    report: &mut DependencyAdmission,
) -> Result<()> {
    let mut inspector = Inspector { capture, locked, projects, lock, report,
        actual: BTreeMap::new(), manifests: BTreeMap::new() };
    inspector.walk()?;
    let mut edges = 0;
    routes(projects, true, &inspector.actual, locked, inspector.report, inspector.capture.deadline, &mut edges)?;
    routes(&inspector.manifests, false, &inspector.actual, locked, inspector.report, inspector.capture.deadline, &mut edges)?;
    // Reuse the actual native alias/version/peer checker, with manifest bytes
    // read from the installation rather than trusting the lock's projection.
    let actual_lock = serde_json::json!({"lockfileVersion":3,"packages":inspector.manifests});
    graph::inspect(Some(&actual_lock), &inspector.actual, "captured-installed-manifests", inspector.report, inspector.capture.deadline)?;
    // Recheck every metadata input against its recorded hash after enumeration.
    // This does not recapture or replace the already-verified observations.
    let mut recheck = Capture { root: inspector.capture.root.try_clone()?, deadline: inspector.capture.deadline,
        bytes: 0, inputs: BTreeMap::new() };
    for input in inspector.capture.inputs.values() {
        let limit = if Path::new(&input.path).file_name().is_some_and(|name| name == "package.json") {
            MAX_MANIFEST_BYTES
        } else { MAX_LOCK_BYTES };
        ensure!(recheck.read(&input.path, limit)?.is_some(), "dependency metadata disappeared during installed inspection");
        ensure!(recheck.inputs.get(&input.path) == Some(input), "dependency metadata changed during installed inspection");
    }
    time_remaining(inspector.capture.deadline)?;
    inspector.report.scope = INSTALLED_SCOPE.into();
    inspector.report.installation_checked = true;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::{inspect as metadata, inspect_for_execution};
    use serde_json::json;
    use sha2::{Digest, Sha256};
    use std::fs;
    use std::os::unix::fs::symlink;
    use std::time::Duration;

    fn deadline() -> Instant { Instant::now() + Duration::from_secs(15) }
    fn put(root: &Path, path: &str, bytes: impl AsRef<[u8]>) {
        let path = root.join(path);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, bytes).unwrap();
    }
    fn project(manifest: Value, records: Value) -> tempfile::TempDir {
        let root = tempfile::tempdir().unwrap();
        put(root.path(), "package.json", serde_json::to_vec(&manifest).unwrap());
        put(root.path(), "package-lock.json", serde_json::to_vec(&json!({
            "lockfileVersion":3,"packages":records
        })).unwrap());
        root
    }
    fn package(root: &Path, path: &str, manifest: Value) {
        put(root, &format!("{path}/package.json"), serde_json::to_vec(&manifest).unwrap());
        put(root, &format!("{path}/index.js"), "module.exports=42;\n");
    }
    fn codes(report: &DependencyAdmission) -> Vec<&str> {
        report.findings.iter().map(|finding| finding.code.as_str()).collect()
    }
    fn inspect(root: &Path) -> DependencyAdmission { inspect_for_execution(root, deadline()).unwrap() }
    fn ordinary() -> tempfile::TempDir {
        let root = project(json!({"dependencies":{"a":"^1"}}), json!({
            "node_modules/a":{"version":"1.2.3"}
        }));
        package(root.path(), "node_modules/a", json!({"name":"a","version":"1.2.3"}));
        root
    }

    #[test]
    fn metadata_report_is_distinct_from_installed_execution_admission() {
        let root = project(json!({"dependencies":{"a":"^1"}}), json!({
            "node_modules/a":{"version":"1.2.3"}
        }));
        let only_metadata = metadata(root.path(), deadline()).unwrap();
        assert!(!only_metadata.requires_review());
        assert!(!only_metadata.installation_checked);
        let installed = inspect(root.path());
        assert!(installed.installation_checked);
        assert!(codes(&installed).contains(&"missing_installed_dependency"));
        assert!(!root.path().join("node_modules").exists());
    }

    #[test]
    fn real_manifest_bytes_and_complete_chain_are_bound_without_execution() {
        let root = project(json!({"dependencies":{"a":"^1"}}), json!({
            "node_modules/a":{"version":"1.0.0","dependencies":{"b":"^2"}},
            "node_modules/b":{"version":"2.1.0"}
        }));
        package(root.path(), "node_modules/a", json!({"name":"a","version":"1.0.0","dependencies":{"b":"^2"}}));
        package(root.path(), "node_modules/b", json!({"name":"b","version":"2.1.0"}));
        let report = inspect(root.path());
        assert!(!report.requires_review(), "{report:#?}");
        assert!(report.installation_checked);
        assert_eq!(report.installed_packages_scanned, 2);
        assert_eq!(report.manifests_scanned, 3);
        let input = report.inputs.iter().find(|input| input.path == "node_modules/a/package.json").unwrap();
        let bytes = fs::read(root.path().join(&input.path)).unwrap();
        assert_eq!(input.bytes, bytes.len());
        assert_eq!(input.sha256, hex::encode(Sha256::digest(&bytes)));
        assert!(report.scope.contains("not registry-content authentication"));
        assert_eq!(report, inspect(root.path()));
    }

    #[test]
    fn exact_installed_identity_is_required_even_when_the_requested_range_matches() {
        for manifest in [json!({"name":"other","version":"1.2.3"}),
            json!({"name":"a","version":"1.9.0"}),
            json!({"name":"a","version":"1.2.3+changed"})] {
            let root = ordinary();
            package(root.path(), "node_modules/a", manifest);
            assert!(codes(&inspect(root.path())).contains(&"installed_identity_mismatch"));
        }
    }

    #[test]
    fn missing_private_installation_cannot_fall_through_to_a_hoisted_copy() {
        let root = project(json!({"dependencies":{"a":"1"}}), json!({
            "node_modules/a":{"version":"1.0.0","dependencies":{"b":"2"}},
            "node_modules/a/node_modules/b":{"version":"2.0.0"},
            "node_modules/b":{"version":"2.0.0"}
        }));
        package(root.path(), "node_modules/a", json!({"name":"a","version":"1.0.0","dependencies":{"b":"2"}}));
        package(root.path(), "node_modules/b", json!({"name":"b","version":"2.0.0"}));
        let report = inspect(root.path());
        let finding = report.findings.iter().find(|finding| finding.code == "installed_dependency_route_mismatch").unwrap();
        assert_eq!(finding.package_path.as_deref(), Some("node_modules/a/node_modules/b"));
    }

    #[test]
    fn absent_optional_is_allowed_but_present_optional_is_not_exempt_from_identity_checks() {
        let root = project(json!({"optionalDependencies":{"a":"1"}}), json!({
            "node_modules/a":{"version":"1.0.0","optional":true}
        }));
        assert!(!inspect(root.path()).requires_review());
        package(root.path(), "node_modules/a", json!({"name":"a","version":"1.5.0"}));
        assert!(codes(&inspect(root.path())).contains(&"installed_identity_mismatch"));
    }

    #[test]
    fn transitive_optional_and_optional_peers_may_be_absent_but_required_edges_may_not() {
        for (section_name, optional_peer, expected_missing) in [
            ("optionalDependencies", false, false),
            ("peerDependencies", true, false),
            ("peerDependencies", false, true),
            ("dependencies", false, true),
        ] {
            let mut consumer = json!({"name":"a","version":"1.0.0"});
            consumer[section_name] = json!({"b":"2"});
            if optional_peer { consumer["peerDependenciesMeta"] = json!({"b":{"optional":true}}); }
            let root = project(json!({"dependencies":{"a":"1"}}), json!({
                "node_modules/a":consumer.clone(),"node_modules/b":{"version":"2.0.0"}
            }));
            package(root.path(), "node_modules/a", consumer);
            let report = inspect(root.path());
            assert_eq!(codes(&report).contains(&"missing_installed_dependency"), expected_missing, "{section_name}: {report:#?}");
            assert_eq!(report.requires_review(), expected_missing, "{report:#?}");
        }
    }

    #[test]
    fn actual_dependencies_cannot_be_hidden_by_a_clean_lockfile_projection() {
        let root = ordinary();
        package(root.path(), "node_modules/a", json!({"name":"a","version":"1.2.3","dependencies":{"hidden":"^1"}}));
        let report = inspect(root.path());
        assert!(codes(&report).contains(&"installed_dependency_metadata_mismatch"));
        assert!(codes(&report).contains(&"missing_installed_dependency"));
        assert!(codes(&report).contains(&"unresolved_transitive_dependency"));
    }

    #[test]
    fn installations_under_application_subdirectories_are_not_invisible_shadows() {
        let root = ordinary();
        package(root.path(), "src/node_modules/a", json!({"name":"a","version":"1.2.3"}));
        let report = inspect(root.path());
        assert!(codes(&report).contains(&"unrecorded_installed_package"));
        assert_eq!(report.installed_packages_scanned, 2);
    }

    #[test]
    fn scoped_aliases_bind_the_actual_name_not_the_directory_name() {
        let root = project(json!({"dependencies":{"alias":"npm:@scope/real@^1"}}), json!({
            "node_modules/alias":{"name":"@scope/real","version":"1.0.0"}
        }));
        package(root.path(), "node_modules/alias", json!({"name":"@scope/real","version":"1.0.0"}));
        assert!(!inspect(root.path()).requires_review());
        package(root.path(), "node_modules/alias", json!({"name":"alias","version":"1.0.0"}));
        assert!(codes(&inspect(root.path())).contains(&"installed_identity_mismatch"));
    }

    #[test]
    fn legacy_aliases_and_requires_are_bound_to_real_manifests() {
        let root = project(json!({"dependencies":{"alias":"npm:real@1"}}), json!({}));
        put(root.path(), "package-lock.json", serde_json::to_vec(&json!({
            "lockfileVersion":1,"dependencies":{
                "alias":{"version":"npm:real@1.0.0","requires":{"b":"2"}},
                "b":{"version":"2.0.0"}
            }
        })).unwrap());
        package(root.path(), "node_modules/alias", json!({"name":"real","version":"1.0.0","dependencies":{"b":"2"}}));
        package(root.path(), "node_modules/b", json!({"name":"b","version":"2.0.0"}));
        assert!(!inspect(root.path()).requires_review());
    }

    #[test]
    fn lifecycle_scripts_and_native_markers_are_read_from_the_installation() {
        for (manifest, marker, expected) in [
            (json!({"name":"a","version":"1.2.3","scripts":{"postinstall":"do-not-run-secret-command"}}), None, "install_script"),
            (json!({"name":"a","version":"1.2.3","gypfile":true}), None, "native_build"),
            (json!({"name":"a","version":"1.2.3"}), Some("binding.gyp"), "native_payload"),
            (json!({"name":"a","version":"1.2.3"}), Some("build/Release/custom.node"), "native_payload"),
        ] {
            let root = ordinary();
            package(root.path(), "node_modules/a", manifest);
            if let Some(marker) = marker { put(root.path(), &format!("node_modules/a/{marker}"), b"fixture marker, never execute"); }
            let report = inspect(root.path());
            assert!(codes(&report).contains(&expected), "{report:#?}");
            assert!(!serde_json::to_string(&report).unwrap().contains("do-not-run-secret-command"));
        }
    }

    #[test]
    fn ordinary_workspace_links_require_the_exact_metadata_bound_physical_target() {
        for target in ["../packages/local", "../packages/other"] {
            let root = project(json!({"name":"root","workspaces":["packages/local"],"dependencies":{"local":"1"}}), json!({
                "node_modules/local":{"link":true,"resolved":"packages/local"},
                "packages/local":{"name":"local","version":"1.0.0"}
            }));
            package(root.path(), "packages/local", json!({"name":"local","version":"1.0.0"}));
            package(root.path(), "packages/other", json!({"name":"local","version":"1.0.0"}));
            fs::create_dir(root.path().join("node_modules")).unwrap();
            symlink(target, root.path().join("node_modules/local")).unwrap();
            let result = inspect_for_execution(root.path(), deadline());
            if target.ends_with("/local") {
                let report = result.unwrap();
                assert!(!report.requires_review(), "{report:#?}");
                assert_eq!(report.installed_packages_scanned, 1);
                assert_eq!(report.manifests_scanned, 2);
            } else { assert!(result.unwrap_err().to_string().contains("differs from its captured target")); }
        }
    }

    #[test]
    fn linked_containers_and_package_contents_are_not_followed() {
        let external = tempfile::tempdir().unwrap();
        package(external.path(), "a", json!({"name":"a","version":"1.2.3"}));
        let root = project(json!({"dependencies":{"a":"1"}}), json!({"node_modules/a":{"version":"1.2.3"}}));
        symlink(external.path(), root.path().join("node_modules")).unwrap();
        let report = inspect(root.path());
        assert!(codes(&report).contains(&"installed_tree_link"));
        assert!(report.inputs.iter().all(|input| !input.path.starts_with("node_modules/")));
        let root = ordinary();
        symlink(external.path(), root.path().join("node_modules/a/linked-content")).unwrap();
        assert!(codes(&inspect(root.path())).contains(&"installed_content_link"));
    }

    #[test]
    fn installed_manifest_symlinks_special_files_and_ambiguous_json_fail_closed() {
        for raw in [r#"{"name":"a","version":"1.2.3","version":"1.9.0"}"#,
            r#"{"name":"a","version":"1.2.3","dependencies":{"b":"1","\u0062":"2"}}"#] {
            let root = ordinary();
            put(root.path(), "node_modules/a/package.json", raw);
            assert!(inspect_for_execution(root.path(), deadline()).is_err());
        }
        let root = project(json!({"dependencies":{"a":"1"}}), json!({"node_modules/a":{"version":"1.2.3"}}));
        fs::create_dir_all(root.path().join("node_modules/a")).unwrap();
        put(root.path(), "manifest.json", r#"{"name":"a","version":"1.2.3"}"#);
        symlink("../../manifest.json", root.path().join("node_modules/a/package.json")).unwrap();
        assert!(inspect_for_execution(root.path(), deadline()).is_err());
        let root = project(json!({"dependencies":{"a":"1"}}), json!({"node_modules/a":{"version":"1.2.3"}}));
        fs::create_dir_all(root.path().join("node_modules/a/package.json")).unwrap();
        assert!(inspect_for_execution(root.path(), deadline()).is_err());
    }

    #[test]
    fn project_development_dependencies_are_required_but_transitive_development_is_not_installed() {
        let root = project(json!({"devDependencies":{"a":"1"}}), json!({"node_modules/a":{"version":"1.2.3","dev":true}}));
        assert!(codes(&inspect(root.path())).contains(&"missing_installed_dependency"));
        package(root.path(), "node_modules/a", json!({"name":"a","version":"1.2.3","devDependencies":{"test-only":"1"}}));
        assert!(!inspect(root.path()).requires_review());
    }

    #[test]
    fn npm_bin_shims_and_hidden_lock_are_not_packages_or_authority() {
        let root = ordinary();
        fs::create_dir(root.path().join("node_modules/.bin")).unwrap();
        symlink("../a/index.js", root.path().join("node_modules/.bin/a")).unwrap();
        put(root.path(), "node_modules/.package-lock.json", b"not a trusted authority");
        assert!(!inspect(root.path()).requires_review());
        put(root.path(), "node_modules/rogue.js", "throw new Error('never run');");
        assert!(codes(&inspect(root.path())).contains(&"installed_package_not_directory"));
    }

    #[test]
    fn workspace_link_normalization_never_erases_unverified_intermediate_traversal() {
        assert_eq!(workspace_target("node_modules/local", "../packages/local").unwrap(), "packages/local");
        assert_eq!(workspace_target("node_modules/@s/local", "../../packages/local").unwrap(), "packages/local");
        for target in ["/packages/local", "../../outside", "../alias/../packages/local", "../packages//local", "../packages/./local", "../packages\\local"] {
            assert!(workspace_target("node_modules/local", target).is_err(), "{target}");
        }
    }

    #[test]
    fn resource_limits_are_errors_not_partial_installed_approvals() {
        let mut budget = TreeBudget { entries: MAX_TREE_ENTRIES - 1, ..TreeBudget::default() };
        assert!(budget.entry("a").is_ok());
        assert!(budget.entry("b").is_err());
        let mut budget = TreeBudget { path_bytes: MAX_TREE_PATH_BYTES, ..TreeBudget::default() };
        assert!(budget.entry("a").is_err());
        let mut budget = TreeBudget { directories: MAX_TREE_DIRECTORIES, ..TreeBudget::default() };
        assert!(budget.directory(1).is_err());
        assert!(TreeBudget::default().directory(MAX_DEPTH + 1).is_err());
        let root = ordinary();
        assert!(inspect_for_execution(root.path(), Instant::now()).is_err());
        put(root.path(), "node_modules/a/package.json", vec![b' '; MAX_MANIFEST_BYTES + 1]);
        assert!(inspect_for_execution(root.path(), deadline()).is_err());
    }

    #[test]
    fn historical_metadata_reports_never_deserialize_as_checked_installations() {
        let report: DependencyAdmission = serde_json::from_value(json!({
            "schema_version":"franken-node/native-dependency-admission/v1","scope":"metadata only",
            "packages_scanned":1,"manifests_scanned":1,"inputs":[],"findings":[]
        })).unwrap();
        assert!(!report.installation_checked);
        assert_eq!(report.installed_packages_scanned, 0);
    }
}
