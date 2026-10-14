//! Bind Bun's project-local isolated layout to the already admitted lock graph.
//!
//! Store directory labels are not package identities. We follow the captured
//! installation links logically, then feed a physical-path projection into the
//! SAME installed-manifest, lifecycle, native-payload and dependency checks as
//! hoisted installs. No source is executed and no filesystem symlink is opened.
//! Spec: https://bun.com/docs/pm/isolated-installs
//!
//! Global stores, chained links and unreferenced store payloads are not admitted.
//! A matching manifest is not archive SRI or publisher authentication.

use super::{
    Capture, DependencyAdmission, DependencyFinding, LockedPackage, MAX_DEPTH,
    MAX_EDGES, MAX_PACKAGES, TreeBudget, declaration_selection, directory, identity,
    installation_name, lock_record, nearest_package, relative, time_remaining,
    workspace_target, workspaces,
};
use super::super::{MAX_METADATA_BYTES, MetadataInput};
use anyhow::{Context, Result, ensure};
use rustix::fs::{AtFlags, Dir, FileType, Mode, OFlags, openat, readlinkat_raw, statat};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::fs::File;
use std::time::Instant;

pub(super) const STORE: &str = "node_modules/.bun";
pub(super) const SCOPE: &str = "captured Bun text-lock metadata and project-local isolated installation: physical package identities, dependency routes, link text and native/lifecycle markers; not registry-content authentication, archive SRI verification, a global-store grant, a sandbox or runtime compatibility proof";
const MAX_LINK_BYTES: usize = 4096;
type FileIdentity = (u64, u64, u64, u32, i64, i64, i64, i64);

struct Link {
    text: String,
    target: String,
}

#[derive(Clone, Copy)]
enum ContainerKind { Store, Modules, Scope }

#[derive(Default)]
struct Shape {
    ordinary: BTreeSet<String>,
    occupied: BTreeSet<String>,
    links: BTreeMap<String, Link>,
    directories: BTreeMap<String, FileIdentity>,
    budget: TreeBudget,
}

fn link_text(root: &File, path: &str) -> Result<String> {
    let (parent, leaf) = path.rsplit_once('/').context("isolated link has no parent")?;
    let parent = directory(root, parent)?;
    let mut bytes = [0_u8; MAX_LINK_BYTES + 1];
    let count = readlinkat_raw(&parent, leaf, &mut bytes[..])?;
    ensure!(count <= MAX_LINK_BYTES, "isolated link text exceeds its byte limit");
    Ok(std::str::from_utf8(&bytes[..count]).context("isolated link must be UTF-8")?.into())
}

impl Shape {
    /// Enumerate installation containers, not package payloads. The existing
    /// full installed-tree walk still inspects every ordinary payload later.
    fn capture(capture: &Capture, projects: &BTreeMap<String, Value>) -> Result<Self> {
        let mut shape = Self::default();
        let mut pending = vec![(STORE.to_owned(), ContainerKind::Store, true)];
        for project in projects.keys() {
            let modules = if project.is_empty() { "node_modules".into() }
                else { format!("{project}/node_modules") };
            pending.push((modules, ContainerKind::Modules, false));
        }
        let mut seen = BTreeSet::new();
        while let Some((path, kind, required)) = pending.pop() {
            time_remaining(capture.deadline)?;
            if !seen.insert(path.clone()) { continue; }
            relative(&path)?;
            shape.budget.directory(path.split('/').count())?;
            let (parent, leaf) = path.rsplit_once('/').unwrap_or(("", path.as_str()));
            let parent = directory(&capture.root, parent)?;
            let fd = match openat(&parent, leaf,
                OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::empty()) {
                Ok(fd) => File::from(fd),
                Err(rustix::io::Errno::NOENT) if !required => continue,
                Err(error) => return Err(error).context("isolated installation container is not an ordinary captured directory"),
            };
            let before = identity(&fd.metadata()?);
            let mut entries = BTreeMap::new();
            for entry in Dir::read_from(&fd)? {
                time_remaining(capture.deadline)?;
                let entry = entry?;
                let leaf = entry.file_name().to_str().context("isolated installation name must be UTF-8")?;
                if matches!(leaf, "." | "..") { continue; }
                let child = format!("{path}/{leaf}");
                relative(&child)?;
                shape.budget.entry(&child)?;
                let stat = statat(&fd, entry.file_name(), AtFlags::SYMLINK_NOFOLLOW)?;
                ensure!(entries.insert(child, (leaf.to_owned(), FileType::from_raw_mode(stat.st_mode))).is_none(),
                    "isolated directory changed during enumeration");
            }
            ensure!(identity(&fd.metadata()?) == before, "isolated directory changed during enumeration");
            shape.directories.insert(path.clone(), before);
            for (child, (leaf, file_type)) in entries.into_iter().rev() {
                if matches!(kind, ContainerKind::Store) {
                    ensure!(file_type == FileType::Directory,
                        "isolated store entries must be project-local ordinary directories, not global-store links");
                    let modules = if leaf == "node_modules" { child } else { format!("{child}/node_modules") };
                    pending.push((modules, ContainerKind::Modules, true));
                    continue;
                }
                if child == STORE { continue; }
                if matches!(kind, ContainerKind::Modules) {
                    if (leaf == ".bin" && file_type == FileType::Directory)
                        || (leaf == ".package-lock.json" && file_type == FileType::RegularFile) { continue; }
                    if leaf.starts_with('@') {
                        ensure!(file_type == FileType::Directory, "isolated package scope cannot be linked or nonregular");
                        pending.push((child, ContainerKind::Scope, true));
                        continue;
                    }
                }
                installation_name(&child)?.context("invalid isolated installation position")?;
                ensure!(shape.occupied.insert(child.clone()), "duplicate isolated installation position");
                ensure!(shape.occupied.len() <= MAX_PACKAGES, "isolated installation position limit exceeded");
                match file_type {
                    FileType::Directory => {
                        shape.ordinary.insert(child.clone());
                        pending.push((format!("{child}/node_modules"), ContainerKind::Modules, false));
                    }
                    FileType::Symlink => {
                        let text = link_text(&capture.root, &child)?;
                        let target = workspace_target(&child, &text)?;
                        ensure!(target.split('/').count() <= MAX_DEPTH, "isolated link target depth exceeded");
                        shape.budget.entry(&text)?;
                        shape.budget.entry(&target)?;
                        shape.links.insert(child, Link { text, target });
                    }
                    _ => {} // Retain the occupied slot; it must not be skipped for an outer copy.
                }
            }
        }
        Ok(shape)
    }

    fn resolve(&self, start: &str, package: &str, projects: &BTreeMap<String, Value>) -> Result<Option<(String, String)>> {
        let mut parent = start;
        loop {
            if parent.rsplit('/').next() != Some("node_modules") {
                let slot = if parent.is_empty() { format!("node_modules/{package}") }
                    else { format!("{parent}/node_modules/{package}") };
                if self.occupied.contains(&slot) {
                    if self.ordinary.contains(&slot) { return Ok(Some((slot.clone(), slot))); }
                    let link = self.links.get(&slot).context("nearest isolated installation is nonregular")?;
                    ensure!(!self.links.contains_key(&link.target), "chained isolated installation links are unsupported");
                    ensure!(self.ordinary.contains(&link.target)
                        || (!link.target.is_empty() && projects.contains_key(&link.target)),
                        "isolated link does not select a captured package or selected workspace");
                    return Ok(Some((slot, link.target.clone())));
                }
            }
            if parent.is_empty() { return Ok(None); }
            parent = parent.rsplit_once('/').map_or("", |(parent, _)| parent);
        }
    }
}

pub(super) struct Layout {
    pub(super) packages: BTreeMap<String, LockedPackage>,
    pub(super) lock: Value,
    shape: Shape,
    registry_aliases: BTreeMap<String, String>,
}

fn pin_at(pin: &LockedPackage, physical: &str, linked: bool) -> LockedPackage {
    LockedPackage {
        name: pin.name.clone(), installed_as: pin.installed_as.clone(), version: pin.version.clone(),
        path: physical.into(), install: pin.install, linked, unresolved: pin.unresolved,
    }
}

fn insert_pin(packages: &mut BTreeMap<String, LockedPackage>, slot: &str,
    pin: &LockedPackage, physical: &str, linked: bool, bytes: &mut usize) -> Result<()> {
    // Alias fan-out must not multiply a large version/name into unbounded
    // retained strings. Account before cloning, including concrete versions.
    *bytes = bytes.checked_add(slot.len() + physical.len() + pin.name.len()
        + pin.installed_as.len() + pin.version.as_ref().map_or(0, String::len))
        .context("isolated projected identity overflow")?;
    ensure!(*bytes <= super::MAX_TREE_PATH_BYTES && packages.len() < MAX_PACKAGES,
        "isolated projected identity budget exceeded");
    ensure!(packages.insert(slot.into(), pin_at(pin, physical, linked)).is_none(),
        "duplicate isolated projected installation");
    Ok(())
}

struct Binding<'a> {
    shape: &'a Shape,
    locked: &'a BTreeMap<String, LockedPackage>,
    projects: &'a BTreeMap<String, Value>,
    lock: &'a Value,
    report: &'a mut DependencyAdmission,
    deadline: Instant,
    physical: BTreeMap<String, String>,
    names: BTreeMap<String, BTreeSet<String>>,
    registry_slots: BTreeMap<String, String>,
    workspace_slots: BTreeMap<String, (String, String)>,
    pending: VecDeque<(String, String, bool)>,
    scheduled: BTreeSet<(String, String, bool)>,
    scheduled_path_bytes: usize,
}

impl Binding<'_> {
    fn enqueue(&mut self, logical: String, physical: String, project: bool) -> Result<()> {
        let key = (logical, physical, project);
        if self.scheduled.contains(&key) { return Ok(()); }
        self.scheduled_path_bytes = self.scheduled_path_bytes.checked_add(key.0.len() + key.1.len())
            .context("isolated context byte count overflow")?;
        ensure!(self.scheduled.len() < MAX_PACKAGES
            && self.scheduled_path_bytes <= super::MAX_TREE_PATH_BYTES,
            "isolated dependency context limit exceeded");
        self.scheduled.insert(key.clone());
        self.pending.push_back(key);
        Ok(())
    }

    fn finding(&mut self, source: &str, package: &str, code: &str, detail: &str) -> Result<()> {
        self.report.finding(DependencyFinding {
            code: code.into(), source: workspaces::manifest_path(source),
            package: package.into(), installed_as: package.into(),
            package_path: None, version: None, detail: detail.into(),
        })
    }

    fn bind(&mut self, expected: &LockedPackage, slot: String, physical: String) -> Result<()> {
        if expected.linked {
            let target = lock_record(Some(self.lock), &expected.path)
                .and_then(|record| record.get("resolved")).and_then(Value::as_str);
            if target != Some(physical.as_str()) || !self.projects.contains_key(&physical)
                || !self.shape.links.contains_key(&slot) {
                return self.finding(&slot, &expected.name, "isolated_workspace_mismatch",
                    "Isolated workspace link differs from the independently selected, manifest-bound target");
            }
            self.workspace_slots.insert(slot, (expected.path.clone(), physical));
            return Ok(());
        }
        if !self.shape.ordinary.contains(&physical)
            || (slot != physical && !physical.starts_with(&format!("{STORE}/"))) {
            return self.finding(&slot, &expected.name, "isolated_package_target",
                "Registry installation link must select an ordinary package in the project-local Bun store");
        }
        if let Some(previous) = self.physical.get(&physical) {
            ensure!(lock_record(Some(self.lock), previous) == lock_record(Some(self.lock), &expected.path),
                "one isolated physical package cannot satisfy conflicting locked identities or dependency contexts");
        } else {
            self.physical.insert(physical.clone(), expected.path.clone());
        }
        self.names.entry(physical.clone()).or_default().extend([
            expected.name.clone(), expected.installed_as.clone(),
        ]);
        self.registry_slots.insert(slot, physical.clone());
        self.enqueue(expected.path.clone(), physical, false)
    }

    fn bind_graph(&mut self) -> Result<()> {
        let projects = self.projects;
        let locked = self.locked;
        let lock = self.lock;
        let shape = self.shape;
        for source in projects.keys() {
            self.enqueue(source.clone(), source.clone(), true)?;
        }
        // A selected workspace's canonical root link is mandatory even when
        // no root declaration imports it. Source selection remains independent.
        for expected in locked.values().filter(|package| package.linked) {
            time_remaining(self.deadline)?;
            match shape.resolve("", &expected.installed_as, projects)? {
                Some((slot, physical)) => self.bind(expected, slot, physical)?,
                None => self.finding("", &expected.name, "missing_installed_dependency",
                    "Selected workspace has no physical root installation link")?,
            }
        }
        let mut edges = 0;
        while let Some((logical, physical, project)) = self.pending.pop_front() {
            time_remaining(self.deadline)?;
            let manifest = if project { projects.get(&logical) }
                else { lock_record(Some(lock), &logical) }.context("isolated consumer has no captured metadata")?;
            let source = workspaces::manifest_path(&logical);
            for edge in declaration_selection::select(manifest, project, self.deadline, &mut edges, MAX_EDGES)? {
                let found = shape.resolve(&physical, edge.installed_as, projects)?;
                if found.is_none() && edge.optional { continue; }
                let expected = nearest_package(locked, &source, edge.installed_as);
                let Some((slot, target)) = found else {
                    self.finding(&physical, edge.package, "missing_installed_dependency",
                        "Required isolated dependency has no physical installation")?;
                    continue;
                };
                let Some(expected) = expected else {
                    self.finding(&physical, edge.package, "unrecorded_isolated_dependency",
                        "Present isolated dependency has no selected lockfile pin")?;
                    continue;
                };
                // A peer belongs beside/above its consumer, not inside it.
                if !project && edge.section == "peerDependencies"
                    && slot.starts_with(&format!("{physical}/node_modules/")) {
                    self.finding(&physical, edge.package, "invalid_peer_placement",
                        "Isolated peer is shadowed inside its consumer")?;
                }
                self.bind(expected, slot, target)?;
            }
        }
        // Bun's store fallback and public-hoist aliases may expose an already
        // bound package, but cannot introduce a new identity or source grant.
        for (slot, link) in &shape.links {
            time_remaining(self.deadline)?;
            if self.registry_slots.contains_key(slot) || self.workspace_slots.contains_key(slot) { continue; }
            let installed_as = installation_name(slot)?.context("isolated link is not an installation")?;
            if link.target.starts_with(&format!("{STORE}/"))
                && self.names.get(&link.target).is_some_and(|names| names.contains(&installed_as)) {
                self.registry_slots.insert(slot.clone(), link.target.clone());
            } else if let Some(manifest) = projects.get(&link.target)
                && manifest.get("name").and_then(Value::as_str) == Some(installed_as.as_str()) {
                let canonical = format!("node_modules/{installed_as}");
                if self.workspace_slots.contains_key(&canonical) {
                    self.workspace_slots.insert(slot.clone(), (canonical, link.target.clone()));
                } else {
                    self.finding(slot, &installed_as, "unrecorded_isolated_link",
                        "Workspace alias has no verified canonical installation")?;
                }
            } else {
                self.finding(slot, &installed_as, "unrecorded_isolated_link",
                    "Isolated link targets unbound code or changes its admitted installation name")?;
            }
        }
        Ok(())
    }
}

impl Layout {
    pub(super) fn capture(capture: &Capture, locked: &BTreeMap<String, LockedPackage>,
        projects: &BTreeMap<String, Value>, lock: Option<&Value>, report: &mut DependencyAdmission) -> Result<Option<Self>> {
        // Only the selected raw Bun lock grants this layout interpretation.
        // An npm project cannot opt in merely by creating a .bun directory.
        if !capture.inputs.contains_key("bun.lock") { return Ok(None); }
        time_remaining(capture.deadline)?;
        let modules = match openat(&capture.root, "node_modules",
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC, Mode::empty()) {
            Ok(fd) => fd,
            Err(rustix::io::Errno::NOENT) => return Ok(None),
            Err(error) => return Err(error).context("Bun node_modules must be an ordinary directory"),
        };
        match statat(&modules, ".bun", AtFlags::SYMLINK_NOFOLLOW) {
            Err(rustix::io::Errno::NOENT) => return Ok(None),
            Err(error) => return Err(error).context("inspect Bun installation store"),
            Ok(stat) => ensure!(FileType::from_raw_mode(stat.st_mode) == FileType::Directory,
                "Bun store must be a project-local ordinary directory"),
        }
        let lock = lock.context("isolated layout requires a captured Bun graph")?;
        let shape = Shape::capture(capture, projects)?;
        let mut binding = Binding {
            shape: &shape, locked, projects, lock, report, deadline: capture.deadline,
            physical: BTreeMap::new(), names: BTreeMap::new(), registry_slots: BTreeMap::new(),
            workspace_slots: BTreeMap::new(), pending: VecDeque::new(),
            scheduled: BTreeSet::new(), scheduled_path_bytes: 0,
        };
        binding.bind_graph()?;
        let mut packages = BTreeMap::new();
        let mut records = Map::new();
        let mut bytes = 0_usize;
        let mut identity_bytes = 0_usize;
        for (physical, logical) in &binding.physical {
            time_remaining(capture.deadline)?;
            let record = lock_record(Some(lock), logical).context("missing isolated pin")?.clone();
            bytes = bytes.checked_add(serde_json::to_vec(&record)?.len()).context("isolated projection overflow")?;
            ensure!(bytes <= MAX_METADATA_BYTES, "isolated projection exceeds metadata budget");
            insert_pin(&mut packages, physical, &locked[logical], physical, false, &mut identity_bytes)?;
            records.insert(physical.clone(), record);
        }
        let mut registry_aliases = BTreeMap::new();
        for (slot, physical) in &binding.registry_slots {
            time_remaining(capture.deadline)?;
            if slot == physical { continue; }
            let logical = binding.physical.get(physical).context("unbound isolated alias")?;
            insert_pin(&mut packages, slot, &locked[logical], physical, false, &mut identity_bytes)?;
            registry_aliases.insert(slot.clone(), physical.clone());
        }
        for (slot, (logical, target)) in &binding.workspace_slots {
            time_remaining(capture.deadline)?;
            insert_pin(&mut packages, slot, &locked[logical], slot, true, &mut identity_bytes)?;
            records.insert(slot.clone(), serde_json::json!({"link":true,"resolved":target}));
        }
        time_remaining(capture.deadline)?;
        drop(binding);
        Ok(Some(Self { packages, lock: serde_json::json!({"lockfileVersion":3,"packages":records}), shape, registry_aliases }))
    }

    pub(super) fn is_registry_alias(&self, path: &str) -> bool { self.registry_aliases.contains_key(path) }

    /// Alias positions share the already inspected physical record. Its path
    /// stays physical, so transitive lookups never restart at a lexical alias.
    pub(super) fn populate_aliases(&self, actual: &mut BTreeMap<String, LockedPackage>, deadline: Instant) -> Result<()> {
        for (slot, physical) in &self.registry_aliases {
            time_remaining(deadline)?;
            let Some(pin) = actual.get(physical) else { continue; };
            let expected = self.packages.get(physical).context("isolated physical expectation missing")?;
            // Mismatches already produced an installed-identity finding. Do
            // not fan out attacker-controlled oversized identity strings.
            if pin.name != expected.name || pin.version != expected.version { continue; }
            let pin = pin_at(pin, physical, false);
            ensure!(actual.len() < MAX_PACKAGES && !actual.contains_key(slot),
                "isolated alias changed kind or exceeds installation limit");
            actual.insert(slot.clone(), pin);
        }
        Ok(())
    }

    pub(super) fn recheck_and_record(&self, capture: &mut Capture) -> Result<()> {
        for (path, before) in &self.shape.directories {
            time_remaining(capture.deadline)?;
            ensure!(identity(&directory(&capture.root, path)?.metadata()?) == *before,
                "isolated installation directory changed during inspection");
        }
        for (path, link) in &self.shape.links {
            time_remaining(capture.deadline)?;
            ensure!(link_text(&capture.root, path)? == link.text,
                "isolated installation link changed during inspection");
            // MetadataInput at a link position fingerprints the link TEXT,
            // not target-file bytes. No verifier may treat it as archive SRI.
            capture.bytes = capture.bytes.checked_add(link.text.len()).context("isolated link budget overflow")?;
            ensure!(capture.bytes <= MAX_METADATA_BYTES, "isolated link inputs exceed metadata budget");
            ensure!(capture.inputs.insert(path.clone(), MetadataInput {
                path: path.clone(), bytes: link.text.len(), sha256: hex::encode(Sha256::digest(link.text.as_bytes())),
            }).is_none(), "duplicate isolated input path");
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::super::{inspect, inspect_for_execution};
    use serde_json::json;
    use std::fs;
    use std::os::unix::fs::symlink;
    use std::path::Path;
    use std::time::Duration;

    fn deadline() -> Instant { Instant::now() + Duration::from_secs(15) }
    fn put(root: &Path, path: &str, bytes: impl AsRef<[u8]>) {
        let path = root.join(path);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, bytes).unwrap();
    }
    fn link(root: &Path, path: &str, target: &str) {
        fs::create_dir_all(root.join(path).parent().unwrap()).unwrap();
        symlink(target, root.join(path)).unwrap();
    }
    fn tuple(name: &str, metadata: Value) -> Value { json!([name, "", metadata, ""]) }
    fn fixture(manifest: Value, packages: Value) -> tempfile::TempDir {
        let root = tempfile::tempdir().unwrap();
        put(root.path(), "package.json", serde_json::to_vec(&manifest).unwrap());
        put(root.path(), "bun.lock", serde_json::to_vec(&json!({
            "lockfileVersion":2, "configVersion":1, "workspaces":{"":manifest}, "packages":packages,
        })).unwrap());
        root
    }
    fn store(root: &Path, label: &str, package: &str, version: &str, mut metadata: Value) -> String {
        let path = format!("{STORE}/{label}/node_modules/{package}");
        metadata["name"] = package.into();
        metadata["version"] = version.into();
        put(root, &format!("{path}/package.json"), serde_json::to_vec(&metadata).unwrap());
        put(root, &format!("{path}/index.js"), "throw Error('inspection must never execute this source');");
        path
    }
    fn ordinary() -> tempfile::TempDir {
        let root = fixture(json!({"dependencies":{"a":"1"}}), json!({
            "a":tuple("a@1.0.0",json!({"dependencies":{"b":"2"}})),
            "b":tuple("b@2.0.0",json!({})),
        }));
        store(root.path(), "a@1.0.0", "a", "1.0.0", json!({"dependencies":{"b":"2"}}));
        store(root.path(), "b@2.0.0", "b", "2.0.0", json!({}));
        link(root.path(), "node_modules/a", ".bun/a@1.0.0/node_modules/a");
        link(root.path(), "node_modules/.bun/a@1.0.0/node_modules/b", "../../b@2.0.0/node_modules/b");
        link(root.path(), "node_modules/.bun/node_modules/b", "../b@2.0.0/node_modules/b");
        root
    }
    fn checked(root: &Path) -> DependencyAdmission { inspect_for_execution(root, deadline()).unwrap() }

    #[test]
    fn isolated_chain_uses_shared_installed_checks_and_fingerprints_link_text() {
        let root = ordinary();
        let metadata = inspect(root.path(), deadline()).unwrap();
        assert!(!metadata.requires_review());
        assert!(!metadata.installation_checked);
        let report = checked(root.path());
        assert!(!report.requires_review(), "{report:#?}");
        assert!(report.installation_checked);
        assert!(report.scope.contains("isolated"));
        assert_eq!(report.manifests_scanned, 3); // Source manifests, not alias copies.
        let input = report.inputs.iter().find(|input| input.path == "node_modules/a").unwrap();
        let text = ".bun/a@1.0.0/node_modules/a";
        assert_eq!(input.bytes, text.len());
        assert_eq!(input.sha256, hex::encode(Sha256::digest(text.as_bytes())));
        assert!(!serde_json::to_string(&report).unwrap().contains("inspection must never execute"));
        assert_eq!(report, checked(root.path()));
    }

    #[test]
    fn actual_store_identity_is_checked_instead_of_trusting_the_directory_label() {
        for (name, version) in [("b", "2.9.0"), ("wrong", "2.0.0")] {
            let root = ordinary();
            put(root.path(), "node_modules/.bun/b@2.0.0/node_modules/b/package.json",
                serde_json::to_vec(&json!({"name":name,"version":version})).unwrap());
            let report = checked(root.path());
            assert!(report.findings.iter().any(|finding| finding.code == "installed_identity_mismatch"));
        }
    }

    #[test]
    fn isolated_aliases_keep_the_actual_scoped_name_and_physical_module_context() {
        let root = fixture(json!({"dependencies":{"alias":"npm:@s/real@1"}}), json!({
            "alias":tuple("@s/real@1.0.0",json!({"dependencies":{"b":"2"}})),
            "b":tuple("b@2.0.0",json!({})),
        }));
        store(root.path(), "@s+real@1.0.0", "@s/real", "1.0.0", json!({"dependencies":{"b":"2"}}));
        store(root.path(), "b@2.0.0", "b", "2.0.0", json!({}));
        link(root.path(), "node_modules/alias", ".bun/@s+real@1.0.0/node_modules/@s/real");
        link(root.path(), "node_modules/.bun/@s+real@1.0.0/node_modules/b", "../../b@2.0.0/node_modules/b");
        let report = checked(root.path());
        assert!(!report.requires_review(), "{report:#?}");
        assert_eq!(report.manifests_scanned, 3);
    }

    #[test]
    fn isolated_cycles_share_physical_records_without_recursive_graph_expansion() {
        let root = fixture(json!({"dependencies":{"a":"1"}}), json!({
            "a":tuple("a@1.0.0",json!({"dependencies":{"b":"1"}})),
            "b":tuple("b@1.0.0",json!({"dependencies":{"a":"1"}})),
        }));
        store(root.path(), "a@1.0.0", "a", "1.0.0", json!({"dependencies":{"b":"1"}}));
        store(root.path(), "b@1.0.0", "b", "1.0.0", json!({"dependencies":{"a":"1"}}));
        link(root.path(), "node_modules/a", ".bun/a@1.0.0/node_modules/a");
        link(root.path(), "node_modules/.bun/a@1.0.0/node_modules/b", "../../b@1.0.0/node_modules/b");
        link(root.path(), "node_modules/.bun/b@1.0.0/node_modules/a", "../../a@1.0.0/node_modules/a");
        let report = checked(root.path());
        assert!(!report.requires_review(), "{report:#?}");
        assert_eq!(report.manifests_scanned, 3);
    }

    #[test]
    fn isolated_optional_absence_does_not_exempt_present_wrong_code() {
        let root = fixture(json!({"dependencies":{"a":"1"}}), json!({
            "a":tuple("a@1.0.0",json!({"optionalDependencies":{"b":"2"}})),
            "b":tuple("b@2.0.0",json!({})),
        }));
        store(root.path(), "a@1.0.0", "a", "1.0.0", json!({"optionalDependencies":{"b":"2"}}));
        link(root.path(), "node_modules/a", ".bun/a@1.0.0/node_modules/a");
        assert!(!checked(root.path()).requires_review());
        store(root.path(), "b@2.0.0", "b", "2.1.0", json!({}));
        link(root.path(), "node_modules/.bun/a@1.0.0/node_modules/b", "../../b@2.0.0/node_modules/b");
        assert!(checked(root.path()).requires_review());
    }

    #[test]
    fn isolated_layout_never_bypasses_native_lifecycle_or_hidden_dependency_checks() {
        for (metadata, marker, code) in [
            (json!({"scripts":{"postinstall":"do-not-run-private-command"}}), None, "install_script"),
            (json!({"dependencies":{"hidden":"1"}}), None, "installed_dependency_metadata_mismatch"),
            (json!({}), Some("build/native.node"), "native_payload"),
        ] {
            let root = ordinary();
            let path = store(root.path(), "b@2.0.0", "b", "2.0.0", metadata);
            if let Some(marker) = marker { put(root.path(), &format!("{path}/{marker}"), b"not executable"); }
            let report = checked(root.path());
            assert!(report.findings.iter().any(|finding| finding.code == code), "{report:#?}");
            assert!(!serde_json::to_string(&report).unwrap().contains("do-not-run-private-command"));
        }
    }

    #[test]
    fn global_stores_and_external_registry_links_are_refused_without_following_them() {
        let outside = tempfile::tempdir().unwrap();
        put(outside.path(), "package.json", b"private invalid JSON must never be parsed");
        let root = fixture(json!({"dependencies":{"a":"1"}}), json!({"a":tuple("a@1.0.0",json!({}))}));
        fs::create_dir(root.path().join("node_modules")).unwrap();
        symlink(outside.path(), root.path().join(STORE)).unwrap();
        assert!(inspect_for_execution(root.path(), deadline()).unwrap_err().to_string().contains("project-local"));
        let root = fixture(json!({"dependencies":{"a":"1"}}), json!({"a":tuple("a@1.0.0",json!({}))}));
        fs::create_dir_all(root.path().join(STORE)).unwrap();
        symlink(outside.path(), root.path().join("node_modules/a")).unwrap();
        assert!(inspect_for_execution(root.path(), deadline()).is_err());
    }

    #[test]
    fn stale_unreferenced_store_payloads_and_unbound_aliases_require_review() {
        let root = ordinary();
        store(root.path(), "extra@1.0.0", "extra", "1.0.0", json!({}));
        link(root.path(), "node_modules/extra", ".bun/extra@1.0.0/node_modules/extra");
        let report = checked(root.path());
        assert!(report.findings.iter().any(|finding| finding.code == "unrecorded_isolated_link"));
        assert!(report.findings.iter().any(|finding| finding.code == "unrecorded_installed_package"));
    }
}
