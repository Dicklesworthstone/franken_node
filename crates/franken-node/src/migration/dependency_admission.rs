//! Native checked-rewrite admission over captured dependency metadata.
//!
//! Inventories every recorded installation location, not just root dependency
//! names. No npm invocation, registry access, lifecycle execution or live
//! node_modules traversal in metadata-only mode. Supported registry version
//! ranges must match the nearest recorded pin; opaque requests require review.
//! npm v1/v2/v3 and Bun v1/v2 hoisted registry/workspace inputs share the graph
//! and installed-tree checks. This is NOT installed-content authentication,
//! a complete package solver, or runtime compatibility proof.
//!
//! Format reference: https://docs.npmjs.com/cli/v11/configuring-npm/package-lock-json/

use anyhow::{Context, Result, bail, ensure};
use rustix::fs::{Mode, OFlags, open, openat};
use serde::de::{self, DeserializeSeed, MapAccess, SeqAccess, Visitor};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::fs::{File, Metadata};
use std::io::Read;
use std::os::unix::fs::MetadataExt;
use std::path::Path;
use std::time::Instant;

#[path = "dependency_workspaces.rs"]
mod workspaces;

#[path = "dependency_graph_admission.rs"]
mod graph;

#[path = "dependency_installed.rs"]
mod installed;

#[path = "dependency_declarations.rs"]
mod declaration_selection;

#[path = "dependency_bun_lock.rs"]
mod bun;

const MAX_MANIFEST_BYTES: usize = 512 * 1024;
const MAX_LOCK_BYTES: usize = 16 * 1024 * 1024;
const MAX_METADATA_BYTES: usize = 64 * 1024 * 1024;
const MAX_PACKAGES: usize = 50_000;
const MAX_FINDINGS: usize = 1_000;
const MAX_JSON_NODES: usize = 1_000_000;
const MAX_DEPTH: usize = 64;
const SECTIONS: &[&str] = &[
    "dependencies", "devDependencies", "peerDependencies", "optionalDependencies",
];
const SCOPE: &str = "captured npm metadata and supported registry version ranges only; not installed-content authentication, npm override resolution or runtime compatibility proof";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MetadataInput {
    pub path: String,
    pub bytes: usize,
    pub sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DependencyFinding {
    pub code: String,
    pub source: String,
    pub package: String,
    pub installed_as: String,
    pub package_path: Option<String>,
    pub version: Option<String>,
    pub detail: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DependencyAdmission {
    pub schema_version: String,
    pub scope: String,
    pub packages_scanned: usize,
    pub manifests_scanned: usize,
    /// Completed inspection of the private staged installation, not approval
    /// or authentication against registry artifacts. Findings still block use.
    #[serde(default)]
    pub installation_checked: bool,
    /// Installation positions inspected, including workspace links and Bun
    /// registry aliases. Shared physical manifests are counted once by
    /// `manifests_scanned`, even when multiple positions select them.
    #[serde(default)]
    pub installed_packages_scanned: usize,
    pub inputs: Vec<MetadataInput>,
    pub findings: Vec<DependencyFinding>,
}

impl DependencyAdmission {
    pub fn requires_review(&self) -> bool {
        !self.findings.is_empty()
    }

    fn finding(&mut self, finding: DependencyFinding) -> Result<()> {
        ensure!(self.findings.len() < MAX_FINDINGS, "dependency review inventory exceeds its complete-report limit");
        self.findings.push(finding);
        Ok(())
    }
}

fn time_remaining(deadline: Instant) -> Result<()> {
    ensure!(Instant::now() < deadline, "dependency inventory deadline exceeded");
    Ok(())
}

fn bounded_text<'a>(value: &'a Value, field: &str) -> Result<&'a str> {
    let text = value.as_str().with_context(|| format!("{field} must be a string"))?;
    ensure!(!text.trim().is_empty() && text.trim() == text && text.len() <= 4096 && !text.chars().any(char::is_control), "invalid or oversized {field}");
    Ok(text)
}

fn name(text: &str) -> Result<&str> {
    let parts: Vec<_> = text.split('/').collect();
    let expected = if text.starts_with('@') { 2 } else { 1 };
    ensure!(
        !text.is_empty() && text.len() <= 4096 && parts.len() == expected
            && parts.iter().all(|part| !part.is_empty() && *part != "." && *part != "..")
            && !text.contains(['\\', ':'])
            && !text.chars().any(|ch| ch.is_control() || ch.is_whitespace())
            && (expected == 1 || parts[0].len() > 1)
            && !text.strip_prefix('@').unwrap_or(text).contains('@'),
        "invalid dependency package name"
    );
    Ok(text)
}

fn relative(text: &str) -> Result<&str> {
    ensure!(
        !text.is_empty() && text.len() <= 4096 && !text.contains(['\\', ':'])
            && !text.chars().any(char::is_control)
            && text.split('/').all(|part| !matches!(part, "" | "." | ".." | ".git")),
        "dependency metadata path must be canonical and project-relative"
    );
    Ok(text)
}

fn flag(record: &Map<String, Value>, key: &str) -> Result<bool> {
    match record.get(key) {
        None => Ok(false),
        Some(Value::Bool(value)) => Ok(*value),
        _ => bail!("invalid dependency {key} flag"),
    }
}

fn native_addon(package: &str) -> bool {
    matches!(package, "bcrypt" | "sharp" | "canvas" | "better-sqlite3" | "node-gyp"
        | "node-pre-gyp" | "nan" | "node-addon-api" | "ffi-napi" | "ref-napi"
        | "leveldown" | "sodium-native" | "argon2")
}

/// npm aliases may omit a version. That means unspecified, not a guessed pin.
fn alias<'a>(installed_as: &'a str, version: Option<&'a str>) -> Result<(&'a str, Option<&'a str>)> {
    let Some(target) = version.and_then(|version| version.strip_prefix("npm:")) else {
        return Ok((name(installed_as)?, version));
    };
    match target.rfind('@').filter(|index| *index > 0) {
        Some(index) => {
            let requested = &target[index + 1..];
            ensure!(!requested.is_empty(), "empty npm alias request");
            Ok((name(&target[..index])?, Some(requested)))
        }
        None => Ok((name(target)?, None)),
    }
}

fn identity(metadata: &Metadata) -> (u64, u64, u64, u32, i64, i64, i64, i64) {
    (metadata.dev(), metadata.ino(), metadata.len(), metadata.mode(), metadata.mtime(),
     metadata.mtime_nsec(), metadata.ctime(), metadata.ctime_nsec())
}

struct Capture {
    root: File,
    deadline: Instant,
    bytes: usize,
    inputs: BTreeMap<String, MetadataInput>,
}

impl Capture {
    fn new(root: &Path, deadline: Instant) -> Result<Self> {
        time_remaining(deadline)?;
        let fd = open(root, OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC, Mode::empty())?;
        Ok(Self { root: File::from(fd), deadline, bytes: 0, inputs: BTreeMap::new() })
    }

    /// Resolve each parent through held directory descriptors. A nested
    /// symlink cannot redirect metadata reads outside the captured tree.
    fn read(&mut self, path: &str, limit: usize) -> Result<Option<Value>> {
        time_remaining(self.deadline)?;
        relative(path)?;
        ensure!(!self.inputs.contains_key(path), "duplicate dependency metadata capture");
        let mut directory = self.root.try_clone()?;
        let mut parts = path.split('/').peekable();
        while let Some(part) = parts.next() {
            if parts.peek().is_none() {
                let flags = OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC;
                let fd = match openat(&directory, part, flags, Mode::empty()) {
                    Ok(fd) => fd,
                    Err(rustix::io::Errno::NOENT) => return Ok(None),
                    Err(error) => return Err(error).with_context(|| format!("cannot capture {path}")),
                };
                let mut file = File::from(fd);
                let before = file.metadata()?;
                ensure!(before.is_file() && before.len() <= limit as u64, "{path}: expected a bounded regular metadata file");
                let mut bytes = Vec::new();
                let mut buffer = [0_u8; 64 * 1024];
                loop {
                    time_remaining(self.deadline)?;
                    let remaining = (limit + 1 - bytes.len()).min(buffer.len());
                    let count = file.read(&mut buffer[..remaining])?;
                    if count == 0 { break; }
                    bytes.extend_from_slice(&buffer[..count]);
                    ensure!(bytes.len() <= limit, "{path}: metadata byte limit exceeded");
                }
                let reopened = File::from(openat(&directory, part, flags, Mode::empty())?);
                ensure!(identity(&before) == identity(&file.metadata()?)
                    && identity(&before) == identity(&reopened.metadata()?)
                    && bytes.len() as u64 == before.len(), "{path}: metadata changed during capture");
                self.bytes = self.bytes.checked_add(bytes.len()).context("metadata byte count overflow")?;
                ensure!(self.bytes <= MAX_METADATA_BYTES, "dependency metadata exceeds aggregate byte limit");
                // Bun's JSONC allowance is local to named text lock inputs.
                // npm manifests/locks remain strict, recursively unique JSON.
                let value = if path.rsplit('/').next() == Some("bun.lock") {
                    bun::parse(&bytes, self.deadline)
                } else {
                    parse_unique(&bytes, self.deadline)
                }.with_context(|| format!("invalid dependency JSON in {path}"))?;
                ensure!(value.is_object(), "{path}: dependency metadata must be an object");
                self.inputs.insert(path.into(), MetadataInput {
                    path: path.into(), bytes: bytes.len(), sha256: hex::encode(Sha256::digest(&bytes)),
                });
                return Ok(Some(value));
            }
            directory = File::from(openat(&directory, part,
                OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC, Mode::empty())?);
        }
        bail!("empty dependency metadata path")
    }

    fn refuse_binary_bun_lock(&mut self, path: &str) -> Result<()> {
        // Reuse the descriptor-relative, no-follow capture with a zero-byte
        // budget. Any present input (even empty, linked or nonregular) fails;
        // absence is the only successful result. No binary bytes are parsed.
        let absent = self.read(path, 0).with_context(|| format!(
            "{path}: binary Bun lockfiles are unsupported; convert to a reviewed bun.lock before checked execution"
        ))?.is_none();
        ensure!(absent, "unsupported binary Bun lockfile: {path}");
        Ok(())
    }
}

struct JsonBudget { nodes: usize, deadline: Instant }
struct JsonSeed<'a> { budget: &'a mut JsonBudget, depth: usize }

impl<'de> DeserializeSeed<'de> for JsonSeed<'_> {
    type Value = Value;
    fn deserialize<D: serde::Deserializer<'de>>(self, input: D) -> std::result::Result<Value, D::Error> {
        self.budget.nodes += 1;
        if self.budget.nodes > MAX_JSON_NODES || self.depth > MAX_DEPTH || Instant::now() >= self.budget.deadline {
            return Err(de::Error::custom("dependency JSON resource budget exceeded"));
        }
        input.deserialize_any(self)
    }
}

impl<'de> Visitor<'de> for JsonSeed<'_> {
    type Value = Value;
    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> std::result::Result<(), fmt::Error> { f.write_str("bounded JSON with unique object members") }
    fn visit_unit<E: de::Error>(self) -> std::result::Result<Value, E> { Ok(Value::Null) }
    fn visit_bool<E: de::Error>(self, value: bool) -> std::result::Result<Value, E> { Ok(Value::Bool(value)) }
    fn visit_i64<E: de::Error>(self, value: i64) -> std::result::Result<Value, E> { Ok(value.into()) }
    fn visit_u64<E: de::Error>(self, value: u64) -> std::result::Result<Value, E> { Ok(value.into()) }
    fn visit_f64<E: de::Error>(self, value: f64) -> std::result::Result<Value, E> {
        serde_json::Number::from_f64(value).map(Value::Number).ok_or_else(|| de::Error::custom("non-finite dependency number"))
    }
    fn visit_str<E: de::Error>(self, value: &str) -> std::result::Result<Value, E> { Ok(value.into()) }
    fn visit_string<E: de::Error>(self, value: String) -> std::result::Result<Value, E> { Ok(value.into()) }
    fn visit_seq<A: SeqAccess<'de>>(self, mut input: A) -> std::result::Result<Value, A::Error> {
        let mut values = Vec::new();
        while let Some(value) = input.next_element_seed(JsonSeed { budget: &mut *self.budget, depth: self.depth + 1 })? {
            values.push(value);
        }
        Ok(Value::Array(values))
    }
    fn visit_map<A: MapAccess<'de>>(self, mut input: A) -> std::result::Result<Value, A::Error> {
        let mut values = Map::new();
        while let Some(key) = input.next_key::<String>()? {
            if values.contains_key(&key) { return Err(de::Error::custom("duplicate dependency JSON member")); }
            let value = input.next_value_seed(JsonSeed { budget: &mut *self.budget, depth: self.depth + 1 })?;
            values.insert(key, value);
        }
        Ok(Value::Object(values))
    }
}

pub(crate) fn parse_unique(bytes: &[u8], deadline: Instant) -> Result<Value> {
    let mut input = serde_json::Deserializer::from_slice(bytes);
    let mut budget = JsonBudget { nodes: 0, deadline };
    let value = JsonSeed { budget: &mut budget, depth: 0 }.deserialize(&mut input)?;
    input.end()?;
    Ok(value)
}

#[derive(Debug)]
struct LockedPackage {
    name: String,
    installed_as: String,
    version: Option<String>,
    path: String,
    install: bool,
    linked: bool,
    unresolved: bool,
}

fn descriptor(record: &Map<String, Value>, installed_as: &str, path: &str) -> Result<LockedPackage> {
    let version = record.get("version").map(|value| bounded_text(value, "locked version")).transpose()?;
    let actual = record.get("name").map(|value| bounded_text(value, "package name")).transpose()?.unwrap_or(installed_as);
    let (actual, version) = alias(name(actual)?, version)?;
    // Validate flags without omitting dev/optional packages from the inventory.
    for key in ["dev", "optional", "devOptional", "inBundle", "bundled", "peer"] { flag(record, key)?; }
    Ok(LockedPackage {
        name: actual.into(), installed_as: installed_as.into(), version: version.map(str::to_owned),
        path: path.into(), install: flag(record, "hasInstallScript")?, linked: false, unresolved: version.is_none(),
    })
}

fn modern(lock: &Value, deadline: Instant) -> Result<BTreeMap<String, LockedPackage>> {
    let packages = lock.get("packages").and_then(Value::as_object).context("modern npm lockfile requires a packages object")?;
    ensure!(packages.len() <= MAX_PACKAGES + 1, "dependency package count exceeds limit");
    let mut result = BTreeMap::new();
    for (location, value) in packages {
        time_remaining(deadline)?;
        let record = value.as_object().context("invalid npm package descriptor")?;
        if location.is_empty() { continue; }
        relative(location)?;
        let parts: Vec<_> = location.split('/').collect();
        let Some(index) = parts.iter().rposition(|part| *part == "node_modules") else { continue; };
        let installed_as = parts[index + 1..].join("/");
        name(&installed_as)?;
        let mut package = if flag(record, "link")? {
            let target = relative(bounded_text(record.get("resolved").context("link target missing")?, "link target")?)?;
            match packages.get(target) {
                Some(Value::Object(target)) => {
                    ensure!(!flag(target, "link")?, "linked npm descriptor must not name another link");
                    descriptor(target, &installed_as, location)?
                }
                None => descriptor(&Map::new(), &installed_as, location)?,
                _ => bail!("invalid linked npm descriptor"),
            }
        } else { descriptor(record, &installed_as, location)? };
        package.linked = flag(record, "link")?;
        result.insert(location.clone(), package);
    }
    Ok(result)
}

fn legacy(lock: &Value, deadline: Instant) -> Result<BTreeMap<String, LockedPackage>> {
    let empty = Map::new();
    let root = match lock.get("dependencies") {
        None => &empty,
        Some(value) => value.as_object().context("legacy dependencies must be an object")?,
    };
    let mut pending = vec![(String::new(), root, 0_usize)];
    let mut result = BTreeMap::new();
    while let Some((parent, children, depth)) = pending.pop() {
        time_remaining(deadline)?;
        ensure!(depth <= MAX_DEPTH, "legacy npm dependency nesting exceeds limit");
        for (installed_as, value) in children {
            time_remaining(deadline)?;
            name(installed_as)?;
            let record = value.as_object().context("invalid legacy npm descriptor")?;
            let path = if parent.is_empty() { format!("node_modules/{installed_as}") }
                else { format!("{parent}/node_modules/{installed_as}") };
            relative(&path)?;
            ensure!(result.len() < MAX_PACKAGES, "dependency package count exceeds limit");
            result.insert(path.clone(), descriptor(record, installed_as, &path)?);
            if let Some(nested) = record.get("dependencies") {
                let nested = nested.as_object().context("nested legacy dependencies must be an object")?;
                if !nested.is_empty() { pending.push((path, nested, depth + 1)); }
            }
        }
    }
    Ok(result)
}

fn package_findings(report: &mut DependencyAdmission, packages: &BTreeMap<String, LockedPackage>, source: &str, workspace_links: &std::collections::BTreeSet<String>) -> Result<()> {
    for package in packages.values() {
        let mut add = |code: &str, detail: &str| report.finding(DependencyFinding {
            code: code.into(), source: source.into(), package: package.name.clone(),
            installed_as: package.installed_as.clone(), package_path: Some(package.path.clone()),
            version: package.version.clone(), detail: detail.into(),
        });
        if native_addon(&package.name) || native_addon(&package.installed_as) {
            add("native_addon", "Known native-addon/build dependency requires explicit migration review")?;
        }
        if package.install {
            add("install_script", "Lockfile records install lifecycle code; review before checked execution")?;
        }
        if package.unresolved {
            add("unresolved_package", "Recorded installation has no complete version/target metadata")?;
        }
        if package.linked && !workspace_links.contains(&package.path) {
            add("local_link", "Local package link needs captured manifest assessment before checked execution")?;
        }
    }
    Ok(())
}

/// Stop at the first recorded installation, even if its identity is wrong.
/// A workspace-private shadow must never be rescued by a matching hoisted pin.
fn nearest_package<'a>(packages: &'a BTreeMap<String, LockedPackage>, source: &str, installed_as: &str) -> Option<&'a LockedPackage> {
    let mut directory = source.strip_suffix("/package.json").unwrap_or("");
    loop {
        // Node skips an ancestor named node_modules instead of appending a
        // second node_modules component. Such a fictitious installation must
        // not shadow the real hoisted package during metadata admission.
        if directory.rsplit('/').next() != Some("node_modules") {
            let path = if directory.is_empty() { format!("node_modules/{installed_as}") }
                else { format!("{directory}/node_modules/{installed_as}") };
            if let Some(package) = packages.get(&path) { return Some(package); }
        }
        if directory.is_empty() { return None; }
        directory = directory.rsplit_once('/').map_or("", |(parent, _)| parent);
    }
}

fn declarations(report: &mut DependencyAdmission, manifest: &Value, packages: &BTreeMap<String, LockedPackage>, source: &str, count: &mut usize, deadline: Instant, bun_workspace_links: Option<&BTreeSet<String>>) -> Result<()> {
    for edge in declaration_selection::select(manifest, true, deadline, count, MAX_PACKAGES)? {
        let selected = nearest_package(packages, source, edge.installed_as);
        // Optionality belongs to the selected edge, not to the package name.
        // Present installations still need exact identity and range checks.
        if selected.is_none() && edge.optional { continue; }
        // The prefix is authority, not just a range abbreviation. It cannot
        // select a registry namesake, arbitrary link, or unselected workspace.
        // npm paths keep their existing opaque-protocol refusal semantics.
        let workspace_range = bun_workspace_links.and_then(|_| edge.request.strip_prefix("workspace:"));
        let represented = selected.is_some_and(|package| package.name == edge.package && !package.unresolved
            && if workspace_range.is_some() {
                package.linked && bun_workspace_links.is_some_and(|links| links.contains(&package.path))
            } else {
                // Opaque requests cannot substitute a same-named local workspace.
                !package.linked || !edge.request.contains([':', '/', '\\'])
            });
        let native = native_addon(edge.package) || native_addon(edge.installed_as);
        let locked_version = selected.and_then(|package| package.version.as_deref());
        let requirement = match workspace_range {
            // These shorthands select the bound local version, including
            // prereleases. They are NOT registry wildcards that omit prereleases.
            Some("*" | "^" | "~") => locked_version,
            Some(range) => Some(range),
            None => edge.requirement,
        };
        let version_issue = if represented {
            if workspace_range == Some("") {
                Some(("unverifiable_dependency_version", "workspace: requires an explicit shorthand or supported version range"))
            } else {
                graph::version_review(requirement, locked_version)
            }
        } else { None };
        let unresolved = if workspace_range.is_some() {
            ("unresolved_workspace_dependency", "workspace: request requires the nearest installation to be an independently selected and manifest-bound workspace link")
        } else {
            ("unresolved_declaration", "Declaration has no matching complete nearest lockfile identity; version satisfaction is not established")
        };
        if !represented || native || version_issue.is_some() {
            report.finding(DependencyFinding {
                code: if native { "native_addon" }
                    else { version_issue.unwrap_or(unresolved).0 }.into(),
                source: format!("{source}#{}", edge.section), package: edge.package.into(),
                installed_as: edge.installed_as.into(), package_path: None, version: Some(edge.request.into()),
                detail: if native { "Declared native-addon/build dependency requires explicit migration review" }
                    else { version_issue.unwrap_or(unresolved).1 }.into(),
            })?;
        }
    }
    Ok(())
}

/// Assess captured metadata without opening installed dependency contents.
/// A clean metadata report alone is not permission to execute an installation;
/// checked execution must use [`inspect_for_execution`] on its private capture.
pub fn inspect(project: &Path, deadline: Instant) -> Result<DependencyAdmission> {
    inspect_with_installation(project, deadline, false)
}

/// Inspect metadata AND the actual private staged installation before either
/// comparison runtime starts. This is not a reusable approval of a mutable
/// source tree, a sandbox, or registry-content authentication.
pub fn inspect_for_execution(project: &Path, deadline: Instant) -> Result<DependencyAdmission> {
    inspect_with_installation(project, deadline, true)
}

/// Project a captured Bun lock into the shared installation graph used by
/// runtime trust admission. The caller owns the bounded, descriptor-relative
/// capture of these manifests; this function never reopens the project.
/// Bind every raw workspace declaration before expanding catalog references,
/// so a stale lock cannot redirect aliases or hide a dependency from trust.
pub(crate) fn project_bun_lock_for_topology(
    bytes: &[u8],
    manifests: &mut BTreeMap<String, Value>,
    deadline: Instant,
) -> Result<Value> {
    let root = manifests.get("").context("Bun topology requires a captured root manifest")?;
    let (lock, catalogs) = bun::project_lock(bun::parse(bytes, deadline)?, root, deadline)?;
    let records = lock.get("packages").and_then(Value::as_object)
        .context("Bun projected installation records missing")?;
    let workspace_count = records.keys()
        .filter(|path| !path.split('/').any(|part| part == "node_modules"))
        .count();
    ensure!(workspace_count == manifests.len(),
        "Bun lock workspaces differ from the captured project selection");
    for (path, manifest) in manifests.iter() {
        time_remaining(deadline)?;
        let recorded = records.get(path)
            .context("Bun lock is missing a captured workspace manifest")?;
        if !path.is_empty() {
            ensure!(manifest.get("workspaces").is_none(),
                "nested Bun workspace configuration requires separate assessment");
            ensure!(manifest.get("name") == recorded.get("name")
                && manifest.get("version") == recorded.get("version"),
                "Bun workspace identity differs from its captured manifest");
        }
        ensure!(workspaces::dependency_metadata_matches(manifest, recorded),
            "Bun workspace dependencies differ from their captured manifest");
    }
    catalogs.expand(manifests, deadline)?;
    Ok(lock)
}

fn inspect_with_installation(project: &Path, deadline: Instant, check_installation: bool) -> Result<DependencyAdmission> {
    let mut capture = Capture::new(project, deadline)?;
    let manifest = capture.read("package.json", MAX_MANIFEST_BYTES)?.context("dependency admission requires package.json")?;
    capture.refuse_binary_bun_lock("bun.lockb")?;
    let package_lock = capture.read("package-lock.json", MAX_LOCK_BYTES)?;
    let shrinkwrap = capture.read("npm-shrinkwrap.json", MAX_LOCK_BYTES)?;
    ensure!(package_lock.is_none() || shrinkwrap.is_none(), "both npm lockfiles are present; dependency inventory is ambiguous");
    let bun_lock = capture.read("bun.lock", MAX_LOCK_BYTES)?;
    ensure!(bun_lock.is_none() || (package_lock.is_none() && shrinkwrap.is_none()),
        "Bun and npm lockfiles are both present; select one dependency authority before checked execution");
    let (source, lock, catalogs) = if let Some(bun_lock) = bun_lock {
        let (projection, catalogs) = bun::project_lock(bun_lock, &manifest, deadline)?;
        ("bun.lock", Some(projection), Some(catalogs))
    } else if package_lock.is_some() { ("package-lock.json", package_lock, None) }
        else { ("npm-shrinkwrap.json", shrinkwrap, None) };
    let packages = match &lock {
        None => BTreeMap::new(),
        Some(lock) => match lock.get("lockfileVersion").and_then(Value::as_u64) {
            Some(1) => legacy(lock, deadline)?,
            Some(2 | 3) => modern(lock, deadline)?,
            _ => bail!("unsupported or missing npm lockfileVersion; expected 1, 2 or 3"),
        },
    };
    let mut manifests = match &catalogs {
        Some(catalogs) => catalogs.capture_workspaces(&mut capture, manifest)?,
        None => workspaces::capture(&mut capture, manifest)?,
    };
    let mut report = DependencyAdmission {
        schema_version: "franken-node/native-dependency-admission/v1".into(), scope: SCOPE.into(),
        packages_scanned: packages.len(), manifests_scanned: manifests.len(), inputs: Vec::new(), findings: Vec::new(),
        installation_checked: false, installed_packages_scanned: 0,
    };
    let workspace_links = workspaces::bind_links(&mut capture, &manifests, lock.as_ref(), &packages, &mut report)?;
    if let Some(catalogs) = &catalogs {
        // Match raw workspace declarations BEFORE expanding the private
        // project projection. Capture still pins original manifest bytes;
        // published registry manifests never inherit these root definitions.
        catalogs.expand(&mut manifests, deadline)?;
    }
    package_findings(&mut report, &packages, source, &workspace_links)?;
    graph::inspect(lock.as_ref(), &packages, source, &mut report, deadline)?;
    let mut declared = 0;
    let bun_workspace_links = (source == "bun.lock").then_some(&workspace_links);
    for (directory, manifest) in &manifests {
        let source = workspaces::manifest_path(directory);
        declarations(&mut report, manifest, &packages, &source, &mut declared, deadline, bun_workspace_links)?;
        workspaces::manifest_findings(&mut report, manifest, &source)?;
        if !directory.is_empty() {
            capture.refuse_binary_bun_lock(&format!("{directory}/bun.lockb"))?;
            let path = format!("{directory}/bun.lock");
            if capture.read(&path, MAX_LOCK_BYTES)?.is_some() {
                report.finding(DependencyFinding {
                    code: "workspace_lockfile".into(), source: path,
                    package: manifest.get("name").and_then(Value::as_str).unwrap_or_default().into(),
                    installed_as: String::new(), package_path: Some(directory.clone()),
                    version: manifest.get("version").and_then(Value::as_str).map(str::to_owned),
                    detail: "Workspace has an independent Bun lockfile; assess it separately instead of mixing lock authorities".into(),
                })?;
            }
        }
    }
    if check_installation {
        if report.requires_review() {
            report.scope.push_str("; installed tree not inspected because metadata already requires review");
        } else {
            installed::inspect(&mut capture, &packages, &manifests, lock.as_ref(), &mut report)?;
        }
    }
    if source == "bun.lock" {
        report.scope = report.scope.replacen("captured npm metadata",
            "captured Bun v1/v2 text-lock metadata (hoisted registry and manifest-bound workspace subset)", 1);
    }
    if catalogs.as_ref().is_some_and(bun::Catalogs::has_entries) {
        report.scope.push_str("; project catalog references resolved from matching captured root/lock definitions");
    }
    time_remaining(deadline)?;
    report.inputs = capture.inputs.into_values().collect();
    report.findings.sort_by(|left, right| (&left.source, &left.package_path, &left.package, &left.code)
        .cmp(&(&right.source, &right.package_path, &right.package, &right.code)));
    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::fs;
    use std::time::Duration;

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

    #[test]
    fn empty_project_has_no_dependency_review_but_makes_no_compatibility_claim() {
        let root = fixture(json!({}), None);
        let report = inspect(root.path(), deadline()).unwrap();
        assert!(!report.requires_review());
        assert_eq!(report.packages_scanned, 0);
        assert_eq!(report.manifests_scanned, 1);
        assert!(report.scope.contains("not installed-content authentication"));
        assert_eq!(report.inputs[0].path, "package.json");
    }

    #[test]
    fn complete_ordinary_lock_identity_is_admitted_without_executing_a_package_manager() {
        let root = fixture(json!({"dependencies":{"ordinary":"^1"}}), Some(modern_fixture(json!({
            "":{}, "node_modules/ordinary":{"version":"1.2.3"}
        }))));
        let report = inspect(root.path(), deadline()).unwrap();
        assert!(!report.requires_review(), "{report:#?}");
        assert_eq!(report.packages_scanned, 1);
        assert_eq!(report.inputs.len(), 2);
        assert!(!root.path().join("node_modules").exists());
    }

    #[test]
    fn nested_native_addons_keep_each_location_and_version() {
        let root = fixture(json!({}), Some(modern_fixture(json!({
            "node_modules/ordinary":{"version":"1.0.0"},
            "node_modules/ordinary/node_modules/sharp":{"version":"0.32.0","optional":true},
            "node_modules/sharp":{"version":"0.33.0","dev":true}
        }))));
        let report = inspect(root.path(), deadline()).unwrap();
        assert_eq!(report.packages_scanned, 3);
        assert_eq!(codes(&report), ["native_addon", "native_addon"]);
        assert_eq!(report.findings[0].package_path.as_deref(), Some("node_modules/ordinary/node_modules/sharp"));
        assert_eq!(report.findings[0].version.as_deref(), Some("0.32.0"));
        assert_eq!(report.findings[1].version.as_deref(), Some("0.33.0"));
    }

    #[test]
    fn npm_v2_uses_packages_not_its_legacy_projection() {
        let root = fixture(json!({}), Some(json!({"lockfileVersion":2,
            "packages":{"node_modules/ordinary":{"version":"1.0.0"}},
            "dependencies":{"sharp":{"version":"0.32.0"}}
        })));
        let report = inspect(root.path(), deadline()).unwrap();
        assert_eq!(report.packages_scanned, 1);
        assert!(!report.requires_review());
    }

    #[test]
    fn legacy_tree_preserves_transitive_alias_identity() {
        let root = fixture(json!({}), Some(json!({"lockfileVersion":1,"dependencies":{
            "outer":{"version":"1.0.0","dependencies":{
                "image":{"version":"npm:sharp@0.32.0"}
            }}
        }})));
        let report = inspect(root.path(), deadline()).unwrap();
        assert_eq!(report.packages_scanned, 2);
        assert_eq!(codes(&report), ["native_addon"]);
        assert_eq!(report.findings[0].package, "sharp");
        assert_eq!(report.findings[0].installed_as, "image");
        assert_eq!(report.findings[0].version.as_deref(), Some("0.32.0"));
    }

    #[test]
    fn install_lifecycle_is_review_not_an_invented_native_addon() {
        let root = fixture(json!({}), Some(modern_fixture(json!({
            "node_modules/ordinary":{"version":"1.0.0","hasInstallScript":true}
        }))));
        let report = inspect(root.path(), deadline()).unwrap();
        assert_eq!(codes(&report), ["install_script"]);
    }

    #[test]
    fn declaration_alias_cannot_hide_behind_stale_lock_identity() {
        let root = fixture(json!({"dependencies":{"image":"npm:sharp@^0.33"}}), Some(modern_fixture(json!({
            "node_modules/image":{"name":"ordinary","version":"1.0.0"}
        }))));
        let report = inspect(root.path(), deadline()).unwrap();
        assert_eq!(codes(&report), ["native_addon"]);
        assert_eq!(report.findings[0].package, "sharp");
        assert_eq!(report.findings[0].source, "package.json#dependencies");
    }

    #[test]
    fn aliases_support_scopes_and_unspecified_versions_without_guessing_pins() {
        assert_eq!(alias("alias", Some("npm:sharp")).unwrap(), ("sharp", None));
        assert_eq!(alias("alias", Some("npm:@scope/name")).unwrap(), ("@scope/name", None));
        assert_eq!(alias("alias", Some("npm:@scope/name@^2")).unwrap(), ("@scope/name", Some("^2")));
        for bad in ["npm:", "npm:@scope", "npm:sharp@", "npm:foo/bar@1", "npm:foo@@1"] {
            assert!(alias("alias", Some(bad)).is_err(), "{bad}");
        }
    }

    #[test]
    fn every_dependency_section_is_reviewed_even_without_a_lock() {
        for section in SECTIONS {
            let mut package = Map::new();
            package.insert((*section).into(), json!({"ordinary":"^1"}));
            let root = fixture(Value::Object(package), None);
            let report = inspect(root.path(), deadline()).unwrap();
            if *section == "optionalDependencies" {
                assert!(!report.requires_review());
            } else {
                assert_eq!(codes(&report), ["unresolved_declaration"]);
                assert_eq!(report.findings[0].source, format!("package.json#{section}"));
            }
        }
    }

    #[test]
    fn local_links_never_follow_external_filesystem_targets() {
        let root = fixture(json!({}), Some(modern_fixture(json!({
            "node_modules/local":{"link":true,"resolved":"packages/local"},
            "packages/local":{"name":"local","version":"1.0.0","hasInstallScript":true}
        }))));
        let report = inspect(root.path(), deadline()).unwrap();
        assert_eq!(codes(&report), ["install_script", "local_link"]);
        assert!(!root.path().join("packages").exists());
        for target in ["../outside", "/outside", "node_modules/../outside", "C:/outside"] {
            fs::write(root.path().join("package-lock.json"), serde_json::to_vec(&modern_fixture(json!({
                "node_modules/local":{"link":true,"resolved":target}
            }))).unwrap()).unwrap();
            assert!(inspect(root.path(), deadline()).is_err(), "{target}");
        }
    }

    #[test]
    fn malformed_or_ambiguous_metadata_never_returns_a_clean_report() {
        for lock in [json!({}), json!({"lockfileVersion":true}), json!({"lockfileVersion":4}),
            json!({"lockfileVersion":3,"packages":[]}),
            modern_fixture(json!({"../escape":{}})),
            modern_fixture(json!({"node_modules/a":{"version":"1","hasInstallScript":1}})),
            json!({"lockfileVersion":1,"dependencies":{"a":{"version":"1","dependencies":null}}})] {
            let root = fixture(json!({}), Some(lock));
            assert!(inspect(root.path(), deadline()).is_err());
        }
        let root = fixture(json!({}), Some(modern_fixture(json!({}))));
        fs::write(root.path().join("npm-shrinkwrap.json"), r#"{"lockfileVersion":1}"#).unwrap();
        assert!(inspect(root.path(), deadline()).unwrap_err().to_string().contains("both npm lockfiles"));
    }

    #[test]
    fn duplicate_keys_and_escaped_aliases_are_refused_recursively() {
        for source in [
            r#"{"dependencies":{"a":"1","a":"2"}}"#,
            r#"{"dependencies":{"a":"1","\u0061":"2"}}"#,
            r#"{"metadata":[{"x":1,"x":2}]}"#,
            r#"{} {}"#,
        ] {
            assert!(parse_unique(source.as_bytes(), deadline()).is_err(), "{source}");
        }
        let value = parse_unique(br#"{"n":18446744073709551615,"custom":1.25}"#, deadline()).unwrap();
        assert_eq!(value["n"].as_u64(), Some(u64::MAX));
    }

    #[test]
    fn deadlines_json_depth_and_byte_limits_fail_without_partial_success() {
        let root = fixture(json!({}), None);
        assert!(inspect(root.path(), Instant::now()).is_err());
        let deep = format!("{}0{}", "[".repeat(MAX_DEPTH + 1), "]".repeat(MAX_DEPTH + 1));
        assert!(parse_unique(deep.as_bytes(), deadline()).is_err());
        fs::write(root.path().join("package.json"), vec![b' '; MAX_MANIFEST_BYTES + 1]).unwrap();
        assert!(inspect(root.path(), deadline()).is_err());
    }

    #[test]
    fn metadata_capture_refuses_symlinks_and_nonregular_files() {
        use std::os::unix::fs::symlink;
        let root = fixture(json!({}), None);
        let target = root.path().join("actual-lock");
        fs::write(&target, r#"{"lockfileVersion":3,"packages":{}}"#).unwrap();
        symlink(&target, root.path().join("package-lock.json")).unwrap();
        assert!(inspect(root.path(), deadline()).is_err());
        let other = fixture(json!({}), None);
        fs::create_dir(other.path().join("package-lock.json")).unwrap();
        assert!(inspect(other.path(), deadline()).is_err());
    }

    #[test]
    fn utf8_names_never_panic_and_output_is_deterministic() {
        assert_eq!(name("π").unwrap(), "π");
        let root = fixture(json!({"dependencies":{"π":"1"}}), None);
        let first = inspect(root.path(), deadline()).unwrap();
        assert_eq!(first, inspect(root.path(), deadline()).unwrap());
        let bytes = fs::read(root.path().join("package.json")).unwrap();
        assert_eq!(first.inputs[0].sha256, hex::encode(Sha256::digest(&bytes)));
        assert_eq!(first, serde_json::from_value::<DependencyAdmission>(serde_json::to_value(&first).unwrap()).unwrap());
    }

    #[test]
    fn findings_limit_is_a_failure_not_a_truncated_approval() {
        let packages: Map<_, _> = (0..MAX_FINDINGS + 1).map(|index| (
            format!("node_modules/package-{index}"), json!({"version":"1.0.0","hasInstallScript":true})
        )).collect();
        let root = fixture(json!({}), Some(modern_fixture(Value::Object(packages))));
        assert!(inspect(root.path(), deadline()).unwrap_err().to_string().contains("complete-report limit"));
    }

    fn bun_workspace_fixture(request: &str, version: &str) -> tempfile::TempDir {
        let manifest = json!({"workspaces":["packages/*"],"dependencies":{"@local/dep":request}});
        let member = json!({"name":"@local/dep","version":version});
        let lock = json!({"lockfileVersion":2,"configVersion":0,
            "workspaces":{"":{"dependencies":{"@local/dep":request}},"packages/dep":member},
            "packages":{"@local/dep":["@local/dep@workspace:packages/dep"]}});
        let root = fixture(manifest, None);
        fs::write(root.path().join("bun.lock"), serde_json::to_vec(&lock).unwrap()).unwrap();
        fs::create_dir_all(root.path().join("packages/dep")).unwrap();
        fs::write(root.path().join("packages/dep/package.json"),
            serde_json::to_vec(&lock["workspaces"]["packages/dep"]).unwrap()).unwrap();
        fs::write(root.path().join("packages/dep/index.js"), "throw Error('must not execute');").unwrap();
        fs::create_dir_all(root.path().join("node_modules/@local")).unwrap();
        std::os::unix::fs::symlink("../../packages/dep", root.path().join("node_modules/@local/dep")).unwrap();
        root
    }

    #[test]
    fn bun_workspace_protocol_shorthands_and_ranges_reach_staged_admission() {
        for request in ["workspace:*", "workspace:^", "workspace:~", "workspace:1.2.3",
            "workspace:^1.2", "workspace:~1.2.0", "workspace:>=1.2.0 <2"] {
            let root = bun_workspace_fixture(request, "1.2.3");
            let report = inspect_for_execution(root.path(), deadline()).unwrap();
            assert!(!report.requires_review(), "{request}: {report:?}");
            assert!(report.installation_checked);
            assert_eq!(report.installed_packages_scanned, 1);
            assert!(report.scope.contains("manifest-bound workspace"));
            assert_eq!(report, inspect_for_execution(root.path(), deadline()).unwrap());
        }
        for request in ["workspace:*", "workspace:^", "workspace:~"] {
            let root = bun_workspace_fixture(request, "1.2.3-beta.1+local");
            assert!(!inspect_for_execution(root.path(), deadline()).unwrap().requires_review(), "{request}");
        }
    }

    #[test]
    fn bun_workspace_explicit_range_mismatches_and_opaque_suffixes_require_review() {
        for (request, expected) in [
            ("workspace:^2", "dependency_version_mismatch"),
            ("workspace:<1", "dependency_version_mismatch"),
            ("workspace:", "unverifiable_dependency_version"),
            ("workspace:../dep", "unverifiable_dependency_version"),
            ("workspace:npm:other@1", "unverifiable_dependency_version"),
            ("workspace:latest", "unverifiable_dependency_version"),
        ] {
            let root = bun_workspace_fixture(request, "1.2.3");
            let report = inspect_for_execution(root.path(), deadline()).unwrap();
            assert!(report.findings.iter().any(|finding| finding.code == expected
                && finding.source == "package.json#dependencies"), "{request}: {report:?}");
            assert!(!report.installation_checked);
        }
    }

    #[test]
    fn bun_workspace_protocol_never_selects_a_registry_namesake_or_unbound_link() {
        let manifest = json!({"dependencies":{"dep":"workspace:*"}});
        let root = fixture(manifest.clone(), None);
        let lock = json!({"lockfileVersion":2,"workspaces":{"":manifest},
            "packages":{"dep":["dep@1.2.3","",{},""]}});
        fs::write(root.path().join("bun.lock"), serde_json::to_vec(&lock).unwrap()).unwrap();
        let report = inspect(root.path(), deadline()).unwrap();
        assert!(codes(&report).contains(&"unresolved_workspace_dependency"));

        let root = bun_workspace_fixture("workspace:*", "1.2.3");
        fs::write(root.path().join("packages/dep/package.json"),
            r#"{"name":"@local/dep","version":"2.0.0"}"#).unwrap();
        let report = inspect_for_execution(root.path(), deadline()).unwrap();
        assert!(codes(&report).contains(&"workspace_review"));
        assert!(codes(&report).contains(&"unresolved_workspace_dependency"));
        assert!(!report.installation_checked);
    }

    #[test]
    fn npm_lock_cannot_opt_into_bun_workspace_protocol_admission() {
        let root = bun_workspace_fixture("workspace:*", "1.2.3");
        let lock = bun::parse(&fs::read(root.path().join("bun.lock")).unwrap(), deadline()).unwrap();
        let manifest: Value = serde_json::from_slice(&fs::read(root.path().join("package.json")).unwrap()).unwrap();
        let (projected, _) = bun::project_lock(lock, &manifest, deadline()).unwrap();
        fs::rename(root.path().join("bun.lock"), root.path().join("retained-bun-lock.txt")).unwrap();
        fs::write(root.path().join("package-lock.json"), serde_json::to_vec(&projected).unwrap()).unwrap();
        let report = inspect_for_execution(root.path(), deadline()).unwrap();
        assert!(report.requires_review());
        assert!(codes(&report).contains(&"unresolved_declaration"));
        assert!(!report.installation_checked);
    }

    #[test]
    fn workspace_protocol_cycles_are_checked_from_real_project_manifests() {
        let root = bun_workspace_fixture("workspace:*", "1.2.3");
        let peer = json!({"name":"peer","version":"2.0.0","dependencies":{"@local/dep":"workspace:^"}});
        let mut dep = json!({"name":"@local/dep","version":"1.2.3"});
        dep["dependencies"] = json!({"peer":"workspace:~"});
        let mut lock = bun::parse(&fs::read(root.path().join("bun.lock")).unwrap(), deadline()).unwrap();
        lock["workspaces"]["packages/dep"] = dep.clone();
        lock["workspaces"]["packages/peer"] = peer.clone();
        lock["packages"]["peer"] = json!(["peer@workspace:packages/peer"]);
        fs::write(root.path().join("bun.lock"), serde_json::to_vec(&lock).unwrap()).unwrap();
        fs::write(root.path().join("packages/dep/package.json"), serde_json::to_vec(&dep).unwrap()).unwrap();
        fs::create_dir(root.path().join("packages/peer")).unwrap();
        fs::write(root.path().join("packages/peer/package.json"), serde_json::to_vec(&peer).unwrap()).unwrap();
        std::os::unix::fs::symlink("../packages/peer", root.path().join("node_modules/peer")).unwrap();
        let report = inspect_for_execution(root.path(), deadline()).unwrap();
        assert!(!report.requires_review(), "{report:?}");
        assert!(report.installation_checked);
        assert_eq!(report.installed_packages_scanned, 2);
    }

    #[test]
    fn independent_workspace_bun_lock_is_fingerprinted_but_never_unioned() {
        let root = bun_workspace_fixture("workspace:*", "1.2.3");
        let path = "packages/dep/bun.lock";
        let raw = b"// independent project\n{\"lockfileVersion\":2,\"workspaces\":{\"\":{}},\"packages\":{},}\n";
        fs::write(root.path().join(path), raw).unwrap();
        let report = inspect_for_execution(root.path(), deadline()).unwrap();
        assert!(report.findings.iter().any(|finding| finding.code == "workspace_lockfile" && finding.source == path));
        assert!(!report.installation_checked);
        assert_eq!(report.packages_scanned, 1);
        let input = report.inputs.iter().find(|input| input.path == path).unwrap();
        assert_eq!(input.sha256, hex::encode(Sha256::digest(raw)));
        assert_eq!(input.bytes, raw.len());
    }

    #[test]
    fn binary_bun_authority_never_disappears_into_a_clean_empty_inventory() {
        for contents in [b"binary\0\xff".as_slice(), b"", b"{}"] {
            let root = fixture(json!({}), None);
            fs::write(root.path().join("bun.lockb"), contents).unwrap();
            let error = inspect(root.path(), deadline()).unwrap_err();
            assert!(format!("{error:#}").contains("binary Bun lockfiles are unsupported"));
            let root = bun_workspace_fixture("workspace:*", "1.2.3");
            fs::write(root.path().join("packages/dep/bun.lockb"), contents).unwrap();
            assert!(inspect_for_execution(root.path(), deadline()).is_err());
        }
    }

    #[test]
    fn workspace_protocol_still_requires_the_physical_bound_link() {
        let root = bun_workspace_fixture("workspace:*", "1.2.3");
        fs::rename(root.path().join("node_modules/@local/dep"),
            root.path().join("retained-workspace-link")).unwrap();
        fs::create_dir_all(root.path().join("packages/wrong")).unwrap();
        std::os::unix::fs::symlink("../../packages/wrong", root.path().join("node_modules/@local/dep")).unwrap();
        let error = inspect_for_execution(root.path(), deadline()).unwrap_err();
        assert!(error.to_string().contains("installed workspace link differs"), "{error:#}");
    }
}
