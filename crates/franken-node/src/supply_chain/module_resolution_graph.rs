//! Canonical npm/Bun-style module-resolution graph construction.
//!
//! This module intentionally models project metadata and lockfile facts, not
//! full Node/Bun runtime resolution semantics. Runtime parity remains the job
//! of the lockstep oracle; this graph gives admission and receipt layers stable
//! bytes for package manifests, workspace edges, dependency ranges, conditional
//! exports/imports, and npm package-lock pins.

use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::path::{Path, PathBuf};

const MAX_PACKAGE_JSON_BYTES: u64 = 512 * 1024;
const MAX_PACKAGE_MANIFESTS: usize = 256;
const MAX_WORKSPACE_PATTERNS: usize = 128;
const MAX_DEPENDENCY_EDGES: usize = 16_384;
const MAX_LOCKFILE_BYTES: u64 = 4 * 1024 * 1024;
const MAX_LOCKFILE_PACKAGES: usize = 16_384;
const MAX_CONDITIONAL_TARGETS: usize = 4_096;
const MODULE_RESOLUTION_GRAPH_HASH_DOMAIN: &[u8] =
    b"franken-node/module-resolution-graph/canonical-hash/v1:";

pub const MODULE_RESOLUTION_GRAPH_SCHEMA: &str = crate::schema_versions::MODULE_RESOLUTION_GRAPH;

#[derive(Debug)]
pub enum ModuleResolutionGraphError {
    MissingRootManifest {
        path: PathBuf,
    },
    Io {
        path: PathBuf,
        source: std::io::Error,
    },
    Json {
        path: PathBuf,
        source: serde_json::Error,
    },
    InvalidWorkspacePattern {
        pattern: String,
    },
    BoundExceeded {
        bound: &'static str,
        limit: usize,
    },
}

impl fmt::Display for ModuleResolutionGraphError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingRootManifest { path } => {
                write!(
                    formatter,
                    "package manifest not found at {}",
                    path.display()
                )
            }
            Self::Io { path, source } => {
                write!(formatter, "failed reading {}: {source}", path.display())
            }
            Self::Json { path, source } => {
                write!(
                    formatter,
                    "failed parsing JSON from {}: {source}",
                    path.display()
                )
            }
            Self::InvalidWorkspacePattern { pattern } => {
                write!(formatter, "unsupported workspace pattern `{pattern}`")
            }
            Self::BoundExceeded { bound, limit } => {
                write!(formatter, "{bound} exceeds deterministic bound of {limit}")
            }
        }
    }
}

impl std::error::Error for ModuleResolutionGraphError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io { source, .. } => Some(source),
            Self::Json { source, .. } => Some(source),
            Self::MissingRootManifest { .. }
            | Self::InvalidWorkspacePattern { .. }
            | Self::BoundExceeded { .. } => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ModuleResolutionGraph {
    pub schema_version: String,
    pub project_root: String,
    pub root_package_id: String,
    pub packages: Vec<PackageNode>,
    pub dependency_edges: Vec<DependencyEdge>,
    pub lockfile_pins: Vec<LockfilePin>,
    pub canonical_hash: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PackageNode {
    pub package_id: String,
    pub name: Option<String>,
    pub version: Option<String>,
    pub relative_manifest_path: String,
    pub workspace: bool,
    pub workspace_patterns: Vec<String>,
    pub exports: Vec<ConditionalResolutionEntry>,
    pub imports: Vec<ConditionalResolutionEntry>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DependencyKind {
    Production,
    Development,
    Peer,
    Optional,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DependencyEdge {
    pub from_package_id: String,
    pub dependency_name: String,
    pub requested_range: String,
    pub dependency_kind: DependencyKind,
    pub target_package_id: Option<String>,
    pub lockfile_package_path: Option<String>,
    pub optional: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConditionalResolutionEntry {
    pub specifier: String,
    pub targets: Vec<ConditionalTarget>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConditionalTarget {
    pub condition: String,
    pub target: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LockfilePin {
    pub package_path: String,
    pub package_name: String,
    pub version: Option<String>,
    pub resolved: Option<String>,
    pub integrity: Option<String>,
    pub dependencies: Vec<LockfileDependency>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LockfileDependency {
    pub name: String,
    pub requested_range: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct ModuleResolutionGraphPayload {
    schema_version: String,
    project_root: String,
    root_package_id: String,
    packages: Vec<PackageNode>,
    dependency_edges: Vec<DependencyEdge>,
    lockfile_pins: Vec<LockfilePin>,
}

#[derive(Debug, Clone)]
struct ParsedManifest {
    relative_manifest_path: String,
    package: PackageNode,
    dependencies: Vec<DependencySpec>,
}

#[derive(Debug, Clone)]
struct DependencySpec {
    name: String,
    requested_range: String,
    kind: DependencyKind,
    optional: bool,
}

pub type ModuleResolutionGraphResult<T> = Result<T, ModuleResolutionGraphError>;

pub fn build_canonical_module_resolution_graph(
    project_root: impl AsRef<Path>,
) -> ModuleResolutionGraphResult<ModuleResolutionGraph> {
    let project_root = project_root.as_ref();
    let root_manifest_path = project_root.join("package.json");
    if !root_manifest_path.exists() {
        return Err(ModuleResolutionGraphError::MissingRootManifest {
            path: root_manifest_path,
        });
    }

    let root_manifest = parse_manifest(project_root, &root_manifest_path, false)?;
    let workspace_manifest_paths =
        collect_workspace_manifest_paths(project_root, &root_manifest.package.workspace_patterns)?;

    let mut manifests = Vec::new();
    manifests.push(root_manifest);
    for manifest_path in workspace_manifest_paths {
        manifests.push(parse_manifest(project_root, &manifest_path, true)?);
        enforce_len("package manifests", manifests.len(), MAX_PACKAGE_MANIFESTS)?;
    }

    manifests.sort_by(|left, right| {
        left.relative_manifest_path
            .cmp(&right.relative_manifest_path)
    });

    let packages = manifests
        .iter()
        .map(|manifest| manifest.package.clone())
        .collect::<Vec<_>>();
    let root_package_id = packages
        .iter()
        .find(|package| !package.workspace)
        .map(|package| package.package_id.clone())
        .unwrap_or_default();
    let workspace_by_name = packages
        .iter()
        .filter_map(|package| {
            package
                .name
                .as_ref()
                .map(|name| (name.clone(), package.package_id.clone()))
        })
        .collect::<BTreeMap<_, _>>();

    let lockfile_pins = read_package_lock(project_root)?;
    let lockfile_path_by_name = lockfile_pins
        .iter()
        .map(|pin| (pin.package_name.clone(), pin.package_path.clone()))
        .collect::<BTreeMap<_, _>>();

    let mut dependency_edges = Vec::new();
    for manifest in &manifests {
        for dependency in &manifest.dependencies {
            dependency_edges.push(DependencyEdge {
                from_package_id: manifest.package.package_id.clone(),
                dependency_name: dependency.name.clone(),
                requested_range: dependency.requested_range.clone(),
                dependency_kind: dependency.kind,
                target_package_id: workspace_by_name.get(&dependency.name).cloned(),
                lockfile_package_path: lockfile_path_by_name.get(&dependency.name).cloned(),
                optional: dependency.optional,
            });
            enforce_len(
                "dependency edges",
                dependency_edges.len(),
                MAX_DEPENDENCY_EDGES,
            )?;
        }
    }
    dependency_edges.sort_by(|left, right| {
        (
            &left.from_package_id,
            &left.dependency_kind,
            &left.dependency_name,
        )
            .cmp(&(
                &right.from_package_id,
                &right.dependency_kind,
                &right.dependency_name,
            ))
    });

    let payload = ModuleResolutionGraphPayload {
        schema_version: MODULE_RESOLUTION_GRAPH_SCHEMA.to_string(),
        project_root: ".".to_string(),
        root_package_id,
        packages,
        dependency_edges,
        lockfile_pins,
    };
    let bytes = serialize_payload(&payload)?;
    let canonical_hash = canonical_hash(&bytes);

    Ok(ModuleResolutionGraph {
        schema_version: payload.schema_version,
        project_root: payload.project_root,
        root_package_id: payload.root_package_id,
        packages: payload.packages,
        dependency_edges: payload.dependency_edges,
        lockfile_pins: payload.lockfile_pins,
        canonical_hash,
    })
}

pub fn canonical_module_resolution_graph_bytes(
    graph: &ModuleResolutionGraph,
) -> ModuleResolutionGraphResult<Vec<u8>> {
    serialize_payload(&ModuleResolutionGraphPayload {
        schema_version: graph.schema_version.clone(),
        project_root: graph.project_root.clone(),
        root_package_id: graph.root_package_id.clone(),
        packages: graph.packages.clone(),
        dependency_edges: graph.dependency_edges.clone(),
        lockfile_pins: graph.lockfile_pins.clone(),
    })
}

pub fn recompute_module_resolution_graph_hash(
    graph: &ModuleResolutionGraph,
) -> ModuleResolutionGraphResult<String> {
    canonical_module_resolution_graph_bytes(graph).map(|bytes| canonical_hash(&bytes))
}

fn parse_manifest(
    project_root: &Path,
    manifest_path: &Path,
    workspace: bool,
) -> ModuleResolutionGraphResult<ParsedManifest> {
    let raw =
        crate::bounded_read_to_string(manifest_path, MAX_PACKAGE_JSON_BYTES).map_err(|source| {
            ModuleResolutionGraphError::Io {
                path: manifest_path.to_path_buf(),
                source,
            }
        })?;
    let value: Value =
        serde_json::from_str(&raw).map_err(|source| ModuleResolutionGraphError::Json {
            path: manifest_path.to_path_buf(),
            source,
        })?;

    let relative_manifest_path = relative_display(project_root, manifest_path);
    let manifest_dir = manifest_path.parent().unwrap_or(project_root);
    let relative_package_dir = relative_display(project_root, manifest_dir);
    let name = value
        .get("name")
        .and_then(Value::as_str)
        .filter(|name| !name.trim().is_empty())
        .map(ToString::to_string);
    let version = value
        .get("version")
        .and_then(Value::as_str)
        .filter(|version| !version.trim().is_empty())
        .map(ToString::to_string);
    let package_id = package_id(name.as_deref(), version.as_deref(), &relative_package_dir);
    let workspace_patterns = if workspace {
        Vec::new()
    } else {
        workspace_patterns(&value)?
    };

    let mut dependencies = Vec::new();
    collect_dependencies(
        &value,
        "dependencies",
        DependencyKind::Production,
        false,
        &mut dependencies,
    )?;
    collect_dependencies(
        &value,
        "devDependencies",
        DependencyKind::Development,
        false,
        &mut dependencies,
    )?;
    collect_dependencies(
        &value,
        "peerDependencies",
        DependencyKind::Peer,
        false,
        &mut dependencies,
    )?;
    collect_dependencies(
        &value,
        "optionalDependencies",
        DependencyKind::Optional,
        true,
        &mut dependencies,
    )?;
    dependencies.sort_by(|left, right| {
        (&left.kind, &left.name, &left.requested_range).cmp(&(
            &right.kind,
            &right.name,
            &right.requested_range,
        ))
    });

    Ok(ParsedManifest {
        relative_manifest_path: relative_manifest_path.clone(),
        package: PackageNode {
            package_id,
            name,
            version,
            relative_manifest_path,
            workspace,
            workspace_patterns,
            exports: conditional_entries(value.get("exports"), true)?,
            imports: conditional_entries(value.get("imports"), false)?,
        },
        dependencies,
    })
}

fn collect_dependencies(
    manifest: &Value,
    field: &'static str,
    kind: DependencyKind,
    optional: bool,
    dependencies: &mut Vec<DependencySpec>,
) -> ModuleResolutionGraphResult<()> {
    let Some(entries) = manifest.get(field).and_then(Value::as_object) else {
        return Ok(());
    };
    for (name, range) in entries {
        let Some(requested_range) = range.as_str() else {
            continue;
        };
        dependencies.push(DependencySpec {
            name: name.clone(),
            requested_range: requested_range.to_string(),
            kind,
            optional,
        });
        enforce_len("dependency edges", dependencies.len(), MAX_DEPENDENCY_EDGES)?;
    }
    Ok(())
}

fn workspace_patterns(manifest: &Value) -> ModuleResolutionGraphResult<Vec<String>> {
    let Some(workspaces) = manifest.get("workspaces") else {
        return Ok(Vec::new());
    };
    let mut patterns = Vec::new();
    match workspaces {
        Value::Array(items) => {
            for item in items {
                if let Some(pattern) = item.as_str() {
                    patterns.push(pattern.to_string());
                }
            }
        }
        Value::Object(object) => {
            if let Some(Value::Array(items)) = object.get("packages") {
                for item in items {
                    if let Some(pattern) = item.as_str() {
                        patterns.push(pattern.to_string());
                    }
                }
            }
        }
        _ => {}
    }
    patterns.sort();
    patterns.dedup();
    enforce_len("workspace patterns", patterns.len(), MAX_WORKSPACE_PATTERNS)?;
    Ok(patterns)
}

fn collect_workspace_manifest_paths(
    project_root: &Path,
    patterns: &[String],
) -> ModuleResolutionGraphResult<Vec<PathBuf>> {
    let mut manifests = BTreeSet::new();
    for pattern in patterns {
        for manifest in expand_workspace_pattern(project_root, pattern)? {
            manifests.insert(manifest);
            enforce_len(
                "package manifests",
                manifests.len().saturating_add(1),
                MAX_PACKAGE_MANIFESTS,
            )?;
        }
    }
    Ok(manifests.into_iter().collect())
}

fn expand_workspace_pattern(
    project_root: &Path,
    pattern: &str,
) -> ModuleResolutionGraphResult<Vec<PathBuf>> {
    if pattern.trim().is_empty() || pattern.contains("..") || pattern.starts_with('/') {
        return Err(ModuleResolutionGraphError::InvalidWorkspacePattern {
            pattern: pattern.to_string(),
        });
    }
    if !pattern.contains('*') {
        let manifest = project_root.join(pattern).join("package.json");
        return Ok(manifest.exists().then_some(manifest).into_iter().collect());
    }
    if pattern.matches('*').count() != 1 || !pattern.ends_with("/*") {
        return Err(ModuleResolutionGraphError::InvalidWorkspacePattern {
            pattern: pattern.to_string(),
        });
    }

    let base = project_root.join(pattern.trim_end_matches("/*"));
    if !base.is_dir() {
        return Ok(Vec::new());
    }
    let mut manifests = Vec::new();
    for entry in std::fs::read_dir(&base).map_err(|source| ModuleResolutionGraphError::Io {
        path: base.clone(),
        source,
    })? {
        let entry = entry.map_err(|source| ModuleResolutionGraphError::Io {
            path: base.clone(),
            source,
        })?;
        let path = entry.path();
        if path.is_dir() {
            let manifest = path.join("package.json");
            if manifest.exists() {
                manifests.push(manifest);
            }
        }
    }
    manifests.sort();
    Ok(manifests)
}

fn conditional_entries(
    field: Option<&Value>,
    exports_field: bool,
) -> ModuleResolutionGraphResult<Vec<ConditionalResolutionEntry>> {
    let Some(field) = field else {
        return Ok(Vec::new());
    };
    let mut entries = Vec::new();
    match field {
        Value::String(_) => {
            entries.push(ConditionalResolutionEntry {
                specifier: ".".to_string(),
                targets: flatten_targets(field)?,
            });
        }
        Value::Object(object) if exports_field && object.keys().any(|key| key.starts_with('.')) => {
            for (specifier, value) in object {
                entries.push(ConditionalResolutionEntry {
                    specifier: specifier.clone(),
                    targets: flatten_targets(value)?,
                });
            }
        }
        Value::Object(object) if !exports_field => {
            for (specifier, value) in object {
                entries.push(ConditionalResolutionEntry {
                    specifier: specifier.clone(),
                    targets: flatten_targets(value)?,
                });
            }
        }
        Value::Object(_) => {
            entries.push(ConditionalResolutionEntry {
                specifier: ".".to_string(),
                targets: flatten_targets(field)?,
            });
        }
        _ => {}
    }

    entries.sort_by(|left, right| left.specifier.cmp(&right.specifier));
    enforce_len(
        "conditional resolution entries",
        entries.len(),
        MAX_CONDITIONAL_TARGETS,
    )?;
    Ok(entries)
}

fn flatten_targets(value: &Value) -> ModuleResolutionGraphResult<Vec<ConditionalTarget>> {
    let mut targets = Vec::new();
    flatten_targets_inner(value, &mut Vec::new(), &mut targets)?;
    targets.sort_by(|left, right| {
        (&left.condition, &left.target).cmp(&(&right.condition, &right.target))
    });
    Ok(targets)
}

fn flatten_targets_inner(
    value: &Value,
    conditions: &mut Vec<String>,
    targets: &mut Vec<ConditionalTarget>,
) -> ModuleResolutionGraphResult<()> {
    match value {
        Value::String(target) => {
            targets.push(ConditionalTarget {
                condition: if conditions.is_empty() {
                    "default".to_string()
                } else {
                    conditions.join(".")
                },
                target: target.clone(),
            });
            enforce_len(
                "conditional targets",
                targets.len(),
                MAX_CONDITIONAL_TARGETS,
            )?;
        }
        Value::Object(object) => {
            for (condition, nested) in object {
                conditions.push(condition.clone());
                flatten_targets_inner(nested, conditions, targets)?;
                conditions.pop();
            }
        }
        Value::Array(items) => {
            for (index, nested) in items.iter().enumerate() {
                conditions.push(format!("array_{index}"));
                flatten_targets_inner(nested, conditions, targets)?;
                conditions.pop();
            }
        }
        Value::Null | Value::Bool(_) | Value::Number(_) => {}
    }
    Ok(())
}

fn read_package_lock(project_root: &Path) -> ModuleResolutionGraphResult<Vec<LockfilePin>> {
    let lockfile_path = project_root.join("package-lock.json");
    if !lockfile_path.exists() {
        return Ok(Vec::new());
    }
    let raw =
        crate::bounded_read_to_string(&lockfile_path, MAX_LOCKFILE_BYTES).map_err(|source| {
            ModuleResolutionGraphError::Io {
                path: lockfile_path.clone(),
                source,
            }
        })?;
    let value: Value =
        serde_json::from_str(&raw).map_err(|source| ModuleResolutionGraphError::Json {
            path: lockfile_path.clone(),
            source,
        })?;

    let mut pins = Vec::new();
    if let Some(packages) = value.get("packages").and_then(Value::as_object) {
        for (package_path, package) in packages {
            if package_path.is_empty() {
                continue;
            }
            let Some(package_name) = package_name_from_lock_path(package_path) else {
                continue;
            };
            pins.push(LockfilePin {
                package_path: package_path.clone(),
                package_name,
                version: package
                    .get("version")
                    .and_then(Value::as_str)
                    .map(ToString::to_string),
                resolved: package
                    .get("resolved")
                    .and_then(Value::as_str)
                    .map(ToString::to_string),
                integrity: package
                    .get("integrity")
                    .and_then(Value::as_str)
                    .map(ToString::to_string),
                dependencies: lockfile_dependencies(package.get("dependencies"))?,
            });
            enforce_len("lockfile packages", pins.len(), MAX_LOCKFILE_PACKAGES)?;
        }
    }
    pins.sort_by(|left, right| left.package_path.cmp(&right.package_path));
    Ok(pins)
}

fn lockfile_dependencies(
    value: Option<&Value>,
) -> ModuleResolutionGraphResult<Vec<LockfileDependency>> {
    let mut dependencies = Vec::new();
    if let Some(object) = value.and_then(Value::as_object) {
        for (name, range) in object {
            let Some(requested_range) = range.as_str() else {
                continue;
            };
            dependencies.push(LockfileDependency {
                name: name.clone(),
                requested_range: requested_range.to_string(),
            });
            enforce_len(
                "lockfile dependencies",
                dependencies.len(),
                MAX_DEPENDENCY_EDGES,
            )?;
        }
    }
    dependencies.sort_by(|left, right| left.name.cmp(&right.name));
    Ok(dependencies)
}

fn package_name_from_lock_path(package_path: &str) -> Option<String> {
    let marker = "node_modules/";
    let offset = package_path.rfind(marker)?;
    let suffix = &package_path[offset + marker.len()..];
    let mut parts = suffix.split('/');
    let first = parts.next()?;
    if first.is_empty() {
        return None;
    }
    if first.starts_with('@') {
        let second = parts.next()?;
        Some(format!("{first}/{second}"))
    } else {
        Some(first.to_string())
    }
}

fn package_id(name: Option<&str>, version: Option<&str>, relative_package_dir: &str) -> String {
    let stable_path = if relative_package_dir.is_empty() {
        "."
    } else {
        relative_package_dir
    };
    match (name, version) {
        (Some(name), Some(version)) => format!("npm:{name}@{version}#{stable_path}"),
        (Some(name), None) => format!("npm:{name}@unknown#{stable_path}"),
        (None, Some(version)) => format!("manifest:{stable_path}@{version}"),
        (None, None) => format!("manifest:{stable_path}"),
    }
}

fn serialize_payload(
    payload: &ModuleResolutionGraphPayload,
) -> ModuleResolutionGraphResult<Vec<u8>> {
    serde_json::to_vec(payload).map_err(|source| ModuleResolutionGraphError::Json {
        path: PathBuf::from("<module-resolution-graph>"),
        source,
    })
}

fn canonical_hash(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(MODULE_RESOLUTION_GRAPH_HASH_DOMAIN);
    hasher.update(bytes);
    format!("sha256:{}", hex::encode(hasher.finalize()))
}

fn relative_display(root: &Path, path: &Path) -> String {
    path.strip_prefix(root)
        .unwrap_or(path)
        .to_string_lossy()
        .replace('\\', "/")
}

fn enforce_len(
    bound: &'static str,
    actual: usize,
    limit: usize,
) -> ModuleResolutionGraphResult<()> {
    if actual > limit {
        return Err(ModuleResolutionGraphError::BoundExceeded { bound, limit });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn canonical_graph_captures_workspaces_lockfile_and_conditions() {
        let tmp = tempdir().expect("tempdir");
        let root = tmp.path();
        std::fs::create_dir_all(root.join("packages/app")).expect("app dir");
        std::fs::create_dir_all(root.join("packages/lib")).expect("lib dir");
        std::fs::write(
            root.join("package.json"),
            r##"{
                "name": "root-app",
                "version": "1.0.0",
                "workspaces": ["packages/*"],
                "dependencies": {"left-pad": "^1.3.0"},
                "devDependencies": {"@scope/tool": "~2.0.0"},
                "exports": {
                    ".": {"import": "./esm/index.js", "require": "./cjs/index.cjs"},
                    "./feature": {"node": {"import": "./esm/feature.js"}}
                },
                "imports": {"#internal": {"default": "./src/internal.js"}}
            }"##,
        )
        .expect("root package");
        std::fs::write(
            root.join("packages/app/package.json"),
            r#"{"name":"@acme/app","version":"0.1.0","dependencies":{"@acme/lib":"workspace:*"}}"#,
        )
        .expect("app package");
        std::fs::write(
            root.join("packages/lib/package.json"),
            r#"{"name":"@acme/lib","version":"0.1.0","peerDependencies":{"react":"^18.2.0"}}"#,
        )
        .expect("lib package");
        std::fs::write(
            root.join("package-lock.json"),
            r#"{
                "lockfileVersion": 3,
                "packages": {
                    "": {"name": "root-app", "version": "1.0.0"},
                    "node_modules/left-pad": {
                        "version": "1.3.0",
                        "resolved": "https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz",
                        "integrity": "sha512-left",
                        "dependencies": {"repeat-string": "^1.6.1"}
                    },
                    "node_modules/@scope/tool": {
                        "version": "2.0.1",
                        "integrity": "sha512-tool"
                    },
                    "node_modules/repeat-string": {"version": "1.6.1"}
                }
            }"#,
        )
        .expect("lockfile");

        let graph = build_canonical_module_resolution_graph(root).expect("graph");

        assert_eq!(graph.schema_version, MODULE_RESOLUTION_GRAPH_SCHEMA);
        assert_eq!(graph.packages.len(), 3);
        assert_eq!(graph.lockfile_pins.len(), 3);
        assert!(graph.dependency_edges.iter().any(|edge| {
            edge.dependency_name == "@acme/lib"
                && edge
                    .target_package_id
                    .as_deref()
                    .is_some_and(|id| id.contains("@acme/lib"))
        }));
        assert!(
            graph
                .dependency_edges
                .iter()
                .any(|edge| edge.dependency_name == "left-pad"
                    && edge.lockfile_package_path.as_deref() == Some("node_modules/left-pad"))
        );

        let root_package = graph
            .packages
            .iter()
            .find(|package| package.name.as_deref() == Some("root-app"))
            .expect("root package node");
        let export_targets = root_package
            .exports
            .iter()
            .find(|entry| entry.specifier == ".")
            .expect("root export")
            .targets
            .iter()
            .map(|target| (target.condition.as_str(), target.target.as_str()))
            .collect::<BTreeSet<_>>();
        assert!(export_targets.contains(&("import", "./esm/index.js")));
        assert!(export_targets.contains(&("require", "./cjs/index.cjs")));

        let bytes = canonical_module_resolution_graph_bytes(&graph).expect("canonical bytes");
        let hash = recompute_module_resolution_graph_hash(&graph).expect("hash");
        assert_eq!(graph.canonical_hash, hash);
        assert!(
            String::from_utf8(bytes)
                .expect("json")
                .contains("\"dependency_edges\"")
        );
    }

    #[test]
    fn graph_is_deterministic_for_repeated_builds() {
        let tmp = tempdir().expect("tempdir");
        let root = tmp.path();
        std::fs::write(
            root.join("package.json"),
            r#"{"name":"deterministic","version":"1.0.0","dependencies":{"b":"2","a":"1"}}"#,
        )
        .expect("package");

        let first = build_canonical_module_resolution_graph(root).expect("first");
        let second = build_canonical_module_resolution_graph(root).expect("second");

        assert_eq!(first, second);
        assert_eq!(
            canonical_module_resolution_graph_bytes(&first).expect("first bytes"),
            canonical_module_resolution_graph_bytes(&second).expect("second bytes")
        );
    }

    #[test]
    fn missing_manifest_fails_closed() {
        let tmp = tempdir().expect("tempdir");
        let error = build_canonical_module_resolution_graph(tmp.path())
            .expect_err("missing manifest must fail");

        assert!(matches!(
            error,
            ModuleResolutionGraphError::MissingRootManifest { .. }
        ));
    }

    #[test]
    fn unsupported_workspace_pattern_fails_closed() {
        let tmp = tempdir().expect("tempdir");
        std::fs::write(
            tmp.path().join("package.json"),
            r#"{"name":"bad-workspace","version":"1.0.0","workspaces":["../*"]}"#,
        )
        .expect("package");

        let error = build_canonical_module_resolution_graph(tmp.path())
            .expect_err("workspace escape must fail");

        assert!(matches!(
            error,
            ModuleResolutionGraphError::InvalidWorkspacePattern { .. }
        ));
    }
}
