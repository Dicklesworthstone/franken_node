//! Executable transitive and reverse-impact analysis of captured npm metadata.
//!
//! Package locations, not package names, identify installed nodes. Lookup uses
//! the same nearest-node_modules resolver as direct workspace edges. Workspace
//! links traverse the real captured workspace before resolving its requirements.
//! No source code, package manager, network, semver solver or live loader runs.
//! Legacy requires records cannot prove modern dependency-kind completeness.

use super::{
    DependencyKind, LockfileDetails, ModuleResolutionGraph, ModuleResolutionGraphError,
    ModuleResolutionGraphResult, build_graph_parts, enforce_len, invalid_metadata,
    manifest_directory, nearest_lockfile_pin,
};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::path::Path;

const SCHEMA: &str = "franken-node/module-dependency-topology/v1";
const HASH_DOMAIN: &[u8] = b"franken-node/module-dependency-topology/v1\0";
const MAX_NODES: usize = super::MAX_PACKAGE_MANIFESTS + super::MAX_LOCKFILE_PACKAGES;
const MAX_EDGES: usize = super::MAX_DEPENDENCY_EDGES + super::MAX_LOCKFILE_DEPENDENCY_EDGES;
const MAX_TEXT_BYTES: usize = 32 * 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PackageSource {
    Manifest,
    Lockfile,
    WorkspaceLink,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PackageLocation {
    pub location: String,
    pub manifest_path: String,
    pub name: Option<String>,
    pub version: Option<String>,
    pub source: PackageSource,
    pub link_target: Option<String>,
    pub dependency_kinds_complete: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Selection {
    Lockfile,
    WorkspaceIntent,
    Unresolved,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Requirement {
    pub importer: String,
    pub dependency_name: String,
    pub requested_range: String,
    /// None means npm v1 requires data did not preserve dependency kinds.
    pub dependency_kind: Option<DependencyKind>,
    pub optional: bool,
    pub target: Option<String>,
    pub selection: Selection,
}

/// One declared identity that must be consulted by a package trust gate.
/// The installation name can be an npm alias; `package_name` is its target.
/// These are bounded metadata observations, not proof of installed contents
/// or a complete inventory of dynamically loaded JavaScript.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct TrustDependency {
    pub importer: String,
    pub dependency_name: String,
    pub package_name: String,
    pub requested_range: String,
    pub dependency_kind: Option<DependencyKind>,
    pub target: Option<String>,
    pub pinned_version: Option<String>,
    pub integrity: Option<String>,
}

#[derive(Debug)]
struct TrustPin {
    version: Option<String>,
    integrity: Option<String>,
}

fn requested_package_name<'a>(
    installed_as: &'a str,
    requested_range: &'a str,
) -> ModuleResolutionGraphResult<&'a str> {
    super::validate_package_name(installed_as)?;
    let Some(alias) = requested_range.strip_prefix("npm:") else {
        return Ok(installed_as);
    };
    let name = match alias.rfind('@').filter(|index| *index > 0) {
        Some(index) => {
            if alias[index + 1..].is_empty() {
                return invalid_metadata("npm alias version must not be empty");
            }
            &alias[..index]
        }
        None => alias,
    };
    super::validate_package_name(name)?;
    Ok(name)
}

/// Constructed only by the bounded metadata builder. No unsigned JSON-import
/// approval path: private graph storage keeps query indices consistent.
#[derive(Debug, Serialize)]
pub struct DependencyTopology {
    schema_version: &'static str,
    source_graph_hash: String,
    canonical_hash: String,
    nodes: Vec<PackageLocation>,
    edges: Vec<Requirement>,
    #[serde(skip)]
    locations: BTreeMap<String, usize>,
    #[serde(skip)]
    forward: Vec<Vec<usize>>,
    #[serde(skip)]
    reverse: Vec<Vec<usize>>,
    // Captured by the same parse as source_graph_hash, which binds these
    // exact pins. Queries never reopen a lockfile or select by name alone.
    #[serde(skip)]
    trust_pins: BTreeMap<String, TrustPin>,
}

#[derive(Debug, Serialize)]
pub struct Closure {
    pub start: String,
    /// Sorted locations, including the starting package and explicit links.
    pub reachable: Vec<String>,
    pub metadata_complete: bool,
    /// Indices into the accompanying topology's edges, never guessed targets.
    pub unresolved_edges: Vec<usize>,
    pub unresolved_required_edges: usize,
    pub unresolved_optional_edges: usize,
    pub intent_only_edges: Vec<usize>,
    pub fully_resolved: bool,
}

#[derive(Debug, Serialize)]
pub struct ImpactHop {
    pub location: String,
    /// One deterministic shortest-path step toward the queried location.
    pub next: String,
}

#[derive(Debug, Serialize)]
pub struct Impact {
    pub target: String,
    pub affected_locations: Vec<String>,
    pub affected_manifests: Vec<String>,
    /// A bounded shared witness tree, not exponentially many dependency paths.
    pub toward_target: Vec<ImpactHop>,
    /// Global gaps can conceal additional dependents, even outside the known
    /// reverse closure. An empty affected set is not proof of no exposure.
    pub metadata_complete: bool,
    pub unresolved_edges: Vec<usize>,
    pub intent_only_edges: Vec<usize>,
    pub fully_resolved: bool,
}

/// One metadata capture feeds the direct graph hash and the richer topology.
/// The topology's own hash also binds peer/optional requirements and links;
/// a legacy direct-graph hash alone must not approve a transitive assessment.
pub fn build(project_root: impl AsRef<Path>) -> ModuleResolutionGraphResult<DependencyTopology> {
    let (graph, details) = build_graph_parts(project_root.as_ref())?;
    from_parts(&graph, &details)
}

fn location(manifest: &str) -> String {
    let directory = manifest_directory(manifest);
    if directory.is_empty() {
        ".".into()
    } else {
        directory.into()
    }
}

fn reserve_text(used: &mut usize, bytes: usize) -> ModuleResolutionGraphResult<()> {
    *used = used.saturating_add(bytes);
    enforce_len("dependency topology text bytes", *used, MAX_TEXT_BYTES)
}

fn from_parts(
    graph: &ModuleResolutionGraph,
    details: &LockfileDetails,
) -> ModuleResolutionGraphResult<DependencyTopology> {
    let mut nodes = BTreeMap::new();
    let mut package_ids = BTreeMap::new();
    let mut text_bytes = 0;
    for package in &graph.packages {
        let loc = location(&package.relative_manifest_path);
        package_ids.insert(package.package_id.as_str(), loc.clone());
        nodes.insert(
            loc.clone(),
            PackageLocation {
                location: loc,
                manifest_path: package.relative_manifest_path.clone(),
                name: package.name.clone(),
                version: package.version.clone(),
                source: PackageSource::Manifest,
                link_target: None,
                dependency_kinds_complete: true,
            },
        );
    }
    for pin in &graph.lockfile_pins {
        let link_target = details.links.get(&pin.package_path).cloned();
        if let Some(target) = &link_target {
            if !nodes.contains_key(target) {
                return invalid_metadata("topology link target is not a captured workspace");
            }
            if details
                .requirements
                .get(&pin.package_path)
                .is_some_and(|requirements| !requirements.is_empty())
            {
                return invalid_metadata(
                    "workspace link cannot carry conflicting installed dependency requirements",
                );
            }
        }
        let node = PackageLocation {
            location: pin.package_path.clone(),
            manifest_path: format!("{}/package.json", pin.package_path),
            name: Some(pin.package_name.clone()),
            version: pin.version.clone(),
            source: if link_target.is_some() {
                PackageSource::WorkspaceLink
            } else {
                PackageSource::Lockfile
            },
            dependency_kinds_complete: details.dependency_kinds_complete,
            link_target,
        };
        if nodes.insert(pin.package_path.clone(), node).is_some() {
            return invalid_metadata("installed location collides with a captured manifest");
        }
    }
    enforce_len("dependency topology nodes", nodes.len(), MAX_NODES)?;
    for node in nodes.values() {
        reserve_text(
            &mut text_bytes,
            node.location.len()
                + node.manifest_path.len()
                + node.name.as_ref().map_or(0, String::len)
                + node.version.as_ref().map_or(0, String::len)
                + node.link_target.as_ref().map_or(0, String::len),
        )?;
    }
    let mut edges = Vec::new();
    let mut append = |edge: Requirement| -> ModuleResolutionGraphResult<()> {
        reserve_text(
            &mut text_bytes,
            edge.importer.len()
                + edge.dependency_name.len()
                + edge.requested_range.len()
                + edge.target.as_ref().map_or(0, String::len),
        )?;
        enforce_len("dependency topology edges", edges.len() + 1, MAX_EDGES)?;
        edges.push(edge);
        Ok(())
    };
    for edge in &graph.dependency_edges {
        let importer = package_ids
            .get(edge.from_package_id.as_str())
            .ok_or_else(|| ModuleResolutionGraphError::InvalidMetadata {
                detail: "dependency importer missing from graph".into(),
            })?;
        let target = edge.lockfile_package_path.clone().or_else(|| {
            edge.target_package_id
                .as_deref()
                .and_then(|id| package_ids.get(id).cloned())
        });
        let selection = if edge.lockfile_package_path.is_some() {
            Selection::Lockfile
        } else if target.is_some() {
            Selection::WorkspaceIntent
        } else {
            Selection::Unresolved
        };
        append(Requirement {
            importer: importer.clone(),
            dependency_name: edge.dependency_name.clone(),
            requested_range: edge.requested_range.clone(),
            dependency_kind: Some(edge.dependency_kind),
            optional: edge.optional,
            target,
            selection,
        })?;
    }
    let pins = graph
        .lockfile_pins
        .iter()
        .map(|pin| (pin.package_path.as_str(), pin))
        .collect();
    for (importer, requirements) in &details.requirements {
        if details.links.contains_key(importer) {
            continue;
        }
        for requirement in requirements {
            let selected = nearest_lockfile_pin(importer, &requirement.name, &pins);
            append(Requirement {
                importer: importer.clone(),
                dependency_name: requirement.name.clone(),
                requested_range: requirement.requested_range.clone(),
                dependency_kind: details
                    .dependency_kinds_complete
                    .then_some(requirement.kind),
                optional: requirement.optional,
                target: selected.map(|pin| pin.package_path.clone()),
                selection: if selected.is_some() {
                    Selection::Lockfile
                } else {
                    Selection::Unresolved
                },
            })?;
        }
    }
    edges.sort_by(|left, right| {
        (&left.importer, &left.dependency_kind, &left.dependency_name).cmp(&(
            &right.importer,
            &right.dependency_kind,
            &right.dependency_name,
        ))
    });
    let nodes: Vec<_> = nodes.into_values().collect();
    let locations: BTreeMap<_, _> = nodes
        .iter()
        .enumerate()
        .map(|(index, node)| (node.location.clone(), index))
        .collect();
    let mut forward = vec![BTreeSet::new(); nodes.len()];
    let mut reverse = forward.clone();
    let mut connect = |from: &str, to: &str| -> ModuleResolutionGraphResult<()> {
        let source =
            locations
                .get(from)
                .ok_or_else(|| ModuleResolutionGraphError::InvalidMetadata {
                    detail: format!("topology importer {from:?} is unavailable"),
                })?;
        let target =
            locations
                .get(to)
                .ok_or_else(|| ModuleResolutionGraphError::InvalidMetadata {
                    detail: format!("topology target {to:?} is unavailable"),
                })?;
        forward[*source].insert(*target);
        reverse[*target].insert(*source);
        Ok(())
    };
    for node in &nodes {
        if let Some(target) = &node.link_target {
            connect(&node.location, target)?;
        }
    }
    for edge in &edges {
        if let Some(target) = &edge.target {
            connect(&edge.importer, target)?;
        }
    }
    let mut topology = DependencyTopology {
        schema_version: SCHEMA,
        source_graph_hash: graph.canonical_hash.clone(),
        canonical_hash: String::new(),
        nodes,
        edges,
        locations,
        forward: forward
            .into_iter()
            .map(|row| row.into_iter().collect())
            .collect(),
        reverse: reverse
            .into_iter()
            .map(|row| row.into_iter().collect())
            .collect(),
        trust_pins: graph
            .lockfile_pins
            .iter()
            .filter(|pin| !details.links.contains_key(&pin.package_path))
            .map(|pin| {
                (
                    pin.package_path.clone(),
                    TrustPin {
                        version: pin.version.clone(),
                        integrity: pin.integrity.clone(),
                    },
                )
            })
            .collect(),
    };
    // Empty hash is a fixed sentinel in the preimage, not a recursive hash.
    let bytes =
        serde_json::to_vec(&topology).map_err(|source| ModuleResolutionGraphError::Json {
            path: "<dependency-topology>".into(),
            source,
        })?;
    let mut hash = Sha256::new();
    hash.update(HASH_DOMAIN);
    hash.update((bytes.len() as u64).to_le_bytes());
    hash.update(bytes);
    topology.canonical_hash = format!("sha256:{}", hex::encode(hash.finalize()));
    Ok(topology)
}

impl DependencyTopology {
    pub fn canonical_hash(&self) -> &str {
        &self.canonical_hash
    }
    pub fn nodes(&self) -> &[PackageLocation] {
        &self.nodes
    }
    pub fn edges(&self) -> &[Requirement] {
        &self.edges
    }

    /// Select root and known transitive package identities for trust checks.
    /// Production runs exclude development-only edges; scanning may include
    /// them. Optional and peer requirements remain visible, even unresolved,
    /// so absence of a lockfile pin never hides a known revoked identity.
    /// Workspace links traverse their captured target before its dependencies.
    /// Every location is visited once, including cyclic and nested installs.
    pub fn trust_dependencies(
        &self,
        start: &str,
        include_development: bool,
    ) -> ModuleResolutionGraphResult<Vec<TrustDependency>> {
        let start = self.index(start)?;
        let mut outgoing = vec![Vec::new(); self.nodes.len()];
        for (index, edge) in self.edges.iter().enumerate() {
            if include_development || edge.dependency_kind != Some(DependencyKind::Development) {
                outgoing[self.locations[&edge.importer]].push(index);
            }
        }
        let mut visited = vec![false; self.nodes.len()];
        let mut pending = VecDeque::from([start]);
        visited[start] = true;
        let mut result = Vec::new();
        let mut text_bytes = 0;
        while let Some(index) = pending.pop_front() {
            let node = &self.nodes[index];
            if let Some(target) = &node.link_target {
                let next = self.index(target)?;
                if !visited[next] {
                    visited[next] = true;
                    pending.push_back(next);
                }
            }
            for &edge_index in &outgoing[index] {
                let edge = &self.edges[edge_index];
                let package_name =
                    requested_package_name(&edge.dependency_name, &edge.requested_range)?;
                if let Some(target) = &edge.target {
                    let next = self.index(target)?;
                    let selected = &self.nodes[next];
                    if let Some(name) = &selected.name {
                        // Older locks can omit an alias's actual name, in
                        // which case the path-derived installation name is
                        // all we know. It must never replace the explicit
                        // alias target used for trust/revocation lookup.
                        if name != package_name && name != &edge.dependency_name {
                            return invalid_metadata(format!(
                                "dependency {} from {} requests {package_name:?}, but its captured target {target:?} names {name:?}",
                                edge.dependency_name, edge.importer
                            ));
                        }
                    }
                    if let Some(version) = &selected.version
                        && version.starts_with("npm:")
                        && requested_package_name(&edge.dependency_name, version)? != package_name
                    {
                        return invalid_metadata(format!(
                            "dependency {} from {} has a conflicting captured npm alias",
                            edge.dependency_name, edge.importer
                        ));
                    }
                    if !visited[next] {
                        visited[next] = true;
                        pending.push_back(next);
                    }
                }
                let pin = edge
                    .target
                    .as_ref()
                    .and_then(|target| self.trust_pins.get(target));
                let pinned_version =
                    pin.and_then(|pin| pin.version.as_deref())
                        .and_then(|version| {
                            if let Some(alias) = version.strip_prefix("npm:") {
                                alias
                                    .rfind('@')
                                    .filter(|index| *index > 0)
                                    .map(|index| &alias[index + 1..])
                            } else {
                                Some(version)
                            }
                        });
                let integrity = pin.and_then(|pin| pin.integrity.as_deref());
                reserve_text(
                    &mut text_bytes,
                    edge.importer.len()
                        + edge.dependency_name.len()
                        + package_name.len()
                        + edge.requested_range.len()
                        + edge.target.as_ref().map_or(0, String::len)
                        + pinned_version.map_or(0, str::len)
                        + integrity.map_or(0, str::len),
                )?;
                result.push(TrustDependency {
                    importer: edge.importer.clone(),
                    dependency_name: edge.dependency_name.clone(),
                    package_name: package_name.to_owned(),
                    requested_range: edge.requested_range.clone(),
                    dependency_kind: edge.dependency_kind,
                    target: edge.target.clone(),
                    pinned_version: pinned_version.map(str::to_owned),
                    integrity: integrity.map(str::to_owned),
                });
            }
        }
        // Root observations precede transitive ones when callers deduplicate
        // by registry identity; all locations were still traversed above.
        result.sort_by(|left, right| {
            (&left.importer, &left.dependency_kind, &left.dependency_name).cmp(&(
                &right.importer,
                &right.dependency_kind,
                &right.dependency_name,
            ))
        });
        Ok(result)
    }

    fn index(&self, location: &str) -> ModuleResolutionGraphResult<usize> {
        self.locations.get(location).copied().ok_or_else(|| {
            ModuleResolutionGraphError::InvalidMetadata {
                detail: format!("unknown exact package location {location:?}"),
            }
        })
    }

    /// Includes dependencies of workspace links from their real location.
    /// Traversal is iterative and visits each location once, including cycles.
    pub fn closure(&self, start: &str) -> ModuleResolutionGraphResult<Closure> {
        let (visited, _) = self.walk(self.index(start)?, &self.forward);
        let reachable = self
            .nodes
            .iter()
            .enumerate()
            .filter(|(index, _)| visited[*index])
            .map(|(_, node)| node.location.clone())
            .collect();
        let metadata_complete = self
            .nodes
            .iter()
            .enumerate()
            .all(|(index, node)| !visited[index] || node.dependency_kinds_complete);
        let unresolved_edges: Vec<_> = self
            .edges
            .iter()
            .enumerate()
            .filter(|(_, edge)| {
                visited[self.locations[&edge.importer]] && edge.selection == Selection::Unresolved
            })
            .map(|(index, _)| index)
            .collect();
        let unresolved_optional_edges = unresolved_edges
            .iter()
            .filter(|index| self.edges[**index].optional)
            .count();
        let intent_only_edges: Vec<_> = self
            .edges
            .iter()
            .enumerate()
            .filter(|(_, edge)| {
                visited[self.locations[&edge.importer]]
                    && edge.selection == Selection::WorkspaceIntent
            })
            .map(|(index, _)| index)
            .collect();
        Ok(Closure {
            start: start.into(),
            reachable,
            metadata_complete,
            fully_resolved: metadata_complete
                && unresolved_edges.is_empty()
                && intent_only_edges.is_empty(),
            unresolved_required_edges: unresolved_edges.len() - unresolved_optional_edges,
            unresolved_optional_edges,
            unresolved_edges,
            intent_only_edges,
        })
    }

    /// Known reverse reachability plus a shared shortest-path witness tree.
    /// Completeness is global: an unresolved branch may conceal another path.
    pub fn impact(&self, target: &str) -> ModuleResolutionGraphResult<Impact> {
        let target_index = self.index(target)?;
        let (visited, next) = self.walk(target_index, &self.reverse);
        let mut affected_locations = Vec::new();
        let mut affected_manifests = Vec::new();
        let mut toward_target = Vec::new();
        for (index, node) in self.nodes.iter().enumerate() {
            if !visited[index] {
                continue;
            }
            affected_locations.push(node.location.clone());
            if node.source == PackageSource::Manifest {
                affected_manifests.push(node.manifest_path.clone());
            }
            if let Some(next) = next[index] {
                toward_target.push(ImpactHop {
                    location: node.location.clone(),
                    next: self.nodes[next].location.clone(),
                });
            }
        }
        let metadata_complete = self.nodes.iter().all(|node| node.dependency_kinds_complete);
        let unresolved_edges: Vec<_> = self
            .edges
            .iter()
            .enumerate()
            .filter(|(_, edge)| edge.selection == Selection::Unresolved)
            .map(|(index, _)| index)
            .collect();
        let intent_only_edges: Vec<_> = self
            .edges
            .iter()
            .enumerate()
            .filter(|(_, edge)| edge.selection == Selection::WorkspaceIntent)
            .map(|(index, _)| index)
            .collect();
        Ok(Impact {
            target: target.into(),
            affected_locations,
            affected_manifests,
            toward_target,
            metadata_complete,
            fully_resolved: metadata_complete
                && unresolved_edges.is_empty()
                && intent_only_edges.is_empty(),
            unresolved_edges,
            intent_only_edges,
        })
    }

    fn walk(&self, start: usize, adjacency: &[Vec<usize>]) -> (Vec<bool>, Vec<Option<usize>>) {
        let mut visited = vec![false; self.nodes.len()];
        let mut parent = vec![None; self.nodes.len()];
        let mut pending = VecDeque::from([start]);
        visited[start] = true;
        while let Some(index) = pending.pop_front() {
            for &neighbor in &adjacency[index] {
                if !visited[neighbor] {
                    visited[neighbor] = true;
                    parent[neighbor] = Some(index);
                    pending.push_back(neighbor);
                }
            }
        }
        (visited, parent)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{Value, json};
    use std::fs;

    fn put(root: &Path, name: &str, value: Value) {
        let path = root.join(name);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, value.to_string()).unwrap();
    }
    fn fixture(packages: Value) -> tempfile::TempDir {
        let root = tempfile::tempdir().unwrap();
        put(
            root.path(),
            "package.json",
            json!({"name":"root", "dependencies":{"a":"*"}}),
        );
        put(
            root.path(),
            "package-lock.json",
            json!({"lockfileVersion":3, "packages":packages}),
        );
        root
    }

    #[test]
    fn trust_walk_tracks_nested_pins_cycles_and_optional_peers_but_excludes_development() {
        let root = fixture(json!({
            "node_modules/a":{"version":"1", "dependencies":{"b":"2"},
                "optionalDependencies":{"missing":"1"}, "peerDependencies":{"host":"*"}},
            "node_modules/a/node_modules/b":{"version":"2", "integrity":"sha512-bmVzdGVk",
                "dependencies":{"a":"1"}},
            "node_modules/b":{"version":"9", "integrity":"sha512-dW5yZWFjaGVk"},
            "node_modules/dev":{"dependencies":{"dev-child":"1"}},
            "node_modules/dev-child":{"version":"1"}
        }));
        put(
            root.path(),
            "package.json",
            json!({"dependencies":{"a":"1"},
            "devDependencies":{"dev":"1"}}),
        );
        let topology = build(root.path()).unwrap();
        let runtime = topology.trust_dependencies(".", false).unwrap();
        assert_eq!(
            runtime.len(),
            5,
            "cycle must terminate while retaining requirements"
        );
        assert!(
            !runtime
                .iter()
                .any(|entry| entry.package_name.starts_with("dev"))
        );
        let nested = runtime
            .iter()
            .find(|entry| entry.package_name == "b")
            .unwrap();
        assert_eq!(
            nested.target.as_deref(),
            Some("node_modules/a/node_modules/b")
        );
        assert_eq!(nested.pinned_version.as_deref(), Some("2"));
        assert_eq!(nested.integrity.as_deref(), Some("sha512-bmVzdGVk"));
        for missing in ["missing", "host"] {
            assert!(
                runtime
                    .iter()
                    .any(|entry| entry.package_name == missing && entry.target.is_none())
            );
        }
        let scan = topology.trust_dependencies(".", true).unwrap();
        assert!(scan.iter().any(|entry| entry.package_name == "dev-child"));
        // Metadata queries use the original capture, never a later name-only
        // lookup against a replacement lockfile.
        put(root.path(), "package-lock.json", json!({"packages":{}}));
        assert_eq!(runtime, topology.trust_dependencies(".", false).unwrap());
    }

    #[test]
    fn trust_aliases_keep_the_declared_target_and_refuse_conflicting_captured_names() {
        let root = fixture(json!({"node_modules/a":{"name":"@scope/actual", "version":"2.3.4"}}));
        put(
            root.path(),
            "package.json",
            json!({"dependencies":{"a":"npm:@scope/actual@^2"}}),
        );
        let selected = build(root.path())
            .unwrap()
            .trust_dependencies(".", false)
            .unwrap();
        assert_eq!(selected[0].package_name, "@scope/actual");
        assert_eq!(selected[0].dependency_name, "a");
        assert_eq!(selected[0].pinned_version.as_deref(), Some("2.3.4"));
        put(
            root.path(),
            "package-lock.json",
            json!({"packages":{
                "node_modules/a":{"name":"unrelated", "version":"2.3.4"}
            }}),
        );
        assert!(
            build(root.path())
                .unwrap()
                .trust_dependencies(".", false)
                .is_err()
        );
        for malformed in [
            "npm:",
            "npm:@scope",
            "npm:../escape@1",
            "npm:actual@",
            "npm:actual@1@2",
        ] {
            assert!(
                requested_package_name("alias", malformed).is_err(),
                "{malformed}"
            );
        }
        assert!(requested_package_name("../escape", "npm:actual@1").is_err());
        assert_eq!(
            requested_package_name("alias", "npm:@scope/actual").unwrap(),
            "@scope/actual"
        );
    }

    #[test]
    fn trust_walk_includes_legacy_requires_and_resolves_alias_pin_versions() {
        let root = fixture(json!({}));
        put(
            root.path(),
            "package.json",
            json!({"dependencies":{"a":"npm:actual@^1"}}),
        );
        put(
            root.path(),
            "package-lock.json",
            json!({"lockfileVersion":1,"dependencies":{
                "a":{"version":"npm:actual@1.2.3", "requires":{"nested":"2"},
                    "dependencies":{"nested":{"version":"2"}}}
            }}),
        );
        let selected = build(root.path())
            .unwrap()
            .trust_dependencies(".", false)
            .unwrap();
        assert_eq!(selected[0].package_name, "actual");
        assert_eq!(selected[0].pinned_version.as_deref(), Some("1.2.3"));
        assert_eq!(selected[1].package_name, "nested");
        assert_eq!(selected[1].dependency_kind, None);
        assert_eq!(selected[1].pinned_version.as_deref(), Some("2"));
    }

    #[test]
    fn trust_walk_uses_shrinkwrap_and_does_not_fall_back_after_its_failure() {
        let root = fixture(json!({"node_modules/a":{"version":"1"}}));
        put(
            root.path(),
            "npm-shrinkwrap.json",
            json!({"lockfileVersion":3,"packages":{
                "node_modules/a":{"version":"2", "dependencies":{"contained":"1"}}
            }}),
        );
        let selected = build(root.path())
            .unwrap()
            .trust_dependencies(".", false)
            .unwrap();
        assert_eq!(selected[0].pinned_version.as_deref(), Some("2"));
        assert!(
            selected
                .iter()
                .any(|entry| entry.package_name == "contained")
        );
        std::fs::write(root.path().join("npm-shrinkwrap.json"), "{").unwrap();
        assert!(build(root.path()).is_err());
    }

    #[test]
    fn nested_transitive_versions_keep_distinct_locations_and_exact_reverse_impact() {
        let root = fixture(json!({
            "node_modules/a":{"version":"1", "dependencies":{"b":"2"}},
            "node_modules/a/node_modules/b":{"version":"2", "dependencies":{"c":"*"}},
            "node_modules/b":{"version":"1"}, "node_modules/c":{"version":"3"}
        }));
        let graph = build(root.path()).unwrap();
        let closure = graph.closure(".").unwrap();
        assert!(closure.fully_resolved);
        assert_eq!(
            closure.reachable,
            [
                ".",
                "node_modules/a",
                "node_modules/a/node_modules/b",
                "node_modules/c"
            ]
        );
        assert_eq!(
            graph
                .impact("node_modules/b")
                .unwrap()
                .affected_manifests
                .len(),
            0
        );
        let impact = graph.impact("node_modules/c").unwrap();
        assert_eq!(impact.affected_manifests, ["package.json"]);
        assert_eq!(impact.toward_target.len(), 3);
        assert_eq!(impact.toward_target[0].next, "node_modules/a");
        assert_eq!(
            impact.toward_target[1].next,
            "node_modules/a/node_modules/b"
        );
    }

    #[test]
    fn cycles_and_diamonds_are_bounded_and_witnesses_choose_a_stable_shortest_path() {
        let root = fixture(json!({
            "node_modules/a":{"dependencies":{"b":"*", "c":"*"}},
            "node_modules/b":{"dependencies":{"d":"*"}},
            "node_modules/c":{"dependencies":{"d":"*"}},
            "node_modules/d":{"dependencies":{"a":"*"}}
        }));
        let graph = build(root.path()).unwrap();
        assert_eq!(graph.closure(".").unwrap().reachable.len(), 5);
        let impact = graph.impact("node_modules/d").unwrap();
        assert_eq!(impact.toward_target.len(), 4);
        assert_eq!(
            impact
                .toward_target
                .iter()
                .find(|hop| hop.location == "node_modules/a")
                .unwrap()
                .next,
            "node_modules/b"
        );
    }

    #[test]
    fn optional_overrides_and_optional_peers_remain_distinct_from_missing_required_edges() {
        let root = fixture(json!({"node_modules/a":{
            "dependencies":{"dep":"wrong", "required":"1"},
            "optionalDependencies":{"dep":"right"}, "peerDependencies":{"host":"*"},
            "peerDependenciesMeta":{"host":{"optional":true}}, "devDependencies":{"not-consumed":"*"}
        }}));
        let graph = build(root.path()).unwrap();
        let closure = graph.closure(".").unwrap();
        assert!(!closure.fully_resolved);
        assert_eq!(closure.unresolved_required_edges, 1);
        assert_eq!(closure.unresolved_optional_edges, 2);
        assert_eq!(graph.edges.len(), 4);
        assert!(graph.edges.iter().any(|edge| edge.dependency_name == "dep"
            && edge.requested_range == "right"
            && edge.dependency_kind == Some(DependencyKind::Optional)));
        assert!(
            !graph
                .edges
                .iter()
                .any(|edge| edge.dependency_name == "not-consumed")
        );
    }

    #[test]
    fn workspace_link_looks_up_requirements_from_the_target_not_the_link_location() {
        let root = fixture(json!({
            "node_modules/a":{"link":true,"resolved":"packages/a"},
            "packages/a/node_modules/dep":{"version":"2"}, "node_modules/dep":{"version":"1"}
        }));
        put(
            root.path(),
            "package.json",
            json!({"workspaces":["packages/*"],"dependencies":{"a":"*"}}),
        );
        put(
            root.path(),
            "packages/a/package.json",
            json!({"name":"a","dependencies":{"dep":"*"}}),
        );
        let graph = build(root.path()).unwrap();
        assert!(graph.closure(".").unwrap().fully_resolved);
        assert_eq!(
            graph.closure("node_modules/a").unwrap().reachable,
            [
                "node_modules/a",
                "packages/a",
                "packages/a/node_modules/dep"
            ]
        );
        assert!(
            graph
                .impact("node_modules/dep")
                .unwrap()
                .affected_manifests
                .is_empty()
        );
        assert_eq!(
            graph
                .impact("packages/a/node_modules/dep")
                .unwrap()
                .affected_manifests
                .len(),
            2
        );
    }

    #[test]
    fn workspace_intent_is_reachable_but_not_installed_evidence() {
        let root = fixture(json!({}));
        put(
            root.path(),
            "package.json",
            json!({"workspaces":["packages/*"],"dependencies":{"a":"workspace:*"}}),
        );
        put(root.path(), "packages/a/package.json", json!({"name":"a"}));
        let graph = build(root.path()).unwrap();
        let closure = graph.closure(".").unwrap();
        assert_eq!(closure.reachable, [".", "packages/a"]);
        assert_eq!(closure.intent_only_edges.len(), 1);
        assert!(!closure.fully_resolved);
        assert!(!graph.impact("packages/a").unwrap().fully_resolved);
    }

    #[test]
    fn unresolved_unrelated_branches_prevent_a_false_complete_negative_impact() {
        let root = fixture(json!({"node_modules/a":{"dependencies":{"missing":"*"}},
            "node_modules/unreferenced":{"version":"1"}}));
        let graph = build(root.path()).unwrap();
        let impact = graph.impact("node_modules/unreferenced").unwrap();
        assert!(impact.affected_manifests.is_empty());
        assert_eq!(impact.unresolved_edges.len(), 1);
        assert!(!impact.fully_resolved);
        assert!(
            graph
                .closure("node_modules/unreferenced")
                .unwrap()
                .fully_resolved
        );
    }

    #[test]
    fn legacy_requires_resolve_without_inventing_modern_dependency_kind_completeness() {
        let root = fixture(json!({}));
        put(
            root.path(),
            "package-lock.json",
            json!({"lockfileVersion":1,"dependencies":{
                "a":{"version":"1","requires":{"b":"2"},"dependencies":{"b":{"version":"2"}}}
            }}),
        );
        let graph = build(root.path()).unwrap();
        let closure = graph.closure(".").unwrap();
        assert_eq!(closure.reachable.len(), 3);
        assert!(closure.unresolved_edges.is_empty());
        assert!(!closure.metadata_complete);
        assert!(!closure.fully_resolved);
        assert!(
            graph
                .edges
                .iter()
                .any(|edge| edge.importer == "node_modules/a" && edge.dependency_kind.is_none())
        );
    }

    #[test]
    fn topology_hash_binds_optional_peer_and_link_facts_not_in_the_legacy_direct_hash() {
        let root = fixture(json!({"node_modules/a":{"optionalDependencies":{"b":"1"}}}));
        let first = build(root.path()).unwrap();
        put(
            root.path(),
            "package-lock.json",
            json!({"lockfileVersion":3,"packages":{
                "node_modules/a":{"optionalDependencies":{"b":"2"}}
            }}),
        );
        let second = build(root.path()).unwrap();
        assert_eq!(first.source_graph_hash, second.source_graph_hash);
        assert_ne!(first.canonical_hash(), second.canonical_hash());
        let other = fixture(json!({"node_modules/a":{"optionalDependencies":{"b":"2"}}}));
        assert_eq!(
            second.canonical_hash(),
            build(other.path()).unwrap().canonical_hash()
        );
    }

    #[test]
    fn captured_topology_queries_never_recapture_later_manifest_or_lockfile_changes() {
        let root =
            fixture(json!({"node_modules/a":{"dependencies":{"b":"*"}},"node_modules/b":{}}));
        let graph = build(root.path()).unwrap();
        let before = serde_json::to_value(graph.impact("node_modules/b").unwrap()).unwrap();
        put(root.path(), "package.json", json!({}));
        put(root.path(), "package-lock.json", json!({"packages":{}}));
        assert_eq!(
            before,
            serde_json::to_value(graph.impact("node_modules/b").unwrap()).unwrap()
        );
        assert!(
            build(root.path())
                .unwrap()
                .impact("node_modules/b")
                .is_err()
        );
    }

    #[test]
    fn malformed_dependency_kinds_and_conflicting_link_requirements_fail_closed() {
        for record in [
            json!({"optionalDependencies":[]}),
            json!({"peerDependencies":{"b":false}}),
            json!({"peerDependenciesMeta":[]}),
            json!({"peerDependenciesMeta":{"b":{"optional":"true"}}}),
        ] {
            let root = fixture(json!({"node_modules/a":record}));
            assert!(build(root.path()).is_err());
        }
        let root = fixture(
            json!({"node_modules/a":{"link":true,"resolved":"packages/a","dependencies":{"x":"*"}}}),
        );
        put(
            root.path(),
            "package.json",
            json!({"workspaces":["packages/*"]}),
        );
        put(root.path(), "packages/a/package.json", json!({"name":"a"}));
        assert!(build(root.path()).is_err());
    }

    #[test]
    fn topology_rejects_unknown_and_noncanonical_locations_instead_of_aliasing_them() {
        let root = fixture(json!({"node_modules/a":{}}));
        let graph = build(root.path()).unwrap();
        for name in [
            "",
            "./",
            "./node_modules/a",
            "node_modules/a/",
            "node_modules//a",
            "missing",
        ] {
            assert!(graph.closure(name).is_err(), "{name}");
            assert!(graph.impact(name).is_err(), "{name}");
        }
    }

    #[test]
    fn deep_flat_cycles_and_shared_witnesses_do_not_recurse_or_enumerate_all_paths() {
        let mut packages = serde_json::Map::new();
        for index in 0..1500 {
            packages.insert(
                format!("node_modules/n{index}"),
                json!({"dependencies":{
                format!("n{}", (index + 1) % 1500):"*"}}),
            );
        }
        let root = fixture(Value::Object(packages));
        put(
            root.path(),
            "package.json",
            json!({"dependencies":{"n0":"*"}}),
        );
        let graph = build(root.path()).unwrap();
        assert_eq!(graph.closure(".").unwrap().reachable.len(), 1501);
        assert_eq!(
            graph
                .impact("node_modules/n1499")
                .unwrap()
                .toward_target
                .len(),
            1500
        );
    }

    #[test]
    fn global_requirement_and_serialized_text_budgets_fail_without_partial_results() {
        let mut details = LockfileDetails {
            edges: super::super::MAX_LOCKFILE_DEPENDENCY_EDGES,
            ..Default::default()
        };
        assert!(
            details
                .record(
                    "node_modules/a",
                    vec![super::super::DependencySpec {
                        name: "b".into(),
                        requested_range: "*".into(),
                        kind: DependencyKind::Production,
                        optional: false,
                    }]
                )
                .is_err()
        );
        let mut used = MAX_TEXT_BYTES;
        assert!(reserve_text(&mut used, 1).is_err());
    }
}
