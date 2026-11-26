//! Bounded selection of npm workspace manifests from the private capture.
//!
//! Selectors support literal components, `*`, `?`, ASCII character classes,
//! standalone `**`, bounded nested brace alternatives, and lock-authority-specific
//! exclusions. Unsupported glob dialects fail explicitly. No installed-package or
//! state-directory traversal, symlink following, package-manager execution or
//! fallback to trusting the lockfile's workspace projection.

use super::{
    Capture, DependencyAdmission, DependencyFinding, LockedPackage, MAX_DEPTH, MAX_LOCK_BYTES,
    MAX_MANIFEST_BYTES, MAX_PACKAGES, SECTIONS, bounded_text, declaration_selection, flag,
    name, nearest_package, time_remaining,
};
use crate::supply_chain::module_resolution_graph::{
    WorkspaceSelectionMode, npm_file_dependency_target, npm_file_manifest_matches,
};
use crate::supply_chain::module_resolution_graph::workspace_selection::{
    self, open_directory as directory,
};
use anyhow::{Context, Result, ensure};
use rustix::fs::{AtFlags, statat};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};

const MAX_PATTERNS: usize = 64;
const MAX_MANIFESTS: usize = 1024;
const MAX_DIRECTORIES: usize = 4096;
const MAX_ENTRIES: usize = 50_000;

pub(super) fn manifest_path(directory: &str) -> String {
    if directory.is_empty() {
        "package.json".into()
    } else {
        format!("{directory}/package.json")
    }
}

/// The root and all selected manifests are read exactly once, even when
/// selectors overlap. Directory handles are reopened relative to the held root
/// instead of retaining one descriptor per queued directory.
pub(super) fn capture(
    capture: &mut Capture,
    root: Value,
    mode: WorkspaceSelectionMode,
) -> Result<BTreeMap<String, Value>> {
    let raw = match root.get("workspaces") {
        None => &[][..],
        Some(value) => value
            .as_array()
            .context("workspaces must be an array of selectors")?
            .as_slice(),
    };
    ensure!(
        raw.len() <= MAX_PATTERNS,
        "workspace selector count exceeds limit"
    );
    let patterns = raw
        .iter()
        .map(|selector| bounded_text(selector, "workspace selector").map(str::to_owned))
        .collect::<Result<Vec<_>>>()?;
    let mut manifests = BTreeMap::from([(String::new(), root)]);
    if patterns.is_empty() {
        return Ok(manifests);
    }
    let mut names = BTreeSet::new();
    if let Some(value) = manifests[""].get("name") {
        names.insert(name(bounded_text(value, "root package name")?)?.to_owned());
    }
    let held_root = capture.root.try_clone()?;
    workspace_selection::walk::<anyhow::Error>(
        &held_root,
        &patterns,
        workspace_selection::Limits {
            mode,
            patterns: MAX_PATTERNS,
            manifests: MAX_MANIFESTS,
            directories: MAX_DIRECTORIES,
            entries: MAX_ENTRIES,
            depth: MAX_DEPTH,
            require_matches: true,
        },
        Some(capture.deadline),
        |path, _| {
            let source = manifest_path(path);
            let Some(manifest) = capture.read(&source, MAX_MANIFEST_BYTES)? else {
                return Ok(false);
            };
            let package = name(bounded_text(
                manifest
                    .get("name")
                    .context("workspace package name missing")?,
                "workspace package name",
            )?)?;
            ensure!(
                names.insert(package.to_owned()),
                "duplicate workspace/root package name"
            );
            // Nested project managers are not silently treated as part of
            // the root's npm resolution contract.
            ensure!(
                manifest.get("workspaces").is_none(),
                "nested workspace configuration requires separate assessment"
            );
            manifests.insert(path.to_owned(), manifest);
            Ok(true)
        },
    )?;
    Ok(manifests)
}

#[derive(Default)]
pub(super) struct LocalDependencies {
    /// Directory dependencies are consumers, not workspace development roots.
    pub directories: BTreeSet<String>,
    /// Only a captured declaration and its nearest exact lock link grant this
    /// position. Arbitrary local descriptors never authorize a new manifest.
    pub links: BTreeMap<String, String>,
}

pub(super) fn capture_file_dependencies(
    capture: &mut Capture,
    manifests: &mut BTreeMap<String, Value>,
    lock: Option<&Value>,
    packages: &BTreeMap<String, LockedPackage>,
) -> Result<LocalDependencies> {
    let mut local = LocalDependencies::default();
    let mut pending: Vec<_> = manifests.keys().cloned().collect();
    let mut count = 0;
    while let Some(consumer) = pending.pop() {
        time_remaining(capture.deadline)?;
        let manifest = manifests[&consumer].clone();
        let edges = declaration_selection::select(
            &manifest,
            !local.directories.contains(&consumer),
            capture.deadline,
            &mut count,
            MAX_PACKAGES,
        )?;
        for edge in edges {
            // Keep unsupported file requests opaque for the declaration review
            // pass. No external, encoded or tarball path is opened here.
            let Ok(Some(target)) = npm_file_dependency_target(&consumer, edge.request) else {
                continue;
            };
            ensure!(
                manifests[""].get("overrides").is_none_or(|rules| {
                    rules.as_object().is_some_and(serde_json::Map::is_empty)
                }),
                "file: dependencies with root overrides require explicit review"
            );
            let selected = nearest_package(packages, &manifest_path(&consumer), edge.installed_as);
            if selected.is_none() && edge.optional {
                continue;
            }
            let selected = selected.context("file: dependency has no nearest locked installation")?;
            let records = lock
                .filter(|lock| matches!(lock.get("lockfileVersion").and_then(Value::as_u64), Some(2 | 3)))
                .and_then(|lock| lock.get("packages"))
                .and_then(Value::as_object)
                .context("file: directory links require an npm v2/v3 packages lock")?;
            ensure!(
                selected.linked
                    && !selected.unresolved
                    && records.get(&selected.path)
                        .and_then(|record| record.get("resolved"))
                        .and_then(Value::as_str) == Some(target.as_str()),
                "file: request differs from its nearest locked link target"
            );
            let recorded = records.get(&target).context("file: link target descriptor is missing")?;
            if !manifests.contains_key(&target) {
                ensure!(manifests.len() < MAX_MANIFESTS, "file dependency manifest count exceeds limit");
                let value = capture.read(&manifest_path(&target), MAX_MANIFEST_BYTES)?
                    .context("file: dependency target manifest is missing")?;
                ensure!(value.get("workspaces").is_none(), "file: dependency cannot introduce another workspace authority");
                manifests.insert(target.clone(), value);
                local.directories.insert(target.clone());
                pending.push(target.clone());
            }
            let value = &manifests[&target];
            ensure!(
                value.get("name").and_then(Value::as_str) == Some(edge.installed_as)
                    && selected.name == edge.installed_as
                    && selected.version.as_deref() == value.get("version").and_then(Value::as_str)
                    && npm_file_manifest_matches(value, recorded),
                "file: dependency name, version or runtime declarations differ from its captured lock descriptor"
            );
            if let Some(previous) = local.links.insert(selected.path.clone(), target.clone()) {
                ensure!(previous == target, "conflicting file: dependency link targets");
            }
        }
    }
    Ok(local)
}

pub(super) fn manifest_findings(
    report: &mut DependencyAdmission,
    manifest: &Value,
    source: &str,
) -> Result<()> {
    let Some(scripts) = manifest.get("scripts") else {
        return Ok(());
    };
    let scripts = scripts
        .as_object()
        .context("package scripts must be an object")?;
    for (script, command) in scripts {
        let command = command
            .as_str()
            .context("package script command must be a string")?;
        if ["preinstall", "install", "postinstall", "prepare"].contains(&script.as_str())
            && !command.trim().is_empty()
        {
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

fn workspace_finding(
    report: &mut DependencyAdmission,
    manifest: &Value,
    directory: &str,
    code: &str,
    detail: &str,
) -> Result<()> {
    let package = manifest
        .get("name")
        .and_then(Value::as_str)
        .unwrap_or_default();
    report.finding(DependencyFinding {
        code: code.into(),
        source: manifest_path(directory),
        package: package.into(),
        installed_as: package.into(),
        package_path: Some(directory.into()),
        version: manifest
            .get("version")
            .and_then(Value::as_str)
            .map(str::to_owned),
        detail: detail.into(),
    })
}

pub(super) fn dependency_metadata_matches(manifest: &Value, recorded: &Value) -> bool {
    // Missing and empty declaration maps are equivalent. Do not conflate null
    // or another type with an empty map, or silently discard peer metadata.
    SECTIONS
        .iter()
        .copied()
        .chain(["peerDependenciesMeta"])
        .all(|field| {
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
    local: &LocalDependencies,
    report: &mut DependencyAdmission,
) -> Result<BTreeSet<String>> {
    let recorded = lock
        .and_then(|lock| lock.get("packages"))
        .and_then(Value::as_object);
    let mut admitted: BTreeSet<_> = local.links.keys().cloned().collect();
    for (path, manifest) in manifests {
        time_remaining(capture.deadline)?;
        let fd = directory(&capture.root, path)?;
        let has_binding = match statat(&fd, "binding.gyp", AtFlags::SYMLINK_NOFOLLOW) {
            Ok(_) => true,
            Err(rustix::io::Errno::NOENT) => false,
            Err(error) => return Err(error).context("inspect captured native-build marker"),
        };
        let gypfile = flag(
            manifest
                .as_object()
                .context("captured manifest must be an object")?,
            "gypfile",
        )?;
        if has_binding || gypfile {
            workspace_finding(
                report,
                manifest,
                path,
                "native_build",
                "Captured package has a binding.gyp marker or declares gypfile; native-build review required",
            )?;
        }
        if path.is_empty() {
            continue;
        }
        for filename in ["package-lock.json", "npm-shrinkwrap.json"] {
            if capture
                .read(&format!("{path}/{filename}"), MAX_LOCK_BYTES)?
                .is_some()
            {
                workspace_finding(
                    report,
                    manifest,
                    path,
                    "workspace_lockfile",
                    "Workspace has an independent lockfile; assess it as a separate project instead of mixing lock authorities",
                )?;
            }
        }
        if local.directories.contains(path) {
            continue;
        }
        let package = name(bounded_text(
            manifest.get("name").context("workspace name missing")?,
            "workspace name",
        )?)?;
        let version = manifest
            .get("version")
            .map(|value| bounded_text(value, "workspace version"))
            .transpose()?;
        let location = format!("node_modules/{package}");
        let record = recorded.and_then(|records| records.get(path));
        let link = recorded.and_then(|records| records.get(&location));
        let matched = match (version, record, link, packages.get(&location)) {
            (Some(version), Some(record), Some(link), Some(locked)) => {
                locked.linked
                    && !locked.unresolved
                    && locked.name == package
                    && locked.installed_as == package
                    && locked.version.as_deref() == Some(version)
                    && link.get("resolved").and_then(Value::as_str) == Some(path.as_str())
                    && record.get("version").and_then(Value::as_str) == Some(version)
                    && record
                        .get("name")
                        .is_none_or(|value| value.as_str() == Some(package))
                    && dependency_metadata_matches(manifest, record)
            }
            _ => false,
        };
        if matched {
            admitted.insert(location);
        } else {
            workspace_finding(
                report,
                manifest,
                path,
                "workspace_review",
                "Workspace root link, target identity, version or dependency metadata does not match the captured manifest",
            )?;
        }
    }
    Ok(admitted)
}

#[cfg(test)]
mod tests {
    use super::super::inspect;
    use super::*;
    use serde_json::json;
    use std::fs;
    use std::path::Path;
    use std::time::{Duration, Instant};

    fn deadline() -> Instant {
        Instant::now() + Duration::from_secs(5)
    }
    fn fixture(package: Value, lock: Option<Value>) -> tempfile::TempDir {
        let root = tempfile::tempdir().unwrap();
        fs::write(
            root.path().join("package.json"),
            serde_json::to_vec(&package).unwrap(),
        )
        .unwrap();
        if let Some(lock) = lock {
            fs::write(
                root.path().join("package-lock.json"),
                serde_json::to_vec(&lock).unwrap(),
            )
            .unwrap();
        }
        root
    }
    fn modern_fixture(packages: Value) -> Value {
        json!({"lockfileVersion":3,"packages":packages})
    }
    fn codes(report: &DependencyAdmission) -> Vec<&str> {
        report
            .findings
            .iter()
            .map(|finding| finding.code.as_str())
            .collect()
    }

    fn write(root: &Path, directory: &str, manifest: Value) {
        fs::create_dir_all(root.join(directory)).unwrap();
        fs::write(
            root.join(manifest_path(directory)),
            serde_json::to_vec(&manifest).unwrap(),
        )
        .unwrap();
    }

    fn npm_file_fixture() -> tempfile::TempDir {
        use std::os::unix::fs::symlink;
        let app = json!({"name":"local-app","version":"1.0.0",
            "dependencies":{"shared":"file:./packages/shared","dep":"^1"}});
        let shared = json!({"name":"shared","version":"1.0.0",
            "dependencies":{"leaf":"file:../leaf","dep":"^2"},
            "devDependencies":{"never-installed":"99"}});
        let leaf = json!({"name":"leaf","version":"1.0.0",
            "dependencies":{"shared":"file:../shared"}});
        let root = fixture(app.clone(), Some(json!({"lockfileVersion":3,"packages":{
            "":app, "packages/shared":shared, "packages/leaf":leaf,
            "node_modules/shared":{"resolved":"packages/shared","link":true},
            "node_modules/leaf":{"resolved":"packages/leaf","link":true},
            "node_modules/dep":{"name":"dep","version":"1.4.0"},
            "packages/shared/node_modules/dep":{"name":"dep","version":"2.1.0"}
        }})));
        write(root.path(), "packages/shared", shared);
        write(root.path(), "packages/leaf", leaf);
        write(root.path(), "node_modules/dep", json!({"name":"dep","version":"1.4.0"}));
        write(root.path(), "packages/shared/node_modules/dep", json!({"name":"dep","version":"2.1.0"}));
        symlink("../packages/shared", root.path().join("node_modules/shared")).unwrap();
        symlink("../packages/leaf", root.path().join("node_modules/leaf")).unwrap();
        root
    }

    #[test]
    fn npm_file_links_bind_cycles_private_versions_and_runtime_only_consumers() {
        use super::super::inspect_for_execution;
        use crate::supply_chain::module_resolution_graph::{
            build_canonical_module_resolution_graph, dependency_topology,
        };
        for version in [2, 3] {
            let root = npm_file_fixture();
            let path = root.path().join("package-lock.json");
            let mut lock: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
            lock["lockfileVersion"] = json!(version);
            fs::write(&path, serde_json::to_vec(&lock).unwrap()).unwrap();
            let report = inspect_for_execution(root.path(), deadline()).unwrap();
            assert!(report.installation_checked && !report.requires_review(), "{report:?}");
            assert_eq!(report.packages_scanned, 4);
            assert_eq!(report.installed_packages_scanned, 4);
            assert_eq!(report.manifests_scanned, 5);
            assert!(report.inputs.iter().any(|input| input.path == "packages/shared/package.json"));
            assert!(report.scope.contains("project-contained npm file:"));
            let graph = build_canonical_module_resolution_graph(root.path()).unwrap();
            assert_eq!(graph.packages.len(), 3);
            assert!(graph.packages.iter().all(|package| !package.workspace));
            assert_eq!(graph.root_package_id, graph.packages.iter()
                .find(|package| package.relative_manifest_path == "package.json").unwrap().package_id);
            assert!(!graph.dependency_edges.iter().any(|edge| edge.dependency_name == "never-installed"));
            let topology = dependency_topology::build(root.path()).unwrap();
            let projection = topology.trust_graph_projection().unwrap();
            assert_eq!(projection.dependencies["shared"], BTreeSet::from(["dep".into(), "leaf".into()]));
            assert_eq!(projection.dependencies["leaf"], BTreeSet::from(["shared".into()]));
            assert!(projection.placements.iter().any(|pin| {
                pin.location == "packages/shared/node_modules/dep" && pin.version.as_deref() == Some("2.1.0")
            }));
            assert!(projection.placements.iter().any(|pin| {
                pin.location == "node_modules/shared"
                    && pin.source == dependency_topology::PackageSource::LocalDirectoryLink
            }));
            assert!(projection.coverage.metadata_complete);
            assert_eq!(projection.coverage.unresolved_required_edges, 0);
        }
    }

    #[test]
    fn npm_file_links_refuse_manifest_target_and_authority_substitution() {
        use crate::supply_chain::module_resolution_graph::dependency_topology;
        for mutation in ["request", "lock-target", "version", "dependency", "name", "override", "nested-lock"] {
            let root = npm_file_fixture();
            let path = root.path().join("packages/shared/package.json");
            let mut local: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
            match mutation {
                "request" => {
                    let path = root.path().join("package.json");
                    let mut app: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
                    app["dependencies"]["shared"] = json!("file:packages/other");
                    fs::write(path, serde_json::to_vec(&app).unwrap()).unwrap();
                }
                "lock-target" => {
                    let path = root.path().join("package-lock.json");
                    let mut lock: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
                    lock["packages"]["node_modules/shared"]["resolved"] = json!("packages/leaf");
                    fs::write(path, serde_json::to_vec(&lock).unwrap()).unwrap();
                }
                "version" => local["version"] = json!("1.0.1"),
                "dependency" => local["dependencies"]["dep"] = json!("^1"),
                "name" => local["name"] = json!("different-package"),
                "override" => {
                    let path = root.path().join("package.json");
                    let mut app: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
                    app["overrides"] = json!({"dep":"^1"});
                    fs::write(path, serde_json::to_vec(&app).unwrap()).unwrap();
                }
                "nested-lock" => fs::write(root.path().join("packages/shared/package-lock.json"), "{}").unwrap(),
                _ => unreachable!(),
            }
            fs::write(path, serde_json::to_vec(&local).unwrap()).unwrap();
            let admission = inspect(root.path(), deadline());
            assert!(admission.is_err() || admission.unwrap().requires_review(), "{mutation}");
            assert!(dependency_topology::build(root.path()).is_err(), "{mutation}");
        }
    }

    #[test]
    fn npm_file_links_refuse_changed_installation_routes_and_link_text() {
        use super::super::inspect_for_execution;
        use std::os::unix::fs::symlink;
        for mutation in ["target", "private-version", "missing-private"] {
            let root = npm_file_fixture();
            match mutation {
                "target" => {
                    let path = root.path().join("node_modules/shared");
                    fs::rename(&path, root.path().join("retained-original-link")).unwrap();
                    symlink("../packages/leaf", path).unwrap();
                }
                "private-version" => write(root.path(), "packages/shared/node_modules/dep",
                    json!({"name":"dep","version":"1.4.0"})),
                "missing-private" => fs::rename(
                    root.path().join("packages/shared/node_modules/dep"),
                    root.path().join("retained-private-package"),
                ).unwrap(),
                _ => unreachable!(),
            }
            let report = inspect_for_execution(root.path(), deadline());
            assert!(report.is_err() || report.unwrap().requires_review(), "{mutation}");
        }
    }

    #[test]
    fn npm_file_paths_and_target_metadata_cannot_escape_capture() {
        use crate::supply_chain::module_resolution_graph::{dependency_topology, npm_file_dependency_target};
        use std::os::unix::fs::symlink;
        assert_eq!(npm_file_dependency_target("packages/shared", "file:../leaf").unwrap(), Some("packages/leaf".into()));
        for request in ["file:", "file:../outside", "file:/tmp/shared", "file:~/shared",
            "file:packages/%2e%2e/shared", "file:packages/shared.tgz", "file:node_modules/shared",
            "file:.franken-node/shared", "file:packages/shared?query"] {
            assert!(npm_file_dependency_target("", request).is_err(), "{request}");
        }
        let root = npm_file_fixture();
        let path = root.path().join("packages/shared/package.json");
        let retained = root.path().join("retained-package.json");
        fs::rename(&path, &retained).unwrap();
        symlink("../../retained-package.json", path).unwrap();
        assert!(inspect(root.path(), deadline()).is_err());
        assert!(dependency_topology::build(root.path()).is_err());
    }

    #[test]
    fn npm_file_links_preserve_lifecycle_and_native_payload_refusals() {
        use super::super::inspect_for_execution;
        for marker in ["lifecycle", "gyp", "native-payload"] {
            let root = npm_file_fixture();
            match marker {
                "lifecycle" => {
                    let path = root.path().join("packages/shared/package.json");
                    let mut manifest: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
                    manifest["scripts"] = json!({"prepare":"node build.js"});
                    fs::write(path, serde_json::to_vec(&manifest).unwrap()).unwrap();
                }
                "gyp" => fs::write(root.path().join("packages/shared/binding.gyp"), "{}").unwrap(),
                "native-payload" => fs::write(root.path().join("packages/shared/addon.node"), b"native").unwrap(),
                _ => unreachable!(),
            }
            let report = inspect_for_execution(root.path(), deadline()).unwrap();
            assert!(report.requires_review(), "{marker}: {report:?}");
        }
    }

    #[test]
    fn npm_file_optional_absence_never_grants_an_unrequested_local_link() {
        use crate::supply_chain::module_resolution_graph::dependency_topology;
        let root = fixture(json!({"optionalDependencies":{"absent":"file:packages/absent"}}),
            Some(json!({"lockfileVersion":3,"packages":{}})));
        assert!(!inspect(root.path(), deadline()).unwrap().requires_review());
        let projection = dependency_topology::build(root.path()).unwrap().trust_graph_projection().unwrap();
        assert_eq!(projection.coverage.unresolved_optional_edges, 1);

        let root = npm_file_fixture();
        let path = root.path().join("package-lock.json");
        let mut lock: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        lock["packages"]["packages/leaf/node_modules/shared"] =
            json!({"resolved":"packages/shared","link":true});
        lock["packages"]["node_modules/unrequested"] =
            json!({"resolved":"packages/shared","link":true});
        fs::write(path, serde_json::to_vec(&lock).unwrap()).unwrap();
        assert!(inspect(root.path(), deadline()).unwrap().requires_review());
        assert!(dependency_topology::build(root.path()).is_err());
    }

    #[test]
    fn overlapping_star_and_globstar_selectors_capture_once_and_bind_real_bytes() {
        let root = fixture(
            json!({"workspaces":["./packages/*/", "packages/**", "packages/a"]}),
            None,
        );
        write(
            root.path(),
            "packages/a",
            json!({"name":"a","dependencies":{"sharp":"^1"}}),
        );
        write(
            root.path(),
            "packages/group/b",
            json!({"name":"b","peerDependencies":{"peer":"^2"}}),
        );
        let report = inspect(root.path(), deadline()).unwrap();
        assert_eq!(report.manifests_scanned, 3);
        assert_eq!(report.inputs.len(), 3);
        assert!(report.findings.iter().any(
            |f| f.source == "packages/a/package.json#dependencies" && f.code == "native_addon"
        ));
        assert!(report.findings.iter().any(|f| f.source
            == "packages/group/b/package.json#peerDependencies"
            && f.code == "unresolved_declaration"));
        use sha2::{Digest, Sha256};
        for input in &report.inputs {
            assert_eq!(
                input.sha256,
                hex::encode(Sha256::digest(
                    fs::read(root.path().join(&input.path)).unwrap()
                ))
            );
        }
        assert_eq!(report, inspect(root.path(), deadline()).unwrap());
    }

    #[test]
    fn excluded_npm_and_bun_workspaces_preserve_installed_link_and_lifecycle_authority() {
        use super::super::inspect_for_execution;
        use crate::supply_chain::module_resolution_graph::{
            build_canonical_module_resolution_graph, recompute_module_resolution_graph_hash,
        };
        use std::os::unix::fs::symlink;

        let member = json!({"name":"keep", "version":"1.0.0"});
        for bun in [false, true] {
            let manifest = json!({"name":"root", "workspaces":[
                "packages/**", "!packages/excluded/**", "!packages/missing/**"
            ], "dependencies":{"keep":"^1"}});
            let root = fixture(manifest.clone(), None);
            write(root.path(), "packages/keep", member.clone());
            fs::create_dir_all(root.path().join("packages/excluded/child")).unwrap();
            fs::write(
                root.path().join("packages/excluded/package.json"),
                "not JSON",
            )
            .unwrap();
            let (filename, lock) = if bun {
                (
                    "bun.lock",
                    json!({"lockfileVersion":2, "workspaces":{
                    "":{"name":"root","dependencies":{"keep":"^1"}},
                    "packages/keep":member
                },"packages":{"keep":["keep@workspace:packages/keep"]}}),
                )
            } else {
                (
                    "package-lock.json",
                    modern_fixture(json!({
                        "":manifest,"packages/keep":member,
                        "node_modules/keep":{"link":true,"resolved":"packages/keep"}
                    })),
                )
            };
            fs::write(
                root.path().join(filename),
                serde_json::to_vec(&lock).unwrap(),
            )
            .unwrap();
            fs::create_dir(root.path().join("node_modules")).unwrap();
            symlink("../packages/keep", root.path().join("node_modules/keep")).unwrap();

            let admitted = inspect_for_execution(root.path(), deadline()).unwrap();
            assert!(
                admitted.installation_checked && !admitted.requires_review(),
                "{filename}: {admitted:#?}"
            );
            assert_eq!(admitted.manifests_scanned, 2);
            assert!(
                !admitted
                    .inputs
                    .iter()
                    .any(|input| input.path.contains("excluded"))
            );
            let graph = build_canonical_module_resolution_graph(root.path()).unwrap();
            assert_eq!(graph.packages.len(), 2);
            assert_eq!(
                graph.workspace_selection_mode,
                Some(if bun {
                    WorkspaceSelectionMode::Bun
                } else {
                    WorkspaceSelectionMode::Npm
                })
            );
            assert_eq!(
                recompute_module_resolution_graph_hash(&graph).unwrap(),
                graph.canonical_hash
            );
            let mut relabelled = graph.clone();
            relabelled.workspace_selection_mode = Some(if bun {
                WorkspaceSelectionMode::Npm
            } else {
                WorkspaceSelectionMode::Bun
            });
            assert_ne!(
                recompute_module_resolution_graph_hash(&relabelled).unwrap(),
                graph.canonical_hash
            );

            // Exclusion does not exempt a surviving workspace from installed
            // source checks or hide a lifecycle script behind a clean lock.
            write(
                root.path(),
                "packages/keep",
                json!({
                    "name":"keep","version":"1.0.0","scripts":{"prepare":"node build.js"}
                }),
            );
            let changed = inspect_for_execution(root.path(), deadline()).unwrap();
            assert!(changed.requires_review());
            assert!(
                changed
                    .findings
                    .iter()
                    .any(|finding| finding.code == "install_script")
            );
            assert!(!root.path().join("build.js").exists());
        }
    }

    #[test]
    fn glob_selected_npm_and_bun_workspaces_bind_the_actual_installation() {
        use super::super::inspect_for_execution;
        use crate::supply_chain::module_resolution_graph::build_canonical_module_resolution_graph;
        use std::os::unix::fs::symlink;

        let core = json!({"name":"core","version":"1.0.0"});
        let ui = json!({"name":"ui","version":"1.0.0","dependencies":{"core":"^1"}});
        for selectors in [
            json!(["{apps,packages}/{core,ui,missing}", "packages/{core,core}"]),
            json!(["packages/cor?", "apps/[uv]i", "!packages/[!c]*"]),
            json!([
                "{apps,packages}/[cu]*",
                "!{apps,packages}/*[!ei]",
                "packages/co??"
            ]),
        ] {
            for bun in [false, true] {
                let root_manifest = json!({"name":"root", "workspaces":selectors,
                "dependencies":{"core":"^1","ui":"^1"}});
                let root = fixture(root_manifest.clone(), None);
                write(root.path(), "packages/core", core.clone());
                write(root.path(), "apps/ui", ui.clone());
                fs::create_dir_all(root.path().join("packages/unselected")).unwrap();
                fs::write(
                    root.path().join("packages/unselected/package.json"),
                    "must not parse",
                )
                .unwrap();
                let (filename, lock) = if bun {
                    (
                        "bun.lock",
                        json!({"lockfileVersion":1,"workspaces":{
                            "":{"name":"root","dependencies":{"core":"^1","ui":"^1"}},
                            "packages/core":core,"apps/ui":ui
                        },"packages":{
                            "core":["core@workspace:packages/core"],
                            "ui":["ui@workspace:apps/ui"]
                        }}),
                    )
                } else {
                    (
                        "package-lock.json",
                        modern_fixture(json!({
                            "":root_manifest,"packages/core":core,"apps/ui":ui,
                            "node_modules/core":{"link":true,"resolved":"packages/core"},
                            "node_modules/ui":{"link":true,"resolved":"apps/ui"}
                        })),
                    )
                };
                fs::write(
                    root.path().join(filename),
                    serde_json::to_vec(&lock).unwrap(),
                )
                .unwrap();
                fs::create_dir(root.path().join("node_modules")).unwrap();
                symlink("../packages/core", root.path().join("node_modules/core")).unwrap();
                symlink("../apps/ui", root.path().join("node_modules/ui")).unwrap();

                let report = inspect_for_execution(root.path(), deadline()).unwrap();
                assert!(
                    report.installation_checked && !report.requires_review(),
                    "{filename}: {report:#?}"
                );
                for path in [
                    "package.json",
                    "packages/core/package.json",
                    "apps/ui/package.json",
                ] {
                    assert_eq!(
                        report
                            .inputs
                            .iter()
                            .filter(|input| input.path == path)
                            .count(),
                        1
                    );
                }
                assert!(
                    !report
                        .inputs
                        .iter()
                        .any(|input| input.path.contains("unselected"))
                );
                let graph = build_canonical_module_resolution_graph(root.path()).unwrap();
                assert_eq!(graph.packages.len(), 3);
                assert!(
                    graph
                        .dependency_edges
                        .iter()
                        .all(|edge| edge.target_package_id.is_some())
                );
                assert_eq!(
                    report,
                    inspect_for_execution(root.path(), deadline()).unwrap()
                );
            }
        }
    }

    #[test]
    fn brace_selected_workspaces_preserve_lifecycle_and_link_authority_checks() {
        use std::os::unix::fs::symlink;
        let root = fixture(
            json!({"workspaces":["packages/{safe,{risky,missing}}"]}),
            None,
        );
        write(root.path(), "packages/safe", json!({"name":"safe"}));
        write(
            root.path(),
            "packages/risky",
            json!({"name":"risky", "scripts":{"prepare":"must never execute"}}),
        );
        let report = inspect(root.path(), deadline()).unwrap();
        assert!(
            report
                .findings
                .iter()
                .any(|finding| finding.code == "install_script"
                    && finding.source == "packages/risky/package.json#scripts.prepare")
        );
        let outside = tempfile::tempdir().unwrap();
        fs::write(
            outside.path().join("package.json"),
            "private unparseable bytes",
        )
        .unwrap();
        symlink(outside.path(), root.path().join("packages/missing")).unwrap();
        assert!(
            inspect(root.path(), deadline())
                .unwrap_err()
                .to_string()
                .contains("symlink")
        );
    }

    #[test]
    fn private_and_hoisted_identities_are_used_without_double_counting_packages() {
        let root = fixture(
            json!({"workspaces":["packages/*"]}),
            Some(modern_fixture(json!({
                "node_modules/dep":{"version":"1.0.0"},
                "packages/a/node_modules/private":{"version":"2.0.0"}
            }))),
        );
        write(
            root.path(),
            "packages/a",
            json!({"name":"a","dependencies":{"dep":"^1","private":"^2"}}),
        );
        write(
            root.path(),
            "packages/b",
            json!({"name":"b","dependencies":{"dep":"^1"}}),
        );
        let report = inspect(root.path(), deadline()).unwrap();
        assert_eq!(report.packages_scanned, 2);
        assert_eq!(codes(&report), ["workspace_review", "workspace_review"]);
    }

    #[test]
    fn a_private_wrong_identity_is_not_rescued_by_a_matching_root_record() {
        let root = fixture(
            json!({"workspaces":["packages/a"]}),
            Some(modern_fixture(json!({
                "node_modules/dep":{"version":"1.0.0"},
                "packages/a/node_modules/dep":{"name":"other","version":"1.0.0"}
            }))),
        );
        write(
            root.path(),
            "packages/a",
            json!({"name":"a","dependencies":{"dep":"^1"}}),
        );
        let report = inspect(root.path(), deadline()).unwrap();
        assert!(
            report
                .findings
                .iter()
                .any(|f| f.source == "packages/a/package.json#dependencies"
                    && f.code == "unresolved_declaration")
        );
    }

    #[test]
    fn captured_workspace_lifecycle_is_not_hidden_by_a_clean_lock_projection() {
        let root = fixture(json!({"workspaces":["packages/a"]}), None);
        write(
            root.path(),
            "packages/a",
            json!({"name":"a","scripts":{"prepare":"node build.js"}}),
        );
        let report = inspect(root.path(), deadline()).unwrap();
        assert!(
            report
                .findings
                .iter()
                .any(|f| f.source == "packages/a/package.json#scripts.prepare"
                    && f.code == "install_script")
        );
        assert!(!root.path().join("build.js").exists());
    }

    #[test]
    fn unknown_glob_dialects_and_reserved_or_missing_selections_fail_explicitly() {
        for selector in [
            "../outside",
            "/outside",
            "packages/{1..3}",
            "packages/[z-a]",
            "!../outside",
            "!!packages/a",
            "packages/a[",
            "node_modules/*",
            ".git/*",
            "packages/a**b",
            "missing/*",
        ] {
            let root = fixture(json!({"workspaces":[selector]}), None);
            assert!(inspect(root.path(), deadline()).is_err(), "{selector}");
        }
        for workspaces in [
            Value::Null,
            json!("packages/*"),
            json!({"packages":["packages/*"]}),
        ] {
            let root = fixture(json!({"workspaces":workspaces}), None);
            assert!(inspect(root.path(), deadline()).is_err());
        }
        let root = fixture(json!({"workspaces":[]}), None);
        assert!(!inspect(root.path(), deadline()).unwrap().requires_review());
    }

    #[test]
    fn malformed_missing_duplicate_and_nested_workspace_manifests_fail_closed() {
        for manifest in [
            json!({}),
            json!({"name":"root"}),
            json!({"name":"a","workspaces":[]}),
            json!({"name":"a","scripts":{"prepare":false}}),
        ] {
            let root = fixture(json!({"name":"root","workspaces":["packages/a"]}), None);
            write(root.path(), "packages/a", manifest);
            assert!(inspect(root.path(), deadline()).is_err());
        }
        let root = fixture(json!({"workspaces":["packages/*"]}), None);
        write(root.path(), "packages/a", json!({"name":"duplicate"}));
        write(root.path(), "packages/b", json!({"name":"duplicate"}));
        assert!(inspect(root.path(), deadline()).is_err());
        fs::write(
            root.path().join("packages/b/package.json"),
            r#"{"name":"b","name":"c"}"#,
        )
        .unwrap();
        assert!(inspect(root.path(), deadline()).is_err());
    }

    #[test]
    fn selectors_never_follow_directory_or_manifest_symlinks() {
        use std::os::unix::fs::symlink;
        let outside = tempfile::tempdir().unwrap();
        fs::write(outside.path().join("package.json"), r#"{"name":"outside"}"#).unwrap();
        for wildcard in [false, true] {
            let root = fixture(
                json!({"workspaces":[if wildcard {"packages/*"} else {"packages/a"}]}),
                None,
            );
            fs::create_dir(root.path().join("packages")).unwrap();
            symlink(outside.path(), root.path().join("packages/a")).unwrap();
            assert!(inspect(root.path(), deadline()).is_err());
        }
        let root = fixture(json!({"workspaces":["packages/a"]}), None);
        fs::create_dir_all(root.path().join("packages/a")).unwrap();
        symlink(
            outside.path().join("package.json"),
            root.path().join("packages/a/package.json"),
        )
        .unwrap();
        assert!(inspect(root.path(), deadline()).is_err());
    }

    #[test]
    fn reserved_subtrees_are_not_read_and_dot_directories_require_explicit_selection() {
        let root = fixture(json!({"workspaces":["packages/**"]}), None);
        write(root.path(), "packages/a", json!({"name":"a"}));
        for path in [
            "packages/node_modules/bad",
            "packages/.git/bad",
            "packages/.hidden",
        ] {
            fs::create_dir_all(root.path().join(path)).unwrap();
            fs::write(root.path().join(path).join("package.json"), "invalid").unwrap();
        }
        let report = inspect(root.path(), deadline()).unwrap();
        assert_eq!(report.manifests_scanned, 2);
        assert_eq!(report.inputs.len(), 2);
    }

    #[test]
    fn selector_count_and_manifest_bytes_have_non_truncating_limits() {
        let root = fixture(
            json!({"workspaces":vec!["packages/a"; MAX_PATTERNS + 1]}),
            None,
        );
        assert!(inspect(root.path(), deadline()).is_err());
        let root = fixture(json!({"workspaces":["packages/a"]}), None);
        fs::create_dir_all(root.path().join("packages/a")).unwrap();
        fs::write(
            root.path().join("packages/a/package.json"),
            vec![b' '; MAX_MANIFEST_BYTES + 1],
        )
        .unwrap();
        assert!(inspect(root.path(), deadline()).is_err());
    }

    fn linked_fixture() -> tempfile::TempDir {
        let root = fixture(
            json!({"name":"root","workspaces":["packages/*"],"dependencies":{"a":"^1"}}),
            Some(modern_fixture(json!({
                "node_modules/a":{"link":true,"resolved":"packages/a"},
                "packages/a":{"name":"a","version":"1.0.0","dependencies":{"dep":"^1"}},
                "node_modules/dep":{"version":"1.2.3"}
            }))),
        );
        write(
            root.path(),
            "packages/a",
            json!({"name":"a","version":"1.0.0","dependencies":{"dep":"^1"}}),
        );
        root
    }

    #[test]
    fn captured_workspace_link_and_hoisted_dependency_can_pass_metadata_admission() {
        let root = linked_fixture();
        let report = inspect(root.path(), deadline()).unwrap();
        assert!(!report.requires_review(), "{report:#?}");
        assert_eq!(report.packages_scanned, 2);
        assert_eq!(report.manifests_scanned, 2);
        assert_eq!(
            report
                .inputs
                .iter()
                .map(|input| input.path.as_str())
                .collect::<Vec<_>>(),
            [
                "package-lock.json",
                "package.json",
                "packages/a/package.json"
            ]
        );
        // Metadata inspection neither installs a link nor runs the project.
        assert!(!root.path().join("node_modules").exists());
        assert_eq!(report, inspect(root.path(), deadline()).unwrap());
    }

    #[test]
    fn inter_workspace_cycles_and_scoped_names_resolve_without_recursing_through_links() {
        let root = fixture(
            json!({"workspaces":["packages/*"]}),
            Some(modern_fixture(json!({
                "node_modules/@team/a":{"link":true,"resolved":"packages/a"},
                "node_modules/b":{"link":true,"resolved":"packages/b"},
                "packages/a":{"name":"@team/a","version":"1.0.0","dependencies":{"b":"^1"}},
                "packages/b":{"name":"b","version":"1.0.0","dependencies":{"@team/a":"^1"}}
            }))),
        );
        write(
            root.path(),
            "packages/a",
            json!({"name":"@team/a","version":"1.0.0","dependencies":{"b":"^1"}}),
        );
        write(
            root.path(),
            "packages/b",
            json!({"name":"b","version":"1.0.0","dependencies":{"@team/a":"^1"}}),
        );
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
            (
                "node_modules/extra",
                "unselected",
                json!({"name":"extra","version":"1.0.0"}),
            ),
            (
                "packages/a/node_modules/a",
                "packages/a",
                json!({"name":"a","version":"1.0.0","dependencies":{"dep":"^1"}}),
            ),
        ] {
            let root = linked_fixture();
            let path = root.path().join("package-lock.json");
            let mut lock: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
            lock["packages"][location] = json!({"link":true,"resolved":target});
            lock["packages"][target] = descriptor;
            fs::write(path, serde_json::to_vec(&lock).unwrap()).unwrap();
            let report = inspect(root.path(), deadline()).unwrap();
            assert!(
                report
                    .findings
                    .iter()
                    .any(|finding| finding.code == "local_link"
                        && finding.package_path.as_deref() == Some(location)),
                "{report:#?}"
            );
        }
    }

    #[test]
    fn wrong_root_link_target_or_missing_target_descriptor_never_passes() {
        for missing in [false, true] {
            let root = linked_fixture();
            let path = root.path().join("package-lock.json");
            let mut lock: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
            if missing {
                lock["packages"]
                    .as_object_mut()
                    .unwrap()
                    .remove("packages/a");
            } else {
                lock["packages"]["node_modules/a"]["resolved"] = json!("packages/other");
                lock["packages"]["packages/other"] =
                    json!({"name":"a","version":"1.0.0","dependencies":{"dep":"^1"}});
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
            let expected = if kind == "script" {
                "install_script"
            } else {
                "native_build"
            };
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
            fs::write(
                root.path().join("packages/a").join(filename),
                r#"{"lockfileVersion":3,"packages":{}}"#,
            )
            .unwrap();
            let report = inspect(root.path(), deadline()).unwrap();
            assert!(
                codes(&report).contains(&"workspace_lockfile"),
                "{report:#?}"
            );
            assert!(
                report
                    .inputs
                    .iter()
                    .any(|input| input.path == format!("packages/a/{filename}"))
            );
        }
    }

    #[test]
    fn symlinked_or_malformed_nested_lockfiles_are_errors_not_unobserved_approval() {
        use std::os::unix::fs::symlink;
        let root = linked_fixture();
        symlink(
            "../../package-lock.json",
            root.path().join("packages/a/package-lock.json"),
        )
        .unwrap();
        assert!(inspect(root.path(), deadline()).is_err());
        let root = linked_fixture();
        fs::write(root.path().join("packages/a/package-lock.json"), "invalid").unwrap();
        assert!(inspect(root.path(), deadline()).is_err());
    }

    #[test]
    fn external_or_alias_requests_are_not_substituted_with_same_named_workspaces() {
        for request in [
            "npm:a@1",
            "file:../external",
            "https://example.invalid/a.tgz",
            "owner/repo",
        ] {
            let root = linked_fixture();
            fs::write(
                root.path().join("package.json"),
                serde_json::to_vec(&json!({
                    "name":"root","workspaces":["packages/*"],"dependencies":{"a":request}
                }))
                .unwrap(),
            )
            .unwrap();
            let report = inspect(root.path(), deadline()).unwrap();
            assert!(
                report
                    .findings
                    .iter()
                    .any(|finding| finding.source == "package.json#dependencies"
                        && finding.code == "unresolved_declaration"),
                "{request}: {report:#?}"
            );
        }
    }

    #[test]
    fn stale_locked_workspace_projection_cannot_hide_a_new_native_dependency() {
        let root = linked_fixture();
        write(
            root.path(),
            "packages/a",
            json!({"name":"a","version":"1.0.0","dependencies":{"image":"npm:sharp@^1"}}),
        );
        let report = inspect(root.path(), deadline()).unwrap();
        assert!(report.findings.iter().any(|finding| finding.source
            == "packages/a/package.json#dependencies"
            && finding.package == "sharp"
            && finding.code == "native_addon"));
        assert!(codes(&report).contains(&"workspace_review"));
    }
}
