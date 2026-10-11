//! Admission of the dependency edges inside captured npm lockfiles.
//!
//! Package inventory alone cannot prove even metadata-level graph completeness:
//! a recorded package can require an absent dependency or a differently named
//! alias hidden behind a private installation. This gate runs before checked
//! migration executes either runtime. It never opens installed package files.
//!
//! Modern ordinary dependencies supersede same-named peer dependencies;
//! optional dependencies supersede both. Absent optional dependencies/optional
//! peers need no invented installation.
//! PRESENT optional installations still undergo every identity/risk check.
//! Transitive development dependencies are not runtime installation edges.
//! Legacy `requires` lacks per-edge optionality: unresolved edges stay review
//! findings rather than being guessed optional. Supported registry version
//! ranges are checked; opaque requests require review. Installed-content
//! authentication, npm overrides and JS resolution remain separate claims.

use super::{
    DependencyAdmission, DependencyFinding, LockedPackage, MAX_DEPTH, MAX_PACKAGES,
    alias, bounded_text, flag, name, native_addon, nearest_package, time_remaining,
};
use anyhow::{Context, Result, ensure};
use serde_json::{Map, Value};
use std::collections::BTreeMap;
use std::time::Instant;

#[path = "npm_version_req.rs"]
mod versions;

const MAX_DEPENDENCY_EDGES: usize = 200_000;

pub(super) fn version_review(
    request: Option<&str>,
    locked_version: Option<&str>,
) -> Option<(&'static str, &'static str)> {
    match request.zip(locked_version).and_then(|(request, version)| versions::matches(request, version)) {
        Some(true) => None,
        Some(false) => Some((
            "dependency_version_mismatch",
            "Nearest locked version does not satisfy the declared npm registry range; review stale pins or explicit overrides before execution",
        )),
        None => Some((
            "unverifiable_dependency_version",
            "Dependency request or locked version cannot be verified by the bounded registry-range checker; tags, URLs, Git and unsupported forms require explicit review",
        )),
    }
}

#[derive(Clone, Copy)]
struct Edge<'a> {
    consumer: &'a str,
    section: &'a str,
    installed_as: &'a str,
    request: &'a str,
    optional: bool,
    peer: bool,
}

struct Admission<'a> {
    packages: &'a BTreeMap<String, LockedPackage>,
    source: &'a str,
    report: &'a mut DependencyAdmission,
    deadline: Instant,
    edges: usize,
}

impl Admission<'_> {
    fn edge(&mut self, edge: Edge<'_>) -> Result<()> {
        time_remaining(self.deadline)?;
        self.edges += 1;
        ensure!(
            self.edges <= MAX_DEPENDENCY_EDGES,
            "transitive dependency edge limit exceeded"
        );
        let (actual, requirement) = alias(edge.installed_as, Some(edge.request))?;
        let source = format!("{}/package.json", edge.consumer);
        let selected = nearest_package(self.packages, &source, edge.installed_as);
        let private_peer = edge.peer
            && selected.is_some_and(|package| {
                package.path.starts_with(&format!("{}/node_modules/", edge.consumer))
            });
        let represented = selected.is_some_and(|package| {
            package.name == actual
                && !package.unresolved
                && (!package.linked || !edge.request.contains([':', '/', '\\']))
                && !private_peer
        });
        // Missing optional code cannot run. Do not extend that exemption to a
        // present-but-wrong installation, malformed alias or a required peer.
        if selected.is_none() && edge.optional {
            return Ok(());
        }
        let native = native_addon(actual) || native_addon(edge.installed_as);
        let version_issue = if represented {
            version_review(requirement, selected.and_then(|package| package.version.as_deref()))
        } else { None };
        if !represented || native || version_issue.is_some() {
            let (code, detail) = if native {
                (
                    "native_addon",
                    "Transitive declaration names a native-addon/build dependency; explicit migration review is required",
                )
            } else if private_peer {
                (
                    "invalid_peer_placement",
                    "Peer dependency is shadowed inside its consumer instead of being provided at or above the consumer's installation level",
                )
            } else if let Some(issue) = version_issue {
                issue
            } else {
                (
                    "unresolved_transitive_dependency",
                    "Transitive declaration has no matching complete nearest lockfile identity; version satisfaction is not established",
                )
            };
            self.report.finding(DependencyFinding {
                code: code.into(),
                source: format!("{}#{}#{}", self.source, edge.consumer, edge.section),
                package: actual.into(),
                installed_as: edge.installed_as.into(),
                package_path: selected.map(|package| package.path.clone()),
                version: Some(edge.request.into()),
                detail: detail.into(),
            })?;
        }
        Ok(())
    }

    fn modern_record(&mut self, consumer: &str, record: &Map<String, Value>) -> Result<()> {
        let empty = Map::new();
        let dependencies = section(record, "dependencies", &empty)?;
        let optional = section(record, "optionalDependencies", &empty)?;
        let peers = section(record, "peerDependencies", &empty)?;
        let peer_meta = section(record, "peerDependenciesMeta", &empty)?;
        // Validate metadata even when its key has no active edge. Invalid
        // optional markers cannot silently suppress a required dependency.
        for (installed_as, metadata) in peer_meta {
            time_remaining(self.deadline)?;
            name(installed_as)?;
            let metadata = metadata.as_object().context("peer dependency metadata must be an object")?;
            flag(metadata, "optional")?;
        }
        for (section_name, declarations) in [
            ("dependencies", dependencies),
            ("optionalDependencies", optional),
            ("peerDependencies", peers),
        ] {
            for (installed_as, request) in declarations {
                time_remaining(self.deadline)?;
                name(installed_as)?;
                let request = bounded_text(request, "transitive dependency request")?;
                // Validate overridden entries too, without treating the losing
                // declaration as the package actually selected by npm.
                alias(installed_as, Some(request))?;
                // npm loads peer edges first, production edges next, and
                // optional edges last. Later declarations replace earlier
                // edges with the same installation name.
                if (section_name == "dependencies" && optional.contains_key(installed_as))
                    || (section_name == "peerDependencies"
                        && (dependencies.contains_key(installed_as)
                            || optional.contains_key(installed_as)))
                {
                    continue;
                }
                let peer_optional = peer_meta.get(installed_as)
                    .and_then(Value::as_object)
                    .map(|metadata| flag(metadata, "optional"))
                    .transpose()?
                    .unwrap_or(false);
                self.edge(Edge {
                    consumer,
                    section: section_name,
                    installed_as,
                    request,
                    optional: section_name == "optionalDependencies"
                        || (section_name == "peerDependencies" && peer_optional),
                    peer: section_name == "peerDependencies",
                })?;
            }
        }
        Ok(())
    }
}

fn section<'a>(
    record: &'a Map<String, Value>,
    key: &str,
    empty: &'a Map<String, Value>,
) -> Result<&'a Map<String, Value>> {
    match record.get(key) {
        None => Ok(empty),
        Some(value) => value.as_object().with_context(|| format!("transitive {key} must be an object")),
    }
}

pub(super) fn inspect(
    lock: Option<&Value>,
    packages: &BTreeMap<String, LockedPackage>,
    source: &str,
    report: &mut DependencyAdmission,
    deadline: Instant,
) -> Result<()> {
    time_remaining(deadline)?;
    let Some(lock) = lock else { return Ok(()); };
    let mut admission = Admission { packages, source, report, deadline, edges: 0 };
    match lock.get("lockfileVersion").and_then(Value::as_u64) {
        Some(2 | 3) => {
            let records = lock.get("packages").and_then(Value::as_object)
                .context("modern dependency graph requires packages")?;
            for package in packages.values() {
                time_remaining(deadline)?;
                // Linked workspaces are already assessed from captured REAL
                // manifests by the caller, not the link placeholder or a stale
                // lockfile projection. Unbound links already require review.
                if package.linked { continue; }
                let record = records.get(&package.path).and_then(Value::as_object)
                    .context("recorded package missing from dependency graph")?;
                admission.modern_record(&package.path, record)?;
            }
        }
        Some(1) => {
            let empty = Map::new();
            let root = lock.as_object().context("legacy dependency graph requires an object")?;
            let root = section(root, "dependencies", &empty)?;
            let mut pending = vec![(String::new(), root, 0_usize)];
            let mut visited = 0_usize;
            while let Some((parent, children, depth)) = pending.pop() {
                time_remaining(deadline)?;
                ensure!(depth <= MAX_DEPTH, "legacy dependency graph nesting exceeds limit");
                for (installed_as, value) in children {
                    time_remaining(deadline)?;
                    visited += 1;
                    ensure!(visited <= MAX_PACKAGES, "legacy dependency graph package limit exceeded");
                    name(installed_as)?;
                    let path = if parent.is_empty() { format!("node_modules/{installed_as}") }
                        else { format!("{parent}/node_modules/{installed_as}") };
                    ensure!(packages.contains_key(&path), "legacy dependency graph inventory mismatch");
                    let record = value.as_object().context("invalid legacy dependency graph record")?;
                    for (dependency, request) in section(record, "requires", &empty)? {
                        name(dependency)?;
                        admission.edge(Edge {
                            consumer: &path,
                            section: "requires",
                            installed_as: dependency,
                            request: bounded_text(request, "legacy dependency request")?,
                            optional: false,
                            peer: false,
                        })?;
                    }
                    let nested = section(record, "dependencies", &empty)?;
                    if !nested.is_empty() { pending.push((path, nested, depth + 1)); }
                }
            }
        }
        _ => anyhow::bail!("unsupported npm dependency graph version"),
    }
    time_remaining(deadline)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::fs;
    use std::time::Duration;

    fn deadline() -> Instant { Instant::now() + Duration::from_secs(10) }

    fn assess(lock: Value) -> Result<DependencyAdmission> {
        let root = tempfile::tempdir()?;
        fs::write(root.path().join("package.json"), "{}")?;
        fs::write(root.path().join("package-lock.json"), serde_json::to_vec(&lock)?)?;
        let report = super::super::inspect(root.path(), deadline());
        assert!(!root.path().join("node_modules").exists());
        report
    }

    fn modern(records: Value) -> Result<DependencyAdmission> {
        assess(json!({"lockfileVersion":3,"packages":records}))
    }

    #[test]
    fn missing_transitive_dependency_reaches_the_live_admission_barrier() {
        let report = modern(json!({
            "node_modules/app":{"version":"1.0.0","dependencies":{"missing":"^1"}}
        })).unwrap();
        assert!(report.requires_review());
        assert_eq!(report.findings.len(), 1);
        let finding = &report.findings[0];
        assert_eq!(finding.code, "unresolved_transitive_dependency");
        assert_eq!(finding.package, "missing");
        assert_eq!(finding.source, "package-lock.json#node_modules/app#dependencies");
        assert!(finding.package_path.is_none());
    }

    #[test]
    fn hoisted_dependencies_and_cycles_are_checked_without_graph_recursion() {
        let report = modern(json!({
            "node_modules/a":{"version":"1.0.0","dependencies":{"b":"1"}},
            "node_modules/b":{"version":"1.0.0","dependencies":{"a":"1"}}
        })).unwrap();
        assert!(!report.requires_review(), "{report:?}");
        assert_eq!(report.packages_scanned, 2);
    }

    #[test]
    fn private_alias_mismatch_cannot_be_rescued_by_a_matching_hoist() {
        let report = modern(json!({
            "node_modules/a":{"version":"1.0.0","dependencies":{"alias":"npm:actual@1"}},
            "node_modules/alias":{"name":"actual","version":"1.0.0"},
            "node_modules/a/node_modules/alias":{"name":"wrong","version":"1.0.0"}
        })).unwrap();
        assert_eq!(report.findings.len(), 1);
        assert_eq!(report.findings[0].package, "actual");
        assert_eq!(report.findings[0].package_path.as_deref(), Some("node_modules/a/node_modules/alias"));
    }

    #[test]
    fn fictitious_double_node_modules_cannot_satisfy_an_edge() {
        let report = modern(json!({
            "node_modules/a":{"version":"1.0.0","dependencies":{"b":"1"}},
            "node_modules/node_modules/b":{"version":"1.0.0"}
        })).unwrap();
        assert!(report.requires_review());
        assert_eq!(report.findings[0].code, "unresolved_transitive_dependency");
    }

    #[test]
    fn scoped_and_nested_consumers_use_the_nearest_real_installation() {
        let report = modern(json!({
            "node_modules/outer/node_modules/@scope/a":{"version":"1.0.0","dependencies":{"@scope/b":"1"}},
            "node_modules/outer/node_modules/@scope/b":{"version":"1.0.0"},
            "node_modules/@scope/b":{"name":"wrong","version":"1.0.0"}
        })).unwrap();
        assert!(!report.requires_review(), "{report:?}");
    }

    #[test]
    fn optional_absence_is_not_optional_identity_and_override_uses_the_winner() {
        let report = modern(json!({
            "node_modules/a":{"version":"1.0.0",
                "dependencies":{"alias":"npm:old@1"},
                "optionalDependencies":{"alias":"npm:new@2","platform-only":"1"}},
            "node_modules/alias":{"name":"new","version":"2.0.0"}
        })).unwrap();
        assert!(!report.requires_review(), "{report:?}");
        let report = modern(json!({
            "node_modules/a":{"version":"1.0.0","optionalDependencies":{"alias":"npm:new@2"}},
            "node_modules/alias":{"name":"wrong","version":"2.0.0"}
        })).unwrap();
        assert_eq!(report.findings[0].code, "unresolved_transitive_dependency");
    }

    #[test]
    fn runtime_dependencies_supersede_same_named_peer_edges() {
        for section in ["dependencies", "optionalDependencies"] {
            let mut consumer = json!({
                "version": "1.0.0",
                "peerDependencies": { "adapter": "npm:sharp@1" }
            });
            consumer[section] = json!({ "adapter": "npm:ordinary@1" });
            let report = modern(json!({
                "node_modules/a": consumer,
                "node_modules/a/node_modules/adapter": {
                    "name": "ordinary",
                    "version": "1.0.0"
                }
            }))
            .unwrap();
            assert!(!report.requires_review(), "{section}: {report:?}");
        }
    }

    #[test]
    fn overridden_peer_edges_still_validate_request_metadata() {
        for request in [json!(12), json!("npm:")] {
            let report = modern(json!({
                "node_modules/a": {
                    "version": "1.0.0",
                    "dependencies": { "adapter": "npm:ordinary@1" },
                    "peerDependencies": { "adapter": request }
                },
                "node_modules/a/node_modules/adapter": {
                    "name": "ordinary",
                    "version": "1.0.0"
                }
            }));
            assert!(report.is_err());
        }
    }

    #[test]
    fn required_peers_are_not_hidden_by_optional_peers_or_private_copies() {
        let report = modern(json!({
            "node_modules/a":{"version":"1.0.0","peerDependencies":{"required":"1","optional":"1"},
                "peerDependenciesMeta":{"optional":{"optional":true}}}
        })).unwrap();
        assert_eq!(report.findings.len(), 1);
        assert_eq!(report.findings[0].package, "required");
        let report = modern(json!({
            "node_modules/a":{"version":"1.0.0","peerDependencies":{"peer":"1"}},
            "node_modules/a/node_modules/peer":{"version":"1.0.0"},
            "node_modules/peer":{"version":"1.0.0"}
        })).unwrap();
        assert_eq!(report.findings[0].code, "invalid_peer_placement");
    }

    #[test]
    fn package_development_dependencies_are_not_installed_runtime_edges() {
        let report = modern(json!({
            "node_modules/a":{"version":"1.0.0","devDependencies":{"uninstalled-test-tool":"1"}}
        })).unwrap();
        assert!(!report.requires_review());
    }

    #[test]
    fn transitive_version_ranges_do_not_accept_an_incompatible_private_pin() {
        let report = modern(json!({
            "node_modules/a":{"version":"1.0.0","dependencies":{"b":"^2"}},
            "node_modules/a/node_modules/b":{"version":"1.9.9"},
            "node_modules/b":{"version":"2.1.0"}
        })).unwrap();
        assert_eq!(report.findings.len(), 1);
        assert_eq!(report.findings[0].code, "dependency_version_mismatch");
        assert_eq!(report.findings[0].package_path.as_deref(), Some("node_modules/a/node_modules/b"));
    }

    #[test]
    fn root_declarations_share_the_actual_version_admission_not_just_graph_checks() {
        let root = tempfile::tempdir().unwrap();
        fs::write(root.path().join("package.json"), r#"{"dependencies":{"a":"^2"}}"#).unwrap();
        fs::write(root.path().join("package-lock.json"), serde_json::to_vec(&json!({
            "lockfileVersion":3,"packages":{"node_modules/a":{"version":"1.0.0"}}
        })).unwrap()).unwrap();
        let report = super::super::inspect(root.path(), deadline()).unwrap();
        assert_eq!(report.findings.len(), 1);
        assert_eq!(report.findings[0].code, "dependency_version_mismatch");
        assert_eq!(report.findings[0].source, "package.json#dependencies");
        assert!(!root.path().join("node_modules").exists());
    }

    #[test]
    fn alias_and_legacy_requests_check_the_target_version_and_do_not_guess_tags() {
        let report = assess(json!({"lockfileVersion":1,"dependencies":{
            "a":{"version":"1.0.0","requires":{"alias":"npm:actual@^2"}},
            "alias":{"version":"npm:actual@1.0.0"}
        }})).unwrap();
        assert_eq!(report.findings[0].code, "dependency_version_mismatch");
        for request in ["latest", "npm:actual", "https://example.invalid/actual.tgz"] {
            let report = modern(json!({
                "node_modules/a":{"version":"1.0.0","dependencies":{"actual":request}},
                "node_modules/actual":{"version":"1.0.0"}
            })).unwrap();
            assert_eq!(report.findings[0].code, "unverifiable_dependency_version", "{request}");
        }
    }

    #[test]
    fn installed_optional_and_peer_versions_remain_load_bearing() {
        for section in ["optionalDependencies", "peerDependencies"] {
            let mut record = json!({"version":"1.0.0"});
            record[section] = json!({"b":"^2"});
            let report = modern(json!({
                "node_modules/a":record,"node_modules/b":{"version":"1.0.0"}
            })).unwrap();
            assert_eq!(report.findings[0].code, "dependency_version_mismatch", "{section}");
        }
    }

    #[test]
    fn legacy_requires_cannot_hide_missing_or_alias_substituted_dependencies() {
        let report = assess(json!({"lockfileVersion":1,"dependencies":{
            "a":{"version":"1.0.0","requires":{"alias":"npm:actual@1"},
                "dependencies":{"alias":{"version":"npm:wrong@1.0.0"}}},
            "alias":{"version":"npm:actual@1.0.0"}
        }})).unwrap();
        assert_eq!(report.findings.len(), 1);
        assert_eq!(report.findings[0].package, "actual");
        assert!(report.findings[0].source.ends_with("#requires"));
        assert_eq!(report.findings[0].package_path.as_deref(), Some("node_modules/a/node_modules/alias"));
    }

    #[test]
    fn native_alias_declarations_are_reviewed_even_when_locked_name_is_innocuous() {
        let report = modern(json!({
            "node_modules/a":{"version":"1.0.0","dependencies":{"image":"npm:sharp@1"}},
            "node_modules/image":{"name":"ordinary","version":"1.0.0"}
        })).unwrap();
        assert_eq!(report.findings[0].code, "native_addon");
        assert_eq!(report.findings[0].package, "sharp");
    }

    #[test]
    fn invalid_edge_metadata_fails_closed_instead_of_disappearing() {
        for record in [
            json!({"version":"1.0.0","dependencies":null}),
            json!({"version":"1.0.0","dependencies":{"a":12}}),
            json!({"version":"1.0.0","optionalDependencies":{"a":"npm:"}}),
            json!({"version":"1.0.0","peerDependenciesMeta":{"a":{"optional":"true"}}}),
            json!({"version":"1.0.0","peerDependenciesMeta":{"a":null}}),
        ] {
            assert!(modern(json!({"node_modules/a":record})).is_err());
        }
        assert!(assess(json!({"lockfileVersion":1,"dependencies":{
            "a":{"version":"1.0.0","requires":true}
        }})).is_err());
    }

    #[test]
    fn bounded_edge_and_deadline_failures_never_return_partial_approval() {
        let mut report = DependencyAdmission {
            schema_version: String::new(), scope: String::new(), packages_scanned: 0,
            manifests_scanned: 0, inputs: Vec::new(), findings: Vec::new(),
            installation_checked: false, installed_packages_scanned: 0,
        };
        let packages = BTreeMap::new();
        let mut admission = Admission {
            packages: &packages, source: "package-lock.json", report: &mut report,
            deadline: deadline(), edges: MAX_DEPENDENCY_EDGES,
        };
        assert!(admission.edge(Edge {
            consumer: "node_modules/a", section: "optionalDependencies", installed_as: "b",
            request: "1", optional: true, peer: false,
        }).unwrap_err().to_string().contains("edge limit"));
        assert!(inspect(None, &packages, "package-lock.json", &mut report, Instant::now()).is_err());
    }
}
