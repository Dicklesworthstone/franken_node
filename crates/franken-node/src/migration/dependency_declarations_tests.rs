use super::*;
use super::super::{DependencyAdmission, inspect, inspect_for_execution};
use serde_json::json;
use std::fs;
use std::os::unix::fs::symlink;
use std::path::Path;
use std::time::Duration;

const FIELDS: [&str; 4] = ["dependencies", "devDependencies", "peerDependencies", "optionalDependencies"];

fn deadline() -> Instant { Instant::now() + Duration::from_secs(15) }
fn selection(manifest: &Value, project: bool) -> Vec<Declaration<'_>> {
    select(manifest, project, deadline(), &mut 0, 100).unwrap()
}
fn put(root: &Path, path: &str, value: &Value) {
    let path = root.join(path);
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(path, serde_json::to_vec(value).unwrap()).unwrap();
}
fn fixture(manifest: Value, records: Value) -> tempfile::TempDir {
    let root = tempfile::tempdir().unwrap();
    put(root.path(), "package.json", &manifest);
    put(root.path(), "package-lock.json", &json!({"lockfileVersion":3,"packages":records}));
    root
}
fn has(report: &DependencyAdmission, code: &str) -> bool {
    report.findings.iter().any(|finding| finding.code == code)
}
fn collision(mask: usize) -> Value {
    let mut manifest = json!({"name":"consumer","version":"1.0.0"});
    for (index, field) in FIELDS.iter().enumerate() {
        if mask & (1 << index) != 0 { manifest[*field] = json!({"x":(index + 1).to_string()}); }
    }
    manifest
}

#[test]
fn all_declaration_collisions_match_independent_npm_reference_table() {
    // npm 10.9.2 / Arborist 8.0.0, loadActual over real root and workspace
    // trees. Literal expected winners, not computed by the selector under test.
    let project_winners = [0, 1, 1, 2, 0, 1, 1, 3, 3, 1, 1, 3, 3, 1, 1];
    let package_winners = [Some(0), None, Some(0), Some(2), Some(0), Some(2), Some(0),
        Some(3), Some(3), Some(3), Some(3), Some(3), Some(3), Some(3), Some(3)];
    for mask in 1..16 {
        let manifest = collision(mask);
        let selected = selection(&manifest, true);
        let winner = project_winners[mask - 1];
        assert_eq!(selected.len(), 1);
        assert_eq!(selected[0].section, FIELDS[winner]);
        assert_eq!(selected[0].request, (winner + 1).to_string());
        assert_eq!(selected[0].optional, winner == 3);
        let selected = selection(&manifest, false);
        match package_winners[mask - 1] {
            None => assert!(selected.is_empty()),
            Some(winner) => {
                assert_eq!(selected.len(), 1);
                assert_eq!(selected[0].section, FIELDS[winner]);
                assert_eq!(selected[0].request, (winner + 1).to_string());
                assert_eq!(selected[0].optional, winner == 3);
            }
        }
    }
}

#[test]
fn all_project_and_workspace_collisions_reach_live_installed_admission() {
    let winners = [0, 1, 1, 2, 0, 1, 1, 3, 3, 1, 1, 3, 3, 1, 1];
    for workspace in [false, true] {
        for mask in 1..16 {
            let manifest = collision(mask);
            let version = format!("{}.0.0", winners[mask - 1] + 1);
            let mut records = json!({"node_modules/x":{"version":version.clone()}});
            let root = if workspace {
                records["packages/consumer"] = manifest.clone();
                records["node_modules/consumer"] = json!({"link":true,"resolved":"packages/consumer"});
                let root = fixture(json!({"name":"root","workspaces":["packages/consumer"]}), records);
                put(root.path(), "packages/consumer/package.json", &manifest);
                fs::create_dir(root.path().join("node_modules")).unwrap();
                symlink("../packages/consumer", root.path().join("node_modules/consumer")).unwrap();
                root
            } else { fixture(manifest, records) };
            put(root.path(), "node_modules/x/package.json", &json!({"name":"x","version":version}));
            let metadata = inspect(root.path(), deadline()).unwrap();
            assert!(!metadata.requires_review(), "workspace={workspace} mask={mask}: {metadata:#?}");
            let installed = inspect_for_execution(root.path(), deadline()).unwrap();
            assert!(!installed.requires_review(), "workspace={workspace} mask={mask}: {installed:#?}");
            assert!(installed.installation_checked);
            assert_eq!(installed.installed_packages_scanned, if workspace { 2 } else { 1 });
        }
    }
}

#[test]
fn optional_dependencies_and_optional_peers_may_have_no_locked_installation() {
    for manifest in [
        json!({"optionalDependencies":{"x":"^1"}}),
        json!({"dependencies":{"x":"^9"},"optionalDependencies":{"x":"^1"}}),
        json!({"peerDependencies":{"x":"^1"},"peerDependenciesMeta":{"x":{"optional":true}}}),
    ] {
        let root = fixture(manifest, json!({}));
        assert!(!inspect(root.path(), deadline()).unwrap().requires_review());
        let report = inspect_for_execution(root.path(), deadline()).unwrap();
        assert!(report.installation_checked && !report.requires_review(), "{report:#?}");
        assert!(!root.path().join("node_modules").exists());
    }
}

#[test]
fn a_dev_declaration_cannot_be_softened_by_same_named_optional_metadata() {
    for manifest in [
        json!({"devDependencies":{"x":"1"},"optionalDependencies":{"x":"1"}}),
        json!({"devDependencies":{"x":"1"},"peerDependencies":{"x":"1"},"peerDependenciesMeta":{"x":{"optional":true}}}),
    ] {
        let root = fixture(manifest, json!({"node_modules/x":{"version":"1.0.0"}}));
        assert!(!inspect(root.path(), deadline()).unwrap().requires_review());
        let installed = inspect_for_execution(root.path(), deadline()).unwrap();
        assert!(installed.installation_checked && has(&installed, "missing_installed_dependency"), "{installed:#?}");
        let finding = installed.findings.iter().find(|finding| finding.code == "missing_installed_dependency").unwrap();
        assert_eq!(finding.source, "package.json#devDependencies");
        assert_eq!(finding.package_path.as_deref(), Some("node_modules/x"));
    }
}

#[test]
fn installed_optional_versions_and_alias_identities_remain_checked() {
    for manifest in [
        json!({"optionalDependencies":{"x":"^2"}}),
        json!({"peerDependencies":{"x":"^2"},"peerDependenciesMeta":{"x":{"optional":true}}}),
    ] {
        let root = fixture(manifest, json!({"node_modules/x":{"version":"1.0.0"}}));
        assert!(has(&inspect(root.path(), deadline()).unwrap(), "dependency_version_mismatch"));
    }
    let root = fixture(json!({"optionalDependencies":{"x":"npm:expected@1"}}),
        json!({"node_modules/x":{"name":"wrong","version":"1.0.0"}}));
    assert!(has(&inspect(root.path(), deadline()).unwrap(), "unresolved_declaration"));
}

#[test]
fn only_the_effective_alias_controls_declaration_risk_but_inventory_is_not_hidden() {
    let root = fixture(json!({"dependencies":{"x":"npm:sharp@1"},"devDependencies":{"x":"npm:ordinary@2"}}),
        json!({"node_modules/x":{"name":"ordinary","version":"2.0.0"}}));
    put(root.path(), "node_modules/x/package.json", &json!({"name":"ordinary","version":"2.0.0"}));
    assert!(!inspect_for_execution(root.path(), deadline()).unwrap().requires_review());
    let root = fixture(json!({"dependencies":{"x":"npm:ordinary@2"},"devDependencies":{"x":"npm:sharp@1"}}),
        json!({"node_modules/x":{"name":"sharp","version":"1.0.0"}}));
    assert!(has(&inspect(root.path(), deadline()).unwrap(), "native_addon"));
    let root = fixture(json!({"optionalDependencies":{"x":"1"}}),
        json!({"node_modules/x":{"version":"1.0.0","hasInstallScript":true}}));
    assert!(has(&inspect(root.path(), deadline()).unwrap(), "install_script"));
}

#[test]
fn superseded_declarations_and_unattached_peer_metadata_are_still_validated() {
    for losing in [json!(17), json!("npm:"), json!("npm:bad@@1")] {
        let root = fixture(json!({"dependencies":{"x":losing},"devDependencies":{"x":"2"}}),
            json!({"node_modules/x":{"version":"2.0.0"}}));
        assert!(inspect(root.path(), deadline()).is_err());
    }
    for meta in [json!(null), json!({"unused":null}), json!({"unused":{"optional":"true"}})] {
        let root = fixture(json!({"devDependencies":{"x":"2"},"peerDependenciesMeta":meta}),
            json!({"node_modules/x":{"version":"2.0.0"}}));
        assert!(inspect(root.path(), deadline()).is_err());
    }
    for field in FIELDS {
        let mut manifest = json!({"devDependencies":{"x":"2"}});
        manifest[field] = Value::Null;
        assert!(select(&manifest, true, deadline(), &mut 0, 100).is_err());
    }
}

#[test]
fn declaration_budgets_count_losing_entries_and_peer_metadata_without_overflow() {
    let manifest = collision(15);
    let mut count = 0;
    assert!(select(&manifest, true, deadline(), &mut count, 3).is_err());
    let mut count = 0;
    assert_eq!(select(&manifest, true, deadline(), &mut count, 4).unwrap().len(), 1);
    assert_eq!(count, 4);
    let metadata = json!({"peerDependenciesMeta":{"unused":{"optional":true}}});
    assert!(select(&metadata, true, deadline(), &mut 0, 0).is_err());
    let mut overflow = usize::MAX;
    assert!(select(&manifest, true, deadline(), &mut overflow, usize::MAX).is_err());
    assert!(select(&json!({}), true, Instant::now(), &mut 0, 100).is_err());
}

#[test]
fn workspace_private_required_tool_cannot_be_rescued_by_an_optional_hoist() {
    let manifest = json!({"name":"consumer","version":"1.0.0", "devDependencies":{"x":"2"}, "optionalDependencies":{"x":"1"}});
    let root = fixture(json!({"name":"root","workspaces":["packages/consumer"]}), json!({
        "packages/consumer":manifest.clone(),
        "node_modules/consumer":{"link":true,"resolved":"packages/consumer"},
        "packages/consumer/node_modules/x":{"version":"2.0.0"},
        "node_modules/x":{"version":"2.0.0"}
    }));
    put(root.path(), "packages/consumer/package.json", &manifest);
    put(root.path(), "node_modules/x/package.json", &json!({"name":"x","version":"2.0.0"}));
    symlink("../packages/consumer", root.path().join("node_modules/consumer")).unwrap();
    let report = inspect_for_execution(root.path(), deadline()).unwrap();
    assert!(report.installation_checked && has(&report, "installed_dependency_route_mismatch"), "{report:#?}");
    let finding = report.findings.iter().find(|finding| finding.code == "installed_dependency_route_mismatch").unwrap();
    assert_eq!(finding.source, "packages/consumer/package.json#devDependencies");
    assert_eq!(finding.package_path.as_deref(), Some("packages/consumer/node_modules/x"));
}

#[test]
fn stable_selection_retains_alias_requirements_without_mutating_captured_maps() {
    let manifest = json!({"optionalDependencies":{"z":"npm:@scope/z@^2","a":"1"}, "peerDependenciesMeta":{"z":{"optional":true}}});
    let original = serde_json::to_vec(&manifest).unwrap();
    let selected = selection(&manifest, true);
    assert_eq!(selected.iter().map(|edge| edge.installed_as).collect::<Vec<_>>(), ["a", "z"]);
    assert_eq!(selected[1].package, "@scope/z");
    assert_eq!(selected[1].requirement, Some("^2"));
    assert!(selected[1].optional);
    assert_eq!(selected, selection(&manifest, true));
    assert_eq!(serde_json::to_vec(&manifest).unwrap(), original);
}
