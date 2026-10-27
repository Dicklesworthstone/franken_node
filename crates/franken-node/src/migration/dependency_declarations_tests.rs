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

fn overridden_tree(overrides: Value, request: &str, version: &str) -> tempfile::TempDir {
    let parent = json!({"name":"parent","version":"1.0.0","dependencies":{"child":request}});
    let child = json!({"name":"child","version":version});
    let root = fixture(
        json!({"dependencies":{"parent":"1"},"overrides":overrides}),
        json!({
            "node_modules/parent":parent,"node_modules/child":child
        }),
    );
    put(root.path(), "node_modules/parent/package.json", &parent);
    put(root.path(), "node_modules/child/package.json", &child);
    root
}

#[test]
fn scalar_root_overrides_reach_actual_installation_for_every_supported_npm_lock_version() {
    use sha2::{Digest, Sha256};
    // npm 11.9.0 / Arborist 9.2.0 loadActual: parent requires ^1, root
    // overrides child to 2.0.0, and the installed child 2.0.0 edge is valid.
    for version in [1, 2, 3] {
        let root = overridden_tree(json!({"child":"2.0.0"}), "^1", "2.0.0");
        let lock = if version == 1 {
            json!({"lockfileVersion":1,"dependencies":{
                "parent":{"version":"1.0.0","requires":{"child":"^1"}},
                "child":{"version":"2.0.0"}
            }})
        } else {
            json!({"lockfileVersion":version,"packages":{
                "node_modules/parent":{"version":"1.0.0","dependencies":{"child":"^1"}},
                "node_modules/child":{"version":"2.0.0"}
            }})
        };
        put(root.path(), "package-lock.json", &lock);
        let report = inspect_for_execution(root.path(), deadline()).unwrap();
        assert!(
            !report.requires_review() && report.installation_checked,
            "v{version}: {report:#?}"
        );
        assert_eq!(report.installed_packages_scanned, 2);
        assert!(report.scope.contains("captured root scalar npm overrides"));
        let root_bytes = fs::read(root.path().join("package.json")).unwrap();
        let input = report
            .inputs
            .iter()
            .find(|input| input.path == "package.json")
            .unwrap();
        assert_eq!(input.sha256, hex::encode(Sha256::digest(&root_bytes)));
        assert_eq!(
            report,
            inspect_for_execution(root.path(), deadline()).unwrap()
        );

        put(
            root.path(),
            "node_modules/child/package.json",
            &json!({"name":"child","version":"2.1.0"}),
        );
        let changed = inspect_for_execution(root.path(), deadline()).unwrap();
        assert!(changed.installation_checked && has(&changed, "installed_identity_mismatch"));
        put(
            root.path(),
            "package.json",
            &json!({"dependencies":{"parent":"1"}}),
        );
        let no_authority = inspect_for_execution(root.path(), deadline()).unwrap();
        assert!(
            has(&no_authority, "dependency_version_mismatch") && !no_authority.installation_checked
        );
    }
}

fn fork_override_tree(
    overrides: Value,
    request: &str,
    fork: &str,
    version: &str,
) -> tempfile::TempDir {
    let parent = json!({"name":"parent","version":"1.0.0","dependencies":{"child":request}});
    let child = json!({"name":fork,"version":version});
    let root = fixture(
        json!({"dependencies":{"parent":"1"},"overrides":overrides}),
        json!({"node_modules/parent":parent,"node_modules/child":child}),
    );
    put(root.path(), "node_modules/parent/package.json", &parent);
    put(root.path(), "node_modules/child/package.json", &child);
    root
}

#[test]
fn registry_fork_overrides_bind_actual_identities_for_every_npm_lock_version() {
    // npm 11.9.0 / Arborist 9.2.0 loadActual independently selects the
    // literal fork spec for ordinary AND aliased incoming requests. npm v1
    // stores a fork identity inside version; v2/v3 use a separate name.
    for lock_version in [1, 2, 3] {
        for fork in ["maintained-child", "@patched/child"] {
            for request in ["^1", "npm:original-child@^1"] {
                let replacement = format!("npm:{fork}@^2");
                let root = fork_override_tree(json!({"child":replacement}), request, fork, "2.1.0");
                let lock = if lock_version == 1 {
                    json!({"lockfileVersion":1,"dependencies":{
                        "parent":{"version":"1.0.0","requires":{"child":request}},
                        "child":{"version":format!("npm:{fork}@2.1.0")}
                    }})
                } else {
                    json!({"lockfileVersion":lock_version,"packages":{
                        "node_modules/parent":{"version":"1.0.0","dependencies":{"child":request}},
                        "node_modules/child":{"name":fork,"version":"2.1.0"}
                    }})
                };
                put(root.path(), "package-lock.json", &lock);
                let before_root = fs::read(root.path().join("package.json")).unwrap();
                let before_parent =
                    fs::read(root.path().join("node_modules/parent/package.json")).unwrap();
                let report = inspect_for_execution(root.path(), deadline()).unwrap();
                assert!(
                    report.installation_checked && !report.requires_review(),
                    "v{lock_version} {replacement} {request}: {report:#?}"
                );
                assert_eq!(report.installed_packages_scanned, 2);
                assert!(report.scope.contains("including explicit registry aliases"));
                assert_eq!(
                    fs::read(root.path().join("package.json")).unwrap(),
                    before_root
                );
                assert_eq!(
                    fs::read(root.path().join("node_modules/parent/package.json")).unwrap(),
                    before_parent
                );
                assert_eq!(
                    report,
                    inspect_for_execution(root.path(), deadline()).unwrap()
                );
            }
        }
    }
}

#[test]
fn registry_fork_references_and_direct_conflicts_follow_npm_exact_specs() {
    // Literal expected outcomes observed with npm 11.9.0 / Arborist 9.2.0,
    // including EOVERRIDE for an equivalent but differently spelled range.
    for section in FIELDS {
        for (rule, conflict) in [
            ("npm:@patched/child@^2", false),
            ("$child", false),
            ("$patch", false),
            ("npm:@patched/child@>=2 <3", true),
            ("npm:another-fork@^2", true),
            ("^2", true),
        ] {
            let mut manifest = json!({"dependencies":{"patch":"npm:@patched/child@^2"},
                "overrides":{"child":rule}});
            manifest[section] = json!({"child":"npm:@patched/child@^2"});
            manifest["dependencies"]["patch"] = json!("npm:@patched/child@^2");
            let child = json!({"name":"@patched/child","version":"2.1.0"});
            let root = fixture(
                manifest,
                json!({
                    "node_modules/child":child,"node_modules/patch":child
                }),
            );
            put(root.path(), "node_modules/child/package.json", &child);
            put(root.path(), "node_modules/patch/package.json", &child);
            let report = inspect_for_execution(root.path(), deadline()).unwrap();
            assert_eq!(
                has(&report, "conflicting_npm_override"),
                conflict,
                "{section} {rule}: {report:#?}"
            );
            assert_eq!(
                report.requires_review(),
                conflict,
                "{section} {rule}: {report:#?}"
            );
            assert_eq!(report.installation_checked, !conflict);
        }
    }
    let root = fork_override_tree(json!({"child":"$patch"}), "^1", "@patched/child", "2.1.0");
    put(
        root.path(),
        "package.json",
        &json!({"dependencies":{"parent":"1"},
        "optionalDependencies":{"patch":"npm:@patched/child@^2"},"overrides":{"child":"$patch"}}),
    );
    let report = inspect_for_execution(root.path(), deadline()).unwrap();
    assert!(
        report.installation_checked && !report.requires_review(),
        "{report:#?}"
    );
}

#[test]
fn registry_fork_overrides_reach_workspace_optional_peer_and_private_edges() {
    let member = json!({"name":"member","version":"1.0.0","dependencies":{"child":"^1"},
        "overrides":{"child":"npm:untrusted-fork@99"}});
    let a = json!({"name":"a","version":"1.0.0","dependencies":{"child":"npm:original-child@^1"}});
    let b =
        json!({"name":"b","version":"1.0.0","optionalDependencies":{"child":"^1","absent":"^1"}});
    let c = json!({"name":"c","version":"1.0.0","peerDependencies":{"child":"^1"}});
    let child = json!({"name":"@patched/child","version":"2.1.0"});
    let root_manifest = json!({"workspaces":["packages/member"],"dependencies":{"a":"1","b":"1","c":"1"},
        "overrides":{"child":"npm:@patched/child@^2","absent":"npm:optional-fork@^2"}});
    let root = fixture(
        root_manifest.clone(),
        json!({
            "packages/member":member,"node_modules/member":{"link":true,"resolved":"packages/member"},
            "node_modules/a":a,"node_modules/b":b,"node_modules/c":c,
            "node_modules/a/node_modules/child":child,"node_modules/child":child
        }),
    );
    for (path, manifest) in [
        ("packages/member", &member),
        ("node_modules/a", &a),
        ("node_modules/b", &b),
        ("node_modules/c", &c),
        ("node_modules/a/node_modules/child", &child),
        ("node_modules/child", &child),
    ] {
        put(root.path(), &format!("{path}/package.json"), manifest);
    }
    symlink(
        "../packages/member",
        root.path().join("node_modules/member"),
    )
    .unwrap();
    let report = inspect_for_execution(root.path(), deadline()).unwrap();
    assert!(
        report.installation_checked && !report.requires_review(),
        "{report:#?}"
    );
    assert_eq!(report.installed_packages_scanned, 6);
    let mut no_authority = root_manifest;
    no_authority.as_object_mut().unwrap().remove("overrides");
    put(root.path(), "package.json", &no_authority);
    let report = inspect_for_execution(root.path(), deadline()).unwrap();
    assert!(
        has(&report, "unresolved_transitive_dependency") && !report.installation_checked,
        "workspace/package overrides became authority: {report:#?}"
    );
}

#[test]
fn registry_fork_identity_version_and_installed_metadata_cannot_be_substituted() {
    for (field, value, expected) in [
        ("name", "child", "unresolved_transitive_dependency"),
        ("name", "other-fork", "unresolved_transitive_dependency"),
        ("version", "1.9.9", "dependency_version_mismatch"),
    ] {
        let root = fork_override_tree(
            json!({"child":"npm:@patched/child@^2"}),
            "^1",
            "@patched/child",
            "2.1.0",
        );
        let mut lock: Value =
            serde_json::from_slice(&fs::read(root.path().join("package-lock.json")).unwrap())
                .unwrap();
        lock["packages"]["node_modules/child"][field] = json!(value);
        put(root.path(), "package-lock.json", &lock);
        let report = inspect_for_execution(root.path(), deadline()).unwrap();
        assert!(
            has(&report, expected) && !report.installation_checked,
            "{field}={value}: {report:#?}"
        );
    }
    for (name, version) in [("child", "2.1.0"), ("@patched/child", "2.2.0")] {
        let root = fork_override_tree(
            json!({"child":"npm:@patched/child@^2"}),
            "^1",
            "@patched/child",
            "2.1.0",
        );
        put(
            root.path(),
            "node_modules/child/package.json",
            &json!({"name":name,"version":version}),
        );
        let report = inspect_for_execution(root.path(), deadline()).unwrap();
        assert!(
            has(&report, "installed_identity_mismatch") && report.installation_checked,
            "{name}@{version}: {report:#?}"
        );
    }
    let root = fork_override_tree(
        json!({"child":"npm:@patched/child@^2"}),
        "^1",
        "@patched/child",
        "2.1.0",
    );
    put(
        root.path(),
        "node_modules/parent/package.json",
        &json!({"name":"parent","version":"1.0.0",
        "dependencies":{"child":"npm:@patched/child@^2"}}),
    );
    let report = inspect_for_execution(root.path(), deadline()).unwrap();
    assert!(
        has(&report, "installed_dependency_metadata_mismatch") && report.installation_checked,
        "raw declaration rewrite was hidden by the effective override: {report:#?}"
    );
}

#[test]
fn registry_fork_overrides_cannot_rescue_missing_private_installations() {
    let parent = json!({"name":"parent","version":"1.0.0","dependencies":{"child":"^1"}});
    let child = json!({"name":"@patched/child","version":"2.1.0"});
    let root = fixture(
        json!({"dependencies":{"parent":"1"},"overrides":{"child":"npm:@patched/child@^2"}}),
        json!({"node_modules/parent":parent,"node_modules/child":child,
            "node_modules/parent/node_modules/child":child}),
    );
    put(root.path(), "node_modules/parent/package.json", &parent);
    put(root.path(), "node_modules/child/package.json", &child);
    let report = inspect_for_execution(root.path(), deadline()).unwrap();
    assert!(
        report.installation_checked && has(&report, "installed_dependency_route_mismatch"),
        "{report:#?}"
    );
    let mismatch = report
        .findings
        .iter()
        .find(|finding| finding.code == "installed_dependency_route_mismatch")
        .unwrap();
    assert_eq!(
        mismatch.package_path.as_deref(),
        Some("node_modules/parent/node_modules/child")
    );
}

#[test]
fn registry_alias_wildcards_replace_identity_and_scoped_lookup_names_stay_intact() {
    let parent = json!({"name":"parent","version":"1.0.0","dependencies":{"@original/child":"^1"}});
    let child = json!({"name":"@patched/child","version":"4.0.0"});
    let root = fixture(
        json!({"dependencies":{"parent":"1"},
        "overrides":{"@original/child":"npm:@patched/child@*"}}),
        json!({"node_modules/parent":parent,"node_modules/@original/child":child}),
    );
    put(root.path(), "node_modules/parent/package.json", &parent);
    put(
        root.path(),
        "node_modules/@original/child/package.json",
        &child,
    );
    let report = inspect_for_execution(root.path(), deadline()).unwrap();
    assert!(
        report.installation_checked && !report.requires_review(),
        "{report:#?}"
    );
    assert!(
        report
            .inputs
            .iter()
            .any(|input| input.path == "node_modules/@original/child/package.json")
    );
}

#[test]
fn registry_fork_overrides_preserve_native_lifecycle_and_shrinkwrap_review() {
    for (request, fork) in [("npm:sharp@^1", "@patched/child"), ("^1", "sharp")] {
        let root = fork_override_tree(
            json!({"child":format!("npm:{fork}@^2")}),
            request,
            fork,
            "2.1.0",
        );
        let report = inspect_for_execution(root.path(), deadline()).unwrap();
        assert!(
            has(&report, "native_addon") && !report.installation_checked,
            "{request} {fork}: {report:#?}"
        );
    }
    for (case, code) in [
        ("script", "install_script"),
        ("native", "native_payload"),
        ("shrinkwrap", "unsupported_npm_override_context"),
        ("bundle", "unsupported_npm_override_context"),
    ] {
        let root = fork_override_tree(
            json!({"child":"npm:@patched/child@^2"}),
            "^1",
            "@patched/child",
            "2.1.0",
        );
        let mut child = json!({"name":"@patched/child","version":"2.1.0"});
        match case {
            "script" => child["scripts"] = json!({"install":"must never execute"}),
            "native" => put(
                root.path(),
                "node_modules/child/native.node",
                &json!("inert fixture"),
            ),
            "shrinkwrap" => put(
                root.path(),
                "node_modules/parent/npm-shrinkwrap.json",
                &json!({"lockfileVersion":3,"packages":{}}),
            ),
            "bundle" => child["bundleDependencies"] = json!(["nested"]),
            _ => unreachable!(),
        }
        put(root.path(), "node_modules/child/package.json", &child);
        let report = inspect_for_execution(root.path(), deadline()).unwrap();
        assert!(
            report.installation_checked && has(&report, code),
            "{case}: {report:#?}"
        );
    }
}

#[test]
fn global_overrides_check_production_optional_peer_and_private_edges() {
    let a = json!({"name":"a","version":"1.0.0","dependencies":{"child":"^1"}});
    let b =
        json!({"name":"b","version":"1.0.0","optionalDependencies":{"child":"^1","absent":"^1"}});
    let c = json!({"name":"c","version":"1.0.0","peerDependencies":{"child":"^1"}});
    let root = fixture(
        json!({"dependencies":{"a":"1","b":"1","c":"1"},
        "overrides":{"child":"^2","absent":"^2"}}),
        json!({
            "node_modules/a":a,"node_modules/b":b,"node_modules/c":c,
            "node_modules/a/node_modules/child":{"version":"2.0.0"},
            "node_modules/child":{"version":"2.1.0"}
        }),
    );
    for (path, manifest) in [("a", &a), ("b", &b), ("c", &c)] {
        put(
            root.path(),
            &format!("node_modules/{path}/package.json"),
            manifest,
        );
    }
    put(
        root.path(),
        "node_modules/a/node_modules/child/package.json",
        &json!({"name":"child","version":"2.0.0"}),
    );
    put(
        root.path(),
        "node_modules/child/package.json",
        &json!({"name":"child","version":"2.1.0"}),
    );
    let report = inspect_for_execution(root.path(), deadline()).unwrap();
    assert!(
        !report.requires_review() && report.installation_checked,
        "{report:#?}"
    );
    assert_eq!(report.installed_packages_scanned, 5);
    let mut lock: Value =
        serde_json::from_slice(&fs::read(root.path().join("package-lock.json")).unwrap()).unwrap();
    lock["packages"]["node_modules/a/node_modules/child"]["version"] = json!("1.0.0");
    put(root.path(), "package-lock.json", &lock);
    let report = inspect(root.path(), deadline()).unwrap();
    let mismatch = report
        .findings
        .iter()
        .find(|finding| finding.code == "dependency_version_mismatch")
        .unwrap();
    assert_eq!(
        mismatch.package_path.as_deref(),
        Some("node_modules/a/node_modules/child")
    );
    assert_eq!(mismatch.version.as_deref(), Some("^2"));
}

#[test]
fn only_root_override_authority_applies_to_workspace_and_installed_manifests() {
    let member = json!({"name":"member","version":"1.0.0","dependencies":{"child":"^1"},
        "overrides":{"child":"99"}});
    let parent = json!({"name":"parent","version":"1.0.0","dependencies":{"child":"^1"},
        "overrides":{"child":{"nested":"99"}}});
    let root_manifest = json!({"workspaces":["packages/member"],"dependencies":{"parent":"1"},
        "overrides":{"child":"2"}});
    let root = fixture(
        root_manifest.clone(),
        json!({
            "packages/member":member,"node_modules/member":{"link":true,"resolved":"packages/member"},
            "node_modules/parent":parent,"node_modules/child":{"version":"2.0.0"}
        }),
    );
    put(root.path(), "packages/member/package.json", &member);
    put(root.path(), "node_modules/parent/package.json", &parent);
    put(
        root.path(),
        "node_modules/child/package.json",
        &json!({"name":"child","version":"2.0.0"}),
    );
    symlink(
        "../packages/member",
        root.path().join("node_modules/member"),
    )
    .unwrap();
    let report = inspect_for_execution(root.path(), deadline()).unwrap();
    assert!(
        !report.requires_review() && report.installation_checked,
        "{report:#?}"
    );
    let mut no_authority = root_manifest;
    no_authority.as_object_mut().unwrap().remove("overrides");
    put(root.path(), "package.json", &no_authority);
    let report = inspect_for_execution(root.path(), deadline()).unwrap();
    assert!(has(&report, "dependency_version_mismatch") && !report.installation_checked);
}

#[test]
fn implicit_workspace_root_edges_enforce_the_npm_override_conflict_contract() {
    // npm 11.9.0 / Arborist 9.2.0 makes this a file: edge even when an
    // explicit direct dependency says "2". Its assertRootOverrides rejects
    // scalar and $self replacements; a literal wildcard remains a no-op.
    for (direct, rule, conflict) in [
        (false, "2", true),
        (true, "2", true),
        (true, "$member", true),
        (false, "*", false),
    ] {
        let member = json!({"name":"member","version":"2.0.0"});
        let mut manifest = json!({"workspaces":["packages/member"],"overrides":{"member":rule}});
        if direct {
            manifest["dependencies"] = json!({"member":"2"});
        }
        let root = fixture(
            manifest,
            json!({"packages/member":member,
            "node_modules/member":{"link":true,"resolved":"packages/member"}}),
        );
        put(root.path(), "packages/member/package.json", &member);
        fs::create_dir(root.path().join("node_modules")).unwrap();
        symlink(
            "../packages/member",
            root.path().join("node_modules/member"),
        )
        .unwrap();
        let report = inspect_for_execution(root.path(), deadline()).unwrap();
        assert_eq!(
            has(&report, "conflicting_npm_override"),
            conflict,
            "direct={direct} {rule}: {report:#?}"
        );
        assert_eq!(report.requires_review(), conflict, "{report:#?}");
        assert_eq!(report.installation_checked, !conflict);
    }
}

#[test]
fn unversioned_scoped_package_override_keys_select_the_captured_scoped_identity() {
    let parent = json!({"name":"parent","version":"1.0.0","dependencies":{"@scope/child":"^1"}});
    let root = fixture(
        json!({"dependencies":{"parent":"1"},"overrides":{"@scope/child":"^2"}}),
        json!({"node_modules/parent":parent,"node_modules/@scope/child":{"version":"2.0.0"}}),
    );
    put(root.path(), "node_modules/parent/package.json", &parent);
    put(
        root.path(),
        "node_modules/@scope/child/package.json",
        &json!({"name":"@scope/child","version":"2.0.0"}),
    );
    let report = inspect_for_execution(root.path(), deadline()).unwrap();
    assert!(
        !report.requires_review() && report.installation_checked,
        "{report:#?}"
    );
}

#[test]
fn root_override_reference_precedence_matches_independent_npm_v11_table() {
    // npm 11.9.0 / Arborist 9.2.0, all 15 nonempty combinations of
    // dependencies/devDependencies/peerDependencies/optionalDependencies.
    let expected = [
        "1.0.0", "2.0.0", "2.0.0", "3.0.0", "1.0.0", "2.0.0", "2.0.0", "4.0.0", "4.0.0", "2.0.0",
        "2.0.0", "4.0.0", "4.0.0", "2.0.0", "2.0.0",
    ];
    for mask in 1..16 {
        let mut manifest = collision(mask);
        for (index, field) in FIELDS.iter().enumerate() {
            if mask & (1 << index) != 0 {
                manifest[*field] = json!({"x":format!("{}.0.0", index + 1)});
            }
        }
        manifest["overrides"] = json!({"child":"$x"});
        let bytes = serde_json::to_vec(&manifest).unwrap();
        let root = fixture(json!({}), json!({}));
        let mut report = inspect(root.path(), deadline()).unwrap();
        let overrides = Overrides::capture(&manifest, &mut report, deadline()).unwrap();
        assert!(!report.requires_review(), "mask {mask}: {report:#?}");
        assert_eq!(overrides.apply("child", "^9"), expected[mask - 1]);
        assert_eq!(serde_json::to_vec(&manifest).unwrap(), bytes);
    }
}

#[test]
fn root_direct_override_conflicts_match_npm_eoverride_exact_text_contract() {
    // npm 11.9.0 `npm ls --json --offline --ignore-scripts`: exact/self
    // references pass, semantically equivalent differently written ranges fail.
    for section in FIELDS {
        for (rule, conflict) in [
            ("^1", false),
            (">=1 <2", true),
            ("2", true),
            ("$child", false),
            ("$ref", true),
            ("*", false),
            ("", false),
        ] {
            let mut manifest = json!({"dependencies":{"ref":"^2"},"overrides":{"child":rule}});
            manifest[section] = json!({"child":"^1"});
            manifest["dependencies"]["ref"] = json!("^2");
            let root = fixture(
                manifest,
                json!({
                    "node_modules/child":{"version":"1.2.0"},"node_modules/ref":{"version":"2.0.0"}
                }),
            );
            put(
                root.path(),
                "node_modules/child/package.json",
                &json!({"name":"child","version":"1.2.0"}),
            );
            put(
                root.path(),
                "node_modules/ref/package.json",
                &json!({"name":"ref","version":"2.0.0"}),
            );
            let report = inspect_for_execution(root.path(), deadline()).unwrap();
            assert_eq!(
                has(&report, "conflicting_npm_override"),
                conflict,
                "{section} {rule}: {report:#?}"
            );
            assert_eq!(
                report.requires_review(),
                conflict,
                "{section} {rule}: {report:#?}"
            );
            assert_eq!(report.installation_checked, !conflict);
        }
    }
}

#[test]
fn literal_override_wildcard_is_noop_but_referenced_wildcard_is_a_replacement() {
    for rule in ["*", ""] {
        let root = overridden_tree(json!({"child":rule}), "^1", "2.0.0");
        let report = inspect_for_execution(root.path(), deadline()).unwrap();
        assert!(has(&report, "dependency_version_mismatch") && !report.installation_checked);
    }
    let root = overridden_tree(json!({"child":"$ref"}), "^1", "2.0.0");
    put(
        root.path(),
        "package.json",
        &json!({"dependencies":{"parent":"1"},
        "optionalDependencies":{"ref":"*"},"overrides":{"child":"$ref"}}),
    );
    let report = inspect_for_execution(root.path(), deadline()).unwrap();
    assert!(
        !report.requires_review() && report.installation_checked,
        "{report:#?}"
    );
}

#[test]
fn unsupported_override_rules_cannot_be_hidden_by_a_supported_prefix_or_unused_name() {
    for (key, value) in [
        ("unused@^1", json!("2")),
        ("@scope/unused@^1", json!("2")),
        ("unused", json!({"child":"2"})),
        ("unused", json!({".":"2"})),
        ("unused", json!(["2"])),
        ("unused", json!(true)),
        ("unused", json!(null)),
        ("unused", json!("latest")),
        ("unused", json!("npm:fork@latest")),
        ("unused", json!("npm:fork")),
        ("unused", json!("npm:@scope/fork")),
        ("unused", json!("npm:fork@^2 || unsupported")),
        ("unused", json!("npm:fork@npm:another@2")),
        ("unused", json!("file:../fork")),
        ("unused", json!("git+https://example.invalid/fork")),
        ("unused", json!("workspace:*")),
        ("unused", json!("$missing")),
        ("unused", json!("^2 || unsupported")),
    ] {
        let mut rules = json!({"child":"2"});
        rules[key] = value;
        let root = overridden_tree(rules, "^1", "2.0.0");
        let report = inspect_for_execution(root.path(), deadline()).unwrap();
        assert!(
            has(&report, "unsupported_npm_override"),
            "{key}: {report:#?}"
        );
        assert!(
            has(&report, "dependency_version_mismatch"),
            "partial rules applied: {report:#?}"
        );
        assert!(!report.installation_checked);
        assert!(
            report
                .findings
                .iter()
                .any(|finding| finding.source == "package.json#overrides")
        );
    }
}

#[test]
fn effective_override_identity_and_original_native_risk_are_both_retained() {
    let root = overridden_tree(json!({"child":"2"}), "npm:ordinary@^1", "2.0.0");
    assert!(
        !inspect_for_execution(root.path(), deadline())
            .unwrap()
            .requires_review()
    );
    let mut lock: Value =
        serde_json::from_slice(&fs::read(root.path().join("package-lock.json")).unwrap()).unwrap();
    lock["packages"]["node_modules/child"]["name"] = json!("ordinary");
    put(root.path(), "package-lock.json", &lock);
    assert!(has(
        &inspect(root.path(), deadline()).unwrap(),
        "unresolved_transitive_dependency"
    ));
    let native = overridden_tree(json!({"child":"2"}), "npm:sharp@^1", "2.0.0");
    assert!(has(
        &inspect_for_execution(native.path(), deadline()).unwrap(),
        "native_addon"
    ));
    let script = overridden_tree(json!({"child":"2"}), "^1", "2.0.0");
    put(
        script.path(),
        "node_modules/child/package.json",
        &json!({"name":"child","version":"2.0.0",
        "scripts":{"install":"must never execute"}}),
    );
    let report = inspect_for_execution(script.path(), deadline()).unwrap();
    assert!(
        report.installation_checked && report.requires_review(),
        "{report:#?}"
    );
}

#[test]
fn root_overrides_never_approximate_bundled_or_nested_shrinkwrap_exclusions() {
    for field in ["inBundle", "bundled", "hasShrinkwrap"] {
        let root = overridden_tree(json!({"child":"2"}), "^1", "2.0.0");
        let mut lock: Value =
            serde_json::from_slice(&fs::read(root.path().join("package-lock.json")).unwrap())
                .unwrap();
        lock["packages"]["node_modules/child"][field] = json!(true);
        put(root.path(), "package-lock.json", &lock);
        let report = inspect_for_execution(root.path(), deadline()).unwrap();
        assert!(
            has(&report, "unsupported_npm_override_context") && !report.installation_checked,
            "{field}: {report:#?}"
        );
    }
    for context in ["bundle", "file", "directory"] {
        let root = overridden_tree(json!({"child":"2"}), "^1", "2.0.0");
        if context == "directory" {
            fs::create_dir(root.path().join("node_modules/parent/npm-shrinkwrap.json")).unwrap();
        } else if context == "file" {
            put(
                root.path(),
                "node_modules/parent/npm-shrinkwrap.json",
                &json!({"lockfileVersion":3,"packages":{}}),
            );
        } else {
            put(
                root.path(),
                "node_modules/parent/package.json",
                &json!({"name":"parent","version":"1.0.0",
                "dependencies":{"child":"^1"},"bundleDependencies":["child"]}),
            );
        }
        assert!(!inspect(root.path(), deadline()).unwrap().requires_review());
        let report = inspect_for_execution(root.path(), deadline()).unwrap();
        assert!(
            report.installation_checked && has(&report, "unsupported_npm_override_context"),
            "{context}: {report:#?}"
        );
    }
}

#[test]
fn malformed_and_expired_override_inputs_never_return_partial_authority() {
    for rules in [
        json!([]),
        json!({"child":"2".repeat(4097)}),
        json!({"bad\nname":"2"}),
    ] {
        let root = overridden_tree(rules, "^1", "2.0.0");
        assert!(inspect_for_execution(root.path(), deadline()).is_err());
    }
    let root = fixture(json!({}), json!({}));
    let mut report = inspect(root.path(), deadline()).unwrap();
    assert!(
        Overrides::capture(
            &json!({"overrides":{"child":"2"}}),
            &mut report,
            Instant::now()
        )
        .is_err()
    );
}
