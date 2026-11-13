//! Strict dependency admission uses the same signed durable registry at
//! product preflight, dispatcher admission, and native worker rechecks.

use super::{parse_json_stdout, run_cli_in_workspace_with_env, write_run_package_manifest};
use frankenengine_node::config::{CliOverrides, Config, Profile};
use frankenengine_node::ops::engine_dispatcher::{RunTrustRequirements, validate_execution_trust};
use frankenengine_node::supply_chain::trust_card::{
    CapturedDependencyTrust, SnapshotSourceContext, TrustCardRegistry,
};
use frankenengine_node::supply_chain::trust_card_registry_store::{
    record_revocation_frontier, registry_snapshot_path,
};
use serde_json::json;
use std::fs;
use std::path::Path;
use std::process::Output;

const DEPENDENCY_ID: &str = "npm:lodash";
const GUEST_OUTPUT: &str = "strict-admission-body\n";

struct Fixture {
    project: tempfile::TempDir,
    operator_state: tempfile::TempDir,
    config: Config,
}

impl Fixture {
    fn new() -> Self {
        let project = tempfile::tempdir().expect("dependency admission project");
        let operator_state = tempfile::tempdir().expect("isolated operator state");
        let initialized = Self::invoke_at(
            project.path(),
            operator_state.path(),
            &["init", "--profile", "balanced", "--out-dir", ".", "--json"],
        );
        assert!(initialized.status.success(), "{initialized:?}");
        write_run_package_manifest(project.path(), &[("lodash", "4.17.21")]);
        fs::write(
            project.path().join("index.js"),
            "console.log('strict-admission-body');\n",
        )
        .unwrap();
        let config = Config::resolve_with_env(
            Some(&project.path().join("franken_node.toml")),
            CliOverrides::default(),
            &|_| None,
        )
        .expect("the same provisioned trust authority the CLI reads")
        .config;
        Self {
            project,
            operator_state,
            config,
        }
    }

    fn invoke_at(project: &Path, operator_state: &Path, args: &[&str]) -> Output {
        let config_home = operator_state.join("config");
        run_cli_in_workspace_with_env(
            project,
            args,
            &[
                ("XDG_STATE_HOME", operator_state.to_str().unwrap()),
                ("XDG_CONFIG_HOME", config_home.to_str().unwrap()),
            ],
        )
    }

    fn cli(&self, args: &[&str]) -> Output {
        Self::invoke_at(self.project.path(), self.operator_state.path(), args)
    }

    fn run(&self, profile: &str) -> Output {
        self.cli(&["run", "--policy", profile, "--json", "index.js"])
    }

    fn config_for(&self, profile: Profile) -> Config {
        let mut config = self.config.clone();
        config.profile = profile;
        config
    }

    fn now() -> u64 {
        chrono::Utc::now().timestamp().max(0) as u64
    }

    fn refresh_frontier(&self) {
        // This is a hermetic trust-store fixture, not a claim that an external
        // revocation service was contacted. Exercise its real authenticated row.
        record_revocation_frontier(
            &registry_snapshot_path(self.project.path()),
            &self.config.trust,
            Self::now(),
            "test: strict dependency admission",
        )
        .expect("persist the authenticated revocation frontier");
    }

    fn scan(&self) {
        let scan = self.cli(&["trust", "scan", ".", "--json"]);
        assert!(scan.status.success(), "{scan:?}");
        self.refresh_frontier();
    }

    fn requirements(&self, retain_card: bool, registry_required: bool) -> RunTrustRequirements {
        let required = if retain_card {
            vec![DEPENDENCY_ID.to_string()]
        } else {
            Vec::new()
        };
        RunTrustRequirements::new(&[], &required, registry_required)
            .unwrap()
            .with_dependency_capture(
                CapturedDependencyTrust::capture(self.project.path())
                    .expect("actual dependency graph"),
            )
            .expect("retain every captured identity")
    }

    fn replace_registry_with_empty(&self) {
        // Preserve the former authority and its WAL together. A replacement
        // empty registry with the legitimate key must not erase a dependency.
        fs::rename(
            self.project.path().join(".franken-node/state"),
            self.project.path().join("retained-trust-state"),
        )
        .unwrap();
        TrustCardRegistry::from_config(&self.config.trust)
            .unwrap()
            .persist_authoritative_state(&registry_snapshot_path(self.project.path()))
            .unwrap();
        self.refresh_frontier();
    }
}

#[test]
fn strict_preflight_refuses_untracked_alias_and_reachable_transitive_with_scan_recovery() {
    let fixture = Fixture::new();
    fs::write(
        fixture.project.path().join("package.json"),
        json!({
            "name": "strict-admission",
            "main": "index.js",
            "dependencies": { "local-alias": "npm:lodash@4.17.21" },
            "devDependencies": { "unused-dev": "1.0.0" },
        })
        .to_string(),
    )
    .unwrap();
    fs::write(
        fixture.project.path().join("package-lock.json"),
        json!({
            "lockfileVersion": 3,
            "packages": {
                "": {
                    "name": "strict-admission",
                    "dependencies": { "local-alias": "npm:lodash@4.17.21" },
                    "devDependencies": { "unused-dev": "1.0.0" },
                },
                "node_modules/local-alias": {
                    "name": "lodash",
                    "version": "4.17.21",
                    "dependencies": { "runtime-child": "1.0.0" },
                },
                "node_modules/runtime-child": { "version": "1.0.0" },
                "node_modules/unused-dev": { "version": "1.0.0", "dev": true },
            },
        })
        .to_string(),
    )
    .unwrap();

    let output = fixture.run("strict");
    assert!(
        !output.status.success(),
        "untracked dependencies must stop preflight"
    );
    let report = parse_json_stdout(&output, "strict untracked dependency refusal");
    assert_eq!(report["verdict"]["status"], "blocked");
    assert_eq!(
        report["receipt"]["rollback_command"],
        "franken-node trust scan ."
    );
    assert_eq!(report["receipt"]["decision"], "denied");
    let violations = report["verdict"]["violations"].as_array().unwrap();
    let mut refused = violations
        .iter()
        .map(|v| {
            assert_eq!(v["kind"], "untracked", "{report}");
            assert!(
                v["detail"]
                    .as_str()
                    .unwrap()
                    .contains("strict policy requires a local trust card")
            );
            v["extension_id"].as_str().unwrap()
        })
        .collect::<Vec<_>>();
    refused.sort_unstable();
    assert_eq!(refused, vec!["npm:lodash", "npm:runtime-child"]);
    let results = report["verdict"]["results"].as_array().unwrap();
    assert_eq!(
        results.len(),
        2,
        "development-only branches are not run dependencies"
    );
    assert!(
        results
            .iter()
            .all(|r| r["status"] == "untracked" && r["trust_card_version"].is_null())
    );
    assert!(report.get("dispatch").is_none());
    assert!(!String::from_utf8_lossy(&output.stdout).contains(GUEST_OUTPUT.trim()));

    let human = fixture.cli(&["run", "--policy", "strict", "index.js"]);
    assert!(!human.status.success());
    assert!(
        String::from_utf8_lossy(&human.stderr).contains("fix_command=franken-node trust scan ."),
        "{human:?}",
    );
}

#[cfg(feature = "engine")]
#[test]
fn strict_scan_recovery_executes_while_balanced_and_legacy_keep_unknown_card_warnings() {
    let fixture = Fixture::new();
    for profile in ["balanced", "legacy-risky"] {
        let output = fixture.run(profile);
        assert!(output.status.success(), "{profile}: {output:?}");
        let report = parse_json_stdout(&output, "less restrictive unknown-card admission");
        assert_eq!(report["preflight"]["verdict"]["status"], "passed");
        assert_eq!(
            report["preflight"]["verdict"]["results"][0]["status"],
            "untracked"
        );
        assert!(
            report["preflight"]["verdict"]["warnings"]
                .as_array()
                .unwrap()
                .iter()
                .any(|w| w.as_str().unwrap().contains(DEPENDENCY_ID))
        );
        assert_eq!(
            report["dispatch"]["captured_output"]["stdout"],
            GUEST_OUTPUT
        );
    }

    assert!(!fixture.run("strict").status.success());
    fixture.scan();
    let output = fixture.run("strict");
    assert!(
        output.status.success(),
        "scan must make the real strict run usable: {output:?}"
    );
    let report = parse_json_stdout(&output, "strict run after local scan");
    assert_eq!(report["preflight"]["verdict"]["status"], "passed");
    let dependency = &report["preflight"]["verdict"]["results"][0];
    assert_eq!(dependency["extension_id"], DEPENDENCY_ID);
    assert!(dependency["trust_card_version"].is_number());
    // A local inventory card does not attest installed source bytes. Preserve
    // that existing distinction instead of making a stronger provenance claim.
    assert_eq!(dependency["status"], "unverified");
    assert_eq!(
        report["dispatch"]["captured_output"]["stdout"],
        GUEST_OUTPUT
    );
}

#[test]
fn strict_execution_admission_requires_cards_even_without_a_preflight_card_requirement() {
    let fixture = Fixture::new();
    for registry_required in [false, true] {
        let requirements = fixture.requirements(false, registry_required);
        let requirements: RunTrustRequirements =
            serde_json::from_slice(&serde_json::to_vec(&requirements).unwrap()).unwrap();
        let error = validate_execution_trust(
            fixture.project.path(),
            &fixture.config_for(Profile::Strict),
            &requirements,
            Fixture::now(),
        )
        .expect_err("the strict profile cannot inherit an unknown-card exception")
        .to_string();
        assert!(error.contains(DEPENDENCY_ID), "{error}");
        assert!(
            error.contains("strict policy requires a local trust card"),
            "{error}"
        );
        assert!(error.contains("franken-node trust scan ."), "{error}");

        for profile in [Profile::Balanced, Profile::LegacyRisky] {
            let warnings = validate_execution_trust(
                fixture.project.path(),
                &fixture.config_for(profile),
                &requirements,
                Fixture::now(),
            )
            .expect("existing non-strict admission remains warning-only");
            assert!(
                warnings
                    .iter()
                    .any(|w| w.contains(DEPENDENCY_ID) && w.contains("untracked"))
            );
        }
    }
    write_run_package_manifest(fixture.project.path(), &[]);
    let dependency_free = fixture.requirements(false, false);
    validate_execution_trust(
        fixture.project.path(),
        &fixture.config_for(Profile::Strict),
        &dependency_free,
        Fixture::now(),
    )
    .expect("a captured dependency-free project has no invented card requirement");
}

#[test]
fn strict_execution_admission_rechecks_trusted_card_loss_and_revocation() {
    for revoke in [false, true] {
        let fixture = Fixture::new();
        fixture.scan();
        let strict = fixture.config_for(Profile::Strict);
        let retained = fixture.requirements(true, true);
        validate_execution_trust(fixture.project.path(), &strict, &retained, Fixture::now())
            .expect("the actual scanned dependency is initially admitted");
        if revoke {
            let output = fixture.cli(&["trust", "revoke", DEPENDENCY_ID, "--json"]);
            assert!(output.status.success(), "{output:?}");
        } else {
            fixture.replace_registry_with_empty();
        }

        let expected = if revoke {
            "revoked since preflight"
        } else {
            "no longer tracked"
        };
        let error =
            validate_execution_trust(fixture.project.path(), &strict, &retained, Fixture::now())
                .expect_err("a completed preflight cannot authorize changed trust state")
                .to_string();
        assert!(
            error.contains(DEPENDENCY_ID) && error.contains(expected),
            "{error}"
        );

        // Name-only library callers also retain dependency identities. Losing
        // the separate required-card set must never make strict admission pass.
        let name_only = RunTrustRequirements::new(&[DEPENDENCY_ID.to_string()], &[], true).unwrap();
        let error =
            validate_execution_trust(fixture.project.path(), &strict, &name_only, Fixture::now())
                .expect_err("strict still requires current trust for name-only callers")
                .to_string();
        assert!(error.contains(DEPENDENCY_ID), "{error}");
        assert!(
            error.contains(if revoke { "revoked" } else { "untracked" }),
            "{error}"
        );

        #[cfg(feature = "engine")]
        {
            use frankenengine_node::config::PreferredRuntime;
            use frankenengine_node::ops::engine_dispatcher::EngineDispatcher;
            let dispatcher = EngineDispatcher::new(None, PreferredRuntime::FrankenEngine)
                .with_preflight_dependency_ids(vec![DEPENDENCY_ID.to_string()])
                .with_preflight_dependency_capture(Some(
                    CapturedDependencyTrust::capture(fixture.project.path()).unwrap(),
                ))
                .with_preflight_registry_requirement(true);
            let error = dispatcher
                .dispatch_run(
                    &fixture.project.path().join("index.js"),
                    &strict,
                    "strict",
                    &[DEPENDENCY_ID.to_string()],
                    Fixture::now(),
                )
                .expect_err("dispatcher must refuse before starting its native worker")
                .to_string();
            assert!(
                error.contains(DEPENDENCY_ID) && error.contains(expected),
                "{error}"
            );
        }

        // Verify the refusal was based on the replacement's authentic state,
        // rather than a corrupt or unreadable registry.
        TrustCardRegistry::load_authoritative_state_from_config(
            &registry_snapshot_path(fixture.project.path()),
            &fixture.config.trust,
            Fixture::now(),
            SnapshotSourceContext::TrustedFile,
        )
        .expect("the changed durable trust state remains authenticated");
    }
}
