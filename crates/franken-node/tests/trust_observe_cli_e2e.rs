//! Real CLI, Ed25519 collector signatures, and the durable trust-card store.
//! Counts below are explicit test measurements, not runtime-collected evidence.

use std::collections::BTreeMap;
use std::path::Path;
use std::process::{Command, Output};
use std::time::{SystemTime, UNIX_EPOCH};

use base64::Engine;
use ed25519_dalek::SigningKey;
use frankenengine_node::config::timeouts::TRUST_CARD_CACHE_TTL_SECS;
use frankenengine_node::supply_chain::behavioral_observation::{
    BehavioralObservation, SignedBehavioralObservation,
};
use frankenengine_node::supply_chain::certification::{EvidenceType, VerifiedEvidenceRef};
use frankenengine_node::supply_chain::trust_card::{
    BehavioralProfile, CapabilityDeclaration, CapabilityRisk, CertificationLevel,
    DependencyTrustStatus, ExtensionIdentity, ProvenanceSummary, PublisherIdentity,
    ReputationTrend, RevocationStatus, RiskAssessment, RiskLevel, TrustCardInput,
    TrustCardRegistry,
};
use frankenengine_node::supply_chain::trust_card_registry_store::{
    TrustCardRegistryStore, registry_snapshot_path,
};
use serde_json::Value;

const EXTENSION: &str = "npm:@acme/auth-guard";
const REGISTRY_KEY: &[u8] = b"franken-node-trust-card-registry-key-v1";

fn run(root: &Path, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_franken-node"))
        .current_dir(root)
        .args(args)
        .output()
        .expect("execute trust CLI")
}

fn json(output: &Output) -> Value {
    serde_json::from_slice(&output.stdout).unwrap_or_else(|error| {
        panic!(
            "JSON report: {error}; stdout={}; stderr={}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr),
        )
    })
}

fn auth_guard_registry(now: u64) -> TrustCardRegistry {
    // Keep the original auth-guard fixture's inputs, using the public registry
    // API so this default-feature CLI test needs no test-support-only export.
    // The collector measurements below are explicitly synthetic test inputs.
    let mut registry = TrustCardRegistry::new(TRUST_CARD_CACHE_TTL_SECS, REGISTRY_KEY);
    registry
        .create(
            TrustCardInput {
                extension: ExtensionIdentity {
                    extension_id: EXTENSION.to_string(),
                    version: "1.4.2".to_string(),
                },
                publisher: PublisherIdentity {
                    publisher_id: "pub-acme".to_string(),
                    display_name: "Acme Security".to_string(),
                },
                certification_level: CertificationLevel::Gold,
                capability_declarations: vec![
                    CapabilityDeclaration {
                        name: "auth.validate-token".to_string(),
                        description: "Validate JWT and attach identity context".to_string(),
                        risk: CapabilityRisk::Medium,
                    },
                    CapabilityDeclaration {
                        name: "auth.revoke-session".to_string(),
                        description: "Invalidate compromised sessions".to_string(),
                        risk: CapabilityRisk::High,
                    },
                ],
                behavioral_profile: BehavioralProfile {
                    network_access: true,
                    filesystem_access: false,
                    subprocess_access: false,
                    profile_summary: "Network-only auth checks with bounded side effects"
                        .to_string(),
                },
                revocation_status: RevocationStatus::Active,
                provenance_summary: ProvenanceSummary {
                    attestation_level: "slsa-l3".to_string(),
                    source_uri: "fixture://trust-card/acme/auth-guard".to_string(),
                    artifact_hashes: vec![format!("sha256:deadbeef{}", "a".repeat(56))],
                    verified_at: "2026-02-20T12:00:00Z".to_string(),
                },
                reputation_score_basis_points: 920,
                reputation_trend: ReputationTrend::Improving,
                active_quarantine: false,
                dependency_trust_summary: vec![DependencyTrustStatus {
                    dependency_id: "npm:jsonwebtoken@9".to_string(),
                    trust_level: "verified".to_string(),
                }],
                last_verified_timestamp: "2026-02-20T12:00:00Z".to_string(),
                user_facing_risk_assessment: RiskAssessment {
                    level: RiskLevel::Low,
                    summary:
                        "Token validation extension with strong provenance and no local disk access"
                            .to_string(),
                },
                evidence_refs: vec![
                    VerifiedEvidenceRef {
                        evidence_id: "ev-fixture-prov-001".to_string(),
                        evidence_type: EvidenceType::ProvenanceChain,
                        verified_at_epoch: 1000,
                        verification_receipt_hash: "a".repeat(64),
                    },
                    VerifiedEvidenceRef {
                        evidence_id: "ev-fixture-rep-001".to_string(),
                        evidence_type: EvidenceType::ReputationSignal,
                        verified_at_epoch: 1000,
                        verification_receipt_hash: "b".repeat(64),
                    },
                ],
            },
            now,
            "trace-fixture-registry",
        )
        .expect("create the original auth-guard fixture through the public registry");
    registry
}

fn workspace() -> (tempfile::TempDir, SigningKey, u64) {
    let root = tempfile::tempdir().expect("trust observation workspace");
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("test clock")
        .as_secs();
    let registry_key = base64::engine::general_purpose::STANDARD.encode(REGISTRY_KEY);
    std::fs::write(
        root.path().join("franken_node.toml"),
        format!(
            "profile = \"balanced\"\n[trust]\nregistry_signing_key = \"{registry_key}\"\n\
             [security]\nauthorized_api_keys = [\"observation-cli-test\"]\n"
        ),
    )
    .expect("explicit fixture signing config");
    let registry = auth_guard_registry(now);
    registry
        .persist_authoritative_state(&registry_snapshot_path(root.path()))
        .expect("seed actual durable store");
    let collector = SigningKey::from_bytes(&[91; 32]);
    std::fs::write(
        root.path().join("collector.pub"),
        hex::encode(collector.verifying_key().to_bytes()),
    )
    .expect("pin test collector");
    (root, collector, now)
}

fn observation(now: u64, sequence: u64, previous: Option<String>) -> BehavioralObservation {
    BehavioralObservation {
        extension_id: EXTENSION.to_string(),
        package_version: "1.4.2".to_string(),
        artifact_hash: format!("sha256:deadbeef{}", "a".repeat(56)),
        workload_id: "auth-validation-fixture-v1".to_string(),
        measurement_scope: "isolated_package".to_string(),
        sequence,
        observed_at_epoch_secs: now - 120 + sequence,
        window_duration_ms: 1_000,
        workload_iterations: 100,
        previous_observation_id: previous,
        observed_capabilities: BTreeMap::from([
            ("fs.read".to_string(), 100),
            ("net.egress".to_string(), 10),
        ]),
        declared_capabilities: BTreeMap::from([
            ("fs.read".to_string(), 100),
            ("net.egress".to_string(), 10),
        ]),
    }
}

fn submit(root: &Path, signed: &SignedBehavioralObservation) -> Output {
    std::fs::write(
        root.join("observation.json"),
        serde_json::to_vec(signed).expect("signed observation JSON"),
    )
    .expect("write signed observation");
    run(
        root,
        &[
            "trust",
            "observe",
            "observation.json",
            "--collector-key",
            "collector.pub",
            "--json",
        ],
    )
}

fn durable_state(root: &Path) -> Option<(String, Option<String>)> {
    TrustCardRegistryStore::open(&registry_snapshot_path(root))
        .expect("open registry store")
        .load_state()
        .expect("read registry state")
}

#[test]
fn trust_observe_commits_verified_evidence_and_retries_without_card_churn() {
    let (root, collector, now) = workspace();
    let signed = SignedBehavioralObservation::sign(observation(now, 0, None), &collector)
        .expect("sign collector measurement");
    let output = submit(root.path(), &signed);
    let accepted = json(&output);
    assert!(output.status.success(), "{accepted}");
    assert_eq!(accepted["status"], "accepted");
    assert_eq!(accepted["extension_id"], EXTENSION);
    assert_eq!(accepted["package_version"], "1.4.2");
    assert_eq!(accepted["sample_count"], 1);
    assert_eq!(accepted["observation_id"], signed.observation_id().unwrap());

    let committed = durable_state(root.path());
    let output = submit(root.path(), &signed);
    let duplicate = json(&output);
    assert!(output.status.success(), "{duplicate}");
    assert_eq!(duplicate["status"], "duplicate");
    assert_eq!(duplicate["card_hash"], accepted["card_hash"]);
    assert_eq!(duplicate["card_version"], accepted["card_version"]);
    assert_eq!(durable_state(root.path()), committed);

    let output = run(root.path(), &["trust", "card", EXTENSION, "--json"]);
    let card = json(&output);
    assert!(output.status.success(), "{card}");
    assert_eq!(card["card_hash"], accepted["card_hash"]);
    assert!(
        card["derivation_evidence"].to_string().contains(
            accepted["evidence_ref"]
                .as_str()
                .expect("evidence identity")
        ),
        "admitted collector evidence must reach the signed trust card: {card}"
    );
}

#[test]
fn trust_observe_rejects_untrusted_signer_and_broken_chain_without_mutation() {
    let (root, collector, now) = workspace();
    let before = durable_state(root.path());
    let untrusted = SigningKey::from_bytes(&[92; 32]);
    let signed = SignedBehavioralObservation::sign(observation(now, 0, None), &untrusted)
        .expect("sign with another collector");
    let output = submit(root.path(), &signed);
    let error = json(&output);
    assert!(!output.status.success());
    assert_eq!(error["schema_version"], "franken-node/trust-error-cli/v1");
    assert_eq!(error["command"], "trust.observe");
    assert_eq!(error["ok"], false);
    assert_eq!(durable_state(root.path()), before);

    let signed = SignedBehavioralObservation::sign(observation(now, 1, None), &collector)
        .expect("sign measurement starting after the required first sequence");
    let output = submit(root.path(), &signed);
    assert!(!output.status.success(), "{}", json(&output));
    assert_eq!(durable_state(root.path()), before);
}

#[test]
fn trust_observe_routes_real_detector_findings_into_persistent_card_risk() {
    let (root, collector, now) = workspace();
    let mut previous = None;
    let mut last = Value::Null;
    for sequence in 0..8 {
        let mut sample = observation(now, sequence, previous);
        if sequence >= 4 {
            sample
                .observed_capabilities
                .insert("net.egress".to_string(), 1_000);
        }
        let signed = SignedBehavioralObservation::sign(sample, &collector)
            .expect("sign ordered test measurements");
        previous = Some(signed.observation_id().unwrap());
        let output = submit(root.path(), &signed);
        last = json(&output);
        assert!(output.status.success(), "sequence {sequence}: {last}");
    }
    assert_eq!(last["sample_count"], 8);
    assert!(
        !last["hints"]
            .as_array()
            .expect("detector findings")
            .is_empty(),
        "{last}"
    );
    let output = run(root.path(), &["trust", "card", EXTENSION, "--json"]);
    let card = json(&output);
    assert!(output.status.success(), "{card}");
    assert!(
        !card["camouflage_hints"]
            .as_array()
            .expect("persisted hints")
            .is_empty()
    );
    assert_eq!(card["card_hash"], last["card_hash"]);
    assert_ne!(card["user_facing_risk_assessment"]["level"], "low");
    assert_eq!(
        card["active_quarantine"], false,
        "a heuristic must not silently quarantine"
    );
}

#[test]
fn package_effect_attribution_does_not_mistake_targets_or_imports_for_callers() {
    // Both executions read the provider's file, but in the second execution a
    // different package invokes a builtin function delegated by the provider.
    // Neither target ownership nor the direct builtin importer proves caller
    // identity, and the real caller must remain in the candidate inventory.
    for delegated in [false, true] {
        let dir = tempfile::tempdir().expect("caller attribution workspace");
        let root = dir.path();
        std::fs::write(
            root.join("package.json"),
            r#"{"name":"caller-app","version":"1.0.0","type":"commonjs"}"#,
        )
        .unwrap();
        for (name, code) in [
            (
                "provider",
                "const fs = require('fs');\nexports.read = fs.readFileSync;\n",
            ),
            (
                "relay",
                "exports.call = (read, path) => read(path, 'utf8');\n",
            ),
        ] {
            let package = root.join("node_modules").join(name);
            std::fs::create_dir_all(&package).unwrap();
            std::fs::write(
                package.join("package.json"),
                serde_json::to_vec(&serde_json::json!({
                    "name": name,
                    "version": "1.0.0",
                    "main": "index.js"
                }))
                .unwrap(),
            )
            .unwrap();
            std::fs::write(package.join("index.js"), code).unwrap();
        }
        std::fs::write(
            root.join("node_modules/provider/data.txt"),
            "delegated-value",
        )
        .unwrap();
        std::fs::write(
            root.join("app.js"),
            if delegated {
                "const read = require('provider').read;\nconst relay = require('relay');\nconsole.log(relay.call(read, 'node_modules/provider/data.txt'));\n"
            } else {
                "const fs = require('fs');\nrequire('provider');\nconsole.log(fs.readFileSync('node_modules/provider/data.txt', 'utf8'));\n"
            },
        )
        .unwrap();
        let init = run(
            root,
            &["init", "--profile", "balanced", "--out-dir", ".", "--json"],
        );
        assert!(
            init.status.success(),
            "init: {}",
            String::from_utf8_lossy(&init.stderr)
        );
        let output = run(
            root,
            &[
                "run",
                "app.js",
                "--policy",
                "balanced",
                "--frozen-modules",
                "--json",
            ],
        );
        let report = json(&output);
        assert!(output.status.success(), "delegated={delegated}: {report}");
        assert_eq!(
            report["dispatch"]["captured_output"]["stdout"],
            "delegated-value\n"
        );
        let attribution = &report["receipt"]["package_attribution"];
        assert_eq!(
            attribution["schema_version"],
            "franken-node/package-attribution-report/v2"
        );
        let effects = attribution["effects"].as_array().unwrap();
        assert_eq!(effects.len(), 1, "{attribution}");
        let effect = &effects[0];
        assert_eq!(effect["effect_kind"], "fs_read");
        assert_eq!(effect["outcome"], "allowed");
        assert_eq!(effect["attribution_basis"], "candidate_loaded_packages");
        assert!(effect["attributed_package"].is_null(), "{effect}");
        assert_eq!(effect["target_package_hint"], "npm:provider@1.0.0");
        let candidates = effect["candidate_packages"].as_array().unwrap();
        assert!(candidates.contains(&serde_json::json!("app:caller-app@1.0.0")));
        assert!(candidates.contains(&serde_json::json!("npm:provider@1.0.0")));
        let importers = effect["capability_importing_packages"].as_array().unwrap();
        if delegated {
            assert!(candidates.contains(&serde_json::json!("npm:relay@1.0.0")));
            assert_eq!(importers, &[serde_json::json!("npm:provider@1.0.0")]);
        } else {
            assert!(importers.contains(&serde_json::json!("app:caller-app@1.0.0")));
            assert!(importers.contains(&serde_json::json!("npm:provider@1.0.0")));
        }
        for package in attribution["packages"].as_array().unwrap() {
            assert!(package["exact_effect_seqs"].as_array().unwrap().is_empty());
            assert_eq!(package["allowed_effects"], 0);
            assert_eq!(package["denied_effects"], 0);
            assert_eq!(package["failed_effects"], 0);
            if candidates.contains(&package["package_id"]) {
                assert!(
                    package["candidate_effect_seqs"]
                        .as_array()
                        .unwrap()
                        .contains(&effect["seq"]),
                    "candidate must retain the real effect sequence: {package}"
                );
            }
        }
    }
}

#[test]
fn complete_readme_trust_scenario_and_multi_dependency_effect_attribution() {
    let dir = tempfile::tempdir().expect("readme scenario workspace");
    let root = dir.path();

    let hash_b64 = |seed: &[u8]| -> (String, String) {
        use sha2::{Digest, Sha256};
        let digest = Sha256::digest(seed);
        (
            format!(
                "sha256-{}",
                base64::engine::general_purpose::STANDARD.encode(digest)
            ),
            format!("sha256:{}", hex::encode(digest)),
        )
    };
    let (cfg_sri, _) = hash_b64(b"config-loader@1.0.0");
    let (exp_sri, _) = hash_b64(b"expresss@4.0.0");
    let (tel_sri, tel_sha256) = hash_b64(b"telemetry-drift@0.0.5");

    std::fs::write(
        root.join("package.json"),
        serde_json::to_vec_pretty(&serde_json::json!({
            "name": "readme-scenario-app",
            "version": "1.0.0",
            "dependencies": {
                "config-loader": "1.0.0",
                "expresss": "4.0.0",
                "telemetry-drift": "0.0.5"
            }
        }))
        .unwrap(),
    )
    .unwrap();
    std::fs::write(
        root.join("package-lock.json"),
        serde_json::to_vec_pretty(&serde_json::json!({
            "name": "readme-scenario-app",
            "version": "1.0.0",
            "lockfileVersion": 3,
            "requires": true,
            "packages": {
                "": {
                    "name": "readme-scenario-app",
                    "version": "1.0.0",
                    "dependencies": {
                        "config-loader": "1.0.0",
                        "expresss": "4.0.0",
                        "telemetry-drift": "0.0.5"
                    }
                },
                "node_modules/config-loader": {
                    "version": "1.0.0",
                    "integrity": cfg_sri
                },
                "node_modules/expresss": {
                    "version": "4.0.0",
                    "integrity": exp_sri
                },
                "node_modules/telemetry-drift": {
                    "version": "0.0.5",
                    "integrity": tel_sri
                }
            }
        }))
        .unwrap(),
    )
    .unwrap();

    std::fs::write(root.join("app-config.json"), br#"{"env":"prod"}"#).unwrap();

    let write_pkg = |name: &str, version: &str, code: &str| {
        let pkg_dir = root.join("node_modules").join(name);
        std::fs::create_dir_all(&pkg_dir).unwrap();
        std::fs::write(
            pkg_dir.join("package.json"),
            serde_json::to_vec_pretty(&serde_json::json!({
                "name": name,
                "version": version,
                "main": "index.js"
            }))
            .unwrap(),
        )
        .unwrap();
        std::fs::write(pkg_dir.join("index.js"), code).unwrap();
    };
    write_pkg(
        "config-loader",
        "1.0.0",
        "const fs = require('fs');\nexports.loadConfig = () => JSON.parse(fs.readFileSync('app-config.json', 'utf8'));\n",
    );
    write_pkg(
        "expresss",
        "4.0.0",
        "exports.banner = (env) => 'route:' + env;\n",
    );
    write_pkg(
        "telemetry-drift",
        "0.0.5",
        "const http = require('http');\nexports.ping = () => {\n  const req = http.get('http://169.254.169.254/latest/meta-data/', () => {});\n  req.on('error', () => console.log('telemetry-egress-refused'));\n};\n",
    );
    std::fs::write(
        root.join("app.js"),
        "const cfg = require('config-loader').loadConfig();\nconst banner = require('expresss').banner(cfg.env);\nrequire('telemetry-drift').ping();\nconsole.log(banner);\n",
    )
    .unwrap();

    let offline_dir = root.join("offline-registry");
    std::fs::create_dir_all(&offline_dir).unwrap();
    let fourteen_days_ago = (chrono::Utc::now() - chrono::Duration::days(14)).to_rfc3339();
    let two_years_ago = (chrono::Utc::now() - chrono::Duration::days(730)).to_rfc3339();

    std::fs::write(
        offline_dir.join("config-loader.json"),
        serde_json::to_vec_pretty(&serde_json::json!({
            "_fixture": "Hermetic offline npm packument: fresh package (14d old) + sole maintainer.",
            "_hermetic_dependent_count": 3,
            "name": "config-loader",
            "maintainers": [{"name": "newpub", "email": "newpub@example.test"}],
            "time": {
                "created": fourteen_days_ago,
                "1.0.0": fourteen_days_ago
            },
            "versions": {
                "1.0.0": {
                    "dist": {"integrity": cfg_sri}
                }
            }
        }))
        .unwrap(),
    )
    .unwrap();
    std::fs::write(
        offline_dir.join("expresss.json"),
        serde_json::to_vec_pretty(&serde_json::json!({
            "_fixture": "Hermetic offline npm packument: distance-1 typosquat of express.",
            "_hermetic_dependent_count": 0,
            "name": "expresss",
            "maintainers": [{"name": "squatter", "email": "squatter@example.test"}],
            "time": {
                "created": fourteen_days_ago,
                "4.0.0": fourteen_days_ago
            },
            "versions": {
                "4.0.0": {
                    "dist": {"integrity": exp_sri}
                }
            }
        }))
        .unwrap(),
    )
    .unwrap();
    std::fs::write(
        offline_dir.join("telemetry-drift.json"),
        serde_json::to_vec_pretty(&serde_json::json!({
            "_fixture": "Hermetic offline npm packument: 6-release window introducing postinstall + bin drift.",
            "_hermetic_dependent_count": 42,
            "name": "telemetry-drift",
            "maintainers": [{"name": "driftmaint", "email": "drift@example.test"}],
            "time": {
                "created": two_years_ago,
                "0.0.0": "2024-01-01T00:00:00.000Z",
                "0.0.1": "2024-02-01T00:00:00.000Z",
                "0.0.2": "2024-03-01T00:00:00.000Z",
                "0.0.3": "2024-04-01T00:00:00.000Z",
                "0.0.4": "2024-05-01T00:00:00.000Z",
                "0.0.5": "2024-06-01T00:00:00.000Z"
            },
            "versions": {
                "0.0.0": {},
                "0.0.1": {"dependencies": {"helper-a": "1.0.0"}},
                "0.0.2": {"dependencies": {"helper-a": "1.0.1"}},
                "0.0.3": {"scripts": {"postinstall": "node install.js"}},
                "0.0.4": {"scripts": {"postinstall": "node install.js"}, "bin": {"td": "bin/td.js"}},
                "0.0.5": {
                    "scripts": {"postinstall": "node install.js"},
                    "bin": {"td": "bin/td.js"},
                    "dist": {"integrity": tel_sri}
                }
            }
        }))
        .unwrap(),
    )
    .unwrap();

    // 1. Initialize workspace under balanced profile
    let init_out = run(
        root,
        &["init", "--profile", "balanced", "--out-dir", ".", "--json"],
    );
    assert!(
        init_out.status.success(),
        "init failed: {}",
        String::from_utf8_lossy(&init_out.stderr)
    );

    // 2. Run hermetic deep scan and verify typosquat + fresh-package + camouflage drift signals
    let scan_out = run(
        root,
        &[
            "trust",
            "scan",
            ".",
            "--deep",
            "--offline-registry-dir",
            "offline-registry",
            "--json",
        ],
    );
    let scan_json = json(&scan_out);
    assert!(scan_out.status.success(), "{scan_json}");
    assert_eq!(scan_json["metadata_source"], "hermetic_fixture");

    let cfg_card = json(&run(
        root,
        &["trust", "card", "npm:config-loader", "--json"],
    ));
    assert_eq!(
        cfg_card["user_facing_risk_assessment"]["level"], "medium",
        "{cfg_card}"
    );
    assert!(
        cfg_card["user_facing_risk_assessment"]["summary"]
            .as_str()
            .unwrap_or_default()
            .contains("new package: first published"),
        "{cfg_card}"
    );

    let exp_card = json(&run(root, &["trust", "card", "npm:expresss", "--json"]));
    assert_eq!(
        exp_card["user_facing_risk_assessment"]["level"], "high",
        "{exp_card}"
    );
    assert!(
        exp_card["user_facing_risk_assessment"]["summary"]
            .as_str()
            .unwrap_or_default()
            .contains("typosquat"),
        "{exp_card}"
    );

    let tel_card = json(&run(
        root,
        &["trust", "card", "npm:telemetry-drift", "--json"],
    ));
    assert_eq!(
        tel_card["user_facing_risk_assessment"]["level"], "critical",
        "{tel_card}"
    );
    assert!(
        !tel_card["camouflage_hints"]
            .as_array()
            .expect("camouflage_hints")
            .is_empty(),
        "6-release install-hook drift must land camouflage_hints on card: {tel_card}"
    );

    // 3. Submit 4 chained collector-attested behavioral observations on telemetry-drift
    //    demonstrating monotonic capability creep (`GradualCreep`) on real behavioral telemetry
    let collector = SigningKey::from_bytes(&[73; 32]);
    std::fs::write(
        root.join("collector.pub"),
        hex::encode(collector.verifying_key().to_bytes()),
    )
    .unwrap();
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let mut prev_obs_id: Option<String> = None;
    let mut final_obs_json = serde_json::Value::Null;
    for seq in 0_u64..4 {
        let obs = SignedBehavioralObservation::sign(
            BehavioralObservation {
                extension_id: "npm:telemetry-drift".to_string(),
                package_version: "0.0.5".to_string(),
                artifact_hash: tel_sha256.clone(),
                workload_id: "readme-scenario-collector-v1".to_string(),
                measurement_scope: "isolated_package".to_string(),
                sequence: seq,
                observed_at_epoch_secs: now.saturating_sub(60 - seq * 10),
                window_duration_ms: 1_000,
                workload_iterations: 1,
                previous_observation_id: prev_obs_id.take(),
                observed_capabilities: BTreeMap::from([(
                    "network.requests".to_string(),
                    100 + seq * 5,
                )]),
                declared_capabilities: BTreeMap::from([("network.requests".to_string(), 100)]),
            },
            &collector,
        )
        .unwrap();
        prev_obs_id = Some(obs.observation_id().unwrap());
        let obs_out = submit(root, &obs);
        let obs_json = json(&obs_out);
        assert!(obs_out.status.success(), "{obs_json}");
        assert_eq!(obs_json["status"], "accepted");
        final_obs_json = obs_json;
    }
    assert!(
        final_obs_json["hints"]
            .as_array()
            .expect("hints")
            .iter()
            .any(|hint| hint["kind"].as_str() == Some("gradual_creep")),
        "monotonic behavioral drift must trigger gradual_creep: {final_obs_json}"
    );

    // 4a. Execute multi-dependency app under default balanced (non-frozen) and verify
    //     package candidates and import hints without requiring --frozen-modules.
    let plain_out = run(root, &["run", "app.js", "--policy", "balanced", "--json"]);
    let plain_json = json(&plain_out);
    assert!(
        plain_out.status.success(),
        "plain balanced run failed: stdout={plain_json} stderr={}",
        String::from_utf8_lossy(&plain_out.stderr)
    );
    let plain_effects = plain_json["receipt"]["package_attribution"]["effects"]
        .as_array()
        .expect("plain run effect candidates");
    assert_eq!(plain_effects.len(), 2);
    for (effect, importer) in plain_effects
        .iter()
        .zip(["npm:config-loader@1.0.0", "npm:telemetry-drift@0.0.5"])
    {
        assert!(effect["attributed_package"].is_null(), "{effect}");
        assert_eq!(effect["attribution_basis"], "candidate_loaded_packages");
        assert!(
            effect["capability_importing_packages"]
                .as_array()
                .unwrap()
                .contains(&serde_json::json!(importer)),
            "{effect}"
        );
    }

    // 4b. Execute multi-dependency app under balanced with --frozen-modules --capture-replay
    //     and verify candidate attribution plus hermetic replay capture.
    let run_out = run(
        root,
        &[
            "run",
            "app.js",
            "--policy",
            "balanced",
            "--frozen-modules",
            "--capture-replay",
            "--json",
        ],
    );
    let run_json = json(&run_out);
    assert!(
        run_out.status.success(),
        "balanced run failed: stdout={run_json} stderr={}",
        String::from_utf8_lossy(&run_out.stderr)
    );
    assert_eq!(
        run_json["dispatch"]["captured_output"]["stdout"],
        "route:prod\ntelemetry-egress-refused\n"
    );
    let attribution = &run_json["receipt"]["package_attribution"];
    assert_eq!(
        attribution["schema_version"],
        "franken-node/package-attribution-report/v2"
    );
    assert_eq!(
        attribution["root_package_id"],
        "app:readme-scenario-app@1.0.0"
    );
    assert_eq!(
        attribution,
        &run_json["dispatch"]["engine_decision"]["package_attribution"]
    );
    let effects = attribution["effects"]
        .as_array()
        .expect("attributed effects");
    assert_eq!(effects.len(), 2, "{attribution}");
    assert_eq!(effects[0]["effect_kind"], "fs_read");
    assert_eq!(effects[0]["outcome"], "allowed");
    assert_eq!(effects[0]["attribution_basis"], "candidate_loaded_packages");
    assert!(effects[0]["attributed_package"].is_null());
    assert_eq!(
        effects[0]["capability_importing_packages"],
        serde_json::json!(["npm:config-loader@1.0.0"])
    );
    assert_eq!(effects[1]["effect_kind"], "http_request");
    assert_eq!(effects[1]["outcome"], "denied");
    assert_eq!(effects[1]["attribution_basis"], "candidate_loaded_packages");
    assert!(effects[1]["attributed_package"].is_null());
    assert_eq!(
        effects[1]["capability_importing_packages"],
        serde_json::json!(["npm:telemetry-drift@0.0.5"])
    );

    let packages = attribution["packages"]
        .as_array()
        .expect("attributed packages");
    let pkg_for = |id: &str| {
        packages
            .iter()
            .find(|entry| entry["package_id"].as_str() == Some(id))
            .unwrap_or_else(|| panic!("missing package {id} in {packages:?}"))
    };
    assert_eq!(pkg_for("npm:config-loader@1.0.0")["allowed_effects"], 0);
    assert_eq!(pkg_for("npm:config-loader@1.0.0")["denied_effects"], 0);
    assert_eq!(pkg_for("npm:telemetry-drift@0.0.5")["allowed_effects"], 0);
    assert_eq!(pkg_for("npm:telemetry-drift@0.0.5")["denied_effects"], 0);
    assert_eq!(pkg_for("npm:expresss@4.0.0")["allowed_effects"], 0);
    assert_eq!(pkg_for("npm:expresss@4.0.0")["denied_effects"], 0);
    for effect in effects {
        for candidate in effect["candidate_packages"].as_array().unwrap() {
            assert!(
                pkg_for(candidate.as_str().unwrap())["candidate_effect_seqs"]
                    .as_array()
                    .unwrap()
                    .contains(&effect["seq"])
            );
        }
    }

    // 5. Strict profile refuses high-risk dependencies at preflight before guest execution
    let strict_out = run(root, &["run", "app.js", "--policy", "strict", "--json"]);
    assert!(
        !strict_out.status.success(),
        "strict must refuse high-risk card"
    );
    let strict_json = json(&strict_out);
    assert_eq!(strict_json["verdict"]["status"], "blocked", "{strict_json}");
    assert_eq!(
        strict_json["receipt"]["decision"], "denied",
        "{strict_json}"
    );

    // 6. Revoke telemetry-drift and verify even balanced refuses at preflight
    let revoke_out = run(root, &["trust", "revoke", "npm:telemetry-drift", "--json"]);
    assert!(
        revoke_out.status.success(),
        "{}",
        String::from_utf8_lossy(&revoke_out.stderr)
    );
    let revoked_run = run(root, &["run", "app.js", "--policy", "balanced", "--json"]);
    assert!(
        !revoked_run.status.success(),
        "revoked package must block balanced run"
    );

    // 7. Verify durable signed hash-chained evidence ledger across all decisions
    let ledger_out = run(
        root,
        &[
            "verify",
            "transparency-log",
            ".franken-node/state/evidence-ledger.db",
            "--public-key",
            ".franken-node/keys/receipt-signing.pub",
            "--json",
        ],
    );
    let ledger_json = json(&ledger_out);
    assert!(ledger_out.status.success(), "{ledger_json}");
    assert_eq!(ledger_json["status"], "valid");
    assert_eq!(ledger_json["signatures_verified"], true);
    assert!(
        ledger_json["total_entries"].as_u64().unwrap_or(0) >= 4,
        "expected >=4 chained ledger entries (run + strict denial + revoke + balanced denial): {ledger_json}"
    );

    // 8. Export incident bundle from recorded run, execute native replay, and score strict counterfactual
    let receipt_id = run_json["receipt"]["receipt_id"]
        .as_str()
        .expect("receipt_id");
    let cap_out = run(
        root,
        &["incident", "capture", "--from-run", receipt_id, "--json"],
    );
    let cap_json = json(&cap_out);
    assert!(cap_out.status.success(), "{cap_json}");
    let incident_id = cap_json["incident_id"].as_str().expect("incident_id");
    let bundle_out = run(
        root,
        &[
            "incident",
            "bundle",
            "--id",
            incident_id,
            "--verify",
            "--json",
        ],
    );
    assert!(
        bundle_out.status.success(),
        "{}",
        String::from_utf8_lossy(&bundle_out.stderr)
    );
    let bundle_name = format!("{incident_id}.fnbundle");

    let replay_out = run(
        root,
        &[
            "incident",
            "replay",
            "--bundle",
            &bundle_name,
            "--execute",
            "--trusted-public-key",
            ".franken-node/keys/receipt-signing.pub",
            "--json",
        ],
    );
    let replay_json = json(&replay_out);
    assert!(replay_out.status.success(), "{replay_json}");
    assert_eq!(replay_json["replay_result"]["matched"], true);
    assert_eq!(replay_json["execution_result"]["matched"], true);
    assert_eq!(
        replay_json["execution_result"]["verification_scope"],
        "guest_execution"
    );

    let cf_out = run(
        root,
        &[
            "incident",
            "counterfactual",
            "--bundle",
            &bundle_name,
            "--trusted-public-key",
            ".franken-node/keys/receipt-signing.pub",
            "--policy",
            "strict",
        ],
    );
    assert!(
        cf_out.status.success(),
        "counterfactual failed: {}",
        String::from_utf8_lossy(&cf_out.stderr)
    );
}
