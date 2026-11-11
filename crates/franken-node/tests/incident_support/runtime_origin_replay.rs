//! Authenticate an actual native incident's exporter, original run, and
//! product-root-certified engine ledger before any offline guest replay.

use super::{config_only_workspace, run_cli_in_workspace};
use serde_json::Value;

#[test]
fn policy_equivalence_requires_execution_and_both_origin_anchors_before_reading_inputs() {
    let workspace = config_only_workspace();
    for extra in [
        &[][..],
        &["--execute"][..],
        &["--execute", "--trusted-run-public-key", "absent-run.pub"][..],
        &["--execute", "--trusted-runtime-public-key", "absent-root.pub"][..],
        &[
            "--trusted-run-public-key",
            "absent-run.pub",
            "--trusted-runtime-public-key",
            "absent-root.pub",
        ][..],
    ] {
        let mut args = vec![
            "incident",
            "replay",
            "--bundle",
            "absent.fnbundle",
            "--require-policy-equivalence",
            "--json",
        ];
        args.extend_from_slice(extra);
        let output = run_cli_in_workspace(workspace.path(), &args);
        assert!(!output.status.success(), "{output:?}");
        let report: Value = serde_json::from_slice(&output.stdout)
            .expect("one structured policy-scope dependency error");
        assert_eq!(report["ok"], false);
        assert_eq!(report["command"], "incident.replay");
        assert!(
            report["error"].as_str().unwrap().contains(
                "--require-policy-equivalence requires --execute, --trusted-run-public-key and --trusted-runtime-public-key"
            ),
            "{report}"
        );
        assert!(report.get("execution_result").is_none());
    }
}

#[test]
fn runtime_origin_replay_requires_an_explicit_run_anchor_before_reading_inputs() {
    let workspace = config_only_workspace();
    let output = run_cli_in_workspace(
        workspace.path(),
        &[
            "incident",
            "replay",
            "--bundle",
            "absent.fnbundle",
            "--trusted-runtime-public-key",
            "absent-root.pub",
            "--execute",
            "--json",
        ],
    );
    assert!(!output.status.success());
    let report: Value =
        serde_json::from_slice(&output.stdout).expect("structured dependency error");
    assert_eq!(report["ok"], false);
    assert!(
        report["error"]
            .as_str()
            .unwrap()
            .contains("--trusted-runtime-public-key requires --trusted-run-public-key"),
        "{report}"
    );
    assert!(report.get("execution_result").is_none());
}

#[cfg(all(feature = "engine", target_os = "linux"))]
mod native {
    use super::super::{
        capture_native_run_bundle_with, native_replay_workspace_with_arguments_in_state_home,
        run_cli_in_workspace_with_state_home,
    };
    use super::*;
    use ed25519_dalek::{SigningKey, VerifyingKey};
    use frankenengine_node::tools::replay_bundle::{
        IncidentEvidencePackage, ReplayBundleSigningMaterial, generate_replay_bundle_from_evidence,
        read_verified_incident_evidence_package, sign_incident_evidence_package,
        sign_replay_bundle, sign_run_ledger_record, to_canonical_json,
    };
    use frankenengine_verifier_sdk::incident_bundle::{
        IncidentBundleError, verify_incident_bundle_with_run_key,
        verify_incident_bundle_with_runtime_keys,
    };
    use serde_json::json;
    use std::fs;
    use std::path::PathBuf;
    use std::process::Output;

    const PROGRAM: &str = "const fs = require('fs'); const input = fs.readFileSync('input.txt', 'utf8'); fs.writeFileSync('output.txt', input); console.log(input);";
    const ROOT_KEY_PATH: &str = "franken-node/runtime-evidence/keys/product-root.key";

    struct Fixture {
        producer: tempfile::TempDir,
        producer_state: tempfile::TempDir,
        operator: tempfile::TempDir,
        operator_state: tempfile::TempDir,
        archive: tempfile::TempDir,
        source: IncidentEvidencePackage,
        receipt_id: String,
        bundle_name: String,
        run_signer: SigningKey,
        exporter: SigningKey,
        runtime_root: VerifyingKey,
    }

    impl Fixture {
        fn new(guest_exception: bool) -> Self {
            Self::new_with_frozen_modules(guest_exception, false)
        }

        fn new_with_frozen_modules(guest_exception: bool, frozen_modules: bool) -> Self {
            let producer_state = tempfile::tempdir().expect("independent producer authority");
            let source_text = format!(
                "{PROGRAM} {}",
                if guest_exception {
                    "throw 'captured-stop';"
                } else {
                    ""
                },
            );
            let (producer, run) = if frozen_modules {
                let producer = tempfile::tempdir().expect("frozen native producer");
                fs::write(
                    producer.path().join("app.js"),
                    format!("console.log(require('./replay-dependency.cjs')); {source_text}"),
                )
                .unwrap();
                fs::write(
                    producer.path().join("replay-dependency.cjs"),
                    "module.exports = 'captured-dependency';",
                )
                .unwrap();
                fs::write(producer.path().join("input.txt"), "ORIGINAL").unwrap();
                let initialized = run_cli_in_workspace_with_state_home(
                    producer.path(),
                    &["init", "--profile", "legacy-risky", "--out-dir", ".", "--json"],
                    Some(producer_state.path()),
                );
                assert!(initialized.status.success(), "{initialized:?}");
                let recorded = run_cli_in_workspace_with_state_home(
                    producer.path(),
                    &["run", "app.js", "--frozen-modules", "--capture-replay", "--json"],
                    Some(producer_state.path()),
                );
                assert_eq!(recorded.status.success(), !guest_exception, "{recorded:?}");
                let run: Value = serde_json::from_slice(&recorded.stdout).unwrap();
                (producer, run)
            } else {
                native_replay_workspace_with_arguments_in_state_home(
                    &source_text,
                    "legacy-risky",
                    !guest_exception,
                    false,
                    &[],
                    Some(producer_state.path()),
                )
            };
            let receipt_id = run["receipt"]["receipt_id"].as_str().unwrap().to_string();
            let (bundle_name, captured) =
                capture_native_run_bundle_with(producer.path(), &receipt_id, |args| {
                    run_cli_in_workspace_with_state_home(
                        producer.path(),
                        args,
                        Some(producer_state.path()),
                    )
                });

            // Retain the root independently from the producer's protected
            // provisioning directory, never from the bundle under review.
            let root_seed: [u8; 32] = fs::read(producer_state.path().join(ROOT_KEY_PATH))
                .expect("producer-owned runtime root")
                .try_into()
                .expect("runtime root seed width");
            let runtime_root = SigningKey::from_bytes(&root_seed).verifying_key();
            let mut run_seed = [0_u8; 32];
            hex::decode_to_slice(
                fs::read_to_string(
                    producer
                        .path()
                        .join(".franken-node/keys/receipt-signing.key"),
                )
                .unwrap()
                .trim(),
                &mut run_seed,
            )
            .unwrap();
            let run_signer = SigningKey::from_bytes(&run_seed);
            let exporter = SigningKey::from_bytes(&[0x74; 32]);
            assert_ne!(runtime_root, run_signer.verifying_key());
            assert_ne!(runtime_root, exporter.verifying_key());
            assert_ne!(run_signer.verifying_key(), exporter.verifying_key());

            fs::write(
                producer.path().join("exporter.key"),
                hex::encode(exporter.to_bytes()),
            )
            .unwrap();
            let exported = run_cli_in_workspace_with_state_home(
                producer.path(),
                &[
                    "incident",
                    "bundle",
                    "--id",
                    captured["incident_id"].as_str().unwrap(),
                    "--receipt-signing-key",
                    "exporter.key",
                    "--verify",
                    "--json",
                ],
                Some(producer_state.path()),
            );
            assert!(exported.status.success(), "{exported:?}");
            let bytes = fs::read(producer.path().join(&bundle_name)).unwrap();
            let verified = verify_incident_bundle_with_runtime_keys(
                &bytes,
                &exporter.verifying_key(),
                &run_signer.verifying_key(),
                &runtime_root,
            )
            .expect("standalone SDK authenticates the actual product export");
            assert_eq!(verified.run_origin.receipt_id, receipt_id);
            assert_eq!(
                verified.runtime_origin.product_root_key_id,
                format!("ed25519:{}", hex::encode(runtime_root.as_bytes()))
            );

            let source_path = producer.path().join(format!(
                ".franken-node/state/incidents/{}/evidence.v1.json",
                captured["incident_id"].as_str().unwrap(),
            ));
            let source = read_verified_incident_evidence_package(
                &source_path,
                None,
                &run_signer.verifying_key(),
            )
            .expect("authenticated product evidence source");
            assert_eq!(
                source.initial_state_snapshot["runtime_evidence_identity_capture"],
                run["dispatch"]["runtime_evidence_identity_capture"],
                "export must carry the same public capture authenticated with the original ledger",
            );

            let operator = config_only_workspace();
            let operator_state = tempfile::tempdir().expect("independent verifier state");
            let archive = tempfile::tempdir().expect("unavailable original inputs");
            fs::write(operator.path().join(&bundle_name), bytes).unwrap();
            for (name, key) in [
                ("exporter.pub", exporter.verifying_key()),
                ("run.pub", run_signer.verifying_key()),
                ("runtime.pub", runtime_root),
                (
                    "foreign.pub",
                    SigningKey::from_bytes(&[0x75; 32]).verifying_key(),
                ),
            ] {
                fs::write(operator.path().join(name), hex::encode(key.as_bytes())).unwrap();
            }
            Self {
                producer,
                producer_state,
                operator,
                operator_state,
                archive,
                source,
                receipt_id,
                bundle_name,
                run_signer,
                exporter,
                runtime_root,
            }
        }

        fn source_path(&self) -> PathBuf {
            self.producer.path().join(format!(
                ".franken-node/state/incidents/{}/evidence.v1.json",
                self.source.incident_id,
            ))
        }

        fn capture_again(&self) -> Output {
            run_cli_in_workspace_with_state_home(
                self.producer.path(),
                &[
                    "incident",
                    "capture",
                    "--from-run",
                    &self.receipt_id,
                    "--json",
                ],
                Some(self.producer_state.path()),
            )
        }

        fn install_signed_source(&self, source: &IncidentEvidencePackage) -> Vec<u8> {
            let signed = sign_incident_evidence_package(source.clone(), &self.run_signer).unwrap();
            let bytes = serde_json::to_vec_pretty(&signed).unwrap();
            fs::write(self.source_path(), &bytes).unwrap();
            bytes
        }

        fn candidate(&self, name: &str, source: &IncidentEvidencePackage) -> Vec<u8> {
            let mut bundle = generate_replay_bundle_from_evidence(source).unwrap();
            sign_replay_bundle(
                &mut bundle,
                &ReplayBundleSigningMaterial {
                    signing_key: &self.exporter,
                    key_source: "configured",
                    signing_identity: "runtime-origin-adversarial-exporter",
                },
            )
            .unwrap();
            let bytes = to_canonical_json(&bundle).unwrap().into_bytes();
            verify_incident_bundle_with_run_key(
                &bytes,
                &self.exporter.verifying_key(),
                &self.run_signer.verifying_key(),
            )
            .expect("candidate retains valid exporter and original run signatures");
            fs::write(self.operator.path().join(name), &bytes).unwrap();
            bytes
        }

        fn archive_original_authority_and_inputs(&self) {
            for name in ["app.js", "input.txt", "output.txt"] {
                fs::rename(
                    self.producer.path().join(name),
                    self.archive.path().join(name),
                )
                .unwrap();
            }
            let dependency = self.producer.path().join("replay-dependency.cjs");
            if dependency.exists() {
                fs::rename(dependency, self.archive.path().join("replay-dependency.cjs"))
                    .unwrap();
            }
            fs::rename(
                self.producer_state.path().join("franken-node"),
                self.archive.path().join("producer-state"),
            )
            .unwrap();
            assert!(!self.producer_state.path().join(ROOT_KEY_PATH).exists());
        }

        fn replay(&self, name: &str, root_key: Option<&str>, execute: bool) -> Output {
            let mut args = vec![
                "incident",
                "replay",
                "--bundle",
                name,
                "--trusted-public-key",
                "exporter.pub",
                "--trusted-run-public-key",
                "run.pub",
                "--json",
                "--structured-logs-jsonl",
            ];
            if let Some(key) = root_key {
                args.extend(["--trusted-runtime-public-key", key]);
            }
            if execute {
                args.push("--execute");
            }
            run_cli_in_workspace_with_state_home(
                self.operator.path(),
                &args,
                Some(self.operator_state.path()),
            )
        }

        fn assert_no_repeated_effects(&self) {
            assert!(!self.producer.path().join("output.txt").exists());
            assert!(!self.operator.path().join("output.txt").exists());
            assert!(!self.operator.path().join("input.txt").exists());
            assert!(!self.operator_state.path().join(ROOT_KEY_PATH).exists());
            assert_eq!(
                fs::read_to_string(self.archive.path().join("output.txt")).unwrap(),
                "ORIGINAL",
            );
        }
    }

    fn assert_runtime_refusal(output: Output) {
        assert!(!output.status.success(), "{output:?}");
        let report: Value = serde_json::from_slice(&output.stdout).expect("structured refusal");
        assert_eq!(report["ok"], false);
        assert!(
            report["error"]
                .as_str()
                .unwrap()
                .contains("original runtime proof verification failed before replay"),
            "{report}"
        );
        assert!(report.get("execution_result").is_none());
        assert!(
            !String::from_utf8_lossy(&output.stderr).contains("\"event_code\":\"FN-TTR-001\""),
            "verification must refuse before replay begins",
        );
    }

    #[test]
    fn policy_equivalence_replays_frozen_modules_offline_and_refuses_failure_prefixes() {
        for guest_exception in [false, true] {
            let fixture = Fixture::new_with_frozen_modules(guest_exception, true);
            fixture.archive_original_authority_and_inputs();
            assert!(!fixture.producer.path().join("replay-dependency.cjs").exists());
            let output = run_cli_in_workspace_with_state_home(
                fixture.operator.path(),
                &[
                    "incident",
                    "replay",
                    "--bundle",
                    &fixture.bundle_name,
                    "--trusted-public-key",
                    "exporter.pub",
                    "--trusted-run-public-key",
                    "run.pub",
                    "--trusted-runtime-public-key",
                    "runtime.pub",
                    "--execute",
                    "--require-policy-equivalence",
                    "--json",
                ],
                Some(fixture.operator_state.path()),
            );
            assert_eq!(output.status.success(), !guest_exception, "{output:?}");
            let report: Value = serde_json::from_slice(&output.stdout).unwrap();
            assert_eq!(report["run_origin_verified"], true);
            assert_eq!(report["runtime_origin_verified"], true);
            assert_eq!(report["replay_result"]["matched"], !guest_exception);
            let execution = &report["execution_result"];
            assert_eq!(execution["verification_scope"], "guest_execution_and_policy");
            assert_eq!(execution["module_load_disabled"], false);
            assert_eq!(execution["matched"], !guest_exception);
            assert_eq!(execution["console_match"], true);
            assert_eq!(execution["host_effects_match"], true);
            if guest_exception {
                assert!(execution["decisions_match"].is_null());
                assert!(!execution["divergences"].as_array().unwrap().is_empty());
            } else {
                for comparison in [
                    "terminal_state_match",
                    "ir3_hash_match",
                    "ir4_witness_match",
                    "execution_value_match",
                    "instruction_count_match",
                    "nondeterminism_trace_match",
                    "lane_match",
                    "exit_code_match",
                    "decisions_match",
                ] {
                    assert_eq!(execution[comparison], true, "{comparison}: {report}");
                }
                assert!(execution["divergences"].as_array().unwrap().is_empty());
            }
            fixture.assert_no_repeated_effects();
        }
    }

    #[test]
    fn runtime_origin_replay_authenticates_real_completed_and_failed_runs_offline() {
        for guest_exception in [false, true] {
            let fixture = Fixture::new(guest_exception);
            fixture.archive_original_authority_and_inputs();
            verify_incident_bundle_with_runtime_keys(
                &fs::read(fixture.operator.path().join(&fixture.bundle_name)).unwrap(),
                &fixture.exporter.verifying_key(),
                &fixture.run_signer.verifying_key(),
                &fixture.runtime_root,
            )
            .expect("offline SDK needs neither original source nor producer authority files");
            for execute in [false, true] {
                let output = fixture.replay(&fixture.bundle_name, Some("runtime.pub"), execute);
                assert!(output.status.success(), "{output:?}");
                let report: Value = serde_json::from_slice(&output.stdout).unwrap();
                assert_eq!(
                    report["authentication_scope"],
                    "authenticated_runtime_incident"
                );
                assert_eq!(report["run_origin_verified"], true);
                assert_eq!(report["runtime_origin_verified"], true);
                assert_eq!(report["run_origin"]["receipt_id"], fixture.receipt_id);
                assert_eq!(
                    report["runtime_origin"]["product_root_key_id"],
                    format!("ed25519:{}", hex::encode(fixture.runtime_root.as_bytes()))
                );
                assert!(report["runtime_origin"]["signed_epoch"].is_string());
                assert_eq!(report["replay_result"]["matched"], true);
                if execute {
                    assert_eq!(report["execution_result"]["matched"], true);
                    assert_eq!(
                        report["execution_result"]["verification_scope"],
                        if guest_exception {
                            "guest_failure_prefix"
                        } else {
                            "guest_execution"
                        }
                    );
                } else {
                    assert!(report["execution_result"].is_null());
                }
                fixture.assert_no_repeated_effects();
            }
        }
    }

    #[test]
    fn policy_equivalence_does_not_upgrade_an_authenticated_unfrozen_guest_match() {
        for guest_exception in [false, true] {
            let fixture = Fixture::new(guest_exception);
            fixture.archive_original_authority_and_inputs();
            let ordinary = fixture.replay(&fixture.bundle_name, Some("runtime.pub"), true);
            assert!(ordinary.status.success(), "{ordinary:?}");
            let output = run_cli_in_workspace_with_state_home(
                fixture.operator.path(),
                &[
                    "incident",
                    "replay",
                    "--bundle",
                    &fixture.bundle_name,
                    "--trusted-public-key",
                    "exporter.pub",
                    "--trusted-run-public-key",
                    "run.pub",
                    "--trusted-runtime-public-key",
                    "runtime.pub",
                    "--execute",
                    "--require-policy-equivalence",
                    "--json",
                ],
                Some(fixture.operator_state.path()),
            );
            assert!(!output.status.success(), "{output:?}");
            let report: Value = serde_json::from_slice(&output.stdout).unwrap();
            assert_eq!(report["runtime_origin_verified"], true);
            assert_eq!(report["replay_result"]["matched"], false);
            assert_eq!(report["execution_result"]["matched"], false);
            assert_eq!(report["execution_result"]["module_load_disabled"], true);
            assert_eq!(
                report["execution_result"]["verification_scope"],
                "guest_execution_and_policy"
            );
            assert!(
                !report["execution_result"]["divergences"]
                    .as_array()
                    .unwrap()
                    .is_empty()
            );
            fixture.assert_no_repeated_effects();
        }
    }

    #[test]
    fn runtime_origin_replay_rejects_foreign_and_resigned_missing_or_forged_origin() {
        let fixture = Fixture::new(false);
        let mut missing = fixture.source.clone();
        missing
            .initial_state_snapshot
            .as_object_mut()
            .unwrap()
            .remove("runtime_evidence_identity_capture");
        let missing_bytes = fixture.candidate("missing-runtime.fnbundle", &missing);
        assert!(matches!(
            verify_incident_bundle_with_runtime_keys(
                &missing_bytes,
                &fixture.exporter.verifying_key(),
                &fixture.run_signer.verifying_key(),
                &fixture.runtime_root,
            ),
            Err(IncidentBundleError::RuntimeOriginMissing)
        ));

        let mut tampered = fixture.source.clone();
        tampered.initial_state_snapshot["runtime_evidence_identity_capture"]["signature_hex"] =
            json!("00".repeat(64));
        let tampered_bytes = fixture.candidate("tampered-runtime.fnbundle", &tampered);
        assert!(matches!(
            verify_incident_bundle_with_runtime_keys(
                &tampered_bytes,
                &fixture.exporter.verifying_key(),
                &fixture.run_signer.verifying_key(),
                &fixture.runtime_root,
            ),
            Err(IncidentBundleError::RuntimeOriginCaptureSignatureInvalid)
        ));

        // A valid receipt-authority signature cannot repair a forged engine
        // signature. Keep the root-certified session and every ledger entry.
        let mut forged = fixture.source.clone();
        let mut record: Value = serde_json::from_str(
            forged.initial_state_snapshot["run_origin"]["record_json"]
                .as_str()
                .unwrap(),
        )
        .unwrap();
        let byte = &mut record["host_effect_ledger"]["signature"]["signature"]["lower"][0];
        *byte = json!(byte.as_u64().unwrap() ^ 1);
        let record_signature = sign_run_ledger_record(&record, &fixture.run_signer).unwrap();
        record["record_signature"] = json!(record_signature);
        forged.initial_state_snapshot["run_origin"]["record_json"] =
            json!(serde_json::to_string(&record).unwrap());
        let forged_bytes = fixture.candidate("forged-ledger.fnbundle", &forged);
        assert!(matches!(
            verify_incident_bundle_with_runtime_keys(
                &forged_bytes,
                &fixture.exporter.verifying_key(),
                &fixture.run_signer.verifying_key(),
                &fixture.runtime_root,
            ),
            Err(IncidentBundleError::RuntimeOriginLedgerSignatureInvalid)
        ));

        fixture.archive_original_authority_and_inputs();
        for root in ["foreign.pub", "exporter.pub", "run.pub"] {
            assert_runtime_refusal(fixture.replay(&fixture.bundle_name, Some(root), true));
        }
        for name in [
            "missing-runtime.fnbundle",
            "tampered-runtime.fnbundle",
            "forged-ledger.fnbundle",
        ] {
            assert_runtime_refusal(fixture.replay(name, Some("runtime.pub"), true));
        }
        let weaker = fixture.replay("missing-runtime.fnbundle", None, false);
        assert!(weaker.status.success(), "{weaker:?}");
        let weaker: Value = serde_json::from_slice(&weaker.stdout).unwrap();
        assert_eq!(weaker["authentication_scope"], "authenticated_run_incident");
        assert_eq!(weaker["run_origin_verified"], true);
        assert_eq!(weaker["runtime_origin_verified"], false);
        assert!(weaker["runtime_origin"].is_null());
        fixture.assert_no_repeated_effects();
    }

    #[test]
    fn runtime_origin_capture_upgrades_only_absence_and_preserves_authenticated_source() {
        let fixture = Fixture::new(false);
        let mut legacy = fixture.source.clone();
        legacy
            .initial_state_snapshot
            .as_object_mut()
            .unwrap()
            .remove("runtime_evidence_identity_capture");
        legacy.metadata.title = "Retained operator title".to_string();
        legacy
            .metadata
            .tags
            .push("retained-operator-tag".to_string());
        fixture.install_signed_source(&legacy);
        let historical = fixture.candidate("historical.fnbundle", &legacy);

        let upgraded = fixture.capture_again();
        assert!(upgraded.status.success(), "{upgraded:?}");
        let upgraded: Value = serde_json::from_slice(&upgraded.stdout).unwrap();
        assert_eq!(upgraded["status"], "upgraded");
        let source = read_verified_incident_evidence_package(
            &fixture.source_path(),
            None,
            &fixture.run_signer.verifying_key(),
        )
        .unwrap();
        let mut expected = legacy;
        expected.initial_state_snapshot["runtime_evidence_identity_capture"] =
            fixture.source.initial_state_snapshot["runtime_evidence_identity_capture"].clone();
        assert_eq!(
            source, expected,
            "upgrade changes only the public identity field"
        );
        assert_eq!(
            fs::read(fixture.operator.path().join("historical.fnbundle")).unwrap(),
            historical,
            "existing exports retain their exact bytes and original scope"
        );
        let before = fs::read(fixture.source_path()).unwrap();
        let again = fixture.capture_again();
        assert!(again.status.success(), "{again:?}");
        let again: Value = serde_json::from_slice(&again.stdout).unwrap();
        assert_eq!(again["status"], "already_captured");
        assert_eq!(fs::read(fixture.source_path()).unwrap(), before);

        let mut different =
            expected.initial_state_snapshot["runtime_evidence_identity_capture"].clone();
        different["session_nonce"] = json!("11111111-1111-4111-8111-111111111111");
        for replacement in [
            Value::Null,
            json!({}),
            json!("untrusted-public-capture"),
            different,
        ] {
            let mut contradiction = expected.clone();
            contradiction.initial_state_snapshot["runtime_evidence_identity_capture"] = replacement;
            let before = fixture.install_signed_source(&contradiction);
            let refused = fixture.capture_again();
            assert!(!refused.status.success(), "{refused:?}");
            assert_eq!(fs::read(fixture.source_path()).unwrap(), before);
        }
        let mut wrong_record = expected.clone();
        wrong_record.initial_state_snapshot["run_origin"]["record_json"] = json!("{}");
        let before = fixture.install_signed_source(&wrong_record);
        let refused = fixture.capture_again();
        assert!(!refused.status.success(), "{refused:?}");
        assert_eq!(fs::read(fixture.source_path()).unwrap(), before);
    }
}
