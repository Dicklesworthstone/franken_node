use frankenengine_node::security::remote_cap::{
    CapabilityGate, CapabilityProvider, ConnectivityMode, RemoteCap, RemoteOperation, RemoteScope,
};

const KEY_MATERIAL: &str = "r12-capability-gate-fuzz-secret-7d9f1a2c9b8e6f4a";
const ISSUED_AT: u64 = 1_700_000_000;

#[derive(Clone, Copy)]
struct CapabilityGateFuzzCase {
    label: &'static str,
    issued_operation: RemoteOperation,
    attempted_operation: RemoteOperation,
    prefix: &'static str,
    endpoint: &'static str,
    ttl_secs: u64,
    now_epoch_secs: u64,
    mode: ConnectivityMode,
    expected_error_code: Option<&'static str>,
}

#[derive(Clone, Copy)]
struct EndpointBoundaryFuzzCase {
    label: &'static str,
    prefix: &'static str,
    endpoint: &'static str,
    should_authorize: bool,
}

fn provider() -> Result<CapabilityProvider, String> {
    CapabilityProvider::new(KEY_MATERIAL).map_err(|err| err.to_string())
}

fn issue_case_cap(case: &CapabilityGateFuzzCase) -> Result<RemoteCap, String> {
    let scope = RemoteScope::new(vec![case.issued_operation], vec![case.prefix.to_string()]);
    let (cap, _) = provider()?
        .issue(
            "r12-capability-fuzz",
            scope,
            ISSUED_AT,
            case.ttl_secs,
            true,
            false,
            case.label,
        )
        .map_err(|err| err.to_string())?;
    Ok(cap)
}

fn assert_gate_case(case: &CapabilityGateFuzzCase) -> Result<(), String> {
    let cap = issue_case_cap(case)?;
    let mut gate =
        CapabilityGate::with_mode(KEY_MATERIAL, case.mode).map_err(|err| err.to_string())?;
    let result = gate.authorize_network(
        Some(&cap),
        case.attempted_operation,
        case.endpoint,
        case.now_epoch_secs,
        case.label,
    );

    match case.expected_error_code {
        Some(expected_code) => {
            let Err(err) = result else {
                return Err(format!("{} should fail closed", case.label));
            };
            assert_eq!(
                err.code(),
                expected_code,
                "{} denial code mismatch",
                case.label
            );
            let Some(event) = gate.audit_log().last() else {
                return Err(format!("{} denial must be audited", case.label));
            };
            assert!(
                !event.allowed,
                "{} denial audit must be fail-closed",
                case.label
            );
            assert_eq!(
                event.denial_code.as_deref(),
                Some(expected_code),
                "{} denial audit code mismatch",
                case.label
            );
        }
        None => {
            assert!(result.is_ok(), "{} should authorize", case.label);
            let Some(event) = gate.audit_log().last() else {
                return Err(format!("{} authorization must be audited", case.label));
            };
            assert!(event.allowed, "{} audit should record an allow", case.label);
            assert_eq!(event.denial_code.as_deref(), None);
        }
    }

    Ok(())
}

#[test]
fn capability_gate_endpoint_boundary_fuzz_corpus_preserves_prefix_delimiters() -> Result<(), String>
{
    let cases = [
        EndpointBoundaryFuzzCase {
            label: "path child under exact prefix authorizes",
            prefix: "https://api.example.com/root",
            endpoint: "https://api.example.com/root/jobs",
            should_authorize: true,
        },
        EndpointBoundaryFuzzCase {
            label: "query delimiter under exact prefix authorizes",
            prefix: "https://api.example.com/root",
            endpoint: "https://api.example.com/root?job=deploy",
            should_authorize: true,
        },
        EndpointBoundaryFuzzCase {
            label: "explicit port path child authorizes",
            prefix: "https://api.example.com:8443/root",
            endpoint: "https://api.example.com:8443/root/jobs",
            should_authorize: true,
        },
        EndpointBoundaryFuzzCase {
            label: "encoded slash suffix does not extend prefix",
            prefix: "https://api.example.com/root",
            endpoint: "https://api.example.com/root%2fadmin",
            should_authorize: false,
        },
        EndpointBoundaryFuzzCase {
            label: "sibling path prefix confusion fails closed",
            prefix: "https://api.example.com/root",
            endpoint: "https://api.example.com/rooted/admin",
            should_authorize: false,
        },
        EndpointBoundaryFuzzCase {
            label: "sibling host with explicit port fails closed",
            prefix: "https://api.example.com:8443/root",
            endpoint: "https://api.example.com:8443.evil/root/jobs",
            should_authorize: false,
        },
        EndpointBoundaryFuzzCase {
            label: "fragment continuation fails closed",
            prefix: "https://api.example.com/root",
            endpoint: "https://api.example.com/root#admin",
            should_authorize: false,
        },
        EndpointBoundaryFuzzCase {
            label: "backslash continuation fails closed",
            prefix: "https://api.example.com/root",
            endpoint: "https://api.example.com/root\\admin",
            should_authorize: false,
        },
        EndpointBoundaryFuzzCase {
            label: "cross-origin port escalation under default-port prefix fails closed",
            prefix: "https://api.example.com",
            endpoint: "https://api.example.com:8443/root",
            should_authorize: false,
        },
    ];

    for case in cases {
        let scope = RemoteScope::new(
            vec![RemoteOperation::NetworkEgress],
            vec![case.prefix.to_string()],
        );
        let predicate_allows = scope.allows_endpoint(case.endpoint);
        assert_eq!(
            predicate_allows, case.should_authorize,
            "{} predicate mismatch",
            case.label
        );

        let (cap, _) = provider()?
            .issue(
                "r65-capability-boundary-fuzz",
                scope,
                ISSUED_AT,
                300,
                true,
                true,
                case.label,
            )
            .map_err(|err| err.to_string())?;
        let mut gate = CapabilityGate::new(KEY_MATERIAL).map_err(|err| err.to_string())?;
        let result = gate.authorize_network(
            Some(&cap),
            RemoteOperation::NetworkEgress,
            case.endpoint,
            ISSUED_AT + 1,
            case.label,
        );

        if case.should_authorize {
            assert!(result.is_ok(), "{} should authorize", case.label);
            let Some(event) = gate.audit_log().last() else {
                return Err(format!("{} allow must be audited", case.label));
            };
            assert!(event.allowed, "{} audit should record allow", case.label);
            assert_eq!(event.denial_code.as_deref(), None);
        } else {
            let Err(err) = result else {
                return Err(format!("{} should fail closed", case.label));
            };
            assert_eq!(err.code(), "REMOTECAP_SCOPE_DENIED");
            let Some(event) = gate.audit_log().last() else {
                return Err(format!("{} denial must be audited", case.label));
            };
            assert!(
                !event.allowed,
                "{} denial audit must fail closed",
                case.label
            );
            assert_eq!(event.denial_code.as_deref(), Some("REMOTECAP_SCOPE_DENIED"));
        }
    }

    Ok(())
}

#[test]
fn capability_gate_structure_aware_fuzz_seed_matrix() -> Result<(), String> {
    let cases = [
        CapabilityGateFuzzCase {
            label: "valid telemetry endpoint under declared prefix",
            issued_operation: RemoteOperation::TelemetryExport,
            attempted_operation: RemoteOperation::TelemetryExport,
            prefix: "https://telemetry.example.com/v1",
            endpoint: "https://telemetry.example.com/v1/push",
            ttl_secs: 300,
            now_epoch_secs: ISSUED_AT + 1,
            mode: ConnectivityMode::Connected,
            expected_error_code: None,
        },
        CapabilityGateFuzzCase {
            label: "expiry boundary rejects at exact expires_at",
            issued_operation: RemoteOperation::TelemetryExport,
            attempted_operation: RemoteOperation::TelemetryExport,
            prefix: "https://telemetry.example.com/v1",
            endpoint: "https://telemetry.example.com/v1/push",
            ttl_secs: 60,
            now_epoch_secs: ISSUED_AT + 60,
            mode: ConnectivityMode::Connected,
            expected_error_code: Some("REMOTECAP_EXPIRED"),
        },
        CapabilityGateFuzzCase {
            label: "sibling host prefix confusion fails closed",
            issued_operation: RemoteOperation::NetworkEgress,
            attempted_operation: RemoteOperation::NetworkEgress,
            prefix: "https://api.example.com",
            endpoint: "https://api.example.com.evil/jobs",
            ttl_secs: 300,
            now_epoch_secs: ISSUED_AT + 1,
            mode: ConnectivityMode::Connected,
            expected_error_code: Some("REMOTECAP_SCOPE_DENIED"),
        },
        CapabilityGateFuzzCase {
            label: "encoded traversal under path prefix fails closed",
            issued_operation: RemoteOperation::NetworkEgress,
            attempted_operation: RemoteOperation::NetworkEgress,
            prefix: "https://api.example.com/root/",
            endpoint: "https://api.example.com/root/%2e%2e/admin",
            ttl_secs: 300,
            now_epoch_secs: ISSUED_AT + 1,
            mode: ConnectivityMode::Connected,
            expected_error_code: Some("REMOTECAP_SCOPE_DENIED"),
        },
        CapabilityGateFuzzCase {
            label: "operation escalation fails closed",
            issued_operation: RemoteOperation::TelemetryExport,
            attempted_operation: RemoteOperation::FederationSync,
            prefix: "https://telemetry.example.com",
            endpoint: "https://telemetry.example.com/push",
            ttl_secs: 300,
            now_epoch_secs: ISSUED_AT + 1,
            mode: ConnectivityMode::Connected,
            expected_error_code: Some("REMOTECAP_SCOPE_DENIED"),
        },
        CapabilityGateFuzzCase {
            label: "local only mode denies network even with valid token",
            issued_operation: RemoteOperation::TelemetryExport,
            attempted_operation: RemoteOperation::TelemetryExport,
            prefix: "https://telemetry.example.com",
            endpoint: "https://telemetry.example.com/push",
            ttl_secs: 300,
            now_epoch_secs: ISSUED_AT + 1,
            mode: ConnectivityMode::LocalOnly,
            expected_error_code: Some("REMOTECAP_CONNECTIVITY_MODE_DENIED"),
        },
    ];

    for case in &cases {
        assert_gate_case(case)?;
    }

    Ok(())
}

#[test]
fn capability_gate_mutated_signature_seed_corpus_fails_closed() -> Result<(), String> {
    let base_case = CapabilityGateFuzzCase {
        label: "signature mutation seed",
        issued_operation: RemoteOperation::TelemetryExport,
        attempted_operation: RemoteOperation::TelemetryExport,
        prefix: "https://telemetry.example.com",
        endpoint: "https://telemetry.example.com/push",
        ttl_secs: 300,
        now_epoch_secs: ISSUED_AT + 1,
        mode: ConnectivityMode::Connected,
        expected_error_code: Some("REMOTECAP_INVALID"),
    };
    let cap = issue_case_cap(&base_case)?;
    let mut signature_seeds = vec![
        String::new(),
        "0".to_string(),
        "not-hex-signature".to_string(),
        "deadbeef".to_string(),
    ];
    signature_seeds.push("a".repeat(128));

    for signature in signature_seeds {
        let mut value = serde_json::to_value(&cap).map_err(|err| err.to_string())?;
        let Some(cap_fields) = value.as_object_mut() else {
            return Err("serialized capability must be a JSON object".to_string());
        };
        cap_fields.insert(
            "signature".to_string(),
            serde_json::Value::String(signature),
        );
        let mutated_cap: RemoteCap =
            serde_json::from_value(value).map_err(|err| err.to_string())?;
        let mut gate = CapabilityGate::with_mode(KEY_MATERIAL, base_case.mode)
            .map_err(|err| err.to_string())?;
        let result = gate.authorize_network(
            Some(&mutated_cap),
            base_case.attempted_operation,
            base_case.endpoint,
            base_case.now_epoch_secs,
            base_case.label,
        );

        let Err(err) = result else {
            return Err("mutated signature seed should fail closed".to_string());
        };
        assert_eq!(err.code(), "REMOTECAP_INVALID");
        let Some(event) = gate.audit_log().last() else {
            return Err("mutated signature denial must be audited".to_string());
        };
        assert!(!event.allowed);
        assert_eq!(event.denial_code.as_deref(), Some("REMOTECAP_INVALID"));
    }

    Ok(())
}

#[test]
fn capability_provider_rejects_empty_port_and_query_string_prefixes() -> Result<(), String> {
    let invalid_prefixes = [
        "http://api.example.com:",
        "http://api.example.com:/root",
        "https://[::1]:/root",
        "https://api.example.com/root?tenant=acme",
        "https://api.example.com/root?tenant=acme/",
    ];

    for invalid_prefix in invalid_prefixes {
        let scope = RemoteScope::new(
            vec![RemoteOperation::NetworkEgress],
            vec![invalid_prefix.to_string()],
        );
        let err = provider()?
            .issue(
                "r79-invalid-prefix-regression",
                scope,
                ISSUED_AT,
                300,
                true,
                false,
                "invalid-prefix-check",
            )
            .expect_err("empty-port or query-bearing prefix must fail closed");
        assert_eq!(
            err.code(),
            "REMOTECAP_SCOPE_INVALID",
            "unexpected code for invalid prefix {invalid_prefix}: {err}"
        );
    }

    Ok(())
}

#[test]
fn checked_in_fuzz_crash_artifacts_replay_deterministically_without_panicking() -> Result<(), String>
{
    let artifacts_root =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../fuzz/artifacts");
    let mut crash_files = Vec::new();
    for target_entry in std::fs::read_dir(&artifacts_root).map_err(|err| err.to_string())? {
        let target_dir = target_entry.map_err(|err| err.to_string())?.path();
        if !target_dir.is_dir() {
            continue;
        }
        for file_entry in std::fs::read_dir(&target_dir).map_err(|err| err.to_string())? {
            let file_path = file_entry.map_err(|err| err.to_string())?.path();
            if file_path
                .file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| name.starts_with("crash-"))
            {
                crash_files.push(file_path);
            }
        }
    }
    crash_files.sort();
    assert!(
        crash_files.len() >= 9,
        "expected at least 9 checked-in fuzz crash artifacts, found {}",
        crash_files.len()
    );

    for crash_path in crash_files {
        let bytes = std::fs::read(&crash_path).map_err(|err| err.to_string())?;
        exercise_domain_parsers(&bytes);
    }

    Ok(())
}

fn exercise_domain_parsers(bytes: &[u8]) {
    use frankenengine_node::api::fleet_quarantine::QuarantineRequest;
    use frankenengine_node::replay::time_travel_engine::WorkflowTrace;
    use frankenengine_node::runtime::checkpoint::{
        CheckpointBackend, CheckpointContract, CheckpointRecord, CheckpointWriter,
        InMemoryCheckpointBackend,
    };
    use frankenengine_node::security::decision_receipt::SignedReceipt;
    use frankenengine_node::supply_chain::artifact_signing::ChecksumManifest;
    use frankenengine_node::supply_chain::extension_registry::ExtensionRegistrationManifest;
    use frankenengine_node::supply_chain::provenance::{
        ProvenanceAttestation, VerificationPolicy, verify_and_project_gates,
    };
    use frankenengine_node::supply_chain::trust_card::{TrustCard, TrustCardRegistrySnapshot};
    use frankenengine_node::tools::replay_bundle::{ReplayBundle, to_canonical_json};

    let r1 = serde_json::from_slice::<RemoteCap>(bytes);
    let r2 = serde_json::from_slice::<RemoteCap>(bytes);
    assert_eq!(r1.is_ok(), r2.is_ok());

    if let Ok(scope) = serde_json::from_slice::<RemoteScope>(bytes) {
        let _ = scope.allows_endpoint("https://api.example.com/v1/health");
    }
    let _ = serde_json::from_slice::<QuarantineRequest>(bytes);
    let _ = serde_json::from_slice::<ExtensionRegistrationManifest>(bytes);
    let _ = serde_json::from_slice::<SignedReceipt>(bytes);
    let _ = serde_json::from_slice::<TrustCard>(bytes);
    let _ = serde_json::from_slice::<TrustCardRegistrySnapshot>(bytes);
    let _ = serde_json::from_slice::<WorkflowTrace>(bytes);

    if let Ok(record) = serde_json::from_slice::<CheckpointRecord>(bytes) {
        let mut writer = CheckpointWriter::new(InMemoryCheckpointBackend::default());
        let _ = writer.backend_mut().save(record.clone());
        let _ = writer.read_latest_valid("fuzz-regression", &record.orchestration_id);
        let _ = writer.list_checkpoints(&record.orchestration_id);
    }
    if let Ok(bundle) = serde_json::from_slice::<ReplayBundle>(bytes) {
        let _ = to_canonical_json(&bundle);
    }
    if let Ok(attestation) = serde_json::from_slice::<ProvenanceAttestation>(bytes) {
        let _ = verify_and_project_gates(
            &attestation,
            &VerificationPolicy::production_default(),
            ISSUED_AT,
            "fuzz-regression",
        );
    }

    if let Ok(text) = std::str::from_utf8(bytes) {
        let _ = ChecksumManifest::parse_canonical(text);
        let _ = toml::from_str::<toml::Value>(text);
        if let Some((last_char_idx, _)) = text.char_indices().next_back()
            && last_char_idx > 0
        {
            let truncated = &text[..last_char_idx];
            let _ = serde_json::from_str::<serde_json::Value>(truncated);
        }
    }
}

#[test]
fn promoted_fuzz_regression_manifest_and_146_target_seed_corpora_replay_cleanly()
-> Result<(), String> {
    use sha2::{Digest, Sha256};

    let repo_root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let manifest_bytes = std::fs::read(repo_root.join("fuzz/regression/manifest.json"))
        .map_err(|err| err.to_string())?;
    let manifest: serde_json::Value =
        serde_json::from_slice(&manifest_bytes).map_err(|err| err.to_string())?;
    assert_eq!(
        manifest["schema_version"],
        "franken-node/fuzz-regression-manifest/v1"
    );
    assert_eq!(manifest["registered_targets"], 146);
    assert_eq!(manifest["seeded_targets"], 146);

    let promoted = manifest["promoted_target_regressions"]
        .as_array()
        .ok_or_else(|| "promoted_target_regressions must be an array".to_string())?;
    assert!(
        promoted.len() >= 9,
        "expected >=9 promoted target regressions, got {}",
        promoted.len()
    );

    let mut replayed_regression_inputs = 0usize;
    for entry in promoted {
        let reg_rel = entry["regression_input"]
            .as_str()
            .ok_or_else(|| "missing regression_input".to_string())?;
        let reg_bytes =
            std::fs::read(repo_root.join(reg_rel)).map_err(|err| format!("{reg_rel}: {err}"))?;
        let actual_sha = hex::encode(Sha256::digest(&reg_bytes));
        assert_eq!(
            Some(actual_sha.as_str()),
            entry["original_sha256"].as_str(),
            "sha256 mismatch on {reg_rel}"
        );
        exercise_domain_parsers(&reg_bytes);
        replayed_regression_inputs += 1;

        if let Some(min_rel) = entry["minimized_input"].as_str() {
            let min_bytes = std::fs::read(repo_root.join(min_rel))
                .map_err(|err| format!("{min_rel}: {err}"))?;
            assert!(
                min_bytes.len() < reg_bytes.len(),
                "minimized input {min_rel} must be strictly smaller than {reg_rel}"
            );
            let min_sha = hex::encode(Sha256::digest(&min_bytes));
            assert_eq!(
                Some(min_sha.as_str()),
                entry["minimized_sha256"].as_str(),
                "sha256 mismatch on {min_rel}"
            );
            exercise_domain_parsers(&min_bytes);
            replayed_regression_inputs += 1;
        }
    }
    assert!(replayed_regression_inputs >= 16);

    let fuzz_toml_text = std::fs::read_to_string(repo_root.join("fuzz/Cargo.toml"))
        .map_err(|err| err.to_string())?;
    let fuzz_toml: toml::Value = toml::from_str(&fuzz_toml_text).map_err(|err| err.to_string())?;
    let bins = fuzz_toml["bin"]
        .as_array()
        .ok_or_else(|| "fuzz/Cargo.toml missing [[bin]]".to_string())?;
    assert_eq!(bins.len(), 146);

    for bin in bins {
        let name = bin["name"]
            .as_str()
            .ok_or_else(|| "bin missing name".to_string())?;
        let target_corpus = repo_root.join("fuzz/corpus").join(name);
        let mut seeds: Vec<std::path::PathBuf> = std::fs::read_dir(&target_corpus)
            .map_err(|err| format!("corpus dir {}: {err}", target_corpus.display()))?
            .filter_map(|e| e.ok().map(|entry| entry.path()))
            .filter(|p| p.is_file())
            .collect();
        seeds.sort();
        assert!(
            !seeds.is_empty(),
            "target {name} must have at least 1 seed in fuzz/corpus/{name}"
        );
        // Replay bounded sample (first 4 seeds per target) so test stays sub-second across 18k+ files.
        for seed_path in seeds.into_iter().take(4) {
            let bytes = std::fs::read(&seed_path).map_err(|err| err.to_string())?;
            if bytes.len() <= 65_536 {
                exercise_domain_parsers(&bytes);
            }
        }
    }

    Ok(())
}
