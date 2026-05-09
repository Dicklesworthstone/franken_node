use std::collections::{BTreeMap, BTreeSet};

use chrono::{DateTime, Utc};
use frankenengine_node::migration::{
    MigrationRollbackEntry, MigrationRollbackPlan, MigrationRollbackValidationError,
    MigrationRollbackValidationPolicy, validate_rollback_plan,
};
use frankenengine_node::ops::validation_broker::{
    CommandSpec, DigestRef, EnvironmentPolicy, InputDigest, READINESS_REF_SCHEMA_VERSION,
    RECEIPT_SCHEMA_VERSION, RchMode, RchReceipt, ReceiptArtifacts, ReceiptClassifications,
    ReceiptRequestRef, ReceiptTrust, SourceOnlyReason, TargetDirPolicy, TimeoutClass,
    ValidationBrokerError, ValidationErrorClass, ValidationExit, ValidationExitKind,
    ValidationReadinessRef, ValidationReceipt, ValidationTiming, error_codes,
};
use frankenengine_node::security::remote_cap::{
    CapabilityGate, CapabilityProvider, RemoteCap, RemoteOperation, RemoteScope,
};
use frankenengine_node::supply_chain::trust_card::{TrustCard, to_canonical_json};
use frankenengine_node::tools::replay_bundle::{
    EventType, RawEvent, ReplayBundle, ReplayBundleSigningMaterial, generate_replay_bundle,
    replay_bundle_adversarial_fuzz_one, replay_bundle_with_trusted_key, sign_replay_bundle,
};
use serde::Deserialize;
use serde_json::{Value, json};

const MANIFEST_JSON: &str = include_str!(
    "../../../artifacts/spec_derived_fuzz_seeds/bd-38hez.12/spec_derived_fuzz_seed_manifest.json"
);

const REQUIRED_CLASSES: [&str; 6] = [
    "valid",
    "missing_field",
    "oversized",
    "stale",
    "malformed_signature_or_hash",
    "path_safety",
];

const REQUIRED_SURFACES: [&str; 5] = [
    "trust_card",
    "replay_bundle",
    "remote_capability",
    "migration_rollback",
    "validation_receipt",
];

const REMOTE_KEY_MATERIAL: &str = "spec-derived-remote-cap-fixture-material";
const REMOTE_NOW: u64 = 1_700_000_000;

#[derive(Debug, Deserialize)]
struct SeedManifest {
    schema_version: String,
    bead_id: String,
    required_seed_classes: Vec<String>,
    source_specs: Vec<String>,
    surfaces: Vec<SeedSurface>,
}

#[derive(Debug, Deserialize)]
struct SeedSurface {
    name: String,
    parser_entrypoint: String,
    seeds: Vec<SeedCase>,
}

#[derive(Debug, Deserialize)]
struct SeedCase {
    id: String,
    #[serde(rename = "class")]
    seed_class: String,
    payload_variant: String,
}

#[test]
fn manifest_declares_required_seed_classes_for_every_surface() {
    let manifest = load_manifest();
    assert_eq!(
        manifest.schema_version,
        "franken-node/spec-derived-fuzz-seeds/v1"
    );
    assert_eq!(manifest.bead_id, "bd-38hez.12");
    assert_eq!(
        manifest.required_seed_classes,
        REQUIRED_CLASSES
            .into_iter()
            .map(str::to_string)
            .collect::<Vec<_>>()
    );
    assert!(
        manifest.source_specs.len() >= REQUIRED_SURFACES.len(),
        "manifest should cite source specs/modules for every supported surface"
    );

    let surface_names = manifest
        .surfaces
        .iter()
        .map(|surface| surface.name.as_str())
        .collect::<BTreeSet<_>>();
    assert_eq!(surface_names, REQUIRED_SURFACES.into_iter().collect());

    for surface in &manifest.surfaces {
        assert!(
            !surface.parser_entrypoint.trim().is_empty(),
            "{} must name the production parser entrypoint",
            surface.name
        );
        let classes = surface
            .seeds
            .iter()
            .map(|seed| seed.seed_class.as_str())
            .collect::<BTreeSet<_>>();
        assert_eq!(
            classes,
            REQUIRED_CLASSES.into_iter().collect(),
            "{} must carry every required seed class",
            surface.name
        );
    }
}

#[test]
fn spec_derived_seeds_exercise_production_parsers() {
    let manifest = load_manifest();
    let mut exercised = BTreeMap::<String, usize>::new();

    for surface in &manifest.surfaces {
        for seed in &surface.seeds {
            assert!(
                !seed.payload_variant.trim().is_empty(),
                "{} must name a deterministic seed payload variant",
                seed.id
            );
            match surface.name.as_str() {
                "trust_card" => exercise_trust_card_seed(seed),
                "replay_bundle" => exercise_replay_bundle_seed(seed),
                "remote_capability" => exercise_remote_capability_seed(seed),
                "migration_rollback" => exercise_migration_rollback_seed(seed),
                "validation_receipt" => exercise_validation_receipt_seed(seed),
                other => assert_eq!(other, "", "unknown seed surface: {other}"),
            }
            *exercised.entry(surface.name.clone()).or_insert(0) += 1;
        }
    }

    for surface in REQUIRED_SURFACES {
        assert_eq!(
            exercised.get(surface).copied(),
            Some(REQUIRED_CLASSES.len()),
            "{surface} seeds should all be replayed through production entrypoints"
        );
    }
}

fn load_manifest() -> SeedManifest {
    serde_json::from_str(MANIFEST_JSON).expect("spec-derived fuzz seed manifest should parse")
}

fn exercise_trust_card_seed(seed: &SeedCase) {
    let mut value = trust_card_value();
    match seed.seed_class.as_str() {
        "valid" => {}
        "missing_field" => {
            value
                .as_object_mut()
                .expect("trust-card seed is object")
                .remove("schema_version");
            assert!(
                serde_json::from_value::<TrustCard>(value).is_err(),
                "{} should reject a missing required field",
                seed.id
            );
            return;
        }
        "oversized" => {
            let history = value
                .get_mut("audit_history")
                .and_then(Value::as_array_mut)
                .expect("audit history should be an array");
            for index in 0..96 {
                history.push(json!({
                    "timestamp": "2026-05-09T16:12:00Z",
                    "event_code": "SPEC_DERIVED_OVERSIZED_AUDIT",
                    "detail": format!("oversized audit record {index:03}"),
                    "trace_id": format!("trace-oversized-{index:03}")
                }));
            }
            assert!(
                serde_json::to_vec(&value)
                    .expect("trust-card seed bytes")
                    .len()
                    > 8 * 1024,
                "{} should carry an oversized JSON envelope",
                seed.id
            );
        }
        "stale" => {
            value["last_verified_timestamp"] = json!("1970-01-01T00:00:00Z");
            value["provenance_summary"]["verified_at"] = json!("1970-01-01T00:00:00Z");
        }
        "malformed_signature_or_hash" => {
            value["card_hash"] = json!("sha256:not-a-hex-digest");
            value["registry_signature"] = json!("not-a-signature");
        }
        "path_safety" => {
            value["provenance_summary"]["source_uri"] = json!("file://../../../../etc/passwd");
        }
        other => assert_eq!(
            other, "",
            "{} has unknown trust-card seed class {other}",
            seed.id
        ),
    }

    let card: TrustCard = serde_json::from_value(value).expect("trust-card seed should parse");
    let canonical = to_canonical_json(&card).expect("trust-card seed should canonicalize");
    let reparsed: TrustCard =
        serde_json::from_str(&canonical).expect("canonical trust-card seed should parse");
    assert_eq!(
        canonical,
        to_canonical_json(&reparsed).expect("reparsed trust-card seed should canonicalize")
    );
}

fn exercise_replay_bundle_seed(seed: &SeedCase) {
    let mut value = replay_bundle_value(&seed.id);
    match seed.seed_class.as_str() {
        "valid" => {
            let bundle: ReplayBundle =
                serde_json::from_value(value).expect("valid replay seed should deserialize");
            let trusted_key_id = replay_seed_trusted_key_id();
            replay_bundle_with_trusted_key(&bundle, &trusted_key_id)
                .expect("valid replay bundle seed should replay with trust anchor");
        }
        "missing_field" => {
            value
                .as_object_mut()
                .expect("replay seed is object")
                .remove("chunks");
            let bytes = serde_json::to_vec(&value).expect("replay seed bytes");
            assert!(
                replay_bundle_adversarial_fuzz_one(&bytes).is_err(),
                "{} should reject missing chunks",
                seed.id
            );
        }
        "oversized" => {
            value["chunks"][0]["events"][0]["payload"]["blob"] = json!("x".repeat(128 * 1024));
            let bytes = serde_json::to_vec(&value).expect("replay seed bytes");
            assert!(
                bytes.len() > 128 * 1024,
                "{} should carry an oversized event payload",
                seed.id
            );
            let _ = replay_bundle_adversarial_fuzz_one(&bytes);
        }
        "stale" => {
            value["created_at"] = json!("9999-12-31T23:59:59.000000Z");
            value["chunks"][0]["events"][0]["timestamp"] = json!("9999-12-31T23:59:59.000000Z");
            let bytes = serde_json::to_vec(&value).expect("replay seed bytes");
            assert!(
                replay_bundle_adversarial_fuzz_one(&bytes).is_err(),
                "{} should reject future/stale replay time bounds",
                seed.id
            );
        }
        "malformed_signature_or_hash" => {
            value["bundle_id"] = json!("00000000-0000-0000-0000-000000000000");
            let bytes = serde_json::to_vec(&value).expect("replay seed bytes");
            assert!(
                replay_bundle_adversarial_fuzz_one(&bytes).is_err(),
                "{} should reject bundle hash/id mismatch",
                seed.id
            );
        }
        "path_safety" => {
            value["chunks"][0]["events"][0]["payload"]["path"] = json!("../../incident.json");
            let bytes = serde_json::to_vec(&value).expect("replay seed bytes");
            let _ = replay_bundle_adversarial_fuzz_one(&bytes);
        }
        other => assert_eq!(
            other, "",
            "{} has unknown replay seed class {other}",
            seed.id
        ),
    }
}

fn exercise_remote_capability_seed(seed: &SeedCase) {
    match seed.seed_class.as_str() {
        "valid" => {
            let cap = issued_remote_cap(REMOTE_NOW, 60, "https://api.example.com/v1");
            let decoded: RemoteCap =
                serde_json::from_value(serde_json::to_value(&cap).expect("remote cap JSON"))
                    .expect("issued remote cap should parse");
            let mut gate =
                CapabilityGate::new(REMOTE_KEY_MATERIAL).expect("remote cap gate fixture");
            gate.authorize_network(
                Some(&decoded),
                RemoteOperation::NetworkEgress,
                "https://api.example.com/v1/resource",
                REMOTE_NOW + 1,
                "trace-spec-derived-valid",
            )
            .expect("valid remote cap seed should authorize");
        }
        "missing_field" => {
            let cap = issued_remote_cap(REMOTE_NOW, 60, "https://api.example.com/v1");
            let mut value = serde_json::to_value(&cap).expect("remote cap JSON");
            value
                .as_object_mut()
                .expect("remote cap seed is object")
                .remove("scope");
            assert!(
                serde_json::from_value::<RemoteCap>(value).is_err(),
                "{} should reject a missing scope",
                seed.id
            );
        }
        "oversized" => {
            let scope = RemoteScope::new(
                vec![RemoteOperation::NetworkEgress],
                (0..96)
                    .map(|index| format!("https://api.example.com/{index:03}/"))
                    .collect(),
            );
            let value = serde_json::to_value(&scope).expect("remote scope JSON");
            let decoded: RemoteScope =
                serde_json::from_value(value).expect("oversized remote scope should parse");
            assert_eq!(decoded.endpoint_prefixes().len(), 96);
        }
        "stale" => {
            let cap = issued_remote_cap(REMOTE_NOW, 1, "https://api.example.com/v1");
            let decoded: RemoteCap =
                serde_json::from_value(serde_json::to_value(&cap).expect("remote cap JSON"))
                    .expect("expired remote cap should parse");
            let mut gate =
                CapabilityGate::new(REMOTE_KEY_MATERIAL).expect("remote cap gate fixture");
            assert!(
                gate.authorize_network(
                    Some(&decoded),
                    RemoteOperation::NetworkEgress,
                    "https://api.example.com/v1/resource",
                    REMOTE_NOW + 60,
                    "trace-spec-derived-expired",
                )
                .is_err(),
                "{} should reject an expired token",
                seed.id
            );
        }
        "malformed_signature_or_hash" => {
            let cap = issued_remote_cap(REMOTE_NOW, 60, "https://api.example.com/v1");
            let mut value = serde_json::to_value(&cap).expect("remote cap JSON");
            value["signature"] = json!("tampered-signature");
            let decoded: RemoteCap =
                serde_json::from_value(value).expect("tampered remote cap should still parse");
            let mut gate =
                CapabilityGate::new(REMOTE_KEY_MATERIAL).expect("remote cap gate fixture");
            assert!(
                gate.authorize_network(
                    Some(&decoded),
                    RemoteOperation::NetworkEgress,
                    "https://api.example.com/v1/resource",
                    REMOTE_NOW + 1,
                    "trace-spec-derived-tampered",
                )
                .is_err(),
                "{} should reject a tampered signature",
                seed.id
            );
        }
        "path_safety" => {
            let scope = RemoteScope::new(
                vec![RemoteOperation::NetworkEgress],
                vec!["file://../../../../etc".to_string()],
            );
            let value = serde_json::to_value(&scope).expect("remote scope JSON");
            assert!(
                serde_json::from_value::<RemoteScope>(value).is_err(),
                "{} should reject non-network path-like endpoint prefixes",
                seed.id
            );
        }
        other => assert_eq!(
            other, "",
            "{} has unknown remote-cap seed class {other}",
            seed.id
        ),
    }
}

fn exercise_migration_rollback_seed(seed: &SeedCase) {
    let policy = MigrationRollbackValidationPolicy {
        max_entries: 4,
        max_content_bytes_per_entry: 4096,
        allow_absolute_paths: false,
    };
    let mut value = serde_json::to_value(migration_plan()).expect("migration plan JSON");
    match seed.seed_class.as_str() {
        "valid" => {
            let plan: MigrationRollbackPlan =
                serde_json::from_value(value).expect("valid migration plan should parse");
            validate_rollback_plan(&plan, &policy).expect("valid migration plan should validate");
        }
        "missing_field" => {
            value
                .as_object_mut()
                .expect("migration plan seed is object")
                .remove("entries");
            assert!(
                serde_json::from_value::<MigrationRollbackPlan>(value).is_err(),
                "{} should reject missing entries",
                seed.id
            );
        }
        "oversized" => {
            let mut plan = migration_plan();
            plan.entries
                .extend((0..8).map(|index| MigrationRollbackEntry {
                    path: format!("src/oversized-{index}.js"),
                    original_content: "old".to_string(),
                    rewritten_content: "new".to_string(),
                }));
            plan.entry_count = plan.entries.len();
            assert!(matches!(
                validate_rollback_plan(&plan, &policy),
                Err(MigrationRollbackValidationError::TooManyEntries { .. })
            ));
        }
        "stale" => {
            let mut plan = migration_plan();
            plan.schema_version = "0.0.0-stale".to_string();
            assert!(matches!(
                validate_rollback_plan(&plan, &policy),
                Err(MigrationRollbackValidationError::UnsupportedSchemaVersion { .. })
            ));
        }
        "malformed_signature_or_hash" => {
            let mut plan = migration_plan();
            plan.entry_count = plan.entries.len().saturating_add(1);
            assert!(matches!(
                validate_rollback_plan(&plan, &policy),
                Err(MigrationRollbackValidationError::EntryCountMismatch { .. })
            ));
        }
        "path_safety" => {
            let mut plan = migration_plan();
            plan.entries[0].path = "../package.json".to_string();
            assert!(matches!(
                validate_rollback_plan(&plan, &policy),
                Err(MigrationRollbackValidationError::ParentTraversal { .. })
            ));
        }
        other => assert_eq!(
            other, "",
            "{} has unknown migration seed class {other}",
            seed.id
        ),
    }
}

fn exercise_validation_receipt_seed(seed: &SeedCase) {
    let now = ts(3);
    let mut receipt = validation_receipt();
    match seed.seed_class.as_str() {
        "valid" => {
            let parsed: ValidationReceipt =
                serde_json::from_value(serde_json::to_value(&receipt).expect("receipt JSON"))
                    .expect("valid receipt should parse");
            parsed
                .validate_at(now)
                .expect("valid receipt should validate");
        }
        "missing_field" => {
            let mut value = serde_json::to_value(&receipt).expect("receipt JSON");
            value
                .as_object_mut()
                .expect("receipt seed is object")
                .remove("request_id");
            assert!(
                serde_json::from_value::<ValidationReceipt>(value).is_err(),
                "{} should reject missing request_id",
                seed.id
            );
        }
        "oversized" => {
            receipt.input_digests.extend((0..80).map(|index| {
                InputDigest::new(
                    format!("src/oversized-input-{index:03}.rs"),
                    format!("input-{index:03}").as_bytes(),
                    "source-tree",
                )
            }));
            let parsed: ValidationReceipt =
                serde_json::from_value(serde_json::to_value(&receipt).expect("receipt JSON"))
                    .expect("oversized receipt should parse");
            assert!(parsed.input_digests.len() > 80);
            parsed
                .validate_at(now)
                .expect("oversized digest-list receipt still has valid digests");
        }
        "stale" => {
            receipt.timing.freshness_expires_at = ts(2);
            assert_contract_code(
                receipt.validate_at(now),
                error_codes::ERR_VB_STALE_RECEIPT,
                seed,
            );
        }
        "malformed_signature_or_hash" => {
            receipt.command_digest.hex = "0".repeat(64);
            assert_contract_code(
                receipt.validate_at(now),
                error_codes::ERR_VB_MISSING_COMMAND_DIGEST,
                seed,
            );
        }
        "path_safety" => {
            receipt.readiness_ref = Some(ValidationReadinessRef {
                schema_version: READINESS_REF_SCHEMA_VERSION.to_string(),
                path: "../proof/readiness.json".to_string(),
                digest: DigestRef::sha256(b"readiness"),
                generated_at: ts(1),
                freshness_expires_at: ts(10),
                reason_code: "SPEC_DERIVED_PATH_SAFETY".to_string(),
                event_code: "SPEC-SEED-001".to_string(),
                required_action: "reject traversal path".to_string(),
            });
            assert_contract_code(
                receipt.validate_at(now),
                error_codes::ERR_VB_INVALID_READINESS_REF,
                seed,
            );
        }
        other => assert_eq!(
            other, "",
            "{} has unknown validation receipt seed class {other}",
            seed.id
        ),
    }
}

fn trust_card_value() -> Value {
    json!({
        "schema_version": "trust-card-v1.0",
        "trust_card_version": 1,
        "previous_version_hash": null,
        "extension": {
            "extension_id": "npm:@spec-derived/trust-card",
            "version": "1.0.0"
        },
        "publisher": {
            "publisher_id": "publisher-spec-derived",
            "display_name": "Spec Derived Publisher"
        },
        "certification_level": "gold",
        "capability_declarations": [{
            "name": "network.egress",
            "description": "Outbound API access",
            "risk": "medium"
        }],
        "behavioral_profile": {
            "network_access": true,
            "filesystem_access": false,
            "subprocess_access": false,
            "profile_summary": "Spec-derived trust card seed"
        },
        "revocation_status": {
            "status": "active"
        },
        "provenance_summary": {
            "attestation_level": "slsa-3",
            "source_uri": "https://example.com/spec-derived/trust-card",
            "artifact_hashes": ["sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"],
            "verified_at": "2026-05-09T16:12:00Z"
        },
        "reputation_score_basis_points": 9000,
        "reputation_trend": "stable",
        "active_quarantine": false,
        "dependency_trust_summary": [{
            "dependency_id": "npm:left-pad@1.3.0",
            "trust_level": "verified"
        }],
        "last_verified_timestamp": "2026-05-09T16:12:00Z",
        "user_facing_risk_assessment": {
            "level": "medium",
            "summary": "Fixture risk summary"
        },
        "audit_history": [{
            "timestamp": "2026-05-09T16:12:00Z",
            "event_code": "SPEC_DERIVED_TRUST_CARD",
            "detail": "Seed generated from trust-card schema",
            "trace_id": "trace-trust-card-seed"
        }],
        "derivation_evidence": null,
        "card_hash": "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        "registry_signature": "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
    })
}

fn replay_bundle_value(seed_id: &str) -> Value {
    let events = vec![
        RawEvent::new(
            "2026-02-20T12:00:00.000001Z",
            EventType::StateChange,
            json!({"seed_id": seed_id, "state": "before"}),
        ),
        RawEvent::new(
            "2026-02-20T12:00:01.000001Z",
            EventType::OperatorAction,
            json!({"seed_id": seed_id, "command": "validate"}),
        ),
    ];
    let mut bundle = generate_replay_bundle(&format!("INC-SPEC-SEED-{seed_id}"), &events)
        .expect("spec-derived replay bundle should generate");
    let signing_key = replay_seed_signing_key();
    let signing_material = ReplayBundleSigningMaterial {
        signing_key: &signing_key,
        key_source: "env",
        signing_identity: "spec-derived-fuzz-seed",
    };
    sign_replay_bundle(&mut bundle, &signing_material)
        .expect("spec-derived replay bundle should sign");
    serde_json::to_value(bundle).expect("replay bundle should serialize")
}

fn replay_seed_signing_key() -> ed25519_dalek::SigningKey {
    ed25519_dalek::SigningKey::from_bytes(&[37_u8; 32])
}

fn replay_seed_trusted_key_id() -> String {
    let signing_key = replay_seed_signing_key();
    frankenengine_node::supply_chain::artifact_signing::KeyId::from_verifying_key(
        &signing_key.verifying_key(),
    )
    .to_string()
}

fn issued_remote_cap(now: u64, ttl: u64, endpoint_prefix: &str) -> RemoteCap {
    let provider = CapabilityProvider::new(REMOTE_KEY_MATERIAL).expect("remote cap provider");
    let scope = RemoteScope::new(
        vec![RemoteOperation::NetworkEgress],
        vec![endpoint_prefix.to_string()],
    );
    let (cap, _audit) = provider
        .issue(
            "spec-derived-agent",
            scope,
            now,
            ttl,
            true,
            false,
            "trace-spec-derived-remote-cap",
        )
        .expect("remote cap seed should issue");
    cap
}

fn migration_plan() -> MigrationRollbackPlan {
    MigrationRollbackPlan {
        schema_version: "1.0.0".to_string(),
        project_path: "/tmp/franken-node-spec-derived".to_string(),
        generated_at_utc: "2026-05-09T16:12:00Z".to_string(),
        apply_mode: false,
        entry_count: 1,
        entries: vec![MigrationRollbackEntry {
            path: "src/index.js".to_string(),
            original_content: "console.log('old');".to_string(),
            rewritten_content: "console.log('new');".to_string(),
        }],
    }
}

fn validation_receipt() -> ValidationReceipt {
    let command = CommandSpec {
        program: "cargo".to_string(),
        argv: vec![
            "test".to_string(),
            "-p".to_string(),
            "frankenengine-node".to_string(),
            "spec_derived_fuzz_seeds".to_string(),
        ],
        cwd: "/data/projects/franken_node".to_string(),
        environment_policy_id: "env-rch-remote-required".to_string(),
        target_dir_policy_id: "target-off-repo".to_string(),
    };
    let command_digest = command.digest();
    let input_digest = InputDigest::new(
        "artifacts/spec_derived_fuzz_seeds/bd-38hez.12/spec_derived_fuzz_seed_manifest.json",
        MANIFEST_JSON.as_bytes(),
        "manifest",
    );

    ValidationReceipt {
        schema_version: RECEIPT_SCHEMA_VERSION.to_string(),
        receipt_id: "vbrcpt-bd-38hez-12-spec-seeds".to_string(),
        request_id: "vbreq-bd-38hez-12-spec-seeds".to_string(),
        bead_id: "bd-38hez.12".to_string(),
        thread_id: "bd-38hez.12".to_string(),
        request_ref: ReceiptRequestRef {
            request_id: "vbreq-bd-38hez-12-spec-seeds".to_string(),
            bead_id: "bd-38hez.12".to_string(),
            thread_id: "bd-38hez.12".to_string(),
            dedupe_key: DigestRef::from_command_digest(&command_digest),
            cross_thread_waiver: None,
        },
        command,
        command_digest,
        environment_policy: EnvironmentPolicy {
            policy_id: "env-rch-remote-required".to_string(),
            allowed_env: vec![
                "RCH_REQUIRE_REMOTE".to_string(),
                "CARGO_TARGET_DIR".to_string(),
            ],
            redacted_env: Vec::new(),
            remote_required: true,
            network_policy: "rch-only".to_string(),
        },
        target_dir_policy: TargetDirPolicy {
            policy_id: "target-off-repo".to_string(),
            kind: "off_repo".to_string(),
            path: "/data/tmp/franken_node-spec-derived-fuzz-seeds-target".to_string(),
            path_digest: DigestRef::sha256(
                b"/data/tmp/franken_node-spec-derived-fuzz-seeds-target",
            ),
            cleanup: "best_effort_after_receipt".to_string(),
        },
        input_digests: vec![input_digest],
        rch: RchReceipt {
            mode: RchMode::Remote,
            worker_id: Some("vmi-spec-derived".to_string()),
            require_remote: true,
            capability_observation_id: Some("vbobs-spec-derived".to_string()),
            worker_pool: "default".to_string(),
        },
        timing: ValidationTiming {
            started_at: ts(1),
            finished_at: ts(2),
            duration_ms: 1_000,
            freshness_expires_at: ts(10),
        },
        exit: ValidationExit {
            kind: ValidationExitKind::Success,
            code: Some(0),
            signal: None,
            timeout_class: TimeoutClass::None,
            error_class: ValidationErrorClass::None,
            retryable: false,
        },
        artifacts: ReceiptArtifacts {
            stdout_path: "artifacts/spec_derived_fuzz_seeds/bd-38hez.12/stdout.txt".to_string(),
            stderr_path: "artifacts/spec_derived_fuzz_seeds/bd-38hez.12/stderr.txt".to_string(),
            summary_path: "artifacts/spec_derived_fuzz_seeds/bd-38hez.12/summary.json".to_string(),
            receipt_path: "artifacts/spec_derived_fuzz_seeds/bd-38hez.12/receipt.json".to_string(),
            stdout_digest: DigestRef::sha256(b"stdout"),
            stderr_digest: DigestRef::sha256(b"stderr"),
        },
        readiness_ref: None,
        flight_recorder_ref: None,
        trust: ReceiptTrust {
            generated_by: "spec_derived_fuzz_seeds".to_string(),
            agent_name: "SnowyBeaver".to_string(),
            git_commit: "cfe3d66101c14e7b39b77dc538221a0275fb7754".to_string(),
            dirty_worktree: true,
            freshness: "fresh".to_string(),
            signature_status: "unsigned-test-fixture".to_string(),
        },
        classifications: ReceiptClassifications {
            source_only_fallback: false,
            source_only_reason: None::<SourceOnlyReason>,
            doctor_readiness: "ready".to_string(),
            ci_consumable: true,
        },
    }
}

fn assert_contract_code(
    result: Result<(), ValidationBrokerError>,
    expected_code: &'static str,
    seed: &SeedCase,
) {
    match result {
        Err(ValidationBrokerError::ContractViolation { code, .. }) => {
            assert_eq!(code, expected_code, "{} returned wrong error code", seed.id);
        }
        other => assert_eq!(
            format!("{other:?}"),
            "",
            "{} should return validation broker code {expected_code}, got {other:?}",
            seed.id
        ),
    }
}

fn ts(offset_seconds: i64) -> DateTime<Utc> {
    DateTime::parse_from_rfc3339("2026-05-09T16:12:00Z")
        .expect("base timestamp")
        .with_timezone(&Utc)
        + chrono::Duration::seconds(offset_seconds)
}
