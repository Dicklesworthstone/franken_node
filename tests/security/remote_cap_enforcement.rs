//! Security tests for bd-1nfu RemoteCap enforcement.
//!
//! Verifies:
//! - network-bound operations fail without RemoteCap
//! - signature/expiry/scope/replay/revocation checks are fail-closed
//! - local-only operations remain functional without RemoteCap
//! - network guard enforces centralized capability gate

use std::fs;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::path::Path;
use std::process::Command;
use std::sync::{Arc, Mutex, Once};

use ed25519_dalek::{Signer, SigningKey};
use frankenengine_node::security::impossible_default::{
    CapabilityEnforcer, CapabilityToken, ERR_IBD_SUBJECT_MISMATCH, ImpossibleCapability,
};
use frankenengine_node::security::network_guard::{
    Action, EgressPolicy, EgressRule, NetworkGuard, Protocol,
};
use frankenengine_node::security::remote_cap::{
    CapabilityGate, CapabilityProvider, ConnectivityMode, RemoteOperation, RemoteScope,
};
use frankenengine_node::supply_chain::certification::{EvidenceType, VerifiedEvidenceRef};
use frankenengine_node::supply_chain::trust_card::{
    BehavioralProfile, CapabilityDeclaration, CapabilityRisk, CertificationLevel,
    DependencyTrustStatus, ExtensionIdentity, ProvenanceSummary, PublisherIdentity,
    ReputationTrend, RevocationStatus, RiskAssessment, RiskLevel, TrustCardInput,
    TrustCardRegistry,
};

static TEST_TRACING_INIT: Once = Once::new();

fn provider() -> CapabilityProvider {
    CapabilityProvider::new("remote-cap-test-secret")
        .expect("remote cap test signing secret should be valid")
}

fn init_test_tracing() {
    TEST_TRACING_INIT.call_once(|| {
        let _ = tracing_subscriber::fmt().with_test_writer().try_init();
    });
}

fn read_http_request(stream: &mut impl Read) -> String {
    let mut buffer = Vec::new();
    let mut chunk = [0_u8; 1024];

    loop {
        let bytes_read = stream.read(&mut chunk).expect("read request chunk");
        if bytes_read == 0 {
            break;
        }
        buffer.extend_from_slice(&chunk[..bytes_read]);

        let Some(headers_end) = buffer.windows(4).position(|window| window == b"\r\n\r\n") else {
            continue;
        };
        let headers = String::from_utf8_lossy(&buffer[..headers_end + 4]);
        let content_length = headers
            .lines()
            .find_map(|line| {
                let (name, value) = line.split_once(':')?;
                name.eq_ignore_ascii_case("Content-Length")
                    .then(|| value.trim().parse::<usize>().ok())
                    .flatten()
            })
            .unwrap_or(0);
        let total_length = headers_end + 4 + content_length;
        if buffer.len() >= total_length {
            break;
        }
    }

    String::from_utf8_lossy(&buffer).to_string()
}

fn spawn_osv_fixture_server() -> (String, Arc<Mutex<Vec<String>>>, std::thread::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind OSV fixture server");
    let address = format!("http://{}", listener.local_addr().expect("local addr"));
    let requests = Arc::new(Mutex::new(Vec::new()));
    let captured_requests = Arc::clone(&requests);

    let handle = std::thread::spawn(move || {
        for stream in listener.incoming().take(2) {
            let mut stream = stream.expect("accept fixture connection");
            let request = read_http_request(&mut stream);
            let body = request
                .split("\r\n\r\n")
                .nth(1)
                .unwrap_or_default()
                .to_string();
            captured_requests
                .lock()
                .expect("lock requests")
                .push(body.clone());

            let (status_code, status_text, response_body) = if body.contains("\"@acme/auth-guard\"")
            {
                (
                    200,
                    "OK",
                    r#"{"vulns":[{"id":"OSV-2026-0001"}]}"#.to_string(),
                )
            } else if body.contains("\"@beta/telemetry-bridge\"") {
                (
                    503,
                    "Service Unavailable",
                    r#"{"error":"upstream unavailable"}"#.to_string(),
                )
            } else {
                (
                    404,
                    "Not Found",
                    r#"{"error":"unexpected package"}"#.to_string(),
                )
            };

            let response = format!(
                "HTTP/1.1 {status_code} {status_text}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                response_body.len(),
                response_body
            );
            stream
                .write_all(response.as_bytes())
                .expect("write fixture response");
        }
    });

    (format!("{address}/query"), requests, handle)
}

fn spawn_osv_observer_server() -> (String, Arc<Mutex<usize>>, std::thread::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind observer server");
    listener
        .set_nonblocking(true)
        .expect("set observer listener nonblocking");
    let address = format!("http://{}", listener.local_addr().expect("local addr"));
    let request_count = Arc::new(Mutex::new(0_usize));
    let captured_count = Arc::clone(&request_count);

    let handle = std::thread::spawn(move || {
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
        while std::time::Instant::now() < deadline {
            match listener.accept() {
                Ok((mut stream, _)) => {
                    let _ = read_http_request(&mut stream);
                    *captured_count.lock().expect("lock observer count") += 1;
                    let response_body = r#"{"vulns":[]}"#;
                    let response = format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                        response_body.len(),
                        response_body
                    );
                    stream
                        .write_all(response.as_bytes())
                        .expect("write observer response");
                }
                Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => {
                    std::thread::sleep(std::time::Duration::from_millis(10));
                }
                Err(err) => panic!("observer accept failed: {err}"),
            }
        }
    });

    (format!("{address}/query"), request_count, handle)
}

fn seeded_fixture_trust_workspace() -> tempfile::TempDir {
    let dir = tempfile::tempdir().expect("tempdir");
    fs::write(
        dir.path().join("franken_node.toml"),
        "profile = \"balanced\"\n",
    )
    .expect("write config");

    let mut registry = TrustCardRegistry::default();
    registry
        .create(
            TrustCardInput {
                extension: ExtensionIdentity {
                    extension_id: "npm:@acme/auth-guard".to_string(),
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
                    source_uri:
                        "https://registry.npmjs.org/@acme/auth-guard/-/auth-guard-1.4.2.tgz"
                            .to_string(),
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
                        verified_at_epoch: 1_000,
                        verification_receipt_hash: "a".repeat(64),
                    },
                    VerifiedEvidenceRef {
                        evidence_id: "ev-fixture-rep-001".to_string(),
                        evidence_type: EvidenceType::ReputationSignal,
                        verified_at_epoch: 1_000,
                        verification_receipt_hash: "b".repeat(64),
                    },
                ],
            },
            1_000,
            "trace-remote-cap-fixture-auth-guard",
        )
        .expect("create auth-guard trust card");
    registry
        .create(
            TrustCardInput {
                extension: ExtensionIdentity {
                    extension_id: "npm:@beta/telemetry-bridge".to_string(),
                    version: "0.9.1".to_string(),
                },
                publisher: PublisherIdentity {
                    publisher_id: "pub-beta".to_string(),
                    display_name: "Beta Labs".to_string(),
                },
                certification_level: CertificationLevel::Silver,
                capability_declarations: vec![CapabilityDeclaration {
                    name: "telemetry.forward".to_string(),
                    description: "Forward runtime telemetry to remote collector".to_string(),
                    risk: CapabilityRisk::High,
                }],
                behavioral_profile: BehavioralProfile {
                    network_access: true,
                    filesystem_access: true,
                    subprocess_access: false,
                    profile_summary: "Network telemetry forwarding with local spool fallback"
                        .to_string(),
                },
                revocation_status: RevocationStatus::Active,
                provenance_summary: ProvenanceSummary {
                    attestation_level: "slsa-l2".to_string(),
                    source_uri: "https://registry.npmjs.org/@beta/telemetry-bridge/-/telemetry-bridge-0.9.1.tgz"
                        .to_string(),
                    artifact_hashes: vec![format!("sha256:deadbeef{}", "b".repeat(56))],
                    verified_at: "2026-02-20T12:00:00Z".to_string(),
                },
                reputation_score_basis_points: 640,
                reputation_trend: ReputationTrend::Stable,
                active_quarantine: false,
                dependency_trust_summary: vec![DependencyTrustStatus {
                    dependency_id: "npm:ws@8".to_string(),
                    trust_level: "conditional".to_string(),
                }],
                last_verified_timestamp: "2026-02-20T12:00:00Z".to_string(),
                user_facing_risk_assessment: RiskAssessment {
                    level: RiskLevel::Medium,
                    summary:
                        "Telemetry egress remains operator-reviewed because runtime signals leave the host"
                            .to_string(),
                },
                evidence_refs: vec![
                    VerifiedEvidenceRef {
                        evidence_id: "ev-fixture-prov-002".to_string(),
                        evidence_type: EvidenceType::ProvenanceChain,
                        verified_at_epoch: 1_000,
                        verification_receipt_hash: "c".repeat(64),
                    },
                    VerifiedEvidenceRef {
                        evidence_id: "ev-fixture-rep-002".to_string(),
                        evidence_type: EvidenceType::ReputationSignal,
                        verified_at_epoch: 1_000,
                        verification_receipt_hash: "d".repeat(64),
                    },
                ],
            },
            1_000,
            "trace-remote-cap-fixture-telemetry-bridge",
        )
        .expect("create telemetry-bridge trust card");
    let path = dir
        .path()
        .join(".franken-node/state/trust-card-registry.v1.json");
    registry
        .persist_authoritative_state(&path)
        .expect("persist trust registry");
    fs::write(
        dir.path()
            .join(".franken-node/state/trust-card-registry.fixture-source.json"),
        concat!(
            "{\n",
            "  \"source_helper\": \"fixture_registry\",\n",
            "  \"purpose\": \"remote-cap-enforcement deterministic fixture seed\",\n",
            "  \"authoritative_state_path\": \".franken-node/state/trust-card-registry.v1.json\"\n",
            "}\n"
        ),
    )
    .expect("write fixture metadata");
    dir
}

fn write_remotecap_token(path: &Path, cap: &frankenengine_node::security::remote_cap::RemoteCap) {
    fs::write(
        path,
        serde_json::to_vec_pretty(&serde_json::json!({ "token": cap })).expect("token JSON"),
    )
    .expect("write token");
}

fn write_scannable_trust_workspace(workspace: &std::path::Path) {
    fs::write(
        workspace.join("franken_node.toml"),
        "profile = \"balanced\"\n",
    )
    .expect("write config");
    fs::write(
        workspace.join("package.json"),
        r#"{"name":"remote-cap-scan","version":"1.0.0","dependencies":{"left-pad":"1.3.0"}}"#,
    )
    .expect("write package manifest");
}

#[test]
fn capability_provider_debug_redacts_signing_secret() {
    let secret = "debug-provider-secret-do-not-leak";
    let provider = CapabilityProvider::new(secret).expect("provider secret should be valid");

    let rendered = format!("{provider:?}");

    assert!(rendered.contains("CapabilityProvider"));
    assert!(rendered.contains("<redacted>"));
    assert!(!rendered.contains(secret));
}

#[test]
fn capability_gate_debug_redacts_verification_secret() {
    let secret = "debug-gate-secret-do-not-leak";
    let gate = CapabilityGate::new(secret).expect("gate secret should be valid");

    let rendered = format!("{gate:?}");

    assert!(rendered.contains("CapabilityGate"));
    assert!(rendered.contains("<redacted>"));
    assert!(rendered.contains("Connected"));
    assert!(!rendered.contains(secret));
}

fn full_scope() -> RemoteScope {
    RemoteScope::new(
        vec![
            RemoteOperation::NetworkEgress,
            RemoteOperation::FederationSync,
            RemoteOperation::RevocationFetch,
            RemoteOperation::RemoteAttestationVerify,
            RemoteOperation::TelemetryExport,
        ],
        vec![
            "http://api.example.com".to_string(),
            "http://egress.example.com".to_string(),
            "https://egress.example.com".to_string(),
            "https://api.example.com".to_string(),
            "https://attestation.example.com".to_string(),
            "https://telemetry.example.com".to_string(),
            "revocation://global-feed".to_string(),
            "federation://cluster-a".to_string(),
        ],
    )
}

fn issue_cap(single_use: bool) -> frankenengine_node::security::remote_cap::RemoteCap {
    provider()
        .issue(
            "ops-control-plane",
            full_scope(),
            1_700_000_000,
            3_600,
            true,
            single_use,
            "trace-issue",
        )
        .expect("issue")
        .0
}

fn sign_impossible_default_token(token: &mut CapabilityToken, signing_key: &SigningKey) {
    let hash = token.content_hash();
    let signature = signing_key.sign(hash.as_bytes());
    token.signature = hex::encode(signature.to_bytes());
}

fn impossible_default_token_for(
    subject: &str,
    capability: ImpossibleCapability,
    signing_key: &SigningKey,
) -> CapabilityToken {
    let mut token = CapabilityToken {
        token_id: format!("subject-bound-{}", capability.label()),
        capability,
        issuer: "security-test-issuer".to_string(),
        subject: subject.to_string(),
        issued_at_ms: 1_700_000_000_000,
        expires_at_ms: 1_700_000_060_000,
        signature: String::new(),
        justification: "subject-bound capability regression".to_string(),
    };
    sign_impossible_default_token(&mut token, signing_key);
    token
}

#[test]
fn all_network_operations_require_token() {
    let mut gate = CapabilityGate::new("remote-cap-test-secret")
        .expect("remote cap test gate should be valid");

    let ops = [
        (RemoteOperation::NetworkEgress, "https://egress.example.com"),
        (RemoteOperation::FederationSync, "federation://cluster-a"),
        (
            RemoteOperation::RevocationFetch,
            "revocation://global-feed/latest",
        ),
        (
            RemoteOperation::RemoteAttestationVerify,
            "https://attestation.example.com/verify",
        ),
        (
            RemoteOperation::TelemetryExport,
            "https://telemetry.example.com/push",
        ),
    ];

    for (idx, (operation, endpoint)) in ops.iter().enumerate() {
        let err = gate
            .authorize_network(
                None,
                *operation,
                endpoint,
                1_700_000_100 + idx as u64,
                "trace-missing",
            )
            .expect_err("missing token should fail");
        assert_eq!(err.code(), "REMOTECAP_MISSING");
        assert_eq!(err.compatibility_code(), Some("ERR_REMOTE_CAP_REQUIRED"));
    }
}

#[test]
fn remote_cap_signed_subject_mismatch_is_rejected() {
    let signing_key = SigningKey::from_bytes(&[0x42; 32]);
    let capability = ImpossibleCapability::OutboundNetwork;
    let token = impossible_default_token_for("subject-a", capability, &signing_key);
    let mut enforcer = CapabilityEnforcer::with_ed25519_verifier(signing_key.verifying_key());

    let mismatch_err = enforcer
        .opt_in(token.clone(), "subject-b", 1_700_000_001_000)
        .expect_err("token signed for subject A must not opt in subject B");
    assert_eq!(mismatch_err.code, ERR_IBD_SUBJECT_MISMATCH);
    assert!(!enforcer.is_enabled(capability));
    assert_eq!(
        enforcer
            .audit_log()
            .last()
            .map(|entry| entry.event_code.as_str()),
        Some(ERR_IBD_SUBJECT_MISMATCH)
    );

    enforcer
        .opt_in(token, "subject-a", 1_700_000_001_000)
        .expect("signed subject may opt in itself");
    enforcer
        .enforce(capability, "subject-a", 1_700_000_002_000)
        .expect("signed subject may use its capability");

    let cross_actor_err = enforcer
        .enforce(capability, "subject-b", 1_700_000_003_000)
        .expect_err("enabled capability must not become global");
    assert_eq!(cross_actor_err.code, ERR_IBD_SUBJECT_MISMATCH);
}

#[test]
fn valid_token_allows_scoped_operations() {
    let cap = issue_cap(false);
    let mut gate = CapabilityGate::new("remote-cap-test-secret")
        .expect("remote cap test gate should be valid");
    gate.authorize_network(
        Some(&cap),
        RemoteOperation::FederationSync,
        "federation://cluster-a",
        1_700_000_010,
        "trace-ok",
    )
    .expect("scoped operation should pass");
}

#[test]
fn forged_signature_is_rejected() {
    let cap = issue_cap(false);
    let mut tampered = serde_json::to_value(&cap).expect("to value");
    tampered["signature"] = serde_json::Value::String("forged-signature".to_string());
    let forged: frankenengine_node::security::remote_cap::RemoteCap =
        serde_json::from_value(tampered).expect("from value");

    let mut gate = CapabilityGate::new("remote-cap-test-secret")
        .expect("remote cap test gate should be valid");
    let err = gate
        .authorize_network(
            Some(&forged),
            RemoteOperation::TelemetryExport,
            "https://telemetry.example.com/push",
            1_700_000_020,
            "trace-forge",
        )
        .expect_err("forged token must fail");
    assert_eq!(err.code(), "REMOTECAP_INVALID");
}

#[test]
fn expired_token_is_rejected() {
    let cap = provider()
        .issue(
            "ops-control-plane",
            full_scope(),
            1_700_000_000,
            5,
            true,
            false,
            "trace-expired-issue",
        )
        .expect("issue")
        .0;
    let mut gate = CapabilityGate::new("remote-cap-test-secret")
        .expect("remote cap test gate should be valid");
    let err = gate
        .authorize_network(
            Some(&cap),
            RemoteOperation::RevocationFetch,
            "revocation://global-feed/latest",
            1_700_000_100,
            "trace-expired-use",
        )
        .expect_err("expired token must fail");
    assert_eq!(err.code(), "REMOTECAP_EXPIRED");
}

#[test]
fn scope_escalation_is_rejected() {
    let narrow_scope = RemoteScope::new(
        vec![RemoteOperation::TelemetryExport],
        vec!["https://telemetry.example.com".to_string()],
    );
    let cap = provider()
        .issue(
            "ops-control-plane",
            narrow_scope,
            1_700_000_000,
            3_600,
            true,
            false,
            "trace-narrow-issue",
        )
        .expect("issue")
        .0;

    let mut gate = CapabilityGate::new("remote-cap-test-secret")
        .expect("remote cap test gate should be valid");
    let err = gate
        .authorize_network(
            Some(&cap),
            RemoteOperation::FederationSync,
            "federation://cluster-a",
            1_700_000_010,
            "trace-scope-denied",
        )
        .expect_err("out-of-scope operation must fail");
    assert_eq!(err.code(), "REMOTECAP_SCOPE_DENIED");
}

#[test]
fn replay_of_consumed_single_use_token_is_rejected() {
    let cap = issue_cap(true);
    let mut gate = CapabilityGate::new("remote-cap-test-secret")
        .expect("remote cap test gate should be valid");
    gate.authorize_network(
        Some(&cap),
        RemoteOperation::TelemetryExport,
        "https://telemetry.example.com/push",
        1_700_000_010,
        "trace-replay-first",
    )
    .expect("first use should pass");

    let err = gate
        .authorize_network(
            Some(&cap),
            RemoteOperation::TelemetryExport,
            "https://telemetry.example.com/push",
            1_700_000_011,
            "trace-replay-second",
        )
        .expect_err("replay must fail");
    assert_eq!(err.code(), "REMOTECAP_REPLAY");
}

#[test]
fn revocation_blocks_previously_valid_token() {
    let cap = issue_cap(false);
    let mut gate = CapabilityGate::new("remote-cap-test-secret")
        .expect("remote cap test gate should be valid");
    gate.revoke(&cap, 1_700_000_020, "trace-revoke");

    let err = gate
        .authorize_network(
            Some(&cap),
            RemoteOperation::RevocationFetch,
            "revocation://global-feed/latest",
            1_700_000_021,
            "trace-after-revoke",
        )
        .expect_err("revoked token must fail");
    assert_eq!(err.code(), "REMOTECAP_REVOKED");
}

#[test]
fn local_only_mode_keeps_local_ops_functional() {
    let mut gate = CapabilityGate::with_mode("remote-cap-test-secret", ConnectivityMode::LocalOnly)
        .expect("remote cap test gate should be valid");
    gate.authorize_local_operation("evidence_ledger_append", 1_700_000_030, "trace-local-op");
    let event = gate.audit_log().last().expect("local event");
    assert_eq!(event.event_code, "REMOTECAP_LOCAL_MODE_ACTIVE");
    assert!(event.allowed);
}

#[test]
fn network_guard_is_enforced_by_capability_gate() {
    let mut policy = EgressPolicy::new("conn-remote-cap".to_string(), Action::Deny);
    policy
        .add_rule(EgressRule {
            host: "api.example.com".to_string(),
            port: Some(443),
            action: Action::Allow,
            protocol: Protocol::Http,
        })
        .expect("add rule");
    let mut guard = NetworkGuard::new(policy);
    let mut gate = CapabilityGate::new("remote-cap-test-secret")
        .expect("remote cap test gate should be valid");

    let err = guard
        .process_egress(
            "api.example.com",
            443,
            Protocol::Http,
            None,
            &mut gate,
            "trace-guard-missing",
            "ts",
            1_700_000_040,
        )
        .expect_err("missing cap must fail before policy allow");

    match err {
        frankenengine_node::security::network_guard::GuardError::RemoteCapDenied {
            code, ..
        } => {
            assert_eq!(code, "REMOTECAP_MISSING");
        }
        other => panic!("expected GuardError::RemoteCapDenied, got {other:?}"),
    }

    let cap = issue_cap(false);
    let ok = guard.process_egress(
        "api.example.com",
        443,
        Protocol::Http,
        Some(&cap),
        &mut gate,
        "trace-guard-ok",
        "ts",
        1_700_000_041,
    );
    assert!(ok.is_ok(), "valid cap should permit policy evaluation");
}

#[test]
fn osv_trust_sync_network_egress_requires_authorization() {
    init_test_tracing();

    let secret = "osv-test-secret";
    let workspace = seeded_fixture_trust_workspace();
    tracing::info!(
        phase = "workspace_seeded",
        workspace = %workspace.path().display(),
        "seeded authoritative trust registry for CLI trust sync"
    );

    let (blocked_osv_url, blocked_request_count, blocked_server) = spawn_osv_observer_server();
    tracing::info!(
        phase = "observer_server_started",
        osv_url = %blocked_osv_url,
        "started observer server for unauthenticated trust sync"
    );

    let blocked = Command::new(env!("CARGO_BIN_EXE_franken-node"))
        .current_dir(workspace.path())
        .env("FRANKEN_NODE_REMOTECAP_KEY", secret)
        .env("FRANKEN_NODE_OSV_QUERY_URL", &blocked_osv_url)
        .args(["trust", "sync", "--force"])
        .output()
        .expect("run unauthenticated trust sync");
    tracing::info!(
        phase = "unauthenticated_sync_completed",
        success = blocked.status.success(),
        stdout_len = blocked.stdout.len(),
        stderr_len = blocked.stderr.len(),
        "completed trust sync without RemoteCap token"
    );

    blocked_server.join().expect("join observer server");
    let blocked_requests = *blocked_request_count.lock().expect("lock observer count");
    let blocked_stdout = String::from_utf8_lossy(&blocked.stdout);
    let blocked_stderr = String::from_utf8_lossy(&blocked.stderr);
    tracing::info!(
        phase = "unauthenticated_sync_observed",
        request_count = blocked_requests,
        stdout = %blocked_stdout,
        stderr = %blocked_stderr,
        "captured unauthenticated trust sync outputs"
    );
    assert_eq!(
        blocked_requests, 0,
        "trust sync should fail closed before OSV egress without RemoteCap:\nstdout:\n{blocked_stdout}\nstderr:\n{blocked_stderr}"
    );
    assert!(
        blocked_stderr.contains("REMOTECAP_MISSING"),
        "unauthenticated trust sync should surface RemoteCap denial:\nstdout:\n{blocked_stdout}\nstderr:\n{blocked_stderr}"
    );

    let (osv_url, requests, server) = spawn_osv_fixture_server();
    tracing::info!(
        phase = "fixture_server_started",
        osv_url = %osv_url,
        "started OSV fixture server for authorized trust sync"
    );

    let now_epoch_secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system clock after epoch")
        .as_secs();
    let provider = CapabilityProvider::new(secret).expect("OSV test provider should be valid");
    let (cap, _audit_event) = provider
        .issue(
            "test-issuer",
            RemoteScope::new(vec![RemoteOperation::NetworkEgress], vec![osv_url.clone()]),
            now_epoch_secs,
            3_600,
            true,
            false,
            "trace-osv-issue",
        )
        .expect("OSV test cap should be valid");
    tracing::info!(
        phase = "cap_issued",
        token_id = %cap.token_id(),
        issued_at_epoch_secs = cap.issued_at_epoch_secs(),
        expires_at_epoch_secs = cap.expires_at_epoch_secs(),
        "issued RemoteCap token for trust sync"
    );

    let token_path = workspace.path().join("capability.json");
    write_remotecap_token(&token_path, &cap);
    tracing::info!(
        phase = "token_written",
        token_path = %token_path.display(),
        "wrote RemoteCap token to disk"
    );

    let authorized = Command::new(env!("CARGO_BIN_EXE_franken-node"))
        .current_dir(workspace.path())
        .env("FRANKEN_NODE_REMOTECAP_KEY", secret)
        .env("FRANKEN_NODE_OSV_QUERY_URL", &osv_url)
        .env("FRANKEN_NODE_TRUST_SCAN_REMOTECAP_TOKEN", &token_path)
        .args(["trust", "sync", "--force"])
        .output()
        .expect("run authorized trust sync");
    tracing::info!(
        phase = "authorized_sync_completed",
        success = authorized.status.success(),
        stdout_len = authorized.stdout.len(),
        stderr_len = authorized.stderr.len(),
        "completed trust sync with authorized RemoteCap token"
    );

    server.join().expect("join OSV fixture server");
    let request_bodies = requests.lock().expect("lock requests").clone();
    let stdout = String::from_utf8_lossy(&authorized.stdout);
    let stderr = String::from_utf8_lossy(&authorized.stderr);
    tracing::info!(
        phase = "authorized_sync_observed",
        request_count = request_bodies.len(),
        stdout = %stdout,
        stderr = %stderr,
        "captured authorized trust sync outputs"
    );

    assert!(
        authorized.status.success(),
        "authorized trust sync should succeed:\nstdout:\n{stdout}\nstderr:\n{stderr}"
    );
    assert_eq!(
        request_bodies.len(),
        2,
        "authorized trust sync should reach the OSV network boundary for both seeded cards:\nrequests:\n{request_bodies:#?}\nstdout:\n{stdout}\nstderr:\n{stderr}"
    );
    assert!(stdout.contains("trust sync completed: force=true"));
    assert!(stdout.contains("refreshed=1"));
    assert!(stdout.contains("vulnerabilities=1"));
    assert!(stdout.contains("network_errors=1"));
    assert!(
        stderr.contains("@beta/telemetry-bridge"),
        "authorized trust sync should preserve downstream error breadcrumbs:\nstdout:\n{stdout}\nstderr:\n{stderr}"
    );
}

// Conformance test that validates INV-REMOTECAP-REQUIRED spec invariant
// for trust sync operations
#[test]
fn trust_sync_network_operations_conform_to_remotecap_spec() {
    // Regression test for bd-piggu: Trust sync OSV/deps.dev operations must follow
    // docs/specs/remote_cap_contract.md:41 - "Every network-bound operation must pass CapabilityGate::authorize_network"

    let test_scenarios = vec![
        ("OSV vulnerability query", "https://api.osv.dev/v1/query"),
        (
            "deps.dev dependents API",
            "https://deps.dev/systems/npm/packages/lodash/versions/4.17.21:dependents",
        ),
        (
            "deps.dev security API",
            "https://deps.dev/systems/npm/packages/lodash/versions/4.17.21:security",
        ),
    ];

    for (description, endpoint) in test_scenarios {
        let mut gate = CapabilityGate::new(&format!("test-{}", description.replace(' ', "-")))
            .expect("test gate should be valid");

        // Verify spec invariant: network-bound operations fail without proper authorization
        let result = gate.authorize_network(
            None,
            RemoteOperation::NetworkEgress,
            endpoint,
            1_700_000_300,
            &format!("trace-{}", description.replace(' ', "-")),
        );

        assert!(
            result.is_err(),
            "{} should fail without RemoteCap authorization per INV-REMOTECAP-REQUIRED",
            description
        );

        let err = result.unwrap_err();
        assert_eq!(
            err.code(),
            "REMOTECAP_MISSING",
            "{} should return REMOTECAP_MISSING error",
            description
        );
    }
}

#[test]
fn trust_scan_deep_denies_token_without_network_egress_scope() {
    let workspace = tempfile::tempdir().expect("tempdir");
    write_scannable_trust_workspace(workspace.path());
    let secret = "trust-scan-cli-remote-cap-secret";
    let issued_at = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system clock after epoch")
        .as_secs();
    let provider = CapabilityProvider::new(secret).expect("provider");
    let (cap, _) = provider
        .issue(
            "remote-cap-regression",
            RemoteScope::new(
                vec![RemoteOperation::TelemetryExport],
                vec!["https://telemetry.example.com".to_string()],
            ),
            issued_at,
            3_600,
            true,
            false,
            "trace-trust-scan-no-egress",
        )
        .expect("issue non-egress token");
    let token_path = workspace.path().join("capability.json");
    fs::write(
        &token_path,
        serde_json::to_vec_pretty(&serde_json::json!({ "token": cap })).expect("token JSON"),
    )
    .expect("write token");

    let output = Command::new(env!("CARGO_BIN_EXE_franken-node"))
        .current_dir(workspace.path())
        .env("FRANKEN_NODE_REMOTECAP_KEY", secret)
        .env("FRANKEN_NODE_TRUST_SCAN_REMOTECAP_TOKEN", &token_path)
        .args(["trust", "scan", ".", "--deep"])
        .output()
        .expect("run trust scan");

    assert!(
        !output.status.success(),
        "trust scan deep should fail closed when token lacks network_egress scope"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("REMOTECAP_SCOPE_DENIED"),
        "stderr should include RemoteCap denial, got:\n{stderr}"
    );
}
