//! Security tests for bd-1nfu RemoteCap enforcement.
//!
//! Verifies:
//! - network-bound operations fail without RemoteCap
//! - signature/expiry/scope/replay/revocation checks are fail-closed
//! - local-only operations remain functional without RemoteCap
//! - network guard enforces centralized capability gate

use std::fs;
use std::process::Command;

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

fn provider() -> CapabilityProvider {
    CapabilityProvider::new("remote-cap-test-secret")
        .expect("remote cap test signing secret should be valid")
}

fn write_scannable_trust_workspace(workspace: &std::path::Path) {
    fs::write(workspace.join("franken_node.toml"), "profile = \"balanced\"\n")
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
    let mut gate =
        CapabilityGate::new("remote-cap-test-secret").expect("remote cap test gate should be valid");

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
    let mut gate =
        CapabilityGate::new("remote-cap-test-secret").expect("remote cap test gate should be valid");
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

    let mut gate =
        CapabilityGate::new("remote-cap-test-secret").expect("remote cap test gate should be valid");
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
    let mut gate =
        CapabilityGate::new("remote-cap-test-secret").expect("remote cap test gate should be valid");
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

    let mut gate =
        CapabilityGate::new("remote-cap-test-secret").expect("remote cap test gate should be valid");
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
    let mut gate =
        CapabilityGate::new("remote-cap-test-secret").expect("remote cap test gate should be valid");
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
    let mut gate =
        CapabilityGate::new("remote-cap-test-secret").expect("remote cap test gate should be valid");
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
    let mut gate =
        CapabilityGate::with_mode("remote-cap-test-secret", ConnectivityMode::LocalOnly)
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
    let mut gate =
        CapabilityGate::new("remote-cap-test-secret").expect("remote cap test gate should be valid");

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
    // Test for bd-piggu: Verify OSV network operations pass through CapabilityGate::authorize_network
    let mut gate =
        CapabilityGate::new("osv-test-secret").expect("OSV test gate should be valid");

    // Test OSV query endpoint - should fail without RemoteCap
    let osv_url = "https://api.osv.dev/v1/query";
    let err = gate
        .authorize_network(
            None, // No RemoteCap token
            RemoteOperation::NetworkEgress,
            osv_url,
            1_700_000_200,
            "trace-osv-missing-cap",
        )
        .expect_err("OSV network call without RemoteCap should fail");

    assert_eq!(err.code(), "REMOTECAP_MISSING");
    assert_eq!(err.compatibility_code(), Some("ERR_REMOTE_CAP_REQUIRED"));

    // Test deps.dev dependents endpoint - should also fail without RemoteCap
    let deps_url = "https://deps.dev/systems/npm/packages/test/versions/1.0.0:dependents";
    let err = gate
        .authorize_network(
            None,
            RemoteOperation::NetworkEgress,
            deps_url,
            1_700_000_201,
            "trace-deps-missing-cap",
        )
        .expect_err("deps.dev network call without RemoteCap should fail");

    assert_eq!(err.code(), "REMOTECAP_MISSING");
    assert_eq!(err.compatibility_code(), Some("ERR_REMOTE_CAP_REQUIRED"));

    // Test with valid RemoteCap - should succeed
    let provider = CapabilityProvider::new("osv-test-secret")
        .expect("OSV test provider should be valid");

    let scope = RemoteScope::new(
        vec![RemoteOperation::NetworkEgress],
        vec![osv_url.to_string(), deps_url.to_string()],
    );

    let (cap, _audit_event) = provider
        .issue(
            "test-issuer",
            scope,
            1_700_010_000,
            1_700_000_100,
            true, // operator_authorized
            false, // single_use
            "trace-osv-issue",
        )
        .expect("OSV test cap should be valid");

    // OSV query should now succeed with valid cap
    gate.authorize_network(
        Some(&cap),
        RemoteOperation::NetworkEgress,
        osv_url,
        1_700_000_202,
        "trace-osv-authorized",
    )
    .expect("OSV query with valid RemoteCap should pass");

    // deps.dev query should also succeed with valid cap
    gate.authorize_network(
        Some(&cap),
        RemoteOperation::NetworkEgress,
        deps_url,
        1_700_000_203,
        "trace-deps-authorized",
    )
    .expect("deps.dev query with valid RemoteCap should pass");
}

// Conformance test that validates INV-REMOTECAP-REQUIRED spec invariant
// for trust sync operations
#[test]
fn trust_sync_network_operations_conform_to_remotecap_spec() {
    // Regression test for bd-piggu: Trust sync OSV/deps.dev operations must follow
    // docs/specs/remote_cap_contract.md:41 - "Every network-bound operation must pass CapabilityGate::authorize_network"

    let test_scenarios = vec![
        ("OSV vulnerability query", "https://api.osv.dev/v1/query"),
        ("deps.dev dependents API", "https://deps.dev/systems/npm/packages/lodash/versions/4.17.21:dependents"),
        ("deps.dev security API", "https://deps.dev/systems/npm/packages/lodash/versions/4.17.21:security"),
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
