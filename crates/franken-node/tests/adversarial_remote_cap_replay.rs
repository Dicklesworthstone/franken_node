use std::fs;
use std::path::PathBuf;

use frankenengine_node::security::remote_cap::{
    CapabilityGate, CapabilityProvider, RemoteCap, RemoteCapError, RemoteOperation, RemoteScope,
};
use tempfile::TempDir;

const SHARED_SECRET: &str = "adversarial-remote-cap-replay-secret";
const ISSUER: &str = "ops@example";
const BASE_TIME: u64 = 1_700_100_000;
const ENDPOINT_PREFIX: &str = "https://telemetry.example.com/v1";
const ENDPOINT: &str = "https://telemetry.example.com/v1/export";

struct ReplayAttackHarness {
    provider: CapabilityProvider,
    replay_store: TempDir,
}

impl ReplayAttackHarness {
    fn new() -> Self {
        Self {
            provider: CapabilityProvider::new(SHARED_SECRET).expect("provider"),
            replay_store: tempfile::tempdir().expect("replay store"),
        }
    }

    fn gate(&self) -> CapabilityGate {
        CapabilityGate::with_durable_replay_store(SHARED_SECRET, self.replay_store.path())
            .expect("durable replay gate")
    }

    fn issue_single_use(&self, trace_id: &str) -> RemoteCap {
        self.provider
            .issue(
                ISSUER,
                RemoteScope::new(
                    vec![RemoteOperation::TelemetryExport],
                    vec![ENDPOINT_PREFIX.to_string()],
                ),
                BASE_TIME,
                300,
                true,
                true,
                trace_id,
            )
            .expect("issue single-use token")
            .0
    }

    fn consumed_dir(&self) -> PathBuf {
        self.replay_store.path().join("consumed")
    }
}

fn authorize(
    gate: &mut CapabilityGate,
    cap: &RemoteCap,
    now_epoch_secs: u64,
    trace_id: &str,
) -> Result<(), RemoteCapError> {
    gate.authorize_network(
        Some(cap),
        RemoteOperation::TelemetryExport,
        ENDPOINT,
        now_epoch_secs,
        trace_id,
    )
}

fn recheck(
    gate: &mut CapabilityGate,
    cap: &RemoteCap,
    now_epoch_secs: u64,
    trace_id: &str,
) -> Result<(), RemoteCapError> {
    gate.recheck_network(
        Some(cap),
        RemoteOperation::TelemetryExport,
        ENDPOINT,
        now_epoch_secs,
        trace_id,
    )
}

#[test]
fn adversarial_remote_cap_replay_reused_nonce_is_rejected_after_restart() {
    let harness = ReplayAttackHarness::new();
    let captured = harness.issue_single_use("trace-replay-nonce-reuse");
    let attacker_clone = harness.issue_single_use("trace-replay-nonce-reuse");

    assert_eq!(
        captured, attacker_clone,
        "reused issuance trace/nonce should reconstruct the same signed token"
    );

    {
        let mut first_gate = harness.gate();
        recheck(
            &mut first_gate,
            &captured,
            BASE_TIME + 5,
            "trace-replay-preflight",
        )
        .expect("preflight must not consume single-use token");
        authorize(
            &mut first_gate,
            &captured,
            BASE_TIME + 10,
            "trace-replay-first-use",
        )
        .expect("first use must pass");

        let consumed_events = first_gate
            .audit_log()
            .iter()
            .filter(|event| event.event_code == "REMOTECAP_CONSUMED")
            .count();
        assert_eq!(consumed_events, 1, "first gate should consume exactly once");
    }

    let consumed_markers = fs::read_dir(harness.consumed_dir())
        .expect("read replay markers")
        .count();
    assert_eq!(consumed_markers, 1, "replay store should persist one consumed token");

    let mut restarted_gate = harness.gate();
    let err = authorize(
        &mut restarted_gate,
        &attacker_clone,
        BASE_TIME + 11,
        "trace-replay-attacker-clone",
    )
    .expect_err("replayed single-use token must fail after gate restart");

    assert_eq!(
        err,
        RemoteCapError::ReplayDetected {
            token_id: captured.token_id().to_string(),
        }
    );
    assert_eq!(err.code(), "REMOTECAP_REPLAY");

    let denial = restarted_gate.audit_log().last().expect("replay denial audit");
    assert!(!denial.allowed, "replay attempt must be denied");
    assert_eq!(denial.token_id.as_deref(), Some(captured.token_id()));
    assert_eq!(denial.denial_code.as_deref(), Some("REMOTECAP_REPLAY"));
}

#[test]
fn adversarial_remote_cap_replay_unique_nonces_issue_distinct_usable_tokens() {
    let harness = ReplayAttackHarness::new();
    let first = harness.issue_single_use("trace-replay-nonce-a");
    let second = harness.issue_single_use("trace-replay-nonce-b");

    assert_ne!(
        first.token_id(),
        second.token_id(),
        "distinct trace/nonces should issue distinct tokens"
    );
    assert_ne!(
        first.signature(),
        second.signature(),
        "distinct trace/nonces should not collide on signature"
    );

    let mut gate = harness.gate();
    authorize(&mut gate, &first, BASE_TIME + 10, "trace-replay-first")
        .expect("first distinct token should pass");
    authorize(&mut gate, &second, BASE_TIME + 11, "trace-replay-second")
        .expect("second distinct token should pass");

    let consumed_events = gate
        .audit_log()
        .iter()
        .filter(|event| event.event_code == "REMOTECAP_CONSUMED")
        .count();
    assert_eq!(
        consumed_events, 2,
        "durable replay store should allow distinct single-use tokens once each"
    );
}
