//! Integration fixture checks for bd-274s:
//! deterministic Bayesian risk updates and reproducible quarantine actions.

use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::cmp::Ordering;
use std::fs;

const FIXTURE_REL: &str = "artifacts/10.17/adversary_graph_state.json";

#[derive(Debug, Deserialize)]
struct FixtureState {
    schema_version: String,
    generated_at: String,
    thresholds: Thresholds,
    posteriors: Vec<PosteriorEntry>,
    actions: Vec<ActionEntry>,
}

#[derive(Debug, Deserialize)]
struct Thresholds {
    throttle: f64,
    isolate: f64,
    quarantine: f64,
    revoke: f64,
}

#[derive(Debug, Clone, Deserialize)]
struct PosteriorEntry {
    principal_id: String,
    alpha: u64,
    beta: u64,
    posterior: f64,
    evidence_count: u64,
}

#[derive(Debug, Clone, Deserialize)]
struct ActionEntry {
    principal_id: String,
    decision: String,
    posterior: f64,
    trace_id: String,
    evidence_signature: String,
}

fn fixture_path() -> std::path::PathBuf {
    // Resolve relative to CARGO_MANIFEST_DIR to work reliably regardless of
    // the test runner's CWD (local builds vs remote rch workers).
    let manifest = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut root = manifest.to_path_buf();
    loop {
        let candidate = root.join(FIXTURE_REL);
        if candidate.exists() {
            return candidate;
        }
        if !root.pop() {
            break;
        }
    }
    std::path::PathBuf::from(FIXTURE_REL)
}

fn load_fixture() -> FixtureState {
    let path = fixture_path();
    let raw = fs::read_to_string(&path)
        .unwrap_or_else(|err| panic!("failed reading fixture `{}`: {err}", path.display()));
    serde_json::from_str::<FixtureState>(&raw)
        .unwrap_or_else(|err| {
            panic!("failed parsing fixture `{}` as json: {err}", path.display())
        })
}

fn posterior_from_beta(alpha: u64, beta: u64) -> f64 {
    let total = alpha + beta;
    if total == 0 {
        return 0.0;
    }
    (alpha as f64) / (total as f64)
}

fn deterministic_bayes_update(
    prior_alpha: u64,
    prior_beta: u64,
    observed_successes: u64,
    observed_failures: u64,
) -> f64 {
    posterior_from_beta(
        prior_alpha.saturating_add(observed_successes),
        prior_beta.saturating_add(observed_failures),
    )
}

fn action_for_posterior(posterior: f64, thresholds: &Thresholds) -> Option<&'static str> {
    if posterior >= thresholds.revoke {
        Some("revoke")
    } else if posterior >= thresholds.quarantine {
        Some("quarantine")
    } else if posterior >= thresholds.isolate {
        Some("isolate")
    } else if posterior >= thresholds.throttle {
        Some("throttle")
    } else {
        None
    }
}

fn signed_evidence(principal_id: &str, decision: &str, posterior: f64, trace_id: &str) -> String {
    let payload = format!("{principal_id}|{decision}|{posterior:.12}|{trace_id}");
    let digest = Sha256::digest(payload.as_bytes());
    format!("sha256:{digest:x}")
}

#[test]
fn deterministic_posterior_updates_match_identical_inputs() {
    let a = deterministic_bayes_update(3, 4, 7, 2);
    let b = deterministic_bayes_update(3, 4, 7, 2);
    assert!(
        (a - b).abs() < 1e-12,
        "deterministic Bayesian update must be stable for identical evidence"
    );
    assert!(
        (a - (10.0 / 16.0)).abs() < 1e-12,
        "posterior should match the expected closed-form value"
    );
}

#[test]
fn threshold_policy_maps_to_all_control_actions() {
    let fixture = load_fixture();
    let thresholds = fixture.thresholds;

    let cases = [
        (0.46_f64, "throttle"),
        (0.61_f64, "isolate"),
        (0.80_f64, "quarantine"),
        (0.95_f64, "revoke"),
    ];

    for (posterior, expected) in cases {
        let actual = action_for_posterior(posterior, &thresholds)
            .unwrap_or_else(|| panic!("expected action for posterior {posterior}"));
        assert_eq!(
            actual, expected,
            "threshold policy should deterministically map posterior to action"
        );
    }
}

#[test]
fn fixture_posteriors_align_with_beta_parameters() {
    let fixture = load_fixture();
    assert_eq!(fixture.schema_version, "adversary-graph-state-v1");
    assert!(
        fixture.generated_at.ends_with('Z'),
        "fixture timestamp should be UTC RFC3339"
    );

    for row in fixture.posteriors {
        let expected = posterior_from_beta(row.alpha, row.beta);
        assert!(
            (expected - row.posterior).abs() < 1e-12,
            "posterior mismatch for {}: expected {expected}, got {}",
            row.principal_id,
            row.posterior
        );
        assert!(
            row.evidence_count > 0,
            "evidence_count must be non-zero for {}",
            row.principal_id
        );
    }
}

#[test]
fn fixture_actions_have_deterministic_signatures() {
    let fixture = load_fixture();
    let thresholds = fixture.thresholds;

    for action in fixture.actions {
        let expected_decision = action_for_posterior(action.posterior, &thresholds)
            .unwrap_or_else(|| panic!("missing threshold decision for {}", action.principal_id));
        assert_eq!(
            action.decision, expected_decision,
            "decision mismatch for {}",
            action.principal_id
        );

        let expected_signature = signed_evidence(
            &action.principal_id,
            &action.decision,
            action.posterior,
            &action.trace_id,
        );
        assert_eq!(
            action.evidence_signature, expected_signature,
            "signed evidence mismatch for {}",
            action.principal_id
        );
    }
}

#[test]
fn fixture_actions_are_sorted_for_replay_determinism() {
    let fixture = load_fixture();
    let mut sorted = fixture.actions.clone();

    sorted.sort_by(|left, right| {
        right
            .posterior
            .partial_cmp(&left.posterior)
            .unwrap_or(Ordering::Equal)
            .then_with(|| left.principal_id.cmp(&right.principal_id))
    });

    for (idx, expected) in sorted.iter().enumerate() {
        let actual = &fixture.actions[idx];
        assert_eq!(
            (actual.principal_id.as_str(), actual.decision.as_str()),
            (expected.principal_id.as_str(), expected.decision.as_str()),
            "action ordering must remain deterministic for replay traces"
        );
    }
}
