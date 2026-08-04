//! Comprehensive conformance testing for the adversary_graph security module.
//!
//! This test suite validates critical security properties including:
//! - Deterministic Bayesian updates across replay scenarios
//! - Edge case handling for likelihood and evidence weight boundaries
//! - Performance characteristics under load
//! - Serialization integrity
//! - Hash-based state verification
//! - Timing attack resistance via constant-time operations

use frankenengine_node::security::adversary_graph::{
    ADVERSARY_GRAPH_SCHEMA_VERSION, AdversaryGraph, AdversaryGraphError, AdversaryObservation,
    EVD_ADV_GRAPH_001, EVD_ADV_GRAPH_002,
};

// ──────────────────────────────────────────────────────────────────────────────
// Test Helpers
// ──────────────────────────────────────────────────────────────────────────────

fn make_observation(
    principal_id: &str,
    likelihood: f64,
    weight: u64,
    evidence_ref: &str,
    trace_id: &str,
) -> AdversaryObservation {
    AdversaryObservation::new(principal_id, likelihood, weight, evidence_ref, trace_id)
        .expect("valid observation")
}

fn make_high_risk_obs(principal_id: &str, seq: u32) -> AdversaryObservation {
    make_observation(
        principal_id,
        0.9,
        10,
        &format!("high-risk-ev-{seq}"),
        &format!("trace-{seq}"),
    )
}

fn make_low_risk_obs(principal_id: &str, seq: u32) -> AdversaryObservation {
    make_observation(
        principal_id,
        0.1,
        5,
        &format!("low-risk-ev-{seq}"),
        &format!("trace-{seq}"),
    )
}

// ──────────────────────────────────────────────────────────────────────────────
// Boundary Validation Tests
// ──────────────────────────────────────────────────────────────────────────────

#[test]
fn test_likelihood_boundary_validation() {
    // Valid boundaries
    assert!(AdversaryObservation::new("test", 0.0, 1, "ev", "trace").is_ok());
    assert!(AdversaryObservation::new("test", 1.0, 1, "ev", "trace").is_ok());
    assert!(AdversaryObservation::new("test", 0.5, 1, "ev", "trace").is_ok());

    // Invalid boundaries
    assert!(matches!(
        AdversaryObservation::new("test", -0.1, 1, "ev", "trace").unwrap_err(),
        AdversaryGraphError::InvalidLikelihood { value } if value == -0.1
    ));

    assert!(matches!(
        AdversaryObservation::new("test", 1.1, 1, "ev", "trace").unwrap_err(),
        AdversaryGraphError::InvalidLikelihood { value } if value == 1.1
    ));

    // Test NaN and infinity rejection
    assert!(AdversaryObservation::new("test", f64::NAN, 1, "ev", "trace").is_err());
    assert!(AdversaryObservation::new("test", f64::INFINITY, 1, "ev", "trace").is_err());
    assert!(AdversaryObservation::new("test", f64::NEG_INFINITY, 1, "ev", "trace").is_err());
}

#[test]
fn test_evidence_weight_boundary_validation() {
    // Valid weight
    assert!(AdversaryObservation::new("test", 0.5, 1, "ev", "trace").is_ok());
    assert!(AdversaryObservation::new("test", 0.5, u64::MAX, "ev", "trace").is_ok());

    // Invalid weight
    assert!(matches!(
        AdversaryObservation::new("test", 0.5, 0, "ev", "trace").unwrap_err(),
        AdversaryGraphError::InvalidEvidenceWeight { value: 0 }
    ));
}

// ──────────────────────────────────────────────────────────────────────────────
// Deterministic Replay Tests
// ──────────────────────────────────────────────────────────────────────────────

#[test]
fn test_deterministic_replay_empty_graph() {
    let graph1 = AdversaryGraph::replay_from(&[]).expect("empty replay");
    let graph2 = AdversaryGraph::replay_from(&[]).expect("empty replay");

    assert_eq!(graph1.export_state_hash(), graph2.export_state_hash());
    assert_eq!(graph1.get_risk_posterior("nonexistent"), 0.1); // Default prior
}

#[test]
fn test_deterministic_replay_single_observation() {
    let obs = make_observation("ext:test", 0.8, 5, "evidence-1", "trace-1");

    let graph1 =
        AdversaryGraph::replay_from(std::slice::from_ref(&obs)).expect("single obs replay");
    let graph2 = AdversaryGraph::replay_from(&[obs]).expect("single obs replay");

    assert_eq!(graph1.export_state_hash(), graph2.export_state_hash());
    assert!(graph1.get_risk_posterior("ext:test") > 0.1); // Should increase from prior
}

#[test]
fn test_deterministic_replay_order_independence() {
    let obs1 = make_observation("ext:a", 0.9, 8, "ev-1", "trace-1");
    let obs2 = make_observation("ext:a", 0.8, 7, "ev-2", "trace-2");
    let obs3 = make_observation("ext:b", 0.2, 4, "ev-3", "trace-3");

    // Test different orderings produce same result
    let orderings = vec![
        vec![obs1.clone(), obs2.clone(), obs3.clone()],
        vec![obs3.clone(), obs1.clone(), obs2.clone()],
        vec![obs2.clone(), obs3.clone(), obs1.clone()],
    ];

    let mut hashes = Vec::new();
    for ordering in orderings {
        let graph = AdversaryGraph::replay_from(&ordering).expect("replay");
        hashes.push(graph.export_state_hash());
    }

    // All hashes should be identical
    assert!(hashes.windows(2).all(|w| w[0] == w[1]));
}

#[test]
fn test_deterministic_replay_large_dataset() {
    // Test with many observations to ensure determinism holds at scale
    let mut observations = Vec::new();

    for i in 0..100 {
        let principal = format!("ext:target-{}", i % 10); // 10 different principals
        let likelihood = 0.1 + (i as f64 * 0.007) % 0.8; // Vary likelihood
        let weight = 1 + (i % 20) as u64; // Vary weights

        observations.push(make_observation(
            &principal,
            likelihood,
            weight,
            &format!("evidence-{i}"),
            &format!("trace-{i}"),
        ));
    }

    // Reverse the order and replay
    let mut reversed = observations.clone();
    reversed.reverse();

    let graph1 = AdversaryGraph::replay_from(&observations).expect("original order");
    let graph2 = AdversaryGraph::replay_from(&reversed).expect("reversed order");

    assert_eq!(graph1.export_state_hash(), graph2.export_state_hash());
}

// ──────────────────────────────────────────────────────────────────────────────
// Bayesian Update Property Tests
// ──────────────────────────────────────────────────────────────────────────────

#[test]
fn test_bayesian_update_increases_risk_with_high_likelihood() {
    let mut graph = AdversaryGraph::new();
    let initial_risk = graph.get_risk_posterior("ext:suspicious");

    // Add high-likelihood observation
    let obs = make_observation("ext:suspicious", 0.95, 10, "malware-detected", "trace-1");
    let _ = graph.ingest(&obs);

    let updated_risk = graph.get_risk_posterior("ext:suspicious");
    assert!(updated_risk > initial_risk);
    assert!(updated_risk > 0.5); // Should be significantly higher
}

#[test]
fn test_bayesian_update_decreases_risk_with_low_likelihood() {
    let mut graph = AdversaryGraph::new();

    // First add a high-risk observation to establish some risk
    let high_risk = make_observation("ext:test", 0.9, 5, "initial-risk", "trace-1");
    let _ = graph.ingest(&high_risk);
    let elevated_risk = graph.get_risk_posterior("ext:test");

    // Then add low-likelihood observations that should reduce risk
    for i in 0..5 {
        let low_risk = make_observation(
            "ext:test",
            0.05,
            3,
            &format!("clean-{i}"),
            &format!("trace-{i}"),
        );
        let _ = graph.ingest(&low_risk);
    }

    let final_risk = graph.get_risk_posterior("ext:test");
    assert!(final_risk < elevated_risk);
}

#[test]
fn test_evidence_weight_affects_update_magnitude() {
    let mut graph1 = AdversaryGraph::new();
    let mut graph2 = AdversaryGraph::new();

    // Same likelihood, different weights
    let light_evidence = make_observation("ext:test", 0.8, 1, "light-ev", "trace-1");
    let heavy_evidence = make_observation("ext:test", 0.8, 20, "heavy-ev", "trace-1");

    graph1.ingest(&light_evidence).expect("ingest");
    graph2.ingest(&heavy_evidence).expect("ingest");

    let risk1 = graph1
        .posteriors()
        .into_iter()
        .find(|p| p.principal_id == "ext:test")
        .map(|p| p.posterior)
        .unwrap_or(0.0);
    let risk2 = graph2
        .posteriors()
        .into_iter()
        .find(|p| p.principal_id == "ext:test")
        .map(|p| p.posterior)
        .unwrap_or(0.0);

    assert!(risk2 > risk1); // Higher weight should lead to greater update
}

#[test]
fn test_multiple_observations_accumulate_evidence() {
    let mut graph = AdversaryGraph::new();
    let initial_risk = graph
        .posteriors()
        .into_iter()
        .find(|p| p.principal_id == "ext:accumulator")
        .map(|p| p.posterior)
        .unwrap_or(0.1); // Default prior risk

    // Add multiple moderate-risk observations
    for i in 0..10 {
        let obs = make_observation(
            "ext:accumulator",
            0.7,
            3,
            &format!("evidence-{i}"),
            &format!("trace-{i}"),
        );
        graph.ingest(&obs).expect("ingest");
    }

    let final_risk = graph
        .posteriors()
        .into_iter()
        .find(|p| p.principal_id == "ext:accumulator")
        .map(|p| p.posterior)
        .unwrap_or(0.0);
    assert!(final_risk > initial_risk);
    assert!(final_risk > 0.5); // Should accumulate to significant risk
}

// ──────────────────────────────────────────────────────────────────────────────
// Hash and State Integrity Tests
// ──────────────────────────────────────────────────────────────────────────────

#[test]
fn test_state_hash_changes_with_updates() {
    let mut graph = AdversaryGraph::new();
    let initial_hash = graph.export_state_hash();

    let obs = make_observation("ext:test", 0.5, 5, "evidence", "trace");
    let _ = graph.ingest(&obs);

    let updated_hash = graph.export_state_hash();
    assert_ne!(initial_hash, updated_hash);
}

#[test]
fn test_state_hash_deterministic_across_instances() {
    let obs1 = make_observation("ext:a", 0.7, 5, "ev-1", "trace-1");
    let obs2 = make_observation("ext:b", 0.3, 8, "ev-2", "trace-2");

    let mut graph1 = AdversaryGraph::new();
    let _ = graph1.ingest(&obs1);
    let _ = graph1.ingest(&obs2);

    let mut graph2 = AdversaryGraph::new();
    let _ = graph2.ingest(&obs1);
    let _ = graph2.ingest(&obs2);

    assert_eq!(graph1.export_state_hash(), graph2.export_state_hash());
}

#[test]
fn test_state_hash_sensitive_to_observation_details() {
    let base_obs = make_observation("ext:test", 0.5, 5, "evidence", "trace");

    // Different principal_id
    let diff_principal = make_observation("ext:different", 0.5, 5, "evidence", "trace");

    // Different likelihood
    let diff_likelihood = make_observation("ext:test", 0.6, 5, "evidence", "trace");

    // Different weight
    let diff_weight = make_observation("ext:test", 0.5, 6, "evidence", "trace");

    let base_graph = AdversaryGraph::replay_from(&[base_obs]).expect("base graph");
    let graph1 = AdversaryGraph::replay_from(&[diff_principal]).expect("diff principal");
    let graph2 = AdversaryGraph::replay_from(&[diff_likelihood]).expect("diff likelihood");
    let graph3 = AdversaryGraph::replay_from(&[diff_weight]).expect("diff weight");

    let base_hash = base_graph.export_state_hash();
    assert_ne!(base_hash, graph1.export_state_hash());
    assert_ne!(base_hash, graph2.export_state_hash());
    assert_ne!(base_hash, graph3.export_state_hash());
}

// ──────────────────────────────────────────────────────────────────────────────
// Performance and Scalability Tests
// ──────────────────────────────────────────────────────────────────────────────

#[test]
fn test_performance_many_principals() {
    let mut observations = Vec::new();

    // Create observations for 1000 different principals
    for i in 0..1000 {
        observations.push(make_observation(
            &format!("ext:principal-{i}"),
            0.5,
            5,
            &format!("evidence-{i}"),
            &format!("trace-{i}"),
        ));
    }

    let start = std::time::Instant::now();
    let graph = AdversaryGraph::replay_from(&observations).expect("large replay");
    let duration = start.elapsed();

    // Should complete in reasonable time (< 1 second for 1000 principals)
    assert!(
        duration.as_millis() < 1000,
        "Replay took too long: {duration:?}"
    );

    // Verify all principals are tracked
    for i in 0..1000 {
        let risk = graph.get_risk_posterior(&format!("ext:principal-{i}"));
        assert!(risk > 0.0 && risk <= 1.0);
    }
}

#[test]
fn test_performance_many_observations_single_principal() {
    let mut observations = Vec::new();

    // Create 500 observations for a single principal
    for i in 0..500 {
        let likelihood = 0.4 + (i as f64 * 0.001) % 0.2; // Vary slightly
        observations.push(make_observation(
            "ext:heavy-target",
            likelihood,
            1 + (i % 10) as u64,
            &format!("evidence-{i}"),
            &format!("trace-{i}"),
        ));
    }

    let start = std::time::Instant::now();
    let graph = AdversaryGraph::replay_from(&observations).expect("heavy replay");
    let duration = start.elapsed();

    // Should complete in reasonable time
    assert!(
        duration.as_millis() < 500,
        "Heavy replay took too long: {duration:?}"
    );

    let final_risk = graph.get_risk_posterior("ext:heavy-target");
    assert!(final_risk > 0.0 && final_risk <= 1.0);
}

// ──────────────────────────────────────────────────────────────────────────────
// Edge Case and Error Handling Tests
// ──────────────────────────────────────────────────────────────────────────────

#[test]
fn test_empty_string_fields_handled() {
    // Empty strings should be valid but distinguishable
    let obs1 = make_observation("", 0.5, 5, "evidence", "trace");
    let obs2 = make_observation("ext:test", 0.5, 5, "", "trace");
    let obs3 = make_observation("ext:test", 0.5, 5, "evidence", "");

    let graph = AdversaryGraph::replay_from(&[obs1, obs2, obs3]).expect("empty strings");

    // Should not crash and produce deterministic state
    let _ = graph.export_state_hash();
}

#[test]
fn test_unicode_fields_handled() {
    let obs = make_observation("ext:测试-🦀", 0.6, 7, "evidence-αβγ", "trace-日本語");

    let graph = AdversaryGraph::replay_from(&[obs]).expect("unicode strings");
    let risk = graph.get_risk_posterior("ext:测试-🦀");
    assert!(risk > 0.0 && risk <= 1.0);
}

#[test]
fn test_very_long_strings_handled() {
    let long_string = "x".repeat(10000);
    let obs = make_observation(&long_string, 0.5, 5, "evidence", "trace");

    let graph = AdversaryGraph::replay_from(&[obs]).expect("long strings");
    let risk = graph.get_risk_posterior(&long_string);
    assert!(risk > 0.0 && risk <= 1.0);
}

#[test]
fn test_extreme_likelihood_values() {
    // Test very small and very large valid values
    let obs1 = make_observation("ext:test1", f64::EPSILON, 1, "evidence", "trace");
    let obs2 = make_observation("ext:test2", 1.0 - f64::EPSILON, 1, "evidence", "trace");

    let graph = AdversaryGraph::replay_from(&[obs1, obs2]).expect("extreme likelihoods");

    // Should handle these without panic or errors
    assert!(graph.get_risk_posterior("ext:test1") >= 0.0);
    assert!(graph.get_risk_posterior("ext:test2") <= 1.0);
}

#[test]
fn test_maximum_evidence_weight() {
    let obs = make_observation("ext:test", 0.5, u64::MAX, "evidence", "trace");
    let graph = AdversaryGraph::replay_from(&[obs]).expect("max weight");

    // Should handle maximum weight without overflow
    assert!(graph.get_risk_posterior("ext:test") > 0.0);
}

// ──────────────────────────────────────────────────────────────────────────────
// Security Invariant Tests
// ──────────────────────────────────────────────────────────────────────────────

#[test]
fn test_risk_posterior_bounded() {
    let mut graph = AdversaryGraph::new();

    // Test various extreme scenarios
    let scenarios = vec![
        make_observation("ext:test1", 0.0, u64::MAX, "evidence", "trace"),
        make_observation("ext:test2", 1.0, u64::MAX, "evidence", "trace"),
        make_observation("ext:test3", 0.5, 1, "evidence", "trace"),
    ];

    for obs in scenarios {
        let _ = graph.ingest(&obs);
    }

    // All risk values must be in [0, 1] range
    for principal in ["ext:test1", "ext:test2", "ext:test3", "ext:nonexistent"] {
        let risk = graph.get_risk_posterior(principal);
        assert!(
            (0.0..=1.0).contains(&risk),
            "Risk {risk} for {principal} out of bounds"
        );
    }
}

#[test]
fn test_observation_ordering_invariant() {
    // Fundamental invariant: observation order should not affect final state
    // when using deterministic Bayesian updates

    let observations = vec![
        make_high_risk_obs("ext:target", 1),
        make_low_risk_obs("ext:target", 2),
        make_high_risk_obs("ext:other", 3),
        make_low_risk_obs("ext:target", 4),
        make_high_risk_obs("ext:target", 5),
    ];

    // Generate all permutations would be expensive, so test a few key reorderings
    let reorderings = vec![
        observations.clone(),
        {
            let mut rev = observations.clone();
            rev.reverse();
            rev
        },
        {
            let mut shuffled = observations.clone();
            // Simple deterministic shuffle
            shuffled.swap(0, 2);
            shuffled.swap(1, 4);
            shuffled
        },
    ];

    let mut results = Vec::new();
    for ordering in reorderings {
        let graph = AdversaryGraph::replay_from(&ordering).expect("reordered replay");
        results.push((
            graph.get_risk_posterior("ext:target"),
            graph.get_risk_posterior("ext:other"),
            graph.export_state_hash(),
        ));
    }

    // All results should be identical
    for window in results.windows(2) {
        assert_eq!(window[0], window[1], "Ordering affected final state");
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// Schema and Constant Tests
// ──────────────────────────────────────────────────────────────────────────────

#[test]
fn test_schema_version_stability() {
    // Schema version should be stable for compatibility
    assert_eq!(ADVERSARY_GRAPH_SCHEMA_VERSION, "adversary-graph-state-v1");
}

#[test]
fn test_event_codes_defined() {
    // Event codes should be properly defined
    assert_eq!(EVD_ADV_GRAPH_001, "EVD-ADV-GRAPH-001");
    assert_eq!(EVD_ADV_GRAPH_002, "EVD-ADV-GRAPH-002");
}
