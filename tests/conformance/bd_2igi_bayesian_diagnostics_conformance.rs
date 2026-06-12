//! bd-2igi: Bayesian Posterior Diagnostics Conformance Test Harness
//!
//! Verifies the four core invariants of explainable policy ranking:
//! - INV-BAYES-ADVISORY: Diagnostics never directly execute actions
//! - INV-BAYES-REPRODUCIBLE: replay_from with identical observations produces bit-identical rankings
//! - INV-BAYES-NORMALIZED: Posterior probabilities sum to 1.0 within floating-point tolerance
//! - INV-BAYES-TRANSPARENT: Every ranking includes full posterior, prior, observation count, and confidence interval
//!
//! Pattern 4: Spec-Derived Test Matrix with comprehensive requirement coverage

use frankenengine_node::policy::bayesian_diagnostics::{
    BayesianDiagnostics, CandidateRef, DiagnosticConfidence, E_PROCESS_SCALE_PPM,
    LikelihoodRatioEvidence, MixtureSprtComponent, Observation, RankedCandidate,
    RuntimeSentinelEProcess,
};
use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// Conformance Test Framework
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RequirementLevel {
    Must,   // Specification MUST - failure = non-conformant
    Should, // Specification SHOULD - failure = degraded conformance
    May,    // Specification MAY - optional behavior
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TestCategory {
    Advisory,        // INV-BAYES-ADVISORY tests
    Reproducibility, // INV-BAYES-REPRODUCIBLE tests
    Normalization,   // INV-BAYES-NORMALIZED tests
    Transparency,    // INV-BAYES-TRANSPARENT tests
    EventCodes,      // Event code coverage
    EdgeCase,        // Boundary conditions
    EProcess,        // Runtime Sentinel e-process
    Integration,     // Multi-invariant scenarios
}

#[derive(Debug, Clone)]
pub struct ConformanceTestCase {
    pub id: &'static str,
    pub requirement_level: RequirementLevel,
    pub category: TestCategory,
    pub description: &'static str,
    pub test_fn: fn() -> TestResult,
}

#[derive(Debug, Clone, Serialize)]
#[serde(tag = "status")]
pub enum TestResult {
    Pass,
    Fail { reason: String },
    Skipped { reason: String },
    ExpectedFailure { reason: String },
}

// ---------------------------------------------------------------------------
// Test Fixture Builders
// ---------------------------------------------------------------------------

fn candidate_a() -> CandidateRef {
    CandidateRef::new("candidate_a")
}

fn candidate_b() -> CandidateRef {
    CandidateRef::new("candidate_b")
}

fn candidate_c() -> CandidateRef {
    CandidateRef::new("candidate_c")
}

fn test_epoch() -> u64 {
    42
}

fn success_observation(candidate: CandidateRef, epoch: u64) -> Observation {
    Observation::new(candidate, true, epoch)
}

fn failure_observation(candidate: CandidateRef, epoch: u64) -> Observation {
    Observation::new(candidate, false, epoch)
}

// ---------------------------------------------------------------------------
// INV-BAYES-ADVISORY: Diagnostics never directly execute actions
// ---------------------------------------------------------------------------

fn test_advisory_only_returns_rankings() -> TestResult {
    let mut diagnostics = BayesianDiagnostics::new();

    // Add some observations
    diagnostics.update(&success_observation(candidate_a(), test_epoch()));
    diagnostics.update(&failure_observation(candidate_b(), test_epoch()));

    let candidates = vec![candidate_a(), candidate_b()];
    let rankings = diagnostics.rank_candidates(&candidates, &[]);

    // Verify that ranking only returns analysis, doesn't execute anything
    // This is tested by verifying the method signature: it returns Vec<RankedCandidate>
    // and takes &self (immutable reference), proving it's purely advisory
    if rankings.len() == 2 {
        // Verify it's purely informational - contains diagnostic data only
        let has_diagnostic_data = rankings.iter().all(|r| {
            r.posterior_prob.is_finite()
                && r.prior_prob.is_finite()
                && r.confidence_interval.0.is_finite()
                && r.confidence_interval.1.is_finite()
        });

        if has_diagnostic_data {
            TestResult::Pass
        } else {
            TestResult::Fail {
                reason: "Rankings missing required diagnostic data".to_string(),
            }
        }
    } else {
        TestResult::Fail {
            reason: format!("Expected 2 rankings, got {}", rankings.len()),
        }
    }
}

fn test_advisory_immutable_ranking_call() -> TestResult {
    let diagnostics = BayesianDiagnostics::new();
    let candidates = vec![candidate_a()];

    // Call rank_candidates multiple times - should not modify diagnostics
    let rankings1 = diagnostics.rank_candidates(&candidates, &[]);
    let rankings2 = diagnostics.rank_candidates(&candidates, &[]);

    // Verify rankings are identical (immutable operation)
    if rankings1.len() == rankings2.len() && rankings1.len() == 1 {
        let r1 = &rankings1[0];
        let r2 = &rankings2[0];

        if r1.candidate_ref == r2.candidate_ref
            && (r1.posterior_prob - r2.posterior_prob).abs() < 1e-10
        {
            TestResult::Pass
        } else {
            TestResult::Fail {
                reason: "Multiple ranking calls produced different results - not purely advisory"
                    .to_string(),
            }
        }
    } else {
        TestResult::Fail {
            reason: "Rankings had different lengths between calls".to_string(),
        }
    }
}

// ---------------------------------------------------------------------------
// INV-BAYES-REPRODUCIBLE: Replay with identical observations produces bit-identical rankings
// ---------------------------------------------------------------------------

fn test_reproducible_identical_observations() -> TestResult {
    let observations = vec![
        success_observation(candidate_a(), test_epoch()),
        failure_observation(candidate_a(), test_epoch() + 1),
        success_observation(candidate_b(), test_epoch() + 2),
    ];

    // Run 1: Apply observations in order
    let mut diagnostics1 = BayesianDiagnostics::new();
    for obs in &observations {
        diagnostics1.update(obs);
    }
    let candidates = vec![candidate_a(), candidate_b()];
    let rankings1 = diagnostics1.rank_candidates(&candidates, &[]);

    // Run 2: Apply same observations in same order
    let mut diagnostics2 = BayesianDiagnostics::new();
    for obs in &observations {
        diagnostics2.update(obs);
    }
    let rankings2 = diagnostics2.rank_candidates(&candidates, &[]);

    // Verify bit-identical results
    if rankings1.len() == rankings2.len() {
        let identical = rankings1.iter().zip(rankings2.iter()).all(|(r1, r2)| {
            r1.candidate_ref == r2.candidate_ref
                && r1.posterior_prob.to_bits() == r2.posterior_prob.to_bits()
                && r1.prior_prob.to_bits() == r2.prior_prob.to_bits()
                && r1.observation_count == r2.observation_count
                && r1.confidence_interval.0.to_bits() == r2.confidence_interval.0.to_bits()
                && r1.confidence_interval.1.to_bits() == r2.confidence_interval.1.to_bits()
        });

        if identical {
            TestResult::Pass
        } else {
            TestResult::Fail {
                reason:
                    "Identical observations produced different rankings - reproducibility violated"
                        .to_string(),
            }
        }
    } else {
        TestResult::Fail {
            reason: "Different ranking counts between identical observation sequences".to_string(),
        }
    }
}

fn test_reproducible_deterministic_reduction_order() -> TestResult {
    let mut diagnostics = BayesianDiagnostics::new();

    // Add observations for multiple candidates
    diagnostics.update(&success_observation(candidate_a(), test_epoch()));
    diagnostics.update(&success_observation(candidate_b(), test_epoch()));
    diagnostics.update(&success_observation(candidate_c(), test_epoch()));

    let candidates = vec![candidate_a(), candidate_b(), candidate_c()];

    // Call ranking multiple times - order should be deterministic
    let rankings1 = diagnostics.rank_candidates(&candidates, &[]);
    let rankings2 = diagnostics.rank_candidates(&candidates, &[]);
    let rankings3 = diagnostics.rank_candidates(&candidates, &[]);

    // Verify deterministic ordering
    if rankings1.len() == rankings2.len() && rankings2.len() == rankings3.len() {
        let order_identical = rankings1
            .iter()
            .zip(rankings2.iter())
            .zip(rankings3.iter())
            .all(|((r1, r2), r3)| {
                r1.candidate_ref == r2.candidate_ref && r2.candidate_ref == r3.candidate_ref
            });

        if order_identical {
            TestResult::Pass
        } else {
            TestResult::Fail {
                reason: "Reduction order not deterministic - reproducibility violated".to_string(),
            }
        }
    } else {
        TestResult::Fail {
            reason: "Ranking counts differed between calls".to_string(),
        }
    }
}

// ---------------------------------------------------------------------------
// INV-BAYES-NORMALIZED: Posterior probabilities sum to 1.0 within tolerance
// ---------------------------------------------------------------------------

fn test_normalized_posterior_sum() -> TestResult {
    let mut diagnostics = BayesianDiagnostics::new();

    // Add observations to create varied posteriors
    diagnostics.update(&success_observation(candidate_a(), test_epoch()));
    diagnostics.update(&success_observation(candidate_a(), test_epoch() + 1));
    diagnostics.update(&failure_observation(candidate_b(), test_epoch() + 2));
    diagnostics.update(&success_observation(candidate_c(), test_epoch() + 3));

    let candidates = vec![candidate_a(), candidate_b(), candidate_c()];
    let rankings = diagnostics.rank_candidates(&candidates, &[]);

    // Sum posterior probabilities
    let posterior_sum: f64 = rankings.iter().map(|r| r.posterior_prob).sum();

    // Check normalization within floating-point tolerance
    let tolerance = 1e-10;
    if (posterior_sum - 1.0).abs() < tolerance {
        TestResult::Pass
    } else {
        TestResult::Fail {
            reason: format!(
                "Posterior probabilities sum to {}, not 1.0 (tolerance {})",
                posterior_sum, tolerance
            ),
        }
    }
}

fn test_normalized_uniform_prior_sum() -> TestResult {
    let diagnostics = BayesianDiagnostics::new(); // No observations

    let candidates = vec![candidate_a(), candidate_b(), candidate_c()];
    let rankings = diagnostics.rank_candidates(&candidates, &[]);

    // With no observations, should get uniform priors that sum to 1.0
    let posterior_sum: f64 = rankings.iter().map(|r| r.posterior_prob).sum();
    let prior_sum: f64 = rankings.iter().map(|r| r.prior_prob).sum();

    let tolerance = 1e-10;
    if (posterior_sum - 1.0).abs() < tolerance && (prior_sum - 1.0).abs() < tolerance {
        TestResult::Pass
    } else {
        TestResult::Fail {
            reason: format!(
                "Uniform priors: posterior sum = {}, prior sum = {} (expected 1.0)",
                posterior_sum, prior_sum
            ),
        }
    }
}

// ---------------------------------------------------------------------------
// INV-BAYES-TRANSPARENT: Full diagnostic information included
// ---------------------------------------------------------------------------

fn test_transparent_complete_diagnostic_info() -> TestResult {
    let mut diagnostics = BayesianDiagnostics::new();

    // Add observations
    diagnostics.update(&success_observation(candidate_a(), test_epoch()));
    diagnostics.update(&failure_observation(candidate_a(), test_epoch() + 1));

    let candidates = vec![candidate_a()];
    let rankings = diagnostics.rank_candidates(&candidates, &[]);

    if rankings.len() != 1 {
        return TestResult::Fail {
            reason: "Expected exactly one ranking".to_string(),
        };
    }

    let ranking = &rankings[0];

    // Verify all required diagnostic information is present and valid
    let has_posterior = ranking.posterior_prob.is_finite()
        && ranking.posterior_prob >= 0.0
        && ranking.posterior_prob <= 1.0;
    let has_prior =
        ranking.prior_prob.is_finite() && ranking.prior_prob >= 0.0 && ranking.prior_prob <= 1.0;
    let has_count = ranking.observation_count > 0; // We added observations
    let has_ci = ranking.confidence_interval.0.is_finite()
        && ranking.confidence_interval.1.is_finite()
        && ranking.confidence_interval.0 <= ranking.confidence_interval.1;

    if has_posterior && has_prior && has_count && has_ci {
        TestResult::Pass
    } else {
        TestResult::Fail {
            reason: format!(
                "Missing transparent diagnostic info: posterior_valid={}, prior_valid={}, count_valid={}, ci_valid={}",
                has_posterior, has_prior, has_count, has_ci
            ),
        }
    }
}

fn test_transparent_confidence_interval_properties() -> TestResult {
    let mut diagnostics = BayesianDiagnostics::new();

    // Add enough observations to get meaningful confidence interval
    for i in 0..10 {
        let success = i % 3 == 0; // ~33% success rate
        diagnostics.update(&Observation::new(candidate_a(), success, test_epoch() + i));
    }

    let candidates = vec![candidate_a()];
    let rankings = diagnostics.rank_candidates(&candidates, &[]);

    if rankings.len() != 1 {
        return TestResult::Fail {
            reason: "Expected exactly one ranking".to_string(),
        };
    }

    let ranking = &rankings[0];
    let (ci_lower, ci_upper) = ranking.confidence_interval;
    let posterior = ranking.posterior_prob;

    // Verify confidence interval contains posterior and is well-formed
    if ci_lower <= posterior && posterior <= ci_upper && ci_lower < ci_upper {
        TestResult::Pass
    } else {
        TestResult::Fail {
            reason: format!(
                "Invalid confidence interval: [{}, {}] for posterior {}",
                ci_lower, ci_upper, posterior
            ),
        }
    }
}

// ---------------------------------------------------------------------------
// Edge Cases
// ---------------------------------------------------------------------------

fn test_edge_case_empty_candidates() -> TestResult {
    let diagnostics = BayesianDiagnostics::new();
    let rankings = diagnostics.rank_candidates(&[], &[]);

    if rankings.is_empty() {
        TestResult::Pass
    } else {
        TestResult::Fail {
            reason: "Empty candidates should return empty rankings".to_string(),
        }
    }
}

fn test_edge_case_guardrail_filtering() -> TestResult {
    let mut diagnostics = BayesianDiagnostics::new();

    diagnostics.update(&success_observation(candidate_a(), test_epoch()));
    diagnostics.update(&success_observation(candidate_b(), test_epoch()));

    let candidates = vec![candidate_a(), candidate_b()];
    let blocked = vec![candidate_a()]; // Block the first candidate

    let rankings = diagnostics.rank_candidates(&candidates, &blocked);

    // Verify guardrail filtering is marked correctly
    let a_ranking = rankings.iter().find(|r| r.candidate_ref == candidate_a());
    let b_ranking = rankings.iter().find(|r| r.candidate_ref == candidate_b());

    match (a_ranking, b_ranking) {
        (Some(a), Some(b)) => {
            if a.guardrail_filtered && !b.guardrail_filtered {
                TestResult::Pass
            } else {
                TestResult::Fail {
                    reason: format!(
                        "Guardrail filtering incorrect: a.filtered={}, b.filtered={}",
                        a.guardrail_filtered, b.guardrail_filtered
                    ),
                }
            }
        }
        _ => TestResult::Fail {
            reason: "Missing ranking for one or both candidates".to_string(),
        },
    }
}

// ---------------------------------------------------------------------------
// Integration Tests
// ---------------------------------------------------------------------------

fn test_integration_full_bayesian_workflow() -> TestResult {
    let mut diagnostics = BayesianDiagnostics::with_epoch(test_epoch());

    // Simulate a full workflow: observations -> ranking -> transparency check
    let observations = vec![
        success_observation(candidate_a(), test_epoch()),
        success_observation(candidate_a(), test_epoch() + 1),
        failure_observation(candidate_b(), test_epoch() + 2),
        success_observation(candidate_c(), test_epoch() + 3),
        success_observation(candidate_c(), test_epoch() + 4),
        success_observation(candidate_c(), test_epoch() + 5),
    ];

    // Update with all observations
    for obs in observations {
        diagnostics.update(&obs);
    }

    let candidates = vec![candidate_a(), candidate_b(), candidate_c()];
    let rankings = diagnostics.rank_candidates(&candidates, &[]);

    // Verify full workflow properties
    let proper_ranking = rankings.len() == 3;
    let normalized = {
        let sum: f64 = rankings.iter().map(|r| r.posterior_prob).sum();
        (sum - 1.0).abs() < 1e-10
    };
    let transparent = rankings.iter().all(|r| {
        r.posterior_prob.is_finite()
            && r.observation_count > 0
            && r.confidence_interval.0 <= r.confidence_interval.1
    });
    let descending_order = rankings
        .windows(2)
        .all(|w| w[0].posterior_prob >= w[1].posterior_prob);

    if proper_ranking && normalized && transparent && descending_order {
        TestResult::Pass
    } else {
        TestResult::Fail {
            reason: format!(
                "Full workflow failed: ranking={}, normalized={}, transparent={}, ordered={}",
                proper_ranking, normalized, transparent, descending_order
            ),
        }
    }
}

// ---------------------------------------------------------------------------
// Runtime Sentinel E-Process
// ---------------------------------------------------------------------------

fn test_e_process_replay_is_bit_exact() -> TestResult {
    let evidence = vec![
        LikelihoodRatioEvidence::new("bpet_drift", 1, E_PROCESS_SCALE_PPM * 2),
        LikelihoodRatioEvidence::new("ssrf_denial", 2, E_PROCESS_SCALE_PPM * 3),
        LikelihoodRatioEvidence::new("revocation_freshness", 3, E_PROCESS_SCALE_PPM / 2),
    ];

    let first = match RuntimeSentinelEProcess::replay_from(&evidence) {
        Ok(state) => state,
        Err(err) => {
            return TestResult::Fail {
                reason: format!("first replay failed: {err:?}"),
            };
        }
    };
    let second = match RuntimeSentinelEProcess::replay_from(&evidence) {
        Ok(state) => state,
        Err(err) => {
            return TestResult::Fail {
                reason: format!("second replay failed: {err:?}"),
            };
        }
    };

    if first == second && first.e_value_ppm == E_PROCESS_SCALE_PPM * 3 {
        TestResult::Pass
    } else {
        TestResult::Fail {
            reason: format!(
                "e-process replay was not bit-exact: first={first:?}, second={second:?}"
            ),
        }
    }
}

fn test_e_process_mixture_order_is_deterministic() -> TestResult {
    let left = vec![
        MixtureSprtComponent::new("slow_drift", 250_000, E_PROCESS_SCALE_PPM * 4),
        MixtureSprtComponent::new("capability_denial", 750_000, E_PROCESS_SCALE_PPM * 2),
    ];
    let right = vec![
        MixtureSprtComponent::new("capability_denial", 750_000, E_PROCESS_SCALE_PPM * 2),
        MixtureSprtComponent::new("slow_drift", 250_000, E_PROCESS_SCALE_PPM * 4),
    ];

    let left_evidence = match LikelihoodRatioEvidence::from_mixture("mixed", 1, &left) {
        Ok(evidence) => evidence,
        Err(err) => {
            return TestResult::Fail {
                reason: format!("left mixture failed: {err:?}"),
            };
        }
    };
    let right_evidence = match LikelihoodRatioEvidence::from_mixture("mixed", 1, &right) {
        Ok(evidence) => evidence,
        Err(err) => {
            return TestResult::Fail {
                reason: format!("right mixture failed: {err:?}"),
            };
        }
    };

    if left_evidence.likelihood_ratio_ppm == right_evidence.likelihood_ratio_ppm
        && left_evidence.likelihood_ratio_ppm == 2_500_000
    {
        TestResult::Pass
    } else {
        TestResult::Fail {
            reason: format!(
                "mixture order changed likelihood ratio: left={}, right={}",
                left_evidence.likelihood_ratio_ppm, right_evidence.likelihood_ratio_ppm
            ),
        }
    }
}

fn test_e_process_rejects_non_monotonic_replay() -> TestResult {
    let evidence = vec![
        LikelihoodRatioEvidence::new("first", 2, E_PROCESS_SCALE_PPM * 2),
        LikelihoodRatioEvidence::new("second", 2, E_PROCESS_SCALE_PPM * 2),
    ];

    match RuntimeSentinelEProcess::replay_from(&evidence) {
        Ok(state) => TestResult::Fail {
            reason: format!("non-monotonic evidence was accepted: {state:?}"),
        },
        Err(_) => TestResult::Pass,
    }
}

fn test_e_process_ville_bound_controls_escalation() -> TestResult {
    let evidence = vec![LikelihoodRatioEvidence::new(
        "strong_signal",
        1,
        E_PROCESS_SCALE_PPM * 10,
    )];
    let state = match RuntimeSentinelEProcess::replay_from(&evidence) {
        Ok(state) => state,
        Err(err) => {
            return TestResult::Fail {
                reason: format!("replay failed: {err:?}"),
            };
        }
    };

    let bound = state.false_alarm_bound_ppm();
    if bound == 100_000 && state.should_escalate(100_000) && !state.should_escalate(99_999) {
        TestResult::Pass
    } else {
        TestResult::Fail {
            reason: format!("unexpected Ville bound/escalation behavior: bound={bound}"),
        }
    }
}

// ---------------------------------------------------------------------------
// Test Registry & Runner
// ---------------------------------------------------------------------------

const CONFORMANCE_TESTS: &[ConformanceTestCase] = &[
    // INV-BAYES-ADVISORY tests
    ConformanceTestCase {
        id: "BD2IGI-ADV-001",
        requirement_level: RequirementLevel::Must,
        category: TestCategory::Advisory,
        description: "Ranking returns diagnostic data only, executes no actions",
        test_fn: test_advisory_only_returns_rankings,
    },
    ConformanceTestCase {
        id: "BD2IGI-ADV-002",
        requirement_level: RequirementLevel::Must,
        category: TestCategory::Advisory,
        description: "Ranking calls are immutable operations (purely advisory)",
        test_fn: test_advisory_immutable_ranking_call,
    },
    // INV-BAYES-REPRODUCIBLE tests
    ConformanceTestCase {
        id: "BD2IGI-REPRO-001",
        requirement_level: RequirementLevel::Must,
        category: TestCategory::Reproducibility,
        description: "Identical observation sequences produce bit-identical rankings",
        test_fn: test_reproducible_identical_observations,
    },
    ConformanceTestCase {
        id: "BD2IGI-REPRO-002",
        requirement_level: RequirementLevel::Must,
        category: TestCategory::Reproducibility,
        description: "Ranking reduction order is deterministic",
        test_fn: test_reproducible_deterministic_reduction_order,
    },
    // INV-BAYES-NORMALIZED tests
    ConformanceTestCase {
        id: "BD2IGI-NORM-001",
        requirement_level: RequirementLevel::Must,
        category: TestCategory::Normalization,
        description: "Posterior probabilities sum to 1.0 within floating-point tolerance",
        test_fn: test_normalized_posterior_sum,
    },
    ConformanceTestCase {
        id: "BD2IGI-NORM-002",
        requirement_level: RequirementLevel::Must,
        category: TestCategory::Normalization,
        description: "Uniform priors sum to 1.0 when no observations exist",
        test_fn: test_normalized_uniform_prior_sum,
    },
    // INV-BAYES-TRANSPARENT tests
    ConformanceTestCase {
        id: "BD2IGI-TRANS-001",
        requirement_level: RequirementLevel::Must,
        category: TestCategory::Transparency,
        description: "Rankings include full posterior, prior, observation count, confidence interval",
        test_fn: test_transparent_complete_diagnostic_info,
    },
    ConformanceTestCase {
        id: "BD2IGI-TRANS-002",
        requirement_level: RequirementLevel::Should,
        category: TestCategory::Transparency,
        description: "Confidence intervals contain posterior mean and are well-formed",
        test_fn: test_transparent_confidence_interval_properties,
    },
    // Edge cases
    ConformanceTestCase {
        id: "BD2IGI-EDGE-001",
        requirement_level: RequirementLevel::Should,
        category: TestCategory::EdgeCase,
        description: "Empty candidates list returns empty rankings",
        test_fn: test_edge_case_empty_candidates,
    },
    ConformanceTestCase {
        id: "BD2IGI-EDGE-002",
        requirement_level: RequirementLevel::Should,
        category: TestCategory::EdgeCase,
        description: "Guardrail filtering correctly marks blocked candidates",
        test_fn: test_edge_case_guardrail_filtering,
    },
    // Integration
    ConformanceTestCase {
        id: "BD2IGI-INT-001",
        requirement_level: RequirementLevel::Should,
        category: TestCategory::Integration,
        description: "Full Bayesian workflow: observations → ranking → transparency verification",
        test_fn: test_integration_full_bayesian_workflow,
    },
    // Runtime Sentinel e-process tests
    ConformanceTestCase {
        id: "BD2IGI-EPROC-001",
        requirement_level: RequirementLevel::Must,
        category: TestCategory::EProcess,
        description: "Likelihood-ratio e-process replay is bit-exact and fixed-point",
        test_fn: test_e_process_replay_is_bit_exact,
    },
    ConformanceTestCase {
        id: "BD2IGI-EPROC-002",
        requirement_level: RequirementLevel::Must,
        category: TestCategory::EProcess,
        description: "Mixture-SPRT component ordering is deterministic",
        test_fn: test_e_process_mixture_order_is_deterministic,
    },
    ConformanceTestCase {
        id: "BD2IGI-EPROC-003",
        requirement_level: RequirementLevel::Must,
        category: TestCategory::EProcess,
        description: "Runtime Sentinel e-process rejects non-monotonic evidence",
        test_fn: test_e_process_rejects_non_monotonic_replay,
    },
    ConformanceTestCase {
        id: "BD2IGI-EPROC-004",
        requirement_level: RequirementLevel::Must,
        category: TestCategory::EProcess,
        description: "Ville false-alarm bound controls escalation",
        test_fn: test_e_process_ville_bound_controls_escalation,
    },
];

pub fn run_conformance_tests() -> ConformanceReport {
    let mut results = Vec::new();
    let mut must_pass = 0;
    let mut must_fail = 0;
    let mut should_pass = 0;
    let mut should_fail = 0;

    for test_case in CONFORMANCE_TESTS {
        let result = (test_case.test_fn)();

        match (&result, &test_case.requirement_level) {
            (TestResult::Pass, RequirementLevel::Must) => must_pass += 1,
            (TestResult::Fail { .. }, RequirementLevel::Must) => must_fail += 1,
            (TestResult::Pass, RequirementLevel::Should) => should_pass += 1,
            (TestResult::Fail { .. }, RequirementLevel::Should) => should_fail += 1,
            _ => {} // Skip/XFAIL don't count toward pass/fail
        }

        // Structured JSON-line output for CI parsing
        println!(
            "{{\"id\":\"{}\",\"verdict\":\"{}\",\"level\":\"{:?}\",\"category\":\"{:?}\"}}",
            test_case.id,
            match &result {
                TestResult::Pass => "PASS",
                TestResult::Fail { .. } => "FAIL",
                TestResult::Skipped { .. } => "SKIP",
                TestResult::ExpectedFailure { .. } => "XFAIL",
            },
            test_case.requirement_level,
            test_case.category
        );

        if let TestResult::Fail { reason } = &result {
            eprintln!(
                "FAIL {}: {}\n  Reason: {}",
                test_case.id, test_case.description, reason
            );
        }

        results.push(TestCaseResult {
            id: test_case.id,
            description: test_case.description,
            requirement_level: test_case.requirement_level.clone(),
            category: test_case.category.clone(),
            result,
        });
    }

    let total_must = must_pass + must_fail;
    let total_should = should_pass + should_fail;
    let must_score = if total_must > 0 {
        (must_pass as f64 / total_must as f64) * 100.0
    } else {
        100.0
    };
    let should_score = if total_should > 0 {
        (should_pass as f64 / total_should as f64) * 100.0
    } else {
        100.0
    };

    println!("\nbd-2igi Bayesian Diagnostics Conformance Report:");
    println!(
        "MUST clauses: {}/{} pass ({:.1}%)",
        must_pass, total_must, must_score
    );
    println!(
        "SHOULD clauses: {}/{} pass ({:.1}%)",
        should_pass, total_should, should_score
    );

    assert_eq!(
        must_fail, 0,
        "{} MUST-level conformance tests failed",
        must_fail
    );

    ConformanceReport {
        must_pass,
        must_fail,
        must_score,
        should_pass,
        should_fail,
        should_score,
        results,
    }
}

#[derive(Debug)]
pub struct ConformanceReport {
    pub must_pass: usize,
    pub must_fail: usize,
    pub must_score: f64,
    pub should_pass: usize,
    pub should_fail: usize,
    pub should_score: f64,
    pub results: Vec<TestCaseResult>,
}

#[derive(Debug)]
pub struct TestCaseResult {
    pub id: &'static str,
    pub description: &'static str,
    pub requirement_level: RequirementLevel,
    pub category: TestCategory,
    pub result: TestResult,
}

#[cfg(test)]
mod conformance_tests {
    use super::*;

    #[test]
    fn bd_2igi_bayesian_diagnostics_conformance() {
        run_conformance_tests();
    }
}
