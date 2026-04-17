// Comprehensive conformance tests for BOCPD - edge cases and hardening patterns
//
// Tests focus on:
// - Arithmetic overflow/underflow scenarios
// - NaN/Inf input handling
// - Boundary conditions
// - Memory bounds
// - Division by zero scenarios
// - Large input sequences

use super::bocpd::*;
use std::f64;

/// Test saturating arithmetic patterns in GaussianSuffStats
#[test]
fn test_gaussian_stats_overflow_protection() {
    let mut stats = GaussianSuffStats::new();

    // Test massive number of observations (overflow scenario)
    for _ in 0..10000 {
        stats.update(f64::MAX / 10000.0);
    }

    // Stats should remain finite and not overflow
    assert!(stats.n.is_finite(), "n should remain finite");
    assert!(
        stats.mean.is_finite() || stats.mean == 0.0,
        "mean should be finite or reset to 0"
    );
    assert!(
        stats.sum_sq.is_finite() || stats.sum_sq == 0.0,
        "sum_sq should be finite or reset to 0"
    );
}

/// Test PoissonSuffStats overflow protection
#[test]
fn test_poisson_stats_overflow_protection() {
    let mut stats = PoissonSuffStats::new();

    // Test massive inputs
    for _ in 0..10000 {
        stats.update(f64::MAX / 10000.0);
    }

    assert!(stats.n.is_finite(), "n should remain finite");
    assert!(
        stats.sum.is_finite() || stats.sum == 0.0,
        "sum should be finite or reset to 0"
    );
}

/// Test CategoricalSuffStats overflow protection
#[test]
fn test_categorical_stats_overflow_protection() {
    let mut stats = CategoricalSuffStats::new(5);

    // Test massive updates to same category
    for _ in 0..10000 {
        stats.update(0);
    }

    assert!(stats.counts[0].is_finite(), "counts should remain finite");
}

/// Test detector with extreme input values
#[test]
fn test_detector_extreme_inputs() {
    let mut det = BocpdDetector::new(
        "extreme_test",
        BocpdConfig::default(),
        HazardFunction::Constant { lambda: 100.0 },
        ObservationModel::Gaussian(GaussianModel::default()),
    )
    .unwrap();

    // Test with very large values
    det.observe(f64::MAX / 1000.0, 1000);
    assert_eq!(det.observation_count(), 1);

    // Test with very small values
    det.observe(f64::MIN_POSITIVE, 1001);
    assert_eq!(det.observation_count(), 2);

    // Test with zero
    det.observe(0.0, 1002);
    assert_eq!(det.observation_count(), 3);

    // Test with negative values
    det.observe(-1000.0, 1003);
    assert_eq!(det.observation_count(), 4);

    // Posterior should still sum to ~1.0
    assert!((det.posterior_sum() - 1.0).abs() < 1e-6);
}

/// Test detector with NaN and infinity inputs (should be rejected)
#[test]
fn test_detector_invalid_inputs() {
    let mut det = BocpdDetector::new(
        "invalid_test",
        BocpdConfig::default(),
        HazardFunction::Constant { lambda: 100.0 },
        ObservationModel::Gaussian(GaussianModel::default()),
    )
    .unwrap();

    let initial_count = det.observation_count();

    // NaN should be rejected
    let result = det.observe(f64::NAN, 1000);
    assert!(result.is_none());
    assert_eq!(det.observation_count(), initial_count);

    // Positive infinity should be rejected
    let result = det.observe(f64::INFINITY, 1001);
    assert!(result.is_none());
    assert_eq!(det.observation_count(), initial_count);

    // Negative infinity should be rejected
    let result = det.observe(f64::NEG_INFINITY, 1002);
    assert!(result.is_none());
    assert_eq!(det.observation_count(), initial_count);
}

/// Test hazard function edge cases
#[test]
fn test_hazard_function_edge_cases() {
    // Test constant hazard with edge values
    let h1 = HazardFunction::Constant {
        lambda: f64::MIN_POSITIVE,
    };
    assert!(h1.evaluate(0) > 0.0 && h1.evaluate(0).is_finite());

    let h2 = HazardFunction::Constant { lambda: f64::MAX };
    assert!(h2.evaluate(0) > 0.0 && h2.evaluate(0) < 1e-300); // Should be very small

    // Test with invalid lambda values
    let h3 = HazardFunction::Constant { lambda: 0.0 };
    assert_eq!(h3.evaluate(0), 0.0);

    let h4 = HazardFunction::Constant { lambda: -1.0 };
    assert_eq!(h4.evaluate(0), 0.0);

    let h5 = HazardFunction::Constant { lambda: f64::NAN };
    assert_eq!(h5.evaluate(0), 0.0);

    // Test geometric hazard edge cases
    let g1 = HazardFunction::Geometric { p: 0.0 };
    assert_eq!(g1.evaluate(0), 0.0);

    let g2 = HazardFunction::Geometric { p: 1.0 };
    assert_eq!(g2.evaluate(0), 1.0);

    let g3 = HazardFunction::Geometric { p: f64::NAN };
    assert_eq!(g3.evaluate(0), 0.0);

    let g4 = HazardFunction::Geometric { p: -0.1 };
    assert_eq!(g4.evaluate(0), 0.0);
}

/// Test observation model edge cases
#[test]
fn test_gaussian_model_edge_cases() {
    let model = GaussianModel {
        mu0: 0.0,
        kappa0: f64::MIN_POSITIVE, // Very small precision
        alpha0: 0.1,
        beta0: 0.1,
    };

    let mut stats = GaussianSuffStats::new();
    stats.update(100.0);
    stats.update(200.0);

    let prob = model.predictive_prob(&stats, 150.0);
    assert!(prob > 0.0 && prob.is_finite());

    // Test with zero/negative hyperparameters
    let model2 = GaussianModel {
        mu0: 0.0,
        kappa0: 0.0, // Should cause fallback
        alpha0: 0.0,
        beta0: 0.0,
    };

    let prob2 = model2.predictive_prob(&stats, 150.0);
    assert_eq!(prob2, 1e-300); // Should return minimum probability
}

/// Test Poisson model edge cases
#[test]
fn test_poisson_model_edge_cases() {
    let model = PoissonModel {
        alpha0: 0.1,
        beta0: 0.1,
    };

    let mut stats = PoissonSuffStats::new();
    stats.update(5.0);
    stats.update(3.0);

    // Test negative observation (should return 0)
    assert_eq!(model.predictive_prob(&stats, -1.0), 0.0);

    // Test very large observation
    let prob = model.predictive_prob(&stats, 1000.0);
    assert!(prob >= 0.0 && prob.is_finite());
}

/// Test categorical model edge cases
#[test]
fn test_categorical_model_edge_cases() {
    let model = CategoricalModel { k: 3, alpha0: 0.1 };

    let stats = CategoricalSuffStats::new(3);

    // Test out-of-bounds category
    assert_eq!(model.predictive_prob(&stats, 5), 1e-300);

    // Test with zero alpha0
    let model2 = CategoricalModel { k: 3, alpha0: 0.0 };

    let prob = model2.predictive_prob(&stats, 0);
    assert!(prob >= 0.0);
}

/// Test multi-stream correlator edge cases
#[test]
fn test_correlator_edge_cases() {
    let mut correlator = MultiStreamCorrelator::new(0); // Zero window

    let shift1 = RegimeShift {
        stream_name: "test1".to_string(),
        timestamp: 1000,
        confidence: 0.8,
        run_length: 10,
        old_regime_mean: 5.0,
        new_regime_mean: 15.0,
    };

    let shift2 = RegimeShift {
        stream_name: "test2".to_string(),
        timestamp: 1000,
        confidence: 0.9,
        run_length: 8,
        old_regime_mean: 3.0,
        new_regime_mean: 12.0,
    };

    correlator.record_shift(shift1);
    let correlated = correlator.record_shift(shift2);

    // With zero window, no correlation should be found
    assert!(correlated.is_empty());
}

/// Test detector memory bounds
#[test]
fn test_detector_memory_bounds() {
    let config = BocpdConfig {
        hazard_lambda: 50.0,
        changepoint_threshold: 0.3,
        min_run_length: 5,
        max_run_length: 100, // Limited memory
        max_regime_history: 10,
        correlation_window_secs: 60,
    };

    let mut det = BocpdDetector::new(
        "bounded_test",
        config,
        HazardFunction::Constant { lambda: 50.0 },
        ObservationModel::Gaussian(GaussianModel::default()),
    )
    .unwrap();

    // Process many observations to test memory bounds
    for i in 0..500 {
        let value = if i % 100 < 50 { 10.0 } else { 50.0 };
        det.observe(value, i as u64);
    }

    // Memory should be bounded
    assert!(det.run_length_probs.len() <= 102); // max_run_length + 1 + small buffer
    assert!(det.regime_history().len() <= 10);
}

/// Test ln_gamma function edge cases
#[test]
fn test_ln_gamma_edge_cases() {
    use super::bocpd::ln_gamma;

    // Test very small positive values
    let result = ln_gamma(1e-10);
    assert!(result.is_finite());

    // Test values close to 1
    let result = ln_gamma(1.0 + 1e-10);
    assert!(result.is_finite() && result.abs() < 1.0);

    // Test larger values
    let result = ln_gamma(100.0);
    assert!(result.is_finite() && result > 0.0);

    // Test negative values (should return infinity)
    let result = ln_gamma(-1.0);
    assert_eq!(result, f64::INFINITY);

    // Test zero
    let result = ln_gamma(0.0);
    assert_eq!(result, f64::INFINITY);
}

/// Test config validation edge cases
#[test]
fn test_config_validation_edge_cases() {
    // Test valid edge case configs
    let config1 = BocpdConfig {
        hazard_lambda: f64::MIN_POSITIVE,
        changepoint_threshold: 0.0, // Minimum threshold
        min_run_length: 1,
        max_run_length: 1,
        max_regime_history: 1,
        correlation_window_secs: 0,
    };
    assert!(config1.validate().is_ok());

    let config2 = BocpdConfig {
        hazard_lambda: f64::MAX,
        changepoint_threshold: 1.0, // Maximum threshold
        min_run_length: usize::MAX,
        max_run_length: usize::MAX,
        max_regime_history: usize::MAX,
        correlation_window_secs: u64::MAX,
    };
    assert!(config2.validate().is_ok());

    // Test invalid configs
    let bad_config1 = BocpdConfig {
        hazard_lambda: f64::NAN,
        ..BocpdConfig::default()
    };
    assert!(bad_config1.validate().is_err());

    let bad_config2 = BocpdConfig {
        changepoint_threshold: -0.1,
        ..BocpdConfig::default()
    };
    assert!(bad_config2.validate().is_err());

    let bad_config3 = BocpdConfig {
        changepoint_threshold: 1.1,
        ..BocpdConfig::default()
    };
    assert!(bad_config3.validate().is_err());

    let bad_config4 = BocpdConfig {
        max_run_length: 0,
        ..BocpdConfig::default()
    };
    assert!(bad_config4.validate().is_err());
}

/// Test detector with rapidly alternating regime changes
#[test]
fn test_rapid_regime_changes() {
    let config = BocpdConfig {
        hazard_lambda: 5.0,         // High hazard for frequent changepoints
        changepoint_threshold: 0.1, // Low threshold
        min_run_length: 2,
        max_run_length: 50,
        max_regime_history: 100,
        correlation_window_secs: 60,
    };

    let mut det = BocpdDetector::new(
        "rapid_test",
        config,
        HazardFunction::Constant { lambda: 5.0 },
        ObservationModel::Gaussian(GaussianModel {
            mu0: 0.0,
            kappa0: 0.1,
            alpha0: 1.0,
            beta0: 0.1,
        }),
    )
    .unwrap();

    let mut shift_count = 0;
    for i in 0..200 {
        // Rapidly alternating values
        let value = if i % 4 < 2 { 0.0 } else { 100.0 };
        if det.observe(value, i as u64).is_some() {
            shift_count += 1;
        }
    }

    // Should detect multiple shifts but not too many (avoid false positives)
    assert!(shift_count >= 1, "Should detect at least one shift");
    assert!(
        shift_count <= 50,
        "Should not have excessive false positives"
    );

    // Posterior should still be valid
    assert!((det.posterior_sum() - 1.0).abs() < 1e-6);
}

/// Test timestamp overflow scenarios
#[test]
fn test_timestamp_edge_cases() {
    let mut correlator = MultiStreamCorrelator::new(3600);

    // Test with maximum timestamp values
    let shift1 = RegimeShift {
        stream_name: "test1".to_string(),
        timestamp: u64::MAX - 1000,
        confidence: 0.8,
        run_length: 10,
        old_regime_mean: 5.0,
        new_regime_mean: 15.0,
    };

    let shift2 = RegimeShift {
        stream_name: "test2".to_string(),
        timestamp: u64::MAX,
        confidence: 0.9,
        run_length: 8,
        old_regime_mean: 3.0,
        new_regime_mean: 12.0,
    };

    correlator.record_shift(shift1);
    let correlated = correlator.record_shift(shift2);

    // Should handle overflow gracefully
    assert!(correlated.len() <= 1);

    // Test with zero timestamps
    let shift3 = RegimeShift {
        stream_name: "test3".to_string(),
        timestamp: 0,
        confidence: 0.7,
        run_length: 5,
        old_regime_mean: 1.0,
        new_regime_mean: 10.0,
    };

    correlator.record_shift(shift3);
    assert!(correlator.recent_count() >= 1);
}

#[test]
fn negative_detector_rejects_zero_hazard_lambda_config() {
    let config = BocpdConfig {
        hazard_lambda: 0.0,
        ..BocpdConfig::default()
    };

    let err = BocpdDetector::new(
        "bad_zero_hazard",
        config,
        HazardFunction::Constant { lambda: 1.0 },
        ObservationModel::Gaussian(GaussianModel::default()),
    )
    .unwrap_err();

    assert!(matches!(err, BocpdError::InvalidConfig(_)));
    assert!(err.to_string().contains(ERR_BCP_INVALID_CONFIG));
}

#[test]
fn negative_detector_rejects_infinite_hazard_lambda_config() {
    let config = BocpdConfig {
        hazard_lambda: f64::INFINITY,
        ..BocpdConfig::default()
    };

    let err = BocpdDetector::new(
        "bad_infinite_hazard",
        config,
        HazardFunction::Constant { lambda: 1.0 },
        ObservationModel::Gaussian(GaussianModel::default()),
    )
    .unwrap_err();

    assert!(matches!(err, BocpdError::InvalidConfig(_)));
}

#[test]
fn negative_detector_rejects_nan_threshold_config() {
    let config = BocpdConfig {
        changepoint_threshold: f64::NAN,
        ..BocpdConfig::default()
    };

    let err = BocpdDetector::new(
        "bad_nan_threshold",
        config,
        HazardFunction::Constant { lambda: 1.0 },
        ObservationModel::Gaussian(GaussianModel::default()),
    )
    .unwrap_err();

    assert!(matches!(err, BocpdError::InvalidConfig(_)));
}

#[test]
fn negative_detector_rejects_zero_max_run_length_config() {
    let config = BocpdConfig {
        max_run_length: 0,
        ..BocpdConfig::default()
    };

    let err = BocpdDetector::new(
        "bad_zero_run_length",
        config,
        HazardFunction::Constant { lambda: 1.0 },
        ObservationModel::Gaussian(GaussianModel::default()),
    )
    .unwrap_err();

    assert!(matches!(err, BocpdError::InvalidConfig(_)));
}

#[test]
fn negative_non_finite_observations_do_not_mutate_detector() {
    let mut det = BocpdDetector::new(
        "non_finite_negative",
        BocpdConfig::default(),
        HazardFunction::Constant { lambda: 100.0 },
        ObservationModel::Gaussian(GaussianModel::default()),
    )
    .unwrap();

    for value in [f64::NAN, f64::INFINITY, f64::NEG_INFINITY] {
        assert!(det.observe(value, 1_000).is_none());
    }

    assert_eq!(det.observation_count(), 0);
    assert_eq!(det.events().len(), 0);
    assert_eq!(det.map_run_length(), 0);
    assert!((det.posterior_sum() - 1.0).abs() < 1e-6);
}

#[test]
fn negative_poisson_model_rejects_non_finite_observations() {
    let model = PoissonModel::default();
    let mut stats = PoissonSuffStats::new();
    stats.update(3.0);

    assert_eq!(model.predictive_prob(&stats, f64::NAN), 0.0);
    assert_eq!(model.predictive_prob(&stats, f64::INFINITY), 0.0);
    assert_eq!(model.predictive_prob(&stats, f64::NEG_INFINITY), 0.0);
}

#[test]
fn negative_categorical_stats_ignore_out_of_range_updates() {
    let mut stats = CategoricalSuffStats::new(2);

    stats.update(usize::MAX);
    stats.update(2);

    assert_eq!(stats.counts, vec![0.0, 0.0]);
}

#[test]
fn negative_categorical_zero_width_model_returns_floor_probability() {
    let model = CategoricalModel { k: 0, alpha0: 1.0 };
    let stats = CategoricalSuffStats::new(0);

    assert_eq!(model.predictive_prob(&stats, 0), 1e-300);
}

#[test]
fn negative_same_stream_shift_is_not_correlated() {
    let mut correlator = MultiStreamCorrelator::new(60);
    let first = RegimeShift {
        stream_name: "same-stream".to_string(),
        timestamp: 1_000,
        confidence: 0.8,
        run_length: 5,
        old_regime_mean: 1.0,
        new_regime_mean: 10.0,
    };
    let second = RegimeShift {
        stream_name: "same-stream".to_string(),
        timestamp: 1_010,
        confidence: 0.9,
        run_length: 6,
        old_regime_mean: 2.0,
        new_regime_mean: 20.0,
    };

    assert!(correlator.record_shift(first).is_empty());
    assert!(correlator.record_shift(second).is_empty());
    assert_eq!(correlator.recent_count(), 2);
}

#[test]
fn negative_correlator_prunes_old_shifts_before_matching() {
    let mut correlator = MultiStreamCorrelator::new(5);
    let old_shift = RegimeShift {
        stream_name: "old-stream".to_string(),
        timestamp: 1_000,
        confidence: 0.8,
        run_length: 5,
        old_regime_mean: 1.0,
        new_regime_mean: 10.0,
    };
    let new_shift = RegimeShift {
        stream_name: "new-stream".to_string(),
        timestamp: 1_010,
        confidence: 0.9,
        run_length: 6,
        old_regime_mean: 2.0,
        new_regime_mean: 20.0,
    };

    correlator.record_shift(old_shift);
    let correlated = correlator.record_shift(new_shift);

    assert!(correlated.is_empty());
    assert_eq!(correlator.recent_count(), 1);
}

#[test]
fn negative_detector_rejects_zero_min_run_length_config() {
    let config = BocpdConfig {
        min_run_length: 0,
        ..BocpdConfig::default()
    };

    let err = BocpdDetector::new(
        "bad_zero_min_run",
        config,
        HazardFunction::Constant { lambda: 1.0 },
        ObservationModel::Gaussian(GaussianModel::default()),
    )
    .unwrap_err();

    assert!(matches!(err, BocpdError::InvalidConfig(_)));
    assert!(err.to_string().contains("min_run_length"));
}

#[test]
fn negative_detector_rejects_min_run_length_above_max() {
    let config = BocpdConfig {
        min_run_length: 10,
        max_run_length: 9,
        ..BocpdConfig::default()
    };

    let err = BocpdDetector::new(
        "bad_min_above_max",
        config,
        HazardFunction::Constant { lambda: 1.0 },
        ObservationModel::Gaussian(GaussianModel::default()),
    )
    .unwrap_err();

    assert!(matches!(err, BocpdError::InvalidConfig(_)));
    assert!(err.to_string().contains("min_run_length"));
}

#[test]
fn negative_detector_rejects_zero_regime_history_config() {
    let config = BocpdConfig {
        max_regime_history: 0,
        ..BocpdConfig::default()
    };

    let err = BocpdDetector::new(
        "bad_zero_history",
        config,
        HazardFunction::Constant { lambda: 1.0 },
        ObservationModel::Gaussian(GaussianModel::default()),
    )
    .unwrap_err();

    assert!(matches!(err, BocpdError::InvalidConfig(_)));
    assert!(err.to_string().contains("max_regime_history"));
}

#[test]
fn negative_detector_rejects_noncanonical_stream_names() {
    for stream_name in ["", " ", "bad stream", "\tbad", "bad\n"] {
        let err = BocpdDetector::new(
            stream_name,
            BocpdConfig::default(),
            HazardFunction::Constant { lambda: 1.0 },
            ObservationModel::Gaussian(GaussianModel::default()),
        )
        .unwrap_err();

        assert!(matches!(err, BocpdError::InvalidConfig(_)));
        assert!(err.to_string().contains("stream_name"));
    }
}

#[test]
fn negative_poisson_stats_ignore_invalid_updates() {
    let mut stats = PoissonSuffStats::new();

    for value in [-1.0, 1.5, f64::NAN, f64::INFINITY, f64::NEG_INFINITY] {
        stats.update(value);
    }

    assert_eq!(stats.n, 0.0);
    assert_eq!(stats.sum, 0.0);
}

#[test]
fn negative_categorical_model_rejects_mismatched_stats_width() {
    let model = CategoricalModel { k: 3, alpha0: 1.0 };
    let stats = CategoricalSuffStats::new(2);

    assert_eq!(model.predictive_prob(&stats, 0), 1e-300);
}

#[test]
fn negative_correlator_rejects_zero_run_length_shift() {
    let mut correlator = MultiStreamCorrelator::new(60);
    let shift = RegimeShift {
        stream_name: "zero-run".to_string(),
        timestamp: 1_000,
        confidence: 0.8,
        run_length: 0,
        old_regime_mean: 1.0,
        new_regime_mean: 2.0,
    };

    assert!(correlator.record_shift(shift).is_empty());
    assert_eq!(correlator.recent_count(), 0);
}

#[test]
fn negative_correlator_rejects_nonfinite_means() {
    for (old_regime_mean, new_regime_mean) in [
        (f64::NAN, 2.0),
        (1.0, f64::NAN),
        (f64::INFINITY, 2.0),
        (1.0, f64::NEG_INFINITY),
    ] {
        let mut correlator = MultiStreamCorrelator::new(60);
        let shift = RegimeShift {
            stream_name: "nonfinite-mean".to_string(),
            timestamp: 1_000,
            confidence: 0.8,
            run_length: 5,
            old_regime_mean,
            new_regime_mean,
        };

        assert!(correlator.record_shift(shift).is_empty());
        assert_eq!(correlator.recent_count(), 0);
    }
}
