// Regression tests for BOCPD hardening fixes
// Tests security vulnerabilities that were fixed in bd-15rz3, bd-3bggj, bd-1hekx

#[cfg(test)]
mod bocpd_hardening_regression_tests {
    use super::super::bocpd::*;

    // bd-15rz3: Test NaN/infinite guard in PoissonModel::predictive_prob
    #[test]
    fn test_poisson_nan_infinite_guard_regression() {
        let model = PoissonModel::default();
        let stats = PoissonSuffStats { n: 1.0, sum: 5.0 };

        // Should safely handle NaN without panic/undefined behavior
        let result = model.predictive_prob(&stats, f64::NAN);
        assert_eq!(result, 0.0, "NaN input should return 0.0");

        // Should safely handle positive infinity
        let result = model.predictive_prob(&stats, f64::INFINITY);
        assert_eq!(result, 0.0, "Positive infinity should return 0.0");

        // Should safely handle negative infinity
        let result = model.predictive_prob(&stats, f64::NEG_INFINITY);
        assert_eq!(result, 0.0, "Negative infinity should return 0.0");

        // Normal positive values should work
        let result = model.predictive_prob(&stats, 5.0);
        assert!(
            result > 0.0 && result.is_finite(),
            "Normal positive value should return positive finite result: got {}",
            result
        );
    }

    // bd-3bggj: Test overflow protection in CategoricalModel fold operation
    #[test]
    fn test_categorical_fold_overflow_protection_regression() {
        let model = CategoricalModel { k: 3, alpha0: 1.0 };

        // Create stats with very large counts that would overflow with raw addition
        let stats = CategoricalSuffStats {
            counts: vec![f64::MAX / 2.0, f64::MAX / 2.0, 1.0],
        };

        // Should not overflow to infinity - protected by saturating logic
        let result = model.predictive_prob(&stats, 0);
        assert!(
            result.is_finite() && result >= 0.0 && result <= 1.0,
            "Large counts should not cause overflow: got {}",
            result
        );

        // Test with extreme case - all MAX values
        let extreme_stats = CategoricalSuffStats {
            counts: vec![f64::MAX; 3],
        };
        let result = model.predictive_prob(&extreme_stats, 1);
        assert!(
            result.is_finite() && result >= 0.0,
            "Extreme large counts should be handled safely: got {}",
            result
        );
    }

    // bd-1hekx: Test changepoint_mass accumulation overflow protection
    #[test]
    fn test_detector_changepoint_mass_overflow_regression() {
        let mut config = BocpdConfig::default();
        config.max_run_length = 100; // Moderate size to stress-test accumulation
        config.changepoint_threshold = 0.01; // Low threshold to encourage detection

        let mut detector = BocpdDetector::new(
            "test",
            config,
            HazardFunction::Constant { lambda: 1.0 }, // Very high hazard (changepoint every step)
            ObservationModel::Gaussian(GaussianModel {
                mu0: 0.0,
                kappa0: 0.01, // Low precision -> higher probability mass
                alpha0: 0.5,
                beta0: 0.5,
            }),
        )
        .unwrap();

        // Process observations that would cause accumulation overflow without protection
        for i in 0..200 {
            // Large magnitude values to stress numerical stability
            let value = if i % 2 == 0 { 1000.0 } else { -1000.0 };
            let result = detector.observe(value, i as u64);

            // Verify changepoint probability stays finite after each observation
            let cp_prob = detector.changepoint_probability();
            assert!(
                cp_prob.is_finite(),
                "Changepoint probability should stay finite: got {} at iteration {}",
                cp_prob,
                i
            );

            // Verify posterior probabilities stay finite
            let posterior_sum = detector.posterior_sum();
            assert!(
                posterior_sum.is_finite() && posterior_sum > 0.0,
                "Posterior sum should stay finite and positive: got {} at iteration {}",
                posterior_sum,
                i
            );
        }
    }

    // Additional test: Verify normal operation still works after hardening
    #[test]
    fn test_hardening_preserves_normal_operation() {
        let model = PoissonModel::default();
        let stats = PoissonSuffStats { n: 10.0, sum: 50.0 };

        // Normal operation should be unaffected
        let result = model.predictive_prob(&stats, 5.0);
        assert!(
            result > 0.0 && result.is_finite(),
            "Normal operation should work: got {}",
            result
        );

        // Test categorical model normal operation
        let cat_model = CategoricalModel { k: 3, alpha0: 1.0 };
        let cat_stats = CategoricalSuffStats {
            counts: vec![5.0, 3.0, 2.0],
        };
        let result = cat_model.predictive_prob(&cat_stats, 0);
        assert!(
            result > 0.0 && result <= 1.0 && result.is_finite(),
            "Normal categorical operation should work: got {}",
            result
        );

        // Test detector normal operation
        let mut detector = BocpdDetector::new(
            "normal",
            BocpdConfig::default(),
            HazardFunction::Constant { lambda: 200.0 },
            ObservationModel::Gaussian(GaussianModel::default()),
        )
        .unwrap();

        for i in 0..20 {
            detector.observe(10.0 + (i as f64) * 0.1, i as u64);
            assert!(detector.changepoint_probability().is_finite());
            assert!(detector.posterior_sum().is_finite());
        }
    }

    // Edge case: Test boundary values
    #[test]
    fn test_boundary_values() {
        let model = PoissonModel::default();
        let stats = PoissonSuffStats { n: 1.0, sum: 1.0 };

        // Test exactly zero
        let result = model.predictive_prob(&stats, 0.0);
        assert!(
            result.is_finite() && result >= 0.0,
            "Zero should be handled: got {}",
            result
        );

        // Test very small positive
        let result = model.predictive_prob(&stats, f64::MIN_POSITIVE);
        assert!(
            result.is_finite() && result >= 0.0,
            "MIN_POSITIVE should be handled: got {}",
            result
        );

        // Test very large but finite
        let result = model.predictive_prob(&stats, f64::MAX / 2.0);
        assert!(
            result.is_finite() && result >= 0.0,
            "Large finite value should be handled: got {}",
            result
        );
    }

    #[test]
    fn negative_hazard_invalid_parameters_evaluate_to_zero() {
        for hazard in [
            HazardFunction::Constant { lambda: 0.0 },
            HazardFunction::Constant { lambda: -1.0 },
            HazardFunction::Constant { lambda: f64::NAN },
            HazardFunction::Constant {
                lambda: f64::INFINITY,
            },
            HazardFunction::Geometric { p: -0.01 },
            HazardFunction::Geometric { p: 1.01 },
            HazardFunction::Geometric { p: f64::NAN },
        ] {
            assert_eq!(
                hazard.evaluate(0),
                0.0,
                "invalid hazard must not produce changepoint mass: {hazard:?}"
            );
        }
    }

    #[test]
    fn negative_config_rejects_nonfinite_and_out_of_range_thresholds() {
        for threshold in [f64::NAN, f64::INFINITY, f64::NEG_INFINITY, -0.01, 1.01] {
            let mut config = BocpdConfig::default();
            config.changepoint_threshold = threshold;

            assert!(
                config.validate().is_err(),
                "invalid threshold unexpectedly accepted: {threshold:?}"
            );
        }
    }

    #[test]
    fn negative_detector_rejects_noncanonical_stream_names() {
        for stream_name in ["", "   ", " leading", "trailing ", "\tstream"] {
            let err = BocpdDetector::new(
                stream_name,
                BocpdConfig::default(),
                HazardFunction::Constant { lambda: 200.0 },
                ObservationModel::Gaussian(GaussianModel::default()),
            )
            .expect_err("noncanonical stream name must fail detector construction");

            assert!(matches!(
                err,
                BocpdError::InvalidConfig(msg) if msg.contains("stream_name")
            ));
        }
    }

    #[test]
    fn negative_detector_rejects_categorical_state_overflow() {
        let mut config = BocpdConfig::default();
        config.max_run_length = 1;

        let err = BocpdDetector::new(
            "categorical-overflow",
            config,
            HazardFunction::Constant { lambda: 200.0 },
            ObservationModel::Categorical(CategoricalModel {
                k: usize::MAX,
                alpha0: 1.0,
            }),
        )
        .expect_err("oversized categorical state must fail before allocation");

        assert!(matches!(
            err,
            BocpdError::InvalidConfig(msg) if msg.contains("categorical state")
        ));
    }

    #[test]
    fn negative_poisson_detector_rejects_invalid_observations_before_tracking() {
        for x in [-1.0, 1.5, f64::NAN, f64::INFINITY] {
            let mut detector = BocpdDetector::new(
                "poisson-invalid-input",
                BocpdConfig::default(),
                HazardFunction::Constant { lambda: 200.0 },
                ObservationModel::Poisson(PoissonModel::default()),
            )
            .unwrap();

            assert!(
                detector.observe(x, 1).is_none(),
                "invalid poisson observation should not emit a shift: {x:?}"
            );
            assert_eq!(detector.observation_count(), 0);
            assert!(detector.events().is_empty());
        }
    }

    #[test]
    fn negative_categorical_detector_rejects_invalid_observations_before_tracking() {
        for x in [-1.0, 3.0, 1.5, f64::NAN, f64::INFINITY] {
            let mut detector = BocpdDetector::new(
                "categorical-invalid-input",
                BocpdConfig::default(),
                HazardFunction::Constant { lambda: 200.0 },
                ObservationModel::Categorical(CategoricalModel { k: 3, alpha0: 1.0 }),
            )
            .unwrap();

            assert!(
                detector.observe(x, 1).is_none(),
                "invalid categorical observation should not emit a shift: {x:?}"
            );
            assert_eq!(detector.observation_count(), 0);
            assert!(detector.events().is_empty());
        }
    }

    #[test]
    fn negative_correlator_drops_invalid_shift_records() {
        let invalid_shifts = [
            RegimeShift {
                stream_name: String::new(),
                timestamp: 10,
                confidence: 0.8,
                run_length: 5,
                old_regime_mean: 1.0,
                new_regime_mean: 2.0,
            },
            RegimeShift {
                stream_name: "bad-confidence".to_string(),
                timestamp: 10,
                confidence: f64::NAN,
                run_length: 5,
                old_regime_mean: 1.0,
                new_regime_mean: 2.0,
            },
            RegimeShift {
                stream_name: "zero-run".to_string(),
                timestamp: 10,
                confidence: 0.8,
                run_length: 0,
                old_regime_mean: 1.0,
                new_regime_mean: 2.0,
            },
            RegimeShift {
                stream_name: "bad-mean".to_string(),
                timestamp: 10,
                confidence: 0.8,
                run_length: 5,
                old_regime_mean: f64::INFINITY,
                new_regime_mean: 2.0,
            },
        ];

        for shift in invalid_shifts {
            let mut correlator = MultiStreamCorrelator::new(60);

            assert!(correlator.record_shift(shift).is_empty());
            assert_eq!(correlator.recent_count(), 0);
        }
    }

    #[test]
    fn negative_config_rejects_nonpositive_or_nonfinite_hazard_lambda() {
        for lambda in [0.0, -1.0, f64::NAN, f64::INFINITY, f64::NEG_INFINITY] {
            let mut config = BocpdConfig::default();
            config.hazard_lambda = lambda;

            let err = config.validate().unwrap_err();

            assert!(matches!(
                err,
                BocpdError::InvalidConfig(msg) if msg.contains("hazard_lambda")
            ));
        }
    }

    #[test]
    fn negative_config_rejects_zero_max_run_length() {
        let mut config = BocpdConfig::default();
        config.max_run_length = 0;

        let err = config.validate().unwrap_err();

        assert!(matches!(
            err,
            BocpdError::InvalidConfig(msg) if msg.contains("max_run_length")
        ));
    }

    #[test]
    fn negative_config_rejects_zero_min_run_length() {
        let mut config = BocpdConfig::default();
        config.min_run_length = 0;

        let err = config.validate().unwrap_err();

        assert!(matches!(
            err,
            BocpdError::InvalidConfig(msg) if msg.contains("min_run_length")
        ));
    }

    #[test]
    fn negative_config_rejects_min_run_length_above_max() {
        let mut config = BocpdConfig::default();
        config.min_run_length = 8;
        config.max_run_length = 7;

        let err = config.validate().unwrap_err();

        assert!(matches!(
            err,
            BocpdError::InvalidConfig(msg) if msg.contains("min_run_length")
        ));
    }

    #[test]
    fn negative_config_rejects_zero_regime_history_capacity() {
        let mut config = BocpdConfig::default();
        config.max_regime_history = 0;

        let err = config.validate().unwrap_err();

        assert!(matches!(
            err,
            BocpdError::InvalidConfig(msg) if msg.contains("max_regime_history")
        ));
    }

    #[test]
    fn negative_gaussian_detector_rejects_invalid_model_observations() {
        let invalid_models = [
            GaussianModel {
                kappa0: 0.0,
                ..GaussianModel::default()
            },
            GaussianModel {
                alpha0: f64::NAN,
                ..GaussianModel::default()
            },
            GaussianModel {
                beta0: f64::NEG_INFINITY,
                ..GaussianModel::default()
            },
        ];

        for model in invalid_models {
            let mut detector = BocpdDetector::new(
                "gaussian-invalid-model",
                BocpdConfig::default(),
                HazardFunction::Constant { lambda: 200.0 },
                ObservationModel::Gaussian(model),
            )
            .unwrap();

            assert!(detector.observe(1.0, 1).is_none());
            assert_eq!(detector.observation_count(), 0);
            assert!(detector.events().is_empty());
        }
    }

    #[test]
    fn negative_poisson_detector_rejects_invalid_model_observations() {
        let invalid_models = [
            PoissonModel {
                alpha0: 0.0,
                ..PoissonModel::default()
            },
            PoissonModel {
                beta0: f64::NAN,
                ..PoissonModel::default()
            },
        ];

        for model in invalid_models {
            let mut detector = BocpdDetector::new(
                "poisson-invalid-model",
                BocpdConfig::default(),
                HazardFunction::Constant { lambda: 200.0 },
                ObservationModel::Poisson(model),
            )
            .unwrap();

            assert!(detector.observe(1.0, 1).is_none());
            assert_eq!(detector.observation_count(), 0);
            assert!(detector.events().is_empty());
        }
    }

    #[test]
    fn negative_categorical_detector_rejects_invalid_model_observations() {
        let invalid_models = [
            CategoricalModel { k: 0, alpha0: 1.0 },
            CategoricalModel { k: 3, alpha0: 0.0 },
            CategoricalModel {
                k: 3,
                alpha0: f64::INFINITY,
            },
        ];

        for model in invalid_models {
            let mut detector = BocpdDetector::new(
                "categorical-invalid-model",
                BocpdConfig::default(),
                HazardFunction::Constant { lambda: 200.0 },
                ObservationModel::Categorical(model),
            )
            .unwrap();

            assert!(detector.observe(1.0, 1).is_none());
            assert_eq!(detector.observation_count(), 0);
            assert!(detector.events().is_empty());
        }
    }

    fn valid_shift(stream_name: &str, timestamp: u64) -> RegimeShift {
        RegimeShift {
            stream_name: stream_name.to_string(),
            timestamp,
            confidence: 0.8,
            run_length: 5,
            old_regime_mean: 1.0,
            new_regime_mean: 2.0,
        }
    }

    #[test]
    fn negative_correlator_rejects_whitespace_stream_names() {
        for stream_name in ["bad stream", "bad\tstream", "\nstream", "stream\n"] {
            let mut correlator = MultiStreamCorrelator::new(60);

            assert!(
                correlator
                    .record_shift(valid_shift(stream_name, 10))
                    .is_empty()
            );
            assert_eq!(correlator.recent_count(), 0);
        }
    }

    #[test]
    fn negative_correlator_rejects_confidence_outside_unit_interval() {
        for confidence in [-0.01, 1.01, f64::INFINITY] {
            let mut shift = valid_shift("bad-confidence-range", 10);
            shift.confidence = confidence;
            let mut correlator = MultiStreamCorrelator::new(60);

            assert!(correlator.record_shift(shift).is_empty());
            assert_eq!(correlator.recent_count(), 0);
        }
    }

    #[test]
    fn negative_correlator_drops_prior_shift_outside_window() {
        let mut correlator = MultiStreamCorrelator::new(60);

        assert!(
            correlator
                .record_shift(valid_shift("stream-a", 100))
                .is_empty()
        );
        let correlated = correlator.record_shift(valid_shift("stream-b", 161));

        assert!(correlated.is_empty());
        assert_eq!(correlator.recent_count(), 1);
    }
}
