//! Comprehensive conformance tests for benchmark_suite - edge cases and hardening patterns
//!
//! Tests focus on:
//! - Statistical function edge cases with extreme/invalid inputs
//! - Arithmetic overflow/underflow scenarios
//! - NaN/Inf input handling and propagation
//! - Division by zero scenarios
//! - Memory bounds and capacity limits
//! - Large dataset stress testing
//! - Scoring function boundary conditions

#[cfg(test)]
mod benchmark_suite_edge_cases {
    use super::super::benchmark_suite::*;
    use std::collections::BTreeMap;
    use std::f64;

    // -------------------------------------------------------------------------
    // STATISTICAL FUNCTIONS EDGE CASE TESTS
    // -------------------------------------------------------------------------

    #[test]
    fn test_mean_empty_slice() {
        assert_eq!(mean(&[]), 0.0);
    }

    #[test]
    fn test_mean_single_value() {
        assert_eq!(mean(&[42.0]), 42.0);
    }

    #[test]
    fn test_mean_with_extreme_values() {
        // Test with very large values that could cause overflow
        let large_values = vec![f64::MAX / 2.0, f64::MAX / 2.0];
        let result = mean(&large_values);
        assert!(result.is_finite(), "mean of large values should be finite");
    }

    #[test]
    fn test_mean_with_inf_values() {
        // Test with infinity - should handle gracefully
        let inf_values = vec![f64::INFINITY, 100.0, 200.0];
        let result = mean(&inf_values);
        // Result may be infinity but should not panic
        assert!(result == f64::INFINITY || result.is_finite());
    }

    #[test]
    fn test_mean_with_nan_values() {
        // Test with NaN - should propagate NaN
        let nan_values = vec![f64::NAN, 100.0, 200.0];
        let result = mean(&nan_values);
        assert!(result.is_nan());
    }

    #[test]
    fn test_mean_very_large_collection() {
        // Test with very large collection to stress length conversion
        let large_collection: Vec<f64> = (0..100_000).map(|i| i as f64).collect();
        let result = mean(&large_collection);
        assert!(result.is_finite());
        assert!(result > 0.0);
    }

    #[test]
    fn test_std_dev_empty_slice() {
        assert_eq!(std_dev(&[]), 0.0);
    }

    #[test]
    fn test_std_dev_single_value() {
        assert_eq!(std_dev(&[42.0]), 0.0);
    }

    #[test]
    fn test_std_dev_identical_values() {
        assert_eq!(std_dev(&[5.0, 5.0, 5.0, 5.0]), 0.0);
    }

    #[test]
    fn test_std_dev_with_extreme_variance() {
        // Test with extreme variance to check numerical stability
        let extreme_values = vec![0.0, f64::MAX / 1000.0];
        let result = std_dev(&extreme_values);
        assert!(result.is_finite() || result.is_infinite());
        assert!(!result.is_nan());
    }

    #[test]
    fn test_std_dev_with_nan() {
        let nan_values = vec![1.0, f64::NAN, 3.0];
        let result = std_dev(&nan_values);
        assert!(result.is_nan());
    }

    #[test]
    fn test_coefficient_of_variation_zero_mean() {
        // When mean is zero, CV should be 0 (edge case)
        let zero_mean_values = vec![-1.0, 0.0, 1.0]; // mean = 0
        let result = coefficient_of_variation(&zero_mean_values);
        assert_eq!(result, 0.0);
    }

    #[test]
    fn test_coefficient_of_variation_near_zero_mean() {
        // Test with very small mean (near epsilon)
        let tiny_values = vec![f64::EPSILON / 2.0, f64::EPSILON / 2.0];
        let result = coefficient_of_variation(&tiny_values);
        assert_eq!(result, 0.0); // Should hit the epsilon guard
    }

    #[test]
    fn test_coefficient_of_variation_extreme_values() {
        let extreme_values = vec![1e-100, 1e100];
        let result = coefficient_of_variation(&extreme_values);
        assert!(result.is_finite() || result.is_infinite());
    }

    #[test]
    fn test_confidence_interval_empty_slice() {
        let ci = confidence_interval_95(&[]);
        assert_eq!(ci.lower, 0.0);
        assert_eq!(ci.upper, 0.0);
    }

    #[test]
    fn test_confidence_interval_single_value() {
        let ci = confidence_interval_95(&[42.0]);
        assert_eq!(ci.lower, 42.0);
        assert_eq!(ci.upper, 42.0);
    }

    #[test]
    fn test_confidence_interval_with_extreme_values() {
        let extreme_values = vec![f64::MIN_POSITIVE, f64::MAX / 1000.0];
        let ci = confidence_interval_95(&extreme_values);
        assert!(ci.lower.is_finite() || ci.lower.is_infinite());
        assert!(ci.upper.is_finite() || ci.upper.is_infinite());
        assert!(ci.lower <= ci.upper);
    }

    #[test]
    fn test_confidence_interval_large_sample() {
        // Test with sample size larger than the t-value lookup table
        let large_sample: Vec<f64> = (0..100).map(|i| i as f64).collect();
        let ci = confidence_interval_95(&large_sample);
        assert!(ci.lower.is_finite());
        assert!(ci.upper.is_finite());
        assert!(ci.lower < ci.upper);
    }

    // -------------------------------------------------------------------------
    // SCORING FUNCTION EDGE CASE TESTS
    // -------------------------------------------------------------------------

    #[test]
    fn test_scoring_config_identical_ideal_threshold() {
        // Edge case: ideal and threshold are the same
        let config = ScoringConfig::lower_is_better(100.0, 100.0);

        // Should handle the epsilon check
        assert_eq!(config.score(100.0), 100); // At ideal
        assert_eq!(config.score(200.0), 0); // Above ideal
        assert_eq!(config.score(50.0), 100); // Below ideal
    }

    #[test]
    fn test_scoring_config_extreme_values() {
        let config = ScoringConfig::lower_is_better(1e-10, 1e10);

        // Test with very large measured value
        assert_eq!(config.score(1e20), 0);

        // Test with very small measured value
        assert_eq!(config.score(1e-20), 100);
    }

    #[test]
    fn test_scoring_config_nan_input() {
        let config = ScoringConfig::lower_is_better(100.0, 500.0);

        // NaN input should not panic, should produce some deterministic result
        let score = config.score(f64::NAN);
        assert!(score <= 100); // Score should be bounded
    }

    #[test]
    fn test_scoring_config_infinity_input() {
        let config = ScoringConfig::lower_is_better(100.0, 500.0);

        assert_eq!(config.score(f64::INFINITY), 0); // Infinity is worst for lower-is-better
        assert_eq!(config.score(f64::NEG_INFINITY), 100); // Negative infinity is best
    }

    #[test]
    fn test_scoring_config_higher_is_better_edge_cases() {
        let config = ScoringConfig::higher_is_better(1000.0, 100.0);

        assert_eq!(config.score(f64::INFINITY), 100); // Infinity is best for higher-is-better
        assert_eq!(config.score(f64::NEG_INFINITY), 0); // Negative infinity is worst
        assert_eq!(config.score(0.0), 0); // Below threshold
    }

    // -------------------------------------------------------------------------
    // REGRESSION DETECTION EDGE CASE TESTS
    // -------------------------------------------------------------------------

    #[test]
    fn test_regression_detection_zero_baseline() {
        let baseline = create_test_report(vec![("test", 0.0)]);
        let current = create_test_report(vec![("test", 100.0)]);

        // Zero baseline should be skipped (division by zero protection)
        let findings = detect_regressions(&baseline, &current, 10.0);
        assert!(findings.is_empty());
    }

    #[test]
    fn test_regression_detection_negative_baseline() {
        let baseline = create_test_report(vec![("test", -100.0)]);
        let current = create_test_report(vec![("test", -50.0)]);

        // Should handle negative baselines correctly
        let findings = detect_regressions(&baseline, &current, 10.0);
        // This would be an improvement (less negative) for lower-is-better
        assert!(findings.is_empty());
    }

    #[test]
    fn test_regression_detection_extreme_change() {
        let baseline = create_test_report(vec![("test", 1.0)]);
        let current = create_test_report(vec![("test", 1e10)]);

        // Massive regression should be detected
        let findings = detect_regressions(&baseline, &current, 10.0);
        assert_eq!(findings.len(), 1);
        assert!(findings[0].change_pct > 1000.0);
    }

    #[test]
    fn test_regression_detection_nan_threshold_edge_case() {
        let baseline = create_test_report(vec![("test", 100.0)]);
        let current = create_test_report(vec![("test", 200.0)]);

        // NaN threshold should fail closed (treat as 0% - any change is regression)
        let findings = detect_regressions(&baseline, &current, f64::NAN);
        assert_eq!(findings.len(), 1); // Should detect regression with NaN threshold
    }

    #[test]
    fn test_regression_detection_infinite_threshold() {
        let baseline = create_test_report(vec![("test", 100.0)]);
        let current = create_test_report(vec![("test", 1000.0)]);

        // Infinite threshold should fail closed (treat as 0%)
        let findings = detect_regressions(&baseline, &current, f64::INFINITY);
        assert_eq!(findings.len(), 1); // Should detect regression even with infinite threshold
    }

    // -------------------------------------------------------------------------
    // BENCHMARK SUITE EDGE CASE TESTS
    // -------------------------------------------------------------------------

    #[test]
    fn test_suite_with_empty_measurements() {
        let config = SuiteConfig::with_defaults();
        let mut suite = BenchmarkSuite::new(config);

        suite.add_scenario(create_test_scenario(
            "test",
            BenchmarkDimension::PerformanceUnderHardening,
        ));

        let measurements = BTreeMap::new(); // Empty measurements
        let result = suite.run(&measurements);

        // Should produce empty report without crashing
        assert!(result.is_ok());
        assert_eq!(result.unwrap().scenarios.len(), 0);
    }

    #[test]
    fn test_suite_with_non_finite_measurements() {
        let config = SuiteConfig::with_defaults();
        let mut suite = BenchmarkSuite::new(config);

        let scenario = create_test_scenario("test", BenchmarkDimension::PerformanceUnderHardening);

        // Test with NaN measurement
        let result = suite.execute_scenario(&scenario, &[1.0, f64::NAN, 3.0]);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            BenchRunError::NonFiniteMeasurement { .. }
        ));

        // Test with infinity measurement
        let result = suite.execute_scenario(&scenario, &[1.0, f64::INFINITY, 3.0]);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            BenchRunError::NonFiniteMeasurement { .. }
        ));
    }

    #[test]
    fn test_suite_aggregate_score_overflow_protection() {
        let config = SuiteConfig::with_defaults();
        let mut suite = BenchmarkSuite::new(config);

        // Add many scenarios with max scores to test aggregation overflow
        for i in 0..1000 {
            suite.add_scenario(ScenarioDefinition {
                dimension: BenchmarkDimension::PerformanceUnderHardening,
                name: format!("test_{}", i),
                unit: "ms".to_string(),
                iterations: 1,
                warmup_iterations: 0,
                sandbox_required: false,
                scoring: ScoringConfig::lower_is_better(1.0, 10.0),
            });
        }

        let mut measurements = BTreeMap::new();
        for i in 0..1000 {
            measurements.insert(format!("test_{}", i), vec![1.0]); // Perfect scores
        }

        let report = suite
            .run(&measurements)
            .expect("should handle many scenarios");
        assert_eq!(report.aggregate_score, 100); // Should average to 100, not overflow
    }

    #[test]
    fn test_hardware_fingerprint_with_extreme_values() {
        let hw = HardwareProfile {
            cpu: "a".repeat(10000), // Very long string
            memory_mb: u64::MAX,    // Maximum value
            os: "".to_string(),     // Empty string
        };

        let fingerprint = hw.fingerprint();
        assert!(!fingerprint.is_empty());
        assert!(fingerprint.len() > 10); // Should be a hex hash

        // Should be deterministic
        assert_eq!(fingerprint, hw.fingerprint());
    }

    #[test]
    fn test_deterministic_measurements_extreme_scoring() {
        let scenario = ScenarioDefinition {
            dimension: BenchmarkDimension::PerformanceUnderHardening,
            name: "extreme_test".to_string(),
            unit: "ms".to_string(),
            iterations: 10,
            warmup_iterations: 0,
            sandbox_required: false,
            scoring: ScoringConfig::lower_is_better(1e-100, 1e100), // Extreme range
        };

        let measurements = deterministic_measurements_for_scenario(&scenario);

        assert_eq!(measurements.len(), 10);
        assert!(measurements.iter().all(|&x| x.is_finite() && x >= 0.0));
    }

    #[test]
    fn test_deterministic_measurements_zero_iterations() {
        let scenario = ScenarioDefinition {
            dimension: BenchmarkDimension::PerformanceUnderHardening,
            name: "zero_iterations".to_string(),
            unit: "ms".to_string(),
            iterations: 0, // Edge case: zero iterations
            warmup_iterations: 0,
            sandbox_required: false,
            scoring: ScoringConfig::lower_is_better(100.0, 500.0),
        };

        let measurements = deterministic_measurements_for_scenario(&scenario);
        assert_eq!(measurements.len(), 1); // Should clamp to minimum of 1
    }

    // -------------------------------------------------------------------------
    // VALIDATION EDGE CASE TESTS
    // -------------------------------------------------------------------------

    #[test]
    fn test_validate_report_with_non_finite_values() {
        let mut report = create_simple_test_report();

        // Test with non-finite raw_value
        report.scenarios[0].raw_value = f64::NAN;
        assert!(validate_report(&report).is_err());

        // Test with non-finite confidence interval
        report.scenarios[0].raw_value = 100.0;
        report.scenarios[0].confidence_interval.lower = f64::INFINITY;
        assert!(validate_report(&report).is_err());

        // Test with non-finite variance
        report.scenarios[0].confidence_interval.lower = 95.0;
        report.scenarios[0].variance_pct = f64::NAN;
        assert!(validate_report(&report).is_err());
    }

    #[test]
    fn test_to_canonical_json_with_non_finite_report() {
        let mut report = create_simple_test_report();
        report.scenarios[0].raw_value = f64::INFINITY;

        let result = to_canonical_json(&report);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            BenchRunError::NonFiniteReportValue { .. }
        ));
    }

    // -------------------------------------------------------------------------
    // MEMORY AND CAPACITY TESTS
    // -------------------------------------------------------------------------

    #[test]
    fn test_suite_scenario_capacity_bounds() {
        let config = SuiteConfig::with_defaults();
        let mut suite = BenchmarkSuite::new(config);

        // Add more scenarios than MAX_SCENARIOS to test capacity bounds
        for i in 0..5000 {
            // Exceeds MAX_SCENARIOS = 4096
            suite.add_scenario(create_test_scenario(
                &format!("test_{}", i),
                BenchmarkDimension::PerformanceUnderHardening,
            ));
        }

        // Should be bounded at MAX_SCENARIOS
        assert!(suite.scenarios().len() <= 4096);
    }

    #[test]
    fn test_suite_events_capacity_bounds() {
        let config = SuiteConfig::with_defaults();
        let mut suite = BenchmarkSuite::new(config);

        // Generate many scenarios to create many events
        for i in 0..1000 {
            suite.add_scenario(create_test_scenario(
                &format!("test_{}", i),
                BenchmarkDimension::PerformanceUnderHardening,
            ));
        }

        let mut measurements = BTreeMap::new();
        for i in 0..1000 {
            measurements.insert(format!("test_{}", i), vec![100.0; 5]);
        }

        let _report = suite
            .run(&measurements)
            .expect("should handle many scenarios");

        // Events should be bounded by MAX_EVENTS
        assert!(suite.events().len() <= crate::capacity_defaults::aliases::MAX_EVENTS);
    }

    // -------------------------------------------------------------------------
    // NEGATIVE-PATH REGRESSION TESTS
    // -------------------------------------------------------------------------

    #[test]
    fn negative_suite_run_rejects_empty_measurement_vector() {
        let config = SuiteConfig::with_defaults();
        let mut suite = BenchmarkSuite::new(config);
        let scenario = create_test_scenario(
            "negative_empty",
            BenchmarkDimension::PerformanceUnderHardening,
        );
        suite.add_scenario(scenario);

        let mut measurements = BTreeMap::new();
        measurements.insert("negative_empty".to_string(), Vec::new());

        let err = suite.run(&measurements).unwrap_err();
        assert!(matches!(
            err,
            BenchRunError::EmptyMeasurements { ref scenario }
                if scenario == "negative_empty"
        ));
    }

    #[test]
    fn negative_suite_run_rejects_nan_measurement() {
        let config = SuiteConfig::with_defaults();
        let mut suite = BenchmarkSuite::new(config);
        let scenario = create_test_scenario(
            "negative_nan",
            BenchmarkDimension::PerformanceUnderHardening,
        );
        suite.add_scenario(scenario);

        let mut measurements = BTreeMap::new();
        measurements.insert("negative_nan".to_string(), vec![1.0, f64::NAN, 2.0]);

        let err = suite.run(&measurements).unwrap_err();
        assert!(matches!(
            err,
            BenchRunError::NonFiniteMeasurement { ref scenario }
                if scenario == "negative_nan"
        ));
    }

    #[test]
    fn negative_execute_scenario_rejects_negative_infinity_measurement() {
        let config = SuiteConfig::with_defaults();
        let mut suite = BenchmarkSuite::new(config);
        let scenario =
            create_test_scenario("negative_infinity", BenchmarkDimension::ResourceEfficiency);

        let err = suite
            .execute_scenario(&scenario, &[1.0, f64::NEG_INFINITY, 3.0])
            .unwrap_err();

        assert!(matches!(
            err,
            BenchRunError::NonFiniteMeasurement { ref scenario }
                if scenario == "negative_infinity"
        ));
    }

    #[test]
    fn negative_canonical_json_rejects_non_finite_confidence_upper() {
        let mut report = create_simple_test_report();
        report.scenarios[0].confidence_interval.upper = f64::INFINITY;

        let err = to_canonical_json(&report).unwrap_err();
        assert!(matches!(err, BenchRunError::NonFiniteReportValue { .. }));
        assert!(err.to_string().contains("confidence_interval.upper"));
    }

    #[test]
    fn negative_canonical_json_rejects_non_finite_variance() {
        let mut report = create_simple_test_report();
        report.scenarios[0].variance_pct = f64::NEG_INFINITY;

        let err = to_canonical_json(&report).unwrap_err();
        assert!(matches!(err, BenchRunError::NonFiniteReportValue { .. }));
        assert!(err.to_string().contains("variance_pct"));
    }

    #[test]
    fn negative_from_json_rejects_malformed_payload() {
        let err = from_json("{not-valid-json").unwrap_err();

        assert!(err.is_syntax() || err.is_eof());
    }

    #[test]
    fn negative_regression_detection_ignores_missing_baseline_scenario() {
        let baseline = create_test_report(vec![("only-baseline", 100.0)]);
        let current = create_test_report(vec![("only-current", 10_000.0)]);

        let findings = detect_regressions(&baseline, &current, 0.0);

        assert!(findings.is_empty());
    }

    // -------------------------------------------------------------------------
    // HELPER FUNCTIONS
    // -------------------------------------------------------------------------

    fn create_test_scenario(name: &str, dimension: BenchmarkDimension) -> ScenarioDefinition {
        ScenarioDefinition {
            dimension,
            name: name.to_string(),
            unit: "ms".to_string(),
            iterations: 5,
            warmup_iterations: 1,
            sandbox_required: false,
            scoring: ScoringConfig::lower_is_better(100.0, 500.0),
        }
    }

    fn create_test_report(scenarios: Vec<(&str, f64)>) -> BenchmarkReport {
        let scenario_results: Vec<ScenarioResult> = scenarios
            .into_iter()
            .map(|(name, raw_value)| ScenarioResult {
                dimension: BenchmarkDimension::PerformanceUnderHardening,
                name: name.to_string(),
                raw_value,
                unit: "ms".to_string(),
                confidence_interval: ConfidenceInterval {
                    lower: raw_value - 5.0,
                    upper: raw_value + 5.0,
                },
                score: 50,
                iterations: 5,
                variance_pct: 2.0,
            })
            .collect();

        BenchmarkReport {
            suite_version: "1.0.0".to_string(),
            scoring_formula_version: "sf-v1".to_string(),
            timestamp_utc: "2026-02-21T00:00:00Z".to_string(),
            hardware_profile: HardwareProfile {
                cpu: "test".to_string(),
                memory_mb: 8192,
                os: "linux".to_string(),
            },
            runtime_versions: RuntimeVersions {
                franken_node: "0.1.0".to_string(),
                node: None,
                bun: None,
            },
            scenarios: scenario_results,
            aggregate_score: 50,
            provenance_hash: "test".to_string(),
        }
    }

    fn create_simple_test_report() -> BenchmarkReport {
        create_test_report(vec![("test_scenario", 100.0)])
    }

    fn validate_report(report: &BenchmarkReport) -> Result<(), BenchRunError> {
        super::super::benchmark_suite::validate_report(report)
    }
}
