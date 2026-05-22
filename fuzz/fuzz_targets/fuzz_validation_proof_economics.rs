#![no_main]

use libfuzzer_sys::fuzz_target;
use arbitrary::{Arbitrary, Unstructured};
use chrono::{DateTime, Utc, Duration};

use frankenengine_node::observability::validation_proof_economics::{
    ValidationProofEconomicsGenerator, ValidationProofEconomicsReport,
    EconomicsReportingPeriod, SloTargets,
};
use frankenengine_node::ops::validation_broker::{
    ValidationProofStatus, ProofEvidenceSource, ProofQualification,
};
use frankenengine_node::ops::validation_proof_debt_ledger::{
    ValidationProofDebtLedger, ValidationProofDebtClass, ValidationProofDebtState,
};

// Size limits for bounded fuzzing
const MAX_PROOF_STATUSES: usize = 100;
const MAX_DEBT_ENTRIES: usize = 50;
const MAX_DURATION_SECONDS: u64 = 86400 * 7; // 1 week max
const MAX_SLO_VALUE: f64 = 1000000.0; // Reasonable upper bound
const MAX_TIMESTAMP_OFFSET_SECONDS: i64 = 86400 * 365; // 1 year

/// Fuzzable SLO targets with bounded values
#[derive(Debug, Clone, Arbitrary)]
struct FuzzSloTargets {
    #[arbitrary(with = bounded_queue_depth)]
    max_queue_depth: usize,
    #[arbitrary(with = bounded_slo_time)]
    max_average_wait_time_seconds: f64,
    #[arbitrary(with = bounded_failure_rate)]
    max_failure_rate: f64,
    #[arbitrary(with = bounded_slo_time)]
    max_debt_age_seconds: f64,
    #[arbitrary(with = bounded_efficiency)]
    min_coalescing_efficiency: f64,
}

impl From<FuzzSloTargets> for SloTargets {
    fn from(fuzz: FuzzSloTargets) -> Self {
        Self {
            max_queue_depth: fuzz.max_queue_depth,
            max_average_wait_time_seconds: fuzz.max_average_wait_time_seconds,
            max_failure_rate: fuzz.max_failure_rate,
            max_debt_age_seconds: fuzz.max_debt_age_seconds,
            min_coalescing_efficiency: fuzz.min_coalescing_efficiency,
        }
    }
}

/// Fuzzable reporting period with bounded time ranges
#[derive(Debug, Clone, Arbitrary)]
struct FuzzEconomicsReportingPeriod {
    #[arbitrary(with = bounded_timestamp_offset)]
    start_offset_seconds: i64,
    #[arbitrary(with = bounded_duration)]
    duration_seconds: u64,
}

impl From<FuzzEconomicsReportingPeriod> for EconomicsReportingPeriod {
    fn from(fuzz: FuzzEconomicsReportingPeriod) -> Self {
        let base_time = Utc::now();
        let start_time = base_time + Duration::seconds(fuzz.start_offset_seconds);
        let end_time = start_time + Duration::seconds(fuzz.duration_seconds as i64);

        Self {
            start_time,
            end_time,
            duration_seconds: fuzz.duration_seconds,
        }
    }
}

/// Fuzzable validation proof status
#[derive(Debug, Clone, Arbitrary)]
struct FuzzValidationProofStatus {
    #[arbitrary(with = bounded_proof_id)]
    proof_id: String,
    proof_source: ProofEvidenceSource,
    qualification: ProofQualification,
    deduplicated: bool,
    #[arbitrary(with = bounded_timestamp_offset)]
    created_offset_seconds: i64,
    #[arbitrary(with = bounded_wait_time)]
    wait_time_seconds: f64,
    #[arbitrary(with = bounded_processing_time)]
    processing_time_seconds: f64,
}

impl From<FuzzValidationProofStatus> for ValidationProofStatus {
    fn from(fuzz: FuzzValidationProofStatus) -> Self {
        let created_at = Utc::now() + Duration::seconds(fuzz.created_offset_seconds);

        Self {
            proof_id: fuzz.proof_id,
            proof_source: fuzz.proof_source,
            qualification: fuzz.qualification,
            deduplicated: fuzz.deduplicated,
            created_at,
            wait_time_seconds: fuzz.wait_time_seconds,
            processing_time_seconds: fuzz.processing_time_seconds,
        }
    }
}

/// Fuzzable debt ledger entry
#[derive(Debug, Clone, Arbitrary)]
struct FuzzDebtEntry {
    #[arbitrary(with = bounded_debt_id)]
    debt_id: String,
    debt_class: ValidationProofDebtClass,
    debt_state: ValidationProofDebtState,
    #[arbitrary(with = bounded_timestamp_offset)]
    created_offset_seconds: i64,
    #[arbitrary(with = bounded_debt_amount)]
    debt_amount: u64,
}

/// Operations to test on the economics generator
#[derive(Debug, Clone, Arbitrary)]
enum EconomicsOperation {
    GenerateReport {
        slo_targets: FuzzSloTargets,
        reporting_period: FuzzEconomicsReportingPeriod,
        #[arbitrary(with = bounded_proof_statuses)]
        proof_statuses: Vec<FuzzValidationProofStatus>,
        #[arbitrary(with = bounded_debt_entries)]
        debt_entries: Vec<FuzzDebtEntry>,
    },
    TestSloTargetsDefaults,
    TestReportSerialization {
        slo_targets: FuzzSloTargets,
        reporting_period: FuzzEconomicsReportingPeriod,
        #[arbitrary(with = bounded_proof_statuses)]
        proof_statuses: Vec<FuzzValidationProofStatus>,
        #[arbitrary(with = bounded_debt_entries)]
        debt_entries: Vec<FuzzDebtEntry>,
    },
}

/// Complete fuzz input
#[derive(Debug, Arbitrary)]
struct FuzzInput {
    #[arbitrary(with = bounded_economics_operations)]
    operations: Vec<EconomicsOperation>,
}

// Bounded arbitrary helpers

fn bounded_queue_depth(u: &mut Unstructured) -> arbitrary::Result<usize> {
    u.int_in_range(0..=10000)
}

fn bounded_slo_time(u: &mut Unstructured) -> arbitrary::Result<f64> {
    let value = u.choose(&[
        0.0,           // Zero
        1.0,           // Small
        60.0,          // 1 minute
        300.0,         // 5 minutes
        3600.0,        // 1 hour
        86400.0,       // 1 day
        f64::NAN,      // NaN
        f64::INFINITY, // Infinity
        -1.0,          // Negative
        MAX_SLO_VALUE, // Large value
    ])?;
    Ok(*value)
}

fn bounded_failure_rate(u: &mut Unstructured) -> arbitrary::Result<f64> {
    let value = u.choose(&[
        0.0,      // No failures
        0.01,     // 1%
        0.05,     // 5%
        0.1,      // 10%
        0.5,      // 50%
        1.0,      // 100%
        1.5,      // >100%
        f64::NAN, // NaN
        -0.1,     // Negative
    ])?;
    Ok(*value)
}

fn bounded_efficiency(u: &mut Unstructured) -> arbitrary::Result<f64> {
    let value = u.choose(&[
        0.0,      // No efficiency
        0.2,      // 20%
        0.5,      // 50%
        0.8,      // 80%
        1.0,      // 100%
        1.2,      // >100%
        f64::NAN, // NaN
        -0.1,     // Negative
    ])?;
    Ok(*value)
}

fn bounded_timestamp_offset(u: &mut Unstructured) -> arbitrary::Result<i64> {
    u.int_in_range(-MAX_TIMESTAMP_OFFSET_SECONDS..=MAX_TIMESTAMP_OFFSET_SECONDS)
}

fn bounded_duration(u: &mut Unstructured) -> arbitrary::Result<u64> {
    u.int_in_range(1..=MAX_DURATION_SECONDS)
}

fn bounded_proof_id(u: &mut Unstructured) -> arbitrary::Result<String> {
    let choice = u.int_in_range(0..=5)?;
    Ok(match choice {
        0 => String::new(), // Empty
        1 => "PROOF-001".to_string(), // Valid
        2 => "PROOF\x00002".to_string(), // Null byte
        3 => "PROOF\n003".to_string(), // Newline
        4 => "a".repeat(1000), // Very long
        5 => {
            let len = u.int_in_range(0..=100)?;
            let bytes = u.bytes(len)?;
            String::from_utf8_lossy(bytes).into_owned()
        }
        _ => unreachable!(),
    })
}

fn bounded_debt_id(u: &mut Unstructured) -> arbitrary::Result<String> {
    bounded_proof_id(u) // Same logic
}

fn bounded_wait_time(u: &mut Unstructured) -> arbitrary::Result<f64> {
    let value = u.choose(&[
        0.0,
        1.0,
        60.0,
        300.0,
        3600.0,
        f64::NAN,
        f64::INFINITY,
        -1.0,
    ])?;
    Ok(*value)
}

fn bounded_processing_time(u: &mut Unstructured) -> arbitrary::Result<f64> {
    bounded_wait_time(u) // Same logic
}

fn bounded_debt_amount(u: &mut Unstructured) -> arbitrary::Result<u64> {
    u.int_in_range(0..=1_000_000)
}

fn bounded_proof_statuses(u: &mut Unstructured) -> arbitrary::Result<Vec<FuzzValidationProofStatus>> {
    let len = u.int_in_range(0..=MAX_PROOF_STATUSES)?;
    (0..len).map(|_| u.arbitrary()).collect()
}

fn bounded_debt_entries(u: &mut Unstructured) -> arbitrary::Result<Vec<FuzzDebtEntry>> {
    let len = u.int_in_range(0..=MAX_DEBT_ENTRIES)?;
    (0..len).map(|_| u.arbitrary()).collect()
}

fn bounded_economics_operations(u: &mut Unstructured) -> arbitrary::Result<Vec<EconomicsOperation>> {
    let len = u.int_in_range(1..=8)?;
    (0..len).map(|_| u.arbitrary()).collect()
}

fuzz_target!(|data: &[u8]| {
    // Input size guard to prevent OOM
    if data.len() > 100_000 {
        return;
    }

    let input: FuzzInput = match Unstructured::new(data).arbitrary() {
        Ok(input) => input,
        Err(_) => return, // Invalid input, skip silently
    };

    // Track state for invariant checking
    let mut report_count = 0;
    let mut successful_generations = 0;
    let mut serialization_attempts = 0;
    let mut successful_serializations = 0;

    // Execute fuzzed operations
    for op in input.operations {
        match op {
            EconomicsOperation::GenerateReport {
                slo_targets,
                reporting_period,
                proof_statuses,
                debt_entries,
            } => {
                report_count += 1;

                // Create generator with fuzzed SLO targets
                let targets: SloTargets = slo_targets.into();
                let generator = ValidationProofEconomicsGenerator::with_slo_targets(targets);

                // Convert fuzz inputs to real types
                let period: EconomicsReportingPeriod = reporting_period.into();
                let statuses: Vec<ValidationProofStatus> = proof_statuses
                    .into_iter()
                    .map(|s| s.into())
                    .collect();

                // Create debt ledger with fuzzed entries
                let mut debt_ledger = ValidationProofDebtLedger::new();
                for debt_entry in debt_entries {
                    let created_at = Utc::now() + Duration::seconds(debt_entry.created_offset_seconds);
                    debt_ledger.add_debt(
                        debt_entry.debt_id,
                        debt_entry.debt_class,
                        debt_entry.debt_state,
                        created_at,
                        debt_entry.debt_amount,
                    );
                }

                // Generate the report
                let report = generator.generate_report(&statuses, &debt_ledger, period);
                successful_generations += 1;

                // Verify report properties
                assert_eq!(
                    report.schema_version,
                    "franken-node/validation-proof-economics/v1",
                    "Schema version should be consistent"
                );

                // Validate time consistency
                assert!(
                    report.reporting_period.end_time >= report.reporting_period.start_time,
                    "End time should be >= start time"
                );

                let calculated_duration = (report.reporting_period.end_time
                    - report.reporting_period.start_time).num_seconds() as u64;

                // Allow some tolerance for duration calculation
                assert!(
                    calculated_duration <= report.reporting_period.duration_seconds.saturating_add(60),
                    "Calculated duration should match reported duration (with tolerance)"
                );

                // Validate economics summary bounds
                assert!(
                    report.summary.duplicate_proofs_avoided <= statuses.len(),
                    "Duplicates avoided cannot exceed total proofs"
                );

                // Worker time saved should be reasonable
                let max_time_saved = report.summary.duplicate_proofs_avoided as u64 * 3600; // 1 hour per proof max
                assert!(
                    report.summary.worker_time_saved_seconds <= max_time_saved,
                    "Worker time saved should be reasonable"
                );

                // SLO compliance values should be finite or specifically handled
                for slo_metric in &report.slo_compliance.slo_metrics {
                    if slo_metric.current_value.is_finite() && slo_metric.target_value.is_finite() {
                        // Normal comparison case
                        assert!(
                            slo_metric.current_value >= 0.0 || slo_metric.metric_name.contains("offset"),
                            "Metrics should generally be non-negative unless they're offset values"
                        );
                    }
                    // Non-finite values (NaN, infinity) should be handled gracefully
                }

                // Economics breakdown should have consistent totals
                let breakdown_total = report.economics_breakdown.savings_by_source.values().sum::<f64>();
                if breakdown_total.is_finite() {
                    assert!(breakdown_total >= 0.0, "Total savings should be non-negative");
                }
            }

            EconomicsOperation::TestSloTargetsDefaults => {
                // Test default SLO targets
                let default_targets = SloTargets::default();

                assert!(default_targets.max_queue_depth > 0, "Default queue depth should be positive");
                assert!(default_targets.max_average_wait_time_seconds > 0.0, "Default wait time should be positive");
                assert!(default_targets.max_failure_rate >= 0.0 && default_targets.max_failure_rate <= 1.0,
                       "Default failure rate should be between 0 and 1");
                assert!(default_targets.max_debt_age_seconds > 0.0, "Default debt age should be positive");
                assert!(default_targets.min_coalescing_efficiency >= 0.0 && default_targets.min_coalescing_efficiency <= 1.0,
                       "Default coalescing efficiency should be between 0 and 1");

                // Test generator creation with defaults
                let default_generator = ValidationProofEconomicsGenerator::new();
                let custom_generator = ValidationProofEconomicsGenerator::with_slo_targets(default_targets);

                // Both should work without panicking
                let _ = default_generator;
                let _ = custom_generator;
            }

            EconomicsOperation::TestReportSerialization {
                slo_targets,
                reporting_period,
                proof_statuses,
                debt_entries,
            } => {
                serialization_attempts += 1;

                // Generate a report
                let targets: SloTargets = slo_targets.into();
                let generator = ValidationProofEconomicsGenerator::with_slo_targets(targets);
                let period: EconomicsReportingPeriod = reporting_period.into();
                let statuses: Vec<ValidationProofStatus> = proof_statuses
                    .into_iter()
                    .map(|s| s.into())
                    .collect();

                let mut debt_ledger = ValidationProofDebtLedger::new();
                for debt_entry in debt_entries {
                    let created_at = Utc::now() + Duration::seconds(debt_entry.created_offset_seconds);
                    debt_ledger.add_debt(
                        debt_entry.debt_id,
                        debt_entry.debt_class,
                        debt_entry.debt_state,
                        created_at,
                        debt_entry.debt_amount,
                    );
                }

                let report = generator.generate_report(&statuses, &debt_ledger, period);

                // Test JSON serialization
                match serde_json::to_string(&report) {
                    Ok(json_str) => {
                        successful_serializations += 1;

                        // Verify JSON is not empty
                        assert!(!json_str.is_empty(), "Serialized JSON should not be empty");
                        assert!(json_str.contains("schema_version"), "JSON should contain schema version");

                        // Test round-trip deserialization
                        match serde_json::from_str::<ValidationProofEconomicsReport>(&json_str) {
                            Ok(deserialized) => {
                                // Verify round-trip consistency
                                assert_eq!(
                                    report.schema_version,
                                    deserialized.schema_version,
                                    "Schema version should survive round-trip"
                                );
                                assert_eq!(
                                    report.reporting_period.duration_seconds,
                                    deserialized.reporting_period.duration_seconds,
                                    "Duration should survive round-trip"
                                );
                            }
                            Err(_) => {
                                // Deserialization can fail due to non-finite values, which is acceptable
                            }
                        }
                    }
                    Err(_) => {
                        // Serialization can fail due to non-finite floating point values, which is acceptable
                    }
                }
            }
        }
    }

    // Invariant checks - these must hold regardless of input
    assert!(successful_generations <= report_count, "Successful generations should not exceed attempts");
    assert!(successful_serializations <= serialization_attempts, "Successful serializations should not exceed attempts");

    // At least one operation should have been attempted
    assert!(report_count > 0 || serialization_attempts > 0, "At least one operation should be attempted");

    // Test edge cases with extreme SLO values
    let extreme_targets = SloTargets {
        max_queue_depth: usize::MAX,
        max_average_wait_time_seconds: f64::MAX,
        max_failure_rate: f64::MAX,
        max_debt_age_seconds: f64::MAX,
        min_coalescing_efficiency: f64::MIN,
    };

    let extreme_generator = ValidationProofEconomicsGenerator::with_slo_targets(extreme_targets);
    let empty_statuses: Vec<ValidationProofStatus> = vec![];
    let empty_debt_ledger = ValidationProofDebtLedger::new();
    let now = Utc::now();
    let extreme_period = EconomicsReportingPeriod {
        start_time: now,
        end_time: now + Duration::seconds(1),
        duration_seconds: 1,
    };

    // This should not panic even with extreme values
    let _extreme_report = extreme_generator.generate_report(&empty_statuses, &empty_debt_ledger, extreme_period);
});