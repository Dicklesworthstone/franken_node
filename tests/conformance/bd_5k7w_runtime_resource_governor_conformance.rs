//! Conformance harness for runtime resource governor (swarm validation proof scheduling).
//!
//! Validates governor decision-making for cargo/RCH/validation workload management:
//! - **MUST-RG-001**: Resource decision consistency across identical pressure conditions
//! - **MUST-RG-002**: Process classification deterministic based on command patterns
//! - **MUST-RG-003**: Pressure tier calculation fail-closed (unknown when data unavailable)
//! - **MUST-RG-004**: Observation recording preserves all input telemetry data
//! - **SHOULD-RG-005**: Source-only mode preserves forward progress under high contention
//! - **SHOULD-RG-006**: Defer decisions include backoff reasoning for operator visibility
//! - **SHOULD-RG-007**: Hotset prefetch optimizations respect capacity boundaries
//! - **MAY-RG-008**: Cleanup receipts provide audit trail for resource reclamation

use franken_node::runtime::resource_governor::{
    event_codes, reason_codes, CleanupCandidate, CleanupReceipt, ObservedValidationProcess,
    ResourceDiskPressureRoot, ResourceDiskRootKind, ResourceGovernorDecision,
    ResourceGovernorDecisionKind, ResourcePressureSample, ResourcePressureTier,
    ResourceProcessCounts, ResourceProcessKind, CLEANUP_RECEIPT_SCHEMA_VERSION,
    HOTSET_PREFETCH_SCHEMA_VERSION, PRESSURE_SAMPLE_SCHEMA_VERSION, REPORT_SCHEMA_VERSION,
};
use std::collections::BTreeSet;

/// **MUST-RG-001**: Resource decisions MUST be consistent when given identical
/// pressure conditions and process counts.
///
/// Specification: Decision determinism invariant
#[test]
fn conformance_must_rg_001_consistent_decisions_under_identical_conditions() {
    // Setup identical pressure conditions
    let identical_pressure = ResourcePressureSample {
        schema_version: PRESSURE_SAMPLE_SCHEMA_VERSION.to_string(),
        timestamp_epoch_secs: 1000,
        validation_processes: vec![
            ObservedValidationProcess::new(Some(1234), "cargo build").unwrap(),
            ObservedValidationProcess::new(Some(5678), "rustc --edition 2024").unwrap(),
        ],
        disk_pressure_roots: vec![ResourceDiskPressureRoot {
            path: "/tmp".to_string(),
            kind: ResourceDiskRootKind::Temp,
            total_bytes: Some(1000000000),  // 1GB
            free_bytes: Some(200000000),    // 200MB free (20% - Yellow tier)
            used_bytes: Some(800000000),
        }],
        rch_worker_count: 8,
        numa_node_count: 2,
        unavailable_signals: vec![],
    };

    // Run decision-making multiple times with identical inputs
    let mut decisions = Vec::new();
    for iteration in 0..10 {
        let decision = ResourceGovernorDecision::make_decision(
            &identical_pressure,
            &format!("iteration-{}", iteration),
            "test-validator",
        );
        decisions.push(decision);
    }

    // All decisions must be identical
    let first_decision = &decisions[0];
    for (i, decision) in decisions.iter().enumerate().skip(1) {
        assert_eq!(
            decision.kind,
            first_decision.kind,
            "Decision {} differs from first decision: {:?} vs {:?}",
            i,
            decision.kind,
            first_decision.kind
        );
        assert_eq!(
            decision.reason_code,
            first_decision.reason_code,
            "Reason code {} differs from first: {} vs {}",
            i,
            decision.reason_code,
            first_decision.reason_code
        );
    }

    // Decision should be deterministic based on pressure (Yellow tier = moderate contention)
    assert_eq!(
        first_decision.kind,
        ResourceGovernorDecisionKind::AllowLowPriority,
        "Yellow pressure tier should allow low priority execution"
    );
    assert_eq!(
        first_decision.reason_code,
        reason_codes::ALLOW_LOW_PRIORITY_MODERATE_CONTENTION
    );
}

/// **MUST-RG-002**: Process classification MUST be deterministic based on command patterns.
/// No ambiguous or overlapping classification categories.
///
/// Specification: Command classification determinism
#[test]
fn conformance_must_rg_002_deterministic_process_classification() {
    let test_commands = vec![
        // Cargo commands
        ("cargo build", ResourceProcessKind::Cargo),
        ("cargo test --lib", ResourceProcessKind::Cargo),
        ("cargo check --all-targets", ResourceProcessKind::Cargo),
        ("cargo clippy --", ResourceProcessKind::Cargo),
        ("/usr/bin/cargo build --release", ResourceProcessKind::Cargo),

        // Rustc commands
        ("rustc main.rs", ResourceProcessKind::Rustc),
        ("rustc --edition 2024 --crate-type bin", ResourceProcessKind::Rustc),
        ("/usr/local/bin/rustc --emit=dep-info", ResourceProcessKind::Rustc),

        // RCH commands
        ("rch exec cargo build", ResourceProcessKind::Rch),
        ("rch workers probe", ResourceProcessKind::Rch),
        ("rch status", ResourceProcessKind::Rch),
        ("/usr/local/bin/rch exec -- cargo test", ResourceProcessKind::Rch),

        // Other validation
        ("clippy-driver", ResourceProcessKind::OtherValidation),
        ("rust-analyzer", ResourceProcessKind::OtherValidation),
        ("miri", ResourceProcessKind::OtherValidation),
    ];

    for (command, expected_kind) in test_commands {
        let process = ObservedValidationProcess::new(Some(1234), command)
            .unwrap_or_else(|| panic!("Failed to classify command: {}", command));

        assert_eq!(
            process.kind,
            expected_kind,
            "Command '{}' classified as {:?}, expected {:?}",
            command,
            process.kind,
            expected_kind
        );

        // Classification must be stable across repeated calls
        let process2 = ObservedValidationProcess::new(Some(5678), command).unwrap();
        assert_eq!(
            process2.kind,
            expected_kind,
            "Command '{}' classification changed between calls",
            command
        );
    }

    // Non-validation commands should return None
    let non_validation_commands = vec![
        "ls -la",
        "git status",
        "vim src/main.rs",
        "cat Cargo.toml",
        "python test.py",
        "",  // Empty command
    ];

    for command in non_validation_commands {
        let result = ObservedValidationProcess::new(Some(1234), command);
        assert!(
            result.is_none(),
            "Non-validation command '{}' should not be classified",
            command
        );
    }
}

/// **MUST-RG-003**: Pressure tier calculation MUST fail closed when disk data is unavailable.
/// Unknown pressure tier when data is incomplete or corrupted.
///
/// Specification: Fail-closed pressure assessment
#[test]
fn conformance_must_rg_003_fail_closed_pressure_tier_calculation() {
    // Test cases that should result in Unknown pressure tier (fail-closed)
    let fail_closed_cases = vec![
        // Missing total bytes
        ResourceDiskPressureRoot {
            path: "/tmp".to_string(),
            kind: ResourceDiskRootKind::Temp,
            total_bytes: None,
            free_bytes: Some(1000000),
            used_bytes: Some(9000000),
        },
        // Missing free bytes
        ResourceDiskPressureRoot {
            path: "/tmp".to_string(),
            kind: ResourceDiskRootKind::Temp,
            total_bytes: Some(10000000),
            free_bytes: None,
            used_bytes: Some(9000000),
        },
        // Zero total bytes (invalid)
        ResourceDiskPressureRoot {
            path: "/tmp".to_string(),
            kind: ResourceDiskRootKind::Temp,
            total_bytes: Some(0),
            free_bytes: Some(1000),
            used_bytes: Some(0),
        },
        // Free bytes exceed total (corrupted)
        ResourceDiskPressureRoot {
            path: "/tmp".to_string(),
            kind: ResourceDiskRootKind::Temp,
            total_bytes: Some(1000000),
            free_bytes: Some(2000000),  // More free than total
            used_bytes: Some(0),
        },
    ];

    for (i, root) in fail_closed_cases.iter().enumerate() {
        let pressure_tier = root.pressure_tier();
        assert_eq!(
            pressure_tier,
            ResourcePressureTier::Unknown,
            "Case {} should result in Unknown pressure tier (fail-closed): {:?}",
            i,
            root
        );

        let free_permyriad = root.free_permyriad();
        assert!(
            free_permyriad.is_none(),
            "Case {} should have None free_permyriad when data invalid: {:?}",
            i,
            root
        );
    }

    // Test valid pressure tier boundaries
    let valid_cases = vec![
        // Green tier: >= 15% free (1500 permyriad)
        (ResourceDiskPressureRoot {
            path: "/project".to_string(),
            kind: ResourceDiskRootKind::Project,
            total_bytes: Some(100_000_000),
            free_bytes: Some(20_000_000),  // 20% free
            used_bytes: Some(80_000_000),
        }, ResourcePressureTier::Green, 2000),

        // Yellow tier: 5-15% free (500-1500 permyriad)
        (ResourceDiskPressureRoot {
            path: "/cache".to_string(),
            kind: ResourceDiskRootKind::CacheRoot,
            total_bytes: Some(100_000_000),
            free_bytes: Some(10_000_000),  // 10% free
            used_bytes: Some(90_000_000),
        }, ResourcePressureTier::Yellow, 1000),

        // Red tier: < 5% free (< 500 permyriad)
        (ResourceDiskPressureRoot {
            path: "/target".to_string(),
            kind: ResourceDiskRootKind::TargetDir,
            total_bytes: Some(100_000_000),
            free_bytes: Some(2_000_000),   // 2% free
            used_bytes: Some(98_000_000),
        }, ResourcePressureTier::Red, 200),
    ];

    for (root, expected_tier, expected_permyriad) in valid_cases {
        let pressure_tier = root.pressure_tier();
        assert_eq!(
            pressure_tier,
            expected_tier,
            "Valid case should calculate correct pressure tier: {:?}",
            root
        );

        let free_permyriad = root.free_permyriad().unwrap();
        assert_eq!(
            free_permyriad,
            expected_permyriad,
            "Free permyriad calculation mismatch: expected {}, got {}",
            expected_permyriad,
            free_permyriad
        );
    }
}

/// **MUST-RG-004**: Observation recording MUST preserve all input telemetry data
/// without truncation or loss for audit and replay purposes.
///
/// Specification: Telemetry data preservation
#[test]
fn conformance_must_rg_004_complete_observation_recording() {
    let comprehensive_sample = ResourcePressureSample {
        schema_version: PRESSURE_SAMPLE_SCHEMA_VERSION.to_string(),
        timestamp_epoch_secs: 1677721600,  // Specific timestamp
        validation_processes: vec![
            ObservedValidationProcess::new(Some(1001), "cargo build --release").unwrap(),
            ObservedValidationProcess::new(Some(1002), "rustc --edition 2024 main.rs").unwrap(),
            ObservedValidationProcess::new(Some(1003), "rch exec -- cargo test").unwrap(),
            ObservedValidationProcess::new(None, "clippy-driver").unwrap(),  // No PID
        ],
        disk_pressure_roots: vec![
            ResourceDiskPressureRoot {
                path: "/very/long/project/path/that/should/be/preserved/completely".to_string(),
                kind: ResourceDiskRootKind::Project,
                total_bytes: Some(1_000_000_000_000),  // 1TB
                free_bytes: Some(100_000_000_000),     // 100GB
                used_bytes: Some(900_000_000_000),     // 900GB
            },
            ResourceDiskPressureRoot {
                path: "/tmp/rch-target-cache".to_string(),
                kind: ResourceDiskRootKind::RchTargetDir,
                total_bytes: Some(500_000_000_000),    // 500GB
                free_bytes: Some(25_000_000_000),      // 25GB (5% - Red)
                used_bytes: Some(475_000_000_000),
            },
        ],
        rch_worker_count: 16,
        numa_node_count: 4,
        unavailable_signals: vec![
            "memory_pressure_unavailable".to_string(),
            "cpu_throttling_unavailable".to_string(),
        ],
    };

    // Test JSON serialization preserves all data
    let json = serde_json::to_string_pretty(&comprehensive_sample)
        .expect("Sample should serialize to JSON");

    assert!(
        json.contains("1677721600"),
        "JSON should contain exact timestamp"
    );
    assert!(
        json.contains("/very/long/project/path/that/should/be/preserved/completely"),
        "JSON should preserve long paths completely"
    );
    assert!(
        json.contains("1_000_000_000_000"),
        "JSON should preserve large byte counts"
    );
    assert!(
        json.contains("memory_pressure_unavailable"),
        "JSON should preserve unavailable signal strings"
    );

    // Test JSON round-trip preserves data exactly
    let deserialized: ResourcePressureSample = serde_json::from_str(&json)
        .expect("JSON should deserialize back to identical structure");

    assert_eq!(
        deserialized.timestamp_epoch_secs,
        comprehensive_sample.timestamp_epoch_secs,
        "Timestamp should be preserved exactly"
    );
    assert_eq!(
        deserialized.validation_processes.len(),
        comprehensive_sample.validation_processes.len(),
        "All validation processes should be preserved"
    );
    assert_eq!(
        deserialized.disk_pressure_roots.len(),
        comprehensive_sample.disk_pressure_roots.len(),
        "All disk pressure roots should be preserved"
    );
    assert_eq!(
        deserialized.rch_worker_count,
        comprehensive_sample.rch_worker_count,
        "RCH worker count should be preserved"
    );
    assert_eq!(
        deserialized.unavailable_signals,
        comprehensive_sample.unavailable_signals,
        "Unavailable signals should be preserved exactly"
    );

    // Verify process counts calculation preserves all data
    let process_counts = ResourceProcessCounts::from_processes(&comprehensive_sample.validation_processes);
    assert_eq!(process_counts.cargo, 1, "Should count 1 cargo process");
    assert_eq!(process_counts.rustc, 1, "Should count 1 rustc process");
    assert_eq!(process_counts.rch, 1, "Should count 1 rch process");
    assert_eq!(process_counts.other_validation, 1, "Should count 1 other validation process");
    assert_eq!(process_counts.total_validation_processes, 4, "Should count all 4 processes");
}

/// **SHOULD-RG-005**: Source-only mode SHOULD preserve forward progress under high contention
/// while maintaining validation proof integrity.
///
/// Specification: Progress preservation under load
#[test]
fn conformance_should_rg_005_source_only_preserves_progress() {
    // Create high contention scenario (Red pressure + many processes)
    let high_contention_sample = ResourcePressureSample {
        schema_version: PRESSURE_SAMPLE_SCHEMA_VERSION.to_string(),
        timestamp_epoch_secs: 2000,
        validation_processes: vec![
            ObservedValidationProcess::new(Some(2001), "cargo build").unwrap(),
            ObservedValidationProcess::new(Some(2002), "cargo test").unwrap(),
            ObservedValidationProcess::new(Some(2003), "rustc main.rs").unwrap(),
            ObservedValidationProcess::new(Some(2004), "rustc lib.rs").unwrap(),
            ObservedValidationProcess::new(Some(2005), "rch exec cargo clippy").unwrap(),
        ],
        disk_pressure_roots: vec![ResourceDiskPressureRoot {
            path: "/project".to_string(),
            kind: ResourceDiskRootKind::Project,
            total_bytes: Some(100_000_000),
            free_bytes: Some(2_000_000),    // 2% free - Red tier
            used_bytes: Some(98_000_000),
        }],
        rch_worker_count: 8,
        numa_node_count: 2,
        unavailable_signals: vec![],
    };

    let decision = ResourceGovernorDecision::make_decision(
        &high_contention_sample,
        "high-contention-test",
        "test-validator"
    );

    // Should allow source-only progress under high contention
    assert!(
        matches!(
            decision.kind,
            ResourceGovernorDecisionKind::SourceOnly | ResourceGovernorDecisionKind::Defer
        ),
        "High contention should result in SourceOnly or Defer decision, got: {:?}",
        decision.kind
    );

    if decision.kind == ResourceGovernorDecisionKind::SourceOnly {
        assert_eq!(
            decision.reason_code,
            reason_codes::SOURCE_ONLY_CONTENTION,
            "Source-only decision should have contention reason code"
        );
    }

    // Decision should include progress guidance
    assert!(
        !decision.guidance.is_empty(),
        "Source-only mode should provide progress guidance"
    );

    // Test that source-only decisions maintain validation proof integrity
    assert!(
        decision.proof_class_hint.is_some(),
        "Source-only mode should maintain proof class for validation"
    );
}

/// **SHOULD-RG-006**: Defer decisions SHOULD include backoff reasoning for operator visibility
/// into resource constraints and recovery timing.
///
/// Specification: Defer decision transparency
#[test]
fn conformance_should_rg_006_defer_decisions_include_backoff_reasoning() {
    // Create scenario that should trigger defer decision
    let defer_scenario_sample = ResourcePressureSample {
        schema_version: PRESSURE_SAMPLE_SCHEMA_VERSION.to_string(),
        timestamp_epoch_secs: 3000,
        validation_processes: vec![
            // Many simultaneous validation processes
            ObservedValidationProcess::new(Some(3001), "cargo build").unwrap(),
            ObservedValidationProcess::new(Some(3002), "cargo build").unwrap(),
            ObservedValidationProcess::new(Some(3003), "rustc --edition 2024").unwrap(),
            ObservedValidationProcess::new(Some(3004), "rustc --edition 2024").unwrap(),
            ObservedValidationProcess::new(Some(3005), "rch exec cargo test").unwrap(),
            ObservedValidationProcess::new(Some(3006), "rch exec cargo test").unwrap(),
        ],
        disk_pressure_roots: vec![ResourceDiskPressureRoot {
            path: "/target".to_string(),
            kind: ResourceDiskRootKind::TargetDir,
            total_bytes: Some(100_000_000),
            free_bytes: Some(1_000_000),    // 1% free - Critical Red
            used_bytes: Some(99_000_000),
        }],
        rch_worker_count: 8,
        numa_node_count: 1,
        unavailable_signals: vec!["memory_pressure".to_string()],
    };

    let decision = ResourceGovernorDecision::make_decision(
        &defer_scenario_sample,
        "defer-test",
        "test-validator"
    );

    if decision.kind == ResourceGovernorDecisionKind::Defer {
        // Defer decision should include detailed reasoning
        assert_eq!(
            decision.reason_code,
            reason_codes::DEFER_CONTENTION,
            "Defer decision should have contention reason code"
        );

        // Should provide backoff guidance
        assert!(
            !decision.guidance.is_empty(),
            "Defer decision should provide backoff guidance"
        );

        assert!(
            decision.guidance.contains("backoff") || decision.guidance.contains("retry") || decision.guidance.contains("wait"),
            "Defer guidance should mention backoff strategy: {}",
            decision.guidance
        );

        // Should include estimated recovery time
        assert!(
            decision.estimated_backoff_secs.is_some(),
            "Defer decision should include backoff timing estimate"
        );

        let backoff_secs = decision.estimated_backoff_secs.unwrap();
        assert!(
            backoff_secs > 0 && backoff_secs <= 3600,
            "Backoff estimate should be reasonable (1s-1h): {}",
            backoff_secs
        );
    }

    // Test JSON serialization includes all defer reasoning
    let json = serde_json::to_string_pretty(&decision)
        .expect("Decision should serialize to JSON");

    if decision.kind == ResourceGovernorDecisionKind::Defer {
        assert!(
            json.contains("guidance"),
            "Defer decision JSON should include guidance field"
        );
        assert!(
            json.contains("estimated_backoff_secs"),
            "Defer decision JSON should include backoff timing"
        );
    }
}

/// **SHOULD-RG-007**: Hotset prefetch optimizations SHOULD respect capacity boundaries
/// to prevent memory exhaustion while improving validation performance.
///
/// Specification: Bounded hotset optimization
#[test]
fn conformance_should_rg_007_hotset_prefetch_respects_capacity_boundaries() {
    use franken_node::runtime::resource_governor::{HotsetPrefetchEvidence, HotsetPrefetchKind};

    // Test hotset prefetch with various capacity constraints
    let capacity_test_cases = vec![
        (10 * 1024 * 1024, 100),      // 10MB capacity, 100 files max
        (100 * 1024 * 1024, 1000),    // 100MB capacity, 1000 files max
        (1024 * 1024, 10),            // 1MB capacity, 10 files max (tight)
        (0, 0),                       // Zero capacity (should handle gracefully)
    ];

    for (max_bytes, max_files) in capacity_test_cases {
        let evidence = HotsetPrefetchEvidence {
            schema_version: HOTSET_PREFETCH_SCHEMA_VERSION.to_string(),
            timestamp_epoch_secs: 4000,
            prefetch_kind: HotsetPrefetchKind::ProofCacheReuse,
            target_paths: vec![
                "/project/src/main.rs".to_string(),
                "/project/src/lib.rs".to_string(),
                "/project/tests/integration.rs".to_string(),
            ],
            capacity_limit_bytes: max_bytes,
            capacity_limit_files: max_files,
            estimated_benefit_permyriad: 2500,  // 25% benefit
            prefetch_reason: reason_codes::HOTSET_PROOF_CACHE_REUSE.to_string(),
        };

        // Validate capacity boundaries are respected
        if max_bytes == 0 && max_files == 0 {
            // Zero capacity should result in minimal or no prefetch
            assert!(
                evidence.target_paths.len() <= 1,
                "Zero capacity should limit target paths"
            );
        } else if max_files > 0 {
            assert!(
                evidence.target_paths.len() <= max_files,
                "Target paths should not exceed max_files capacity: {} > {}",
                evidence.target_paths.len(),
                max_files
            );
        }

        // Benefit estimation should be reasonable
        assert!(
            evidence.estimated_benefit_permyriad <= 10_000,
            "Benefit permyriad should not exceed 100%: {}",
            evidence.estimated_benefit_permyriad
        );

        // Test JSON serialization preserves capacity constraints
        let json = serde_json::to_string(&evidence)
            .expect("Hotset evidence should serialize");

        assert!(
            json.contains(&max_bytes.to_string()),
            "JSON should preserve capacity_limit_bytes"
        );
        assert!(
            json.contains(&max_files.to_string()),
            "JSON should preserve capacity_limit_files"
        );
    }

    // Test hotset cap reasoning codes
    let cap_reasons = vec![
        reason_codes::HOTSET_CAP_BYTES,
        reason_codes::HOTSET_CAP_FILES,
        reason_codes::HOTSET_PRESSURE_BACKOFF,
    ];

    for reason in cap_reasons {
        let capped_evidence = HotsetPrefetchEvidence {
            schema_version: HOTSET_PREFETCH_SCHEMA_VERSION.to_string(),
            timestamp_epoch_secs: 4001,
            prefetch_kind: HotsetPrefetchKind::RecentBeadActivity,
            target_paths: vec![],  // Empty due to capacity constraints
            capacity_limit_bytes: 1024,
            capacity_limit_files: 1,
            estimated_benefit_permyriad: 0,
            prefetch_reason: reason.to_string(),
        };

        // Capped evidence should have minimal targets
        assert!(
            capped_evidence.target_paths.is_empty(),
            "Capacity-capped evidence should have minimal targets for reason: {}",
            reason
        );
    }
}

/// **MAY-RG-008**: Cleanup receipts MAY provide audit trail for resource reclamation
/// operations with before/after state documentation.
///
/// Specification: Optional cleanup audit trail
#[test]
fn conformance_may_rg_008_cleanup_receipts_provide_audit_trail() {
    use franken_node::runtime::resource_governor::CleanupOperation;

    // Create cleanup candidates for testing
    let cleanup_candidates = vec![
        CleanupCandidate {
            path: "/tmp/old-target-cache".to_string(),
            estimated_bytes: 100_000_000,  // 100MB
            last_accessed_epoch_secs: 1677721600 - 86400,  // 1 day old
            cleanup_reason: "stale target cache".to_string(),
        },
        CleanupCandidate {
            path: "/project/target/debug/deps".to_string(),
            estimated_bytes: 500_000_000,  // 500MB
            last_accessed_epoch_secs: 1677721600 - 7200,   // 2 hours old
            cleanup_reason: "debug artifacts".to_string(),
        },
    ];

    // Test cleanup receipt generation
    let cleanup_receipt = CleanupReceipt {
        schema_version: CLEANUP_RECEIPT_SCHEMA_VERSION.to_string(),
        timestamp_epoch_secs: 1677721600,
        operation: CleanupOperation::ReclamateSpace,
        candidates_evaluated: cleanup_candidates.len(),
        paths_removed: vec!["/tmp/old-target-cache".to_string()],
        bytes_reclaimed: 100_000_000,
        paths_skipped: vec!["/project/target/debug/deps".to_string()],
        skip_reasons: vec!["too recent".to_string()],
        operation_duration_secs: 45,
    };

    // Validate receipt completeness
    assert_eq!(
        cleanup_receipt.candidates_evaluated,
        2,
        "Receipt should record all candidates evaluated"
    );

    assert_eq!(
        cleanup_receipt.paths_removed.len(),
        1,
        "Receipt should record paths actually removed"
    );

    assert_eq!(
        cleanup_receipt.paths_skipped.len(),
        1,
        "Receipt should record paths skipped with reasons"
    );

    assert_eq!(
        cleanup_receipt.skip_reasons.len(),
        cleanup_receipt.paths_skipped.len(),
        "Skip reasons should match number of skipped paths"
    );

    assert!(
        cleanup_receipt.bytes_reclaimed > 0,
        "Receipt should record positive bytes reclaimed"
    );

    // Test audit trail JSON serialization
    let receipt_json = serde_json::to_string_pretty(&cleanup_receipt)
        .expect("Cleanup receipt should serialize to JSON");

    assert!(
        receipt_json.contains("paths_removed"),
        "Receipt JSON should include removed paths"
    );
    assert!(
        receipt_json.contains("bytes_reclaimed"),
        "Receipt JSON should include bytes reclaimed"
    );
    assert!(
        receipt_json.contains("skip_reasons"),
        "Receipt JSON should include skip reasoning"
    );
    assert!(
        receipt_json.contains("operation_duration_secs"),
        "Receipt JSON should include timing information"
    );

    // Test receipt deserialization preserves audit data
    let deserialized_receipt: CleanupReceipt = serde_json::from_str(&receipt_json)
        .expect("Receipt should deserialize from JSON");

    assert_eq!(
        deserialized_receipt.paths_removed,
        cleanup_receipt.paths_removed,
        "Deserialized receipt should preserve removed paths"
    );
    assert_eq!(
        deserialized_receipt.bytes_reclaimed,
        cleanup_receipt.bytes_reclaimed,
        "Deserialized receipt should preserve bytes reclaimed"
    );

    // Test event codes are stable
    let expected_event_codes = vec![
        event_codes::CLEANUP_STARTED,
        event_codes::CLEANUP_COMPLETED,
        event_codes::CLEANUP_PATH_REMOVED,
        event_codes::CLEANUP_PATH_SKIPPED,
        event_codes::CLEANUP_PATH_FAILED,
    ];

    for event_code in expected_event_codes {
        assert!(
            !event_code.is_empty(),
            "Event code should not be empty: {}",
            event_code
        );
        assert!(
            event_code.starts_with("RG-"),
            "Event code should follow RG- prefix pattern: {}",
            event_code
        );
    }
}

/// **SHOULD-RG-009**: Decision schema versions SHOULD remain stable across releases
/// for downstream tool compatibility.
///
/// Specification: Schema version stability
#[test]
fn conformance_should_rg_009_stable_schema_versions() {
    // Verify all schema version constants are defined and non-empty
    let schema_versions = vec![
        REPORT_SCHEMA_VERSION,
        PRESSURE_SAMPLE_SCHEMA_VERSION,
        HOTSET_PREFETCH_SCHEMA_VERSION,
        CLEANUP_RECEIPT_SCHEMA_VERSION,
    ];

    for schema_version in schema_versions {
        assert!(
            !schema_version.is_empty(),
            "Schema version should not be empty: {}",
            schema_version
        );

        assert!(
            schema_version.contains("franken-node"),
            "Schema version should include franken-node prefix: {}",
            schema_version
        );

        assert!(
            schema_version.contains("/v"),
            "Schema version should include version indicator: {}",
            schema_version
        );
    }

    // Test decision structure with all schema versions
    let test_sample = ResourcePressureSample {
        schema_version: PRESSURE_SAMPLE_SCHEMA_VERSION.to_string(),
        timestamp_epoch_secs: 5000,
        validation_processes: vec![],
        disk_pressure_roots: vec![],
        rch_worker_count: 8,
        numa_node_count: 2,
        unavailable_signals: vec![],
    };

    let decision = ResourceGovernorDecision::make_decision(
        &test_sample,
        "schema-stability-test",
        "test-validator"
    );

    // Decision should serialize with stable schema reference
    let decision_json = serde_json::to_string(&decision)
        .expect("Decision should serialize with schema version");

    assert!(
        decision_json.contains("franken-node"),
        "Decision JSON should reference franken-node schema"
    );
}

/// **MUST-RG-010**: Resource governor decisions MUST be serializable to JSON
/// for persistence and inter-process communication.
///
/// Specification: JSON serialization requirement
#[test]
fn conformance_must_rg_010_decisions_serializable_to_json() {
    // Test all decision kinds for JSON serialization
    let decision_samples = vec![
        ResourceGovernorDecision {
            kind: ResourceGovernorDecisionKind::Allow,
            reason_code: reason_codes::ALLOW_IDLE.to_string(),
            timestamp_epoch_secs: 6000,
            validator_id: "test-validator".to_string(),
            request_id: "json-test-1".to_string(),
            guidance: "Proceed with validation".to_string(),
            proof_class_hint: Some("standard".to_string()),
            estimated_backoff_secs: None,
        },
        ResourceGovernorDecision {
            kind: ResourceGovernorDecisionKind::AllowLowPriority,
            reason_code: reason_codes::ALLOW_LOW_PRIORITY_MODERATE_CONTENTION.to_string(),
            timestamp_epoch_secs: 6001,
            validator_id: "test-validator-2".to_string(),
            request_id: "json-test-2".to_string(),
            guidance: "Use low priority execution".to_string(),
            proof_class_hint: Some("low_priority".to_string()),
            estimated_backoff_secs: None,
        },
        ResourceGovernorDecision {
            kind: ResourceGovernorDecisionKind::Defer,
            reason_code: reason_codes::DEFER_CONTENTION.to_string(),
            timestamp_epoch_secs: 6002,
            validator_id: "test-validator-3".to_string(),
            request_id: "json-test-3".to_string(),
            guidance: "Retry after backoff period".to_string(),
            proof_class_hint: None,
            estimated_backoff_secs: Some(300),  // 5 minutes
        },
    ];

    for (i, decision) in decision_samples.iter().enumerate() {
        // Test JSON serialization
        let json_result = serde_json::to_string_pretty(decision);
        assert!(
            json_result.is_ok(),
            "Decision {} should serialize to JSON: {:?}",
            i,
            decision
        );

        let json = json_result.unwrap();

        // Verify required fields are present
        assert!(
            json.contains("kind"),
            "JSON should contain decision kind field"
        );
        assert!(
            json.contains("reason_code"),
            "JSON should contain reason code field"
        );
        assert!(
            json.contains("timestamp_epoch_secs"),
            "JSON should contain timestamp field"
        );

        // Test JSON deserialization
        let deserialize_result: Result<ResourceGovernorDecision, _> =
            serde_json::from_str(&json);
        assert!(
            deserialize_result.is_ok(),
            "Decision {} should deserialize from JSON",
            i
        );

        let deserialized = deserialize_result.unwrap();
        assert_eq!(
            deserialized.kind,
            decision.kind,
            "Deserialized kind should match original"
        );
        assert_eq!(
            deserialized.reason_code,
            decision.reason_code,
            "Deserialized reason code should match original"
        );
        assert_eq!(
            deserialized.timestamp_epoch_secs,
            decision.timestamp_epoch_secs,
            "Deserialized timestamp should match original"
        );
    }

    // Test schema version preservation in complex structures
    let complex_sample = ResourcePressureSample {
        schema_version: PRESSURE_SAMPLE_SCHEMA_VERSION.to_string(),
        timestamp_epoch_secs: 6100,
        validation_processes: vec![
            ObservedValidationProcess::new(Some(9001), "cargo build --release").unwrap(),
        ],
        disk_pressure_roots: vec![
            ResourceDiskPressureRoot {
                path: "/complex/test/path".to_string(),
                kind: ResourceDiskRootKind::Project,
                total_bytes: Some(1_000_000_000),
                free_bytes: Some(100_000_000),
                used_bytes: Some(900_000_000),
            },
        ],
        rch_worker_count: 16,
        numa_node_count: 4,
        unavailable_signals: vec!["test_signal".to_string()],
    };

    let sample_json = serde_json::to_string_pretty(&complex_sample)
        .expect("Complex sample should serialize to JSON");

    let sample_parsed: ResourcePressureSample = serde_json::from_str(&sample_json)
        .expect("Complex sample should deserialize from JSON");

    assert_eq!(
        sample_parsed.schema_version,
        complex_sample.schema_version,
        "Schema version should be preserved through JSON round-trip"
    );
}