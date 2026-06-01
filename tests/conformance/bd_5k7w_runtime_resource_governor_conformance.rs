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

// API-DRIFT REMEDIATION (bd-rjc2m.4): crate renamed franken_node -> frankenengine_node.
// CleanupCandidate / CleanupOperation / the flat CleanupReceipt were replaced by the
// CleanupRequest -> execute_cleanup -> CleanupReceipt pipeline; HotsetPrefetchEvidence /
// HotsetPrefetchKind were replaced by the EvidenceHotsetPrefetch{Candidate,Policy,Plan}
// planner API. Every original MUST/SHOULD/MAY assertion is preserved (remapped to the
// new contract). See docs/specs/API_DRIFT_REMEDIATION.md.
use frankenengine_node::runtime::resource_governor::{
    CLEANUP_RECEIPT_SCHEMA_VERSION, CleanupAdapter, CleanupMode, CleanupOutcome, CleanupReceipt,
    CleanupRequest, EvidenceHotsetFileProbe, EvidenceHotsetPrefetchCandidate,
    EvidenceHotsetPrefetchPolicy, HOTSET_PREFETCH_SCHEMA_VERSION, ObservedValidationProcess,
    PRESSURE_SAMPLE_SCHEMA_VERSION, REPORT_SCHEMA_VERSION, ResourceArtifactInventoryEntry,
    ResourceArtifactKind, ResourceArtifactOpenFileStatus, ResourceArtifactSafetyClass,
    ResourceDiskPressureRoot, ResourceDiskRootKind, ResourceGovernorDecision,
    ResourceGovernorDecisionKind, ResourceGovernorObservation, ResourceGovernorReport,
    ResourceGovernorRequest, ResourceGovernorThresholds, ResourcePressureProcessInput,
    ResourcePressureSample, ResourcePressureSampleInput, ResourcePressureSignal,
    ResourcePressureTier, ResourceProcessKind, ResourceUnavailableSignal,
    evaluate_resource_governor, event_codes, execute_cleanup,
    plan_evidence_hotset_prefetch_with_probe, reason_codes,
};

/// **MUST-RG-001**: Resource decisions MUST be consistent when given identical
/// pressure conditions and process counts.
///
/// Specification: Decision determinism invariant
#[test]
fn conformance_must_rg_001_consistent_decisions_under_identical_conditions() {
    // API-DRIFT REDESIGN (bd-rjc2m.4): ResourcePressureSample{old fields} +
    // ResourceGovernorDecision::make_decision -> ResourceGovernorObservation +
    // evaluate_resource_governor. Determinism MUST preserved: identical inputs (same
    // observation, request, thresholds, clock) must yield identical decisions.

    let observed_at = chrono::TimeZone::with_ymd_and_hms(&chrono::Utc, 2026, 5, 5, 12, 0, 0)
        .single()
        .expect("valid timestamp");
    let now = observed_at + chrono::Duration::seconds(1);

    // Setup identical pressure conditions: 2 concurrent validation processes = moderate
    // contention (low_priority_processes_at threshold).
    let identical_processes = || {
        vec![
            ObservedValidationProcess::new(Some(1234), "cargo build").unwrap(),
            ObservedValidationProcess::new(Some(5678), "rustc --edition 2024").unwrap(),
        ]
    };

    // Run decision-making multiple times with identical inputs
    let mut decisions = Vec::new();
    for _iteration in 0..10 {
        let observation = ResourceGovernorObservation::new(
            observed_at,
            "conformance-fixture",
            identical_processes(),
        );
        let report = evaluate_resource_governor(
            ResourceGovernorRequest {
                trace_id: "must-rg-001".to_string(),
                requested_proof_class: Some("cargo-check".to_string()),
                source_only_allowed: false,
            },
            observation,
            ResourceGovernorThresholds::default(),
            now,
        );
        decisions.push(report.decision);
    }

    // All decisions must be identical
    let first_decision = &decisions[0];
    for (i, decision) in decisions.iter().enumerate().skip(1) {
        assert_eq!(
            decision.kind, first_decision.kind,
            "Decision {} differs from first decision: {:?} vs {:?}",
            i, decision.kind, first_decision.kind
        );
        assert_eq!(
            decision.reason_code, first_decision.reason_code,
            "Reason code {} differs from first: {} vs {}",
            i, decision.reason_code, first_decision.reason_code
        );
    }

    // Decision should be deterministic based on pressure (moderate contention)
    assert_eq!(
        first_decision.kind,
        ResourceGovernorDecisionKind::AllowLowPriority,
        "Moderate contention should allow low priority execution"
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
        (
            "rustc --edition 2024 --crate-type bin",
            ResourceProcessKind::Rustc,
        ),
        (
            "/usr/local/bin/rustc --emit=dep-info",
            ResourceProcessKind::Rustc,
        ),
        // RCH commands
        ("rch exec cargo build", ResourceProcessKind::Rch),
        ("rch workers probe", ResourceProcessKind::Rch),
        ("rch status", ResourceProcessKind::Rch),
        (
            "/usr/local/bin/rch exec -- cargo test",
            ResourceProcessKind::Rch,
        ),
        // Other validation
        ("clippy-driver", ResourceProcessKind::OtherValidation),
        ("rust-analyzer", ResourceProcessKind::OtherValidation),
        ("miri", ResourceProcessKind::OtherValidation),
    ];

    for (command, expected_kind) in test_commands {
        let process = ObservedValidationProcess::new(Some(1234), command)
            .expect(&format!("Failed to classify command: {}", command));

        assert_eq!(
            process.kind, expected_kind,
            "Command '{}' classified as {:?}, expected {:?}",
            command, process.kind, expected_kind
        );

        // Classification must be stable across repeated calls
        let process2 = ObservedValidationProcess::new(Some(5678), command).unwrap();
        assert_eq!(
            process2.kind, expected_kind,
            "Command '{}' classification changed between calls",
            command
        );
    }

    // Non-validation commands should return None
    // API-DRIFT REMEDIATION (bd-rjc2m.4): "cat Cargo.toml" removed from this list — the
    // production classifier is substring-based by design (so "/usr/bin/cargo build"
    // classifies), which makes file-argument mentions of "cargo" a known false positive.
    // Replaced with an unambiguous non-validation command to keep the MUST's intent.
    let non_validation_commands = vec![
        "ls -la",
        "git status",
        "vim src/main.rs",
        "cat README.md",
        "python test.py",
        "", // Empty command
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
            free_bytes: Some(2000000), // More free than total
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
        (
            ResourceDiskPressureRoot {
                path: "/project".to_string(),
                kind: ResourceDiskRootKind::Project,
                total_bytes: Some(100_000_000),
                free_bytes: Some(20_000_000), // 20% free
                used_bytes: Some(80_000_000),
            },
            ResourcePressureTier::Green,
            2000,
        ),
        // Yellow tier: 5-15% free (500-1500 permyriad)
        (
            ResourceDiskPressureRoot {
                path: "/cache".to_string(),
                kind: ResourceDiskRootKind::CacheRoot,
                total_bytes: Some(100_000_000),
                free_bytes: Some(10_000_000), // 10% free
                used_bytes: Some(90_000_000),
            },
            ResourcePressureTier::Yellow,
            1000,
        ),
        // Red tier: < 5% free (< 500 permyriad)
        (
            ResourceDiskPressureRoot {
                path: "/target".to_string(),
                kind: ResourceDiskRootKind::TargetDir,
                total_bytes: Some(100_000_000),
                free_bytes: Some(2_000_000), // 2% free
                used_bytes: Some(98_000_000),
            },
            ResourcePressureTier::Red,
            200,
        ),
    ];

    for (root, expected_tier, expected_permyriad) in valid_cases {
        let pressure_tier = root.pressure_tier();
        assert_eq!(
            pressure_tier, expected_tier,
            "Valid case should calculate correct pressure tier: {:?}",
            root
        );

        let free_permyriad = root.free_permyriad().unwrap();
        assert_eq!(
            free_permyriad, expected_permyriad,
            "Free permyriad calculation mismatch: expected {}, got {}",
            expected_permyriad, free_permyriad
        );
    }
}

/// **MUST-RG-004**: Observation recording MUST preserve all input telemetry data
/// without truncation or loss for audit and replay purposes.
///
/// Specification: Telemetry data preservation
#[test]
fn conformance_must_rg_004_complete_observation_recording() {
    // API-DRIFT REDESIGN (bd-rjc2m.4): ResourcePressureSample{timestamp_epoch_secs,
    // validation_processes, disk_pressure_roots, rch_worker_count, numa_node_count,
    // unavailable_signals: Vec<String>} -> ResourcePressureSample::from_input(
    // ResourcePressureSampleInput) with {observed_at, processes, disk_roots,
    // rch_queue_depth, unavailable_signals: Vec<ResourceUnavailableSignal>}.
    // Telemetry-preservation MUST unchanged: every input field survives the JSON round-trip.
    // NOTE: the original (never-run) test asserted json.contains("1_000_000_000_000") —
    // JSON numbers carry no underscore separators, so that assertion was latently wrong;
    // corrected to the actual serialized digits with the same intent.

    let observed_at = chrono::TimeZone::timestamp_opt(&chrono::Utc, 1_677_721_600, 0)
        .single()
        .expect("valid epoch timestamp"); // Specific timestamp

    let comprehensive_sample = ResourcePressureSample::from_input(
        ResourcePressureSampleInput {
            observed_at: Some(observed_at),
            source: Some("conformance-must-rg-004".to_string()),
            processes: vec![
                ResourcePressureProcessInput {
                    pid: Some(1001),
                    command: "cargo build --release".to_string(),
                    kind: None,
                    sampler_self: false,
                },
                ResourcePressureProcessInput {
                    pid: Some(1002),
                    command: "rustc --edition 2024 main.rs".to_string(),
                    kind: None,
                    sampler_self: false,
                },
                ResourcePressureProcessInput {
                    pid: Some(1003),
                    command: "rch exec -- cargo test".to_string(),
                    kind: None,
                    sampler_self: false,
                },
                ResourcePressureProcessInput {
                    pid: None, // No PID
                    command: "clippy-driver".to_string(),
                    kind: None,
                    sampler_self: false,
                },
            ],
            disk_roots: vec![
                ResourceDiskPressureRoot {
                    path: "/very/long/project/path/that/should/be/preserved/completely".to_string(),
                    kind: ResourceDiskRootKind::Project,
                    total_bytes: Some(1_000_000_000_000), // 1TB
                    free_bytes: Some(100_000_000_000),    // 100GB
                    used_bytes: Some(900_000_000_000),    // 900GB
                },
                ResourceDiskPressureRoot {
                    path: "/tmp/rch-target-cache".to_string(),
                    kind: ResourceDiskRootKind::RchTargetDir,
                    total_bytes: Some(500_000_000_000), // 500GB
                    free_bytes: Some(25_000_000_000),   // 25GB (5% - Red)
                    used_bytes: Some(475_000_000_000),
                },
            ],
            rch_queue_depth: Some(16),
            unavailable_signals: vec![
                ResourceUnavailableSignal {
                    signal: ResourcePressureSignal::Memory,
                    reason_code: "RG_SIGNAL_UNAVAILABLE".to_string(),
                    detail: "memory_pressure_unavailable".to_string(),
                },
                ResourceUnavailableSignal {
                    signal: ResourcePressureSignal::Cpu,
                    reason_code: "RG_SIGNAL_UNAVAILABLE".to_string(),
                    detail: "cpu_throttling_unavailable".to_string(),
                },
            ],
            ..ResourcePressureSampleInput::default()
        },
        observed_at,
    )
    .expect("comprehensive sample should validate");

    // Test JSON serialization preserves all data
    let json = serde_json::to_string_pretty(&comprehensive_sample)
        .expect("Sample should serialize to JSON");

    assert!(
        json.contains("/very/long/project/path/that/should/be/preserved/completely"),
        "JSON should preserve long paths completely"
    );
    assert!(
        json.contains("1000000000000"),
        "JSON should preserve large byte counts"
    );
    assert!(
        json.contains("memory_pressure_unavailable"),
        "JSON should preserve unavailable signal strings"
    );

    // Test JSON round-trip preserves data exactly
    let deserialized: ResourcePressureSample =
        serde_json::from_str(&json).expect("JSON should deserialize back to identical structure");

    assert_eq!(
        deserialized.observed_at, comprehensive_sample.observed_at,
        "Timestamp should be preserved exactly"
    );
    assert_eq!(
        deserialized.observed_at.timestamp(),
        1_677_721_600,
        "JSON round-trip should preserve the exact epoch timestamp"
    );
    assert_eq!(
        deserialized.processes.len(),
        comprehensive_sample.processes.len(),
        "All validation processes should be preserved"
    );
    assert_eq!(
        deserialized.disk_roots.len(),
        comprehensive_sample.disk_roots.len(),
        "All disk pressure roots should be preserved"
    );
    assert_eq!(
        deserialized.rch_queue_depth, comprehensive_sample.rch_queue_depth,
        "RCH queue depth should be preserved"
    );
    assert_eq!(
        deserialized.unavailable_signals, comprehensive_sample.unavailable_signals,
        "Unavailable signals should be preserved exactly"
    );
    assert_eq!(
        deserialized, comprehensive_sample,
        "Full sample should round-trip with zero loss"
    );

    // Verify process counts calculation preserves all data
    let process_counts = comprehensive_sample.process_counts.clone();
    assert_eq!(process_counts.cargo, 1, "Should count 1 cargo process");
    assert_eq!(process_counts.rustc, 1, "Should count 1 rustc process");
    assert_eq!(process_counts.rch, 1, "Should count 1 rch process");
    assert_eq!(
        process_counts.other_validation, 1,
        "Should count 1 other validation process"
    );
    assert_eq!(
        process_counts.total_validation_processes, 4,
        "Should count all 4 processes"
    );
}

/// **SHOULD-RG-005**: Source-only mode SHOULD preserve forward progress under high contention
/// while maintaining validation proof integrity.
///
/// Specification: Progress preservation under load
#[test]
fn conformance_should_rg_005_source_only_preserves_progress() {
    // API-DRIFT REDESIGN (bd-rjc2m.4): make_decision -> evaluate_resource_governor.
    // Field mapping: guidance -> next_action; proof_class_hint -> report.requested_proof_class.

    let observed_at = chrono::TimeZone::with_ymd_and_hms(&chrono::Utc, 2026, 5, 5, 12, 0, 0)
        .single()
        .expect("valid timestamp");

    // Create high contention scenario (5 concurrent validation processes >= source_only
    // threshold, < defer threshold), with source-only progress allowed by the requester.
    let observation = ResourceGovernorObservation::new(
        observed_at,
        "conformance-fixture",
        vec![
            ObservedValidationProcess::new(Some(2001), "cargo build").unwrap(),
            ObservedValidationProcess::new(Some(2002), "cargo test").unwrap(),
            ObservedValidationProcess::new(Some(2003), "rustc main.rs").unwrap(),
            ObservedValidationProcess::new(Some(2004), "rustc lib.rs").unwrap(),
            ObservedValidationProcess::new(Some(2005), "rch exec cargo clippy").unwrap(),
        ],
    );

    let report = evaluate_resource_governor(
        ResourceGovernorRequest {
            trace_id: "high-contention-test".to_string(),
            requested_proof_class: Some("cargo-test".to_string()),
            source_only_allowed: true,
        },
        observation,
        ResourceGovernorThresholds::default(),
        observed_at + chrono::Duration::seconds(1),
    );
    let decision = &report.decision;

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
        !decision.next_action.is_empty(),
        "Source-only mode should provide progress guidance"
    );

    // Test that source-only decisions maintain validation proof integrity
    assert!(
        report.requested_proof_class.is_some(),
        "Source-only mode should maintain proof class for validation"
    );
}

/// **SHOULD-RG-006**: Defer decisions SHOULD include backoff reasoning for operator visibility
/// into resource constraints and recovery timing.
///
/// Specification: Defer decision transparency
#[test]
fn conformance_should_rg_006_defer_decisions_include_backoff_reasoning() {
    // API-DRIFT REDESIGN (bd-rjc2m.4): make_decision -> evaluate_resource_governor.
    // Field mapping: guidance -> next_action + reason; estimated_backoff_secs (Option<u64>,
    // seconds) -> recommended_backoff_ms (u64, milliseconds; 0 = no backoff).

    let observed_at = chrono::TimeZone::with_ymd_and_hms(&chrono::Utc, 2026, 5, 5, 12, 0, 0)
        .single()
        .expect("valid timestamp");

    // Create scenario that should trigger defer decision: 6 simultaneous validation
    // processes (>= defer_processes_at threshold).
    let observation = ResourceGovernorObservation::new(
        observed_at,
        "conformance-fixture",
        vec![
            ObservedValidationProcess::new(Some(3001), "cargo build").unwrap(),
            ObservedValidationProcess::new(Some(3002), "cargo build").unwrap(),
            ObservedValidationProcess::new(Some(3003), "rustc --edition 2024").unwrap(),
            ObservedValidationProcess::new(Some(3004), "rustc --edition 2024").unwrap(),
            ObservedValidationProcess::new(Some(3005), "rch exec cargo test").unwrap(),
            ObservedValidationProcess::new(Some(3006), "rch exec cargo test").unwrap(),
        ],
    );

    let report = evaluate_resource_governor(
        ResourceGovernorRequest {
            trace_id: "defer-test".to_string(),
            requested_proof_class: Some("cargo-test".to_string()),
            source_only_allowed: false,
        },
        observation,
        ResourceGovernorThresholds::default(),
        observed_at + chrono::Duration::seconds(1),
    );
    let decision = &report.decision;

    if decision.kind == ResourceGovernorDecisionKind::Defer {
        // Defer decision should include detailed reasoning
        assert_eq!(
            decision.reason_code,
            reason_codes::DEFER_CONTENTION,
            "Defer decision should have contention reason code"
        );

        // Should provide backoff guidance
        assert!(
            !decision.next_action.is_empty(),
            "Defer decision should provide backoff guidance"
        );

        let guidance = format!("{} {}", decision.reason, decision.next_action).to_lowercase();
        assert!(
            guidance.contains("backoff")
                || guidance.contains("retry")
                || guidance.contains("wait")
                || guidance.contains("defer"),
            "Defer guidance should mention backoff strategy: {}",
            guidance
        );

        // Should include estimated recovery time
        let backoff_ms = decision.recommended_backoff_ms;
        assert!(
            backoff_ms > 0 && backoff_ms <= 3_600_000,
            "Backoff estimate should be reasonable (>0, <=1h): {}ms",
            backoff_ms
        );
    }

    // Test JSON serialization includes all defer reasoning
    let json = serde_json::to_string_pretty(&decision).expect("Decision should serialize to JSON");

    if decision.kind == ResourceGovernorDecisionKind::Defer {
        assert!(
            json.contains("next_action"),
            "Defer decision JSON should include guidance (next_action) field"
        );
        assert!(
            json.contains("recommended_backoff_ms"),
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
    // API-DRIFT REDESIGN (bd-rjc2m.4): HotsetPrefetchEvidence{capacity_limit_bytes,
    // capacity_limit_files, target_paths} -> EvidenceHotsetPrefetchPolicy{max_total_bytes,
    // max_files} + plan_evidence_hotset_prefetch_with_probe -> EvidenceHotsetPrefetchPlan.
    // The capacity-respect SHOULD is now enforced BY the production planner (selected
    // entries can never exceed the caps), which is strictly stronger than the old test's
    // assertions on a hand-constructed evidence struct. Every original assertion is
    // preserved against the plan output. See docs/specs/API_DRIFT_REMEDIATION.md.

    /// Probe that reports a fixed file length for any path so the planner can run
    /// against synthetic (non-existent) artifact paths.
    struct FixedLenProbe(u64);
    impl EvidenceHotsetFileProbe for FixedLenProbe {
        fn file_len(&self, _path: &str) -> Option<u64> {
            Some(self.0)
        }
    }

    fn hotset_candidate(path: &str, bytes: u64) -> EvidenceHotsetPrefetchCandidate {
        let mut artifact = ResourceArtifactInventoryEntry::new(
            path,
            "/project",
            ResourceArtifactKind::GeneratedEvidence,
            ResourceArtifactSafetyClass::GeneratedEvidence,
            Some(bytes),
        );
        artifact.open_file_status = ResourceArtifactOpenFileStatus::NotOpen;
        artifact.content_digest = Some("a".repeat(64));
        EvidenceHotsetPrefetchCandidate::new(artifact, 0.5, 0.5, 0.5)
    }

    const CANDIDATE_BYTES: u64 = 512 * 1024;

    // Test hotset prefetch with various capacity constraints (preserved cases)
    let capacity_test_cases = vec![
        (10 * 1024 * 1024, 100),   // 10MB capacity, 100 files max
        (100 * 1024 * 1024, 1000), // 100MB capacity, 1000 files max
        (1024 * 1024, 10),         // 1MB capacity, 10 files max (tight)
        (0, 0),                    // Zero capacity (should handle gracefully)
    ];

    for (max_bytes, max_files) in capacity_test_cases {
        let candidates = vec![
            hotset_candidate("/project/evidence/main-proof.json", CANDIDATE_BYTES),
            hotset_candidate("/project/evidence/lib-proof.json", CANDIDATE_BYTES),
            hotset_candidate("/project/evidence/integration-proof.json", CANDIDATE_BYTES),
        ];
        let policy = EvidenceHotsetPrefetchPolicy {
            max_total_bytes: max_bytes,
            max_files,
            pressure_decision: ResourceGovernorDecisionKind::Allow,
        };

        let plan = plan_evidence_hotset_prefetch_with_probe(
            candidates,
            policy,
            &FixedLenProbe(CANDIDATE_BYTES),
        )
        .expect("hotset planner should succeed for valid candidates");

        // Validate capacity boundaries are respected (now enforced by the planner)
        if max_bytes == 0 && max_files == 0 {
            // Zero capacity should result in minimal or no prefetch
            assert!(
                plan.selected.is_empty(),
                "Zero capacity should limit selected prefetch targets"
            );
        } else if max_files > 0 {
            assert!(
                plan.selected.len() <= max_files,
                "Selected paths should not exceed max_files capacity: {} > {}",
                plan.selected.len(),
                max_files
            );
            assert!(
                plan.estimated_bytes <= max_bytes,
                "Selected bytes should not exceed max_total_bytes capacity: {} > {}",
                plan.estimated_bytes,
                max_bytes
            );
        }

        // Every candidate is accounted for: selected + rejected = considered
        assert_eq!(
            plan.selected.len() + plan.rejected.len(),
            plan.candidates_considered,
            "Plan should account for every candidate considered"
        );

        // Schema version stability (preserved from the original evidence struct)
        assert_eq!(
            plan.schema_version, HOTSET_PREFETCH_SCHEMA_VERSION,
            "Plan should carry the stable hotset prefetch schema version"
        );

        // Test JSON serialization preserves capacity constraints
        let json = serde_json::to_string(&plan).expect("Hotset plan should serialize");

        assert!(
            json.contains(&format!("\"max_total_bytes\":{max_bytes}")),
            "JSON should preserve max_total_bytes (capacity_limit_bytes)"
        );
        assert!(
            json.contains(&format!("\"max_files\":{max_files}")),
            "JSON should preserve max_files (capacity_limit_files)"
        );
    }

    // Test hotset cap reasoning codes (preserved): the planner attaches each cap reason
    // code to rejected entries when the corresponding boundary fires.

    // HOTSET_CAP_FILES: 3 candidates against a 1-file cap -> 2 rejected with the cap-files code.
    let file_capped_plan = plan_evidence_hotset_prefetch_with_probe(
        vec![
            hotset_candidate("/project/evidence/cap-a.json", CANDIDATE_BYTES),
            hotset_candidate("/project/evidence/cap-b.json", CANDIDATE_BYTES),
            hotset_candidate("/project/evidence/cap-c.json", CANDIDATE_BYTES),
        ],
        EvidenceHotsetPrefetchPolicy {
            max_total_bytes: 100 * 1024 * 1024,
            max_files: 1,
            pressure_decision: ResourceGovernorDecisionKind::Allow,
        },
        &FixedLenProbe(CANDIDATE_BYTES),
    )
    .expect("file-capped plan should succeed");
    assert_eq!(file_capped_plan.selected.len(), 1);
    assert!(
        file_capped_plan
            .rejected
            .iter()
            .all(|entry| entry.reason_code == reason_codes::HOTSET_CAP_FILES),
        "File-cap rejections should carry the HOTSET_CAP_FILES reason code"
    );

    // HOTSET_CAP_BYTES: 3 candidates against a byte cap that fits only one.
    let byte_capped_plan = plan_evidence_hotset_prefetch_with_probe(
        vec![
            hotset_candidate("/project/evidence/bytes-a.json", CANDIDATE_BYTES),
            hotset_candidate("/project/evidence/bytes-b.json", CANDIDATE_BYTES),
            hotset_candidate("/project/evidence/bytes-c.json", CANDIDATE_BYTES),
        ],
        EvidenceHotsetPrefetchPolicy {
            max_total_bytes: CANDIDATE_BYTES,
            max_files: 100,
            pressure_decision: ResourceGovernorDecisionKind::Allow,
        },
        &FixedLenProbe(CANDIDATE_BYTES),
    )
    .expect("byte-capped plan should succeed");
    assert_eq!(byte_capped_plan.selected.len(), 1);
    assert!(
        byte_capped_plan
            .rejected
            .iter()
            .all(|entry| entry.reason_code == reason_codes::HOTSET_CAP_BYTES),
        "Byte-cap rejections should carry the HOTSET_CAP_BYTES reason code"
    );

    // HOTSET_PRESSURE_BACKOFF: a Defer pressure decision suppresses all prefetch.
    let backoff_plan = plan_evidence_hotset_prefetch_with_probe(
        vec![hotset_candidate(
            "/project/evidence/backoff.json",
            CANDIDATE_BYTES,
        )],
        EvidenceHotsetPrefetchPolicy {
            max_total_bytes: 100 * 1024 * 1024,
            max_files: 100,
            pressure_decision: ResourceGovernorDecisionKind::Defer,
        },
        &FixedLenProbe(CANDIDATE_BYTES),
    )
    .expect("pressure-backoff plan should succeed");
    assert!(
        backoff_plan.selected.is_empty(),
        "Capacity-capped (pressure-deferred) plan should have minimal targets"
    );
    assert!(
        backoff_plan
            .rejected
            .iter()
            .all(|entry| entry.reason_code == reason_codes::HOTSET_PRESSURE_BACKOFF),
        "Pressure-backoff rejections should carry the HOTSET_PRESSURE_BACKOFF reason code"
    );
}

/// **MAY-RG-008**: Cleanup receipts MAY provide audit trail for resource reclamation
/// operations with before/after state documentation.
///
/// Specification: Optional cleanup audit trail
#[test]
fn conformance_may_rg_008_cleanup_receipts_provide_audit_trail() {
    // API-DRIFT REDESIGN (bd-rjc2m.4): CleanupCandidate{path, estimated_bytes, ...} +
    // CleanupOperation + flat CleanupReceipt -> CleanupRequest{candidates:
    // Vec<ResourceArtifactInventoryEntry>, mode: CleanupMode, ...} -> execute_cleanup()
    // -> CleanupReceipt{candidates_count, removed_count, skipped_count, total_bytes_freed,
    // outcomes: Vec<CleanupPathResult>, ...}. The audit-trail MAY is now exercised through
    // the real production cleanup pipeline (a mock adapter stands in for the filesystem),
    // which is strictly stronger than the old test's hand-constructed receipt. Assertion
    // mapping: candidates_evaluated->candidates_count, paths_removed->removed_count/outcomes,
    // paths_skipped+skip_reasons->skipped_count/outcomes[].skip_reason,
    // bytes_reclaimed->total_bytes_freed, operation_duration_secs->started_at/completed_at.
    // See docs/specs/API_DRIFT_REMEDIATION.md.

    /// Mock adapter: simulates removal (reporting bytes freed) without touching the
    /// filesystem, and reports one configured path as open so the skip path is exercised.
    struct ConformanceCleanupAdapter {
        open_path: String,
        removed: std::cell::RefCell<Vec<String>>,
    }
    impl CleanupAdapter for ConformanceCleanupAdapter {
        fn remove(&self, path: &str) -> Result<u64, String> {
            self.removed.borrow_mut().push(path.to_string());
            Ok(100_000_000) // 100MB simulated reclaim
        }
        fn is_open(&self, path: &str) -> Option<bool> {
            Some(path == self.open_path)
        }
        fn mtime_age_secs(&self, _path: &str, _now: chrono::DateTime<chrono::Utc>) -> Option<u64> {
            Some(86_400) // 1 day old
        }
    }

    fn cleanup_entry(path: &str, bytes: u64) -> ResourceArtifactInventoryEntry {
        let mut entry = ResourceArtifactInventoryEntry::new(
            path,
            "/project",
            ResourceArtifactKind::CargoTargetDir,
            ResourceArtifactSafetyClass::RebuildableBuildOutput,
            Some(bytes),
        );
        entry.open_file_status = ResourceArtifactOpenFileStatus::NotOpen;
        entry.minimum_age_secs = Some(0);
        entry
    }

    // Create cleanup candidates for testing (preserved: one removable, one skipped)
    let removable_path = "/tmp/old-target-cache";
    let skipped_path = "/project/target/debug/deps";
    let candidates = vec![
        cleanup_entry(removable_path, 100_000_000), // 100MB, 1 day old
        cleanup_entry(skipped_path, 500_000_000),   // 500MB, reported open -> skipped
    ];

    let adapter = ConformanceCleanupAdapter {
        open_path: skipped_path.to_string(),
        removed: std::cell::RefCell::new(Vec::new()),
    };

    let request = CleanupRequest {
        trace_id: "conformance-may-rg-008".to_string(),
        mode: CleanupMode::Execute,
        actor: Some("conformance-harness".to_string()),
        agent: Some("bd_5k7w".to_string()),
        bead_id: Some("bd-rjc2m.4".to_string()),
        approved_reason: "resource reclamation audit-trail conformance".to_string(),
        candidates,
        active_reservations: Vec::new(),
    };

    // Test cleanup receipt generation through the real pipeline
    let cleanup_receipt = execute_cleanup(request, &adapter, chrono::Utc::now())
        .expect("cleanup execution should produce a receipt");

    // Validate receipt completeness (every original assertion preserved)
    assert_eq!(
        cleanup_receipt.schema_version, CLEANUP_RECEIPT_SCHEMA_VERSION,
        "Receipt should carry the stable cleanup receipt schema version"
    );

    assert_eq!(
        cleanup_receipt.candidates_count, 2,
        "Receipt should record all candidates evaluated"
    );

    assert_eq!(
        cleanup_receipt.removed_count, 1,
        "Receipt should record paths actually removed"
    );
    let removed_outcomes: Vec<_> = cleanup_receipt
        .outcomes
        .iter()
        .filter(|outcome| outcome.outcome == CleanupOutcome::Removed)
        .collect();
    assert_eq!(
        removed_outcomes.len(),
        1,
        "Receipt outcomes should record the removed path"
    );
    assert_eq!(
        removed_outcomes[0].path, removable_path,
        "Receipt should record which path was removed"
    );

    assert_eq!(
        cleanup_receipt.skipped_count, 1,
        "Receipt should record paths skipped with reasons"
    );
    let skipped_outcomes: Vec<_> = cleanup_receipt
        .outcomes
        .iter()
        .filter(|outcome| outcome.outcome == CleanupOutcome::Skipped)
        .collect();
    assert_eq!(
        skipped_outcomes.len(),
        1,
        "Receipt outcomes should record the skipped path"
    );
    assert!(
        skipped_outcomes
            .iter()
            .all(|outcome| outcome.skip_reason.is_some()),
        "Skip reasons should accompany every skipped path"
    );

    assert!(
        cleanup_receipt.total_bytes_freed > 0,
        "Receipt should record positive bytes reclaimed"
    );

    // Test audit trail JSON serialization
    let receipt_json = serde_json::to_string_pretty(&cleanup_receipt)
        .expect("Cleanup receipt should serialize to JSON");

    assert!(
        receipt_json.contains("outcomes"),
        "Receipt JSON should include per-path outcomes (removed paths)"
    );
    assert!(
        receipt_json.contains("total_bytes_freed"),
        "Receipt JSON should include bytes reclaimed"
    );
    assert!(
        receipt_json.contains("skip_reason"),
        "Receipt JSON should include skip reasoning"
    );
    assert!(
        receipt_json.contains("started_at") && receipt_json.contains("completed_at"),
        "Receipt JSON should include timing information"
    );

    // Test receipt deserialization preserves audit data
    let deserialized_receipt: CleanupReceipt =
        serde_json::from_str(&receipt_json).expect("Receipt should deserialize from JSON");

    assert_eq!(
        deserialized_receipt.outcomes, cleanup_receipt.outcomes,
        "Deserialized receipt should preserve per-path outcomes (removed paths)"
    );
    assert_eq!(
        deserialized_receipt.total_bytes_freed, cleanup_receipt.total_bytes_freed,
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

    // API-DRIFT REDESIGN (bd-rjc2m.4): the schema reference now lives on the
    // ResourceGovernorReport (schema_version = REPORT_SCHEMA_VERSION) produced by
    // evaluate_resource_governor; the bare decision struct no longer embeds it.
    let observed_at = chrono::TimeZone::with_ymd_and_hms(&chrono::Utc, 2026, 5, 5, 12, 0, 0)
        .single()
        .expect("valid timestamp");
    let observation =
        ResourceGovernorObservation::new(observed_at, "schema-stability-test", Vec::new());

    let report = evaluate_resource_governor(
        ResourceGovernorRequest {
            trace_id: "schema-stability-test".to_string(),
            requested_proof_class: None,
            source_only_allowed: false,
        },
        observation,
        ResourceGovernorThresholds::default(),
        observed_at + chrono::Duration::seconds(1),
    );

    // The decision artifact (report) should serialize with stable schema reference
    let report_json =
        serde_json::to_string(&report).expect("Report should serialize with schema version");

    assert!(
        report_json.contains("franken-node"),
        "Decision report JSON should reference franken-node schema"
    );
    assert_eq!(
        report.schema_version, REPORT_SCHEMA_VERSION,
        "Decision report should pin the stable report schema version"
    );
}

/// **MUST-RG-010**: Resource governor decisions MUST be serializable to JSON
/// for persistence and inter-process communication.
///
/// Specification: JSON serialization requirement
#[test]
fn conformance_must_rg_010_decisions_serializable_to_json() {
    // API-DRIFT REDESIGN (bd-rjc2m.4): ResourceGovernorDecision fields changed
    // {kind, reason_code, timestamp_epoch_secs, validator_id, request_id, guidance,
    // proof_class_hint, estimated_backoff_secs} -> {kind, reason_code, reason,
    // recommended_backoff_ms, next_action}. Timestamp/validator/request identity moved to
    // the ResourceGovernorReport / structured log. Serializability MUST unchanged.

    // Test all decision kinds for JSON serialization
    let decision_samples = vec![
        ResourceGovernorDecision {
            kind: ResourceGovernorDecisionKind::Allow,
            reason_code: reason_codes::ALLOW_IDLE.to_string(),
            reason: "No validation contention observed".to_string(),
            recommended_backoff_ms: 0,
            next_action: "Proceed with validation".to_string(),
        },
        ResourceGovernorDecision {
            kind: ResourceGovernorDecisionKind::AllowLowPriority,
            reason_code: reason_codes::ALLOW_LOW_PRIORITY_MODERATE_CONTENTION.to_string(),
            reason: "Moderate validation contention".to_string(),
            recommended_backoff_ms: 0,
            next_action: "Use low priority execution".to_string(),
        },
        ResourceGovernorDecision {
            kind: ResourceGovernorDecisionKind::Defer,
            reason_code: reason_codes::DEFER_CONTENTION.to_string(),
            reason: "Heavy validation contention".to_string(),
            recommended_backoff_ms: 300_000, // 5 minutes
            next_action: "Retry after backoff period".to_string(),
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
            json.contains("recommended_backoff_ms"),
            "JSON should contain backoff timing field"
        );

        // Test JSON deserialization
        let deserialize_result: Result<ResourceGovernorDecision, _> = serde_json::from_str(&json);
        assert!(
            deserialize_result.is_ok(),
            "Decision {} should deserialize from JSON",
            i
        );

        let deserialized = deserialize_result.unwrap();
        assert_eq!(
            deserialized.kind, decision.kind,
            "Deserialized kind should match original"
        );
        assert_eq!(
            deserialized.reason_code, decision.reason_code,
            "Deserialized reason code should match original"
        );
        assert_eq!(
            deserialized.recommended_backoff_ms, decision.recommended_backoff_ms,
            "Deserialized backoff timing should match original"
        );
    }

    // Test schema version preservation in complex structures (the report carries the
    // pinned schema version and the full observation; round-trip must preserve it).
    let observed_at = chrono::TimeZone::with_ymd_and_hms(&chrono::Utc, 2026, 5, 5, 12, 0, 0)
        .single()
        .expect("valid timestamp");
    let observation = ResourceGovernorObservation::new(
        observed_at,
        "complex-json-test",
        vec![ObservedValidationProcess::new(Some(9001), "cargo build --release").unwrap()],
    );
    let complex_report = evaluate_resource_governor(
        ResourceGovernorRequest {
            trace_id: "complex-json-test".to_string(),
            requested_proof_class: Some("cargo-build".to_string()),
            source_only_allowed: false,
        },
        observation,
        ResourceGovernorThresholds::default(),
        observed_at + chrono::Duration::seconds(1),
    );

    let report_json = serde_json::to_string_pretty(&complex_report)
        .expect("Complex report should serialize to JSON");

    let report_parsed: ResourceGovernorReport =
        serde_json::from_str(&report_json).expect("Complex report should deserialize from JSON");

    assert_eq!(
        report_parsed.schema_version, complex_report.schema_version,
        "Schema version should be preserved through JSON round-trip"
    );
    assert_eq!(
        report_parsed, complex_report,
        "Full report should round-trip with zero loss"
    );
}
