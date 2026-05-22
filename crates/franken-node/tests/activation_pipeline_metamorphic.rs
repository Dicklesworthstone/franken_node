//! Metamorphic tests for connector::activation_pipeline state machine determinism.
//!
//! Tests metamorphic relations to validate state machine invariants:
//! - INV-ACT-DETERMINISTIC: Same inputs → identical transcripts
//! - INV-ACT-NO-SECRET-LEAK: Failure → cleanup state consistency
//! - INV-ACT-STAGE-ORDER: Stage progression determinism
//! - Input commutativity within semantic constraints

use std::collections::BTreeSet;

use frankenengine_node::connector::activation_pipeline::{
    ActivationInput, ActivationStage, DefaultExecutor, StageExecutor, activate, transcripts_match,
    verify_stage_order,
};

const TEST_ITERATIONS: usize = 100;
const FUZZ_CAPABILITY_BOUNDARY: usize = 1024;
const FUZZ_SECRET_BOUNDARY: usize = 4096;

/// Test executor that can be configured to fail at specific stages
#[derive(Debug, Clone)]
struct ConfigurableExecutor {
    fail_sandbox: bool,
    fail_secret_mount: bool,
    fail_capability: bool,
    fail_health: bool,
    secret_mount_behavior: SecretMountBehavior,
}

#[derive(Debug, Clone)]
enum SecretMountBehavior {
    /// Mount exactly the requested secrets
    Exact,
    /// Mount secrets in different order but same set
    Reordered,
    /// Mount partial set (first N secrets only)
    Partial(usize),
    /// Mount extra secrets
    Extra(Vec<String>),
}

impl StageExecutor for ConfigurableExecutor {
    fn create_sandbox(&self, config: &str) -> Result<(), String> {
        if self.fail_sandbox {
            return Err("configurable sandbox failure".to_string());
        }
        if config.is_empty() {
            return Err("sandbox config must not be empty".to_string());
        }
        if serde_json::from_str::<serde_json::Value>(config).is_err() {
            return Err("sandbox config must be valid JSON".to_string());
        }
        Ok(())
    }

    fn mount_secrets(&self, refs: &[String]) -> Result<Vec<String>, String> {
        if self.fail_secret_mount {
            return Err("configurable secret mount failure".to_string());
        }

        match &self.secret_mount_behavior {
            SecretMountBehavior::Exact => Ok(refs.to_vec()),
            SecretMountBehavior::Reordered => {
                let mut reordered = refs.to_vec();
                reordered.reverse(); // Simple reordering
                Ok(reordered)
            }
            SecretMountBehavior::Partial(count) => Ok(refs.iter().take(*count).cloned().collect()),
            SecretMountBehavior::Extra(extras) => {
                let mut mounted = refs.to_vec();
                mounted.extend_from_slice(extras);
                Ok(mounted)
            }
        }
    }

    fn issue_capabilities(&self, caps: &[String]) -> Result<(), String> {
        if self.fail_capability {
            return Err("configurable capability failure".to_string());
        }
        if caps.len() > 1024 {
            return Err("too many capabilities".to_string());
        }
        Ok(())
    }

    fn health_check(&self) -> Result<(), String> {
        if self.fail_health {
            return Err("configurable health failure".to_string());
        }
        Ok(())
    }
}

impl Default for ConfigurableExecutor {
    fn default() -> Self {
        Self {
            fail_sandbox: false,
            fail_secret_mount: false,
            fail_capability: false,
            fail_health: false,
            secret_mount_behavior: SecretMountBehavior::Exact,
        }
    }
}

fn generate_test_input(seed: u64) -> ActivationInput {
    let connector_id = format!("connector-{:04}", seed % 1000);
    let trace_id = format!("trace-{:08x}", seed);
    let timestamp = format!(
        "2026-04-23T{:02}:{:02}:{:02}Z",
        (seed % 24) as u8,
        ((seed / 24) % 60) as u8,
        ((seed / (24 * 60)) % 60) as u8
    );

    let sandbox_config = serde_json::json!({
        "container_image": format!("app:v{}", seed % 10),
        "memory_limit": format!("{}MB", 64 + (seed % 512)),
        "cpu_limit": format!("{}m", 100 + (seed % 900)),
    })
    .to_string();

    let secret_count = (seed % 5) + 1; // 1-5 secrets
    let secret_refs = (0..secret_count)
        .map(|i| format!("secret-{}-{:02}", seed, i))
        .collect();

    let capability_count = (seed % 8) + 1; // 1-8 capabilities
    let capabilities = (0..capability_count)
        .map(|i| format!("cap-{}-{:02}", seed, i))
        .collect();

    ActivationInput {
        connector_id,
        sandbox_config,
        secret_refs,
        capabilities,
        trace_id,
        timestamp,
    }
}

struct ActivationConformanceCase {
    requirement: &'static str,
    executor: ConfigurableExecutor,
    expected_completed: bool,
    expected_stages: &'static [ActivationStage],
    expected_error_code: Option<&'static str>,
}

struct ActivationFuzzSeed {
    label: &'static str,
    input: ActivationInput,
    executor: ConfigurableExecutor,
    expected_completed: bool,
    expected_stages: &'static [ActivationStage],
    expected_error_code: Option<&'static str>,
}

const SANDBOX_ONLY: &[ActivationStage] = &[ActivationStage::SandboxCreate];
const THROUGH_SECRET_MOUNT: &[ActivationStage] =
    &[ActivationStage::SandboxCreate, ActivationStage::SecretMount];
const THROUGH_CAPABILITY_ISSUE: &[ActivationStage] = &[
    ActivationStage::SandboxCreate,
    ActivationStage::SecretMount,
    ActivationStage::CapabilityIssue,
];
const FULL_ACTIVATION: &[ActivationStage] = &[
    ActivationStage::SandboxCreate,
    ActivationStage::SecretMount,
    ActivationStage::CapabilityIssue,
    ActivationStage::HealthReady,
];

fn input_with_capability_count(seed: u64, count: usize) -> ActivationInput {
    let mut input = generate_test_input(seed);
    input.capabilities = (0..count)
        .map(|idx| format!("cap-boundary-{idx:04}"))
        .collect();
    input
}

fn input_with_secret_count(seed: u64, count: usize) -> ActivationInput {
    let mut input = generate_test_input(seed);
    input.secret_refs = (0..count)
        .map(|idx| format!("secret-boundary-{idx:04}"))
        .collect();
    input
}

fn activation_transition_fuzz_seeds() -> Vec<ActivationFuzzSeed> {
    let mut empty_sandbox_config = generate_test_input(0xa110_c001);
    empty_sandbox_config.sandbox_config.clear();

    let mut invalid_sandbox_json = generate_test_input(0xa110_c002);
    invalid_sandbox_json.sandbox_config = "{not-json".to_string();

    vec![
        ActivationFuzzSeed {
            label: "valid exact secret and capability issue reaches health",
            input: generate_test_input(0xa110_c100),
            executor: ConfigurableExecutor::default(),
            expected_completed: true,
            expected_stages: FULL_ACTIVATION,
            expected_error_code: None,
        },
        ActivationFuzzSeed {
            label: "secret mount order is semantic-set equivalent",
            input: generate_test_input(0xa110_c101),
            executor: ConfigurableExecutor {
                secret_mount_behavior: SecretMountBehavior::Reordered,
                ..Default::default()
            },
            expected_completed: true,
            expected_stages: FULL_ACTIVATION,
            expected_error_code: None,
        },
        ActivationFuzzSeed {
            label: "empty sandbox config stops before secret mount",
            input: empty_sandbox_config,
            executor: ConfigurableExecutor::default(),
            expected_completed: false,
            expected_stages: SANDBOX_ONLY,
            expected_error_code: Some("ACT_SANDBOX_FAILED"),
        },
        ActivationFuzzSeed {
            label: "invalid sandbox json stops before secret mount",
            input: invalid_sandbox_json,
            executor: ConfigurableExecutor::default(),
            expected_completed: false,
            expected_stages: SANDBOX_ONLY,
            expected_error_code: Some("ACT_SANDBOX_FAILED"),
        },
        ActivationFuzzSeed {
            label: "partial secret mount fails before capability issue",
            input: generate_test_input(0xa110_c102),
            executor: ConfigurableExecutor {
                secret_mount_behavior: SecretMountBehavior::Partial(1),
                ..Default::default()
            },
            expected_completed: false,
            expected_stages: THROUGH_SECRET_MOUNT,
            expected_error_code: Some("ACT_SECRET_MOUNT_FAILED"),
        },
        ActivationFuzzSeed {
            label: "extra secret mount fails before capability issue",
            input: generate_test_input(0xa110_c103),
            executor: ConfigurableExecutor {
                secret_mount_behavior: SecretMountBehavior::Extra(vec![
                    "unexpected-secret".to_string(),
                ]),
                ..Default::default()
            },
            expected_completed: false,
            expected_stages: THROUGH_SECRET_MOUNT,
            expected_error_code: Some("ACT_SECRET_MOUNT_FAILED"),
        },
        ActivationFuzzSeed {
            label: "explicit secret executor failure stops before capability issue",
            input: generate_test_input(0xa110_c104),
            executor: ConfigurableExecutor {
                fail_secret_mount: true,
                ..Default::default()
            },
            expected_completed: false,
            expected_stages: THROUGH_SECRET_MOUNT,
            expected_error_code: Some("ACT_SECRET_MOUNT_FAILED"),
        },
        ActivationFuzzSeed {
            label: "explicit capability executor failure stops before health",
            input: generate_test_input(0xa110_c105),
            executor: ConfigurableExecutor {
                fail_capability: true,
                ..Default::default()
            },
            expected_completed: false,
            expected_stages: THROUGH_CAPABILITY_ISSUE,
            expected_error_code: Some("ACT_CAPABILITY_FAILED"),
        },
        ActivationFuzzSeed {
            label: "explicit health executor failure is terminal",
            input: generate_test_input(0xa110_c106),
            executor: ConfigurableExecutor {
                fail_health: true,
                ..Default::default()
            },
            expected_completed: false,
            expected_stages: FULL_ACTIVATION,
            expected_error_code: Some("ACT_HEALTH_FAILED"),
        },
        ActivationFuzzSeed {
            label: "exact capability boundary still reaches health",
            input: input_with_capability_count(0xa110_c107, FUZZ_CAPABILITY_BOUNDARY),
            executor: ConfigurableExecutor::default(),
            expected_completed: true,
            expected_stages: FULL_ACTIVATION,
            expected_error_code: None,
        },
        ActivationFuzzSeed {
            label: "capability boundary overflow fails before side-effecting stages",
            input: input_with_capability_count(0xa110_c108, FUZZ_CAPABILITY_BOUNDARY + 1),
            executor: ConfigurableExecutor::default(),
            expected_completed: false,
            expected_stages: SANDBOX_ONLY,
            expected_error_code: Some("ACT_SANDBOX_FAILED"),
        },
        ActivationFuzzSeed {
            label: "secret boundary is fail-closed at capacity",
            input: input_with_secret_count(0xa110_c109, FUZZ_SECRET_BOUNDARY),
            executor: ConfigurableExecutor::default(),
            expected_completed: false,
            expected_stages: THROUGH_SECRET_MOUNT,
            expected_error_code: Some("ACT_SECRET_MOUNT_FAILED"),
        },
    ]
}

fn assert_activation_fuzz_seed(seed: &ActivationFuzzSeed) -> Result<(), String> {
    let transcript = activate(&seed.input, &seed.executor);
    let replayed = activate(&seed.input, &seed.executor);

    if !transcripts_match(&transcript, &replayed) {
        return Err(format!("{} replay transcript diverged", seed.label));
    }
    if !verify_stage_order(&transcript) {
        return Err(format!("{} violated canonical stage order", seed.label));
    }

    let actual_stages: Vec<_> = transcript.stages.iter().map(|stage| stage.stage).collect();
    if actual_stages.as_slice() != seed.expected_stages {
        return Err(format!(
            "{} stage prefix mismatch: got {:?}, expected {:?}",
            seed.label, actual_stages, seed.expected_stages
        ));
    }
    if transcript.completed != seed.expected_completed {
        return Err(format!(
            "{} completion mismatch: got {}, expected {}",
            seed.label, transcript.completed, seed.expected_completed
        ));
    }

    if seed.expected_completed {
        if transcript
            .stages
            .iter()
            .any(|stage| !stage.success || stage.error.is_some())
        {
            return Err(format!(
                "{} completed transcript contains failed stage or error",
                seed.label
            ));
        }
        return Ok(());
    }

    let Some((last, previous)) = transcript.stages.split_last() else {
        return Err(format!("{} failed without recording a stage", seed.label));
    };
    if previous
        .iter()
        .any(|stage| !stage.success || stage.error.is_some())
    {
        return Err(format!(
            "{} recorded an earlier failed stage before the terminal failure",
            seed.label
        ));
    }
    if last.success {
        return Err(format!(
            "{} incomplete transcript ended with success",
            seed.label
        ));
    }

    let expected_code = seed
        .expected_error_code
        .ok_or_else(|| format!("{} missing expected failure code", seed.label))?;
    let Some(error) = last.error.as_ref() else {
        return Err(format!("{} terminal stage omitted an error", seed.label));
    };
    if error.code() != expected_code {
        return Err(format!(
            "{} error code mismatch: got {}, expected {}",
            seed.label,
            error.code(),
            expected_code
        ));
    }

    Ok(())
}

/// Spec-derived conformance matrix for the activation stage contract.
#[test]
fn activation_pipeline_stage_contract_conformance_matrix() {
    let input = generate_test_input(0x5eed);
    let cases = [
        ActivationConformanceCase {
            requirement: "ACT-MUST-001 success visits every stage in canonical order",
            executor: ConfigurableExecutor::default(),
            expected_completed: true,
            expected_stages: FULL_ACTIVATION,
            expected_error_code: None,
        },
        ActivationConformanceCase {
            requirement: "ACT-MUST-002 sandbox failure stops before secret mount",
            executor: ConfigurableExecutor {
                fail_sandbox: true,
                ..Default::default()
            },
            expected_completed: false,
            expected_stages: SANDBOX_ONLY,
            expected_error_code: Some("ACT_SANDBOX_FAILED"),
        },
        ActivationConformanceCase {
            requirement: "ACT-MUST-003 secret mount failure stops before capability issue",
            executor: ConfigurableExecutor {
                fail_secret_mount: true,
                ..Default::default()
            },
            expected_completed: false,
            expected_stages: THROUGH_SECRET_MOUNT,
            expected_error_code: Some("ACT_SECRET_MOUNT_FAILED"),
        },
        ActivationConformanceCase {
            requirement: "ACT-MUST-004 capability failure stops before health readiness",
            executor: ConfigurableExecutor {
                fail_capability: true,
                ..Default::default()
            },
            expected_completed: false,
            expected_stages: THROUGH_CAPABILITY_ISSUE,
            expected_error_code: Some("ACT_CAPABILITY_FAILED"),
        },
        ActivationConformanceCase {
            requirement: "ACT-MUST-005 health failure is terminal and never completes",
            executor: ConfigurableExecutor {
                fail_health: true,
                ..Default::default()
            },
            expected_completed: false,
            expected_stages: FULL_ACTIVATION,
            expected_error_code: Some("ACT_HEALTH_FAILED"),
        },
        ActivationConformanceCase {
            requirement: "ACT-MUST-006 mounted secrets must exactly match requested refs",
            executor: ConfigurableExecutor {
                secret_mount_behavior: SecretMountBehavior::Extra(vec!["unexpected-secret".into()]),
                ..Default::default()
            },
            expected_completed: false,
            expected_stages: THROUGH_SECRET_MOUNT,
            expected_error_code: Some("ACT_SECRET_MOUNT_FAILED"),
        },
    ];

    for case in cases {
        let transcript = activate(&input, &case.executor);

        assert_eq!(
            transcript.completed, case.expected_completed,
            "{} completed mismatch",
            case.requirement
        );
        assert!(
            verify_stage_order(&transcript),
            "{} violated canonical stage order",
            case.requirement
        );

        let actual_stages: Vec<_> = transcript.stages.iter().map(|stage| stage.stage).collect();
        assert_eq!(
            actual_stages, case.expected_stages,
            "{} stage prefix mismatch",
            case.requirement
        );

        match case.expected_error_code {
            Some(expected_code) => {
                let Some(last) = transcript.stages.last() else {
                    assert!(
                        false,
                        "{} failed conformance cases must record a failed stage",
                        case.requirement
                    );
                    continue;
                };
                assert!(!last.success, "{} final stage must fail", case.requirement);
                let Some(error) = last.error.as_ref() else {
                    assert!(
                        false,
                        "{} failed stage must carry an error",
                        case.requirement
                    );
                    continue;
                };
                assert_eq!(
                    error.code(),
                    expected_code,
                    "{} error code mismatch",
                    case.requirement
                );
            }
            None => assert!(
                transcript.stages.iter().all(|stage| stage.error.is_none()),
                "{} successful activation must not emit errors",
                case.requirement
            ),
        }
    }
}

/// Structure-aware fuzz seed regression for activation state transitions.
#[test]
fn activation_pipeline_structure_aware_state_transition_fuzz_seeds() -> Result<(), String> {
    for seed in activation_transition_fuzz_seeds() {
        assert_activation_fuzz_seed(&seed)?;
    }

    Ok(())
}

/// Production default must fail closed until a real executor is supplied.
#[test]
fn activation_pipeline_default_executor_fail_closed_conformance() {
    let transcript = activate(&generate_test_input(0xdefa_17), &DefaultExecutor);

    assert!(!transcript.completed);
    assert!(verify_stage_order(&transcript));
    assert_eq!(transcript.stages.len(), 1);

    let Some(failure) = transcript.stages.first() else {
        assert!(false, "default executor must record a failed sandbox stage");
        return;
    };
    assert_eq!(failure.stage, ActivationStage::SandboxCreate);
    assert!(!failure.success);
    let Some(error) = failure.error.as_ref() else {
        assert!(false, "default executor failure must record a stage error");
        return;
    };
    assert_eq!(error.code(), "ACT_SANDBOX_FAILED");
    assert!(
        error
            .to_string()
            .contains("no real activation executor configured"),
        "default executor must explain the missing production executor: {error}"
    );
}

/// MR1: Equivalence - Duplicate inputs should produce identical transcripts (determinism)
#[test]
fn mr_duplicate_inputs_identical_transcripts() {
    for seed in 0..TEST_ITERATIONS {
        let input = generate_test_input(seed as u64);
        let executor = ConfigurableExecutor::default();

        let transcript1 = activate(&input, &executor);
        let transcript2 = activate(&input, &executor);

        // Transcripts should be byte-for-byte identical
        assert_eq!(
            transcript1.connector_id, transcript2.connector_id,
            "Connector IDs differ for seed {}",
            seed
        );
        assert_eq!(
            transcript1.trace_id, transcript2.trace_id,
            "Trace IDs differ for seed {}",
            seed
        );
        assert_eq!(
            transcript1.completed, transcript2.completed,
            "Completion status differs for seed {}",
            seed
        );
        assert_eq!(
            transcript1.stages.len(),
            transcript2.stages.len(),
            "Stage count differs for seed {}",
            seed
        );

        for (i, (stage1, stage2)) in transcript1
            .stages
            .iter()
            .zip(transcript2.stages.iter())
            .enumerate()
        {
            assert_eq!(
                stage1.stage, stage2.stage,
                "Stage type differs at index {} for seed {}",
                i, seed
            );
            assert_eq!(
                stage1.success, stage2.success,
                "Stage success differs at index {} for seed {}",
                i, seed
            );
            assert_eq!(
                stage1.timestamp, stage2.timestamp,
                "Stage timestamp differs at index {} for seed {}",
                i, seed
            );

            assert_eq!(
                stage1.error.is_some(),
                stage2.error.is_some(),
                "Error presence differs at index {} for seed {}",
                i,
                seed
            );
            if let (Some(e1), Some(e2)) = (&stage1.error, &stage2.error) {
                assert_eq!(
                    e1.code(),
                    e2.code(),
                    "Error codes differ at index {} for seed {}",
                    i,
                    seed
                );
            }
        }
    }
}

/// MR2: Permutative - Secret/capability reordering should preserve stage progression
/// (when semantic constraints allow exact mounting)
#[test]
fn mr_secret_reordering_preserves_progression() {
    for seed in 0..TEST_ITERATIONS {
        let input = generate_test_input(seed as u64);

        // Only test when we have multiple secrets to reorder
        if input.secret_refs.len() < 2 {
            continue;
        }

        let executor_exact = ConfigurableExecutor {
            secret_mount_behavior: SecretMountBehavior::Exact,
            ..Default::default()
        };

        let executor_reordered = ConfigurableExecutor {
            secret_mount_behavior: SecretMountBehavior::Reordered,
            ..Default::default()
        };

        let transcript_exact = activate(&input, &executor_exact);
        let transcript_reordered = activate(&input, &executor_reordered);

        // Stage progression should be identical (same stages reached)
        assert_eq!(
            transcript_exact.stages.len(),
            transcript_reordered.stages.len(),
            "Stage count differs after reordering for seed {}",
            seed
        );
        assert_eq!(
            transcript_exact.completed, transcript_reordered.completed,
            "Completion status differs after reordering for seed {}",
            seed
        );

        for (i, (stage1, stage2)) in transcript_exact
            .stages
            .iter()
            .zip(transcript_reordered.stages.iter())
            .enumerate()
        {
            assert_eq!(
                stage1.stage, stage2.stage,
                "Stage type differs at index {} after reordering for seed {}",
                i, seed
            );
            assert_eq!(
                stage1.success, stage2.success,
                "Stage success differs at index {} after reordering for seed {}",
                i, seed
            );
        }
    }
}

/// MR3: Inclusive - Capability subset should reach at least same stages as superset
#[test]
fn mr_capability_subset_stage_inclusion() {
    for seed in 0..TEST_ITERATIONS {
        let input_full = generate_test_input(seed as u64);

        // Only test when we have multiple capabilities
        if input_full.capabilities.len() < 2 {
            continue;
        }

        // Create subset by taking first half of capabilities
        let mut input_subset = input_full.clone();
        let subset_size = input_full.capabilities.len() / 2;
        input_subset.capabilities = input_full
            .capabilities
            .iter()
            .take(subset_size)
            .cloned()
            .collect();

        let executor = ConfigurableExecutor::default();

        let transcript_full = activate(&input_full, &executor);
        let transcript_subset = activate(&input_subset, &executor);

        // If subset completes successfully, full set should too (monotonic)
        if transcript_subset.completed {
            assert!(
                transcript_full.completed,
                "Full capability set failed while subset succeeded for seed {}",
                seed
            );

            // Should reach at least as many stages
            assert!(
                transcript_subset.stages.len() <= transcript_full.stages.len(),
                "Subset reached more stages than full set for seed {}",
                seed
            );
        }

        // Both should have same stage types in same order (prefix relation)
        let min_stages = transcript_subset
            .stages
            .len()
            .min(transcript_full.stages.len());
        for i in 0..min_stages {
            assert_eq!(
                transcript_subset.stages[i].stage, transcript_full.stages[i].stage,
                "Stage order differs at index {} for seed {}",
                i, seed
            );
        }
    }
}

/// MR4: Invertive - Failed activation cleanup should be idempotent
#[test]
fn mr_failure_cleanup_idempotent() {
    for seed in 0..TEST_ITERATIONS {
        let input = generate_test_input(seed as u64);

        // Test each failure mode
        let failure_configs = [
            ConfigurableExecutor {
                fail_sandbox: true,
                ..Default::default()
            },
            ConfigurableExecutor {
                fail_secret_mount: true,
                ..Default::default()
            },
            ConfigurableExecutor {
                fail_capability: true,
                ..Default::default()
            },
            ConfigurableExecutor {
                fail_health: true,
                ..Default::default()
            },
        ];

        for (failure_idx, executor) in failure_configs.iter().enumerate() {
            let transcript1 = activate(&input, executor);
            let transcript2 = activate(&input, executor);

            // Failed activations should be identical (idempotent cleanup)
            assert!(
                !transcript1.completed,
                "Expected failure for config {} seed {}",
                failure_idx, seed
            );
            assert_eq!(
                transcript1.completed, transcript2.completed,
                "Completion status differs for failure config {} seed {}",
                failure_idx, seed
            );
            assert_eq!(
                transcript1.stages.len(),
                transcript2.stages.len(),
                "Stage count differs for failure config {} seed {}",
                failure_idx,
                seed
            );

            // Last stage should have failed consistently
            let last1 = transcript1.stages.last().unwrap();
            let last2 = transcript2.stages.last().unwrap();
            assert!(
                !last1.success && !last2.success,
                "Last stages should both fail for config {} seed {}",
                failure_idx,
                seed
            );
            assert_eq!(
                last1.error.as_ref().unwrap().code(),
                last2.error.as_ref().unwrap().code(),
                "Error codes differ for failure config {} seed {}",
                failure_idx,
                seed
            );
        }
    }
}

/// MR5: Additive - Adding valid capabilities should preserve existing stage success
#[test]
fn mr_capability_addition_preserves_stages() {
    for seed in 0..TEST_ITERATIONS {
        let input_base = generate_test_input(seed as u64);

        // Create extended input with additional capabilities
        let mut input_extended = input_base.clone();
        let additional_caps = vec![
            format!("extra-cap-{}-01", seed),
            format!("extra-cap-{}-02", seed),
        ];
        input_extended.capabilities.extend(additional_caps);

        let executor = ConfigurableExecutor::default();

        let transcript_base = activate(&input_base, &executor);
        let transcript_extended = activate(&input_extended, &executor);

        // If base succeeds, extended should succeed (capability addition is monotonic)
        if transcript_base.completed {
            assert!(
                transcript_extended.completed,
                "Extended capability set failed while base succeeded for seed {}",
                seed
            );
        }

        // Extended should reach at least as many stages as base
        assert!(
            transcript_base.stages.len() <= transcript_extended.stages.len(),
            "Base reached more stages than extended for seed {}",
            seed
        );

        // Stages that both reached should have same success patterns
        let min_stages = transcript_base
            .stages
            .len()
            .min(transcript_extended.stages.len());
        for i in 0..min_stages {
            assert_eq!(
                transcript_base.stages[i].stage, transcript_extended.stages[i].stage,
                "Stage type differs at index {} for seed {}",
                i, seed
            );

            // If base stage succeeded, extended should too (monotonic success)
            if transcript_base.stages[i].success {
                assert!(
                    transcript_extended.stages[i].success,
                    "Extended stage failed while base succeeded at index {} for seed {}",
                    i, seed
                );
            }
        }
    }
}

/// MR6: Equivalence - Stage ordering must be deterministic regardless of input variations
#[test]
fn mr_stage_order_invariant() {
    for seed in 0..TEST_ITERATIONS {
        let input = generate_test_input(seed as u64);
        let executor = ConfigurableExecutor::default();

        let transcript = activate(&input, &executor);

        // Verify stage order matches canonical sequence
        let expected_order = [
            ActivationStage::SandboxCreate,
            ActivationStage::SecretMount,
            ActivationStage::CapabilityIssue,
            ActivationStage::HealthReady,
        ];

        for (i, stage_result) in transcript.stages.iter().enumerate() {
            assert_eq!(
                stage_result.stage, expected_order[i],
                "Stage order violation at index {} for seed {}: expected {:?}, got {:?}",
                i, seed, expected_order[i], stage_result.stage
            );

            assert_eq!(
                stage_result.stage.order(),
                i as u8,
                "Stage order value mismatch at index {} for seed {}",
                i,
                seed
            );
        }

        // If we reached stage N, we must have reached all stages 0..N-1
        let reached_stages: BTreeSet<_> =
            transcript.stages.iter().map(|s| s.stage.order()).collect();

        if let Some(&max_reached) = reached_stages.iter().max() {
            for stage_order in 0..=max_reached {
                assert!(
                    reached_stages.contains(&stage_order),
                    "Missing intermediate stage {} when max reached {} for seed {}",
                    stage_order,
                    max_reached,
                    seed
                );
            }
        }
    }
}

/// Composite MR: Combine determinism + stage ordering + cleanup consistency
#[test]
fn mr_composite_state_machine_invariants() {
    for seed in 0..TEST_ITERATIONS {
        let input = generate_test_input(seed as u64);

        // Test multiple executor configurations
        let executors = [
            ConfigurableExecutor::default(),
            ConfigurableExecutor {
                fail_capability: true,
                ..Default::default()
            },
            ConfigurableExecutor {
                secret_mount_behavior: SecretMountBehavior::Reordered,
                ..Default::default()
            },
            ConfigurableExecutor {
                secret_mount_behavior: SecretMountBehavior::Partial(1),
                ..Default::default()
            },
            ConfigurableExecutor {
                secret_mount_behavior: SecretMountBehavior::Extra(vec!["extra-secret".to_string()]),
                ..Default::default()
            },
        ];

        for (exec_idx, executor) in executors.iter().enumerate() {
            // MR1: Determinism - multiple runs should be identical
            let transcript1 = activate(&input, executor);
            let transcript2 = activate(&input, executor);

            assert_eq!(
                transcript1.completed, transcript2.completed,
                "Determinism violated for executor {} seed {}",
                exec_idx, seed
            );
            assert_eq!(
                transcript1.stages.len(),
                transcript2.stages.len(),
                "Determinism violated for executor {} seed {}",
                exec_idx,
                seed
            );

            // MR6: Stage ordering - must follow canonical sequence
            for (i, stage_result) in transcript1.stages.iter().enumerate() {
                assert_eq!(
                    stage_result.stage.order(),
                    i as u8,
                    "Stage ordering violated at index {} for executor {} seed {}",
                    i,
                    exec_idx,
                    seed
                );
            }

            // MR4: Cleanup consistency - failure state should be clean
            if !transcript1.completed {
                // Verify failure occurred at expected stage progression point
                let failed_stage = transcript1.stages.last().unwrap();
                assert!(
                    !failed_stage.success,
                    "Incomplete activation should end with failed stage for executor {} seed {}",
                    exec_idx, seed
                );

                // Should have error details
                assert!(
                    failed_stage.error.is_some(),
                    "Failed stage missing error details for executor {} seed {}",
                    exec_idx,
                    seed
                );
            }
        }
    }
}
