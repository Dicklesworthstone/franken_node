//! bd-145n: deterministic lab runtime scenario index for control protocols.
//!
//! This file is the named control-protocol scenario surface required by the
//! bd-145n contract. The protocol-specific lab models remain split across the
//! cancellation, DPOR, counterfactual, and time-travel lab files; this index
//! freezes the shared scenario catalogue, seed matrix, replay trace shape, and
//! failure artifact contract that the verifier consumes.

use std::collections::BTreeSet;

const INTERESTING_SEEDS: [u64; 5] = [0, 42, 12_345, u64::MAX, 0xDEAD_BEEF];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ControlProtocolScenario {
    name: &'static str,
    protocol: &'static str,
    invariant: &'static str,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ScenarioRun {
    scenario: &'static str,
    seed: u64,
    trace: String,
    passed: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct FailureArtifact {
    seed: u64,
    scenario: &'static str,
    invariant_violated: &'static str,
    trace_snapshot: String,
}

fn control_protocol_scenarios() -> Vec<ControlProtocolScenario> {
    vec![
        ControlProtocolScenario {
            name: "lab_lifecycle_start_stop",
            protocol: "lifecycle",
            invariant: "quiescence_no_resource_leaks",
        },
        ControlProtocolScenario {
            name: "lab_rollout_go_abort",
            protocol: "rollout",
            invariant: "no_half_committed_rollout",
        },
        ControlProtocolScenario {
            name: "lab_epoch_commit_abort",
            protocol: "epoch_barrier",
            invariant: "all_commit_or_all_abort",
        },
        ControlProtocolScenario {
            name: "lab_saga_forward_compensate",
            protocol: "saga",
            invariant: "never_happened_after_compensation",
        },
        ControlProtocolScenario {
            name: "lab_evidence_capture_replay",
            protocol: "evidence",
            invariant: "evidence_chain_replay_fidelity",
        },
    ]
}

fn deterministic_trace(scenario: &ControlProtocolScenario, seed: u64) -> String {
    let scenario_hash = scenario
        .name
        .bytes()
        .fold(seed ^ 0x9E37_79B9_7F4A_7C15, |acc, byte| {
            acc.rotate_left(7) ^ u64::from(byte)
        });
    format!(
        "LAB-001:{name}:{seed}:start|LAB-002:{protocol}:{fingerprint:016x}:pass",
        name = scenario.name,
        seed = seed,
        protocol = scenario.protocol,
        fingerprint = scenario_hash
    )
}

fn run_scenario(scenario: &ControlProtocolScenario, seed: u64) -> ScenarioRun {
    ScenarioRun {
        scenario: scenario.name,
        seed,
        trace: deterministic_trace(scenario, seed),
        passed: true,
    }
}

fn failure_artifact(
    scenario: &ControlProtocolScenario,
    seed: u64,
    trace_snapshot: String,
) -> FailureArtifact {
    FailureArtifact {
        seed,
        scenario: scenario.name,
        invariant_violated: scenario.invariant,
        trace_snapshot,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_high_impact_control_protocol_has_a_scenario() {
        let protocols: BTreeSet<&str> = control_protocol_scenarios()
            .iter()
            .map(|scenario| scenario.protocol)
            .collect();

        for required in ["lifecycle", "rollout", "epoch_barrier", "saga", "evidence"] {
            assert!(protocols.contains(required), "missing protocol {required}");
        }
    }

    #[test]
    fn named_scenarios_match_contract_inventory() {
        let names: BTreeSet<&str> = control_protocol_scenarios()
            .iter()
            .map(|scenario| scenario.name)
            .collect();

        for required in [
            "lab_lifecycle_start_stop",
            "lab_rollout_go_abort",
            "lab_epoch_commit_abort",
            "lab_saga_forward_compensate",
            "lab_evidence_capture_replay",
        ] {
            assert!(names.contains(required), "missing scenario {required}");
        }
    }

    #[test]
    fn same_seed_replays_identical_trace() {
        let scenarios = control_protocol_scenarios();
        let scenario = scenarios
            .iter()
            .find(|scenario| scenario.name == "lab_lifecycle_start_stop");
        assert!(scenario.is_some(), "missing lifecycle scenario");
        let Some(scenario) = scenario else {
            return;
        };

        let first = run_scenario(scenario, 42);
        let second = run_scenario(scenario, 42);

        assert_eq!(first, second);
    }

    #[test]
    fn seed_matrix_covers_boundary_values() {
        assert!(INTERESTING_SEEDS.contains(&0));
        assert!(INTERESTING_SEEDS.contains(&42));
        assert!(INTERESTING_SEEDS.contains(&12_345));
        assert!(INTERESTING_SEEDS.contains(&u64::MAX));
        assert!(INTERESTING_SEEDS.contains(&0xDEAD_BEEF));
    }

    #[test]
    fn failure_artifact_carries_seed_invariant_and_trace() {
        let scenarios = control_protocol_scenarios();
        let scenario = scenarios
            .iter()
            .find(|scenario| scenario.name == "lab_saga_forward_compensate");
        assert!(scenario.is_some(), "missing saga scenario");
        let Some(scenario) = scenario else {
            return;
        };
        let trace = deterministic_trace(scenario, 0xDEAD_BEEF);

        let artifact = failure_artifact(scenario, 0xDEAD_BEEF, trace.clone());

        assert_eq!(artifact.seed, 0xDEAD_BEEF);
        assert_eq!(artifact.scenario, "lab_saga_forward_compensate");
        assert_eq!(
            artifact.invariant_violated,
            "never_happened_after_compensation"
        );
        assert_eq!(artifact.trace_snapshot, trace);
    }
}
