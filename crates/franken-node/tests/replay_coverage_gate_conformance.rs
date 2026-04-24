use chrono::{DateTime, Utc};
use serde::Deserialize;
use std::collections::BTreeSet;
use std::error::Error;
use std::io::{Error as IoError, ErrorKind};
use std::path::{Path, PathBuf};

const MATRIX_PATH: &str = "artifacts/13/replay_coverage_matrix.json";
const SPEC_PATH: &str = "docs/specs/section_13/bd-2l1k_contract.md";
const SPEC_REQUIRED_INCIDENT_TYPES: &[&str] = &[
    "rce",
    "privilege_escalation",
    "data_exfiltration",
    "sandbox_escape",
    "trust_system_bypass",
    "supply_chain_compromise",
    "denial_of_service",
    "memory_corruption",
];
const MIN_DETERMINISTIC_RUNS: u64 = 10;
const REQUIRED_COVERAGE_RATIO: f64 = 1.0;
const NEW_INCIDENT_SLA_DAYS: i64 = 14;

#[derive(Debug, Deserialize)]
struct ReplayCoverageMatrix {
    bead_id: String,
    trace_id: String,
    minimum_required_coverage_ratio: f64,
    new_incident_type_sla_days: i64,
    required_incident_types: Vec<String>,
    replay_artifacts: Vec<ReplayArtifactRecord>,
    coverage_summary: CoverageSummary,
}

#[derive(Debug, Clone, Deserialize)]
struct ReplayArtifactRecord {
    incident_type: String,
    artifact_path: String,
    last_verified_utc: String,
    deterministic_runs: u64,
    deterministic_match: bool,
    initial_state_snapshot: String,
    input_sequence: Vec<String>,
    expected_behavior_trace: Vec<String>,
    actual_behavior_trace: Vec<String>,
    divergence_point: String,
    reproduction_command: String,
    discovered_at_utc: String,
}

#[derive(Debug, Deserialize)]
struct CoverageSummary {
    required_count: usize,
    covered_count: usize,
    coverage_ratio: f64,
}

#[derive(Debug, Deserialize)]
struct ReplayArtifact {
    incident_type: String,
    initial_state_snapshot: String,
    input_sequence: Vec<String>,
    expected_behavior_trace: Vec<String>,
    actual_behavior_trace: Vec<String>,
    divergence_point: String,
    last_verified_utc: String,
    deterministic_runs: u64,
    deterministic_match: bool,
    reproduction_command: String,
}

#[derive(Debug, PartialEq, Eq)]
struct GateVerdict {
    pass: bool,
    required_count: usize,
    covered_count: usize,
    missing_incident_types: Vec<String>,
}

fn repo_root() -> Result<PathBuf, Box<dyn Error>> {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .map(Path::to_path_buf)
        .ok_or_else(|| IoError::new(ErrorKind::NotFound, "workspace root").into())
}

fn read_workspace_file(relative_path: &str) -> Result<String, Box<dyn Error>> {
    let path = repo_root()?.join(relative_path);
    std::fs::read_to_string(&path).map_err(|err| {
        IoError::new(
            err.kind(),
            format!("failed to read {}: {err}", path.display()),
        )
        .into()
    })
}

fn load_matrix() -> Result<ReplayCoverageMatrix, Box<dyn Error>> {
    let raw = read_workspace_file(MATRIX_PATH)?;
    serde_json::from_str(&raw).map_err(|err| {
        IoError::new(
            ErrorKind::InvalidData,
            format!("{MATRIX_PATH} must parse as replay coverage matrix JSON: {err}"),
        )
        .into()
    })
}

fn load_artifact(path: &str) -> Result<ReplayArtifact, Box<dyn Error>> {
    let raw = read_workspace_file(path)?;
    serde_json::from_str(&raw).map_err(|err| {
        IoError::new(
            ErrorKind::InvalidData,
            format!("{path} must parse as replay artifact JSON: {err}"),
        )
        .into()
    })
}

fn parse_utc(timestamp: &str, field_name: &str) -> Result<DateTime<Utc>, Box<dyn Error>> {
    DateTime::parse_from_rfc3339(timestamp)
        .map(|parsed| parsed.with_timezone(&Utc))
        .map_err(|err| {
            IoError::new(
                ErrorKind::InvalidData,
                format!("{field_name} must be RFC3339 UTC timestamp: {err}"),
            )
            .into()
        })
}

fn evaluate_gate(records: &[ReplayArtifactRecord], required: &[String]) -> GateVerdict {
    let covered: BTreeSet<&str> = records
        .iter()
        .filter(|record| {
            record.deterministic_match
                && record.deterministic_runs >= MIN_DETERMINISTIC_RUNS
                && !record.initial_state_snapshot.is_empty()
                && !record.input_sequence.is_empty()
                && !record.expected_behavior_trace.is_empty()
                && record.expected_behavior_trace == record.actual_behavior_trace
                && record.divergence_point == "none"
        })
        .map(|record| record.incident_type.as_str())
        .collect();
    let missing_incident_types: Vec<String> = required
        .iter()
        .filter(|incident| !covered.contains(incident.as_str()))
        .cloned()
        .collect();
    let required_count = required.len();
    let covered_count = required_count.saturating_sub(missing_incident_types.len());

    GateVerdict {
        pass: required_count > 0 && missing_incident_types.is_empty(),
        required_count,
        covered_count,
        missing_incident_types,
    }
}

#[test]
fn replay_coverage_matrix_matches_spec_enumeration_and_summary() -> Result<(), Box<dyn Error>> {
    let spec = read_workspace_file(SPEC_PATH)?;
    for incident_type in SPEC_REQUIRED_INCIDENT_TYPES {
        assert!(
            spec.contains(incident_type),
            "{SPEC_PATH} must enumerate incident type {incident_type}"
        );
    }

    let matrix = load_matrix()?;
    assert_eq!(matrix.bead_id, "bd-2l1k");
    assert_eq!(matrix.trace_id, "trace-bd-2l1k-replay-coverage");
    assert!(
        (matrix.minimum_required_coverage_ratio - REQUIRED_COVERAGE_RATIO).abs() < f64::EPSILON
    );
    assert_eq!(matrix.new_incident_type_sla_days, NEW_INCIDENT_SLA_DAYS);
    assert_eq!(
        matrix.required_incident_types,
        SPEC_REQUIRED_INCIDENT_TYPES
            .iter()
            .map(|incident| (*incident).to_string())
            .collect::<Vec<_>>()
    );

    let verdict = evaluate_gate(&matrix.replay_artifacts, &matrix.required_incident_types);
    assert!(verdict.pass);
    assert_eq!(
        matrix.coverage_summary.required_count,
        verdict.required_count
    );
    assert_eq!(matrix.coverage_summary.covered_count, verdict.covered_count);
    assert!(
        (matrix.coverage_summary.coverage_ratio - REQUIRED_COVERAGE_RATIO).abs() < f64::EPSILON
    );
    Ok(())
}

#[test]
fn replay_coverage_records_match_checked_in_artifacts() -> Result<(), Box<dyn Error>> {
    let matrix = load_matrix()?;
    for record in &matrix.replay_artifacts {
        let artifact_path = repo_root()?.join(&record.artifact_path);
        assert!(
            artifact_path.is_file(),
            "{} must exist for {}",
            record.artifact_path,
            record.incident_type
        );
        let artifact = load_artifact(&record.artifact_path)?;

        assert_eq!(artifact.incident_type, record.incident_type);
        assert_eq!(
            artifact.initial_state_snapshot,
            record.initial_state_snapshot
        );
        assert_eq!(artifact.input_sequence, record.input_sequence);
        assert_eq!(
            artifact.expected_behavior_trace,
            record.expected_behavior_trace
        );
        assert_eq!(artifact.actual_behavior_trace, record.actual_behavior_trace);
        assert_eq!(artifact.divergence_point, record.divergence_point);
        assert_eq!(artifact.last_verified_utc, record.last_verified_utc);
        assert_eq!(artifact.deterministic_runs, record.deterministic_runs);
        assert_eq!(artifact.deterministic_match, record.deterministic_match);
        assert_eq!(artifact.reproduction_command, record.reproduction_command);
    }
    Ok(())
}

#[test]
fn replay_coverage_records_satisfy_determinism_content_and_sla() -> Result<(), Box<dyn Error>> {
    let matrix = load_matrix()?;
    for record in &matrix.replay_artifacts {
        assert!(
            record.deterministic_runs >= MIN_DETERMINISTIC_RUNS,
            "{} must have at least {MIN_DETERMINISTIC_RUNS} deterministic runs",
            record.incident_type
        );
        assert!(record.deterministic_match);
        assert!(!record.initial_state_snapshot.is_empty());
        assert!(!record.input_sequence.is_empty());
        assert!(!record.expected_behavior_trace.is_empty());
        assert_eq!(record.expected_behavior_trace, record.actual_behavior_trace);
        assert_eq!(record.divergence_point, "none");
        assert!(
            record
                .reproduction_command
                .starts_with("python3 scripts/check_replay_coverage_gate.py --replay-incident ")
        );

        let discovered_at = parse_utc(&record.discovered_at_utc, "discovered_at_utc")?;
        let last_verified_at = parse_utc(&record.last_verified_utc, "last_verified_utc")?;
        assert!(last_verified_at >= discovered_at);
        assert!(
            last_verified_at.signed_duration_since(discovered_at)
                <= chrono::Duration::days(matrix.new_incident_type_sla_days),
            "{} must be verified within the new-incident replay artifact SLA",
            record.incident_type
        );
    }
    Ok(())
}

#[test]
fn replay_coverage_verdict_is_order_independent_and_perturbation_sensitive()
-> Result<(), Box<dyn Error>> {
    let matrix = load_matrix()?;
    let baseline = evaluate_gate(&matrix.replay_artifacts, &matrix.required_incident_types);
    assert!(baseline.pass);

    let mut reordered = matrix.replay_artifacts.clone();
    reordered.reverse();
    assert_eq!(
        evaluate_gate(&reordered, &matrix.required_incident_types),
        baseline
    );

    let mut perturbed = matrix.replay_artifacts.clone();
    let removed = perturbed.pop().ok_or_else(|| {
        IoError::new(
            ErrorKind::InvalidData,
            "expected at least one replay artifact",
        )
    })?;
    let perturbed_verdict = evaluate_gate(&perturbed, &matrix.required_incident_types);
    assert!(!perturbed_verdict.pass);
    assert_eq!(
        perturbed_verdict.missing_incident_types,
        vec![removed.incident_type]
    );
    Ok(())
}
