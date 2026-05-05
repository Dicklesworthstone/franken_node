//! Deterministic product-level swarm scenario runner.
//!
//! The runner exercises the real file-backed fleet transport, incident evidence
//! package, replay bundle, and incident timeline contracts with fixed seeds and
//! timestamps. Reports are intended for integration tests and release evidence,
//! not as a simulation layer.

use std::{
    collections::BTreeSet,
    fs::{self, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
};

use chrono::{DateTime, SecondsFormat, TimeDelta, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use crate::control_plane::fleet_transport::{
    FLEET_ACTION_LOG_FILE, FileFleetTransport, FleetAction, FleetActionRecord, FleetSharedState,
    FleetTargetKind, FleetTransport, FleetTransportError, NodeHealth, NodeStatus,
};

use super::{
    incident_timeline::{
        IncidentEvidenceSource, IncidentTimelineInput, IncidentTimelineVerdict, ReplayBundleSource,
        build_incident_timeline_report,
    },
    replay_bundle::{
        EventType, INCIDENT_EVIDENCE_SCHEMA, IncidentEvidenceEvent, IncidentEvidenceMetadata,
        IncidentEvidencePackage, IncidentSeverity, ReplayBundleError,
        generate_replay_bundle_from_evidence,
    },
};

pub const SWARM_SCENARIO_SCHEMA_VERSION: &str = "franken-node/deterministic-swarm-scenario/v1";
pub const EVENT_SETUP: &str = "SWARM_SCENARIO_SETUP";
pub const EVENT_FLEET_STATE_SEEDED: &str = "SWARM_SCENARIO_FLEET_STATE_SEEDED";
pub const EVENT_FLEET_ACTION_PUBLISHED: &str = "SWARM_SCENARIO_FLEET_ACTION_PUBLISHED";
pub const EVENT_REPLAY_BUILT: &str = "SWARM_SCENARIO_REPLAY_BUILT";
pub const EVENT_TIMELINE_BUILT: &str = "SWARM_SCENARIO_TIMELINE_BUILT";
pub const EVENT_FAIL_CLOSED_CONFIRMED: &str = "SWARM_SCENARIO_FAIL_CLOSED_CONFIRMED";
pub const EVENT_EVIDENCE_COLLECTED: &str = "SWARM_SCENARIO_EVIDENCE_COLLECTED";
pub const EVENT_EXPECTED_EVENTS_CONFIRMED: &str = "SWARM_SCENARIO_EXPECTED_EVENTS_CONFIRMED";
pub const EVENT_COMPLETED: &str = "SWARM_SCENARIO_COMPLETED";
pub const EVENT_ASSERTION_FAILED: &str = "SWARM_SCENARIO_ASSERTION_FAILED";

const DEFAULT_BASE_TIMESTAMP: &str = "2026-05-05T10:00:00.000000Z";
const DEFAULT_DEADLINE_MILLIS: u64 = 5_000;
const ALL_GREEN_ID: &str = "all-green-fleet-replay";
const RECOVERY_ID: &str = "negative-recovery-fail-closed";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SwarmScenarioSpec {
    pub scenario_id: String,
    pub seed: u64,
    pub base_timestamp: String,
    pub deadline_millis: u64,
    pub nodes: Vec<SwarmScenarioNode>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fault: Option<SwarmScenarioFault>,
    pub expected_event_codes: Vec<String>,
    pub expected_artifact_paths: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SwarmScenarioNode {
    pub node_id: String,
    pub zone_id: String,
    pub health: NodeHealth,
    pub quarantine_version: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SwarmScenarioFault {
    TamperReplayIntegrity,
    OmitReplayBundle,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SwarmScenarioVerdict {
    Pass,
    FailClosed,
    Fail,
}

impl SwarmScenarioVerdict {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pass => "pass",
            Self::FailClosed => "fail_closed",
            Self::Fail => "fail",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SwarmScenarioReport {
    pub schema_version: String,
    pub scenario_id: String,
    pub seed: u64,
    pub verdict: SwarmScenarioVerdict,
    pub operator_output: Vec<String>,
    pub logs: Vec<SwarmScenarioLog>,
    pub artifacts: Vec<SwarmScenarioArtifact>,
    pub assertions: Vec<SwarmScenarioAssertion>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SwarmScenarioLog {
    pub timestamp: String,
    pub phase: String,
    pub event_code: String,
    pub success: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub artifact_path: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub assertion_summary: Option<SwarmScenarioAssertionSummary>,
    pub detail: Value,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SwarmScenarioAssertionSummary {
    pub name: String,
    pub success: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SwarmScenarioArtifact {
    pub artifact_path: String,
    pub artifact_kind: String,
    pub digest: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SwarmScenarioAssertion {
    pub name: String,
    pub phase: String,
    pub event_code: String,
    pub expected: String,
    pub actual: String,
    pub artifact_path: String,
    pub success: bool,
}

#[derive(Debug, thiserror::Error)]
pub enum SwarmScenarioError {
    #[error("scenario id cannot be empty")]
    EmptyScenarioId,
    #[error("invalid scenario id `{scenario_id}`: use only letters, numbers, '.', '_', and '-'")]
    InvalidScenarioId { scenario_id: String },
    #[error("scenario `{scenario_id}` must declare at least one node")]
    EmptyNodeSet { scenario_id: String },
    #[error("invalid rfc3339 timestamp `{timestamp}`: {source}")]
    TimestampParse {
        timestamp: String,
        source: chrono::ParseError,
    },
    #[error("timestamp offset overflow for `{timestamp}` by {offset_seconds} seconds")]
    TimestampOverflow {
        timestamp: String,
        offset_seconds: i64,
    },
    #[error("scenario log count exceeded signed timestamp offset range")]
    LogCountOverflow,
    #[error("scenario artifact already exists: {path}")]
    ArtifactAlreadyExists { path: PathBuf },
    #[error("scenario artifact path is not relative and safe: {path}")]
    UnsafeArtifactPath { path: String },
    #[error("fleet transport error: {0}")]
    FleetTransport(#[from] FleetTransportError),
    #[error("replay bundle error: {0}")]
    ReplayBundle(#[from] ReplayBundleError),
    #[error("json error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
}

#[must_use]
pub fn all_green_fleet_replay_scenario_spec() -> SwarmScenarioSpec {
    SwarmScenarioSpec {
        scenario_id: ALL_GREEN_ID.to_string(),
        seed: 0x5eed_0001,
        base_timestamp: DEFAULT_BASE_TIMESTAMP.to_string(),
        deadline_millis: DEFAULT_DEADLINE_MILLIS,
        nodes: vec![
            SwarmScenarioNode {
                node_id: "node-a".to_string(),
                zone_id: "zone-a".to_string(),
                health: NodeHealth::Healthy,
                quarantine_version: 0,
            },
            SwarmScenarioNode {
                node_id: "node-b".to_string(),
                zone_id: "zone-a".to_string(),
                health: NodeHealth::Healthy,
                quarantine_version: 0,
            },
        ],
        fault: None,
        expected_event_codes: vec![
            EVENT_SETUP.to_string(),
            EVENT_FLEET_STATE_SEEDED.to_string(),
            EVENT_FLEET_ACTION_PUBLISHED.to_string(),
            EVENT_REPLAY_BUILT.to_string(),
            EVENT_TIMELINE_BUILT.to_string(),
            EVENT_EVIDENCE_COLLECTED.to_string(),
            EVENT_COMPLETED.to_string(),
        ],
        expected_artifact_paths: vec![
            "fleet/actions.jsonl".to_string(),
            "scenario_artifacts/all-green-fleet-replay/incident_evidence.json".to_string(),
            "scenario_artifacts/all-green-fleet-replay/replay_bundle.json".to_string(),
            "scenario_artifacts/all-green-fleet-replay/incident_timeline.json".to_string(),
        ],
    }
}

#[must_use]
pub fn recovery_fail_closed_scenario_spec() -> SwarmScenarioSpec {
    SwarmScenarioSpec {
        scenario_id: RECOVERY_ID.to_string(),
        seed: 0x5eed_0002,
        base_timestamp: DEFAULT_BASE_TIMESTAMP.to_string(),
        deadline_millis: DEFAULT_DEADLINE_MILLIS,
        nodes: vec![
            SwarmScenarioNode {
                node_id: "node-a".to_string(),
                zone_id: "zone-a".to_string(),
                health: NodeHealth::Healthy,
                quarantine_version: 0,
            },
            SwarmScenarioNode {
                node_id: "node-b".to_string(),
                zone_id: "zone-a".to_string(),
                health: NodeHealth::Degraded,
                quarantine_version: 1,
            },
        ],
        fault: Some(SwarmScenarioFault::TamperReplayIntegrity),
        expected_event_codes: vec![
            EVENT_SETUP.to_string(),
            EVENT_FLEET_STATE_SEEDED.to_string(),
            EVENT_FLEET_ACTION_PUBLISHED.to_string(),
            EVENT_REPLAY_BUILT.to_string(),
            EVENT_TIMELINE_BUILT.to_string(),
            EVENT_FAIL_CLOSED_CONFIRMED.to_string(),
            EVENT_EVIDENCE_COLLECTED.to_string(),
            EVENT_COMPLETED.to_string(),
        ],
        expected_artifact_paths: vec![
            "fleet/actions.jsonl".to_string(),
            "scenario_artifacts/negative-recovery-fail-closed/incident_evidence.json".to_string(),
            "scenario_artifacts/negative-recovery-fail-closed/replay_bundle.json".to_string(),
            "scenario_artifacts/negative-recovery-fail-closed/incident_timeline.json".to_string(),
        ],
    }
}

#[must_use]
pub fn registered_swarm_scenarios() -> Vec<SwarmScenarioSpec> {
    vec![
        all_green_fleet_replay_scenario_spec(),
        recovery_fail_closed_scenario_spec(),
    ]
}

pub fn run_deterministic_swarm_scenario(
    spec: &SwarmScenarioSpec,
    workspace_root: &Path,
) -> Result<SwarmScenarioReport, SwarmScenarioError> {
    validate_spec(spec)?;

    let base_timestamp = parse_base_timestamp(&spec.base_timestamp)?;
    let artifact_root = Path::new("scenario_artifacts").join(&spec.scenario_id);
    let mut logs = Vec::new();
    let mut assertions = Vec::new();
    let mut artifacts = Vec::new();

    push_log(
        &mut logs,
        base_timestamp,
        "setup",
        EVENT_SETUP,
        true,
        None,
        None,
        json!({
            "scenario_id": &spec.scenario_id,
            "seed": spec.seed,
            "deadline_millis": spec.deadline_millis,
            "node_count": spec.nodes.len(),
            "fault": spec.fault,
        }),
    )?;

    let mut transport = FileFleetTransport::new(workspace_root.join("fleet"));
    transport.initialize()?;
    seed_fleet_nodes(spec, base_timestamp, &mut transport)?;
    let fleet_state = transport.read_shared_state()?;
    push_log(
        &mut logs,
        base_timestamp,
        "fleet",
        EVENT_FLEET_STATE_SEEDED,
        true,
        Some("fleet/nodes".to_string()),
        None,
        json!({
            "nodes": &fleet_state.nodes,
            "schema_version": &fleet_state.schema_version,
        }),
    )?;

    assert_and_log(
        &mut logs,
        &mut assertions,
        base_timestamp,
        SwarmScenarioAssertion {
            name: "fleet node count".to_string(),
            phase: "fleet".to_string(),
            event_code: EVENT_FLEET_STATE_SEEDED.to_string(),
            expected: spec.nodes.len().to_string(),
            actual: fleet_state.nodes.len().to_string(),
            artifact_path: "fleet/nodes".to_string(),
            success: fleet_state.nodes.len() == spec.nodes.len(),
        },
    )?;

    let action = fleet_action_for_spec(spec, base_timestamp)?;
    transport.publish_action(&action)?;
    let fleet_state = transport.read_shared_state()?;
    push_log(
        &mut logs,
        base_timestamp,
        "fleet",
        EVENT_FLEET_ACTION_PUBLISHED,
        true,
        Some("fleet/actions.jsonl".to_string()),
        None,
        json!({
            "action_id": &action.action_id,
            "action": &action.action,
            "action_count": fleet_state.actions.len(),
        }),
    )?;
    assert_and_log(
        &mut logs,
        &mut assertions,
        base_timestamp,
        SwarmScenarioAssertion {
            name: "fleet action persisted".to_string(),
            phase: "fleet".to_string(),
            event_code: EVENT_FLEET_ACTION_PUBLISHED.to_string(),
            expected: "1 quarantine action".to_string(),
            actual: format!("{} actions", fleet_state.actions.len()),
            artifact_path: "fleet/actions.jsonl".to_string(),
            success: fleet_state.actions.iter().any(|candidate| {
                candidate.action_id == action.action_id
                    && matches!(candidate.action, FleetAction::Quarantine { .. })
            }),
        },
    )?;

    artifacts.push(record_existing_artifact(
        workspace_root,
        Path::new("fleet").join(FLEET_ACTION_LOG_FILE),
        "fleet_action_log",
    )?);

    let package = incident_evidence_for_spec(spec, &fleet_state, base_timestamp)?;
    let evidence_path = artifact_root.join("incident_evidence.json");
    artifacts.push(write_json_artifact(
        workspace_root,
        &evidence_path,
        "incident_evidence",
        &package,
    )?);

    let mut replay_bundle = generate_replay_bundle_from_evidence(&package)?;
    if spec.fault == Some(SwarmScenarioFault::TamperReplayIntegrity) {
        replay_bundle.integrity_hash = "sha256:tampered-by-deterministic-scenario".to_string();
    }
    let replay_path = artifact_root.join("replay_bundle.json");
    artifacts.push(write_json_artifact(
        workspace_root,
        &replay_path,
        "replay_bundle",
        &replay_bundle,
    )?);

    push_log(
        &mut logs,
        base_timestamp,
        "replay",
        EVENT_REPLAY_BUILT,
        true,
        Some(relative_path_string(&replay_path)?),
        None,
        json!({
            "bundle_id": &replay_bundle.bundle_id,
            "incident_id": &replay_bundle.incident_id,
            "event_count": replay_bundle.timeline.len(),
            "integrity_hash": &replay_bundle.integrity_hash,
            "fault": spec.fault,
        }),
    )?;

    let replay_source = match spec.fault {
        Some(SwarmScenarioFault::OmitReplayBundle) => None,
        Some(SwarmScenarioFault::TamperReplayIntegrity) | None => Some(ReplayBundleSource {
            label: path_string(&replay_path)?,
            bundle: &replay_bundle,
            trusted_signature_key_id: None,
        }),
    };
    let timeline_report = build_incident_timeline_report(IncidentTimelineInput {
        incident_id: &package.incident_id,
        evidence_package: Some(IncidentEvidenceSource {
            label: path_string(&evidence_path)?,
            package: &package,
        }),
        replay_bundle: replay_source,
    });
    let timeline_path = artifact_root.join("incident_timeline.json");
    artifacts.push(write_json_artifact(
        workspace_root,
        &timeline_path,
        "incident_timeline",
        &timeline_report,
    )?);

    let expected_timeline_verdict = match spec.fault {
        None => IncidentTimelineVerdict::Pass,
        Some(SwarmScenarioFault::TamperReplayIntegrity | SwarmScenarioFault::OmitReplayBundle) => {
            IncidentTimelineVerdict::Fail
        }
    };
    let timeline_success = timeline_report.overall_verdict == expected_timeline_verdict;
    push_log(
        &mut logs,
        base_timestamp,
        "timeline",
        EVENT_TIMELINE_BUILT,
        timeline_success,
        Some(relative_path_string(&timeline_path)?),
        Some(SwarmScenarioAssertionSummary {
            name: "incident timeline verdict".to_string(),
            success: timeline_success,
        }),
        json!({
            "expected_verdict": expected_timeline_verdict,
            "actual_verdict": &timeline_report.overall_verdict,
            "gap_codes": gap_codes(&timeline_report.gaps),
        }),
    )?;
    assertions.push(SwarmScenarioAssertion {
        name: "incident timeline verdict".to_string(),
        phase: "timeline".to_string(),
        event_code: EVENT_TIMELINE_BUILT.to_string(),
        expected: format!("{expected_timeline_verdict:?}"),
        actual: format!("{:?}", timeline_report.overall_verdict),
        artifact_path: relative_path_string(&timeline_path)?,
        success: timeline_success,
    });

    if let Some(fault) = spec.fault {
        let expected_gap = expected_gap_for_fault(fault);
        let actual_gap_codes = gap_codes(&timeline_report.gaps);
        let success = actual_gap_codes.iter().any(|gap| gap == expected_gap);
        push_log(
            &mut logs,
            base_timestamp,
            "recovery",
            EVENT_FAIL_CLOSED_CONFIRMED,
            success,
            Some(relative_path_string(&timeline_path)?),
            Some(SwarmScenarioAssertionSummary {
                name: "fail closed gap surfaced".to_string(),
                success,
            }),
            json!({
                "fault": fault,
                "expected_gap": expected_gap,
                "actual_gaps": actual_gap_codes,
            }),
        )?;
        assertions.push(SwarmScenarioAssertion {
            name: "fail closed gap surfaced".to_string(),
            phase: "recovery".to_string(),
            event_code: EVENT_FAIL_CLOSED_CONFIRMED.to_string(),
            expected: expected_gap.to_string(),
            actual: gap_codes(&timeline_report.gaps).join(","),
            artifact_path: relative_path_string(&timeline_path)?,
            success,
        });
    }

    let artifact_paths = artifacts
        .iter()
        .map(|artifact| artifact.artifact_path.clone())
        .collect::<Vec<_>>();
    push_log(
        &mut logs,
        base_timestamp,
        "evidence",
        EVENT_EVIDENCE_COLLECTED,
        true,
        None,
        None,
        json!({
            "artifact_paths": artifact_paths,
        }),
    )?;
    assert_expected_artifacts(spec, &artifacts, &mut logs, &mut assertions, base_timestamp)?;

    let preliminary_verdict = scenario_verdict(spec, &assertions);
    push_log(
        &mut logs,
        base_timestamp,
        "complete",
        EVENT_COMPLETED,
        preliminary_verdict != SwarmScenarioVerdict::Fail,
        None,
        None,
        json!({
            "verdict": preliminary_verdict.as_str(),
            "assertions": assertions.len(),
            "failed_assertions": assertions.iter().filter(|assertion| !assertion.success).count(),
        }),
    )?;

    assert_expected_event_codes(spec, &mut logs, &mut assertions, base_timestamp)?;

    let verdict = scenario_verdict(spec, &assertions);
    let log_path = artifact_root.join("scenario_logs.jsonl");
    let log_bytes = render_swarm_scenario_jsonl_from_logs(&logs)?.into_bytes();
    artifacts.push(write_bytes_artifact(
        workspace_root,
        &log_path,
        "scenario_jsonl_log",
        &log_bytes,
    )?);

    Ok(SwarmScenarioReport {
        schema_version: SWARM_SCENARIO_SCHEMA_VERSION.to_string(),
        scenario_id: spec.scenario_id.clone(),
        seed: spec.seed,
        verdict,
        operator_output: operator_output_for_verdict(verdict),
        logs,
        artifacts,
        assertions,
    })
}

pub fn render_swarm_scenario_jsonl(
    report: &SwarmScenarioReport,
) -> Result<String, serde_json::Error> {
    render_swarm_scenario_jsonl_from_logs(&report.logs)
}

fn render_swarm_scenario_jsonl_from_logs(
    logs: &[SwarmScenarioLog],
) -> Result<String, serde_json::Error> {
    let mut output = String::new();
    for log in logs {
        output.push_str(&serde_json::to_string(log)?);
        output.push('\n');
    }
    Ok(output)
}

fn validate_spec(spec: &SwarmScenarioSpec) -> Result<(), SwarmScenarioError> {
    if spec.scenario_id.trim().is_empty() {
        return Err(SwarmScenarioError::EmptyScenarioId);
    }
    if !is_safe_component(&spec.scenario_id) {
        return Err(SwarmScenarioError::InvalidScenarioId {
            scenario_id: spec.scenario_id.clone(),
        });
    }
    if spec.nodes.is_empty() {
        return Err(SwarmScenarioError::EmptyNodeSet {
            scenario_id: spec.scenario_id.clone(),
        });
    }
    Ok(())
}

fn is_safe_component(value: &str) -> bool {
    value
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
}

fn parse_base_timestamp(timestamp: &str) -> Result<DateTime<Utc>, SwarmScenarioError> {
    DateTime::parse_from_rfc3339(timestamp)
        .map(|parsed| parsed.with_timezone(&Utc))
        .map_err(|source| SwarmScenarioError::TimestampParse {
            timestamp: timestamp.to_string(),
            source,
        })
}

fn timestamp_at(
    base_timestamp: DateTime<Utc>,
    offset_seconds: i64,
) -> Result<String, SwarmScenarioError> {
    let shifted = base_timestamp
        .checked_add_signed(TimeDelta::seconds(offset_seconds))
        .ok_or(SwarmScenarioError::TimestampOverflow {
            timestamp: base_timestamp.to_rfc3339_opts(SecondsFormat::Micros, true),
            offset_seconds,
        })?;
    Ok(shifted.to_rfc3339_opts(SecondsFormat::Micros, true))
}

fn seed_fleet_nodes(
    spec: &SwarmScenarioSpec,
    base_timestamp: DateTime<Utc>,
    transport: &mut impl FleetTransport,
) -> Result<(), SwarmScenarioError> {
    for (index, node) in spec.nodes.iter().enumerate() {
        let offset_seconds =
            i64::try_from(index).map_err(|_| SwarmScenarioError::LogCountOverflow)?;
        transport.upsert_node_status(&NodeStatus {
            zone_id: node.zone_id.clone(),
            node_id: node.node_id.clone(),
            last_seen: base_timestamp
                .checked_add_signed(TimeDelta::seconds(offset_seconds))
                .ok_or(SwarmScenarioError::TimestampOverflow {
                    timestamp: spec.base_timestamp.clone(),
                    offset_seconds,
                })?,
            quarantine_version: node.quarantine_version,
            health: node.health,
        })?;
    }
    Ok(())
}

fn fleet_action_for_spec(
    spec: &SwarmScenarioSpec,
    base_timestamp: DateTime<Utc>,
) -> Result<FleetActionRecord, SwarmScenarioError> {
    let first_node = spec
        .nodes
        .first()
        .ok_or_else(|| SwarmScenarioError::EmptyNodeSet {
            scenario_id: spec.scenario_id.clone(),
        })?;
    Ok(FleetActionRecord {
        action_id: stable_id("action", &spec.scenario_id, spec.seed),
        emitted_at: base_timestamp
            .checked_add_signed(TimeDelta::seconds(2))
            .ok_or(SwarmScenarioError::TimestampOverflow {
                timestamp: spec.base_timestamp.clone(),
                offset_seconds: 2,
            })?,
        action: FleetAction::Quarantine {
            zone_id: first_node.zone_id.clone(),
            incident_id: incident_id(spec),
            target_id: first_node.node_id.clone(),
            target_kind: FleetTargetKind::Artifact,
            reason: format!("deterministic scenario {}", spec.scenario_id),
            quarantine_version: first_node.quarantine_version.saturating_add(1),
        },
    })
}

fn incident_evidence_for_spec(
    spec: &SwarmScenarioSpec,
    fleet_state: &FleetSharedState,
    base_timestamp: DateTime<Utc>,
) -> Result<IncidentEvidencePackage, SwarmScenarioError> {
    let incident_id = incident_id(spec);
    let first_node = spec
        .nodes
        .first()
        .ok_or_else(|| SwarmScenarioError::EmptyNodeSet {
            scenario_id: spec.scenario_id.clone(),
        })?;
    let action = fleet_state.actions.first();
    let action_id = action
        .map(|record| record.action_id.as_str())
        .unwrap_or("missing-action");
    let action_event_timestamp = timestamp_at(base_timestamp, 3)?;

    Ok(IncidentEvidencePackage {
        schema_version: INCIDENT_EVIDENCE_SCHEMA.to_string(),
        incident_id: incident_id.clone(),
        collected_at: timestamp_at(base_timestamp, 4)?,
        trace_id: stable_id("trace", &spec.scenario_id, spec.seed),
        severity: if spec.fault.is_some() {
            IncidentSeverity::Critical
        } else {
            IncidentSeverity::High
        },
        incident_type: "deterministic_swarm_scenario".to_string(),
        detector: "swarm-scenario-runner".to_string(),
        policy_version: "swarm-policy-2026.05".to_string(),
        initial_state_snapshot: json!({
            "scenario_id": &spec.scenario_id,
            "seed": spec.seed,
            "fleet_state": fleet_state,
        }),
        events: vec![
            IncidentEvidenceEvent {
                event_id: stable_id("event-signal", &spec.scenario_id, spec.seed),
                timestamp: timestamp_at(base_timestamp, 1)?,
                event_type: EventType::ExternalSignal,
                payload: json!({
                    "event_code": "swarm_signal_detected",
                    "actor_node": &first_node.node_id,
                    "severity": if spec.fault.is_some() { "critical" } else { "high" },
                    "summary": format!("scenario {} entered deterministic fleet workflow", spec.scenario_id),
                    "seed": spec.seed,
                }),
                provenance_ref: "fleet/actions.jsonl".to_string(),
                parent_event_id: None,
                state_snapshot: None,
                policy_version: None,
            },
            IncidentEvidenceEvent {
                event_id: stable_id("event-action", &spec.scenario_id, spec.seed),
                timestamp: action_event_timestamp,
                event_type: EventType::OperatorAction,
                payload: json!({
                    "event_code": "swarm_quarantine_action_recorded",
                    "actor_node": "operator-control-plane",
                    "severity": "medium",
                    "summary": format!("fleet action {action_id} persisted for scenario {}", spec.scenario_id),
                    "action_id": action_id,
                }),
                provenance_ref: "fleet/actions.jsonl".to_string(),
                parent_event_id: Some(stable_id("event-signal", &spec.scenario_id, spec.seed)),
                state_snapshot: None,
                policy_version: Some("swarm-policy-2026.05".to_string()),
            },
        ],
        evidence_refs: vec!["fleet/actions.jsonl".to_string()],
        metadata: IncidentEvidenceMetadata {
            title: format!("deterministic swarm scenario {}", spec.scenario_id),
            affected_components: spec.nodes.iter().map(|node| node.node_id.clone()).collect(),
            tags: vec![
                "deterministic-swarm".to_string(),
                "bd-bm5g3".to_string(),
                spec.scenario_id.clone(),
            ],
        },
    })
}

fn incident_id(spec: &SwarmScenarioSpec) -> String {
    stable_id("incident", &spec.scenario_id, spec.seed)
}

fn stable_id(prefix: &str, scenario_id: &str, seed: u64) -> String {
    let mut hasher = Sha256::new();
    hasher.update(prefix.as_bytes());
    hasher.update(b":");
    hasher.update(scenario_id.as_bytes());
    hasher.update(b":");
    hasher.update(seed.to_le_bytes());
    let digest = hex::encode(hasher.finalize());
    let suffix = digest.chars().take(16).collect::<String>();
    format!("{prefix}-{suffix}")
}

fn gap_codes(gaps: &[super::incident_timeline::IncidentTimelineGap]) -> Vec<String> {
    gaps.iter().map(|gap| gap.gap_code.clone()).collect()
}

fn expected_gap_for_fault(fault: SwarmScenarioFault) -> &'static str {
    match fault {
        SwarmScenarioFault::TamperReplayIntegrity => "ITR-REPLAY-INTEGRITY",
        SwarmScenarioFault::OmitReplayBundle => "ITR-REPLAY-MISSING",
    }
}

#[allow(clippy::too_many_arguments)]
fn push_log(
    logs: &mut Vec<SwarmScenarioLog>,
    base_timestamp: DateTime<Utc>,
    phase: &str,
    event_code: &str,
    success: bool,
    artifact_path: Option<String>,
    assertion_summary: Option<SwarmScenarioAssertionSummary>,
    detail: Value,
) -> Result<(), SwarmScenarioError> {
    let offset_seconds =
        i64::try_from(logs.len()).map_err(|_| SwarmScenarioError::LogCountOverflow)?;
    logs.push(SwarmScenarioLog {
        timestamp: timestamp_at(base_timestamp, offset_seconds)?,
        phase: phase.to_string(),
        event_code: event_code.to_string(),
        success,
        artifact_path,
        assertion_summary,
        detail,
    });
    Ok(())
}

fn assert_and_log(
    logs: &mut Vec<SwarmScenarioLog>,
    assertions: &mut Vec<SwarmScenarioAssertion>,
    base_timestamp: DateTime<Utc>,
    assertion: SwarmScenarioAssertion,
) -> Result<(), SwarmScenarioError> {
    push_log(
        logs,
        base_timestamp,
        &assertion.phase,
        &assertion.event_code,
        assertion.success,
        Some(assertion.artifact_path.clone()),
        Some(SwarmScenarioAssertionSummary {
            name: assertion.name.clone(),
            success: assertion.success,
        }),
        json!({
            "expected": &assertion.expected,
            "actual": &assertion.actual,
        }),
    )?;
    if !assertion.success {
        push_assertion_failure_log(logs, base_timestamp, &assertion)?;
    }
    assertions.push(assertion);
    Ok(())
}

fn push_assertion_failure_log(
    logs: &mut Vec<SwarmScenarioLog>,
    base_timestamp: DateTime<Utc>,
    assertion: &SwarmScenarioAssertion,
) -> Result<(), SwarmScenarioError> {
    push_log(
        logs,
        base_timestamp,
        &assertion.phase,
        EVENT_ASSERTION_FAILED,
        false,
        Some(assertion.artifact_path.clone()),
        Some(SwarmScenarioAssertionSummary {
            name: assertion.name.clone(),
            success: false,
        }),
        json!({
            "phase": &assertion.phase,
            "event_code": &assertion.event_code,
            "expected": &assertion.expected,
            "actual": &assertion.actual,
            "artifact_path": &assertion.artifact_path,
        }),
    )
}

fn assert_expected_artifacts(
    spec: &SwarmScenarioSpec,
    artifacts: &[SwarmScenarioArtifact],
    logs: &mut Vec<SwarmScenarioLog>,
    assertions: &mut Vec<SwarmScenarioAssertion>,
    base_timestamp: DateTime<Utc>,
) -> Result<(), SwarmScenarioError> {
    let actual = artifacts
        .iter()
        .map(|artifact| artifact.artifact_path.as_str())
        .collect::<BTreeSet<_>>();
    let missing = spec
        .expected_artifact_paths
        .iter()
        .filter(|path| !actual.contains(path.as_str()))
        .cloned()
        .collect::<Vec<_>>();
    assert_and_log(
        logs,
        assertions,
        base_timestamp,
        SwarmScenarioAssertion {
            name: "expected artifacts present".to_string(),
            phase: "evidence".to_string(),
            event_code: EVENT_EVIDENCE_COLLECTED.to_string(),
            expected: spec.expected_artifact_paths.join(","),
            actual: artifacts
                .iter()
                .map(|artifact| artifact.artifact_path.clone())
                .collect::<Vec<_>>()
                .join(","),
            artifact_path: "scenario_artifacts".to_string(),
            success: missing.is_empty(),
        },
    )
}

fn assert_expected_event_codes(
    spec: &SwarmScenarioSpec,
    logs: &mut Vec<SwarmScenarioLog>,
    assertions: &mut Vec<SwarmScenarioAssertion>,
    base_timestamp: DateTime<Utc>,
) -> Result<(), SwarmScenarioError> {
    let actual = logs
        .iter()
        .map(|log| log.event_code.as_str())
        .collect::<BTreeSet<_>>();
    let missing = spec
        .expected_event_codes
        .iter()
        .filter(|event_code| !actual.contains(event_code.as_str()))
        .cloned()
        .collect::<Vec<_>>();
    assert_and_log(
        logs,
        assertions,
        base_timestamp,
        SwarmScenarioAssertion {
            name: "expected event codes present".to_string(),
            phase: "complete".to_string(),
            event_code: EVENT_EXPECTED_EVENTS_CONFIRMED.to_string(),
            expected: spec.expected_event_codes.join(","),
            actual: logs
                .iter()
                .map(|log| log.event_code.clone())
                .collect::<Vec<_>>()
                .join(","),
            artifact_path: "scenario_logs.jsonl".to_string(),
            success: missing.is_empty(),
        },
    )
}

fn scenario_verdict(
    spec: &SwarmScenarioSpec,
    assertions: &[SwarmScenarioAssertion],
) -> SwarmScenarioVerdict {
    if assertions.iter().any(|assertion| !assertion.success) {
        SwarmScenarioVerdict::Fail
    } else if spec.fault.is_some() {
        SwarmScenarioVerdict::FailClosed
    } else {
        SwarmScenarioVerdict::Pass
    }
}

fn operator_output_for_verdict(verdict: SwarmScenarioVerdict) -> Vec<String> {
    match verdict {
        SwarmScenarioVerdict::Pass => vec![
            "scenario completed with deterministic fleet and replay evidence".to_string(),
            "attach scenario logs and artifacts to release evidence".to_string(),
        ],
        SwarmScenarioVerdict::FailClosed => vec![
            "scenario halted recovery on verified fail-closed evidence gap".to_string(),
            "regenerate or inspect the flagged replay artifact before proceeding".to_string(),
        ],
        SwarmScenarioVerdict::Fail => vec![
            "scenario assertions failed".to_string(),
            "inspect assertion event_code, expected, actual, and artifact_path fields".to_string(),
        ],
    }
}

fn write_json_artifact<T: Serialize>(
    workspace_root: &Path,
    relative_path: &Path,
    artifact_kind: &str,
    value: &T,
) -> Result<SwarmScenarioArtifact, SwarmScenarioError> {
    let bytes = serde_json::to_vec_pretty(value)?;
    write_bytes_artifact(workspace_root, relative_path, artifact_kind, &bytes)
}

fn write_bytes_artifact(
    workspace_root: &Path,
    relative_path: &Path,
    artifact_kind: &str,
    bytes: &[u8],
) -> Result<SwarmScenarioArtifact, SwarmScenarioError> {
    validate_relative_path(relative_path)?;
    let path = workspace_root.join(relative_path);
    if path.exists() {
        return Err(SwarmScenarioError::ArtifactAlreadyExists { path });
    }
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(SwarmScenarioArtifact {
        artifact_path: relative_path_string(relative_path)?,
        artifact_kind: artifact_kind.to_string(),
        digest: sha256_digest(bytes),
    })
}

fn record_existing_artifact(
    workspace_root: &Path,
    relative_path: impl AsRef<Path>,
    artifact_kind: &str,
) -> Result<SwarmScenarioArtifact, SwarmScenarioError> {
    let relative_path = relative_path.as_ref();
    validate_relative_path(relative_path)?;
    let bytes = fs::read(workspace_root.join(relative_path))?;
    Ok(SwarmScenarioArtifact {
        artifact_path: relative_path_string(relative_path)?,
        artifact_kind: artifact_kind.to_string(),
        digest: sha256_digest(&bytes),
    })
}

fn validate_relative_path(path: &Path) -> Result<(), SwarmScenarioError> {
    if path.as_os_str().is_empty()
        || path.is_absolute()
        || path
            .components()
            .any(|component| matches!(component, std::path::Component::ParentDir))
    {
        return Err(SwarmScenarioError::UnsafeArtifactPath {
            path: path.display().to_string(),
        });
    }
    Ok(())
}

fn relative_path_string(path: &Path) -> Result<String, SwarmScenarioError> {
    validate_relative_path(path)?;
    path.to_str()
        .map(str::to_string)
        .ok_or_else(|| SwarmScenarioError::UnsafeArtifactPath {
            path: path.display().to_string(),
        })
}

fn path_string(path: &Path) -> Result<&str, SwarmScenarioError> {
    validate_relative_path(path)?;
    path.to_str()
        .ok_or_else(|| SwarmScenarioError::UnsafeArtifactPath {
            path: path.display().to_string(),
        })
}

fn sha256_digest(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    format!("sha256:{}", hex::encode(hasher.finalize()))
}
