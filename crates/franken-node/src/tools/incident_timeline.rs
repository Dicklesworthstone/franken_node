//! Incident timeline and recovery report generation.
//!
//! This module normalizes incident evidence packages and replay bundles into
//! one chronological report. The JSON report is the machine contract; the
//! Markdown renderer is a compact operator view of the same evidence.

use std::collections::{BTreeMap, BTreeSet};

use chrono::{DateTime, SecondsFormat, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};

use super::replay_bundle::{
    EventType, IncidentEvidenceEvent, IncidentEvidencePackage, IncidentSeverity, ReplayBundle,
    ReplayBundleError, TimelineEvent, canonicalize_value, to_canonical_json,
    validate_bundle_integrity, validate_incident_evidence_package, verify_replay_bundle_signature,
};

pub const INCIDENT_TIMELINE_SCHEMA_VERSION: &str = "franken-node/incident-timeline-report/v1";
const CLOCK_SKEW_THRESHOLD_MICROS: u64 = 5 * 60 * 1_000_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IncidentTimelineVerdict {
    Pass,
    Fail,
}

impl IncidentTimelineVerdict {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pass => "pass",
            Self::Fail => "fail",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IncidentTimelineVerificationStatus {
    Verified,
    Failed,
}

impl IncidentTimelineVerificationStatus {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Verified => "verified",
            Self::Failed => "failed",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IncidentTimelineReport {
    pub schema_version: String,
    pub incident_id: String,
    pub overall_verdict: IncidentTimelineVerdict,
    pub events: Vec<IncidentTimelineEvent>,
    pub gaps: Vec<IncidentTimelineGap>,
    pub recovery_actions: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IncidentTimelineEvent {
    pub timestamp: String,
    pub monotonic_order: u64,
    pub source_artifact: String,
    pub source_digest: String,
    pub actor_node: String,
    pub event_code: String,
    pub severity: String,
    pub verification_status: IncidentTimelineVerificationStatus,
    pub summary: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IncidentTimelineGap {
    pub gap_code: String,
    pub source_artifact: String,
    pub expected: String,
    pub observed: String,
    pub severity: String,
    pub recovery_hint: String,
}

pub struct IncidentTimelineInput<'a> {
    pub incident_id: &'a str,
    pub evidence_package: Option<IncidentEvidenceSource<'a>>,
    pub replay_bundle: Option<ReplayBundleSource<'a>>,
}

pub struct IncidentEvidenceSource<'a> {
    pub label: &'a str,
    pub package: &'a IncidentEvidencePackage,
}

pub struct ReplayBundleSource<'a> {
    pub label: &'a str,
    pub bundle: &'a ReplayBundle,
    pub trusted_signature_key_id: Option<&'a str>,
}

#[derive(Debug, Clone)]
struct StagedTimelineEvent {
    event: IncidentTimelineEvent,
    sort_micros: i64,
    source_rank: u8,
}

#[must_use]
pub fn build_incident_timeline_report(input: IncidentTimelineInput<'_>) -> IncidentTimelineReport {
    let mut staged_events = Vec::new();
    let mut gaps = Vec::new();

    if let Some(source) = input.evidence_package {
        ingest_evidence_source(input.incident_id, source, &mut staged_events, &mut gaps);
    } else {
        push_gap(
            &mut gaps,
            "ITR-EVIDENCE-MISSING",
            "incident-evidence",
            "incident evidence package present",
            "source was not provided",
            "critical",
            "provide the incident evidence package before recovery",
        );
    }

    if let Some(source) = input.replay_bundle {
        ingest_replay_source(input.incident_id, source, &mut staged_events, &mut gaps);
    } else {
        push_gap(
            &mut gaps,
            "ITR-REPLAY-MISSING",
            "replay-bundle",
            "replay bundle present",
            "source was not provided",
            "critical",
            "provide a replay bundle or regenerate it from the incident evidence package",
        );
    }

    detect_duplicate_events(&staged_events, &mut gaps);
    detect_clock_skew(&staged_events, &mut gaps);
    detect_conflicting_node_reports(&staged_events, &mut gaps);

    staged_events.sort_by(|left, right| {
        left.sort_micros
            .cmp(&right.sort_micros)
            .then_with(|| left.source_rank.cmp(&right.source_rank))
            .then_with(|| left.event.source_artifact.cmp(&right.event.source_artifact))
            .then_with(|| left.event.actor_node.cmp(&right.event.actor_node))
            .then_with(|| left.event.event_code.cmp(&right.event.event_code))
            .then_with(|| left.event.summary.cmp(&right.event.summary))
    });

    let events = staged_events
        .into_iter()
        .enumerate()
        .map(|(idx, mut staged)| {
            staged.event.monotonic_order = u64::try_from(idx.saturating_add(1)).unwrap_or(u64::MAX);
            staged.event
        })
        .collect::<Vec<_>>();

    finalize_report(input.incident_id, events, gaps)
}

#[must_use]
pub fn render_incident_timeline_markdown(report: &IncidentTimelineReport) -> String {
    let mut output = String::new();
    output.push_str(&format!("# Incident Timeline: {}\n\n", report.incident_id));
    output.push_str(&format!(
        "- schema: `{}`\n- verdict: `{}`\n- events: `{}`\n- gaps: `{}`\n\n",
        report.schema_version,
        report.overall_verdict.as_str(),
        report.events.len(),
        report.gaps.len()
    ));

    output.push_str("## Timeline\n\n");
    if report.events.is_empty() {
        output.push_str("- No verified or failed events were available.\n");
    } else {
        for event in &report.events {
            output.push_str(&format!(
                "- {}. `{}` `{}` `{}` `{}` `{}` `{}` - {}\n",
                event.monotonic_order,
                event.timestamp,
                event.source_artifact,
                event.event_code,
                event.actor_node,
                event.severity,
                event.verification_status.as_str(),
                event.summary
            ));
        }
    }

    output.push_str("\n## Gaps\n\n");
    if report.gaps.is_empty() {
        output.push_str("- No evidence gaps detected.\n");
    } else {
        for gap in &report.gaps {
            output.push_str(&format!(
                "- `{}` `{}` `{}` expected `{}` observed `{}`. {}\n",
                gap.gap_code,
                gap.source_artifact,
                gap.severity,
                gap.expected,
                gap.observed,
                gap.recovery_hint
            ));
        }
    }

    output.push_str("\n## Recovery Actions\n\n");
    for action in &report.recovery_actions {
        output.push_str(&format!("- {action}\n"));
    }
    output
}

fn ingest_evidence_source(
    incident_id: &str,
    source: IncidentEvidenceSource<'_>,
    staged_events: &mut Vec<StagedTimelineEvent>,
    gaps: &mut Vec<IncidentTimelineGap>,
) {
    let source_artifact = nonempty_label(source.label, "incident-evidence");
    let mut verified = true;
    let source_digest = match incident_evidence_digest(source.package) {
        Ok(digest) => digest,
        Err(err) => {
            verified = false;
            push_gap(
                gaps,
                "ITR-SOURCE-DIGEST",
                &source_artifact,
                "canonical source digest",
                &err.to_string(),
                "high",
                "regenerate the incident evidence package with deterministic JSON values",
            );
            "unavailable".to_string()
        }
    };

    if let Err(err) = validate_incident_evidence_package(source.package, Some(incident_id)) {
        verified = false;
        push_gap(
            gaps,
            "ITR-EVIDENCE-VALIDATION",
            &source_artifact,
            "valid incident evidence package for the requested incident id",
            &err.to_string(),
            "critical",
            "fix or recollect the incident evidence package before recovery",
        );
    }

    detect_evidence_non_monotonic(&source_artifact, &source.package.events, gaps);

    let status = verification_status(verified);
    for event in &source.package.events {
        staged_events.push(stage_evidence_event(
            event,
            source.package,
            &source_artifact,
            &source_digest,
            status,
            gaps,
        ));
    }
}

fn ingest_replay_source(
    incident_id: &str,
    source: ReplayBundleSource<'_>,
    staged_events: &mut Vec<StagedTimelineEvent>,
    gaps: &mut Vec<IncidentTimelineGap>,
) {
    let source_artifact = nonempty_label(source.label, "replay-bundle");
    let mut verified = true;
    let source_digest = match replay_bundle_digest(source.bundle) {
        Ok(digest) => digest,
        Err(err) => {
            verified = false;
            push_gap(
                gaps,
                "ITR-SOURCE-DIGEST",
                &source_artifact,
                "canonical replay bundle digest",
                &err.to_string(),
                "high",
                "regenerate the replay bundle from deterministic incident evidence",
            );
            "unavailable".to_string()
        }
    };

    if source.bundle.incident_id != incident_id {
        verified = false;
        push_gap(
            gaps,
            "ITR-REPLAY-INCIDENT-ID",
            &source_artifact,
            incident_id,
            &source.bundle.incident_id,
            "critical",
            "regenerate the replay bundle for the incident under investigation",
        );
    }

    match validate_bundle_integrity(source.bundle) {
        Ok(true) => {}
        Ok(false) => {
            verified = false;
            push_gap(
                gaps,
                "ITR-REPLAY-INTEGRITY",
                &source_artifact,
                "replay bundle integrity hash matches canonical contents",
                "integrity hash mismatch",
                "critical",
                "discard the replay bundle and regenerate it from trusted evidence",
            );
        }
        Err(err) => {
            verified = false;
            push_gap(
                gaps,
                "ITR-REPLAY-INTEGRITY",
                &source_artifact,
                "structurally valid replay bundle",
                &err.to_string(),
                "critical",
                "discard the replay bundle and regenerate it from trusted evidence",
            );
        }
    }

    if source.bundle.signature.is_some() {
        match source.trusted_signature_key_id {
            Some(key_id) => {
                if let Err(err) = verify_replay_bundle_signature(source.bundle, Some(key_id)) {
                    verified = false;
                    push_gap(
                        gaps,
                        "ITR-REPLAY-SIGNATURE",
                        &source_artifact,
                        "replay bundle signature verifies against trusted key",
                        &err.to_string(),
                        "critical",
                        "verify the signing key or regenerate the replay bundle signature",
                    );
                }
            }
            None => {
                verified = false;
                push_gap(
                    gaps,
                    "ITR-REPLAY-SIGNATURE-UNVERIFIED",
                    &source_artifact,
                    "trusted replay bundle signature key id",
                    "signed bundle was provided without a trust anchor",
                    "high",
                    "supply the trusted replay bundle key id before using this report for recovery",
                );
            }
        }
    }

    detect_replay_non_monotonic(&source_artifact, &source.bundle.timeline, gaps);

    let status = verification_status(verified);
    for event in &source.bundle.timeline {
        staged_events.push(stage_replay_event(
            event,
            &source_artifact,
            &source_digest,
            status,
            gaps,
        ));
    }
}

fn stage_evidence_event(
    event: &IncidentEvidenceEvent,
    package: &IncidentEvidencePackage,
    source_artifact: &str,
    source_digest: &str,
    verification_status: IncidentTimelineVerificationStatus,
    gaps: &mut Vec<IncidentTimelineGap>,
) -> StagedTimelineEvent {
    let (timestamp, sort_micros) =
        normalize_or_gap(&event.timestamp, source_artifact, &event.event_id, gaps);
    let severity = extract_string_field(&event.payload, &["severity"])
        .map(|raw| normalize_atom(&raw))
        .unwrap_or_else(|| severity_as_str(package.severity).to_string());
    let event_code = extract_string_field(&event.payload, &["event_code", "code"])
        .map(|raw| normalize_atom(&raw))
        .unwrap_or_else(|| event.event_type.as_str().to_string());
    let actor_node = extract_string_field(
        &event.payload,
        &["actor_node", "node_id", "node", "actor", "actor_id"],
    )
    .map(|raw| normalize_atom(&raw))
    .unwrap_or_else(|| normalize_atom(&package.detector));

    StagedTimelineEvent {
        event: IncidentTimelineEvent {
            timestamp,
            monotonic_order: 0,
            source_artifact: source_artifact.to_string(),
            source_digest: source_digest.to_string(),
            actor_node,
            event_code,
            severity,
            verification_status,
            summary: summarize_payload(event.event_type, &event.payload),
        },
        sort_micros,
        source_rank: 0,
    }
}

fn stage_replay_event(
    event: &TimelineEvent,
    source_artifact: &str,
    source_digest: &str,
    verification_status: IncidentTimelineVerificationStatus,
    gaps: &mut Vec<IncidentTimelineGap>,
) -> StagedTimelineEvent {
    let event_identity = format!("sequence_number={}", event.sequence_number);
    let (timestamp, sort_micros) =
        normalize_or_gap(&event.timestamp, source_artifact, &event_identity, gaps);
    let severity = extract_string_field(&event.payload, &["severity"])
        .map(|raw| normalize_atom(&raw))
        .unwrap_or_else(|| "unknown".to_string());
    let event_code = extract_string_field(&event.payload, &["event_code", "code"])
        .map(|raw| normalize_atom(&raw))
        .unwrap_or_else(|| event.event_type.as_str().to_string());
    let actor_node = extract_string_field(
        &event.payload,
        &["actor_node", "node_id", "node", "actor", "actor_id"],
    )
    .map(|raw| normalize_atom(&raw))
    .unwrap_or_else(|| "replay-bundle".to_string());

    StagedTimelineEvent {
        event: IncidentTimelineEvent {
            timestamp,
            monotonic_order: 0,
            source_artifact: source_artifact.to_string(),
            source_digest: source_digest.to_string(),
            actor_node,
            event_code,
            severity,
            verification_status,
            summary: summarize_payload(event.event_type, &event.payload),
        },
        sort_micros,
        source_rank: 1,
    }
}

fn detect_evidence_non_monotonic(
    source_artifact: &str,
    events: &[IncidentEvidenceEvent],
    gaps: &mut Vec<IncidentTimelineGap>,
) {
    let mut previous: Option<(&str, i64)> = None;
    for event in events {
        let Ok((_, micros)) = parse_timestamp(&event.timestamp) else {
            continue;
        };
        if let Some((previous_timestamp, previous_micros)) = previous
            && micros < previous_micros
        {
            push_gap(
                gaps,
                "ITR-NON-MONOTONIC",
                source_artifact,
                "events sorted by nondecreasing timestamp",
                &format!("{previous_timestamp} before {}", event.timestamp),
                "high",
                "recollect or sort the incident evidence events before recovery",
            );
        }
        previous = Some((&event.timestamp, micros));
    }
}

fn detect_replay_non_monotonic(
    source_artifact: &str,
    events: &[TimelineEvent],
    gaps: &mut Vec<IncidentTimelineGap>,
) {
    let mut previous: Option<(&str, i64)> = None;
    for event in events {
        let Ok((_, micros)) = parse_timestamp(&event.timestamp) else {
            continue;
        };
        if let Some((previous_timestamp, previous_micros)) = previous
            && micros < previous_micros
        {
            push_gap(
                gaps,
                "ITR-NON-MONOTONIC",
                source_artifact,
                "replay timeline sorted by nondecreasing timestamp",
                &format!("{previous_timestamp} before {}", event.timestamp),
                "high",
                "regenerate the replay bundle from sorted incident events",
            );
        }
        previous = Some((&event.timestamp, micros));
    }
}

fn detect_duplicate_events(
    staged_events: &[StagedTimelineEvent],
    gaps: &mut Vec<IncidentTimelineGap>,
) {
    let mut seen = BTreeSet::new();
    for staged in staged_events {
        let event = &staged.event;
        let key = (
            event.source_artifact.as_str(),
            event.timestamp.as_str(),
            event.actor_node.as_str(),
            event.event_code.as_str(),
        );
        if !seen.insert(key) {
            push_gap(
                gaps,
                "ITR-DUPLICATE-EVENT",
                &event.source_artifact,
                "unique timestamp/actor/event_code tuple within each source",
                &format!(
                    "{} {} {}",
                    event.timestamp, event.actor_node, event.event_code
                ),
                "medium",
                "deduplicate the source artifact before treating the report as complete",
            );
        }
    }
}

fn detect_clock_skew(staged_events: &[StagedTimelineEvent], gaps: &mut Vec<IncidentTimelineGap>) {
    let mut earliest_by_source = BTreeMap::<&str, (&str, i64)>::new();
    for staged in staged_events {
        let source = staged.event.source_artifact.as_str();
        let timestamp = staged.event.timestamp.as_str();
        earliest_by_source
            .entry(source)
            .and_modify(|current| {
                if staged.sort_micros < current.1 {
                    *current = (timestamp, staged.sort_micros);
                }
            })
            .or_insert((timestamp, staged.sort_micros));
    }

    let sources = earliest_by_source.into_iter().collect::<Vec<_>>();
    for (left_idx, left) in sources.iter().enumerate() {
        for right in sources.iter().skip(left_idx.saturating_add(1)) {
            let (left_source, (left_ts, left_micros)) = *left;
            let (right_source, (right_ts, right_micros)) = *right;
            let skew = left_micros.abs_diff(right_micros);
            if skew > CLOCK_SKEW_THRESHOLD_MICROS {
                push_gap(
                    gaps,
                    "ITR-CLOCK-SKEW",
                    "incident-timeline",
                    "source first events within 300000000 microseconds",
                    &format!(
                        "{left_source}={left_ts} {right_source}={right_ts} skew_micros={skew}"
                    ),
                    "high",
                    "reconcile source clocks before ordering recovery actions",
                );
            }
        }
    }
}

fn detect_conflicting_node_reports(
    staged_events: &[StagedTimelineEvent],
    gaps: &mut Vec<IncidentTimelineGap>,
) {
    let mut reports = BTreeMap::<(&str, &str, &str), &IncidentTimelineEvent>::new();
    for staged in staged_events {
        let event = &staged.event;
        let key = (
            event.timestamp.as_str(),
            event.actor_node.as_str(),
            event.event_code.as_str(),
        );
        if let Some(previous) = reports.get(&key) {
            if previous.source_artifact != event.source_artifact
                && (previous.severity != event.severity || previous.summary != event.summary)
            {
                push_gap(
                    gaps,
                    "ITR-CONFLICTING-REPORT",
                    "incident-timeline",
                    "matching node reports agree on severity and summary",
                    &format!(
                        "{} reports `{}`/`{}` while {} reports `{}`/`{}`",
                        previous.source_artifact,
                        previous.severity,
                        previous.summary,
                        event.source_artifact,
                        event.severity,
                        event.summary
                    ),
                    "high",
                    "inspect the conflicting source artifacts before recovery",
                );
            }
        } else {
            reports.insert(key, event);
        }
    }
}

fn finalize_report(
    incident_id: &str,
    events: Vec<IncidentTimelineEvent>,
    gaps: Vec<IncidentTimelineGap>,
) -> IncidentTimelineReport {
    let overall_verdict = if gaps.is_empty() {
        IncidentTimelineVerdict::Pass
    } else {
        IncidentTimelineVerdict::Fail
    };
    let recovery_actions = recovery_actions_for_gaps(&gaps);
    IncidentTimelineReport {
        schema_version: INCIDENT_TIMELINE_SCHEMA_VERSION.to_string(),
        incident_id: incident_id.to_string(),
        overall_verdict,
        events,
        gaps,
        recovery_actions,
    }
}

fn recovery_actions_for_gaps(gaps: &[IncidentTimelineGap]) -> Vec<String> {
    if gaps.is_empty() {
        return vec![
            "attach the JSON report to the incident record".to_string(),
            "review the Markdown timeline before executing recovery".to_string(),
        ];
    }

    let mut actions = vec![
        "pause automated recovery until critical gaps are resolved".to_string(),
        "regenerate missing or invalid replay and evidence artifacts".to_string(),
    ];
    let unique_hints = gaps
        .iter()
        .map(|gap| gap.recovery_hint.as_str())
        .collect::<BTreeSet<_>>();
    actions.extend(unique_hints.into_iter().map(str::to_string));
    actions
}

fn incident_evidence_digest(
    package: &IncidentEvidencePackage,
) -> Result<String, ReplayBundleError> {
    let value = serde_json::to_value(package)?;
    canonical_value_digest(&value, "$.incident_evidence_package")
}

fn replay_bundle_digest(bundle: &ReplayBundle) -> Result<String, ReplayBundleError> {
    let canonical_json = to_canonical_json(bundle)?;
    Ok(sha256_digest(canonical_json.as_bytes()))
}

fn canonical_value_digest(value: &Value, path: &str) -> Result<String, ReplayBundleError> {
    let canonical = canonicalize_value(value, path)?;
    let bytes = serde_json::to_vec(&canonical)?;
    Ok(sha256_digest(&bytes))
}

fn sha256_digest(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    format!("sha256:{}", hex::encode(hasher.finalize()))
}

fn normalize_or_gap(
    timestamp: &str,
    source_artifact: &str,
    event_identity: &str,
    gaps: &mut Vec<IncidentTimelineGap>,
) -> (String, i64) {
    match parse_timestamp(timestamp) {
        Ok(parsed) => parsed,
        Err(observed) => {
            push_gap(
                gaps,
                "ITR-EVENT-TIMESTAMP",
                source_artifact,
                "RFC3339 event timestamp",
                &format!("{event_identity}: {observed}"),
                "high",
                "fix the event timestamp before trusting chronological order",
            );
            (timestamp.to_string(), i64::MAX)
        }
    }
}

fn parse_timestamp(timestamp: &str) -> Result<(String, i64), String> {
    let parsed = DateTime::parse_from_rfc3339(timestamp).map_err(|err| err.to_string())?;
    let normalized = parsed
        .with_timezone(&Utc)
        .to_rfc3339_opts(SecondsFormat::Micros, true);
    Ok((normalized, parsed.timestamp_micros()))
}

fn extract_string_field(payload: &Value, fields: &[&str]) -> Option<String> {
    fields.iter().find_map(|field| {
        payload
            .get(*field)
            .and_then(compact_value_string)
            .filter(|value| !value.trim().is_empty())
    })
}

fn compact_value_string(value: &Value) -> Option<String> {
    match value {
        Value::String(raw) => Some(raw.clone()),
        Value::Bool(raw) => Some(raw.to_string()),
        Value::Number(raw) => Some(raw.to_string()),
        Value::Null | Value::Array(_) | Value::Object(_) => None,
    }
}

fn summarize_payload(event_type: EventType, payload: &Value) -> String {
    extract_string_field(
        payload,
        &[
            "summary",
            "message",
            "action",
            "signal",
            "decision",
            "state",
            "event_code",
            "code",
        ],
    )
    .map(|summary| summary.trim().to_string())
    .unwrap_or_else(|| event_type.as_str().to_string())
}

fn nonempty_label(label: &str, fallback: &str) -> String {
    let trimmed = label.trim();
    if trimmed.is_empty() {
        fallback.to_string()
    } else {
        trimmed.to_string()
    }
}

fn normalize_atom(raw: &str) -> String {
    raw.trim().to_ascii_lowercase().replace(' ', "_")
}

fn severity_as_str(severity: IncidentSeverity) -> &'static str {
    match severity {
        IncidentSeverity::Low => "low",
        IncidentSeverity::Medium => "medium",
        IncidentSeverity::High => "high",
        IncidentSeverity::Critical => "critical",
        IncidentSeverity::Unknown => "unknown",
    }
}

fn verification_status(verified: bool) -> IncidentTimelineVerificationStatus {
    if verified {
        IncidentTimelineVerificationStatus::Verified
    } else {
        IncidentTimelineVerificationStatus::Failed
    }
}

fn push_gap(
    gaps: &mut Vec<IncidentTimelineGap>,
    gap_code: &str,
    source_artifact: &str,
    expected: &str,
    observed: &str,
    severity: &str,
    recovery_hint: &str,
) {
    gaps.push(IncidentTimelineGap {
        gap_code: gap_code.to_string(),
        source_artifact: source_artifact.to_string(),
        expected: expected.to_string(),
        observed: observed.to_string(),
        severity: severity.to_string(),
        recovery_hint: recovery_hint.to_string(),
    });
}
