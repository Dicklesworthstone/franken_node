use frankenengine_node::tools::{
    incident_timeline::{
        IncidentEvidenceSource, IncidentTimelineInput, IncidentTimelineVerdict,
        IncidentTimelineVerificationStatus, ReplayBundleSource, build_incident_timeline_report,
        render_incident_timeline_markdown,
    },
    replay_bundle::{
        EventType, INCIDENT_EVIDENCE_SCHEMA, IncidentEvidenceEvent, IncidentEvidenceMetadata,
        IncidentEvidencePackage, IncidentSeverity, RawEvent, generate_replay_bundle,
        generate_replay_bundle_from_evidence,
    },
};
use serde_json::json;

type TestResult = Result<(), String>;

fn evidence_package(incident_id: &str, first_timestamp: &str) -> IncidentEvidencePackage {
    IncidentEvidencePackage {
        schema_version: INCIDENT_EVIDENCE_SCHEMA.to_string(),
        incident_id: incident_id.to_string(),
        collected_at: first_timestamp.to_string(),
        trace_id: format!("trace-{incident_id}"),
        severity: IncidentSeverity::High,
        incident_type: "availability".to_string(),
        detector: "detector-node-a".to_string(),
        policy_version: "2026.05".to_string(),
        initial_state_snapshot: json!({
            "epoch": 7_u64,
            "service": "checkout",
            "state": "degraded"
        }),
        events: vec![
            IncidentEvidenceEvent {
                event_id: "event-001".to_string(),
                timestamp: first_timestamp.to_string(),
                event_type: EventType::ExternalSignal,
                payload: json!({
                    "event_code": "latency_spike",
                    "actor_node": "node-a",
                    "severity": "high",
                    "summary": "p95 latency crossed budget"
                }),
                provenance_ref: "signals/latency.json".to_string(),
                parent_event_id: None,
                state_snapshot: None,
                policy_version: None,
            },
            IncidentEvidenceEvent {
                event_id: "event-002".to_string(),
                timestamp: "2026-05-05T10:00:01.000000Z".to_string(),
                event_type: EventType::OperatorAction,
                payload: json!({
                    "event_code": "quarantine_node",
                    "actor_node": "operator-1",
                    "severity": "medium",
                    "summary": "node quarantined after policy confirmation"
                }),
                provenance_ref: "operator/actions.json".to_string(),
                parent_event_id: Some("event-001".to_string()),
                state_snapshot: None,
                policy_version: None,
            },
        ],
        evidence_refs: vec![
            "signals/latency.json".to_string(),
            "operator/actions.json".to_string(),
        ],
        metadata: IncidentEvidenceMetadata {
            title: "checkout latency incident".to_string(),
            affected_components: vec!["checkout".to_string()],
            tags: vec!["incident-timeline".to_string()],
        },
    }
}

#[test]
fn incident_timeline_report_all_green_json_and_markdown_contract() -> TestResult {
    let package = evidence_package("inc-green", "2026-05-05T10:00:00.000000Z");
    let bundle = generate_replay_bundle_from_evidence(&package)
        .map_err(|err| format!("bundle must generate: {err}"))?;

    let report = build_incident_timeline_report(IncidentTimelineInput {
        incident_id: "inc-green",
        evidence_package: Some(IncidentEvidenceSource {
            label: "incident.json",
            package: &package,
        }),
        replay_bundle: Some(ReplayBundleSource {
            label: "bundle.json",
            bundle: &bundle,
            trusted_signature_key_id: None,
        }),
    });

    if report.overall_verdict != IncidentTimelineVerdict::Pass {
        return Err(format!("expected pass report, got {:?}", report.gaps));
    }
    if !report.gaps.is_empty() {
        return Err(format!("all-green report produced gaps: {:?}", report.gaps));
    }
    if report.events.len() != 4 {
        return Err(format!(
            "expected four normalized events, got {}",
            report.events.len()
        ));
    }
    if !report
        .events
        .iter()
        .any(|event| event.source_artifact == "incident.json")
    {
        return Err("incident source events missing".to_string());
    }
    if !report
        .events
        .iter()
        .any(|event| event.source_artifact == "bundle.json")
    {
        return Err("replay source events missing".to_string());
    }
    if report
        .events
        .iter()
        .any(|event| !event.source_digest.starts_with("sha256:"))
    {
        return Err("source digests must be sha256-prefixed".to_string());
    }

    let json_value = serde_json::to_value(&report)
        .map_err(|err| format!("report should serialize as JSON: {err}"))?;
    if json_value.get("schema_version") != Some(&json!("franken-node/incident-timeline-report/v1"))
    {
        return Err(format!("unexpected schema version: {json_value}"));
    }

    let markdown = render_incident_timeline_markdown(&report);
    if !markdown.contains("# Incident Timeline: inc-green")
        || !markdown.contains("latency_spike")
        || !markdown.contains("No evidence gaps detected")
    {
        return Err(format!(
            "markdown omitted expected contract content:\n{markdown}"
        ));
    }

    Ok(())
}

#[test]
fn incident_timeline_report_keeps_missing_replay_visible() {
    let package = evidence_package("inc-missing", "2026-05-05T10:00:00.000000Z");

    let report = build_incident_timeline_report(IncidentTimelineInput {
        incident_id: "inc-missing",
        evidence_package: Some(IncidentEvidenceSource {
            label: "incident.json",
            package: &package,
        }),
        replay_bundle: None,
    });

    assert_eq!(report.overall_verdict, IncidentTimelineVerdict::Fail);
    assert!(
        report
            .gaps
            .iter()
            .any(|gap| gap.gap_code == "ITR-REPLAY-MISSING")
    );
    assert!(render_incident_timeline_markdown(&report).contains("ITR-REPLAY-MISSING"));
}

#[test]
fn incident_timeline_report_flags_tampered_replay_bundle() -> TestResult {
    let package = evidence_package("inc-tampered", "2026-05-05T10:00:00.000000Z");
    let mut bundle = generate_replay_bundle_from_evidence(&package)
        .map_err(|err| format!("bundle must generate: {err}"))?;
    bundle.integrity_hash = "sha256:tampered".to_string();

    let report = build_incident_timeline_report(IncidentTimelineInput {
        incident_id: "inc-tampered",
        evidence_package: Some(IncidentEvidenceSource {
            label: "incident.json",
            package: &package,
        }),
        replay_bundle: Some(ReplayBundleSource {
            label: "bundle.json",
            bundle: &bundle,
            trusted_signature_key_id: None,
        }),
    });

    if report.overall_verdict != IncidentTimelineVerdict::Fail {
        return Err("tampered replay bundle should fail the report".to_string());
    }
    if !report
        .gaps
        .iter()
        .any(|gap| gap.gap_code == "ITR-REPLAY-INTEGRITY")
    {
        return Err(format!("expected integrity gap, got {:?}", report.gaps));
    }
    if !report.events.iter().any(|event| {
        event.source_artifact.as_str().eq("bundle.json")
            && matches!(
                event.verification_status,
                IncidentTimelineVerificationStatus::Failed
            )
    }) {
        return Err("tampered replay events should remain visible as failed".to_string());
    }

    Ok(())
}

#[test]
fn incident_timeline_report_flags_cross_source_clock_skew() -> TestResult {
    let package = evidence_package("inc-skew", "2026-05-05T10:00:00.000000Z");
    let replay_events = vec![
        RawEvent::new(
            "2026-05-05T10:10:00.000000Z",
            EventType::ExternalSignal,
            json!({
                "event_code": "latency_spike",
                "actor_node": "node-a",
                "severity": "high",
                "summary": "p95 latency crossed budget"
            }),
        )
        .with_state_snapshot(json!({ "epoch": 7_u64 }))
        .with_policy_version("2026.05"),
    ];
    let bundle = generate_replay_bundle("inc-skew", &replay_events)
        .map_err(|err| format!("bundle must generate: {err}"))?;

    let report = build_incident_timeline_report(IncidentTimelineInput {
        incident_id: "inc-skew",
        evidence_package: Some(IncidentEvidenceSource {
            label: "incident.json",
            package: &package,
        }),
        replay_bundle: Some(ReplayBundleSource {
            label: "bundle.json",
            bundle: &bundle,
            trusted_signature_key_id: None,
        }),
    });

    if report.overall_verdict != IncidentTimelineVerdict::Fail {
        return Err("clock skew should fail the report".to_string());
    }
    if !report
        .gaps
        .iter()
        .any(|gap| gap.gap_code == "ITR-CLOCK-SKEW")
    {
        return Err(format!("expected clock skew gap, got {:?}", report.gaps));
    }

    Ok(())
}
