use frankenengine_node::ops::operator_transcripts::{
    OPERATOR_TRANSCRIPT_AUDIT_SCHEMA_VERSION, OPERATOR_TRANSCRIPT_GOLDEN_SCHEMA_VERSION,
    OperatorTranscript, OperatorTranscriptAuditStatus, OperatorTranscriptGoldenSet,
    audit_operator_transcript_golden_set, reason_codes, render_operator_transcript_audit_json,
};
use serde_json::json;
use std::collections::BTreeSet;
use std::io::{Error, ErrorKind};

const FIXTURES: &str = include_str!(
    "../../../artifacts/validation_broker/bd-38hez.13/operator_transcripts_golden.json"
);

fn fixture_set() -> Result<OperatorTranscriptGoldenSet, Box<dyn std::error::Error>> {
    Ok(serde_json::from_str(FIXTURES)?)
}

fn transcript_mut<'a>(
    fixture: &'a mut OperatorTranscriptGoldenSet,
    name: &str,
) -> Result<&'a mut OperatorTranscript, Box<dyn std::error::Error>> {
    fixture
        .transcripts
        .iter_mut()
        .find(|transcript| transcript.name == name)
        .ok_or_else(|| {
            Error::new(
                ErrorKind::NotFound,
                format!("missing transcript fixture {name}"),
            )
            .into()
        })
}

#[test]
fn golden_operator_transcripts_cover_required_surfaces_and_scenarios()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture = fixture_set()?;
    assert_eq!(
        fixture.schema_version,
        OPERATOR_TRANSCRIPT_GOLDEN_SCHEMA_VERSION
    );
    assert_eq!(fixture.transcripts.len(), 6);

    let names = fixture
        .transcripts
        .iter()
        .map(|transcript| transcript.name.as_str())
        .collect::<BTreeSet<_>>();
    assert_eq!(
        names,
        BTreeSet::from([
            "blocked_validation_closeout",
            "clean_readiness",
            "proxy_only_traceability_audit",
            "rch_unavailable_command_budget",
            "resource_saturated_doctor",
            "stale_sibling_impact_mapper",
        ])
    );

    let report = audit_operator_transcript_golden_set(&fixture);

    assert_eq!(
        report.schema_version,
        OPERATOR_TRANSCRIPT_AUDIT_SCHEMA_VERSION
    );
    assert_eq!(report.status, OperatorTranscriptAuditStatus::Pass);
    assert_eq!(report.status_label, "PASS");
    assert_eq!(report.reason_code, reason_codes::PASS);
    assert!(report.findings.is_empty());
    assert!(!report.mutates_bead_state);
    assert_eq!(
        report.covered_surfaces,
        [
            "doctor",
            "readiness",
            "validation_closeout",
            "command_budget",
            "impact_mapper",
            "traceability_audit",
        ]
    );
    assert_eq!(
        report.covered_scenario_kinds,
        [
            "clean",
            "blocked",
            "proxy_only",
            "stale_sibling",
            "rch_unavailable",
            "resource_saturated",
        ]
    );
    render_operator_transcript_audit_json(&report)?;

    Ok(())
}

#[test]
fn audit_fails_when_json_loses_stable_reason_codes() -> Result<(), Box<dyn std::error::Error>> {
    let mut fixture = fixture_set()?;
    let transcript = transcript_mut(&mut fixture, "clean_readiness")?;
    let json_object = transcript
        .normalized_json
        .as_object_mut()
        .ok_or_else(|| Error::new(ErrorKind::InvalidData, "normalized_json must be an object"))?;
    json_object.insert("reason_codes".to_string(), json!([]));

    let report = audit_operator_transcript_golden_set(&fixture);

    assert_eq!(report.status, OperatorTranscriptAuditStatus::Fail);
    assert!(report.findings.iter().any(|finding| {
        finding.reason_code == reason_codes::FAIL_MISSING_REASON_CODE_IN_JSON
            && finding.transcript_name == "clean_readiness"
    }));

    Ok(())
}

#[test]
fn audit_fails_when_human_output_omits_actionable_next_step()
-> Result<(), Box<dyn std::error::Error>> {
    let mut fixture = fixture_set()?;
    let transcript = transcript_mut(&mut fixture, "blocked_validation_closeout")?;
    let next_step = transcript.expected_next_step.clone();
    transcript.normalized_human = transcript.normalized_human.replace(&next_step, "");

    let report = audit_operator_transcript_golden_set(&fixture);

    assert_eq!(report.status, OperatorTranscriptAuditStatus::Fail);
    assert!(report.findings.iter().any(|finding| {
        finding.reason_code == reason_codes::FAIL_MISSING_ACTION
            && finding.transcript_name == "blocked_validation_closeout"
    }));

    Ok(())
}

#[test]
fn audit_fails_on_unscrubbed_paths_timestamps_and_sensitive_env()
-> Result<(), Box<dyn std::error::Error>> {
    let mut fixture = fixture_set()?;
    let transcript = transcript_mut(&mut fixture, "proxy_only_traceability_audit")?;
    let sensitive_key = ["OPENAI", "API", "KEY"].join("_");
    transcript
        .sanitized_env
        .insert(sensitive_key, "[REDACTED]".to_string());
    transcript
        .normalized_human
        .push_str("\nRaw path /data/projects/franken_node at 2026-05-09T22:15:00Z");

    let report = audit_operator_transcript_golden_set(&fixture);

    assert_eq!(report.status, OperatorTranscriptAuditStatus::Fail);
    assert!(report.findings.iter().any(|finding| {
        finding.reason_code == reason_codes::FAIL_SENSITIVE_ENV
            && finding.transcript_name == "proxy_only_traceability_audit"
    }));
    assert!(report.findings.iter().any(|finding| {
        finding.reason_code == reason_codes::FAIL_UNSCRUBBED_DYNAMIC_FIELD
            && finding.transcript_name == "proxy_only_traceability_audit"
    }));

    Ok(())
}
