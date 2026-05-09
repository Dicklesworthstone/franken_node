use frankenengine_node::ops::closed_bead_compliance::{
    CLOSED_BEAD_COMPLIANCE_INPUT_SCHEMA_VERSION, CLOSED_BEAD_COMPLIANCE_SCHEMA_VERSION,
    ClosedBeadComplianceInput, ClosedBeadComplianceStatus, ClosedBeadEvidenceKind,
    audit_closed_bead_compliance, reason_codes, render_closed_bead_compliance_json,
};
use serde::Deserialize;
use std::collections::BTreeSet;

const FIXTURES: &str = include_str!(
    "../../../artifacts/validation_broker/bd-38hez.11/closed_bead_compliance_fixtures.json"
);
const FIXTURE_SCHEMA_VERSION: &str = "franken-node/closed-bead-compliance/fixtures/v1";

#[derive(Debug, Deserialize)]
struct Fixture {
    schema_version: String,
    scenarios: Vec<Scenario>,
}

#[derive(Debug, Deserialize)]
struct Scenario {
    name: String,
    input: ClosedBeadComplianceInput,
    expected_status: String,
    expected_reason_code: String,
}

#[test]
fn fixture_scenarios_cover_closed_bead_compliance_outcomes()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture: Fixture = serde_json::from_str(FIXTURES)?;
    assert_eq!(fixture.schema_version, FIXTURE_SCHEMA_VERSION);
    assert_eq!(fixture.scenarios.len(), 6);

    let names = fixture
        .scenarios
        .iter()
        .map(|scenario| scenario.name.as_str())
        .collect::<BTreeSet<_>>();
    assert_eq!(
        names,
        BTreeSet::from([
            "clean_closed_bead_passes",
            "closed_with_blocker_warns",
            "missing_tests_fail",
            "reopened_stale_bead_fails",
            "source_only_proof_warns",
            "unrelated_test_pass_fails",
        ])
    );

    for scenario in fixture.scenarios {
        assert_eq!(
            scenario.input.schema_version,
            CLOSED_BEAD_COMPLIANCE_INPUT_SCHEMA_VERSION
        );

        let report = audit_closed_bead_compliance(scenario.input);

        assert_eq!(report.schema_version, CLOSED_BEAD_COMPLIANCE_SCHEMA_VERSION);
        assert_eq!(
            report.status_label, scenario.expected_status,
            "{}",
            scenario.name
        );
        assert_eq!(
            report.reason_code, scenario.expected_reason_code,
            "{}",
            scenario.name
        );
        assert!(!report.mutates_bead_state, "{}", scenario.name);
        assert!(
            report.human_summary.contains("bead=")
                && report.human_summary.contains(report.bead_id.as_str()),
            "{}",
            scenario.name
        );
        render_closed_bead_compliance_json(&report)?;

        match scenario.name.as_str() {
            "clean_closed_bead_passes" => {
                assert_eq!(report.status, ClosedBeadComplianceStatus::Pass);
                assert_eq!(report.reason_code, reason_codes::PASS);
                assert!(report.suggested_br_commands.is_empty());
                assert_eq!(report.evidence_summary.direct_fresh, 6);
            }
            "closed_with_blocker_warns" => {
                assert_eq!(report.status, ClosedBeadComplianceStatus::Warn);
                assert_eq!(report.evidence_summary.direct_blocked, 1);
                assert!(report.required_action.contains("blocked_proof"));
            }
            "source_only_proof_warns" => {
                assert_eq!(report.status, ClosedBeadComplianceStatus::Warn);
                assert!(report.evidence_summary.direct_source_only >= 1);
                assert_eq!(report.reason_code, reason_codes::WARN_SOURCE_ONLY);
            }
            "missing_tests_fail" => {
                assert_eq!(report.status, ClosedBeadComplianceStatus::Fail);
                assert!(report.requirements.iter().any(|requirement| {
                    requirement
                        .missing_kinds
                        .contains(&ClosedBeadEvidenceKind::Test)
                }));
            }
            "unrelated_test_pass_fails" => {
                assert_eq!(report.status, ClosedBeadComplianceStatus::Fail);
                assert_eq!(report.reason_code, reason_codes::FAIL_UNRELATED_EVIDENCE);
                assert_eq!(report.evidence_summary.proxy_or_unrelated, 1);
            }
            "reopened_stale_bead_fails" => {
                assert_eq!(report.status, ClosedBeadComplianceStatus::Fail);
                assert_eq!(report.reason_code, reason_codes::FAIL_BEAD_NOT_CLOSED);
                assert!(
                    report
                        .suggested_br_commands
                        .iter()
                        .any(|command| command == "br show bd-reopened")
                );
            }
            _ => {}
        }
    }

    Ok(())
}
