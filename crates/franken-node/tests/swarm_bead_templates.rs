use frankenengine_node::ops::swarm_bead_templates::{
    ExistingBeadRef, SWARM_BEAD_TEMPLATE_INPUT_SCHEMA_VERSION,
    SWARM_BEAD_TEMPLATE_REPORT_SCHEMA_VERSION, SwarmBeadTemplateInput, SwarmBlockerKind,
    SwarmTemplateReportStatus, generate_swarm_bead_templates, reason_codes,
    render_swarm_bead_template_report_json,
};
use serde::Deserialize;
use std::collections::BTreeSet;
use std::io::{Error, ErrorKind};

const FIXTURES: &str = include_str!(
    "../../../artifacts/validation_broker/bd-38hez.15/swarm_bead_template_fixtures.json"
);
const FIXTURE_SCHEMA_VERSION: &str = "franken-node/swarm-bead-templates/fixtures/v1";

#[derive(Debug, Deserialize)]
struct Fixture {
    schema_version: String,
    input: SwarmBeadTemplateInput,
    expected_generated_count: usize,
    expected_deduped_count: usize,
}

fn fixture() -> Result<Fixture, Box<dyn std::error::Error>> {
    Ok(serde_json::from_str(FIXTURES)?)
}

fn observation_index(
    input: &SwarmBeadTemplateInput,
    kind: SwarmBlockerKind,
) -> Result<usize, Box<dyn std::error::Error>> {
    input
        .observations
        .iter()
        .position(|observation| observation.blocker_kind == kind)
        .ok_or_else(|| Error::new(ErrorKind::NotFound, "missing observation kind").into())
}

#[test]
fn fixture_generates_reusable_templates_with_dedupe() -> Result<(), Box<dyn std::error::Error>> {
    let fixture = fixture()?;
    assert_eq!(fixture.schema_version, FIXTURE_SCHEMA_VERSION);
    assert_eq!(
        fixture.input.schema_version,
        SWARM_BEAD_TEMPLATE_INPUT_SCHEMA_VERSION
    );
    assert_eq!(fixture.input.observations.len(), 6);

    let covered = fixture
        .input
        .observations
        .iter()
        .map(|observation| observation.blocker_kind.as_str())
        .collect::<BTreeSet<_>>();
    assert_eq!(
        covered,
        BTreeSet::from([
            "compile_drift",
            "rch_stall",
            "cargo_contention",
            "stale_assignee",
            "missing_artifact",
            "false_positive_scanner_warning",
        ])
    );

    let report = generate_swarm_bead_templates(&fixture.input);

    assert_eq!(
        report.schema_version,
        SWARM_BEAD_TEMPLATE_REPORT_SCHEMA_VERSION
    );
    assert_eq!(report.status, SwarmTemplateReportStatus::Pass);
    assert_eq!(report.reason_code, reason_codes::PASS_WITH_DEDUPE);
    assert!(!report.mutates_bead_state);
    assert_eq!(report.generated_count, fixture.expected_generated_count);
    assert_eq!(report.deduped_count, fixture.expected_deduped_count);
    assert_eq!(report.templates.len(), fixture.expected_generated_count);
    assert_eq!(
        report.covered_blocker_kinds,
        [
            "compile_drift",
            "rch_stall",
            "cargo_contention",
            "stale_assignee",
            "missing_artifact",
            "false_positive_scanner_warning",
        ]
    );
    assert!(
        report
            .deduped_observations
            .iter()
            .any(|dedupe| dedupe.observation_id == "cargo-contention-queue-depth")
    );

    for template in &report.templates {
        assert!(template.suggested_br_create.starts_with("br create "));
        assert!(template.suggested_br_create.contains("--priority 2"));
        assert!(template.description.contains(template.dedupe_key.as_str()));
        assert!(!template.evidence.is_empty());
        for evidence in &template.evidence {
            assert!(
                template
                    .description
                    .contains(evidence.source_bead_id.as_str())
            );
            assert!(template.description.contains(evidence.command.as_str()));
            assert!(
                template
                    .description
                    .contains(evidence.evidence_excerpt.as_str())
            );
            if let Some(error_code) = &evidence.error_code {
                assert!(template.description.contains(error_code.as_str()));
            }
            if let Some(path) = &evidence.file_path {
                assert!(template.description.contains(path.as_str()));
            }
        }
    }

    render_swarm_bead_template_report_json(&report)?;

    Ok(())
}

#[test]
fn dedupe_prevents_duplicate_template_generation() -> Result<(), Box<dyn std::error::Error>> {
    let mut fixture = fixture()?;
    let report = generate_swarm_bead_templates(&fixture.input);
    let compile_template = report
        .templates
        .iter()
        .find(|template| template.blocker_kind == SwarmBlockerKind::CompileDrift)
        .ok_or_else(|| Error::new(ErrorKind::NotFound, "missing compile template"))?;

    fixture.input.existing_beads.push(ExistingBeadRef {
        bead_id: "bd-existing-compile".to_string(),
        title: "Existing compile drift template".to_string(),
        description: format!("already filed {}", compile_template.dedupe_key),
    });

    let deduped = generate_swarm_bead_templates(&fixture.input);

    assert_eq!(deduped.status, SwarmTemplateReportStatus::Pass);
    assert!(
        !deduped
            .templates
            .iter()
            .any(|template| template.blocker_kind == SwarmBlockerKind::CompileDrift)
    );
    assert!(deduped.deduped_observations.iter().any(|dedupe| {
        dedupe.existing_bead_id == "bd-existing-compile"
            && dedupe.observation_id == "compile-drift-perf-wins"
    }));

    Ok(())
}

#[test]
fn audit_fails_when_blocker_evidence_is_missing() -> Result<(), Box<dyn std::error::Error>> {
    let mut fixture = fixture()?;
    let index = observation_index(&fixture.input, SwarmBlockerKind::RchStall)?;
    fixture
        .input
        .observations
        .get_mut(index)
        .ok_or_else(|| Error::new(ErrorKind::NotFound, "missing rch stall observation"))?
        .evidence_excerpt
        .clear();

    let report = generate_swarm_bead_templates(&fixture.input);

    assert_eq!(report.status, SwarmTemplateReportStatus::Fail);
    assert!(report.findings.iter().any(|finding| {
        finding.reason_code == reason_codes::FAIL_MISSING_EVIDENCE
            && finding.observation_id == "rch-stall-no-output"
    }));

    Ok(())
}

#[test]
fn audit_fails_when_required_blocker_kind_is_missing() -> Result<(), Box<dyn std::error::Error>> {
    let mut fixture = fixture()?;
    fixture
        .input
        .observations
        .retain(|observation| observation.blocker_kind != SwarmBlockerKind::MissingArtifact);

    let report = generate_swarm_bead_templates(&fixture.input);

    assert_eq!(report.status, SwarmTemplateReportStatus::Fail);
    assert!(report.findings.iter().any(|finding| {
        finding.reason_code == reason_codes::FAIL_MISSING_KIND
            && finding.message.contains("missing_artifact")
    }));

    Ok(())
}
