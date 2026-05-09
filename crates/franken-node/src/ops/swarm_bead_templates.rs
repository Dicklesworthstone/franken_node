//! Reusable swarm bead template generation.
//!
//! This module turns repeated validation/proof blockers into deterministic bead
//! template suggestions. It is deliberately pure: callers provide observations
//! and known beads, and the generator returns candidate `br create` commands
//! without mutating Beads, Agent Mail, or repository state.

use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;

pub const SWARM_BEAD_TEMPLATE_INPUT_SCHEMA_VERSION: &str =
    "franken-node/swarm-bead-templates/input/v1";
pub const SWARM_BEAD_TEMPLATE_REPORT_SCHEMA_VERSION: &str =
    "franken-node/swarm-bead-templates/report/v1";
pub const MAX_TEMPLATE_OBSERVATIONS: usize = 128;
pub const MAX_EXISTING_BEADS: usize = 512;
const MAX_FIELD_BYTES: usize = 4096;

pub mod reason_codes {
    pub const PASS: &str = "SBT_PASS";
    pub const PASS_WITH_DEDUPE: &str = "SBT_PASS_WITH_DEDUPE";
    pub const FAIL_SCHEMA_VERSION: &str = "SBT_FAIL_SCHEMA_VERSION";
    pub const FAIL_EMPTY_INPUT: &str = "SBT_FAIL_EMPTY_INPUT";
    pub const FAIL_MISSING_KIND: &str = "SBT_FAIL_MISSING_KIND";
    pub const FAIL_INVALID_OBSERVATION: &str = "SBT_FAIL_INVALID_OBSERVATION";
    pub const FAIL_MISSING_EVIDENCE: &str = "SBT_FAIL_MISSING_EVIDENCE";
    pub const FAIL_DUPLICATE_OBSERVATION: &str = "SBT_FAIL_DUPLICATE_OBSERVATION";
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SwarmBlockerKind {
    CompileDrift,
    RchStall,
    CargoContention,
    StaleAssignee,
    MissingArtifact,
    FalsePositiveScannerWarning,
}

impl SwarmBlockerKind {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::CompileDrift => "compile_drift",
            Self::RchStall => "rch_stall",
            Self::CargoContention => "cargo_contention",
            Self::StaleAssignee => "stale_assignee",
            Self::MissingArtifact => "missing_artifact",
            Self::FalsePositiveScannerWarning => "false_positive_scanner_warning",
        }
    }

    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::CompileDrift => "compile-drift",
            Self::RchStall => "rch-stall",
            Self::CargoContention => "cargo-contention",
            Self::StaleAssignee => "stale-assignee",
            Self::MissingArtifact => "missing-artifact",
            Self::FalsePositiveScannerWarning => "scanner-false-positive",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SwarmProofObservation {
    pub observation_id: String,
    pub source_bead_id: String,
    pub blocker_kind: SwarmBlockerKind,
    pub command: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_code: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub file_path: Option<String>,
    pub evidence_excerpt: String,
    pub resolution_pattern: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExistingBeadRef {
    pub bead_id: String,
    pub title: String,
    pub description: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SwarmBeadTemplateInput {
    pub schema_version: String,
    pub observations: Vec<SwarmProofObservation>,
    pub existing_beads: Vec<ExistingBeadRef>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SwarmTemplateEvidence {
    pub source_bead_id: String,
    pub command: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_code: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub file_path: Option<String>,
    pub evidence_excerpt: String,
    pub resolution_pattern: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SwarmBeadTemplate {
    pub template_id: String,
    pub dedupe_key: String,
    pub blocker_kind: SwarmBlockerKind,
    pub title: String,
    pub description: String,
    pub priority: u8,
    pub labels: Vec<String>,
    pub source_observation_ids: Vec<String>,
    pub evidence: Vec<SwarmTemplateEvidence>,
    pub suggested_br_create: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SwarmTemplateDedupe {
    pub observation_id: String,
    pub source_bead_id: String,
    pub existing_bead_id: String,
    pub dedupe_key: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SwarmTemplateFinding {
    pub observation_id: String,
    pub reason_code: String,
    pub message: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SwarmTemplateReportStatus {
    Pass,
    Fail,
}

impl SwarmTemplateReportStatus {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Pass => "PASS",
            Self::Fail => "FAIL",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SwarmBeadTemplateReport {
    pub schema_version: String,
    pub status: SwarmTemplateReportStatus,
    pub status_label: String,
    pub reason_code: String,
    pub mutates_bead_state: bool,
    pub observation_count: usize,
    pub generated_count: usize,
    pub deduped_count: usize,
    pub covered_blocker_kinds: Vec<String>,
    pub templates: Vec<SwarmBeadTemplate>,
    pub deduped_observations: Vec<SwarmTemplateDedupe>,
    pub findings: Vec<SwarmTemplateFinding>,
    pub human_summary: String,
}

#[must_use]
pub fn generate_swarm_bead_templates(input: &SwarmBeadTemplateInput) -> SwarmBeadTemplateReport {
    let mut findings = Vec::new();
    let mut covered_kinds = BTreeSet::new();
    let mut observation_ids = BTreeSet::new();

    if input.schema_version != SWARM_BEAD_TEMPLATE_INPUT_SCHEMA_VERSION {
        push_finding(
            &mut findings,
            "*",
            reason_codes::FAIL_SCHEMA_VERSION,
            format!(
                "schema_version must be {}",
                SWARM_BEAD_TEMPLATE_INPUT_SCHEMA_VERSION
            ),
        );
    }

    if input.observations.is_empty() || input.observations.len() > MAX_TEMPLATE_OBSERVATIONS {
        push_finding(
            &mut findings,
            "*",
            reason_codes::FAIL_EMPTY_INPUT,
            format!("observations must contain 1..={MAX_TEMPLATE_OBSERVATIONS} records"),
        );
    }

    if input.existing_beads.len() > MAX_EXISTING_BEADS {
        push_finding(
            &mut findings,
            "*",
            reason_codes::FAIL_EMPTY_INPUT,
            format!("existing_beads must contain at most {MAX_EXISTING_BEADS} records"),
        );
    }

    for observation in &input.observations {
        covered_kinds.insert(observation.blocker_kind);
        audit_observation(observation, &mut findings);
        if !observation_ids.insert(observation.observation_id.as_str()) {
            push_finding(
                &mut findings,
                &observation.observation_id,
                reason_codes::FAIL_DUPLICATE_OBSERVATION,
                format!("duplicate observation_id {}", observation.observation_id),
            );
        }
    }

    for required_kind in required_blocker_kinds() {
        if !covered_kinds.contains(required_kind) {
            push_finding(
                &mut findings,
                "*",
                reason_codes::FAIL_MISSING_KIND,
                format!("missing blocker kind {}", required_kind.as_str()),
            );
        }
    }

    let mut grouped: BTreeMap<String, Vec<&SwarmProofObservation>> = BTreeMap::new();
    for observation in input
        .observations
        .iter()
        .filter(|observation| observation_is_templateable(observation))
    {
        grouped
            .entry(dedupe_key_for_observation(observation))
            .or_default()
            .push(observation);
    }

    let mut templates = Vec::new();
    let mut deduped_observations = Vec::new();
    for (dedupe_key, observations) in grouped {
        let Some(first_observation) = observations.first().copied() else {
            continue;
        };
        if let Some(existing) = find_existing_template(
            input.existing_beads.as_slice(),
            &dedupe_key,
            first_observation,
        ) {
            for observation in observations {
                deduped_observations.push(SwarmTemplateDedupe {
                    observation_id: observation.observation_id.clone(),
                    source_bead_id: observation.source_bead_id.clone(),
                    existing_bead_id: existing.bead_id.clone(),
                    dedupe_key: dedupe_key.clone(),
                });
            }
            continue;
        }
        templates.push(build_template(
            &dedupe_key,
            first_observation,
            observations.as_slice(),
        ));
    }

    templates.sort_by(|left, right| left.template_id.cmp(&right.template_id));
    deduped_observations.sort_by(|left, right| {
        left.observation_id
            .cmp(&right.observation_id)
            .then_with(|| left.existing_bead_id.cmp(&right.existing_bead_id))
    });

    let status = if findings.is_empty() {
        SwarmTemplateReportStatus::Pass
    } else {
        SwarmTemplateReportStatus::Fail
    };
    let reason_code = if status == SwarmTemplateReportStatus::Fail {
        findings
            .first()
            .map(|finding| finding.reason_code.clone())
            .unwrap_or_else(|| reason_codes::FAIL_INVALID_OBSERVATION.to_string())
    } else if deduped_observations.is_empty() {
        reason_codes::PASS.to_string()
    } else {
        reason_codes::PASS_WITH_DEDUPE.to_string()
    };
    let covered_blocker_kinds = covered_kinds
        .into_iter()
        .map(SwarmBlockerKind::as_str)
        .map(str::to_string)
        .collect::<Vec<_>>();

    SwarmBeadTemplateReport {
        schema_version: SWARM_BEAD_TEMPLATE_REPORT_SCHEMA_VERSION.to_string(),
        status,
        status_label: status.as_str().to_string(),
        reason_code,
        mutates_bead_state: false,
        observation_count: input.observations.len(),
        generated_count: templates.len(),
        deduped_count: deduped_observations.len(),
        human_summary: format!(
            "swarm bead templates status={} observations={} generated={} deduped={} findings={}",
            status.as_str(),
            input.observations.len(),
            templates.len(),
            deduped_observations.len(),
            findings.len()
        ),
        covered_blocker_kinds,
        templates,
        deduped_observations,
        findings,
    }
}

pub fn render_swarm_bead_template_report_json(
    report: &SwarmBeadTemplateReport,
) -> serde_json::Result<String> {
    serde_json::to_string_pretty(report)
}

fn audit_observation(
    observation: &SwarmProofObservation,
    findings: &mut Vec<SwarmTemplateFinding>,
) {
    check_required_string(
        findings,
        &observation.observation_id,
        "observation_id",
        observation.observation_id.as_str(),
    );
    check_required_string(
        findings,
        &observation.observation_id,
        "source_bead_id",
        observation.source_bead_id.as_str(),
    );
    check_required_string(
        findings,
        &observation.observation_id,
        "command",
        observation.command.as_str(),
    );
    check_required_string(
        findings,
        &observation.observation_id,
        "evidence_excerpt",
        observation.evidence_excerpt.as_str(),
    );
    check_required_string(
        findings,
        &observation.observation_id,
        "resolution_pattern",
        observation.resolution_pattern.as_str(),
    );

    if observation.evidence_excerpt.trim().is_empty() {
        push_finding(
            findings,
            &observation.observation_id,
            reason_codes::FAIL_MISSING_EVIDENCE,
            "observation must include exact blocker evidence".to_string(),
        );
    }
    if observation.error_code.as_deref().is_none_or(str::is_empty)
        && observation.file_path.as_deref().is_none_or(str::is_empty)
    {
        push_finding(
            findings,
            &observation.observation_id,
            reason_codes::FAIL_INVALID_OBSERVATION,
            "observation must include an error_code or file_path".to_string(),
        );
    }
}

fn check_required_string(
    findings: &mut Vec<SwarmTemplateFinding>,
    observation_id: &str,
    field: &str,
    value: &str,
) {
    if value.trim().is_empty() {
        push_finding(
            findings,
            observation_id,
            reason_codes::FAIL_INVALID_OBSERVATION,
            format!("{field} must be non-empty"),
        );
    }
    if value.len() > MAX_FIELD_BYTES {
        push_finding(
            findings,
            observation_id,
            reason_codes::FAIL_INVALID_OBSERVATION,
            format!("{field} exceeds {MAX_FIELD_BYTES} bytes"),
        );
    }
}

fn push_finding(
    findings: &mut Vec<SwarmTemplateFinding>,
    observation_id: &str,
    reason_code: &'static str,
    message: String,
) {
    findings.push(SwarmTemplateFinding {
        observation_id: observation_id.to_string(),
        reason_code: reason_code.to_string(),
        message,
    });
}

fn required_blocker_kinds() -> &'static [SwarmBlockerKind] {
    &[
        SwarmBlockerKind::CompileDrift,
        SwarmBlockerKind::RchStall,
        SwarmBlockerKind::CargoContention,
        SwarmBlockerKind::StaleAssignee,
        SwarmBlockerKind::MissingArtifact,
        SwarmBlockerKind::FalsePositiveScannerWarning,
    ]
}

fn observation_is_templateable(observation: &SwarmProofObservation) -> bool {
    !observation.observation_id.trim().is_empty()
        && !observation.source_bead_id.trim().is_empty()
        && !observation.command.trim().is_empty()
        && !observation.evidence_excerpt.trim().is_empty()
        && !observation.resolution_pattern.trim().is_empty()
}

fn dedupe_key_for_observation(observation: &SwarmProofObservation) -> String {
    format!(
        "swarm-template:{}:{}:{}:{}",
        observation.blocker_kind.as_str(),
        normalize_key_part(&observation.command),
        normalize_key_part(observation.file_path.as_deref().unwrap_or("")),
        normalize_key_part(observation.error_code.as_deref().unwrap_or(""))
    )
}

fn normalize_key_part(value: &str) -> String {
    let mut normalized = String::new();
    for ch in value.chars().flat_map(char::to_lowercase) {
        if ch.is_ascii_alphanumeric() {
            normalized.push(ch);
        } else if !normalized.ends_with('-') {
            normalized.push('-');
        }
    }
    normalized.trim_matches('-').to_string()
}

fn find_existing_template<'a>(
    existing_beads: &'a [ExistingBeadRef],
    dedupe_key: &str,
    first_observation: &SwarmProofObservation,
) -> Option<&'a ExistingBeadRef> {
    let candidate_title = template_title(first_observation);
    existing_beads.iter().find(|existing| {
        existing.description.contains(dedupe_key)
            || existing
                .title
                .eq_ignore_ascii_case(candidate_title.as_str())
    })
}

fn build_template(
    dedupe_key: &str,
    first: &SwarmProofObservation,
    observations: &[&SwarmProofObservation],
) -> SwarmBeadTemplate {
    let evidence = observations
        .iter()
        .map(|observation| SwarmTemplateEvidence {
            source_bead_id: observation.source_bead_id.clone(),
            command: observation.command.clone(),
            error_code: observation.error_code.clone(),
            file_path: observation.file_path.clone(),
            evidence_excerpt: observation.evidence_excerpt.clone(),
            resolution_pattern: observation.resolution_pattern.clone(),
        })
        .collect::<Vec<_>>();
    let source_observation_ids = observations
        .iter()
        .map(|observation| observation.observation_id.clone())
        .collect::<Vec<_>>();
    let title = template_title(first);
    let labels = vec![
        "swarm-template".to_string(),
        first.blocker_kind.label().to_string(),
        "validation".to_string(),
    ];
    let description = template_description(dedupe_key, first, evidence.as_slice());
    let suggested_br_create = format!(
        "br create --type bug --priority 2 --labels {} --description {} {}",
        shell_quote(&labels.join(",")),
        shell_quote(&description),
        shell_quote(&title)
    );

    SwarmBeadTemplate {
        template_id: format!("sbt-{}", normalize_key_part(dedupe_key)),
        dedupe_key: dedupe_key.to_string(),
        blocker_kind: first.blocker_kind,
        title,
        description,
        priority: 2,
        labels,
        source_observation_ids,
        evidence,
        suggested_br_create,
    }
}

fn template_title(observation: &SwarmProofObservation) -> String {
    let target = observation
        .file_path
        .as_deref()
        .filter(|path| !path.trim().is_empty())
        .or(observation.error_code.as_deref())
        .unwrap_or(observation.source_bead_id.as_str());
    match observation.blocker_kind {
        SwarmBlockerKind::CompileDrift => {
            format!("Template: compile drift blocker for {target}")
        }
        SwarmBlockerKind::RchStall => format!("Template: RCH stall recovery for {target}"),
        SwarmBlockerKind::CargoContention => {
            format!("Template: cargo contention backoff for {target}")
        }
        SwarmBlockerKind::StaleAssignee => {
            format!("Template: stale assignee recovery for {target}")
        }
        SwarmBlockerKind::MissingArtifact => {
            format!("Template: missing artifact evidence for {target}")
        }
        SwarmBlockerKind::FalsePositiveScannerWarning => {
            format!("Template: scanner false-positive evidence for {target}")
        }
    }
}

fn template_description(
    dedupe_key: &str,
    first: &SwarmProofObservation,
    evidence: &[SwarmTemplateEvidence],
) -> String {
    let mut description = format!(
        "Dedupe key: {dedupe_key}\n\nObserved blocker class: {}\nResolution pattern: {}\n\n",
        first.blocker_kind.as_str(),
        first.resolution_pattern
    );
    description.push_str("Exact blocker evidence:\n");
    for item in evidence {
        let _ = write!(
            description,
            "- source_bead={} command=`{}`",
            item.source_bead_id, item.command
        );
        if let Some(error_code) = &item.error_code {
            let _ = write!(description, " error_code=`{error_code}`");
        }
        if let Some(file_path) = &item.file_path {
            let _ = write!(description, " file_path=`{file_path}`");
        }
        let _ = writeln!(description, " evidence=`{}`", item.evidence_excerpt);
    }
    description.push_str(
        "\nAcceptance:\n- Generated bead preserves exact command, error code, path, and blocker excerpt.\n- Dedupe check searches existing beads for the dedupe key before creating new work.\n- Closeout records whether the issue was product code, worker infra, contention, missing evidence, stale ownership, or scanner noise.",
    );
    description
}

fn shell_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\\''"))
}
