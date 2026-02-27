#![forbid(unsafe_code)]
extern crate self as frankenengine_node;

pub mod api;
pub mod claims;
mod cli;
mod config;
pub mod conformance;
pub mod connector;
pub mod control_plane;
pub mod encoding;
pub mod extensions;
pub mod federation;
pub mod migration;
pub mod observability;
pub mod ops;
pub mod perf;
pub mod policy;
pub mod registry;
pub mod remote;
pub mod repair;
pub mod replay;
pub mod runtime;
pub mod sdk;
pub mod security;
pub mod storage;
pub mod supply_chain;
pub mod testing;
pub mod tools;
pub mod verifier_economy;

use anyhow::{Context, Result};
use clap::Parser;
use serde::{Deserialize, Serialize};
use sha2::Digest;
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::time::Instant;

use api::trust_card_routes::{
    Pagination, compare_trust_card_versions, compare_trust_cards, get_trust_card,
    get_trust_cards_by_publisher, list_trust_cards, search_trust_cards,
};
use api::{
    fleet_quarantine::{
        FleetActionResult, FleetStatus, ReleaseRequest, handle_reconcile as handle_fleet_reconcile,
        handle_release as handle_fleet_release, handle_status as handle_fleet_status,
    },
    middleware::{AuthIdentity, AuthMethod, TraceContext},
};
use cli::{
    BenchCommand, Cli, Command, FleetCommand, IncidentCommand, MigrateCommand, RegistryCommand,
    RemoteCapCommand, RemoteCapIssueArgs, TrustCardCommand, TrustCommand, VerifyCommand,
    VerifyReleaseArgs,
};
use config::{CliOverrides, Profile};
use policy::bayesian_diagnostics::{BayesianDiagnostics, CandidateRef, Observation};
use policy::decision_engine::{DecisionEngine, DecisionOutcome, DecisionReason};
use policy::guardrail_monitor::{
    GuardrailCertificate, GuardrailFinding, GuardrailMonitorSet, GuardrailVerdict,
    MemoryTailRiskTelemetry, ReliabilityTelemetry, SystemState,
};
use policy::hardening_state_machine::HardeningLevel;
use policy::policy_explainer::{
    PolicyExplainer, PolicyExplanation, WordingValidation, validate_wording,
};
use security::decision_receipt::{
    Decision, Receipt, ReceiptQuery, append_signed_receipt, demo_signing_key,
    export_receipts_to_path, write_receipts_markdown,
};
use security::remote_cap::{CapabilityProvider, RemoteOperation, RemoteScope};
use supply_chain::extension_registry::{
    ExtensionSignature, ExtensionStatus, ProvenanceAttestation, RegistrationRequest,
    SignedExtension, SignedExtensionRegistry, VersionEntry,
};
use supply_chain::trust_card::{
    ReputationTrend, RevocationStatus, RiskAssessment, RiskLevel, TrustCard, TrustCardListFilter,
    TrustCardMutation, TrustCardRegistry, demo_registry as demo_trust_registry,
    render_comparison_human, render_trust_card_human, to_canonical_json as trust_card_to_json,
};
use tools::benchmark_suite::{
    render_human_summary as benchmark_suite_render_human_summary,
    run_default_suite as benchmark_suite_run_default_suite,
    to_canonical_json as benchmark_suite_to_json,
};
use tools::counterfactual_replay::{
    CounterfactualReplayEngine, PolicyConfig, summarize_output,
    to_canonical_json as counterfactual_to_json,
};
use tools::replay_bundle::{
    generate_replay_bundle, read_bundle_from_path, replay_bundle as replay_incident_bundle,
    sample_incident_events, validate_bundle_integrity, write_bundle_to_path,
};

const PROFILE_EXAMPLES_TEMPLATE: &str =
    include_str!("../../../config/franken_node.profile_examples.toml");
const VERIFY_CLI_CONTRACT_VERSION: &str = "2.0.0";
const VERIFY_CLI_CONTRACT_MAJOR: u16 = 2;

#[derive(Debug, Serialize)]
struct VerifyContractStubOutput {
    command: String,
    contract_version: String,
    schema_version: String,
    compat_version: Option<u16>,
    verdict: String,
    status: String,
    exit_code: i32,
    reason: String,
}

fn maybe_export_demo_receipts(
    action_name: &str,
    actor_identity: &str,
    rationale: &str,
    receipt_out: Option<&Path>,
    receipt_summary_out: Option<&Path>,
) -> Result<()> {
    if receipt_out.is_none() && receipt_summary_out.is_none() {
        return Ok(());
    }

    let mut chain = Vec::new();
    let key = demo_signing_key();

    let receipt = Receipt::new(
        action_name,
        actor_identity,
        &serde_json::json!({
            "command": action_name,
            "actor": actor_identity,
        }),
        &serde_json::json!({
            "status": "accepted",
            "receipt_exported": true,
        }),
        Decision::Approved,
        rationale,
        vec!["ledger:pending-10.14".to_string()],
        vec!["policy.rule.high-impact-receipt".to_string()],
        0.93,
        "franken-node trust sync --force",
    )?;
    append_signed_receipt(&mut chain, receipt, &key)?;

    let filter = ReceiptQuery::default();
    if let Some(path) = receipt_out {
        export_receipts_to_path(&chain, &filter, path)
            .with_context(|| format!("failed writing receipt export to {}", path.display()))?;
    }
    if let Some(path) = receipt_summary_out {
        write_receipts_markdown(&chain, path)
            .with_context(|| format!("failed writing receipt summary to {}", path.display()))?;
    }

    Ok(())
}

fn incident_bundle_output_path(incident_id: &str) -> PathBuf {
    let mut slug = String::new();
    for ch in incident_id.chars() {
        if ch.is_ascii_alphanumeric() || ch == '-' || ch == '_' {
            slug.push(ch);
        } else {
            slug.push('_');
        }
    }
    if slug.is_empty() {
        slug.push_str("incident");
    }
    PathBuf::from(format!("{}.fnbundle", slug))
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct IncidentListEntry {
    incident_id: String,
    severity: String,
    event_count: usize,
    created_at: String,
    path: String,
}

fn normalize_incident_severity_label(raw: &str) -> Option<&'static str> {
    let normalized = raw.trim().to_ascii_lowercase();
    match normalized.as_str() {
        "low" => Some("low"),
        "medium" => Some("medium"),
        "high" => Some("high"),
        "critical" => Some("critical"),
        "unknown" => Some("unknown"),
        _ => None,
    }
}

fn parse_incident_severity_filter(raw: Option<&str>) -> Result<Option<String>> {
    raw.map(|value| {
        normalize_incident_severity_label(value)
            .map(str::to_string)
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "invalid --severity `{value}`; expected one of: low, medium, high, critical, unknown"
                )
            })
    })
    .transpose()
}

fn should_skip_bundle_scan_dir(path: &Path) -> bool {
    path.file_name()
        .and_then(std::ffi::OsStr::to_str)
        .is_some_and(|name| {
            matches!(
                name,
                ".git" | ".beads" | "target" | "node_modules" | ".venv" | ".next"
            )
        })
}

fn collect_incident_bundle_paths(root: &Path) -> Result<Vec<PathBuf>> {
    let mut bundles = Vec::new();
    let mut pending = vec![root.to_path_buf()];

    while let Some(dir) = pending.pop() {
        let entries = std::fs::read_dir(&dir)
            .with_context(|| format!("failed reading directory {}", dir.display()))?;
        for entry in entries {
            let entry =
                entry.with_context(|| format!("failed reading entry in {}", dir.display()))?;
            let path = entry.path();
            if path.is_dir() {
                if should_skip_bundle_scan_dir(&path) {
                    continue;
                }
                pending.push(path);
                continue;
            }
            if path.is_file()
                && path
                    .extension()
                    .and_then(std::ffi::OsStr::to_str)
                    .is_some_and(|ext| ext.eq_ignore_ascii_case("fnbundle"))
            {
                bundles.push(path);
            }
        }
    }

    bundles.sort();
    Ok(bundles)
}

fn infer_incident_bundle_severity(bundle: &tools::replay_bundle::ReplayBundle) -> String {
    for event in &bundle.timeline {
        let candidate = event
            .payload
            .get("severity")
            .and_then(serde_json::Value::as_str)
            .or_else(|| {
                event
                    .payload
                    .get("risk")
                    .and_then(serde_json::Value::as_str)
            })
            .or_else(|| {
                event
                    .payload
                    .get("risk_level")
                    .and_then(serde_json::Value::as_str)
            });

        if let Some(label) = candidate
            && let Some(normalized) = normalize_incident_severity_label(label)
        {
            return normalized.to_string();
        }
    }
    "unknown".to_string()
}

fn collect_incident_list_entries(
    root: &Path,
    severity_filter: Option<&str>,
) -> Result<Vec<IncidentListEntry>> {
    let mut entries = Vec::new();

    for path in collect_incident_bundle_paths(root)? {
        let bundle = read_bundle_from_path(&path)
            .with_context(|| format!("failed reading incident bundle {}", path.display()))?;
        let severity = infer_incident_bundle_severity(&bundle);
        if let Some(filter) = severity_filter
            && severity != filter
        {
            continue;
        }
        let display_path = path
            .strip_prefix(root)
            .unwrap_or(&path)
            .display()
            .to_string();
        entries.push(IncidentListEntry {
            incident_id: bundle.incident_id,
            severity,
            event_count: bundle.manifest.event_count,
            created_at: bundle.created_at,
            path: display_path,
        });
    }

    entries.sort_by(|left, right| {
        left.incident_id
            .cmp(&right.incident_id)
            .then_with(|| left.path.cmp(&right.path))
    });
    Ok(entries)
}

fn render_incident_list(entries: &[IncidentListEntry], severity_filter: Option<&str>) -> String {
    if entries.is_empty() {
        return match severity_filter {
            Some(filter) => format!("incident list: no bundles found for severity={filter}"),
            None => "incident list: no bundles found".to_string(),
        };
    }

    let mut lines = Vec::new();
    lines.push(format!("incident list: count={}", entries.len()));
    if let Some(filter) = severity_filter {
        lines.push(format!("severity_filter={filter}"));
    }
    lines.push("incident_id | severity | events | created_at | path".to_string());
    lines.push("----------- | -------- | ------ | ---------- | ----".to_string());
    for entry in entries {
        lines.push(format!(
            "{} | {} | {} | {} | {}",
            entry.incident_id, entry.severity, entry.event_count, entry.created_at, entry.path
        ));
    }
    lines.join("\n")
}

fn now_unix_secs() -> u64 {
    let ts = chrono::Utc::now().timestamp();
    if ts <= 0 { 0 } else { ts as u64 }
}

fn parse_ttl_secs(ttl: &str) -> Result<u64> {
    let raw = ttl.trim();
    if raw.is_empty() {
        anyhow::bail!("ttl cannot be empty");
    }

    let (numeric, multiplier) = match raw.chars().last() {
        Some('s') | Some('S') => (&raw[..raw.len() - 1], 1_u64),
        Some('m') | Some('M') => (&raw[..raw.len() - 1], 60_u64),
        Some('h') | Some('H') => (&raw[..raw.len() - 1], 3_600_u64),
        Some('d') | Some('D') => (&raw[..raw.len() - 1], 86_400_u64),
        _ => (raw, 1_u64),
    };

    let base = numeric
        .trim()
        .parse::<u64>()
        .with_context(|| format!("invalid ttl value: `{raw}`"))?;
    base.checked_mul(multiplier)
        .ok_or_else(|| anyhow::anyhow!("ttl overflow for `{raw}`"))
}

fn parse_remote_operation(token: &str) -> Result<RemoteOperation> {
    let normalized = token.trim().to_ascii_lowercase().replace('-', "_");
    let op = match normalized.as_str() {
        "network_egress" => RemoteOperation::NetworkEgress,
        "federation_sync" => RemoteOperation::FederationSync,
        "revocation_fetch" => RemoteOperation::RevocationFetch,
        "remote_attestation_verify" => RemoteOperation::RemoteAttestationVerify,
        "telemetry_export" => RemoteOperation::TelemetryExport,
        "remote_computation" => RemoteOperation::RemoteComputation,
        "artifact_upload" => RemoteOperation::ArtifactUpload,
        _ => {
            anyhow::bail!(
                "unknown operation `{token}`; expected one of: network_egress,federation_sync,revocation_fetch,remote_attestation_verify,telemetry_export,remote_computation,artifact_upload"
            )
        }
    };
    Ok(op)
}

fn parse_profile_override(raw: Option<&str>) -> Result<Option<Profile>> {
    raw.map(|value| {
        value
            .parse::<Profile>()
            .map_err(|err| anyhow::anyhow!(err.to_string()))
    })
    .transpose()
}

fn write_migration_report_file(
    rendered: &str,
    out_path: &Path,
    report_label: &str,
) -> Result<PathBuf> {
    if let Some(parent) = out_path.parent()
        && !parent.as_os_str().is_empty()
    {
        std::fs::create_dir_all(parent).with_context(|| {
            format!(
                "failed creating output directory {} for {report_label}",
                parent.display()
            )
        })?;
    }
    std::fs::write(out_path, rendered.as_bytes())
        .with_context(|| format!("failed writing {report_label} to {}", out_path.display()))?;
    Ok(out_path.to_path_buf())
}

fn emit_migration_audit_report(rendered: &str, out_path: Option<&Path>) -> Result<Option<PathBuf>> {
    if let Some(out_path) = out_path {
        return write_migration_report_file(rendered, out_path, "migrate audit report").map(Some);
    }

    println!("{rendered}");
    Ok(None)
}

fn handle_bench_run(args: &cli::BenchRunArgs) -> Result<()> {
    let report = benchmark_suite_run_default_suite(args.scenario.as_deref())
        .map_err(|err| anyhow::anyhow!("benchmark suite run failed: {err}"))?;
    println!("{}", benchmark_suite_to_json(&report));
    eprintln!("{}", benchmark_suite_render_human_summary(&report));
    Ok(())
}

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum InitFileActionKind {
    Created,
    Overwritten,
    BackedUpAndOverwritten,
}

#[derive(Debug, Clone, Serialize)]
struct InitFileAction {
    path: String,
    action: InitFileActionKind,
    backup_path: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
struct InitReport {
    command: String,
    trace_id: String,
    generated_at_utc: String,
    selected_profile: String,
    source_path: Option<String>,
    wrote_to_stdout: bool,
    stdout_config_toml: Option<String>,
    file_actions: Vec<InitFileAction>,
    merge_decision_count: usize,
    merge_decisions: Vec<config::MergeDecision>,
}

fn validate_init_flags(overwrite: bool, backup_existing: bool) -> Result<()> {
    if overwrite && backup_existing {
        anyhow::bail!("--overwrite and --backup-existing are mutually exclusive");
    }
    Ok(())
}

fn build_backup_path(path: &Path, timestamp_suffix: &str) -> PathBuf {
    let mut index = 0usize;
    loop {
        let candidate = if index == 0 {
            PathBuf::from(format!("{}.bak.{timestamp_suffix}", path.display()))
        } else {
            PathBuf::from(format!("{}.bak.{timestamp_suffix}.{index}", path.display()))
        };
        if !candidate.exists() {
            return candidate;
        }
        index += 1;
    }
}

fn apply_init_write_policy(
    path: &Path,
    content: &str,
    overwrite: bool,
    backup_existing: bool,
    timestamp_suffix: &str,
) -> Result<InitFileAction> {
    if path.exists() {
        if backup_existing {
            let backup_path = build_backup_path(path, timestamp_suffix);
            std::fs::copy(path, &backup_path).with_context(|| {
                format!(
                    "failed creating backup {} from {}",
                    backup_path.display(),
                    path.display()
                )
            })?;
            std::fs::write(path, content)
                .with_context(|| format!("failed writing {}", path.display()))?;
            return Ok(InitFileAction {
                path: path.display().to_string(),
                action: InitFileActionKind::BackedUpAndOverwritten,
                backup_path: Some(backup_path.display().to_string()),
            });
        }
        if overwrite {
            std::fs::write(path, content)
                .with_context(|| format!("failed writing {}", path.display()))?;
            return Ok(InitFileAction {
                path: path.display().to_string(),
                action: InitFileActionKind::Overwritten,
                backup_path: None,
            });
        }
        anyhow::bail!(
            "refusing to overwrite existing file {} without --overwrite or --backup-existing",
            path.display()
        );
    }

    std::fs::write(path, content).with_context(|| format!("failed writing {}", path.display()))?;
    Ok(InitFileAction {
        path: path.display().to_string(),
        action: InitFileActionKind::Created,
        backup_path: None,
    })
}

fn init_target_paths(out_dir: &Path) -> (PathBuf, PathBuf) {
    (
        out_dir.join("franken_node.toml"),
        out_dir.join("franken_node.profile_examples.toml"),
    )
}

fn build_init_report(
    trace_id: &str,
    resolved: &config::ResolvedConfig,
    file_actions: Vec<InitFileAction>,
    wrote_to_stdout: bool,
    stdout_config_toml: Option<String>,
) -> InitReport {
    InitReport {
        command: "init".to_string(),
        trace_id: trace_id.to_string(),
        generated_at_utc: chrono::Utc::now().to_rfc3339(),
        selected_profile: resolved.selected_profile.to_string(),
        source_path: resolved
            .source_path
            .as_ref()
            .map(|path| path.display().to_string()),
        wrote_to_stdout,
        stdout_config_toml,
        file_actions,
        merge_decision_count: resolved.decisions.len(),
        merge_decisions: resolved.decisions.clone(),
    }
}

fn render_init_report_human(report: &InitReport, verbose: bool) -> String {
    let mut lines = Vec::new();
    lines.push(format!(
        "franken-node init: profile={} trace_id={}",
        report.selected_profile, report.trace_id
    ));
    lines.push(format!(
        "source={}",
        report
            .source_path
            .clone()
            .unwrap_or_else(|| "<defaults>".to_string())
    ));
    lines.push(format!("wrote_to_stdout={}", report.wrote_to_stdout));
    if let Some(config_toml) = &report.stdout_config_toml {
        lines.push(format!("stdout_config_toml_bytes={}", config_toml.len()));
    }
    if report.file_actions.is_empty() {
        lines.push("file_actions=<none>".to_string());
    } else {
        lines.push("file_actions:".to_string());
        for action in &report.file_actions {
            lines.push(format!(
                "  action={:?} path={} backup={}",
                action.action,
                action.path,
                action
                    .backup_path
                    .clone()
                    .unwrap_or_else(|| "<none>".to_string())
            ));
        }
    }

    if verbose {
        lines.push(format!(
            "generated_at={} merge_decision_count={}",
            report.generated_at_utc, report.merge_decision_count
        ));
        for decision in &report.merge_decisions {
            lines.push(format!(
                "  merge_decision stage={:?} field={} value={}",
                decision.stage, decision.field, decision.value
            ));
        }
    }
    lines.join("\n")
}

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum DoctorGuardrailVerdictKind {
    Allow,
    Warn,
    Block,
}

impl DoctorGuardrailVerdictKind {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Allow => "allow",
            Self::Warn => "warn",
            Self::Block => "block",
        }
    }
}

#[derive(Debug, Clone, Serialize)]
struct DoctorGuardrailFindingReport {
    monitor_name: String,
    budget_id: String,
    verdict: DoctorGuardrailVerdictKind,
    event_code: String,
    anytime_valid: bool,
    reason: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
struct DoctorGuardrailCertificateReport {
    epoch_id: u64,
    dominant_verdict: DoctorGuardrailVerdictKind,
    findings: Vec<DoctorGuardrailFindingReport>,
    blocking_budget_ids: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
struct DoctorPolicyActivationReport {
    input_path: String,
    candidate_count: usize,
    observation_count: usize,
    prefiltered_candidate_count: usize,
    top_ranked_candidate: Option<String>,
    guardrail_certificate: DoctorGuardrailCertificateReport,
    decision_outcome: DecisionOutcome,
    explanation: PolicyExplanation,
    wording_validation: WordingValidation,
}

#[derive(Debug, Deserialize)]
struct DoctorPolicyMemoryTailRiskInput {
    sample_count: u64,
    mean_utilization: f64,
    variance_utilization: f64,
    peak_utilization: f64,
}

#[derive(Debug, Deserialize)]
struct DoctorPolicyReliabilityTelemetryInput {
    sample_count: u64,
    nonconforming_count: u64,
}

#[derive(Debug, Deserialize)]
struct DoctorPolicySystemStateInput {
    memory_used_bytes: u64,
    memory_budget_bytes: u64,
    durability_level: f64,
    hardening_level: String,
    #[serde(default)]
    proposed_hardening_level: Option<String>,
    #[serde(default = "doctor_policy_default_evidence_emission_active")]
    evidence_emission_active: bool,
    #[serde(default)]
    memory_tail_risk: Option<DoctorPolicyMemoryTailRiskInput>,
    #[serde(default)]
    reliability_telemetry: Option<DoctorPolicyReliabilityTelemetryInput>,
    #[serde(default)]
    epoch_id: Option<u64>,
}

#[derive(Debug, Deserialize)]
struct DoctorPolicyObservationInput {
    candidate: String,
    success: bool,
    #[serde(default)]
    epoch_id: Option<u64>,
}

#[derive(Debug, Deserialize)]
struct DoctorPolicyActivationInput {
    #[serde(default)]
    epoch_id: Option<u64>,
    system_state: DoctorPolicySystemStateInput,
    candidates: Vec<String>,
    #[serde(default)]
    prefiltered_candidates: Vec<String>,
    #[serde(default)]
    observations: Vec<DoctorPolicyObservationInput>,
}

const fn doctor_policy_default_evidence_emission_active() -> bool {
    true
}

fn parse_hardening_level(label: &str, field: &str) -> Result<HardeningLevel> {
    let normalized = label.trim().to_ascii_lowercase();
    HardeningLevel::from_label(&normalized).ok_or_else(|| {
        anyhow::anyhow!(
            "invalid {} `{}`; expected one of: baseline, standard, enhanced, maximum, critical",
            field,
            label
        )
    })
}

fn map_guardrail_verdict(verdict: &GuardrailVerdict) -> DoctorGuardrailVerdictKind {
    match verdict {
        GuardrailVerdict::Allow => DoctorGuardrailVerdictKind::Allow,
        GuardrailVerdict::Warn { .. } => DoctorGuardrailVerdictKind::Warn,
        GuardrailVerdict::Block { .. } => DoctorGuardrailVerdictKind::Block,
    }
}

fn guardrail_reason(verdict: &GuardrailVerdict) -> Option<String> {
    match verdict {
        GuardrailVerdict::Allow => None,
        GuardrailVerdict::Warn { reason } => Some(reason.clone()),
        GuardrailVerdict::Block { reason, .. } => Some(reason.clone()),
    }
}

fn map_guardrail_finding(finding: &GuardrailFinding) -> DoctorGuardrailFindingReport {
    DoctorGuardrailFindingReport {
        monitor_name: finding.monitor_name.clone(),
        budget_id: finding.budget_id.as_str().to_string(),
        verdict: map_guardrail_verdict(&finding.verdict),
        event_code: finding.event_code.to_string(),
        anytime_valid: finding.anytime_valid,
        reason: guardrail_reason(&finding.verdict),
    }
}

fn map_guardrail_certificate(
    certificate: &GuardrailCertificate,
) -> DoctorGuardrailCertificateReport {
    DoctorGuardrailCertificateReport {
        epoch_id: certificate.epoch_id,
        dominant_verdict: map_guardrail_verdict(&certificate.dominant_verdict),
        findings: certificate
            .findings
            .iter()
            .map(map_guardrail_finding)
            .collect(),
        blocking_budget_ids: certificate
            .blocking_budget_ids
            .iter()
            .map(|id| id.as_str().to_string())
            .collect(),
    }
}

fn load_doctor_policy_activation_input(path: &Path) -> Result<DoctorPolicyActivationInput> {
    let raw = std::fs::read_to_string(path)
        .with_context(|| format!("failed reading policy activation input {}", path.display()))?;
    let input = serde_json::from_str::<DoctorPolicyActivationInput>(&raw).with_context(|| {
        format!(
            "failed parsing policy activation input {} as JSON",
            path.display()
        )
    })?;
    Ok(input)
}

fn build_system_state(input: &DoctorPolicyActivationInput) -> Result<SystemState> {
    let epoch_id = input
        .system_state
        .epoch_id
        .or(input.epoch_id)
        .unwrap_or_default();

    let hardening_level =
        parse_hardening_level(&input.system_state.hardening_level, "hardening_level")?;
    let proposed_hardening_level = input
        .system_state
        .proposed_hardening_level
        .as_ref()
        .map(|label| parse_hardening_level(label, "proposed_hardening_level"))
        .transpose()?;

    let memory_tail_risk =
        input
            .system_state
            .memory_tail_risk
            .as_ref()
            .map(|raw| MemoryTailRiskTelemetry {
                sample_count: raw.sample_count,
                mean_utilization: raw.mean_utilization,
                variance_utilization: raw.variance_utilization,
                peak_utilization: raw.peak_utilization,
            });

    let reliability_telemetry = input
        .system_state
        .reliability_telemetry
        .as_ref()
        .map(|raw| ReliabilityTelemetry {
            sample_count: raw.sample_count,
            nonconforming_count: raw.nonconforming_count,
        });

    Ok(SystemState {
        memory_used_bytes: input.system_state.memory_used_bytes,
        memory_budget_bytes: input.system_state.memory_budget_bytes,
        durability_level: input.system_state.durability_level,
        hardening_level,
        proposed_hardening_level,
        evidence_emission_active: input.system_state.evidence_emission_active,
        memory_tail_risk,
        reliability_telemetry,
        epoch_id,
    })
}

fn normalize_candidate_ids(raw_candidates: &[String], field: &str) -> Result<Vec<CandidateRef>> {
    let mut unique = std::collections::BTreeSet::new();
    let mut candidates = Vec::new();

    for raw in raw_candidates {
        let candidate = raw.trim();
        if candidate.is_empty() {
            anyhow::bail!("{field} contains an empty candidate identifier");
        }
        if unique.insert(candidate.to_string()) {
            candidates.push(CandidateRef::new(candidate));
        }
    }

    Ok(candidates)
}

fn required_candidate_ids(raw_candidates: &[String], field: &str) -> Result<Vec<CandidateRef>> {
    let candidates = normalize_candidate_ids(raw_candidates, field)?;
    if candidates.is_empty() {
        anyhow::bail!("{field} must include at least one candidate identifier");
    }
    Ok(candidates)
}

fn build_observations(
    input: &DoctorPolicyActivationInput,
    epoch_id: u64,
) -> Result<Vec<Observation>> {
    let mut observations = Vec::with_capacity(input.observations.len());
    for raw in &input.observations {
        let candidate = raw.candidate.trim();
        if candidate.is_empty() {
            anyhow::bail!("observations contains an empty candidate identifier");
        }
        observations.push(Observation::new(
            CandidateRef::new(candidate),
            raw.success,
            raw.epoch_id.unwrap_or(epoch_id),
        ));
    }
    Ok(observations)
}

fn run_doctor_policy_activation(path: &Path) -> Result<DoctorPolicyActivationReport> {
    let input = load_doctor_policy_activation_input(path)?;
    let system_state = build_system_state(&input)?;
    let candidate_refs = required_candidate_ids(&input.candidates, "candidates")?;
    let prefiltered_refs =
        normalize_candidate_ids(&input.prefiltered_candidates, "prefiltered_candidates")?;
    let observations = build_observations(&input, system_state.epoch_id)?;

    let diagnostics = BayesianDiagnostics::replay_from(&observations);
    let ranked = diagnostics.rank_candidates(&candidate_refs, &prefiltered_refs);
    let top_ranked_candidate = ranked.first().map(|entry| entry.candidate_ref.0.clone());

    let monitors = GuardrailMonitorSet::with_defaults();
    let certificate = monitors.certify(&system_state);
    let decision_outcome =
        DecisionEngine::new(system_state.epoch_id).decide(&ranked, &monitors, &system_state);
    let explanation = PolicyExplainer::explain(&decision_outcome, &diagnostics);
    let wording_validation = validate_wording(&explanation);

    Ok(DoctorPolicyActivationReport {
        input_path: path.display().to_string(),
        candidate_count: candidate_refs.len(),
        observation_count: observations.len(),
        prefiltered_candidate_count: prefiltered_refs.len(),
        top_ranked_candidate,
        guardrail_certificate: map_guardrail_certificate(&certificate),
        decision_outcome,
        explanation,
        wording_validation,
    })
}

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
enum DoctorStatus {
    Pass,
    Warn,
    Fail,
}

impl DoctorStatus {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Pass => "PASS",
            Self::Warn => "WARN",
            Self::Fail => "FAIL",
        }
    }
}

#[derive(Debug, Clone, Serialize)]
struct DoctorCheck {
    code: String,
    event_code: String,
    scope: String,
    status: DoctorStatus,
    message: String,
    remediation: String,
    duration_ms: u64,
}

#[derive(Debug, Clone, Serialize)]
struct DoctorLogEvent {
    trace_id: String,
    event_code: String,
    check_code: String,
    scope: String,
    status: DoctorStatus,
    duration_ms: u64,
}

#[derive(Debug, Clone, Serialize)]
struct DoctorStatusCounts {
    pass: usize,
    warn: usize,
    fail: usize,
}

#[derive(Debug, Clone, Serialize)]
struct DoctorReport {
    command: String,
    trace_id: String,
    generated_at_utc: String,
    selected_profile: String,
    source_path: Option<String>,
    overall_status: DoctorStatus,
    status_counts: DoctorStatusCounts,
    checks: Vec<DoctorCheck>,
    structured_logs: Vec<DoctorLogEvent>,
    merge_decision_count: usize,
    merge_decisions: Vec<config::MergeDecision>,
    #[serde(skip_serializing_if = "Option::is_none")]
    policy_activation: Option<DoctorPolicyActivationReport>,
}

fn summarize_statuses(checks: &[DoctorCheck]) -> (DoctorStatusCounts, DoctorStatus) {
    let pass = checks
        .iter()
        .filter(|check| matches!(check.status, DoctorStatus::Pass))
        .count();
    let warn = checks
        .iter()
        .filter(|check| matches!(check.status, DoctorStatus::Warn))
        .count();
    let fail = checks
        .iter()
        .filter(|check| matches!(check.status, DoctorStatus::Fail))
        .count();
    let overall = if fail > 0 {
        DoctorStatus::Fail
    } else if warn > 0 {
        DoctorStatus::Warn
    } else {
        DoctorStatus::Pass
    };
    (DoctorStatusCounts { pass, warn, fail }, overall)
}

fn evaluate_doctor_check(
    code: &str,
    event_code: &str,
    scope: &str,
    check: impl FnOnce() -> (DoctorStatus, String, String),
) -> DoctorCheck {
    let start = Instant::now();
    let (status, message, remediation) = check();
    DoctorCheck {
        code: code.to_string(),
        event_code: event_code.to_string(),
        scope: scope.to_string(),
        status,
        message,
        remediation,
        duration_ms: start.elapsed().as_millis() as u64,
    }
}

fn build_doctor_report(resolved: &config::ResolvedConfig, trace_id: &str) -> DoctorReport {
    build_doctor_report_with_cwd_and_policy_input(resolved, trace_id, std::env::current_dir(), None)
}

fn build_doctor_report_with_policy_input(
    resolved: &config::ResolvedConfig,
    trace_id: &str,
    policy_activation_input: Option<&Path>,
) -> DoctorReport {
    if let Some(path) = policy_activation_input {
        build_doctor_report_with_cwd_and_policy_input(
            resolved,
            trace_id,
            std::env::current_dir(),
            Some(path),
        )
    } else {
        build_doctor_report(resolved, trace_id)
    }
}

#[cfg(test)]
fn build_doctor_report_with_cwd(
    resolved: &config::ResolvedConfig,
    trace_id: &str,
    cwd_result: std::io::Result<PathBuf>,
) -> DoctorReport {
    build_doctor_report_with_cwd_and_policy_input(resolved, trace_id, cwd_result, None)
}

fn build_doctor_report_with_cwd_and_policy_input(
    resolved: &config::ResolvedConfig,
    trace_id: &str,
    cwd_result: std::io::Result<PathBuf>,
    policy_activation_input: Option<&Path>,
) -> DoctorReport {
    let source = resolved
        .source_path
        .as_ref()
        .map(|path| path.display().to_string());

    let mut checks: Vec<DoctorCheck> = vec![evaluate_doctor_check(
        "DR-CONFIG-001",
        "DOC-001",
        "config.resolve",
        || {
            (
                DoctorStatus::Pass,
                "Configuration resolved successfully.".to_string(),
                "No action required.".to_string(),
            )
        },
    )];

    if source.is_some() {
        checks.push(evaluate_doctor_check(
            "DR-CONFIG-002",
            "DOC-002",
            "config.source",
            || {
                (
                    DoctorStatus::Pass,
                    "Config source file discovered.".to_string(),
                    "No action required.".to_string(),
                )
            },
        ));
    } else {
        checks.push(evaluate_doctor_check(
            "DR-CONFIG-002",
            "DOC-002",
            "config.source",
            || {
                (
                    DoctorStatus::Warn,
                    "No config file discovered; defaults are active.".to_string(),
                    "Create franken_node.toml or pass --config to lock deterministic project settings.".to_string(),
                )
            },
        ));
    }

    if resolved.config.profile == Profile::LegacyRisky {
        checks.push(evaluate_doctor_check(
            "DR-PROFILE-003",
            "DOC-003",
            "profile.safety",
            || {
                (
                    DoctorStatus::Warn,
                    "Profile is legacy-risky.".to_string(),
                    "Prefer --profile balanced or --profile strict for stronger controls."
                        .to_string(),
                )
            },
        ));
    } else {
        checks.push(evaluate_doctor_check(
            "DR-PROFILE-003",
            "DOC-003",
            "profile.safety",
            || {
                (
                    DoctorStatus::Pass,
                    "Profile safety level is acceptable.".to_string(),
                    "No action required.".to_string(),
                )
            },
        ));
    }

    if resolved.config.registry.minimum_assurance_level >= 3 {
        checks.push(evaluate_doctor_check(
            "DR-TRUST-004",
            "DOC-004",
            "registry.assurance",
            || {
                (
                    DoctorStatus::Pass,
                    "Registry assurance level meets bootstrap target.".to_string(),
                    "No action required.".to_string(),
                )
            },
        ));
    } else {
        checks.push(evaluate_doctor_check(
            "DR-TRUST-004",
            "DOC-004",
            "registry.assurance",
            || {
                (
                    DoctorStatus::Warn,
                    "Registry assurance level is below bootstrap target (3).".to_string(),
                    "Raise registry.minimum_assurance_level to 3+.".to_string(),
                )
            },
        ));
    }

    if resolved.config.migration.require_lockstep_validation {
        checks.push(evaluate_doctor_check(
            "DR-MIGRATE-005",
            "DOC-005",
            "migration.lockstep",
            || {
                (
                    DoctorStatus::Pass,
                    "Lockstep validation requirement is enabled.".to_string(),
                    "No action required.".to_string(),
                )
            },
        ));
    } else {
        checks.push(evaluate_doctor_check(
            "DR-MIGRATE-005",
            "DOC-005",
            "migration.lockstep",
            || {
                (
                    DoctorStatus::Warn,
                    "Lockstep validation requirement is disabled.".to_string(),
                    "Set migration.require_lockstep_validation=true for safer rollout validation."
                        .to_string(),
                )
            },
        ));
    }

    if resolved.config.observability.emit_structured_audit_events {
        checks.push(evaluate_doctor_check(
            "DR-OBS-006",
            "DOC-006",
            "observability.audit_events",
            || {
                (
                    DoctorStatus::Pass,
                    "Structured audit events are enabled.".to_string(),
                    "No action required.".to_string(),
                )
            },
        ));
    } else {
        checks.push(evaluate_doctor_check(
            "DR-OBS-006",
            "DOC-006",
            "observability.audit_events",
            || {
                (
                    DoctorStatus::Warn,
                    "Structured audit events are disabled.".to_string(),
                    "Set observability.emit_structured_audit_events=true for stronger traceability.".to_string(),
                )
            },
        ));
    }

    match cwd_result {
        Ok(path) => checks.push(evaluate_doctor_check(
            "DR-ENV-007",
            "DOC-007",
            "environment.cwd",
            || {
                (
                    DoctorStatus::Pass,
                    format!("Current working directory is available: {}", path.display()),
                    "No action required.".to_string(),
                )
            },
        )),
        Err(err) => checks.push(evaluate_doctor_check(
            "DR-ENV-007",
            "DOC-007",
            "environment.cwd",
            || {
                (
                    DoctorStatus::Fail,
                    "Current working directory is unavailable.".to_string(),
                    format!("Fix working directory access before running operations ({err})."),
                )
            },
        )),
    }

    if resolved.decisions.is_empty() {
        checks.push(evaluate_doctor_check(
            "DR-CONFIG-008",
            "DOC-008",
            "config.provenance",
            || {
                (
                    DoctorStatus::Warn,
                    "No merge decisions recorded for this configuration.".to_string(),
                    "Investigate resolver instrumentation before relying on doctor provenance."
                        .to_string(),
                )
            },
        ));
    } else {
        checks.push(evaluate_doctor_check(
            "DR-CONFIG-008",
            "DOC-008",
            "config.provenance",
            || {
                (
                    DoctorStatus::Pass,
                    format!(
                        "Merge provenance recorded ({} decisions).",
                        resolved.decisions.len()
                    ),
                    "No action required.".to_string(),
                )
            },
        ));
    }

    let mut policy_activation = None;
    if let Some(input_path) = policy_activation_input {
        match run_doctor_policy_activation(input_path) {
            Ok(report) => {
                let dominant_verdict = report.guardrail_certificate.dominant_verdict;
                let blocked_budgets = report.guardrail_certificate.blocking_budget_ids.clone();
                let guardrail_status = match dominant_verdict {
                    DoctorGuardrailVerdictKind::Allow => DoctorStatus::Pass,
                    DoctorGuardrailVerdictKind::Warn => DoctorStatus::Warn,
                    DoctorGuardrailVerdictKind::Block => DoctorStatus::Fail,
                };
                checks.push(evaluate_doctor_check(
                    "DR-POLICY-009",
                    "DOC-009",
                    "policy.guardrails",
                    || {
                        let message = match dominant_verdict {
                            DoctorGuardrailVerdictKind::Allow => format!(
                                "Policy guardrails passed with dominant verdict {} across {} monitors.",
                                dominant_verdict.as_str(),
                                report.guardrail_certificate.findings.len()
                            ),
                            DoctorGuardrailVerdictKind::Warn => format!(
                                "Policy guardrails reported WARN with dominant verdict {} (blocking_budgets={}).",
                                dominant_verdict.as_str(),
                                blocked_budgets.len()
                            ),
                            DoctorGuardrailVerdictKind::Block => format!(
                                "Policy guardrails reported BLOCK with budgets: {}.",
                                blocked_budgets.join(", ")
                            ),
                        };
                        let remediation = match dominant_verdict {
                            DoctorGuardrailVerdictKind::Allow => "No action required.".to_string(),
                            DoctorGuardrailVerdictKind::Warn => {
                                "Review high-risk telemetry before promoting aggressive policy actions."
                                    .to_string()
                            }
                            DoctorGuardrailVerdictKind::Block => {
                                "Resolve blocked budgets before executing policy actions."
                                    .to_string()
                            }
                        };
                        (guardrail_status, message, remediation)
                    },
                ));

                let decision_reason = report.decision_outcome.reason.clone();
                let chosen_candidate = report.decision_outcome.chosen.as_ref().map(|c| c.0.clone());
                checks.push(evaluate_doctor_check(
                    "DR-POLICY-010",
                    "DOC-010",
                    "policy.decision_engine",
                    || {
                        let (status, message, remediation) = match decision_reason {
                            DecisionReason::TopCandidateAccepted => (
                                DoctorStatus::Pass,
                                format!(
                                    "Decision engine selected top candidate `{}`.",
                                    chosen_candidate.clone().unwrap_or_else(|| "unknown".to_string())
                                ),
                                "No action required.".to_string(),
                            ),
                            DecisionReason::TopCandidateBlockedFallbackUsed { fallback_rank } => (
                                DoctorStatus::Warn,
                                format!(
                                    "Decision engine used fallback candidate `{}` at rank {}.",
                                    chosen_candidate.clone().unwrap_or_else(|| "unknown".to_string()),
                                    fallback_rank
                                ),
                                "Inspect blocked higher-ranked candidates before rollout."
                                    .to_string(),
                            ),
                            DecisionReason::AllCandidatesBlocked => (
                                DoctorStatus::Fail,
                                "Decision engine blocked all candidates after guardrail evaluation."
                                    .to_string(),
                                "Reduce risk exposure or provide safer candidate actions."
                                    .to_string(),
                            ),
                            DecisionReason::NoCandidates => (
                                DoctorStatus::Fail,
                                "Decision engine received no candidates from policy activation input."
                                    .to_string(),
                                "Populate `candidates` with at least one viable policy action."
                                    .to_string(),
                            ),
                        };
                        (status, message, remediation)
                    },
                ));

                let wording_valid = report.wording_validation.valid;
                let violations = report.wording_validation.violations.clone();
                checks.push(evaluate_doctor_check(
                    "DR-POLICY-011",
                    "DOC-011",
                    "policy.explainer_wording",
                    || {
                        if wording_valid {
                            (
                                DoctorStatus::Pass,
                                "Policy explanation wording passed diagnostic/guarantee separation checks."
                                    .to_string(),
                                "No action required.".to_string(),
                            )
                        } else {
                            (
                                DoctorStatus::Fail,
                                format!(
                                    "Policy explanation wording validation failed (violations={}).",
                                    violations.join("; ")
                                ),
                                "Fix explanation wording to preserve diagnostic vs guarantee separation."
                                    .to_string(),
                            )
                        }
                    },
                ));

                policy_activation = Some(report);
            }
            Err(err) => {
                let detail = err.to_string();
                checks.push(evaluate_doctor_check(
                    "DR-POLICY-009",
                    "DOC-009",
                    "policy.guardrails",
                    || {
                        (
                            DoctorStatus::Fail,
                            format!("Policy activation input failed to load: {detail}"),
                            "Provide a valid JSON input via --policy-activation-input.".to_string(),
                        )
                    },
                ));
                checks.push(evaluate_doctor_check(
                    "DR-POLICY-010",
                    "DOC-010",
                    "policy.decision_engine",
                    || {
                        (
                            DoctorStatus::Fail,
                            "Decision engine check skipped because policy activation input failed."
                                .to_string(),
                            "Fix policy activation input errors first.".to_string(),
                        )
                    },
                ));
                checks.push(evaluate_doctor_check(
                    "DR-POLICY-011",
                    "DOC-011",
                    "policy.explainer_wording",
                    || {
                        (
                            DoctorStatus::Fail,
                            "Policy explanation check skipped because decision pipeline did not run."
                                .to_string(),
                            "Fix policy activation input errors first.".to_string(),
                        )
                    },
                ));
            }
        }
    }

    let (status_counts, overall_status) = summarize_statuses(&checks);
    let structured_logs = checks
        .iter()
        .map(|check| DoctorLogEvent {
            trace_id: trace_id.to_string(),
            event_code: check.event_code.clone(),
            check_code: check.code.clone(),
            scope: check.scope.clone(),
            status: check.status,
            duration_ms: check.duration_ms,
        })
        .collect::<Vec<_>>();

    DoctorReport {
        command: "doctor".to_string(),
        trace_id: trace_id.to_string(),
        generated_at_utc: chrono::Utc::now().to_rfc3339(),
        selected_profile: resolved.selected_profile.to_string(),
        source_path: source,
        overall_status,
        status_counts,
        checks,
        structured_logs,
        merge_decision_count: resolved.decisions.len(),
        merge_decisions: resolved.decisions.clone(),
        policy_activation,
    }
}

fn render_doctor_report_human(report: &DoctorReport, verbose: bool) -> String {
    let mut lines = Vec::new();
    lines.push(format!(
        "franken-node doctor: overall={} profile={} trace_id={}",
        report.overall_status.as_str(),
        report.selected_profile,
        report.trace_id
    ));
    lines.push(format!(
        "source={}",
        report
            .source_path
            .clone()
            .unwrap_or_else(|| "<defaults>".to_string())
    ));
    lines.push(format!(
        "status_counts: pass={} warn={} fail={}",
        report.status_counts.pass, report.status_counts.warn, report.status_counts.fail
    ));
    lines.push(String::new());

    for check in &report.checks {
        lines.push(format!(
            "[{}] {} ({}) {} - {}",
            check.status.as_str(),
            check.code,
            check.event_code,
            check.scope,
            check.message
        ));
        lines.push(format!(
            "  remediation: {} (duration_ms={})",
            check.remediation, check.duration_ms
        ));
    }

    if let Some(policy_activation) = &report.policy_activation {
        lines.push(String::new());
        lines.push(format!(
            "policy_activation: dominant_verdict={} candidates={} observations={} input={}",
            policy_activation
                .guardrail_certificate
                .dominant_verdict
                .as_str(),
            policy_activation.candidate_count,
            policy_activation.observation_count,
            policy_activation.input_path
        ));
    }

    if verbose {
        lines.push(String::new());
        lines.push(format!(
            "generated_at={} merge_decision_count={}",
            report.generated_at_utc, report.merge_decision_count
        ));
        lines.push("merge decisions:".to_string());
        for decision in &report.merge_decisions {
            lines.push(format!(
                "  stage={:?} field={} value={}",
                decision.stage, decision.field, decision.value
            ));
        }
        lines.push("structured logs:".to_string());
        for event in &report.structured_logs {
            lines.push(format!(
                "  trace_id={} event_code={} check_code={} scope={} status={} duration_ms={}",
                event.trace_id,
                event.event_code,
                event.check_code,
                event.scope,
                event.status.as_str(),
                event.duration_ms
            ));
        }
    }

    lines.join("\n")
}

#[cfg(test)]
mod init_tests {
    use super::*;

    #[test]
    fn init_flags_are_mutually_exclusive() {
        assert!(validate_init_flags(false, false).is_ok());
        assert!(validate_init_flags(true, false).is_ok());
        assert!(validate_init_flags(false, true).is_ok());
        assert!(validate_init_flags(true, true).is_err());
    }

    #[test]
    fn write_policy_creates_new_file() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("franken_node.toml");
        let action = apply_init_write_policy(&path, "profile = \"balanced\"\n", false, false, "t0")
            .expect("create file");
        assert_eq!(action.action, InitFileActionKind::Created);
        assert_eq!(
            std::fs::read_to_string(&path).unwrap(),
            "profile = \"balanced\"\n"
        );
    }

    #[test]
    fn write_policy_rejects_existing_without_explicit_mode() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("franken_node.toml");
        std::fs::write(&path, "old").expect("seed");
        let err =
            apply_init_write_policy(&path, "new", false, false, "t0").expect_err("should fail");
        assert!(
            err.to_string()
                .contains("without --overwrite or --backup-existing")
        );
    }

    #[test]
    fn write_policy_overwrites_existing_file() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("franken_node.toml");
        std::fs::write(&path, "old").expect("seed");
        let action = apply_init_write_policy(&path, "new", true, false, "t0").expect("overwrite");
        assert_eq!(action.action, InitFileActionKind::Overwritten);
        assert!(action.backup_path.is_none());
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "new");
    }

    #[test]
    fn write_policy_backups_then_overwrites() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("franken_node.toml");
        std::fs::write(&path, "old").expect("seed");
        let action =
            apply_init_write_policy(&path, "new", false, true, "t0").expect("backup overwrite");
        assert_eq!(action.action, InitFileActionKind::BackedUpAndOverwritten);
        let backup_path = action.backup_path.expect("backup path");
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "new");
        assert_eq!(std::fs::read_to_string(backup_path).unwrap(), "old");
    }
}

#[cfg(test)]
mod doctor_tests {
    use super::*;

    fn resolved_fixture(profile: Profile) -> config::ResolvedConfig {
        config::ResolvedConfig {
            config: config::Config::for_profile(profile),
            selected_profile: profile,
            source_path: None,
            decisions: vec![
                config::MergeDecision {
                    stage: config::MergeStage::Default,
                    field: "profile".to_string(),
                    value: "balanced".to_string(),
                },
                config::MergeDecision {
                    stage: config::MergeStage::Cli,
                    field: "profile".to_string(),
                    value: profile.to_string(),
                },
            ],
        }
    }

    #[test]
    fn summarize_statuses_prioritizes_fail_over_warn() {
        let checks = vec![
            DoctorCheck {
                code: "A".to_string(),
                event_code: "DOC-A".to_string(),
                scope: "x".to_string(),
                status: DoctorStatus::Pass,
                message: String::new(),
                remediation: String::new(),
                duration_ms: 0,
            },
            DoctorCheck {
                code: "B".to_string(),
                event_code: "DOC-B".to_string(),
                scope: "x".to_string(),
                status: DoctorStatus::Warn,
                message: String::new(),
                remediation: String::new(),
                duration_ms: 0,
            },
            DoctorCheck {
                code: "C".to_string(),
                event_code: "DOC-C".to_string(),
                scope: "x".to_string(),
                status: DoctorStatus::Fail,
                message: String::new(),
                remediation: String::new(),
                duration_ms: 0,
            },
        ];

        let (counts, overall) = summarize_statuses(&checks);
        assert_eq!(counts.pass, 1);
        assert_eq!(counts.warn, 1);
        assert_eq!(counts.fail, 1);
        assert_eq!(overall, DoctorStatus::Fail);
    }

    #[test]
    fn doctor_report_uses_stable_check_order_and_codes() {
        let report = build_doctor_report_with_cwd(
            &resolved_fixture(Profile::Balanced),
            "trace-test",
            Ok(PathBuf::from(".")),
        );
        let codes = report
            .checks
            .iter()
            .map(|check| check.code.as_str())
            .collect::<Vec<_>>();
        assert_eq!(
            codes,
            vec![
                "DR-CONFIG-001",
                "DR-CONFIG-002",
                "DR-PROFILE-003",
                "DR-TRUST-004",
                "DR-MIGRATE-005",
                "DR-OBS-006",
                "DR-ENV-007",
                "DR-CONFIG-008",
            ]
        );
        assert_eq!(report.structured_logs.len(), report.checks.len());
        assert_eq!(report.trace_id, "trace-test");
    }

    #[test]
    fn doctor_report_warns_on_legacy_profile() {
        let report = build_doctor_report_with_cwd(
            &resolved_fixture(Profile::LegacyRisky),
            "trace-legacy",
            Ok(PathBuf::from(".")),
        );
        let profile_check = report
            .checks
            .iter()
            .find(|check| check.code == "DR-PROFILE-003")
            .expect("profile check present");
        assert_eq!(profile_check.status, DoctorStatus::Warn);
        assert_eq!(report.overall_status, DoctorStatus::Warn);
    }

    #[test]
    fn doctor_report_fails_when_cwd_is_unavailable() {
        let report = build_doctor_report_with_cwd(
            &resolved_fixture(Profile::Strict),
            "trace-fail",
            Err(std::io::Error::other("cwd unavailable")),
        );
        let cwd_check = report
            .checks
            .iter()
            .find(|check| check.code == "DR-ENV-007")
            .expect("cwd check present");
        assert_eq!(cwd_check.status, DoctorStatus::Fail);
        assert_eq!(report.overall_status, DoctorStatus::Fail);
    }

    #[test]
    fn verbose_human_report_includes_merge_decisions_and_logs() {
        let report = build_doctor_report_with_cwd(
            &resolved_fixture(Profile::Balanced),
            "trace-verbose",
            Ok(PathBuf::from(".")),
        );
        let rendered = render_doctor_report_human(&report, true);
        assert!(rendered.contains("merge decisions:"));
        assert!(rendered.contains("structured logs:"));
        assert!(rendered.contains("trace_id=trace-verbose"));
    }

    #[test]
    fn doctor_report_runs_policy_activation_pipeline_when_input_is_present() {
        let dir = tempfile::tempdir().expect("tempdir");
        let policy_input_path = dir.path().join("policy_activation.json");
        std::fs::write(
            &policy_input_path,
            r#"{
  "epoch_id": 77,
  "system_state": {
    "memory_used_bytes": 400000000,
    "memory_budget_bytes": 1000000000,
    "durability_level": 0.97,
    "hardening_level": "standard",
    "proposed_hardening_level": "enhanced",
    "evidence_emission_active": true,
    "memory_tail_risk": {
      "sample_count": 128,
      "mean_utilization": 0.62,
      "variance_utilization": 0.01,
      "peak_utilization": 0.70
    },
    "reliability_telemetry": {
      "sample_count": 4096,
      "nonconforming_count": 24
    }
  },
  "candidates": ["fast-path", "safe-path"],
  "prefiltered_candidates": [],
  "observations": [
    {"candidate": "fast-path", "success": false},
    {"candidate": "fast-path", "success": false},
    {"candidate": "safe-path", "success": true},
    {"candidate": "safe-path", "success": true}
  ]
}"#,
        )
        .expect("write policy input");

        let report = build_doctor_report_with_cwd_and_policy_input(
            &resolved_fixture(Profile::Balanced),
            "trace-policy",
            Ok(PathBuf::from(".")),
            Some(&policy_input_path),
        );

        let codes = report
            .checks
            .iter()
            .map(|check| check.code.as_str())
            .collect::<Vec<_>>();
        assert!(codes.contains(&"DR-POLICY-009"));
        assert!(codes.contains(&"DR-POLICY-010"));
        assert!(codes.contains(&"DR-POLICY-011"));

        let policy = report.policy_activation.expect("policy activation report");
        assert_eq!(
            policy.guardrail_certificate.dominant_verdict,
            DoctorGuardrailVerdictKind::Allow
        );
        assert!(policy.wording_validation.valid);
    }

    #[test]
    fn doctor_report_records_policy_input_failures_without_panicking() {
        let dir = tempfile::tempdir().expect("tempdir");
        let policy_input_path = dir.path().join("policy_activation_invalid.json");
        std::fs::write(&policy_input_path, "{ invalid json").expect("write policy input");

        let report = build_doctor_report_with_cwd_and_policy_input(
            &resolved_fixture(Profile::Balanced),
            "trace-policy-invalid",
            Ok(PathBuf::from(".")),
            Some(&policy_input_path),
        );

        assert!(report.policy_activation.is_none());
        let policy_checks = report
            .checks
            .iter()
            .filter(|check| check.code.starts_with("DR-POLICY-"))
            .collect::<Vec<_>>();
        assert_eq!(policy_checks.len(), 3);
        assert!(
            policy_checks
                .iter()
                .all(|check| matches!(check.status, DoctorStatus::Fail))
        );
        assert_eq!(report.overall_status, DoctorStatus::Fail);
    }
}

#[cfg(test)]
mod trust_command_tests {
    use super::*;

    #[test]
    fn parse_risk_level_filter_accepts_supported_values() {
        assert_eq!(
            parse_risk_level_filter(Some("low")).expect("parse low"),
            Some(RiskLevel::Low)
        );
        assert_eq!(
            parse_risk_level_filter(Some("MEDIUM")).expect("parse medium"),
            Some(RiskLevel::Medium)
        );
        assert_eq!(
            parse_risk_level_filter(Some("high")).expect("parse high"),
            Some(RiskLevel::High)
        );
        assert_eq!(
            parse_risk_level_filter(Some("critical")).expect("parse critical"),
            Some(RiskLevel::Critical)
        );
        let err = parse_risk_level_filter(Some("critical-risk")).expect_err("invalid");
        assert!(
            err.to_string()
                .contains("expected one of: low, medium, high, critical")
        );
    }

    #[test]
    fn parse_risk_level_filter_rejects_unknown_value() {
        let err = parse_risk_level_filter(Some("severe")).expect_err("invalid risk");
        assert!(
            err.to_string()
                .contains("expected one of: low, medium, high, critical")
        );
    }

    #[test]
    fn parse_risk_level_filter_handles_absent_value() {
        assert!(parse_risk_level_filter(None).expect("none").is_none());
    }

    #[test]
    fn trust_list_filters_by_risk_and_revocation_status() {
        let mut registry = trust_card_cli_registry().expect("registry");
        let cards = registry.list(&TrustCardListFilter::empty(), "trace-test", now_unix_secs());

        let critical_revoked = filter_trust_cards_for_trust_command(
            cards.clone(),
            Some(RiskLevel::Critical),
            Some(true),
        );
        assert_eq!(critical_revoked.len(), 1);
        assert_eq!(
            critical_revoked[0].extension.extension_id,
            "npm:@beta/telemetry-bridge"
        );
        assert!(matches!(
            &critical_revoked[0].revocation_status,
            RevocationStatus::Revoked { .. }
        ));

        let low_active =
            filter_trust_cards_for_trust_command(cards, Some(RiskLevel::Low), Some(false));
        assert_eq!(low_active.len(), 1);
        assert_eq!(low_active[0].extension.extension_id, "npm:@acme/auth-guard");
        assert!(matches!(
            &low_active[0].revocation_status,
            RevocationStatus::Active
        ));
    }
}

#[cfg(test)]
mod registry_command_tests {
    use super::*;

    #[test]
    fn parse_min_assurance_accepts_range() {
        assert_eq!(parse_min_assurance(None).expect("none"), None);
        assert_eq!(parse_min_assurance(Some(1)).expect("one"), Some(1));
        assert_eq!(parse_min_assurance(Some(5)).expect("five"), Some(5));
    }

    #[test]
    fn parse_min_assurance_rejects_out_of_range() {
        let err = parse_min_assurance(Some(0)).expect_err("must reject");
        assert!(err.to_string().contains("between 1 and 5"));
        let err = parse_min_assurance(Some(6)).expect_err("must reject");
        assert!(err.to_string().contains("between 1 and 5"));
    }

    #[test]
    fn assurance_level_is_higher_for_active_than_revoked() {
        let registry = registry_cli_registry().expect("registry");
        let entries = registry.list(None);
        let active = entries
            .iter()
            .find(|extension| extension.status == ExtensionStatus::Active)
            .expect("active extension");
        let revoked = entries
            .iter()
            .find(|extension| extension.status == ExtensionStatus::Revoked)
            .expect("revoked extension");

        assert!(extension_assurance_level(active) > extension_assurance_level(revoked));
    }

    #[test]
    fn search_registry_entries_filters_by_query_and_assurance() {
        let registry = registry_cli_registry().expect("registry");
        let telemetry_results = search_registry_entries(&registry, "telemetry", Some(3));
        assert!(!telemetry_results.is_empty());
        assert!(
            telemetry_results
                .iter()
                .all(|(_, extension)| extension_matches_query(extension, "telemetry"))
        );
        assert!(
            telemetry_results
                .iter()
                .all(|(assurance, _)| *assurance >= 3)
        );

        let high_assurance = search_registry_entries(&registry, "", Some(5));
        assert!(!high_assurance.is_empty());
        assert!(high_assurance.iter().all(|(assurance, _)| *assurance == 5));
    }

    #[test]
    fn render_registry_search_results_handles_empty_rows() {
        let rendered = render_registry_search_results(&[], "nomatch", Some(4));
        assert!(rendered.contains("no extensions matched"));
        assert!(rendered.contains("query=`nomatch`"));
    }

    #[test]
    fn build_registry_publish_request_derives_stable_metadata() {
        let temp = tempfile::tempdir().expect("tempdir");
        let package = temp.path().join("My Extension!.tar.gz");
        std::fs::write(&package, "artifact").expect("write package");
        let hash = "a".repeat(64);

        let request = build_registry_publish_request(&package, &hash);
        assert!(!request.name.is_empty());
        assert!(request.name.chars().all(|ch| {
            ch.is_ascii_lowercase() || ch.is_ascii_digit() || ch == '-' || ch == '_'
        }));
        assert_eq!(request.initial_version.content_hash, hash);
        assert_eq!(request.signature.signature_hex.len(), 128);
    }
}

#[cfg(test)]
mod fleet_command_tests {
    use super::*;
    use crate::api::fleet_quarantine::{ConvergencePhase, ConvergenceState, DecisionReceipt};

    #[test]
    fn fleet_cli_identity_has_operator_and_admin_roles() {
        let identity = fleet_cli_identity();
        assert_eq!(identity.principal, "cli-fleet-operator");
        assert_eq!(identity.method, AuthMethod::MtlsClientCert);
        assert!(identity.roles.iter().any(|role| role == "fleet-admin"));
        assert!(identity.roles.iter().any(|role| role == "operator"));
    }

    #[test]
    fn fleet_cli_trace_uses_supplied_trace_id() {
        let trace = fleet_cli_trace("trace-test-fleet");
        assert_eq!(trace.trace_id, "trace-test-fleet");
        assert_eq!(trace.trace_flags, 1);
    }

    #[test]
    fn fleet_status_render_includes_activation_and_counts() {
        let status = FleetStatus {
            zone_id: "zone-1".to_string(),
            active_quarantines: 2,
            active_revocations: 1,
            healthy_nodes: 9,
            total_nodes: 10,
            activated: false,
            pending_convergences: Vec::new(),
        };
        let rendered = render_fleet_status_human(&status, true);
        assert!(rendered.contains("fleet status: zone=zone-1"));
        assert!(rendered.contains("activated=false"));
        assert!(rendered.contains("quarantines=2 revocations=1"));
        assert!(rendered.contains("healthy_nodes=9/10"));
        assert!(rendered.contains("pending_convergences=0"));
    }

    #[test]
    fn fleet_action_render_includes_convergence_details() {
        let action = FleetActionResult {
            operation_id: "fleet-op-7".to_string(),
            action_type: "reconcile".to_string(),
            success: true,
            receipt: DecisionReceipt {
                receipt_id: "rcpt-7".to_string(),
                issuer: "cli-fleet-operator".to_string(),
                issued_at: "2026-02-25T00:00:00Z".to_string(),
                zone_id: "all".to_string(),
                payload_hash: "hash".to_string(),
            },
            convergence: Some(ConvergenceState {
                converged_nodes: 4,
                total_nodes: 5,
                progress_pct: 80,
                eta_seconds: Some(5),
                phase: ConvergencePhase::Propagating,
            }),
            trace_id: "trace-fleet".to_string(),
            event_code: "FLEET-005".to_string(),
        };
        let rendered = render_fleet_action_human(&action);
        assert!(rendered.contains("fleet action: type=reconcile operation_id=fleet-op-7"));
        assert!(rendered.contains("success=true"));
        assert!(rendered.contains("event_code=FLEET-005"));
        assert!(rendered.contains("convergence=4/5 (80%)"));
    }
}

#[cfg(test)]
mod migrate_audit_output_tests {
    use super::*;

    #[test]
    fn emit_migration_audit_report_writes_to_requested_path() {
        let temp = tempfile::tempdir().expect("tempdir");
        let output_path = temp.path().join("reports/migration/audit.txt");
        let rendered = "migration-audit-report\nstatus: ok\n";

        let written = emit_migration_audit_report(rendered, Some(&output_path)).expect("written");
        assert_eq!(written, Some(output_path.clone()));
        assert_eq!(
            std::fs::read_to_string(&output_path).expect("read output"),
            rendered
        );
    }
}

#[cfg(test)]
mod incident_list_tests {
    use super::*;

    fn write_sample_bundle(path: &Path, incident_id: &str, severity: &str) {
        let mut events = sample_incident_events(incident_id);
        if let Some(first) = events.first_mut()
            && let Some(payload) = first.payload.as_object_mut()
        {
            payload.insert("severity".to_string(), serde_json::json!(severity));
        }
        let bundle = generate_replay_bundle(incident_id, &events).expect("bundle");
        write_bundle_to_path(&bundle, path).expect("write bundle");
    }

    #[test]
    fn parse_incident_severity_filter_accepts_case_insensitive_input() {
        assert_eq!(
            parse_incident_severity_filter(Some("High")).expect("parse"),
            Some("high".to_string())
        );
        assert_eq!(
            parse_incident_severity_filter(Some("unknown")).expect("parse"),
            Some("unknown".to_string())
        );
    }

    #[test]
    fn parse_incident_severity_filter_rejects_unknown_values() {
        let err = parse_incident_severity_filter(Some("severe")).expect_err("must fail");
        assert!(err.to_string().contains(
            "invalid --severity `severe`; expected one of: low, medium, high, critical, unknown"
        ));
    }

    #[test]
    fn collect_incident_list_entries_filters_by_severity() {
        let temp = tempfile::tempdir().expect("tempdir");
        let root = temp.path();
        let nested = root.join("incidents");
        std::fs::create_dir_all(&nested).expect("create nested dir");

        write_sample_bundle(&root.join("high-incident.fnbundle"), "INC-HIGH-001", "high");
        write_sample_bundle(&nested.join("low-incident.fnbundle"), "INC-LOW-001", "low");

        let all = collect_incident_list_entries(root, None).expect("all entries");
        assert_eq!(all.len(), 2);

        let high = collect_incident_list_entries(root, Some("high")).expect("high entries");
        assert_eq!(high.len(), 1);
        assert_eq!(high[0].incident_id, "INC-HIGH-001");
        assert_eq!(high[0].severity, "high");
        assert!(high[0].path.ends_with("high-incident.fnbundle"));
    }

    #[test]
    fn render_incident_list_handles_empty_results() {
        let rendered = render_incident_list(&[], Some("critical"));
        assert_eq!(
            rendered,
            "incident list: no bundles found for severity=critical"
        );
    }
}

fn handle_remotecap_issue(args: &RemoteCapIssueArgs) -> Result<()> {
    let operations = args
        .scope
        .split(',')
        .map(str::trim)
        .filter(|entry| !entry.is_empty())
        .map(parse_remote_operation)
        .collect::<Result<Vec<_>>>()?;
    if operations.is_empty() {
        anyhow::bail!("--scope must include at least one operation");
    }

    let endpoint_prefixes = args
        .endpoint_prefixes
        .iter()
        .map(|entry| entry.trim().to_string())
        .filter(|entry| !entry.is_empty())
        .collect::<Vec<_>>();
    if endpoint_prefixes.is_empty() {
        anyhow::bail!("--endpoint must include at least one endpoint prefix");
    }

    let ttl_secs = parse_ttl_secs(&args.ttl)?;
    let now_epoch_secs = now_unix_secs();
    let signing_key = std::env::var("FRANKEN_NODE_REMOTECAP_KEY")
        .unwrap_or_else(|_| ["franken-node", "dev", "remotecap", "key"].join("-"));
    let provider = CapabilityProvider::new(&signing_key);
    let scope = RemoteScope::new(operations, endpoint_prefixes);

    let (cap, audit_event) = provider
        .issue(
            &args.issuer,
            scope,
            now_epoch_secs,
            ttl_secs,
            args.operator_approved,
            args.single_use,
            &args.trace_id,
        )
        .map_err(|err| anyhow::anyhow!(err.to_string()))?;

    if args.json {
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "token": cap,
                "audit_event": audit_event,
                "ttl_secs": ttl_secs,
                "issued_at_epoch_secs": now_epoch_secs,
            }))?
        );
    } else {
        println!("RemoteCap issued");
        println!("  token_id: {}", cap.token_id());
        println!("  issuer: {}", cap.issuer_identity());
        println!("  ttl_secs: {}", ttl_secs);
        println!("  expires_at_epoch_secs: {}", cap.expires_at_epoch_secs());
        println!(
            "  operations: {}",
            cap.scope()
                .operations
                .iter()
                .map(|op| op.as_str())
                .collect::<Vec<_>>()
                .join(",")
        );
        println!("  endpoints: {}", cap.scope().endpoint_prefixes.join(","));
        println!("  event_code: {}", audit_event.event_code);
    }

    Ok(())
}

fn trust_card_cli_registry() -> Result<TrustCardRegistry> {
    demo_trust_registry(now_unix_secs()).map_err(Into::into)
}

fn build_registry_seed_request(
    name: &str,
    description: &str,
    publisher_id: &str,
    version: &str,
    tags: &[&str],
) -> RegistrationRequest {
    let attestation_hash = hex::encode(sha2::Sha256::digest(
        format!("{name}:{publisher_id}:{version}").as_bytes(),
    ));
    let signature_hex = format!("{attestation_hash}{attestation_hash}");
    RegistrationRequest {
        name: name.to_string(),
        description: description.to_string(),
        publisher_id: publisher_id.to_string(),
        signature: ExtensionSignature {
            key_id: format!("{publisher_id}-key"),
            algorithm: "ed25519".to_string(),
            signature_hex,
            signed_at: chrono::Utc::now().to_rfc3339(),
        },
        provenance: ProvenanceAttestation {
            publisher_id: publisher_id.to_string(),
            build_system: "github-actions".to_string(),
            source_repository: format!("https://github.com/{publisher_id}/{name}"),
            vcs_commit: attestation_hash[..12].to_string(),
            attestation_hash,
        },
        initial_version: VersionEntry {
            version: version.to_string(),
            parent_version: None,
            content_hash: hex::encode(sha2::Sha256::digest(
                format!("{name}:{version}:content").as_bytes(),
            )),
            registered_at: chrono::Utc::now().to_rfc3339(),
            compatible_with: vec!["franken-node".to_string()],
        },
        tags: tags.iter().map(|tag| (*tag).to_string()).collect(),
    }
}

fn registry_cli_registry() -> Result<SignedExtensionRegistry> {
    let mut registry = SignedExtensionRegistry::default();

    let baseline = [
        build_registry_seed_request(
            "auth-guard",
            "Access policy enforcement extension",
            "acme-sec",
            "1.4.0",
            &["auth", "security", "policy"],
        ),
        build_registry_seed_request(
            "telemetry-bridge",
            "Telemetry fan-out and export bridge",
            "beta-observability",
            "2.1.3",
            &["telemetry", "metrics", "export"],
        ),
        build_registry_seed_request(
            "sandbox-runner",
            "Sandboxed task execution runtime",
            "gamma-runtime",
            "0.9.2",
            &["runtime", "sandbox", "worker"],
        ),
    ];

    let mut ids = Vec::new();
    for request in baseline {
        let result = registry.register(request, "trace-cli-registry-seed");
        if !result.success {
            anyhow::bail!("failed seeding extension registry: {}", result.detail);
        }
        let id = result
            .extension_id
            .ok_or_else(|| anyhow::anyhow!("seeded registry entry missing extension id"))?;
        ids.push(id);
    }

    if let Some(id) = ids.get(1) {
        let _ = registry.deprecate(id, "trace-cli-registry-seed-deprecate");
    }
    if let Some(id) = ids.get(2) {
        let _ = registry.revoke(
            id,
            supply_chain::extension_registry::RevocationReason::SecurityVulnerability,
            "registry-seed",
            "trace-cli-registry-seed-revoke",
        );
    }

    Ok(registry)
}

fn normalize_registry_name(raw: &str) -> String {
    let mut normalized = raw
        .trim()
        .to_ascii_lowercase()
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() || ch == '-' || ch == '_' {
                ch
            } else {
                '-'
            }
        })
        .collect::<String>();
    normalized = normalized.trim_matches('-').to_string();
    if normalized.is_empty() {
        "extension-artifact".to_string()
    } else {
        normalized
    }
}

fn build_registry_publish_request(package_path: &Path, content_hash: &str) -> RegistrationRequest {
    let inferred_name = package_path
        .file_stem()
        .and_then(std::ffi::OsStr::to_str)
        .unwrap_or("extension-artifact");
    let name = normalize_registry_name(inferred_name);
    let publisher_id = normalize_registry_name(
        &std::env::var("USER")
            .or_else(|_| std::env::var("USERNAME"))
            .unwrap_or_else(|_| "local-operator".to_string()),
    );

    RegistrationRequest {
        name: name.clone(),
        description: format!("CLI-published artifact from {}", package_path.display()),
        publisher_id: publisher_id.clone(),
        signature: ExtensionSignature {
            key_id: format!("{publisher_id}-cli-key"),
            algorithm: "ed25519".to_string(),
            signature_hex: format!("{content_hash}{content_hash}"),
            signed_at: chrono::Utc::now().to_rfc3339(),
        },
        provenance: ProvenanceAttestation {
            publisher_id,
            build_system: "franken-node-cli".to_string(),
            source_repository: "local://workspace".to_string(),
            vcs_commit: content_hash[..12].to_string(),
            attestation_hash: content_hash.to_string(),
        },
        initial_version: VersionEntry {
            version: "1.0.0".to_string(),
            parent_version: None,
            content_hash: content_hash.to_string(),
            registered_at: chrono::Utc::now().to_rfc3339(),
            compatible_with: vec!["franken-node".to_string()],
        },
        tags: vec!["cli-publish".to_string(), "local".to_string()],
    }
}

fn parse_min_assurance(raw: Option<u8>) -> Result<Option<u8>> {
    let Some(value) = raw else {
        return Ok(None);
    };
    if (1..=5).contains(&value) {
        Ok(Some(value))
    } else {
        anyhow::bail!("invalid --min-assurance `{value}`; expected a value between 1 and 5");
    }
}

fn extension_assurance_level(extension: &SignedExtension) -> u8 {
    let mut score = 1_u8;

    if extension.status == ExtensionStatus::Active {
        score = score.saturating_add(1);
    }
    if extension
        .signature
        .algorithm
        .eq_ignore_ascii_case("ed25519")
        && extension.signature.signature_hex.len() >= 64
    {
        score = score.saturating_add(1);
    }
    if !extension.provenance.attestation_hash.is_empty()
        && !extension.provenance.source_repository.is_empty()
    {
        score = score.saturating_add(1);
    }
    if !extension.versions.is_empty() {
        score = score.saturating_add(1);
    }
    if extension.status == ExtensionStatus::Revoked {
        score = score.saturating_sub(2);
    }

    score.clamp(1, 5)
}

fn extension_matches_query(extension: &SignedExtension, query: &str) -> bool {
    let needle = query.trim().to_ascii_lowercase();
    if needle.is_empty() {
        return true;
    }

    extension
        .extension_id
        .to_ascii_lowercase()
        .contains(&needle)
        || extension.name.to_ascii_lowercase().contains(&needle)
        || extension
            .publisher_id
            .to_ascii_lowercase()
            .contains(&needle)
        || extension.description.to_ascii_lowercase().contains(&needle)
        || extension
            .tags
            .iter()
            .any(|tag| tag.to_ascii_lowercase().contains(&needle))
}

fn search_registry_entries<'a>(
    registry: &'a SignedExtensionRegistry,
    query: &str,
    min_assurance: Option<u8>,
) -> Vec<(u8, &'a SignedExtension)> {
    let mut results = registry
        .list(None)
        .into_iter()
        .filter(|extension| extension_matches_query(extension, query))
        .map(|extension| (extension_assurance_level(extension), extension))
        .filter(|(assurance, _)| min_assurance.is_none_or(|minimum| *assurance >= minimum))
        .collect::<Vec<_>>();

    results.sort_by(|left, right| {
        right
            .0
            .cmp(&left.0)
            .then_with(|| left.1.name.cmp(&right.1.name))
            .then_with(|| left.1.extension_id.cmp(&right.1.extension_id))
    });
    results
}

fn render_registry_search_results(
    rows: &[(u8, &SignedExtension)],
    query: &str,
    min_assurance: Option<u8>,
) -> String {
    if rows.is_empty() {
        return format!(
            "registry search: no extensions matched query=`{query}` min_assurance={}",
            min_assurance.map_or_else(|| "none".to_string(), |value| value.to_string())
        );
    }

    let mut lines = Vec::with_capacity(rows.len() + 3);
    lines.push(format!(
        "registry search: query=`{query}` min_assurance={}",
        min_assurance.map_or_else(|| "none".to_string(), |value| value.to_string())
    ));
    lines.push("extension_id | name | publisher | status | assurance".to_string());
    lines.push("------------ | ---- | --------- | ------ | ---------".to_string());
    for (assurance, extension) in rows {
        lines.push(format!(
            "{} | {} | {} | {} | {}",
            extension.extension_id,
            extension.name,
            extension.publisher_id,
            extension.status.label(),
            assurance
        ));
    }
    lines.join("\n")
}

fn handle_registry_publish(args: &cli::RegistryPublishArgs) -> Result<()> {
    if !args.package_path.exists() {
        anyhow::bail!(
            "registry publish target does not exist: {}",
            args.package_path.display()
        );
    }
    if !args.package_path.is_file() {
        anyhow::bail!(
            "registry publish target must be a file: {}",
            args.package_path.display()
        );
    }

    let package_bytes = std::fs::read(&args.package_path)
        .with_context(|| format!("failed reading package {}", args.package_path.display()))?;
    let content_hash = hex::encode(sha2::Sha256::digest(&package_bytes));
    let request = build_registry_publish_request(&args.package_path, &content_hash);

    let mut registry = registry_cli_registry()?;
    let result = registry.register(request, "trace-cli-registry-publish");
    if !result.success {
        anyhow::bail!("registry publish failed: {}", result.detail);
    }
    let extension_id = result
        .extension_id
        .ok_or_else(|| anyhow::anyhow!("registry publish returned no extension id"))?;
    let published = registry
        .query(&extension_id)
        .ok_or_else(|| anyhow::anyhow!("registry publish stored entry is missing"))?;

    println!(
        "registry publish: extension_id={} name={} status={} content_sha256={}",
        published.extension_id,
        published.name,
        published.status.label(),
        content_hash
    );
    println!(
        "registry state: entries={} revocations={} audit_records={} content_hash={}",
        registry.list(None).len(),
        registry.revocations().len(),
        registry.audit_log().len(),
        registry.content_hash()
    );

    Ok(())
}

fn handle_registry_search(args: &cli::RegistrySearchArgs) -> Result<()> {
    let min_assurance = parse_min_assurance(args.min_assurance)?;
    let registry = registry_cli_registry()?;
    let rows = search_registry_entries(&registry, &args.query, min_assurance);
    println!(
        "{}",
        render_registry_search_results(&rows, &args.query, min_assurance)
    );
    Ok(())
}

fn parse_risk_level_filter(raw: Option<&str>) -> Result<Option<RiskLevel>> {
    let Some(raw_value) = raw else {
        return Ok(None);
    };

    let normalized = raw_value.trim().to_ascii_lowercase().replace('-', "_");
    let level = match normalized.as_str() {
        "low" => RiskLevel::Low,
        "medium" => RiskLevel::Medium,
        "high" => RiskLevel::High,
        "critical" => RiskLevel::Critical,
        _ => {
            anyhow::bail!(
                "invalid --risk `{raw_value}`; expected one of: low, medium, high, critical"
            )
        }
    };
    Ok(Some(level))
}

fn filter_trust_cards_for_trust_command(
    cards: Vec<TrustCard>,
    risk_filter: Option<RiskLevel>,
    revoked_filter: Option<bool>,
) -> Vec<TrustCard> {
    let mut filtered = cards
        .into_iter()
        .filter(|card| {
            let risk_matches = risk_filter
                .map(|risk| card.user_facing_risk_assessment.level == risk)
                .unwrap_or(true);
            let revoked_matches = revoked_filter
                .map(|revoked| {
                    let is_revoked =
                        matches!(&card.revocation_status, RevocationStatus::Revoked { .. });
                    is_revoked == revoked
                })
                .unwrap_or(true);
            risk_matches && revoked_matches
        })
        .collect::<Vec<_>>();

    filtered.sort_by(|left, right| {
        left.extension
            .extension_id
            .cmp(&right.extension.extension_id)
    });
    filtered
}

fn render_trust_card_list(cards: &[TrustCard]) -> String {
    if cards.is_empty() {
        return "no trust cards matched the current filters".to_string();
    }

    let mut lines = Vec::with_capacity(cards.len() + 1);
    lines.push("extension | publisher | cert | reputation | status".to_string());
    for card in cards {
        let status = match &card.revocation_status {
            supply_chain::trust_card::RevocationStatus::Active => "active".to_string(),
            supply_chain::trust_card::RevocationStatus::Revoked { reason, .. } => {
                format!("revoked:{reason}")
            }
        };
        lines.push(format!(
            "{} | {} | {:?} | {}bp ({:?}) | {}",
            card.extension.extension_id,
            card.publisher.publisher_id,
            card.certification_level,
            card.reputation_score_basis_points,
            card.reputation_trend,
            status
        ));
    }
    lines.join("\n")
}

fn revoke_trust_card(
    registry: &mut TrustCardRegistry,
    extension_id: &str,
    now_secs: u64,
) -> Result<TrustCard> {
    let now_rfc3339 = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
    registry
        .update(
            extension_id,
            TrustCardMutation {
                certification_level: None,
                revocation_status: Some(RevocationStatus::Revoked {
                    reason: "manual revoke via franken-node trust revoke".to_string(),
                    revoked_at: now_rfc3339.clone(),
                }),
                active_quarantine: Some(true),
                reputation_score_basis_points: None,
                reputation_trend: Some(ReputationTrend::Declining),
                user_facing_risk_assessment: Some(RiskAssessment {
                    level: RiskLevel::Critical,
                    summary: "Revoked by operator action via trust revoke.".to_string(),
                }),
                last_verified_timestamp: Some(now_rfc3339),
            },
            now_secs,
            "trace-cli-trust-revoke",
        )
        .map_err(|err| anyhow::anyhow!(err.to_string()))
}

fn quarantine_trust_cards(
    registry: &mut TrustCardRegistry,
    artifact: &str,
    now_secs: u64,
) -> Result<Vec<TrustCard>> {
    let now_rfc3339 = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
    let mut targets = Vec::new();

    let direct_match = registry
        .read(artifact, now_secs, "trace-cli-trust-quarantine-lookup")
        .map_err(|err| anyhow::anyhow!(err.to_string()))?;

    if let Some(card) = direct_match {
        targets.push(card.extension.extension_id);
    } else if artifact.starts_with("sha256:") {
        targets = registry
            .list(
                &TrustCardListFilter::empty(),
                "trace-cli-trust-quarantine-list",
                now_secs,
            )
            .into_iter()
            .map(|card| card.extension.extension_id)
            .collect();
    } else {
        anyhow::bail!(
            "artifact `{artifact}` did not match a trust card extension id; use extension id or sha256:* reference"
        );
    }

    if targets.is_empty() {
        anyhow::bail!("no trust cards available for quarantine");
    }

    let mut updates = Vec::new();
    for extension_id in targets {
        let updated = registry
            .update(
                &extension_id,
                TrustCardMutation {
                    certification_level: None,
                    revocation_status: None,
                    active_quarantine: Some(true),
                    reputation_score_basis_points: None,
                    reputation_trend: None,
                    user_facing_risk_assessment: None,
                    last_verified_timestamp: Some(now_rfc3339.clone()),
                },
                now_secs,
                "trace-cli-trust-quarantine",
            )
            .map_err(|err| anyhow::anyhow!(err.to_string()))?;
        updates.push(updated);
    }

    updates.sort_by(|left, right| {
        left.extension
            .extension_id
            .cmp(&right.extension.extension_id)
    });
    Ok(updates)
}

fn render_trust_sync_summary(cards: &[TrustCard], force: bool) -> String {
    let revoked = cards
        .iter()
        .filter(|card| matches!(card.revocation_status, RevocationStatus::Revoked { .. }))
        .count();
    let quarantined = cards.iter().filter(|card| card.active_quarantine).count();
    let critical = cards
        .iter()
        .filter(|card| card.user_facing_risk_assessment.level == RiskLevel::Critical)
        .count();
    format!(
        "trust sync completed: force={force} cards={} revoked={} quarantined={} critical_risk={critical}",
        cards.len(),
        revoked,
        quarantined
    )
}

fn fleet_cli_identity() -> AuthIdentity {
    AuthIdentity {
        principal: "cli-fleet-operator".to_string(),
        method: AuthMethod::MtlsClientCert,
        roles: vec!["fleet-admin".to_string(), "operator".to_string()],
    }
}

fn fleet_cli_trace(trace_id: &str) -> TraceContext {
    TraceContext {
        trace_id: trace_id.to_string(),
        span_id: "0000000000000001".to_string(),
        trace_flags: 1,
    }
}

fn render_fleet_status_human(status: &FleetStatus, verbose: bool) -> String {
    let mut lines = vec![
        format!("fleet status: zone={}", status.zone_id),
        format!("  activated={}", status.activated),
        format!(
            "  quarantines={} revocations={}",
            status.active_quarantines, status.active_revocations
        ),
        format!(
            "  healthy_nodes={}/{}",
            status.healthy_nodes, status.total_nodes
        ),
    ];

    if verbose {
        lines.push(format!(
            "  pending_convergences={}",
            status.pending_convergences.len()
        ));
    }
    lines.join("\n")
}

fn render_fleet_action_human(action: &FleetActionResult) -> String {
    let mut lines = vec![
        format!(
            "fleet action: type={} operation_id={}",
            action.action_type, action.operation_id
        ),
        format!("  success={}", action.success),
        format!("  event_code={}", action.event_code),
        format!(
            "  receipt_id={} issuer={} zone={}",
            action.receipt.receipt_id, action.receipt.issuer, action.receipt.zone_id
        ),
    ];

    if let Some(convergence) = &action.convergence {
        lines.push(format!(
            "  convergence={}/{} ({}%) phase={:?} eta_seconds={:?}",
            convergence.converged_nodes,
            convergence.total_nodes,
            convergence.progress_pct,
            convergence.phase,
            convergence.eta_seconds
        ));
    }
    lines.join("\n")
}

const RELEASE_MANIFEST_FILE: &str = "SHA256SUMS";
const RELEASE_MANIFEST_SIGNATURE_FILE: &str = "SHA256SUMS.sig";

struct ReleaseVerificationContext {
    manifest: supply_chain::artifact_signing::ChecksumManifest,
    artifacts: BTreeMap<String, Vec<u8>>,
    detached_signatures: BTreeMap<String, Vec<u8>>,
    key_ring: supply_chain::artifact_signing::KeyRing,
    unlisted_artifacts: Vec<String>,
}

fn decode_signature_blob(raw: &[u8]) -> Vec<u8> {
    use base64::Engine;

    if let Ok(text) = std::str::from_utf8(raw) {
        let trimmed = text.trim();
        if !trimmed.is_empty() {
            if let Ok(decoded_hex) = hex::decode(trimmed)
                && decoded_hex.len() == 64
            {
                return decoded_hex;
            }

            if let Ok(decoded_b64) = base64::engine::general_purpose::STANDARD.decode(trimmed)
                && decoded_b64.len() == 64
            {
                return decoded_b64;
            }
        }
    }

    raw.to_vec()
}

fn parse_verifying_key_from_blob(raw: &[u8]) -> Option<ed25519_dalek::VerifyingKey> {
    use base64::Engine;

    if raw.len() == 32
        && let Ok(bytes) = <[u8; 32]>::try_from(raw)
        && let Ok(key) = ed25519_dalek::VerifyingKey::from_bytes(&bytes)
    {
        return Some(key);
    }

    let Ok(text) = std::str::from_utf8(raw) else {
        return None;
    };
    let trimmed = text.trim();
    if trimmed.is_empty() {
        return None;
    }

    let mut candidates = vec![trimmed.to_string()];
    if trimmed.starts_with('{')
        && let Ok(value) = serde_json::from_str::<serde_json::Value>(trimmed)
    {
        for field in ["public_key", "verifying_key", "key", "ed25519_public_key"] {
            if let Some(entry) = value.get(field).and_then(serde_json::Value::as_str) {
                candidates.push(entry.to_string());
            }
        }
    }

    for candidate in candidates {
        let normalized = candidate.trim().trim_start_matches("ed25519:").trim();
        if normalized.is_empty() {
            continue;
        }

        if let Ok(decoded_hex) = hex::decode(normalized)
            && let Ok(bytes) = <[u8; 32]>::try_from(decoded_hex.as_slice())
            && let Ok(key) = ed25519_dalek::VerifyingKey::from_bytes(&bytes)
        {
            return Some(key);
        }

        if let Ok(decoded_b64) = base64::engine::general_purpose::STANDARD.decode(normalized)
            && let Ok(bytes) = <[u8; 32]>::try_from(decoded_b64.as_slice())
            && let Ok(key) = ed25519_dalek::VerifyingKey::from_bytes(&bytes)
        {
            return Some(key);
        }
    }

    None
}

fn load_verifying_keys(key_dir: Option<&Path>) -> Result<Vec<ed25519_dalek::VerifyingKey>> {
    if let Some(key_dir) = key_dir {
        if !key_dir.is_dir() {
            anyhow::bail!("--key-dir must point to a directory: {}", key_dir.display());
        }

        let mut paths = std::fs::read_dir(key_dir)?
            .filter_map(Result::ok)
            .map(|entry| entry.path())
            .filter(|path| path.is_file())
            .collect::<Vec<_>>();
        paths.sort();

        let mut keys = Vec::new();
        for path in paths {
            let raw = std::fs::read(&path)
                .with_context(|| format!("failed reading {}", path.display()))?;
            if let Some(key) = parse_verifying_key_from_blob(&raw) {
                keys.push(key);
            }
        }

        if keys.is_empty() {
            anyhow::bail!(
                "no usable Ed25519 public keys found in key directory {}",
                key_dir.display()
            );
        }
        Ok(keys)
    } else {
        Ok(vec![
            supply_chain::artifact_signing::demo_signing_key().verifying_key(),
        ])
    }
}

fn collect_release_files(root: &Path) -> Result<Vec<String>> {
    let mut files = Vec::new();
    let mut stack = vec![root.to_path_buf()];

    while let Some(current) = stack.pop() {
        let mut entries = std::fs::read_dir(&current)?
            .filter_map(Result::ok)
            .map(|entry| entry.path())
            .collect::<Vec<_>>();
        entries.sort();

        for path in entries {
            if path.is_dir() {
                stack.push(path);
            } else if path.is_file() {
                let relative = path
                    .strip_prefix(root)
                    .with_context(|| {
                        format!("failed deriving relative path for {}", path.display())
                    })?
                    .to_string_lossy()
                    .replace('\\', "/");
                files.push(relative);
            }
        }
    }

    files.sort();
    Ok(files)
}

fn find_unlisted_artifacts(
    release_dir: &Path,
    manifest: &supply_chain::artifact_signing::ChecksumManifest,
) -> Result<Vec<String>> {
    let mut allowed = BTreeSet::new();
    allowed.insert(RELEASE_MANIFEST_FILE.to_string());
    allowed.insert(RELEASE_MANIFEST_SIGNATURE_FILE.to_string());
    for name in manifest.entries.keys() {
        allowed.insert(name.clone());
        allowed.insert(format!("{name}.sig"));
    }

    let mut extras = collect_release_files(release_dir)?
        .into_iter()
        .filter(|path| !allowed.contains(path))
        .collect::<Vec<_>>();
    extras.sort();
    Ok(extras)
}

fn load_release_verification_context(
    release_dir: &Path,
    key_dir: Option<&Path>,
) -> Result<ReleaseVerificationContext> {
    use supply_chain::artifact_signing::{ChecksumManifest, KeyRing, verify_signature};

    if !release_dir.is_dir() {
        anyhow::bail!(
            "release path must be a directory: {}",
            release_dir.display()
        );
    }

    let manifest_path = release_dir.join(RELEASE_MANIFEST_FILE);
    let manifest_raw = std::fs::read_to_string(&manifest_path)
        .with_context(|| format!("failed reading {}", manifest_path.display()))?;
    let parsed_entries = ChecksumManifest::parse_canonical(&manifest_raw);
    if parsed_entries.is_empty() {
        anyhow::bail!("manifest {} contains no entries", manifest_path.display());
    }

    let mut entries = BTreeMap::new();
    for entry in parsed_entries {
        entries.insert(entry.name.clone(), entry);
    }

    let manifest_signature_path = release_dir.join(RELEASE_MANIFEST_SIGNATURE_FILE);
    let manifest_signature_raw = std::fs::read(&manifest_signature_path)
        .with_context(|| format!("failed reading {}", manifest_signature_path.display()))?;
    let manifest_signature = decode_signature_blob(&manifest_signature_raw);

    let verifying_keys = load_verifying_keys(key_dir)?;
    let mut key_ring = KeyRing::new();
    let mut key_ids = Vec::new();
    for verifying_key in verifying_keys {
        let key_id = key_ring.add_key(verifying_key);
        key_ids.push(key_id);
    }

    let default_key_id = key_ids
        .first()
        .cloned()
        .ok_or_else(|| anyhow::anyhow!("no verifying keys available"))?;

    let mut manifest = ChecksumManifest {
        entries,
        key_id: default_key_id,
        signature: manifest_signature,
    };
    let canonical_manifest = manifest.canonical_bytes();
    if let Some(matched_key_id) = key_ids
        .iter()
        .find(|key_id| {
            key_ring.get_key(key_id).is_some_and(|key| {
                verify_signature(key, &canonical_manifest, &manifest.signature).is_ok()
            })
        })
        .cloned()
    {
        manifest.key_id = matched_key_id;
    }

    let mut artifacts = BTreeMap::new();
    let mut detached_signatures = BTreeMap::new();
    for artifact_name in manifest.entries.keys() {
        let artifact_path = release_dir.join(artifact_name);
        if artifact_path.is_file() {
            let artifact_bytes = std::fs::read(&artifact_path)
                .with_context(|| format!("failed reading {}", artifact_path.display()))?;
            artifacts.insert(artifact_name.clone(), artifact_bytes);
        }

        let signature_path = release_dir.join(format!("{artifact_name}.sig"));
        if signature_path.is_file() {
            let detached_bytes = std::fs::read(&signature_path)
                .with_context(|| format!("failed reading {}", signature_path.display()))?;
            detached_signatures.insert(
                artifact_name.clone(),
                decode_signature_blob(&detached_bytes),
            );
        }
    }

    let unlisted_artifacts = find_unlisted_artifacts(release_dir, &manifest)?;

    Ok(ReleaseVerificationContext {
        manifest,
        artifacts,
        detached_signatures,
        key_ring,
        unlisted_artifacts,
    })
}

fn handle_verify_release(args: &VerifyReleaseArgs) -> Result<()> {
    use supply_chain::artifact_signing::{
        ASV_002_VERIFICATION_OK, ASV_003_VERIFICATION_FAILED, ArtifactVerificationResult,
        AuditLogEntry, verify_release,
    };

    let release_dir = &args.release_path;
    let context = load_release_verification_context(release_dir, args.key_dir.as_deref())?;
    let mut report = verify_release(
        &context.manifest,
        &context.artifacts,
        &context.detached_signatures,
        &context.key_ring,
    );

    for artifact_name in &context.unlisted_artifacts {
        report.results.push(ArtifactVerificationResult {
            artifact_name: artifact_name.clone(),
            passed: false,
            key_id: context.manifest.key_id.0.clone(),
            failure_reason: Some("artifact present but not listed in SHA256SUMS".to_string()),
        });
    }

    report
        .results
        .sort_by(|left, right| left.artifact_name.cmp(&right.artifact_name));

    let overall_pass = report.manifest_signature_ok && report.results.iter().all(|row| row.passed);
    let result_rows = report
        .results
        .iter()
        .map(|row| {
            serde_json::json!({
                "artifact_name": row.artifact_name,
                "passed": row.passed,
                "key_id": row.key_id,
                "failure_reason": row.failure_reason,
            })
        })
        .collect::<Vec<_>>();

    let payload = serde_json::json!({
        "release_path": release_dir.display().to_string(),
        "manifest_signature_ok": report.manifest_signature_ok,
        "results": result_rows,
        "overall_pass": overall_pass,
        "unlisted_artifact_count": context.unlisted_artifacts.len(),
    });

    if args.json {
        println!("{}", serde_json::to_string_pretty(&payload)?);
    } else {
        println!(
            "verify release: {} manifest_signature_ok={} overall_pass={}",
            release_dir.display(),
            report.manifest_signature_ok,
            overall_pass
        );
        for row in &report.results {
            if row.passed {
                println!("  [ok] {}", row.artifact_name);
            } else {
                println!(
                    "  [fail] {}: {}",
                    row.artifact_name,
                    row.failure_reason
                        .clone()
                        .unwrap_or_else(|| "verification failed".to_string())
                );
            }
        }
    }

    let event_code = if overall_pass {
        ASV_002_VERIFICATION_OK
    } else {
        ASV_003_VERIFICATION_FAILED
    };
    let _audit_log = AuditLogEntry::now(
        event_code,
        &release_dir.display().to_string(),
        &context.manifest.key_id.0,
        "verify-release",
        if overall_pass { "passed" } else { "failed" },
    );

    if !overall_pass {
        anyhow::bail!("release verification failed");
    }

    Ok(())
}

fn emit_verify_contract_stub(command: &str, json: bool, compat_version: Option<u16>) -> i32 {
    let (exit_code, verdict, status, reason) = match compat_version {
        Some(version)
            if version > VERIFY_CLI_CONTRACT_MAJOR || version + 1 < VERIFY_CLI_CONTRACT_MAJOR =>
        {
            (
                2,
                "ERROR".to_string(),
                "error".to_string(),
                format!(
                    "unsupported --compat-version={version}; supported versions: {} or {}",
                    VERIFY_CLI_CONTRACT_MAJOR,
                    VERIFY_CLI_CONTRACT_MAJOR.saturating_sub(1)
                ),
            )
        }
        _ => (
            3,
            "SKIPPED".to_string(),
            "skipped".to_string(),
            "verifier command wiring is present but execution backend is not implemented yet"
                .to_string(),
        ),
    };

    let payload = VerifyContractStubOutput {
        command: command.to_string(),
        contract_version: VERIFY_CLI_CONTRACT_VERSION.to_string(),
        schema_version: "verifier-cli-contract-v1".to_string(),
        compat_version,
        verdict,
        status,
        exit_code,
        reason,
    };

    if json {
        if let Ok(blob) = serde_json::to_string_pretty(&payload) {
            println!("{blob}");
        } else {
            println!(
                "{{\"command\":\"{command}\",\"status\":\"error\",\"exit_code\":2,\"reason\":\"serialization-failed\"}}"
            );
            return 2;
        }
    } else {
        eprintln!("franken-node {command}: {}", payload.reason);
        eprintln!(
            "  contract_version={} compat_version={:?} status={} exit_code={}",
            payload.contract_version, payload.compat_version, payload.status, payload.exit_code
        );
    }

    exit_code
}

fn handle_trust_card_command(command: TrustCardCommand) -> Result<()> {
    let mut registry = trust_card_cli_registry()?;
    let now_secs = now_unix_secs();
    let trace_id = "trace-cli-trust-card";

    match command {
        TrustCardCommand::Show(args) => {
            let response = get_trust_card(&mut registry, &args.extension_id, now_secs, trace_id)?;
            let card = response
                .data
                .ok_or_else(|| anyhow::anyhow!("trust card not found: {}", args.extension_id))?;
            if args.json {
                println!("{}", trust_card_to_json(&card)?);
            } else {
                println!("{}", render_trust_card_human(&card));
            }
        }
        TrustCardCommand::Export(args) => {
            if !args.json {
                anyhow::bail!("`trust-card export` requires `--json`");
            }
            let response = get_trust_card(&mut registry, &args.extension_id, now_secs, trace_id)?;
            let card = response
                .data
                .ok_or_else(|| anyhow::anyhow!("trust card not found: {}", args.extension_id))?;
            println!("{}", trust_card_to_json(&card)?);
        }
        TrustCardCommand::List(args) => {
            let pagination = Pagination {
                page: args.page,
                per_page: args.per_page,
            };
            let response = if let Some(query) = args.query.as_deref() {
                search_trust_cards(&mut registry, query, now_secs, trace_id, pagination)?
            } else if let Some(publisher_id) = args.publisher.as_deref() {
                get_trust_cards_by_publisher(
                    &mut registry,
                    publisher_id,
                    now_secs,
                    trace_id,
                    pagination,
                )?
            } else {
                list_trust_cards(
                    &mut registry,
                    &TrustCardListFilter::empty(),
                    now_secs,
                    trace_id,
                    pagination,
                )?
            };

            if args.json {
                println!("{}", trust_card_to_json(&response)?);
            } else {
                println!("{}", render_trust_card_list(&response.data));
            }
        }
        TrustCardCommand::Compare(args) => {
            let response = compare_trust_cards(
                &mut registry,
                &args.left_extension_id,
                &args.right_extension_id,
                now_secs,
                trace_id,
            )?;
            if args.json {
                println!("{}", trust_card_to_json(&response)?);
            } else {
                println!("{}", render_comparison_human(&response.data));
            }
        }
        TrustCardCommand::Diff(args) => {
            let response = compare_trust_card_versions(
                &mut registry,
                &args.extension_id,
                args.left_version,
                args.right_version,
                now_secs,
                trace_id,
            )?;
            if args.json {
                println!("{}", trust_card_to_json(&response)?);
            } else {
                println!("{}", render_comparison_human(&response.data));
            }
        }
    }

    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Command::Init(args) => {
            let cli::InitArgs {
                profile,
                config,
                out_dir,
                overwrite,
                backup_existing,
                json,
                trace_id,
            } = args;

            validate_init_flags(overwrite, backup_existing)?;
            let profile_override = parse_profile_override(profile.as_deref())?;
            let resolved = config::Config::resolve(
                config.as_deref(),
                CliOverrides {
                    profile: profile_override,
                },
            )
            .context("failed resolving configuration for init")?;
            let config_toml = resolved
                .config
                .to_toml()
                .context("failed serializing resolved config")?;

            let mut wrote_to_stdout = false;
            let mut stdout_config_toml: Option<String> = None;
            let mut file_actions = Vec::new();

            if let Some(out_dir) = out_dir {
                std::fs::create_dir_all(&out_dir).with_context(|| {
                    format!("failed creating init output dir {}", out_dir.display())
                })?;
                let (config_path, profile_path) = init_target_paths(&out_dir);

                if !overwrite && !backup_existing {
                    let existing = [&config_path, &profile_path]
                        .into_iter()
                        .filter(|path| path.exists())
                        .map(|path| path.display().to_string())
                        .collect::<Vec<_>>();
                    if !existing.is_empty() {
                        anyhow::bail!(
                            "init target already contains generated files: {} (use --overwrite or --backup-existing)",
                            existing.join(", ")
                        );
                    }
                }

                let backup_suffix = chrono::Utc::now().format("%Y%m%dT%H%M%SZ").to_string();
                file_actions.push(apply_init_write_policy(
                    &config_path,
                    &config_toml,
                    overwrite,
                    backup_existing,
                    &backup_suffix,
                )?);
                file_actions.push(apply_init_write_policy(
                    &profile_path,
                    PROFILE_EXAMPLES_TEMPLATE,
                    overwrite,
                    backup_existing,
                    &backup_suffix,
                )?);
            } else {
                wrote_to_stdout = true;
                stdout_config_toml = Some(config_toml.clone());
            }

            let report = build_init_report(
                &trace_id,
                &resolved,
                file_actions,
                wrote_to_stdout,
                stdout_config_toml.clone(),
            );

            if json {
                println!("{}", serde_json::to_string_pretty(&report)?);
            } else if wrote_to_stdout {
                if let Some(config) = stdout_config_toml {
                    println!("{config}");
                }
                eprintln!("{}", render_init_report_human(&report, false));
            } else {
                eprintln!("{}", render_init_report_human(&report, false));
            }
        }

        Command::Run(args) => {
            let profile_override = parse_profile_override(Some(&args.policy))?;
            let resolved = config::Config::resolve(
                args.config.as_deref(),
                CliOverrides {
                    profile: profile_override,
                },
            )
            .context("failed resolving configuration for run")?;

            let dispatcher = ops::engine_dispatcher::EngineDispatcher::default();
            eprintln!(
                "Dispatching to franken_engine for {}",
                args.app_path.display()
            );
            dispatcher.dispatch_run(&args.app_path, &resolved.config, &args.policy)?;
        }

        Command::Migrate(sub) => match sub {
            MigrateCommand::Audit(args) => {
                let format = migration::AuditOutputFormat::parse(&args.format)
                    .map_err(|err| anyhow::anyhow!(err))?;
                let report = migration::run_audit(&args.project_path).with_context(|| {
                    format!(
                        "failed running migration audit for {}",
                        args.project_path.display()
                    )
                })?;
                let rendered = migration::render_audit_report(&report, format)?;

                if let Some(out_path) = emit_migration_audit_report(&rendered, args.out.as_deref())?
                {
                    eprintln!("migration audit report written: {}", out_path.display());
                }
            }
            MigrateCommand::Rewrite(args) => {
                let report =
                    migration::run_rewrite(&args.project_path, args.apply).with_context(|| {
                        format!(
                            "failed running migration rewrite for {}",
                            args.project_path.display()
                        )
                    })?;
                println!("{}", migration::render_rewrite_report(&report));

                if let Some(out_path) = args.emit_rollback.as_deref() {
                    let rollback_plan = migration::build_rollback_plan(&report);
                    let rollback_json =
                        serde_json::to_string_pretty(&rollback_plan).with_context(|| {
                            format!(
                                "failed serializing migration rollback plan for {}",
                                args.project_path.display()
                            )
                        })?;
                    let written_path = write_migration_report_file(
                        &rollback_json,
                        out_path,
                        "migration rollback artifact",
                    )?;
                    eprintln!(
                        "migration rollback artifact written: {}",
                        written_path.display()
                    );
                }
            }
            MigrateCommand::Validate(args) => {
                let report = migration::run_validate(&args.project_path).with_context(|| {
                    format!(
                        "failed running migration validate for {}",
                        args.project_path.display()
                    )
                })?;
                println!("{}", migration::render_validate_report(&report));
                if !report.is_pass() {
                    anyhow::bail!(
                        "migration validation failed for {}",
                        args.project_path.display()
                    );
                }
            }
        },

        Command::Verify(sub) => match sub {
            VerifyCommand::Module(args) => {
                let code =
                    emit_verify_contract_stub("verify module", args.json, args.compat_version);
                std::process::exit(code);
            }
            VerifyCommand::Migration(args) => {
                let code =
                    emit_verify_contract_stub("verify migration", args.json, args.compat_version);
                std::process::exit(code);
            }
            VerifyCommand::Compatibility(args) => {
                let code = emit_verify_contract_stub(
                    "verify compatibility",
                    args.json,
                    args.compat_version,
                );
                std::process::exit(code);
            }
            VerifyCommand::Corpus(args) => {
                let code =
                    emit_verify_contract_stub("verify corpus", args.json, args.compat_version);
                std::process::exit(code);
            }
            VerifyCommand::Lockstep(args) => {
                let runtimes: Vec<String> = args
                    .runtimes
                    .split(',')
                    .map(|s| s.trim().to_string())
                    .collect();
                let harness = runtime::lockstep_harness::LockstepHarness::new(runtimes);
                eprintln!(
                    "Running lockstep verification on {}",
                    args.project_path.display()
                );
                if let Err(e) = harness.verify_lockstep(&args.project_path) {
                    eprintln!("Lockstep harness failed: {}", e);
                    std::process::exit(1);
                }
            }
            VerifyCommand::Release(args) => {
                handle_verify_release(&args)?;
            }
        },

        Command::Trust(sub) => match sub {
            TrustCommand::Card(args) => {
                let mut registry = trust_card_cli_registry()?;
                let response = get_trust_card(
                    &mut registry,
                    &args.extension_id,
                    now_unix_secs(),
                    "trace-cli-trust-card",
                )?;
                let card = response.data.ok_or_else(|| {
                    anyhow::anyhow!("trust card not found: {}", args.extension_id)
                })?;
                println!("{}", render_trust_card_human(&card));
            }
            TrustCommand::List(args) => {
                let risk_filter = parse_risk_level_filter(args.risk.as_deref())?;
                let mut registry = trust_card_cli_registry()?;
                let cards = registry.list(
                    &TrustCardListFilter::empty(),
                    "trace-cli-trust-list",
                    now_unix_secs(),
                );
                let filtered =
                    filter_trust_cards_for_trust_command(cards, risk_filter, args.revoked);
                println!("{}", render_trust_card_list(&filtered));
            }
            TrustCommand::Revoke(args) => {
                let now_secs = now_unix_secs();
                let mut registry = trust_card_cli_registry()?;
                let card = revoke_trust_card(&mut registry, &args.extension_id, now_secs)?;
                println!("{}", render_trust_card_human(&card));
                maybe_export_demo_receipts(
                    "revocation",
                    "trust-control-plane",
                    "Revocation decision exported for audit traceability",
                    args.receipt_out.as_deref(),
                    args.receipt_summary_out.as_deref(),
                )?;
            }
            TrustCommand::Quarantine(args) => {
                let now_secs = now_unix_secs();
                let mut registry = trust_card_cli_registry()?;
                let updates = quarantine_trust_cards(&mut registry, &args.artifact, now_secs)?;
                println!(
                    "quarantine applied: artifact={} affected_cards={}",
                    args.artifact,
                    updates.len()
                );
                println!("{}", render_trust_card_list(&updates));
                maybe_export_demo_receipts(
                    "quarantine",
                    "trust-control-plane",
                    "Quarantine decision exported for incident forensics",
                    args.receipt_out.as_deref(),
                    args.receipt_summary_out.as_deref(),
                )?;
            }
            TrustCommand::Sync(args) => {
                let mut registry = trust_card_cli_registry()?;
                let now_secs = now_unix_secs();
                let cards = registry.list(
                    &TrustCardListFilter::empty(),
                    "trace-cli-trust-sync",
                    now_secs,
                );
                println!("{}", render_trust_sync_summary(&cards, args.force));
            }
        },

        Command::Remotecap(sub) => match sub {
            RemoteCapCommand::Issue(args) => {
                handle_remotecap_issue(&args)?;
            }
        },

        Command::TrustCard(sub) => {
            handle_trust_card_command(sub)?;
        }

        Command::Fleet(sub) => match sub {
            FleetCommand::Status(args) => {
                let zone_id = args.zone.unwrap_or_else(|| "all".to_string());
                let identity = fleet_cli_identity();
                let trace = fleet_cli_trace("trace-cli-fleet-status");
                let response = handle_fleet_status(&identity, &trace, &zone_id)
                    .map_err(|err| anyhow::anyhow!(err.to_string()))?;
                println!(
                    "{}",
                    render_fleet_status_human(&response.data, args.verbose)
                );
            }
            FleetCommand::Release(args) => {
                let identity = fleet_cli_identity();
                let trace = fleet_cli_trace("trace-cli-fleet-release");
                let response = handle_fleet_release(
                    &identity,
                    &trace,
                    &ReleaseRequest {
                        incident_id: args.incident,
                    },
                )
                .map_err(|err| anyhow::anyhow!(err.to_string()))?;
                println!("{}", render_fleet_action_human(&response.data));
            }
            FleetCommand::Reconcile(_) => {
                let identity = fleet_cli_identity();
                let trace = fleet_cli_trace("trace-cli-fleet-reconcile");
                let response = handle_fleet_reconcile(&identity, &trace)
                    .map_err(|err| anyhow::anyhow!(err.to_string()))?;
                println!("{}", render_fleet_action_human(&response.data));
            }
        },

        Command::Incident(sub) => match sub {
            IncidentCommand::Bundle(args) => {
                eprintln!(
                    "franken-node incident bundle: id={} verify={}",
                    args.id, args.verify
                );
                let events = sample_incident_events(&args.id);
                let bundle = generate_replay_bundle(&args.id, &events)
                    .with_context(|| format!("failed generating replay bundle for {}", args.id))?;
                if args.verify {
                    let valid = validate_bundle_integrity(&bundle).with_context(|| {
                        format!("failed validating replay bundle for {}", args.id)
                    })?;
                    eprintln!(
                        "bundle integrity: {}",
                        if valid { "valid" } else { "invalid" }
                    );
                }

                let output_path = incident_bundle_output_path(&args.id);
                write_bundle_to_path(&bundle, &output_path).with_context(|| {
                    format!(
                        "failed writing incident bundle to {}",
                        output_path.display()
                    )
                })?;

                maybe_export_demo_receipts(
                    "incident_bundle",
                    "incident-control-plane",
                    "Incident bundle receipt export for deterministic replay evidence",
                    args.receipt_out.as_deref(),
                    args.receipt_summary_out.as_deref(),
                )?;
                eprintln!("incident bundle written: {}", output_path.display());
            }
            IncidentCommand::Replay(args) => {
                eprintln!(
                    "franken-node incident replay: bundle={}",
                    args.bundle.display()
                );
                let bundle = read_bundle_from_path(&args.bundle).with_context(|| {
                    format!("failed reading replay bundle {}", args.bundle.display())
                })?;
                let outcome = replay_incident_bundle(&bundle).with_context(|| {
                    format!("failed replaying bundle {}", args.bundle.display())
                })?;
                eprintln!(
                    "incident replay result: matched={} event_count={} expected={} replayed={}",
                    outcome.matched,
                    outcome.event_count,
                    outcome.expected_sequence_hash,
                    outcome.replayed_sequence_hash
                );
                if !outcome.matched {
                    anyhow::bail!(
                        "replay mismatch for incident {} in bundle {}",
                        outcome.incident_id,
                        args.bundle.display()
                    );
                }
            }
            IncidentCommand::Counterfactual(args) => {
                eprintln!(
                    "franken-node incident counterfactual: bundle={} policy={}",
                    args.bundle.display(),
                    args.policy
                );
                let bundle = read_bundle_from_path(&args.bundle).with_context(|| {
                    format!("failed reading replay bundle {}", args.bundle.display())
                })?;
                let baseline_policy = PolicyConfig::from_bundle(&bundle);
                let mode = PolicyConfig::from_cli_spec(&args.policy, &baseline_policy)
                    .with_context(|| format!("invalid policy override spec `{}`", args.policy))?;
                let engine = CounterfactualReplayEngine::default();
                let output = engine
                    .simulate(&bundle, &baseline_policy, mode)
                    .with_context(|| {
                        format!(
                            "counterfactual replay failed for bundle {}",
                            args.bundle.display()
                        )
                    })?;
                let (total_decisions, changed_decisions, severity_delta) =
                    summarize_output(&output);
                eprintln!(
                    "counterfactual summary: total_decisions={} changed_decisions={} severity_delta={}",
                    total_decisions, changed_decisions, severity_delta
                );
                let canonical = counterfactual_to_json(&output)
                    .context("failed encoding counterfactual output to canonical json")?;
                eprintln!("counterfactual output: {canonical}");
            }
            IncidentCommand::List(args) => {
                let severity_filter = parse_incident_severity_filter(args.severity.as_deref())?;
                let cwd = std::env::current_dir()
                    .context("failed resolving current working directory for incident list")?;
                let entries = collect_incident_list_entries(&cwd, severity_filter.as_deref())?;
                println!(
                    "{}",
                    render_incident_list(&entries, severity_filter.as_deref())
                );
            }
        },

        Command::Registry(sub) => match sub {
            RegistryCommand::Publish(args) => {
                handle_registry_publish(&args)?;
            }
            RegistryCommand::Search(args) => {
                handle_registry_search(&args)?;
            }
        },

        Command::Bench(sub) => match sub {
            BenchCommand::Run(args) => {
                handle_bench_run(&args)?;
            }
        },

        Command::Doctor(args) => {
            let profile_override = parse_profile_override(args.profile.as_deref())?;
            let resolved = config::Config::resolve(
                args.config.as_deref(),
                CliOverrides {
                    profile: profile_override,
                },
            )
            .context("failed resolving configuration for doctor")?;
            let report = build_doctor_report_with_policy_input(
                &resolved,
                &args.trace_id,
                args.policy_activation_input.as_deref(),
            );

            if args.json {
                println!("{}", serde_json::to_string_pretty(&report)?);
            } else {
                println!("{}", render_doctor_report_human(&report, args.verbose));
            }
        }
    }

    Ok(())
}
