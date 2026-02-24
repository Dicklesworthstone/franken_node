#![forbid(unsafe_code)]

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
#[path = "control_plane/root_pointer.rs"]
pub mod root_pointer;
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
use serde::Serialize;
use std::path::{Path, PathBuf};
use std::time::Instant;

use api::trust_card_routes::{
    Pagination, compare_trust_card_versions, compare_trust_cards, get_trust_card,
    get_trust_cards_by_publisher, list_trust_cards, search_trust_cards,
};
use cli::{
    BenchCommand, Cli, Command, FleetCommand, IncidentCommand, MigrateCommand, RegistryCommand,
    RemoteCapCommand, RemoteCapIssueArgs, TrustCardCommand, TrustCommand, VerifyCommand,
    VerifyReleaseArgs,
};
use config::{CliOverrides, Profile};
use security::decision_receipt::{
    Decision, Receipt, ReceiptQuery, append_signed_receipt, demo_signing_key,
    export_receipts_to_path, write_receipts_markdown,
};
use security::remote_cap::{CapabilityProvider, RemoteOperation, RemoteScope};
use supply_chain::trust_card::{
    TrustCard, TrustCardListFilter, TrustCardRegistry, demo_registry as demo_trust_registry,
    render_comparison_human, render_trust_card_human, to_canonical_json as trust_card_to_json,
};
use tools::counterfactual_replay::{
    CounterfactualReplayEngine, PolicyConfig, summarize_output,
    to_canonical_json as counterfactual_to_json,
};
use tools::replay_bundle::{
    generate_replay_bundle, read_bundle_from_path, replay_bundle as replay_incident_bundle,
    synthetic_incident_events, validate_bundle_integrity, write_bundle_to_path,
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
    build_doctor_report_with_cwd(resolved, trace_id, std::env::current_dir())
}

fn build_doctor_report_with_cwd(
    resolved: &config::ResolvedConfig,
    trace_id: &str,
    cwd_result: std::io::Result<PathBuf>,
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
    let secret = std::env::var("FRANKEN_NODE_REMOTECAP_SECRET")
        .unwrap_or_else(|_| "franken-node-dev-remotecap-secret".to_string());
    let provider = CapabilityProvider::new(&secret);
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

fn handle_verify_release(args: &VerifyReleaseArgs) {
    use supply_chain::artifact_signing::{
        ASV_002_VERIFICATION_OK, ASV_003_VERIFICATION_FAILED, AuditLogEntry,
    };

    let release_dir = &args.release_path;
    eprintln!(
        "franken-node verify release: path={} key_dir={:?}",
        release_dir.display(),
        args.key_dir
    );

    // In a full implementation, this would:
    // 1. Read SHA256SUMS manifest and its .sig from release_dir.
    // 2. Load public keys from key_dir.
    // 3. Verify the manifest signature.
    // 4. Iterate manifest entries, verify each checksum and .sig file.
    // 5. Output structured JSON (--json) or human-readable report.
    //
    // Placeholder emits a structured stub so CLI wiring can be tested.
    let stub_result = serde_json::json!({
        "release_path": release_dir.display().to_string(),
        "manifest_signature_ok": false,
        "results": [],
        "overall_pass": false,
        "error": "release directory verification not yet wired to filesystem I/O"
    });

    if args.json {
        println!(
            "{}",
            serde_json::to_string_pretty(&stub_result).unwrap_or_default()
        );
    } else {
        eprintln!("[verify-release stub] — filesystem I/O not yet wired.");
        eprintln!(
            "  Use the library API `supply_chain::artifact_signing::verify_release` for full verification."
        );
    }

    let _log = AuditLogEntry::now(
        ASV_003_VERIFICATION_FAILED,
        &release_dir.display().to_string(),
        "none",
        "verify-release",
        "stub",
    );

    // Suppress unused-import warnings for the success event code.
    let _ = ASV_002_VERIFICATION_OK;
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
            eprintln!("Dispatching to franken_engine for {}", args.app_path.display());
            dispatcher.dispatch_run(&args.app_path, &resolved.config, &args.policy)?;
        }

        Command::Migrate(sub) => match sub {
            MigrateCommand::Audit(args) => {
                eprintln!(
                    "franken-node migrate audit: project={} format={}",
                    args.project_path.display(),
                    args.format
                );
                eprintln!("[not yet implemented]");
            }
            MigrateCommand::Rewrite(args) => {
                eprintln!(
                    "franken-node migrate rewrite: project={} apply={}",
                    args.project_path.display(),
                    args.apply
                );
                eprintln!("[not yet implemented]");
            }
            MigrateCommand::Validate(args) => {
                eprintln!(
                    "franken-node migrate validate: project={}",
                    args.project_path.display()
                );
                eprintln!("[not yet implemented]");
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
                let runtimes: Vec<String> = args.runtimes.split(',').map(|s| s.trim().to_string()).collect();
                let harness = runtime::lockstep_harness::LockstepHarness::new(runtimes);
                eprintln!("Running lockstep verification on {}", args.project_path.display());
                if let Err(e) = harness.verify_lockstep(&args.project_path) {
                    eprintln!("Lockstep harness failed: {}", e);
                    std::process::exit(1);
                }
            }
            VerifyCommand::Release(args) => {
                handle_verify_release(&args);
            }
        },

        Command::Trust(sub) => match sub {
            TrustCommand::Card(args) => {
                eprintln!("franken-node trust card: extension={}", args.extension_id);
                eprintln!("[not yet implemented]");
            }
            TrustCommand::List(args) => {
                eprintln!(
                    "franken-node trust list: risk={:?} revoked={:?}",
                    args.risk, args.revoked
                );
                eprintln!("[not yet implemented]");
            }
            TrustCommand::Revoke(args) => {
                eprintln!("franken-node trust revoke: extension={}", args.extension_id);
                maybe_export_demo_receipts(
                    "revocation",
                    "trust-control-plane",
                    "Revocation decision exported for audit traceability",
                    args.receipt_out.as_deref(),
                    args.receipt_summary_out.as_deref(),
                )?;
                eprintln!("[not yet implemented]");
            }
            TrustCommand::Quarantine(args) => {
                eprintln!("franken-node trust quarantine: artifact={}", args.artifact);
                maybe_export_demo_receipts(
                    "quarantine",
                    "trust-control-plane",
                    "Quarantine decision exported for incident forensics",
                    args.receipt_out.as_deref(),
                    args.receipt_summary_out.as_deref(),
                )?;
                eprintln!("[not yet implemented]");
            }
            TrustCommand::Sync(args) => {
                eprintln!("franken-node trust sync: force={}", args.force);
                eprintln!("[not yet implemented]");
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
                eprintln!(
                    "franken-node fleet status: zone={:?} verbose={}",
                    args.zone, args.verbose
                );
                eprintln!("[not yet implemented]");
            }
            FleetCommand::Release(args) => {
                eprintln!("franken-node fleet release: incident={}", args.incident);
                eprintln!("[not yet implemented]");
            }
            FleetCommand::Reconcile(_) => {
                eprintln!("franken-node fleet reconcile");
                eprintln!("[not yet implemented]");
            }
        },

        Command::Incident(sub) => match sub {
            IncidentCommand::Bundle(args) => {
                eprintln!(
                    "franken-node incident bundle: id={} verify={}",
                    args.id, args.verify
                );
                let events = synthetic_incident_events(&args.id);
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
                eprintln!("franken-node incident list: severity={:?}", args.severity);
                eprintln!("[not yet implemented]");
            }
        },

        Command::Registry(sub) => match sub {
            RegistryCommand::Publish(args) => {
                eprintln!(
                    "franken-node registry publish: package={}",
                    args.package_path.display()
                );
                eprintln!("[not yet implemented]");
            }
            RegistryCommand::Search(args) => {
                eprintln!(
                    "franken-node registry search: query={} min_assurance={:?}",
                    args.query, args.min_assurance
                );
                eprintln!("[not yet implemented]");
            }
        },

        Command::Bench(sub) => match sub {
            BenchCommand::Run(args) => {
                eprintln!("franken-node bench run: scenario={:?}", args.scenario);
                eprintln!("[not yet implemented]");
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
            let report = build_doctor_report(&resolved, &args.trace_id);

            if args.json {
                println!("{}", serde_json::to_string_pretty(&report)?);
            } else {
                println!("{}", render_doctor_report_human(&report, args.verbose));
            }
        }
    }

    Ok(())
}
