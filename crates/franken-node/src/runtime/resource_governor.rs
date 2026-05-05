//! Swarm resource-governor telemetry for validation proof scheduling.
//!
//! The governor is intentionally advisory. It gives agents and operators a
//! deterministic decision before cargo/RCH work starts, while preserving
//! source-only progress when validation pressure is too high.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::fs;
use std::path::Path;

pub const REPORT_SCHEMA_VERSION: &str = "franken-node/resource-governor/report/v1";
pub const COMMAND_NAME: &str = "ops resource-governor";

pub mod event_codes {
    pub const OBSERVATION_RECORDED: &str = "RG-001";
    pub const DECISION_RECORDED: &str = "RG-002";
}

pub mod reason_codes {
    pub const ALLOW_IDLE: &str = "RG_ALLOW_IDLE";
    pub const ALLOW_LOW_PRIORITY_MODERATE_CONTENTION: &str =
        "RG_ALLOW_LOW_PRIORITY_MODERATE_CONTENTION";
    pub const DEDUPE_ACTIVE_PROOF_CLASS: &str = "RG_DEDUPE_ACTIVE_PROOF_CLASS";
    pub const SOURCE_ONLY_CONTENTION: &str = "RG_SOURCE_ONLY_CONTENTION";
    pub const DEFER_CONTENTION: &str = "RG_DEFER_CONTENTION";
    pub const DEFER_STALE_OBSERVATION: &str = "RG_DEFER_STALE_OBSERVATION";
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ResourceGovernorDecisionKind {
    Allow,
    AllowLowPriority,
    DedupeOnly,
    SourceOnly,
    Defer,
}

impl ResourceGovernorDecisionKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Allow => "allow",
            Self::AllowLowPriority => "allow_low_priority",
            Self::DedupeOnly => "dedupe_only",
            Self::SourceOnly => "source_only",
            Self::Defer => "defer",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ResourceProcessKind {
    Cargo,
    Rustc,
    Rch,
    OtherValidation,
}

impl ResourceProcessKind {
    fn as_str(self) -> &'static str {
        match self {
            Self::Cargo => "cargo",
            Self::Rustc => "rustc",
            Self::Rch => "rch",
            Self::OtherValidation => "other_validation",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ObservedValidationProcess {
    pub pid: Option<u32>,
    pub command: String,
    pub kind: ResourceProcessKind,
}

impl ObservedValidationProcess {
    pub fn new(pid: Option<u32>, command: impl Into<String>) -> Option<Self> {
        let command = command.into();
        classify_validation_process(&command).map(|kind| Self { pid, command, kind })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResourceProcessCounts {
    pub cargo: u64,
    pub rustc: u64,
    pub rch: u64,
    pub other_validation: u64,
    pub total_validation_processes: u64,
}

impl ResourceProcessCounts {
    pub fn from_processes(processes: &[ObservedValidationProcess]) -> Self {
        let mut counts = Self {
            cargo: 0,
            rustc: 0,
            rch: 0,
            other_validation: 0,
            total_validation_processes: usize_to_u64(processes.len()),
        };
        for process in processes {
            match process.kind {
                ResourceProcessKind::Cargo => counts.cargo = counts.cargo.saturating_add(1),
                ResourceProcessKind::Rustc => counts.rustc = counts.rustc.saturating_add(1),
                ResourceProcessKind::Rch => counts.rch = counts.rch.saturating_add(1),
                ResourceProcessKind::OtherValidation => {
                    counts.other_validation = counts.other_validation.saturating_add(1);
                }
            }
        }
        counts
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResourceGovernorThresholds {
    pub stale_observation_after_ms: u64,
    pub low_priority_processes_at: u64,
    pub source_only_processes_at: u64,
    pub defer_processes_at: u64,
    pub low_priority_rch_queue_at: u64,
    pub source_only_rch_queue_at: u64,
    pub defer_rch_queue_at: u64,
    pub low_priority_target_dir_mb_at: u64,
    pub source_only_target_dir_mb_at: u64,
    pub defer_target_dir_mb_at: u64,
    pub low_priority_memory_mb_at: u64,
    pub source_only_memory_mb_at: u64,
    pub defer_memory_mb_at: u64,
    pub low_priority_cpu_permyriad_at: u64,
    pub source_only_cpu_permyriad_at: u64,
    pub defer_cpu_permyriad_at: u64,
}

impl Default for ResourceGovernorThresholds {
    fn default() -> Self {
        Self {
            stale_observation_after_ms: 300_000,
            low_priority_processes_at: 2,
            source_only_processes_at: 4,
            defer_processes_at: 6,
            low_priority_rch_queue_at: 2,
            source_only_rch_queue_at: 4,
            defer_rch_queue_at: 8,
            low_priority_target_dir_mb_at: 8_192,
            source_only_target_dir_mb_at: 32_768,
            defer_target_dir_mb_at: 65_536,
            low_priority_memory_mb_at: 64_000,
            source_only_memory_mb_at: 128_000,
            defer_memory_mb_at: 192_000,
            low_priority_cpu_permyriad_at: 7_500,
            source_only_cpu_permyriad_at: 9_000,
            defer_cpu_permyriad_at: 9_750,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResourceGovernorObservation {
    pub observed_at: DateTime<Utc>,
    pub source: String,
    pub processes: Vec<ObservedValidationProcess>,
    pub process_counts: ResourceProcessCounts,
    pub rch_queue_depth: Option<u64>,
    pub active_proof_classes: Vec<String>,
    pub target_dir_usage_mb: Option<u64>,
    pub memory_used_mb: Option<u64>,
    pub cpu_load_permyriad: Option<u64>,
}

impl ResourceGovernorObservation {
    pub fn new(
        observed_at: DateTime<Utc>,
        source: impl Into<String>,
        processes: Vec<ObservedValidationProcess>,
    ) -> Self {
        let process_counts = ResourceProcessCounts::from_processes(&processes);
        Self {
            observed_at,
            source: source.into(),
            processes,
            process_counts,
            rch_queue_depth: None,
            active_proof_classes: Vec::new(),
            target_dir_usage_mb: None,
            memory_used_mb: None,
            cpu_load_permyriad: None,
        }
    }

    pub fn from_snapshot(
        input: ResourceGovernorSnapshotInput,
        default_observed_at: DateTime<Utc>,
    ) -> Self {
        let processes = input
            .processes
            .into_iter()
            .filter_map(|process| {
                let kind = process
                    .kind
                    .or_else(|| classify_validation_process(&process.command))?;
                Some(ObservedValidationProcess {
                    pid: process.pid,
                    command: process.command,
                    kind,
                })
            })
            .collect::<Vec<_>>();
        let mut observation = Self::new(
            input.observed_at.unwrap_or(default_observed_at),
            input.source.unwrap_or_else(|| "snapshot".to_string()),
            processes,
        );
        observation.merge_hints(
            input.rch_queue_depth,
            input.active_proof_classes,
            input.target_dir_usage_mb,
            input.memory_used_mb,
            input.cpu_load_permyriad,
        );
        observation
    }

    pub fn merge_hints(
        &mut self,
        rch_queue_depth: Option<u64>,
        active_proof_classes: Vec<String>,
        target_dir_usage_mb: Option<u64>,
        memory_used_mb: Option<u64>,
        cpu_load_permyriad: Option<u64>,
    ) {
        if let Some(depth) = rch_queue_depth {
            self.rch_queue_depth = Some(depth);
        }
        if let Some(usage) = target_dir_usage_mb {
            self.target_dir_usage_mb = Some(usage);
        }
        if let Some(usage) = memory_used_mb {
            self.memory_used_mb = Some(usage);
        }
        if let Some(load) = cpu_load_permyriad {
            self.cpu_load_permyriad = Some(load);
        }
        let classes = self
            .active_proof_classes
            .iter()
            .filter(|class| !class.trim().is_empty())
            .map(|class| class.trim().to_string())
            .chain(
                active_proof_classes
                    .into_iter()
                    .filter(|class| !class.trim().is_empty())
                    .map(|class| class.trim().to_string()),
            )
            .collect::<BTreeSet<_>>();
        self.active_proof_classes = classes.into_iter().collect();
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SnapshotProcessInput {
    pub pid: Option<u32>,
    pub command: String,
    pub kind: Option<ResourceProcessKind>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct ResourceGovernorSnapshotInput {
    pub observed_at: Option<DateTime<Utc>>,
    pub source: Option<String>,
    #[serde(default)]
    pub processes: Vec<SnapshotProcessInput>,
    pub rch_queue_depth: Option<u64>,
    #[serde(default)]
    pub active_proof_classes: Vec<String>,
    pub target_dir_usage_mb: Option<u64>,
    pub memory_used_mb: Option<u64>,
    pub cpu_load_permyriad: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResourceGovernorRequest {
    pub trace_id: String,
    pub requested_proof_class: Option<String>,
    pub source_only_allowed: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResourceGovernorDecision {
    pub kind: ResourceGovernorDecisionKind,
    pub reason_code: String,
    pub reason: String,
    pub recommended_backoff_ms: u64,
    pub next_action: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResourceGovernorStructuredLog {
    pub event_code: String,
    pub trace_id: String,
    pub decision: ResourceGovernorDecisionKind,
    pub reason_code: String,
    pub observed_validation_processes: u64,
    pub rch_queue_depth: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResourceGovernorReport {
    pub schema_version: String,
    pub command: String,
    pub trace_id: String,
    pub observed_at: DateTime<Utc>,
    pub observation_age_ms: u64,
    pub observation: ResourceGovernorObservation,
    pub thresholds: ResourceGovernorThresholds,
    pub requested_proof_class: Option<String>,
    pub source_only_allowed: bool,
    pub decision: ResourceGovernorDecision,
    pub structured_log: ResourceGovernorStructuredLog,
}

pub fn evaluate_resource_governor(
    request: ResourceGovernorRequest,
    observation: ResourceGovernorObservation,
    thresholds: ResourceGovernorThresholds,
    now: DateTime<Utc>,
) -> ResourceGovernorReport {
    let observation_age_ms = timestamp_age_ms(now, observation.observed_at);
    let requested_proof_class = request
        .requested_proof_class
        .as_deref()
        .map(str::trim)
        .filter(|class| !class.is_empty())
        .map(ToOwned::to_owned);
    let decision = decide_resource_action(
        requested_proof_class.as_deref(),
        request.source_only_allowed,
        &observation,
        &thresholds,
        observation_age_ms,
    );
    let structured_log = ResourceGovernorStructuredLog {
        event_code: event_codes::DECISION_RECORDED.to_string(),
        trace_id: request.trace_id.clone(),
        decision: decision.kind,
        reason_code: decision.reason_code.clone(),
        observed_validation_processes: observation.process_counts.total_validation_processes,
        rch_queue_depth: observation.rch_queue_depth,
    };

    ResourceGovernorReport {
        schema_version: REPORT_SCHEMA_VERSION.to_string(),
        command: COMMAND_NAME.to_string(),
        trace_id: request.trace_id,
        observed_at: now,
        observation_age_ms,
        observation,
        thresholds,
        requested_proof_class,
        source_only_allowed: request.source_only_allowed,
        decision,
        structured_log,
    }
}

pub fn observe_live_validation_processes(now: DateTime<Utc>) -> ResourceGovernorObservation {
    let mut processes = Vec::new();
    if let Ok(entries) = fs::read_dir("/proc") {
        for entry in entries.flatten() {
            let Ok(pid) = entry.file_name().to_string_lossy().parse::<u32>() else {
                continue;
            };
            let cmdline_path = entry.path().join("cmdline");
            let Ok(raw) = fs::read(&cmdline_path) else {
                continue;
            };
            let command = decode_proc_cmdline(&raw);
            if command.trim().is_empty() {
                continue;
            }
            if let Some(process) = ObservedValidationProcess::new(Some(pid), command) {
                processes.push(process);
            }
        }
    }
    ResourceGovernorObservation::new(now, "procfs", processes)
}

pub fn read_snapshot_file(
    path: &Path,
    default_observed_at: DateTime<Utc>,
) -> Result<ResourceGovernorObservation, ResourceGovernorSnapshotError> {
    let raw = fs::read_to_string(path).map_err(|source| ResourceGovernorSnapshotError::Read {
        path: path.display().to_string(),
        source,
    })?;
    let input = serde_json::from_str::<ResourceGovernorSnapshotInput>(&raw).map_err(|source| {
        ResourceGovernorSnapshotError::Parse {
            path: path.display().to_string(),
            source,
        }
    })?;
    Ok(ResourceGovernorObservation::from_snapshot(
        input,
        default_observed_at,
    ))
}

#[derive(Debug, thiserror::Error)]
pub enum ResourceGovernorSnapshotError {
    #[error("failed reading resource-governor snapshot {path}: {source}")]
    Read {
        path: String,
        source: std::io::Error,
    },
    #[error("failed parsing resource-governor snapshot {path}: {source}")]
    Parse {
        path: String,
        source: serde_json::Error,
    },
}

fn decide_resource_action(
    requested_proof_class: Option<&str>,
    source_only_allowed: bool,
    observation: &ResourceGovernorObservation,
    thresholds: &ResourceGovernorThresholds,
    observation_age_ms: u64,
) -> ResourceGovernorDecision {
    if observation_age_ms > thresholds.stale_observation_after_ms {
        return decision(
            ResourceGovernorDecisionKind::Defer,
            reason_codes::DEFER_STALE_OBSERVATION,
            "resource observation is stale; refresh telemetry before expensive validation",
            thresholds.stale_observation_after_ms,
            "rerun ops resource-governor with a fresh snapshot",
        );
    }

    if let Some(requested) = requested_proof_class
        && observation
            .active_proof_classes
            .iter()
            .any(|active| active == requested)
    {
        return decision(
            ResourceGovernorDecisionKind::DedupeOnly,
            reason_codes::DEDUPE_ACTIVE_PROOF_CLASS,
            "an equivalent proof class is already active",
            0,
            "reuse or wait for the active broker receipt instead of launching duplicate proof work",
        );
    }

    let pressure = pressure_tier(observation, thresholds);
    match pressure {
        PressureTier::Defer if source_only_allowed => decision(
            ResourceGovernorDecisionKind::SourceOnly,
            reason_codes::SOURCE_ONLY_CONTENTION,
            "validation pressure is high; source-only work remains allowed",
            60_000,
            "skip cargo/RCH proof for now and record a source-only waiver with this reason code",
        ),
        PressureTier::Defer => decision(
            ResourceGovernorDecisionKind::Defer,
            reason_codes::DEFER_CONTENTION,
            "validation pressure exceeds defer thresholds",
            180_000,
            "defer cargo/RCH proof and retry after the recommended backoff",
        ),
        PressureTier::SourceOnly if source_only_allowed => decision(
            ResourceGovernorDecisionKind::SourceOnly,
            reason_codes::SOURCE_ONLY_CONTENTION,
            "validation pressure reached source-only thresholds",
            60_000,
            "continue source-only work and avoid launching new cargo/RCH proof",
        ),
        PressureTier::SourceOnly | PressureTier::LowPriority => decision(
            ResourceGovernorDecisionKind::AllowLowPriority,
            reason_codes::ALLOW_LOW_PRIORITY_MODERATE_CONTENTION,
            "validation pressure is moderate",
            15_000,
            "run only low-priority remote validation or wait for quieter conditions",
        ),
        PressureTier::Allow => decision(
            ResourceGovernorDecisionKind::Allow,
            reason_codes::ALLOW_IDLE,
            "validation pressure is below backoff thresholds",
            0,
            "cargo/RCH validation may run",
        ),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum PressureTier {
    Allow,
    LowPriority,
    SourceOnly,
    Defer,
}

fn pressure_tier(
    observation: &ResourceGovernorObservation,
    thresholds: &ResourceGovernorThresholds,
) -> PressureTier {
    let mut tier = tier_for_value(
        observation.process_counts.total_validation_processes,
        thresholds.low_priority_processes_at,
        thresholds.source_only_processes_at,
        thresholds.defer_processes_at,
    );
    if let Some(queue_depth) = observation.rch_queue_depth {
        tier = tier.max(tier_for_value(
            queue_depth,
            thresholds.low_priority_rch_queue_at,
            thresholds.source_only_rch_queue_at,
            thresholds.defer_rch_queue_at,
        ));
    }
    if let Some(usage) = observation.target_dir_usage_mb {
        tier = tier.max(tier_for_value(
            usage,
            thresholds.low_priority_target_dir_mb_at,
            thresholds.source_only_target_dir_mb_at,
            thresholds.defer_target_dir_mb_at,
        ));
    }
    if let Some(usage) = observation.memory_used_mb {
        tier = tier.max(tier_for_value(
            usage,
            thresholds.low_priority_memory_mb_at,
            thresholds.source_only_memory_mb_at,
            thresholds.defer_memory_mb_at,
        ));
    }
    if let Some(load) = observation.cpu_load_permyriad {
        tier = tier.max(tier_for_value(
            load,
            thresholds.low_priority_cpu_permyriad_at,
            thresholds.source_only_cpu_permyriad_at,
            thresholds.defer_cpu_permyriad_at,
        ));
    }
    tier
}

fn tier_for_value(
    value: u64,
    low_priority_at: u64,
    source_only_at: u64,
    defer_at: u64,
) -> PressureTier {
    if value >= defer_at {
        PressureTier::Defer
    } else if value >= source_only_at {
        PressureTier::SourceOnly
    } else if value >= low_priority_at {
        PressureTier::LowPriority
    } else {
        PressureTier::Allow
    }
}

fn decision(
    kind: ResourceGovernorDecisionKind,
    reason_code: &str,
    reason: &str,
    recommended_backoff_ms: u64,
    next_action: &str,
) -> ResourceGovernorDecision {
    ResourceGovernorDecision {
        kind,
        reason_code: reason_code.to_string(),
        reason: reason.to_string(),
        recommended_backoff_ms,
        next_action: next_action.to_string(),
    }
}

fn classify_validation_process(command: &str) -> Option<ResourceProcessKind> {
    let normalized = command.to_ascii_lowercase();
    if normalized.contains("rustc") {
        Some(ResourceProcessKind::Rustc)
    } else if normalized.contains("rch") {
        Some(ResourceProcessKind::Rch)
    } else if normalized.contains("cargo") {
        Some(ResourceProcessKind::Cargo)
    } else if normalized.contains("validation") || normalized.contains("proof") {
        Some(ResourceProcessKind::OtherValidation)
    } else {
        None
    }
}

fn decode_proc_cmdline(raw: &[u8]) -> String {
    raw.split(|byte| *byte == 0)
        .filter(|part| !part.is_empty())
        .map(|part| String::from_utf8_lossy(part))
        .collect::<Vec<_>>()
        .join(" ")
}

fn timestamp_age_ms(now: DateTime<Utc>, observed_at: DateTime<Utc>) -> u64 {
    let millis = now
        .signed_duration_since(observed_at)
        .num_milliseconds()
        .max(0);
    u64::try_from(millis).unwrap_or(u64::MAX)
}

fn usize_to_u64(value: usize) -> u64 {
    u64::try_from(value).unwrap_or(u64::MAX)
}

pub fn process_kind_label(kind: ResourceProcessKind) -> &'static str {
    kind.as_str()
}
