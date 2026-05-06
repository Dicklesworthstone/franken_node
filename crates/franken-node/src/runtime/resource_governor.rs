//! Swarm resource-governor telemetry for validation proof scheduling.
//!
//! The governor is intentionally advisory. It gives agents and operators a
//! deterministic decision before cargo/RCH work starts, while preserving
//! source-only progress when validation pressure is too high.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::fs;
use std::path::{Component, Path};

pub const REPORT_SCHEMA_VERSION: &str = "franken-node/resource-governor/report/v1";
pub const ARTIFACT_SCHEMA_VERSION: &str = "franken-node/resource-governor/artifact/v1";
pub const COMMAND_NAME: &str = "ops resource-governor";
pub const MAX_ARTIFACT_INVENTORY_ENTRIES: usize = 1_024;
pub const MAX_ARTIFACT_PATH_BYTES: usize = 4_096;
pub const MAX_ARTIFACT_FIELD_BYTES: usize = 512;

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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ResourceArtifactKind {
    CargoTargetDir,
    RchTargetDir,
    GeneratedEvidence,
    TempOutput,
    CacheEntry,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ResourceArtifactSafetyClass {
    SourceNeverDelete,
    UserDataNeverDelete,
    LogsSessionHistoryNeverDelete,
    BeadsMailNeverDelete,
    PinnedGeneratedArtifact,
    GeneratedEvidence,
    RebuildableBuildOutput,
    DisposableTempOutput,
}

impl ResourceArtifactSafetyClass {
    pub fn allows_cleanup(self) -> bool {
        matches!(
            self,
            Self::GeneratedEvidence | Self::RebuildableBuildOutput | Self::DisposableTempOutput
        )
    }

    pub fn is_protected(self) -> bool {
        !self.allows_cleanup()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ResourceArtifactOpenFileStatus {
    Unknown,
    Open,
    NotOpen,
}

impl Default for ResourceArtifactOpenFileStatus {
    fn default() -> Self {
        Self::Unknown
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResourceArtifactPin {
    pub reason: String,
    pub owner_agent: Option<String>,
    pub bead_id: Option<String>,
    pub expires_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResourceArtifactInventoryEntry {
    pub path: String,
    pub repo_key: String,
    pub kind: ResourceArtifactKind,
    pub safety_class: ResourceArtifactSafetyClass,
    pub bytes: Option<u64>,
    pub mtime: Option<DateTime<Utc>>,
    pub owner_agent: Option<String>,
    pub bead_id: Option<String>,
    pub producer_command_digest: Option<String>,
    pub content_digest: Option<String>,
    pub pin: Option<ResourceArtifactPin>,
    #[serde(default)]
    pub open_file_status: ResourceArtifactOpenFileStatus,
    pub minimum_age_secs: Option<u64>,
    pub cleanup_eligible: bool,
}

impl ResourceArtifactInventoryEntry {
    pub fn new(
        path: impl Into<String>,
        repo_key: impl Into<String>,
        kind: ResourceArtifactKind,
        safety_class: ResourceArtifactSafetyClass,
        bytes: Option<u64>,
    ) -> Self {
        let mut entry = Self {
            path: path.into(),
            repo_key: repo_key.into(),
            kind,
            safety_class,
            bytes,
            mtime: None,
            owner_agent: None,
            bead_id: None,
            producer_command_digest: None,
            content_digest: None,
            pin: None,
            open_file_status: ResourceArtifactOpenFileStatus::Unknown,
            minimum_age_secs: None,
            cleanup_eligible: false,
        };
        entry.cleanup_eligible = entry.derived_cleanup_eligibility();
        entry
    }

    pub fn with_pin(mut self, pin: ResourceArtifactPin) -> Self {
        self.pin = Some(pin);
        self.cleanup_eligible = self.derived_cleanup_eligibility();
        self
    }

    pub fn with_open_file_status(mut self, status: ResourceArtifactOpenFileStatus) -> Self {
        self.open_file_status = status;
        self.cleanup_eligible = self.derived_cleanup_eligibility();
        self
    }

    fn validated(mut self) -> Result<Self, ResourceArtifactInventoryError> {
        validate_artifact_string("path", &self.path, MAX_ARTIFACT_PATH_BYTES)?;
        validate_artifact_string("repo_key", &self.repo_key, MAX_ARTIFACT_PATH_BYTES)?;
        reject_unsafe_path("path", &self.path)?;
        reject_unsafe_path("repo_key", &self.repo_key)?;
        validate_optional_artifact_string("owner_agent", self.owner_agent.as_deref())?;
        validate_optional_artifact_string("bead_id", self.bead_id.as_deref())?;
        validate_optional_artifact_string(
            "producer_command_digest",
            self.producer_command_digest.as_deref(),
        )?;
        validate_optional_artifact_string("content_digest", self.content_digest.as_deref())?;
        if let Some(pin) = &self.pin {
            validate_artifact_string("pin.reason", &pin.reason, MAX_ARTIFACT_FIELD_BYTES)?;
            validate_optional_artifact_string("pin.owner_agent", pin.owner_agent.as_deref())?;
            validate_optional_artifact_string("pin.bead_id", pin.bead_id.as_deref())?;
        }
        if path_is_protected_workspace_state(&self.path) && !self.safety_class.is_protected() {
            return Err(ResourceArtifactInventoryError::ProtectedPath {
                field: "path",
                path: self.path,
            });
        }
        self.cleanup_eligible = self.derived_cleanup_eligibility();
        Ok(self)
    }

    fn derived_cleanup_eligibility(&self) -> bool {
        self.safety_class.allows_cleanup()
            && self.kind != ResourceArtifactKind::Unknown
            && self.bytes.is_some()
            && self.pin.is_none()
            && self.open_file_status == ResourceArtifactOpenFileStatus::NotOpen
            && !path_is_protected_workspace_state(&self.path)
            && !(self.minimum_age_secs.unwrap_or(0) > 0 && self.mtime.is_none())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResourceArtifactInventory {
    pub schema_version: String,
    pub entries: Vec<ResourceArtifactInventoryEntry>,
}

impl Default for ResourceArtifactInventory {
    fn default() -> Self {
        Self {
            schema_version: ARTIFACT_SCHEMA_VERSION.to_string(),
            entries: Vec::new(),
        }
    }
}

impl ResourceArtifactInventory {
    pub fn try_new(
        entries: Vec<ResourceArtifactInventoryEntry>,
    ) -> Result<Self, ResourceArtifactInventoryError> {
        if entries.len() > MAX_ARTIFACT_INVENTORY_ENTRIES {
            return Err(ResourceArtifactInventoryError::TooManyEntries {
                count: entries.len(),
                max: MAX_ARTIFACT_INVENTORY_ENTRIES,
            });
        }

        let mut seen_paths = BTreeSet::new();
        let mut validated_entries = Vec::with_capacity(entries.len());
        for entry in entries {
            let entry = entry.validated()?;
            if !seen_paths.insert(entry.path.clone()) {
                return Err(ResourceArtifactInventoryError::DuplicatePath { path: entry.path });
            }
            validated_entries.push(entry);
        }

        Ok(Self {
            schema_version: ARTIFACT_SCHEMA_VERSION.to_string(),
            entries: validated_entries,
        })
    }

    pub fn cleanup_candidates(&self) -> impl Iterator<Item = &ResourceArtifactInventoryEntry> {
        self.entries.iter().filter(|entry| entry.cleanup_eligible)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ResourceArtifactInventoryError {
    #[error("RG_ARTIFACT_TOO_MANY_ENTRIES: inventory has {count} entries, max {max}")]
    TooManyEntries { count: usize, max: usize },
    #[error("RG_ARTIFACT_STRING_TOO_LONG: {field} has {len} bytes, max {max}")]
    StringTooLong {
        field: &'static str,
        len: usize,
        max: usize,
    },
    #[error("RG_ARTIFACT_PATH_CONTAINS_NUL: {field} contains a NUL byte")]
    PathContainsNul { field: &'static str },
    #[error("RG_ARTIFACT_PATH_TRAVERSAL: {field} contains parent traversal")]
    PathTraversal { field: &'static str },
    #[error("RG_ARTIFACT_PROTECTED_PATH: {field} is protected workspace state: {path}")]
    ProtectedPath { field: &'static str, path: String },
    #[error("RG_ARTIFACT_DUPLICATE_PATH: duplicate artifact path {path}")]
    DuplicatePath { path: String },
}

impl ResourceArtifactInventoryError {
    pub fn code(&self) -> &'static str {
        match self {
            Self::TooManyEntries { .. } => "RG_ARTIFACT_TOO_MANY_ENTRIES",
            Self::StringTooLong { .. } => "RG_ARTIFACT_STRING_TOO_LONG",
            Self::PathContainsNul { .. } => "RG_ARTIFACT_PATH_CONTAINS_NUL",
            Self::PathTraversal { .. } => "RG_ARTIFACT_PATH_TRAVERSAL",
            Self::ProtectedPath { .. } => "RG_ARTIFACT_PROTECTED_PATH",
            Self::DuplicatePath { .. } => "RG_ARTIFACT_DUPLICATE_PATH",
        }
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
    pub artifact_inventory: ResourceArtifactInventory,
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
            artifact_inventory: ResourceArtifactInventory::default(),
        }
    }

    pub fn from_snapshot(
        input: ResourceGovernorSnapshotInput,
        default_observed_at: DateTime<Utc>,
    ) -> Result<Self, ResourceArtifactInventoryError> {
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
        observation.artifact_inventory =
            ResourceArtifactInventory::try_new(input.artifact_inventory)?;
        Ok(observation)
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

    pub fn replace_artifact_inventory(&mut self, inventory: ResourceArtifactInventory) {
        self.artifact_inventory = inventory;
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
    #[serde(default)]
    pub artifact_inventory: Vec<ResourceArtifactInventoryEntry>,
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
    ResourceGovernorObservation::from_snapshot(input, default_observed_at).map_err(|source| {
        ResourceGovernorSnapshotError::InvalidArtifactInventory {
            path: path.display().to_string(),
            source,
        }
    })
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
    #[error("failed validating resource-governor artifact inventory {path}: {source}")]
    InvalidArtifactInventory {
        path: String,
        source: ResourceArtifactInventoryError,
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

fn validate_artifact_string(
    field: &'static str,
    value: &str,
    max: usize,
) -> Result<(), ResourceArtifactInventoryError> {
    let len = value.len();
    if len > max {
        Err(ResourceArtifactInventoryError::StringTooLong { field, len, max })
    } else {
        Ok(())
    }
}

fn validate_optional_artifact_string(
    field: &'static str,
    value: Option<&str>,
) -> Result<(), ResourceArtifactInventoryError> {
    if let Some(value) = value {
        validate_artifact_string(field, value, MAX_ARTIFACT_FIELD_BYTES)?;
    }
    Ok(())
}

fn reject_unsafe_path(
    field: &'static str,
    value: &str,
) -> Result<(), ResourceArtifactInventoryError> {
    if value.contains('\0') {
        return Err(ResourceArtifactInventoryError::PathContainsNul { field });
    }
    if Path::new(value)
        .components()
        .any(|component| component == Component::ParentDir)
    {
        return Err(ResourceArtifactInventoryError::PathTraversal { field });
    }
    Ok(())
}

fn path_is_protected_workspace_state(path: &str) -> bool {
    path.split('/')
        .any(|component| matches!(component, ".beads" | ".agent-mail" | "agent-mail"))
        || path.contains("/messages/")
        || path.contains("/agents/")
        || path.contains("/sessions/")
        || path.contains("/memories/")
        || path.contains("/logs/")
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

#[cfg(test)]
mod tests {
    use super::*;

    fn target_entry(path: &str) -> ResourceArtifactInventoryEntry {
        ResourceArtifactInventoryEntry::new(
            path,
            "/data/projects/franken_node",
            ResourceArtifactKind::CargoTargetDir,
            ResourceArtifactSafetyClass::RebuildableBuildOutput,
            Some(1024),
        )
        .with_open_file_status(ResourceArtifactOpenFileStatus::NotOpen)
    }

    fn generated_evidence_entry(path: &str) -> ResourceArtifactInventoryEntry {
        ResourceArtifactInventoryEntry::new(
            path,
            "/data/projects/franken_node",
            ResourceArtifactKind::GeneratedEvidence,
            ResourceArtifactSafetyClass::GeneratedEvidence,
            Some(512),
        )
        .with_open_file_status(ResourceArtifactOpenFileStatus::NotOpen)
    }

    fn pin() -> ResourceArtifactPin {
        ResourceArtifactPin {
            reason: "active bead proof".to_string(),
            owner_agent: Some("DustyDesert".to_string()),
            bead_id: Some("bd-p9mpd.2".to_string()),
            expires_at: None,
        }
    }

    #[test]
    fn empty_artifact_inventory_has_schema_and_no_candidates() {
        let inventory = ResourceArtifactInventory::try_new(Vec::new()).expect("empty inventory");

        assert_eq!(inventory.schema_version, ARTIFACT_SCHEMA_VERSION);
        assert_eq!(inventory.cleanup_candidates().count(), 0);
    }

    #[test]
    fn valid_artifact_inventory_round_trips_and_marks_cleanup_candidate() {
        let inventory = ResourceArtifactInventory::try_new(vec![target_entry(
            "/data/projects/franken_node/target",
        )])
        .expect("valid inventory");

        assert_eq!(inventory.cleanup_candidates().count(), 1);
        let encoded = serde_json::to_string(&inventory).expect("serialize inventory");
        assert!(encoded.contains("franken-node/resource-governor/artifact/v1"));
        assert!(encoded.contains("rebuildable-build-output"));

        let decoded =
            serde_json::from_str::<ResourceArtifactInventory>(&encoded).expect("decode inventory");
        assert_eq!(decoded.entries.len(), 1);
        assert!(decoded.entries[0].cleanup_eligible);
    }

    #[test]
    fn artifact_inventory_rejects_nul_paths() {
        let err = ResourceArtifactInventory::try_new(vec![target_entry(
            "/data/projects/franken_node/\0",
        )])
        .expect_err("nul path should fail");

        assert_eq!(err.code(), "RG_ARTIFACT_PATH_CONTAINS_NUL");
    }

    #[test]
    fn artifact_inventory_rejects_parent_traversal() {
        let err = ResourceArtifactInventory::try_new(vec![target_entry(
            "/data/projects/franken_node/../franken_engine/target",
        )])
        .expect_err("parent traversal should fail");

        assert_eq!(err.code(), "RG_ARTIFACT_PATH_TRAVERSAL");
    }

    #[test]
    fn artifact_inventory_rejects_duplicate_paths() {
        let err = ResourceArtifactInventory::try_new(vec![
            target_entry("/data/projects/franken_node/target"),
            target_entry("/data/projects/franken_node/target"),
        ])
        .expect_err("duplicate path should fail");

        assert_eq!(err.code(), "RG_ARTIFACT_DUPLICATE_PATH");
    }

    #[test]
    fn artifact_inventory_caps_entry_count() {
        let entries = (0..=MAX_ARTIFACT_INVENTORY_ENTRIES)
            .map(|idx| target_entry(&format!("/data/projects/franken_node/target/{idx}")))
            .collect::<Vec<_>>();
        let err = ResourceArtifactInventory::try_new(entries).expect_err("entry cap should fail");

        assert_eq!(err.code(), "RG_ARTIFACT_TOO_MANY_ENTRIES");
    }

    #[test]
    fn pinned_generated_output_is_not_cleanup_eligible() {
        let entry = generated_evidence_entry("/data/projects/franken_node/artifacts/report.json")
            .with_pin(pin());
        let inventory = ResourceArtifactInventory::try_new(vec![entry]).expect("pinned inventory");

        assert_eq!(inventory.cleanup_candidates().count(), 0);
        assert!(!inventory.entries[0].cleanup_eligible);
    }

    #[test]
    fn open_generated_output_is_not_cleanup_eligible() {
        let entry = generated_evidence_entry("/data/projects/franken_node/artifacts/report.json")
            .with_open_file_status(ResourceArtifactOpenFileStatus::Open);
        let inventory = ResourceArtifactInventory::try_new(vec![entry]).expect("open inventory");

        assert_eq!(inventory.cleanup_candidates().count(), 0);
        assert!(!inventory.entries[0].cleanup_eligible);
    }

    #[test]
    fn unknown_open_file_status_fails_closed_for_cleanup() {
        let entry = ResourceArtifactInventoryEntry::new(
            "/data/projects/franken_node/artifacts/report.json",
            "/data/projects/franken_node",
            ResourceArtifactKind::GeneratedEvidence,
            ResourceArtifactSafetyClass::GeneratedEvidence,
            Some(512),
        );
        let inventory = ResourceArtifactInventory::try_new(vec![entry]).expect("unknown inventory");

        assert_eq!(inventory.cleanup_candidates().count(), 0);
        assert!(!inventory.entries[0].cleanup_eligible);
    }

    #[test]
    fn protected_workspace_paths_cannot_be_marked_rebuildable() {
        let err = ResourceArtifactInventory::try_new(vec![target_entry(
            "/data/projects/franken_node/.beads/issues.jsonl",
        )])
        .expect_err("beads path should be protected");

        assert_eq!(err.code(), "RG_ARTIFACT_PROTECTED_PATH");
    }

    #[test]
    fn protected_safety_classes_are_never_cleanup_candidates() {
        let entry = ResourceArtifactInventoryEntry::new(
            "/data/projects/franken_node/src/lib.rs",
            "/data/projects/franken_node",
            ResourceArtifactKind::Unknown,
            ResourceArtifactSafetyClass::SourceNeverDelete,
            Some(1),
        );
        let inventory = ResourceArtifactInventory::try_new(vec![entry]).expect("source inventory");

        assert_eq!(inventory.cleanup_candidates().count(), 0);
        assert!(!inventory.entries[0].cleanup_eligible);
    }

    #[test]
    fn observation_can_carry_artifact_inventory() {
        let inventory = ResourceArtifactInventory::try_new(vec![target_entry(
            "/data/projects/franken_node/target",
        )])
        .expect("valid inventory");
        let mut observation = ResourceGovernorObservation::new(Utc::now(), "fixture", Vec::new());
        observation.replace_artifact_inventory(inventory);

        assert_eq!(observation.artifact_inventory.entries.len(), 1);
        assert_eq!(
            observation.artifact_inventory.cleanup_candidates().count(),
            1
        );
    }

    #[test]
    fn snapshot_input_attaches_valid_artifact_inventory() {
        let observation = ResourceGovernorObservation::from_snapshot(
            ResourceGovernorSnapshotInput {
                artifact_inventory: vec![target_entry("/data/projects/franken_node/target")],
                ..ResourceGovernorSnapshotInput::default()
            },
            Utc::now(),
        )
        .expect("valid snapshot inventory");

        assert_eq!(observation.artifact_inventory.entries.len(), 1);
        assert_eq!(
            observation.artifact_inventory.cleanup_candidates().count(),
            1
        );
    }

    #[test]
    fn snapshot_input_rejects_invalid_artifact_inventory() {
        let err = ResourceGovernorObservation::from_snapshot(
            ResourceGovernorSnapshotInput {
                artifact_inventory: vec![target_entry(
                    "/data/projects/franken_node/.beads/issues.jsonl",
                )],
                ..ResourceGovernorSnapshotInput::default()
            },
            Utc::now(),
        )
        .expect_err("invalid snapshot inventory");

        assert_eq!(err.code(), "RG_ARTIFACT_PROTECTED_PATH");
    }
}
