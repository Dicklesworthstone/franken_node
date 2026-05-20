//! Swarm resource-governor telemetry for validation proof scheduling.
//!
//! The governor is intentionally advisory. It gives agents and operators a
//! deterministic decision before cargo/RCH work starts, while preserving
//! source-only progress when validation pressure is too high.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::fs;
use std::path::{Component, Path};

pub const REPORT_SCHEMA_VERSION: &str = "franken-node/resource-governor/report/v1";
pub const ARTIFACT_SCHEMA_VERSION: &str = "franken-node/resource-governor/artifact/v1";
pub const PRESSURE_SAMPLE_SCHEMA_VERSION: &str =
    "franken-node/resource-governor/pressure-sample/v1";
pub const HOTSET_PREFETCH_SCHEMA_VERSION: &str =
    "franken-node/resource-governor/evidence-hotset-prefetch/v1";
pub const COMMAND_NAME: &str = "ops resource-governor";
pub const MAX_ARTIFACT_INVENTORY_ENTRIES: usize = 1_024;
pub const MAX_ARTIFACT_PATH_BYTES: usize = 4_096;
pub const MAX_ARTIFACT_FIELD_BYTES: usize = 512;
pub const MAX_PRESSURE_SAMPLE_PROCESSES: usize = 2_048;
pub const MAX_PRESSURE_SAMPLE_ROOTS: usize = 128;
pub const MAX_PRESSURE_SAMPLE_RCH_WORKERS: usize = 256;
pub const MAX_PRESSURE_SAMPLE_NUMA_NODES: usize = 128;
pub const MAX_PRESSURE_SAMPLE_UNAVAILABLE_SIGNALS: usize = 128;
pub const MAX_CLEANUP_CANDIDATES: usize = 1_024;
pub const CLEANUP_RECEIPT_SCHEMA_VERSION: &str =
    "franken-node/resource-governor/cleanup-receipt/v1";
pub const DEFAULT_MINIMUM_AGE_SECS: u64 = 300;

pub mod event_codes {
    pub const OBSERVATION_RECORDED: &str = "RG-001";
    pub const DECISION_RECORDED: &str = "RG-002";
    pub const CLEANUP_STARTED: &str = "RG-010";
    pub const CLEANUP_COMPLETED: &str = "RG-011";
    pub const CLEANUP_PATH_REMOVED: &str = "RG-012";
    pub const CLEANUP_PATH_SKIPPED: &str = "RG-013";
    pub const CLEANUP_PATH_FAILED: &str = "RG-014";
}

pub mod reason_codes {
    pub const ALLOW_IDLE: &str = "RG_ALLOW_IDLE";
    pub const ALLOW_LOW_PRIORITY_MODERATE_CONTENTION: &str =
        "RG_ALLOW_LOW_PRIORITY_MODERATE_CONTENTION";
    pub const DEDUPE_ACTIVE_PROOF_CLASS: &str = "RG_DEDUPE_ACTIVE_PROOF_CLASS";
    pub const SOURCE_ONLY_CORRUPT_COORDINATION: &str = "RG_SOURCE_ONLY_CORRUPT_COORDINATION";
    pub const SOURCE_ONLY_CONTENTION: &str = "RG_SOURCE_ONLY_CONTENTION";
    pub const DEFER_CORRUPT_COORDINATION: &str = "RG_DEFER_CORRUPT_COORDINATION";
    pub const DEFER_CONTENTION: &str = "RG_DEFER_CONTENTION";
    pub const DEFER_STALE_OBSERVATION: &str = "RG_DEFER_STALE_OBSERVATION";
    pub const HOTSET_RECENT_BEAD_ACTIVITY: &str = "RG_HOTSET_RECENT_BEAD_ACTIVITY";
    pub const HOTSET_PROOF_CACHE_REUSE: &str = "RG_HOTSET_PROOF_CACHE_REUSE";
    pub const HOTSET_TEST_TARGET_FREQUENCY: &str = "RG_HOTSET_TEST_TARGET_FREQUENCY";
    pub const HOTSET_SOURCE_MANIFEST: &str = "RG_HOTSET_SOURCE_MANIFEST";
    pub const HOTSET_GENERATED_EVIDENCE: &str = "RG_HOTSET_GENERATED_EVIDENCE";
    pub const HOTSET_PROOF_CACHE_METADATA: &str = "RG_HOTSET_PROOF_CACHE_METADATA";
    pub const HOTSET_REBUILDABLE_OUTPUT: &str = "RG_HOTSET_REBUILDABLE_OUTPUT";
    pub const HOTSET_UNKNOWN_KIND: &str = "RG_HOTSET_UNKNOWN_KIND";
    pub const HOTSET_CAP_BYTES: &str = "RG_HOTSET_CAP_BYTES";
    pub const HOTSET_CAP_FILES: &str = "RG_HOTSET_CAP_FILES";
    pub const HOTSET_PRESSURE_BACKOFF: &str = "RG_HOTSET_PRESSURE_BACKOFF";
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
pub enum ResourceDiskRootKind {
    Project,
    Temp,
    TargetDir,
    RchTargetDir,
    CacheRoot,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ResourcePressureTier {
    Green,
    Yellow,
    Red,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResourceDiskPressureRoot {
    pub path: String,
    pub kind: ResourceDiskRootKind,
    pub total_bytes: Option<u64>,
    pub free_bytes: Option<u64>,
    pub used_bytes: Option<u64>,
}

impl ResourceDiskPressureRoot {
    pub fn free_permyriad(&self) -> Option<u64> {
        let total = self.total_bytes?;
        if total == 0 {
            return None;
        }
        Some(self.free_bytes?.saturating_mul(10_000) / total)
    }

    pub fn pressure_tier(&self) -> ResourcePressureTier {
        match self.free_permyriad() {
            Some(free) if free >= 1_500 => ResourcePressureTier::Green,
            Some(free) if free >= 500 => ResourcePressureTier::Yellow,
            Some(_) => ResourcePressureTier::Red,
            None => ResourcePressureTier::Unknown,
        }
    }

    fn validated(self) -> Result<Self, ResourcePressureSampleError> {
        reject_unsafe_path("disk_root.path", &self.path)
            .map_err(ResourcePressureSampleError::Artifact)?;
        validate_artifact_string("disk_root.path", &self.path, MAX_ARTIFACT_PATH_BYTES)
            .map_err(ResourcePressureSampleError::Artifact)?;
        Ok(self)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResourcePressureProcessInput {
    pub pid: Option<u32>,
    pub command: String,
    pub kind: Option<ResourceProcessKind>,
    #[serde(default)]
    pub sampler_self: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ResourceRchWorkerState {
    Available,
    Busy,
    Unreachable,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResourceRchWorkerPressure {
    pub worker_id: String,
    pub state: ResourceRchWorkerState,
    pub slots_total: Option<u64>,
    pub slots_free: Option<u64>,
}

impl ResourceRchWorkerPressure {
    fn validated(self) -> Result<Self, ResourcePressureSampleError> {
        validate_artifact_string(
            "rch_worker.worker_id",
            &self.worker_id,
            MAX_ARTIFACT_FIELD_BYTES,
        )
        .map_err(ResourcePressureSampleError::Artifact)?;
        Ok(self)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResourceMemoryPressure {
    pub total_bytes: Option<u64>,
    pub available_bytes: Option<u64>,
    pub used_bytes: Option<u64>,
    pub swap_total_bytes: Option<u64>,
    pub swap_used_bytes: Option<u64>,
    pub swap_used_permyriad: Option<u64>,
}

impl ResourceMemoryPressure {
    fn validated(self) -> Result<Self, ResourcePressureSampleError> {
        if let Some(value) = self.swap_used_permyriad {
            validate_permyriad("memory.swap_used_permyriad", value)?;
        }
        Ok(self)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResourceCpuPressure {
    pub load_permyriad: Option<u64>,
    pub build_job_cap: Option<u64>,
}

impl ResourceCpuPressure {
    fn validated(self) -> Result<Self, ResourcePressureSampleError> {
        if let Some(value) = self.load_permyriad {
            validate_permyriad("cpu.load_permyriad", value)?;
        }
        Ok(self)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResourceNumaNodePressure {
    pub node_id: u32,
    pub total_bytes: Option<u64>,
    pub available_bytes: Option<u64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum ResourceCoordinationHealth {
    Healthy,
    Degraded,
    Corrupt,
    #[default]
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct ResourceCoordinationPressure {
    pub agent_mail_health: ResourceCoordinationHealth,
    pub beads_health: ResourceCoordinationHealth,
    pub recovery_mode: Option<String>,
    pub stale_lock_count: u64,
    pub active_reservation_count: u64,
}

impl ResourceCoordinationPressure {
    fn validated(self) -> Result<Self, ResourcePressureSampleError> {
        validate_optional_artifact_string(
            "coordination.recovery_mode",
            self.recovery_mode.as_deref(),
        )
        .map_err(ResourcePressureSampleError::Artifact)?;
        Ok(self)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ResourcePressureSignal {
    Disk,
    TargetDir,
    RchQueue,
    RchWorkers,
    Memory,
    Swap,
    Cpu,
    Numa,
    Coordination,
    Reservations,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResourceUnavailableSignal {
    pub signal: ResourcePressureSignal,
    pub reason_code: String,
    pub detail: String,
}

impl ResourceUnavailableSignal {
    fn validated(self) -> Result<Self, ResourcePressureSampleError> {
        validate_artifact_string(
            "unavailable_signal.reason_code",
            &self.reason_code,
            MAX_ARTIFACT_FIELD_BYTES,
        )
        .map_err(ResourcePressureSampleError::Artifact)?;
        validate_artifact_string(
            "unavailable_signal.detail",
            &self.detail,
            MAX_ARTIFACT_FIELD_BYTES,
        )
        .map_err(ResourcePressureSampleError::Artifact)?;
        Ok(self)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct ResourcePressureSampleInput {
    pub observed_at: Option<DateTime<Utc>>,
    pub source: Option<String>,
    #[serde(default)]
    pub processes: Vec<ResourcePressureProcessInput>,
    #[serde(default)]
    pub disk_roots: Vec<ResourceDiskPressureRoot>,
    pub rch_queue_depth: Option<u64>,
    #[serde(default)]
    pub rch_workers: Vec<ResourceRchWorkerPressure>,
    pub memory: Option<ResourceMemoryPressure>,
    pub cpu: Option<ResourceCpuPressure>,
    #[serde(default)]
    pub numa_nodes: Vec<ResourceNumaNodePressure>,
    #[serde(default)]
    pub coordination: ResourceCoordinationPressure,
    #[serde(default)]
    pub unavailable_signals: Vec<ResourceUnavailableSignal>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResourcePressureSample {
    pub schema_version: String,
    pub observed_at: DateTime<Utc>,
    pub sample_age_ms: u64,
    pub source: String,
    pub processes: Vec<ObservedValidationProcess>,
    pub process_counts: ResourceProcessCounts,
    pub ignored_sampler_self_matches: u64,
    pub disk_roots: Vec<ResourceDiskPressureRoot>,
    pub target_dir_total_bytes: u64,
    pub rch_target_dir_total_bytes: u64,
    pub rch_queue_depth: Option<u64>,
    pub rch_workers: Vec<ResourceRchWorkerPressure>,
    pub memory: Option<ResourceMemoryPressure>,
    pub cpu: Option<ResourceCpuPressure>,
    pub numa_nodes: Vec<ResourceNumaNodePressure>,
    pub coordination: ResourceCoordinationPressure,
    pub unavailable_signals: Vec<ResourceUnavailableSignal>,
}

impl ResourcePressureSample {
    pub fn from_input(
        input: ResourcePressureSampleInput,
        default_observed_at: DateTime<Utc>,
    ) -> Result<Self, ResourcePressureSampleError> {
        validate_artifact_string(
            "pressure_sample.source",
            input.source.as_deref().unwrap_or("fixture"),
            MAX_ARTIFACT_FIELD_BYTES,
        )
        .map_err(ResourcePressureSampleError::Artifact)?;
        if input.processes.len() > MAX_PRESSURE_SAMPLE_PROCESSES {
            return Err(ResourcePressureSampleError::TooManyItems {
                field: "processes",
                count: input.processes.len(),
                max: MAX_PRESSURE_SAMPLE_PROCESSES,
            });
        }
        if input.disk_roots.len() > MAX_PRESSURE_SAMPLE_ROOTS {
            return Err(ResourcePressureSampleError::TooManyItems {
                field: "disk_roots",
                count: input.disk_roots.len(),
                max: MAX_PRESSURE_SAMPLE_ROOTS,
            });
        }
        if input.rch_workers.len() > MAX_PRESSURE_SAMPLE_RCH_WORKERS {
            return Err(ResourcePressureSampleError::TooManyItems {
                field: "rch_workers",
                count: input.rch_workers.len(),
                max: MAX_PRESSURE_SAMPLE_RCH_WORKERS,
            });
        }
        if input.numa_nodes.len() > MAX_PRESSURE_SAMPLE_NUMA_NODES {
            return Err(ResourcePressureSampleError::TooManyItems {
                field: "numa_nodes",
                count: input.numa_nodes.len(),
                max: MAX_PRESSURE_SAMPLE_NUMA_NODES,
            });
        }
        if input.unavailable_signals.len() > MAX_PRESSURE_SAMPLE_UNAVAILABLE_SIGNALS {
            return Err(ResourcePressureSampleError::TooManyItems {
                field: "unavailable_signals",
                count: input.unavailable_signals.len(),
                max: MAX_PRESSURE_SAMPLE_UNAVAILABLE_SIGNALS,
            });
        }

        let (processes, ignored_sampler_self_matches) =
            normalize_pressure_processes(input.processes)?;
        let process_counts = ResourceProcessCounts::from_processes(&processes);
        let disk_roots = input
            .disk_roots
            .into_iter()
            .map(ResourceDiskPressureRoot::validated)
            .collect::<Result<Vec<_>, _>>()?;
        let target_dir_total_bytes = sum_disk_root_used_bytes(&disk_roots, |kind| {
            matches!(kind, ResourceDiskRootKind::TargetDir)
        });
        let rch_target_dir_total_bytes = sum_disk_root_used_bytes(&disk_roots, |kind| {
            matches!(kind, ResourceDiskRootKind::RchTargetDir)
        });
        let rch_workers = input
            .rch_workers
            .into_iter()
            .map(ResourceRchWorkerPressure::validated)
            .collect::<Result<Vec<_>, _>>()?;
        let memory = input
            .memory
            .map(ResourceMemoryPressure::validated)
            .transpose()?;
        let cpu = input.cpu.map(ResourceCpuPressure::validated).transpose()?;
        let coordination = input.coordination.validated()?;
        let unavailable_signals = input
            .unavailable_signals
            .into_iter()
            .map(ResourceUnavailableSignal::validated)
            .collect::<Result<Vec<_>, _>>()?;

        let observed_at = input.observed_at.unwrap_or(default_observed_at);
        Ok(Self {
            schema_version: PRESSURE_SAMPLE_SCHEMA_VERSION.to_string(),
            observed_at,
            sample_age_ms: timestamp_age_ms(default_observed_at, observed_at),
            source: input.source.unwrap_or_else(|| "fixture".to_string()),
            processes,
            process_counts,
            ignored_sampler_self_matches,
            disk_roots,
            target_dir_total_bytes,
            rch_target_dir_total_bytes,
            rch_queue_depth: input.rch_queue_depth,
            rch_workers,
            memory,
            cpu,
            numa_nodes: input.numa_nodes,
            coordination,
            unavailable_signals,
        })
    }

    pub fn to_governor_observation(&self) -> ResourceGovernorObservation {
        let mut observation = ResourceGovernorObservation::new(
            self.observed_at,
            self.source.clone(),
            self.processes.clone(),
        );
        observation.rch_queue_depth = self.rch_queue_depth;
        observation.target_dir_usage_mb = Some(bytes_to_mb(self.target_dir_total_bytes));
        observation.memory_used_mb = self
            .memory
            .as_ref()
            .and_then(|memory| memory.used_bytes)
            .map(bytes_to_mb);
        observation.cpu_load_permyriad = self.cpu.as_ref().and_then(|cpu| cpu.load_permyriad);
        observation.coordination = self.coordination.clone();
        observation.unavailable_signals = self.unavailable_signals.clone();
        observation
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ResourcePressureSampleError {
    #[error("RG_PRESSURE_TOO_MANY_ITEMS: {field} has {count} items, max {max}")]
    TooManyItems {
        field: &'static str,
        count: usize,
        max: usize,
    },
    #[error("RG_PRESSURE_INVALID_PERMYRIAD: {field} is {value}, max 10000")]
    InvalidPermyriad { field: &'static str, value: u64 },
    #[error("{0}")]
    Artifact(ResourceArtifactInventoryError),
}

impl ResourcePressureSampleError {
    pub fn code(&self) -> &'static str {
        match self {
            Self::TooManyItems { .. } => "RG_PRESSURE_TOO_MANY_ITEMS",
            Self::InvalidPermyriad { .. } => "RG_PRESSURE_INVALID_PERMYRIAD",
            Self::Artifact(source) => source.code(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ResourceArtifactKind {
    CargoTargetDir,
    RchTargetDir,
    GeneratedEvidence,
    TempOutput,
    CacheEntry,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum ResourceArtifactOpenFileStatus {
    #[default]
    Unknown,
    Open,
    NotOpen,
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
        reject_unsafe_path("path", &self.path)?;
        reject_unsafe_path("repo_key", &self.repo_key)?;
        validate_artifact_string("path", &self.path, MAX_ARTIFACT_PATH_BYTES)?;
        validate_artifact_string("repo_key", &self.repo_key, MAX_ARTIFACT_PATH_BYTES)?;
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

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct EvidenceHotsetPrefetchCandidate {
    pub artifact: ResourceArtifactInventoryEntry,
    pub recent_bead_activity: f64,
    pub proof_cache_reuse: f64,
    pub test_target_frequency: f64,
}

impl EvidenceHotsetPrefetchCandidate {
    pub fn new(
        artifact: ResourceArtifactInventoryEntry,
        recent_bead_activity: f64,
        proof_cache_reuse: f64,
        test_target_frequency: f64,
    ) -> Self {
        Self {
            artifact,
            recent_bead_activity,
            proof_cache_reuse,
            test_target_frequency,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvidenceHotsetPrefetchPolicy {
    pub max_total_bytes: u64,
    pub max_files: usize,
    pub pressure_decision: ResourceGovernorDecisionKind,
}

impl Default for EvidenceHotsetPrefetchPolicy {
    fn default() -> Self {
        Self {
            max_total_bytes: 512 * 1024 * 1024,
            max_files: 256,
            pressure_decision: ResourceGovernorDecisionKind::Allow,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvidenceHotsetPrefetchEntry {
    pub path: String,
    pub kind: ResourceArtifactKind,
    pub safety_class: ResourceArtifactSafetyClass,
    pub artifact_digest: String,
    pub estimated_bytes: u64,
    pub score_micros: u64,
    pub reason_codes: Vec<String>,
    pub eviction_priority: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvidenceHotsetRejectedEntry {
    pub path: String,
    pub reason_code: String,
    pub detail: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvidenceHotsetPrefetchPlan {
    pub schema_version: String,
    pub pressure_decision: ResourceGovernorDecisionKind,
    pub max_total_bytes: u64,
    pub max_files: usize,
    pub estimated_bytes: u64,
    pub candidates_considered: usize,
    pub selected: Vec<EvidenceHotsetPrefetchEntry>,
    pub rejected: Vec<EvidenceHotsetRejectedEntry>,
}

#[derive(Debug, Clone, PartialEq, thiserror::Error)]
pub enum EvidenceHotsetPrefetchError {
    #[error("RG_HOTSET_TOO_MANY_CANDIDATES: hotset has {count} candidates, max {max}")]
    TooManyCandidates { count: usize, max: usize },
    #[error("RG_HOTSET_DUPLICATE_ARTIFACT: duplicate artifact path {path}")]
    DuplicateArtifact { path: String },
    #[error("RG_HOTSET_MISSING_FILE: artifact path {path} is not a readable file")]
    MissingFile { path: String },
    #[error("RG_HOTSET_MISSING_DIGEST: artifact path {path} has no content digest")]
    MissingDigest { path: String },
    #[error("RG_HOTSET_PROTECTED_PATH: artifact path {path} is protected workspace state")]
    ProtectedPath { path: String },
    #[error("RG_HOTSET_INVALID_SCORE: {field} for {path} is {value}")]
    InvalidScore {
        path: String,
        field: &'static str,
        value: f64,
    },
    #[error("{0}")]
    Artifact(ResourceArtifactInventoryError),
}

impl EvidenceHotsetPrefetchError {
    pub fn code(&self) -> &'static str {
        match self {
            Self::TooManyCandidates { .. } => "RG_HOTSET_TOO_MANY_CANDIDATES",
            Self::DuplicateArtifact { .. } => "RG_HOTSET_DUPLICATE_ARTIFACT",
            Self::MissingFile { .. } => "RG_HOTSET_MISSING_FILE",
            Self::MissingDigest { .. } => "RG_HOTSET_MISSING_DIGEST",
            Self::ProtectedPath { .. } => "RG_HOTSET_PROTECTED_PATH",
            Self::InvalidScore { .. } => "RG_HOTSET_INVALID_SCORE",
            Self::Artifact(source) => source.code(),
        }
    }
}

pub trait EvidenceHotsetFileProbe {
    fn file_len(&self, path: &str) -> Option<u64>;
}

pub struct FsEvidenceHotsetFileProbe;

impl EvidenceHotsetFileProbe for FsEvidenceHotsetFileProbe {
    fn file_len(&self, path: &str) -> Option<u64> {
        let metadata = fs::metadata(path).ok()?;
        if metadata.is_file() {
            Some(metadata.len())
        } else {
            None
        }
    }
}

pub fn plan_evidence_hotset_prefetch(
    candidates: Vec<EvidenceHotsetPrefetchCandidate>,
    policy: EvidenceHotsetPrefetchPolicy,
) -> Result<EvidenceHotsetPrefetchPlan, EvidenceHotsetPrefetchError> {
    plan_evidence_hotset_prefetch_with_probe(candidates, policy, &FsEvidenceHotsetFileProbe)
}

pub fn plan_evidence_hotset_prefetch_with_probe(
    candidates: Vec<EvidenceHotsetPrefetchCandidate>,
    policy: EvidenceHotsetPrefetchPolicy,
    probe: &impl EvidenceHotsetFileProbe,
) -> Result<EvidenceHotsetPrefetchPlan, EvidenceHotsetPrefetchError> {
    if candidates.len() > MAX_ARTIFACT_INVENTORY_ENTRIES {
        return Err(EvidenceHotsetPrefetchError::TooManyCandidates {
            count: candidates.len(),
            max: MAX_ARTIFACT_INVENTORY_ENTRIES,
        });
    }

    let mut seen_paths = BTreeSet::new();
    let mut ranked = Vec::with_capacity(candidates.len());
    for candidate in candidates {
        let ranked_candidate = RankedHotsetCandidate::try_from_candidate(candidate, probe)?;
        if !seen_paths.insert(ranked_candidate.artifact.path.clone()) {
            return Err(EvidenceHotsetPrefetchError::DuplicateArtifact {
                path: ranked_candidate.artifact.path,
            });
        }
        ranked.push(ranked_candidate);
    }

    ranked.sort_by(|left, right| {
        right
            .score_micros
            .cmp(&left.score_micros)
            .then_with(|| left.estimated_bytes.cmp(&right.estimated_bytes))
            .then_with(|| left.artifact.path.cmp(&right.artifact.path))
    });

    let (max_total_bytes, max_files) = pressure_adjusted_hotset_caps(&policy);
    let pressure_backoff = max_total_bytes == 0 || max_files == 0;
    let mut estimated_bytes = 0_u64;
    let mut selected = Vec::new();
    let mut rejected = Vec::new();

    for candidate in ranked {
        if pressure_backoff {
            rejected.push(candidate.rejected(
                reason_codes::HOTSET_PRESSURE_BACKOFF,
                "resource-governor pressure decision suppresses prefetch",
            ));
            continue;
        }
        if selected.len() >= max_files {
            rejected.push(candidate.rejected(
                reason_codes::HOTSET_CAP_FILES,
                "hotset file-count cap reached",
            ));
            continue;
        }
        let Some(next_bytes) = estimated_bytes.checked_add(candidate.estimated_bytes) else {
            rejected.push(candidate.rejected(
                reason_codes::HOTSET_CAP_BYTES,
                "hotset byte estimate overflowed",
            ));
            continue;
        };
        if next_bytes > max_total_bytes {
            rejected.push(
                candidate.rejected(reason_codes::HOTSET_CAP_BYTES, "hotset byte cap reached"),
            );
            continue;
        }

        estimated_bytes = next_bytes;
        selected.push(candidate.selected());
    }

    let selected_len = selected.len();
    for (idx, entry) in selected.iter_mut().enumerate() {
        entry.eviction_priority = selected_len.saturating_sub(idx);
    }

    Ok(EvidenceHotsetPrefetchPlan {
        schema_version: HOTSET_PREFETCH_SCHEMA_VERSION.to_string(),
        pressure_decision: policy.pressure_decision,
        max_total_bytes,
        max_files,
        estimated_bytes,
        candidates_considered: seen_paths.len(),
        selected,
        rejected,
    })
}

#[derive(Debug, Clone)]
struct RankedHotsetCandidate {
    artifact: ResourceArtifactInventoryEntry,
    estimated_bytes: u64,
    artifact_digest: String,
    score_micros: u64,
    reason_codes: Vec<String>,
}

impl RankedHotsetCandidate {
    fn try_from_candidate(
        candidate: EvidenceHotsetPrefetchCandidate,
        probe: &impl EvidenceHotsetFileProbe,
    ) -> Result<Self, EvidenceHotsetPrefetchError> {
        let artifact = candidate
            .artifact
            .validated()
            .map_err(EvidenceHotsetPrefetchError::Artifact)?;
        if path_is_protected_workspace_state(&artifact.path)
            || hotset_safety_class_is_protected(artifact.safety_class)
        {
            return Err(EvidenceHotsetPrefetchError::ProtectedPath {
                path: artifact.path,
            });
        }

        let estimated_bytes = probe.file_len(&artifact.path).ok_or_else(|| {
            EvidenceHotsetPrefetchError::MissingFile {
                path: artifact.path.clone(),
            }
        })?;
        let artifact_digest = artifact
            .content_digest
            .as_deref()
            .map(str::trim)
            .filter(|digest| !digest.is_empty())
            .map(ToOwned::to_owned)
            .ok_or_else(|| EvidenceHotsetPrefetchError::MissingDigest {
                path: artifact.path.clone(),
            })?;
        let recent = validate_hotset_score(
            &artifact.path,
            "recent_bead_activity",
            candidate.recent_bead_activity,
        )?;
        let reuse = validate_hotset_score(
            &artifact.path,
            "proof_cache_reuse",
            candidate.proof_cache_reuse,
        )?;
        let frequency = validate_hotset_score(
            &artifact.path,
            "test_target_frequency",
            candidate.test_target_frequency,
        )?;
        let score_micros = recent
            .saturating_mul(5)
            .saturating_add(reuse.saturating_mul(4))
            .saturating_add(frequency.saturating_mul(3))
            .saturating_add(hotset_kind_weight_micros(artifact.kind))
            .saturating_sub((estimated_bytes / 4096).min(250_000));
        let reason_codes = hotset_reason_codes(&artifact, recent, reuse, frequency);

        Ok(Self {
            artifact,
            estimated_bytes,
            artifact_digest,
            score_micros,
            reason_codes,
        })
    }

    fn selected(self) -> EvidenceHotsetPrefetchEntry {
        EvidenceHotsetPrefetchEntry {
            path: self.artifact.path,
            kind: self.artifact.kind,
            safety_class: self.artifact.safety_class,
            artifact_digest: self.artifact_digest,
            estimated_bytes: self.estimated_bytes,
            score_micros: self.score_micros,
            reason_codes: self.reason_codes,
            eviction_priority: 0,
        }
    }

    fn rejected(self, reason_code: &str, detail: &str) -> EvidenceHotsetRejectedEntry {
        EvidenceHotsetRejectedEntry {
            path: self.artifact.path,
            reason_code: reason_code.to_string(),
            detail: detail.to_string(),
        }
    }
}

fn validate_hotset_score(
    path: &str,
    field: &'static str,
    value: f64,
) -> Result<u64, EvidenceHotsetPrefetchError> {
    if !value.is_finite() || value.is_sign_negative() {
        return Err(EvidenceHotsetPrefetchError::InvalidScore {
            path: path.to_string(),
            field,
            value,
        });
    }
    let scaled = value * 1_000_000.0;
    if !scaled.is_finite() || scaled > u64::MAX as f64 {
        return Err(EvidenceHotsetPrefetchError::InvalidScore {
            path: path.to_string(),
            field,
            value,
        });
    }
    Ok(scaled.round() as u64)
}

fn hotset_safety_class_is_protected(safety_class: ResourceArtifactSafetyClass) -> bool {
    matches!(
        safety_class,
        ResourceArtifactSafetyClass::UserDataNeverDelete
            | ResourceArtifactSafetyClass::LogsSessionHistoryNeverDelete
            | ResourceArtifactSafetyClass::BeadsMailNeverDelete
    )
}

fn hotset_kind_weight_micros(kind: ResourceArtifactKind) -> u64 {
    match kind {
        ResourceArtifactKind::CacheEntry => 3_000_000,
        ResourceArtifactKind::GeneratedEvidence => 2_000_000,
        ResourceArtifactKind::CargoTargetDir | ResourceArtifactKind::RchTargetDir => 1_000_000,
        ResourceArtifactKind::TempOutput => 250_000,
        ResourceArtifactKind::Unknown => 0,
    }
}

fn hotset_reason_codes(
    artifact: &ResourceArtifactInventoryEntry,
    recent: u64,
    reuse: u64,
    frequency: u64,
) -> Vec<String> {
    let mut reasons = Vec::new();
    if recent > 0 {
        reasons.push(reason_codes::HOTSET_RECENT_BEAD_ACTIVITY.to_string());
    }
    if reuse > 0 {
        reasons.push(reason_codes::HOTSET_PROOF_CACHE_REUSE.to_string());
    }
    if frequency > 0 {
        reasons.push(reason_codes::HOTSET_TEST_TARGET_FREQUENCY.to_string());
    }
    reasons.push(
        match artifact.kind {
            ResourceArtifactKind::CacheEntry => reason_codes::HOTSET_PROOF_CACHE_METADATA,
            ResourceArtifactKind::GeneratedEvidence => reason_codes::HOTSET_GENERATED_EVIDENCE,
            ResourceArtifactKind::CargoTargetDir | ResourceArtifactKind::RchTargetDir => {
                reason_codes::HOTSET_REBUILDABLE_OUTPUT
            }
            ResourceArtifactKind::TempOutput => reason_codes::HOTSET_REBUILDABLE_OUTPUT,
            ResourceArtifactKind::Unknown => reason_codes::HOTSET_UNKNOWN_KIND,
        }
        .to_string(),
    );
    if artifact.safety_class == ResourceArtifactSafetyClass::SourceNeverDelete {
        reasons.push(reason_codes::HOTSET_SOURCE_MANIFEST.to_string());
    }
    reasons
}

fn pressure_adjusted_hotset_caps(policy: &EvidenceHotsetPrefetchPolicy) -> (u64, usize) {
    match policy.pressure_decision {
        ResourceGovernorDecisionKind::Allow => (policy.max_total_bytes, policy.max_files),
        ResourceGovernorDecisionKind::AllowLowPriority
        | ResourceGovernorDecisionKind::DedupeOnly => (
            policy.max_total_bytes / 2,
            if policy.max_files == 0 {
                0
            } else {
                (policy.max_files / 2).max(1)
            },
        ),
        ResourceGovernorDecisionKind::SourceOnly | ResourceGovernorDecisionKind::Defer => (0, 0),
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
    #[error("RG_ARTIFACT_STRING_CONTAINS_CONTROL: {field} contains a control character")]
    StringContainsControl { field: &'static str },
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
            Self::StringContainsControl { .. } => "RG_ARTIFACT_STRING_CONTAINS_CONTROL",
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
    #[serde(default)]
    pub coordination: ResourceCoordinationPressure,
    #[serde(default)]
    pub unavailable_signals: Vec<ResourceUnavailableSignal>,
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
            coordination: ResourceCoordinationPressure::default(),
            unavailable_signals: Vec::new(),
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
        observation.coordination = input.coordination;
        observation.unavailable_signals = input.unavailable_signals;
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
    #[serde(default)]
    pub coordination: ResourceCoordinationPressure,
    #[serde(default)]
    pub unavailable_signals: Vec<ResourceUnavailableSignal>,
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

pub trait ResourceProcessProbe {
    fn observe_processes(&self) -> Vec<ObservedValidationProcess>;
}

pub struct ProcfsResourceProcessProbe;

impl ResourceProcessProbe for ProcfsResourceProcessProbe {
    fn observe_processes(&self) -> Vec<ObservedValidationProcess> {
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
        processes
    }
}

pub fn observe_live_validation_processes(now: DateTime<Utc>) -> ResourceGovernorObservation {
    observe_validation_processes_with_probe(now, &ProcfsResourceProcessProbe)
}

pub fn observe_validation_processes_with_probe(
    now: DateTime<Utc>,
    probe: &impl ResourceProcessProbe,
) -> ResourceGovernorObservation {
    ResourceGovernorObservation::new(now, "procfs", probe.observe_processes())
}

pub fn sample_live_process_pressure(now: DateTime<Utc>) -> ResourcePressureSample {
    let processes = ProcfsResourceProcessProbe
        .observe_processes()
        .into_iter()
        .map(|process| ResourcePressureProcessInput {
            pid: process.pid,
            command: process.command,
            kind: Some(process.kind),
            sampler_self: false,
        })
        .collect::<Vec<_>>();
    ResourcePressureSample::from_input(
        ResourcePressureSampleInput {
            observed_at: Some(now),
            source: Some("procfs".to_string()),
            processes,
            ..ResourcePressureSampleInput::default()
        },
        now,
    )
    .unwrap_or_else(|_| ResourcePressureSample {
        schema_version: PRESSURE_SAMPLE_SCHEMA_VERSION.to_string(),
        observed_at: now,
        sample_age_ms: 0,
        source: "procfs".to_string(),
        processes: Vec::new(),
        process_counts: ResourceProcessCounts::from_processes(&[]),
        ignored_sampler_self_matches: 0,
        disk_roots: Vec::new(),
        target_dir_total_bytes: 0,
        rch_target_dir_total_bytes: 0,
        rch_queue_depth: None,
        rch_workers: Vec::new(),
        memory: None,
        cpu: None,
        numa_nodes: Vec::new(),
        coordination: ResourceCoordinationPressure::default(),
        unavailable_signals: vec![ResourceUnavailableSignal {
            signal: ResourcePressureSignal::Coordination,
            reason_code: "RG_PRESSURE_PROCFS_SAMPLE_INVALID".to_string(),
            detail: "live process sample failed validation".to_string(),
        }],
    })
}

fn normalize_pressure_processes(
    inputs: Vec<ResourcePressureProcessInput>,
) -> Result<(Vec<ObservedValidationProcess>, u64), ResourcePressureSampleError> {
    let mut ignored_sampler_self_matches = 0_u64;
    let mut processes = Vec::new();
    for input in inputs {
        validate_artifact_string(
            "pressure_process.command",
            &input.command,
            MAX_ARTIFACT_PATH_BYTES,
        )
        .map_err(ResourcePressureSampleError::Artifact)?;
        if input.sampler_self {
            ignored_sampler_self_matches = ignored_sampler_self_matches.saturating_add(1);
            continue;
        }
        let Some(kind) = input
            .kind
            .or_else(|| classify_validation_process(&input.command))
        else {
            continue;
        };
        processes.push(ObservedValidationProcess {
            pid: input.pid,
            command: input.command,
            kind,
        });
    }
    Ok((processes, ignored_sampler_self_matches))
}

fn sum_disk_root_used_bytes(
    roots: &[ResourceDiskPressureRoot],
    matches_kind: impl Fn(ResourceDiskRootKind) -> bool,
) -> u64 {
    roots
        .iter()
        .filter(|root| matches_kind(root.kind))
        .filter_map(|root| root.used_bytes)
        .fold(0, u64::saturating_add)
}

fn bytes_to_mb(bytes: u64) -> u64 {
    bytes / (1024 * 1024)
}

fn validate_permyriad(field: &'static str, value: u64) -> Result<(), ResourcePressureSampleError> {
    if value > 10_000 {
        Err(ResourcePressureSampleError::InvalidPermyriad { field, value })
    } else {
        Ok(())
    }
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

    if coordination_requires_fail_closed(observation) {
        return if source_only_allowed {
            decision(
                ResourceGovernorDecisionKind::SourceOnly,
                reason_codes::SOURCE_ONLY_CORRUPT_COORDINATION,
                "coordination state is corrupt or stale; source-only work remains allowed",
                60_000,
                "record a source-only blocker and repair Agent Mail/Beads coordination before cargo/RCH proof",
            )
        } else {
            decision(
                ResourceGovernorDecisionKind::Defer,
                reason_codes::DEFER_CORRUPT_COORDINATION,
                "coordination state is corrupt or stale",
                180_000,
                "repair Agent Mail/Beads coordination and refresh reservations before cargo/RCH proof or cleanup",
            )
        };
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

fn coordination_requires_fail_closed(observation: &ResourceGovernorObservation) -> bool {
    matches!(
        observation.coordination.agent_mail_health,
        ResourceCoordinationHealth::Corrupt
    ) || matches!(
        observation.coordination.beads_health,
        ResourceCoordinationHealth::Corrupt
    ) || observation.coordination.stale_lock_count > 0
        || observation.unavailable_signals.iter().any(|signal| {
            matches!(
                signal.signal,
                ResourcePressureSignal::Coordination | ResourcePressureSignal::Reservations
            )
        })
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
    } else if value.chars().any(char::is_control) {
        Err(ResourceArtifactInventoryError::StringContainsControl { field })
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
    // Segment-match every protected directory name. The previous mix of
    // `split('/').any(...)` for three names and `path.contains("/foo/")`
    // substring checks for the other five let three classes of input slip
    // past as "not protected":
    //   1. Relative paths under a protected dir, e.g. "messages/secret.md"
    //      (no leading "/" so `.contains("/messages/")` is false).
    //   2. Absolute paths to the protected dir itself with no trailing
    //      slash, e.g. "/data/projects/franken_node/messages".
    //   3. Backslash-separated paths on cross-platform fixtures.
    // Once `path_is_protected_workspace_state` returned false, an entry
    // with `safety_class == GeneratedEvidence` would be accepted by
    // `validated()`, marked `cleanup_eligible = true` by
    // `derived_cleanup_eligibility`, pass `check_cleanup_eligibility`, and
    // get handed to the cleanup adapter which calls `fs::remove_file` /
    // `fs::remove_dir_all` on the path. Segment-matching closes the gap
    // without changing behavior for any path that already matched the
    // substring form.
    path.split(['/', '\\']).any(|component| {
        matches!(
            component,
            ".beads"
                | ".agent-mail"
                | "agent-mail"
                | "messages"
                | "agents"
                | "sessions"
                | "memories"
                | "logs"
        )
    })
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CleanupMode {
    ReportOnly,
    DryRun,
    Execute,
}

impl CleanupMode {
    pub fn is_destructive(self) -> bool {
        matches!(self, Self::Execute)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CleanupRequest {
    pub trace_id: String,
    pub mode: CleanupMode,
    pub actor: Option<String>,
    pub agent: Option<String>,
    pub bead_id: Option<String>,
    pub approved_reason: String,
    pub candidates: Vec<ResourceArtifactInventoryEntry>,
    pub active_reservations: Vec<String>,
}

impl CleanupRequest {
    pub fn validated(self) -> Result<Self, CleanupError> {
        if self.candidates.len() > MAX_CLEANUP_CANDIDATES {
            return Err(CleanupError::TooManyCandidates {
                count: self.candidates.len(),
                max: MAX_CLEANUP_CANDIDATES,
            });
        }
        validate_artifact_string("trace_id", &self.trace_id, MAX_ARTIFACT_FIELD_BYTES).map_err(
            |err| CleanupError::InvalidField {
                field: "trace_id",
                reason: err.to_string(),
            },
        )?;
        validate_artifact_string(
            "approved_reason",
            &self.approved_reason,
            MAX_ARTIFACT_FIELD_BYTES,
        )
        .map_err(|err| CleanupError::InvalidField {
            field: "approved_reason",
            reason: err.to_string(),
        })?;
        validate_optional_artifact_string("actor", self.actor.as_deref()).map_err(|err| {
            CleanupError::InvalidField {
                field: "actor",
                reason: err.to_string(),
            }
        })?;
        validate_optional_artifact_string("agent", self.agent.as_deref()).map_err(|err| {
            CleanupError::InvalidField {
                field: "agent",
                reason: err.to_string(),
            }
        })?;
        validate_optional_artifact_string("bead_id", self.bead_id.as_deref()).map_err(|err| {
            CleanupError::InvalidField {
                field: "bead_id",
                reason: err.to_string(),
            }
        })?;
        for candidate in &self.candidates {
            if candidate.safety_class.is_protected() {
                return Err(CleanupError::ProtectedSafetyClass {
                    path: candidate.path.clone(),
                    safety_class: format!("{:?}", candidate.safety_class),
                });
            }
        }
        Ok(self)
    }

    pub fn candidates_digest(&self) -> String {
        let mut hasher = Sha256::new();
        let mut candidates: Vec<&ResourceArtifactInventoryEntry> = self.candidates.iter().collect();
        candidates.sort_by(|left, right| {
            left.path
                .cmp(&right.path)
                .then_with(|| left.kind.cmp(&right.kind))
                .then_with(|| left.safety_class.cmp(&right.safety_class))
                .then_with(|| left.bytes.cmp(&right.bytes))
        });

        hasher.update(usize_to_u64(candidates.len()).to_be_bytes());
        for candidate in candidates {
            update_cleanup_digest_field(&mut hasher, &candidate.path);
            update_cleanup_digest_field(&mut hasher, &candidate.repo_key);
            update_cleanup_digest_field(&mut hasher, &format!("{:?}", candidate.kind));
            update_cleanup_digest_field(&mut hasher, &format!("{:?}", candidate.safety_class));
            hasher.update(candidate.bytes.unwrap_or(0).to_be_bytes());
            update_cleanup_digest_optional(&mut hasher, candidate.owner_agent.as_deref());
            update_cleanup_digest_optional(&mut hasher, candidate.bead_id.as_deref());
            update_cleanup_digest_optional(
                &mut hasher,
                candidate.producer_command_digest.as_deref(),
            );
            update_cleanup_digest_optional(&mut hasher, candidate.content_digest.as_deref());
        }

        format!("sha256:{}", hex::encode(hasher.finalize()))
    }
}

fn update_cleanup_digest_field(hasher: &mut Sha256, value: &str) {
    hasher.update(usize_to_u64(value.len()).to_be_bytes());
    hasher.update(value.as_bytes());
}

fn update_cleanup_digest_optional(hasher: &mut Sha256, value: Option<&str>) {
    match value {
        Some(value) => {
            hasher.update([1]);
            update_cleanup_digest_field(hasher, value);
        }
        None => hasher.update([0]),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CleanupOutcome {
    Removed,
    WouldRemove,
    Skipped,
    Failed,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CleanupPathResult {
    pub path: String,
    pub outcome: CleanupOutcome,
    pub candidate_bytes: Option<u64>,
    pub bytes_freed: u64,
    pub skip_reason: Option<String>,
    pub error: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CleanupReceipt {
    pub schema_version: String,
    pub trace_id: String,
    pub mode: CleanupMode,
    pub actor: Option<String>,
    pub agent: Option<String>,
    pub bead_id: Option<String>,
    pub approved_reason: String,
    pub candidates_digest: String,
    pub candidates_count: usize,
    pub started_at: DateTime<Utc>,
    pub completed_at: DateTime<Utc>,
    pub total_bytes_freed: u64,
    pub estimated_bytes_reclaimable: u64,
    pub removed_count: usize,
    pub would_remove_count: usize,
    pub skipped_count: usize,
    pub failed_count: usize,
    pub skipped_pins: Vec<String>,
    pub outcomes: Vec<CleanupPathResult>,
    pub event_code: String,
}

impl CleanupReceipt {
    pub fn summary(&self) -> String {
        format!(
            "mode={:?} candidates={} removed={} would_remove={} skipped={} failed={} bytes_freed={} estimated_bytes_reclaimable={}",
            self.mode,
            self.candidates_count,
            self.removed_count,
            self.would_remove_count,
            self.skipped_count,
            self.failed_count,
            self.total_bytes_freed,
            self.estimated_bytes_reclaimable
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum CleanupError {
    #[error("RG_CLEANUP_TOO_MANY_CANDIDATES: {count} candidates, max {max}")]
    TooManyCandidates { count: usize, max: usize },
    #[error("RG_CLEANUP_INVALID_FIELD: {field} is invalid: {reason}")]
    InvalidField { field: &'static str, reason: String },
    #[error(
        "RG_CLEANUP_PROTECTED_SAFETY_CLASS: path {path} has protected safety class {safety_class}"
    )]
    ProtectedSafetyClass { path: String, safety_class: String },
    #[error("RG_CLEANUP_PROTECTED_PATH: path {path} is protected workspace state")]
    ProtectedPath { path: String },
    #[error("RG_CLEANUP_ACTIVE_RESERVATION: path {path} has active reservation")]
    ActiveReservation { path: String },
    #[error("RG_CLEANUP_OPEN_FILE: path {path} is open")]
    OpenFile { path: String },
    #[error(
        "RG_CLEANUP_TOO_YOUNG: path {path} is younger than minimum age ({age_secs}s < {min_age_secs}s)"
    )]
    TooYoung {
        path: String,
        age_secs: u64,
        min_age_secs: u64,
    },
    #[error("RG_CLEANUP_PINNED: path {path} is pinned: {reason}")]
    Pinned { path: String, reason: String },
    #[error("RG_CLEANUP_ADAPTER_ERROR: {0}")]
    Adapter(String),
}

impl CleanupError {
    pub fn code(&self) -> &'static str {
        match self {
            Self::TooManyCandidates { .. } => "RG_CLEANUP_TOO_MANY_CANDIDATES",
            Self::InvalidField { .. } => "RG_CLEANUP_INVALID_FIELD",
            Self::ProtectedSafetyClass { .. } => "RG_CLEANUP_PROTECTED_SAFETY_CLASS",
            Self::ProtectedPath { .. } => "RG_CLEANUP_PROTECTED_PATH",
            Self::ActiveReservation { .. } => "RG_CLEANUP_ACTIVE_RESERVATION",
            Self::OpenFile { .. } => "RG_CLEANUP_OPEN_FILE",
            Self::TooYoung { .. } => "RG_CLEANUP_TOO_YOUNG",
            Self::Pinned { .. } => "RG_CLEANUP_PINNED",
            Self::Adapter(_) => "RG_CLEANUP_ADAPTER_ERROR",
        }
    }
}

pub trait CleanupAdapter {
    fn remove(&self, path: &str) -> Result<u64, String>;
    fn is_open(&self, path: &str) -> Option<bool>;
    fn mtime_age_secs(&self, path: &str, now: DateTime<Utc>) -> Option<u64>;
}

pub struct DefaultCleanupAdapter;

impl CleanupAdapter for DefaultCleanupAdapter {
    fn remove(&self, path: &str) -> Result<u64, String> {
        let path_obj = Path::new(path);
        let metadata = fs::metadata(path_obj).map_err(|err| err.to_string())?;
        let bytes = metadata.len();
        if metadata.is_dir() {
            fs::remove_dir_all(path_obj).map_err(|err| err.to_string())?;
        } else {
            fs::remove_file(path_obj).map_err(|err| err.to_string())?;
        }
        Ok(bytes)
    }

    fn is_open(&self, _path: &str) -> Option<bool> {
        None
    }

    fn mtime_age_secs(&self, path: &str, now: DateTime<Utc>) -> Option<u64> {
        let metadata = fs::metadata(path).ok()?;
        let mtime = metadata.modified().ok()?;
        let mtime_utc: DateTime<Utc> = mtime.into();
        let age_ms = now
            .signed_duration_since(mtime_utc)
            .num_milliseconds()
            .max(0);
        Some(u64::try_from(age_ms).unwrap_or(u64::MAX) / 1000)
    }
}

fn check_cleanup_eligibility(
    entry: &ResourceArtifactInventoryEntry,
    active_reservations: &[String],
    adapter: &dyn CleanupAdapter,
    now: DateTime<Utc>,
) -> Result<(), CleanupError> {
    if entry.safety_class.is_protected() {
        return Err(CleanupError::ProtectedSafetyClass {
            path: entry.path.clone(),
            safety_class: format!("{:?}", entry.safety_class),
        });
    }
    if path_is_protected_workspace_state(&entry.path) {
        return Err(CleanupError::ProtectedPath {
            path: entry.path.clone(),
        });
    }
    if let Some(pin) = &entry.pin {
        return Err(CleanupError::Pinned {
            path: entry.path.clone(),
            reason: pin.reason.clone(),
        });
    }
    if active_reservations
        .iter()
        .any(|res| entry.path.starts_with(res) || res.starts_with(&entry.path))
    {
        return Err(CleanupError::ActiveReservation {
            path: entry.path.clone(),
        });
    }
    let is_open = entry.open_file_status == ResourceArtifactOpenFileStatus::Open
        || adapter.is_open(&entry.path) == Some(true);
    if is_open {
        return Err(CleanupError::OpenFile {
            path: entry.path.clone(),
        });
    }
    let min_age_secs = entry.minimum_age_secs.unwrap_or(DEFAULT_MINIMUM_AGE_SECS);
    if min_age_secs > 0 {
        let age_secs = entry
            .mtime
            .map(|mtime| {
                let age_ms = now.signed_duration_since(mtime).num_milliseconds().max(0);
                u64::try_from(age_ms).unwrap_or(u64::MAX) / 1000
            })
            .or_else(|| adapter.mtime_age_secs(&entry.path, now));
        if let Some(age) = age_secs {
            if age < min_age_secs {
                return Err(CleanupError::TooYoung {
                    path: entry.path.clone(),
                    age_secs: age,
                    min_age_secs,
                });
            }
        } else {
            return Err(CleanupError::TooYoung {
                path: entry.path.clone(),
                age_secs: 0,
                min_age_secs,
            });
        }
    }
    Ok(())
}

pub fn execute_cleanup<A: CleanupAdapter>(
    request: CleanupRequest,
    adapter: &A,
    now: DateTime<Utc>,
) -> Result<CleanupReceipt, CleanupError> {
    let request = request.validated()?;
    let started_at = now;
    let candidates_digest = request.candidates_digest();
    let candidates_count = request.candidates.len();
    let mut outcomes = Vec::with_capacity(candidates_count);
    let mut total_bytes_freed: u64 = 0;
    let mut estimated_bytes_reclaimable: u64 = 0;
    let mut removed_count: usize = 0;
    let mut would_remove_count: usize = 0;
    let mut skipped_count: usize = 0;
    let mut failed_count: usize = 0;
    let mut skipped_pins = Vec::new();

    for candidate in &request.candidates {
        let eligibility =
            check_cleanup_eligibility(candidate, &request.active_reservations, adapter, now);
        match eligibility {
            Err(err) => {
                let skip_reason = err.to_string();
                if let CleanupError::Pinned { path, reason } = &err {
                    skipped_pins.push(format!("{}: {}", path, reason));
                }
                skipped_count = skipped_count.saturating_add(1);
                outcomes.push(CleanupPathResult {
                    path: candidate.path.clone(),
                    outcome: CleanupOutcome::Skipped,
                    candidate_bytes: candidate.bytes,
                    bytes_freed: 0,
                    skip_reason: Some(skip_reason),
                    error: None,
                });
            }
            Ok(()) => {
                if request.mode.is_destructive() {
                    match adapter.remove(&candidate.path) {
                        Ok(bytes) => {
                            total_bytes_freed = total_bytes_freed.saturating_add(bytes);
                            removed_count = removed_count.saturating_add(1);
                            outcomes.push(CleanupPathResult {
                                path: candidate.path.clone(),
                                outcome: CleanupOutcome::Removed,
                                candidate_bytes: candidate.bytes,
                                bytes_freed: bytes,
                                skip_reason: None,
                                error: None,
                            });
                        }
                        Err(err) => {
                            failed_count = failed_count.saturating_add(1);
                            outcomes.push(CleanupPathResult {
                                path: candidate.path.clone(),
                                outcome: CleanupOutcome::Failed,
                                candidate_bytes: candidate.bytes,
                                bytes_freed: 0,
                                skip_reason: None,
                                error: Some(err),
                            });
                        }
                    }
                } else {
                    let estimated_bytes = candidate.bytes.unwrap_or(0);
                    estimated_bytes_reclaimable =
                        estimated_bytes_reclaimable.saturating_add(estimated_bytes);
                    would_remove_count = would_remove_count.saturating_add(1);
                    outcomes.push(CleanupPathResult {
                        path: candidate.path.clone(),
                        outcome: CleanupOutcome::WouldRemove,
                        candidate_bytes: candidate.bytes,
                        bytes_freed: 0,
                        skip_reason: None,
                        error: None,
                    });
                }
            }
        }
    }

    let completed_at = now;
    let event_code = event_codes::CLEANUP_COMPLETED;

    Ok(CleanupReceipt {
        schema_version: CLEANUP_RECEIPT_SCHEMA_VERSION.to_string(),
        trace_id: request.trace_id,
        mode: request.mode,
        actor: request.actor,
        agent: request.agent,
        bead_id: request.bead_id,
        approved_reason: request.approved_reason,
        candidates_digest,
        candidates_count,
        started_at,
        completed_at,
        total_bytes_freed,
        estimated_bytes_reclaimable,
        removed_count,
        would_remove_count,
        skipped_count,
        failed_count,
        skipped_pins,
        outcomes,
        event_code: event_code.to_string(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;
    use tempfile::TempDir;

    fn sample_ts(second: u32) -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 5, 6, 12, 0, second)
            .single()
            .expect("valid timestamp")
    }

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

    fn disk_root(
        path: &str,
        kind: ResourceDiskRootKind,
        total_bytes: u64,
        free_bytes: u64,
    ) -> ResourceDiskPressureRoot {
        ResourceDiskPressureRoot {
            path: path.to_string(),
            kind,
            total_bytes: Some(total_bytes),
            free_bytes: Some(free_bytes),
            used_bytes: Some(total_bytes.saturating_sub(free_bytes)),
        }
    }

    fn pressure_process(command: &str) -> ResourcePressureProcessInput {
        ResourcePressureProcessInput {
            pid: None,
            command: command.to_string(),
            kind: None,
            sampler_self: false,
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

    #[test]
    fn disk_pressure_roots_classify_green_yellow_red() {
        assert_eq!(
            disk_root(
                "/data/projects/franken_node",
                ResourceDiskRootKind::Project,
                1000,
                200
            )
            .pressure_tier(),
            ResourcePressureTier::Green
        );
        assert_eq!(
            disk_root("/tmp", ResourceDiskRootKind::Temp, 1000, 100).pressure_tier(),
            ResourcePressureTier::Yellow
        );
        assert_eq!(
            disk_root(
                "/data/projects/franken_node/target",
                ResourceDiskRootKind::TargetDir,
                1000,
                20
            )
            .pressure_tier(),
            ResourcePressureTier::Red
        );
    }

    #[test]
    fn pressure_sample_fixture_serializes_stable_workspace_signals() {
        let sample = ResourcePressureSample::from_input(
            ResourcePressureSampleInput {
                observed_at: Some(sample_ts(1)),
                source: Some("fixture".to_string()),
                processes: vec![
                    pressure_process("cargo check -p frankenengine-node"),
                    pressure_process("rustc --crate-name frankenengine_node"),
                ],
                disk_roots: vec![
                    disk_root(
                        "/data/projects/franken_node",
                        ResourceDiskRootKind::Project,
                        100_000,
                        40_000,
                    ),
                    disk_root(
                        "/data/projects/franken_node/target",
                        ResourceDiskRootKind::TargetDir,
                        20_000,
                        5_000,
                    ),
                    disk_root(
                        "/data/tmp/franken_node-rch-target",
                        ResourceDiskRootKind::RchTargetDir,
                        30_000,
                        10_000,
                    ),
                ],
                rch_queue_depth: Some(2),
                rch_workers: vec![
                    ResourceRchWorkerPressure {
                        worker_id: "worker-a".to_string(),
                        state: ResourceRchWorkerState::Available,
                        slots_total: Some(8),
                        slots_free: Some(4),
                    },
                    ResourceRchWorkerPressure {
                        worker_id: "worker-b".to_string(),
                        state: ResourceRchWorkerState::Busy,
                        slots_total: Some(8),
                        slots_free: Some(0),
                    },
                ],
                memory: Some(ResourceMemoryPressure {
                    total_bytes: Some(256_000),
                    available_bytes: Some(96_000),
                    used_bytes: Some(160_000),
                    swap_total_bytes: Some(32_000),
                    swap_used_bytes: Some(8_000),
                    swap_used_permyriad: Some(2_500),
                }),
                cpu: Some(ResourceCpuPressure {
                    load_permyriad: Some(6_500),
                    build_job_cap: Some(12),
                }),
                numa_nodes: vec![ResourceNumaNodePressure {
                    node_id: 0,
                    total_bytes: Some(128_000),
                    available_bytes: Some(64_000),
                }],
                coordination: ResourceCoordinationPressure {
                    agent_mail_health: ResourceCoordinationHealth::Healthy,
                    beads_health: ResourceCoordinationHealth::Healthy,
                    recovery_mode: Some("normal".to_string()),
                    stale_lock_count: 0,
                    active_reservation_count: 2,
                },
                unavailable_signals: Vec::new(),
            },
            sample_ts(3),
        )
        .expect("valid pressure sample");

        assert_eq!(sample.schema_version, PRESSURE_SAMPLE_SCHEMA_VERSION);
        assert_eq!(sample.sample_age_ms, 2_000);
        assert_eq!(sample.process_counts.cargo, 1);
        assert_eq!(sample.process_counts.rustc, 1);
        assert_eq!(sample.target_dir_total_bytes, 15_000);
        assert_eq!(sample.rch_target_dir_total_bytes, 20_000);
        assert_eq!(
            sample
                .rch_workers
                .iter()
                .filter(|worker| worker.state == ResourceRchWorkerState::Busy)
                .count(),
            1
        );
        let encoded = serde_json::to_string(&sample).expect("serialize pressure sample");
        assert!(encoded.contains("franken-node/resource-governor/pressure-sample/v1"));
        assert!(encoded.contains("active_reservation_count"));
    }

    #[test]
    fn pressure_sample_normalizes_sampler_self_matches() {
        let sample = ResourcePressureSample::from_input(
            ResourcePressureSampleInput {
                processes: vec![
                    ResourcePressureProcessInput {
                        sampler_self: true,
                        ..pressure_process("cargo grep self-match")
                    },
                    pressure_process("cargo test"),
                    pressure_process("rustc crate-a"),
                    pressure_process("rch exec -- cargo check"),
                    pressure_process("not validation"),
                ],
                ..ResourcePressureSampleInput::default()
            },
            sample_ts(0),
        )
        .expect("valid process sample");

        assert_eq!(sample.ignored_sampler_self_matches, 1);
        assert_eq!(sample.process_counts.cargo, 1);
        assert_eq!(sample.process_counts.rustc, 1);
        assert_eq!(sample.process_counts.rch, 1);
        assert_eq!(sample.process_counts.total_validation_processes, 3);
    }

    #[test]
    fn pressure_sample_covers_high_cargo_contention_fixture() {
        let sample = ResourcePressureSample::from_input(
            ResourcePressureSampleInput {
                processes: vec![
                    pressure_process("cargo check"),
                    pressure_process("cargo test"),
                    pressure_process("cargo clippy"),
                    pressure_process("rustc crate-a"),
                    pressure_process("rustc crate-b"),
                    pressure_process("rustc crate-c"),
                    pressure_process("rch exec -- cargo test"),
                ],
                ..ResourcePressureSampleInput::default()
            },
            sample_ts(0),
        )
        .expect("valid contention sample");
        let report = evaluate_resource_governor(
            ResourceGovernorRequest {
                trace_id: "contention-fixture".to_string(),
                requested_proof_class: Some("cargo-test".to_string()),
                source_only_allowed: false,
            },
            sample.to_governor_observation(),
            ResourceGovernorThresholds::default(),
            sample_ts(1),
        );

        assert_eq!(sample.process_counts.total_validation_processes, 7);
        assert_eq!(report.decision.kind, ResourceGovernorDecisionKind::Defer);
    }

    #[test]
    fn pressure_sample_rejects_unbounded_disk_roots() {
        let disk_roots = (0..=MAX_PRESSURE_SAMPLE_ROOTS)
            .map(|idx| {
                disk_root(
                    &format!("/data/projects/franken_node/target/{idx}"),
                    ResourceDiskRootKind::TargetDir,
                    1000,
                    500,
                )
            })
            .collect::<Vec<_>>();
        let err = ResourcePressureSample::from_input(
            ResourcePressureSampleInput {
                disk_roots,
                ..ResourcePressureSampleInput::default()
            },
            sample_ts(0),
        )
        .expect_err("disk root cap should fail");

        assert_eq!(err.code(), "RG_PRESSURE_TOO_MANY_ITEMS");
    }

    #[test]
    fn pressure_sample_rejects_invalid_permyriad_inputs() {
        let err = ResourcePressureSample::from_input(
            ResourcePressureSampleInput {
                cpu: Some(ResourceCpuPressure {
                    load_permyriad: Some(10_001),
                    build_job_cap: Some(1),
                }),
                ..ResourcePressureSampleInput::default()
            },
            sample_ts(0),
        )
        .expect_err("invalid CPU permyriad should fail");

        assert_eq!(err.code(), "RG_PRESSURE_INVALID_PERMYRIAD");
    }

    #[test]
    fn pressure_sample_records_missing_numa_without_host_probe() {
        let sample = ResourcePressureSample::from_input(
            ResourcePressureSampleInput {
                unavailable_signals: vec![ResourceUnavailableSignal {
                    signal: ResourcePressureSignal::Numa,
                    reason_code: "RG_NUMA_UNAVAILABLE".to_string(),
                    detail: "fixture host has no NUMA inventory".to_string(),
                }],
                ..ResourcePressureSampleInput::default()
            },
            sample_ts(0),
        )
        .expect("missing numa is an explicit signal");

        assert!(sample.numa_nodes.is_empty());
        assert_eq!(sample.unavailable_signals.len(), 1);
        assert_eq!(
            sample.unavailable_signals[0].signal,
            ResourcePressureSignal::Numa
        );
    }

    #[test]
    fn pressure_sample_preserves_corrupt_coordination_hint() {
        let sample = ResourcePressureSample::from_input(
            ResourcePressureSampleInput {
                coordination: ResourceCoordinationPressure {
                    agent_mail_health: ResourceCoordinationHealth::Corrupt,
                    beads_health: ResourceCoordinationHealth::Degraded,
                    recovery_mode: Some("corrupt".to_string()),
                    stale_lock_count: 3,
                    active_reservation_count: 5,
                },
                unavailable_signals: vec![ResourceUnavailableSignal {
                    signal: ResourcePressureSignal::Coordination,
                    reason_code: "RG_COORDINATION_CORRUPT".to_string(),
                    detail: "mail archive and beads locks disagree".to_string(),
                }],
                ..ResourcePressureSampleInput::default()
            },
            sample_ts(0),
        )
        .expect("valid coordination sample");

        assert_eq!(
            sample.coordination.agent_mail_health,
            ResourceCoordinationHealth::Corrupt
        );
        assert_eq!(sample.coordination.stale_lock_count, 3);
        assert_eq!(
            sample.unavailable_signals[0].signal,
            ResourcePressureSignal::Coordination
        );
    }

    #[test]
    fn pressure_sample_carries_coordination_into_governor_observation() {
        let sample = ResourcePressureSample::from_input(
            ResourcePressureSampleInput {
                coordination: ResourceCoordinationPressure {
                    agent_mail_health: ResourceCoordinationHealth::Corrupt,
                    beads_health: ResourceCoordinationHealth::Healthy,
                    recovery_mode: Some("mail-db-corrupt".to_string()),
                    stale_lock_count: 2,
                    active_reservation_count: 4,
                },
                unavailable_signals: vec![ResourceUnavailableSignal {
                    signal: ResourcePressureSignal::Reservations,
                    reason_code: "RG_RESERVATIONS_STALE".to_string(),
                    detail: "reservation leases are stale".to_string(),
                }],
                ..ResourcePressureSampleInput::default()
            },
            sample_ts(0),
        )
        .expect("valid corrupt coordination sample");

        let observation = sample.to_governor_observation();

        assert_eq!(
            observation.coordination.agent_mail_health,
            ResourceCoordinationHealth::Corrupt
        );
        assert_eq!(observation.coordination.stale_lock_count, 2);
        assert_eq!(observation.unavailable_signals.len(), 1);
        assert_eq!(
            observation.unavailable_signals[0].signal,
            ResourcePressureSignal::Reservations
        );
    }

    #[test]
    fn corrupt_coordination_defers_remote_validation_even_when_pressure_is_idle() {
        let sample = ResourcePressureSample::from_input(
            ResourcePressureSampleInput {
                coordination: ResourceCoordinationPressure {
                    agent_mail_health: ResourceCoordinationHealth::Corrupt,
                    beads_health: ResourceCoordinationHealth::Healthy,
                    recovery_mode: Some("mail-db-corrupt".to_string()),
                    stale_lock_count: 0,
                    active_reservation_count: 0,
                },
                ..ResourcePressureSampleInput::default()
            },
            sample_ts(0),
        )
        .expect("valid corrupt coordination sample");

        let report = evaluate_resource_governor(
            ResourceGovernorRequest {
                trace_id: "corrupt-coordination".to_string(),
                requested_proof_class: Some("cargo-check".to_string()),
                source_only_allowed: false,
            },
            sample.to_governor_observation(),
            ResourceGovernorThresholds::default(),
            sample_ts(1),
        );

        assert_eq!(report.decision.kind, ResourceGovernorDecisionKind::Defer);
        assert_eq!(
            report.decision.reason_code,
            reason_codes::DEFER_CORRUPT_COORDINATION
        );
        assert_eq!(
            report.structured_log.reason_code,
            reason_codes::DEFER_CORRUPT_COORDINATION
        );
    }

    #[test]
    fn corrupt_coordination_uses_source_only_when_allowed() {
        let sample = ResourcePressureSample::from_input(
            ResourcePressureSampleInput {
                coordination: ResourceCoordinationPressure {
                    agent_mail_health: ResourceCoordinationHealth::Healthy,
                    beads_health: ResourceCoordinationHealth::Corrupt,
                    recovery_mode: Some("beads-locks-corrupt".to_string()),
                    stale_lock_count: 1,
                    active_reservation_count: 3,
                },
                ..ResourcePressureSampleInput::default()
            },
            sample_ts(0),
        )
        .expect("valid corrupt beads sample");

        let report = evaluate_resource_governor(
            ResourceGovernorRequest {
                trace_id: "source-only-corrupt-coordination".to_string(),
                requested_proof_class: Some("cargo-test".to_string()),
                source_only_allowed: true,
            },
            sample.to_governor_observation(),
            ResourceGovernorThresholds::default(),
            sample_ts(1),
        );

        assert_eq!(
            report.decision.kind,
            ResourceGovernorDecisionKind::SourceOnly
        );
        assert_eq!(
            report.decision.reason_code,
            reason_codes::SOURCE_ONLY_CORRUPT_COORDINATION
        );
        assert!(
            report
                .decision
                .next_action
                .contains("repair Agent Mail/Beads coordination")
        );
    }

    #[test]
    fn pressure_sample_converts_to_existing_governor_observation() {
        let sample = ResourcePressureSample::from_input(
            ResourcePressureSampleInput {
                processes: vec![pressure_process("cargo check")],
                disk_roots: vec![disk_root(
                    "/data/projects/franken_node/target",
                    ResourceDiskRootKind::TargetDir,
                    4 * 1024 * 1024,
                    1024 * 1024,
                )],
                rch_queue_depth: Some(4),
                memory: Some(ResourceMemoryPressure {
                    total_bytes: Some(8 * 1024 * 1024),
                    available_bytes: Some(2 * 1024 * 1024),
                    used_bytes: Some(6 * 1024 * 1024),
                    swap_total_bytes: None,
                    swap_used_bytes: None,
                    swap_used_permyriad: None,
                }),
                cpu: Some(ResourceCpuPressure {
                    load_permyriad: Some(7_500),
                    build_job_cap: Some(2),
                }),
                ..ResourcePressureSampleInput::default()
            },
            sample_ts(0),
        )
        .expect("valid sample");
        let observation = sample.to_governor_observation();

        assert_eq!(observation.process_counts.cargo, 1);
        assert_eq!(observation.rch_queue_depth, Some(4));
        assert_eq!(observation.target_dir_usage_mb, Some(3));
        assert_eq!(observation.memory_used_mb, Some(6));
        assert_eq!(observation.cpu_load_permyriad, Some(7_500));
    }

    struct MockCleanupAdapter {
        removed: std::cell::RefCell<Vec<String>>,
        open_paths: Vec<String>,
        remove_error: Option<String>,
        mtimes: std::collections::HashMap<String, DateTime<Utc>>,
    }

    impl MockCleanupAdapter {
        fn new() -> Self {
            Self {
                removed: std::cell::RefCell::new(Vec::new()),
                open_paths: Vec::new(),
                remove_error: None,
                mtimes: std::collections::HashMap::new(),
            }
        }

        fn with_open(mut self, path: &str) -> Self {
            self.open_paths.push(path.to_string());
            self
        }

        fn with_mtime(mut self, path: &str, mtime: DateTime<Utc>) -> Self {
            self.mtimes.insert(path.to_string(), mtime);
            self
        }

        fn with_remove_error(mut self, error: &str) -> Self {
            self.remove_error = Some(error.to_string());
            self
        }
    }

    impl CleanupAdapter for MockCleanupAdapter {
        fn remove(&self, path: &str) -> Result<u64, String> {
            if let Some(ref error) = self.remove_error {
                return Err(error.clone());
            }
            self.removed.borrow_mut().push(path.to_string());
            Ok(1024)
        }

        fn is_open(&self, path: &str) -> Option<bool> {
            Some(self.open_paths.contains(&path.to_string()))
        }

        fn mtime_age_secs(&self, path: &str, now: DateTime<Utc>) -> Option<u64> {
            self.mtimes.get(path).map(|mtime| {
                let age_ms = now.signed_duration_since(*mtime).num_milliseconds().max(0);
                u64::try_from(age_ms).unwrap_or(u64::MAX) / 1000
            })
        }
    }

    fn cleanup_candidate(path: &str, bytes: u64) -> ResourceArtifactInventoryEntry {
        let mut entry = ResourceArtifactInventoryEntry::new(
            path,
            "/data/projects/franken_node",
            ResourceArtifactKind::CargoTargetDir,
            ResourceArtifactSafetyClass::RebuildableBuildOutput,
            Some(bytes),
        );
        entry.open_file_status = ResourceArtifactOpenFileStatus::NotOpen;
        entry.minimum_age_secs = Some(0);
        entry
    }

    fn cleanup_request(
        candidates: Vec<ResourceArtifactInventoryEntry>,
        mode: CleanupMode,
    ) -> CleanupRequest {
        CleanupRequest {
            trace_id: "test-cleanup".to_string(),
            mode,
            actor: Some("test-actor".to_string()),
            agent: Some("TestAgent".to_string()),
            bead_id: Some("bd-test".to_string()),
            approved_reason: "test cleanup".to_string(),
            candidates,
            active_reservations: Vec::new(),
        }
    }

    #[test]
    fn cleanup_report_only_mode_produces_would_remove_outcomes() {
        let adapter = MockCleanupAdapter::new();
        let candidates = vec![
            cleanup_candidate("/tmp/target/debug/build/foo", 1024),
            cleanup_candidate("/tmp/target/debug/build/bar", 2048),
        ];
        let request = cleanup_request(candidates, CleanupMode::ReportOnly);

        let receipt =
            execute_cleanup(request, &adapter, sample_ts(600)).expect("cleanup should succeed");

        assert_eq!(receipt.mode, CleanupMode::ReportOnly);
        assert_eq!(receipt.candidates_count, 2);
        assert_eq!(receipt.removed_count, 0);
        assert_eq!(receipt.would_remove_count, 2);
        assert_eq!(receipt.skipped_count, 0);
        assert_eq!(receipt.total_bytes_freed, 0);
        assert_eq!(receipt.estimated_bytes_reclaimable, 3072);
        assert!(adapter.removed.borrow().is_empty());
        assert!(
            receipt
                .outcomes
                .iter()
                .all(|o| o.outcome == CleanupOutcome::WouldRemove)
        );
    }

    #[test]
    fn cleanup_dry_run_mode_does_not_remove_files() {
        let adapter = MockCleanupAdapter::new();
        let candidates = vec![cleanup_candidate("/tmp/target/debug/build/foo", 1024)];
        let request = cleanup_request(candidates, CleanupMode::DryRun);

        let receipt =
            execute_cleanup(request, &adapter, sample_ts(600)).expect("cleanup should succeed");

        assert_eq!(receipt.mode, CleanupMode::DryRun);
        assert!(!receipt.mode.is_destructive());
        assert!(adapter.removed.borrow().is_empty());
        assert_eq!(receipt.outcomes[0].outcome, CleanupOutcome::WouldRemove);
        assert_eq!(receipt.outcomes[0].candidate_bytes, Some(1024));
        assert_eq!(receipt.outcomes[0].bytes_freed, 0);
        assert_eq!(receipt.total_bytes_freed, 0);
        assert_eq!(receipt.estimated_bytes_reclaimable, 1024);
    }

    #[test]
    fn cleanup_execute_mode_removes_files_via_adapter() {
        let adapter = MockCleanupAdapter::new();
        let candidates = vec![
            cleanup_candidate("/tmp/target/debug/build/foo", 1024),
            cleanup_candidate("/tmp/target/debug/build/bar", 2048),
        ];
        let request = cleanup_request(candidates, CleanupMode::Execute);

        let receipt =
            execute_cleanup(request, &adapter, sample_ts(600)).expect("cleanup should succeed");

        assert_eq!(receipt.mode, CleanupMode::Execute);
        assert!(receipt.mode.is_destructive());
        assert_eq!(adapter.removed.borrow().len(), 2);
        assert_eq!(receipt.removed_count, 2);
        assert_eq!(receipt.would_remove_count, 0);
        assert_eq!(receipt.total_bytes_freed, 2048);
        assert!(
            receipt
                .outcomes
                .iter()
                .all(|o| o.outcome == CleanupOutcome::Removed)
        );
    }

    #[test]
    fn cleanup_skips_protected_safety_class() {
        let adapter = MockCleanupAdapter::new();
        let mut protected = cleanup_candidate("/data/source/main.rs", 1024);
        protected.safety_class = ResourceArtifactSafetyClass::SourceNeverDelete;
        let candidates = vec![protected];

        let result = cleanup_request(candidates, CleanupMode::Execute).validated();
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            CleanupError::ProtectedSafetyClass { path, .. }
                if path == "/data/source/main.rs"
        ));
    }

    #[test]
    fn cleanup_skips_protected_workspace_paths() {
        let adapter = MockCleanupAdapter::new();
        let mut entry = cleanup_candidate("/data/projects/franken_node/.beads/issues.jsonl", 1024);
        entry.safety_class = ResourceArtifactSafetyClass::DisposableTempOutput;
        let candidates = vec![entry];
        let request = cleanup_request(candidates, CleanupMode::Execute);

        let receipt =
            execute_cleanup(request, &adapter, sample_ts(600)).expect("cleanup should succeed");

        assert_eq!(receipt.skipped_count, 1);
        assert!(adapter.removed.borrow().is_empty());
        assert!(
            receipt.outcomes[0]
                .skip_reason
                .as_ref()
                .unwrap()
                .contains("protected")
        );
    }

    #[test]
    fn cleanup_skips_pinned_artifacts() {
        let adapter = MockCleanupAdapter::new();
        let pinned = cleanup_candidate("/tmp/target/debug/build/pinned", 1024).with_pin(
            ResourceArtifactPin {
                reason: "manual pin by operator".to_string(),
                owner_agent: Some("TestAgent".to_string()),
                bead_id: None,
                expires_at: None,
            },
        );
        let candidates = vec![pinned];
        let request = cleanup_request(candidates, CleanupMode::Execute);

        let receipt =
            execute_cleanup(request, &adapter, sample_ts(600)).expect("cleanup should succeed");

        assert_eq!(receipt.skipped_count, 1);
        assert_eq!(receipt.skipped_pins.len(), 1);
        assert!(receipt.skipped_pins[0].contains("manual pin by operator"));
        assert!(adapter.removed.borrow().is_empty());
    }

    #[test]
    fn cleanup_skips_open_files() {
        let adapter = MockCleanupAdapter::new().with_open("/tmp/target/debug/build/open-file");
        let candidates = vec![cleanup_candidate("/tmp/target/debug/build/open-file", 1024)];
        let request = cleanup_request(candidates, CleanupMode::Execute);

        let receipt =
            execute_cleanup(request, &adapter, sample_ts(600)).expect("cleanup should succeed");

        assert_eq!(receipt.skipped_count, 1);
        assert!(
            receipt.outcomes[0]
                .skip_reason
                .as_ref()
                .unwrap()
                .contains("open")
        );
        assert!(adapter.removed.borrow().is_empty());
    }

    #[test]
    fn cleanup_skips_active_reservations() {
        let adapter = MockCleanupAdapter::new();
        let candidates = vec![cleanup_candidate("/tmp/target/debug/build/reserved", 1024)];
        let mut request = cleanup_request(candidates, CleanupMode::Execute);
        request.active_reservations = vec!["/tmp/target/debug/build/reserved".to_string()];

        let receipt =
            execute_cleanup(request, &adapter, sample_ts(600)).expect("cleanup should succeed");

        assert_eq!(receipt.skipped_count, 1);
        assert!(
            receipt.outcomes[0]
                .skip_reason
                .as_ref()
                .unwrap()
                .contains("reservation")
        );
        assert!(adapter.removed.borrow().is_empty());
    }

    #[test]
    fn cleanup_skips_files_younger_than_minimum_age() {
        let now = sample_ts(600);
        let recent_mtime = sample_ts(500);
        let adapter =
            MockCleanupAdapter::new().with_mtime("/tmp/target/debug/build/young", recent_mtime);
        let mut entry = cleanup_candidate("/tmp/target/debug/build/young", 1024);
        entry.minimum_age_secs = Some(300);
        let candidates = vec![entry];
        let request = cleanup_request(candidates, CleanupMode::Execute);

        let receipt = execute_cleanup(request, &adapter, now).expect("cleanup should succeed");

        assert_eq!(receipt.skipped_count, 1);
        assert!(
            receipt.outcomes[0]
                .skip_reason
                .as_ref()
                .unwrap()
                .contains("younger")
        );
        assert!(adapter.removed.borrow().is_empty());
    }

    #[test]
    fn cleanup_removes_files_older_than_minimum_age() {
        let now = sample_ts(600);
        let old_mtime = sample_ts(0);
        let adapter =
            MockCleanupAdapter::new().with_mtime("/tmp/target/debug/build/old", old_mtime);
        let mut entry = cleanup_candidate("/tmp/target/debug/build/old", 1024);
        entry.minimum_age_secs = Some(300);
        let candidates = vec![entry];
        let request = cleanup_request(candidates, CleanupMode::Execute);

        let receipt = execute_cleanup(request, &adapter, now).expect("cleanup should succeed");

        assert_eq!(receipt.removed_count, 1);
        assert_eq!(adapter.removed.borrow().len(), 1);
    }

    #[test]
    fn cleanup_records_adapter_failures() {
        let adapter = MockCleanupAdapter::new().with_remove_error("permission denied");
        let candidates = vec![cleanup_candidate("/tmp/target/debug/build/error", 1024)];
        let request = cleanup_request(candidates, CleanupMode::Execute);

        let receipt =
            execute_cleanup(request, &adapter, sample_ts(600)).expect("cleanup should succeed");

        assert_eq!(receipt.failed_count, 1);
        assert_eq!(receipt.outcomes[0].outcome, CleanupOutcome::Failed);
        assert!(
            receipt.outcomes[0]
                .error
                .as_ref()
                .unwrap()
                .contains("permission denied")
        );
    }

    #[test]
    fn cleanup_receipt_has_stable_schema_version() {
        let adapter = MockCleanupAdapter::new();
        let candidates = vec![cleanup_candidate("/tmp/target/foo", 1024)];
        let request = cleanup_request(candidates, CleanupMode::ReportOnly);

        let receipt =
            execute_cleanup(request, &adapter, sample_ts(600)).expect("cleanup should succeed");

        assert_eq!(receipt.schema_version, CLEANUP_RECEIPT_SCHEMA_VERSION);
        assert!(receipt.candidates_digest.starts_with("sha256:"));
        assert_eq!(receipt.candidates_digest.len(), "sha256:".len() + 64);
        assert!(receipt.summary().contains("mode=ReportOnly"));
        assert!(receipt.summary().contains("estimated_bytes_reclaimable="));
    }

    #[test]
    fn cleanup_candidates_digest_is_order_independent_and_stable() {
        let candidates1 = vec![
            cleanup_candidate("/tmp/target/foo", 1024),
            cleanup_candidate("/tmp/target/bar", 2048),
        ];
        let candidates2 = vec![
            cleanup_candidate("/tmp/target/bar", 2048),
            cleanup_candidate("/tmp/target/foo", 1024),
        ];

        let digest1 = cleanup_request(candidates1, CleanupMode::ReportOnly).candidates_digest();
        let digest2 = cleanup_request(candidates2, CleanupMode::ReportOnly).candidates_digest();

        assert_eq!(digest1, digest2);
        assert!(digest1.starts_with("sha256:"));
        assert_eq!(digest1.len(), "sha256:".len() + 64);
    }

    #[test]
    fn cleanup_receipt_round_trips_through_serde() {
        let adapter = MockCleanupAdapter::new();
        let candidates = vec![
            cleanup_candidate("/tmp/target/foo", 1024),
            cleanup_candidate("/tmp/target/bar", 2048),
        ];
        let request = cleanup_request(candidates, CleanupMode::DryRun);

        let receipt =
            execute_cleanup(request, &adapter, sample_ts(600)).expect("cleanup should succeed");

        let json = serde_json::to_string(&receipt).expect("serialize");
        let decoded: CleanupReceipt = serde_json::from_str(&json).expect("deserialize");

        assert_eq!(decoded.trace_id, receipt.trace_id);
        assert_eq!(decoded.mode, receipt.mode);
        assert_eq!(decoded.candidates_count, receipt.candidates_count);
        assert_eq!(decoded.outcomes.len(), receipt.outcomes.len());
    }

    #[test]
    fn cleanup_validates_too_many_candidates() {
        let candidates: Vec<_> = (0..MAX_CLEANUP_CANDIDATES + 1)
            .map(|i| cleanup_candidate(&format!("/tmp/target/{}", i), 1024))
            .collect();
        let request = cleanup_request(candidates, CleanupMode::ReportOnly);

        let result = request.validated();
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            CleanupError::TooManyCandidates { count, max }
                if count == MAX_CLEANUP_CANDIDATES + 1 && max == MAX_CLEANUP_CANDIDATES
        ));
    }

    #[test]
    fn cleanup_executor_e2e_tempdir_removes_only_eligible_artifacts() {
        let temp_dir = TempDir::new().expect("temp dir");
        let eligible_file = temp_dir.path().join("eligible_artifact.o");
        let protected_dir = temp_dir.path().join(".beads");
        let protected_file = protected_dir.join("issues.jsonl");

        std::fs::write(&eligible_file, b"artifact content").expect("write eligible");
        std::fs::create_dir_all(&protected_dir).expect("create protected dir");
        std::fs::write(&protected_file, b"protected content").expect("write protected");

        assert!(eligible_file.exists());
        assert!(protected_file.exists());

        let old_mtime = sample_ts(0);
        let now = sample_ts(600);

        let mut eligible_entry = ResourceArtifactInventoryEntry::new(
            eligible_file.to_string_lossy(),
            temp_dir.path().to_string_lossy(),
            ResourceArtifactKind::TempOutput,
            ResourceArtifactSafetyClass::DisposableTempOutput,
            Some(16),
        );
        eligible_entry.open_file_status = ResourceArtifactOpenFileStatus::NotOpen;
        eligible_entry.minimum_age_secs = Some(0);
        eligible_entry.mtime = Some(old_mtime);

        let mut protected_entry = ResourceArtifactInventoryEntry::new(
            protected_file.to_string_lossy(),
            temp_dir.path().to_string_lossy(),
            ResourceArtifactKind::Unknown,
            ResourceArtifactSafetyClass::DisposableTempOutput,
            Some(17),
        );
        protected_entry.open_file_status = ResourceArtifactOpenFileStatus::NotOpen;
        protected_entry.minimum_age_secs = Some(0);
        protected_entry.mtime = Some(old_mtime);

        let request = CleanupRequest {
            trace_id: "e2e-tempdir-test".to_string(),
            mode: CleanupMode::Execute,
            actor: Some("e2e-test".to_string()),
            agent: Some("TestAgent".to_string()),
            bead_id: Some("bd-e2e".to_string()),
            approved_reason: "e2e temp cleanup test".to_string(),
            candidates: vec![eligible_entry, protected_entry],
            active_reservations: Vec::new(),
        };

        let receipt =
            execute_cleanup(request, &DefaultCleanupAdapter, now).expect("cleanup should succeed");

        assert!(
            !eligible_file.exists(),
            "eligible artifact should be removed"
        );
        assert!(
            protected_file.exists(),
            "protected .beads file should NOT be removed"
        );

        assert_eq!(receipt.removed_count, 1);
        assert_eq!(receipt.skipped_count, 1);

        let eligible_outcome = receipt
            .outcomes
            .iter()
            .find(|o| o.path.contains("eligible_artifact"))
            .expect("eligible outcome");
        assert_eq!(eligible_outcome.outcome, CleanupOutcome::Removed);

        let protected_outcome = receipt
            .outcomes
            .iter()
            .find(|o| o.path.contains(".beads"))
            .expect("protected outcome");
        assert_eq!(protected_outcome.outcome, CleanupOutcome::Skipped);
        assert!(
            protected_outcome
                .skip_reason
                .as_ref()
                .expect("skip reason")
                .contains("protected")
        );
    }
}
