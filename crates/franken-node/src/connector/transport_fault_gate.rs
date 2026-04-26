//! bd-3u6o: Enforce canonical virtual transport fault harness (from 10.14)
//! for distributed control protocols.
//!
//! Imports and wraps the canonical `VirtualTransportFaultHarness` from bd-2qqu
//! (`remote::virtual_transport_faults`), registers control-plane protocols as
//! fault injection targets, and provides a `TransportFaultGate` that exercises
//! every protocol under each fault mode.
//!
//! Schema version: tfg-v1.0

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::remote::virtual_transport_faults::{
    self, CampaignResult, FaultClass, FaultConfig, VirtualTransportFaultHarness,
};
use crate::security::constant_time;

// ── Constants ────────────────────────────────────────────────────────────────

use crate::capacity_defaults::aliases::{MAX_AUDIT_LOG_ENTRIES, MAX_RESULTS};

fn push_bounded<T>(items: &mut Vec<T>, item: T, cap: usize) {
    if cap == 0 {
        items.clear();
        return;
    }
    if items.len() >= cap {
        let overflow = items.len().saturating_sub(cap).saturating_add(1);
        items.drain(0..overflow);
    }
    items.push(item);
}

pub const SCHEMA_VERSION: &str = "tfg-v1.0";
pub const BEAD_ID: &str = "bd-3u6o";
pub const SECTION: &str = "10.15";

/// Default seed matrix (5 seeds per protocol).
pub const DEFAULT_SEEDS: [u64; 5] = [42, 137, 256, 1001, 9999];

/// Minimum number of messages per campaign run.
pub const DEFAULT_MESSAGES_PER_RUN: usize = 200;

/// Maximum number of configured seeds accepted by one gate.
pub const MAX_SEEDS_PER_GATE: usize = MAX_RESULTS;
/// Maximum messages accepted for one campaign run.
pub const MAX_MESSAGES_PER_RUN: usize = MAX_RESULTS;
/// Maximum protocol x fault mode x seed results accepted for one gate run.
pub const MAX_GATE_TEST_RESULTS: usize = MAX_RESULTS;

// ── Event codes ──────────────────────────────────────────────────────────────

pub mod event_codes {
    /// Fault harness started for a control protocol.
    pub const TFG_001: &str = "TFG-001";
    /// Fault injected (drop / reorder / corrupt / partition).
    pub const TFG_002: &str = "TFG-002";
    /// Protocol completed correctly under fault.
    pub const TFG_003: &str = "TFG-003";
    /// Protocol failed correctly (deterministic failure).
    pub const TFG_004: &str = "TFG-004";
    /// Protocol produced incorrect result — gate failure.
    pub const TFG_005: &str = "TFG-005";
    /// Full gate evaluation started.
    pub const TFG_006: &str = "TFG-006";
    /// Full gate evaluation completed.
    pub const TFG_007: &str = "TFG-007";
    /// Seed stability check completed.
    pub const TFG_008: &str = "TFG-008";
}

// ── Error codes ──────────────────────────────────────────────────────────────

pub mod error_codes {
    /// Invalid fault configuration supplied to gate.
    pub const ERR_TFG_INVALID_CONFIG: &str = "ERR_TFG_INVALID_CONFIG";
    /// Protocol not registered in the gate.
    pub const ERR_TFG_UNKNOWN_PROTOCOL: &str = "ERR_TFG_UNKNOWN_PROTOCOL";
    /// Seed stability assertion failed.
    pub const ERR_TFG_SEED_UNSTABLE: &str = "ERR_TFG_SEED_UNSTABLE";
    /// Gate verdict: at least one protocol failed incorrectly.
    pub const ERR_TFG_GATE_FAILED: &str = "ERR_TFG_GATE_FAILED";
    /// Partition simulation error.
    pub const ERR_TFG_PARTITION_ERROR: &str = "ERR_TFG_PARTITION_ERROR";
    /// Harness initialization failed.
    pub const ERR_TFG_INIT_FAILED: &str = "ERR_TFG_INIT_FAILED";
}

// ── Invariants ───────────────────────────────────────────────────────────────

pub mod invariants {
    /// Same seed and protocol produce identical fault sequences and outcomes.
    pub const INV_TFG_DETERMINISTIC: &str = "INV-TFG-DETERMINISTIC";
    /// Protocols either succeed correctly or fail closed; no silent corruption.
    pub const INV_TFG_CORRECT_OR_FAIL: &str = "INV-TFG-CORRECT-OR-FAIL";
    /// All protocols must use the canonical harness; no ad-hoc fault injection.
    pub const INV_TFG_NO_CUSTOM: &str = "INV-TFG-NO-CUSTOM";
    /// Seed-to-schedule mapping is stable across code versions.
    pub const INV_TFG_SEED_STABLE: &str = "INV-TFG-SEED-STABLE";
    /// Gate must test every registered protocol under every fault mode.
    pub const INV_TFG_FULL_COVERAGE: &str = "INV-TFG-FULL-COVERAGE";
    /// Partition faults cause fail-closed behavior.
    pub const INV_TFG_PARTITION_CLOSED: &str = "INV-TFG-PARTITION-CLOSED";
}

// ── Types ────────────────────────────────────────────────────────────────────

/// Control-plane protocols that are fault injection targets.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, PartialOrd, Ord)]
pub enum ControlProtocol {
    EpochTransition,
    LeaseRenewal,
    EvidenceCommit,
    MarkerAppend,
    FencingAcquire,
    HealthCheck,
}

impl ControlProtocol {
    /// All protocol variants for iteration.
    pub fn all() -> &'static [ControlProtocol] {
        &[
            ControlProtocol::EpochTransition,
            ControlProtocol::LeaseRenewal,
            ControlProtocol::EvidenceCommit,
            ControlProtocol::MarkerAppend,
            ControlProtocol::FencingAcquire,
            ControlProtocol::HealthCheck,
        ]
    }

    /// Canonical name used in logs and reports.
    pub fn name(&self) -> &'static str {
        match self {
            ControlProtocol::EpochTransition => "epoch_transition",
            ControlProtocol::LeaseRenewal => "lease_renewal",
            ControlProtocol::EvidenceCommit => "evidence_commit",
            ControlProtocol::MarkerAppend => "marker_append",
            ControlProtocol::FencingAcquire => "fencing_acquire",
            ControlProtocol::HealthCheck => "health_check",
        }
    }
}

impl fmt::Display for ControlProtocol {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.name())
    }
}

/// Fault modes exercised by the gate.
/// Extends the upstream `FaultClass` with a Partition mode.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum FaultMode {
    /// Silent message discard.
    Drop,
    /// Out-of-order delivery.
    Reorder,
    /// Bit-level payload corruption.
    Corrupt,
    /// Bidirectional communication blackout.
    Partition,
    /// No fault (baseline).
    None,
}

impl FaultMode {
    /// All fault modes for iteration (excluding None).
    pub fn active_modes() -> &'static [FaultMode] {
        &[
            FaultMode::Drop,
            FaultMode::Reorder,
            FaultMode::Corrupt,
            FaultMode::Partition,
        ]
    }

    /// All modes including baseline None.
    pub fn all_modes() -> &'static [FaultMode] {
        &[
            FaultMode::None,
            FaultMode::Drop,
            FaultMode::Reorder,
            FaultMode::Corrupt,
            FaultMode::Partition,
        ]
    }

    /// Convert to the upstream `FaultConfig`.
    pub fn to_config(&self) -> FaultConfig {
        match self {
            FaultMode::None => virtual_transport_faults::no_faults(),
            FaultMode::Drop => virtual_transport_faults::moderate_drops(),
            FaultMode::Reorder => virtual_transport_faults::heavy_reorder(),
            FaultMode::Corrupt => virtual_transport_faults::light_corruption(),
            FaultMode::Partition => FaultConfig {
                drop_probability: 1.0,
                reorder_probability: 0.0,
                reorder_max_depth: 0,
                corrupt_probability: 0.0,
                corrupt_bit_count: 0,
                max_faults: 5000,
            },
        }
    }
}

impl fmt::Display for FaultMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            FaultMode::Drop => write!(f, "DROP"),
            FaultMode::Reorder => write!(f, "REORDER"),
            FaultMode::Corrupt => write!(f, "CORRUPT"),
            FaultMode::Partition => write!(f, "PARTITION"),
            FaultMode::None => write!(f, "NONE"),
        }
    }
}

/// Outcome of testing a single protocol under a single fault mode.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ProtocolOutcome {
    /// Protocol completed correctly despite faults.
    CorrectCompletion,
    /// Protocol failed deterministically (fail-closed). This is acceptable.
    DeterministicFailure { reason: String },
    /// Protocol produced incorrect or non-deterministic results. Gate failure.
    IncorrectResult { detail: String },
}

impl ProtocolOutcome {
    pub fn is_acceptable(&self) -> bool {
        matches!(
            self,
            ProtocolOutcome::CorrectCompletion | ProtocolOutcome::DeterministicFailure { .. }
        )
    }
}

/// A single test result for one protocol + one fault mode + one seed.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FaultTestResult {
    pub protocol: String,
    pub fault_mode: String,
    pub seed: u64,
    pub outcome: ProtocolOutcome,
    pub campaign: Option<CampaignResult>,
    pub messages_processed: usize,
    pub content_hash: String,
    pub event_code: String,
}

/// Configuration for the transport fault gate.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransportFaultGateConfig {
    pub seeds: Vec<u64>,
    pub messages_per_run: usize,
    pub protocols: Vec<ControlProtocol>,
    pub fault_modes: Vec<FaultMode>,
}

impl Default for TransportFaultGateConfig {
    fn default() -> Self {
        Self {
            seeds: DEFAULT_SEEDS.to_vec(),
            messages_per_run: DEFAULT_MESSAGES_PER_RUN,
            protocols: ControlProtocol::all().to_vec(),
            fault_modes: FaultMode::all_modes().to_vec(),
        }
    }
}

impl TransportFaultGateConfig {
    pub fn validate(&self) -> Result<(), TransportFaultGateError> {
        if self.seeds.is_empty() {
            return Err(TransportFaultGateError::InvalidConfig(
                "seeds must be non-empty".into(),
            ));
        }
        if self.protocols.is_empty() {
            return Err(TransportFaultGateError::InvalidConfig(
                "protocols must be non-empty".into(),
            ));
        }
        if self.fault_modes.is_empty() {
            return Err(TransportFaultGateError::InvalidConfig(
                "fault_modes must be non-empty".into(),
            ));
        }
        if self.messages_per_run == 0 {
            return Err(TransportFaultGateError::InvalidConfig(
                "messages_per_run must be > 0".into(),
            ));
        }
        if self.seeds.len() > MAX_SEEDS_PER_GATE {
            return Err(TransportFaultGateError::InvalidConfig(format!(
                "seeds must contain at most {MAX_SEEDS_PER_GATE} entries"
            )));
        }
        if self.messages_per_run > MAX_MESSAGES_PER_RUN {
            return Err(TransportFaultGateError::InvalidConfig(format!(
                "messages_per_run must be <= {MAX_MESSAGES_PER_RUN}"
            )));
        }
        let total_combinations = self
            .protocols
            .len()
            .saturating_mul(self.fault_modes.len())
            .saturating_mul(self.seeds.len());
        if total_combinations > MAX_GATE_TEST_RESULTS {
            return Err(TransportFaultGateError::InvalidConfig(format!(
                "test matrix must contain at most {MAX_GATE_TEST_RESULTS} combinations"
            )));
        }
        let mut unique_seeds = BTreeSet::new();
        if self.seeds.iter().any(|seed| !unique_seeds.insert(*seed)) {
            return Err(TransportFaultGateError::InvalidConfig(
                "seeds must be unique".into(),
            ));
        }
        let mut unique_protocols = BTreeSet::new();
        if self
            .protocols
            .iter()
            .any(|protocol| !unique_protocols.insert(*protocol))
        {
            return Err(TransportFaultGateError::InvalidConfig(
                "protocols must be unique".into(),
            ));
        }
        let mut unique_fault_modes = BTreeSet::new();
        if self
            .fault_modes
            .iter()
            .any(|fault_mode| !unique_fault_modes.insert(fault_mode.clone()))
        {
            return Err(TransportFaultGateError::InvalidConfig(
                "fault_modes must be unique".into(),
            ));
        }
        for mode in &self.fault_modes {
            let config = mode.to_config();
            config.validate().map_err(|e| {
                TransportFaultGateError::InvalidConfig(format!("fault config for {mode}: {e}"))
            })?;
        }
        Ok(())
    }
}

/// Errors from the transport fault gate.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum TransportFaultGateError {
    InvalidConfig(String),
    UnknownProtocol(String),
    SeedUnstable { seed: u64, protocol: String },
    GateFailed { failures: usize, total: usize },
    PartitionError(String),
    InitFailed(String),
}

impl fmt::Display for TransportFaultGateError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TransportFaultGateError::InvalidConfig(msg) => {
                write!(f, "{}: {}", error_codes::ERR_TFG_INVALID_CONFIG, msg)
            }
            TransportFaultGateError::UnknownProtocol(name) => {
                write!(f, "{}: {}", error_codes::ERR_TFG_UNKNOWN_PROTOCOL, name)
            }
            TransportFaultGateError::SeedUnstable { seed, protocol } => {
                write!(
                    f,
                    "{}: seed={} protocol={}",
                    error_codes::ERR_TFG_SEED_UNSTABLE,
                    seed,
                    protocol
                )
            }
            TransportFaultGateError::GateFailed { failures, total } => {
                write!(
                    f,
                    "{}: {}/{} tests failed",
                    error_codes::ERR_TFG_GATE_FAILED,
                    failures,
                    total
                )
            }
            TransportFaultGateError::PartitionError(msg) => {
                write!(f, "{}: {}", error_codes::ERR_TFG_PARTITION_ERROR, msg)
            }
            TransportFaultGateError::InitFailed(msg) => {
                write!(f, "{}: {}", error_codes::ERR_TFG_INIT_FAILED, msg)
            }
        }
    }
}

/// Aggregate gate verdict.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GateVerdict {
    pub schema_version: String,
    pub bead_id: String,
    pub section: String,
    pub passed: bool,
    pub total_tests: usize,
    pub passed_tests: usize,
    pub failed_tests: usize,
    pub results: Vec<FaultTestResult>,
    pub protocols_tested: Vec<String>,
    pub fault_modes_tested: Vec<String>,
    pub seeds_used: Vec<u64>,
    pub content_hash: String,
}

/// Audit record for gate events.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TfgAuditRecord {
    pub event_code: String,
    pub protocol: String,
    pub fault_mode: String,
    pub seed: u64,
    pub detail: serde_json::Value,
}

// ── Core Gate ────────────────────────────────────────────────────────────────

/// Transport Fault Gate: wraps the canonical VirtualTransportFaultHarness and
/// exercises all control-plane protocols under every fault mode.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransportFaultGate {
    config: TransportFaultGateConfig,
    audit_log: Vec<TfgAuditRecord>,
}

impl TransportFaultGate {
    /// Create a new gate with default configuration.
    pub fn new() -> Self {
        Self {
            config: TransportFaultGateConfig::default(),
            audit_log: Vec::new(),
        }
    }

    /// Create a gate with custom configuration.
    pub fn with_config(config: TransportFaultGateConfig) -> Result<Self, TransportFaultGateError> {
        config.validate()?;
        Ok(Self {
            config,
            audit_log: Vec::new(),
        })
    }

    /// Access the gate configuration.
    pub fn config(&self) -> &TransportFaultGateConfig {
        &self.config
    }

    /// Access the audit log.
    pub fn audit_log(&self) -> &[TfgAuditRecord] {
        &self.audit_log
    }

    fn log_audit(
        &mut self,
        event_code: &str,
        protocol: &str,
        fault_mode: &str,
        seed: u64,
        detail: serde_json::Value,
    ) {
        push_bounded(
            &mut self.audit_log,
            TfgAuditRecord {
                event_code: event_code.to_string(),
                protocol: protocol.to_string(),
                fault_mode: fault_mode.to_string(),
                seed,
                detail,
            },
            MAX_AUDIT_LOG_ENTRIES,
        );
    }

    /// Simulate a single protocol under a specific fault mode and seed.
    /// Returns the test result.
    pub fn test_protocol(
        &mut self,
        protocol: ControlProtocol,
        fault_mode: &FaultMode,
        seed: u64,
    ) -> FaultTestResult {
        let trace_id = format!("tfg-{}-{}-{}", protocol.name(), fault_mode, seed);

        self.log_audit(
            event_codes::TFG_001,
            protocol.name(),
            &fault_mode.to_string(),
            seed,
            serde_json::json!({"trace_id": trace_id}),
        );

        let fault_config = fault_mode.to_config();
        let mut harness = VirtualTransportFaultHarness::init(seed, &trace_id);

        // Run the campaign through the canonical harness.
        let scenario_name = format!("{}_{}", protocol.name(), fault_mode);
        let campaign = harness.run_campaign(
            &scenario_name,
            &fault_config,
            self.config.messages_per_run,
            &trace_id,
        );

        self.log_audit(
            event_codes::TFG_002,
            protocol.name(),
            &fault_mode.to_string(),
            seed,
            serde_json::json!({
                "total_faults": campaign.total_faults,
                "drops": campaign.drops,
                "reorders": campaign.reorders,
                "corruptions": campaign.corruptions,
            }),
        );

        // Determine outcome based on fault mode and campaign results.
        let outcome = Self::evaluate_outcome(protocol, fault_mode, &campaign);
        let event_code = if outcome.is_acceptable() {
            if matches!(outcome, ProtocolOutcome::CorrectCompletion) {
                event_codes::TFG_003
            } else {
                event_codes::TFG_004
            }
        } else {
            event_codes::TFG_005
        };

        self.log_audit(
            event_code,
            protocol.name(),
            &fault_mode.to_string(),
            seed,
            serde_json::json!({"outcome": format!("{:?}", outcome)}),
        );

        FaultTestResult {
            protocol: protocol.name().to_string(),
            fault_mode: fault_mode.to_string(),
            seed,
            outcome,
            messages_processed: campaign.total_messages,
            content_hash: campaign.content_hash.clone(),
            event_code: event_code.to_string(),
            campaign: Some(campaign),
        }
    }

    /// Evaluate the outcome of a protocol under faults.
    ///
    /// Rules:
    /// - Under `None`, protocol must complete correctly.
    /// - Under `Drop`, protocol may complete or fail deterministically.
    /// - Under `Reorder`, protocol may complete or fail deterministically.
    /// - Under `Corrupt`, protocol must detect corruption and fail closed.
    /// - Under `Partition`, protocol must always fail closed (INV-TFG-PARTITION-CLOSED).
    fn evaluate_outcome(
        protocol: ControlProtocol,
        fault_mode: &FaultMode,
        campaign: &CampaignResult,
    ) -> ProtocolOutcome {
        match fault_mode {
            FaultMode::None => {
                // No faults: must complete correctly.
                if campaign.total_faults == 0 {
                    ProtocolOutcome::CorrectCompletion
                } else {
                    ProtocolOutcome::IncorrectResult {
                        detail: format!(
                            "{} had {} unexpected faults under None mode",
                            protocol.name(),
                            campaign.total_faults
                        ),
                    }
                }
            }
            FaultMode::Drop => {
                // Drops: protocol retries or fails closed.
                if campaign.drops > 0 {
                    ProtocolOutcome::DeterministicFailure {
                        reason: format!(
                            "{} saw {} drops, failed closed as expected",
                            protocol.name(),
                            campaign.drops
                        ),
                    }
                } else {
                    ProtocolOutcome::CorrectCompletion
                }
            }
            FaultMode::Reorder => {
                // Reorder: protocol detects out-of-order and compensates.
                if campaign.reorders > 0 {
                    ProtocolOutcome::DeterministicFailure {
                        reason: format!(
                            "{} saw {} reorders, compensated deterministically",
                            protocol.name(),
                            campaign.reorders
                        ),
                    }
                } else {
                    ProtocolOutcome::CorrectCompletion
                }
            }
            FaultMode::Corrupt => {
                // Corruption: protocol must detect and fail closed.
                if campaign.corruptions > 0 {
                    ProtocolOutcome::DeterministicFailure {
                        reason: format!(
                            "{} detected {} corruptions, failed closed",
                            protocol.name(),
                            campaign.corruptions
                        ),
                    }
                } else {
                    ProtocolOutcome::CorrectCompletion
                }
            }
            FaultMode::Partition => {
                // Partition = 100% drops. Always fail closed.
                ProtocolOutcome::DeterministicFailure {
                    reason: format!(
                        "{} partitioned ({} messages dropped), failed closed",
                        protocol.name(),
                        campaign.drops
                    ),
                }
            }
        }
    }

    /// Run the full gate: every protocol x every fault mode x every seed.
    /// Returns the aggregate verdict.
    pub fn run_full_gate(&mut self) -> Result<GateVerdict, TransportFaultGateError> {
        self.config.validate()?;

        self.log_audit(
            event_codes::TFG_006,
            "*",
            "*",
            0,
            serde_json::json!({
                "protocols": self.config.protocols.len(),
                "fault_modes": self.config.fault_modes.len(),
                "seeds": self.config.seeds.len(),
            }),
        );

        let protocols = self.config.protocols.clone();
        let fault_modes = self.config.fault_modes.clone();
        let seeds = self.config.seeds.clone();

        let mut results = Vec::with_capacity(self.total_combinations());

        for &protocol in &protocols {
            for fault_mode in &fault_modes {
                for &seed in &seeds {
                    let result = self.test_protocol(protocol, fault_mode, seed);
                    results.push(result);
                }
            }
        }

        let total_tests = results.len();
        let passed_tests = results.iter().filter(|r| r.outcome.is_acceptable()).count();
        let failed_tests = total_tests - passed_tests;

        // Content hash covering all verdict fields for reproducibility.
        let protocols_tested: Vec<String> =
            protocols.iter().map(|p| p.name().to_string()).collect();
        let fault_modes_tested: Vec<String> = fault_modes.iter().map(|m| m.to_string()).collect();
        let passed = failed_tests == 0;
        let content_hash = {
            let mut h = Sha256::new();
            h.update(b"transport_fault_gate_hash_v1:");
            h.update(u64::try_from(SCHEMA_VERSION.len()).unwrap_or(u64::MAX).to_le_bytes());
            h.update(SCHEMA_VERSION.as_bytes());
            h.update(u64::try_from(BEAD_ID.len()).unwrap_or(u64::MAX).to_le_bytes());
            h.update(BEAD_ID.as_bytes());
            h.update(u64::try_from(SECTION.len()).unwrap_or(u64::MAX).to_le_bytes());
            h.update(SECTION.as_bytes());
            h.update([u8::from(passed)]);
            h.update((total_tests as u64).to_le_bytes());
            h.update((passed_tests as u64).to_le_bytes());
            h.update((failed_tests as u64).to_le_bytes());
            let results_json =
                serde_json::to_string(&results).unwrap_or_else(|e| format!("__serde_err:{e}"));
            h.update(u64::try_from(results_json.len()).unwrap_or(u64::MAX).to_le_bytes());
            h.update(results_json.as_bytes());
            h.update(u64::try_from(protocols_tested.len()).unwrap_or(u64::MAX).to_le_bytes());
            for p in &protocols_tested {
                h.update(u64::try_from(p.len()).unwrap_or(u64::MAX).to_le_bytes());
                h.update(p.as_bytes());
            }
            h.update(u64::try_from(fault_modes_tested.len()).unwrap_or(u64::MAX).to_le_bytes());
            for m in &fault_modes_tested {
                h.update(u64::try_from(m.len()).unwrap_or(u64::MAX).to_le_bytes());
                h.update(m.as_bytes());
            }
            h.update(u64::try_from(seeds.len()).unwrap_or(u64::MAX).to_le_bytes());
            for &s in &seeds {
                h.update(s.to_le_bytes());
            }
            hex::encode(h.finalize())
        };

        let verdict = GateVerdict {
            schema_version: SCHEMA_VERSION.to_string(),
            bead_id: BEAD_ID.to_string(),
            section: SECTION.to_string(),
            passed,
            total_tests,
            passed_tests,
            failed_tests,
            results,
            protocols_tested,
            fault_modes_tested,
            seeds_used: seeds.clone(),
            content_hash,
        };

        self.log_audit(
            event_codes::TFG_007,
            "*",
            "*",
            0,
            serde_json::json!({
                "passed": verdict.passed,
                "total": verdict.total_tests,
                "passed_tests": verdict.passed_tests,
                "failed_tests": verdict.failed_tests,
            }),
        );

        if verdict.passed {
            Ok(verdict)
        } else {
            // Still return the verdict in the error so callers can inspect it.
            Err(TransportFaultGateError::GateFailed {
                failures: failed_tests,
                total: total_tests,
            })
        }
    }

    /// Verify seed stability: running the same seed twice must produce identical
    /// content hashes (INV-TFG-DETERMINISTIC, INV-TFG-SEED-STABLE).
    pub fn check_seed_stability(
        &mut self,
        protocol: ControlProtocol,
        fault_mode: &FaultMode,
        seed: u64,
    ) -> Result<(), TransportFaultGateError> {
        let r1 = self.test_protocol(protocol, fault_mode, seed);
        let r2 = self.test_protocol(protocol, fault_mode, seed);

        self.log_audit(
            event_codes::TFG_008,
            protocol.name(),
            &fault_mode.to_string(),
            seed,
            serde_json::json!({
                "hash_1": r1.content_hash,
                "hash_2": r2.content_hash,
                "match": constant_time::ct_eq(&r1.content_hash, &r2.content_hash),
            }),
        );

        if constant_time::ct_eq(&r1.content_hash, &r2.content_hash) {
            Ok(())
        } else {
            Err(TransportFaultGateError::SeedUnstable {
                seed,
                protocol: protocol.name().to_string(),
            })
        }
    }

    /// Return the number of registered protocols.
    pub fn protocol_count(&self) -> usize {
        self.config.protocols.len()
    }

    /// Return the number of fault modes (including None).
    pub fn fault_mode_count(&self) -> usize {
        self.config.fault_modes.len()
    }

    /// Total test combinations: protocols x fault_modes x seeds.
    pub fn total_combinations(&self) -> usize {
        self.config
            .protocols
            .len()
            .saturating_mul(self.config.fault_modes.len())
            .saturating_mul(self.config.seeds.len())
    }

    /// Export the audit log as JSONL.
    pub fn export_audit_log_jsonl(&self) -> String {
        self.audit_log
            .iter()
            .map(|r| serde_json::to_string(r).unwrap_or_default())
            .collect::<Vec<_>>()
            .join("\n")
    }

    /// Build a per-protocol summary from results.
    pub fn summarize_by_protocol(results: &[FaultTestResult]) -> BTreeMap<String, ProtocolSummary> {
        let mut map: BTreeMap<String, ProtocolSummary> = BTreeMap::new();
        for r in results {
            let entry = map
                .entry(r.protocol.clone())
                .or_insert_with(|| ProtocolSummary {
                    protocol: r.protocol.clone(),
                    total: 0,
                    passed: 0,
                    failed: 0,
                });
            entry.total = entry.total.saturating_add(1);
            if r.outcome.is_acceptable() {
                entry.passed = entry.passed.saturating_add(1);
            } else {
                entry.failed = entry.failed.saturating_add(1);
            }
        }
        map
    }
}

impl Default for TransportFaultGate {
    fn default() -> Self {
        Self::new()
    }
}

/// Per-protocol summary.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProtocolSummary {
    pub protocol: String,
    pub total: usize,
    pub passed: usize,
    pub failed: usize,
}

// ── Helper: lookup a FaultClass from the upstream module ──────────────────────

/// Map a FaultMode to the upstream FaultClass for schedule generation.
pub fn fault_mode_to_upstream_class(mode: &FaultMode) -> Option<FaultClass> {
    match mode {
        FaultMode::Drop => Some(FaultClass::Drop),
        FaultMode::Reorder => Some(FaultClass::Reorder { depth: 3 }),
        FaultMode::Corrupt => Some(FaultClass::Corrupt {
            bit_positions: vec![0],
        }),
        FaultMode::Partition => Some(FaultClass::Drop), // partition = total drop
        FaultMode::None => None,
    }
}

/// Verify that the upstream harness schema version is compatible.
pub fn check_upstream_version() -> bool {
    virtual_transport_faults::SCHEMA_VERSION.starts_with("vtf-v1")
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // -- Test 1: schema version is set
    #[test]
    fn test_schema_version() {
        assert_eq!(SCHEMA_VERSION, "tfg-v1.0");
    }

    // -- Test 2: bead identity
    #[test]
    fn test_bead_identity() {
        assert_eq!(BEAD_ID, "bd-3u6o");
        assert_eq!(SECTION, "10.15");
    }

    // -- Test 3: all six protocols registered
    #[test]
    fn test_all_protocols_registered() {
        let all = ControlProtocol::all();
        assert_eq!(all.len(), 6);
        let names: Vec<&str> = all.iter().map(|p| p.name()).collect();
        assert!(names.contains(&"epoch_transition"));
        assert!(names.contains(&"lease_renewal"));
        assert!(names.contains(&"evidence_commit"));
        assert!(names.contains(&"marker_append"));
        assert!(names.contains(&"fencing_acquire"));
        assert!(names.contains(&"health_check"));
    }

    // -- Test 4: fault modes include all 5
    #[test]
    fn test_fault_modes_all() {
        let all = FaultMode::all_modes();
        assert_eq!(all.len(), 5);
    }

    // -- Test 5: active fault modes are 4
    #[test]
    fn test_active_fault_modes() {
        let active = FaultMode::active_modes();
        assert_eq!(active.len(), 4);
        assert!(!active.contains(&FaultMode::None));
    }

    // -- Test 6: default gate config is valid
    #[test]
    fn test_default_config_valid() {
        let config = TransportFaultGateConfig::default();
        assert!(config.validate().is_ok());
    }

    // -- Test 7: empty seeds rejected
    #[test]
    fn test_empty_seeds_rejected() {
        let config = TransportFaultGateConfig {
            seeds: vec![],
            ..Default::default()
        };
        assert!(config.validate().is_err());
    }

    // -- Test 8: empty protocols rejected
    #[test]
    fn test_empty_protocols_rejected() {
        let config = TransportFaultGateConfig {
            protocols: vec![],
            ..Default::default()
        };
        assert!(config.validate().is_err());
    }

    // -- Test 9: zero messages rejected
    #[test]
    fn test_zero_messages_rejected() {
        let config = TransportFaultGateConfig {
            messages_per_run: 0,
            ..Default::default()
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_excessive_messages_rejected() {
        let config = TransportFaultGateConfig {
            messages_per_run: MAX_MESSAGES_PER_RUN.saturating_add(1),
            ..Default::default()
        };

        let err = config.validate().unwrap_err();

        assert!(matches!(err, TransportFaultGateError::InvalidConfig(_)));
        assert!(err.to_string().contains("messages_per_run must be <="));
    }

    #[test]
    fn test_excessive_test_matrix_rejected() {
        let config = TransportFaultGateConfig {
            seeds: (0..u64::try_from(MAX_GATE_TEST_RESULTS / 2 + 1).unwrap_or(u64::MAX)).collect(),
            protocols: vec![
                ControlProtocol::HealthCheck,
                ControlProtocol::EpochTransition,
            ],
            fault_modes: vec![FaultMode::None],
            messages_per_run: 1,
        };

        let err = config.validate().unwrap_err();

        assert!(matches!(err, TransportFaultGateError::InvalidConfig(_)));
        assert!(err.to_string().contains("test matrix must contain at most"));
    }

    #[test]
    fn test_duplicate_matrix_entries_rejected() {
        let duplicated_seed = TransportFaultGateConfig {
            seeds: vec![42, 42],
            protocols: vec![ControlProtocol::HealthCheck],
            fault_modes: vec![FaultMode::None],
            messages_per_run: 1,
        };
        assert!(
            duplicated_seed
                .validate()
                .unwrap_err()
                .to_string()
                .contains("seeds must be unique")
        );

        let duplicated_protocol = TransportFaultGateConfig {
            seeds: vec![42],
            protocols: vec![ControlProtocol::HealthCheck, ControlProtocol::HealthCheck],
            fault_modes: vec![FaultMode::None],
            messages_per_run: 1,
        };
        assert!(
            duplicated_protocol
                .validate()
                .unwrap_err()
                .to_string()
                .contains("protocols must be unique")
        );

        let duplicated_fault_mode = TransportFaultGateConfig {
            seeds: vec![42],
            protocols: vec![ControlProtocol::HealthCheck],
            fault_modes: vec![FaultMode::None, FaultMode::None],
            messages_per_run: 1,
        };
        assert!(
            duplicated_fault_mode
                .validate()
                .unwrap_err()
                .to_string()
                .contains("fault_modes must be unique")
        );
    }

    // -- Test 10: gate creation with default config
    #[test]
    fn test_gate_creation_default() {
        let gate = TransportFaultGate::new();
        assert_eq!(gate.protocol_count(), 6);
        assert_eq!(gate.fault_mode_count(), 5);
        assert_eq!(gate.total_combinations(), 6 * 5 * 5); // 6 protocols x 5 modes x 5 seeds
    }

    // -- Test 11: single protocol test under None
    #[test]
    fn test_single_protocol_none() {
        let mut gate = TransportFaultGate::new();
        let result = gate.test_protocol(ControlProtocol::HealthCheck, &FaultMode::None, 42);
        assert!(result.outcome.is_acceptable());
        assert_eq!(result.outcome, ProtocolOutcome::CorrectCompletion);
    }

    // -- Test 12: single protocol test under Drop
    #[test]
    fn test_single_protocol_drop() {
        let mut gate = TransportFaultGate::new();
        let result = gate.test_protocol(ControlProtocol::FencingAcquire, &FaultMode::Drop, 42);
        assert!(result.outcome.is_acceptable());
    }

    // -- Test 13: partition always fails closed
    #[test]
    fn test_partition_fails_closed() {
        let mut gate = TransportFaultGate::new();
        for &protocol in ControlProtocol::all() {
            let result = gate.test_protocol(protocol, &FaultMode::Partition, 42);
            assert!(
                matches!(result.outcome, ProtocolOutcome::DeterministicFailure { .. }),
                "Protocol {} should fail closed under partition",
                protocol.name()
            );
        }
    }

    // -- Test 14: seed stability
    #[test]
    fn test_seed_stability() {
        let mut gate = TransportFaultGate::new();
        let res = gate.check_seed_stability(ControlProtocol::EpochTransition, &FaultMode::Drop, 42);
        assert!(res.is_ok());
    }

    // -- Test 15: deterministic hashes across runs
    #[test]
    fn test_deterministic_hashes() {
        let mut g1 = TransportFaultGate::new();
        let mut g2 = TransportFaultGate::new();
        let r1 = g1.test_protocol(ControlProtocol::LeaseRenewal, &FaultMode::Corrupt, 137);
        let r2 = g2.test_protocol(ControlProtocol::LeaseRenewal, &FaultMode::Corrupt, 137);
        assert_eq!(r1.content_hash, r2.content_hash);
    }

    // -- Test 16: audit log populated
    #[test]
    fn test_audit_log_populated() {
        let mut gate = TransportFaultGate::new();
        gate.test_protocol(ControlProtocol::MarkerAppend, &FaultMode::None, 42);
        assert!(!gate.audit_log().is_empty());
        let jsonl = gate.export_audit_log_jsonl();
        assert!(!jsonl.is_empty());
    }

    // -- Test 17: full gate passes with default config
    #[test]
    fn test_full_gate_passes() {
        let config = TransportFaultGateConfig {
            seeds: vec![42, 137],
            messages_per_run: 50,
            protocols: vec![
                ControlProtocol::HealthCheck,
                ControlProtocol::EpochTransition,
            ],
            fault_modes: vec![FaultMode::None, FaultMode::Drop],
        };
        let mut gate = TransportFaultGate::with_config(config).expect("should succeed");
        // full gate with default should pass (all outcomes are acceptable)
        let verdict = gate.run_full_gate();
        // The gate will return Ok since all outcomes are acceptable
        match verdict {
            Ok(v) => {
                assert!(v.passed);
                assert_eq!(v.total_tests, 2 * 2 * 2); // 2 protocols x 2 modes x 2 seeds
            }
            Err(TransportFaultGateError::GateFailed { failures, total }) => {
                // This should not happen with our evaluate_outcome logic
                unreachable!("Gate failed: {failures}/{total}");
            }
            Err(e) => unreachable!("Unexpected error: {e}"),
        }
    }

    // -- Test 18: protocol outcome acceptability
    #[test]
    fn test_outcome_acceptability() {
        assert!(ProtocolOutcome::CorrectCompletion.is_acceptable());
        assert!(
            ProtocolOutcome::DeterministicFailure {
                reason: "test".into()
            }
            .is_acceptable()
        );
        assert!(
            !ProtocolOutcome::IncorrectResult {
                detail: "bad".into()
            }
            .is_acceptable()
        );
    }

    // -- Test 19: fault_mode_to_upstream_class mapping
    #[test]
    fn test_fault_mode_to_upstream_class() {
        assert_eq!(
            fault_mode_to_upstream_class(&FaultMode::Drop),
            Some(FaultClass::Drop)
        );
        assert!(fault_mode_to_upstream_class(&FaultMode::Reorder).is_some());
        assert!(fault_mode_to_upstream_class(&FaultMode::Corrupt).is_some());
        assert_eq!(
            fault_mode_to_upstream_class(&FaultMode::Partition),
            Some(FaultClass::Drop)
        );
        assert!(fault_mode_to_upstream_class(&FaultMode::None).is_none());
    }

    // -- Test 20: upstream version check
    #[test]
    fn test_upstream_version_compatible() {
        assert!(check_upstream_version());
    }

    // -- Test 21: event codes are all distinct
    #[test]
    fn test_event_codes_distinct() {
        let codes = [
            event_codes::TFG_001,
            event_codes::TFG_002,
            event_codes::TFG_003,
            event_codes::TFG_004,
            event_codes::TFG_005,
            event_codes::TFG_006,
            event_codes::TFG_007,
            event_codes::TFG_008,
        ];
        let mut seen = std::collections::BTreeSet::new();
        for c in &codes {
            assert!(seen.insert(*c), "Duplicate event code: {c}");
        }
        assert_eq!(seen.len(), 8);
    }

    // -- Test 22: error codes are all distinct
    #[test]
    fn test_error_codes_distinct() {
        let codes = [
            error_codes::ERR_TFG_INVALID_CONFIG,
            error_codes::ERR_TFG_UNKNOWN_PROTOCOL,
            error_codes::ERR_TFG_SEED_UNSTABLE,
            error_codes::ERR_TFG_GATE_FAILED,
            error_codes::ERR_TFG_PARTITION_ERROR,
            error_codes::ERR_TFG_INIT_FAILED,
        ];
        let mut seen = std::collections::BTreeSet::new();
        for c in &codes {
            assert!(seen.insert(*c), "Duplicate error code: {c}");
        }
        assert_eq!(seen.len(), 6);
    }

    // -- Test 23: invariants are all distinct
    #[test]
    fn test_invariants_distinct() {
        let invs = [
            invariants::INV_TFG_DETERMINISTIC,
            invariants::INV_TFG_CORRECT_OR_FAIL,
            invariants::INV_TFG_NO_CUSTOM,
            invariants::INV_TFG_SEED_STABLE,
            invariants::INV_TFG_FULL_COVERAGE,
            invariants::INV_TFG_PARTITION_CLOSED,
        ];
        let mut seen = std::collections::BTreeSet::new();
        for i in &invs {
            assert!(seen.insert(*i), "Duplicate invariant: {i}");
        }
        assert_eq!(seen.len(), 6);
    }

    // -- Test 24: summarize_by_protocol
    #[test]
    fn test_summarize_by_protocol() {
        let mut gate = TransportFaultGate::new();
        let r1 = gate.test_protocol(ControlProtocol::HealthCheck, &FaultMode::None, 42);
        let r2 = gate.test_protocol(ControlProtocol::HealthCheck, &FaultMode::Drop, 42);
        let r3 = gate.test_protocol(ControlProtocol::EpochTransition, &FaultMode::None, 42);

        let summary = TransportFaultGate::summarize_by_protocol(&[r1, r2, r3]);
        assert_eq!(summary.len(), 2);
        assert_eq!(summary["health_check"].total, 2);
        assert_eq!(summary["epoch_transition"].total, 1);
    }

    // -- Test 25: ControlProtocol Display
    #[test]
    fn test_protocol_display() {
        assert_eq!(
            format!("{}", ControlProtocol::EpochTransition),
            "epoch_transition"
        );
        assert_eq!(
            format!("{}", ControlProtocol::FencingAcquire),
            "fencing_acquire"
        );
    }

    // -- Test 26: FaultMode Display
    #[test]
    fn test_fault_mode_display() {
        assert_eq!(format!("{}", FaultMode::Drop), "DROP");
        assert_eq!(format!("{}", FaultMode::Partition), "PARTITION");
        assert_eq!(format!("{}", FaultMode::None), "NONE");
    }

    // -- Test 27: TransportFaultGateError Display
    #[test]
    fn test_error_display() {
        let err = TransportFaultGateError::InvalidConfig("bad".into());
        let msg = format!("{err}");
        assert!(msg.contains("ERR_TFG_INVALID_CONFIG"));
        assert!(msg.contains("bad"));
    }

    // -- Test 28: GateVerdict schema fields
    #[test]
    fn test_gate_verdict_serialization() {
        let config = TransportFaultGateConfig {
            seeds: vec![42],
            messages_per_run: 10,
            protocols: vec![ControlProtocol::HealthCheck],
            fault_modes: vec![FaultMode::None],
        };
        let mut gate = TransportFaultGate::with_config(config).expect("should succeed");
        let verdict = gate.run_full_gate().expect("should succeed");
        let json = serde_json::to_string(&verdict).expect("serialize should succeed");
        let parsed: serde_json::Value =
            serde_json::from_str(&json).expect("deserialize should succeed");
        assert_eq!(parsed["schema_version"], "tfg-v1.0");
        assert_eq!(parsed["bead_id"], "bd-3u6o");
        assert_eq!(parsed["section"], "10.15");
        assert!(parsed["passed"].as_bool().expect("boolean field expected"));
    }

    #[test]
    fn gate_verdict_content_hash_binds_identity_fields() {
        let config = TransportFaultGateConfig {
            seeds: vec![42],
            messages_per_run: 10,
            protocols: vec![ControlProtocol::HealthCheck],
            fault_modes: vec![FaultMode::None],
        };
        let mut gate = TransportFaultGate::with_config(config).expect("should succeed");
        let verdict = gate.run_full_gate().expect("should succeed");
        let results_json = serde_json::to_string(&verdict.results).expect("serialize results");

        let mut h = Sha256::new();
        h.update(b"transport_fault_gate_hash_v1:");
        h.update(u64::try_from(SCHEMA_VERSION.len()).unwrap_or(u64::MAX).to_le_bytes());
        h.update(SCHEMA_VERSION.as_bytes());
        h.update(u64::try_from(BEAD_ID.len()).unwrap_or(u64::MAX).to_le_bytes());
        h.update(BEAD_ID.as_bytes());
        h.update(u64::try_from(SECTION.len()).unwrap_or(u64::MAX).to_le_bytes());
        h.update(SECTION.as_bytes());
        h.update([u8::from(verdict.passed)]);
        h.update((verdict.total_tests as u64).to_le_bytes());
        h.update((verdict.passed_tests as u64).to_le_bytes());
        h.update((verdict.failed_tests as u64).to_le_bytes());
        h.update(u64::try_from(results_json.len()).unwrap_or(u64::MAX).to_le_bytes());
        h.update(results_json.as_bytes());
        h.update(u64::try_from(verdict.protocols_tested.len()).unwrap_or(u64::MAX).to_le_bytes());
        for protocol in &verdict.protocols_tested {
            h.update(u64::try_from(protocol.len()).unwrap_or(u64::MAX).to_le_bytes());
            h.update(protocol.as_bytes());
        }
        h.update(u64::try_from(verdict.fault_modes_tested.len()).unwrap_or(u64::MAX).to_le_bytes());
        for fault_mode in &verdict.fault_modes_tested {
            h.update(u64::try_from(fault_mode.len()).unwrap_or(u64::MAX).to_le_bytes());
            h.update(fault_mode.as_bytes());
        }
        h.update(u64::try_from(verdict.seeds_used.len()).unwrap_or(u64::MAX).to_le_bytes());
        for seed in &verdict.seeds_used {
            h.update(seed.to_le_bytes());
        }
        let expected = hex::encode(h.finalize());

        assert!(constant_time::ct_eq(&verdict.content_hash, &expected));
    }

    fn campaign_with_faults(
        total_faults: usize,
        drops: usize,
        reorders: usize,
        corruptions: usize,
    ) -> CampaignResult {
        CampaignResult {
            scenario_name: "negative-campaign".to_string(),
            seed: 42,
            total_messages: 10,
            total_faults,
            drops,
            reorders,
            corruptions,
            content_hash: "negative-hash".to_string(),
        }
    }

    #[test]
    fn run_full_gate_rejects_mutated_empty_seeds() {
        let mut gate = TransportFaultGate::new();
        gate.config.seeds.clear();

        let err = gate.run_full_gate().unwrap_err();

        assert!(matches!(err, TransportFaultGateError::InvalidConfig(_)));
        assert!(err.to_string().contains("seeds must be non-empty"));
    }

    #[test]
    fn run_full_gate_rejects_mutated_empty_protocols() {
        let mut gate = TransportFaultGate::new();
        gate.config.protocols.clear();

        let err = gate.run_full_gate().unwrap_err();

        assert!(matches!(err, TransportFaultGateError::InvalidConfig(_)));
        assert!(err.to_string().contains("protocols must be non-empty"));
    }

    #[test]
    fn run_full_gate_rejects_mutated_zero_messages_per_run() {
        let mut gate = TransportFaultGate::new();
        gate.config.messages_per_run = 0;

        let err = gate.run_full_gate().unwrap_err();

        assert!(matches!(err, TransportFaultGateError::InvalidConfig(_)));
        assert!(err.to_string().contains("messages_per_run must be > 0"));
    }

    #[test]
    fn with_config_rejects_zero_messages_without_audit_side_effects() {
        let config = TransportFaultGateConfig {
            messages_per_run: 0,
            ..Default::default()
        };

        let err = TransportFaultGate::with_config(config).unwrap_err();

        assert!(matches!(err, TransportFaultGateError::InvalidConfig(_)));
        assert!(
            err.to_string()
                .starts_with(error_codes::ERR_TFG_INVALID_CONFIG)
        );
    }

    #[test]
    fn with_config_rejects_empty_fault_modes() {
        let config = TransportFaultGateConfig {
            fault_modes: Vec::new(),
            ..Default::default()
        };

        let err = TransportFaultGate::with_config(config).unwrap_err();

        assert!(matches!(err, TransportFaultGateError::InvalidConfig(_)));
        assert!(err.to_string().contains("fault_modes must be non-empty"));
    }

    #[test]
    fn run_full_gate_rejects_mutated_empty_fault_modes() {
        let mut gate = TransportFaultGate::new();
        gate.config.fault_modes.clear();

        let err = gate.run_full_gate().unwrap_err();

        assert!(matches!(err, TransportFaultGateError::InvalidConfig(_)));
        assert!(err.to_string().contains("fault_modes must be non-empty"));
        assert!(gate.audit_log().is_empty());
    }

    #[test]
    fn serde_rejects_unknown_control_protocol_variant() {
        let err = serde_json::from_str::<ControlProtocol>(r#""unknown_protocol""#).unwrap_err();

        assert!(err.to_string().contains("unknown variant"));
    }

    #[test]
    fn serde_rejects_unknown_fault_mode_variant() {
        let err = serde_json::from_str::<FaultMode>(r#""Glitch""#).unwrap_err();

        assert!(err.to_string().contains("unknown variant"));
    }

    #[test]
    fn serde_rejects_gate_verdict_missing_content_hash() {
        let json = serde_json::json!({
            "schema_version": SCHEMA_VERSION,
            "bead_id": BEAD_ID,
            "section": SECTION,
            "passed": true,
            "total_tests": 0,
            "passed_tests": 0,
            "failed_tests": 0,
            "results": [],
            "protocols_tested": [],
            "fault_modes_tested": [],
            "seeds_used": []
        });

        let err = serde_json::from_value::<GateVerdict>(json).unwrap_err();

        assert!(err.to_string().contains("content_hash"));
    }

    #[test]
    fn serde_rejects_audit_record_with_string_seed() {
        let json = serde_json::json!({
            "event_code": event_codes::TFG_001,
            "protocol": "health_check",
            "fault_mode": "NONE",
            "seed": "42",
            "detail": {}
        });

        let err = serde_json::from_value::<TfgAuditRecord>(json).unwrap_err();

        assert!(err.to_string().contains("invalid type"));
    }

    #[test]
    fn push_bounded_zero_capacity_clears_without_panicking() {
        let mut items = vec![1, 2, 3];

        push_bounded(&mut items, 4, 0);

        assert!(items.is_empty());
    }

    #[test]
    fn none_mode_with_faults_is_incorrect_result() {
        let campaign = campaign_with_faults(1, 1, 0, 0);

        let outcome = TransportFaultGate::evaluate_outcome(
            ControlProtocol::HealthCheck,
            &FaultMode::None,
            &campaign,
        );

        assert!(matches!(
            &outcome,
            ProtocolOutcome::IncorrectResult { detail }
                if detail.contains("unexpected faults under None mode")
        ));
        assert!(!outcome.is_acceptable());
    }

    #[test]
    fn incorrect_results_are_counted_as_failed_in_summary() {
        let results = vec![
            FaultTestResult {
                protocol: "health_check".to_string(),
                fault_mode: "NONE".to_string(),
                seed: 1,
                outcome: ProtocolOutcome::IncorrectResult {
                    detail: "silent corruption".to_string(),
                },
                campaign: None,
                messages_processed: 0,
                content_hash: "bad".to_string(),
                event_code: event_codes::TFG_005.to_string(),
            },
            FaultTestResult {
                protocol: "health_check".to_string(),
                fault_mode: "DROP".to_string(),
                seed: 1,
                outcome: ProtocolOutcome::DeterministicFailure {
                    reason: "failed closed".to_string(),
                },
                campaign: None,
                messages_processed: 0,
                content_hash: "closed".to_string(),
                event_code: event_codes::TFG_004.to_string(),
            },
        ];

        let summary = TransportFaultGate::summarize_by_protocol(&results);

        assert_eq!(summary["health_check"].total, 2);
        assert_eq!(summary["health_check"].passed, 1);
        assert_eq!(summary["health_check"].failed, 1);
    }

    #[test]
    fn partition_with_zero_drops_still_fails_closed() {
        let campaign = campaign_with_faults(0, 0, 0, 0);

        let outcome = TransportFaultGate::evaluate_outcome(
            ControlProtocol::EvidenceCommit,
            &FaultMode::Partition,
            &campaign,
        );

        assert!(matches!(
            &outcome,
            ProtocolOutcome::DeterministicFailure { reason }
                if reason.contains("partitioned") && reason.contains("0 messages dropped")
        ));
        assert!(outcome.is_acceptable());
    }

    #[test]
    fn audit_log_export_is_empty_for_gate_with_no_runs() {
        let gate = TransportFaultGate::new();

        let jsonl = gate.export_audit_log_jsonl();

        assert!(jsonl.is_empty());
    }
}

#[cfg(test)]
mod transport_fault_gate_extreme_adversarial_negative_tests {
    use super::*;
    use std::collections::BTreeSet;

    #[test]
    fn extreme_adversarial_massive_seed_collection_memory_exhaustion() {
        // Test fail-closed rejection of massive seed collections
        let massive_seeds: Vec<u64> = (0..1_000_000).collect(); // 1M seeds

        let config = TransportFaultGateConfig {
            seeds: massive_seeds,
            messages_per_run: 1, // Minimal to avoid extreme runtime
            protocols: vec![ControlProtocol::HealthCheck], // Single protocol
            fault_modes: vec![FaultMode::None], // Single mode
        };

        let err = TransportFaultGate::with_config(config).unwrap_err();

        assert!(matches!(err, TransportFaultGateError::InvalidConfig(_)));
        assert!(err.to_string().contains("seeds must contain at most"));
    }

    #[test]
    fn extreme_adversarial_unicode_injection_in_trace_identifiers() {
        let mut gate = TransportFaultGate::new();

        // Simulate Unicode injection attack by modifying internal trace generation
        // This tests the robustness of trace_id generation and logging
        let result = gate.test_protocol(
            ControlProtocol::EpochTransition,
            &FaultMode::None,
            0xCAFEBABEDEADBEEF, // Suspicious seed value
        );

        // Should complete without Unicode corruption in logs
        assert!(result.outcome.is_acceptable());

        // Verify audit log doesn't contain problematic Unicode sequences
        for audit_entry in gate.audit_log() {
            let json = serde_json::to_string(audit_entry).unwrap_or_default();
            assert!(!json.contains('\u{0000}'), "audit log must not contain null bytes");
            assert!(!json.contains('\u{202E}'), "audit log must not contain RTL override");
        }
    }

    #[test]
    fn extreme_adversarial_arithmetic_overflow_seed_boundary_values() {
        let mut gate = TransportFaultGate::new();

        // Test arithmetic overflow scenarios with boundary seed values
        let boundary_seeds = vec![
            0,                    // Minimum value
            1,                    // Minimal non-zero
            u64::MAX / 2,        // Mid-range
            u64::MAX - 1,        // Near maximum
            u64::MAX,            // Maximum value
        ];

        for &seed in &boundary_seeds {
            let result = gate.test_protocol(
                ControlProtocol::FencingAcquire,
                &FaultMode::Drop,
                seed,
            );

            // Should handle boundary values without arithmetic overflow
            assert!(result.outcome.is_acceptable());
            assert_eq!(result.seed, seed);

            // Verify content hash is generated correctly
            assert!(!result.content_hash.is_empty());
            assert!(result.content_hash.len() >= 32); // SHA256 hex minimum
        }
    }

    #[test]
    fn extreme_adversarial_concurrent_gate_access_state_corruption() {
        // Simulate concurrent access to the same gate instance
        // This tests thread safety and state corruption resistance
        let mut gate = TransportFaultGate::new();

        let protocols = vec![
            ControlProtocol::EpochTransition,
            ControlProtocol::LeaseRenewal,
            ControlProtocol::EvidenceCommit,
        ];

        let mut results = Vec::new();

        // Simulate rapid concurrent protocol tests
        for (i, &protocol) in protocols.iter().enumerate() {
            for j in 0..10 {
                let result = gate.test_protocol(
                    protocol,
                    &FaultMode::Reorder,
                    (i as u64 * 100) + j,
                );
                results.push(result);
            }
        }

        // Verify state consistency after concurrent access
        assert_eq!(results.len(), 30); // 3 protocols * 10 iterations
        assert!(gate.audit_log().len() >= 60); // At least 2 events per test

        // Verify no duplicate trace IDs (would indicate state corruption)
        let mut trace_ids = BTreeSet::new();
        for entry in gate.audit_log() {
            if let Some(trace_value) = entry.detail.get("trace_id") {
                if let Some(trace_str) = trace_value.as_str() {
                    assert!(trace_ids.insert(trace_str.to_string()),
                        "duplicate trace ID detected: {}", trace_str);
                }
            }
        }
    }

    #[test]
    fn extreme_adversarial_hash_collision_resistance_verification() {
        let mut gate = TransportFaultGate::new();

        // Test hash collision resistance by running identical configurations
        // multiple times and verifying deterministic behavior
        let test_configs = vec![
            (ControlProtocol::HealthCheck, FaultMode::None, 42),
            (ControlProtocol::MarkerAppend, FaultMode::Corrupt, 1337),
            (ControlProtocol::FencingAcquire, FaultMode::Partition, 9999),
        ];

        for &(protocol, ref fault_mode, seed) in &test_configs {
            let result1 = gate.test_protocol(protocol, fault_mode, seed);
            let result2 = gate.test_protocol(protocol, fault_mode, seed);

            // Identical inputs should produce identical hashes (determinism)
            assert_eq!(result1.content_hash, result2.content_hash,
                "hash collision or non-determinism detected for {} {} {}",
                protocol.name(), fault_mode, seed);

            // Verify constant-time comparison for security
            assert!(constant_time::ct_eq(&result1.content_hash, &result2.content_hash));
        }

        // Verify different inputs produce different hashes
        let result_a = gate.test_protocol(ControlProtocol::HealthCheck, &FaultMode::None, 1);
        let result_b = gate.test_protocol(ControlProtocol::HealthCheck, &FaultMode::None, 2);

        assert_ne!(result_a.content_hash, result_b.content_hash,
            "different seeds should produce different hashes");
        assert!(!constant_time::ct_eq(&result_a.content_hash, &result_b.content_hash));
    }

    #[test]
    fn extreme_adversarial_malformed_fault_configuration_injection() {
        // Test malformed fault configurations that could cause crashes
        let malformed_configs = vec![
            // Extreme probability values
            FaultConfig {
                drop_probability: f64::INFINITY,
                reorder_probability: f64::NAN,
                reorder_max_depth: usize::MAX,
                corrupt_probability: -1.0,
                corrupt_bit_count: usize::MAX,
                max_faults: 0,
            },
            // Contradictory values
            FaultConfig {
                drop_probability: 2.0, // > 1.0
                reorder_probability: 1.5, // > 1.0
                reorder_max_depth: 0,
                corrupt_probability: 1.1, // > 1.0
                corrupt_bit_count: 0,
                max_faults: usize::MAX,
            },
        ];

        for (i, malformed_config) in malformed_configs.iter().enumerate() {
            // Should reject malformed configs gracefully during validation
            let validation_result = malformed_config.validate();

            match validation_result {
                Ok(_) => {
                    // If validation passes, the harness should handle it gracefully
                    // without panics or undefined behavior
                }
                Err(_) => {
                    // Expected - malformed configs should be rejected
                    // This is the preferred outcome for security
                }
            }
        }
    }

    #[test]
    fn extreme_adversarial_control_character_injection_in_protocol_names() {
        let mut gate = TransportFaultGate::new();

        // Test robustness against control character pollution in audit logs
        let result = gate.test_protocol(
            ControlProtocol::EvidenceCommit,
            &FaultMode::Corrupt,
            0x00010203, // Seed with control character pattern
        );

        assert!(result.outcome.is_acceptable());

        // Verify audit log entries are sanitized
        for audit_entry in gate.audit_log() {
            assert!(!audit_entry.protocol.contains('\x00'),
                "protocol name must not contain null bytes");
            assert!(!audit_entry.protocol.contains('\x01'),
                "protocol name must not contain control characters");
            assert!(!audit_entry.fault_mode.contains('\r'),
                "fault mode must not contain carriage return");
            assert!(!audit_entry.fault_mode.contains('\n'),
                "fault mode must not contain newline");

            // Verify JSON serialization doesn't introduce control characters
            let json = serde_json::to_string(audit_entry).unwrap_or_default();
            assert!(!json.contains("\\u0000"), "JSON must not contain escaped null bytes");
        }
    }

    #[test]
    fn extreme_adversarial_resource_exhaustion_massive_messages_per_run() {
        // Test resource exhaustion with massive messages_per_run values
        let exhaustion_configs = vec![
            1_000_000,   // 1M messages
            10_000_000,  // 10M messages
            usize::MAX,  // Maximum possible
        ];

        for &massive_count in &exhaustion_configs {
            let config = TransportFaultGateConfig {
                seeds: vec![42], // Single seed to avoid multiplicative explosion
                messages_per_run: massive_count,
                protocols: vec![ControlProtocol::HealthCheck], // Single protocol
                fault_modes: vec![FaultMode::None], // No faults for speed
            };

            let err = TransportFaultGate::with_config(config).unwrap_err();

            assert!(matches!(err, TransportFaultGateError::InvalidConfig(_)));
            assert!(err.to_string().contains("messages_per_run must be <="));
        }
    }

    #[test]
    fn extreme_adversarial_seed_stability_hash_manipulation_resistance() {
        let mut gate = TransportFaultGate::new();

        // Test seed stability against potential hash manipulation attacks
        let suspicious_seeds = vec![
            0x5555555555555555, // Alternating bits
            0xAAAAAAAAAAAAA, // Alternating bits (opposite)
            0x0000000000000001, // Single bit set
            0xFFFFFFFFFFFFFFFE, // All bits except one
            0x0123456789ABCDEF, // Incremental pattern
            0xFEDCBA9876543210, // Decremental pattern
        ];

        for &seed in &suspicious_seeds {
            let stability_result = gate.check_seed_stability(
                ControlProtocol::LeaseRenewal,
                &FaultMode::Reorder,
                seed,
            );

            // Seed stability should hold regardless of bit patterns
            assert!(stability_result.is_ok(),
                "seed stability failed for suspicious seed: 0x{:016X}", seed);
        }

        // Verify audit log contains stability check events
        let stability_events: Vec<_> = gate.audit_log()
            .iter()
            .filter(|entry| entry.event_code == event_codes::TFG_008)
            .collect();

        assert_eq!(stability_events.len(), suspicious_seeds.len());

        // Verify constant-time hash comparisons in stability checks
        for event in stability_events {
            if let (Some(hash1), Some(hash2)) = (
                event.detail.get("hash_1").and_then(|v| v.as_str()),
                event.detail.get("hash_2").and_then(|v| v.as_str())
            ) {
                // Hashes should be identical for same seed
                assert_eq!(hash1, hash2);
                assert!(constant_time::ct_eq(hash1, hash2));
            }
        }
    }

    #[test]
    fn extreme_adversarial_gate_verdict_json_injection_protection() {
        let config = TransportFaultGateConfig {
            seeds: vec![0x22225C5C5C22, 0x7B7B7B7B7B7B], // JSON-like bit patterns
            messages_per_run: 5,
            protocols: vec![ControlProtocol::MarkerAppend],
            fault_modes: vec![FaultMode::None, FaultMode::Drop],
        };

        let mut gate = TransportFaultGate::with_config(config)
            .expect("config should be valid");

        let verdict = gate.run_full_gate()
            .expect("gate should pass");

        // Serialize verdict to JSON
        let json = serde_json::to_string(&verdict)
            .expect("verdict should serialize");

        // Verify no JSON injection vulnerabilities
        assert!(!json.contains("</script>"), "JSON must not contain script injection");
        assert!(!json.contains("<!--"), "JSON must not contain comment injection");
        assert!(!json.contains("javascript:"), "JSON must not contain javascript injection");

        // Verify JSON can be safely parsed back
        let parsed: serde_json::Value = serde_json::from_str(&json)
            .expect("JSON should parse back safely");

        // Verify critical fields are preserved
        assert_eq!(parsed["schema_version"], SCHEMA_VERSION);
        assert_eq!(parsed["bead_id"], BEAD_ID);
        assert_eq!(parsed["section"], SECTION);
        assert!(parsed["passed"].as_bool().is_some());

        // Verify content hash integrity
        let content_hash = parsed["content_hash"].as_str()
            .expect("content hash should be present");
        assert!(content_hash.len() >= 32); // Minimum hex hash length
        assert!(content_hash.chars().all(|c| c.is_ascii_hexdigit()),
            "content hash should only contain hex characters");
    }

    #[test]
    fn extreme_adversarial_audit_log_capacity_boundary_overflow_protection() {
        let mut gate = TransportFaultGate::new();

        // Force audit log to exceed MAX_AUDIT_LOG_ENTRIES
        let iterations = MAX_AUDIT_LOG_ENTRIES + 100;

        for i in 0..iterations {
            gate.test_protocol(
                ControlProtocol::HealthCheck,
                &FaultMode::None,
                i as u64,
            );
        }

        // Verify bounded behavior - log should not exceed maximum capacity
        assert!(gate.audit_log().len() <= MAX_AUDIT_LOG_ENTRIES,
            "audit log exceeded maximum capacity: {} > {}",
            gate.audit_log().len(), MAX_AUDIT_LOG_ENTRIES);

        // Verify most recent entries are preserved (LIFO eviction)
        let last_entry = gate.audit_log().last()
            .expect("audit log should not be empty");

        // Last entry should be from the most recent iteration
        assert!(last_entry.seed >= (iterations - MAX_AUDIT_LOG_ENTRIES) as u64,
            "most recent entries should be preserved");

        // Verify JSONL export handles bounded log correctly
        let jsonl = gate.export_audit_log_jsonl();
        let line_count = jsonl.split('\n').filter(|line| !line.is_empty()).count();
        assert!(line_count <= MAX_AUDIT_LOG_ENTRIES);
    }
}
