//! bd-2qqu: Virtual transport fault harness for remote-control protocol testing.
//!
//! Injects deterministic fault schedules (drop, reorder, corrupt) into a
//! transport layer for systematic protocol testing.

use std::collections::VecDeque;
use std::fmt;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::capacity_defaults::aliases::MAX_RESULTS;
use crate::push_bounded;

// ── Constants ────────────────────────────────────────────────────────────────

pub const SCHEMA_VERSION: &str = "vtf-v1.0";
pub const DEFAULT_MAX_FAULT_LOG_ENTRIES: usize = 4_096;
pub const DEFAULT_MAX_AUDIT_LOG_ENTRIES: usize = 4_096;
pub const MAX_CORRUPT_BITS: usize = 4_096;
pub const MAX_SCHEDULED_FAULTS: usize = MAX_RESULTS;
pub const MAX_CAMPAIGN_MESSAGES: usize = MAX_RESULTS;

fn default_max_fault_log_entries() -> usize {
    DEFAULT_MAX_FAULT_LOG_ENTRIES
}

fn default_max_audit_log_entries() -> usize {
    DEFAULT_MAX_AUDIT_LOG_ENTRIES
}

// ── Event codes ──────────────────────────────────────────────────────────────

pub mod event_codes {
    pub const FAULT_INJECTED: &str = "FAULT_INJECTED";
    pub const FAULT_SCHEDULE_CREATED: &str = "FAULT_SCHEDULE_CREATED";
    pub const FAULT_CAMPAIGN_COMPLETE: &str = "FAULT_CAMPAIGN_COMPLETE";
    pub const FAULT_LOG_EXPORTED: &str = "FAULT_LOG_EXPORTED";
    pub const FAULT_DROP_APPLIED: &str = "FAULT_DROP_APPLIED";
    pub const FAULT_REORDER_APPLIED: &str = "FAULT_REORDER_APPLIED";
    pub const FAULT_CORRUPT_APPLIED: &str = "FAULT_CORRUPT_APPLIED";
    pub const FAULT_NONE: &str = "FAULT_NONE";
    pub const FAULT_HARNESS_INIT: &str = "FAULT_HARNESS_INIT";
    pub const FAULT_SCENARIO_START: &str = "FAULT_SCENARIO_START";
    pub const FAULT_SCENARIO_END: &str = "FAULT_SCENARIO_END";
    pub const FAULT_AUDIT_EMITTED: &str = "FAULT_AUDIT_EMITTED";
}

// ── Invariants ───────────────────────────────────────────────────────────────

pub mod invariants {
    pub const INV_VTF_DETERMINISTIC: &str = "INV-VTF-DETERMINISTIC";
    pub const INV_VTF_DROP: &str = "INV-VTF-DROP";
    pub const INV_VTF_REORDER: &str = "INV-VTF-REORDER";
    pub const INV_VTF_CORRUPT: &str = "INV-VTF-CORRUPT";
    pub const INV_VTF_LOGGED: &str = "INV-VTF-LOGGED";
    pub const INV_VTF_REPRODUCIBLE: &str = "INV-VTF-REPRODUCIBLE";
}

// ── Types ────────────────────────────────────────────────────────────────────

/// Fault classes supported by the harness.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum FaultClass {
    Drop,
    Reorder { depth: usize },
    Corrupt { bit_positions: Vec<usize> },
}

impl fmt::Display for FaultClass {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            FaultClass::Drop => write!(f, "Drop"),
            FaultClass::Reorder { depth } => write!(f, "Reorder(depth={depth})"),
            FaultClass::Corrupt { bit_positions } => {
                write!(f, "Corrupt(bits={})", bit_positions.len())
            }
        }
    }
}

/// Configuration for fault injection.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FaultConfig {
    pub drop_probability: f64,
    pub reorder_probability: f64,
    pub reorder_max_depth: usize,
    pub corrupt_probability: f64,
    pub corrupt_bit_count: usize,
    pub max_faults: usize,
}

impl FaultConfig {
    pub fn validate(&self) -> Result<(), String> {
        if !self.drop_probability.is_finite() || !(0.0..=1.0).contains(&self.drop_probability) {
            return Err("drop_probability must be in [0, 1]".to_string());
        }
        if !self.reorder_probability.is_finite() || !(0.0..=1.0).contains(&self.reorder_probability)
        {
            return Err("reorder_probability must be in [0, 1]".to_string());
        }
        if !self.corrupt_probability.is_finite() || !(0.0..=1.0).contains(&self.corrupt_probability)
        {
            return Err("corrupt_probability must be in [0, 1]".to_string());
        }
        let total_probability =
            self.drop_probability + self.reorder_probability + self.corrupt_probability;
        if total_probability > 1.0 {
            return Err("fault probabilities must sum to <= 1".to_string());
        }
        if self.reorder_probability > 0.0 && self.reorder_max_depth == 0 {
            return Err("reorder_max_depth must be > 0 when reorder_probability > 0".to_string());
        }
        if self.corrupt_probability > 0.0 && self.corrupt_bit_count == 0 {
            return Err("corrupt_bit_count must be > 0 when corrupt_probability > 0".to_string());
        }
        if self.corrupt_bit_count > MAX_CORRUPT_BITS {
            return Err(format!("corrupt_bit_count must be <= {MAX_CORRUPT_BITS}"));
        }
        if self.max_faults == 0 {
            return Err("max_faults must be > 0".to_string());
        }
        if self.max_faults > MAX_SCHEDULED_FAULTS {
            return Err(format!("max_faults must be <= {MAX_SCHEDULED_FAULTS}"));
        }
        Ok(())
    }
}

fn validate_total_messages(total_messages: usize) -> Result<(), String> {
    if total_messages > MAX_CAMPAIGN_MESSAGES {
        return Err(format!("total_messages must be <= {MAX_CAMPAIGN_MESSAGES}"));
    }
    Ok(())
}

/// Pre-built fault scenarios.
pub fn no_faults() -> FaultConfig {
    FaultConfig {
        drop_probability: 0.0,
        reorder_probability: 0.0,
        reorder_max_depth: 0,
        corrupt_probability: 0.0,
        corrupt_bit_count: 0,
        max_faults: 1000,
    }
}

pub fn moderate_drops() -> FaultConfig {
    FaultConfig {
        drop_probability: 0.05,
        reorder_probability: 0.0,
        reorder_max_depth: 0,
        corrupt_probability: 0.0,
        corrupt_bit_count: 0,
        max_faults: 1000,
    }
}

pub fn heavy_reorder() -> FaultConfig {
    FaultConfig {
        drop_probability: 0.0,
        reorder_probability: 0.20,
        reorder_max_depth: 5,
        corrupt_probability: 0.0,
        corrupt_bit_count: 0,
        max_faults: 1000,
    }
}

pub fn light_corruption() -> FaultConfig {
    FaultConfig {
        drop_probability: 0.0,
        reorder_probability: 0.0,
        reorder_max_depth: 0,
        corrupt_probability: 0.01,
        corrupt_bit_count: 1,
        max_faults: 1000,
    }
}

pub fn chaos() -> FaultConfig {
    FaultConfig {
        drop_probability: 0.15,
        reorder_probability: 0.15,
        reorder_max_depth: 5,
        corrupt_probability: 0.10,
        corrupt_bit_count: 2,
        max_faults: 5000,
    }
}

/// A single fault event in the log.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FaultEvent {
    pub fault_id: u64,
    pub fault_class: String,
    pub message_id: u64,
    pub details: serde_json::Value,
}

/// A scheduled fault action for a specific message index.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScheduledFault {
    pub message_index: usize,
    pub fault: FaultClass,
}

/// Deterministic fault schedule derived from a seed.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FaultSchedule {
    pub seed: u64,
    pub faults: Vec<ScheduledFault>,
    pub total_messages: usize,
}

impl FaultSchedule {
    /// Create a deterministic schedule from seed and config, rejecting inputs
    /// that would exceed bounded campaign capacities.
    pub fn try_from_seed(
        seed: u64,
        config: &FaultConfig,
        total_messages: usize,
    ) -> Result<Self, String> {
        config.validate()?;
        validate_total_messages(total_messages)?;

        let mut faults = Vec::with_capacity(config.max_faults.min(total_messages));
        let mut rng_state = if seed == 0 { 1 } else { seed };
        let mut fault_count = 0;

        for msg_idx in 0..total_messages {
            if fault_count >= config.max_faults {
                break;
            }

            // Simple deterministic PRNG (xorshift64)
            rng_state ^= rng_state << 13;
            rng_state ^= rng_state >> 7;
            rng_state ^= rng_state << 17;

            let random_value = rng_state % 10000;
            let roll = f64::from(u16::try_from(random_value).unwrap_or(0)) / 10000.0;
            if !roll.is_finite() {
                continue; // Skip this iteration if conversion produced non-finite value
            }

            if roll < config.drop_probability {
                push_bounded(
                    &mut faults,
                    ScheduledFault {
                        message_index: msg_idx,
                        fault: FaultClass::Drop,
                    },
                    MAX_SCHEDULED_FAULTS,
                );
                fault_count = fault_count.saturating_add(1);
            } else if roll < config.drop_probability + config.reorder_probability {
                let max_depth = u64::try_from(config.reorder_max_depth.max(1)).unwrap_or(u64::MAX);
                let depth = usize::try_from((rng_state % max_depth).saturating_add(1))
                    .unwrap_or(usize::MAX);
                push_bounded(
                    &mut faults,
                    ScheduledFault {
                        message_index: msg_idx,
                        fault: FaultClass::Reorder { depth },
                    },
                    MAX_SCHEDULED_FAULTS,
                );
                fault_count = fault_count.saturating_add(1);
            } else if roll
                < config.drop_probability + config.reorder_probability + config.corrupt_probability
            {
                let corrupt_bit_count = config.corrupt_bit_count.min(MAX_CORRUPT_BITS);
                let mut bits = Vec::with_capacity(corrupt_bit_count);
                for i in 0..corrupt_bit_count {
                    rng_state ^= rng_state << 13;
                    rng_state ^= rng_state >> 7;
                    rng_state ^= rng_state << 17;
                    bits.push(
                        usize::try_from(rng_state % 256)
                            .unwrap_or(usize::MAX)
                            .saturating_add(i),
                    );
                }
                push_bounded(
                    &mut faults,
                    ScheduledFault {
                        message_index: msg_idx,
                        fault: FaultClass::Corrupt {
                            bit_positions: bits,
                        },
                    },
                    MAX_SCHEDULED_FAULTS,
                );
                fault_count = fault_count.saturating_add(1);
            }
        }

        Ok(FaultSchedule {
            seed,
            faults,
            total_messages,
        })
    }

    /// Create a deterministic schedule from seed and config.
    pub fn from_seed(seed: u64, config: &FaultConfig, total_messages: usize) -> Self {
        Self::try_from_seed(seed, config, total_messages).unwrap_or_else(|_| FaultSchedule {
            seed,
            faults: Vec::new(),
            total_messages,
        })
    }

    fn fault_at(&self, msg_idx: usize) -> Option<&ScheduledFault> {
        self.faults
            .iter()
            .find(|fault| fault.message_index == msg_idx)
    }
}

fn campaign_content_hash(schedule_json: &str, delivered_json: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"virtual_transport_faults_content_v1:");
    hasher.update(
        u64::try_from(schedule_json.len())
            .unwrap_or(u64::MAX)
            .to_le_bytes(),
    );
    hasher.update(schedule_json.as_bytes());
    hasher.update(
        u64::try_from(delivered_json.len())
            .unwrap_or(u64::MAX)
            .to_le_bytes(),
    );
    hasher.update(delivered_json.as_bytes());
    hex::encode(hasher.finalize())
}

fn rejected_campaign_content_hash(
    scenario_name: &str,
    seed: u64,
    total_messages: usize,
    reason: &str,
) -> String {
    let schedule_json = serde_json::json!({
        "scenario": scenario_name,
        "seed": seed,
        "total_messages": total_messages,
        "rejected": true,
        "reason": reason,
    })
    .to_string();
    campaign_content_hash(&schedule_json, "[]")
}

impl CampaignResult {
    fn rejected(scenario_name: &str, seed: u64, total_messages: usize, reason: &str) -> Self {
        Self {
            scenario_name: scenario_name.to_string(),
            seed,
            total_messages,
            total_faults: 0,
            drops: 0,
            reorders: 0,
            corruptions: 0,
            content_hash: rejected_campaign_content_hash(
                scenario_name,
                seed,
                total_messages,
                reason,
            ),
        }
    }
}

/// Campaign results.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CampaignResult {
    pub scenario_name: String,
    pub seed: u64,
    pub total_messages: usize,
    pub total_faults: usize,
    pub drops: usize,
    pub reorders: usize,
    pub corruptions: usize,
    pub content_hash: String,
}

/// Audit record for harness operations.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VtfAuditRecord {
    pub event_code: String,
    pub trace_id: String,
    pub detail: serde_json::Value,
}

/// The virtual transport fault harness.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VirtualTransportFaultHarness {
    seed: u64,
    fault_log: Vec<FaultEvent>,
    #[serde(skip, default = "default_max_fault_log_entries")]
    max_fault_log_entries: usize,
    reorder_buffer: VecDeque<(u64, Vec<u8>)>,
    next_fault_id: u64,
    audit_log: Vec<VtfAuditRecord>,
    #[serde(skip, default = "default_max_audit_log_entries")]
    max_audit_log_entries: usize,
}

fn campaign_message_payload(message_id: u64) -> Vec<u8> {
    format!("vtf-msg-{message_id}").into_bytes()
}

fn payload_hash(payload: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"virtual_transport_faults_payload_v1:");
    hasher.update(
        u64::try_from(payload.len())
            .unwrap_or(u64::MAX)
            .to_le_bytes(),
    );
    hasher.update(payload);
    hex::encode(hasher.finalize())
}

impl VirtualTransportFaultHarness {
    pub fn new(seed: u64) -> Self {
        Self::with_log_capacities(
            seed,
            DEFAULT_MAX_FAULT_LOG_ENTRIES,
            DEFAULT_MAX_AUDIT_LOG_ENTRIES,
        )
    }

    pub fn with_log_capacities(
        seed: u64,
        max_fault_log_entries: usize,
        max_audit_log_entries: usize,
    ) -> Self {
        Self {
            seed,
            fault_log: Vec::new(),
            max_fault_log_entries: max_fault_log_entries.max(1),
            reorder_buffer: VecDeque::new(),
            next_fault_id: 1,
            audit_log: Vec::new(),
            max_audit_log_entries: max_audit_log_entries.max(1),
        }
    }

    pub fn init(seed: u64, trace_id: &str) -> Self {
        let mut h = Self::new(seed);
        h.log_audit(
            event_codes::FAULT_HARNESS_INIT,
            trace_id,
            serde_json::json!({"seed": seed}),
        );
        h
    }

    fn log_audit(&mut self, event_code: &str, trace_id: &str, detail: serde_json::Value) {
        let cap = self.max_audit_log_entries;
        push_bounded(
            &mut self.audit_log,
            VtfAuditRecord {
                event_code: event_code.to_string(),
                trace_id: trace_id.to_string(),
                detail,
            },
            cap,
        );
    }

    fn record_fault(
        &mut self,
        fault_class: &str,
        message_id: u64,
        details: serde_json::Value,
    ) -> u64 {
        let id = self.next_fault_id;
        self.next_fault_id = self.next_fault_id.saturating_add(1);
        let cap = self.max_fault_log_entries;
        push_bounded(
            &mut self.fault_log,
            FaultEvent {
                fault_id: id,
                fault_class: fault_class.to_string(),
                message_id,
                details,
            },
            cap,
        );
        id
    }

    /// Apply a drop fault: message is silently discarded.
    pub fn apply_drop(
        &mut self,
        message_id: u64,
        _payload: &[u8],
        trace_id: &str,
    ) -> Option<Vec<u8>> {
        self.record_fault(
            "Drop",
            message_id,
            serde_json::json!({"action": "discarded"}),
        );
        self.log_audit(
            event_codes::FAULT_DROP_APPLIED,
            trace_id,
            serde_json::json!({"message_id": message_id}),
        );
        None // Message dropped
    }

    /// Apply a reorder fault: message is delayed by `depth` slots.
    pub fn apply_reorder(
        &mut self,
        message_id: u64,
        payload: &[u8],
        depth: usize,
        trace_id: &str,
    ) -> Option<Vec<u8>> {
        self.record_fault("Reorder", message_id, serde_json::json!({"depth": depth}));
        self.log_audit(
            event_codes::FAULT_REORDER_APPLIED,
            trace_id,
            serde_json::json!({"message_id": message_id, "depth": depth}),
        );
        self.reorder_buffer
            .push_back((message_id, payload.to_vec()));
        // Return a previously buffered message if buffer exceeds depth
        if self.reorder_buffer.len() > depth {
            self.reorder_buffer.pop_front().map(|(_, p)| p)
        } else {
            None
        }
    }

    /// Apply a corrupt fault: flip specified bits in the payload.
    pub fn apply_corrupt(
        &mut self,
        message_id: u64,
        payload: &[u8],
        bit_positions: &[usize],
        trace_id: &str,
    ) -> Vec<u8> {
        let mut corrupted = payload.to_vec();
        for &bit_pos in bit_positions {
            let byte_idx = bit_pos / 8;
            let bit_idx = bit_pos % 8;
            if byte_idx < corrupted.len() {
                corrupted[byte_idx] ^= 1 << bit_idx;
            }
        }
        self.record_fault(
            "Corrupt",
            message_id,
            serde_json::json!({"bits_flipped": bit_positions}),
        );
        self.log_audit(
            event_codes::FAULT_CORRUPT_APPLIED,
            trace_id,
            serde_json::json!({"message_id": message_id, "bits": bit_positions.len()}),
        );
        corrupted
    }

    /// Process a message through a fault schedule.
    pub fn process_message(
        &mut self,
        schedule: &FaultSchedule,
        msg_idx: usize,
        message_id: u64,
        payload: &[u8],
        trace_id: &str,
    ) -> Option<Vec<u8>> {
        match schedule.fault_at(msg_idx) {
            Some(sf) => match &sf.fault {
                FaultClass::Drop => self.apply_drop(message_id, payload, trace_id),
                FaultClass::Reorder { depth } => {
                    self.apply_reorder(message_id, payload, *depth, trace_id)
                }
                FaultClass::Corrupt { bit_positions } => {
                    Some(self.apply_corrupt(message_id, payload, bit_positions, trace_id))
                }
            },
            None => {
                self.log_audit(
                    event_codes::FAULT_NONE,
                    trace_id,
                    serde_json::json!({"message_id": message_id}),
                );
                Some(payload.to_vec())
            }
        }
    }

    /// Run a full campaign with a scenario.
    pub fn run_campaign(
        &mut self,
        scenario_name: &str,
        config: &FaultConfig,
        total_messages: usize,
        trace_id: &str,
    ) -> CampaignResult {
        self.log_audit(
            event_codes::FAULT_SCENARIO_START,
            trace_id,
            serde_json::json!({"scenario": scenario_name, "messages": total_messages}),
        );

        let schedule = match FaultSchedule::try_from_seed(self.seed, config, total_messages) {
            Ok(schedule) => schedule,
            Err(reason) => {
                self.log_audit(
                    event_codes::FAULT_SCENARIO_END,
                    trace_id,
                    serde_json::json!({
                        "scenario": scenario_name,
                        "total_faults": 0,
                        "total_messages": total_messages,
                        "delivered_messages": 0,
                        "rejected": true,
                        "reason": reason,
                    }),
                );
                return CampaignResult::rejected(scenario_name, self.seed, total_messages, &reason);
            }
        };
        self.log_audit(
            event_codes::FAULT_SCHEDULE_CREATED,
            trace_id,
            serde_json::json!({
                "scenario": scenario_name,
                "seed": self.seed,
                "faults": schedule.faults.len(),
            }),
        );

        let drops = schedule
            .faults
            .iter()
            .filter(|f| matches!(f.fault, FaultClass::Drop))
            .count();
        let reorders = schedule
            .faults
            .iter()
            .filter(|f| matches!(f.fault, FaultClass::Reorder { .. }))
            .count();
        let corruptions = schedule
            .faults
            .iter()
            .filter(|f| matches!(f.fault, FaultClass::Corrupt { .. }))
            .count();

        let mut delivered_payload_hashes = Vec::with_capacity(total_messages);
        for msg_idx in 0..total_messages {
            let message_id = u64::try_from(msg_idx).unwrap_or(u64::MAX).saturating_add(1);
            if let Some(scheduled_fault) = schedule.fault_at(msg_idx) {
                self.log_audit(
                    event_codes::FAULT_INJECTED,
                    trace_id,
                    serde_json::json!({
                        "scenario": scenario_name,
                        "message_id": message_id,
                        "fault": format!("{}", scheduled_fault.fault),
                    }),
                );
            }
            let payload = campaign_message_payload(message_id);
            if let Some(processed) =
                self.process_message(&schedule, msg_idx, message_id, &payload, trace_id)
            {
                push_bounded(
                    &mut delivered_payload_hashes,
                    payload_hash(&processed),
                    MAX_CAMPAIGN_MESSAGES,
                );
            }
        }
        for payload in self.flush_reorder_buffer() {
            push_bounded(
                &mut delivered_payload_hashes,
                payload_hash(&payload),
                MAX_CAMPAIGN_MESSAGES,
            );
        }

        let schedule_json =
            serde_json::to_string(&schedule.faults).unwrap_or_else(|e| format!("__serde_err:{e}"));
        let delivered_json = serde_json::to_string(&delivered_payload_hashes)
            .unwrap_or_else(|e| format!("__serde_err:{e}"));
        let content_hash = campaign_content_hash(&schedule_json, &delivered_json);

        self.log_audit(
            event_codes::FAULT_CAMPAIGN_COMPLETE,
            trace_id,
            serde_json::json!({
                "scenario": scenario_name,
                "total_faults": schedule.faults.len(),
                "total_messages": total_messages,
                "delivered_messages": delivered_payload_hashes.len(),
            }),
        );
        self.log_audit(
            event_codes::FAULT_SCENARIO_END,
            trace_id,
            serde_json::json!({
                "scenario": scenario_name,
                "total_faults": schedule.faults.len(),
                "total_messages": total_messages,
                "delivered_messages": delivered_payload_hashes.len(),
            }),
        );

        CampaignResult {
            scenario_name: scenario_name.to_string(),
            seed: self.seed,
            total_messages,
            total_faults: schedule.faults.len(),
            drops,
            reorders,
            corruptions,
            content_hash,
        }
    }

    /// Drain any remaining reorder-buffered messages.
    pub fn flush_reorder_buffer(&mut self) -> Vec<Vec<u8>> {
        self.reorder_buffer.drain(..).map(|(_, p)| p).collect()
    }

    /// Export fault log as JSONL.
    pub fn export_fault_log_jsonl(&self) -> String {
        self.fault_log
            .iter()
            .map(|r| serde_json::to_string(r).unwrap_or_default())
            .collect::<Vec<_>>()
            .join("\n")
    }

    /// Export audit log as JSONL.
    pub fn export_audit_log_jsonl(&self) -> String {
        self.audit_log
            .iter()
            .map(|r| serde_json::to_string(r).unwrap_or_default())
            .collect::<Vec<_>>()
            .join("\n")
    }

    /// Fault count so far.
    pub fn fault_count(&self) -> usize {
        self.fault_log.len()
    }

    pub fn fault_log(&self) -> &[FaultEvent] {
        &self.fault_log
    }

    pub fn audit_log(&self) -> &[VtfAuditRecord] {
        &self.audit_log
    }

    pub fn fault_log_capacity(&self) -> usize {
        self.max_fault_log_entries
    }

    pub fn audit_log_capacity(&self) -> usize {
        self.max_audit_log_entries
    }
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_schedule_determinism() {
        let config = chaos();
        let s1 = FaultSchedule::from_seed(42, &config, 100);
        let s2 = FaultSchedule::from_seed(42, &config, 100);
        assert_eq!(s1.faults.len(), s2.faults.len());
        for (a, b) in s1.faults.iter().zip(s2.faults.iter()) {
            assert_eq!(a.message_index, b.message_index);
            assert_eq!(a.fault, b.fault);
        }
    }

    #[test]
    fn test_different_seeds_different_schedules() {
        let config = chaos();
        let s1 = FaultSchedule::from_seed(42, &config, 100);
        let s2 = FaultSchedule::from_seed(99, &config, 100);
        // Very unlikely to be identical
        let same = s1
            .faults
            .iter()
            .zip(s2.faults.iter())
            .all(|(a, b)| a.message_index == b.message_index && a.fault == b.fault);
        assert!(!same || s1.faults.len() != s2.faults.len());
    }

    #[test]
    fn test_no_faults_scenario() {
        let config = no_faults();
        let schedule = FaultSchedule::from_seed(42, &config, 100);
        assert_eq!(schedule.faults.len(), 0);
    }

    #[test]
    fn test_config_rejects_cumulative_probability_above_one() {
        let invalid = FaultConfig {
            drop_probability: 0.6,
            reorder_probability: 0.3,
            reorder_max_depth: 1,
            corrupt_probability: 0.2,
            corrupt_bit_count: 1,
            max_faults: 10,
        };

        assert_eq!(
            invalid.validate(),
            Err("fault probabilities must sum to <= 1".to_string())
        );
    }

    #[test]
    fn test_fault_config_rejects_unbounded_fault_budget() {
        let invalid = FaultConfig {
            drop_probability: 1.0,
            reorder_probability: 0.0,
            reorder_max_depth: 0,
            corrupt_probability: 0.0,
            corrupt_bit_count: 0,
            max_faults: MAX_SCHEDULED_FAULTS.saturating_add(1),
        };

        let err = invalid
            .validate()
            .expect_err("fault budgets above the schedule cap must fail");

        assert!(err.contains("max_faults"));
    }

    #[test]
    fn test_fault_schedule_rejects_unbounded_message_count() {
        let err =
            FaultSchedule::try_from_seed(42, &chaos(), MAX_CAMPAIGN_MESSAGES.saturating_add(1))
                .expect_err("message counts above the campaign cap must fail");

        assert!(err.contains("total_messages"));
    }

    #[test]
    fn test_drop_returns_none() {
        let mut harness = VirtualTransportFaultHarness::new(1);
        let result = harness.apply_drop(1, b"hello", "t1");
        assert!(result.is_none());
        assert_eq!(harness.fault_count(), 1);
    }

    #[test]
    fn test_corrupt_flips_bits() {
        let mut harness = VirtualTransportFaultHarness::new(1);
        let payload = vec![0u8; 8];
        let corrupted = harness.apply_corrupt(1, &payload, &[0], "t1");
        assert_ne!(corrupted, payload);
        assert_eq!(corrupted[0], 1); // bit 0 flipped
    }

    #[test]
    fn test_corrupt_exact_bits() {
        let mut harness = VirtualTransportFaultHarness::new(1);
        let payload = vec![0xFF, 0x00];
        let corrupted = harness.apply_corrupt(1, &payload, &[0, 8], "t1");
        assert_eq!(corrupted[0], 0xFE); // bit 0 flipped: 0xFF -> 0xFE
        assert_eq!(corrupted[1], 0x01); // bit 8 (byte 1, bit 0) flipped: 0x00 -> 0x01
    }

    #[test]
    fn test_reorder_delays_delivery() {
        let mut harness = VirtualTransportFaultHarness::new(1);
        // First message goes into buffer, nothing returned yet
        let r1 = harness.apply_reorder(1, b"msg1", 2, "t1");
        assert!(r1.is_none()); // buffered, depth=2, only 1 in buffer

        let r2 = harness.apply_reorder(2, b"msg2", 2, "t1");
        assert!(r2.is_none()); // buffered, depth=2, 2 in buffer

        // Third exceeds depth=2, so first is returned
        let r3 = harness.apply_reorder(3, b"msg3", 2, "t1");
        assert_eq!(r3, Some(b"msg1".to_vec()));
    }

    #[test]
    fn test_flush_reorder_buffer() {
        let mut harness = VirtualTransportFaultHarness::new(1);
        harness.apply_reorder(1, b"a", 5, "t1");
        harness.apply_reorder(2, b"b", 5, "t1");
        let flushed = harness.flush_reorder_buffer();
        assert_eq!(flushed.len(), 2);
    }

    #[test]
    fn test_process_message_no_fault() {
        let mut harness = VirtualTransportFaultHarness::new(1);
        let schedule = FaultSchedule {
            seed: 1,
            faults: vec![],
            total_messages: 1,
        };
        let result = harness.process_message(&schedule, 0, 1, b"data", "t1");
        assert_eq!(result, Some(b"data".to_vec()));
    }

    #[test]
    fn test_process_message_with_drop() {
        let mut harness = VirtualTransportFaultHarness::new(1);
        let schedule = FaultSchedule {
            seed: 1,
            faults: vec![ScheduledFault {
                message_index: 0,
                fault: FaultClass::Drop,
            }],
            total_messages: 1,
        };
        let result = harness.process_message(&schedule, 0, 1, b"data", "t1");
        assert!(result.is_none());
    }

    #[test]
    fn test_process_message_applies_unsorted_manual_schedule() {
        let mut harness = VirtualTransportFaultHarness::new(1);
        let schedule = FaultSchedule {
            seed: 1,
            faults: vec![
                ScheduledFault {
                    message_index: 2,
                    fault: FaultClass::Drop,
                },
                ScheduledFault {
                    message_index: 0,
                    fault: FaultClass::Corrupt {
                        bit_positions: vec![0],
                    },
                },
            ],
            total_messages: 3,
        };

        let result = harness.process_message(&schedule, 0, 1, &[0], "t-unsorted");

        assert_eq!(result, Some(vec![1]));
        assert_eq!(harness.fault_count(), 1);
        assert_eq!(harness.fault_log()[0].fault_class, "Corrupt");
    }

    #[test]
    fn test_campaign_moderate_drops() {
        let mut harness = VirtualTransportFaultHarness::new(42);
        let config = moderate_drops();
        let result = harness.run_campaign("moderate_drops", &config, 1000, "t1");
        assert_eq!(result.scenario_name, "moderate_drops");
        assert!(result.drops > 0 || result.total_faults == 0);
        assert_eq!(result.reorders, 0);
        assert_eq!(result.corruptions, 0);
    }

    #[test]
    fn test_campaign_chaos() {
        let mut harness = VirtualTransportFaultHarness::new(42);
        let config = chaos();
        let result = harness.run_campaign("chaos", &config, 1000, "t1");
        assert!(result.total_faults > 0);
        assert!(!result.content_hash.is_empty());
    }

    #[test]
    fn test_campaign_deterministic_hash() {
        let mut h1 = VirtualTransportFaultHarness::new(42);
        let mut h2 = VirtualTransportFaultHarness::new(42);
        let config = chaos();
        let r1 = h1.run_campaign("chaos", &config, 100, "t1");
        let r2 = h2.run_campaign("chaos", &config, 100, "t1");
        assert_eq!(r1.content_hash, r2.content_hash);
        assert_eq!(r1.total_faults, r2.total_faults);
    }

    #[test]
    fn test_payload_hash_uses_domain_and_length_prefix() {
        let payload = b"data";
        let mut expected = Sha256::new();
        expected.update(b"virtual_transport_faults_payload_v1:");
        expected.update(
            u64::try_from(payload.len())
                .unwrap_or(u64::MAX)
                .to_le_bytes(),
        );
        expected.update(payload);

        let legacy_unframed = hex::encode(Sha256::digest(
            [b"virtual_transport_faults_payload_v1:" as &[u8], payload].concat(),
        ));

        assert_eq!(payload_hash(payload), hex::encode(expected.finalize()));
        assert_ne!(payload_hash(payload), legacy_unframed);
    }

    #[test]
    fn test_campaign_executes_schedule_and_populates_fault_log() {
        let mut harness = VirtualTransportFaultHarness::new(42);
        let config = chaos();
        let result = harness.run_campaign("chaos", &config, 100, "t1");
        assert_eq!(harness.fault_count(), result.total_faults);
        assert!(
            harness
                .audit_log()
                .iter()
                .any(|entry| entry.event_code == event_codes::FAULT_SCHEDULE_CREATED)
        );
        assert!(
            harness
                .audit_log()
                .iter()
                .any(|entry| entry.event_code == event_codes::FAULT_INJECTED)
        );
        assert!(
            harness
                .audit_log()
                .iter()
                .any(|entry| entry.event_code == event_codes::FAULT_SCENARIO_END)
        );
    }

    #[test]
    fn test_campaign_flushes_reorder_buffer() {
        let mut harness = VirtualTransportFaultHarness::new(42);
        let result = harness.run_campaign("reorder", &heavy_reorder(), 100, "t1");
        assert!(result.reorders > 0);
        assert!(harness.reorder_buffer.is_empty());
    }

    #[test]
    fn test_fault_config_validation() {
        assert!(no_faults().validate().is_ok());
        assert!(chaos().validate().is_ok());
        let bad = FaultConfig {
            drop_probability: -1.0,
            reorder_probability: 0.0,
            reorder_max_depth: 0,
            corrupt_probability: 0.0,
            corrupt_bit_count: 0,
            max_faults: 100,
        };
        assert!(bad.validate().is_err());
    }

    #[test]
    fn test_fault_config_rejects_drop_probability_above_one() {
        let bad = FaultConfig {
            drop_probability: 1.01,
            reorder_probability: 0.0,
            reorder_max_depth: 0,
            corrupt_probability: 0.0,
            corrupt_bit_count: 0,
            max_faults: 1,
        };

        let err = bad.validate().expect_err("drop probability > 1 must fail");
        assert!(err.contains("drop_probability"));
    }

    #[test]
    fn test_fault_config_rejects_reorder_probability_below_zero() {
        let bad = FaultConfig {
            drop_probability: 0.0,
            reorder_probability: -0.01,
            reorder_max_depth: 1,
            corrupt_probability: 0.0,
            corrupt_bit_count: 0,
            max_faults: 1,
        };

        let err = bad
            .validate()
            .expect_err("negative reorder probability must fail");
        assert!(err.contains("reorder_probability"));
    }

    #[test]
    fn test_fault_config_rejects_corrupt_probability_infinity() {
        let bad = FaultConfig {
            drop_probability: 0.0,
            reorder_probability: 0.0,
            reorder_max_depth: 0,
            corrupt_probability: f64::INFINITY,
            corrupt_bit_count: 1,
            max_faults: 1,
        };

        let err = bad
            .validate()
            .expect_err("infinite corruption probability must fail");
        assert!(err.contains("corrupt_probability"));
    }

    #[test]
    fn test_fault_config_rejects_corrupt_probability_nan() {
        let bad = FaultConfig {
            drop_probability: 0.0,
            reorder_probability: 0.0,
            reorder_max_depth: 0,
            corrupt_probability: f64::NAN,
            corrupt_bit_count: 1,
            max_faults: 1,
        };

        let err = bad
            .validate()
            .expect_err("NaN corruption probability must fail");
        assert!(err.contains("corrupt_probability"));
        let schedule = FaultSchedule::from_seed(42, &bad, 10);
        assert!(schedule.faults.is_empty());
    }

    #[test]
    fn test_fault_config_zero_budget() {
        let bad = FaultConfig {
            drop_probability: 0.5,
            reorder_probability: 0.0,
            reorder_max_depth: 0,
            corrupt_probability: 0.0,
            corrupt_bit_count: 0,
            max_faults: 0,
        };
        assert!(bad.validate().is_err());
    }

    #[test]
    fn test_fault_config_rejects_nan_probability() {
        let bad = FaultConfig {
            drop_probability: f64::NAN,
            reorder_probability: 0.0,
            reorder_max_depth: 0,
            corrupt_probability: 0.0,
            corrupt_bit_count: 0,
            max_faults: 1,
        };
        assert!(bad.validate().is_err());
    }

    #[test]
    fn test_fault_config_rejects_reorder_without_depth() {
        let bad = FaultConfig {
            drop_probability: 0.0,
            reorder_probability: 0.5,
            reorder_max_depth: 0,
            corrupt_probability: 0.0,
            corrupt_bit_count: 0,
            max_faults: 1,
        };
        assert!(bad.validate().is_err());
    }

    #[test]
    fn test_fault_config_rejects_corruption_without_bits() {
        let bad = FaultConfig {
            drop_probability: 0.0,
            reorder_probability: 0.0,
            reorder_max_depth: 0,
            corrupt_probability: 0.5,
            corrupt_bit_count: 0,
            max_faults: 1,
        };
        assert!(bad.validate().is_err());
    }

    #[test]
    fn test_fault_config_rejects_corrupt_bit_count_zero_when_enabled() {
        let bad = FaultConfig {
            drop_probability: 0.0,
            reorder_probability: 0.0,
            reorder_max_depth: 0,
            corrupt_probability: 0.5,
            corrupt_bit_count: 0,
            max_faults: 1,
        };

        let err = bad
            .validate()
            .expect_err("zero corrupt bit count must fail when corruption is enabled");
        assert!(err.contains("corrupt_bit_count"));
        let schedule = FaultSchedule::from_seed(42, &bad, 10);
        assert!(schedule.faults.is_empty());
    }

    #[test]
    fn test_fault_config_rejects_corrupt_bit_count_above_cap() {
        let bad = FaultConfig {
            drop_probability: 0.0,
            reorder_probability: 0.0,
            reorder_max_depth: 0,
            corrupt_probability: 0.5,
            corrupt_bit_count: MAX_CORRUPT_BITS.saturating_add(1),
            max_faults: 1,
        };

        let err = bad
            .validate()
            .expect_err("corrupt bit count above cap must fail");
        assert!(err.contains("corrupt_bit_count"));
        let schedule = FaultSchedule::from_seed(42, &bad, 10);
        assert!(schedule.faults.is_empty());
    }

    #[test]
    fn test_fault_config_accepts_corrupt_bit_count_just_below_cap() {
        let good = FaultConfig {
            drop_probability: 0.0,
            reorder_probability: 0.0,
            reorder_max_depth: 0,
            corrupt_probability: 1.0,
            corrupt_bit_count: MAX_CORRUPT_BITS.saturating_sub(1),
            max_faults: 1,
        };

        assert!(good.validate().is_ok());
        let schedule = FaultSchedule::from_seed(42, &good, 1);
        assert_eq!(schedule.faults.len(), 1);
        match &schedule.faults[0].fault {
            FaultClass::Corrupt { bit_positions } => {
                assert_eq!(bit_positions.len(), MAX_CORRUPT_BITS.saturating_sub(1));
            }
            other => panic!("expected corrupt fault, got {other:?}"),
        }
    }

    #[test]
    fn test_schedule_with_zero_fault_budget_injects_no_faults() {
        let config = FaultConfig {
            drop_probability: 1.0,
            reorder_probability: 0.0,
            reorder_max_depth: 0,
            corrupt_probability: 0.0,
            corrupt_bit_count: 0,
            max_faults: 0,
        };

        let schedule = FaultSchedule::from_seed(42, &config, 10);

        assert!(schedule.faults.is_empty());
    }

    #[test]
    fn test_corrupt_ignores_out_of_range_bit_positions() {
        let mut harness = VirtualTransportFaultHarness::new(1);
        let payload = vec![0b1010_1010];

        let corrupted = harness.apply_corrupt(1, &payload, &[8, 31, 1024], "t1");

        assert_eq!(corrupted, payload);
        assert_eq!(harness.fault_count(), 1);
        assert_eq!(
            harness.audit_log()[0].event_code,
            event_codes::FAULT_CORRUPT_APPLIED
        );
    }

    #[test]
    fn test_process_message_ignores_fault_for_different_message_index() {
        let mut harness = VirtualTransportFaultHarness::new(1);
        let schedule = FaultSchedule {
            seed: 1,
            faults: vec![ScheduledFault {
                message_index: 3,
                fault: FaultClass::Drop,
            }],
            total_messages: 4,
        };

        let result = harness.process_message(&schedule, 0, 1, b"data", "t1");

        assert_eq!(result, Some(b"data".to_vec()));
        assert_eq!(harness.fault_count(), 0);
        assert_eq!(harness.audit_log()[0].event_code, event_codes::FAULT_NONE);
    }

    #[test]
    fn test_process_message_with_empty_corrupt_bits_keeps_payload_but_logs_fault() {
        let mut harness = VirtualTransportFaultHarness::new(1);
        let schedule = FaultSchedule {
            seed: 1,
            faults: vec![ScheduledFault {
                message_index: 0,
                fault: FaultClass::Corrupt {
                    bit_positions: Vec::new(),
                },
            }],
            total_messages: 1,
        };

        let result = harness.process_message(&schedule, 0, 1, b"data", "t1");

        assert_eq!(result, Some(b"data".to_vec()));
        assert_eq!(harness.fault_count(), 1);
        assert_eq!(harness.fault_log()[0].fault_class, "Corrupt");
    }

    #[test]
    fn test_push_bounded_zero_capacity_clears_without_panic() {
        let mut items = vec![1, 2, 3];

        push_bounded(&mut items, 4, 0);
        push_bounded(&mut items, 5, 0);

        assert!(items.is_empty());
    }

    #[test]
    fn test_fault_config_rejects_drop_probability_negative_infinity() {
        let bad = FaultConfig {
            drop_probability: f64::NEG_INFINITY,
            reorder_probability: 0.0,
            reorder_max_depth: 0,
            corrupt_probability: 0.0,
            corrupt_bit_count: 0,
            max_faults: 1,
        };

        let err = bad
            .validate()
            .expect_err("negative infinite drop probability must fail");
        assert!(err.contains("drop_probability"));
    }

    #[test]
    fn test_fault_config_rejects_reorder_probability_nan() {
        let bad = FaultConfig {
            drop_probability: 0.0,
            reorder_probability: f64::NAN,
            reorder_max_depth: 1,
            corrupt_probability: 0.0,
            corrupt_bit_count: 0,
            max_faults: 1,
        };

        let err = bad
            .validate()
            .expect_err("NaN reorder probability must fail");
        assert!(err.contains("reorder_probability"));
    }

    #[test]
    fn test_fault_config_rejects_corrupt_probability_below_zero() {
        let bad = FaultConfig {
            drop_probability: 0.0,
            reorder_probability: 0.0,
            reorder_max_depth: 0,
            corrupt_probability: -0.01,
            corrupt_bit_count: 1,
            max_faults: 1,
        };

        let err = bad
            .validate()
            .expect_err("negative corruption probability must fail");
        assert!(err.contains("corrupt_probability"));
    }

    #[test]
    fn test_reorder_depth_zero_returns_current_payload_and_drains_buffer() {
        let mut harness = VirtualTransportFaultHarness::new(1);

        let result = harness.apply_reorder(1, b"now", 0, "t1");

        assert_eq!(result, Some(b"now".to_vec()));
        assert!(harness.reorder_buffer.is_empty());
        assert_eq!(harness.fault_count(), 1);
        assert_eq!(
            harness.audit_log()[0].event_code,
            event_codes::FAULT_REORDER_APPLIED
        );
    }

    #[test]
    fn test_corrupt_empty_payload_with_bit_positions_logs_noop_fault() {
        let mut harness = VirtualTransportFaultHarness::new(1);

        let corrupted = harness.apply_corrupt(1, &[], &[0, 7], "t1");

        assert!(corrupted.is_empty());
        assert_eq!(harness.fault_count(), 1);
        assert_eq!(harness.fault_log()[0].fault_class, "Corrupt");
        assert_eq!(
            harness.audit_log()[0].event_code,
            event_codes::FAULT_CORRUPT_APPLIED
        );
    }

    #[test]
    fn test_flush_empty_reorder_buffer_returns_empty_vec() {
        let mut harness = VirtualTransportFaultHarness::new(1);

        let flushed = harness.flush_reorder_buffer();

        assert!(flushed.is_empty());
        assert_eq!(harness.fault_count(), 0);
        assert!(harness.audit_log().is_empty());
    }

    #[test]
    fn test_zero_message_campaign_records_no_faults() {
        let mut harness = VirtualTransportFaultHarness::new(42);

        let result = harness.run_campaign("empty", &chaos(), 0, "t1");

        assert_eq!(result.total_messages, 0);
        assert_eq!(result.total_faults, 0);
        assert_eq!(result.drops, 0);
        assert_eq!(result.reorders, 0);
        assert_eq!(result.corruptions, 0);
        assert_eq!(harness.fault_count(), 0);
        assert!(!result.content_hash.is_empty());
        assert!(
            harness
                .audit_log()
                .iter()
                .any(|record| record.event_code == event_codes::FAULT_SCENARIO_END)
        );
    }

    #[test]
    fn test_oversized_campaign_rejects_without_processing_messages() {
        let mut harness = VirtualTransportFaultHarness::new(42);

        let result = harness.run_campaign(
            "oversized",
            &chaos(),
            MAX_CAMPAIGN_MESSAGES.saturating_add(1),
            "t1",
        );

        assert_eq!(
            result.total_messages,
            MAX_CAMPAIGN_MESSAGES.saturating_add(1)
        );
        assert_eq!(result.total_faults, 0);
        assert_eq!(result.drops, 0);
        assert_eq!(result.reorders, 0);
        assert_eq!(result.corruptions, 0);
        assert_eq!(harness.fault_count(), 0);
        assert!(!result.content_hash.is_empty());
        assert!(harness.audit_log().iter().any(|record| {
            record
                .detail
                .get("rejected")
                .and_then(serde_json::Value::as_bool)
                == Some(true)
        }));
    }

    #[test]
    fn test_log_capacities_clamp_to_one() {
        let harness = VirtualTransportFaultHarness::with_log_capacities(1, 0, 0);
        assert_eq!(harness.fault_log_capacity(), 1);
        assert_eq!(harness.audit_log_capacity(), 1);
    }

    #[test]
    fn test_fault_log_export_jsonl() {
        let mut harness = VirtualTransportFaultHarness::new(1);
        harness.apply_drop(1, b"a", "t1");
        let jsonl = harness.export_fault_log_jsonl();
        assert!(!jsonl.is_empty());
        let parsed: serde_json::Value =
            serde_json::from_str(jsonl.lines().next().unwrap()).unwrap();
        assert_eq!(parsed["fault_class"], "Drop");
    }

    #[test]
    fn test_audit_log_export() {
        let harness = VirtualTransportFaultHarness::init(42, "t1");
        let jsonl = harness.export_audit_log_jsonl();
        assert!(!jsonl.is_empty());
    }

    #[test]
    fn test_fault_log_capacity_enforces_oldest_first_eviction() {
        let mut harness = VirtualTransportFaultHarness::with_log_capacities(1, 2, 4);
        harness.apply_drop(1, b"a", "t1");
        harness.apply_drop(2, b"b", "t1");
        harness.apply_drop(3, b"c", "t1");

        assert_eq!(harness.fault_log().len(), 2);
        assert_eq!(harness.fault_log()[0].fault_id, 2);
        assert_eq!(harness.fault_log()[1].fault_id, 3);
        assert_eq!(harness.fault_log()[0].message_id, 2);
        assert_eq!(harness.fault_log()[1].message_id, 3);
    }

    #[test]
    fn test_audit_log_capacity_enforces_oldest_first_eviction() {
        let mut harness = VirtualTransportFaultHarness::with_log_capacities(1, 4, 2);
        harness.apply_drop(1, b"a", "t1");
        harness.apply_reorder(2, b"b", 1, "t1");
        harness.apply_corrupt(3, b"c", &[0], "t1");

        assert_eq!(harness.audit_log().len(), 2);
        assert_eq!(
            harness.audit_log()[0].event_code,
            event_codes::FAULT_REORDER_APPLIED
        );
        assert_eq!(
            harness.audit_log()[1].event_code,
            event_codes::FAULT_CORRUPT_APPLIED
        );
    }

    #[test]
    fn test_fault_class_display() {
        assert_eq!(format!("{}", FaultClass::Drop), "Drop");
        assert!(format!("{}", FaultClass::Reorder { depth: 3 }).contains("3"));
    }

    #[test]
    fn test_prebuilt_scenarios_exist() {
        let _ = no_faults();
        let _ = moderate_drops();
        let _ = heavy_reorder();
        let _ = light_corruption();
        let _ = chaos();
    }
}
