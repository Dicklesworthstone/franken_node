//! bd-2qqu: Virtual transport fault harness for remote-control protocol testing.
//!
//! Injects deterministic fault schedules (drop, reorder, corrupt) into a
//! transport layer for systematic protocol testing.

use std::collections::VecDeque;
use std::fmt;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

// ── Constants ────────────────────────────────────────────────────────────────

pub const SCHEMA_VERSION: &str = "vtf-v1.0";

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
        if self.drop_probability < 0.0 || self.drop_probability > 1.0 {
            return Err("drop_probability must be in [0, 1]".to_string());
        }
        if self.reorder_probability < 0.0 || self.reorder_probability > 1.0 {
            return Err("reorder_probability must be in [0, 1]".to_string());
        }
        if self.corrupt_probability < 0.0 || self.corrupt_probability > 1.0 {
            return Err("corrupt_probability must be in [0, 1]".to_string());
        }
        if self.max_faults == 0 {
            return Err("max_faults must be > 0".to_string());
        }
        Ok(())
    }
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
    /// Create a deterministic schedule from seed and config.
    pub fn from_seed(seed: u64, config: &FaultConfig, total_messages: usize) -> Self {
        let mut faults = Vec::new();
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

            let roll = (rng_state % 10000) as f64 / 10000.0;

            if roll < config.drop_probability {
                faults.push(ScheduledFault {
                    message_index: msg_idx,
                    fault: FaultClass::Drop,
                });
                fault_count += 1;
            } else if roll < config.drop_probability + config.reorder_probability {
                let depth = ((rng_state % config.reorder_max_depth.max(1) as u64) + 1) as usize;
                faults.push(ScheduledFault {
                    message_index: msg_idx,
                    fault: FaultClass::Reorder { depth },
                });
                fault_count += 1;
            } else if roll
                < config.drop_probability + config.reorder_probability + config.corrupt_probability
            {
                let mut bits = Vec::new();
                for i in 0..config.corrupt_bit_count {
                    rng_state ^= rng_state << 13;
                    rng_state ^= rng_state >> 7;
                    rng_state ^= rng_state << 17;
                    bits.push((rng_state % 256) as usize + i);
                }
                faults.push(ScheduledFault {
                    message_index: msg_idx,
                    fault: FaultClass::Corrupt {
                        bit_positions: bits,
                    },
                });
                fault_count += 1;
            }
        }

        FaultSchedule {
            seed,
            faults,
            total_messages,
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
    reorder_buffer: VecDeque<(u64, Vec<u8>)>,
    next_fault_id: u64,
    audit_log: Vec<VtfAuditRecord>,
}

impl VirtualTransportFaultHarness {
    pub fn new(seed: u64) -> Self {
        Self {
            seed,
            fault_log: Vec::new(),
            reorder_buffer: VecDeque::new(),
            next_fault_id: 1,
            audit_log: Vec::new(),
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
        self.audit_log.push(VtfAuditRecord {
            event_code: event_code.to_string(),
            trace_id: trace_id.to_string(),
            detail,
        });
    }

    fn record_fault(
        &mut self,
        fault_class: &str,
        message_id: u64,
        details: serde_json::Value,
    ) -> u64 {
        let id = self.next_fault_id;
        self.next_fault_id += 1;
        self.fault_log.push(FaultEvent {
            fault_id: id,
            fault_class: fault_class.to_string(),
            message_id,
            details,
        });
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
        let fault = schedule.faults.iter().find(|f| f.message_index == msg_idx);
        match fault {
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

        let schedule = FaultSchedule::from_seed(self.seed, config, total_messages);

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

        let hash_input = serde_json::to_string(&schedule.faults).unwrap_or_default();
        let content_hash = format!(
            "{:x}",
            Sha256::digest(
                [
                    b"virtual_transport_faults_content_v1:" as &[u8],
                    hash_input.as_bytes()
                ]
                .concat()
            )
        );

        self.log_audit(
            event_codes::FAULT_CAMPAIGN_COMPLETE,
            trace_id,
            serde_json::json!({
                "scenario": scenario_name,
                "total_faults": schedule.faults.len(),
                "total_messages": total_messages,
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
