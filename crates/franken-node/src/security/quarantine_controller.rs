//! bd-274s: Automated quarantine controller with policy thresholds.
//!
//! The quarantine controller wraps the Bayesian adversary graph and adds:
//!
//! 1. A signed evidence log where every entry carries an HMAC-SHA256
//!    signature over its canonical JSON.
//! 2. Policy-driven control actions: throttle (>= 0.3), isolate (>= 0.5),
//!    revoke (>= 0.7), quarantine (>= 0.9).
//! 3. Deterministic replay: given the same signing key and evidence
//!    sequence, the evidence log and all node posteriors are bit-identical.
//!
//! # Event Codes
//!
//! - ADV-005: Quarantine action triggered.
//! - ADV-006: Node removed from adversary graph (post-quarantine cleanup).
//! - ADV-008: Signed evidence entry appended to log.
//!
//! # Invariants
//!
//! - **INV-QC-SIGNED-LOG**: Every evidence entry is signed before storage.
//! - **INV-QC-THRESHOLD-REPRODUCIBLE**: Policy thresholds produce identical
//!   actions from identical posteriors.
//! - **INV-QC-SEQUENCE-MONOTONIC**: Evidence log sequence numbers are
//!   strictly monotonically increasing.

use crate::security::adversary_graph::{
    ADV_005_ACTION_TRIGGERED, ADV_008_SIGNED_EVIDENCE, AdversaryGraph, EntityId, EntityType,
    EvidenceEvent, PolicyThreshold, QuarantineAction, SignedEvidenceEntry,
};
use hmac::{Hmac, Mac};
use sha2::Sha256;
use std::collections::BTreeMap;

// ---------------------------------------------------------------------------
// Invariant tags
// ---------------------------------------------------------------------------

/// INV-QC-SIGNED-LOG: Every evidence entry is signed before storage.
pub const INV_QC_SIGNED_LOG: &str = "INV-QC-SIGNED-LOG";
/// INV-QC-THRESHOLD-REPRODUCIBLE: Identical posteriors → identical actions.
pub const INV_QC_THRESHOLD_REPRODUCIBLE: &str = "INV-QC-THRESHOLD-REPRODUCIBLE";
/// INV-QC-SEQUENCE-MONOTONIC: Evidence log sequence numbers are strictly
/// monotonically increasing.
pub const INV_QC_SEQUENCE_MONOTONIC: &str = "INV-QC-SEQUENCE-MONOTONIC";

// ---------------------------------------------------------------------------
// Error codes
// ---------------------------------------------------------------------------

/// Signing key is empty or invalid.
pub const ERR_QC_INVALID_KEY: &str = "ERR_QC_INVALID_KEY";
/// Evidence log sequence invariant violated.
pub const ERR_QC_SEQUENCE_VIOLATION: &str = "ERR_QC_SEQUENCE_VIOLATION";

// ---------------------------------------------------------------------------
// Action record
// ---------------------------------------------------------------------------

/// A record of a control action taken by the quarantine controller.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ActionRecord {
    /// Trace ID that triggered the action.
    pub trace_id: String,
    /// Entity that the action was taken against.
    pub entity_id: EntityId,
    /// The action taken.
    pub action: QuarantineAction,
    /// Risk posterior at the time of the action.
    pub risk_posterior: f64,
    /// Epoch timestamp of the action.
    pub timestamp: u64,
    /// Event code.
    pub event_code: String,
}

// ---------------------------------------------------------------------------
// QuarantineController
// ---------------------------------------------------------------------------

/// The quarantine controller manages evidence ingestion, signing, and
/// policy-driven control actions over the adversary graph.
#[derive(Debug, Clone)]
pub struct QuarantineController {
    graph: AdversaryGraph,
    evidence_log: Vec<SignedEvidenceEntry>,
    action_log: Vec<ActionRecord>,
    signing_key: Vec<u8>,
    next_sequence: u64,
}

impl QuarantineController {
    /// Create a new quarantine controller with the given thresholds and
    /// signing key.
    pub fn new(thresholds: PolicyThreshold, signing_key: &[u8]) -> Self {
        Self {
            graph: AdversaryGraph::new(thresholds),
            evidence_log: Vec::new(),
            action_log: Vec::new(),
            signing_key: signing_key.to_vec(),
            next_sequence: 0,
        }
    }

    /// Create a quarantine controller with default thresholds and a default
    /// development signing key.
    pub fn with_defaults() -> Self {
        Self::new(
            PolicyThreshold::default(),
            b"franken-node-dev-adversary-key",
        )
    }

    /// Return a reference to the underlying adversary graph.
    pub fn graph(&self) -> &AdversaryGraph {
        &self.graph
    }

    /// Return the evidence log.
    pub fn evidence_log(&self) -> &[SignedEvidenceEntry] {
        &self.evidence_log
    }

    /// Return the action log.
    pub fn action_log(&self) -> &[ActionRecord] {
        &self.action_log
    }

    /// Return the number of signed evidence entries.
    pub fn evidence_count(&self) -> u64 {
        self.evidence_log.len() as u64
    }

    /// Register a new entity in the adversary graph.
    pub fn register_entity(
        &mut self,
        id: EntityId,
        entity_type: EntityType,
        timestamp: u64,
        trace_id: &str,
    ) -> Result<(), String> {
        self.graph.add_node(id, entity_type, timestamp, trace_id)
    }

    /// Register a trust relationship between two entities.
    pub fn register_trust_edge(
        &mut self,
        from: EntityId,
        to: EntityId,
        relationship: String,
        timestamp: u64,
        trace_id: &str,
    ) -> Result<(), String> {
        self.graph
            .add_edge(from, to, relationship, timestamp, trace_id)
    }

    /// Submit evidence against an entity. The evidence is signed, logged,
    /// and the posterior is evaluated against policy thresholds to determine
    /// whether a control action is required.
    ///
    /// Returns the action taken and the new posterior.
    pub fn submit_evidence(
        &mut self,
        event: EvidenceEvent,
    ) -> Result<(QuarantineAction, f64), String> {
        // Sign the evidence entry
        let signed = self.sign_evidence(&event)?;
        self.evidence_log.push(signed);

        // Ingest into graph
        let (action, posterior) = self.graph.ingest_evidence(&event)?;

        // Record action if non-trivial
        if action != QuarantineAction::None {
            let record = ActionRecord {
                trace_id: event.trace_id.clone(),
                entity_id: event.entity_id.clone(),
                action,
                risk_posterior: posterior,
                timestamp: event.timestamp,
                event_code: ADV_005_ACTION_TRIGGERED.to_string(),
            };
            self.action_log.push(record);
        }

        Ok((action, posterior))
    }

    /// Replay a batch of evidence events, returning a snapshot of all
    /// posteriors and the actions triggered.
    pub fn replay_batch(
        &mut self,
        events: &[EvidenceEvent],
        trace_id: &str,
    ) -> Result<(BTreeMap<EntityId, f64>, Vec<ActionRecord>), String> {
        let mut batch_actions = Vec::new();
        for event in events {
            let (action, posterior) = self.submit_evidence(event.clone())?;
            if action != QuarantineAction::None {
                batch_actions.push(ActionRecord {
                    trace_id: trace_id.to_string(),
                    entity_id: event.entity_id.clone(),
                    action,
                    risk_posterior: posterior,
                    timestamp: event.timestamp,
                    event_code: ADV_005_ACTION_TRIGGERED.to_string(),
                });
            }
        }
        let snapshot: BTreeMap<EntityId, f64> = {
            let mut map = BTreeMap::new();
            // Iterate through evidence to find all entity IDs
            for event in events {
                if let Some(node) = self.graph.get_node(&event.entity_id) {
                    map.insert(event.entity_id.clone(), node.risk_posterior);
                }
            }
            map
        };
        Ok((snapshot, batch_actions))
    }

    /// Produce a signed evidence entry for a given event.
    fn sign_evidence(&mut self, event: &EvidenceEvent) -> Result<SignedEvidenceEntry, String> {
        let seq = self.next_sequence;
        self.next_sequence += 1;

        let canonical =
            serde_json::to_string(event).map_err(|e| format!("serialization error: {e}"))?;
        let signature = self.hmac_sha256(&canonical);

        Ok(SignedEvidenceEntry {
            event: event.clone(),
            event_code: ADV_008_SIGNED_EVIDENCE.to_string(),
            signature,
            sequence: seq,
        })
    }

    /// Compute HMAC-SHA256 over data using the controller's signing key.
    fn hmac_sha256(&self, data: &str) -> String {
        let mut mac =
            Hmac::<Sha256>::new_from_slice(&self.signing_key).expect("HMAC accepts any key len");
        mac.update(data.as_bytes());
        let result = mac.finalize().into_bytes();
        hex::encode(result)
    }

    /// Produce a JSON-serializable state snapshot of the controller.
    pub fn state_snapshot(&self) -> serde_json::Value {
        serde_json::json!({
            "graph": self.graph.state_snapshot(),
            "evidence_count": self.evidence_log.len(),
            "action_count": self.action_log.len(),
            "next_sequence": self.next_sequence,
            "thresholds": self.graph.thresholds(),
            "actions": self.action_log,
        })
    }

    /// Verify that a signed evidence entry has a valid signature.
    pub fn verify_signature(&self, entry: &SignedEvidenceEntry) -> bool {
        let canonical = match serde_json::to_string(&entry.event) {
            Ok(s) => s,
            Err(_) => return false,
        };
        let expected = self.hmac_sha256(&canonical);
        crate::security::constant_time::ct_eq(&expected, &entry.signature)
    }
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::{Digest, Sha256};

    fn make_controller() -> QuarantineController {
        QuarantineController::with_defaults()
    }

    fn evidence(entity: &str, weight: f64, ts: u64) -> EvidenceEvent {
        EvidenceEvent {
            trace_id: format!("test-trace-{ts}"),
            entity_id: entity.to_string(),
            adverse_weight: weight,
            source: "unit-test".to_string(),
            timestamp: ts,
        }
    }

    #[test]
    fn controller_registers_entities() {
        let mut c = make_controller();
        c.register_entity("pub-1".into(), EntityType::Publisher, 0, "t")
            .unwrap();
        assert_eq!(c.graph().node_count(), 1);
    }

    #[test]
    fn submit_evidence_signs_and_logs() {
        let mut c = make_controller();
        c.register_entity("pub-1".into(), EntityType::Publisher, 0, "t")
            .unwrap();
        let ev = evidence("pub-1", 0.5, 1);
        let (action, posterior) = c.submit_evidence(ev).unwrap();
        assert_eq!(c.evidence_count(), 1);
        assert!(posterior > 0.0);
        // With a single 0.5 evidence, posterior should be moderate
        let _ = action;
    }

    #[test]
    fn evidence_signatures_are_verifiable() {
        let mut c = make_controller();
        c.register_entity("ext-1".into(), EntityType::Extension, 0, "t")
            .unwrap();
        let ev = evidence("ext-1", 0.3, 1);
        c.submit_evidence(ev).unwrap();
        let entry = &c.evidence_log()[0];
        assert!(c.verify_signature(entry));
    }

    #[test]
    fn signature_tamper_detection() {
        let mut c = make_controller();
        c.register_entity("ext-1".into(), EntityType::Extension, 0, "t")
            .unwrap();
        let ev = evidence("ext-1", 0.3, 1);
        c.submit_evidence(ev).unwrap();
        let mut tampered = c.evidence_log()[0].clone();
        tampered.event.adverse_weight = 0.9; // tamper
        assert!(!c.verify_signature(&tampered));
    }

    #[test]
    fn deterministic_replay_produces_identical_results() {
        let events = vec![
            evidence("dep-1", 0.8, 1),
            evidence("dep-1", 0.6, 2),
            evidence("dep-1", 0.9, 3),
            evidence("dep-1", 0.7, 4),
        ];

        let mut c1 = make_controller();
        c1.register_entity("dep-1".into(), EntityType::Dependency, 0, "t")
            .unwrap();
        let (snap1, _) = c1.replay_batch(&events, "r1").unwrap();

        let mut c2 = make_controller();
        c2.register_entity("dep-1".into(), EntityType::Dependency, 0, "t")
            .unwrap();
        let (snap2, _) = c2.replay_batch(&events, "r2").unwrap();

        assert_eq!(snap1["dep-1"].to_bits(), snap2["dep-1"].to_bits());
    }

    #[test]
    fn sequence_numbers_are_strictly_increasing() {
        let mut c = make_controller();
        c.register_entity("n1".into(), EntityType::Publisher, 0, "t")
            .unwrap();
        for i in 0..5 {
            c.submit_evidence(evidence("n1", 0.5, i)).unwrap();
        }
        for (i, entry) in c.evidence_log().iter().enumerate() {
            assert_eq!(entry.sequence, i as u64);
        }
    }

    #[test]
    fn policy_thresholds_trigger_correct_actions() {
        let mut c = make_controller();
        c.register_entity("bad-pub".into(), EntityType::Publisher, 0, "t")
            .unwrap();
        // Pump up the posterior with many adverse evidence events
        let mut last_action = QuarantineAction::None;
        for i in 1..=50 {
            let (action, _posterior) = c.submit_evidence(evidence("bad-pub", 1.0, i)).unwrap();
            last_action = action;
        }
        // After 50 fully-adverse events: posterior = 51/60 ≈ 0.85 → Revoke (≥0.7), not Quarantine (≥0.9).
        assert_eq!(last_action, QuarantineAction::Revoke);
    }

    #[test]
    fn action_log_records_non_none_actions() {
        let mut c = make_controller();
        c.register_entity("pub-x".into(), EntityType::Publisher, 0, "t")
            .unwrap();
        // Submit enough adverse evidence to trigger at least throttle
        for i in 1..=10 {
            c.submit_evidence(evidence("pub-x", 1.0, i)).unwrap();
        }
        assert!(!c.action_log().is_empty(), "expected action records");
        for record in c.action_log() {
            assert_ne!(record.action, QuarantineAction::None);
        }
    }

    #[test]
    fn state_snapshot_is_serializable() {
        let mut c = make_controller();
        c.register_entity("n1".into(), EntityType::Extension, 0, "t")
            .unwrap();
        c.submit_evidence(evidence("n1", 0.5, 1)).unwrap();
        let snap = c.state_snapshot();
        let json = serde_json::to_string_pretty(&snap).unwrap();
        assert!(json.contains("evidence_count"));
        assert!(json.contains("thresholds"));
    }

    #[test]
    fn trust_edge_registration() {
        let mut c = make_controller();
        c.register_entity("a".into(), EntityType::Publisher, 0, "t")
            .unwrap();
        c.register_entity("b".into(), EntityType::Extension, 0, "t")
            .unwrap();
        c.register_trust_edge("a".into(), "b".into(), "publishes".into(), 1, "t")
            .unwrap();
        assert_eq!(c.graph().edge_count(), 1);
    }

    #[test]
    fn submit_evidence_for_unknown_entity_fails() {
        let mut c = make_controller();
        let ev = evidence("unknown", 0.5, 1);
        let err = c.submit_evidence(ev).unwrap_err();
        assert!(err.contains("ERR_ADV_NODE_NOT_FOUND"));
    }

    #[test]
    fn controller_with_defaults_has_expected_thresholds() {
        let c = make_controller();
        let t = c.graph().thresholds();
        assert!((t.throttle - 0.3).abs() < 1e-9);
        assert!((t.isolate - 0.5).abs() < 1e-9);
        assert!((t.revoke - 0.7).abs() < 1e-9);
        assert!((t.quarantine - 0.9).abs() < 1e-9);
    }

    #[test]
    fn replay_batch_with_multiple_entities() {
        let mut c = make_controller();
        c.register_entity("a".into(), EntityType::Publisher, 0, "t")
            .unwrap();
        c.register_entity("b".into(), EntityType::Extension, 0, "t")
            .unwrap();
        let events = vec![
            evidence("a", 0.8, 1),
            evidence("b", 0.2, 2),
            evidence("a", 0.9, 3),
        ];
        let (snap, _) = c.replay_batch(&events, "r").unwrap();
        assert!(snap.contains_key("a"));
        assert!(snap.contains_key("b"));
        // 'a' should have higher posterior than 'b'
        assert!(snap["a"] > snap["b"]);
    }

    #[test]
    fn signatures_use_hmac_not_plain_keyed_hash() {
        let c = make_controller();
        let payload = "{\"probe\":true}";

        let hmac_digest = c.hmac_sha256(payload);

        let mut hasher = Sha256::new();
        hasher.update(&c.signing_key);
        hasher.update(payload.as_bytes());
        let legacy_digest = hex::encode(hasher.finalize());

        assert_ne!(hmac_digest, legacy_digest);
    }
}
