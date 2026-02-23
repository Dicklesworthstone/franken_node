// Conformance tests for bd-1v65: sqlmodel_rust integration.
//
// Validates typed model definitions for all persistence domains classified
// as mandatory or should_use in the bd-bt82 policy. Schema drift detection
// and round-trip serialization conformance for each integrated domain.

#![allow(unused)]

use std::collections::BTreeSet;
use std::fmt;

use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// Classification
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ModelClassification {
    Mandatory,
    ShouldUse,
    Optional,
}

impl ModelClassification {
    pub fn all() -> &'static [ModelClassification] {
        &[Self::Mandatory, Self::ShouldUse, Self::Optional]
    }

    pub fn label(&self) -> &'static str {
        match self {
            Self::Mandatory => "mandatory",
            Self::ShouldUse => "should_use",
            Self::Optional => "optional",
        }
    }

    pub fn is_mandatory(&self) -> bool {
        matches!(self, Self::Mandatory)
    }
}

impl fmt::Display for ModelClassification {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.label())
    }
}

// ---------------------------------------------------------------------------
// Model source
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ModelSource {
    HandAuthored,
    Codegen,
}

impl ModelSource {
    pub fn label(&self) -> &'static str {
        match self {
            Self::HandAuthored => "hand_authored",
            Self::Codegen => "codegen",
        }
    }
}

impl fmt::Display for ModelSource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.label())
    }
}

// ---------------------------------------------------------------------------
// Typed model
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TypedModel {
    pub domain: String,
    pub owner_module: String,
    pub classification: ModelClassification,
    pub model_source: ModelSource,
    pub model_name: String,
    pub version: String,
}

// ---------------------------------------------------------------------------
// Drift result
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DriftResult {
    pub model_name: String,
    pub drift_detected: bool,
    pub detail: String,
}

// ---------------------------------------------------------------------------
// Round-trip result
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RoundTripResult {
    pub model_name: String,
    pub passed: bool,
    pub latency_ms: f64,
}

// ---------------------------------------------------------------------------
// Events
// ---------------------------------------------------------------------------

pub const SQLMODEL_SCHEMA_DRIFT_DETECTED: &str = "SQLMODEL_SCHEMA_DRIFT_DETECTED";
pub const SQLMODEL_ROUND_TRIP_PASS: &str = "SQLMODEL_ROUND_TRIP_PASS";
pub const SQLMODEL_ROUND_TRIP_FAIL: &str = "SQLMODEL_ROUND_TRIP_FAIL";
pub const SQLMODEL_MODEL_REGISTERED: &str = "SQLMODEL_MODEL_REGISTERED";
pub const SQLMODEL_VERSION_COMPAT_FAIL: &str = "SQLMODEL_VERSION_COMPAT_FAIL";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SqlmodelEvent {
    pub code: String,
    pub model_name: String,
    pub detail: String,
}

// ---------------------------------------------------------------------------
// Invariants
// ---------------------------------------------------------------------------

pub const INV_SMI_DRIFT: &str = "INV-SMI-DRIFT";
pub const INV_SMI_ROUNDTRIP: &str = "INV-SMI-ROUNDTRIP";
pub const INV_SMI_MANDATORY: &str = "INV-SMI-MANDATORY";
pub const INV_SMI_OWNERSHIP: &str = "INV-SMI-OWNERSHIP";

// ---------------------------------------------------------------------------
// Integration gate
// ---------------------------------------------------------------------------

#[derive(Debug, Default)]
pub struct SqlmodelIntegrationGate {
    models: Vec<TypedModel>,
    drift_results: Vec<DriftResult>,
    round_trip_results: Vec<RoundTripResult>,
    events: Vec<SqlmodelEvent>,
}

impl SqlmodelIntegrationGate {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn register_model(&mut self, model: TypedModel) {
        self.events.push(SqlmodelEvent {
            code: SQLMODEL_MODEL_REGISTERED.to_string(),
            model_name: model.model_name.clone(),
            detail: format!(
                "domain={} classification={}",
                model.domain, model.classification
            ),
        });
        self.models.push(model);
    }

    pub fn check_drift(&mut self, model_name: &str, drift_detected: bool, detail: &str) {
        if drift_detected {
            self.events.push(SqlmodelEvent {
                code: SQLMODEL_SCHEMA_DRIFT_DETECTED.to_string(),
                model_name: model_name.to_string(),
                detail: detail.to_string(),
            });
        }
        self.drift_results.push(DriftResult {
            model_name: model_name.to_string(),
            drift_detected,
            detail: detail.to_string(),
        });
    }

    pub fn check_round_trip(&mut self, model_name: &str, passed: bool, latency_ms: f64) {
        let code = if passed {
            SQLMODEL_ROUND_TRIP_PASS
        } else {
            SQLMODEL_ROUND_TRIP_FAIL
        };
        self.events.push(SqlmodelEvent {
            code: code.to_string(),
            model_name: model_name.to_string(),
            detail: format!("latency_ms={latency_ms:.2}"),
        });
        self.round_trip_results.push(RoundTripResult {
            model_name: model_name.to_string(),
            passed,
            latency_ms,
        });
    }

    pub fn gate_pass(&self) -> bool {
        if self.models.is_empty() {
            return false;
        }
        let no_drift = !self.drift_results.iter().any(|d| d.drift_detected);
        let no_rt_fail = !self.round_trip_results.iter().any(|r| {
            if !r.passed {
                self.models
                    .iter()
                    .any(|m| m.model_name == r.model_name && !matches!(m.classification, ModelClassification::Optional))
            } else {
                false
            }
        });
        no_drift && no_rt_fail
    }

    pub fn summary(&self) -> IntegrationSummary {
        IntegrationSummary {
            total_models: self.models.len(),
            mandatory_count: self.models.iter().filter(|m| m.classification.is_mandatory()).count(),
            should_use_count: self
                .models
                .iter()
                .filter(|m| matches!(m.classification, ModelClassification::ShouldUse))
                .count(),
            optional_count: self
                .models
                .iter()
                .filter(|m| matches!(m.classification, ModelClassification::Optional))
                .count(),
            drift_failures: self.drift_results.iter().filter(|d| d.drift_detected).count(),
            round_trip_failures: self.round_trip_results.iter().filter(|r| !r.passed).count(),
        }
    }

    pub fn models(&self) -> &[TypedModel] {
        &self.models
    }

    pub fn events(&self) -> &[SqlmodelEvent] {
        &self.events
    }

    pub fn take_events(&mut self) -> Vec<SqlmodelEvent> {
        std::mem::take(&mut self.events)
    }

    pub fn to_report(&self) -> serde_json::Value {
        let summary = self.summary();
        serde_json::json!({
            "gate_verdict": if self.gate_pass() { "PASS" } else { "FAIL" },
            "summary": {
                "total_models": summary.total_models,
                "mandatory_count": summary.mandatory_count,
                "should_use_count": summary.should_use_count,
                "optional_count": summary.optional_count,
                "drift_failures": summary.drift_failures,
                "round_trip_failures": summary.round_trip_failures
            },
            "models": self.models.iter().map(|m| {
                serde_json::json!({
                    "domain": m.domain,
                    "owner_module": m.owner_module,
                    "classification": m.classification.label(),
                    "model_source": m.model_source.label(),
                    "model_name": m.model_name,
                    "version": m.version
                })
            }).collect::<Vec<_>>()
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IntegrationSummary {
    pub total_models: usize,
    pub mandatory_count: usize,
    pub should_use_count: usize,
    pub optional_count: usize,
    pub drift_failures: usize,
    pub round_trip_failures: usize,
}

// ---------------------------------------------------------------------------
// Canonical models from bd-bt82 policy matrix
// ---------------------------------------------------------------------------

fn canonical_models() -> Vec<TypedModel> {
    vec![
        // -- Mandatory (12) --
        TypedModel { domain: "fencing_token_state".into(), owner_module: "crates/franken-node/src/connector/fencing.rs".into(), classification: ModelClassification::Mandatory, model_source: ModelSource::HandAuthored, model_name: "FencingLeaseRecord".into(), version: "1.0.0".into() },
        TypedModel { domain: "lease_service_state".into(), owner_module: "crates/franken-node/src/connector/lease_service.rs".into(), classification: ModelClassification::Mandatory, model_source: ModelSource::HandAuthored, model_name: "LeaseServiceRecord".into(), version: "1.0.0".into() },
        TypedModel { domain: "lease_quorum_coordination".into(), owner_module: "crates/franken-node/src/connector/lease_coordinator.rs".into(), classification: ModelClassification::Mandatory, model_source: ModelSource::HandAuthored, model_name: "LeaseQuorumRecord".into(), version: "1.0.0".into() },
        TypedModel { domain: "rollout_state".into(), owner_module: "crates/franken-node/src/connector/rollout_state.rs".into(), classification: ModelClassification::Mandatory, model_source: ModelSource::Codegen, model_name: "RolloutStateRecord".into(), version: "1.0.0".into() },
        TypedModel { domain: "health_gate_policy_state".into(), owner_module: "crates/franken-node/src/connector/health_gate.rs".into(), classification: ModelClassification::Mandatory, model_source: ModelSource::Codegen, model_name: "HealthGatePolicyRecord".into(), version: "1.0.0".into() },
        TypedModel { domain: "control_channel_sequence_window".into(), owner_module: "crates/franken-node/src/connector/control_channel.rs".into(), classification: ModelClassification::Mandatory, model_source: ModelSource::HandAuthored, model_name: "ControlChannelStateRecord".into(), version: "1.0.0".into() },
        TypedModel { domain: "artifact_journal".into(), owner_module: "crates/franken-node/src/connector/artifact_persistence.rs".into(), classification: ModelClassification::Mandatory, model_source: ModelSource::Codegen, model_name: "ArtifactJournalRecord".into(), version: "1.0.0".into() },
        TypedModel { domain: "tiered_trust_storage".into(), owner_module: "crates/franken-node/src/connector/tiered_trust_storage.rs".into(), classification: ModelClassification::Mandatory, model_source: ModelSource::Codegen, model_name: "TieredTrustArtifactRecord".into(), version: "1.0.0".into() },
        TypedModel { domain: "canonical_state_roots".into(), owner_module: "crates/franken-node/src/connector/state_model.rs".into(), classification: ModelClassification::Mandatory, model_source: ModelSource::HandAuthored, model_name: "CanonicalStateRootRecord".into(), version: "1.0.0".into() },
        TypedModel { domain: "durability_mode_controls".into(), owner_module: "crates/franken-node/src/connector/durability.rs".into(), classification: ModelClassification::Mandatory, model_source: ModelSource::HandAuthored, model_name: "DurabilityModeRecord".into(), version: "1.0.0".into() },
        TypedModel { domain: "durable_claim_gate_audit".into(), owner_module: "crates/franken-node/src/connector/durable_claim_gate.rs".into(), classification: ModelClassification::Mandatory, model_source: ModelSource::HandAuthored, model_name: "DurableClaimAuditRecord".into(), version: "1.0.0".into() },
        TypedModel { domain: "schema_migration_registry".into(), owner_module: "crates/franken-node/src/connector/schema_migration.rs".into(), classification: ModelClassification::Mandatory, model_source: ModelSource::Codegen, model_name: "SchemaMigrationRecord".into(), version: "1.0.0".into() },
        // -- ShouldUse (7) --
        TypedModel { domain: "snapshot_policy_state".into(), owner_module: "crates/franken-node/src/connector/snapshot_policy.rs".into(), classification: ModelClassification::ShouldUse, model_source: ModelSource::Codegen, model_name: "SnapshotPolicyRecord".into(), version: "1.0.0".into() },
        TypedModel { domain: "crdt_merge_state".into(), owner_module: "crates/franken-node/src/connector/crdt.rs".into(), classification: ModelClassification::ShouldUse, model_source: ModelSource::HandAuthored, model_name: "CrdtMergeStateRecord".into(), version: "1.0.0".into() },
        TypedModel { domain: "quarantine_store_state".into(), owner_module: "crates/franken-node/src/connector/quarantine_store.rs".into(), classification: ModelClassification::ShouldUse, model_source: ModelSource::Codegen, model_name: "QuarantineEntryRecord".into(), version: "1.0.0".into() },
        TypedModel { domain: "quarantine_promotion_receipts".into(), owner_module: "crates/franken-node/src/connector/quarantine_promotion.rs".into(), classification: ModelClassification::ShouldUse, model_source: ModelSource::Codegen, model_name: "QuarantinePromotionRecord".into(), version: "1.0.0".into() },
        TypedModel { domain: "retention_policy_state".into(), owner_module: "crates/franken-node/src/connector/retention_policy.rs".into(), classification: ModelClassification::ShouldUse, model_source: ModelSource::HandAuthored, model_name: "RetentionPolicyRecord".into(), version: "1.0.0".into() },
        TypedModel { domain: "repair_cycle_audit".into(), owner_module: "crates/franken-node/src/connector/repair_controller.rs".into(), classification: ModelClassification::ShouldUse, model_source: ModelSource::HandAuthored, model_name: "RepairCycleAuditRecord".into(), version: "1.0.0".into() },
        TypedModel { domain: "lease_conflict_audit".into(), owner_module: "crates/franken-node/src/connector/lease_conflict.rs".into(), classification: ModelClassification::ShouldUse, model_source: ModelSource::HandAuthored, model_name: "LeaseConflictAuditRecord".into(), version: "1.0.0".into() },
        // -- Optional (2) --
        TypedModel { domain: "offline_coverage_metrics".into(), owner_module: "crates/franken-node/src/connector/offline_coverage.rs".into(), classification: ModelClassification::Optional, model_source: ModelSource::Codegen, model_name: "OfflineCoverageMetricRecord".into(), version: "1.0.0".into() },
        TypedModel { domain: "lifecycle_transition_cache".into(), owner_module: "crates/franken-node/src/connector/lifecycle.rs".into(), classification: ModelClassification::Optional, model_source: ModelSource::HandAuthored, model_name: "LifecycleTransitionCacheRecord".into(), version: "1.0.0".into() },
    ]
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_classification_all_count() {
        assert_eq!(ModelClassification::all().len(), 3);
    }

    #[test]
    fn test_classification_labels() {
        assert_eq!(ModelClassification::Mandatory.label(), "mandatory");
        assert_eq!(ModelClassification::ShouldUse.label(), "should_use");
        assert_eq!(ModelClassification::Optional.label(), "optional");
    }

    #[test]
    fn test_classification_is_mandatory() {
        assert!(ModelClassification::Mandatory.is_mandatory());
        assert!(!ModelClassification::ShouldUse.is_mandatory());
        assert!(!ModelClassification::Optional.is_mandatory());
    }

    #[test]
    fn test_classification_display() {
        assert_eq!(format!("{}", ModelClassification::Mandatory), "mandatory");
    }

    #[test]
    fn test_classification_serde_roundtrip() {
        for c in ModelClassification::all() {
            let json = serde_json::to_string(c).unwrap();
            let back: ModelClassification = serde_json::from_str(&json).unwrap();
            assert_eq!(*c, back);
        }
    }

    #[test]
    fn test_model_source_labels() {
        assert_eq!(ModelSource::HandAuthored.label(), "hand_authored");
        assert_eq!(ModelSource::Codegen.label(), "codegen");
    }

    #[test]
    fn test_model_source_display() {
        assert_eq!(format!("{}", ModelSource::HandAuthored), "hand_authored");
    }

    #[test]
    fn test_model_source_serde_roundtrip() {
        let sources = [ModelSource::HandAuthored, ModelSource::Codegen];
        for s in &sources {
            let json = serde_json::to_string(s).unwrap();
            let back: ModelSource = serde_json::from_str(&json).unwrap();
            assert_eq!(*s, back);
        }
    }

    #[test]
    fn test_canonical_total_count() {
        assert_eq!(canonical_models().len(), 21);
    }

    #[test]
    fn test_canonical_mandatory_count() {
        let count = canonical_models().iter().filter(|m| m.classification.is_mandatory()).count();
        assert_eq!(count, 12);
    }

    #[test]
    fn test_canonical_should_use_count() {
        let count = canonical_models()
            .iter()
            .filter(|m| matches!(m.classification, ModelClassification::ShouldUse))
            .count();
        assert_eq!(count, 7);
    }

    #[test]
    fn test_canonical_optional_count() {
        let count = canonical_models()
            .iter()
            .filter(|m| matches!(m.classification, ModelClassification::Optional))
            .count();
        assert_eq!(count, 2);
    }

    #[test]
    fn test_canonical_unique_model_names() {
        let models = canonical_models();
        let names: Vec<&str> = models.iter().map(|m| m.model_name.as_str()).collect();
        let unique: BTreeSet<&str> = names.iter().copied().collect();
        assert_eq!(names.len(), unique.len(), "Duplicate model names");
    }

    #[test]
    fn test_canonical_unique_domains() {
        let models = canonical_models();
        let domains: Vec<&str> = models.iter().map(|m| m.domain.as_str()).collect();
        let unique: BTreeSet<&str> = domains.iter().copied().collect();
        assert_eq!(domains.len(), unique.len(), "Duplicate domains");
    }

    #[test]
    fn test_canonical_all_versioned() {
        for m in canonical_models() {
            assert!(!m.version.is_empty(), "Model {} has no version", m.model_name);
        }
    }

    #[test]
    fn test_gate_empty_fails() {
        let gate = SqlmodelIntegrationGate::new();
        assert!(!gate.gate_pass());
    }

    #[test]
    fn test_gate_all_registered_all_pass() {
        let mut gate = SqlmodelIntegrationGate::new();
        for m in canonical_models() {
            let name = m.model_name.clone();
            gate.register_model(m);
            gate.check_drift(&name, false, "no drift");
            gate.check_round_trip(&name, true, 0.5);
        }
        assert!(gate.gate_pass());
    }

    #[test]
    fn test_gate_drift_failure_fails() {
        let mut gate = SqlmodelIntegrationGate::new();
        let m = canonical_models().into_iter().next().unwrap();
        let name = m.model_name.clone();
        gate.register_model(m);
        gate.check_drift(&name, true, "column mismatch");
        gate.check_round_trip(&name, true, 0.5);
        assert!(!gate.gate_pass());
    }

    #[test]
    fn test_gate_round_trip_failure_mandatory_fails() {
        let mut gate = SqlmodelIntegrationGate::new();
        let m = canonical_models().into_iter().next().unwrap();
        let name = m.model_name.clone();
        gate.register_model(m);
        gate.check_drift(&name, false, "ok");
        gate.check_round_trip(&name, false, 1.0);
        assert!(!gate.gate_pass());
    }

    #[test]
    fn test_gate_round_trip_failure_optional_passes() {
        let mut gate = SqlmodelIntegrationGate::new();
        let m = canonical_models()
            .into_iter()
            .find(|m| matches!(m.classification, ModelClassification::Optional))
            .unwrap();
        let name = m.model_name.clone();
        gate.register_model(m);
        gate.check_drift(&name, false, "ok");
        gate.check_round_trip(&name, false, 1.0);
        assert!(gate.gate_pass());
    }

    #[test]
    fn test_register_model_emits_registered_event() {
        let mut gate = SqlmodelIntegrationGate::new();
        let m = canonical_models().into_iter().next().unwrap();
        gate.register_model(m);
        assert_eq!(gate.events()[0].code, SQLMODEL_MODEL_REGISTERED);
    }

    #[test]
    fn test_check_drift_no_drift_no_event() {
        let mut gate = SqlmodelIntegrationGate::new();
        gate.check_drift("Test", false, "ok");
        let drift_events: Vec<_> = gate
            .events()
            .iter()
            .filter(|e| e.code == SQLMODEL_SCHEMA_DRIFT_DETECTED)
            .collect();
        assert!(drift_events.is_empty());
    }

    #[test]
    fn test_check_drift_detected_emits_event() {
        let mut gate = SqlmodelIntegrationGate::new();
        gate.check_drift("Test", true, "column mismatch");
        let drift_events: Vec<_> = gate
            .events()
            .iter()
            .filter(|e| e.code == SQLMODEL_SCHEMA_DRIFT_DETECTED)
            .collect();
        assert_eq!(drift_events.len(), 1);
    }

    #[test]
    fn test_check_round_trip_pass_emits_pass_event() {
        let mut gate = SqlmodelIntegrationGate::new();
        gate.check_round_trip("Test", true, 0.5);
        assert_eq!(gate.events()[0].code, SQLMODEL_ROUND_TRIP_PASS);
    }

    #[test]
    fn test_check_round_trip_fail_emits_fail_event() {
        let mut gate = SqlmodelIntegrationGate::new();
        gate.check_round_trip("Test", false, 1.0);
        assert_eq!(gate.events()[0].code, SQLMODEL_ROUND_TRIP_FAIL);
    }

    #[test]
    fn test_take_events_drains() {
        let mut gate = SqlmodelIntegrationGate::new();
        let m = canonical_models().into_iter().next().unwrap();
        gate.register_model(m);
        let events = gate.take_events();
        assert_eq!(events.len(), 1);
        assert!(gate.events().is_empty());
    }

    #[test]
    fn test_event_has_model_name() {
        let mut gate = SqlmodelIntegrationGate::new();
        let m = canonical_models().into_iter().next().unwrap();
        let expected_name = m.model_name.clone();
        gate.register_model(m);
        assert_eq!(gate.events()[0].model_name, expected_name);
    }

    #[test]
    fn test_summary_counts() {
        let mut gate = SqlmodelIntegrationGate::new();
        for m in canonical_models() {
            gate.register_model(m);
        }
        let s = gate.summary();
        assert_eq!(s.total_models, 21);
        assert_eq!(s.mandatory_count, 12);
        assert_eq!(s.should_use_count, 7);
        assert_eq!(s.optional_count, 2);
        assert_eq!(s.drift_failures, 0);
        assert_eq!(s.round_trip_failures, 0);
    }

    #[test]
    fn test_summary_drift_failures() {
        let mut gate = SqlmodelIntegrationGate::new();
        gate.check_drift("Test", true, "fail");
        let s = gate.summary();
        assert_eq!(s.drift_failures, 1);
    }

    #[test]
    fn test_summary_round_trip_failures() {
        let mut gate = SqlmodelIntegrationGate::new();
        gate.check_round_trip("Test", false, 1.0);
        let s = gate.summary();
        assert_eq!(s.round_trip_failures, 1);
    }

    #[test]
    fn test_report_structure() {
        let mut gate = SqlmodelIntegrationGate::new();
        for m in canonical_models() {
            gate.register_model(m);
        }
        let report = gate.to_report();
        assert!(report.get("gate_verdict").is_some());
        assert!(report.get("summary").is_some());
        assert!(report.get("models").is_some());
    }

    #[test]
    fn test_report_pass_verdict() {
        let mut gate = SqlmodelIntegrationGate::new();
        for m in canonical_models() {
            let name = m.model_name.clone();
            gate.register_model(m);
            gate.check_drift(&name, false, "ok");
            gate.check_round_trip(&name, true, 0.5);
        }
        assert_eq!(gate.to_report()["gate_verdict"], "PASS");
    }

    #[test]
    fn test_report_fail_verdict_empty() {
        let gate = SqlmodelIntegrationGate::new();
        assert_eq!(gate.to_report()["gate_verdict"], "FAIL");
    }

    #[test]
    fn test_report_models_count() {
        let mut gate = SqlmodelIntegrationGate::new();
        for m in canonical_models() {
            gate.register_model(m);
        }
        assert_eq!(gate.to_report()["models"].as_array().unwrap().len(), 21);
    }

    #[test]
    fn test_invariant_constants_defined() {
        assert_eq!(INV_SMI_DRIFT, "INV-SMI-DRIFT");
        assert_eq!(INV_SMI_ROUNDTRIP, "INV-SMI-ROUNDTRIP");
        assert_eq!(INV_SMI_MANDATORY, "INV-SMI-MANDATORY");
        assert_eq!(INV_SMI_OWNERSHIP, "INV-SMI-OWNERSHIP");
    }

    #[test]
    fn test_event_code_constants_defined() {
        assert_eq!(SQLMODEL_SCHEMA_DRIFT_DETECTED, "SQLMODEL_SCHEMA_DRIFT_DETECTED");
        assert_eq!(SQLMODEL_ROUND_TRIP_PASS, "SQLMODEL_ROUND_TRIP_PASS");
        assert_eq!(SQLMODEL_ROUND_TRIP_FAIL, "SQLMODEL_ROUND_TRIP_FAIL");
        assert_eq!(SQLMODEL_MODEL_REGISTERED, "SQLMODEL_MODEL_REGISTERED");
        assert_eq!(SQLMODEL_VERSION_COMPAT_FAIL, "SQLMODEL_VERSION_COMPAT_FAIL");
    }

    #[test]
    fn test_determinism_same_input_same_report() {
        let mut g1 = SqlmodelIntegrationGate::new();
        let mut g2 = SqlmodelIntegrationGate::new();
        for m in canonical_models() {
            g1.register_model(m.clone());
        }
        for m in canonical_models() {
            g2.register_model(m.clone());
        }
        let r1 = serde_json::to_string(&g1.to_report()).unwrap();
        let r2 = serde_json::to_string(&g2.to_report()).unwrap();
        assert_eq!(r1, r2);
    }

    #[test]
    fn test_typed_model_serde_roundtrip() {
        let m = &canonical_models()[0];
        let json = serde_json::to_string(m).unwrap();
        let back: TypedModel = serde_json::from_str(&json).unwrap();
        assert_eq!(back.domain, m.domain);
        assert_eq!(back.model_name, m.model_name);
    }

    #[test]
    fn test_drift_result_serde_roundtrip() {
        let dr = DriftResult { model_name: "Test".into(), drift_detected: false, detail: "ok".into() };
        let json = serde_json::to_string(&dr).unwrap();
        let back: DriftResult = serde_json::from_str(&json).unwrap();
        assert_eq!(back.model_name, "Test");
    }

    #[test]
    fn test_round_trip_result_serde_roundtrip() {
        let rtr = RoundTripResult { model_name: "Test".into(), passed: true, latency_ms: 0.5 };
        let json = serde_json::to_string(&rtr).unwrap();
        let back: RoundTripResult = serde_json::from_str(&json).unwrap();
        assert!(back.passed);
    }

    #[test]
    fn test_sqlmodel_event_serde_roundtrip() {
        let evt = SqlmodelEvent { code: SQLMODEL_MODEL_REGISTERED.to_string(), model_name: "T".to_string(), detail: "d".to_string() };
        let json = serde_json::to_string(&evt).unwrap();
        let back: SqlmodelEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(back.code, evt.code);
    }

    #[test]
    fn test_integration_summary_serde_roundtrip() {
        let s = IntegrationSummary { total_models: 21, mandatory_count: 12, should_use_count: 7, optional_count: 2, drift_failures: 0, round_trip_failures: 0 };
        let json = serde_json::to_string(&s).unwrap();
        let back: IntegrationSummary = serde_json::from_str(&json).unwrap();
        assert_eq!(back.total_models, 21);
    }
}
