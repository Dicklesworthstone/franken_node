//! bd-n1w: Frontier demo gates with external reproducibility requirements (Section 10.12).
//!
//! Shared demo-gate infrastructure for all five frontier programs:
//! Migration Singularity, Trust Fabric, Verifier Economy, Operator Intelligence,
//! and Ecosystem Network Effects.  Ensures external reproducibility as a hard
//! requirement by producing manifests, a demo-gate runner, and external-verifier
//! bootstrap artefacts.
//!
//! # Capabilities
//!
//! - `FrontierDemoGate` trait for uniform gate execution
//! - `DemoGateRunner` for isolated discovery + execution of registered gates
//! - `ReproducibilityManifest` capturing full execution fingerprints
//! - `ExternalVerifierBootstrap` for re-execution and byte-for-byte diff
//! - Deterministic ordering via `BTreeMap` throughout
//!
//! # Invariants
//!
//! - **INV-DEMO-DETERMINISTIC**: Same inputs always produce the same outputs.
//! - **INV-DEMO-ISOLATED**: Each gate executes in an isolated context.
//! - **INV-DEMO-FINGERPRINTED**: Every input and output has a SHA-256 fingerprint.
//! - **INV-DEMO-REPRODUCIBLE**: External re-execution must yield byte-for-byte match.
//! - **INV-DEMO-MANIFEST-COMPLETE**: Manifest includes git hash, timing, environment.
//! - **INV-DEMO-SCHEMA-VERSIONED**: All serialised artefacts carry schema version.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

use crate::capacity_defaults::aliases::{MAX_EVENTS, MAX_RESULTS};
const MAX_REGISTERED_PROGRAMS: usize = 4096;

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

// ---------------------------------------------------------------------------
// Schema version
// ---------------------------------------------------------------------------

/// Schema version for demo-gate artefacts.
pub const SCHEMA_VERSION: &str = "demo-v1.0";

// ---------------------------------------------------------------------------
// Event codes
// ---------------------------------------------------------------------------

pub mod event_codes {
    pub const DEMO_GATE_START: &str = "DEMO-001";
    pub const DEMO_GATE_PASS: &str = "DEMO-002";
    pub const DEMO_GATE_FAIL: &str = "DEMO-003";
    pub const MANIFEST_GENERATED: &str = "DEMO-004";
    pub const EXTERNAL_VERIFY_START: &str = "DEMO-005";
    pub const EXTERNAL_VERIFY_MATCH: &str = "DEMO-006";
    pub const EXTERNAL_VERIFY_MISMATCH: &str = "DEMO-007";
}

// ---------------------------------------------------------------------------
// Error codes
// ---------------------------------------------------------------------------

pub mod error_codes {
    pub const ERR_DEMO_GATE_NOT_FOUND: &str = "ERR_DEMO_GATE_NOT_FOUND";
    pub const ERR_DEMO_EXECUTION_FAILED: &str = "ERR_DEMO_EXECUTION_FAILED";
    pub const ERR_DEMO_FINGERPRINT_MISMATCH: &str = "ERR_DEMO_FINGERPRINT_MISMATCH";
    pub const ERR_DEMO_MANIFEST_INVALID: &str = "ERR_DEMO_MANIFEST_INVALID";
    pub const ERR_DEMO_BOOTSTRAP_FAILED: &str = "ERR_DEMO_BOOTSTRAP_FAILED";
    pub const ERR_DEMO_ISOLATION_VIOLATED: &str = "ERR_DEMO_ISOLATION_VIOLATED";
    pub const ERR_DEMO_SCHEMA_MISMATCH: &str = "ERR_DEMO_SCHEMA_MISMATCH";
}

// ---------------------------------------------------------------------------
// Invariants
// ---------------------------------------------------------------------------

pub mod invariants {
    pub const INV_DEMO_DETERMINISTIC: &str = "INV-DEMO-DETERMINISTIC";
    pub const INV_DEMO_ISOLATED: &str = "INV-DEMO-ISOLATED";
    pub const INV_DEMO_FINGERPRINTED: &str = "INV-DEMO-FINGERPRINTED";
    pub const INV_DEMO_REPRODUCIBLE: &str = "INV-DEMO-REPRODUCIBLE";
    pub const INV_DEMO_MANIFEST_COMPLETE: &str = "INV-DEMO-MANIFEST-COMPLETE";
    pub const INV_DEMO_SCHEMA_VERSIONED: &str = "INV-DEMO-SCHEMA-VERSIONED";
}

// ---------------------------------------------------------------------------
// Frontier programs
// ---------------------------------------------------------------------------

/// The five frontier programs whose demo gates are managed by this module.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FrontierProgram {
    MigrationSingularity,
    TrustFabric,
    VerifierEconomy,
    OperatorIntelligence,
    EcosystemNetworkEffects,
}

impl FrontierProgram {
    /// Return all five frontier programs in deterministic order.
    pub fn all() -> &'static [FrontierProgram] {
        &[
            Self::MigrationSingularity,
            Self::TrustFabric,
            Self::VerifierEconomy,
            Self::OperatorIntelligence,
            Self::EcosystemNetworkEffects,
        ]
    }

    /// Human-readable label.
    pub fn label(&self) -> &'static str {
        match self {
            Self::MigrationSingularity => "migration_singularity",
            Self::TrustFabric => "trust_fabric",
            Self::VerifierEconomy => "verifier_economy",
            Self::OperatorIntelligence => "operator_intelligence",
            Self::EcosystemNetworkEffects => "ecosystem_network_effects",
        }
    }

    /// Display name for reports.
    pub fn display_name(&self) -> &'static str {
        match self {
            Self::MigrationSingularity => "Migration Singularity",
            Self::TrustFabric => "Trust Fabric",
            Self::VerifierEconomy => "Verifier Economy",
            Self::OperatorIntelligence => "Operator Intelligence",
            Self::EcosystemNetworkEffects => "Ecosystem Network Effects",
        }
    }
}

// ---------------------------------------------------------------------------
// Trait: FrontierDemoGate
// ---------------------------------------------------------------------------

/// Trait that every frontier demo gate must implement.
pub trait FrontierDemoGate {
    /// Return the input corpus for this gate (deterministic BTreeMap).
    fn input_corpus(&self) -> BTreeMap<String, String>;

    /// Execute the gate and produce a `DemoGateResult`.
    fn execute(&self) -> DemoGateResult;

    /// Return the output JSON schema identifier.
    fn output_schema(&self) -> String;

    /// Return an attestation hash over the execution result.
    fn attestation(&self) -> String;
}

// ---------------------------------------------------------------------------
// DemoGateResult
// ---------------------------------------------------------------------------

/// Result of a single demo-gate execution.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DemoGateResult {
    pub program: FrontierProgram,
    pub passed: bool,
    pub timing_ms: u64,
    pub resource_metrics: ResourceMetrics,
    pub output_fingerprint: String,
    pub schema_version: String,
    pub detail: String,
}

/// Resource metrics collected during gate execution.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct ResourceMetrics {
    pub peak_memory_bytes: u64,
    pub cpu_time_ms: u64,
    pub io_operations: u64,
}

// ---------------------------------------------------------------------------
// ReproducibilityManifest
// ---------------------------------------------------------------------------

/// Manifest capturing everything needed for external reproducibility.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ReproducibilityManifest {
    pub schema_version: String,
    pub git_commit_hash: String,
    pub input_fingerprints: BTreeMap<String, String>,
    pub output_fingerprints: BTreeMap<String, String>,
    pub environment_metadata: BTreeMap<String, String>,
    pub timing_per_gate: BTreeMap<String, u64>,
    pub manifest_fingerprint: String,
}

impl ReproducibilityManifest {
    /// Create a new manifest and compute its fingerprint.
    pub fn new(
        git_commit_hash: String,
        input_fingerprints: BTreeMap<String, String>,
        output_fingerprints: BTreeMap<String, String>,
        environment_metadata: BTreeMap<String, String>,
        timing_per_gate: BTreeMap<String, u64>,
    ) -> Self {
        let mut m = Self {
            schema_version: SCHEMA_VERSION.to_string(),
            git_commit_hash,
            input_fingerprints,
            output_fingerprints,
            environment_metadata,
            timing_per_gate,
            manifest_fingerprint: String::new(),
        };
        m.manifest_fingerprint = m.compute_fingerprint();
        m
    }

    /// Recompute the SHA-256 fingerprint over the canonical JSON form.
    pub fn compute_fingerprint(&self) -> String {
        let canonical = serde_json::json!({
            "schema_version": &self.schema_version,
            "git_commit_hash": &self.git_commit_hash,
            "input_fingerprints": &self.input_fingerprints,
            "output_fingerprints": &self.output_fingerprints,
            "environment_metadata": &self.environment_metadata,
            "timing_per_gate": &self.timing_per_gate,
        });
        let bytes = serde_json::to_vec(&canonical)
            .unwrap_or_else(|e| format!("__serde_err:{e}").into_bytes());
        hex::encode(Sha256::digest(
            [b"frontier_demo_hash_v1:" as &[u8], &bytes[..]].concat(),
        ))
    }

    /// Validate that the stored fingerprint matches the computed one.
    pub fn validate_fingerprint(&self) -> bool {
        crate::security::constant_time::ct_eq(
            &self.manifest_fingerprint,
            &self.compute_fingerprint(),
        )
    }
}

// ---------------------------------------------------------------------------
// ExternalVerifierBootstrap
// ---------------------------------------------------------------------------

/// Bootstrap payload for external verifiers to re-execute and diff.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ExternalVerifierBootstrap {
    pub schema_version: String,
    pub manifest: ReproducibilityManifest,
    pub gate_results: Vec<DemoGateResult>,
    pub verification_instructions: String,
    pub expected_output_hash: String,
}

impl ExternalVerifierBootstrap {
    /// Create a bootstrap from a manifest and results.
    pub fn new(manifest: ReproducibilityManifest, gate_results: Vec<DemoGateResult>) -> Self {
        let hash_input =
            serde_json::to_string(&gate_results).unwrap_or_else(|e| format!("__serde_err:{e}"));
        let expected_hash = hex::encode(Sha256::digest(
            [b"frontier_demo_hash_v1:" as &[u8], hash_input.as_bytes()].concat(),
        ));
        Self {
            schema_version: SCHEMA_VERSION.to_string(),
            manifest,
            gate_results,
            verification_instructions: concat!(
                "1. Checkout the git commit in manifest.git_commit_hash.\n",
                "2. Execute each gate in isolation using DemoGateRunner.\n",
                "3. Compare output_fingerprints byte-for-byte.\n",
                "4. Verify expected_output_hash matches recomputed hash.",
            )
            .to_string(),
            expected_output_hash: expected_hash,
        }
    }

    /// Verify that the provided results match the expected hash.
    pub fn verify_results(&self, results: &[DemoGateResult]) -> bool {
        let hash_input =
            serde_json::to_string(results).unwrap_or_else(|e| format!("__serde_err:{e}"));
        let computed = hex::encode(Sha256::digest(
            [b"frontier_demo_hash_v1:" as &[u8], hash_input.as_bytes()].concat(),
        ));
        crate::security::constant_time::ct_eq(&computed, &self.expected_output_hash)
    }
}

// ---------------------------------------------------------------------------
// DemoGateRunner
// ---------------------------------------------------------------------------

/// Runner that discovers and executes registered frontier demo gates in
/// isolation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DemoGateRunner {
    pub schema_version: String,
    pub registered_programs: Vec<FrontierProgram>,
    pub results: Vec<DemoGateResult>,
    pub events: Vec<DemoEvent>,
}

/// An event produced during gate execution.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DemoEvent {
    pub code: String,
    pub program: Option<FrontierProgram>,
    pub detail: String,
    pub timestamp: String,
}

impl Default for DemoGateRunner {
    fn default() -> Self {
        Self {
            schema_version: SCHEMA_VERSION.to_string(),
            registered_programs: FrontierProgram::all().to_vec(),
            results: Vec::new(),
            events: Vec::new(),
        }
    }
}

impl DemoGateRunner {
    /// Create a new runner with all five frontier programs registered.
    pub fn new() -> Self {
        Self::default()
    }

    /// Register an additional program (idempotent if already present).
    pub fn register(&mut self, program: FrontierProgram) {
        if !self.registered_programs.contains(&program) {
            push_bounded(
                &mut self.registered_programs,
                program,
                MAX_REGISTERED_PROGRAMS,
            );
            self.registered_programs.sort();
        }
    }

    /// Execute a single gate and record the result.
    pub fn execute_gate(&mut self, gate: &dyn FrontierDemoGate) -> DemoGateResult {
        let result = gate.execute();
        let event_code = if result.passed {
            event_codes::DEMO_GATE_PASS
        } else {
            event_codes::DEMO_GATE_FAIL
        };
        push_bounded(
            &mut self.events,
            DemoEvent {
                code: event_codes::DEMO_GATE_START.to_string(),
                program: Some(result.program),
                detail: format!("Starting gate for {}", result.program.display_name()),
                timestamp: chrono::Utc::now().to_rfc3339(),
            },
            MAX_EVENTS,
        );
        push_bounded(
            &mut self.events,
            DemoEvent {
                code: event_code.to_string(),
                program: Some(result.program),
                detail: result.detail.clone(),
                timestamp: chrono::Utc::now().to_rfc3339(),
            },
            MAX_EVENTS,
        );
        push_bounded(&mut self.results, result.clone(), MAX_RESULTS);
        result
    }

    /// Execute a list of gates and produce a manifest.
    pub fn run_all(
        &mut self,
        gates: &[&dyn FrontierDemoGate],
        git_commit_hash: &str,
        environment: BTreeMap<String, String>,
    ) -> ReproducibilityManifest {
        let mut input_fps = BTreeMap::new();
        let mut output_fps = BTreeMap::new();
        let mut timing = BTreeMap::new();

        for gate in gates {
            let corpus = gate.input_corpus();
            let result = self.execute_gate(*gate);
            let label = result.program.label().to_string();

            // Compute input fingerprint from corpus
            let corpus_json =
                serde_json::to_string(&corpus).unwrap_or_else(|e| format!("__serde_err:{e}"));
            let input_fp = hex::encode(Sha256::digest(
                [b"frontier_demo_hash_v1:" as &[u8], corpus_json.as_bytes()].concat(),
            ));
            input_fps.insert(label.clone(), input_fp);
            output_fps.insert(label.clone(), result.output_fingerprint.clone());
            timing.insert(label, result.timing_ms);
        }

        let manifest = ReproducibilityManifest::new(
            git_commit_hash.to_string(),
            input_fps,
            output_fps,
            environment,
            timing,
        );

        push_bounded(
            &mut self.events,
            DemoEvent {
                code: event_codes::MANIFEST_GENERATED.to_string(),
                program: None,
                detail: format!("Manifest fingerprint: {}", manifest.manifest_fingerprint),
                timestamp: chrono::Utc::now().to_rfc3339(),
            },
            MAX_EVENTS,
        );

        manifest
    }

    /// Build an `ExternalVerifierBootstrap` from current results and manifest.
    pub fn build_bootstrap(&self, manifest: ReproducibilityManifest) -> ExternalVerifierBootstrap {
        ExternalVerifierBootstrap::new(manifest, self.results.clone())
    }

    /// Return all events collected so far.
    pub fn events(&self) -> &[DemoEvent] {
        &self.events
    }

    /// Return all results collected so far.
    pub fn results(&self) -> &[DemoGateResult] {
        &self.results
    }

    /// Returns true if every executed gate passed.
    pub fn all_passed(&self) -> bool {
        !self.results.is_empty() && self.results.iter().all(|r| r.passed)
    }

    /// Clear results and events for a fresh run.
    pub fn reset(&mut self) {
        self.results.clear();
        self.events.clear();
    }
}

// ---------------------------------------------------------------------------
// Concrete demo gate implementations (for testing / demo purposes)
// ---------------------------------------------------------------------------

/// A concrete demo gate for a given `FrontierProgram`.
#[derive(Debug, Clone)]
pub struct DefaultDemoGate {
    program: FrontierProgram,
    corpus: BTreeMap<String, String>,
    should_pass: bool,
}

impl DefaultDemoGate {
    pub fn new(program: FrontierProgram) -> Self {
        let mut corpus = BTreeMap::new();
        corpus.insert("program".to_string(), program.label().to_string());
        corpus.insert("schema_version".to_string(), SCHEMA_VERSION.to_string());
        Self {
            program,
            corpus,
            should_pass: true,
        }
    }

    pub fn with_pass(mut self, pass: bool) -> Self {
        self.should_pass = pass;
        self
    }

    pub fn with_corpus(mut self, key: &str, value: &str) -> Self {
        self.corpus.insert(key.to_string(), value.to_string());
        self
    }
}

impl FrontierDemoGate for DefaultDemoGate {
    fn input_corpus(&self) -> BTreeMap<String, String> {
        self.corpus.clone()
    }

    fn execute(&self) -> DemoGateResult {
        let corpus_json =
            serde_json::to_string(&self.corpus).unwrap_or_else(|e| format!("__serde_err:{e}"));
        let output_fp = hex::encode(Sha256::digest(
            [b"frontier_demo_hash_v1:" as &[u8], corpus_json.as_bytes()].concat(),
        ));
        DemoGateResult {
            program: self.program,
            passed: self.should_pass,
            timing_ms: 42,
            resource_metrics: ResourceMetrics {
                peak_memory_bytes: 1024,
                cpu_time_ms: 10,
                io_operations: 2,
            },
            output_fingerprint: output_fp,
            schema_version: SCHEMA_VERSION.to_string(),
            detail: if self.should_pass {
                format!("{} gate passed", self.program.display_name())
            } else {
                format!("{} gate failed", self.program.display_name())
            },
        }
    }

    fn output_schema(&self) -> String {
        SCHEMA_VERSION.to_string()
    }

    fn attestation(&self) -> String {
        let input = format!("{}:{}", self.program.label(), SCHEMA_VERSION);
        hex::encode(Sha256::digest(
            [b"frontier_demo_hash_v1:" as &[u8], input.as_bytes()].concat(),
        ))
    }
}

// ---------------------------------------------------------------------------
// Fingerprint helper
// ---------------------------------------------------------------------------

/// Compute SHA-256 fingerprint of an arbitrary byte slice.
pub fn sha256_fingerprint(data: &[u8]) -> String {
    hex::encode(Sha256::digest(
        [b"frontier_demo_hash_v1:" as &[u8], data].concat(),
    ))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -- helpers --

    fn all_gates() -> Vec<DefaultDemoGate> {
        FrontierProgram::all()
            .iter()
            .map(|p| DefaultDemoGate::new(*p))
            .collect()
    }

    fn make_env() -> BTreeMap<String, String> {
        let mut env = BTreeMap::new();
        env.insert("os".to_string(), "linux".to_string());
        env.insert("arch".to_string(), "x86_64".to_string());
        env
    }

    // === bounded collection hardening ===

    #[test]
    fn test_push_bounded_zero_capacity_drops_without_panic() {
        let mut values = vec![1, 2, 3];

        push_bounded(&mut values, 4, 0);

        assert!(values.is_empty());
    }

    #[test]
    fn test_push_bounded_overfull_vector_trims_back_to_capacity() {
        let mut values = vec![1, 2, 3, 4];

        push_bounded(&mut values, 5, 2);

        assert_eq!(values, vec![4, 5]);
    }

    #[test]
    fn test_push_bounded_capacity_one_keeps_newest_item_only() {
        let mut values = vec![10];

        push_bounded(&mut values, 11, 1);

        assert_eq!(values, vec![11]);
    }

    // === FrontierProgram enum ===

    #[test]
    fn test_five_frontier_programs() {
        assert_eq!(FrontierProgram::all().len(), 5);
    }

    #[test]
    fn test_program_labels_unique() {
        let labels: Vec<&str> = FrontierProgram::all().iter().map(|p| p.label()).collect();
        let unique: std::collections::BTreeSet<&str> = labels.iter().copied().collect();
        assert_eq!(labels.len(), unique.len());
    }

    #[test]
    fn test_program_display_names() {
        for p in FrontierProgram::all() {
            assert!(!p.display_name().is_empty());
        }
    }

    #[test]
    fn test_migration_singularity_variant() {
        assert_eq!(
            FrontierProgram::MigrationSingularity.label(),
            "migration_singularity"
        );
    }

    #[test]
    fn test_trust_fabric_variant() {
        assert_eq!(FrontierProgram::TrustFabric.label(), "trust_fabric");
    }

    #[test]
    fn test_verifier_economy_variant() {
        assert_eq!(FrontierProgram::VerifierEconomy.label(), "verifier_economy");
    }

    #[test]
    fn test_operator_intelligence_variant() {
        assert_eq!(
            FrontierProgram::OperatorIntelligence.label(),
            "operator_intelligence"
        );
    }

    #[test]
    fn test_ecosystem_network_effects_variant() {
        assert_eq!(
            FrontierProgram::EcosystemNetworkEffects.label(),
            "ecosystem_network_effects"
        );
    }

    #[test]
    fn test_program_serde_roundtrip() {
        for p in FrontierProgram::all() {
            let json = serde_json::to_string(p).unwrap();
            let back: FrontierProgram = serde_json::from_str(&json).unwrap();
            assert_eq!(*p, back);
        }
    }

    #[test]
    fn test_program_ordering() {
        let mut programs = FrontierProgram::all().to_vec();
        programs.sort();
        // Ordering must be deterministic
        assert_eq!(programs, FrontierProgram::all().to_vec());
    }

    // === DefaultDemoGate ===

    #[test]
    fn test_default_gate_passes() {
        let gate = DefaultDemoGate::new(FrontierProgram::TrustFabric);
        let result = gate.execute();
        assert!(result.passed);
        assert_eq!(result.program, FrontierProgram::TrustFabric);
    }

    #[test]
    fn test_gate_can_fail() {
        let gate = DefaultDemoGate::new(FrontierProgram::TrustFabric).with_pass(false);
        let result = gate.execute();
        assert!(!result.passed);
    }

    #[test]
    fn test_gate_has_timing() {
        let gate = DefaultDemoGate::new(FrontierProgram::MigrationSingularity);
        let result = gate.execute();
        assert!(result.timing_ms > 0);
    }

    #[test]
    fn test_gate_has_resource_metrics() {
        let gate = DefaultDemoGate::new(FrontierProgram::MigrationSingularity);
        let result = gate.execute();
        assert!(result.resource_metrics.peak_memory_bytes > 0);
    }

    #[test]
    fn test_gate_output_fingerprint_is_sha256() {
        let gate = DefaultDemoGate::new(FrontierProgram::TrustFabric);
        let result = gate.execute();
        assert_eq!(result.output_fingerprint.len(), 64);
        assert!(
            result
                .output_fingerprint
                .chars()
                .all(|c| c.is_ascii_hexdigit())
        );
    }

    #[test]
    fn test_gate_schema_version() {
        let gate = DefaultDemoGate::new(FrontierProgram::TrustFabric);
        let result = gate.execute();
        assert_eq!(result.schema_version, SCHEMA_VERSION);
    }

    #[test]
    fn test_gate_input_corpus_deterministic() {
        let g1 = DefaultDemoGate::new(FrontierProgram::TrustFabric);
        let g2 = DefaultDemoGate::new(FrontierProgram::TrustFabric);
        assert_eq!(g1.input_corpus(), g2.input_corpus());
    }

    #[test]
    fn test_gate_output_schema() {
        let gate = DefaultDemoGate::new(FrontierProgram::TrustFabric);
        assert_eq!(gate.output_schema(), SCHEMA_VERSION);
    }

    #[test]
    fn test_gate_attestation_nonempty() {
        let gate = DefaultDemoGate::new(FrontierProgram::TrustFabric);
        let att = gate.attestation();
        assert!(!att.is_empty());
        assert_eq!(att.len(), 64);
    }

    #[test]
    fn test_gate_with_corpus() {
        let gate = DefaultDemoGate::new(FrontierProgram::TrustFabric).with_corpus("extra", "value");
        let corpus = gate.input_corpus();
        assert_eq!(corpus.get("extra").unwrap(), "value");
    }

    // === DemoGateResult serde ===

    #[test]
    fn test_demo_gate_result_serde() {
        let gate = DefaultDemoGate::new(FrontierProgram::VerifierEconomy);
        let result = gate.execute();
        let json = serde_json::to_string(&result).unwrap();
        let back: DemoGateResult = serde_json::from_str(&json).unwrap();
        assert_eq!(result, back);
    }

    // === DemoGateRunner ===

    #[test]
    fn test_runner_default_has_five_programs() {
        let runner = DemoGateRunner::new();
        assert_eq!(runner.registered_programs.len(), 5);
    }

    #[test]
    fn test_runner_execute_gate() {
        let mut runner = DemoGateRunner::new();
        let gate = DefaultDemoGate::new(FrontierProgram::TrustFabric);
        let result = runner.execute_gate(&gate);
        assert!(result.passed);
        assert_eq!(runner.results().len(), 1);
    }

    #[test]
    fn test_runner_events_emitted() {
        let mut runner = DemoGateRunner::new();
        let gate = DefaultDemoGate::new(FrontierProgram::TrustFabric);
        runner.execute_gate(&gate);
        // Should have DEMO_GATE_START + DEMO_GATE_PASS
        let codes: Vec<&str> = runner.events().iter().map(|e| e.code.as_str()).collect();
        assert!(codes.contains(&event_codes::DEMO_GATE_START));
        assert!(codes.contains(&event_codes::DEMO_GATE_PASS));
    }

    #[test]
    fn test_runner_fail_event() {
        let mut runner = DemoGateRunner::new();
        let gate = DefaultDemoGate::new(FrontierProgram::TrustFabric).with_pass(false);
        runner.execute_gate(&gate);
        let codes: Vec<&str> = runner.events().iter().map(|e| e.code.as_str()).collect();
        assert!(codes.contains(&event_codes::DEMO_GATE_FAIL));
    }

    #[test]
    fn test_runner_all_passed_true() {
        let mut runner = DemoGateRunner::new();
        for g in &all_gates() {
            runner.execute_gate(g);
        }
        assert!(runner.all_passed());
    }

    #[test]
    fn test_runner_all_passed_false_when_fail() {
        let mut runner = DemoGateRunner::new();
        let gate = DefaultDemoGate::new(FrontierProgram::TrustFabric).with_pass(false);
        runner.execute_gate(&gate);
        assert!(!runner.all_passed());
    }

    #[test]
    fn test_runner_reset() {
        let mut runner = DemoGateRunner::new();
        let gate = DefaultDemoGate::new(FrontierProgram::TrustFabric);
        runner.execute_gate(&gate);
        assert!(!runner.results().is_empty());
        runner.reset();
        assert!(runner.results().is_empty());
        assert!(runner.events().is_empty());
    }

    #[test]
    fn test_runner_register_idempotent() {
        let mut runner = DemoGateRunner::new();
        runner.register(FrontierProgram::TrustFabric);
        assert_eq!(runner.registered_programs.len(), 5);
    }

    #[test]
    fn test_runner_all_passed_is_false_without_results() {
        let runner = DemoGateRunner::new();
        assert!(!runner.all_passed());
        assert!(runner.results().is_empty());
        assert!(runner.events().is_empty());
    }

    #[test]
    fn test_runner_duplicate_register_does_not_touch_execution_state() {
        let mut runner = DemoGateRunner::new();
        let registered_before = runner.registered_programs.clone();

        runner.register(FrontierProgram::TrustFabric);

        assert_eq!(runner.registered_programs, registered_before);
        assert!(runner.results().is_empty());
        assert!(runner.events().is_empty());
    }

    #[test]
    fn test_failed_gate_records_failure_without_pass_event() {
        let mut runner = DemoGateRunner::new();
        let gate = DefaultDemoGate::new(FrontierProgram::TrustFabric).with_pass(false);

        let result = runner.execute_gate(&gate);

        assert!(!result.passed);
        assert!(!runner.all_passed());
        assert_eq!(runner.results().len(), 1);
        assert!(
            runner
                .events()
                .iter()
                .any(|event| event.code == event_codes::DEMO_GATE_FAIL)
        );
        assert!(
            !runner
                .events()
                .iter()
                .any(|event| event.code == event_codes::DEMO_GATE_PASS)
        );
    }

    // === run_all + manifest ===

    #[test]
    fn test_run_all_produces_manifest() {
        let mut runner = DemoGateRunner::new();
        let gates = all_gates();
        let gate_refs: Vec<&dyn FrontierDemoGate> =
            gates.iter().map(|g| g as &dyn FrontierDemoGate).collect();
        let manifest = runner.run_all(&gate_refs, "abc123", make_env());
        assert_eq!(manifest.git_commit_hash, "abc123");
        assert_eq!(manifest.input_fingerprints.len(), 5);
        assert_eq!(manifest.output_fingerprints.len(), 5);
        assert_eq!(manifest.timing_per_gate.len(), 5);
    }

    #[test]
    fn test_manifest_has_environment() {
        let mut runner = DemoGateRunner::new();
        let gates = all_gates();
        let gate_refs: Vec<&dyn FrontierDemoGate> =
            gates.iter().map(|g| g as &dyn FrontierDemoGate).collect();
        let manifest = runner.run_all(&gate_refs, "abc123", make_env());
        assert!(manifest.environment_metadata.contains_key("os"));
    }

    #[test]
    fn test_manifest_fingerprint_valid() {
        let mut runner = DemoGateRunner::new();
        let gates = all_gates();
        let gate_refs: Vec<&dyn FrontierDemoGate> =
            gates.iter().map(|g| g as &dyn FrontierDemoGate).collect();
        let manifest = runner.run_all(&gate_refs, "abc123", make_env());
        assert!(manifest.validate_fingerprint());
    }

    #[test]
    fn test_manifest_schema_version() {
        let manifest = ReproducibilityManifest::new(
            "hash".to_string(),
            BTreeMap::new(),
            BTreeMap::new(),
            BTreeMap::new(),
            BTreeMap::new(),
        );
        assert_eq!(manifest.schema_version, SCHEMA_VERSION);
    }

    #[test]
    fn test_manifest_deterministic() {
        let mut r1 = DemoGateRunner::new();
        let mut r2 = DemoGateRunner::new();
        let gates = all_gates();
        let refs1: Vec<&dyn FrontierDemoGate> =
            gates.iter().map(|g| g as &dyn FrontierDemoGate).collect();
        let refs2: Vec<&dyn FrontierDemoGate> =
            gates.iter().map(|g| g as &dyn FrontierDemoGate).collect();
        let m1 = r1.run_all(&refs1, "abc", make_env());
        let m2 = r2.run_all(&refs2, "abc", make_env());
        assert_eq!(m1.manifest_fingerprint, m2.manifest_fingerprint);
    }

    #[test]
    fn test_manifest_serde_roundtrip() {
        let manifest = ReproducibilityManifest::new(
            "abc".to_string(),
            BTreeMap::from([("k".to_string(), "v".to_string())]),
            BTreeMap::from([("o".to_string(), "p".to_string())]),
            BTreeMap::new(),
            BTreeMap::from([("g".to_string(), 42)]),
        );
        let json = serde_json::to_string(&manifest).unwrap();
        let back: ReproducibilityManifest = serde_json::from_str(&json).unwrap();
        assert_eq!(manifest, back);
    }

    #[test]
    fn test_manifest_changed_hash_invalidates() {
        let mut manifest = ReproducibilityManifest::new(
            "abc".to_string(),
            BTreeMap::new(),
            BTreeMap::new(),
            BTreeMap::new(),
            BTreeMap::new(),
        );
        manifest.git_commit_hash = "changed".to_string();
        assert!(!manifest.validate_fingerprint());
    }

    #[test]
    fn test_run_all_empty_gate_list_does_not_create_results() {
        let mut runner = DemoGateRunner::new();
        let gates: [&dyn FrontierDemoGate; 0] = [];

        let manifest = runner.run_all(&gates, "abc123", make_env());

        assert!(runner.results().is_empty());
        assert_eq!(runner.events().len(), 1);
        assert_eq!(runner.events()[0].code, event_codes::MANIFEST_GENERATED);
        assert!(manifest.input_fingerprints.is_empty());
        assert!(manifest.output_fingerprints.is_empty());
        assert!(manifest.timing_per_gate.is_empty());
        assert!(!runner.all_passed());
    }

    #[test]
    fn test_run_all_with_failed_gate_preserves_failed_result() {
        let mut runner = DemoGateRunner::new();
        let gate = DefaultDemoGate::new(FrontierProgram::TrustFabric).with_pass(false);
        let gates: [&dyn FrontierDemoGate; 1] = [&gate];

        let manifest = runner.run_all(&gates, "abc123", make_env());

        assert_eq!(runner.results().len(), 1);
        assert!(!runner.results()[0].passed);
        assert!(!runner.all_passed());
        assert!(
            manifest
                .output_fingerprints
                .contains_key(FrontierProgram::TrustFabric.label())
        );
        assert!(
            runner
                .events()
                .iter()
                .any(|event| event.code == event_codes::DEMO_GATE_FAIL)
        );
    }

    #[test]
    fn test_manifest_environment_tamper_invalidates_without_recomputing() {
        let mut manifest = ReproducibilityManifest::new(
            "abc".to_string(),
            BTreeMap::new(),
            BTreeMap::new(),
            make_env(),
            BTreeMap::new(),
        );
        let stored_fingerprint = manifest.manifest_fingerprint.clone();

        manifest
            .environment_metadata
            .insert("arch".to_string(), "arm64".to_string());

        assert!(!manifest.validate_fingerprint());
        assert!(!stored_fingerprint.is_empty());
        assert!(crate::security::constant_time::ct_eq(
            &manifest.manifest_fingerprint,
            &stored_fingerprint
        ));
    }

    #[test]
    fn test_manifest_input_fingerprint_tamper_invalidates_without_recomputing() {
        let mut manifest = ReproducibilityManifest::new(
            "abc".to_string(),
            BTreeMap::from([("trust_fabric".to_string(), sha256_fingerprint(b"input"))]),
            BTreeMap::new(),
            BTreeMap::new(),
            BTreeMap::new(),
        );
        let stored_fingerprint = manifest.manifest_fingerprint.clone();

        manifest
            .input_fingerprints
            .insert("trust_fabric".to_string(), sha256_fingerprint(b"tampered"));

        assert!(!manifest.validate_fingerprint());
        assert!(crate::security::constant_time::ct_eq(
            &manifest.manifest_fingerprint,
            &stored_fingerprint
        ));
    }

    #[test]
    fn test_manifest_output_fingerprint_tamper_invalidates_without_recomputing() {
        let mut manifest = ReproducibilityManifest::new(
            "abc".to_string(),
            BTreeMap::new(),
            BTreeMap::from([("trust_fabric".to_string(), sha256_fingerprint(b"output"))]),
            BTreeMap::new(),
            BTreeMap::new(),
        );

        manifest.output_fingerprints.insert(
            "trust_fabric".to_string(),
            sha256_fingerprint(b"different-output"),
        );

        assert!(!manifest.validate_fingerprint());
    }

    #[test]
    fn test_manifest_timing_tamper_invalidates_without_recomputing() {
        let mut manifest = ReproducibilityManifest::new(
            "abc".to_string(),
            BTreeMap::new(),
            BTreeMap::new(),
            BTreeMap::new(),
            BTreeMap::from([("trust_fabric".to_string(), 42)]),
        );

        manifest
            .timing_per_gate
            .insert("trust_fabric".to_string(), 43);

        assert!(!manifest.validate_fingerprint());
    }

    // === ExternalVerifierBootstrap ===

    #[test]
    fn test_bootstrap_creation() {
        let manifest = ReproducibilityManifest::new(
            "abc".to_string(),
            BTreeMap::new(),
            BTreeMap::new(),
            BTreeMap::new(),
            BTreeMap::new(),
        );
        let gate = DefaultDemoGate::new(FrontierProgram::TrustFabric);
        let result = gate.execute();
        let bootstrap = ExternalVerifierBootstrap::new(manifest.clone(), vec![result.clone()]);
        assert_eq!(bootstrap.schema_version, SCHEMA_VERSION);
        assert!(!bootstrap.expected_output_hash.is_empty());
        assert!(bootstrap.verify_results(&[result]));
    }

    #[test]
    fn test_bootstrap_verify_mismatch() {
        let manifest = ReproducibilityManifest::new(
            "abc".to_string(),
            BTreeMap::new(),
            BTreeMap::new(),
            BTreeMap::new(),
            BTreeMap::new(),
        );
        let gate = DefaultDemoGate::new(FrontierProgram::TrustFabric);
        let result = gate.execute();
        let bootstrap = ExternalVerifierBootstrap::new(manifest, vec![result]);

        let other_gate = DefaultDemoGate::new(FrontierProgram::VerifierEconomy);
        let other_result = other_gate.execute();
        assert!(!bootstrap.verify_results(&[other_result]));
    }

    #[test]
    fn test_bootstrap_empty_expected_results_rejects_extra_result() {
        let manifest = ReproducibilityManifest::new(
            "abc".to_string(),
            BTreeMap::new(),
            BTreeMap::new(),
            BTreeMap::new(),
            BTreeMap::new(),
        );
        let bootstrap = ExternalVerifierBootstrap::new(manifest, vec![]);
        let unexpected = DefaultDemoGate::new(FrontierProgram::TrustFabric).execute();

        assert!(!bootstrap.verify_results(&[unexpected]));
        assert!(bootstrap.gate_results.is_empty());
        assert_eq!(bootstrap.schema_version, SCHEMA_VERSION);
    }

    #[test]
    fn test_bootstrap_rejects_schema_tampered_result() {
        let manifest = ReproducibilityManifest::new(
            "abc".to_string(),
            BTreeMap::new(),
            BTreeMap::new(),
            BTreeMap::new(),
            BTreeMap::new(),
        );
        let gate = DefaultDemoGate::new(FrontierProgram::TrustFabric);
        let result = gate.execute();
        let bootstrap = ExternalVerifierBootstrap::new(manifest, vec![result.clone()]);
        let mut tampered = result;
        tampered.schema_version = "demo-v0.9".to_string();

        assert!(!bootstrap.verify_results(&[tampered]));
        assert_eq!(bootstrap.gate_results.len(), 1);
        assert_eq!(bootstrap.schema_version, SCHEMA_VERSION);
    }

    #[test]
    fn test_bootstrap_rejects_reordered_results() {
        let manifest = ReproducibilityManifest::new(
            "abc".to_string(),
            BTreeMap::new(),
            BTreeMap::new(),
            BTreeMap::new(),
            BTreeMap::new(),
        );
        let trust_result = DefaultDemoGate::new(FrontierProgram::TrustFabric).execute();
        let verifier_result = DefaultDemoGate::new(FrontierProgram::VerifierEconomy).execute();
        let bootstrap = ExternalVerifierBootstrap::new(
            manifest,
            vec![trust_result.clone(), verifier_result.clone()],
        );

        assert!(!bootstrap.verify_results(&[verifier_result, trust_result]));
    }

    #[test]
    fn test_bootstrap_rejects_tampered_output_fingerprint() {
        let manifest = ReproducibilityManifest::new(
            "abc".to_string(),
            BTreeMap::new(),
            BTreeMap::new(),
            BTreeMap::new(),
            BTreeMap::new(),
        );
        let result = DefaultDemoGate::new(FrontierProgram::TrustFabric).execute();
        let bootstrap = ExternalVerifierBootstrap::new(manifest, vec![result.clone()]);
        let mut tampered = result;
        tampered.output_fingerprint = sha256_fingerprint(b"tampered-output");

        assert!(!bootstrap.verify_results(&[tampered]));
    }

    #[test]
    fn test_bootstrap_instructions_nonempty() {
        let manifest = ReproducibilityManifest::new(
            "abc".to_string(),
            BTreeMap::new(),
            BTreeMap::new(),
            BTreeMap::new(),
            BTreeMap::new(),
        );
        let bootstrap = ExternalVerifierBootstrap::new(manifest, vec![]);
        assert!(!bootstrap.verification_instructions.is_empty());
    }

    #[test]
    fn test_bootstrap_serde_roundtrip() {
        let manifest = ReproducibilityManifest::new(
            "abc".to_string(),
            BTreeMap::new(),
            BTreeMap::new(),
            BTreeMap::new(),
            BTreeMap::new(),
        );
        let bootstrap = ExternalVerifierBootstrap::new(manifest, vec![]);
        let json = serde_json::to_string(&bootstrap).unwrap();
        let back: ExternalVerifierBootstrap = serde_json::from_str(&json).unwrap();
        assert_eq!(bootstrap, back);
    }

    // === Event codes ===

    #[test]
    fn test_event_code_demo_gate_start() {
        assert_eq!(event_codes::DEMO_GATE_START, "DEMO-001");
    }

    #[test]
    fn test_event_code_demo_gate_pass() {
        assert_eq!(event_codes::DEMO_GATE_PASS, "DEMO-002");
    }

    #[test]
    fn test_event_code_demo_gate_fail() {
        assert_eq!(event_codes::DEMO_GATE_FAIL, "DEMO-003");
    }

    #[test]
    fn test_event_code_manifest_generated() {
        assert_eq!(event_codes::MANIFEST_GENERATED, "DEMO-004");
    }

    #[test]
    fn test_event_code_external_verify_start() {
        assert_eq!(event_codes::EXTERNAL_VERIFY_START, "DEMO-005");
    }

    #[test]
    fn test_event_code_external_verify_match() {
        assert_eq!(event_codes::EXTERNAL_VERIFY_MATCH, "DEMO-006");
    }

    #[test]
    fn test_event_code_external_verify_mismatch() {
        assert_eq!(event_codes::EXTERNAL_VERIFY_MISMATCH, "DEMO-007");
    }

    // === Error codes ===

    #[test]
    fn test_error_codes_defined() {
        assert!(!error_codes::ERR_DEMO_GATE_NOT_FOUND.is_empty());
        assert!(!error_codes::ERR_DEMO_EXECUTION_FAILED.is_empty());
        assert!(!error_codes::ERR_DEMO_FINGERPRINT_MISMATCH.is_empty());
        assert!(!error_codes::ERR_DEMO_MANIFEST_INVALID.is_empty());
        assert!(!error_codes::ERR_DEMO_BOOTSTRAP_FAILED.is_empty());
        assert!(!error_codes::ERR_DEMO_ISOLATION_VIOLATED.is_empty());
        assert!(!error_codes::ERR_DEMO_SCHEMA_MISMATCH.is_empty());
    }

    // === Invariants ===

    #[test]
    fn test_invariants_defined() {
        assert!(!invariants::INV_DEMO_DETERMINISTIC.is_empty());
        assert!(!invariants::INV_DEMO_ISOLATED.is_empty());
        assert!(!invariants::INV_DEMO_FINGERPRINTED.is_empty());
        assert!(!invariants::INV_DEMO_REPRODUCIBLE.is_empty());
        assert!(!invariants::INV_DEMO_MANIFEST_COMPLETE.is_empty());
        assert!(!invariants::INV_DEMO_SCHEMA_VERSIONED.is_empty());
    }

    // === sha256_fingerprint ===

    #[test]
    fn test_sha256_fingerprint() {
        let fp = sha256_fingerprint(b"hello");
        assert_eq!(fp.len(), 64);
        assert!(fp.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn test_sha256_deterministic() {
        let fp1 = sha256_fingerprint(b"test");
        let fp2 = sha256_fingerprint(b"test");
        assert_eq!(fp1, fp2);
    }

    #[test]
    fn test_sha256_fingerprint_is_domain_separated_from_raw_sha256() {
        let domain_separated = sha256_fingerprint(b"hello");
        let raw = hex::encode(Sha256::digest(b"hello"));

        assert!(!crate::security::constant_time::ct_eq(
            &domain_separated,
            &raw
        ));
    }

    // === ResourceMetrics ===

    #[test]
    fn test_resource_metrics_default() {
        let m = ResourceMetrics::default();
        assert_eq!(m.peak_memory_bytes, 0);
        assert_eq!(m.cpu_time_ms, 0);
        assert_eq!(m.io_operations, 0);
    }

    // === DemoEvent ===

    #[test]
    fn test_demo_event_serde() {
        let event = DemoEvent {
            code: event_codes::DEMO_GATE_START.to_string(),
            program: Some(FrontierProgram::TrustFabric),
            detail: "test".to_string(),
            timestamp: "2026-01-01T00:00:00Z".to_string(),
        };
        let json = serde_json::to_string(&event).unwrap();
        let back: DemoEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(event, back);
    }

    // === DemoGateRunner serde ===

    #[test]
    fn test_runner_serde_roundtrip() {
        let runner = DemoGateRunner::new();
        let json = serde_json::to_string(&runner).unwrap();
        let back: DemoGateRunner = serde_json::from_str(&json).unwrap();
        assert_eq!(back.registered_programs.len(), 5);
    }

    // === Full end-to-end ===

    #[test]
    fn test_full_e2e_five_programs() {
        let mut runner = DemoGateRunner::new();
        let gates = all_gates();
        let gate_refs: Vec<&dyn FrontierDemoGate> =
            gates.iter().map(|g| g as &dyn FrontierDemoGate).collect();
        let manifest = runner.run_all(&gate_refs, "deadbeef", make_env());
        let bootstrap = runner.build_bootstrap(manifest.clone());

        assert!(runner.all_passed());
        assert_eq!(runner.results().len(), 5);
        assert!(manifest.validate_fingerprint());
        assert!(bootstrap.verify_results(runner.results()));

        // All five programs represented in fingerprints
        for p in FrontierProgram::all() {
            assert!(manifest.input_fingerprints.contains_key(p.label()));
            assert!(manifest.output_fingerprints.contains_key(p.label()));
            assert!(manifest.timing_per_gate.contains_key(p.label()));
        }
    }

    #[test]
    fn test_btreemap_ordering_preserved() {
        let mut runner = DemoGateRunner::new();
        let gates = all_gates();
        let gate_refs: Vec<&dyn FrontierDemoGate> =
            gates.iter().map(|g| g as &dyn FrontierDemoGate).collect();
        let manifest = runner.run_all(&gate_refs, "abc", make_env());
        let keys: Vec<&String> = manifest.input_fingerprints.keys().collect();
        let mut sorted = keys.clone();
        sorted.sort();
        assert_eq!(keys, sorted);
    }

    #[test]
    fn negative_frontier_program_deserialize_rejects_display_name() {
        let parsed: Result<FrontierProgram, _> = serde_json::from_str("\"Trust Fabric\"");

        assert!(parsed.is_err());
    }

    #[test]
    fn negative_frontier_program_deserialize_rejects_unknown_label() {
        let parsed: Result<FrontierProgram, _> = serde_json::from_str("\"unknown_program\"");

        assert!(parsed.is_err());
    }

    #[test]
    fn negative_demo_gate_result_deserialize_rejects_missing_program() {
        let raw = serde_json::json!({
            "passed": true,
            "timing_ms": 42_u64,
            "resource_metrics": {
                "peak_memory_bytes": 1024_u64,
                "cpu_time_ms": 10_u64,
                "io_operations": 2_u64
            },
            "output_fingerprint": sha256_fingerprint(b"output"),
            "schema_version": SCHEMA_VERSION,
            "detail": "missing program"
        });

        let parsed: Result<DemoGateResult, _> = serde_json::from_value(raw);

        assert!(parsed.is_err());
    }

    #[test]
    fn negative_demo_gate_result_deserialize_rejects_string_timing() {
        let raw = serde_json::json!({
            "program": "trust_fabric",
            "passed": true,
            "timing_ms": "42",
            "resource_metrics": {
                "peak_memory_bytes": 1024_u64,
                "cpu_time_ms": 10_u64,
                "io_operations": 2_u64
            },
            "output_fingerprint": sha256_fingerprint(b"output"),
            "schema_version": SCHEMA_VERSION,
            "detail": "bad timing type"
        });

        let parsed: Result<DemoGateResult, _> = serde_json::from_value(raw);

        assert!(parsed.is_err());
    }

    #[test]
    fn negative_demo_event_deserialize_rejects_unknown_program_label() {
        let raw = serde_json::json!({
            "code": event_codes::DEMO_GATE_START,
            "program": "not_a_frontier_program",
            "detail": "bad program",
            "timestamp": "2026-04-17T00:00:00Z"
        });

        let parsed: Result<DemoEvent, _> = serde_json::from_value(raw);

        assert!(parsed.is_err());
    }

    #[test]
    fn negative_manifest_deserialize_rejects_string_timing_value() {
        let raw = serde_json::json!({
            "schema_version": SCHEMA_VERSION,
            "git_commit_hash": "abc123",
            "input_fingerprints": {},
            "output_fingerprints": {},
            "environment_metadata": {},
            "timing_per_gate": {"trust_fabric": "42"},
            "manifest_fingerprint": sha256_fingerprint(b"manifest")
        });

        let parsed: Result<ReproducibilityManifest, _> = serde_json::from_value(raw);

        assert!(parsed.is_err());
    }

    #[test]
    fn negative_manifest_validation_rejects_empty_output_fingerprint_mutation() {
        let mut manifest = ReproducibilityManifest::new(
            "abc".to_string(),
            BTreeMap::new(),
            BTreeMap::from([("trust_fabric".to_string(), sha256_fingerprint(b"output"))]),
            BTreeMap::new(),
            BTreeMap::new(),
        );

        manifest
            .output_fingerprints
            .insert("trust_fabric".to_string(), String::new());

        assert!(!manifest.validate_fingerprint());
    }

    #[test]
    fn negative_bootstrap_verify_rejects_missing_expected_result() {
        let manifest = ReproducibilityManifest::new(
            "abc".to_string(),
            BTreeMap::new(),
            BTreeMap::new(),
            BTreeMap::new(),
            BTreeMap::new(),
        );
        let trust_result = DefaultDemoGate::new(FrontierProgram::TrustFabric).execute();
        let verifier_result = DefaultDemoGate::new(FrontierProgram::VerifierEconomy).execute();
        let bootstrap =
            ExternalVerifierBootstrap::new(manifest, vec![trust_result.clone(), verifier_result]);

        assert!(!bootstrap.verify_results(&[trust_result]));
    }

    #[test]
    fn negative_bootstrap_verify_rejects_extra_duplicate_result() {
        let manifest = ReproducibilityManifest::new(
            "abc".to_string(),
            BTreeMap::new(),
            BTreeMap::new(),
            BTreeMap::new(),
            BTreeMap::new(),
        );
        let result = DefaultDemoGate::new(FrontierProgram::TrustFabric).execute();
        let bootstrap = ExternalVerifierBootstrap::new(manifest, vec![result.clone()]);

        assert!(!bootstrap.verify_results(&[result.clone(), result]));
    }
}
