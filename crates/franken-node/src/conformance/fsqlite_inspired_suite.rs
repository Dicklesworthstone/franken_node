//! bd-3i6c: FrankenSQLite-inspired conformance suite.
//!
//! Normative test fixtures verifying four critical runtime properties:
//! 1. Ledger determinism — identical input ⇒ identical output
//! 2. Idempotency — repeated operations ⇒ same result as single
//! 3. Epoch validity — all epoch invariants hold
//! 4. Marker/MMR proof correctness — proofs verify correctly
//!
//! Each test has a stable conformance ID (FSQL-{domain}-NNN).
//!
//! # Invariants
//!
//! - INV-CONF-DETERMINISTIC: operations produce identical output for identical input
//! - INV-CONF-IDEMPOTENT: repeated operations produce same result as single
//! - INV-CONF-EPOCH-VALID: all epoch-related invariants hold
//! - INV-CONF-PROOF-CORRECT: all proof operations are correct
//! - INV-CONF-STABLE-IDS: conformance IDs are permanent and never reused
//! - INV-CONF-RELEASE-GATE: release builds require all conformance tests passing

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fmt;

/// Schema version for conformance reports.
pub const SCHEMA_VERSION: &str = "cs-v1.0";

/// Conformance suite version.
pub const SUITE_VERSION: &str = "1.0.0";

// ---- Event codes ----

pub mod event_codes {
    pub const CONFORMANCE_SUITE_START: &str = "CONFORMANCE_SUITE_START";
    pub const CONFORMANCE_TEST_PASS: &str = "CONFORMANCE_TEST_PASS";
    pub const CONFORMANCE_TEST_FAIL: &str = "CONFORMANCE_TEST_FAIL";
    pub const CONFORMANCE_SUITE_COMPLETE: &str = "CONFORMANCE_SUITE_COMPLETE";
    pub const CONFORMANCE_FIXTURE_LOADED: &str = "CONFORMANCE_FIXTURE_LOADED";
    pub const CONFORMANCE_REPORT_EXPORTED: &str = "CONFORMANCE_REPORT_EXPORTED";
}

// ---- Error codes ----

pub mod error_codes {
    pub const ERR_CONF_DETERMINISM_MISMATCH: &str = "ERR_CONF_DETERMINISM_MISMATCH";
    pub const ERR_CONF_IDEMPOTENCY_VIOLATION: &str = "ERR_CONF_IDEMPOTENCY_VIOLATION";
    pub const ERR_CONF_EPOCH_INVARIANT_BROKEN: &str = "ERR_CONF_EPOCH_INVARIANT_BROKEN";
    pub const ERR_CONF_PROOF_INVALID: &str = "ERR_CONF_PROOF_INVALID";
    pub const ERR_CONF_DUPLICATE_ID: &str = "ERR_CONF_DUPLICATE_ID";
    pub const ERR_CONF_FIXTURE_PARSE: &str = "ERR_CONF_FIXTURE_PARSE";
    pub const ERR_CONF_RELEASE_BLOCKED: &str = "ERR_CONF_RELEASE_BLOCKED";
    pub const ERR_CONF_MISSING_DOMAIN: &str = "ERR_CONF_MISSING_DOMAIN";
}

// ---- Core types ----

/// Conformance test domains.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum ConformanceDomain {
    Determinism,
    Idempotency,
    EpochValidity,
    ProofCorrectness,
}

impl ConformanceDomain {
    pub fn all() -> &'static [ConformanceDomain] {
        &[
            Self::Determinism,
            Self::Idempotency,
            Self::EpochValidity,
            Self::ProofCorrectness,
        ]
    }

    pub fn prefix(&self) -> &'static str {
        match self {
            Self::Determinism => "FSQL-DET",
            Self::Idempotency => "FSQL-IDP",
            Self::EpochValidity => "FSQL-EPO",
            Self::ProofCorrectness => "FSQL-PRF",
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Determinism => "determinism",
            Self::Idempotency => "idempotency",
            Self::EpochValidity => "epoch_validity",
            Self::ProofCorrectness => "proof_correctness",
        }
    }
}

impl fmt::Display for ConformanceDomain {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// A stable conformance ID (e.g., FSQL-DET-001).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct ConformanceId(pub String);

impl ConformanceId {
    pub fn new(domain: ConformanceDomain, number: u16) -> Self {
        Self(format!("{}-{:03}", domain.prefix(), number))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn domain(&self) -> Option<ConformanceDomain> {
        if self.0.starts_with("FSQL-DET") {
            Some(ConformanceDomain::Determinism)
        } else if self.0.starts_with("FSQL-IDP") {
            Some(ConformanceDomain::Idempotency)
        } else if self.0.starts_with("FSQL-EPO") {
            Some(ConformanceDomain::EpochValidity)
        } else if self.0.starts_with("FSQL-PRF") {
            Some(ConformanceDomain::ProofCorrectness)
        } else {
            None
        }
    }
}

impl fmt::Display for ConformanceId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Result of a single conformance test.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ConformanceTestResult {
    Pass,
    Fail { expected: String, actual: String },
}

/// Record for a single conformance test execution.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConformanceTestRecord {
    pub conformance_id: ConformanceId,
    pub domain: ConformanceDomain,
    pub description: String,
    pub result: ConformanceTestResult,
    pub elapsed_ms: u64,
}

/// Conformance report from a full suite execution.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConformanceReport {
    pub suite_version: String,
    pub schema_version: String,
    pub timestamp_ms: u64,
    pub pass_count: usize,
    pub fail_count: usize,
    pub total_elapsed_ms: u64,
    pub results: Vec<ConformanceTestRecord>,
    pub release_eligible: bool,
}

/// A conformance fixture definition.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConformanceFixture {
    pub conformance_id: ConformanceId,
    pub domain: ConformanceDomain,
    pub description: String,
    pub input: serde_json::Value,
    pub expected: serde_json::Value,
}

/// Audit record for conformance events.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConformanceAuditRecord {
    pub event_code: String,
    pub conformance_id: String,
    pub domain: String,
    pub timestamp_ms: u64,
    pub detail: String,
    pub trace_id: String,
    pub schema_version: String,
}

/// Conformance suite errors.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConformanceError {
    DeterminismMismatch {
        id: String,
        expected: String,
        actual: String,
    },
    IdempotencyViolation {
        id: String,
        detail: String,
    },
    EpochInvariantBroken {
        id: String,
        detail: String,
    },
    ProofInvalid {
        id: String,
        detail: String,
    },
    DuplicateId {
        id: String,
    },
    FixtureParse {
        detail: String,
    },
    ReleaseBlocked {
        fail_count: usize,
    },
    MissingDomain {
        domain: String,
    },
}

impl ConformanceError {
    pub fn code(&self) -> &'static str {
        match self {
            Self::DeterminismMismatch { .. } => error_codes::ERR_CONF_DETERMINISM_MISMATCH,
            Self::IdempotencyViolation { .. } => error_codes::ERR_CONF_IDEMPOTENCY_VIOLATION,
            Self::EpochInvariantBroken { .. } => error_codes::ERR_CONF_EPOCH_INVARIANT_BROKEN,
            Self::ProofInvalid { .. } => error_codes::ERR_CONF_PROOF_INVALID,
            Self::DuplicateId { .. } => error_codes::ERR_CONF_DUPLICATE_ID,
            Self::FixtureParse { .. } => error_codes::ERR_CONF_FIXTURE_PARSE,
            Self::ReleaseBlocked { .. } => error_codes::ERR_CONF_RELEASE_BLOCKED,
            Self::MissingDomain { .. } => error_codes::ERR_CONF_MISSING_DOMAIN,
        }
    }
}

impl fmt::Display for ConformanceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DeterminismMismatch {
                id,
                expected,
                actual,
            } => {
                write!(
                    f,
                    "{}: {} expected={} actual={}",
                    self.code(),
                    id,
                    expected,
                    actual
                )
            }
            Self::IdempotencyViolation { id, detail } => {
                write!(f, "{}: {} {}", self.code(), id, detail)
            }
            Self::EpochInvariantBroken { id, detail } => {
                write!(f, "{}: {} {}", self.code(), id, detail)
            }
            Self::ProofInvalid { id, detail } => {
                write!(f, "{}: {} {}", self.code(), id, detail)
            }
            Self::DuplicateId { id } => {
                write!(f, "{}: {}", self.code(), id)
            }
            Self::FixtureParse { detail } => {
                write!(f, "{}: {}", self.code(), detail)
            }
            Self::ReleaseBlocked { fail_count } => {
                write!(f, "{}: {} failures block release", self.code(), fail_count)
            }
            Self::MissingDomain { domain } => {
                write!(f, "{}: {}", self.code(), domain)
            }
        }
    }
}

/// The conformance suite runner.
pub struct ConformanceSuiteRunner {
    fixtures: Vec<ConformanceFixture>,
    results: Vec<ConformanceTestRecord>,
    audit_log: Vec<ConformanceAuditRecord>,
    id_registry: BTreeMap<String, bool>,
}

impl ConformanceSuiteRunner {
    /// Create a new runner.
    pub fn new() -> Self {
        Self {
            fixtures: Vec::new(),
            results: Vec::new(),
            audit_log: Vec::new(),
            id_registry: BTreeMap::new(),
        }
    }

    /// Register a fixture. Returns error if ID already registered.
    /// INV-CONF-STABLE-IDS
    pub fn register_fixture(
        &mut self,
        fixture: ConformanceFixture,
    ) -> Result<(), ConformanceError> {
        let id_str = fixture.conformance_id.as_str().to_string();
        if self.id_registry.contains_key(&id_str) {
            return Err(ConformanceError::DuplicateId { id: id_str });
        }
        self.id_registry.insert(id_str, true);
        self.fixtures.push(fixture);
        Ok(())
    }

    /// Register the standard set of built-in fixtures.
    pub fn register_builtin_fixtures(&mut self) -> Result<(), ConformanceError> {
        for f in builtin_determinism_fixtures() {
            self.register_fixture(f)?;
        }
        for f in builtin_idempotency_fixtures() {
            self.register_fixture(f)?;
        }
        for f in builtin_epoch_fixtures() {
            self.register_fixture(f)?;
        }
        for f in builtin_proof_fixtures() {
            self.register_fixture(f)?;
        }
        Ok(())
    }

    /// Record a test result.
    pub fn record_result(&mut self, record: ConformanceTestRecord) {
        self.results.push(record);
    }

    /// Run all registered fixtures using the provided test function.
    pub fn run_all<F>(&mut self, timestamp_ms: u64, trace_id: &str, test_fn: F) -> ConformanceReport
    where
        F: Fn(&ConformanceFixture) -> ConformanceTestResult,
    {
        self.audit_log.push(ConformanceAuditRecord {
            event_code: event_codes::CONFORMANCE_SUITE_START.to_string(),
            conformance_id: String::new(),
            domain: String::new(),
            timestamp_ms,
            detail: format!(
                "suite_version={} fixture_count={}",
                SUITE_VERSION,
                self.fixtures.len()
            ),
            trace_id: trace_id.to_string(),
            schema_version: SCHEMA_VERSION.to_string(),
        });

        let mut pass_count = 0_usize;
        let mut fail_count = 0_usize;

        for fixture in &self.fixtures {
            let result = test_fn(fixture);
            let passed = matches!(result, ConformanceTestResult::Pass);

            if passed {
                pass_count += 1;
            } else {
                fail_count += 1;
            }

            let event_code = if passed {
                event_codes::CONFORMANCE_TEST_PASS
            } else {
                event_codes::CONFORMANCE_TEST_FAIL
            };

            self.audit_log.push(ConformanceAuditRecord {
                event_code: event_code.to_string(),
                conformance_id: fixture.conformance_id.to_string(),
                domain: fixture.domain.to_string(),
                timestamp_ms,
                detail: fixture.description.clone(),
                trace_id: trace_id.to_string(),
                schema_version: SCHEMA_VERSION.to_string(),
            });

            self.results.push(ConformanceTestRecord {
                conformance_id: fixture.conformance_id.clone(),
                domain: fixture.domain,
                description: fixture.description.clone(),
                result,
                elapsed_ms: 0,
            });
        }

        let release_eligible = fail_count == 0;

        self.audit_log.push(ConformanceAuditRecord {
            event_code: event_codes::CONFORMANCE_SUITE_COMPLETE.to_string(),
            conformance_id: String::new(),
            domain: String::new(),
            timestamp_ms,
            detail: format!(
                "pass={} fail={} release_eligible={}",
                pass_count, fail_count, release_eligible
            ),
            trace_id: trace_id.to_string(),
            schema_version: SCHEMA_VERSION.to_string(),
        });

        ConformanceReport {
            suite_version: SUITE_VERSION.to_string(),
            schema_version: SCHEMA_VERSION.to_string(),
            timestamp_ms,
            pass_count,
            fail_count,
            total_elapsed_ms: 0,
            results: self.results.clone(),
            release_eligible,
        }
    }

    /// Check release eligibility.
    /// INV-CONF-RELEASE-GATE
    pub fn check_release_gate(&self) -> Result<(), ConformanceError> {
        let fail_count = self
            .results
            .iter()
            .filter(|r| !matches!(r.result, ConformanceTestResult::Pass))
            .count();
        if fail_count > 0 {
            return Err(ConformanceError::ReleaseBlocked { fail_count });
        }
        Ok(())
    }

    /// Get domain coverage counts.
    pub fn domain_coverage(&self) -> BTreeMap<String, usize> {
        let mut coverage = BTreeMap::new();
        for f in &self.fixtures {
            *coverage.entry(f.domain.to_string()).or_insert(0) += 1;
        }
        coverage
    }

    /// Verify all four domains are represented.
    pub fn verify_domain_coverage(&self) -> Result<(), ConformanceError> {
        let coverage = self.domain_coverage();
        for domain in ConformanceDomain::all() {
            if !coverage.contains_key(domain.as_str()) {
                return Err(ConformanceError::MissingDomain {
                    domain: domain.to_string(),
                });
            }
        }
        Ok(())
    }

    /// Export report as JSON.
    pub fn export_report_json(&self, report: &ConformanceReport) -> String {
        serde_json::to_string_pretty(report).unwrap_or_default()
    }

    /// Export audit log as JSONL.
    pub fn export_audit_log_jsonl(&self) -> String {
        self.audit_log
            .iter()
            .map(|r| serde_json::to_string(r).unwrap_or_default())
            .collect::<Vec<_>>()
            .join("\n")
    }

    /// Get fixture count.
    pub fn fixture_count(&self) -> usize {
        self.fixtures.len()
    }

    /// Get results.
    pub fn results(&self) -> &[ConformanceTestRecord] {
        &self.results
    }

    /// Get audit log.
    pub fn audit_log(&self) -> &[ConformanceAuditRecord] {
        &self.audit_log
    }
}

impl Default for ConformanceSuiteRunner {
    fn default() -> Self {
        Self::new()
    }
}

// ---- Built-in fixtures: Determinism (11) ----

fn builtin_determinism_fixtures() -> Vec<ConformanceFixture> {
    vec![
        ConformanceFixture {
            conformance_id: ConformanceId::new(ConformanceDomain::Determinism, 1),
            domain: ConformanceDomain::Determinism,
            description: "SHA-256 of fixed bytes is stable".to_string(),
            input: serde_json::json!({"data": "determinism-fixture-001"}),
            expected: serde_json::json!({"deterministic": true}),
        },
        ConformanceFixture {
            conformance_id: ConformanceId::new(ConformanceDomain::Determinism, 2),
            domain: ConformanceDomain::Determinism,
            description: "SHA-256 of empty input is well-known constant".to_string(),
            input: serde_json::json!({"data": ""}),
            expected: serde_json::json!({"deterministic": true}),
        },
        ConformanceFixture {
            conformance_id: ConformanceId::new(ConformanceDomain::Determinism, 3),
            domain: ConformanceDomain::Determinism,
            description: "BTreeMap iteration is sorted by key".to_string(),
            input: serde_json::json!({"keys": ["zebra", "alpha", "mango"]}),
            expected: serde_json::json!({"sorted": ["alpha", "mango", "zebra"]}),
        },
        ConformanceFixture {
            conformance_id: ConformanceId::new(ConformanceDomain::Determinism, 4),
            domain: ConformanceDomain::Determinism,
            description: "Canonical JSON serialization is byte-identical".to_string(),
            input: serde_json::json!({"object": {"b": 2, "a": 1}}),
            expected: serde_json::json!({"canonical": "{\"a\":1,\"b\":2}"}),
        },
        ConformanceFixture {
            conformance_id: ConformanceId::new(ConformanceDomain::Determinism, 5),
            domain: ConformanceDomain::Determinism,
            description: "Epoch key derivation is reproducible".to_string(),
            input: serde_json::json!({"epoch": 42, "context": "test"}),
            expected: serde_json::json!({"deterministic": true}),
        },
        ConformanceFixture {
            conformance_id: ConformanceId::new(ConformanceDomain::Determinism, 6),
            domain: ConformanceDomain::Determinism,
            description: "Marker hash chain is deterministic".to_string(),
            input: serde_json::json!({"sequence": 0, "payload": "deadbeef"}),
            expected: serde_json::json!({"deterministic": true}),
        },
        ConformanceFixture {
            conformance_id: ConformanceId::new(ConformanceDomain::Determinism, 7),
            domain: ConformanceDomain::Determinism,
            description: "UUID sorting produces identical output".to_string(),
            input: serde_json::json!({"count": 10}),
            expected: serde_json::json!({"sorted": true}),
        },
        ConformanceFixture {
            conformance_id: ConformanceId::new(ConformanceDomain::Determinism, 8),
            domain: ConformanceDomain::Determinism,
            description: "HMAC-SHA256 with fixed key is deterministic".to_string(),
            input: serde_json::json!({"key": "test", "message": "data"}),
            expected: serde_json::json!({"deterministic": true}),
        },
        ConformanceFixture {
            conformance_id: ConformanceId::new(ConformanceDomain::Determinism, 9),
            domain: ConformanceDomain::Determinism,
            description: "Hex encoding is stable".to_string(),
            input: serde_json::json!({"bytes": [0, 1, 127, 128, 255]}),
            expected: serde_json::json!({"hex": "00017f80ff"}),
        },
        ConformanceFixture {
            conformance_id: ConformanceId::new(ConformanceDomain::Determinism, 10),
            domain: ConformanceDomain::Determinism,
            description: "Base64 encoding is stable".to_string(),
            input: serde_json::json!({"data": "Hello"}),
            expected: serde_json::json!({"base64": "SGVsbG8="}),
        },
        ConformanceFixture {
            conformance_id: ConformanceId::new(ConformanceDomain::Determinism, 11),
            domain: ConformanceDomain::Determinism,
            description: "Concurrent commit serialization is deterministic".to_string(),
            input: serde_json::json!({"commits": 5}),
            expected: serde_json::json!({"deterministic": true}),
        },
    ]
}

// ---- Built-in fixtures: Idempotency (10) ----

fn builtin_idempotency_fixtures() -> Vec<ConformanceFixture> {
    vec![
        ConformanceFixture {
            conformance_id: ConformanceId::new(ConformanceDomain::Idempotency, 1),
            domain: ConformanceDomain::Idempotency,
            description: "Double-commit produces same result as single".to_string(),
            input: serde_json::json!({"operation": "commit", "repeats": 2}),
            expected: serde_json::json!({"idempotent": true}),
        },
        ConformanceFixture {
            conformance_id: ConformanceId::new(ConformanceDomain::Idempotency, 2),
            domain: ConformanceDomain::Idempotency,
            description: "Double-epoch-advance yields same epoch".to_string(),
            input: serde_json::json!({"operation": "epoch_advance", "repeats": 2}),
            expected: serde_json::json!({"idempotent": true}),
        },
        ConformanceFixture {
            conformance_id: ConformanceId::new(ConformanceDomain::Idempotency, 3),
            domain: ConformanceDomain::Idempotency,
            description: "Double-marker-append produces single marker".to_string(),
            input: serde_json::json!({"operation": "marker_append", "repeats": 2}),
            expected: serde_json::json!({"idempotent": true}),
        },
        ConformanceFixture {
            conformance_id: ConformanceId::new(ConformanceDomain::Idempotency, 4),
            domain: ConformanceDomain::Idempotency,
            description: "Idempotency key derivation is stable across calls".to_string(),
            input: serde_json::json!({"operation": "key_derive", "repeats": 3}),
            expected: serde_json::json!({"idempotent": true}),
        },
        ConformanceFixture {
            conformance_id: ConformanceId::new(ConformanceDomain::Idempotency, 5),
            domain: ConformanceDomain::Idempotency,
            description: "Dedupe store returns cached outcome on replay".to_string(),
            input: serde_json::json!({"operation": "dedupe_check", "repeats": 2}),
            expected: serde_json::json!({"idempotent": true}),
        },
        ConformanceFixture {
            conformance_id: ConformanceId::new(ConformanceDomain::Idempotency, 6),
            domain: ConformanceDomain::Idempotency,
            description: "Proof generation is idempotent for same input".to_string(),
            input: serde_json::json!({"operation": "proof_generate", "repeats": 2}),
            expected: serde_json::json!({"idempotent": true}),
        },
        ConformanceFixture {
            conformance_id: ConformanceId::new(ConformanceDomain::Idempotency, 7),
            domain: ConformanceDomain::Idempotency,
            description: "Barrier coordination yields same epoch on retry".to_string(),
            input: serde_json::json!({"operation": "barrier_coordinate", "repeats": 2}),
            expected: serde_json::json!({"idempotent": true}),
        },
        ConformanceFixture {
            conformance_id: ConformanceId::new(ConformanceDomain::Idempotency, 8),
            domain: ConformanceDomain::Idempotency,
            description: "Evidence hash is idempotent".to_string(),
            input: serde_json::json!({"operation": "evidence_hash", "repeats": 5}),
            expected: serde_json::json!({"idempotent": true}),
        },
        ConformanceFixture {
            conformance_id: ConformanceId::new(ConformanceDomain::Idempotency, 9),
            domain: ConformanceDomain::Idempotency,
            description: "Snapshot creation is idempotent".to_string(),
            input: serde_json::json!({"operation": "snapshot_create", "repeats": 2}),
            expected: serde_json::json!({"idempotent": true}),
        },
        ConformanceFixture {
            conformance_id: ConformanceId::new(ConformanceDomain::Idempotency, 10),
            domain: ConformanceDomain::Idempotency,
            description: "Policy validation result is idempotent".to_string(),
            input: serde_json::json!({"operation": "policy_validate", "repeats": 3}),
            expected: serde_json::json!({"idempotent": true}),
        },
    ]
}

// ---- Built-in fixtures: Epoch Validity (13) ----

fn builtin_epoch_fixtures() -> Vec<ConformanceFixture> {
    vec![
        ConformanceFixture {
            conformance_id: ConformanceId::new(ConformanceDomain::EpochValidity, 1),
            domain: ConformanceDomain::EpochValidity,
            description: "Epoch monotonicity: new epoch > previous epoch".to_string(),
            input: serde_json::json!({"prev_epoch": 41, "new_epoch": 42}),
            expected: serde_json::json!({"monotonic": true}),
        },
        ConformanceFixture {
            conformance_id: ConformanceId::new(ConformanceDomain::EpochValidity, 2),
            domain: ConformanceDomain::EpochValidity,
            description: "Epoch zero is valid genesis epoch".to_string(),
            input: serde_json::json!({"epoch": 0}),
            expected: serde_json::json!({"valid": true}),
        },
        ConformanceFixture {
            conformance_id: ConformanceId::new(ConformanceDomain::EpochValidity, 3),
            domain: ConformanceDomain::EpochValidity,
            description: "Validity window accepts current epoch".to_string(),
            input: serde_json::json!({"current_epoch": 10, "artifact_epoch": 10, "window": 3}),
            expected: serde_json::json!({"accepted": true}),
        },
        ConformanceFixture {
            conformance_id: ConformanceId::new(ConformanceDomain::EpochValidity, 4),
            domain: ConformanceDomain::EpochValidity,
            description: "Validity window rejects stale epoch".to_string(),
            input: serde_json::json!({"current_epoch": 10, "artifact_epoch": 3, "window": 3}),
            expected: serde_json::json!({"accepted": false}),
        },
        ConformanceFixture {
            conformance_id: ConformanceId::new(ConformanceDomain::EpochValidity, 5),
            domain: ConformanceDomain::EpochValidity,
            description: "Key derivation bound to specific epoch".to_string(),
            input: serde_json::json!({"epoch": 7, "context": "key-derive"}),
            expected: serde_json::json!({"epoch_bound": true}),
        },
        ConformanceFixture {
            conformance_id: ConformanceId::new(ConformanceDomain::EpochValidity, 6),
            domain: ConformanceDomain::EpochValidity,
            description: "Barrier commit advances to proposed epoch".to_string(),
            input: serde_json::json!({"current": 5, "proposed": 6}),
            expected: serde_json::json!({"committed_epoch": 6}),
        },
        ConformanceFixture {
            conformance_id: ConformanceId::new(ConformanceDomain::EpochValidity, 7),
            domain: ConformanceDomain::EpochValidity,
            description: "Barrier abort preserves current epoch".to_string(),
            input: serde_json::json!({"current": 5, "proposed": 6, "abort": true}),
            expected: serde_json::json!({"epoch_after_abort": 5}),
        },
        ConformanceFixture {
            conformance_id: ConformanceId::new(ConformanceDomain::EpochValidity, 8),
            domain: ConformanceDomain::EpochValidity,
            description: "Concurrent barrier rejected during active transition".to_string(),
            input: serde_json::json!({"active_transition": true}),
            expected: serde_json::json!({"rejected": true}),
        },
        ConformanceFixture {
            conformance_id: ConformanceId::new(ConformanceDomain::EpochValidity, 9),
            domain: ConformanceDomain::EpochValidity,
            description: "Max epoch value is handled correctly".to_string(),
            input: serde_json::json!({"epoch": 18446744073709551615_u64}),
            expected: serde_json::json!({"valid": true}),
        },
        ConformanceFixture {
            conformance_id: ConformanceId::new(ConformanceDomain::EpochValidity, 10),
            domain: ConformanceDomain::EpochValidity,
            description: "Epoch transition timeout triggers abort".to_string(),
            input: serde_json::json!({"timeout_ms": 5000}),
            expected: serde_json::json!({"aborted": true}),
        },
        ConformanceFixture {
            conformance_id: ConformanceId::new(ConformanceDomain::EpochValidity, 11),
            domain: ConformanceDomain::EpochValidity,
            description: "Drain ACK from all participants triggers commit".to_string(),
            input: serde_json::json!({"participants": 3, "acks": 3}),
            expected: serde_json::json!({"committed": true}),
        },
        ConformanceFixture {
            conformance_id: ConformanceId::new(ConformanceDomain::EpochValidity, 12),
            domain: ConformanceDomain::EpochValidity,
            description: "Partial drain ACKs do not commit".to_string(),
            input: serde_json::json!({"participants": 3, "acks": 2}),
            expected: serde_json::json!({"committed": false}),
        },
        ConformanceFixture {
            conformance_id: ConformanceId::new(ConformanceDomain::EpochValidity, 13),
            domain: ConformanceDomain::EpochValidity,
            description: "Force transition policy requires explicit operator identity".to_string(),
            input: serde_json::json!({"force": true, "operator": "admin-1"}),
            expected: serde_json::json!({"requires_operator": true}),
        },
    ]
}

// ---- Built-in fixtures: Proof Correctness (11) ----

fn builtin_proof_fixtures() -> Vec<ConformanceFixture> {
    vec![
        ConformanceFixture {
            conformance_id: ConformanceId::new(ConformanceDomain::ProofCorrectness, 1),
            domain: ConformanceDomain::ProofCorrectness,
            description: "MMR inclusion proof verifies for present leaf".to_string(),
            input: serde_json::json!({"leaf_index": 0, "tree_size": 4}),
            expected: serde_json::json!({"proof_valid": true}),
        },
        ConformanceFixture {
            conformance_id: ConformanceId::new(ConformanceDomain::ProofCorrectness, 2),
            domain: ConformanceDomain::ProofCorrectness,
            description: "MMR inclusion proof rejects tampered leaf".to_string(),
            input: serde_json::json!({"tampered": true}),
            expected: serde_json::json!({"proof_valid": false}),
        },
        ConformanceFixture {
            conformance_id: ConformanceId::new(ConformanceDomain::ProofCorrectness, 3),
            domain: ConformanceDomain::ProofCorrectness,
            description: "Prefix proof validates history consistency".to_string(),
            input: serde_json::json!({"old_size": 3, "new_size": 7}),
            expected: serde_json::json!({"consistent": true}),
        },
        ConformanceFixture {
            conformance_id: ConformanceId::new(ConformanceDomain::ProofCorrectness, 4),
            domain: ConformanceDomain::ProofCorrectness,
            description: "Divergence detection catches forked history".to_string(),
            input: serde_json::json!({"fork_point": 5}),
            expected: serde_json::json!({"divergence_detected": true}),
        },
        ConformanceFixture {
            conformance_id: ConformanceId::new(ConformanceDomain::ProofCorrectness, 5),
            domain: ConformanceDomain::ProofCorrectness,
            description: "Marker hash-chain verification succeeds for valid chain".to_string(),
            input: serde_json::json!({"chain_length": 10}),
            expected: serde_json::json!({"chain_valid": true}),
        },
        ConformanceFixture {
            conformance_id: ConformanceId::new(ConformanceDomain::ProofCorrectness, 6),
            domain: ConformanceDomain::ProofCorrectness,
            description: "Marker hash-chain rejects broken link".to_string(),
            input: serde_json::json!({"broken_link": 5}),
            expected: serde_json::json!({"chain_valid": false}),
        },
        ConformanceFixture {
            conformance_id: ConformanceId::new(ConformanceDomain::ProofCorrectness, 7),
            domain: ConformanceDomain::ProofCorrectness,
            description: "Empty tree proof is trivially valid".to_string(),
            input: serde_json::json!({"tree_size": 0}),
            expected: serde_json::json!({"proof_valid": true}),
        },
        ConformanceFixture {
            conformance_id: ConformanceId::new(ConformanceDomain::ProofCorrectness, 8),
            domain: ConformanceDomain::ProofCorrectness,
            description: "Single-leaf tree proof is valid".to_string(),
            input: serde_json::json!({"tree_size": 1}),
            expected: serde_json::json!({"proof_valid": true}),
        },
        ConformanceFixture {
            conformance_id: ConformanceId::new(ConformanceDomain::ProofCorrectness, 9),
            domain: ConformanceDomain::ProofCorrectness,
            description: "Large tree proof (1000 leaves) is valid".to_string(),
            input: serde_json::json!({"tree_size": 1000}),
            expected: serde_json::json!({"proof_valid": true}),
        },
        ConformanceFixture {
            conformance_id: ConformanceId::new(ConformanceDomain::ProofCorrectness, 10),
            domain: ConformanceDomain::ProofCorrectness,
            description: "Root pointer publication proof is verifiable".to_string(),
            input: serde_json::json!({"root_pointer": true}),
            expected: serde_json::json!({"proof_valid": true}),
        },
        ConformanceFixture {
            conformance_id: ConformanceId::new(ConformanceDomain::ProofCorrectness, 11),
            domain: ConformanceDomain::ProofCorrectness,
            description: "Recomputed root matches published root".to_string(),
            input: serde_json::json!({"leaves": 8}),
            expected: serde_json::json!({"root_matches": true}),
        },
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_runner_with_builtins() -> ConformanceSuiteRunner {
        let mut runner = ConformanceSuiteRunner::new();
        runner.register_builtin_fixtures().unwrap();
        runner
    }

    // ---- ConformanceDomain ----

    #[test]
    fn domain_all_has_four() {
        assert_eq!(ConformanceDomain::all().len(), 4);
    }

    #[test]
    fn domain_prefix_format() {
        assert_eq!(ConformanceDomain::Determinism.prefix(), "FSQL-DET");
        assert_eq!(ConformanceDomain::Idempotency.prefix(), "FSQL-IDP");
        assert_eq!(ConformanceDomain::EpochValidity.prefix(), "FSQL-EPO");
        assert_eq!(ConformanceDomain::ProofCorrectness.prefix(), "FSQL-PRF");
    }

    #[test]
    fn domain_display() {
        assert_eq!(ConformanceDomain::Determinism.to_string(), "determinism");
        assert_eq!(
            ConformanceDomain::EpochValidity.to_string(),
            "epoch_validity"
        );
    }

    // ---- ConformanceId ----

    #[test]
    fn conformance_id_format() {
        let id = ConformanceId::new(ConformanceDomain::Determinism, 1);
        assert_eq!(id.as_str(), "FSQL-DET-001");
    }

    #[test]
    fn conformance_id_domain_parse() {
        let id = ConformanceId::new(ConformanceDomain::Idempotency, 5);
        assert_eq!(id.domain(), Some(ConformanceDomain::Idempotency));
    }

    // ---- Builtin fixtures ----

    #[test]
    fn builtin_determinism_at_least_10() {
        assert_eq!(
            builtin_determinism_fixtures().len(),
            11,
            "determinism fixture count drift"
        );
    }

    #[test]
    fn builtin_idempotency_at_least_8() {
        assert_eq!(
            builtin_idempotency_fixtures().len(),
            10,
            "idempotency fixture count drift"
        );
    }

    #[test]
    fn builtin_epoch_at_least_12() {
        assert_eq!(
            builtin_epoch_fixtures().len(),
            13,
            "epoch fixture count drift"
        );
    }

    #[test]
    fn builtin_proof_at_least_10() {
        assert_eq!(
            builtin_proof_fixtures().len(),
            11,
            "proof fixture count drift"
        );
    }

    #[test]
    fn total_fixtures_at_least_40() {
        let total = builtin_determinism_fixtures().len()
            + builtin_idempotency_fixtures().len()
            + builtin_epoch_fixtures().len()
            + builtin_proof_fixtures().len();
        assert_eq!(total, 45, "total fixture count drift: {total}");
    }

    // ---- Runner ----

    #[test]
    fn runner_registers_builtins() {
        let runner = make_runner_with_builtins();
        assert_eq!(runner.fixture_count(), 45, "runner fixture count drift");
    }

    #[test]
    fn runner_rejects_duplicate_ids() {
        let mut runner = ConformanceSuiteRunner::new();
        let f1 = ConformanceFixture {
            conformance_id: ConformanceId::new(ConformanceDomain::Determinism, 1),
            domain: ConformanceDomain::Determinism,
            description: "test".to_string(),
            input: serde_json::json!({}),
            expected: serde_json::json!({}),
        };
        runner.register_fixture(f1.clone()).unwrap();
        let err = runner.register_fixture(f1).unwrap_err();
        assert_eq!(err.code(), error_codes::ERR_CONF_DUPLICATE_ID);
    }

    // ---- Run all ----

    #[test]
    fn run_all_passing() {
        let mut runner = make_runner_with_builtins();
        let report = runner.run_all(1000, "t1", |_| ConformanceTestResult::Pass);
        assert!(report.release_eligible);
        assert_eq!(report.fail_count, 0);
        assert_eq!(report.pass_count, 45);
    }

    #[test]
    fn run_all_with_failure_blocks_release() {
        let mut runner = ConformanceSuiteRunner::new();
        runner
            .register_fixture(ConformanceFixture {
                conformance_id: ConformanceId::new(ConformanceDomain::Determinism, 1),
                domain: ConformanceDomain::Determinism,
                description: "fail test".to_string(),
                input: serde_json::json!({}),
                expected: serde_json::json!({}),
            })
            .unwrap();
        let report = runner.run_all(1000, "t1", |_| ConformanceTestResult::Fail {
            expected: "x".to_string(),
            actual: "y".to_string(),
        });
        assert!(!report.release_eligible);
        assert_eq!(report.fail_count, 1);
    }

    // ---- Release gate ----

    #[test]
    fn release_gate_passes_on_all_pass() {
        let mut runner = make_runner_with_builtins();
        runner.run_all(1000, "t1", |_| ConformanceTestResult::Pass);
        assert!(runner.check_release_gate().is_ok());
    }

    #[test]
    fn release_gate_blocks_on_failure() {
        let mut runner = ConformanceSuiteRunner::new();
        runner
            .register_fixture(ConformanceFixture {
                conformance_id: ConformanceId::new(ConformanceDomain::Determinism, 1),
                domain: ConformanceDomain::Determinism,
                description: "test".to_string(),
                input: serde_json::json!({}),
                expected: serde_json::json!({}),
            })
            .unwrap();
        runner.run_all(1000, "t1", |_| ConformanceTestResult::Fail {
            expected: "a".to_string(),
            actual: "b".to_string(),
        });
        let err = runner.check_release_gate().unwrap_err();
        assert_eq!(err.code(), error_codes::ERR_CONF_RELEASE_BLOCKED);
    }

    // ---- Domain coverage ----

    #[test]
    fn domain_coverage_all_four() {
        let runner = make_runner_with_builtins();
        let coverage = runner.domain_coverage();
        assert!(coverage.contains_key("determinism"));
        assert!(coverage.contains_key("idempotency"));
        assert!(coverage.contains_key("epoch_validity"));
        assert!(coverage.contains_key("proof_correctness"));
    }

    #[test]
    fn verify_domain_coverage_passes() {
        let runner = make_runner_with_builtins();
        assert!(runner.verify_domain_coverage().is_ok());
    }

    #[test]
    fn verify_domain_coverage_fails_if_missing() {
        let mut runner = ConformanceSuiteRunner::new();
        runner
            .register_fixture(ConformanceFixture {
                conformance_id: ConformanceId::new(ConformanceDomain::Determinism, 1),
                domain: ConformanceDomain::Determinism,
                description: "test".to_string(),
                input: serde_json::json!({}),
                expected: serde_json::json!({}),
            })
            .unwrap();
        let err = runner.verify_domain_coverage().unwrap_err();
        assert_eq!(err.code(), error_codes::ERR_CONF_MISSING_DOMAIN);
    }

    // ---- Report ----

    #[test]
    fn report_json_export() {
        let mut runner = make_runner_with_builtins();
        let report = runner.run_all(1000, "t1", |_| ConformanceTestResult::Pass);
        let json = runner.export_report_json(&report);
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed["suite_version"], SUITE_VERSION);
        assert_eq!(parsed["schema_version"], SCHEMA_VERSION);
        assert!(parsed["release_eligible"].as_bool().unwrap());
    }

    // ---- Audit log ----

    #[test]
    fn audit_log_records_suite_lifecycle() {
        let mut runner = make_runner_with_builtins();
        runner.run_all(1000, "t1", |_| ConformanceTestResult::Pass);

        let log = runner.audit_log();
        assert!(!log.is_empty());
        assert_eq!(log[0].event_code, event_codes::CONFORMANCE_SUITE_START);
        assert_eq!(
            log.last().unwrap().event_code,
            event_codes::CONFORMANCE_SUITE_COMPLETE
        );
    }

    #[test]
    fn audit_export_jsonl() {
        let mut runner = make_runner_with_builtins();
        runner.run_all(1000, "t1", |_| ConformanceTestResult::Pass);
        let jsonl = runner.export_audit_log_jsonl();
        assert!(!jsonl.is_empty());
        let first: serde_json::Value = serde_json::from_str(jsonl.lines().next().unwrap()).unwrap();
        assert_eq!(first["schema_version"], SCHEMA_VERSION);
    }

    // ---- Conformance IDs uniqueness ----

    #[test]
    fn all_builtin_ids_are_unique() {
        let mut ids = std::collections::BTreeSet::new();
        for f in builtin_determinism_fixtures()
            .into_iter()
            .chain(builtin_idempotency_fixtures())
            .chain(builtin_epoch_fixtures())
            .chain(builtin_proof_fixtures())
        {
            assert!(
                ids.insert(f.conformance_id.as_str().to_string()),
                "duplicate ID: {}",
                f.conformance_id
            );
        }
    }

    // ---- Error display ----

    #[test]
    fn error_display_all_variants() {
        let errors: Vec<ConformanceError> = vec![
            ConformanceError::DeterminismMismatch {
                id: "x".into(),
                expected: "a".into(),
                actual: "b".into(),
            },
            ConformanceError::IdempotencyViolation {
                id: "x".into(),
                detail: "d".into(),
            },
            ConformanceError::EpochInvariantBroken {
                id: "x".into(),
                detail: "d".into(),
            },
            ConformanceError::ProofInvalid {
                id: "x".into(),
                detail: "d".into(),
            },
            ConformanceError::DuplicateId { id: "x".into() },
            ConformanceError::FixtureParse { detail: "d".into() },
            ConformanceError::ReleaseBlocked { fail_count: 3 },
            ConformanceError::MissingDomain { domain: "d".into() },
        ];
        for e in &errors {
            let s = e.to_string();
            assert!(s.contains(e.code()), "{:?} should contain {}", e, e.code());
        }
    }

    // ---- ConformanceTestResult ----

    #[test]
    fn test_result_pass_serializes() {
        let r = ConformanceTestResult::Pass;
        let json = serde_json::to_string(&r).unwrap();
        assert!(json.contains("Pass"));
    }

    #[test]
    fn test_result_fail_serializes() {
        let r = ConformanceTestResult::Fail {
            expected: "x".to_string(),
            actual: "y".to_string(),
        };
        let json = serde_json::to_string(&r).unwrap();
        assert!(json.contains("Fail"));
    }

    // ---- Schema constants ----

    #[test]
    fn schema_version_constant() {
        assert_eq!(SCHEMA_VERSION, "cs-v1.0");
    }

    #[test]
    fn suite_version_constant() {
        assert_eq!(SUITE_VERSION, "1.0.0");
    }
}
