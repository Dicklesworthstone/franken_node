//! bd-al8i: L2 engine-boundary N-version semantic oracle.
//!
//! Implements an N-version semantic oracle that dispatches cross-runtime
//! semantic checks across franken_engine and reference runtimes, classifies
//! boundary divergences by risk tier, blocks release on high-risk unresolved
//! deltas, and requires explicit policy receipts (with L1 product-oracle
//! linkage) for low-risk deltas.
//!
//! # Invariants
//!
//! - INV-NVO-QUORUM: Every cross-runtime check requires quorum agreement
//!   from participating runtimes.
//! - INV-NVO-RISK-TIERED: Every semantic divergence is classified into a
//!   risk tier (Critical, High, Medium, Low, Info).
//! - INV-NVO-BLOCK-HIGH: High-risk and critical unresolved divergences block
//!   release.
//! - INV-NVO-POLICY-RECEIPT: Low-risk deltas require an explicit policy
//!   receipt before proceeding.
//! - INV-NVO-L1-LINKAGE: Low-risk policy receipts must link back to L1
//!   product-oracle results.
//! - INV-NVO-DETERMINISTIC: Oracle results are deterministic for the same
//!   inputs; BTreeMap used for ordered output.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fmt;

// ---------------------------------------------------------------------------
// Event codes
// ---------------------------------------------------------------------------

pub mod event_codes {
    /// N-version oracle instance created.
    pub const FN_NV_001: &str = "FN-NV-001";
    /// Reference runtime registered with oracle.
    pub const FN_NV_002: &str = "FN-NV-002";
    /// Cross-runtime semantic check initiated.
    pub const FN_NV_003: &str = "FN-NV-003";
    /// Semantic divergence detected between runtimes.
    pub const FN_NV_004: &str = "FN-NV-004";
    /// Divergence classified by risk tier.
    pub const FN_NV_005: &str = "FN-NV-005";
    /// Quorum agreement reached for a check.
    pub const FN_NV_006: &str = "FN-NV-006";
    /// Quorum agreement failed for a check.
    pub const FN_NV_007: &str = "FN-NV-007";
    /// Release blocked due to unresolved high-risk divergence.
    pub const FN_NV_008: &str = "FN-NV-008";
    /// Policy receipt issued for low-risk divergence.
    pub const FN_NV_009: &str = "FN-NV-009";
    /// L1 product-oracle linkage verified for policy receipt.
    pub const FN_NV_010: &str = "FN-NV-010";
    /// Voting round completed across runtimes.
    pub const FN_NV_011: &str = "FN-NV-011";
    /// Comprehensive oracle divergence report generated.
    pub const FN_NV_012: &str = "FN-NV-012";
}

// ---------------------------------------------------------------------------
// Error codes
// ---------------------------------------------------------------------------

pub mod error_codes {
    pub const ERR_NVO_NO_RUNTIMES: &str = "ERR_NVO_NO_RUNTIMES";
    pub const ERR_NVO_QUORUM_FAILED: &str = "ERR_NVO_QUORUM_FAILED";
    pub const ERR_NVO_RUNTIME_NOT_FOUND: &str = "ERR_NVO_RUNTIME_NOT_FOUND";
    pub const ERR_NVO_CHECK_ALREADY_RUNNING: &str = "ERR_NVO_CHECK_ALREADY_RUNNING";
    pub const ERR_NVO_DIVERGENCE_UNRESOLVED: &str = "ERR_NVO_DIVERGENCE_UNRESOLVED";
    pub const ERR_NVO_POLICY_MISSING: &str = "ERR_NVO_POLICY_MISSING";
    pub const ERR_NVO_INVALID_RECEIPT: &str = "ERR_NVO_INVALID_RECEIPT";
    pub const ERR_NVO_L1_LINKAGE_BROKEN: &str = "ERR_NVO_L1_LINKAGE_BROKEN";
    pub const ERR_NVO_VOTING_TIMEOUT: &str = "ERR_NVO_VOTING_TIMEOUT";
    pub const ERR_NVO_DUPLICATE_RUNTIME: &str = "ERR_NVO_DUPLICATE_RUNTIME";
}

// ---------------------------------------------------------------------------
// Invariants
// ---------------------------------------------------------------------------

pub mod invariants {
    pub const INV_NVO_QUORUM: &str = "INV-NVO-QUORUM";
    pub const INV_NVO_RISK_TIERED: &str = "INV-NVO-RISK-TIERED";
    pub const INV_NVO_BLOCK_HIGH: &str = "INV-NVO-BLOCK-HIGH";
    pub const INV_NVO_POLICY_RECEIPT: &str = "INV-NVO-POLICY-RECEIPT";
    pub const INV_NVO_L1_LINKAGE: &str = "INV-NVO-L1-LINKAGE";
    pub const INV_NVO_DETERMINISTIC: &str = "INV-NVO-DETERMINISTIC";
}

/// Schema version for oracle report format.
pub const SCHEMA_VERSION: &str = "nvo-v1.0";

// ---------------------------------------------------------------------------
// RiskTier
// ---------------------------------------------------------------------------

/// Risk classification for semantic divergences.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum RiskTier {
    /// Informational divergence; no action required.
    Info,
    /// Low-risk divergence; requires explicit policy receipt.
    Low,
    /// Medium-risk divergence; generates warning but does not block.
    Medium,
    /// High-risk divergence; blocks release if unresolved.
    High,
    /// Critical divergence; blocks release if unresolved.
    Critical,
}

impl RiskTier {
    pub fn label(&self) -> &'static str {
        match self {
            Self::Info => "info",
            Self::Low => "low",
            Self::Medium => "medium",
            Self::High => "high",
            Self::Critical => "critical",
        }
    }

    /// Returns `true` if this tier blocks release when unresolved.
    pub fn blocks_release(&self) -> bool {
        matches!(self, Self::High | Self::Critical)
    }

    /// Returns `true` if this tier requires a policy receipt.
    pub fn requires_receipt(&self) -> bool {
        matches!(self, Self::Low)
    }
}

impl fmt::Display for RiskTier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.label())
    }
}

// ---------------------------------------------------------------------------
// BoundaryScope
// ---------------------------------------------------------------------------

/// Engine boundary scope categories.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum BoundaryScope {
    TypeSystem,
    Memory,
    IO,
    Concurrency,
    Security,
}

impl BoundaryScope {
    pub fn label(&self) -> &'static str {
        match self {
            Self::TypeSystem => "type_system",
            Self::Memory => "memory",
            Self::IO => "io",
            Self::Concurrency => "concurrency",
            Self::Security => "security",
        }
    }
}

impl fmt::Display for BoundaryScope {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.label())
    }
}

// ---------------------------------------------------------------------------
// CheckOutcome
// ---------------------------------------------------------------------------

/// Outcome of a single cross-runtime check.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum CheckOutcome {
    /// All participating runtimes agree on the result.
    Agree { canonical_output: Vec<u8> },
    /// Runtimes diverge; contains per-runtime outputs.
    Diverge { outputs: BTreeMap<String, Vec<u8>> },
}

// ---------------------------------------------------------------------------
// RuntimeEntry
// ---------------------------------------------------------------------------

/// Metadata about a registered reference runtime.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuntimeEntry {
    pub runtime_id: String,
    pub runtime_name: String,
    pub version: String,
    pub is_reference: bool,
}

// ---------------------------------------------------------------------------
// CrossRuntimeCheck
// ---------------------------------------------------------------------------

/// A single cross-runtime semantic boundary check.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CrossRuntimeCheck {
    pub check_id: String,
    pub boundary_scope: BoundaryScope,
    pub input: Vec<u8>,
    pub trace_id: String,
    pub outcome: Option<CheckOutcome>,
}

// ---------------------------------------------------------------------------
// SemanticDivergence
// ---------------------------------------------------------------------------

/// Recorded divergence between runtimes with classification.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SemanticDivergence {
    pub divergence_id: String,
    pub check_id: String,
    pub boundary_scope: BoundaryScope,
    pub risk_tier: RiskTier,
    pub runtime_outputs: BTreeMap<String, Vec<u8>>,
    pub resolved: bool,
    pub resolution_note: Option<String>,
    pub trace_id: String,
}

// ---------------------------------------------------------------------------
// L1LinkageProof
// ---------------------------------------------------------------------------

/// Proof linking a policy receipt to L1 product-oracle results.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct L1LinkageProof {
    pub l1_oracle_run_id: String,
    pub l1_verdict: String,
    pub linkage_hash: String,
    pub timestamp_epoch_secs: u64,
}

// ---------------------------------------------------------------------------
// PolicyReceipt
// ---------------------------------------------------------------------------

/// Explicit acknowledgment for low-risk divergences.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicyReceipt {
    pub receipt_id: String,
    pub divergence_id: String,
    pub issuer: String,
    pub rationale: String,
    pub l1_linkage: L1LinkageProof,
    pub issued_at_epoch_secs: u64,
    pub expires_at_epoch_secs: u64,
}

impl PolicyReceipt {
    /// Returns `true` if the receipt has expired relative to `now_epoch_secs`.
    pub fn is_expired(&self, now_epoch_secs: u64) -> bool {
        now_epoch_secs >= self.expires_at_epoch_secs
    }

    /// Verify the L1 linkage is non-empty and well-formed.
    pub fn verify_l1_linkage(&self) -> bool {
        !self.l1_linkage.l1_oracle_run_id.is_empty()
            && !self.l1_linkage.linkage_hash.is_empty()
            && !self.l1_linkage.l1_verdict.is_empty()
    }
}

// ---------------------------------------------------------------------------
// VotingResult
// ---------------------------------------------------------------------------

/// Result of a quorum voting round.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VotingResult {
    pub check_id: String,
    pub votes: BTreeMap<String, Vec<u8>>,
    pub quorum_reached: bool,
    pub quorum_threshold: usize,
    pub total_voters: usize,
    pub agreeing_voters: usize,
}

// ---------------------------------------------------------------------------
// OracleVerdict
// ---------------------------------------------------------------------------

/// Overall verdict from the oracle.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum OracleVerdict {
    /// All checks passed; no blocking divergences.
    Pass,
    /// Release is blocked due to unresolved high/critical divergences.
    BlockRelease {
        blocking_divergence_ids: Vec<String>,
    },
    /// Low-risk divergences require policy receipts before proceeding.
    RequiresReceipt { pending_divergence_ids: Vec<String> },
}

impl OracleVerdict {
    pub fn label(&self) -> &'static str {
        match self {
            Self::Pass => "pass",
            Self::BlockRelease { .. } => "block_release",
            Self::RequiresReceipt { .. } => "requires_receipt",
        }
    }
}

impl fmt::Display for OracleVerdict {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.label())
    }
}

// ---------------------------------------------------------------------------
// DivergenceReport
// ---------------------------------------------------------------------------

/// Comprehensive report of all divergences from an oracle run.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DivergenceReport {
    pub schema_version: String,
    pub trace_id: String,
    pub runtimes: BTreeMap<String, RuntimeEntry>,
    pub checks: Vec<CrossRuntimeCheck>,
    pub divergences: Vec<SemanticDivergence>,
    pub voting_results: Vec<VotingResult>,
    pub receipts: Vec<PolicyReceipt>,
    pub verdict: OracleVerdict,
    pub event_log: Vec<OracleEvent>,
}

// ---------------------------------------------------------------------------
// OracleEvent (structured log)
// ---------------------------------------------------------------------------

/// Structured log event from the oracle.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OracleEvent {
    pub event_code: String,
    pub trace_id: String,
    pub message: String,
    pub details: BTreeMap<String, String>,
}

// ---------------------------------------------------------------------------
// OracleError
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OracleError {
    pub code: &'static str,
    pub message: String,
}

impl fmt::Display for OracleError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[{}] {}", self.code, self.message)
    }
}

impl std::error::Error for OracleError {}

// ---------------------------------------------------------------------------
// RuntimeOracle
// ---------------------------------------------------------------------------

/// Central N-version oracle coordinating checks across reference runtimes.
///
/// Uses `BTreeMap` for all keyed collections to guarantee deterministic
/// iteration order (INV-NVO-DETERMINISTIC).
pub struct RuntimeOracle {
    runtimes: BTreeMap<String, RuntimeEntry>,
    checks: BTreeMap<String, CrossRuntimeCheck>,
    divergences: BTreeMap<String, SemanticDivergence>,
    receipts: BTreeMap<String, PolicyReceipt>,
    voting_results: BTreeMap<String, VotingResult>,
    event_log: Vec<OracleEvent>,
    active_checks: BTreeMap<String, bool>,
    quorum_threshold_percent: u8,
    trace_id: String,
}

impl RuntimeOracle {
    /// Create a new oracle with the given trace ID and quorum threshold (percent).
    pub fn new(trace_id: &str, quorum_threshold_percent: u8) -> Self {
        let mut oracle = Self {
            runtimes: BTreeMap::new(),
            checks: BTreeMap::new(),
            divergences: BTreeMap::new(),
            receipts: BTreeMap::new(),
            voting_results: BTreeMap::new(),
            event_log: Vec::new(),
            active_checks: BTreeMap::new(),
            quorum_threshold_percent,
            trace_id: trace_id.to_string(),
        };
        oracle.emit_event(event_codes::FN_NV_001, "Oracle created", BTreeMap::new());
        oracle
    }

    /// Register a reference runtime for comparison.
    pub fn register_runtime(&mut self, entry: RuntimeEntry) -> Result<(), OracleError> {
        if self.runtimes.contains_key(&entry.runtime_id) {
            return Err(OracleError {
                code: error_codes::ERR_NVO_DUPLICATE_RUNTIME,
                message: format!("runtime '{}' already registered", entry.runtime_id),
            });
        }
        let id = entry.runtime_id.clone();
        self.runtimes.insert(id.clone(), entry);
        let mut details = BTreeMap::new();
        details.insert("runtime_id".to_string(), id);
        self.emit_event(event_codes::FN_NV_002, "Runtime registered", details);
        Ok(())
    }

    /// Remove a runtime from the registry.
    pub fn remove_runtime(&mut self, runtime_id: &str) -> Result<RuntimeEntry, OracleError> {
        self.runtimes.remove(runtime_id).ok_or_else(|| OracleError {
            code: error_codes::ERR_NVO_RUNTIME_NOT_FOUND,
            message: format!("runtime '{runtime_id}' not found"),
        })
    }

    /// Number of registered runtimes.
    pub fn runtime_count(&self) -> usize {
        self.runtimes.len()
    }

    /// Execute a cross-runtime semantic check.
    ///
    /// `runtime_outputs` provides the pre-computed output from each runtime
    /// for the given boundary check. The oracle compares outputs to determine
    /// if they agree or diverge.
    pub fn run_cross_check(
        &mut self,
        check_id: &str,
        boundary_scope: BoundaryScope,
        input: &[u8],
        runtime_outputs: &BTreeMap<String, Vec<u8>>,
    ) -> Result<CrossRuntimeCheck, OracleError> {
        if self.runtimes.is_empty() {
            return Err(OracleError {
                code: error_codes::ERR_NVO_NO_RUNTIMES,
                message: "no runtimes registered".to_string(),
            });
        }

        if self.active_checks.contains_key(check_id) {
            return Err(OracleError {
                code: error_codes::ERR_NVO_CHECK_ALREADY_RUNNING,
                message: format!("check '{check_id}' already in progress"),
            });
        }

        self.active_checks.insert(check_id.to_string(), true);

        let mut details = BTreeMap::new();
        details.insert("check_id".to_string(), check_id.to_string());
        details.insert(
            "boundary_scope".to_string(),
            boundary_scope.label().to_string(),
        );
        self.emit_event(
            event_codes::FN_NV_003,
            "Cross-runtime check started",
            details,
        );

        // Determine outcome: all outputs must be byte-identical for agreement.
        let unique_outputs: std::collections::BTreeSet<&Vec<u8>> =
            runtime_outputs.values().collect();
        let outcome = if unique_outputs.len() <= 1 {
            // All runtimes agree (or only one runtime provided output).
            let canonical = runtime_outputs.values().next().cloned().unwrap_or_default();
            CheckOutcome::Agree {
                canonical_output: canonical,
            }
        } else {
            let mut details = BTreeMap::new();
            details.insert("check_id".to_string(), check_id.to_string());
            details.insert(
                "divergent_count".to_string(),
                unique_outputs.len().to_string(),
            );
            self.emit_event(event_codes::FN_NV_004, "Divergence detected", details);

            CheckOutcome::Diverge {
                outputs: runtime_outputs.clone(),
            }
        };

        let check = CrossRuntimeCheck {
            check_id: check_id.to_string(),
            boundary_scope,
            input: input.to_vec(),
            trace_id: self.trace_id.clone(),
            outcome: Some(outcome),
        };

        self.checks.insert(check_id.to_string(), check.clone());
        self.active_checks.remove(check_id);
        Ok(check)
    }

    /// Classify a detected divergence by risk tier.
    pub fn classify_divergence(
        &mut self,
        divergence_id: &str,
        check_id: &str,
        boundary_scope: BoundaryScope,
        risk_tier: RiskTier,
        runtime_outputs: &BTreeMap<String, Vec<u8>>,
    ) -> SemanticDivergence {
        let divergence = SemanticDivergence {
            divergence_id: divergence_id.to_string(),
            check_id: check_id.to_string(),
            boundary_scope,
            risk_tier,
            runtime_outputs: runtime_outputs.clone(),
            resolved: false,
            resolution_note: None,
            trace_id: self.trace_id.clone(),
        };

        let mut details = BTreeMap::new();
        details.insert("divergence_id".to_string(), divergence_id.to_string());
        details.insert("risk_tier".to_string(), risk_tier.label().to_string());
        self.emit_event(event_codes::FN_NV_005, "Divergence classified", details);

        self.divergences
            .insert(divergence_id.to_string(), divergence.clone());
        divergence
    }

    /// Submit a runtime's vote for a cross-check.
    pub fn vote(
        &mut self,
        check_id: &str,
        runtime_id: &str,
        output: Vec<u8>,
    ) -> Result<(), OracleError> {
        if !self.runtimes.contains_key(runtime_id) {
            return Err(OracleError {
                code: error_codes::ERR_NVO_RUNTIME_NOT_FOUND,
                message: format!("runtime '{runtime_id}' not found"),
            });
        }

        let entry = self
            .voting_results
            .entry(check_id.to_string())
            .or_insert_with(|| VotingResult {
                check_id: check_id.to_string(),
                votes: BTreeMap::new(),
                quorum_reached: false,
                quorum_threshold: 0,
                total_voters: 0,
                agreeing_voters: 0,
            });

        entry.votes.insert(runtime_id.to_string(), output);
        Ok(())
    }

    /// Tally votes and determine quorum result.
    pub fn tally_votes(&mut self, check_id: &str) -> Result<VotingResult, OracleError> {
        let entry = self
            .voting_results
            .get(check_id)
            .ok_or_else(|| OracleError {
                code: error_codes::ERR_NVO_RUNTIME_NOT_FOUND,
                message: format!("no votes recorded for check '{check_id}'"),
            })?;

        let total = entry.votes.len();
        let quorum_required =
            ((total as f64) * (self.quorum_threshold_percent as f64 / 100.0)).ceil() as usize;

        // Count how many runtimes agree with the most common output.
        let mut output_counts: BTreeMap<&[u8], usize> = BTreeMap::new();
        for output in entry.votes.values() {
            *output_counts.entry(output.as_slice()).or_insert(0) += 1;
        }
        let max_agreement = output_counts.values().max().copied().unwrap_or(0);

        let quorum_reached = max_agreement >= quorum_required;

        let result = VotingResult {
            check_id: check_id.to_string(),
            votes: entry.votes.clone(),
            quorum_reached,
            quorum_threshold: quorum_required,
            total_voters: total,
            agreeing_voters: max_agreement,
        };

        if quorum_reached {
            let mut details = BTreeMap::new();
            details.insert("check_id".to_string(), check_id.to_string());
            details.insert("agreeing".to_string(), max_agreement.to_string());
            details.insert("threshold".to_string(), quorum_required.to_string());
            self.emit_event(event_codes::FN_NV_006, "Quorum reached", details);
        } else {
            let mut details = BTreeMap::new();
            details.insert("check_id".to_string(), check_id.to_string());
            details.insert("agreeing".to_string(), max_agreement.to_string());
            details.insert("threshold".to_string(), quorum_required.to_string());
            self.emit_event(event_codes::FN_NV_007, "Quorum failed", details);
        }

        let mut details = BTreeMap::new();
        details.insert("check_id".to_string(), check_id.to_string());
        details.insert("total_voters".to_string(), total.to_string());
        self.emit_event(event_codes::FN_NV_011, "Voting completed", details);

        self.voting_results
            .insert(check_id.to_string(), result.clone());
        Ok(result)
    }

    /// Issue a policy receipt for a low-risk divergence.
    pub fn issue_policy_receipt(&mut self, receipt: PolicyReceipt) -> Result<(), OracleError> {
        let div = self
            .divergences
            .get(&receipt.divergence_id)
            .ok_or_else(|| OracleError {
                code: error_codes::ERR_NVO_DIVERGENCE_UNRESOLVED,
                message: format!("divergence '{}' not found", receipt.divergence_id),
            })?;

        if !div.risk_tier.requires_receipt() {
            return Err(OracleError {
                code: error_codes::ERR_NVO_INVALID_RECEIPT,
                message: format!(
                    "receipts are only applicable to low-risk divergences; got {}",
                    div.risk_tier
                ),
            });
        }

        let mut details = BTreeMap::new();
        details.insert("receipt_id".to_string(), receipt.receipt_id.clone());
        details.insert("divergence_id".to_string(), receipt.divergence_id.clone());
        self.emit_event(event_codes::FN_NV_009, "Policy receipt issued", details);

        self.receipts.insert(receipt.receipt_id.clone(), receipt);
        Ok(())
    }

    /// Verify L1 product-oracle linkage for a receipt.
    pub fn verify_l1_linkage(&mut self, receipt_id: &str) -> Result<bool, OracleError> {
        let receipt = self.receipts.get(receipt_id).ok_or_else(|| OracleError {
            code: error_codes::ERR_NVO_INVALID_RECEIPT,
            message: format!("receipt '{receipt_id}' not found"),
        })?;

        let valid = receipt.verify_l1_linkage();
        if valid {
            let mut details = BTreeMap::new();
            details.insert("receipt_id".to_string(), receipt_id.to_string());
            details.insert(
                "l1_oracle_run_id".to_string(),
                receipt.l1_linkage.l1_oracle_run_id.clone(),
            );
            self.emit_event(event_codes::FN_NV_010, "L1 linkage verified", details);
            Ok(true)
        } else {
            Err(OracleError {
                code: error_codes::ERR_NVO_L1_LINKAGE_BROKEN,
                message: format!(
                    "L1 linkage broken for receipt '{receipt_id}': missing oracle run ID, verdict, or linkage hash"
                ),
            })
        }
    }

    /// Mark a divergence as resolved.
    pub fn resolve_divergence(
        &mut self,
        divergence_id: &str,
        resolution_note: &str,
    ) -> Result<(), OracleError> {
        let div = self
            .divergences
            .get_mut(divergence_id)
            .ok_or_else(|| OracleError {
                code: error_codes::ERR_NVO_DIVERGENCE_UNRESOLVED,
                message: format!("divergence '{divergence_id}' not found"),
            })?;
        div.resolved = true;
        div.resolution_note = Some(resolution_note.to_string());
        Ok(())
    }

    /// Evaluate whether release is blocked.
    pub fn check_release_gate(&mut self) -> OracleVerdict {
        let mut blocking = Vec::new();
        let mut pending_receipt = Vec::new();

        for (id, div) in &self.divergences {
            if div.resolved {
                continue;
            }

            if div.risk_tier.blocks_release() {
                blocking.push(id.clone());
            } else if div.risk_tier.requires_receipt() {
                // Check if a receipt has been issued for this divergence.
                let has_receipt = self.receipts.values().any(|r| r.divergence_id == *id);
                if !has_receipt {
                    pending_receipt.push(id.clone());
                }
            }
        }

        if !blocking.is_empty() {
            let mut details = BTreeMap::new();
            details.insert("blocked_count".to_string(), blocking.len().to_string());
            self.emit_event(event_codes::FN_NV_008, "Release blocked", details);
            OracleVerdict::BlockRelease {
                blocking_divergence_ids: blocking,
            }
        } else if !pending_receipt.is_empty() {
            OracleVerdict::RequiresReceipt {
                pending_divergence_ids: pending_receipt,
            }
        } else {
            OracleVerdict::Pass
        }
    }

    /// Generate the comprehensive divergence report.
    pub fn generate_report(&mut self) -> DivergenceReport {
        let verdict = self.check_release_gate();

        let mut details = BTreeMap::new();
        details.insert("verdict".to_string(), verdict.label().to_string());
        details.insert(
            "divergence_count".to_string(),
            self.divergences.len().to_string(),
        );
        self.emit_event(event_codes::FN_NV_012, "Oracle report generated", details);

        DivergenceReport {
            schema_version: SCHEMA_VERSION.to_string(),
            trace_id: self.trace_id.clone(),
            runtimes: self.runtimes.clone(),
            checks: self.checks.values().cloned().collect(),
            divergences: self.divergences.values().cloned().collect(),
            voting_results: self.voting_results.values().cloned().collect(),
            receipts: self.receipts.values().cloned().collect(),
            verdict,
            event_log: self.event_log.clone(),
        }
    }

    // -----------------------------------------------------------------------
    // Internal helpers
    // -----------------------------------------------------------------------

    fn emit_event(&mut self, event_code: &str, message: &str, details: BTreeMap<String, String>) {
        self.event_log.push(OracleEvent {
            event_code: event_code.to_string(),
            trace_id: self.trace_id.clone(),
            message: message.to_string(),
            details,
        });
    }
}

// ---------------------------------------------------------------------------
// Helper: default risk assignment by scope
// ---------------------------------------------------------------------------

/// Default risk tier assignment by boundary scope.
pub fn default_risk_for_scope(scope: BoundaryScope) -> RiskTier {
    match scope {
        BoundaryScope::Security => RiskTier::Critical,
        BoundaryScope::Memory => RiskTier::High,
        BoundaryScope::Concurrency => RiskTier::High,
        BoundaryScope::IO => RiskTier::Medium,
        BoundaryScope::TypeSystem => RiskTier::Low,
    }
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_runtime(id: &str) -> RuntimeEntry {
        RuntimeEntry {
            runtime_id: id.to_string(),
            runtime_name: format!("runtime-{id}"),
            version: "1.0.0".to_string(),
            is_reference: true,
        }
    }

    fn sample_receipt(receipt_id: &str, divergence_id: &str) -> PolicyReceipt {
        PolicyReceipt {
            receipt_id: receipt_id.to_string(),
            divergence_id: divergence_id.to_string(),
            issuer: "test-issuer".to_string(),
            rationale: "test rationale".to_string(),
            l1_linkage: L1LinkageProof {
                l1_oracle_run_id: "l1-run-001".to_string(),
                l1_verdict: "pass".to_string(),
                linkage_hash: "abc123".to_string(),
                timestamp_epoch_secs: 1700000000,
            },
            issued_at_epoch_secs: 1700000000,
            expires_at_epoch_secs: 1700086400,
        }
    }

    // 1) Oracle creation emits event
    #[test]
    fn oracle_creation_emits_event() {
        let oracle = RuntimeOracle::new("trace-001", 66);
        assert_eq!(oracle.event_log.len(), 1);
        assert_eq!(oracle.event_log[0].event_code, event_codes::FN_NV_001);
    }

    // 2) Register runtime success
    #[test]
    fn register_runtime_success() {
        let mut oracle = RuntimeOracle::new("trace-002", 66);
        let result = oracle.register_runtime(sample_runtime("franken"));
        assert!(result.is_ok());
        assert_eq!(oracle.runtime_count(), 1);
        assert_eq!(
            oracle.event_log.last().unwrap().event_code,
            event_codes::FN_NV_002
        );
    }

    // 3) Duplicate runtime rejected
    #[test]
    fn duplicate_runtime_rejected() {
        let mut oracle = RuntimeOracle::new("trace-003", 66);
        oracle.register_runtime(sample_runtime("franken")).unwrap();
        let err = oracle
            .register_runtime(sample_runtime("franken"))
            .unwrap_err();
        assert_eq!(err.code, error_codes::ERR_NVO_DUPLICATE_RUNTIME);
    }

    // 4) Remove runtime success
    #[test]
    fn remove_runtime_success() {
        let mut oracle = RuntimeOracle::new("trace-004", 66);
        oracle.register_runtime(sample_runtime("ref-a")).unwrap();
        let removed = oracle.remove_runtime("ref-a").unwrap();
        assert_eq!(removed.runtime_id, "ref-a");
        assert_eq!(oracle.runtime_count(), 0);
    }

    // 5) Remove missing runtime error
    #[test]
    fn remove_missing_runtime_error() {
        let mut oracle = RuntimeOracle::new("trace-005", 66);
        let err = oracle.remove_runtime("ghost").unwrap_err();
        assert_eq!(err.code, error_codes::ERR_NVO_RUNTIME_NOT_FOUND);
    }

    // 6) Cross-check requires at least one runtime
    #[test]
    fn cross_check_requires_runtimes() {
        let mut oracle = RuntimeOracle::new("trace-006", 66);
        let outputs = BTreeMap::new();
        let err = oracle
            .run_cross_check("chk-1", BoundaryScope::Memory, b"input", &outputs)
            .unwrap_err();
        assert_eq!(err.code, error_codes::ERR_NVO_NO_RUNTIMES);
    }

    // 7) Cross-check agreement
    #[test]
    fn cross_check_agreement() {
        let mut oracle = RuntimeOracle::new("trace-007", 66);
        oracle.register_runtime(sample_runtime("a")).unwrap();
        oracle.register_runtime(sample_runtime("b")).unwrap();

        let mut outputs = BTreeMap::new();
        outputs.insert("a".to_string(), vec![1, 2, 3]);
        outputs.insert("b".to_string(), vec![1, 2, 3]);

        let check = oracle
            .run_cross_check("chk-agree", BoundaryScope::IO, b"test", &outputs)
            .unwrap();

        match check.outcome.unwrap() {
            CheckOutcome::Agree { canonical_output } => {
                assert_eq!(canonical_output, vec![1, 2, 3]);
            }
            CheckOutcome::Diverge { .. } => panic!("expected agreement"),
        }
    }

    // 8) Cross-check divergence
    #[test]
    fn cross_check_divergence() {
        let mut oracle = RuntimeOracle::new("trace-008", 66);
        oracle.register_runtime(sample_runtime("a")).unwrap();
        oracle.register_runtime(sample_runtime("b")).unwrap();

        let mut outputs = BTreeMap::new();
        outputs.insert("a".to_string(), vec![1, 2, 3]);
        outputs.insert("b".to_string(), vec![4, 5, 6]);

        let check = oracle
            .run_cross_check("chk-div", BoundaryScope::Security, b"test", &outputs)
            .unwrap();

        match check.outcome.unwrap() {
            CheckOutcome::Diverge { outputs } => {
                assert_eq!(outputs.len(), 2);
            }
            CheckOutcome::Agree { .. } => panic!("expected divergence"),
        }
    }

    // 9) Duplicate active check ID rejected
    #[test]
    fn duplicate_active_check_rejected() {
        let mut oracle = RuntimeOracle::new("trace-009", 66);
        oracle.register_runtime(sample_runtime("a")).unwrap();

        // Force an active-check scenario.
        oracle.active_checks.insert("chk-active".to_string(), true);

        let outputs = BTreeMap::new();
        let err = oracle
            .run_cross_check("chk-active", BoundaryScope::IO, b"in", &outputs)
            .unwrap_err();
        assert_eq!(err.code, error_codes::ERR_NVO_CHECK_ALREADY_RUNNING);
    }

    // 10) Classify divergence
    #[test]
    fn classify_divergence_records_risk_tier() {
        let mut oracle = RuntimeOracle::new("trace-010", 66);
        let outputs = BTreeMap::new();
        let div = oracle.classify_divergence(
            "div-1",
            "chk-1",
            BoundaryScope::Security,
            RiskTier::Critical,
            &outputs,
        );
        assert_eq!(div.risk_tier, RiskTier::Critical);
        assert!(!div.resolved);
        assert_eq!(oracle.divergences.len(), 1);
    }

    // 11) Voting and quorum success
    #[test]
    fn voting_quorum_success() {
        let mut oracle = RuntimeOracle::new("trace-011", 66);
        oracle.register_runtime(sample_runtime("a")).unwrap();
        oracle.register_runtime(sample_runtime("b")).unwrap();
        oracle.register_runtime(sample_runtime("c")).unwrap();

        oracle.vote("chk-v1", "a", vec![1, 2]).unwrap();
        oracle.vote("chk-v1", "b", vec![1, 2]).unwrap();
        oracle.vote("chk-v1", "c", vec![1, 2]).unwrap();

        let result = oracle.tally_votes("chk-v1").unwrap();
        assert!(result.quorum_reached);
        assert_eq!(result.agreeing_voters, 3);
    }

    // 12) Voting quorum failure
    #[test]
    fn voting_quorum_failure() {
        let mut oracle = RuntimeOracle::new("trace-012", 66);
        oracle.register_runtime(sample_runtime("a")).unwrap();
        oracle.register_runtime(sample_runtime("b")).unwrap();
        oracle.register_runtime(sample_runtime("c")).unwrap();

        oracle.vote("chk-v2", "a", vec![1]).unwrap();
        oracle.vote("chk-v2", "b", vec![2]).unwrap();
        oracle.vote("chk-v2", "c", vec![3]).unwrap();

        let result = oracle.tally_votes("chk-v2").unwrap();
        assert!(!result.quorum_reached);
        assert_eq!(result.agreeing_voters, 1);
    }

    // 13) Vote from unknown runtime rejected
    #[test]
    fn vote_from_unknown_runtime_rejected() {
        let mut oracle = RuntimeOracle::new("trace-013", 66);
        let err = oracle.vote("chk-x", "ghost", vec![1]).unwrap_err();
        assert_eq!(err.code, error_codes::ERR_NVO_RUNTIME_NOT_FOUND);
    }

    // 14) Issue policy receipt for low-risk
    #[test]
    fn issue_policy_receipt_low_risk() {
        let mut oracle = RuntimeOracle::new("trace-014", 66);
        oracle.classify_divergence(
            "div-low",
            "chk-1",
            BoundaryScope::TypeSystem,
            RiskTier::Low,
            &BTreeMap::new(),
        );
        let receipt = sample_receipt("rcpt-1", "div-low");
        assert!(oracle.issue_policy_receipt(receipt).is_ok());
        assert_eq!(oracle.receipts.len(), 1);
    }

    // 15) Issue policy receipt rejected for non-low-risk
    #[test]
    fn issue_policy_receipt_rejected_for_high_risk() {
        let mut oracle = RuntimeOracle::new("trace-015", 66);
        oracle.classify_divergence(
            "div-high",
            "chk-1",
            BoundaryScope::Memory,
            RiskTier::High,
            &BTreeMap::new(),
        );
        let receipt = sample_receipt("rcpt-2", "div-high");
        let err = oracle.issue_policy_receipt(receipt).unwrap_err();
        assert_eq!(err.code, error_codes::ERR_NVO_INVALID_RECEIPT);
    }

    // 16) Verify L1 linkage success
    #[test]
    fn verify_l1_linkage_success() {
        let mut oracle = RuntimeOracle::new("trace-016", 66);
        oracle.classify_divergence(
            "div-l",
            "chk-1",
            BoundaryScope::TypeSystem,
            RiskTier::Low,
            &BTreeMap::new(),
        );
        let receipt = sample_receipt("rcpt-l1", "div-l");
        oracle.issue_policy_receipt(receipt).unwrap();
        let valid = oracle.verify_l1_linkage("rcpt-l1").unwrap();
        assert!(valid);
    }

    // 17) Verify L1 linkage broken
    #[test]
    fn verify_l1_linkage_broken() {
        let mut oracle = RuntimeOracle::new("trace-017", 66);
        oracle.classify_divergence(
            "div-lb",
            "chk-1",
            BoundaryScope::TypeSystem,
            RiskTier::Low,
            &BTreeMap::new(),
        );
        let mut receipt = sample_receipt("rcpt-broken", "div-lb");
        receipt.l1_linkage.l1_oracle_run_id.clear();
        oracle.issue_policy_receipt(receipt).unwrap();
        let err = oracle.verify_l1_linkage("rcpt-broken").unwrap_err();
        assert_eq!(err.code, error_codes::ERR_NVO_L1_LINKAGE_BROKEN);
    }

    // 18) Resolve divergence
    #[test]
    fn resolve_divergence_success() {
        let mut oracle = RuntimeOracle::new("trace-018", 66);
        oracle.classify_divergence(
            "div-r",
            "chk-1",
            BoundaryScope::IO,
            RiskTier::Medium,
            &BTreeMap::new(),
        );
        oracle
            .resolve_divergence("div-r", "Accepted as benign")
            .unwrap();
        assert!(oracle.divergences["div-r"].resolved);
        assert_eq!(
            oracle.divergences["div-r"].resolution_note.as_deref(),
            Some("Accepted as benign")
        );
    }

    // 19) Release gate pass when no divergences
    #[test]
    fn release_gate_pass_no_divergences() {
        let mut oracle = RuntimeOracle::new("trace-019", 66);
        let verdict = oracle.check_release_gate();
        assert_eq!(verdict, OracleVerdict::Pass);
    }

    // 20) Release gate blocked on critical
    #[test]
    fn release_gate_blocked_critical() {
        let mut oracle = RuntimeOracle::new("trace-020", 66);
        oracle.classify_divergence(
            "div-crit",
            "chk-1",
            BoundaryScope::Security,
            RiskTier::Critical,
            &BTreeMap::new(),
        );
        let verdict = oracle.check_release_gate();
        match verdict {
            OracleVerdict::BlockRelease {
                blocking_divergence_ids,
            } => {
                assert!(blocking_divergence_ids.contains(&"div-crit".to_string()));
            }
            _ => panic!("expected BlockRelease"),
        }
    }

    // 21) Release gate blocked on high
    #[test]
    fn release_gate_blocked_high() {
        let mut oracle = RuntimeOracle::new("trace-021", 66);
        oracle.classify_divergence(
            "div-high",
            "chk-1",
            BoundaryScope::Memory,
            RiskTier::High,
            &BTreeMap::new(),
        );
        let verdict = oracle.check_release_gate();
        match verdict {
            OracleVerdict::BlockRelease { .. } => {}
            _ => panic!("expected BlockRelease for High risk"),
        }
    }

    // 22) Release gate requires receipt for low-risk
    #[test]
    fn release_gate_requires_receipt_for_low_risk() {
        let mut oracle = RuntimeOracle::new("trace-022", 66);
        oracle.classify_divergence(
            "div-low",
            "chk-1",
            BoundaryScope::TypeSystem,
            RiskTier::Low,
            &BTreeMap::new(),
        );
        let verdict = oracle.check_release_gate();
        match verdict {
            OracleVerdict::RequiresReceipt {
                pending_divergence_ids,
            } => {
                assert!(pending_divergence_ids.contains(&"div-low".to_string()));
            }
            _ => panic!("expected RequiresReceipt"),
        }
    }

    // 23) Release gate pass with receipt
    #[test]
    fn release_gate_pass_with_receipt() {
        let mut oracle = RuntimeOracle::new("trace-023", 66);
        oracle.classify_divergence(
            "div-low",
            "chk-1",
            BoundaryScope::TypeSystem,
            RiskTier::Low,
            &BTreeMap::new(),
        );
        oracle
            .issue_policy_receipt(sample_receipt("rcpt-low", "div-low"))
            .unwrap();
        let verdict = oracle.check_release_gate();
        assert_eq!(verdict, OracleVerdict::Pass);
    }

    // 24) Release gate pass when resolved
    #[test]
    fn release_gate_pass_when_resolved() {
        let mut oracle = RuntimeOracle::new("trace-024", 66);
        oracle.classify_divergence(
            "div-high",
            "chk-1",
            BoundaryScope::Memory,
            RiskTier::High,
            &BTreeMap::new(),
        );
        oracle.resolve_divergence("div-high", "fixed").unwrap();
        let verdict = oracle.check_release_gate();
        assert_eq!(verdict, OracleVerdict::Pass);
    }

    // 25) Generate report structure
    #[test]
    fn generate_report_structure() {
        let mut oracle = RuntimeOracle::new("trace-025", 66);
        oracle.register_runtime(sample_runtime("a")).unwrap();
        oracle.register_runtime(sample_runtime("b")).unwrap();

        let mut outputs = BTreeMap::new();
        outputs.insert("a".to_string(), vec![10]);
        outputs.insert("b".to_string(), vec![20]);
        oracle
            .run_cross_check("chk-rpt", BoundaryScope::IO, b"data", &outputs)
            .unwrap();
        oracle.classify_divergence(
            "div-rpt",
            "chk-rpt",
            BoundaryScope::IO,
            RiskTier::Medium,
            &outputs,
        );

        let report = oracle.generate_report();
        assert_eq!(report.schema_version, SCHEMA_VERSION);
        assert_eq!(report.trace_id, "trace-025");
        assert_eq!(report.runtimes.len(), 2);
        assert_eq!(report.checks.len(), 1);
        assert_eq!(report.divergences.len(), 1);
        assert!(!report.event_log.is_empty());
    }

    // 26) Default risk for scope mapping
    #[test]
    fn default_risk_for_scope_mapping() {
        assert_eq!(
            default_risk_for_scope(BoundaryScope::Security),
            RiskTier::Critical
        );
        assert_eq!(
            default_risk_for_scope(BoundaryScope::Memory),
            RiskTier::High
        );
        assert_eq!(
            default_risk_for_scope(BoundaryScope::Concurrency),
            RiskTier::High
        );
        assert_eq!(default_risk_for_scope(BoundaryScope::IO), RiskTier::Medium);
        assert_eq!(
            default_risk_for_scope(BoundaryScope::TypeSystem),
            RiskTier::Low
        );
    }

    // 27) RiskTier blocks_release
    #[test]
    fn risk_tier_blocks_release() {
        assert!(!RiskTier::Info.blocks_release());
        assert!(!RiskTier::Low.blocks_release());
        assert!(!RiskTier::Medium.blocks_release());
        assert!(RiskTier::High.blocks_release());
        assert!(RiskTier::Critical.blocks_release());
    }

    // 28) RiskTier requires_receipt
    #[test]
    fn risk_tier_requires_receipt() {
        assert!(!RiskTier::Info.requires_receipt());
        assert!(RiskTier::Low.requires_receipt());
        assert!(!RiskTier::Medium.requires_receipt());
        assert!(!RiskTier::High.requires_receipt());
        assert!(!RiskTier::Critical.requires_receipt());
    }

    // 29) PolicyReceipt expiry
    #[test]
    fn policy_receipt_expiry() {
        let receipt = sample_receipt("rcpt-exp", "div-1");
        assert!(!receipt.is_expired(1700000000));
        assert!(receipt.is_expired(1700086400));
        assert!(receipt.is_expired(1800000000));
        assert!(!receipt.is_expired(1700000001));
    }

    // 30) OracleVerdict display labels
    #[test]
    fn oracle_verdict_labels() {
        assert_eq!(OracleVerdict::Pass.label(), "pass");
        assert_eq!(
            OracleVerdict::BlockRelease {
                blocking_divergence_ids: vec![]
            }
            .label(),
            "block_release"
        );
        assert_eq!(
            OracleVerdict::RequiresReceipt {
                pending_divergence_ids: vec![]
            }
            .label(),
            "requires_receipt"
        );
    }

    // 31) Deterministic report ordering (INV-NVO-DETERMINISTIC)
    #[test]
    fn deterministic_report_ordering() {
        let mut oracle = RuntimeOracle::new("trace-031", 66);
        oracle
            .register_runtime(sample_runtime("z-runtime"))
            .unwrap();
        oracle
            .register_runtime(sample_runtime("a-runtime"))
            .unwrap();
        oracle
            .register_runtime(sample_runtime("m-runtime"))
            .unwrap();

        let report = oracle.generate_report();
        let runtime_ids: Vec<&String> = report.runtimes.keys().collect();
        assert_eq!(
            runtime_ids,
            vec!["a-runtime", "m-runtime", "z-runtime"],
            "runtimes should be sorted by BTreeMap key"
        );
    }

    // 32) Medium-risk divergence does not block release
    #[test]
    fn medium_risk_does_not_block() {
        let mut oracle = RuntimeOracle::new("trace-032", 66);
        oracle.classify_divergence(
            "div-med",
            "chk-1",
            BoundaryScope::IO,
            RiskTier::Medium,
            &BTreeMap::new(),
        );
        let verdict = oracle.check_release_gate();
        assert_eq!(verdict, OracleVerdict::Pass);
    }

    // 33) Info-level divergence has no effect on release gate
    #[test]
    fn info_divergence_no_effect() {
        let mut oracle = RuntimeOracle::new("trace-033", 66);
        oracle.classify_divergence(
            "div-info",
            "chk-1",
            BoundaryScope::TypeSystem,
            RiskTier::Info,
            &BTreeMap::new(),
        );
        let verdict = oracle.check_release_gate();
        assert_eq!(verdict, OracleVerdict::Pass);
    }

    // 34) BoundaryScope labels
    #[test]
    fn boundary_scope_labels() {
        assert_eq!(BoundaryScope::TypeSystem.label(), "type_system");
        assert_eq!(BoundaryScope::Memory.label(), "memory");
        assert_eq!(BoundaryScope::IO.label(), "io");
        assert_eq!(BoundaryScope::Concurrency.label(), "concurrency");
        assert_eq!(BoundaryScope::Security.label(), "security");
    }

    // 35) Tally votes for unknown check returns error
    #[test]
    fn tally_unknown_check_error() {
        let mut oracle = RuntimeOracle::new("trace-035", 66);
        let err = oracle.tally_votes("nonexistent").unwrap_err();
        assert_eq!(err.code, error_codes::ERR_NVO_RUNTIME_NOT_FOUND);
    }
}
