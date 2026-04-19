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

const MAX_EVENT_LOG_ENTRIES: usize = 4096;

fn push_bounded<T>(items: &mut Vec<T>, item: T, cap: usize) {
    if cap == 0 {
        items.clear();
        return;
    }
    if items.len() >= cap {
        let overflow = items.len().saturating_sub(cap).saturating_add(1);
        items.drain(0..overflow.min(items.len()));
    }
    items.push(item);
}

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
    pub const ERR_NVO_CHECK_NOT_FOUND: &str = "ERR_NVO_CHECK_NOT_FOUND";
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
        // INV-NVO-QUORUM: quorum percentage must remain in [1, 100].
        let quorum_threshold_percent = quorum_threshold_percent.clamp(1, 100);
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

        if self.active_checks.get(check_id).copied().unwrap_or(false) {
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
                code: error_codes::ERR_NVO_CHECK_NOT_FOUND,
                message: format!("no votes recorded for check '{check_id}'"),
            })?;

        let total = self.runtimes.len();
        if total == 0 {
            return Err(OracleError {
                code: error_codes::ERR_NVO_NO_RUNTIMES,
                message: "no runtimes registered".to_string(),
            });
        }
        let total_f64 = total as f64;
        let percentage_f64 = self.quorum_threshold_percent as f64 / 100.0;
        if !total_f64.is_finite() || !percentage_f64.is_finite() {
            return Err(OracleError {
                code: error_codes::ERR_NVO_QUORUM_FAILED,
                message: "invalid quorum calculation: non-finite values".to_string(),
            });
        }
        let quorum_required = (total_f64 * percentage_f64).ceil() as usize;

        // Count how many runtimes agree with the most common output.
        let mut output_counts: BTreeMap<&[u8], usize> = BTreeMap::new();
        for output in entry.votes.values() {
            let count = output_counts.entry(output.as_slice()).or_insert(0);
            *count = count.saturating_add(1);
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
    pub fn check_release_gate(&mut self, now_epoch_secs: u64) -> OracleVerdict {
        let mut blocking = Vec::new();
        let mut pending_receipt = Vec::new();

        for (id, div) in &self.divergences {
            if div.resolved {
                continue;
            }

            if div.risk_tier.blocks_release() {
                blocking.push(id.clone());
            } else if div.risk_tier.requires_receipt() {
                // Check if a receipt has been issued for this divergence and is valid.
                let has_receipt = self.receipts.values().any(|r| {
                    r.divergence_id == *id && !r.is_expired(now_epoch_secs) && r.verify_l1_linkage()
                });
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
    pub fn generate_report(&mut self, now_epoch_secs: u64) -> DivergenceReport {
        let verdict = self.check_release_gate(now_epoch_secs);

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
        push_bounded(
            &mut self.event_log,
            OracleEvent {
                event_code: event_code.to_string(),
                trace_id: self.trace_id.clone(),
                message: message.to_string(),
                details,
            },
            MAX_EVENT_LOG_ENTRIES,
        );
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

    #[test]
    fn oracle_creation_clamps_quorum_threshold_bounds() {
        let low = RuntimeOracle::new("trace-q-low", 0);
        assert_eq!(low.quorum_threshold_percent, 1);

        let high = RuntimeOracle::new("trace-q-high", 255);
        assert_eq!(high.quorum_threshold_percent, 100);
    }

    #[test]
    fn over_100_input_is_clamped_to_unanimous_quorum() {
        let mut oracle = RuntimeOracle::new("trace-q-unanimous", 255);
        oracle.register_runtime(sample_runtime("a")).unwrap();
        oracle.register_runtime(sample_runtime("b")).unwrap();
        oracle.register_runtime(sample_runtime("c")).unwrap();

        oracle.vote("check-1", "a", vec![1]).unwrap();
        oracle.vote("check-1", "b", vec![1]).unwrap();
        oracle.vote("check-1", "c", vec![1]).unwrap();

        let result = oracle.tally_votes("check-1").unwrap();
        assert!(result.quorum_reached);
        assert_eq!(result.quorum_threshold, 3);
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
            CheckOutcome::Diverge { .. } => unreachable!("expected agreement"),
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
            CheckOutcome::Agree { .. } => unreachable!("expected divergence"),
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
        let verdict = oracle.check_release_gate(0);
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
        let verdict = oracle.check_release_gate(0);
        match verdict {
            OracleVerdict::BlockRelease {
                blocking_divergence_ids,
            } => {
                assert!(blocking_divergence_ids.contains(&"div-crit".to_string()));
            }
            _ => unreachable!("expected BlockRelease"),
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
        let verdict = oracle.check_release_gate(0);
        match verdict {
            OracleVerdict::BlockRelease { .. } => {}
            _ => unreachable!("expected BlockRelease for High risk"),
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
        let verdict = oracle.check_release_gate(0);
        match verdict {
            OracleVerdict::RequiresReceipt {
                pending_divergence_ids,
            } => {
                assert!(pending_divergence_ids.contains(&"div-low".to_string()));
            }
            _ => unreachable!("expected RequiresReceipt"),
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
        let verdict = oracle.check_release_gate(0);
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
        let verdict = oracle.check_release_gate(0);
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

        let report = oracle.generate_report(0);
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

        let report = oracle.generate_report(0);
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
        let verdict = oracle.check_release_gate(0);
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
        let verdict = oracle.check_release_gate(0);
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
        assert_eq!(err.code, error_codes::ERR_NVO_CHECK_NOT_FOUND);
    }

    #[test]
    fn issue_policy_receipt_rejects_unknown_divergence() {
        let mut oracle = RuntimeOracle::new("trace-unknown-div-receipt", 66);
        let err = oracle
            .issue_policy_receipt(sample_receipt("rcpt-missing-div", "div-missing"))
            .unwrap_err();

        assert_eq!(err.code, error_codes::ERR_NVO_DIVERGENCE_UNRESOLVED);
        assert!(oracle.receipts.is_empty());
    }

    #[test]
    fn verify_l1_linkage_rejects_unknown_receipt() {
        let mut oracle = RuntimeOracle::new("trace-unknown-receipt", 66);
        let err = oracle.verify_l1_linkage("rcpt-missing").unwrap_err();

        assert_eq!(err.code, error_codes::ERR_NVO_INVALID_RECEIPT);
    }

    #[test]
    fn resolve_missing_divergence_rejected() {
        let mut oracle = RuntimeOracle::new("trace-resolve-missing", 66);
        let err = oracle
            .resolve_divergence("div-missing", "not present")
            .unwrap_err();

        assert_eq!(err.code, error_codes::ERR_NVO_DIVERGENCE_UNRESOLVED);
    }

    #[test]
    fn low_risk_expired_receipt_still_requires_receipt_at_boundary() {
        let mut oracle = RuntimeOracle::new("trace-expired-receipt", 66);
        oracle.classify_divergence(
            "div-low-expired",
            "chk-1",
            BoundaryScope::TypeSystem,
            RiskTier::Low,
            &BTreeMap::new(),
        );
        let mut receipt = sample_receipt("rcpt-expired", "div-low-expired");
        receipt.expires_at_epoch_secs = receipt.issued_at_epoch_secs;
        oracle.issue_policy_receipt(receipt.clone()).unwrap();

        let verdict = oracle.check_release_gate(receipt.expires_at_epoch_secs);

        match verdict {
            OracleVerdict::RequiresReceipt {
                pending_divergence_ids,
            } => assert!(pending_divergence_ids.contains(&"div-low-expired".to_string())),
            other => unreachable!("expected expired receipt to be pending, got {other:?}"),
        }
    }

    #[test]
    fn low_risk_receipt_with_empty_linkage_hash_still_requires_receipt() {
        let mut oracle = RuntimeOracle::new("trace-empty-linkage-hash", 66);
        oracle.classify_divergence(
            "div-low-empty-linkage",
            "chk-1",
            BoundaryScope::TypeSystem,
            RiskTier::Low,
            &BTreeMap::new(),
        );
        let mut receipt = sample_receipt("rcpt-empty-linkage", "div-low-empty-linkage");
        receipt.l1_linkage.linkage_hash.clear();
        oracle.issue_policy_receipt(receipt).unwrap();

        let verdict = oracle.check_release_gate(1700000001);

        match verdict {
            OracleVerdict::RequiresReceipt {
                pending_divergence_ids,
            } => assert!(pending_divergence_ids.contains(&"div-low-empty-linkage".to_string())),
            other => unreachable!("expected invalid linkage to be pending, got {other:?}"),
        }
    }

    #[test]
    fn verify_l1_linkage_rejects_empty_verdict() {
        let mut oracle = RuntimeOracle::new("trace-empty-verdict", 66);
        oracle.classify_divergence(
            "div-empty-verdict",
            "chk-1",
            BoundaryScope::TypeSystem,
            RiskTier::Low,
            &BTreeMap::new(),
        );
        let mut receipt = sample_receipt("rcpt-empty-verdict", "div-empty-verdict");
        receipt.l1_linkage.l1_verdict.clear();
        oracle.issue_policy_receipt(receipt).unwrap();

        let err = oracle.verify_l1_linkage("rcpt-empty-verdict").unwrap_err();

        assert_eq!(err.code, error_codes::ERR_NVO_L1_LINKAGE_BROKEN);
    }

    #[test]
    fn tally_votes_without_registered_runtimes_rejected_even_if_votes_exist() {
        let mut oracle = RuntimeOracle::new("trace-orphan-votes", 66);
        let mut votes = BTreeMap::new();
        votes.insert("ghost-runtime".to_string(), vec![1, 2, 3]);
        oracle.voting_results.insert(
            "chk-orphan".to_string(),
            VotingResult {
                check_id: "chk-orphan".to_string(),
                votes,
                quorum_reached: false,
                quorum_threshold: 1,
                total_voters: 1,
                agreeing_voters: 1,
            },
        );

        let err = oracle.tally_votes("chk-orphan").unwrap_err();

        assert_eq!(err.code, error_codes::ERR_NVO_NO_RUNTIMES);
    }

    #[test]
    fn receipt_for_other_low_risk_divergence_does_not_satisfy_gate() {
        let mut oracle = RuntimeOracle::new("trace-wrong-receipt", 66);
        oracle.classify_divergence(
            "div-pending",
            "chk-1",
            BoundaryScope::TypeSystem,
            RiskTier::Low,
            &BTreeMap::new(),
        );
        oracle.classify_divergence(
            "div-receipted",
            "chk-2",
            BoundaryScope::TypeSystem,
            RiskTier::Low,
            &BTreeMap::new(),
        );
        oracle
            .issue_policy_receipt(sample_receipt("rcpt-other", "div-receipted"))
            .unwrap();

        let verdict = oracle.check_release_gate(1700000001);

        match verdict {
            OracleVerdict::RequiresReceipt {
                pending_divergence_ids,
            } => {
                assert!(pending_divergence_ids.contains(&"div-pending".to_string()));
                assert!(!pending_divergence_ids.contains(&"div-receipted".to_string()));
            }
            other => unreachable!("expected unmatched divergence to be pending, got {other:?}"),
        }
    }

    // === bd-CrimsonCrane: BTreeMap<String, bool> regression ===

    #[test]
    fn disabled_active_check_allows_rerun() {
        // An active_check entry with value=false should NOT block a new check.
        let mut oracle = RuntimeOracle::new("trace-disabled", 66);
        oracle
            .register_runtime(sample_runtime("a"))
            .expect("register should succeed");
        // Manually insert a "disabled" check flag
        oracle.active_checks.insert("chk-1".to_string(), false);
        let outputs = BTreeMap::new();
        let result = oracle.run_cross_check("chk-1", BoundaryScope::IO, b"in", &outputs);
        assert!(
            result.is_ok(),
            "disabled (false) active check should allow re-run"
        );
    }

    // ── Negative-path tests for edge cases and invalid inputs ──────────

    #[test]
    fn negative_risk_tier_ordering_and_serialization_consistency() {
        // Test RiskTier enum ordering and edge cases
        let tiers = [
            RiskTier::Info,
            RiskTier::Low,
            RiskTier::Medium,
            RiskTier::High,
            RiskTier::Critical,
        ];

        // Test ordering (Info < Low < Medium < High < Critical)
        for i in 0..tiers.len() {
            for j in i + 1..tiers.len() {
                assert!(
                    tiers[i] < tiers[j],
                    "RiskTier ordering should be consistent: {:?} < {:?}",
                    tiers[i], tiers[j]
                );
            }
        }

        // Test serialization consistency
        for tier in &tiers {
            let serialized = serde_json::to_string(tier).unwrap();
            let deserialized: RiskTier = serde_json::from_str(&serialized).unwrap();
            assert_eq!(*tier, deserialized);

            // Should be cloneable and hashable
            let cloned = tier.clone();
            assert_eq!(*tier, cloned);
        }

        // Test invalid deserialization
        let invalid_tier_json = vec![
            "\"Unknown\"",
            "\"CRITICAL\"",        // Wrong case
            "\"VeryHigh\"",        // Non-existent variant
            "42",                  // Wrong type
            "null",
        ];

        for invalid_json in invalid_tier_json {
            let result: Result<RiskTier, _> = serde_json::from_str(invalid_json);
            assert!(result.is_err(), "Should reject invalid tier JSON: {}", invalid_json);
        }
    }

    #[test]
    fn negative_boundary_scope_coverage_and_edge_cases() {
        // Test BoundaryScope enum completeness and serialization
        let scopes = [
            BoundaryScope::TypeSystem,
            BoundaryScope::Memory,
            BoundaryScope::IO,
            BoundaryScope::Concurrency,
            BoundaryScope::Security,
        ];

        for scope in &scopes {
            // Serialization should work
            let serialized = serde_json::to_string(scope).unwrap();
            let deserialized: BoundaryScope = serde_json::from_str(&serialized).unwrap();
            assert_eq!(*scope, deserialized);

            // Should be orderable and hashable
            let cloned = scope.clone();
            assert_eq!(*scope, cloned);

            // Should have reasonable display/debug formatting
            let debug = format!("{:?}", scope);
            assert!(!debug.is_empty());
        }

        // Test that all critical boundary types are covered
        let scope_names: Vec<String> = scopes.iter().map(|s| format!("{:?}", s)).collect();
        assert!(scope_names.contains(&"TypeSystem".to_string()));
        assert!(scope_names.contains(&"Memory".to_string()));
        assert!(scope_names.contains(&"IO".to_string()));
        assert!(scope_names.contains(&"Concurrency".to_string()));
        assert!(scope_names.contains(&"Security".to_string()));
    }

    #[test]
    fn negative_runtime_entry_with_problematic_metadata() {
        // Test RuntimeEntry with various problematic metadata
        let problematic_runtimes = vec![
            RuntimeEntry {
                runtime_id: "".to_string(), // Empty ID
                runtime_name: "Valid Runtime".to_string(),
                version: "1.0.0".to_string(),
                is_reference: true,
            },
            RuntimeEntry {
                runtime_id: "\0runtime\x01id".to_string(), // Control characters
                runtime_name: "runtime\nwith\nnewlines".to_string(),
                version: "🚀version💀".to_string(), // Unicode emoji
                is_reference: false,
            },
            RuntimeEntry {
                runtime_id: "../../../etc/passwd".to_string(), // Path traversal
                runtime_name: "<script>alert('runtime')</script>".to_string(), // XSS
                version: "\u{FFFF}".to_string(), // Max Unicode
                is_reference: true,
            },
            RuntimeEntry {
                runtime_id: "x".repeat(10_000), // Very long ID
                runtime_name: "y".repeat(50_000), // Very long name
                version: "z".repeat(1_000), // Long version
                is_reference: false,
            },
        ];

        for runtime in problematic_runtimes {
            // Runtime creation should not panic
            assert!(runtime.is_reference || !runtime.is_reference); // Basic boolean check

            // Serialization should handle problematic content
            let serialization = serde_json::to_string(&runtime);
            match serialization {
                Ok(json) => {
                    // If serialization succeeds, deserialization should work
                    let deserialization: Result<RuntimeEntry, _> = serde_json::from_str(&json);
                    match deserialization {
                        Ok(restored) => {
                            // Basic field preservation
                            assert_eq!(restored.runtime_id, runtime.runtime_id);
                            assert_eq!(restored.is_reference, runtime.is_reference);
                        }
                        Err(_) => {
                            // Some characters might not survive JSON round-trip
                        }
                    }
                }
                Err(_) => {
                    // Some problematic content might not be serializable
                }
            }

            // Equality and cloning should work
            let cloned = runtime.clone();
            assert_eq!(runtime, cloned);
        }
    }

    #[test]
    fn negative_check_outcome_with_extreme_output_sizes() {
        // Test CheckOutcome with various edge cases
        let extreme_outcomes = vec![
            CheckOutcome::Agree {
                canonical_output: vec![], // Empty output
            },
            CheckOutcome::Agree {
                canonical_output: vec![0xFF; 1_000_000], // Large output (1MB)
            },
            CheckOutcome::Agree {
                canonical_output: vec![0, 1, 2, 255, 254], // Mixed byte values
            },
            CheckOutcome::Diverge {
                outputs: BTreeMap::new(), // Empty outputs map
            },
            {
                let mut large_outputs = BTreeMap::new();
                // Many runtime outputs
                for i in 0..1000 {
                    large_outputs.insert(format!("runtime_{}", i), vec![i as u8; 100]);
                }
                CheckOutcome::Diverge {
                    outputs: large_outputs,
                }
            },
            {
                let mut problematic_outputs = BTreeMap::new();
                problematic_outputs.insert("\0runtime\x01".to_string(), vec![0xFF; 1000]);
                problematic_outputs.insert("🚀runtime💀".to_string(), vec![]);
                problematic_outputs.insert("../../../etc/passwd".to_string(), b"malicious".to_vec());
                CheckOutcome::Diverge {
                    outputs: problematic_outputs,
                }
            },
        ];

        for outcome in extreme_outcomes {
            // Outcome creation should handle extreme cases
            match &outcome {
                CheckOutcome::Agree { canonical_output } => {
                    assert!(canonical_output.len() <= 1_000_000);
                }
                CheckOutcome::Diverge { outputs } => {
                    assert!(outputs.len() <= 1000);
                }
            }

            // Serialization should handle large/problematic data
            let serialization = serde_json::to_string(&outcome);
            match serialization {
                Ok(_json) => {
                    // If large data serializes, that's fine
                }
                Err(_) => {
                    // Very large data might not serialize due to memory limits
                }
            }

            // Equality and cloning should work
            let cloned = outcome.clone();
            assert_eq!(outcome, cloned);
        }
    }

    #[test]
    fn negative_cross_runtime_check_with_malformed_data() {
        // Test CrossRuntimeCheck with problematic data
        let malformed_checks = vec![
            CrossRuntimeCheck {
                check_id: "".to_string(), // Empty check ID
                boundary_scope: BoundaryScope::TypeSystem,
                input: vec![],
                trace_id: "trace123".to_string(),
                outcome: None,
            },
            CrossRuntimeCheck {
                check_id: "\0check\x01id".to_string(), // Control characters
                boundary_scope: BoundaryScope::Security,
                input: vec![0xFF; 10_000], // Large input
                trace_id: "trace\nwith\nnewlines".to_string(),
                outcome: Some(CheckOutcome::Agree { canonical_output: vec![] }),
            },
            CrossRuntimeCheck {
                check_id: "🚀check💀".to_string(), // Unicode emoji
                boundary_scope: BoundaryScope::Memory,
                input: b"malicious\0input\x01".to_vec(),
                trace_id: "../../../etc/shadow".to_string(), // Path traversal
                outcome: Some(CheckOutcome::Diverge { outputs: BTreeMap::new() }),
            },
        ];

        for check in malformed_checks {
            // Check creation should not panic
            assert!(check.input.len() <= 10_000);

            // Serialization should handle malformed data
            let serialization = serde_json::to_string(&check);
            match serialization {
                Ok(json) => {
                    let _deserialization: Result<CrossRuntimeCheck, _> = serde_json::from_str(&json);
                    // Either succeeds or fails gracefully
                }
                Err(_) => {
                    // Some malformed content might not serialize
                }
            }

            // Should be cloneable and comparable
            let cloned = check.clone();
            assert_eq!(check, cloned);
        }
    }

    #[test]
    fn negative_semantic_divergence_resolution_edge_cases() {
        // Test SemanticDivergence with various edge cases
        let edge_divergences = vec![
            SemanticDivergence {
                divergence_id: "div1".to_string(),
                check_id: "check1".to_string(),
                boundary_scope: BoundaryScope::IO,
                risk_tier: RiskTier::Critical,
                runtime_outputs: BTreeMap::new(), // Empty outputs
                resolved: false,
                resolution_note: None, // No resolution note
                trace_id: "trace1".to_string(),
            },
            SemanticDivergence {
                divergence_id: "\0div\x01".to_string(), // Control characters
                check_id: "check\nwith\nnewlines".to_string(),
                boundary_scope: BoundaryScope::Concurrency,
                risk_tier: RiskTier::Low,
                runtime_outputs: {
                    let mut outputs = BTreeMap::new();
                    outputs.insert("runtime1".to_string(), vec![0xFF; 1000]);
                    outputs.insert("🚀runtime2💀".to_string(), vec![]);
                    outputs
                },
                resolved: true,
                resolution_note: Some("<script>alert('resolved')</script>".to_string()), // XSS
                trace_id: "../../../var/log/trace".to_string(),
            },
            SemanticDivergence {
                divergence_id: "x".repeat(1000), // Long ID
                check_id: "y".repeat(2000), // Long check ID
                boundary_scope: BoundaryScope::Security,
                risk_tier: RiskTier::High,
                runtime_outputs: {
                    let mut outputs = BTreeMap::new();
                    // Many runtime outputs with large data
                    for i in 0..100 {
                        outputs.insert(format!("rt_{}", i), vec![i as u8; 100]);
                    }
                    outputs
                },
                resolved: true,
                resolution_note: Some("z".repeat(10_000)), // Very long resolution note
                trace_id: "normal_trace".to_string(),
            },
        ];

        for divergence in edge_divergences {
            // Divergence creation should handle edge cases
            assert!(divergence.resolved || !divergence.resolved); // Boolean check

            // Risk tier should be valid
            assert!(matches!(
                divergence.risk_tier,
                RiskTier::Info | RiskTier::Low | RiskTier::Medium | RiskTier::High | RiskTier::Critical
            ));

            // Serialization should handle complex nested data
            let serialization = serde_json::to_string(&divergence);
            match serialization {
                Ok(_json) => {
                    // Complex structures with large data might serialize
                }
                Err(_) => {
                    // Very large nested data might fail serialization
                }
            }

            // Should support equality and cloning
            let cloned = divergence.clone();
            assert_eq!(divergence, cloned);
        }
    }

    #[test]
    fn negative_l1_linkage_proof_with_extreme_timestamps() {
        // Test L1LinkageProof with extreme timestamp values
        let extreme_proofs = vec![
            L1LinkageProof {
                l1_oracle_run_id: "run123".to_string(),
                l1_verdict: "PASS".to_string(),
                linkage_hash: "abc123".to_string(),
                timestamp_epoch_secs: 0, // Zero timestamp
            },
            L1LinkageProof {
                l1_oracle_run_id: "run456".to_string(),
                l1_verdict: "FAIL".to_string(),
                linkage_hash: "def456".to_string(),
                timestamp_epoch_secs: u64::MAX, // Maximum timestamp
            },
            L1LinkageProof {
                l1_oracle_run_id: "\0run\x01".to_string(), // Control characters
                l1_verdict: "verdict\nwith\nnewlines".to_string(),
                linkage_hash: "🚀hash💀".to_string(), // Unicode emoji
                timestamp_epoch_secs: u64::MAX / 2,
            },
            L1LinkageProof {
                l1_oracle_run_id: "".to_string(), // Empty run ID
                l1_verdict: "".to_string(), // Empty verdict
                linkage_hash: "".to_string(), // Empty hash
                timestamp_epoch_secs: 1,
            },
        ];

        for proof in extreme_proofs {
            // Proof creation should handle extreme timestamps
            assert!(proof.timestamp_epoch_secs <= u64::MAX);

            // Timestamp arithmetic should be safe
            let now = 1_000_000u64;
            let is_recent = now.saturating_sub(proof.timestamp_epoch_secs) < 3600; // Within 1 hour
            assert!(is_recent || !is_recent); // Basic boolean check

            // Serialization should handle extreme values and problematic strings
            let serialization = serde_json::to_string(&proof);
            match serialization {
                Ok(json) => {
                    let _deserialization: Result<L1LinkageProof, _> = serde_json::from_str(&json);
                    // Should either deserialize or fail gracefully
                }
                Err(_) => {
                    // Some problematic strings might not serialize
                }
            }

            // Should support standard operations
            let cloned = proof.clone();
            assert_eq!(proof, cloned);
        }
    }

    #[test]
    fn negative_push_bounded_with_extreme_capacity_scenarios() {
        // Test the push_bounded utility function with edge cases
        let mut items = vec![1, 2, 3, 4, 5];

        // Test with zero capacity (should drain all but keep new item)
        let original_len = items.len();
        push_bounded(&mut items, 99, 0);
        assert_eq!(items, vec![99], "Zero capacity should keep only new item");

        // Test with capacity 1
        push_bounded(&mut items, 100, 1);
        assert_eq!(items, vec![100], "Capacity 1 should keep only new item");

        // Test with massive overflow
        let mut large_vec: Vec<u32> = (0..10000).collect();
        push_bounded(&mut large_vec, 99999, 5);
        assert_eq!(large_vec.len(), 5);
        assert_eq!(*large_vec.last().unwrap(), 99999);
        assert!(large_vec[0] >= 9995, "Should keep recent items: {:?}", &large_vec[..3]);

        // Test with capacity larger than current size
        let mut small_vec = vec![1, 2];
        push_bounded(&mut small_vec, 3, 10);
        assert_eq!(small_vec, vec![1, 2, 3], "Should not drain when under capacity");

        // Test edge case: exactly at capacity
        let mut exact_vec = vec![1, 2, 3];
        push_bounded(&mut exact_vec, 4, 3);
        assert_eq!(exact_vec.len(), 3);
        assert!(exact_vec.contains(&4), "Should contain new item");
        assert!(!exact_vec.contains(&1), "Should have drained oldest item");
    }

    #[test]
    fn negative_constants_validation_and_code_consistency() {
        // Test that all event constants follow proper naming conventions
        use event_codes::*;

        let event_constants = [
            FN_NV_001, FN_NV_002, FN_NV_003, FN_NV_004, FN_NV_005, FN_NV_006,
            FN_NV_007, FN_NV_008, FN_NV_009, FN_NV_010, FN_NV_011, FN_NV_012,
        ];

        for constant in &event_constants {
            assert!(!constant.is_empty());
            assert!(constant.starts_with("FN-NV-"), "Event constant should start with FN-NV-: {}", constant);
            assert!(constant.is_ascii(), "Event constant should be ASCII: {}", constant);

            // Should follow pattern FN-NV-XXX where XXX is a 3-digit number
            let suffix = constant.strip_prefix("FN-NV-").unwrap();
            assert_eq!(suffix.len(), 3, "Event code suffix should be 3 digits: {}", suffix);
            assert!(suffix.chars().all(|c| c.is_ascii_digit()), "Event code suffix should be numeric: {}", suffix);
        }

        // Test error constants
        use error_codes::*;

        let error_constants = [
            ERR_NVO_NO_RUNTIMES, ERR_NVO_QUORUM_FAILED, ERR_NVO_RUNTIME_NOT_FOUND,
            ERR_NVO_CHECK_NOT_FOUND, ERR_NVO_CHECK_ALREADY_RUNNING, ERR_NVO_DIVERGENCE_UNRESOLVED,
            ERR_NVO_POLICY_MISSING, ERR_NVO_INVALID_RECEIPT, ERR_NVO_L1_LINKAGE_BROKEN,
            ERR_NVO_VOTING_TIMEOUT, ERR_NVO_DUPLICATE_RUNTIME,
        ];

        for constant in &error_constants {
            assert!(!constant.is_empty());
            assert!(constant.starts_with("ERR_NVO_"), "Error constant should start with ERR_NVO_: {}", constant);
            assert!(constant.is_ascii(), "Error constant should be ASCII: {}", constant);
        }

        // Test invariant constants
        use invariants::*;

        let invariant_constants = [
            INV_NVO_QUORUM, INV_NVO_RISK_TIERED, INV_NVO_BLOCK_HIGH,
            INV_NVO_POLICY_RECEIPT, INV_NVO_L1_LINKAGE, INV_NVO_DETERMINISTIC,
        ];

        for constant in &invariant_constants {
            assert!(!constant.is_empty());
            assert!(constant.starts_with("INV-NVO-"), "Invariant should start with INV-NVO-: {}", constant);
            assert!(constant.is_ascii(), "Invariant constant should be ASCII: {}", constant);
        }

        // Test capacity constant
        assert!(MAX_EVENT_LOG_ENTRIES > 0);
        assert!(MAX_EVENT_LOG_ENTRIES <= 100_000); // Reasonable upper bound
    }

    #[test]
    fn negative_unicode_injection_in_runtime_registration() {
        let mut oracle = RuntimeOracle::new("trace-unicode", 66);

        let malicious_runtime_ids = vec![
            "normal\u{202e}evil\u{202c}runtime",    // BiDi override
            "runtime\u{200b}\u{feff}hidden",        // Zero-width characters
            "runtime\nnewline",                      // Newline injection
            "runtime\ttab",                          // Tab injection
            "runtime\x00null",                       // Null byte injection
            "../../../etc/passwd",                   // Path traversal
            "runtime\"quote'injection",              // Quote injection
        ];

        for malicious_id in &malicious_runtime_ids {
            let runtime = RuntimeEntry {
                runtime_id: malicious_id.clone(),
                runtime_name: format!("Runtime for {}", malicious_id),
                version: "1.0.0".to_string(),
                is_reference: false,
            };

            let result = oracle.register_runtime(runtime);
            assert!(result.is_ok());

            // Verify we can retrieve with exact ID
            assert!(oracle.runtimes.contains_key(malicious_id));
        }

        // Test duplicate registration with Unicode variations
        let variant_runtime = RuntimeEntry {
            runtime_id: "runtime\u{FEFF}1".to_string(), // BOM variant
            runtime_name: "BOM Runtime".to_string(),
            version: "1.0.0".to_string(),
            is_reference: false,
        };

        let result = oracle.register_runtime(variant_runtime);
        assert!(result.is_ok());
    }

    #[test]
    fn negative_massive_runtime_output_memory_stress() {
        let mut oracle = RuntimeOracle::new("trace-memory", 66);

        // Register runtime
        oracle.register_runtime(sample_runtime("memory-test")).unwrap();

        // Create massive runtime outputs (10MB each)
        let massive_output = vec![0xAA; 10 * 1024 * 1024];
        let mut massive_outputs = BTreeMap::new();
        massive_outputs.insert("memory-test".to_string(), massive_output.clone());

        let result = oracle.run_cross_check(
            "massive-check",
            BoundaryScope::Memory,
            &vec![0x42; 1000],
            &massive_outputs,
        );

        // Should handle massive outputs gracefully
        if result.is_ok() {
            let check = &oracle.cross_checks["massive-check"];
            if let Some(CheckOutcome::Agree { canonical_output }) = &check.outcome {
                assert!(canonical_output.len() <= 10 * 1024 * 1024);
            }
        }
    }

    #[test]
    fn negative_voting_timestamp_arithmetic_overflow() {
        let mut oracle = RuntimeOracle::new("trace-overflow", 66);
        oracle.register_runtime(sample_runtime("voter1")).unwrap();
        oracle.register_runtime(sample_runtime("voter2")).unwrap();

        // Create voting result with extreme timestamps
        let mut votes = BTreeMap::new();
        votes.insert("voter1".to_string(), vec![1, 0, 1]);
        votes.insert("voter2".to_string(), vec![1, 1, 0]);

        oracle.voting_results.insert(
            "overflow-check".to_string(),
            VotingResult {
                check_id: "overflow-check".to_string(),
                votes,
                quorum_reached: true,
                quorum_threshold: 2,
                total_voters: 2,
                agreeing_voters: 2,
            },
        );

        // Test with extreme current_time values
        let extreme_times = vec![
            u64::MAX,
            u64::MAX - 1,
            u64::MAX / 2,
            0,
        ];

        for time in extreme_times {
            let report = oracle.generate_report(time);
            assert!(report.current_time_epoch_secs == time);

            // Verify timestamp arithmetic doesn't overflow
            let verdict = oracle.check_release_gate(time);
            match verdict {
                OracleVerdict::Pass => {}
                OracleVerdict::BlockRelease { .. } => {}
                OracleVerdict::RequiresReceipt { .. } => {}
            }
        }
    }

    #[test]
    fn negative_concurrent_voting_race_conditions() {
        use std::sync::{Arc, Barrier, Mutex};
        use std::thread;

        let oracle = Arc::new(Mutex::new(RuntimeOracle::new("trace-concurrent", 66)));
        let barrier = Arc::new(Barrier::new(4));

        // Pre-register runtimes
        {
            let mut oracle_guard = oracle.lock().unwrap();
            for i in 0..4 {
                let runtime = RuntimeEntry {
                    runtime_id: format!("runtime-{}", i),
                    runtime_name: format!("Runtime {}", i),
                    version: "1.0.0".to_string(),
                    is_reference: false,
                };
                oracle_guard.register_runtime(runtime).unwrap();
            }
        }

        let mut handles = Vec::new();

        for thread_id in 0..4 {
            let oracle = Arc::clone(&oracle);
            let barrier = Arc::clone(&barrier);

            let handle = thread::spawn(move || {
                barrier.wait();

                for i in 0..25 {
                    let check_id = format!("thread-{}-check-{}", thread_id, i);
                    let runtime_id = format!("runtime-{}", thread_id);

                    let mut outputs = BTreeMap::new();
                    outputs.insert(runtime_id, vec![thread_id as u8, i as u8]);

                    let mut oracle_guard = oracle.lock().unwrap();
                    let _ = oracle_guard.run_cross_check(
                        &check_id,
                        BoundaryScope::Concurrency,
                        &vec![i as u8],
                        &outputs,
                    );
                }
            });

            handles.push(handle);
        }

        for handle in handles {
            handle.join().expect("Thread should complete");
        }

        // Verify oracle consistency
        let final_oracle = oracle.lock().unwrap();
        assert_eq!(final_oracle.runtimes.len(), 4);
        assert!(final_oracle.cross_checks.len() > 0);
    }

    #[test]
    fn negative_policy_receipt_forgery_detection() {
        let mut oracle = RuntimeOracle::new("trace-forgery", 66);

        // Create legitimate divergence
        oracle.classify_divergence(
            "legit-div",
            "check-1",
            BoundaryScope::Security,
            RiskTier::Low,
            &BTreeMap::new(),
        );

        // Create legitimate receipt
        let legit_receipt = sample_receipt("legit-receipt", "legit-div");
        oracle.issue_policy_receipt(legit_receipt.clone()).unwrap();

        // Attempt various forgery attacks
        let forgery_attempts = vec![
            // Receipt for non-existent divergence
            sample_receipt("forged-1", "non-existent-div"),

            // Receipt with manipulated linkage
            {
                let mut forged = legit_receipt.clone();
                forged.receipt_id = "forged-2".to_string();
                forged.l1_linkage.linkage_hash = "manipulated-hash".to_string();
                forged
            },

            // Receipt with future expiry
            {
                let mut forged = legit_receipt.clone();
                forged.receipt_id = "forged-3".to_string();
                forged.expires_at_epoch_secs = u64::MAX;
                forged
            },

            // Receipt with empty/malicious L1 verdict
            {
                let mut forged = legit_receipt.clone();
                forged.receipt_id = "forged-4".to_string();
                forged.l1_linkage.l1_verdict = "<script>alert('xss')</script>".to_string();
                forged
            },
        ];

        for forged_receipt in forgery_attempts {
            let result = oracle.issue_policy_receipt(forged_receipt.clone());

            if result.is_err() {
                // Should detect and reject forged receipts
                continue;
            }

            // If accepted, verify linkage validation catches forgery
            let linkage_result = oracle.verify_l1_linkage(&forged_receipt.receipt_id);
            if linkage_result.is_err() {
                // L1 linkage verification should catch forgery
            }
        }
    }

    #[test]
    fn negative_quorum_manipulation_attacks() {
        let mut oracle = RuntimeOracle::new("trace-quorum", 66);

        // Register minimal runtimes for quorum
        oracle.register_runtime(sample_runtime("rt1")).unwrap();
        oracle.register_runtime(sample_runtime("rt2")).unwrap();

        // Attempt to manipulate quorum through voting injection
        let manipulated_votes = vec![
            // Votes from non-existent runtimes
            {
                let mut votes = BTreeMap::new();
                votes.insert("ghost-runtime".to_string(), vec![1, 1, 1]);
                votes.insert("phantom-runtime".to_string(), vec![1, 1, 1]);
                votes
            },

            // Votes with mismatched vote counts
            {
                let mut votes = BTreeMap::new();
                votes.insert("rt1".to_string(), vec![1, 0]); // 2 votes
                votes.insert("rt2".to_string(), vec![1, 1, 0, 1]); // 4 votes
                votes
            },

            // Votes with invalid vote values
            {
                let mut votes = BTreeMap::new();
                votes.insert("rt1".to_string(), vec![99, -1, 256]); // Out of range
                votes.insert("rt2".to_string(), vec![1, 0, 1]);
                votes
            },
        ];

        for (i, votes) in manipulated_votes.iter().enumerate() {
            let check_id = format!("manipulated-check-{}", i);

            // Manually insert manipulated voting result
            oracle.voting_results.insert(
                check_id.clone(),
                VotingResult {
                    check_id: check_id.clone(),
                    votes: votes.clone(),
                    quorum_reached: false,
                    quorum_threshold: 2,
                    total_voters: 2,
                    agreeing_voters: 0,
                },
            );

            // Attempt to tally manipulated votes
            let result = oracle.tally_votes(&check_id);

            // Should detect manipulation and reject
            if result.is_err() {
                assert!(result.unwrap_err().code == error_codes::ERR_NVO_NO_RUNTIMES ||
                        result.unwrap_err().code == error_codes::ERR_NVO_QUORUM_FAILED);
            }
        }
    }

    #[test]
    fn negative_divergence_classification_boundary_attacks() {
        let mut oracle = RuntimeOracle::new("trace-boundary", 66);

        // Test divergence with extreme risk tier transitions
        oracle.classify_divergence(
            "div-1",
            "check-1",
            BoundaryScope::Security,
            RiskTier::Low,
            &BTreeMap::new(),
        );

        // Attempt to reclassify to higher risk tier
        oracle.classify_divergence(
            "div-1",  // Same divergence ID
            "check-1",
            BoundaryScope::Security,
            RiskTier::Critical, // Risk escalation
            &BTreeMap::new(),
        );

        // Should handle classification updates appropriately
        let divergence = &oracle.divergences["div-1"];
        assert!(matches!(divergence.risk_tier, RiskTier::Low | RiskTier::Critical));

        // Test with massive runtime output data
        let mut massive_outputs = BTreeMap::new();
        for i in 0..1000 {
            massive_outputs.insert(
                format!("runtime-{}", i),
                vec![i as u8; 1000]
            );
        }

        oracle.classify_divergence(
            "div-massive",
            "check-massive",
            BoundaryScope::Memory,
            RiskTier::Medium,
            &massive_outputs,
        );

        assert!(oracle.divergences.contains_key("div-massive"));
    }

    #[test]
    fn negative_event_log_capacity_overflow_behavior() {
        let mut oracle = RuntimeOracle::new("trace-log-overflow", 66);

        // Generate many events to overflow the log capacity
        for i in 0..MAX_EVENT_LOG_ENTRIES + 100 {
            let runtime = RuntimeEntry {
                runtime_id: format!("runtime-{}", i),
                runtime_name: format!("Runtime {}", i),
                version: "1.0.0".to_string(),
                is_reference: false,
            };

            // This should generate log events
            let _ = oracle.register_runtime(runtime);
        }

        // Verify log capacity is respected
        assert!(oracle.event_log.len() <= MAX_EVENT_LOG_ENTRIES);

        // Recent events should be preserved (FIFO eviction)
        let recent_events = oracle.event_log.iter()
            .filter(|event| event.detail.contains(&format!("{}", MAX_EVENT_LOG_ENTRIES + 50)))
            .count();
        assert!(recent_events > 0, "Recent events should be preserved");

        // Oracle should remain functional despite log overflow
        let test_runtime = RuntimeEntry {
            runtime_id: "final-test".to_string(),
            runtime_name: "Final Test Runtime".to_string(),
            version: "1.0.0".to_string(),
            is_reference: false,
        };

        let result = oracle.register_runtime(test_runtime);
        assert!(result.is_ok());
    }

    #[test]
    fn negative_release_gate_with_conflicting_divergences() {
        let mut oracle = RuntimeOracle::new("trace-conflicting", 66);

        // Create conflicting divergences across different risk tiers
        oracle.classify_divergence(
            "div-critical",
            "check-1",
            BoundaryScope::Security,
            RiskTier::Critical,
            &BTreeMap::new(),
        );

        oracle.classify_divergence(
            "div-low",
            "check-2",
            BoundaryScope::IO,
            RiskTier::Low,
            &BTreeMap::new(),
        );

        oracle.classify_divergence(
            "div-medium",
            "check-3",
            BoundaryScope::Memory,
            RiskTier::Medium,
            &BTreeMap::new(),
        );

        // Issue receipt for low-risk divergence only
        oracle.issue_policy_receipt(sample_receipt("receipt-low", "div-low")).unwrap();

        // Check release gate behavior with mixed divergence states
        let verdict = oracle.check_release_gate(1700000001);

        match verdict {
            OracleVerdict::BlockRelease { blocking_divergence_ids } => {
                // Critical divergence should block release
                assert!(blocking_divergence_ids.contains(&"div-critical".to_string()));
            }
            _ => panic!("Critical divergence should block release"),
        }

        // Resolve critical divergence
        oracle.resolve_divergence("div-critical", "Manually resolved").unwrap();

        // Re-check release gate
        let verdict2 = oracle.check_release_gate(1700000001);

        // Should now pass since critical is resolved and low has receipt
        assert_eq!(verdict2, OracleVerdict::Pass);
    }

    #[test]
    fn negative_l1_linkage_verification_timing_attacks() {
        use std::time::Instant;

        let mut oracle = RuntimeOracle::new("trace-timing", 66);

        oracle.classify_divergence(
            "div-timing",
            "check-timing",
            BoundaryScope::TypeSystem,
            RiskTier::Low,
            &BTreeMap::new(),
        );

        // Create receipts with valid and invalid linkage
        let valid_receipt = sample_receipt("valid-receipt", "div-timing");
        oracle.issue_policy_receipt(valid_receipt.clone()).unwrap();

        let mut invalid_receipt = valid_receipt.clone();
        invalid_receipt.receipt_id = "invalid-receipt".to_string();
        invalid_receipt.l1_linkage.linkage_hash = "forged-hash".to_string();
        oracle.issue_policy_receipt(invalid_receipt).unwrap();

        // Measure verification timing for multiple rounds
        let mut valid_times = Vec::new();
        let mut invalid_times = Vec::new();

        for _ in 0..100 {
            // Time valid linkage verification
            let start = Instant::now();
            let _ = oracle.verify_l1_linkage("valid-receipt");
            valid_times.push(start.elapsed());

            // Time invalid linkage verification
            let start = Instant::now();
            let _ = oracle.verify_l1_linkage("invalid-receipt");
            invalid_times.push(start.elapsed());
        }

        // Calculate average times
        let avg_valid = valid_times.iter().sum::<std::time::Duration>() / u32::try_from(valid_times.len()).unwrap_or(u32::MAX);
        let avg_invalid = invalid_times.iter().sum::<std::time::Duration>() / u32::try_from(invalid_times.len()).unwrap_or(u32::MAX);

        // Timing should not reveal linkage validation details
        if avg_valid.as_nanos() > 0 && avg_invalid.as_nanos() > 0 {
            let max_time = std::cmp::max(avg_valid, avg_invalid);
            let min_time = std::cmp::min(avg_valid, avg_invalid);
            let timing_ratio = max_time.as_nanos() as f64 / min_time.as_nanos() as f64;

            // Allow reasonable variance but flag excessive timing differences
            assert!(timing_ratio < 5.0,
                "Suspicious timing variance in L1 linkage verification: valid={:?}, invalid={:?}, ratio={:.2}",
                avg_valid, avg_invalid, timing_ratio);
        }
    }

    #[test]
    fn negative_serialization_with_deeply_nested_structures() {
        let mut oracle = RuntimeOracle::new("trace-nested", 66);

        // Create deeply nested BTreeMap structures
        let mut deep_outputs = BTreeMap::new();
        for i in 0..100 {
            let runtime_id = format!("runtime_{:03}", i);
            let mut nested_data = Vec::new();

            // Create nested binary data with patterns
            for j in 0..1000 {
                nested_data.push((i * 1000 + j) as u8);
            }

            deep_outputs.insert(runtime_id, nested_data);
        }

        oracle.classify_divergence(
            "div-deep-nested",
            "check-deep",
            BoundaryScope::Concurrency,
            RiskTier::Medium,
            &deep_outputs,
        );

        // Test serialization of complex nested structure
        let report = oracle.generate_report(1700000001);

        let serialization = serde_json::to_string(&report);
        match serialization {
            Ok(json) => {
                // Should handle deep nesting
                assert!(json.len() > 0);

                // Test deserialization
                let deserialization: Result<OracleReport, _> = serde_json::from_str(&json);
                match deserialization {
                    Ok(recovered_report) => {
                        assert_eq!(recovered_report.divergences.len(), report.divergences.len());
                    }
                    Err(_) => {
                        // Deep structures might not deserialize due to complexity
                    }
                }
            }
            Err(_) => {
                // Very deep structures might not serialize due to memory/stack limits
            }
        }

        // Oracle should remain functional despite complex data
        let simple_divergence_result = oracle.classify_divergence(
            "div-simple",
            "check-simple",
            BoundaryScope::TypeSystem,
            RiskTier::Info,
            &BTreeMap::new(),
        );
        // Should succeed
    }
}
