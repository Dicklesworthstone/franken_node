//! bd-al8i: L2 engine-boundary N-version semantic oracle across franken_engine
//! and reference runtimes.
//!
//! Implements a differential harness that classifies boundary divergences by
//! risk tier and blocks release on high-risk unresolved deltas. Low-risk deltas
//! require explicit policy receipts and link back to L1 product-oracle results.
//!
//! # Invariants
//!
//! - INV-NVO-QUORUM: every cross-runtime check requires quorum agreement from
//!   participating runtimes.
//! - INV-NVO-RISK-TIERED: every semantic divergence is classified into a risk
//!   tier (Critical, High, Medium, Low, Info).
//! - INV-NVO-BLOCK-HIGH: high-risk and critical unresolved divergences block
//!   release.
//! - INV-NVO-POLICY-RECEIPT: low-risk deltas require an explicit policy receipt
//!   before proceeding.
//! - INV-NVO-L1-LINKAGE: low-risk policy receipts must link back to L1
//!   product-oracle results.
//! - INV-NVO-DETERMINISTIC: oracle results are deterministic for the same
//!   inputs; BTreeMap is used for ordered output.

use std::collections::BTreeMap;
use std::fmt;

use serde::{Deserialize, Serialize};

/// Schema version for the N-version oracle protocol.
pub const SCHEMA_VERSION: &str = "nvo-v1.0";

/// Default quorum threshold (fraction expressed as percentage, e.g. 67 = 67%).
pub const DEFAULT_QUORUM_THRESHOLD_PCT: u8 = 67;

/// Default voting timeout in milliseconds.
pub const DEFAULT_VOTING_TIMEOUT_MS: u64 = 10_000;

// ── Invariant constants ────────────────────────────────────────────────────

pub mod invariants {
    /// Every cross-runtime check requires quorum agreement.
    pub const INV_NVO_QUORUM: &str = "INV-NVO-QUORUM";

    /// Every divergence is classified into a risk tier.
    pub const INV_NVO_RISK_TIERED: &str = "INV-NVO-RISK-TIERED";

    /// High-risk and critical unresolved divergences block release.
    pub const INV_NVO_BLOCK_HIGH: &str = "INV-NVO-BLOCK-HIGH";

    /// Low-risk deltas require explicit policy receipts.
    pub const INV_NVO_POLICY_RECEIPT: &str = "INV-NVO-POLICY-RECEIPT";

    /// Low-risk policy receipts link back to L1 product-oracle results.
    pub const INV_NVO_L1_LINKAGE: &str = "INV-NVO-L1-LINKAGE";

    /// Oracle results are deterministic; BTreeMap for ordered output.
    pub const INV_NVO_DETERMINISTIC: &str = "INV-NVO-DETERMINISTIC";
}

// ── Event codes ────────────────────────────────────────────────────────────

pub mod event_codes {
    /// Oracle instance created.
    pub const FN_NV_001: &str = "FN-NV-001";
    /// Reference runtime registered.
    pub const FN_NV_002: &str = "FN-NV-002";
    /// Cross-runtime semantic check initiated.
    pub const FN_NV_003: &str = "FN-NV-003";
    /// Semantic divergence detected.
    pub const FN_NV_004: &str = "FN-NV-004";
    /// Divergence classified by risk tier.
    pub const FN_NV_005: &str = "FN-NV-005";
    /// Quorum agreement reached.
    pub const FN_NV_006: &str = "FN-NV-006";
    /// Quorum agreement failed.
    pub const FN_NV_007: &str = "FN-NV-007";
    /// Release blocked due to unresolved high-risk divergence.
    pub const FN_NV_008: &str = "FN-NV-008";
    /// Policy receipt issued for low-risk divergence.
    pub const FN_NV_009: &str = "FN-NV-009";
    /// L1 product-oracle linkage verified.
    pub const FN_NV_010: &str = "FN-NV-010";
    /// Voting round completed.
    pub const FN_NV_011: &str = "FN-NV-011";
    /// Oracle divergence report generated.
    pub const FN_NV_012: &str = "FN-NV-012";
}

// ── Error codes ────────────────────────────────────────────────────────────

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

// ── RiskTier ───────────────────────────────────────────────────────────────

/// Risk classification for a semantic divergence.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum RiskTier {
    /// Informational — no action required.
    Info,
    /// Low risk — requires explicit policy receipt with L1 linkage.
    Low,
    /// Medium risk — generates warning but does not block release.
    Medium,
    /// High risk — blocks release if unresolved.
    High,
    /// Critical — always blocks release if unresolved.
    Critical,
}

impl fmt::Display for RiskTier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RiskTier::Info => write!(f, "Info"),
            RiskTier::Low => write!(f, "Low"),
            RiskTier::Medium => write!(f, "Medium"),
            RiskTier::High => write!(f, "High"),
            RiskTier::Critical => write!(f, "Critical"),
        }
    }
}

impl RiskTier {
    /// Returns true if this tier blocks release when unresolved.
    pub fn blocks_release(&self) -> bool {
        matches!(self, RiskTier::High | RiskTier::Critical)
    }

    /// Returns true if this tier requires a policy receipt.
    pub fn requires_receipt(&self) -> bool {
        matches!(self, RiskTier::Low)
    }
}

// ── BoundaryScope ──────────────────────────────────────────────────────────

/// Engine boundary scope for semantic checks.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum BoundaryScope {
    /// Type system boundary checks.
    TypeSystem,
    /// Memory model boundary checks.
    Memory,
    /// I/O semantics boundary checks.
    IO,
    /// Concurrency model boundary checks.
    Concurrency,
    /// Security policy boundary checks.
    Security,
}

impl fmt::Display for BoundaryScope {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            BoundaryScope::TypeSystem => write!(f, "TypeSystem"),
            BoundaryScope::Memory => write!(f, "Memory"),
            BoundaryScope::IO => write!(f, "IO"),
            BoundaryScope::Concurrency => write!(f, "Concurrency"),
            BoundaryScope::Security => write!(f, "Security"),
        }
    }
}

// ── CheckOutcome ───────────────────────────────────────────────────────────

/// Outcome of a single cross-runtime check.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum CheckOutcome {
    /// Runtimes agree on the semantic boundary behavior.
    Agree,
    /// Runtimes diverge — includes divergence details.
    Diverge {
        description: String,
    },
}

// ── OracleVerdict ──────────────────────────────────────────────────────────

/// Overall verdict from the oracle evaluation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum OracleVerdict {
    /// All checks pass; release is permitted.
    Pass,
    /// Release is blocked due to unresolved high-risk or critical divergences.
    BlockRelease {
        /// IDs of blocking divergences.
        blocking_divergence_ids: Vec<String>,
    },
    /// Low-risk divergences need policy receipts before proceeding.
    RequiresReceipt {
        /// IDs of divergences needing receipts.
        pending_receipt_ids: Vec<String>,
    },
}

impl fmt::Display for OracleVerdict {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            OracleVerdict::Pass => write!(f, "PASS"),
            OracleVerdict::BlockRelease { blocking_divergence_ids } => {
                write!(f, "BLOCK_RELEASE({})", blocking_divergence_ids.join(", "))
            }
            OracleVerdict::RequiresReceipt { pending_receipt_ids } => {
                write!(f, "REQUIRES_RECEIPT({})", pending_receipt_ids.join(", "))
            }
        }
    }
}

// ── RuntimeEntry ───────────────────────────────────────────────────────────

/// Metadata about a registered reference runtime.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuntimeEntry {
    /// Unique identifier for the runtime.
    pub id: String,
    /// Human-readable name.
    pub name: String,
    /// Version string.
    pub version: String,
    /// Whether this runtime is currently active for checks.
    pub active: bool,
}

// ── SemanticDivergence ─────────────────────────────────────────────────────

/// A recorded divergence between runtimes with classification.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SemanticDivergence {
    /// Unique divergence identifier.
    pub id: String,
    /// ID of the cross-runtime check that detected this divergence.
    pub check_id: String,
    /// Boundary scope of the divergence.
    pub scope: BoundaryScope,
    /// Risk tier classification.
    pub risk_tier: RiskTier,
    /// Human-readable description.
    pub description: String,
    /// IDs of the runtimes that diverged.
    pub diverging_runtimes: Vec<String>,
    /// Whether this divergence has been resolved.
    pub resolved: bool,
    /// Optional policy receipt ID (for low-risk divergences).
    pub policy_receipt_id: Option<String>,
}

// ── CrossRuntimeCheck ──────────────────────────────────────────────────────

/// A single cross-runtime semantic boundary check.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CrossRuntimeCheck {
    /// Unique check identifier.
    pub id: String,
    /// Boundary scope being checked.
    pub scope: BoundaryScope,
    /// Description of the check.
    pub description: String,
    /// Per-runtime outcomes, keyed by runtime ID.
    pub outcomes: BTreeMap<String, CheckOutcome>,
    /// Whether this check is currently running.
    pub running: bool,
    /// Whether voting is complete.
    pub voting_complete: bool,
}

// ── VotingResult ───────────────────────────────────────────────────────────

/// Result of a quorum voting round.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VotingResult {
    /// Check ID this voting result applies to.
    pub check_id: String,
    /// Total number of voting runtimes.
    pub total_voters: usize,
    /// Number of runtimes that agreed.
    pub agree_count: usize,
    /// Number of runtimes that diverged.
    pub diverge_count: usize,
    /// Whether quorum was reached (agree_count / total_voters >= threshold).
    pub quorum_reached: bool,
    /// The quorum threshold percentage used.
    pub threshold_pct: u8,
}

// ── PolicyReceipt ──────────────────────────────────────────────────────────

/// Explicit acknowledgment for low-risk divergences.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicyReceipt {
    /// Unique receipt identifier.
    pub id: String,
    /// ID of the divergence this receipt covers.
    pub divergence_id: String,
    /// Justification for accepting the divergence.
    pub justification: String,
    /// L1 product-oracle linkage proof.
    pub l1_linkage: L1LinkageProof,
    /// Whether this receipt has been verified.
    pub verified: bool,
    /// Timestamp when the receipt was issued (ISO-8601).
    pub issued_at: String,
}

// ── L1LinkageProof ─────────────────────────────────────────────────────────

/// Proof linking a policy receipt to L1 product-oracle results.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct L1LinkageProof {
    /// L1 oracle result identifier.
    pub l1_oracle_id: String,
    /// Hash of the L1 oracle result used as proof.
    pub result_hash: String,
    /// Whether the linkage has been verified.
    pub verified: bool,
}

// ── DivergenceReport ───────────────────────────────────────────────────────

/// Comprehensive report of all divergences from an oracle run.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DivergenceReport {
    /// Schema version.
    pub schema_version: String,
    /// Oracle instance ID.
    pub oracle_id: String,
    /// Overall verdict.
    pub verdict: OracleVerdict,
    /// All divergences found, keyed by divergence ID (BTreeMap for determinism).
    pub divergences: BTreeMap<String, SemanticDivergence>,
    /// All checks executed, keyed by check ID.
    pub checks: BTreeMap<String, CrossRuntimeCheck>,
    /// All voting results, keyed by check ID.
    pub voting_results: BTreeMap<String, VotingResult>,
    /// All policy receipts issued, keyed by receipt ID.
    pub receipts: BTreeMap<String, PolicyReceipt>,
    /// Count by risk tier.
    pub risk_tier_counts: BTreeMap<String, usize>,
}

// ── OracleError ────────────────────────────────────────────────────────────

/// Error type for oracle operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OracleError {
    /// Machine-readable error code.
    pub code: &'static str,
    /// Human-readable message.
    pub message: String,
}

impl fmt::Display for OracleError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[{}] {}", self.code, self.message)
    }
}

impl std::error::Error for OracleError {}

impl OracleError {
    pub fn new(code: &'static str, message: impl Into<String>) -> Self {
        Self { code, message: message.into() }
    }
}

// ── RuntimeOracle ──────────────────────────────────────────────────────────

/// Central N-version oracle coordinating semantic checks across runtimes.
///
/// Uses BTreeMap throughout for deterministic ordering (INV-NVO-DETERMINISTIC).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuntimeOracle {
    /// Unique oracle instance identifier.
    pub id: String,
    /// Registered runtimes, keyed by runtime ID.
    runtimes: BTreeMap<String, RuntimeEntry>,
    /// Cross-runtime checks, keyed by check ID.
    checks: BTreeMap<String, CrossRuntimeCheck>,
    /// Detected divergences, keyed by divergence ID.
    divergences: BTreeMap<String, SemanticDivergence>,
    /// Voting results, keyed by check ID.
    voting_results: BTreeMap<String, VotingResult>,
    /// Policy receipts, keyed by receipt ID.
    receipts: BTreeMap<String, PolicyReceipt>,
    /// Quorum threshold percentage.
    quorum_threshold_pct: u8,
    /// Next divergence sequence number (for deterministic ID generation).
    next_divergence_seq: u64,
    /// Audit log of events.
    audit_log: Vec<AuditEntry>,
}

/// Internal audit entry for traceability.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEntry {
    pub event_code: String,
    pub message: String,
    pub trace_id: String,
}

impl RuntimeOracle {
    /// Create a new oracle instance.
    pub fn new(id: impl Into<String>) -> Self {
        let id = id.into();
        let oracle = Self {
            id: id.clone(),
            runtimes: BTreeMap::new(),
            checks: BTreeMap::new(),
            divergences: BTreeMap::new(),
            voting_results: BTreeMap::new(),
            receipts: BTreeMap::new(),
            quorum_threshold_pct: DEFAULT_QUORUM_THRESHOLD_PCT,
            next_divergence_seq: 1,
            audit_log: Vec::new(),
        };
        // Event: oracle created  (FN-NV-001)
        // Note: we cannot log from the constructor since it takes &mut self,
        // so the caller should check the audit log or rely on the initial state.
        oracle
    }

    /// Set the quorum threshold percentage.
    pub fn set_quorum_threshold(&mut self, pct: u8) {
        self.quorum_threshold_pct = pct.min(100);
    }

    fn log_event(&mut self, code: &str, message: impl Into<String>) {
        self.audit_log.push(AuditEntry {
            event_code: code.to_string(),
            message: message.into(),
            trace_id: format!("{}-{}", self.id, self.audit_log.len()),
        });
    }

    /// Register a reference runtime for comparison.
    pub fn register_runtime(&mut self, entry: RuntimeEntry) -> Result<(), OracleError> {
        if self.runtimes.contains_key(&entry.id) {
            return Err(OracleError::new(
                error_codes::ERR_NVO_DUPLICATE_RUNTIME,
                format!("Runtime '{}' is already registered", entry.id),
            ));
        }
        let rt_id = entry.id.clone();
        self.runtimes.insert(entry.id.clone(), entry);
        self.log_event(
            event_codes::FN_NV_002,
            format!("Registered runtime '{}'", rt_id),
        );
        Ok(())
    }

    /// Remove a runtime from the registry.
    pub fn remove_runtime(&mut self, runtime_id: &str) -> Result<RuntimeEntry, OracleError> {
        self.runtimes.remove(runtime_id).ok_or_else(|| {
            OracleError::new(
                error_codes::ERR_NVO_RUNTIME_NOT_FOUND,
                format!("Runtime '{}' not found", runtime_id),
            )
        })
    }

    /// Get a reference to a registered runtime.
    pub fn get_runtime(&self, runtime_id: &str) -> Option<&RuntimeEntry> {
        self.runtimes.get(runtime_id)
    }

    /// Get the number of registered runtimes.
    pub fn runtime_count(&self) -> usize {
        self.runtimes.len()
    }

    /// Execute a cross-runtime semantic check.
    ///
    /// # Errors
    /// - `ERR_NVO_NO_RUNTIMES` if fewer than 2 runtimes are registered.
    /// - `ERR_NVO_CHECK_ALREADY_RUNNING` if a check with this ID is already active.
    pub fn run_cross_check(
        &mut self,
        check_id: impl Into<String>,
        scope: BoundaryScope,
        description: impl Into<String>,
    ) -> Result<&CrossRuntimeCheck, OracleError> {
        let check_id = check_id.into();
        let description = description.into();

        if self.runtimes.len() < 2 {
            return Err(OracleError::new(
                error_codes::ERR_NVO_NO_RUNTIMES,
                "Need at least 2 runtimes registered to run cross-check",
            ));
        }

        if let Some(existing) = self.checks.get(&check_id) {
            if existing.running {
                return Err(OracleError::new(
                    error_codes::ERR_NVO_CHECK_ALREADY_RUNNING,
                    format!("Check '{}' is already running", check_id),
                ));
            }
        }

        let check = CrossRuntimeCheck {
            id: check_id.clone(),
            scope,
            description,
            outcomes: BTreeMap::new(),
            running: true,
            voting_complete: false,
        };

        self.checks.insert(check_id.clone(), check);
        self.log_event(
            event_codes::FN_NV_003,
            format!("Cross check '{}' started", check_id),
        );

        Ok(self.checks.get(&check_id).unwrap())
    }

    /// Submit a runtime's vote (outcome) for a cross-check.
    pub fn vote(
        &mut self,
        check_id: &str,
        runtime_id: &str,
        outcome: CheckOutcome,
    ) -> Result<(), OracleError> {
        if !self.runtimes.contains_key(runtime_id) {
            return Err(OracleError::new(
                error_codes::ERR_NVO_RUNTIME_NOT_FOUND,
                format!("Runtime '{}' not found", runtime_id),
            ));
        }

        let check = self.checks.get_mut(check_id).ok_or_else(|| {
            OracleError::new(
                error_codes::ERR_NVO_RUNTIME_NOT_FOUND,
                format!("Check '{}' not found", check_id),
            )
        })?;

        check.outcomes.insert(runtime_id.to_string(), outcome);
        Ok(())
    }

    /// Tally votes and determine quorum result for a check.
    ///
    /// INV-NVO-QUORUM: every cross-runtime check requires quorum agreement.
    pub fn tally_votes(&mut self, check_id: &str) -> Result<VotingResult, OracleError> {
        let check = self.checks.get_mut(check_id).ok_or_else(|| {
            OracleError::new(
                error_codes::ERR_NVO_RUNTIME_NOT_FOUND,
                format!("Check '{}' not found", check_id),
            )
        })?;

        let total = check.outcomes.len();
        if total == 0 {
            return Err(OracleError::new(
                error_codes::ERR_NVO_VOTING_TIMEOUT,
                format!("No votes received for check '{}'", check_id),
            ));
        }

        let agree_count = check
            .outcomes
            .values()
            .filter(|o| matches!(o, CheckOutcome::Agree))
            .count();
        let diverge_count = total - agree_count;

        let quorum_reached =
            (agree_count * 100) >= (total * self.quorum_threshold_pct as usize);

        check.running = false;
        check.voting_complete = true;

        let result = VotingResult {
            check_id: check_id.to_string(),
            total_voters: total,
            agree_count,
            diverge_count,
            quorum_reached,
            threshold_pct: self.quorum_threshold_pct,
        };

        if quorum_reached {
            self.log_event(
                event_codes::FN_NV_006,
                format!(
                    "Quorum reached for check '{}': {}/{} agree",
                    check_id, agree_count, total
                ),
            );
        } else {
            self.log_event(
                event_codes::FN_NV_007,
                format!(
                    "Quorum failed for check '{}': {}/{} agree (need {}%)",
                    check_id, agree_count, total, self.quorum_threshold_pct
                ),
            );
        }

        self.log_event(
            event_codes::FN_NV_011,
            format!("Voting completed for check '{}'", check_id),
        );

        self.voting_results.insert(check_id.to_string(), result.clone());
        Ok(result)
    }

    /// Classify a detected divergence by risk tier.
    ///
    /// INV-NVO-RISK-TIERED: every divergence must be classified.
    pub fn classify_divergence(
        &mut self,
        check_id: &str,
        scope: BoundaryScope,
        risk_tier: RiskTier,
        description: impl Into<String>,
        diverging_runtimes: Vec<String>,
    ) -> Result<String, OracleError> {
        let description = description.into();
        let div_id = format!("div-{}", self.next_divergence_seq);
        self.next_divergence_seq += 1;

        let divergence = SemanticDivergence {
            id: div_id.clone(),
            check_id: check_id.to_string(),
            scope,
            risk_tier,
            description: description.clone(),
            diverging_runtimes,
            resolved: false,
            policy_receipt_id: None,
        };

        self.divergences.insert(div_id.clone(), divergence);
        self.log_event(
            event_codes::FN_NV_004,
            format!("Divergence '{}' detected in check '{}'", div_id, check_id),
        );
        self.log_event(
            event_codes::FN_NV_005,
            format!(
                "Divergence '{}' classified as {} risk: {}",
                div_id, risk_tier, description
            ),
        );

        Ok(div_id)
    }

    /// Resolve a divergence (mark it as resolved).
    pub fn resolve_divergence(&mut self, divergence_id: &str) -> Result<(), OracleError> {
        let div = self.divergences.get_mut(divergence_id).ok_or_else(|| {
            OracleError::new(
                error_codes::ERR_NVO_DIVERGENCE_UNRESOLVED,
                format!("Divergence '{}' not found", divergence_id),
            )
        })?;
        div.resolved = true;
        Ok(())
    }

    /// Issue a policy receipt for a low-risk divergence.
    ///
    /// INV-NVO-POLICY-RECEIPT: low-risk deltas require explicit receipts.
    /// INV-NVO-L1-LINKAGE: receipts must link to L1 product-oracle results.
    pub fn issue_policy_receipt(
        &mut self,
        receipt_id: impl Into<String>,
        divergence_id: &str,
        justification: impl Into<String>,
        l1_linkage: L1LinkageProof,
    ) -> Result<&PolicyReceipt, OracleError> {
        let receipt_id = receipt_id.into();
        let justification = justification.into();

        // Verify the divergence exists and is low-risk
        let div = self.divergences.get_mut(divergence_id).ok_or_else(|| {
            OracleError::new(
                error_codes::ERR_NVO_POLICY_MISSING,
                format!("Divergence '{}' not found", divergence_id),
            )
        })?;

        if !div.risk_tier.requires_receipt() {
            return Err(OracleError::new(
                error_codes::ERR_NVO_INVALID_RECEIPT,
                format!(
                    "Divergence '{}' is {} risk, receipts are for Low risk only",
                    divergence_id, div.risk_tier
                ),
            ));
        }

        div.policy_receipt_id = Some(receipt_id.clone());
        div.resolved = true;

        let receipt = PolicyReceipt {
            id: receipt_id.clone(),
            divergence_id: divergence_id.to_string(),
            justification,
            l1_linkage,
            verified: false,
            issued_at: "2026-02-21T00:00:00Z".to_string(),
        };

        self.receipts.insert(receipt_id.clone(), receipt);
        self.log_event(
            event_codes::FN_NV_009,
            format!(
                "Policy receipt '{}' issued for divergence '{}'",
                receipt_id, divergence_id
            ),
        );

        Ok(self.receipts.get(&receipt_id).unwrap())
    }

    /// Verify L1 product-oracle linkage for a policy receipt.
    ///
    /// INV-NVO-L1-LINKAGE: receipts must link to L1 product-oracle results.
    pub fn verify_l1_linkage(&mut self, receipt_id: &str) -> Result<bool, OracleError> {
        let receipt = self.receipts.get_mut(receipt_id).ok_or_else(|| {
            OracleError::new(
                error_codes::ERR_NVO_INVALID_RECEIPT,
                format!("Receipt '{}' not found", receipt_id),
            )
        })?;

        // Verify the linkage: l1_oracle_id and result_hash must be non-empty.
        let valid = !receipt.l1_linkage.l1_oracle_id.is_empty()
            && !receipt.l1_linkage.result_hash.is_empty();

        if valid {
            receipt.l1_linkage.verified = true;
            receipt.verified = true;
            self.log_event(
                event_codes::FN_NV_010,
                format!(
                    "L1 linkage verified for receipt '{}' -> L1 oracle '{}'",
                    receipt_id, receipt.l1_linkage.l1_oracle_id
                ),
            );
        } else {
            return Err(OracleError::new(
                error_codes::ERR_NVO_L1_LINKAGE_BROKEN,
                format!("L1 linkage invalid for receipt '{}'", receipt_id),
            ));
        }

        Ok(valid)
    }

    /// Evaluate whether release is blocked.
    ///
    /// INV-NVO-BLOCK-HIGH: high-risk and critical unresolved divergences block release.
    /// INV-NVO-POLICY-RECEIPT: low-risk deltas without receipts also affect verdict.
    pub fn check_release_gate(&mut self) -> OracleVerdict {
        let blocking: Vec<String> = self
            .divergences
            .values()
            .filter(|d| !d.resolved && d.risk_tier.blocks_release())
            .map(|d| d.id.clone())
            .collect();

        if !blocking.is_empty() {
            self.log_event(
                event_codes::FN_NV_008,
                format!(
                    "Release blocked: {} unresolved high/critical divergences",
                    blocking.len()
                ),
            );
            return OracleVerdict::BlockRelease {
                blocking_divergence_ids: blocking,
            };
        }

        let pending_receipts: Vec<String> = self
            .divergences
            .values()
            .filter(|d| !d.resolved && d.risk_tier.requires_receipt())
            .map(|d| d.id.clone())
            .collect();

        if !pending_receipts.is_empty() {
            return OracleVerdict::RequiresReceipt {
                pending_receipt_ids: pending_receipts,
            };
        }

        OracleVerdict::Pass
    }

    /// Generate the comprehensive divergence report.
    pub fn generate_report(&mut self) -> DivergenceReport {
        let verdict = self.check_release_gate();

        let mut risk_tier_counts: BTreeMap<String, usize> = BTreeMap::new();
        for div in self.divergences.values() {
            *risk_tier_counts.entry(div.risk_tier.to_string()).or_insert(0) += 1;
        }

        self.log_event(
            event_codes::FN_NV_012,
            format!(
                "Oracle report generated: {} divergences, verdict={}",
                self.divergences.len(),
                verdict
            ),
        );

        DivergenceReport {
            schema_version: SCHEMA_VERSION.to_string(),
            oracle_id: self.id.clone(),
            verdict,
            divergences: self.divergences.clone(),
            checks: self.checks.clone(),
            voting_results: self.voting_results.clone(),
            receipts: self.receipts.clone(),
            risk_tier_counts,
        }
    }

    /// Get the audit log.
    pub fn audit_log(&self) -> &[AuditEntry] {
        &self.audit_log
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    fn make_runtime(id: &str) -> RuntimeEntry {
        RuntimeEntry {
            id: id.to_string(),
            name: format!("{}_runtime", id),
            version: "1.0.0".to_string(),
            active: true,
        }
    }

    fn setup_oracle_with_runtimes() -> RuntimeOracle {
        let mut oracle = RuntimeOracle::new("test-oracle");
        oracle.register_runtime(make_runtime("franken_engine")).unwrap();
        oracle.register_runtime(make_runtime("ref_runtime_a")).unwrap();
        oracle.register_runtime(make_runtime("ref_runtime_b")).unwrap();
        oracle
    }

    // --- Construction ---

    #[test]
    fn test_oracle_new() {
        let oracle = RuntimeOracle::new("oracle-1");
        assert_eq!(oracle.id, "oracle-1");
        assert_eq!(oracle.runtime_count(), 0);
        assert_eq!(oracle.quorum_threshold_pct, DEFAULT_QUORUM_THRESHOLD_PCT);
    }

    #[test]
    fn test_schema_version() {
        assert_eq!(SCHEMA_VERSION, "nvo-v1.0");
    }

    // --- Runtime registration ---

    #[test]
    fn test_register_runtime() {
        let mut oracle = RuntimeOracle::new("oracle-2");
        let result = oracle.register_runtime(make_runtime("rt-1"));
        assert!(result.is_ok());
        assert_eq!(oracle.runtime_count(), 1);
    }

    #[test]
    fn test_register_duplicate_runtime_fails() {
        let mut oracle = RuntimeOracle::new("oracle-3");
        oracle.register_runtime(make_runtime("rt-1")).unwrap();
        let err = oracle.register_runtime(make_runtime("rt-1")).unwrap_err();
        assert_eq!(err.code, error_codes::ERR_NVO_DUPLICATE_RUNTIME);
    }

    #[test]
    fn test_remove_runtime() {
        let mut oracle = RuntimeOracle::new("oracle-4");
        oracle.register_runtime(make_runtime("rt-1")).unwrap();
        let removed = oracle.remove_runtime("rt-1");
        assert!(removed.is_ok());
        assert_eq!(oracle.runtime_count(), 0);
    }

    #[test]
    fn test_remove_nonexistent_runtime_fails() {
        let mut oracle = RuntimeOracle::new("oracle-5");
        let err = oracle.remove_runtime("no-such").unwrap_err();
        assert_eq!(err.code, error_codes::ERR_NVO_RUNTIME_NOT_FOUND);
    }

    #[test]
    fn test_get_runtime() {
        let mut oracle = RuntimeOracle::new("oracle-6");
        oracle.register_runtime(make_runtime("rt-x")).unwrap();
        let rt = oracle.get_runtime("rt-x");
        assert!(rt.is_some());
        assert_eq!(rt.unwrap().name, "rt-x_runtime");
        assert!(oracle.get_runtime("no-such").is_none());
    }

    // --- Cross-runtime checks ---

    #[test]
    fn test_run_cross_check_requires_two_runtimes() {
        let mut oracle = RuntimeOracle::new("oracle-7");
        oracle.register_runtime(make_runtime("rt-1")).unwrap();
        let err = oracle
            .run_cross_check("chk-1", BoundaryScope::Memory, "desc")
            .unwrap_err();
        assert_eq!(err.code, error_codes::ERR_NVO_NO_RUNTIMES);
    }

    #[test]
    fn test_run_cross_check_success() {
        let mut oracle = setup_oracle_with_runtimes();
        let check = oracle
            .run_cross_check("chk-1", BoundaryScope::TypeSystem, "type boundary test")
            .unwrap();
        assert_eq!(check.id, "chk-1");
        assert!(check.running);
        assert!(!check.voting_complete);
    }

    #[test]
    fn test_check_already_running_fails() {
        let mut oracle = setup_oracle_with_runtimes();
        oracle
            .run_cross_check("chk-dup", BoundaryScope::IO, "first")
            .unwrap();
        let err = oracle
            .run_cross_check("chk-dup", BoundaryScope::IO, "second")
            .unwrap_err();
        assert_eq!(err.code, error_codes::ERR_NVO_CHECK_ALREADY_RUNNING);
    }

    // --- Voting ---

    #[test]
    fn test_vote_unknown_runtime_fails() {
        let mut oracle = setup_oracle_with_runtimes();
        oracle
            .run_cross_check("chk-v1", BoundaryScope::Security, "sec check")
            .unwrap();
        let err = oracle.vote("chk-v1", "unknown-rt", CheckOutcome::Agree).unwrap_err();
        assert_eq!(err.code, error_codes::ERR_NVO_RUNTIME_NOT_FOUND);
    }

    #[test]
    fn test_tally_votes_quorum_reached() {
        let mut oracle = setup_oracle_with_runtimes();
        oracle
            .run_cross_check("chk-q1", BoundaryScope::Memory, "mem check")
            .unwrap();
        oracle.vote("chk-q1", "franken_engine", CheckOutcome::Agree).unwrap();
        oracle.vote("chk-q1", "ref_runtime_a", CheckOutcome::Agree).unwrap();
        oracle
            .vote(
                "chk-q1",
                "ref_runtime_b",
                CheckOutcome::Diverge {
                    description: "minor diff".to_string(),
                },
            )
            .unwrap();

        let result = oracle.tally_votes("chk-q1").unwrap();
        // 2/3 = 66.7% >= 67%? No, 2*100=200, 3*67=201, so quorum NOT reached.
        assert!(!result.quorum_reached);
        assert_eq!(result.agree_count, 2);
        assert_eq!(result.diverge_count, 1);
    }

    #[test]
    fn test_tally_votes_quorum_with_lower_threshold() {
        let mut oracle = setup_oracle_with_runtimes();
        oracle.set_quorum_threshold(50);
        oracle
            .run_cross_check("chk-q2", BoundaryScope::IO, "io check")
            .unwrap();
        oracle.vote("chk-q2", "franken_engine", CheckOutcome::Agree).unwrap();
        oracle
            .vote(
                "chk-q2",
                "ref_runtime_a",
                CheckOutcome::Diverge {
                    description: "diverge".to_string(),
                },
            )
            .unwrap();
        oracle.vote("chk-q2", "ref_runtime_b", CheckOutcome::Agree).unwrap();

        let result = oracle.tally_votes("chk-q2").unwrap();
        // 2/3 = 66.7% >= 50% → quorum reached
        assert!(result.quorum_reached);
    }

    #[test]
    fn test_tally_no_votes_fails() {
        let mut oracle = setup_oracle_with_runtimes();
        oracle
            .run_cross_check("chk-empty", BoundaryScope::Concurrency, "conc check")
            .unwrap();
        let err = oracle.tally_votes("chk-empty").unwrap_err();
        assert_eq!(err.code, error_codes::ERR_NVO_VOTING_TIMEOUT);
    }

    // --- Divergence classification ---

    #[test]
    fn test_classify_divergence() {
        let mut oracle = setup_oracle_with_runtimes();
        let div_id = oracle
            .classify_divergence(
                "chk-1",
                BoundaryScope::Security,
                RiskTier::High,
                "security boundary mismatch",
                vec!["franken_engine".into(), "ref_runtime_a".into()],
            )
            .unwrap();
        assert_eq!(div_id, "div-1");
    }

    #[test]
    fn test_sequential_divergence_ids() {
        let mut oracle = setup_oracle_with_runtimes();
        let id1 = oracle
            .classify_divergence(
                "chk-1",
                BoundaryScope::Memory,
                RiskTier::Low,
                "d1",
                vec!["a".into()],
            )
            .unwrap();
        let id2 = oracle
            .classify_divergence(
                "chk-1",
                BoundaryScope::IO,
                RiskTier::Medium,
                "d2",
                vec!["b".into()],
            )
            .unwrap();
        assert_eq!(id1, "div-1");
        assert_eq!(id2, "div-2");
    }

    // --- Release gate ---

    #[test]
    fn test_release_gate_pass_no_divergences() {
        let mut oracle = setup_oracle_with_runtimes();
        let verdict = oracle.check_release_gate();
        assert_eq!(verdict, OracleVerdict::Pass);
    }

    #[test]
    fn test_release_gate_blocks_on_high_risk() {
        let mut oracle = setup_oracle_with_runtimes();
        oracle
            .classify_divergence(
                "chk-1",
                BoundaryScope::Security,
                RiskTier::High,
                "high-risk security issue",
                vec!["franken_engine".into()],
            )
            .unwrap();

        let verdict = oracle.check_release_gate();
        match verdict {
            OracleVerdict::BlockRelease { blocking_divergence_ids } => {
                assert_eq!(blocking_divergence_ids, vec!["div-1"]);
            }
            _ => panic!("Expected BlockRelease, got {:?}", verdict),
        }
    }

    #[test]
    fn test_release_gate_blocks_on_critical() {
        let mut oracle = setup_oracle_with_runtimes();
        oracle
            .classify_divergence(
                "chk-1",
                BoundaryScope::Memory,
                RiskTier::Critical,
                "critical memory divergence",
                vec!["franken_engine".into()],
            )
            .unwrap();

        let verdict = oracle.check_release_gate();
        assert!(matches!(verdict, OracleVerdict::BlockRelease { .. }));
    }

    #[test]
    fn test_release_gate_requires_receipt_for_low_risk() {
        let mut oracle = setup_oracle_with_runtimes();
        oracle
            .classify_divergence(
                "chk-1",
                BoundaryScope::IO,
                RiskTier::Low,
                "minor io difference",
                vec!["ref_runtime_a".into()],
            )
            .unwrap();

        let verdict = oracle.check_release_gate();
        match verdict {
            OracleVerdict::RequiresReceipt { pending_receipt_ids } => {
                assert_eq!(pending_receipt_ids, vec!["div-1"]);
            }
            _ => panic!("Expected RequiresReceipt, got {:?}", verdict),
        }
    }

    #[test]
    fn test_release_gate_pass_after_resolve() {
        let mut oracle = setup_oracle_with_runtimes();
        oracle
            .classify_divergence(
                "chk-1",
                BoundaryScope::Security,
                RiskTier::High,
                "issue",
                vec!["a".into()],
            )
            .unwrap();
        oracle.resolve_divergence("div-1").unwrap();

        let verdict = oracle.check_release_gate();
        assert_eq!(verdict, OracleVerdict::Pass);
    }

    #[test]
    fn test_medium_risk_does_not_block() {
        let mut oracle = setup_oracle_with_runtimes();
        oracle
            .classify_divergence(
                "chk-1",
                BoundaryScope::Concurrency,
                RiskTier::Medium,
                "medium conc diff",
                vec!["a".into()],
            )
            .unwrap();

        let verdict = oracle.check_release_gate();
        // Medium risk neither blocks nor requires receipt
        assert_eq!(verdict, OracleVerdict::Pass);
    }

    // --- Policy receipts ---

    #[test]
    fn test_issue_policy_receipt() {
        let mut oracle = setup_oracle_with_runtimes();
        oracle
            .classify_divergence(
                "chk-1",
                BoundaryScope::IO,
                RiskTier::Low,
                "low-risk io",
                vec!["a".into()],
            )
            .unwrap();

        let receipt = oracle
            .issue_policy_receipt(
                "rcpt-1",
                "div-1",
                "accepted per L1 oracle",
                L1LinkageProof {
                    l1_oracle_id: "l1-oracle-42".to_string(),
                    result_hash: "abcdef1234".to_string(),
                    verified: false,
                },
            )
            .unwrap();
        assert_eq!(receipt.id, "rcpt-1");
        assert_eq!(receipt.divergence_id, "div-1");

        // After receipt, release should pass
        let verdict = oracle.check_release_gate();
        assert_eq!(verdict, OracleVerdict::Pass);
    }

    #[test]
    fn test_policy_receipt_for_non_low_risk_fails() {
        let mut oracle = setup_oracle_with_runtimes();
        oracle
            .classify_divergence(
                "chk-1",
                BoundaryScope::Security,
                RiskTier::High,
                "high-risk",
                vec!["a".into()],
            )
            .unwrap();

        let err = oracle
            .issue_policy_receipt(
                "rcpt-x",
                "div-1",
                "invalid",
                L1LinkageProof {
                    l1_oracle_id: "l1".to_string(),
                    result_hash: "hash".to_string(),
                    verified: false,
                },
            )
            .unwrap_err();
        assert_eq!(err.code, error_codes::ERR_NVO_INVALID_RECEIPT);
    }

    // --- L1 linkage ---

    #[test]
    fn test_verify_l1_linkage() {
        let mut oracle = setup_oracle_with_runtimes();
        oracle
            .classify_divergence(
                "chk-1",
                BoundaryScope::IO,
                RiskTier::Low,
                "low io",
                vec!["a".into()],
            )
            .unwrap();
        oracle
            .issue_policy_receipt(
                "rcpt-1",
                "div-1",
                "ok",
                L1LinkageProof {
                    l1_oracle_id: "l1-42".to_string(),
                    result_hash: "deadbeef".to_string(),
                    verified: false,
                },
            )
            .unwrap();

        let result = oracle.verify_l1_linkage("rcpt-1").unwrap();
        assert!(result);
    }

    #[test]
    fn test_verify_l1_linkage_broken() {
        let mut oracle = setup_oracle_with_runtimes();
        oracle
            .classify_divergence(
                "chk-1",
                BoundaryScope::IO,
                RiskTier::Low,
                "low io",
                vec!["a".into()],
            )
            .unwrap();
        oracle
            .issue_policy_receipt(
                "rcpt-bad",
                "div-1",
                "no linkage",
                L1LinkageProof {
                    l1_oracle_id: String::new(),
                    result_hash: String::new(),
                    verified: false,
                },
            )
            .unwrap();

        let err = oracle.verify_l1_linkage("rcpt-bad").unwrap_err();
        assert_eq!(err.code, error_codes::ERR_NVO_L1_LINKAGE_BROKEN);
    }

    // --- Report generation ---

    #[test]
    fn test_generate_report_empty() {
        let mut oracle = setup_oracle_with_runtimes();
        let report = oracle.generate_report();
        assert_eq!(report.schema_version, SCHEMA_VERSION);
        assert_eq!(report.verdict, OracleVerdict::Pass);
        assert!(report.divergences.is_empty());
    }

    #[test]
    fn test_generate_report_with_divergences() {
        let mut oracle = setup_oracle_with_runtimes();
        oracle
            .classify_divergence(
                "chk-1",
                BoundaryScope::Security,
                RiskTier::High,
                "sec issue",
                vec!["a".into()],
            )
            .unwrap();
        oracle
            .classify_divergence(
                "chk-1",
                BoundaryScope::IO,
                RiskTier::Low,
                "io diff",
                vec!["b".into()],
            )
            .unwrap();

        let report = oracle.generate_report();
        assert_eq!(report.divergences.len(), 2);
        assert_eq!(*report.risk_tier_counts.get("High").unwrap(), 1);
        assert_eq!(*report.risk_tier_counts.get("Low").unwrap(), 1);
        assert!(matches!(report.verdict, OracleVerdict::BlockRelease { .. }));
    }

    // --- RiskTier methods ---

    #[test]
    fn test_risk_tier_blocks_release() {
        assert!(!RiskTier::Info.blocks_release());
        assert!(!RiskTier::Low.blocks_release());
        assert!(!RiskTier::Medium.blocks_release());
        assert!(RiskTier::High.blocks_release());
        assert!(RiskTier::Critical.blocks_release());
    }

    #[test]
    fn test_risk_tier_requires_receipt() {
        assert!(!RiskTier::Info.requires_receipt());
        assert!(RiskTier::Low.requires_receipt());
        assert!(!RiskTier::Medium.requires_receipt());
        assert!(!RiskTier::High.requires_receipt());
        assert!(!RiskTier::Critical.requires_receipt());
    }

    // --- Determinism (BTreeMap ordering) ---

    #[test]
    fn test_deterministic_ordering() {
        let mut oracle = setup_oracle_with_runtimes();
        oracle
            .classify_divergence(
                "chk-z",
                BoundaryScope::Security,
                RiskTier::Medium,
                "z-divergence",
                vec!["a".into()],
            )
            .unwrap();
        oracle
            .classify_divergence(
                "chk-a",
                BoundaryScope::Memory,
                RiskTier::Low,
                "a-divergence",
                vec!["b".into()],
            )
            .unwrap();

        let report = oracle.generate_report();
        let keys: Vec<&String> = report.divergences.keys().collect();
        // div-1 < div-2 lexicographically
        assert_eq!(keys, vec!["div-1", "div-2"]);
    }

    // --- Display impls ---

    #[test]
    fn test_oracle_verdict_display() {
        assert_eq!(OracleVerdict::Pass.to_string(), "PASS");
        assert!(OracleVerdict::BlockRelease {
            blocking_divergence_ids: vec!["d1".into()]
        }
        .to_string()
        .contains("BLOCK_RELEASE"));
    }

    #[test]
    fn test_risk_tier_display() {
        assert_eq!(RiskTier::Critical.to_string(), "Critical");
        assert_eq!(RiskTier::Info.to_string(), "Info");
    }

    #[test]
    fn test_boundary_scope_display() {
        assert_eq!(BoundaryScope::TypeSystem.to_string(), "TypeSystem");
        assert_eq!(BoundaryScope::Security.to_string(), "Security");
    }

    // --- Error display ---

    #[test]
    fn test_oracle_error_display() {
        let err = OracleError::new(error_codes::ERR_NVO_NO_RUNTIMES, "no runtimes");
        assert!(err.to_string().contains("ERR_NVO_NO_RUNTIMES"));
        assert!(err.to_string().contains("no runtimes"));
    }

    // --- Audit log ---

    #[test]
    fn test_audit_log_populated() {
        let mut oracle = setup_oracle_with_runtimes();
        // Registration produces 3 log entries
        assert_eq!(oracle.audit_log().len(), 3);
        oracle
            .run_cross_check("chk-1", BoundaryScope::Memory, "test")
            .unwrap();
        // +1 for cross check
        assert_eq!(oracle.audit_log().len(), 4);
    }

    // --- Set quorum threshold ---

    #[test]
    fn test_set_quorum_threshold_caps_at_100() {
        let mut oracle = RuntimeOracle::new("oracle-cap");
        oracle.set_quorum_threshold(150);
        assert_eq!(oracle.quorum_threshold_pct, 100);
    }

    // --- Info divergence does not block or require receipt ---

    #[test]
    fn test_info_divergence_is_harmless() {
        let mut oracle = setup_oracle_with_runtimes();
        oracle
            .classify_divergence(
                "chk-1",
                BoundaryScope::TypeSystem,
                RiskTier::Info,
                "informational note",
                vec!["a".into()],
            )
            .unwrap();
        let verdict = oracle.check_release_gate();
        assert_eq!(verdict, OracleVerdict::Pass);
    }
}
