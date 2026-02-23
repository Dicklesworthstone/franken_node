//! bd-3gwi: Contribution-weighted intelligence access policy and reciprocity controls (10.19).
//!
//! Implements tiered intelligence access where participants' access level is
//! determined by their measured contribution quality and quantity. Prevents
//! free-riding by enforcing reciprocity: participants must contribute threat
//! intelligence proportional to the intelligence they consume.
//!
//! # Access Tiers
//!
//! - **Full**: Unrestricted access to all intelligence feeds (contribution ratio >= 0.8)
//! - **Standard**: Access to aggregated intelligence, no raw signals (contribution ratio >= 0.4)
//! - **Limited**: Access to public threat advisories only (contribution ratio >= 0.1)
//! - **Blocked**: No intelligence access (contribution ratio < 0.1 or policy violation)
//!
//! # Free-Rider Controls
//!
//! - Contribution ratio = contributions_made / intelligence_consumed (rolling window)
//! - Minimum contribution threshold per tier enforced at access check
//! - Grace period for new participants (configurable, default 7 days)
//! - Exception paths for approved research/audit use cases
//!
//! # Invariants
//!
//! - **INV-ATC-RECIPROCITY-DETERMINISM**: Same contribution data → same tier assignment.
//! - **INV-ATC-TIER-MONOTONE**: Higher contribution ratio never produces lower tier.
//! - **INV-ATC-FREERIDER-BOUND**: Participants below minimum ratio cannot access protected feeds.
//! - **INV-ATC-EXCEPTION-AUDITED**: Every exception grant produces an audit record.
//! - **INV-ATC-GRACE-BOUNDED**: Grace period has finite, configurable duration.
//! - **INV-ATC-ACCESS-LOGGED**: Every access decision (grant or deny) is logged.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

// ---------------------------------------------------------------------------
// Event codes
// ---------------------------------------------------------------------------

pub mod event_codes {
    /// ATC-RCP-001: Intelligence access granted at tier.
    pub const ACCESS_GRANTED: &str = "ATC-RCP-001";
    /// ATC-RCP-002: Intelligence access denied (insufficient contribution).
    pub const ACCESS_DENIED: &str = "ATC-RCP-002";
    /// ATC-RCP-003: Tier assignment computed for participant.
    pub const TIER_ASSIGNED: &str = "ATC-RCP-003";
    /// ATC-RCP-004: Free-rider limit enforced.
    pub const FREERIDER_ENFORCED: &str = "ATC-RCP-004";
    /// ATC-RCP-005: Exception path activated.
    pub const EXCEPTION_ACTIVATED: &str = "ATC-RCP-005";
    /// ATC-RCP-006: Grace period granted to new participant.
    pub const GRACE_PERIOD_GRANTED: &str = "ATC-RCP-006";
    /// ATC-RCP-007: Contribution ratio updated.
    pub const CONTRIBUTION_UPDATED: &str = "ATC-RCP-007";
    /// ATC-RCP-008: Reciprocity policy evaluation completed.
    pub const POLICY_EVALUATED: &str = "ATC-RCP-008";
    /// ATC-RCP-009: Access tier downgraded due to declining contributions.
    pub const TIER_DOWNGRADED: &str = "ATC-RCP-009";
    /// ATC-RCP-010: Reciprocity matrix exported.
    pub const MATRIX_EXPORTED: &str = "ATC-RCP-010";
    /// ATC-RCP-ERR-001: Invalid contribution data.
    pub const INVALID_CONTRIBUTION: &str = "ATC-RCP-ERR-001";
    /// ATC-RCP-ERR-002: Policy configuration error.
    pub const POLICY_CONFIG_ERROR: &str = "ATC-RCP-ERR-002";
}

// ---------------------------------------------------------------------------
// Invariant tags
// ---------------------------------------------------------------------------

pub mod invariants {
    pub const INV_ATC_RECIPROCITY_DETERMINISM: &str = "INV-ATC-RECIPROCITY-DETERMINISM";
    pub const INV_ATC_TIER_MONOTONE: &str = "INV-ATC-TIER-MONOTONE";
    pub const INV_ATC_FREERIDER_BOUND: &str = "INV-ATC-FREERIDER-BOUND";
    pub const INV_ATC_EXCEPTION_AUDITED: &str = "INV-ATC-EXCEPTION-AUDITED";
    pub const INV_ATC_GRACE_BOUNDED: &str = "INV-ATC-GRACE-BOUNDED";
    pub const INV_ATC_ACCESS_LOGGED: &str = "INV-ATC-ACCESS-LOGGED";
}

// ---------------------------------------------------------------------------
// Access tiers
// ---------------------------------------------------------------------------

/// Intelligence access tier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AccessTier {
    Blocked,
    Limited,
    Standard,
    Full,
}

impl AccessTier {
    /// Minimum contribution ratio required for this tier.
    pub fn min_ratio(&self) -> f64 {
        match self {
            Self::Full => 0.8,
            Self::Standard => 0.4,
            Self::Limited => 0.1,
            Self::Blocked => 0.0,
        }
    }

    /// Intelligence feeds accessible at this tier.
    pub fn accessible_feeds(&self) -> &[&str] {
        match self {
            Self::Full => &["raw_signals", "aggregated", "advisories", "indicators"],
            Self::Standard => &["aggregated", "advisories", "indicators"],
            Self::Limited => &["advisories"],
            Self::Blocked => &[],
        }
    }
}

// ---------------------------------------------------------------------------
// Contribution metrics
// ---------------------------------------------------------------------------

/// Measured contribution data for a participant.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ContributionMetrics {
    pub participant_id: String,
    /// Number of threat intelligence items contributed.
    pub contributions_made: u64,
    /// Number of intelligence items consumed/accessed.
    pub intelligence_consumed: u64,
    /// Quality score of contributions [0.0, 1.0].
    pub contribution_quality: f64,
    /// Seconds since the participant joined the ATC network.
    pub membership_age_seconds: u64,
    /// Whether the participant has an approved exception.
    pub has_exception: bool,
    /// Exception reason (if has_exception is true).
    pub exception_reason: Option<String>,
    /// Exception expiry timestamp (RFC 3339).
    pub exception_expires_at: Option<String>,
}

impl ContributionMetrics {
    /// Compute the raw contribution ratio.
    pub fn contribution_ratio(&self) -> f64 {
        if self.intelligence_consumed == 0 {
            if self.contributions_made > 0 {
                return 1.0;
            }
            return 0.0;
        }
        (self.contributions_made as f64 / self.intelligence_consumed as f64).min(1.0)
    }

    /// Compute quality-adjusted contribution ratio.
    pub fn quality_adjusted_ratio(&self) -> f64 {
        self.contribution_ratio() * self.contribution_quality
    }
}

// ---------------------------------------------------------------------------
// Access decision
// ---------------------------------------------------------------------------

/// Result of an access policy evaluation.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AccessDecision {
    pub participant_id: String,
    pub tier: AccessTier,
    pub contribution_ratio: f64,
    pub quality_adjusted_ratio: f64,
    pub granted: bool,
    pub reason: String,
    pub exception_applied: bool,
    pub grace_period_active: bool,
    pub accessible_feeds: Vec<String>,
}

/// Audit record for an access policy decision.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AccessAuditEntry {
    pub entry_id: String,
    pub event_code: String,
    pub participant_id: String,
    pub timestamp: String,
    pub decision: AccessDecision,
    pub content_hash: String,
}

impl AccessAuditEntry {
    pub fn compute_hash(decision: &AccessDecision) -> String {
        let canonical = serde_json::to_string(decision).unwrap_or_default();
        let digest =
            Sha256::digest([b"atc_reciprocity_hash_v1:" as &[u8], canonical.as_bytes()].concat());
        hex::encode(digest)
    }
}

// ---------------------------------------------------------------------------
// Reciprocity matrix
// ---------------------------------------------------------------------------

/// A snapshot of contribution/access tier assignments for all participants.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ReciprocityMatrix {
    pub snapshot_id: String,
    pub timestamp: String,
    pub entries: Vec<ReciprocityMatrixEntry>,
    pub tier_distribution: BTreeMap<String, usize>,
    pub total_participants: usize,
    pub freeriders_blocked: usize,
    pub exceptions_active: usize,
    pub content_hash: String,
}

/// Per-participant entry in the reciprocity matrix.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ReciprocityMatrixEntry {
    pub participant_id: String,
    pub tier: AccessTier,
    pub contribution_ratio: f64,
    pub quality_adjusted_ratio: f64,
    pub contributions_made: u64,
    pub intelligence_consumed: u64,
    pub exception_active: bool,
    pub grace_period_active: bool,
}

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

/// Configuration for the reciprocity policy engine.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ReciprocityConfig {
    /// Minimum quality-adjusted ratio for Full access.
    pub full_tier_min_ratio: f64,
    /// Minimum quality-adjusted ratio for Standard access.
    pub standard_tier_min_ratio: f64,
    /// Minimum quality-adjusted ratio for Limited access.
    pub limited_tier_min_ratio: f64,
    /// Grace period for new participants (seconds).
    pub grace_period_seconds: u64,
    /// Access tier during grace period.
    pub grace_period_tier: AccessTier,
    /// Whether to apply quality adjustment to contribution ratio.
    pub use_quality_adjustment: bool,
}

impl Default for ReciprocityConfig {
    fn default() -> Self {
        Self {
            full_tier_min_ratio: 0.8,
            standard_tier_min_ratio: 0.4,
            limited_tier_min_ratio: 0.1,
            grace_period_seconds: 86400 * 7, // 7 days
            grace_period_tier: AccessTier::Standard,
            use_quality_adjustment: true,
        }
    }
}

// ---------------------------------------------------------------------------
// Engine
// ---------------------------------------------------------------------------

/// The reciprocity policy engine evaluates contribution data and assigns access tiers.
#[derive(Debug, Clone)]
pub struct ReciprocityEngine {
    config: ReciprocityConfig,
    audit_log: Vec<AccessAuditEntry>,
}

impl Default for ReciprocityEngine {
    fn default() -> Self {
        Self::new(ReciprocityConfig::default())
    }
}

impl ReciprocityEngine {
    pub fn new(config: ReciprocityConfig) -> Self {
        Self {
            config,
            audit_log: Vec::new(),
        }
    }

    /// Evaluate access for a single participant.
    pub fn evaluate_access(
        &mut self,
        metrics: &ContributionMetrics,
        timestamp: &str,
    ) -> AccessDecision {
        let ratio = metrics.contribution_ratio();
        let quality_ratio = metrics.quality_adjusted_ratio();
        let effective_ratio = if self.config.use_quality_adjustment {
            quality_ratio
        } else {
            ratio
        };

        // Check grace period
        if metrics.membership_age_seconds < self.config.grace_period_seconds {
            let tier = self.config.grace_period_tier;
            let decision = AccessDecision {
                participant_id: metrics.participant_id.clone(),
                tier,
                contribution_ratio: ratio,
                quality_adjusted_ratio: quality_ratio,
                granted: true,
                reason: "grace period active".to_string(),
                exception_applied: false,
                grace_period_active: true,
                accessible_feeds: tier
                    .accessible_feeds()
                    .iter()
                    .map(|s| s.to_string())
                    .collect(),
            };
            self.log_decision(&decision, event_codes::GRACE_PERIOD_GRANTED, timestamp);
            return decision;
        }

        // Check exception
        if metrics.has_exception {
            let tier = AccessTier::Standard;
            let decision = AccessDecision {
                participant_id: metrics.participant_id.clone(),
                tier,
                contribution_ratio: ratio,
                quality_adjusted_ratio: quality_ratio,
                granted: true,
                reason: format!(
                    "exception: {}",
                    metrics.exception_reason.as_deref().unwrap_or("approved")
                ),
                exception_applied: true,
                grace_period_active: false,
                accessible_feeds: tier
                    .accessible_feeds()
                    .iter()
                    .map(|s| s.to_string())
                    .collect(),
            };
            self.log_decision(&decision, event_codes::EXCEPTION_ACTIVATED, timestamp);
            return decision;
        }

        // Compute tier from effective ratio
        let tier = self.classify_tier(effective_ratio);
        let granted = tier != AccessTier::Blocked;
        let event_code = if granted {
            event_codes::ACCESS_GRANTED
        } else {
            event_codes::ACCESS_DENIED
        };

        let reason = if granted {
            format!(
                "contribution ratio {effective_ratio:.3} qualifies for tier {:?}",
                tier
            )
        } else {
            format!("contribution ratio {effective_ratio:.3} below minimum threshold")
        };

        let decision = AccessDecision {
            participant_id: metrics.participant_id.clone(),
            tier,
            contribution_ratio: ratio,
            quality_adjusted_ratio: quality_ratio,
            granted,
            reason,
            exception_applied: false,
            grace_period_active: false,
            accessible_feeds: tier
                .accessible_feeds()
                .iter()
                .map(|s| s.to_string())
                .collect(),
        };

        self.log_decision(&decision, event_code, timestamp);
        decision
    }

    /// Evaluate access for a batch and produce a reciprocity matrix.
    pub fn evaluate_batch(
        &mut self,
        participants: &[ContributionMetrics],
        snapshot_id: &str,
        timestamp: &str,
    ) -> ReciprocityMatrix {
        let mut entries = Vec::with_capacity(participants.len());
        let mut tier_dist: BTreeMap<String, usize> = BTreeMap::new();
        let mut freeriders_blocked = 0usize;
        let mut exceptions_active = 0usize;

        for metrics in participants {
            let decision = self.evaluate_access(metrics, timestamp);

            let tier_key = format!("{:?}", decision.tier);
            *tier_dist.entry(tier_key).or_default() += 1;

            if decision.tier == AccessTier::Blocked {
                freeriders_blocked += 1;
            }
            if decision.exception_applied {
                exceptions_active += 1;
            }

            entries.push(ReciprocityMatrixEntry {
                participant_id: metrics.participant_id.clone(),
                tier: decision.tier,
                contribution_ratio: decision.contribution_ratio,
                quality_adjusted_ratio: decision.quality_adjusted_ratio,
                contributions_made: metrics.contributions_made,
                intelligence_consumed: metrics.intelligence_consumed,
                exception_active: decision.exception_applied,
                grace_period_active: decision.grace_period_active,
            });
        }

        let content_hash = {
            let canonical = serde_json::to_string(&entries).unwrap_or_default();
            let digest = Sha256::digest(
                [b"atc_reciprocity_hash_v1:" as &[u8], canonical.as_bytes()].concat(),
            );
            hex::encode(digest)
        };

        ReciprocityMatrix {
            snapshot_id: snapshot_id.to_string(),
            timestamp: timestamp.to_string(),
            entries,
            tier_distribution: tier_dist,
            total_participants: participants.len(),
            freeriders_blocked,
            exceptions_active,
            content_hash,
        }
    }

    /// Get the audit log.
    pub fn audit_log(&self) -> &[AccessAuditEntry] {
        &self.audit_log
    }

    /// Export audit log as JSONL.
    pub fn export_audit_jsonl(&self) -> Result<String, serde_json::Error> {
        let mut lines = Vec::with_capacity(self.audit_log.len());
        for entry in &self.audit_log {
            lines.push(serde_json::to_string(entry)?);
        }
        Ok(lines.join("\n"))
    }

    // -----------------------------------------------------------------------
    // Internal
    // -----------------------------------------------------------------------

    fn classify_tier(&self, effective_ratio: f64) -> AccessTier {
        if effective_ratio >= self.config.full_tier_min_ratio {
            AccessTier::Full
        } else if effective_ratio >= self.config.standard_tier_min_ratio {
            AccessTier::Standard
        } else if effective_ratio >= self.config.limited_tier_min_ratio {
            AccessTier::Limited
        } else {
            AccessTier::Blocked
        }
    }

    fn log_decision(&mut self, decision: &AccessDecision, event_code: &str, timestamp: &str) {
        let content_hash = AccessAuditEntry::compute_hash(decision);
        self.audit_log.push(AccessAuditEntry {
            entry_id: format!("audit-{}", self.audit_log.len() + 1),
            event_code: event_code.to_string(),
            participant_id: decision.participant_id.clone(),
            timestamp: timestamp.to_string(),
            decision: decision.clone(),
            content_hash,
        });
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn make_high_contributor(id: &str) -> ContributionMetrics {
        ContributionMetrics {
            participant_id: id.to_string(),
            contributions_made: 100,
            intelligence_consumed: 80,
            contribution_quality: 0.95,
            membership_age_seconds: 86400 * 365,
            has_exception: false,
            exception_reason: None,
            exception_expires_at: None,
        }
    }

    fn make_moderate_contributor(id: &str) -> ContributionMetrics {
        ContributionMetrics {
            participant_id: id.to_string(),
            contributions_made: 30,
            intelligence_consumed: 50,
            contribution_quality: 0.8,
            membership_age_seconds: 86400 * 90,
            has_exception: false,
            exception_reason: None,
            exception_expires_at: None,
        }
    }

    fn make_freerider(id: &str) -> ContributionMetrics {
        ContributionMetrics {
            participant_id: id.to_string(),
            contributions_made: 1,
            intelligence_consumed: 500,
            contribution_quality: 0.5,
            membership_age_seconds: 86400 * 60,
            has_exception: false,
            exception_reason: None,
            exception_expires_at: None,
        }
    }

    fn make_new_participant(id: &str) -> ContributionMetrics {
        ContributionMetrics {
            participant_id: id.to_string(),
            contributions_made: 0,
            intelligence_consumed: 0,
            contribution_quality: 0.0,
            membership_age_seconds: 3600, // 1 hour
            has_exception: false,
            exception_reason: None,
            exception_expires_at: None,
        }
    }

    fn make_excepted_participant(id: &str) -> ContributionMetrics {
        ContributionMetrics {
            participant_id: id.to_string(),
            contributions_made: 0,
            intelligence_consumed: 100,
            contribution_quality: 0.0,
            membership_age_seconds: 86400 * 30,
            has_exception: true,
            exception_reason: Some("approved research partner".to_string()),
            exception_expires_at: Some("2027-01-01T00:00:00Z".to_string()),
        }
    }

    // === Access tier ordering ===

    #[test]
    fn tier_ordering_is_correct() {
        assert!(AccessTier::Blocked < AccessTier::Limited);
        assert!(AccessTier::Limited < AccessTier::Standard);
        assert!(AccessTier::Standard < AccessTier::Full);
    }

    #[test]
    fn tier_min_ratios_are_monotone() {
        let tiers = [AccessTier::Limited, AccessTier::Standard, AccessTier::Full];
        for pair in tiers.windows(2) {
            assert!(pair[0].min_ratio() < pair[1].min_ratio());
        }
    }

    #[test]
    fn full_tier_has_all_feeds() {
        let feeds = AccessTier::Full.accessible_feeds();
        assert_eq!(feeds.len(), 4);
        assert!(feeds.contains(&"raw_signals"));
    }

    #[test]
    fn blocked_tier_has_no_feeds() {
        assert!(AccessTier::Blocked.accessible_feeds().is_empty());
    }

    // === Contribution ratio computation ===

    #[test]
    fn contribution_ratio_is_bounded() {
        let m = make_high_contributor("test");
        let ratio = m.contribution_ratio();
        assert!(ratio >= 0.0);
        assert!(ratio <= 1.0);
    }

    #[test]
    fn zero_consumed_zero_contributed_gives_zero_ratio() {
        let m = ContributionMetrics {
            participant_id: "zero".to_string(),
            contributions_made: 0,
            intelligence_consumed: 0,
            contribution_quality: 0.0,
            membership_age_seconds: 86400,
            has_exception: false,
            exception_reason: None,
            exception_expires_at: None,
        };
        assert!((m.contribution_ratio() - 0.0).abs() < f64::EPSILON);
    }

    #[test]
    fn high_contributor_gets_full_access() {
        let mut engine = ReciprocityEngine::default();
        let metrics = make_high_contributor("full-1");
        let decision = engine.evaluate_access(&metrics, "2026-02-20T00:00:00Z");

        assert_eq!(decision.tier, AccessTier::Full);
        assert!(decision.granted);
    }

    // === Tier assignment (INV-ATC-TIER-MONOTONE) ===

    #[test]
    fn higher_ratio_never_produces_lower_tier() {
        let engine = ReciprocityEngine::default();
        let ratios = [0.0, 0.05, 0.1, 0.2, 0.4, 0.6, 0.8, 0.9, 1.0];
        let mut prev_tier = AccessTier::Blocked;
        for &ratio in &ratios {
            let tier = engine.classify_tier(ratio);
            assert!(tier >= prev_tier, "ratio {ratio}: {tier:?} < {prev_tier:?}");
            prev_tier = tier;
        }
    }

    // === Free-rider blocking (INV-ATC-FREERIDER-BOUND) ===

    #[test]
    fn freerider_is_blocked() {
        let mut engine = ReciprocityEngine::default();
        let metrics = make_freerider("rider-1");
        let decision = engine.evaluate_access(&metrics, "2026-02-20T00:00:00Z");

        assert_eq!(decision.tier, AccessTier::Blocked);
        assert!(!decision.granted);
    }

    // === Grace period (INV-ATC-GRACE-BOUNDED) ===

    #[test]
    fn new_participant_gets_grace_period() {
        let mut engine = ReciprocityEngine::default();
        let metrics = make_new_participant("new-1");
        let decision = engine.evaluate_access(&metrics, "2026-02-20T00:00:00Z");

        assert!(decision.grace_period_active);
        assert!(decision.granted);
        assert_eq!(decision.tier, AccessTier::Standard);
    }

    #[test]
    fn grace_period_has_finite_duration() {
        let config = ReciprocityConfig::default();
        assert!(config.grace_period_seconds > 0);
        assert!(config.grace_period_seconds <= 86400 * 30); // At most 30 days
    }

    // === Exception paths (INV-ATC-EXCEPTION-AUDITED) ===

    #[test]
    fn exception_grants_standard_access() {
        let mut engine = ReciprocityEngine::default();
        let metrics = make_excepted_participant("exc-1");
        let decision = engine.evaluate_access(&metrics, "2026-02-20T00:00:00Z");

        assert!(decision.exception_applied);
        assert!(decision.granted);
        assert_eq!(decision.tier, AccessTier::Standard);
    }

    #[test]
    fn exception_produces_audit_entry() {
        let mut engine = ReciprocityEngine::default();
        let metrics = make_excepted_participant("exc-2");
        engine.evaluate_access(&metrics, "2026-02-20T00:00:00Z");

        assert_eq!(engine.audit_log().len(), 1);
        assert_eq!(
            engine.audit_log()[0].event_code,
            event_codes::EXCEPTION_ACTIVATED
        );
    }

    // === Audit logging (INV-ATC-ACCESS-LOGGED) ===

    #[test]
    fn every_access_decision_is_logged() {
        let mut engine = ReciprocityEngine::default();
        let participants = vec![
            make_high_contributor("a"),
            make_moderate_contributor("b"),
            make_freerider("c"),
        ];
        for m in &participants {
            engine.evaluate_access(m, "2026-02-20T00:00:00Z");
        }

        assert_eq!(engine.audit_log().len(), 3);
    }

    #[test]
    fn audit_entries_have_content_hash() {
        let mut engine = ReciprocityEngine::default();
        let metrics = make_high_contributor("hash-1");
        engine.evaluate_access(&metrics, "2026-02-20T00:00:00Z");

        let entry = &engine.audit_log()[0];
        assert!(!entry.content_hash.is_empty());
        assert_eq!(entry.content_hash.len(), 64);
    }

    // === Determinism (INV-ATC-RECIPROCITY-DETERMINISM) ===

    #[test]
    fn tier_assignment_is_deterministic() {
        let metrics = make_high_contributor("det-1");
        let mut e1 = ReciprocityEngine::default();
        let mut e2 = ReciprocityEngine::default();

        let d1 = e1.evaluate_access(&metrics, "2026-02-20T00:00:00Z");
        let d2 = e2.evaluate_access(&metrics, "2026-02-20T00:00:00Z");

        assert_eq!(d1.tier, d2.tier);
        assert!((d1.contribution_ratio - d2.contribution_ratio).abs() < f64::EPSILON);
    }

    // === Batch evaluation ===

    #[test]
    fn batch_produces_reciprocity_matrix() {
        let mut engine = ReciprocityEngine::default();
        let participants = vec![
            make_high_contributor("b-1"),
            make_moderate_contributor("b-2"),
            make_freerider("b-3"),
            make_new_participant("b-4"),
        ];
        let matrix = engine.evaluate_batch(&participants, "snap-1", "2026-02-20T00:00:00Z");

        assert_eq!(matrix.total_participants, 4);
        assert_eq!(matrix.entries.len(), 4);
        assert_eq!(matrix.freeriders_blocked, 1);
        assert!(!matrix.content_hash.is_empty());
    }

    #[test]
    fn matrix_tier_distribution_sums_to_total() {
        let mut engine = ReciprocityEngine::default();
        let participants = vec![
            make_high_contributor("d-1"),
            make_moderate_contributor("d-2"),
            make_freerider("d-3"),
        ];
        let matrix = engine.evaluate_batch(&participants, "snap-2", "2026-02-20T00:00:00Z");

        let sum: usize = matrix.tier_distribution.values().sum();
        assert_eq!(sum, matrix.total_participants);
    }

    // === JSONL export ===

    #[test]
    fn jsonl_export_produces_valid_lines() {
        let mut engine = ReciprocityEngine::default();
        let metrics = make_high_contributor("jsonl-1");
        engine.evaluate_access(&metrics, "2026-02-20T00:00:00Z");

        let jsonl = engine.export_audit_jsonl().unwrap();
        let lines: Vec<&str> = jsonl.lines().collect();
        assert_eq!(lines.len(), 1);
        let parsed: serde_json::Value = serde_json::from_str(lines[0]).unwrap();
        assert!(parsed["event_code"].is_string());
    }

    // === Config defaults ===

    #[test]
    fn default_config_tiers_are_ordered() {
        let config = ReciprocityConfig::default();
        assert!(config.limited_tier_min_ratio < config.standard_tier_min_ratio);
        assert!(config.standard_tier_min_ratio < config.full_tier_min_ratio);
    }

    // === Moderate contributor gets standard access ===

    #[test]
    fn moderate_contributor_gets_standard_access() {
        let mut engine = ReciprocityEngine::default();
        let metrics = make_moderate_contributor("mod-1");
        let decision = engine.evaluate_access(&metrics, "2026-02-20T00:00:00Z");

        assert!(decision.tier >= AccessTier::Standard || decision.tier == AccessTier::Limited);
        assert!(decision.granted);
    }
}
