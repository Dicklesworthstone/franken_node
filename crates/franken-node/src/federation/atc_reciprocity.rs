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

use chrono::{DateTime, FixedOffset};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

use crate::capacity_defaults::aliases::MAX_AUDIT_LOG_ENTRIES;

/// Maximum number of reciprocity matrix entries to prevent memory exhaustion.
const MAX_RECIPROCITY_ENTRIES: usize = 10_000;

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

fn parse_rfc3339(value: &str) -> Option<DateTime<FixedOffset>> {
    DateTime::parse_from_rfc3339(value).ok()
}

fn exception_is_active(metrics: &ContributionMetrics, timestamp: &str) -> bool {
    if !metrics.has_exception {
        return false;
    }
    let Some(expires_at) = metrics
        .exception_expires_at
        .as_deref()
        .and_then(parse_rfc3339)
    else {
        return false;
    };
    let Some(now) = parse_rfc3339(timestamp) else {
        return false;
    };
    now < expires_at
}

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
    /// Exception expiry timestamp (RFC 3339, required for an active exception).
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
        let quality = if self.contribution_quality.is_finite() {
            self.contribution_quality.clamp(0.0, 1.0)
        } else {
            0.0
        };
        self.contribution_ratio() * quality
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
        let canonical =
            serde_json::to_string(decision).unwrap_or_else(|e| format!("__serde_err:{e}"));
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
    next_audit_sequence: u64,
    audit_epoch: u64,
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
            next_audit_sequence: 1,
            audit_epoch: 0,
        }
    }

    fn allocate_audit_entry_id(&mut self) -> String {
        let entry_id = format!(
            "audit-{:016x}-{:016x}",
            self.audit_epoch, self.next_audit_sequence
        );

        if self.next_audit_sequence == u64::MAX {
            self.next_audit_sequence = 1;
            self.audit_epoch = self.audit_epoch.saturating_add(1);
        } else {
            self.next_audit_sequence = self.next_audit_sequence.saturating_add(1);
        }

        entry_id
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
            let granted = tier != AccessTier::Blocked;
            let decision = AccessDecision {
                participant_id: metrics.participant_id.clone(),
                tier,
                contribution_ratio: ratio,
                quality_adjusted_ratio: quality_ratio,
                granted,
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
        if exception_is_active(metrics, timestamp) {
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
            let tier_count = tier_dist.entry(tier_key).or_default();
            *tier_count = (*tier_count).saturating_add(1);

            if decision.tier == AccessTier::Blocked {
                freeriders_blocked = freeriders_blocked.saturating_add(1);
            }
            if decision.exception_applied {
                exceptions_active = exceptions_active.saturating_add(1);
            }

            push_bounded(&mut entries, ReciprocityMatrixEntry {
                participant_id: metrics.participant_id.clone(),
                tier: decision.tier,
                contribution_ratio: decision.contribution_ratio,
                quality_adjusted_ratio: decision.quality_adjusted_ratio,
                contributions_made: metrics.contributions_made,
                intelligence_consumed: metrics.intelligence_consumed,
                exception_active: decision.exception_applied,
                grace_period_active: decision.grace_period_active,
            }, MAX_RECIPROCITY_ENTRIES);
        }

        let content_hash = {
            let canonical =
                serde_json::to_string(&entries).unwrap_or_else(|e| format!("__serde_err:{e}"));
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
        let mut lines = Vec::with_capacity(self.audit_log.len().min(MAX_AUDIT_LOG_ENTRIES));
        for entry in &self.audit_log {
            push_bounded(&mut lines, serde_json::to_string(entry)?, MAX_AUDIT_LOG_ENTRIES);
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
        let entry_id = self.allocate_audit_entry_id();
        push_bounded(
            &mut self.audit_log,
            AccessAuditEntry {
                entry_id,
                event_code: event_code.to_string(),
                participant_id: decision.participant_id.clone(),
                timestamp: timestamp.to_string(),
                decision: decision.clone(),
                content_hash,
            },
            MAX_AUDIT_LOG_ENTRIES,
        );
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

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

    #[test]
    fn audit_entry_ids_remain_unique_after_log_eviction() {
        let mut engine = ReciprocityEngine::default();

        for idx in 0..(MAX_AUDIT_LOG_ENTRIES + 3) {
            let participant_id = format!("overflow-{idx}");
            let metrics = make_high_contributor(&participant_id);
            engine.evaluate_access(&metrics, "2026-02-20T00:00:00Z");
        }

        let ids: Vec<String> = engine
            .audit_log()
            .iter()
            .map(|entry| entry.entry_id.clone())
            .collect();
        let unique_ids: BTreeSet<String> = ids.iter().cloned().collect();

        assert_eq!(engine.audit_log().len(), MAX_AUDIT_LOG_ENTRIES);
        assert_eq!(unique_ids.len(), ids.len());
        assert!(ids.windows(2).all(|window| window[0] != window[1]));
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

        let jsonl = engine.export_audit_jsonl().expect("jsonl export fails");
        let lines: Vec<&str> = jsonl.lines().collect();
        assert_eq!(lines.len(), 1);
        let parsed: serde_json::Value = serde_json::from_str(lines[0]).expect("json parsing fails");
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

    #[test]
    fn non_finite_quality_blocks_otherwise_full_contributor() {
        let mut engine = ReciprocityEngine::default();
        let mut metrics = make_high_contributor("nan-quality");
        metrics.contribution_quality = f64::NAN;

        let decision = engine.evaluate_access(&metrics, "2026-02-20T00:00:00Z");

        assert_eq!(metrics.quality_adjusted_ratio(), 0.0);
        assert_eq!(decision.tier, AccessTier::Blocked);
        assert!(!decision.granted);
        assert!(decision.reason.contains("below minimum threshold"));
    }

    #[test]
    fn negative_quality_is_clamped_to_zero_and_blocks_access() {
        let mut engine = ReciprocityEngine::default();
        let mut metrics = make_high_contributor("negative-quality");
        metrics.contribution_quality = -0.25;

        let decision = engine.evaluate_access(&metrics, "2026-02-20T00:00:00Z");

        assert_eq!(metrics.quality_adjusted_ratio(), 0.0);
        assert_eq!(decision.tier, AccessTier::Blocked);
        assert!(decision.accessible_feeds.is_empty());
    }

    #[test]
    fn zero_quality_blocks_high_volume_contributor_after_grace() {
        let mut engine = ReciprocityEngine::default();
        let mut metrics = make_high_contributor("zero-quality");
        metrics.contribution_quality = 0.0;
        metrics.membership_age_seconds = ReciprocityConfig::default().grace_period_seconds;

        let decision = engine.evaluate_access(&metrics, "2026-02-20T00:00:00Z");

        assert_eq!(decision.quality_adjusted_ratio, 0.0);
        assert_eq!(decision.tier, AccessTier::Blocked);
        assert!(!decision.grace_period_active);
    }

    #[test]
    fn grace_period_boundary_is_not_active_at_exact_limit() {
        let mut engine = ReciprocityEngine::default();
        let mut metrics = make_new_participant("grace-boundary");
        metrics.membership_age_seconds = ReciprocityConfig::default().grace_period_seconds;

        let decision = engine.evaluate_access(&metrics, "2026-02-20T00:00:00Z");

        assert!(!decision.grace_period_active);
        assert_eq!(decision.tier, AccessTier::Blocked);
        assert!(!decision.granted);
    }

    #[test]
    fn zero_contribution_stays_blocked_without_quality_adjustment() {
        let mut engine = ReciprocityEngine::new(ReciprocityConfig {
            use_quality_adjustment: false,
            ..ReciprocityConfig::default()
        });
        let mut metrics = make_new_participant("no-quality-adjustment-zero");
        metrics.membership_age_seconds = 86400 * 30;
        metrics.intelligence_consumed = 50;

        let decision = engine.evaluate_access(&metrics, "2026-02-20T00:00:00Z");

        assert_eq!(decision.contribution_ratio, 0.0);
        assert_eq!(decision.tier, AccessTier::Blocked);
        assert!(!decision.granted);
    }

    #[test]
    fn blocked_decision_logs_access_denied_event() {
        let mut engine = ReciprocityEngine::default();
        let metrics = make_freerider("denied-log");

        let decision = engine.evaluate_access(&metrics, "2026-02-20T00:00:00Z");

        assert_eq!(decision.tier, AccessTier::Blocked);
        assert_eq!(engine.audit_log().len(), 1);
        assert_eq!(engine.audit_log()[0].event_code, event_codes::ACCESS_DENIED);
        assert_eq!(engine.audit_log()[0].decision, decision);
    }

    #[test]
    fn blocked_decision_has_no_accessible_feeds() {
        let mut engine = ReciprocityEngine::default();
        let metrics = make_freerider("blocked-feeds");

        let decision = engine.evaluate_access(&metrics, "2026-02-20T00:00:00Z");

        assert_eq!(decision.tier, AccessTier::Blocked);
        assert!(decision.accessible_feeds.is_empty());
    }

    #[test]
    fn empty_batch_matrix_has_no_access_or_audit_side_effects() {
        let mut engine = ReciprocityEngine::default();

        let matrix = engine.evaluate_batch(&[], "empty-snap", "2026-02-20T00:00:00Z");

        assert_eq!(matrix.total_participants, 0);
        assert!(matrix.entries.is_empty());
        assert!(matrix.tier_distribution.is_empty());
        assert_eq!(matrix.freeriders_blocked, 0);
        assert_eq!(matrix.exceptions_active, 0);
        assert!(engine.audit_log().is_empty());
    }

    #[test]
    fn infinite_quality_blocks_otherwise_full_contributor() {
        let mut engine = ReciprocityEngine::default();
        let mut metrics = make_high_contributor("infinite-quality");
        metrics.contribution_quality = f64::INFINITY;

        let decision = engine.evaluate_access(&metrics, "2026-02-20T00:00:00Z");

        assert_eq!(metrics.quality_adjusted_ratio(), 0.0);
        assert_eq!(decision.tier, AccessTier::Blocked);
        assert!(!decision.granted);
        assert!(decision.accessible_feeds.is_empty());
    }

    #[test]
    fn oversized_quality_does_not_amplify_low_contribution_ratio() {
        let mut engine = ReciprocityEngine::default();
        let mut metrics = make_freerider("oversized-quality");
        metrics.contribution_quality = 50.0;

        let decision = engine.evaluate_access(&metrics, "2026-02-20T00:00:00Z");

        assert!(decision.quality_adjusted_ratio < AccessTier::Limited.min_ratio());
        assert_eq!(decision.tier, AccessTier::Blocked);
        assert!(!decision.granted);
    }

    #[test]
    fn zero_grace_period_does_not_grant_new_participant_access() {
        let mut engine = ReciprocityEngine::new(ReciprocityConfig {
            grace_period_seconds: 0,
            ..ReciprocityConfig::default()
        });
        let metrics = make_new_participant("zero-grace");

        let decision = engine.evaluate_access(&metrics, "2026-02-20T00:00:00Z");

        assert!(!decision.grace_period_active);
        assert_eq!(decision.tier, AccessTier::Blocked);
        assert!(!decision.granted);
    }

    #[test]
    fn exception_with_missing_reason_does_not_grant_raw_signal_feed() {
        let mut engine = ReciprocityEngine::default();
        let mut metrics = make_excepted_participant("exception-no-reason");
        metrics.exception_reason = None;

        let decision = engine.evaluate_access(&metrics, "2026-02-20T00:00:00Z");

        assert!(decision.exception_applied);
        assert_eq!(decision.tier, AccessTier::Standard);
        assert!(
            !decision
                .accessible_feeds
                .iter()
                .any(|feed| feed.contains("raw_signals"))
        );
        assert_eq!(decision.reason, "exception: approved");
    }

    #[test]
    fn exception_with_bad_quality_still_avoids_full_access() {
        let mut engine = ReciprocityEngine::default();
        let mut metrics = make_excepted_participant("exception-bad-quality");
        metrics.contribution_quality = f64::NEG_INFINITY;

        let decision = engine.evaluate_access(&metrics, "2026-02-20T00:00:00Z");

        assert!(decision.exception_applied);
        assert_eq!(decision.quality_adjusted_ratio, 0.0);
        assert_eq!(decision.tier, AccessTier::Standard);
        assert!(
            !decision
                .accessible_feeds
                .iter()
                .any(|feed| feed.contains("raw_signals"))
        );
    }

    #[test]
    fn expired_exception_fails_closed_and_logs_denial() {
        let mut engine = ReciprocityEngine::default();
        let mut metrics = make_excepted_participant("exception-expired");
        metrics.exception_expires_at = Some("2026-02-19T23:59:59Z".to_string());

        let decision = engine.evaluate_access(&metrics, "2026-02-20T00:00:00Z");

        assert!(!decision.exception_applied);
        assert_eq!(decision.tier, AccessTier::Blocked);
        assert!(!decision.granted);
        assert_eq!(engine.audit_log().len(), 1);
        assert_eq!(engine.audit_log()[0].event_code, event_codes::ACCESS_DENIED);
    }

    #[test]
    fn exception_without_expiry_fails_closed() {
        let mut engine = ReciprocityEngine::default();
        let mut metrics = make_excepted_participant("exception-missing-expiry");
        metrics.exception_expires_at = None;

        let decision = engine.evaluate_access(&metrics, "2026-02-20T00:00:00Z");

        assert!(!decision.exception_applied);
        assert_eq!(decision.tier, AccessTier::Blocked);
        assert!(!decision.granted);
    }

    #[test]
    fn batch_with_only_blocked_participants_reports_no_active_exceptions() {
        let mut engine = ReciprocityEngine::default();
        let participants = vec![
            make_freerider("blocked-a"),
            make_freerider("blocked-b"),
            make_freerider("blocked-c"),
        ];

        let matrix = engine.evaluate_batch(&participants, "blocked-snap", "2026-02-20T00:00:00Z");

        assert_eq!(matrix.freeriders_blocked, participants.len());
        assert_eq!(matrix.exceptions_active, 0);
        assert_eq!(
            matrix.tier_distribution.get("Blocked").copied(),
            Some(participants.len())
        );
        assert!(
            matrix
                .entries
                .iter()
                .all(|entry| entry.tier == AccessTier::Blocked)
        );
    }

    #[test]
    fn export_empty_audit_log_returns_empty_jsonl() {
        let engine = ReciprocityEngine::default();

        let jsonl = engine
            .export_audit_jsonl()
            .expect("empty export should serialize");

        assert!(jsonl.is_empty());
        assert_eq!(jsonl.lines().count(), 0);
    }

    #[test]
    fn push_bounded_zero_capacity_discards_existing_and_new_items() {
        let mut items = vec![1usize, 2, 3];

        push_bounded(&mut items, 4, 0);

        assert!(items.is_empty());
    }
}

#[cfg(test)]
mod atc_reciprocity_negative_path_tests {
    use super::*;
    use std::collections::BTreeSet;

    #[test]
    fn negative_unicode_injection_participant_id_preserves_exact_bytes() {
        let mut engine = ReciprocityEngine::default();
        let injection_patterns = [
            "participant\u{202E}spoofed",          // Right-to-left override
            "participant\u{200B}invisible",        // Zero-width space
            "participant\u{FEFF}bom",              // Byte order mark
            "participant\x00null",                 // Null byte
            "participant\r\ninjection",            // CRLF injection
            "participant\u{1F4A9}emoji",           // Pile of poo emoji
            "participant\t\x08control",            // Tab and backspace
            "\u{202E}\u{202D}\u{200E}directional", // Bidirectional overrides
        ];

        for pattern in &injection_patterns {
            let metrics = ContributionMetrics {
                participant_id: pattern.to_string(),
                contributions_made: 50,
                intelligence_consumed: 50,
                contribution_quality: 0.8,
                membership_age_seconds: 86400 * 30,
                has_exception: false,
                exception_reason: None,
                exception_expires_at: None,
            };

            let decision = engine.evaluate_access(&metrics, "2026-04-17T00:00:00Z");

            // Unicode should be preserved exactly in decision
            assert_eq!(decision.participant_id, *pattern);

            // JSON serialization should handle injection safely
            let json = serde_json::to_string(&decision)
                .expect("unicode injection should serialize safely");
            assert!(
                !json.contains(&pattern.replace('\\', "")),
                "Raw injection pattern should be escaped in JSON"
            );

            // Deserialization should preserve exact pattern
            let parsed: AccessDecision =
                serde_json::from_str(&json).expect("should deserialize without corruption");
            assert_eq!(parsed.participant_id, *pattern);

            // Audit log should handle injection
            assert!(
                engine
                    .audit_log()
                    .iter()
                    .any(|entry| entry.participant_id == *pattern)
            );
        }
    }

    #[test]
    fn negative_arithmetic_boundary_contributions_saturated_safely() {
        let mut engine = ReciprocityEngine::default();
        let boundary_values = [
            (u64::MAX - 1, u64::MAX), // Near overflow
            (u64::MAX, u64::MAX - 1), // Reverse near overflow
            (u64::MAX, u64::MAX),     // Both at max
            (0, u64::MAX),            // Zero contributions, max consumption
            (u64::MAX, 0),            // Max contributions, zero consumption
        ];

        for (contributions, consumed) in boundary_values {
            let metrics = ContributionMetrics {
                participant_id: format!("boundary_{}__{}", contributions, consumed),
                contributions_made: contributions,
                intelligence_consumed: consumed,
                contribution_quality: 0.9,
                membership_age_seconds: 86400 * 30,
                has_exception: false,
                exception_reason: None,
                exception_expires_at: None,
            };

            // Computation should not overflow
            let ratio = metrics.contribution_ratio();
            assert!(
                ratio >= 0.0 && ratio <= 1.0,
                "Ratio should be bounded: {}",
                ratio
            );
            assert!(ratio.is_finite(), "Ratio should be finite");

            // Quality adjustment should not overflow
            let quality_ratio = metrics.quality_adjusted_ratio();
            assert!(
                quality_ratio >= 0.0 && quality_ratio <= 1.0,
                "Quality ratio should be bounded: {}",
                quality_ratio
            );
            assert!(quality_ratio.is_finite(), "Quality ratio should be finite");

            // Engine evaluation should handle boundary values
            let decision = engine.evaluate_access(&metrics, "2026-04-17T00:00:00Z");
            assert!(decision.contribution_ratio >= 0.0);
            assert!(decision.contribution_ratio <= 1.0);
            assert!(decision.quality_adjusted_ratio >= 0.0);
            assert!(decision.quality_adjusted_ratio <= 1.0);

            // JSON round-trip should preserve boundary values
            let json = serde_json::to_string(&metrics).expect("boundary values should serialize");
            let parsed: ContributionMetrics =
                serde_json::from_str(&json).expect("boundary values should deserialize");
            assert_eq!(parsed.contributions_made, contributions);
            assert_eq!(parsed.intelligence_consumed, consumed);
        }
    }

    #[test]
    fn negative_floating_point_edge_cases_in_contribution_quality() {
        let mut engine = ReciprocityEngine::default();
        let edge_cases = [
            f64::NAN,                 // Not a number
            f64::INFINITY,            // Positive infinity
            f64::NEG_INFINITY,        // Negative infinity
            f64::EPSILON,             // Smallest positive value
            f64::MIN_POSITIVE,        // Smallest normalized positive value
            f64::MAX,                 // Largest finite value
            -f64::MAX,                // Largest negative value
            1.7976931348623157e+308,  // Near overflow
            -1.7976931348623157e+308, // Near underflow
            0.0,                      // Zero
            -0.0,                     // Negative zero
        ];

        for (i, quality) in edge_cases.iter().enumerate() {
            let metrics = ContributionMetrics {
                participant_id: format!("quality_edge_{}", i),
                contributions_made: 100,
                intelligence_consumed: 100,
                contribution_quality: *quality,
                membership_age_seconds: 86400 * 30,
                has_exception: false,
                exception_reason: None,
                exception_expires_at: None,
            };

            // Quality adjustment should handle edge cases gracefully
            let quality_ratio = metrics.quality_adjusted_ratio();
            assert!(
                quality_ratio.is_finite(),
                "Quality ratio must be finite for quality {}",
                quality
            );
            assert!(quality_ratio >= 0.0, "Quality ratio must be non-negative");
            assert!(quality_ratio <= 1.0, "Quality ratio must not exceed 1.0");

            // Engine evaluation should not panic on edge cases
            let decision = engine.evaluate_access(&metrics, "2026-04-17T00:00:00Z");
            assert!(decision.quality_adjusted_ratio.is_finite());
            assert!(decision.quality_adjusted_ratio >= 0.0);
            assert!(decision.quality_adjusted_ratio <= 1.0);

            // JSON serialization should handle edge cases
            match serde_json::to_string(&metrics) {
                Ok(json) => {
                    // Should deserialize back to equivalent value
                    if let Ok(parsed) = serde_json::from_str::<ContributionMetrics>(&json) {
                        let parsed_quality_ratio = parsed.quality_adjusted_ratio();
                        assert!(parsed_quality_ratio.is_finite());
                        assert!(parsed_quality_ratio >= 0.0);
                        assert!(parsed_quality_ratio <= 1.0);
                    }
                }
                Err(_) => {
                    // Some edge cases may not serialize, which is acceptable
                    // as long as we don't panic
                }
            }
        }
    }

    #[test]
    fn negative_exception_reason_massive_payload_memory_stress() {
        let mut engine = ReciprocityEngine::default();

        // Test various large payload sizes
        let payload_sizes = [1000, 10_000, 100_000, 1_000_000];

        for size in payload_sizes {
            let massive_reason = "A".repeat(size);
            let metrics = ContributionMetrics {
                participant_id: format!("massive_reason_{}", size),
                contributions_made: 0,
                intelligence_consumed: 100,
                contribution_quality: 0.0,
                membership_age_seconds: 86400 * 30,
                has_exception: true,
                exception_reason: Some(massive_reason.clone()),
                exception_expires_at: Some("2027-01-01T00:00:00Z".to_string()),
            };

            // Should handle large payloads without crashes
            let decision = engine.evaluate_access(&metrics, "2026-04-17T00:00:00Z");
            assert!(decision.exception_applied);
            assert!(decision.reason.contains(&massive_reason[..100])); // Should contain at least part

            // JSON operations should work with large payloads
            match serde_json::to_string(&decision) {
                Ok(json) => {
                    assert!(json.len() > size); // Should contain the large payload

                    // Deserialization should work
                    match serde_json::from_str::<AccessDecision>(&json) {
                        Ok(parsed) => {
                            assert_eq!(parsed.participant_id, format!("massive_reason_{}", size));
                            assert!(parsed.reason.contains(&massive_reason[..100]));
                        }
                        Err(_) => {
                            // Very large payloads might fail to deserialize, which is acceptable
                            // as long as we don't panic
                        }
                    }
                }
                Err(_) => {
                    // Very large payloads might not serialize, which is acceptable
                    // as long as we don't panic
                }
            }
        }
    }

    #[test]
    fn negative_content_hash_collision_resistance_verification() {
        let mut engine = ReciprocityEngine::default();

        // Create decisions with crafted content designed to test hash collision resistance
        let collision_attempts = [
            // Same data, different participant IDs
            ("participant_a", 50, 50),
            ("participant_b", 50, 50),
            // Different contribution patterns that could hash similarly
            ("hash_test_1", 100, 200),
            ("hash_test_2", 200, 100),
            // Byte boundary cases
            ("hash_boundary", 255, 256),
            ("hash_boundary", 256, 255),
        ];

        let mut observed_hashes = BTreeSet::new();
        let mut decisions = Vec::new();

        for (participant_id, contributions, consumed) in collision_attempts {
            let metrics = ContributionMetrics {
                participant_id: participant_id.to_string(),
                contributions_made: contributions,
                intelligence_consumed: consumed,
                contribution_quality: 0.8,
                membership_age_seconds: 86400 * 30,
                has_exception: false,
                exception_reason: None,
                exception_expires_at: None,
            };

            let decision = engine.evaluate_access(&metrics, "2026-04-17T00:00:00Z");
            decisions.push(decision);
        }

        // Collect hashes from audit log
        for entry in engine.audit_log() {
            observed_hashes.insert(entry.content_hash.clone());

            // Hashes should be proper hex strings
            assert_eq!(entry.content_hash.len(), 64);
            assert!(entry.content_hash.chars().all(|c| c.is_ascii_hexdigit()));

            // Hash should be deterministic for same content
            let recomputed_hash = AccessAuditEntry::compute_hash(&entry.decision);
            assert_eq!(entry.content_hash, recomputed_hash);
        }

        // All different decisions should produce different hashes (no collisions)
        assert_eq!(
            observed_hashes.len(),
            decisions.len(),
            "Hash collision detected: {} unique hashes for {} decisions",
            observed_hashes.len(),
            decisions.len()
        );
    }

    #[test]
    fn negative_timestamp_injection_and_format_validation() {
        let mut engine = ReciprocityEngine::default();
        let malicious_timestamps = [
            // JSON injection attempts
            "2026-04-17T00:00:00Z\",\"injected\":true,\"data\":\"",
            "null}\"evil\":\"payload\",\"timestamp\":\"2026-04-17T00:00:00Z",
            // Control character injection
            "2026-04-17T00:00:00Z\x00\r\n",
            "2026-04-17\x1b[31mT00:00:00Z",
            // Unicode injection
            "2026-04-17T00:00:00Z\u{202E}injection",
            "2026-04-17T00:00:00Z\u{FEFF}bom",
            // Extremely long timestamp
            &"2026-04-17T00:00:00Z".repeat(1000),
            // Empty and whitespace
            "",
            "   ",
            "\t\n\r",
            // Invalid ISO format
            "not-a-timestamp",
            "2026-13-45T25:70:80Z", // Invalid date/time
        ];

        for timestamp in &malicious_timestamps {
            let metrics = ContributionMetrics {
                participant_id: "timestamp_test".to_string(),
                contributions_made: 50,
                intelligence_consumed: 50,
                contribution_quality: 0.8,
                membership_age_seconds: 86400 * 30,
                has_exception: false,
                exception_reason: None,
                exception_expires_at: None,
            };

            // Should handle malicious timestamps without corruption
            let decision = engine.evaluate_access(&metrics, timestamp);
            assert_eq!(decision.participant_id, "timestamp_test");

            // Audit log should preserve timestamp exactly
            let audit_entry = engine.audit_log().last().expect("should have audit entry");
            assert_eq!(audit_entry.timestamp, *timestamp);

            // JSON serialization should escape injection attempts
            let json = serde_json::to_string(audit_entry)
                .expect("should serialize audit entry with malicious timestamp");

            // Raw injection patterns should not appear unescaped
            if timestamp.contains('"') || timestamp.contains('{') || timestamp.contains('}') {
                assert!(
                    !json.contains(&timestamp.replace('\\', "")),
                    "Dangerous timestamp should be escaped in JSON: {}",
                    timestamp.escape_debug()
                );
            }

            // Deserialization should recover exact timestamp
            let parsed: AccessAuditEntry =
                serde_json::from_str(&json).expect("should deserialize audit entry");
            assert_eq!(parsed.timestamp, *timestamp);
        }
    }

    #[test]
    fn negative_configuration_extreme_boundary_values() {
        // Test configurations with extreme or contradictory values
        let extreme_configs = [
            // Zero thresholds
            ReciprocityConfig {
                full_tier_min_ratio: 0.0,
                standard_tier_min_ratio: 0.0,
                limited_tier_min_ratio: 0.0,
                grace_period_seconds: 0,
                grace_period_tier: AccessTier::Blocked,
                use_quality_adjustment: true,
            },
            // Inverted thresholds (higher tier requires lower ratio)
            ReciprocityConfig {
                full_tier_min_ratio: 0.1,
                standard_tier_min_ratio: 0.5,
                limited_tier_min_ratio: 0.9,
                grace_period_seconds: 86400,
                grace_period_tier: AccessTier::Standard,
                use_quality_adjustment: true,
            },
            // Extreme values
            ReciprocityConfig {
                full_tier_min_ratio: f64::MAX,
                standard_tier_min_ratio: f64::INFINITY,
                limited_tier_min_ratio: f64::NAN,
                grace_period_seconds: u64::MAX,
                grace_period_tier: AccessTier::Full,
                use_quality_adjustment: false,
            },
            // Negative ratios
            ReciprocityConfig {
                full_tier_min_ratio: -1.0,
                standard_tier_min_ratio: -0.5,
                limited_tier_min_ratio: -0.1,
                grace_period_seconds: 86400,
                grace_period_tier: AccessTier::Limited,
                use_quality_adjustment: true,
            },
        ];

        for (i, config) in extreme_configs.iter().enumerate() {
            let mut engine = ReciprocityEngine::new(config.clone());

            let test_metrics = ContributionMetrics {
                participant_id: format!("extreme_config_test_{}", i),
                contributions_made: 50,
                intelligence_consumed: 100,
                contribution_quality: 0.8,
                membership_age_seconds: 86400,
                has_exception: false,
                exception_reason: None,
                exception_expires_at: None,
            };

            // Engine should handle extreme configurations without panicking
            let decision = engine.evaluate_access(&test_metrics, "2026-04-17T00:00:00Z");
            assert_eq!(
                decision.participant_id,
                format!("extreme_config_test_{}", i)
            );

            // Decision ratios should remain bounded despite extreme config
            assert!(decision.contribution_ratio >= 0.0);
            assert!(decision.contribution_ratio <= 1.0);
            assert!(decision.quality_adjusted_ratio >= 0.0);
            assert!(decision.quality_adjusted_ratio <= 1.0);

            // Classification should produce valid tier
            let effective_ratio = if config.use_quality_adjustment {
                decision.quality_adjusted_ratio
            } else {
                decision.contribution_ratio
            };
            let tier = engine.classify_tier(effective_ratio);
            assert!(matches!(
                tier,
                AccessTier::Blocked | AccessTier::Limited | AccessTier::Standard | AccessTier::Full
            ));

            // JSON serialization of extreme config should work
            let config_json = serde_json::to_string(config);
            match config_json {
                Ok(json) => {
                    // Should deserialize back
                    if let Ok(parsed_config) = serde_json::from_str::<ReciprocityConfig>(&json) {
                        // Extreme values should be preserved or safely handled
                        assert!(parsed_config.grace_period_seconds <= config.grace_period_seconds);
                    }
                }
                Err(_) => {
                    // Some extreme values might not serialize, which is acceptable
                }
            }
        }
    }

    #[test]
    fn negative_audit_log_overflow_and_sequence_consistency() {
        let mut engine = ReciprocityEngine::default();

        // Generate more audit entries than the maximum capacity
        let overflow_count = MAX_AUDIT_LOG_ENTRIES * 2;
        let mut all_entry_ids = Vec::new();

        for i in 0..overflow_count {
            let metrics = ContributionMetrics {
                participant_id: format!("overflow_test_{}", i),
                contributions_made: i % 100,
                intelligence_consumed: (i % 100) + 1,
                contribution_quality: 0.8,
                membership_age_seconds: 86400 * 30,
                has_exception: false,
                exception_reason: None,
                exception_expires_at: None,
            };

            engine.evaluate_access(&metrics, "2026-04-17T00:00:00Z");

            // Track all generated entry IDs
            if let Some(last_entry) = engine.audit_log().last() {
                all_entry_ids.push(last_entry.entry_id.clone());
            }
        }

        // Audit log should be bounded to MAX_AUDIT_LOG_ENTRIES
        assert_eq!(engine.audit_log().len(), MAX_AUDIT_LOG_ENTRIES);

        // All remaining entry IDs should be unique
        let remaining_ids: BTreeSet<String> = engine
            .audit_log()
            .iter()
            .map(|entry| entry.entry_id.clone())
            .collect();
        assert_eq!(remaining_ids.len(), engine.audit_log().len());

        // Entry IDs should maintain sequence consistency (no duplicates in full history)
        let unique_all_ids: BTreeSet<String> = all_entry_ids.into_iter().collect();
        assert_eq!(
            unique_all_ids.len(),
            overflow_count,
            "Sequence numbering should prevent ID reuse"
        );

        // Epoch and sequence should handle overflow gracefully
        for entry in engine.audit_log() {
            assert!(entry.entry_id.starts_with("audit-"));
            assert_eq!(entry.entry_id.len(), "audit-".len() + 16 + 1 + 16); // epoch-sequence format
        }
    }

    #[test]
    fn negative_reciprocity_matrix_with_massive_participant_batch() {
        let mut engine = ReciprocityEngine::default();

        // Create very large batch to stress memory and processing
        let large_batch_size = 10_000;
        let mut participants = Vec::with_capacity(large_batch_size);

        for i in 0..large_batch_size {
            participants.push(ContributionMetrics {
                participant_id: format!("batch_participant_{:06}", i),
                contributions_made: (i % 1000) as u64,
                intelligence_consumed: ((i % 500) + 1) as u64,
                contribution_quality: (i as f64 / large_batch_size as f64).min(1.0),
                membership_age_seconds: 86400 * ((i % 365) + 1) as u64,
                has_exception: i % 100 == 0, // 1% exceptions
                exception_reason: if i % 100 == 0 {
                    Some("bulk test".to_string())
                } else {
                    None
                },
                exception_expires_at: None,
            });
        }

        // Should handle large batch without memory issues or crashes
        let start_time = std::time::Instant::now();
        let matrix = engine.evaluate_batch(&participants, "massive_batch", "2026-04-17T00:00:00Z");
        let processing_time = start_time.elapsed();

        // Should complete in reasonable time
        assert!(
            processing_time.as_secs() < 30,
            "Large batch processing took too long: {:?}",
            processing_time
        );

        // Matrix should have correct structure
        assert_eq!(matrix.total_participants, large_batch_size);
        assert_eq!(matrix.entries.len(), large_batch_size);

        // Tier distribution should sum to total
        let tier_sum: usize = matrix.tier_distribution.values().sum();
        assert_eq!(tier_sum, matrix.total_participants);

        // Should track exceptions correctly
        assert_eq!(matrix.exceptions_active, large_batch_size / 100); // 1% exceptions

        // Content hash should be consistent
        assert_eq!(matrix.content_hash.len(), 64);
        assert!(matrix.content_hash.chars().all(|c| c.is_ascii_hexdigit()));

        // JSON serialization should handle large matrix
        match serde_json::to_string(&matrix) {
            Ok(json) => {
                assert!(json.len() > 1_000_000); // Should be substantial

                // Deserialization should work
                match serde_json::from_str::<ReciprocityMatrix>(&json) {
                    Ok(parsed_matrix) => {
                        assert_eq!(parsed_matrix.total_participants, large_batch_size);
                        assert_eq!(parsed_matrix.content_hash, matrix.content_hash);
                    }
                    Err(_) => {
                        // Very large matrices might fail to deserialize due to memory limits
                        // This is acceptable as long as we don't panic
                    }
                }
            }
            Err(_) => {
                // Very large matrices might not serialize due to memory limits
                // This is acceptable as long as we don't panic
            }
        }
    }

    #[test]
    fn negative_concurrent_access_pattern_simulation() {
        // Simulate concurrent access patterns that might reveal race conditions
        use std::sync::{Arc, Mutex};
        use std::thread;

        let engine = Arc::new(Mutex::new(ReciprocityEngine::default()));
        let results = Arc::new(Mutex::new(Vec::new()));

        let thread_count = 8;
        let operations_per_thread = 100;
        let mut handles = Vec::new();

        for thread_id in 0..thread_count {
            let engine = Arc::clone(&engine);
            let results = Arc::clone(&results);

            let handle = thread::spawn(move || {
                let mut thread_results = Vec::new();

                for operation in 0..operations_per_thread {
                    let metrics = ContributionMetrics {
                        participant_id: format!("concurrent_t{}_o{}", thread_id, operation),
                        contributions_made: (thread_id * operations_per_thread + operation) as u64,
                        intelligence_consumed: ((thread_id * operations_per_thread + operation) + 1)
                            as u64,
                        contribution_quality: 0.8,
                        membership_age_seconds: 86400 * 30,
                        has_exception: operation % 10 == 0,
                        exception_reason: if operation % 10 == 0 {
                            Some(format!(
                                "concurrent_exception_t{}_o{}",
                                thread_id, operation
                            ))
                        } else {
                            None
                        },
                        exception_expires_at: None,
                    };

                    // Each thread performs access evaluation
                    let decision = {
                        let mut engine_guard = engine.lock().unwrap();
                        engine_guard.evaluate_access(&metrics, "2026-04-17T00:00:00Z")
                    };

                    thread_results.push((thread_id, operation, decision.tier, decision.granted));
                }

                // Merge results
                {
                    let mut shared_results = results.lock().unwrap();
                    shared_results.extend(thread_results);
                }
            });

            handles.push(handle);
        }

        // Wait for all threads to complete
        for handle in handles {
            handle
                .join()
                .expect("Thread should complete without panics");
        }

        let final_results = results.lock().unwrap();

        // Should have processed all operations
        assert_eq!(final_results.len(), thread_count * operations_per_thread);

        // Check final engine state consistency
        let final_engine = engine.lock().unwrap();

        // Audit log should contain entries from all threads
        assert!(final_engine.audit_log().len() > 0);
        assert!(final_engine.audit_log().len() <= MAX_AUDIT_LOG_ENTRIES);

        // All audit entry IDs should be unique (no race condition duplicates)
        let audit_ids: BTreeSet<String> = final_engine
            .audit_log()
            .iter()
            .map(|entry| entry.entry_id.clone())
            .collect();
        assert_eq!(
            audit_ids.len(),
            final_engine.audit_log().len(),
            "Race conditions may have caused duplicate audit entry IDs"
        );

        // Results should show reasonable distribution of outcomes
        let granted_count = final_results
            .iter()
            .filter(|(_, _, _, granted)| *granted)
            .count();
        assert!(
            granted_count > 0,
            "At least some access should have been granted"
        );
        assert!(
            granted_count < final_results.len(),
            "Not all access should have been granted"
        );
    }

    #[test]
    fn negative_deep_json_nesting_stack_overflow_protection() {
        // Test deeply nested JSON structures that could cause stack overflow
        let mut engine = ReciprocityEngine::default();

        // Create decision with nested data
        let metrics = ContributionMetrics {
            participant_id: "deep_nesting_test".to_string(),
            contributions_made: 50,
            intelligence_consumed: 50,
            contribution_quality: 0.8,
            membership_age_seconds: 86400 * 30,
            has_exception: true,
            exception_reason: Some({
                // Create deeply nested JSON-like string
                let mut nested = String::new();
                nested.push_str(r#"{"level0":{"#);
                for i in 1..1000 {
                    nested.push_str(&format!(r#""level{}":"{{"#, i));
                }
                nested.push_str(r#""deep":"value""#);
                for _ in 0..1000 {
                    nested.push_str("}}");
                }
                nested
            }),
            exception_expires_at: Some("2027-01-01T00:00:00Z".to_string()),
        };

        // Should handle deeply nested content without stack overflow
        let result =
            std::panic::catch_unwind(|| engine.evaluate_access(&metrics, "2026-04-17T00:00:00Z"));

        match result {
            Ok(decision) => {
                // Successfully handled deep nesting
                assert!(decision.exception_applied);
                assert_eq!(decision.participant_id, "deep_nesting_test");

                // JSON serialization should handle or safely reject deep nesting
                match serde_json::to_string(&decision) {
                    Ok(json) => {
                        // If serialization succeeds, deserialization should too
                        match serde_json::from_str::<AccessDecision>(&json) {
                            Ok(parsed) => {
                                assert_eq!(parsed.participant_id, "deep_nesting_test");
                            }
                            Err(_) => {
                                // Deserialization failure acceptable for extremely nested data
                            }
                        }
                    }
                    Err(_) => {
                        // Serialization failure acceptable for extremely nested data
                    }
                }
            }
            Err(_) => {
                // If panic occurs, need better stack protection
                panic!("Deep nesting caused panic - need stack overflow protection");
            }
        }
    }

    #[test]
    fn negative_exception_expiry_timestamp_manipulation_attacks_fail_closed() {
        let mut engine = ReciprocityEngine::default();

        let malicious_timestamps = [
            // Far future dates (year 9999, etc.)
            "9999-12-31T23:59:59Z",
            "3000-01-01T00:00:00Z",
            // Epoch edge cases
            "1970-01-01T00:00:00Z",
            "1969-12-31T23:59:59Z",
            // Invalid but parseable-looking dates
            "2026-02-30T25:00:00Z", // February 30th, 25 o'clock
            "2026-13-45T00:00:00Z", // Month 13, day 45
            // JSON/XML injection attempts
            "2026-04-17T00:00:00Z\"><script>alert('xss')</script>",
            "2026-04-17T00:00:00Z&amp;malicious=true",
            // Unicode and control character injection
            "2026-04-17T00:00:00Z\u{202E}injection",
            "2026-04-17T00:00:00Z\x00\x01\x02",
            // Extremely long timestamps
            &"2026-04-17T00:00:00Z".repeat(10000),
        ];

        for (i, timestamp) in malicious_timestamps.iter().enumerate() {
            let metrics = ContributionMetrics {
                participant_id: format!("timestamp_attack_{}", i),
                contributions_made: 0,
                intelligence_consumed: 100,
                contribution_quality: 0.0,
                membership_age_seconds: 86400 * 30,
                has_exception: true,
                exception_reason: Some("timestamp manipulation test".to_string()),
                exception_expires_at: Some(timestamp.to_string()),
            };

            // Should handle malicious timestamps without corruption or crashes
            let decision = engine.evaluate_access(&metrics, "2026-04-17T00:00:00Z");
            assert!(
                !decision.exception_applied,
                "Malformed exception expiry must not activate the exception path"
            );
            assert_eq!(decision.tier, AccessTier::Blocked);
            assert_eq!(decision.participant_id, format!("timestamp_attack_{}", i));

            // JSON round-trip should preserve exact timestamp
            let json =
                serde_json::to_string(&metrics).expect("malicious timestamp should serialize");

            // Injection patterns should be escaped in JSON
            if timestamp.contains('"') || timestamp.contains('<') || timestamp.contains('&') {
                assert!(
                    !json.contains(&timestamp.replace('\\', "")),
                    "Malicious timestamp should be escaped in JSON"
                );
            }

            // Deserialization should recover exact timestamp
            let parsed: ContributionMetrics =
                serde_json::from_str(&json).expect("should deserialize malicious timestamp");
            assert_eq!(
                parsed.exception_expires_at.as_deref(),
                Some(timestamp.as_str())
            );
        }
    }

    #[test]
    fn negative_push_bounded_edge_cases_and_memory_consistency() {
        // Test edge cases in push_bounded function

        // Test with various capacity values
        let test_cases = [
            (vec![1, 2, 3], 4, 0),         // Zero capacity
            (vec![], 5, 1),                // Empty vec, capacity 1
            (vec![1, 2, 3], 4, 1),         // Overflow by much more than capacity
            (vec![1, 2, 3], 4, 3),         // Exactly at capacity
            (vec![1, 2, 3], 4, 10),        // Much higher capacity
            (vec![1; 1000], 1001, 500),    // Large vec, medium capacity
            (vec![1; 10], 11, usize::MAX), // Extreme capacity value
        ];

        for (mut initial_vec, new_item, capacity) in test_cases {
            let initial_len = initial_vec.len();
            let expected_final_len = if capacity == 0 {
                0
            } else {
                (initial_len + 1).min(capacity)
            };

            push_bounded(&mut initial_vec, new_item, capacity);

            // Length should be bounded by capacity
            assert_eq!(initial_vec.len(), expected_final_len);

            // If capacity > 0, new item should be present (at the end)
            if capacity > 0 {
                assert_eq!(initial_vec.last().copied(), Some(new_item));
            }

            // Vector should not exceed capacity
            assert!(initial_vec.len() <= capacity || capacity == usize::MAX);

            // If we had overflow, oldest items should be removed
            if initial_len >= capacity && capacity > 0 {
                // The vec should start with newer items
                let mut test_vec = vec![1; initial_len];
                push_bounded(&mut test_vec, 999, capacity);
                if capacity > 0 {
                    assert_eq!(test_vec.last().copied(), Some(999));
                }
            }
        }

        // Test memory consistency with repeated pushes
        let mut audit_log = Vec::new();
        for i in 0..1000 {
            push_bounded(&mut audit_log, format!("entry_{}", i), 100);

            // Should never exceed capacity
            assert!(audit_log.len() <= 100);

            // Most recent item should always be present
            assert_eq!(audit_log.last(), Some(&format!("entry_{}", i)));
        }

        // Final state should have correct size and most recent entries
        assert_eq!(audit_log.len(), 100);
        assert_eq!(audit_log[99], "entry_999");
        assert_eq!(audit_log[0], "entry_900"); // Should start from entry 900
    }

    #[test]
    fn negative_access_tier_enum_manipulation_and_serialization_attacks() {
        use serde_json::json;

        // Test serialization/deserialization with malicious values
        let malicious_tier_values = [
            json!("blocked"),                              // Lowercase (should fail)
            json!("FULL"),                                 // Uppercase (should fail)
            json!("limited_access"),                       // Non-existent variant
            json!("admin"),                                // Privileged-sounding variant
            json!(""),                                     // Empty string
            json!(null),                                   // Null value
            json!(42),                                     // Number instead of string
            json!(true),                                   // Boolean instead of string
            json!(["full"]),                               // Array instead of string
            json!({"tier": "full"}),                       // Object instead of string
            json!("full\u{0000}"),                         // Null byte injection
            json!("full\"><script>alert('xss')</script>"), // XSS attempt
        ];

        for (i, malicious_value) in malicious_tier_values.iter().enumerate() {
            // Attempt to deserialize malicious tier value
            let tier_result = serde_json::from_value::<AccessTier>(malicious_value.clone());

            // Should safely reject malicious values
            assert!(
                tier_result.is_err(),
                "Malicious tier value {} should be rejected: {:?}",
                i,
                malicious_value
            );

            // Test in context of decision structure
            let malicious_decision = json!({
                "participant_id": format!("attack_{}", i),
                "tier": malicious_value,
                "contribution_ratio": 0.5,
                "quality_adjusted_ratio": 0.4,
                "granted": true,
                "reason": "test",
                "exception_applied": false,
                "grace_period_active": false,
                "accessible_feeds": []
            });

            let decision_result = serde_json::from_value::<AccessDecision>(malicious_decision);
            assert!(
                decision_result.is_err(),
                "AccessDecision with malicious tier {} should be rejected",
                i
            );
        }

        // Test valid tiers serialize/deserialize correctly
        let valid_tiers = [
            AccessTier::Blocked,
            AccessTier::Limited,
            AccessTier::Standard,
            AccessTier::Full,
        ];

        for tier in &valid_tiers {
            // Should serialize to expected string
            let serialized = serde_json::to_string(tier).expect("valid tier should serialize");
            let expected = format!(
                "\"{}\"",
                match tier {
                    AccessTier::Blocked => "blocked",
                    AccessTier::Limited => "limited",
                    AccessTier::Standard => "standard",
                    AccessTier::Full => "full",
                }
            );
            assert_eq!(serialized, expected);

            // Should deserialize back to same tier
            let deserialized: AccessTier = serde_json::from_str(&serialized)
                .expect("valid serialized tier should deserialize");
            assert_eq!(deserialized, *tier);
        }
    }

    #[test]
    fn negative_batch_evaluation_with_contradictory_participant_states() {
        let mut engine = ReciprocityEngine::default();

        // Create batch with contradictory or extreme participant states
        let contradictory_participants = vec![
            // Participant with exception but past grace period and zero contributions
            ContributionMetrics {
                participant_id: "contradiction_1".to_string(),
                contributions_made: 0,
                intelligence_consumed: 1000,
                contribution_quality: f64::NAN,
                membership_age_seconds: 86400 * 365, // Well past grace period
                has_exception: true,
                exception_reason: Some("contradiction test".to_string()),
                exception_expires_at: Some("1999-01-01T00:00:00Z".to_string()), // Expired exception
            },
            // New participant with massive consumption but in grace period
            ContributionMetrics {
                participant_id: "contradiction_2".to_string(),
                contributions_made: 0,
                intelligence_consumed: u64::MAX,
                contribution_quality: 0.0,
                membership_age_seconds: 1, // Very new
                has_exception: false,
                exception_reason: None,
                exception_expires_at: None,
            },
            // High contributor with zero consumption (infinite ratio case)
            ContributionMetrics {
                participant_id: "contradiction_3".to_string(),
                contributions_made: u64::MAX,
                intelligence_consumed: 0,
                contribution_quality: f64::INFINITY,
                membership_age_seconds: 86400 * 30,
                has_exception: false,
                exception_reason: None,
                exception_expires_at: None,
            },
            // Participant with negative quality and exception
            ContributionMetrics {
                participant_id: "contradiction_4".to_string(),
                contributions_made: 100,
                intelligence_consumed: 50,
                contribution_quality: f64::NEG_INFINITY,
                membership_age_seconds: 86400 * 30,
                has_exception: true,
                exception_reason: Some("negative quality test".to_string()),
                exception_expires_at: Some("2027-12-31T23:59:59Z".to_string()),
            },
        ];

        // Should handle contradictory states without panics or infinite loops
        let matrix = engine.evaluate_batch(
            &contradictory_participants,
            "contradiction_test",
            "2026-04-17T00:00:00Z",
        );

        // Matrix should have correct participant count
        assert_eq!(matrix.total_participants, contradictory_participants.len());
        assert_eq!(matrix.entries.len(), contradictory_participants.len());

        // Each participant should have a valid tier assignment
        for entry in &matrix.entries {
            assert!(matches!(
                entry.tier,
                AccessTier::Blocked | AccessTier::Limited | AccessTier::Standard | AccessTier::Full
            ));

            // Ratios should be bounded and finite
            assert!(entry.contribution_ratio >= 0.0);
            assert!(entry.contribution_ratio <= 1.0);
            assert!(entry.contribution_ratio.is_finite());

            assert!(entry.quality_adjusted_ratio >= 0.0);
            assert!(entry.quality_adjusted_ratio <= 1.0);
            assert!(entry.quality_adjusted_ratio.is_finite());
        }

        // Tier distribution should be consistent
        let tier_sum: usize = matrix.tier_distribution.values().sum();
        assert_eq!(tier_sum, matrix.total_participants);

        // Should count exceptions correctly (participants with has_exception=true)
        let expected_exceptions = contradictory_participants
            .iter()
            .filter(|p| p.has_exception)
            .count();

        // Only the unexpired exception should remain active.
        assert!(matrix.exceptions_active <= expected_exceptions);
        assert_eq!(matrix.exceptions_active, 1);
        assert!(!matrix.entries[0].exception_active);
        assert!(matrix.entries[0].tier == AccessTier::Blocked);
        assert!(matrix.entries[3].exception_active);

        // Content hash should be deterministic despite contradictory inputs
        assert_eq!(matrix.content_hash.len(), 64);
        assert!(matrix.content_hash.chars().all(|c| c.is_ascii_hexdigit()));

        // Re-evaluating same batch should produce same hash
        let matrix2 = engine.evaluate_batch(
            &contradictory_participants,
            "contradiction_test",
            "2026-04-17T00:00:00Z",
        );
        assert_eq!(matrix.content_hash, matrix2.content_hash);
    }

    fn hostile_threshold_metrics(id: &str, made: u64, consumed: u64) -> ContributionMetrics {
        ContributionMetrics {
            participant_id: id.to_string(),
            contributions_made: made,
            intelligence_consumed: consumed,
            contribution_quality: 1.0,
            membership_age_seconds: 86400 * 90,
            has_exception: false,
            exception_reason: None,
            exception_expires_at: None,
        }
    }

    #[test]
    fn negative_blocked_grace_tier_does_not_mark_access_granted() {
        let mut engine = ReciprocityEngine::new(ReciprocityConfig {
            grace_period_tier: AccessTier::Blocked,
            ..ReciprocityConfig::default()
        });
        let metrics = ContributionMetrics {
            participant_id: "blocked-grace-tier".to_string(),
            contributions_made: 0,
            intelligence_consumed: 0,
            contribution_quality: 1.0,
            membership_age_seconds: 60,
            has_exception: false,
            exception_reason: None,
            exception_expires_at: None,
        };

        let decision = engine.evaluate_access(&metrics, "2026-04-17T00:00:00Z");

        assert!(decision.grace_period_active);
        assert_eq!(decision.tier, AccessTier::Blocked);
        assert!(!decision.granted);
        assert!(decision.accessible_feeds.is_empty());
    }

    #[test]
    fn negative_blocked_grace_batch_counts_freerider_without_feeds() {
        let mut engine = ReciprocityEngine::new(ReciprocityConfig {
            grace_period_tier: AccessTier::Blocked,
            ..ReciprocityConfig::default()
        });
        let participants = [ContributionMetrics {
            participant_id: "blocked-grace-batch".to_string(),
            contributions_made: 0,
            intelligence_consumed: 100,
            contribution_quality: 1.0,
            membership_age_seconds: 1,
            has_exception: false,
            exception_reason: None,
            exception_expires_at: None,
        }];

        let matrix = engine.evaluate_batch(&participants, "blocked-grace", "2026-04-17T00:00:00Z");

        assert_eq!(matrix.freeriders_blocked, 1);
        assert_eq!(matrix.entries[0].tier, AccessTier::Blocked);
        assert!(matrix.entries[0].grace_period_active);
        assert_eq!(matrix.exceptions_active, 0);
    }

    #[test]
    fn negative_nan_full_threshold_does_not_grant_raw_signal_access() {
        let mut engine = ReciprocityEngine::new(ReciprocityConfig {
            full_tier_min_ratio: f64::NAN,
            ..ReciprocityConfig::default()
        });
        let metrics = hostile_threshold_metrics("nan-full-threshold", 100, 100);

        let decision = engine.evaluate_access(&metrics, "2026-04-17T00:00:00Z");

        assert_ne!(decision.tier, AccessTier::Full);
        assert!(
            !decision
                .accessible_feeds
                .iter()
                .any(|feed| feed.contains("raw_signals"))
        );
    }

    #[test]
    fn negative_nan_standard_threshold_falls_back_to_limited_for_mid_ratio() {
        let mut engine = ReciprocityEngine::new(ReciprocityConfig {
            standard_tier_min_ratio: f64::NAN,
            ..ReciprocityConfig::default()
        });
        let metrics = hostile_threshold_metrics("nan-standard-threshold", 30, 100);

        let decision = engine.evaluate_access(&metrics, "2026-04-17T00:00:00Z");

        assert_eq!(decision.tier, AccessTier::Limited);
        assert!(decision.granted);
        assert_eq!(decision.accessible_feeds, vec!["advisories".to_string()]);
    }

    #[test]
    fn negative_nan_limited_threshold_blocks_low_ratio() {
        let mut engine = ReciprocityEngine::new(ReciprocityConfig {
            limited_tier_min_ratio: f64::NAN,
            ..ReciprocityConfig::default()
        });
        let metrics = hostile_threshold_metrics("nan-limited-threshold", 1, 100);

        let decision = engine.evaluate_access(&metrics, "2026-04-17T00:00:00Z");

        assert_eq!(decision.tier, AccessTier::Blocked);
        assert!(!decision.granted);
        assert!(decision.accessible_feeds.is_empty());
    }

    #[test]
    fn negative_full_threshold_above_one_prevents_raw_signal_access() {
        let mut engine = ReciprocityEngine::new(ReciprocityConfig {
            full_tier_min_ratio: 1.01,
            ..ReciprocityConfig::default()
        });
        let metrics = hostile_threshold_metrics("full-threshold-above-one", u64::MAX, 0);

        let decision = engine.evaluate_access(&metrics, "2026-04-17T00:00:00Z");

        assert_eq!(decision.contribution_ratio, 1.0);
        assert_ne!(decision.tier, AccessTier::Full);
        assert!(
            !decision
                .accessible_feeds
                .iter()
                .any(|feed| feed.contains("raw_signals"))
        );
    }

    #[test]
    fn negative_all_thresholds_above_one_blocks_even_max_ratio() {
        let mut engine = ReciprocityEngine::new(ReciprocityConfig {
            full_tier_min_ratio: 1.5,
            standard_tier_min_ratio: 1.4,
            limited_tier_min_ratio: 1.3,
            ..ReciprocityConfig::default()
        });
        let metrics = hostile_threshold_metrics("all-thresholds-above-one", 10, 0);

        let decision = engine.evaluate_access(&metrics, "2026-04-17T00:00:00Z");

        assert_eq!(decision.contribution_ratio, 1.0);
        assert_eq!(decision.quality_adjusted_ratio, 1.0);
        assert_eq!(decision.tier, AccessTier::Blocked);
        assert!(!decision.granted);
    }

    #[test]
    fn exception_expiration_regression_bd_2vu01() {
        // Regression test for bd-2vu01: ensure expired exceptions don't grant access
        let mut engine = ReciprocityEngine::default();

        // Test expired exception
        let expired_metrics = ContributionMetrics {
            participant_id: "expired_exception".to_string(),
            contributions_made: 0,
            intelligence_consumed: 100,
            contribution_quality: 0.0,
            membership_age_seconds: 86400 * 365, // Well past grace period
            has_exception: true,
            exception_reason: Some("expired research exception".to_string()),
            exception_expires_at: Some("2020-01-01T00:00:00Z".to_string()), // Long expired
        };

        let decision = engine.evaluate_access(&expired_metrics, "2026-04-17T00:00:00Z");

        // Expired exception should NOT grant access
        assert!(!decision.exception_applied, "Expired exception should not be applied");
        assert_eq!(decision.tier, AccessTier::Blocked, "Expired exception should result in blocked access");
        assert!(!decision.granted, "Expired exception should not grant access");

        // Test valid (unexpired) exception
        let valid_metrics = ContributionMetrics {
            participant_id: "valid_exception".to_string(),
            contributions_made: 0,
            intelligence_consumed: 100,
            contribution_quality: 0.0,
            membership_age_seconds: 86400 * 365, // Well past grace period
            has_exception: true,
            exception_reason: Some("valid research exception".to_string()),
            exception_expires_at: Some("2030-01-01T00:00:00Z".to_string()), // Future expiry
        };

        let decision = engine.evaluate_access(&valid_metrics, "2026-04-17T00:00:00Z");

        // Valid exception should grant access
        assert!(decision.exception_applied, "Valid exception should be applied");
        assert_eq!(decision.tier, AccessTier::Standard, "Valid exception should grant standard access");
        assert!(decision.granted, "Valid exception should grant access");

        // Test malformed expiration timestamp
        let malformed_metrics = ContributionMetrics {
            participant_id: "malformed_expiry".to_string(),
            contributions_made: 0,
            intelligence_consumed: 100,
            contribution_quality: 0.0,
            membership_age_seconds: 86400 * 365, // Well past grace period
            has_exception: true,
            exception_reason: Some("malformed expiry exception".to_string()),
            exception_expires_at: Some("not-a-valid-timestamp".to_string()),
        };

        let decision = engine.evaluate_access(&malformed_metrics, "2026-04-17T00:00:00Z");

        // Malformed expiration should fail closed and not grant access
        assert!(!decision.exception_applied, "Malformed expiry should not grant access");
        assert_eq!(decision.tier, AccessTier::Blocked, "Malformed expiry should result in blocked access");
        assert!(!decision.granted, "Malformed expiry should not grant access");
    }
}
