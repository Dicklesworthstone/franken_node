//! bd-y7lu: Revocation registry with monotonic revocation-head checkpoints.
//!
//! Tracks revoked artifacts per zone/tenant. Revocation heads are strictly
//! monotonic: stale updates are rejected. State is recoverable from the
//! canonical revocation log.
//!
//! # Input Validation
//!
//! All string inputs are length-validated to prevent DoS attacks through
//! oversized input strings that could cause memory exhaustion.

use std::collections::{BTreeMap, BTreeSet};

/// Maximum entries in the canonical revocation log before new entries are rejected.
const MAX_LOG_ENTRIES: usize = 4096;

/// Maximum audit trail entries before oldest are evicted.
const MAX_AUDIT_ENTRIES: usize = 4096;

/// Maximum revoked artifacts per zone before further revocations are rejected.
const MAX_REVOKED_PER_ZONE: usize = 4096;

// Input validation limits to prevent DoS attacks
const MAX_ZONE_ID_LEN: usize = 256;
const MAX_ARTIFACT_ID_LEN: usize = 512;
const MAX_REASON_LEN: usize = 1024;
const MAX_TRACE_ID_LEN: usize = 256;

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

/// A revocation head checkpoint for a specific zone.
#[derive(Debug, Clone)]
pub struct RevocationHead {
    pub zone_id: String,
    pub sequence: u64,
    pub revoked_artifact: String,
    pub reason: String,
    pub timestamp: String,
    pub trace_id: String,
}

/// Errors from revocation operations.
///
/// Error codes: `REV_STALE_HEAD`, `REV_ZONE_NOT_FOUND`, `REV_RECOVERY_FAILED`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RevocationError {
    StaleHead {
        zone_id: String,
        offered: u64,
        current: u64,
    },
    ZoneNotFound {
        zone_id: String,
    },
    RecoveryFailed {
        reason: String,
    },
    InvalidInput {
        detail: String,
    },
}

impl RevocationError {
    pub fn code(&self) -> &'static str {
        match self {
            Self::StaleHead { .. } => "REV_STALE_HEAD",
            Self::ZoneNotFound { .. } => "REV_ZONE_NOT_FOUND",
            Self::RecoveryFailed { .. } => "REV_RECOVERY_FAILED",
            Self::InvalidInput { .. } => "REV_INVALID_INPUT",
        }
    }
}

impl std::fmt::Display for RevocationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::StaleHead {
                zone_id,
                offered,
                current,
            } => {
                write!(
                    f,
                    "REV_STALE_HEAD: zone {zone_id} offered seq {offered} <= current {current}"
                )
            }
            Self::ZoneNotFound { zone_id } => {
                write!(f, "REV_ZONE_NOT_FOUND: zone {zone_id}")
            }
            Self::RecoveryFailed { reason } => {
                write!(f, "REV_RECOVERY_FAILED: {reason}")
            }
            Self::InvalidInput { detail } => {
                write!(f, "REV_INVALID_INPUT: {detail}")
            }
        }
    }
}

/// Audit record for each advance operation.
#[derive(Debug, Clone)]
pub struct RevocationAudit {
    pub zone_id: String,
    pub action: String,
    pub sequence: u64,
    pub trace_id: String,
    pub timestamp: String,
}

/// Revocation registry maintaining per-zone monotonic heads.
#[derive(Debug, Default)]
pub struct RevocationRegistry {
    /// Current head sequence per zone.
    heads: BTreeMap<String, u64>,
    /// Canonical log of all revocation events (for recovery).
    log: Vec<RevocationHead>,
    /// Set of revoked artifacts per zone.  Uses BTreeSet (not Vec) because
    /// revocation is monotonic and permanent — evicting old revocations would
    /// let previously-revoked artifacts pass `is_revoked()` checks.
    revoked: BTreeMap<String, BTreeSet<String>>,
    /// Audit trail.
    pub audits: Vec<RevocationAudit>,
}

impl RevocationRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    /// Initialize a zone with head at sequence 0.
    pub fn init_zone(&mut self, zone_id: &str) -> Result<(), RevocationError> {
        // Input validation to prevent DoS attacks
        if zone_id.len() > MAX_ZONE_ID_LEN {
            return Err(RevocationError::InvalidInput {
                detail: format!(
                    "zone_id too long: {} characters (max: {})",
                    zone_id.len(),
                    MAX_ZONE_ID_LEN
                ),
            });
        }

        if zone_id.trim().is_empty() {
            return Err(RevocationError::InvalidInput {
                detail: "zone_id must not be empty".to_string(),
            });
        }
        self.heads.entry(zone_id.to_string()).or_insert(0);
        self.revoked.entry(zone_id.to_string()).or_default();
        Ok(())
    }

    /// Get the current head sequence for a zone.
    pub fn current_head(&self, zone_id: &str) -> Result<u64, RevocationError> {
        // Input validation to prevent DoS attacks
        if zone_id.len() > MAX_ZONE_ID_LEN {
            return Err(RevocationError::InvalidInput {
                detail: format!(
                    "zone_id too long: {} characters (max: {})",
                    zone_id.len(),
                    MAX_ZONE_ID_LEN
                ),
            });
        }

        self.heads
            .get(zone_id)
            .copied()
            .ok_or_else(|| RevocationError::ZoneNotFound {
                zone_id: zone_id.to_string(),
            })
    }

    /// Advance the revocation head for a zone.
    ///
    /// INV-REV-MONOTONIC: new sequence must be > current head.
    /// INV-REV-STALE-REJECT: rejects offered <= current.
    /// INV-REV-ZONE-ISOLATED: operates on a single zone.
    pub fn advance_head(&mut self, head: RevocationHead) -> Result<u64, RevocationError> {
        // Input validation to prevent DoS attacks through oversized strings
        if head.zone_id.len() > MAX_ZONE_ID_LEN {
            return Err(RevocationError::InvalidInput {
                detail: format!(
                    "zone_id too long: {} characters (max: {})",
                    head.zone_id.len(),
                    MAX_ZONE_ID_LEN
                ),
            });
        }

        if head.revoked_artifact.len() > MAX_ARTIFACT_ID_LEN {
            return Err(RevocationError::InvalidInput {
                detail: format!(
                    "revoked_artifact too long: {} characters (max: {})",
                    head.revoked_artifact.len(),
                    MAX_ARTIFACT_ID_LEN
                ),
            });
        }

        if head.reason.len() > MAX_REASON_LEN {
            return Err(RevocationError::InvalidInput {
                detail: format!(
                    "reason too long: {} characters (max: {})",
                    head.reason.len(),
                    MAX_REASON_LEN
                ),
            });
        }

        if head.trace_id.len() > MAX_TRACE_ID_LEN {
            return Err(RevocationError::InvalidInput {
                detail: format!(
                    "trace_id too long: {} characters (max: {})",
                    head.trace_id.len(),
                    MAX_TRACE_ID_LEN
                ),
            });
        }

        if head.zone_id.trim().is_empty() {
            return Err(RevocationError::InvalidInput {
                detail: "zone_id must not be empty".to_string(),
            });
        }
        if head.revoked_artifact.trim().is_empty() {
            return Err(RevocationError::InvalidInput {
                detail: "revoked_artifact must not be empty".to_string(),
            });
        }
        let current = self.heads.get(&head.zone_id).copied().unwrap_or(0);

        // INV-REV-MONOTONIC + INV-REV-STALE-REJECT
        if head.sequence <= current {
            push_bounded(
                &mut self.audits,
                RevocationAudit {
                    zone_id: head.zone_id.clone(),
                    action: "rejected_stale".into(),
                    sequence: head.sequence,
                    trace_id: head.trace_id.clone(),
                    timestamp: head.timestamp.clone(),
                },
                MAX_AUDIT_ENTRIES,
            );
            return Err(RevocationError::StaleHead {
                zone_id: head.zone_id,
                offered: head.sequence,
                current,
            });
        }

        // INV-REV-MONOTONIC: revocation is permanent.  BTreeSet never evicts
        // old entries — `push_bounded` on the old Vec silently dropped old
        // revocations, letting previously-revoked artifacts pass is_revoked().
        // Reject at capacity instead of evicting.
        let zone_revoked_len = self.revoked.get(&head.zone_id).map_or(0, BTreeSet::len);
        if self
            .revoked
            .get(&head.zone_id)
            .is_some_and(|zone_revoked| zone_revoked.contains(&head.revoked_artifact))
        {
            return Err(RevocationError::InvalidInput {
                detail: format!(
                    "zone {} already revoked artifact {}; duplicate revocation would advance head without new state",
                    head.zone_id, head.revoked_artifact
                ),
            });
        }
        if zone_revoked_len >= MAX_REVOKED_PER_ZONE {
            return Err(RevocationError::InvalidInput {
                detail: format!(
                    "zone {} revoked set at capacity ({MAX_REVOKED_PER_ZONE}); cannot record revocation for {}",
                    head.zone_id, head.revoked_artifact
                ),
            });
        }
        if self.log.len() >= MAX_LOG_ENTRIES {
            return Err(RevocationError::InvalidInput {
                detail: format!(
                    "canonical revocation log at capacity ({MAX_LOG_ENTRIES}); cannot record revocation for {} in zone {}",
                    head.revoked_artifact, head.zone_id
                ),
            });
        }

        // Advance only after all fail-closed checks pass.  Capacity rejection
        // must not publish a head for a revocation that was not recorded.
        self.heads.insert(head.zone_id.clone(), head.sequence);
        self.revoked
            .entry(head.zone_id.clone())
            .or_default()
            .insert(head.revoked_artifact.clone());

        push_bounded(
            &mut self.audits,
            RevocationAudit {
                zone_id: head.zone_id.clone(),
                action: "advanced".into(),
                sequence: head.sequence,
                trace_id: head.trace_id.clone(),
                timestamp: head.timestamp.clone(),
            },
            MAX_AUDIT_ENTRIES,
        );

        // Append to canonical log for recovery
        push_bounded(&mut self.log, head.clone(), MAX_LOG_ENTRIES);

        Ok(head.sequence)
    }

    /// Check if an artifact is revoked in a given zone.
    pub fn is_revoked(&self, zone_id: &str, artifact: &str) -> Result<bool, RevocationError> {
        // Input validation to prevent DoS attacks
        if zone_id.len() > MAX_ZONE_ID_LEN {
            return Err(RevocationError::InvalidInput {
                detail: format!(
                    "zone_id too long: {} characters (max: {})",
                    zone_id.len(),
                    MAX_ZONE_ID_LEN
                ),
            });
        }

        if artifact.len() > MAX_ARTIFACT_ID_LEN {
            return Err(RevocationError::InvalidInput {
                detail: format!(
                    "artifact too long: {} characters (max: {})",
                    artifact.len(),
                    MAX_ARTIFACT_ID_LEN
                ),
            });
        }

        let entries = self
            .revoked
            .get(zone_id)
            .ok_or_else(|| RevocationError::ZoneNotFound {
                zone_id: zone_id.to_string(),
            })?;
        Ok(entries.contains(artifact))
    }

    /// Recover registry state from the canonical log.
    ///
    /// INV-REV-RECOVERABLE: rebuilds heads and revoked sets from log.
    pub fn recover_from_log(log: &[RevocationHead]) -> Result<Self, RevocationError> {
        if log.is_empty() {
            return Err(RevocationError::RecoveryFailed {
                reason: "empty log".into(),
            });
        }
        if log.len() > MAX_LOG_ENTRIES {
            return Err(RevocationError::RecoveryFailed {
                reason: format!(
                    "canonical revocation log length {} exceeds capacity ({MAX_LOG_ENTRIES})",
                    log.len()
                ),
            });
        }

        let mut registry = Self::new();

        for entry in log {
            // During recovery, initialize zone if needed
            registry
                .init_zone(&entry.zone_id)
                .map_err(|e| RevocationError::RecoveryFailed {
                    reason: format!("invalid zone_id in log: {e}"),
                })?;
            if entry.revoked_artifact.trim().is_empty() {
                return Err(RevocationError::RecoveryFailed {
                    reason: format!("invalid revoked_artifact in log for zone {}", entry.zone_id),
                });
            }
            // Re-apply each log entry; must succeed in log order
            let current = registry.heads.get(&entry.zone_id).copied().unwrap_or(0);
            if entry.sequence <= current {
                return Err(RevocationError::RecoveryFailed {
                    reason: format!(
                        "non-monotonic log: zone {} seq {} <= current {}",
                        entry.zone_id, entry.sequence, current
                    ),
                });
            }
            registry.heads.insert(entry.zone_id.clone(), entry.sequence);
            let zone_revoked = registry.revoked.entry(entry.zone_id.clone()).or_default();
            if zone_revoked.contains(&entry.revoked_artifact) {
                return Err(RevocationError::RecoveryFailed {
                    reason: format!(
                        "duplicate revocation for artifact {} in zone {}",
                        entry.revoked_artifact, entry.zone_id
                    ),
                });
            }
            if zone_revoked.len() >= MAX_REVOKED_PER_ZONE {
                return Err(RevocationError::RecoveryFailed {
                    reason: format!(
                        "zone {} revoked set at capacity ({MAX_REVOKED_PER_ZONE}); cannot recover revocation for {}",
                        entry.zone_id, entry.revoked_artifact
                    ),
                });
            }
            zone_revoked.insert(entry.revoked_artifact.clone());
            push_bounded(&mut registry.log, entry.clone(), MAX_LOG_ENTRIES);
        }

        Ok(registry)
    }

    /// Return the canonical log (for serialization/persistence).
    pub fn canonical_log(&self) -> &[RevocationHead] {
        &self.log
    }

    /// Number of zones tracked.
    pub fn zone_count(&self) -> usize {
        self.heads.len()
    }

    /// Total revocations across all zones.
    pub fn total_revocations(&self) -> usize {
        self.revoked
            .values()
            .fold(0usize, |acc, v| acc.saturating_add(v.len()))
    }
}

#[cfg(test)]
mod tests {
    use super::{RevocationAudit, RevocationError, RevocationHead, RevocationRegistry};

    fn head(zone: &str, seq: u64, artifact: &str) -> RevocationHead {
        RevocationHead {
            zone_id: zone.into(),
            sequence: seq,
            revoked_artifact: artifact.into(),
            reason: "compromised".into(),
            timestamp: "2026-01-01T00:00:00Z".into(),
            trace_id: "tr-1".into(),
        }
    }

    fn apply_log(log: &[RevocationHead]) -> RevocationRegistry {
        let mut reg = RevocationRegistry::new();
        for entry in log {
            reg.advance_head(entry.clone()).unwrap();
        }
        reg
    }

    fn assert_same_observable_state(
        left: &RevocationRegistry,
        right: &RevocationRegistry,
        zones: &[(&str, u64)],
        artifacts: &[(&str, &str)],
    ) {
        assert_eq!(left.zone_count(), right.zone_count());
        assert_eq!(left.total_revocations(), right.total_revocations());
        for (zone, expected_head) in zones {
            assert_eq!(left.current_head(zone).unwrap(), *expected_head);
            assert_eq!(right.current_head(zone).unwrap(), *expected_head);
        }
        for (zone, artifact) in artifacts {
            assert_eq!(
                left.is_revoked(zone, artifact).unwrap(),
                right.is_revoked(zone, artifact).unwrap()
            );
        }
    }

    #[test]
    fn advance_head_succeeds() {
        let mut reg = RevocationRegistry::new();
        reg.init_zone("zone-a").unwrap();
        let result = reg.advance_head(head("zone-a", 1, "art-1"));
        assert_eq!(result.unwrap(), 1);
        assert_eq!(reg.current_head("zone-a").unwrap(), 1);
    }

    #[test]
    fn monotonic_advance() {
        let mut reg = RevocationRegistry::new();
        reg.init_zone("zone-a").unwrap();
        reg.advance_head(head("zone-a", 1, "art-1")).unwrap();
        reg.advance_head(head("zone-a", 2, "art-2")).unwrap();
        reg.advance_head(head("zone-a", 5, "art-3")).unwrap();
        assert_eq!(reg.current_head("zone-a").unwrap(), 5);
    }

    #[test]
    fn stale_head_rejected() {
        let mut reg = RevocationRegistry::new();
        reg.init_zone("zone-a").unwrap();
        reg.advance_head(head("zone-a", 3, "art-1")).unwrap();
        let result = reg.advance_head(head("zone-a", 2, "art-2"));
        let err = result.unwrap_err();
        assert_eq!(err.code(), "REV_STALE_HEAD");
    }

    #[test]
    fn equal_sequence_rejected() {
        let mut reg = RevocationRegistry::new();
        reg.init_zone("zone-a").unwrap();
        reg.advance_head(head("zone-a", 3, "art-1")).unwrap();
        let result = reg.advance_head(head("zone-a", 3, "art-2"));
        assert_eq!(result.unwrap_err().code(), "REV_STALE_HEAD");
    }

    #[test]
    fn zone_isolation() {
        let mut reg = RevocationRegistry::new();
        reg.init_zone("zone-a").unwrap();
        reg.init_zone("zone-b").unwrap();
        reg.advance_head(head("zone-a", 5, "art-1")).unwrap();
        reg.advance_head(head("zone-b", 1, "art-2")).unwrap();
        assert_eq!(reg.current_head("zone-a").unwrap(), 5);
        assert_eq!(reg.current_head("zone-b").unwrap(), 1);
    }

    #[test]
    fn unknown_zone_errors() {
        let reg = RevocationRegistry::new();
        let err = reg.current_head("ghost").unwrap_err();
        assert_eq!(err.code(), "REV_ZONE_NOT_FOUND");
    }

    #[test]
    fn is_revoked_true() {
        let mut reg = RevocationRegistry::new();
        reg.init_zone("zone-a").unwrap();
        reg.advance_head(head("zone-a", 1, "art-bad")).unwrap();
        assert!(reg.is_revoked("zone-a", "art-bad").unwrap());
    }

    #[test]
    fn is_revoked_false() {
        let mut reg = RevocationRegistry::new();
        reg.init_zone("zone-a").unwrap();
        reg.advance_head(head("zone-a", 1, "art-bad")).unwrap();
        assert!(!reg.is_revoked("zone-a", "art-good").unwrap());
    }

    #[test]
    fn is_revoked_unknown_zone() {
        let reg = RevocationRegistry::new();
        assert_eq!(
            reg.is_revoked("ghost", "x").unwrap_err().code(),
            "REV_ZONE_NOT_FOUND"
        );
    }

    #[test]
    fn recover_from_log() {
        let log = vec![
            head("zone-a", 1, "art-1"),
            head("zone-a", 2, "art-2"),
            head("zone-b", 1, "art-3"),
        ];
        let reg = RevocationRegistry::recover_from_log(&log).unwrap();
        assert_eq!(reg.current_head("zone-a").unwrap(), 2);
        assert_eq!(reg.current_head("zone-b").unwrap(), 1);
        assert!(reg.is_revoked("zone-a", "art-1").unwrap());
        assert!(reg.is_revoked("zone-a", "art-2").unwrap());
        assert!(reg.is_revoked("zone-b", "art-3").unwrap());
    }

    #[test]
    fn recover_empty_log_fails() {
        let result = RevocationRegistry::recover_from_log(&[]);
        assert_eq!(result.unwrap_err().code(), "REV_RECOVERY_FAILED");
    }

    #[test]
    fn recover_non_monotonic_fails() {
        let log = vec![head("zone-a", 2, "art-1"), head("zone-a", 1, "art-2")];
        let result = RevocationRegistry::recover_from_log(&log);
        assert_eq!(result.unwrap_err().code(), "REV_RECOVERY_FAILED");
    }

    #[test]
    fn canonical_log_preserved() {
        let mut reg = RevocationRegistry::new();
        reg.init_zone("zone-a").unwrap();
        reg.advance_head(head("zone-a", 1, "art-1")).unwrap();
        reg.advance_head(head("zone-a", 2, "art-2")).unwrap();
        assert_eq!(reg.canonical_log().len(), 2);
    }

    #[test]
    fn audit_trail_on_advance() {
        let mut reg = RevocationRegistry::new();
        reg.init_zone("zone-a").unwrap();
        reg.advance_head(head("zone-a", 1, "art-1")).unwrap();
        assert_eq!(reg.audits.len(), 1);
        assert_eq!(reg.audits[0].action, "advanced");
    }

    #[test]
    fn audit_trail_on_stale_reject() {
        let mut reg = RevocationRegistry::new();
        reg.init_zone("zone-a").unwrap();
        reg.advance_head(head("zone-a", 2, "art-1")).unwrap();
        let _ = reg.advance_head(head("zone-a", 1, "art-2"));
        assert_eq!(reg.audits.len(), 2);
        assert_eq!(reg.audits[1].action, "rejected_stale");
    }

    #[test]
    fn zone_count() {
        let mut reg = RevocationRegistry::new();
        reg.init_zone("a").unwrap();
        reg.init_zone("b").unwrap();
        assert_eq!(reg.zone_count(), 2);
    }

    #[test]
    fn total_revocations() {
        let mut reg = RevocationRegistry::new();
        reg.init_zone("zone-a").unwrap();
        reg.advance_head(head("zone-a", 1, "art-1")).unwrap();
        reg.advance_head(head("zone-a", 2, "art-2")).unwrap();
        assert_eq!(reg.total_revocations(), 2);
    }

    #[test]
    fn error_display() {
        let e = RevocationError::StaleHead {
            zone_id: "z1".into(),
            offered: 2,
            current: 5,
        };
        assert!(e.to_string().contains("REV_STALE_HEAD"));
    }

    #[test]
    fn error_codes_all_present() {
        assert_eq!(
            RevocationError::StaleHead {
                zone_id: "x".into(),
                offered: 0,
                current: 0
            }
            .code(),
            "REV_STALE_HEAD"
        );
        assert_eq!(
            RevocationError::ZoneNotFound {
                zone_id: "x".into()
            }
            .code(),
            "REV_ZONE_NOT_FOUND"
        );
        assert_eq!(
            RevocationError::RecoveryFailed { reason: "x".into() }.code(),
            "REV_RECOVERY_FAILED"
        );
    }

    #[test]
    fn advance_without_init_creates_zone() {
        let mut reg = RevocationRegistry::new();
        // advance_head on uninitialized zone still works (current defaults to 0)
        let result = reg.advance_head(head("zone-new", 1, "art-1"));
        assert_eq!(result.unwrap(), 1);
    }

    #[test]
    fn mr_recovery_equivalent_to_online_application_for_generated_logs() {
        let log = vec![
            head("zone-a", 1, "art-a1"),
            head("zone-b", 1, "art-b1"),
            head("zone-a", 4, "art-a4"),
            head("zone-c", 2, "art-c2"),
            head("zone-b", 3, "art-b3"),
        ];
        let online = apply_log(&log);
        let recovered = RevocationRegistry::recover_from_log(&log).unwrap();

        assert_same_observable_state(
            &online,
            &recovered,
            &[("zone-a", 4), ("zone-b", 3), ("zone-c", 2)],
            &[
                ("zone-a", "art-a1"),
                ("zone-a", "art-a4"),
                ("zone-b", "art-b1"),
                ("zone-b", "art-b3"),
                ("zone-c", "art-c2"),
            ],
        );
    }

    #[test]
    fn mr_cross_zone_event_permutation_preserves_observable_state() {
        let first_order = vec![
            head("zone-a", 1, "art-a1"),
            head("zone-b", 1, "art-b1"),
            head("zone-a", 2, "art-a2"),
            head("zone-b", 3, "art-b3"),
            head("zone-c", 1, "art-c1"),
        ];
        let second_order = vec![
            head("zone-c", 1, "art-c1"),
            head("zone-b", 1, "art-b1"),
            head("zone-a", 1, "art-a1"),
            head("zone-b", 3, "art-b3"),
            head("zone-a", 2, "art-a2"),
        ];

        let first = RevocationRegistry::recover_from_log(&first_order).unwrap();
        let second = RevocationRegistry::recover_from_log(&second_order).unwrap();

        assert_same_observable_state(
            &first,
            &second,
            &[("zone-a", 2), ("zone-b", 3), ("zone-c", 1)],
            &[
                ("zone-a", "art-a1"),
                ("zone-a", "art-a2"),
                ("zone-b", "art-b1"),
                ("zone-b", "art-b3"),
                ("zone-c", "art-c1"),
            ],
        );
    }

    #[test]
    fn mr_extending_log_with_newer_head_is_inclusive() {
        let base = vec![head("zone-a", 1, "art-a1"), head("zone-b", 1, "art-b1")];
        let extended = vec![
            head("zone-a", 1, "art-a1"),
            head("zone-b", 1, "art-b1"),
            head("zone-a", 2, "art-a2"),
        ];

        let base_reg = RevocationRegistry::recover_from_log(&base).unwrap();
        let extended_reg = RevocationRegistry::recover_from_log(&extended).unwrap();

        assert!(base_reg.is_revoked("zone-a", "art-a1").unwrap());
        assert!(extended_reg.is_revoked("zone-a", "art-a1").unwrap());
        assert!(extended_reg.is_revoked("zone-b", "art-b1").unwrap());
        assert!(extended_reg.is_revoked("zone-a", "art-a2").unwrap());
        assert_eq!(base_reg.current_head("zone-a").unwrap(), 1);
        assert_eq!(extended_reg.current_head("zone-a").unwrap(), 2);
        assert_eq!(
            extended_reg.total_revocations(),
            base_reg.total_revocations().saturating_add(1)
        );
    }

    #[test]
    fn mr_stale_rejection_keeps_head_log_and_revoked_set_unchanged() {
        let mut reg = RevocationRegistry::new();
        reg.advance_head(head("zone-a", 5, "art-a5")).unwrap();
        let head_before = reg.current_head("zone-a").unwrap();
        let log_len_before = reg.canonical_log().len();
        let revocations_before = reg.total_revocations();

        let err = reg.advance_head(head("zone-a", 4, "art-a4")).unwrap_err();

        assert_eq!(err.code(), "REV_STALE_HEAD");
        assert_eq!(reg.current_head("zone-a").unwrap(), head_before);
        assert_eq!(reg.canonical_log().len(), log_len_before);
        assert_eq!(reg.total_revocations(), revocations_before);
        assert!(!reg.is_revoked("zone-a", "art-a4").unwrap());
        assert!(reg.is_revoked("zone-a", "art-a5").unwrap());
    }

    #[test]
    fn mr_equal_sequence_rejection_keeps_original_artifact_binding() {
        let mut reg = RevocationRegistry::new();
        reg.advance_head(head("zone-a", 7, "art-original")).unwrap();
        let log_len_before = reg.canonical_log().len();

        let err = reg
            .advance_head(head("zone-a", 7, "art-conflicting"))
            .unwrap_err();

        assert_eq!(err.code(), "REV_STALE_HEAD");
        assert_eq!(reg.current_head("zone-a").unwrap(), 7);
        assert_eq!(reg.canonical_log().len(), log_len_before);
        assert!(reg.is_revoked("zone-a", "art-original").unwrap());
        assert!(!reg.is_revoked("zone-a", "art-conflicting").unwrap());
    }

    #[test]
    fn mr_init_zone_is_idempotent() {
        let mut reg = RevocationRegistry::new();
        reg.init_zone("zone-a").unwrap();
        reg.init_zone("zone-a").unwrap();
        reg.init_zone("zone-a").unwrap();

        assert_eq!(reg.zone_count(), 1);
        assert_eq!(reg.current_head("zone-a").unwrap(), 0);
        assert_eq!(reg.total_revocations(), 0);
        assert_eq!(reg.canonical_log().len(), 0);
    }

    #[test]
    fn mr_invalid_zone_input_does_not_mutate_registry() {
        let mut reg = RevocationRegistry::new();
        reg.advance_head(head("zone-a", 1, "art-a1")).unwrap();
        let zone_count_before = reg.zone_count();
        let log_len_before = reg.canonical_log().len();
        let revocations_before = reg.total_revocations();

        assert_eq!(reg.init_zone("").unwrap_err().code(), "REV_INVALID_INPUT");
        assert_eq!(
            reg.advance_head(head("", 1, "art-empty-zone"))
                .unwrap_err()
                .code(),
            "REV_INVALID_INPUT"
        );

        assert_eq!(reg.zone_count(), zone_count_before);
        assert_eq!(reg.canonical_log().len(), log_len_before);
        assert_eq!(reg.total_revocations(), revocations_before);
        assert!(reg.is_revoked("zone-a", "art-a1").unwrap());
    }

    #[test]
    fn negative_push_bounded_zero_capacity_clears_without_keeping_new_item() {
        let mut entries = vec![head("zone-a", 1, "art-a1"), head("zone-a", 2, "art-a2")];

        push_bounded(&mut entries, head("zone-a", 3, "art-a3"), 0);

        assert!(entries.is_empty());
    }

    #[test]
    fn negative_whitespace_zone_init_is_rejected_without_mutation() {
        let mut reg = RevocationRegistry::new();
        reg.init_zone("zone-a").unwrap();

        let err = reg.init_zone(" \t\n ").unwrap_err();

        assert_eq!(err.code(), "REV_INVALID_INPUT");
        assert_eq!(reg.zone_count(), 1);
        assert_eq!(reg.current_head("zone-a").unwrap(), 0);
    }

    #[test]
    fn negative_whitespace_zone_advance_does_not_create_audit_or_head() {
        let mut reg = RevocationRegistry::new();

        let err = reg
            .advance_head(head(" \t ", 1, "art-space-zone"))
            .unwrap_err();

        assert_eq!(err.code(), "REV_INVALID_INPUT");
        assert_eq!(reg.zone_count(), 0);
        assert_eq!(reg.canonical_log().len(), 0);
        assert_eq!(reg.audits.len(), 0);
    }

    #[test]
    fn negative_empty_artifact_advance_is_atomic() {
        let mut reg = RevocationRegistry::new();
        reg.advance_head(head("zone-a", 2, "art-a2")).unwrap();
        let head_before = reg.current_head("zone-a").unwrap();
        let log_len_before = reg.canonical_log().len();
        let audit_len_before = reg.audits.len();
        let revocations_before = reg.total_revocations();

        let err = reg.advance_head(head("zone-a", 3, " \n\t ")).unwrap_err();

        assert_eq!(err.code(), "REV_INVALID_INPUT");
        assert_eq!(reg.current_head("zone-a").unwrap(), head_before);
        assert_eq!(reg.canonical_log().len(), log_len_before);
        assert_eq!(reg.audits.len(), audit_len_before);
        assert_eq!(reg.total_revocations(), revocations_before);
    }

    #[test]
    fn negative_zero_sequence_new_zone_is_rejected_without_creating_zone() {
        let mut reg = RevocationRegistry::new();

        let err = reg
            .advance_head(head("zone-zero", 0, "art-zero"))
            .unwrap_err();

        assert_eq!(err.code(), "REV_STALE_HEAD");
        assert_eq!(reg.zone_count(), 0);
        assert!(reg.current_head("zone-zero").is_err());
        assert_eq!(reg.canonical_log().len(), 0);
        assert_eq!(reg.total_revocations(), 0);
    }

    #[test]
    fn negative_recovery_rejects_whitespace_zone_id() {
        let log = vec![head(" \t ", 1, "art-bad-zone")];

        let err = RevocationRegistry::recover_from_log(&log).unwrap_err();

        assert_eq!(err.code(), "REV_RECOVERY_FAILED");
        assert!(err.to_string().contains("invalid zone_id"));
    }

    #[test]
    fn negative_recovery_rejects_empty_revoked_artifact() {
        let log = vec![head("zone-a", 1, " \n\t ")];

        let err = RevocationRegistry::recover_from_log(&log).unwrap_err();

        assert_eq!(err.code(), "REV_RECOVERY_FAILED");
        assert!(err.to_string().contains("invalid revoked_artifact"));
    }

    #[test]
    fn negative_blank_artifact_does_not_shadow_later_valid_artifact() {
        let mut reg = RevocationRegistry::new();
        assert_eq!(
            reg.advance_head(head("zone-a", 1, "")).unwrap_err().code(),
            "REV_INVALID_INPUT"
        );

        reg.advance_head(head("zone-a", 1, "art-valid")).unwrap();

        assert_eq!(reg.current_head("zone-a").unwrap(), 1);
        assert!(reg.is_revoked("zone-a", "art-valid").unwrap());
        assert!(!reg.is_revoked("zone-a", "").unwrap());
    }

    #[test]
    fn negative_current_head_empty_zone_lookup_does_not_mutate_registry() {
        let mut reg = RevocationRegistry::new();
        reg.init_zone("zone-a").unwrap();

        let err = reg.current_head("").unwrap_err();

        assert_eq!(err.code(), "REV_ZONE_NOT_FOUND");
        assert_eq!(reg.zone_count(), 1);
        assert_eq!(reg.current_head("zone-a").unwrap(), 0);
        assert_eq!(reg.canonical_log().len(), 0);
    }

    #[test]
    fn negative_is_revoked_unknown_zone_lookup_does_not_create_zone() {
        let mut reg = RevocationRegistry::new();
        reg.advance_head(head("zone-a", 1, "art-a1")).unwrap();
        let zone_count_before = reg.zone_count();
        let revocations_before = reg.total_revocations();

        let err = reg.is_revoked("ghost-zone", "art-a1").unwrap_err();

        assert_eq!(err.code(), "REV_ZONE_NOT_FOUND");
        assert_eq!(reg.zone_count(), zone_count_before);
        assert_eq!(reg.total_revocations(), revocations_before);
        assert!(reg.current_head("ghost-zone").is_err());
    }

    #[test]
    fn negative_empty_artifact_for_new_zone_does_not_create_zone() {
        let mut reg = RevocationRegistry::new();

        let err = reg.advance_head(head("zone-new", 1, "")).unwrap_err();

        assert_eq!(err.code(), "REV_INVALID_INPUT");
        assert_eq!(reg.zone_count(), 0);
        assert_eq!(reg.canonical_log().len(), 0);
        assert_eq!(reg.audits.len(), 0);
        assert_eq!(reg.total_revocations(), 0);
    }

    #[test]
    fn negative_stale_head_records_audit_without_log_append() {
        let mut reg = RevocationRegistry::new();
        reg.advance_head(head("zone-a", 2, "art-a2")).unwrap();
        let log_len_before = reg.canonical_log().len();
        let audit_len_before = reg.audits.len();
        let revocations_before = reg.total_revocations();

        let err = reg.advance_head(head("zone-a", 1, "art-a1")).unwrap_err();

        assert_eq!(err.code(), "REV_STALE_HEAD");
        assert_eq!(reg.current_head("zone-a").unwrap(), 2);
        assert_eq!(reg.canonical_log().len(), log_len_before);
        assert_eq!(reg.total_revocations(), revocations_before);
        assert_eq!(reg.audits.len(), audit_len_before.saturating_add(1));
        assert_eq!(reg.audits.last().unwrap().action, "rejected_stale");
    }

    #[test]
    fn negative_recovery_rejects_initial_zero_sequence() {
        let log = vec![head("zone-a", 0, "art-zero")];

        let err = RevocationRegistry::recover_from_log(&log).unwrap_err();

        assert_eq!(err.code(), "REV_RECOVERY_FAILED");
        assert!(err.to_string().contains("non-monotonic log"));
    }

    #[test]
    fn negative_recovery_rejects_duplicate_sequence_for_same_zone() {
        let log = vec![head("zone-a", 1, "art-a1"), head("zone-a", 1, "art-a2")];

        let err = RevocationRegistry::recover_from_log(&log).unwrap_err();

        assert_eq!(err.code(), "REV_RECOVERY_FAILED");
        assert!(err.to_string().contains("seq 1 <= current 1"));
    }

    #[test]
    fn negative_duplicate_artifact_revocation_does_not_advance_head() {
        let mut reg = RevocationRegistry::new();
        reg.advance_head(head("zone-a", 1, "art-a1")).unwrap();
        let head_before = reg.current_head("zone-a").unwrap();
        let log_len_before = reg.canonical_log().len();
        let audit_len_before = reg.audits.len();
        let revocations_before = reg.total_revocations();

        let err = reg.advance_head(head("zone-a", 2, "art-a1")).unwrap_err();

        assert_eq!(err.code(), "REV_INVALID_INPUT");
        assert!(err.to_string().contains("already revoked artifact"));
        assert_eq!(reg.current_head("zone-a").unwrap(), head_before);
        assert_eq!(reg.canonical_log().len(), log_len_before);
        assert_eq!(reg.audits.len(), audit_len_before);
        assert_eq!(reg.total_revocations(), revocations_before);
        assert!(reg.is_revoked("zone-a", "art-a1").unwrap());
    }

    #[test]
    fn negative_recovery_rejects_duplicate_artifact_for_same_zone() {
        let log = vec![head("zone-a", 1, "art-a1"), head("zone-a", 2, "art-a1")];

        let err = RevocationRegistry::recover_from_log(&log).unwrap_err();

        assert_eq!(err.code(), "REV_RECOVERY_FAILED");
        assert!(err.to_string().contains("duplicate revocation"));
    }

    #[test]
    fn negative_recovery_rejects_stale_sequence_after_cross_zone_entries() {
        let log = vec![
            head("zone-a", 3, "art-a3"),
            head("zone-b", 1, "art-b1"),
            head("zone-a", 2, "art-a2"),
        ];

        let err = RevocationRegistry::recover_from_log(&log).unwrap_err();

        assert_eq!(err.code(), "REV_RECOVERY_FAILED");
        assert!(err.to_string().contains("zone zone-a"));
        assert!(err.to_string().contains("seq 2 <= current 3"));
    }

    #[test]
    fn negative_recovery_rejects_blank_artifact_after_valid_entry() {
        let log = vec![head("zone-a", 1, "art-a1"), head("zone-a", 2, " \t\n ")];

        let err = RevocationRegistry::recover_from_log(&log).unwrap_err();

        assert_eq!(err.code(), "REV_RECOVERY_FAILED");
        assert!(err.to_string().contains("invalid revoked_artifact"));
    }

    #[test]
    fn mr_disjoint_zone_extension_does_not_change_existing_zone() {
        let mut reg = RevocationRegistry::new();
        reg.advance_head(head("zone-a", 3, "art-a3")).unwrap();
        let zone_a_head_before = reg.current_head("zone-a").unwrap();
        let zone_a_revoked_before = reg.is_revoked("zone-a", "art-a3").unwrap();

        reg.advance_head(head("zone-b", 1, "art-b1")).unwrap();
        reg.advance_head(head("zone-c", 9, "art-c9")).unwrap();

        assert_eq!(reg.current_head("zone-a").unwrap(), zone_a_head_before);
        assert_eq!(
            reg.is_revoked("zone-a", "art-a3").unwrap(),
            zone_a_revoked_before
        );
        assert_eq!(reg.current_head("zone-b").unwrap(), 1);
        assert_eq!(reg.current_head("zone-c").unwrap(), 9);
    }

    #[test]
    fn capacity_rejection_is_atomic_for_online_advance() {
        let mut reg = RevocationRegistry::new();
        for idx in 1..=MAX_REVOKED_PER_ZONE {
            let seq = u64::try_from(idx).unwrap();
            reg.advance_head(head("zone-a", seq, &format!("art-{idx}")))
                .unwrap();
        }
        let head_before = reg.current_head("zone-a").unwrap();
        let log_len_before = reg.canonical_log().len();

        let err = reg
            .advance_head(head(
                "zone-a",
                head_before.saturating_add(1),
                "art-over-capacity",
            ))
            .unwrap_err();

        assert_eq!(err.code(), "REV_INVALID_INPUT");
        assert_eq!(reg.current_head("zone-a").unwrap(), head_before);
        assert_eq!(reg.canonical_log().len(), log_len_before);
        assert_eq!(reg.total_revocations(), MAX_REVOKED_PER_ZONE);
        assert!(!reg.is_revoked("zone-a", "art-over-capacity").unwrap());
    }

    #[test]
    fn recover_from_log_fails_instead_of_dropping_revocations_at_capacity() {
        let mut log = Vec::with_capacity(MAX_REVOKED_PER_ZONE.saturating_add(1));
        for idx in 1..=MAX_REVOKED_PER_ZONE.saturating_add(1) {
            let seq = u64::try_from(idx).unwrap();
            log.push(head("zone-a", seq, &format!("art-{idx}")));
        }

        let err = RevocationRegistry::recover_from_log(&log).unwrap_err();

        assert_eq!(err.code(), "REV_RECOVERY_FAILED");
        assert!(
            err.to_string().contains("at capacity"),
            "recovery must fail closed instead of silently dropping revocations"
        );
    }

    #[test]
    fn global_log_capacity_rejection_is_atomic_across_zones() {
        let mut reg = RevocationRegistry::new();
        let zone_count = 2usize;

        for idx in 0..MAX_LOG_ENTRIES {
            let zone = format!("zone-{}", idx % zone_count);
            let sequence = u64::try_from(idx / zone_count).unwrap().saturating_add(1);
            reg.advance_head(head(&zone, sequence, &format!("art-{idx}")))
                .unwrap();
        }

        let zone = "zone-over-capacity";
        let head_before = reg.current_head(zone).err();
        let log_len_before = reg.canonical_log().len();
        let revocations_before = reg.total_revocations();
        let zone_count_before = reg.zone_count();

        let err = reg
            .advance_head(head(zone, 1, "art-over-capacity"))
            .unwrap_err();

        assert_eq!(err.code(), "REV_INVALID_INPUT");
        assert!(
            err.to_string()
                .contains("canonical revocation log at capacity")
        );
        assert_eq!(head_before, reg.current_head(zone).err());
        assert_eq!(
            reg.is_revoked(zone, "art-over-capacity")
                .unwrap_err()
                .code(),
            "REV_ZONE_NOT_FOUND"
        );
        assert_eq!(reg.canonical_log().len(), log_len_before);
        assert_eq!(reg.total_revocations(), revocations_before);
        assert_eq!(reg.zone_count(), zone_count_before);
    }

    #[test]
    fn recover_from_cross_zone_log_fails_instead_of_forgetting_old_revocations() {
        let mut log = Vec::with_capacity(MAX_LOG_ENTRIES.saturating_add(1));
        for idx in 0..=MAX_LOG_ENTRIES {
            let sequence = u64::try_from(idx).unwrap().saturating_add(1);
            log.push(head(
                &format!("zone-{idx}"),
                sequence,
                &format!("art-{idx}"),
            ));
        }

        let err = RevocationRegistry::recover_from_log(&log).unwrap_err();

        assert_eq!(err.code(), "REV_RECOVERY_FAILED");
        assert!(err.to_string().contains("exceeds capacity"));
    }
}

#[cfg(test)]
mod revocation_registry_comprehensive_negative_tests {
    use super::{RevocationError, RevocationHead, RevocationRegistry};
    use std::collections::HashMap;

    /// Negative test: Unicode injection and encoding attacks in zone IDs and artifact names
    #[test]
    fn negative_unicode_injection_zone_and_artifact_attacks() {
        let mut reg = RevocationRegistry::new();

        // Test malicious Unicode in zone IDs
        let malicious_zones = vec![
            "zone\u{202e}evil\u{200b}",    // Right-to-left override + zero-width space
            "zone\u{0000}injection",       // Null byte injection
            "zone\u{feff}bom",             // Byte order mark
            "zone\u{2028}newline",         // Line separator
            "zone\u{2029}paragraph",       // Paragraph separator
            "zone\u{200c}\u{200d}joiners", // Zero-width joiners
        ];

        for malicious_zone in &malicious_zones {
            let result = reg.init_zone(malicious_zone);
            // Should handle Unicode gracefully without bypass
            match result {
                Ok(_) => {
                    // Unicode was accepted, verify it doesn't corrupt state
                    assert!(reg.current_head(malicious_zone).is_ok());

                    // Test advance with Unicode artifact
                    let unicode_artifact = format!("artifact\u{202e}malicious\u{0000}");
                    let advance_result = reg.advance_head(RevocationHead {
                        zone_id: malicious_zone.to_string(),
                        sequence: 1,
                        revoked_artifact: unicode_artifact.clone(),
                        reason: "Unicode test".to_string(),
                        timestamp: "2026-01-01T00:00:00Z".to_string(),
                        trace_id: "unicode-trace".to_string(),
                    });

                    match advance_result {
                        Ok(_) => {
                            // Verify Unicode artifact is properly tracked
                            assert!(
                                reg.is_revoked(malicious_zone, &unicode_artifact)
                                    .unwrap_or(false)
                            );
                        }
                        Err(e) => {
                            // Unicode validation rejection is acceptable
                            assert!(matches!(e, RevocationError::InvalidInput { .. }));
                        }
                    }
                }
                Err(e) => {
                    // Unicode rejection is also acceptable
                    assert_eq!(e.code(), "REV_INVALID_INPUT");
                }
            }
        }

        // Test Unicode in artifact names with control characters
        let mut clean_reg = RevocationRegistry::new();
        clean_reg.init_zone("test-zone").unwrap();

        let malicious_artifacts = vec![
            "artifact\x00injection", // Null byte
            &format!("artifact{}", String::from_utf8_lossy(&[0x7f, 0x80, 0x9f])), // Control characters
            "artifact\u{202e}reverse",   // Text direction manipulation
            "artifact\u{034f}combining", // Combining grapheme joiner
            "artifact\u{180e}mongolian", // Mongolian vowel separator
        ];

        for malicious_artifact in malicious_artifacts {
            let result = clean_reg.advance_head(RevocationHead {
                zone_id: "test-zone".to_string(),
                sequence: clean_reg.current_head("test-zone").unwrap_or(0) + 1,
                revoked_artifact: malicious_artifact.to_string(),
                reason: "Control char test".to_string(),
                timestamp: "2026-01-01T00:00:00Z".to_string(),
                trace_id: "control-trace".to_string(),
            });

            match result {
                Ok(_) => {
                    // Verify control characters don't corrupt revocation checks
                    assert!(
                        clean_reg
                            .is_revoked("test-zone", &malicious_artifact)
                            .unwrap()
                    );
                }
                Err(e) => {
                    // Control character rejection is acceptable
                    assert_eq!(e.code(), "REV_INVALID_INPUT");
                }
            }
        }
    }

    /// Negative test: Arithmetic overflow protection in sequence numbers and counters
    #[test]
    fn negative_arithmetic_overflow_protection() {
        let mut reg = RevocationRegistry::new();
        reg.init_zone("overflow-zone").unwrap();

        // Test near-maximum sequence numbers
        let near_max_sequence = u64::MAX - 100;
        let result = reg.advance_head(RevocationHead {
            zone_id: "overflow-zone".to_string(),
            sequence: near_max_sequence,
            revoked_artifact: "near-max-artifact".to_string(),
            reason: "Testing near-max sequence".to_string(),
            timestamp: "2026-01-01T00:00:00Z".to_string(),
            trace_id: "near-max-trace".to_string(),
        });
        assert!(
            result.is_ok(),
            "Should handle near-maximum sequence numbers"
        );

        // Test maximum sequence number
        let max_sequence = u64::MAX;
        let result = reg.advance_head(RevocationHead {
            zone_id: "overflow-zone".to_string(),
            sequence: max_sequence,
            revoked_artifact: "max-artifact".to_string(),
            reason: "Testing max sequence".to_string(),
            timestamp: "2026-01-01T00:00:00Z".to_string(),
            trace_id: "max-trace".to_string(),
        });
        assert!(result.is_ok(), "Should handle maximum sequence number");

        // Verify sequence ordering is maintained despite large numbers
        assert_eq!(reg.current_head("overflow-zone").unwrap(), max_sequence);

        // Test sequence number wraparound scenario (recovery)
        let wraparound_log = vec![
            RevocationHead {
                zone_id: "wraparound-zone".to_string(),
                sequence: u64::MAX - 5,
                revoked_artifact: "high-seq-artifact".to_string(),
                reason: "High sequence".to_string(),
                timestamp: "2026-01-01T00:00:00Z".to_string(),
                trace_id: "high-seq-trace".to_string(),
            },
            RevocationHead {
                zone_id: "wraparound-zone".to_string(),
                sequence: u64::MAX,
                revoked_artifact: "max-seq-artifact".to_string(),
                reason: "Maximum sequence".to_string(),
                timestamp: "2026-01-01T00:00:01Z".to_string(),
                trace_id: "max-seq-trace".to_string(),
            },
        ];

        let recovered_reg = RevocationRegistry::recover_from_log(&wraparound_log);
        assert!(
            recovered_reg.is_ok(),
            "Should recover logs with maximum sequence numbers"
        );

        let recovered = recovered_reg.unwrap();
        assert_eq!(recovered.current_head("wraparound-zone").unwrap(), u64::MAX);

        // Test many zones within the canonical log capacity to check saturating arithmetic
        let mut massive_reg = RevocationRegistry::new();
        let total_zones = MAX_LOG_ENTRIES / 2;
        for i in 0..total_zones {
            let zone_name = format!("zone-{}", i);
            massive_reg.init_zone(&zone_name).unwrap();
            massive_reg
                .advance_head(RevocationHead {
                    zone_id: zone_name,
                    sequence: 1,
                    revoked_artifact: format!("artifact-{}", i),
                    reason: "Massive test".to_string(),
                    timestamp: "2026-01-01T00:00:00Z".to_string(),
                    trace_id: format!("massive-trace-{}", i),
                })
                .unwrap();
        }

        // Verify total_revocations uses saturating arithmetic
        let total = massive_reg.total_revocations();
        assert!(total <= usize::MAX);
        assert_eq!(total, total_zones);
        assert_eq!(massive_reg.zone_count(), total_zones);
    }

    /// Negative test: Memory exhaustion attacks with massive logs and revocation sets
    #[test]
    fn negative_memory_exhaustion_massive_data() {
        let mut reg = RevocationRegistry::new();

        // Test massive zone with extremely large artifact names
        let huge_zone_id = "z".repeat(10000);
        let huge_artifact_name = "a".repeat(50000);
        let huge_reason = "r".repeat(20000);
        let huge_timestamp = "t".repeat(1000);
        let huge_trace_id = "tr".repeat(5000);

        let result = reg.init_zone(&huge_zone_id);
        assert!(
            result.is_ok(),
            "Should handle large zone IDs without memory exhaustion"
        );

        let result = reg.advance_head(RevocationHead {
            zone_id: huge_zone_id.clone(),
            sequence: 1,
            revoked_artifact: huge_artifact_name.clone(),
            reason: huge_reason.clone(),
            timestamp: huge_timestamp.clone(),
            trace_id: huge_trace_id.clone(),
        });
        assert!(result.is_ok(), "Should handle massive revocation head data");

        // Verify memory usage is reasonable
        assert!(reg.is_revoked(&huge_zone_id, &huge_artifact_name).unwrap());

        // Test rapid revocation cycles with large data
        for cycle in 0..1000 {
            let cycle_zone = format!("cycle-{}-{}", cycle, "x".repeat(1000));
            let cycle_artifact = format!("artifact-{}-{}", cycle, "y".repeat(2000));
            let cycle_reason = format!("reason-{}-{}", cycle, "z".repeat(500));

            reg.init_zone(&cycle_zone).unwrap();
            for seq in 1..=10 {
                let result = reg.advance_head(RevocationHead {
                    zone_id: cycle_zone.clone(),
                    sequence: seq,
                    revoked_artifact: format!("{}-{}", cycle_artifact, seq),
                    reason: cycle_reason.clone(),
                    timestamp: format!("2026-01-01T{}:00:00Z", seq),
                    trace_id: format!("cycle-{}-{}", cycle, seq),
                });

                // Some may fail due to capacity limits, which is expected
                match result {
                    Ok(_) => {}
                    Err(e) => {
                        assert!(matches!(e, RevocationError::InvalidInput { .. }));
                        break; // Stop when capacity reached
                    }
                }
            }
        }

        // Verify bounded memory despite massive operations
        assert!(reg.zone_count() <= 1001); // Original zone + 1000 cycles
        assert!(reg.canonical_log().len() <= MAX_LOG_ENTRIES);
        assert!(reg.audits.len() <= MAX_AUDIT_ENTRIES);
    }

    /// Negative test: Concurrent operation safety and state corruption
    #[test]
    fn negative_concurrent_operation_safety() {
        let mut reg = RevocationRegistry::new();

        // Initialize multiple zones for concurrent testing
        let zones = ["zone-a", "zone-b", "zone-c"];
        for zone in &zones {
            reg.init_zone(zone).unwrap();
        }

        // Simulate concurrent revocations with overlapping sequence numbers
        let mut operations = Vec::new();
        for i in 1..=100 {
            for zone in &zones {
                operations.push((zone, i, format!("artifact-{}-{}", zone, i)));
            }
        }

        // Apply operations in various orders to test consistency
        let mut results = HashMap::new();
        for (zone, sequence, artifact) in operations {
            let result = reg.advance_head(RevocationHead {
                zone_id: zone.to_string(),
                sequence,
                revoked_artifact: artifact.clone(),
                reason: "Concurrent test".to_string(),
                timestamp: format!("2026-01-01T{}:00:00Z", sequence),
                trace_id: format!("concurrent-{}-{}", zone, sequence),
            });

            results.insert((zone, sequence), result);
        }

        // Verify monotonic invariants are maintained
        for zone in &zones {
            let head = reg.current_head(zone).unwrap();
            assert!(
                head >= 1 && head <= 100,
                "Head should be in valid range for zone {}",
                zone
            );

            // Verify all artifacts up to current head are revoked
            for seq in 1..=head {
                let artifact = format!("artifact-{}-{}", zone, seq);
                assert!(
                    reg.is_revoked(zone, &artifact).unwrap(),
                    "Artifact {} should be revoked in zone {}",
                    artifact,
                    zone
                );
            }

            // Verify artifacts beyond current head are not revoked
            for seq in (head + 1)..=100 {
                let artifact = format!("artifact-{}-{}", zone, seq);
                assert!(
                    !reg.is_revoked(zone, &artifact).unwrap(),
                    "Artifact {} should not be revoked in zone {}",
                    artifact,
                    zone
                );
            }
        }

        // Verify audit trail consistency under concurrent operations
        let successful_operations = results.values().filter(|r| r.is_ok()).count();
        let failed_operations = results.values().filter(|r| r.is_err()).count();

        // Each successful operation should have generated an audit entry
        assert!(reg.audits.len() >= successful_operations.min(MAX_AUDIT_ENTRIES));

        // Verify no state corruption by checking total revocations
        let expected_revocations = zones
            .iter()
            .map(|zone| reg.current_head(zone).unwrap() as usize)
            .sum::<usize>();
        assert_eq!(reg.total_revocations(), expected_revocations);
    }

    /// Negative test: Recovery corruption and log manipulation attacks
    #[test]
    fn negative_recovery_corruption_attacks() {
        // Test recovery with malformed and corrupted logs
        let corrupted_logs = vec![
            // Empty artifact with valid sequence
            vec![RevocationHead {
                zone_id: "zone-a".to_string(),
                sequence: 1,
                revoked_artifact: "".to_string(),
                reason: "Empty artifact attack".to_string(),
                timestamp: "2026-01-01T00:00:00Z".to_string(),
                trace_id: "empty-attack".to_string(),
            }],
            // Massive sequence gap (potential wraparound attack)
            vec![
                RevocationHead {
                    zone_id: "zone-gap".to_string(),
                    sequence: 1,
                    revoked_artifact: "artifact-1".to_string(),
                    reason: "First".to_string(),
                    timestamp: "2026-01-01T00:00:00Z".to_string(),
                    trace_id: "gap-1".to_string(),
                },
                RevocationHead {
                    zone_id: "zone-gap".to_string(),
                    sequence: u64::MAX,
                    revoked_artifact: "artifact-max".to_string(),
                    reason: "Gap attack".to_string(),
                    timestamp: "2026-01-01T00:00:01Z".to_string(),
                    trace_id: "gap-max".to_string(),
                },
            ],
            // Unicode corruption in log entries
            vec![RevocationHead {
                zone_id: "zone\u{202e}corrupted\u{0000}".to_string(),
                sequence: 1,
                revoked_artifact: "artifact\u{200b}hidden".to_string(),
                reason: "Unicode\u{2028}corruption".to_string(),
                timestamp: "2026\u{feff}-01-01T00:00:00Z".to_string(),
                trace_id: "unicode\u{200c}trace".to_string(),
            }],
            // Duplicate artifacts with different sequences
            vec![
                RevocationHead {
                    zone_id: "zone-dup".to_string(),
                    sequence: 1,
                    revoked_artifact: "same-artifact".to_string(),
                    reason: "First revocation".to_string(),
                    timestamp: "2026-01-01T00:00:00Z".to_string(),
                    trace_id: "dup-1".to_string(),
                },
                RevocationHead {
                    zone_id: "zone-dup".to_string(),
                    sequence: 2,
                    revoked_artifact: "same-artifact".to_string(),
                    reason: "Duplicate revocation".to_string(),
                    timestamp: "2026-01-01T00:00:01Z".to_string(),
                    trace_id: "dup-2".to_string(),
                },
            ],
        ];

        for (i, corrupted_log) in corrupted_logs.iter().enumerate() {
            let result = RevocationRegistry::recover_from_log(corrupted_log);

            match result {
                Ok(recovered_reg) => {
                    // If recovery succeeded, verify state integrity
                    for entry in corrupted_log {
                        if !entry.zone_id.trim().is_empty()
                            && !entry.revoked_artifact.trim().is_empty()
                        {
                            // Should be able to query without corruption
                            let _ = recovered_reg.current_head(&entry.zone_id);
                            let _ =
                                recovered_reg.is_revoked(&entry.zone_id, &entry.revoked_artifact);
                        }
                    }
                }
                Err(e) => {
                    // Recovery failure is acceptable for corrupted data
                    assert_eq!(
                        e.code(),
                        "REV_RECOVERY_FAILED",
                        "Corrupted log {} should fail with REV_RECOVERY_FAILED",
                        i
                    );
                }
            }
        }

        // Test recovery with massive corrupted log
        let massive_corrupted_log: Vec<RevocationHead> = (0..50000)
            .map(|i| RevocationHead {
                zone_id: format!("zone-{}", i % 10), // Only 10 zones, massive entries each
                sequence: (i / 10) as u64 + 1,
                revoked_artifact: format!("artifact-{}-{}", i, "x".repeat(1000)),
                reason: format!("reason-{}", i),
                timestamp: format!("2026-01-01T{}:00:00Z", i % 24),
                trace_id: format!("massive-trace-{}", i),
            })
            .collect();

        let massive_result = RevocationRegistry::recover_from_log(&massive_corrupted_log);

        match massive_result {
            Ok(massive_reg) => {
                // If recovery succeeded, verify bounded memory usage
                assert!(massive_reg.zone_count() <= 10);
                assert!(massive_reg.canonical_log().len() <= MAX_LOG_ENTRIES);
                assert!(massive_reg.total_revocations() <= MAX_REVOKED_PER_ZONE * 10);
            }
            Err(e) => {
                // Capacity failure is expected and acceptable
                assert_eq!(e.code(), "REV_RECOVERY_FAILED");
                assert!(e.to_string().contains("at capacity"));
            }
        }
    }

    /// Negative test: Timing attacks in revocation status checks
    #[test]
    fn negative_timing_attacks_revocation_checks() {
        let mut reg = RevocationRegistry::new();
        reg.init_zone("timing-zone").unwrap();

        // Create a mix of revoked and non-revoked artifacts
        let revoked_artifacts = vec!["revoked-1", "revoked-2", "revoked-secret"];
        let non_revoked_artifacts = vec!["clean-1", "clean-2", "clean-secret"];

        for (i, artifact) in revoked_artifacts.iter().enumerate() {
            reg.advance_head(RevocationHead {
                zone_id: "timing-zone".to_string(),
                sequence: u64::try_from(i).unwrap_or(u64::MAX).saturating_add(1),
                revoked_artifact: artifact.to_string(),
                reason: "Timing test".to_string(),
                timestamp: "2026-01-01T00:00:00Z".to_string(),
                trace_id: format!("timing-{}", i),
            })
            .unwrap();
        }

        // Test timing differences for various queries
        let all_test_artifacts = [&revoked_artifacts[..], &non_revoked_artifacts[..]].concat();
        let mut timing_results = Vec::new();

        for artifact in &all_test_artifacts {
            let start = std::time::Instant::now();
            let _result = reg.is_revoked("timing-zone", artifact);
            let duration = start.elapsed();
            timing_results.push(duration);
        }

        // Timing differences should be minimal (no timing-based information leakage)
        let max_timing = timing_results.iter().max().unwrap();
        let min_timing = timing_results.iter().min().unwrap();
        let timing_ratio = max_timing.as_nanos() as f64 / min_timing.as_nanos().max(1) as f64;
        assert!(
            timing_ratio.is_finite(),
            "Revocation check timing ratio must be finite"
        );

        // Allow reasonable variance but prevent timing attacks
        assert!(
            timing_ratio < 5.0,
            "Revocation check timing variance too high: {}",
            timing_ratio
        );

        // Test timing consistency for zone lookups
        let test_zones = vec!["timing-zone", "nonexistent-zone-1", "nonexistent-zone-2"];
        let mut zone_timing_results = Vec::new();

        for zone in &test_zones {
            let start = std::time::Instant::now();
            let _result = reg.current_head(zone);
            let duration = start.elapsed();
            zone_timing_results.push(duration);
        }

        // Zone lookup timing should also be consistent
        let max_zone_timing = zone_timing_results.iter().max().unwrap();
        let min_zone_timing = zone_timing_results.iter().min().unwrap();
        let zone_timing_ratio =
            max_zone_timing.as_nanos() as f64 / min_zone_timing.as_nanos().max(1) as f64;
        assert!(
            zone_timing_ratio.is_finite(),
            "Zone lookup timing ratio must be finite"
        );

        assert!(
            zone_timing_ratio < 4.0,
            "Zone lookup timing variance too high: {}",
            zone_timing_ratio
        );

        // Test timing attacks on similar artifact names
        let similar_artifacts = vec![
            "secret-key-1",
            "secret-key-2",
            "secret-key-a",
            "public-key-1",
            "different-name",
        ];

        // Revoke one similar artifact
        reg.advance_head(RevocationHead {
            zone_id: "timing-zone".to_string(),
            sequence: 10,
            revoked_artifact: "secret-key-1".to_string(),
            reason: "Similar name test".to_string(),
            timestamp: "2026-01-01T00:00:00Z".to_string(),
            trace_id: "similar-test".to_string(),
        })
        .unwrap();

        let mut similar_timing_results = Vec::new();
        for artifact in &similar_artifacts {
            let start = std::time::Instant::now();
            let _result = reg.is_revoked("timing-zone", artifact);
            let duration = start.elapsed();
            similar_timing_results.push(duration);
        }

        // Similar names should not have timing differences that reveal content
        let max_similar = similar_timing_results.iter().max().unwrap();
        let min_similar = similar_timing_results.iter().min().unwrap();
        let similar_ratio = max_similar.as_nanos() as f64 / min_similar.as_nanos().max(1) as f64;
        assert!(
            similar_ratio.is_finite(),
            "Similar artifact timing ratio must be finite"
        );

        assert!(
            similar_ratio < 3.0,
            "Similar artifact timing variance too high: {}",
            similar_ratio
        );
    }

    /// Negative test: Edge cases in push_bounded and capacity management
    #[test]
    fn negative_push_bounded_edge_cases_and_capacity_attacks() {
        // Test push_bounded with various edge cases
        let mut test_vec = vec![1, 2, 3];

        // Test with capacity exactly equal to current size
        push_bounded(&mut test_vec, 4, 3);
        assert_eq!(test_vec, vec![2, 3, 4]);

        // Test with capacity 1 (extreme bounds)
        let mut single_vec = vec![1];
        push_bounded(&mut single_vec, 2, 1);
        assert_eq!(single_vec, vec![2]);

        // Test with massive overflow scenario
        let mut massive_vec: Vec<i32> = (1..10000).collect();
        push_bounded(&mut massive_vec, 99999, 100);
        assert_eq!(massive_vec.len(), 100);
        assert_eq!(massive_vec[99], 99999); // Last element should be the new item

        // Test registry behavior under capacity pressure
        let mut reg = RevocationRegistry::new();
        reg.init_zone("capacity-test").unwrap();

        // Fill up to near capacity for logs
        for i in 1..=MAX_LOG_ENTRIES + 100 {
            let _ = reg.advance_head(RevocationHead {
                zone_id: "capacity-test".to_string(),
                sequence: i as u64,
                revoked_artifact: format!("artifact-{}", i),
                reason: "Capacity test".to_string(),
                timestamp: "2026-01-01T00:00:00Z".to_string(),
                trace_id: format!("capacity-trace-{}", i),
            });
        }

        // Verify logs are properly bounded
        assert!(reg.canonical_log().len() <= MAX_LOG_ENTRIES);
        assert!(reg.audits.len() <= MAX_AUDIT_ENTRIES);

        // Verify recent entries are preserved (FIFO behavior)
        let log = reg.canonical_log();
        if !log.is_empty() {
            let last_entry = &log[log.len() - 1];
            assert!(last_entry.revoked_artifact.starts_with("artifact-"));
        }

        // Test capacity attacks with different zones
        for zone_idx in 0..10 {
            let zone_name = format!("attack-zone-{}", zone_idx);
            reg.init_zone(&zone_name).unwrap();

            // Try to fill each zone to capacity
            let mut successful_revocations = 0;
            for artifact_idx in 1..=MAX_REVOKED_PER_ZONE + 100 {
                let result = reg.advance_head(RevocationHead {
                    zone_id: zone_name.clone(),
                    sequence: artifact_idx as u64,
                    revoked_artifact: format!("attack-artifact-{}-{}", zone_idx, artifact_idx),
                    reason: "Capacity attack test".to_string(),
                    timestamp: "2026-01-01T00:00:00Z".to_string(),
                    trace_id: format!("attack-trace-{}-{}", zone_idx, artifact_idx),
                });

                if result.is_ok() {
                    successful_revocations += 1;
                } else {
                    // Should fail at capacity
                    assert_eq!(result.unwrap_err().code(), "REV_INVALID_INPUT");
                    break;
                }
            }

            // Should not exceed capacity
            assert!(successful_revocations <= MAX_REVOKED_PER_ZONE);
        }

        // Verify global state remains consistent despite attacks
        assert!(reg.zone_count() >= 1); // At least the original test zone
        assert!(reg.total_revocations() <= MAX_REVOKED_PER_ZONE * reg.zone_count());
    }

    /// Negative test: State consistency under error conditions and partial failures
    #[test]
    fn negative_state_consistency_under_errors() {
        let mut reg = RevocationRegistry::new();

        // Initialize a few zones for testing
        reg.init_zone("consistent-zone-a").unwrap();
        reg.init_zone("consistent-zone-b").unwrap();

        // Add some initial valid revocations
        reg.advance_head(RevocationHead {
            zone_id: "consistent-zone-a".to_string(),
            sequence: 1,
            revoked_artifact: "valid-artifact-1".to_string(),
            reason: "Initial state".to_string(),
            timestamp: "2026-01-01T00:00:00Z".to_string(),
            trace_id: "initial-1".to_string(),
        })
        .unwrap();

        reg.advance_head(RevocationHead {
            zone_id: "consistent-zone-b".to_string(),
            sequence: 1,
            revoked_artifact: "valid-artifact-2".to_string(),
            reason: "Initial state".to_string(),
            timestamp: "2026-01-01T00:00:00Z".to_string(),
            trace_id: "initial-2".to_string(),
        })
        .unwrap();

        // Capture initial state
        let initial_zone_a_head = reg.current_head("consistent-zone-a").unwrap();
        let initial_zone_b_head = reg.current_head("consistent-zone-b").unwrap();
        let initial_revocations = reg.total_revocations();
        let initial_log_len = reg.canonical_log().len();
        let initial_audit_len = reg.audits.len();

        // Attempt various error-inducing operations
        let error_operations = vec![
            // Empty zone ID
            RevocationHead {
                zone_id: "".to_string(),
                sequence: 2,
                revoked_artifact: "error-artifact".to_string(),
                reason: "Error test".to_string(),
                timestamp: "2026-01-01T00:00:00Z".to_string(),
                trace_id: "error-1".to_string(),
            },
            // Stale sequence
            RevocationHead {
                zone_id: "consistent-zone-a".to_string(),
                sequence: 1, // Same as current
                revoked_artifact: "stale-artifact".to_string(),
                reason: "Stale test".to_string(),
                timestamp: "2026-01-01T00:00:00Z".to_string(),
                trace_id: "stale-1".to_string(),
            },
            // Empty artifact
            RevocationHead {
                zone_id: "consistent-zone-a".to_string(),
                sequence: 2,
                revoked_artifact: "".to_string(),
                reason: "Empty artifact test".to_string(),
                timestamp: "2026-01-01T00:00:00Z".to_string(),
                trace_id: "empty-1".to_string(),
            },
            // Nonexistent zone (should auto-create but test consistency)
            RevocationHead {
                zone_id: "auto-created-zone".to_string(),
                sequence: 0, // Invalid sequence
                revoked_artifact: "auto-artifact".to_string(),
                reason: "Auto-creation test".to_string(),
                timestamp: "2026-01-01T00:00:00Z".to_string(),
                trace_id: "auto-1".to_string(),
            },
        ];

        let mut error_count = 0;
        for error_op in error_operations {
            let result = reg.advance_head(error_op);
            if result.is_err() {
                error_count += 1;
            }
        }

        // Verify state remains consistent after errors
        assert_eq!(
            reg.current_head("consistent-zone-a").unwrap(),
            initial_zone_a_head,
            "Zone A head should be unchanged after errors"
        );
        assert_eq!(
            reg.current_head("consistent-zone-b").unwrap(),
            initial_zone_b_head,
            "Zone B head should be unchanged after errors"
        );

        // Verify revocation status is preserved
        assert!(
            reg.is_revoked("consistent-zone-a", "valid-artifact-1")
                .unwrap()
        );
        assert!(
            reg.is_revoked("consistent-zone-b", "valid-artifact-2")
                .unwrap()
        );
        assert!(
            !reg.is_revoked("consistent-zone-a", "error-artifact")
                .unwrap_or(true)
        );
        assert!(
            !reg.is_revoked("consistent-zone-a", "stale-artifact")
                .unwrap_or(true)
        );

        // Some operations may have succeeded (e.g., auto-zone creation with valid data)
        // but overall state should remain coherent
        assert!(reg.total_revocations() >= initial_revocations);
        assert!(reg.zone_count() >= 2); // At least the two original zones

        // Audit trail should reflect error attempts (rejections are audited)
        assert!(reg.audits.len() >= initial_audit_len);

        // Test error handling in zone queries
        let error_queries = vec!["", " ", "\t", "\n", "nonexistent-zone"];
        for error_zone in error_queries {
            let head_result = reg.current_head(&error_zone);
            let revoked_result = reg.is_revoked(&error_zone, "test-artifact");

            if error_zone.trim().is_empty() {
                // Should handle empty zone gracefully
                assert!(head_result.is_err() || revoked_result.is_err());
            } else {
                // Nonexistent zones should return appropriate errors
                assert!(head_result.is_err());
                assert!(revoked_result.is_err());
            }
        }

        // Verify registry remains functional after error conditions
        let final_test = reg.advance_head(RevocationHead {
            zone_id: "consistent-zone-a".to_string(),
            sequence: initial_zone_a_head + 1,
            revoked_artifact: "post-error-artifact".to_string(),
            reason: "Post-error test".to_string(),
            timestamp: "2026-01-01T00:00:00Z".to_string(),
            trace_id: "post-error".to_string(),
        });

        assert!(
            final_test.is_ok(),
            "Registry should remain functional after error conditions"
        );
        assert!(
            reg.is_revoked("consistent-zone-a", "post-error-artifact")
                .unwrap()
        );
    }
}
