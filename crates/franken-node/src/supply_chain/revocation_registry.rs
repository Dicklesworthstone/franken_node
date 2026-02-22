//! bd-y7lu: Revocation registry with monotonic revocation-head checkpoints.
//!
//! Tracks revoked artifacts per zone/tenant. Revocation heads are strictly
//! monotonic: stale updates are rejected. State is recoverable from the
//! canonical revocation log.

use std::collections::BTreeMap;

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
}

impl RevocationError {
    pub fn code(&self) -> &'static str {
        match self {
            Self::StaleHead { .. } => "REV_STALE_HEAD",
            Self::ZoneNotFound { .. } => "REV_ZONE_NOT_FOUND",
            Self::RecoveryFailed { .. } => "REV_RECOVERY_FAILED",
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
    /// Set of revoked artifacts per zone.
    revoked: BTreeMap<String, Vec<String>>,
    /// Audit trail.
    pub audits: Vec<RevocationAudit>,
}

impl RevocationRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    /// Initialize a zone with head at sequence 0.
    pub fn init_zone(&mut self, zone_id: &str) {
        self.heads.entry(zone_id.to_string()).or_insert(0);
        self.revoked.entry(zone_id.to_string()).or_default();
    }

    /// Get the current head sequence for a zone.
    pub fn current_head(&self, zone_id: &str) -> Result<u64, RevocationError> {
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
        let current = self.heads.get(&head.zone_id).copied().unwrap_or(0);

        // INV-REV-MONOTONIC + INV-REV-STALE-REJECT
        if head.sequence <= current {
            self.audits.push(RevocationAudit {
                zone_id: head.zone_id.clone(),
                action: "rejected_stale".into(),
                sequence: head.sequence,
                trace_id: head.trace_id.clone(),
                timestamp: head.timestamp.clone(),
            });
            return Err(RevocationError::StaleHead {
                zone_id: head.zone_id,
                offered: head.sequence,
                current,
            });
        }

        // Advance the head
        self.heads.insert(head.zone_id.clone(), head.sequence);
        self.revoked
            .entry(head.zone_id.clone())
            .or_default()
            .push(head.revoked_artifact.clone());

        self.audits.push(RevocationAudit {
            zone_id: head.zone_id.clone(),
            action: "advanced".into(),
            sequence: head.sequence,
            trace_id: head.trace_id.clone(),
            timestamp: head.timestamp.clone(),
        });

        // Append to canonical log for recovery
        self.log.push(head.clone());

        Ok(head.sequence)
    }

    /// Check if an artifact is revoked in a given zone.
    pub fn is_revoked(&self, zone_id: &str, artifact: &str) -> Result<bool, RevocationError> {
        let entries = self
            .revoked
            .get(zone_id)
            .ok_or_else(|| RevocationError::ZoneNotFound {
                zone_id: zone_id.to_string(),
            })?;
        Ok(entries.iter().any(|a| a == artifact))
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

        let mut registry = Self::new();

        for entry in log {
            // During recovery, initialize zone if needed
            registry.init_zone(&entry.zone_id);
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
            registry
                .revoked
                .entry(entry.zone_id.clone())
                .or_default()
                .push(entry.revoked_artifact.clone());
            registry.log.push(entry.clone());
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
        self.revoked.values().map(|v| v.len()).sum()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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

    #[test]
    fn advance_head_succeeds() {
        let mut reg = RevocationRegistry::new();
        reg.init_zone("zone-a");
        let result = reg.advance_head(head("zone-a", 1, "art-1"));
        assert_eq!(result.unwrap(), 1);
        assert_eq!(reg.current_head("zone-a").unwrap(), 1);
    }

    #[test]
    fn monotonic_advance() {
        let mut reg = RevocationRegistry::new();
        reg.init_zone("zone-a");
        reg.advance_head(head("zone-a", 1, "art-1")).unwrap();
        reg.advance_head(head("zone-a", 2, "art-2")).unwrap();
        reg.advance_head(head("zone-a", 5, "art-3")).unwrap();
        assert_eq!(reg.current_head("zone-a").unwrap(), 5);
    }

    #[test]
    fn stale_head_rejected() {
        let mut reg = RevocationRegistry::new();
        reg.init_zone("zone-a");
        reg.advance_head(head("zone-a", 3, "art-1")).unwrap();
        let result = reg.advance_head(head("zone-a", 2, "art-2"));
        let err = result.unwrap_err();
        assert_eq!(err.code(), "REV_STALE_HEAD");
    }

    #[test]
    fn equal_sequence_rejected() {
        let mut reg = RevocationRegistry::new();
        reg.init_zone("zone-a");
        reg.advance_head(head("zone-a", 3, "art-1")).unwrap();
        let result = reg.advance_head(head("zone-a", 3, "art-2"));
        assert_eq!(result.unwrap_err().code(), "REV_STALE_HEAD");
    }

    #[test]
    fn zone_isolation() {
        let mut reg = RevocationRegistry::new();
        reg.init_zone("zone-a");
        reg.init_zone("zone-b");
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
        reg.init_zone("zone-a");
        reg.advance_head(head("zone-a", 1, "art-bad")).unwrap();
        assert!(reg.is_revoked("zone-a", "art-bad").unwrap());
    }

    #[test]
    fn is_revoked_false() {
        let mut reg = RevocationRegistry::new();
        reg.init_zone("zone-a");
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
        reg.init_zone("zone-a");
        reg.advance_head(head("zone-a", 1, "art-1")).unwrap();
        reg.advance_head(head("zone-a", 2, "art-2")).unwrap();
        assert_eq!(reg.canonical_log().len(), 2);
    }

    #[test]
    fn audit_trail_on_advance() {
        let mut reg = RevocationRegistry::new();
        reg.init_zone("zone-a");
        reg.advance_head(head("zone-a", 1, "art-1")).unwrap();
        assert_eq!(reg.audits.len(), 1);
        assert_eq!(reg.audits[0].action, "advanced");
    }

    #[test]
    fn audit_trail_on_stale_reject() {
        let mut reg = RevocationRegistry::new();
        reg.init_zone("zone-a");
        reg.advance_head(head("zone-a", 2, "art-1")).unwrap();
        let _ = reg.advance_head(head("zone-a", 1, "art-2"));
        assert_eq!(reg.audits.len(), 2);
        assert_eq!(reg.audits[1].action, "rejected_stale");
    }

    #[test]
    fn zone_count() {
        let mut reg = RevocationRegistry::new();
        reg.init_zone("a");
        reg.init_zone("b");
        assert_eq!(reg.zone_count(), 2);
    }

    #[test]
    fn total_revocations() {
        let mut reg = RevocationRegistry::new();
        reg.init_zone("zone-a");
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
}
