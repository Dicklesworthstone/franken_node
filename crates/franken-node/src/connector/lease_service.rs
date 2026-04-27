//! bd-bq6y: Generic lease service for operation execution, state writes,
//! and migration handoff.
//!
//! Leases have deterministic expiry and renewal. Stale lease usage is rejected.

use std::collections::BTreeMap;

/// Maximum number of lease decisions before oldest-first eviction.
const MAX_DECISIONS: usize = 4096;

use crate::capacity_defaults::aliases::MAX_LEASES;

/// Purpose for which a lease is held.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum LeasePurpose {
    Operation,
    StateWrite,
    MigrationHandoff,
}

impl std::fmt::Display for LeasePurpose {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Operation => write!(f, "Operation"),
            Self::StateWrite => write!(f, "StateWrite"),
            Self::MigrationHandoff => write!(f, "MigrationHandoff"),
        }
    }
}

/// A lease granting time-limited access for a specific purpose.
#[derive(Debug, Clone)]
pub struct Lease {
    pub lease_id: String,
    pub holder: String,
    pub purpose: LeasePurpose,
    pub ttl_secs: u64,
    pub granted_at: u64,
    pub renewed_at: u64,
    pub revoked: bool,
}

impl Lease {
    fn expires_at(&self) -> Option<u64> {
        self.renewed_at.checked_add(self.ttl_secs)
    }

    /// Check if the lease is expired at time `now`.
    pub fn is_expired(&self, now: u64) -> bool {
        match self.expires_at() {
            Some(expires_at) => now >= expires_at,
            None => true, // fail closed when expiry arithmetic overflows
        }
    }

    /// Check if the lease is active (not expired and not revoked).
    pub fn is_active(&self, now: u64) -> bool {
        !self.revoked && !self.is_expired(now)
    }

    /// Remaining seconds until expiry (0 if already expired).
    pub fn remaining(&self, now: u64) -> u64 {
        match self.expires_at() {
            Some(expires_at) => expires_at.saturating_sub(now),
            None => 0,
        }
    }
}

/// Audit record for lease operations.
#[derive(Debug, Clone)]
pub struct LeaseDecision {
    pub lease_id: String,
    pub action: String,
    pub allowed: bool,
    pub reason: String,
    pub trace_id: String,
    pub timestamp: String,
}

/// Errors from lease operations.
///
/// Error codes: `LS_EXPIRED`, `LS_STALE_USE`, `LS_ALREADY_REVOKED`,
/// `LS_PURPOSE_MISMATCH`, `LS_NOT_FOUND`, `LS_CAPACITY_EXCEEDED`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LeaseError {
    Expired {
        lease_id: String,
    },
    StaleUse {
        lease_id: String,
    },
    AlreadyRevoked {
        lease_id: String,
    },
    PurposeMismatch {
        lease_id: String,
        expected: String,
        actual: String,
    },
    NotFound {
        lease_id: String,
    },
    CapacityExceeded {
        capacity: usize,
    },
}

impl LeaseError {
    pub fn code(&self) -> &'static str {
        match self {
            Self::Expired { .. } => "LS_EXPIRED",
            Self::StaleUse { .. } => "LS_STALE_USE",
            Self::AlreadyRevoked { .. } => "LS_ALREADY_REVOKED",
            Self::PurposeMismatch { .. } => "LS_PURPOSE_MISMATCH",
            Self::NotFound { .. } => "LS_NOT_FOUND",
            Self::CapacityExceeded { .. } => "LS_CAPACITY_EXCEEDED",
        }
    }
}

impl std::fmt::Display for LeaseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Expired { lease_id } => write!(f, "LS_EXPIRED: {lease_id}"),
            Self::StaleUse { lease_id } => write!(f, "LS_STALE_USE: {lease_id}"),
            Self::AlreadyRevoked { lease_id } => write!(f, "LS_ALREADY_REVOKED: {lease_id}"),
            Self::PurposeMismatch {
                lease_id,
                expected,
                actual,
            } => {
                write!(
                    f,
                    "LS_PURPOSE_MISMATCH: {lease_id} expected {expected}, got {actual}"
                )
            }
            Self::NotFound { lease_id } => write!(f, "LS_NOT_FOUND: {lease_id}"),
            Self::CapacityExceeded { capacity } => {
                write!(f, "LS_CAPACITY_EXCEEDED: registry at capacity {capacity}")
            }
        }
    }
}

/// Generic lease service.
pub struct LeaseService {
    leases: BTreeMap<String, Lease>,
    pub decisions: Vec<LeaseDecision>,
    next_id: u64,
}

impl Default for LeaseService {
    fn default() -> Self {
        Self {
            leases: BTreeMap::new(),
            decisions: Vec::new(),
            next_id: 1,
        }
    }
}

impl LeaseService {
    pub fn new() -> Self {
        Self::default()
    }

    /// Grant a new lease.
    pub fn grant(
        &mut self,
        holder: &str,
        purpose: LeasePurpose,
        ttl_secs: u64,
        now: u64,
        trace_id: &str,
        timestamp: &str,
    ) -> Result<Lease, LeaseError> {
        self.sweep_inactive(now);
        if self.leases.len() >= MAX_LEASES {
            let denied_lease_id = format!("lease-{}", self.next_id);
            push_bounded(
                &mut self.decisions,
                LeaseDecision {
                    lease_id: denied_lease_id,
                    action: "grant".into(),
                    allowed: false,
                    reason: format!("lease capacity exceeded ({MAX_LEASES})"),
                    trace_id: trace_id.to_string(),
                    timestamp: timestamp.to_string(),
                },
                MAX_DECISIONS,
            );
            return Err(LeaseError::CapacityExceeded {
                capacity: MAX_LEASES,
            });
        }

        if self.next_id == u64::MAX {
            return Err(LeaseError::CapacityExceeded {
                capacity: usize::try_from(u64::MAX).unwrap_or(usize::MAX),
            });
        }

        let lease_id = format!("lease-{}", self.next_id);
        self.next_id = self.next_id.saturating_add(1);

        let lease = Lease {
            lease_id: lease_id.clone(),
            holder: holder.to_string(),
            purpose,
            ttl_secs,
            granted_at: now,
            renewed_at: now,
            revoked: false,
        };

        self.leases.insert(lease_id.clone(), lease.clone());
        push_bounded(
            &mut self.decisions,
            LeaseDecision {
                lease_id: lease_id.clone(),
                action: "grant".into(),
                allowed: true,
                reason: format!("granted {purpose} lease to {holder}"),
                trace_id: trace_id.to_string(),
                timestamp: timestamp.to_string(),
            },
            MAX_DECISIONS,
        );

        Ok(lease)
    }

    /// Renew a lease, extending its TTL from `now`.
    ///
    /// INV-LS-RENEWAL: only active leases can be renewed.
    pub fn renew(
        &mut self,
        lease_id: &str,
        now: u64,
        trace_id: &str,
        timestamp: &str,
    ) -> Result<Lease, LeaseError> {
        let lease = self
            .leases
            .get(lease_id)
            .ok_or_else(|| LeaseError::NotFound {
                lease_id: lease_id.to_string(),
            })?;

        if lease.revoked {
            push_bounded(
                &mut self.decisions,
                LeaseDecision {
                    lease_id: lease_id.to_string(),
                    action: "renew".into(),
                    allowed: false,
                    reason: "lease revoked".into(),
                    trace_id: trace_id.to_string(),
                    timestamp: timestamp.to_string(),
                },
                MAX_DECISIONS,
            );
            return Err(LeaseError::AlreadyRevoked {
                lease_id: lease_id.to_string(),
            });
        }

        if lease.is_expired(now) {
            push_bounded(
                &mut self.decisions,
                LeaseDecision {
                    lease_id: lease_id.to_string(),
                    action: "renew".into(),
                    allowed: false,
                    reason: "lease expired".into(),
                    trace_id: trace_id.to_string(),
                    timestamp: timestamp.to_string(),
                },
                MAX_DECISIONS,
            );
            return Err(LeaseError::Expired {
                lease_id: lease_id.to_string(),
            });
        }

        let lease = self
            .leases
            .get_mut(lease_id)
            .ok_or_else(|| LeaseError::NotFound {
                lease_id: lease_id.to_string(),
            })?;
        lease.renewed_at = now;

        push_bounded(
            &mut self.decisions,
            LeaseDecision {
                lease_id: lease_id.to_string(),
                action: "renew".into(),
                allowed: true,
                reason: "renewed".into(),
                trace_id: trace_id.to_string(),
                timestamp: timestamp.to_string(),
            },
            MAX_DECISIONS,
        );

        Ok(lease.clone())
    }

    /// Use a lease for an operation. Validates active + correct purpose.
    ///
    /// INV-LS-STALE-REJECT: expired/revoked leases rejected.
    /// INV-LS-PURPOSE: purpose must match.
    pub fn use_lease(
        &mut self,
        lease_id: &str,
        required_purpose: LeasePurpose,
        now: u64,
        trace_id: &str,
        timestamp: &str,
    ) -> Result<LeaseDecision, LeaseError> {
        let lease = self
            .leases
            .get(lease_id)
            .ok_or_else(|| LeaseError::StaleUse {
                lease_id: lease_id.to_string(),
            })?;

        if lease.revoked {
            let d = LeaseDecision {
                lease_id: lease_id.to_string(),
                action: "use".into(),
                allowed: false,
                reason: "lease revoked".into(),
                trace_id: trace_id.to_string(),
                timestamp: timestamp.to_string(),
            };
            push_bounded(&mut self.decisions, d.clone(), MAX_DECISIONS);
            return Err(LeaseError::StaleUse {
                lease_id: lease_id.to_string(),
            });
        }

        if lease.is_expired(now) {
            let d = LeaseDecision {
                lease_id: lease_id.to_string(),
                action: "use".into(),
                allowed: false,
                reason: "lease expired".into(),
                trace_id: trace_id.to_string(),
                timestamp: timestamp.to_string(),
            };
            push_bounded(&mut self.decisions, d.clone(), MAX_DECISIONS);
            return Err(LeaseError::StaleUse {
                lease_id: lease_id.to_string(),
            });
        }

        // INV-LS-PURPOSE
        if lease.purpose != required_purpose {
            let d = LeaseDecision {
                lease_id: lease_id.to_string(),
                action: "use".into(),
                allowed: false,
                reason: format!(
                    "purpose mismatch: expected {required_purpose}, got {}",
                    lease.purpose
                ),
                trace_id: trace_id.to_string(),
                timestamp: timestamp.to_string(),
            };
            push_bounded(&mut self.decisions, d.clone(), MAX_DECISIONS);
            return Err(LeaseError::PurposeMismatch {
                lease_id: lease_id.to_string(),
                expected: required_purpose.to_string(),
                actual: lease.purpose.to_string(),
            });
        }

        let d = LeaseDecision {
            lease_id: lease_id.to_string(),
            action: "use".into(),
            allowed: true,
            reason: "lease valid".into(),
            trace_id: trace_id.to_string(),
            timestamp: timestamp.to_string(),
        };
        push_bounded(&mut self.decisions, d.clone(), MAX_DECISIONS);
        Ok(d)
    }

    /// Revoke a lease.
    pub fn revoke(
        &mut self,
        lease_id: &str,
        trace_id: &str,
        timestamp: &str,
    ) -> Result<(), LeaseError> {
        let lease = self
            .leases
            .get_mut(lease_id)
            .ok_or_else(|| LeaseError::NotFound {
                lease_id: lease_id.to_string(),
            })?;

        if lease.revoked {
            return Err(LeaseError::AlreadyRevoked {
                lease_id: lease_id.to_string(),
            });
        }

        lease.revoked = true;
        push_bounded(
            &mut self.decisions,
            LeaseDecision {
                lease_id: lease_id.to_string(),
                action: "revoke".into(),
                allowed: true,
                reason: "revoked".into(),
                trace_id: trace_id.to_string(),
                timestamp: timestamp.to_string(),
            },
            MAX_DECISIONS,
        );

        Ok(())
    }

    /// Get a lease by ID (read-only).
    pub fn get(&self, lease_id: &str) -> Option<&Lease> {
        self.leases.get(lease_id)
    }

    /// Total active leases at time `now`.
    pub fn active_count(&self, now: u64) -> usize {
        self.leases.values().filter(|l| l.is_active(now)).count()
    }

    fn sweep_inactive(&mut self, now: u64) {
        let inactive_keys: Vec<String> = self
            .leases
            .iter()
            .filter(|(_, lease)| lease.is_expired(now) || lease.revoked)
            .map(|(lease_id, _)| lease_id.clone())
            .collect();
        for lease_id in inactive_keys {
            self.leases.remove(&lease_id);
        }
    }
}

/// Push an item to a bounded Vec, evicting oldest entries if at capacity.
fn push_bounded<T>(vec: &mut Vec<T>, item: T, max: usize) {
    if max == 0 {
        vec.clear();
        return;
    }
    if vec.len() >= max {
        let overflow = vec.len().saturating_sub(max).saturating_add(1);
        vec.drain(0..overflow);
    }
    vec.push(item);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn live_lease(id: usize, purpose: LeasePurpose, now: u64) -> Lease {
        Lease {
            lease_id: format!("lease-{id}"),
            holder: format!("holder-{id}"),
            purpose,
            ttl_secs: 60,
            granted_at: now,
            renewed_at: now,
            revoked: false,
        }
    }

    #[test]
    fn grant_creates_lease() {
        let mut svc = LeaseService::new();
        let l = svc
            .grant("holder-1", LeasePurpose::Operation, 60, 100, "tr", "ts")
            .unwrap();
        assert_eq!(l.holder, "holder-1");
        assert_eq!(l.purpose, LeasePurpose::Operation);
        assert!(l.is_active(100));
    }

    #[test]
    fn lease_expires_after_ttl() {
        let mut svc = LeaseService::new();
        let l = svc
            .grant("h", LeasePurpose::Operation, 60, 100, "tr", "ts")
            .unwrap();
        assert!(!l.is_expired(159)); // just before TTL boundary
        assert!(l.is_expired(160)); // at TTL boundary (fail-closed: 0 remaining = expired)
    }

    #[test]
    fn overflowed_expiry_is_treated_as_expired() {
        let lease = Lease {
            lease_id: "lease-overflow".into(),
            holder: "h".into(),
            purpose: LeasePurpose::Operation,
            ttl_secs: 10,
            granted_at: u64::MAX - 1,
            renewed_at: u64::MAX - 1,
            revoked: false,
        };

        assert!(lease.is_expired(u64::MAX - 1));
        assert_eq!(lease.remaining(u64::MAX - 1), 0);
    }

    #[test]
    fn renew_extends_ttl() {
        let mut svc = LeaseService::new();
        let l = svc
            .grant("h", LeasePurpose::Operation, 60, 100, "tr", "ts")
            .unwrap();
        let renewed = svc.renew(&l.lease_id, 150, "tr2", "ts2").unwrap();
        assert!(!renewed.is_expired(209)); // 150 + 60 = 210, one before boundary
        assert!(renewed.is_expired(210)); // at boundary (fail-closed)
    }

    #[test]
    fn renew_expired_fails() {
        let mut svc = LeaseService::new();
        let l = svc
            .grant("h", LeasePurpose::Operation, 60, 100, "tr", "ts")
            .unwrap();
        let err = svc.renew(&l.lease_id, 200, "tr2", "ts2").unwrap_err();
        assert_eq!(err.code(), "LS_EXPIRED");
    }

    #[test]
    fn renew_at_exact_expiry_boundary_fails_and_preserves_renewal_time() {
        let mut svc = LeaseService::new();
        let l = svc
            .grant("h", LeasePurpose::Operation, 60, 100, "tr", "ts")
            .unwrap();

        let err = svc
            .renew(&l.lease_id, 160, "tr-expiry", "ts-expiry")
            .unwrap_err();

        assert_eq!(err.code(), "LS_EXPIRED");
        assert_eq!(svc.get(&l.lease_id).unwrap().renewed_at, 100);
        let denial = svc
            .decisions
            .last()
            .expect("denied renew should be audited");
        assert_eq!(denial.action, "renew");
        assert!(!denial.allowed);
        assert_eq!(denial.reason, "lease expired");
    }

    #[test]
    fn renew_revoked_fails() {
        let mut svc = LeaseService::new();
        let l = svc
            .grant("h", LeasePurpose::Operation, 60, 100, "tr", "ts")
            .unwrap();
        svc.revoke(&l.lease_id, "tr", "ts").unwrap();
        let err = svc.renew(&l.lease_id, 110, "tr2", "ts2").unwrap_err();
        assert_eq!(err.code(), "LS_ALREADY_REVOKED");
    }

    #[test]
    fn use_active_lease_ok() {
        let mut svc = LeaseService::new();
        let l = svc
            .grant("h", LeasePurpose::StateWrite, 60, 100, "tr", "ts")
            .unwrap();
        let d = svc
            .use_lease(&l.lease_id, LeasePurpose::StateWrite, 110, "tr2", "ts2")
            .unwrap();
        assert!(d.allowed);
    }

    #[test]
    fn use_expired_lease_rejected() {
        let mut svc = LeaseService::new();
        let l = svc
            .grant("h", LeasePurpose::StateWrite, 60, 100, "tr", "ts")
            .unwrap();
        let err = svc
            .use_lease(&l.lease_id, LeasePurpose::StateWrite, 200, "tr2", "ts2")
            .unwrap_err();
        assert_eq!(err.code(), "LS_STALE_USE");
    }

    #[test]
    fn use_at_exact_expiry_boundary_is_rejected_and_audited() {
        let mut svc = LeaseService::new();
        let l = svc
            .grant("h", LeasePurpose::StateWrite, 60, 100, "tr", "ts")
            .unwrap();

        let err = svc
            .use_lease(&l.lease_id, LeasePurpose::StateWrite, 160, "tr2", "ts2")
            .unwrap_err();

        assert_eq!(err.code(), "LS_STALE_USE");
        let denial = svc.decisions.last().expect("denied use should be audited");
        assert_eq!(denial.action, "use");
        assert!(!denial.allowed);
        assert_eq!(denial.reason, "lease expired");
    }

    #[test]
    fn zero_ttl_lease_is_immediately_stale_on_use() {
        let mut svc = LeaseService::new();
        let l = svc
            .grant("h", LeasePurpose::Operation, 0, 100, "tr", "ts")
            .unwrap();

        assert!(l.is_expired(100));
        assert_eq!(l.remaining(100), 0);

        let err = svc
            .use_lease(
                &l.lease_id,
                LeasePurpose::Operation,
                100,
                "tr-use",
                "ts-use",
            )
            .unwrap_err();

        assert_eq!(err.code(), "LS_STALE_USE");
        assert_eq!(svc.decisions.last().unwrap().reason, "lease expired");
    }

    #[test]
    fn use_lease_with_overflowed_expiry_rejected() {
        let mut svc = LeaseService::new();
        let lease_id = "lease-overflow".to_string();
        svc.leases.insert(
            lease_id.clone(),
            Lease {
                lease_id: lease_id.clone(),
                holder: "h".into(),
                purpose: LeasePurpose::Operation,
                ttl_secs: 10,
                granted_at: u64::MAX - 1,
                renewed_at: u64::MAX - 1,
                revoked: false,
            },
        );

        let err = svc
            .use_lease(&lease_id, LeasePurpose::Operation, u64::MAX - 1, "tr", "ts")
            .unwrap_err();
        assert_eq!(err.code(), "LS_STALE_USE");
    }

    #[test]
    fn use_revoked_lease_rejected() {
        let mut svc = LeaseService::new();
        let l = svc
            .grant("h", LeasePurpose::StateWrite, 60, 100, "tr", "ts")
            .unwrap();
        svc.revoke(&l.lease_id, "tr", "ts").unwrap();
        let err = svc
            .use_lease(&l.lease_id, LeasePurpose::StateWrite, 110, "tr2", "ts2")
            .unwrap_err();
        assert_eq!(err.code(), "LS_STALE_USE");
    }

    #[test]
    fn use_wrong_purpose_rejected() {
        let mut svc = LeaseService::new();
        let l = svc
            .grant("h", LeasePurpose::Operation, 60, 100, "tr", "ts")
            .unwrap();
        let err = svc
            .use_lease(
                &l.lease_id,
                LeasePurpose::MigrationHandoff,
                110,
                "tr2",
                "ts2",
            )
            .unwrap_err();
        assert_eq!(err.code(), "LS_PURPOSE_MISMATCH");
    }

    #[test]
    fn use_missing_lease_returns_stale_use_without_audit_entry() {
        let mut svc = LeaseService::new();

        let err = svc
            .use_lease(
                "missing",
                LeasePurpose::MigrationHandoff,
                100,
                "tr-missing",
                "ts-missing",
            )
            .unwrap_err();

        assert_eq!(err.code(), "LS_STALE_USE");
        assert!(svc.decisions.is_empty());
    }

    #[test]
    fn purpose_mismatch_denial_records_expected_and_actual_purpose() {
        let mut svc = LeaseService::new();
        let l = svc
            .grant("h", LeasePurpose::Operation, 60, 100, "tr", "ts")
            .unwrap();

        let err = svc
            .use_lease(
                &l.lease_id,
                LeasePurpose::StateWrite,
                110,
                "tr-purpose",
                "ts-purpose",
            )
            .unwrap_err();

        assert_eq!(err.code(), "LS_PURPOSE_MISMATCH");
        let denial = svc
            .decisions
            .last()
            .expect("purpose denial should be audited");
        assert_eq!(denial.action, "use");
        assert!(!denial.allowed);
        assert!(
            denial
                .reason
                .contains("purpose mismatch: expected StateWrite, got Operation")
        );
    }

    #[test]
    fn revoke_works() {
        let mut svc = LeaseService::new();
        let l = svc
            .grant("h", LeasePurpose::Operation, 60, 100, "tr", "ts")
            .unwrap();
        svc.revoke(&l.lease_id, "tr", "ts").unwrap();
        assert!(svc.get(&l.lease_id).unwrap().revoked);
    }

    #[test]
    fn double_revoke_fails() {
        let mut svc = LeaseService::new();
        let l = svc
            .grant("h", LeasePurpose::Operation, 60, 100, "tr", "ts")
            .unwrap();
        svc.revoke(&l.lease_id, "tr", "ts").unwrap();
        let err = svc.revoke(&l.lease_id, "tr", "ts").unwrap_err();
        assert_eq!(err.code(), "LS_ALREADY_REVOKED");
    }

    #[test]
    fn second_revoke_failure_does_not_append_duplicate_decision() {
        let mut svc = LeaseService::new();
        let l = svc
            .grant("h", LeasePurpose::Operation, 60, 100, "tr", "ts")
            .unwrap();
        svc.revoke(&l.lease_id, "tr-revoke", "ts-revoke").unwrap();
        let decisions_after_first_revoke = svc.decisions.len();

        let err = svc
            .revoke(&l.lease_id, "tr-revoke-again", "ts-revoke-again")
            .unwrap_err();

        assert_eq!(err.code(), "LS_ALREADY_REVOKED");
        assert_eq!(svc.decisions.len(), decisions_after_first_revoke);
    }

    #[test]
    fn active_count() {
        let mut svc = LeaseService::new();
        svc.grant("h1", LeasePurpose::Operation, 60, 100, "tr", "ts")
            .unwrap();
        svc.grant("h2", LeasePurpose::StateWrite, 60, 100, "tr", "ts")
            .unwrap();
        assert_eq!(svc.active_count(110), 2);
        assert_eq!(svc.active_count(200), 0); // both expired
    }

    #[test]
    fn remaining_time() {
        let mut svc = LeaseService::new();
        let l = svc
            .grant("h", LeasePurpose::Operation, 60, 100, "tr", "ts")
            .unwrap();
        assert_eq!(l.remaining(130), 30);
        assert_eq!(l.remaining(160), 0);
        assert_eq!(l.remaining(200), 0);
    }

    #[test]
    fn purpose_display() {
        assert_eq!(LeasePurpose::Operation.to_string(), "Operation");
        assert_eq!(LeasePurpose::StateWrite.to_string(), "StateWrite");
        assert_eq!(
            LeasePurpose::MigrationHandoff.to_string(),
            "MigrationHandoff"
        );
    }

    #[test]
    fn error_display() {
        let e = LeaseError::Expired {
            lease_id: "l1".into(),
        };
        assert!(e.to_string().contains("LS_EXPIRED"));
    }

    #[test]
    fn error_codes_all_present() {
        assert_eq!(
            LeaseError::Expired {
                lease_id: "x".into()
            }
            .code(),
            "LS_EXPIRED"
        );
        assert_eq!(
            LeaseError::StaleUse {
                lease_id: "x".into()
            }
            .code(),
            "LS_STALE_USE"
        );
        assert_eq!(
            LeaseError::AlreadyRevoked {
                lease_id: "x".into()
            }
            .code(),
            "LS_ALREADY_REVOKED"
        );
        assert_eq!(
            LeaseError::PurposeMismatch {
                lease_id: "x".into(),
                expected: "a".into(),
                actual: "b".into()
            }
            .code(),
            "LS_PURPOSE_MISMATCH"
        );
        assert_eq!(
            LeaseError::NotFound {
                lease_id: "x".into()
            }
            .code(),
            "LS_NOT_FOUND"
        );
        assert_eq!(
            LeaseError::CapacityExceeded { capacity: 1 }.code(),
            "LS_CAPACITY_EXCEEDED"
        );
    }

    #[test]
    fn decisions_recorded() {
        let mut svc = LeaseService::new();
        let l = svc
            .grant("h", LeasePurpose::Operation, 60, 100, "tr", "ts")
            .unwrap();
        svc.use_lease(&l.lease_id, LeasePurpose::Operation, 110, "tr2", "ts2")
            .unwrap();
        assert_eq!(svc.decisions.len(), 2);
        assert_eq!(svc.decisions[0].action, "grant");
        assert_eq!(svc.decisions[1].action, "use");
    }

    #[test]
    fn migration_handoff_purpose() {
        let mut svc = LeaseService::new();
        let l = svc
            .grant(
                "migrator",
                LeasePurpose::MigrationHandoff,
                120,
                100,
                "tr",
                "ts",
            )
            .unwrap();
        let d = svc
            .use_lease(
                &l.lease_id,
                LeasePurpose::MigrationHandoff,
                150,
                "tr2",
                "ts2",
            )
            .unwrap();
        assert!(d.allowed);
    }

    #[test]
    fn renew_missing_lease_returns_not_found() {
        let mut svc = LeaseService::new();
        let err = svc.renew("missing", 100, "tr", "ts").unwrap_err();
        assert_eq!(err.code(), "LS_NOT_FOUND");
    }

    #[test]
    fn revoke_missing_lease_returns_not_found() {
        let mut svc = LeaseService::new();
        let err = svc.revoke("missing", "tr", "ts").unwrap_err();
        assert_eq!(err.code(), "LS_NOT_FOUND");
    }

    #[test]
    fn missing_renew_and_revoke_do_not_record_decisions() {
        let mut svc = LeaseService::new();

        let renew_err = svc.renew("missing-renew", 100, "tr", "ts").unwrap_err();
        let revoke_err = svc.revoke("missing-revoke", "tr", "ts").unwrap_err();

        assert_eq!(renew_err.code(), "LS_NOT_FOUND");
        assert_eq!(revoke_err.code(), "LS_NOT_FOUND");
        assert!(svc.decisions.is_empty());
    }

    #[test]
    fn grant_rejects_exhausted_id_counter_without_mutating_registry() {
        let mut svc = LeaseService::new();
        svc.next_id = u64::MAX;

        let err = svc
            .grant("h", LeasePurpose::Operation, 60, 100, "tr", "ts")
            .unwrap_err();

        assert_eq!(err.code(), "LS_CAPACITY_EXCEEDED");
        assert!(svc.leases.is_empty());
        assert!(svc.decisions.is_empty());
        assert_eq!(svc.next_id, u64::MAX);
    }

    #[test]
    fn grant_rejects_when_registry_full_of_live_leases() {
        let mut svc = LeaseService::new();
        for id in 0..MAX_LEASES {
            svc.leases.insert(
                format!("lease-{id}"),
                live_lease(id, LeasePurpose::Operation, 100),
            );
        }
        svc.next_id = MAX_LEASES as u64 + 1;

        let err = svc
            .grant("extra", LeasePurpose::StateWrite, 60, 100, "tr", "ts")
            .unwrap_err();

        assert_eq!(err.code(), "LS_CAPACITY_EXCEEDED");
        assert_eq!(svc.leases.len(), MAX_LEASES);
        assert!(
            svc.decisions
                .last()
                .is_some_and(|decision| !decision.allowed && decision.reason.contains("capacity"))
        );
    }

    #[test]
    fn grant_reclaims_inactive_leases_before_enforcing_capacity() {
        let mut svc = LeaseService::new();
        for id in 0..MAX_LEASES {
            svc.leases.insert(
                format!("lease-{id}"),
                live_lease(id, LeasePurpose::Operation, 100),
            );
        }
        svc.next_id = MAX_LEASES as u64 + 1;
        svc.leases.get_mut("lease-0").expect("seeded lease").revoked = true;

        let lease = svc
            .grant("extra", LeasePurpose::StateWrite, 60, 100, "tr", "ts")
            .expect("revoked lease should be reclaimed");

        assert_eq!(svc.leases.len(), MAX_LEASES);
        assert_eq!(lease.holder, "extra");
        assert!(!svc.leases.contains_key("lease-0"));
    }

    #[test]
    fn grant_sweeps_expired_leases_before_capacity_check() {
        let mut svc = LeaseService::new();
        for id in 0..MAX_LEASES {
            svc.leases.insert(
                format!("lease-{id}"),
                live_lease(id, LeasePurpose::Operation, 100),
            );
        }
        svc.next_id = MAX_LEASES as u64 + 1;
        svc.leases
            .get_mut("lease-0")
            .expect("seeded lease")
            .ttl_secs = 1;

        let lease = svc
            .grant("replacement", LeasePurpose::StateWrite, 60, 200, "tr", "ts")
            .expect("expired lease should be swept before capacity check");

        assert_eq!(svc.leases.len(), MAX_LEASES);
        assert_eq!(lease.holder, "replacement");
        assert!(!svc.leases.contains_key("lease-0"));
    }

    #[test]
    fn push_bounded_zero_capacity_clears_decisions_without_adding_item() {
        let mut decisions = vec![LeaseDecision {
            lease_id: "lease-old".into(),
            action: "grant".into(),
            allowed: true,
            reason: "seeded".into(),
            trace_id: "tr-old".into(),
            timestamp: "ts-old".into(),
        }];
        let new_decision = LeaseDecision {
            lease_id: "lease-new".into(),
            action: "renew".into(),
            allowed: false,
            reason: "zero capacity".into(),
            trace_id: "tr-new".into(),
            timestamp: "ts-new".into(),
        };

        push_bounded(&mut decisions, new_decision, 0);

        assert!(decisions.is_empty());
    }

    #[test]
    fn push_bounded_single_capacity_replaces_old_decision() {
        let mut decisions = vec![LeaseDecision {
            lease_id: "lease-old".into(),
            action: "grant".into(),
            allowed: true,
            reason: "seeded".into(),
            trace_id: "tr-old".into(),
            timestamp: "ts-old".into(),
        }];
        let new_decision = LeaseDecision {
            lease_id: "lease-new".into(),
            action: "use".into(),
            allowed: false,
            reason: "stale".into(),
            trace_id: "tr-new".into(),
            timestamp: "ts-new".into(),
        };

        push_bounded(&mut decisions, new_decision, 1);

        assert_eq!(decisions.len(), 1);
        assert_eq!(decisions[0].lease_id, "lease-new");
        assert_eq!(decisions[0].reason, "stale");
    }

    #[test]
    fn exhausted_id_grant_after_existing_decision_does_not_append_denial() {
        let mut svc = LeaseService::new();
        svc.decisions.push(LeaseDecision {
            lease_id: "lease-prior".into(),
            action: "grant".into(),
            allowed: true,
            reason: "prior decision".into(),
            trace_id: "tr-prior".into(),
            timestamp: "ts-prior".into(),
        });
        svc.next_id = u64::MAX;

        let err = svc
            .grant("holder", LeasePurpose::Operation, 60, 100, "tr", "ts")
            .unwrap_err();

        assert_eq!(err.code(), "LS_CAPACITY_EXCEEDED");
        assert_eq!(svc.decisions.len(), 1);
        assert_eq!(svc.decisions[0].lease_id, "lease-prior");
        assert!(svc.leases.is_empty());
        assert_eq!(svc.next_id, u64::MAX);
    }

    #[test]
    fn renew_revoked_preserves_original_renewed_at_and_records_denial() {
        let mut svc = LeaseService::new();
        let lease = svc
            .grant("holder", LeasePurpose::Operation, 60, 100, "tr", "ts")
            .unwrap();
        svc.revoke(&lease.lease_id, "tr-revoke", "ts-revoke")
            .unwrap();
        let decisions_before = svc.decisions.len();

        let err = svc
            .renew(&lease.lease_id, 120, "tr-renew", "ts-renew")
            .unwrap_err();

        assert_eq!(err.code(), "LS_ALREADY_REVOKED");
        assert_eq!(svc.get(&lease.lease_id).unwrap().renewed_at, 100);
        assert_eq!(svc.decisions.len(), decisions_before.saturating_add(1));
        let denial = svc
            .decisions
            .last()
            .expect("renew denial should be audited");
        assert_eq!(denial.action, "renew");
        assert!(!denial.allowed);
        assert_eq!(denial.reason, "lease revoked");
    }

    #[test]
    fn revoked_lease_is_swept_before_later_renew_attempt() {
        let mut svc = LeaseService::new();
        let lease = svc
            .grant("holder", LeasePurpose::Operation, 60, 100, "tr", "ts")
            .unwrap();
        svc.revoke(&lease.lease_id, "tr-revoke", "ts-revoke")
            .unwrap();
        svc.grant(
            "replacement",
            LeasePurpose::StateWrite,
            60,
            101,
            "tr-new",
            "ts-new",
        )
        .unwrap();

        let err = svc
            .renew(&lease.lease_id, 102, "tr-renew-old", "ts-renew-old")
            .unwrap_err();

        assert_eq!(err.code(), "LS_NOT_FOUND");
        assert!(svc.get(&lease.lease_id).is_none());
    }

    #[test]
    fn expired_lease_is_swept_before_later_revoke_attempt() {
        let mut svc = LeaseService::new();
        let lease = svc
            .grant("holder", LeasePurpose::Operation, 1, 100, "tr", "ts")
            .unwrap();
        assert!(lease.is_expired(101));

        svc.grant(
            "replacement",
            LeasePurpose::StateWrite,
            60,
            101,
            "tr-new",
            "ts-new",
        )
        .unwrap();

        let err = svc
            .revoke(&lease.lease_id, "tr-revoke-old", "ts-revoke-old")
            .unwrap_err();

        assert_eq!(err.code(), "LS_NOT_FOUND");
        assert!(svc.get(&lease.lease_id).is_none());
    }

    #[test]
    fn active_count_excludes_revoked_and_overflowed_expiry_leases() {
        let mut svc = LeaseService::new();
        svc.leases.insert(
            "lease-live".into(),
            live_lease(1, LeasePurpose::Operation, 100),
        );
        let mut revoked = live_lease(2, LeasePurpose::Operation, 100);
        revoked.revoked = true;
        svc.leases.insert("lease-revoked".into(), revoked);
        svc.leases.insert(
            "lease-overflow".into(),
            Lease {
                lease_id: "lease-overflow".into(),
                holder: "holder-overflow".into(),
                purpose: LeasePurpose::Operation,
                ttl_secs: 10,
                granted_at: u64::MAX - 1,
                renewed_at: u64::MAX - 1,
                revoked: false,
            },
        );

        assert_eq!(svc.active_count(100), 1);
        assert_eq!(svc.active_count(u64::MAX - 1), 0);
    }

    #[test]
    fn capacity_denial_preserves_next_id_and_records_denial_metadata() {
        let mut svc = LeaseService::new();
        for id in 0..MAX_LEASES {
            svc.leases.insert(
                format!("lease-{id}"),
                live_lease(id, LeasePurpose::Operation, 100),
            );
        }
        svc.next_id = 77;

        let err = svc
            .grant(
                "extra",
                LeasePurpose::StateWrite,
                60,
                100,
                "tr-cap",
                "ts-cap",
            )
            .unwrap_err();

        assert_eq!(err.code(), "LS_CAPACITY_EXCEEDED");
        assert_eq!(svc.next_id, 77);
        assert_eq!(svc.leases.len(), MAX_LEASES);
        let denial = svc.decisions.last().expect("capacity denial is audited");
        assert_eq!(denial.lease_id, "lease-77");
        assert_eq!(denial.action, "grant");
        assert!(!denial.allowed);
        assert_eq!(denial.trace_id, "tr-cap");
        assert_eq!(denial.timestamp, "ts-cap");
    }

    #[test]
    fn renew_overflowed_expiry_fails_closed_and_records_denial() {
        let mut svc = LeaseService::new();
        svc.leases.insert(
            "lease-overflow".into(),
            Lease {
                lease_id: "lease-overflow".into(),
                holder: "holder-overflow".into(),
                purpose: LeasePurpose::Operation,
                ttl_secs: 10,
                granted_at: u64::MAX - 1,
                renewed_at: u64::MAX - 1,
                revoked: false,
            },
        );

        let err = svc
            .renew("lease-overflow", u64::MAX - 1, "tr-overflow", "ts-overflow")
            .unwrap_err();

        assert_eq!(err.code(), "LS_EXPIRED");
        let denial = svc.decisions.last().expect("overflow renewal denial");
        assert_eq!(denial.action, "renew");
        assert!(!denial.allowed);
        assert_eq!(denial.reason, "lease expired");
        assert_eq!(denial.trace_id, "tr-overflow");
    }

    #[test]
    fn use_expired_lease_does_not_remove_or_revoke_stale_record() {
        let mut svc = LeaseService::new();
        let lease = svc
            .grant("holder", LeasePurpose::Operation, 1, 100, "tr", "ts")
            .unwrap();

        let err = svc
            .use_lease(
                &lease.lease_id,
                LeasePurpose::Operation,
                101,
                "tr-use",
                "ts-use",
            )
            .unwrap_err();

        assert_eq!(err.code(), "LS_STALE_USE");
        let stored = svc.get(&lease.lease_id).expect("stale use does not sweep");
        assert!(!stored.revoked);
        assert!(stored.is_expired(101));
        let denial = svc.decisions.last().expect("stale use denial");
        assert_eq!(denial.action, "use");
        assert!(!denial.allowed);
        assert_eq!(denial.reason, "lease expired");
    }

    #[test]
    fn use_revoked_lease_records_denial_metadata() {
        let mut svc = LeaseService::new();
        let lease = svc
            .grant("holder", LeasePurpose::StateWrite, 60, 100, "tr", "ts")
            .unwrap();
        svc.revoke(&lease.lease_id, "tr-revoke", "ts-revoke")
            .unwrap();

        let err = svc
            .use_lease(
                &lease.lease_id,
                LeasePurpose::StateWrite,
                110,
                "tr-use-revoked",
                "ts-use-revoked",
            )
            .unwrap_err();

        assert_eq!(err.code(), "LS_STALE_USE");
        let denial = svc.decisions.last().expect("revoked use denial");
        assert_eq!(denial.lease_id, lease.lease_id);
        assert_eq!(denial.action, "use");
        assert!(!denial.allowed);
        assert_eq!(denial.reason, "lease revoked");
        assert_eq!(denial.trace_id, "tr-use-revoked");
    }

    #[test]
    fn purpose_mismatch_does_not_renew_or_revoke_lease() {
        let mut svc = LeaseService::new();
        let lease = svc
            .grant("holder", LeasePurpose::Operation, 60, 100, "tr", "ts")
            .unwrap();

        let err = svc
            .use_lease(
                &lease.lease_id,
                LeasePurpose::MigrationHandoff,
                110,
                "tr-purpose",
                "ts-purpose",
            )
            .unwrap_err();

        assert_eq!(err.code(), "LS_PURPOSE_MISMATCH");
        let stored = svc
            .get(&lease.lease_id)
            .expect("lease remains after mismatch");
        assert_eq!(stored.renewed_at, 100);
        assert!(!stored.revoked);
        assert_eq!(stored.purpose, LeasePurpose::Operation);
    }

    #[test]
    fn missing_use_after_prior_decisions_does_not_append_decision() {
        let mut svc = LeaseService::new();
        let lease = svc
            .grant("holder", LeasePurpose::Operation, 60, 100, "tr", "ts")
            .unwrap();
        let decisions_before = svc.decisions.len();

        let err = svc
            .use_lease(
                "missing",
                LeasePurpose::Operation,
                110,
                "tr-missing",
                "ts-missing",
            )
            .unwrap_err();

        assert_eq!(err.code(), "LS_STALE_USE");
        assert_eq!(svc.decisions.len(), decisions_before);
        assert!(svc.get(&lease.lease_id).is_some());
    }

    #[test]
    fn missing_renew_after_prior_decision_does_not_append_decision() {
        let mut svc = LeaseService::new();
        svc.grant("holder", LeasePurpose::Operation, 60, 100, "tr", "ts")
            .unwrap();
        let decisions_before = svc.decisions.len();

        let err = svc
            .renew("missing", 110, "tr-missing", "ts-missing")
            .unwrap_err();

        assert_eq!(err.code(), "LS_NOT_FOUND");
        assert_eq!(svc.decisions.len(), decisions_before);
    }

    #[test]
    fn grant_sweeps_overflowed_expiry_before_capacity_check() {
        let mut svc = LeaseService::new();
        for id in 0..MAX_LEASES {
            svc.leases.insert(
                format!("lease-{id}"),
                live_lease(id, LeasePurpose::Operation, 100),
            );
        }
        svc.leases.insert(
            "lease-overflow".into(),
            Lease {
                lease_id: "lease-overflow".into(),
                holder: "holder-overflow".into(),
                purpose: LeasePurpose::StateWrite,
                ttl_secs: 10,
                granted_at: u64::MAX - 1,
                renewed_at: u64::MAX - 1,
                revoked: false,
            },
        );
        svc.leases.remove("lease-0");
        let replacement_id = u64::try_from(MAX_LEASES)
            .expect("MAX_LEASES fits in u64")
            .saturating_add(1);
        svc.next_id = replacement_id;

        let lease = svc
            .grant(
                "replacement",
                LeasePurpose::MigrationHandoff,
                60,
                100,
                "tr-reclaim",
                "ts-reclaim",
            )
            .expect("overflowed expiry should be swept before capacity check");

        assert_eq!(lease.lease_id, format!("lease-{replacement_id}"));
        assert_eq!(svc.leases.len(), MAX_LEASES);
        assert!(!svc.leases.contains_key("lease-overflow"));
        assert!(svc.leases.contains_key(&format!("lease-{replacement_id}")));
    }
}
