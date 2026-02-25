//! bd-bq6y: Generic lease service for operation execution, state writes,
//! and migration handoff.
//!
//! Leases have deterministic expiry and renewal. Stale lease usage is rejected.

use std::collections::BTreeMap;

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
/// Error codes: `LS_EXPIRED`, `LS_STALE_USE`, `LS_ALREADY_REVOKED`, `LS_PURPOSE_MISMATCH`.
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
}

impl LeaseError {
    pub fn code(&self) -> &'static str {
        match self {
            Self::Expired { .. } => "LS_EXPIRED",
            Self::StaleUse { .. } => "LS_STALE_USE",
            Self::AlreadyRevoked { .. } => "LS_ALREADY_REVOKED",
            Self::PurposeMismatch { .. } => "LS_PURPOSE_MISMATCH",
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
    ) -> Lease {
        let lease_id = format!("lease-{}", self.next_id);
        self.next_id += 1;

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
        self.decisions.push(LeaseDecision {
            lease_id: lease_id.clone(),
            action: "grant".into(),
            allowed: true,
            reason: format!("granted {purpose} lease to {holder}"),
            trace_id: trace_id.to_string(),
            timestamp: timestamp.to_string(),
        });

        lease
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
            .ok_or_else(|| LeaseError::Expired {
                lease_id: lease_id.to_string(),
            })?;

        if lease.revoked {
            self.decisions.push(LeaseDecision {
                lease_id: lease_id.to_string(),
                action: "renew".into(),
                allowed: false,
                reason: "lease revoked".into(),
                trace_id: trace_id.to_string(),
                timestamp: timestamp.to_string(),
            });
            return Err(LeaseError::AlreadyRevoked {
                lease_id: lease_id.to_string(),
            });
        }

        if lease.is_expired(now) {
            self.decisions.push(LeaseDecision {
                lease_id: lease_id.to_string(),
                action: "renew".into(),
                allowed: false,
                reason: "lease expired".into(),
                trace_id: trace_id.to_string(),
                timestamp: timestamp.to_string(),
            });
            return Err(LeaseError::Expired {
                lease_id: lease_id.to_string(),
            });
        }

        let lease = self
            .leases
            .get_mut(lease_id)
            .expect("lease existence verified above");
        lease.renewed_at = now;

        self.decisions.push(LeaseDecision {
            lease_id: lease_id.to_string(),
            action: "renew".into(),
            allowed: true,
            reason: "renewed".into(),
            trace_id: trace_id.to_string(),
            timestamp: timestamp.to_string(),
        });

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
            self.decisions.push(d.clone());
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
            self.decisions.push(d.clone());
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
            self.decisions.push(d.clone());
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
        self.decisions.push(d.clone());
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
            .ok_or_else(|| LeaseError::Expired {
                lease_id: lease_id.to_string(),
            })?;

        if lease.revoked {
            return Err(LeaseError::AlreadyRevoked {
                lease_id: lease_id.to_string(),
            });
        }

        lease.revoked = true;
        self.decisions.push(LeaseDecision {
            lease_id: lease_id.to_string(),
            action: "revoke".into(),
            allowed: true,
            reason: "revoked".into(),
            trace_id: trace_id.to_string(),
            timestamp: timestamp.to_string(),
        });

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
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn grant_creates_lease() {
        let mut svc = LeaseService::new();
        let l = svc.grant("holder-1", LeasePurpose::Operation, 60, 100, "tr", "ts");
        assert_eq!(l.holder, "holder-1");
        assert_eq!(l.purpose, LeasePurpose::Operation);
        assert!(l.is_active(100));
    }

    #[test]
    fn lease_expires_after_ttl() {
        let mut svc = LeaseService::new();
        let l = svc.grant("h", LeasePurpose::Operation, 60, 100, "tr", "ts");
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
        let l = svc.grant("h", LeasePurpose::Operation, 60, 100, "tr", "ts");
        let renewed = svc.renew(&l.lease_id, 150, "tr2", "ts2").unwrap();
        assert!(!renewed.is_expired(209)); // 150 + 60 = 210, one before boundary
        assert!(renewed.is_expired(210)); // at boundary (fail-closed)
    }

    #[test]
    fn renew_expired_fails() {
        let mut svc = LeaseService::new();
        let l = svc.grant("h", LeasePurpose::Operation, 60, 100, "tr", "ts");
        let err = svc.renew(&l.lease_id, 200, "tr2", "ts2").unwrap_err();
        assert_eq!(err.code(), "LS_EXPIRED");
    }

    #[test]
    fn renew_revoked_fails() {
        let mut svc = LeaseService::new();
        let l = svc.grant("h", LeasePurpose::Operation, 60, 100, "tr", "ts");
        svc.revoke(&l.lease_id, "tr", "ts").unwrap();
        let err = svc.renew(&l.lease_id, 110, "tr2", "ts2").unwrap_err();
        assert_eq!(err.code(), "LS_ALREADY_REVOKED");
    }

    #[test]
    fn use_active_lease_ok() {
        let mut svc = LeaseService::new();
        let l = svc.grant("h", LeasePurpose::StateWrite, 60, 100, "tr", "ts");
        let d = svc
            .use_lease(&l.lease_id, LeasePurpose::StateWrite, 110, "tr2", "ts2")
            .unwrap();
        assert!(d.allowed);
    }

    #[test]
    fn use_expired_lease_rejected() {
        let mut svc = LeaseService::new();
        let l = svc.grant("h", LeasePurpose::StateWrite, 60, 100, "tr", "ts");
        let err = svc
            .use_lease(&l.lease_id, LeasePurpose::StateWrite, 200, "tr2", "ts2")
            .unwrap_err();
        assert_eq!(err.code(), "LS_STALE_USE");
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
        let l = svc.grant("h", LeasePurpose::StateWrite, 60, 100, "tr", "ts");
        svc.revoke(&l.lease_id, "tr", "ts").unwrap();
        let err = svc
            .use_lease(&l.lease_id, LeasePurpose::StateWrite, 110, "tr2", "ts2")
            .unwrap_err();
        assert_eq!(err.code(), "LS_STALE_USE");
    }

    #[test]
    fn use_wrong_purpose_rejected() {
        let mut svc = LeaseService::new();
        let l = svc.grant("h", LeasePurpose::Operation, 60, 100, "tr", "ts");
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
    fn revoke_works() {
        let mut svc = LeaseService::new();
        let l = svc.grant("h", LeasePurpose::Operation, 60, 100, "tr", "ts");
        svc.revoke(&l.lease_id, "tr", "ts").unwrap();
        assert!(svc.get(&l.lease_id).unwrap().revoked);
    }

    #[test]
    fn double_revoke_fails() {
        let mut svc = LeaseService::new();
        let l = svc.grant("h", LeasePurpose::Operation, 60, 100, "tr", "ts");
        svc.revoke(&l.lease_id, "tr", "ts").unwrap();
        let err = svc.revoke(&l.lease_id, "tr", "ts").unwrap_err();
        assert_eq!(err.code(), "LS_ALREADY_REVOKED");
    }

    #[test]
    fn active_count() {
        let mut svc = LeaseService::new();
        svc.grant("h1", LeasePurpose::Operation, 60, 100, "tr", "ts");
        svc.grant("h2", LeasePurpose::StateWrite, 60, 100, "tr", "ts");
        assert_eq!(svc.active_count(110), 2);
        assert_eq!(svc.active_count(200), 0); // both expired
    }

    #[test]
    fn remaining_time() {
        let mut svc = LeaseService::new();
        let l = svc.grant("h", LeasePurpose::Operation, 60, 100, "tr", "ts");
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
    }

    #[test]
    fn decisions_recorded() {
        let mut svc = LeaseService::new();
        let l = svc.grant("h", LeasePurpose::Operation, 60, 100, "tr", "ts");
        svc.use_lease(&l.lease_id, LeasePurpose::Operation, 110, "tr2", "ts2")
            .unwrap();
        assert_eq!(svc.decisions.len(), 2);
        assert_eq!(svc.decisions[0].action, "grant");
        assert_eq!(svc.decisions[1].action, "use");
    }

    #[test]
    fn migration_handoff_purpose() {
        let mut svc = LeaseService::new();
        let l = svc.grant(
            "migrator",
            LeasePurpose::MigrationHandoff,
            120,
            100,
            "tr",
            "ts",
        );
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
}
