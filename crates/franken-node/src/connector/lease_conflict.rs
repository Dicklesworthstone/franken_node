//! bd-8uvb: Overlapping-lease conflict policy and deterministic fork handling logs.
//!
//! Detects overlapping leases on the same resource, resolves via deterministic
//! rules (earliest grant, purpose priority), and halts on dangerous-tier conflicts.
//! Every conflict produces a reproducible fork log entry.

use sha2::Digest;

/// Safety tier context for a lease conflict.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConflictTier {
    Standard,
    Risky,
    Dangerous,
}

impl ConflictTier {
    pub fn parse(s: &str) -> Self {
        match s {
            "Standard" => Self::Standard,
            "Risky" => Self::Risky,
            _ => Self::Dangerous,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Standard => "Standard",
            Self::Risky => "Risky",
            Self::Dangerous => "Dangerous",
        }
    }
}

/// Purpose priority for conflict resolution (higher = wins).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LeasePurposePriority {
    Operation = 0,
    StateWrite = 1,
    MigrationHandoff = 2,
}

impl LeasePurposePriority {
    pub fn parse(s: &str) -> Self {
        match s {
            "MigrationHandoff" => Self::MigrationHandoff,
            "StateWrite" => Self::StateWrite,
            _ => Self::Operation,
        }
    }
}

/// Configuration for conflict resolution policy.
#[derive(Debug, Clone)]
pub struct ConflictPolicy {
    /// If true, earliest-granted lease wins ties; otherwise, purpose priority breaks ties.
    pub prefer_earliest: bool,
    /// If true, dangerous-tier conflicts always halt.
    pub halt_on_dangerous: bool,
}

impl ConflictPolicy {
    pub fn default_policy() -> Self {
        Self {
            prefer_earliest: true,
            halt_on_dangerous: true,
        }
    }
}

/// An active lease descriptor used for overlap detection.
#[derive(Debug, Clone)]
pub struct ActiveLease {
    pub lease_id: String,
    pub holder: String,
    pub resource: String,
    pub purpose: String,
    pub granted_at: u64,
    pub expires_at: u64,
    pub tier: String,
}

/// A detected conflict between two overlapping leases.
#[derive(Debug, Clone)]
pub struct LeaseConflict {
    pub lease_a: String,
    pub lease_b: String,
    pub resource: String,
    pub overlap_start: u64,
    pub overlap_end: u64,
    pub tier: ConflictTier,
}

/// Result of resolving a conflict.
#[derive(Debug, Clone)]
pub struct ConflictResolution {
    pub winner: String,
    pub loser: String,
    pub rule_applied: String,
    pub halted: bool,
    pub resource: String,
}

/// Error codes for conflict operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConflictError {
    DangerousHalt { resource: String },
    BothActive { lease_a: String, lease_b: String },
    NoWinner { lease_a: String, lease_b: String },
    ForkLogIncomplete { field: String },
}

impl ConflictError {
    pub fn code(&self) -> &'static str {
        match self {
            Self::DangerousHalt { .. } => "OLC_DANGEROUS_HALT",
            Self::BothActive { .. } => "OLC_BOTH_ACTIVE",
            Self::NoWinner { .. } => "OLC_NO_WINNER",
            Self::ForkLogIncomplete { .. } => "OLC_FORK_LOG_INCOMPLETE",
        }
    }
}

impl std::fmt::Display for ConflictError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::DangerousHalt { resource } => write!(f, "OLC_DANGEROUS_HALT: {resource}"),
            Self::BothActive { lease_a, lease_b } => {
                write!(f, "OLC_BOTH_ACTIVE: {lease_a} vs {lease_b}")
            }
            Self::NoWinner { lease_a, lease_b } => {
                write!(f, "OLC_NO_WINNER: {lease_a} vs {lease_b}")
            }
            Self::ForkLogIncomplete { field } => {
                write!(f, "OLC_FORK_LOG_INCOMPLETE: missing {field}")
            }
        }
    }
}

/// A deterministic fork handling log entry.
#[derive(Debug, Clone)]
pub struct ForkLogEntry {
    pub entry_id: String,
    pub conflict_lease_a: String,
    pub conflict_lease_b: String,
    pub resource: String,
    pub overlap_start: u64,
    pub overlap_end: u64,
    pub resolution_winner: String,
    pub resolution_rule: String,
    pub halted: bool,
    pub trace_id: String,
    pub action_id: String,
    pub timestamp: String,
}

/// Detect pairwise overlapping leases on the same resource at time `now`.
///
/// INV-OLC-CLASSIFIED: each detected pair is a conflict.
pub fn detect_conflicts(leases: &[ActiveLease], resource: &str, now: u64) -> Vec<LeaseConflict> {
    let relevant: Vec<&ActiveLease> = leases
        .iter()
        .filter(|l| l.resource == resource && l.granted_at <= now && l.expires_at >= now)
        .collect();

    let mut conflicts = Vec::new();
    for i in 0..relevant.len() {
        for j in (i + 1)..relevant.len() {
            let a = relevant[i];
            let b = relevant[j];
            // Overlap window
            let start = a.granted_at.max(b.granted_at);
            let end = a.expires_at.min(b.expires_at);
            if start < end {
                // Effective tier: highest of the two
                let tier_a = ConflictTier::parse(&a.tier);
                let tier_b = ConflictTier::parse(&b.tier);
                let tier = match (tier_a, tier_b) {
                    (ConflictTier::Dangerous, _) | (_, ConflictTier::Dangerous) => {
                        ConflictTier::Dangerous
                    }
                    (ConflictTier::Risky, _) | (_, ConflictTier::Risky) => ConflictTier::Risky,
                    _ => ConflictTier::Standard,
                };
                conflicts.push(LeaseConflict {
                    lease_a: a.lease_id.clone(),
                    lease_b: b.lease_id.clone(),
                    resource: resource.to_string(),
                    overlap_start: start,
                    overlap_end: end,
                    tier,
                });
            }
        }
    }
    conflicts
}

/// Resolve a conflict using the given policy.
///
/// INV-OLC-DETERMINISTIC: same inputs → same resolution.
/// INV-OLC-DANGEROUS-HALT: dangerous-tier conflicts halt.
pub fn resolve_conflict(
    conflict: &LeaseConflict,
    policy: &ConflictPolicy,
    leases: &[ActiveLease],
) -> Result<ConflictResolution, ConflictError> {
    // INV-OLC-DANGEROUS-HALT
    if conflict.tier == ConflictTier::Dangerous && policy.halt_on_dangerous {
        return Err(ConflictError::DangerousHalt {
            resource: conflict.resource.clone(),
        });
    }

    let lease_a = leases.iter().find(|l| l.lease_id == conflict.lease_a);
    let lease_b = leases.iter().find(|l| l.lease_id == conflict.lease_b);

    let (a, b) = match (lease_a, lease_b) {
        (Some(a), Some(b)) => (a, b),
        _ => {
            return Err(ConflictError::NoWinner {
                lease_a: conflict.lease_a.clone(),
                lease_b: conflict.lease_b.clone(),
            });
        }
    };

    // Deterministic resolution: purpose priority first, then earliest grant
    let priority_a = LeasePurposePriority::parse(&a.purpose) as u8;
    let priority_b = LeasePurposePriority::parse(&b.purpose) as u8;

    let (winner, loser, rule) = if priority_a != priority_b {
        if priority_a > priority_b {
            (&a.lease_id, &b.lease_id, "purpose_priority")
        } else {
            (&b.lease_id, &a.lease_id, "purpose_priority")
        }
    } else if policy.prefer_earliest {
        if a.granted_at <= b.granted_at {
            (&a.lease_id, &b.lease_id, "earliest_grant")
        } else {
            (&b.lease_id, &a.lease_id, "earliest_grant")
        }
    } else {
        // Fallback: deterministic hash-based
        let mut ha = sha2::Sha256::new();
        sha2::Digest::update(&mut ha, b"lease_conflict_v1:");
        sha2::Digest::update(&mut ha, a.lease_id.as_bytes());
        let score_a = format!("{:x}", sha2::Digest::finalize(ha));

        let mut hb = sha2::Sha256::new();
        sha2::Digest::update(&mut hb, b"lease_conflict_v1:");
        sha2::Digest::update(&mut hb, b.lease_id.as_bytes());
        let score_b = format!("{:x}", sha2::Digest::finalize(hb));

        if score_a >= score_b {
            (&a.lease_id, &b.lease_id, "hash_tiebreak")
        } else {
            (&b.lease_id, &a.lease_id, "hash_tiebreak")
        }
    };

    Ok(ConflictResolution {
        winner: winner.clone(),
        loser: loser.clone(),
        rule_applied: rule.to_string(),
        halted: false,
        resource: conflict.resource.clone(),
    })
}

/// Create a fork log entry for a resolved (or halted) conflict.
///
/// INV-OLC-FORK-LOG: every conflict produces a reproducible log entry.
pub fn fork_log_entry(
    conflict: &LeaseConflict,
    resolution: Option<&ConflictResolution>,
    trace_id: &str,
    action_id: &str,
    timestamp: &str,
) -> Result<ForkLogEntry, ConflictError> {
    if trace_id.is_empty() {
        return Err(ConflictError::ForkLogIncomplete {
            field: "trace_id".into(),
        });
    }
    if action_id.is_empty() {
        return Err(ConflictError::ForkLogIncomplete {
            field: "action_id".into(),
        });
    }
    if timestamp.is_empty() {
        return Err(ConflictError::ForkLogIncomplete {
            field: "timestamp".into(),
        });
    }

    // Deterministic entry_id from conflict + trace
    let mut hasher = sha2::Sha256::new();
    sha2::Digest::update(&mut hasher, b"lease_conflict_resolution_v1:");
    sha2::Digest::update(&mut hasher, conflict.lease_a.as_bytes());
    sha2::Digest::update(&mut hasher, b"|");
    sha2::Digest::update(&mut hasher, conflict.lease_b.as_bytes());
    sha2::Digest::update(&mut hasher, b"|");
    sha2::Digest::update(&mut hasher, trace_id.as_bytes());
    let hash_hex = format!("{:x}", sha2::Digest::finalize(hasher));
    let entry_id = format!("fork-{}", &hash_hex[..16]);

    let (winner, rule, halted) = match resolution {
        Some(r) => (r.winner.clone(), r.rule_applied.clone(), r.halted),
        None => ("none".to_string(), "dangerous_halt".to_string(), true),
    };

    Ok(ForkLogEntry {
        entry_id,
        conflict_lease_a: conflict.lease_a.clone(),
        conflict_lease_b: conflict.lease_b.clone(),
        resource: conflict.resource.clone(),
        overlap_start: conflict.overlap_start,
        overlap_end: conflict.overlap_end,
        resolution_winner: winner,
        resolution_rule: rule,
        halted,
        trace_id: trace_id.to_string(),
        action_id: action_id.to_string(),
        timestamp: timestamp.to_string(),
    })
}

/// Convenience: detect + resolve all conflicts for a resource, producing fork logs.
pub fn process_conflicts(
    leases: &[ActiveLease],
    resource: &str,
    now: u64,
    policy: &ConflictPolicy,
    trace_id: &str,
    action_id: &str,
    timestamp: &str,
) -> (
    Vec<ConflictResolution>,
    Vec<ForkLogEntry>,
    Vec<ConflictError>,
) {
    let conflicts = detect_conflicts(leases, resource, now);
    let mut resolutions = Vec::new();
    let mut logs = Vec::new();
    let mut errors = Vec::new();

    for conflict in &conflicts {
        match resolve_conflict(conflict, policy, leases) {
            Ok(res) => {
                if let Ok(entry) =
                    fork_log_entry(conflict, Some(&res), trace_id, action_id, timestamp)
                {
                    logs.push(entry);
                }
                resolutions.push(res);
            }
            Err(e) => {
                if let Ok(entry) = fork_log_entry(conflict, None, trace_id, action_id, timestamp) {
                    logs.push(entry);
                }
                errors.push(e);
            }
        }
    }

    (resolutions, logs, errors)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lease(
        id: &str,
        resource: &str,
        purpose: &str,
        granted: u64,
        ttl: u64,
        tier: &str,
    ) -> ActiveLease {
        ActiveLease {
            lease_id: id.into(),
            holder: format!("holder-{id}"),
            resource: resource.into(),
            purpose: purpose.into(),
            granted_at: granted,
            expires_at: granted + ttl,
            tier: tier.into(),
        }
    }

    fn policy() -> ConflictPolicy {
        ConflictPolicy::default_policy()
    }

    #[test]
    fn detect_no_overlap() {
        let leases = vec![
            lease("l1", "res-a", "Operation", 100, 50, "Standard"),
            lease("l2", "res-a", "Operation", 160, 50, "Standard"),
        ];
        let conflicts = detect_conflicts(&leases, "res-a", 170);
        assert_eq!(conflicts.len(), 0); // l1 expired at 150
    }

    #[test]
    fn detect_overlap() {
        let leases = vec![
            lease("l1", "res-a", "Operation", 100, 60, "Standard"),
            lease("l2", "res-a", "Operation", 130, 60, "Standard"),
        ];
        let conflicts = detect_conflicts(&leases, "res-a", 140);
        assert_eq!(conflicts.len(), 1);
        assert_eq!(conflicts[0].overlap_start, 130);
        assert_eq!(conflicts[0].overlap_end, 160);
    }

    #[test]
    fn detect_different_resource_no_conflict() {
        let leases = vec![
            lease("l1", "res-a", "Operation", 100, 60, "Standard"),
            lease("l2", "res-b", "Operation", 100, 60, "Standard"),
        ];
        let conflicts = detect_conflicts(&leases, "res-a", 110);
        assert_eq!(conflicts.len(), 0);
    }

    #[test]
    fn resolve_earliest_grant_wins() {
        let leases = vec![
            lease("l1", "r", "Operation", 100, 60, "Standard"),
            lease("l2", "r", "Operation", 110, 60, "Standard"),
        ];
        let conflict = &detect_conflicts(&leases, "r", 120)[0];
        let res = resolve_conflict(conflict, &policy(), &leases).unwrap();
        assert_eq!(res.winner, "l1"); // granted earlier
        assert_eq!(res.rule_applied, "earliest_grant");
    }

    #[test]
    fn resolve_purpose_priority_wins() {
        let leases = vec![
            lease("l1", "r", "Operation", 100, 60, "Standard"),
            lease("l2", "r", "MigrationHandoff", 110, 60, "Standard"),
        ];
        let conflict = &detect_conflicts(&leases, "r", 120)[0];
        let res = resolve_conflict(conflict, &policy(), &leases).unwrap();
        assert_eq!(res.winner, "l2"); // MigrationHandoff > Operation
        assert_eq!(res.rule_applied, "purpose_priority");
    }

    #[test]
    fn resolve_state_write_beats_operation() {
        let leases = vec![
            lease("l1", "r", "Operation", 100, 60, "Standard"),
            lease("l2", "r", "StateWrite", 110, 60, "Standard"),
        ];
        let conflict = &detect_conflicts(&leases, "r", 120)[0];
        let res = resolve_conflict(conflict, &policy(), &leases).unwrap();
        assert_eq!(res.winner, "l2");
    }

    #[test]
    fn dangerous_halts() {
        let leases = vec![
            lease("l1", "r", "Operation", 100, 60, "Dangerous"),
            lease("l2", "r", "Operation", 110, 60, "Standard"),
        ];
        let conflict = &detect_conflicts(&leases, "r", 120)[0];
        let err = resolve_conflict(conflict, &policy(), &leases).unwrap_err();
        assert_eq!(err.code(), "OLC_DANGEROUS_HALT");
    }

    #[test]
    fn dangerous_halt_disabled_in_policy() {
        let leases = vec![
            lease("l1", "r", "Operation", 100, 60, "Dangerous"),
            lease("l2", "r", "Operation", 110, 60, "Standard"),
        ];
        let mut p = policy();
        p.halt_on_dangerous = false;
        let conflict = &detect_conflicts(&leases, "r", 120)[0];
        let res = resolve_conflict(conflict, &p, &leases).unwrap();
        assert_eq!(res.winner, "l1"); // earliest grant
    }

    #[test]
    fn fork_log_produced() {
        let leases = vec![
            lease("l1", "r", "Operation", 100, 60, "Standard"),
            lease("l2", "r", "Operation", 110, 60, "Standard"),
        ];
        let conflict = &detect_conflicts(&leases, "r", 120)[0];
        let res = resolve_conflict(conflict, &policy(), &leases).unwrap();
        let entry = fork_log_entry(conflict, Some(&res), "tr-1", "act-1", "2026-01-01").unwrap();
        assert_eq!(entry.conflict_lease_a, "l1");
        assert_eq!(entry.conflict_lease_b, "l2");
        assert_eq!(entry.resource, "r");
        assert!(!entry.halted);
        assert_eq!(entry.trace_id, "tr-1");
    }

    #[test]
    fn fork_log_for_halt() {
        let leases = vec![
            lease("l1", "r", "Operation", 100, 60, "Dangerous"),
            lease("l2", "r", "Operation", 110, 60, "Standard"),
        ];
        let conflict = &detect_conflicts(&leases, "r", 120)[0];
        let entry = fork_log_entry(conflict, None, "tr-1", "act-1", "2026-01-01").unwrap();
        assert!(entry.halted);
        assert_eq!(entry.resolution_winner, "none");
        assert_eq!(entry.resolution_rule, "dangerous_halt");
    }

    #[test]
    fn fork_log_missing_trace_id() {
        let conflict = LeaseConflict {
            lease_a: "l1".into(),
            lease_b: "l2".into(),
            resource: "r".into(),
            overlap_start: 100,
            overlap_end: 160,
            tier: ConflictTier::Standard,
        };
        let err = fork_log_entry(&conflict, None, "", "act-1", "2026-01-01").unwrap_err();
        assert_eq!(err.code(), "OLC_FORK_LOG_INCOMPLETE");
    }

    #[test]
    fn fork_log_missing_action_id() {
        let conflict = LeaseConflict {
            lease_a: "l1".into(),
            lease_b: "l2".into(),
            resource: "r".into(),
            overlap_start: 100,
            overlap_end: 160,
            tier: ConflictTier::Standard,
        };
        let err = fork_log_entry(&conflict, None, "tr", "", "2026-01-01").unwrap_err();
        assert_eq!(err.code(), "OLC_FORK_LOG_INCOMPLETE");
    }

    #[test]
    fn fork_log_missing_timestamp() {
        let conflict = LeaseConflict {
            lease_a: "l1".into(),
            lease_b: "l2".into(),
            resource: "r".into(),
            overlap_start: 100,
            overlap_end: 160,
            tier: ConflictTier::Standard,
        };
        let err = fork_log_entry(&conflict, None, "tr", "act", "").unwrap_err();
        assert_eq!(err.code(), "OLC_FORK_LOG_INCOMPLETE");
    }

    #[test]
    fn deterministic_resolution() {
        let leases = vec![
            lease("l1", "r", "Operation", 100, 60, "Standard"),
            lease("l2", "r", "Operation", 110, 60, "Standard"),
        ];
        let conflict = &detect_conflicts(&leases, "r", 120)[0];
        let r1 = resolve_conflict(conflict, &policy(), &leases).unwrap();
        let r2 = resolve_conflict(conflict, &policy(), &leases).unwrap();
        assert_eq!(r1.winner, r2.winner);
        assert_eq!(r1.rule_applied, r2.rule_applied);
    }

    #[test]
    fn process_conflicts_standard() {
        let leases = vec![
            lease("l1", "r", "Operation", 100, 60, "Standard"),
            lease("l2", "r", "Operation", 110, 60, "Standard"),
        ];
        let (resolutions, logs, errors) =
            process_conflicts(&leases, "r", 120, &policy(), "tr", "act", "ts");
        assert_eq!(resolutions.len(), 1);
        assert_eq!(logs.len(), 1);
        assert_eq!(errors.len(), 0);
    }

    #[test]
    fn process_conflicts_dangerous() {
        let leases = vec![
            lease("l1", "r", "Operation", 100, 60, "Dangerous"),
            lease("l2", "r", "Operation", 110, 60, "Standard"),
        ];
        let (resolutions, logs, errors) =
            process_conflicts(&leases, "r", 120, &policy(), "tr", "act", "ts");
        assert_eq!(resolutions.len(), 0);
        assert_eq!(logs.len(), 1); // halt log
        assert_eq!(errors.len(), 1);
        assert_eq!(errors[0].code(), "OLC_DANGEROUS_HALT");
    }

    #[test]
    fn three_way_overlap() {
        let leases = vec![
            lease("l1", "r", "Operation", 100, 60, "Standard"),
            lease("l2", "r", "StateWrite", 110, 60, "Standard"),
            lease("l3", "r", "MigrationHandoff", 120, 60, "Standard"),
        ];
        let conflicts = detect_conflicts(&leases, "r", 130);
        assert_eq!(conflicts.len(), 3); // l1-l2, l1-l3, l2-l3
    }

    #[test]
    fn tier_escalation() {
        let leases = vec![
            lease("l1", "r", "Operation", 100, 60, "Risky"),
            lease("l2", "r", "Operation", 110, 60, "Standard"),
        ];
        let conflicts = detect_conflicts(&leases, "r", 120);
        assert_eq!(conflicts[0].tier, ConflictTier::Risky);
    }

    #[test]
    fn entry_id_deterministic() {
        let conflict = LeaseConflict {
            lease_a: "l1".into(),
            lease_b: "l2".into(),
            resource: "r".into(),
            overlap_start: 100,
            overlap_end: 160,
            tier: ConflictTier::Standard,
        };
        let e1 = fork_log_entry(&conflict, None, "tr", "act", "ts").unwrap();
        let e2 = fork_log_entry(&conflict, None, "tr", "act", "ts").unwrap();
        assert_eq!(e1.entry_id, e2.entry_id);
    }

    #[test]
    fn error_codes_all_present() {
        assert_eq!(
            ConflictError::DangerousHalt {
                resource: "r".into()
            }
            .code(),
            "OLC_DANGEROUS_HALT"
        );
        assert_eq!(
            ConflictError::BothActive {
                lease_a: "a".into(),
                lease_b: "b".into()
            }
            .code(),
            "OLC_BOTH_ACTIVE"
        );
        assert_eq!(
            ConflictError::NoWinner {
                lease_a: "a".into(),
                lease_b: "b".into()
            }
            .code(),
            "OLC_NO_WINNER"
        );
        assert_eq!(
            ConflictError::ForkLogIncomplete { field: "f".into() }.code(),
            "OLC_FORK_LOG_INCOMPLETE"
        );
    }

    #[test]
    fn error_display() {
        let e = ConflictError::DangerousHalt {
            resource: "r".into(),
        };
        assert!(e.to_string().contains("OLC_DANGEROUS_HALT"));
    }

    #[test]
    fn conflict_policy_default() {
        let p = ConflictPolicy::default_policy();
        assert!(p.prefer_earliest);
        assert!(p.halt_on_dangerous);
    }

    #[test]
    fn conflict_tier_from_str() {
        assert_eq!(ConflictTier::parse("Standard"), ConflictTier::Standard);
        assert_eq!(ConflictTier::parse("Risky"), ConflictTier::Risky);
        assert_eq!(ConflictTier::parse("Dangerous"), ConflictTier::Dangerous);
        assert_eq!(ConflictTier::parse("Unknown"), ConflictTier::Dangerous);
    }
}
