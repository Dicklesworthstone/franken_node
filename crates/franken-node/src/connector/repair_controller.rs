//! bd-91gg: Background repair controller with bounded work-per-cycle and fairness.
//!
//! Respects per-cycle work caps. Guarantees no tenant starvation via fairness minimum.
//! Every cycle produces an auditable record.

use std::collections::{BTreeMap, BTreeSet};

/// Configuration for the repair controller.
#[derive(Debug, Clone)]
pub struct RepairConfig {
    pub max_units_per_cycle: u64,
    pub fairness_minimum: u64,
    pub max_tenants_per_cycle: usize,
}

impl RepairConfig {
    pub fn default_config() -> Self {
        Self {
            max_units_per_cycle: 100,
            fairness_minimum: 1,
            max_tenants_per_cycle: 50,
        }
    }
}

/// A pending repair item.
#[derive(Debug, Clone)]
pub struct RepairItem {
    pub item_id: String,
    pub tenant_id: String,
    pub priority: u32,
    pub size_units: u64,
}

/// Per-tenant allocation in a repair cycle.
#[derive(Debug, Clone)]
pub struct RepairAllocation {
    pub tenant_id: String,
    pub items_allocated: Vec<String>,
    pub units_used: u64,
}

/// Audit record for a repair cycle.
#[derive(Debug, Clone)]
pub struct RepairCycleAudit {
    pub cycle_id: String,
    pub allocations: Vec<RepairAllocation>,
    pub total_units_used: u64,
    pub cap: u64,
    pub tenants_served: usize,
    pub tenants_skipped: usize,
    pub trace_id: String,
    pub timestamp: String,
}

/// Errors from repair operations.
#[derive(Debug, Clone, PartialEq)]
pub enum RepairError {
    CapExceeded { used: u64, cap: u64 },
    InvalidConfig { reason: String },
    NoPending,
    Starvation { tenant_id: String },
}

impl RepairError {
    pub fn code(&self) -> &'static str {
        match self {
            Self::CapExceeded { .. } => "BRC_CAP_EXCEEDED",
            Self::InvalidConfig { .. } => "BRC_INVALID_CONFIG",
            Self::NoPending => "BRC_NO_PENDING",
            Self::Starvation { .. } => "BRC_STARVATION",
        }
    }
}

impl std::fmt::Display for RepairError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::CapExceeded { used, cap } => write!(f, "BRC_CAP_EXCEEDED: {used}/{cap}"),
            Self::InvalidConfig { reason } => write!(f, "BRC_INVALID_CONFIG: {reason}"),
            Self::NoPending => write!(f, "BRC_NO_PENDING"),
            Self::Starvation { tenant_id } => write!(f, "BRC_STARVATION: {tenant_id}"),
        }
    }
}

/// Validate repair config.
pub fn validate_config(config: &RepairConfig) -> Result<(), RepairError> {
    if config.max_units_per_cycle == 0 {
        return Err(RepairError::InvalidConfig {
            reason: "max_units_per_cycle must be > 0".into(),
        });
    }
    if config.fairness_minimum == 0 {
        return Err(RepairError::InvalidConfig {
            reason: "fairness_minimum must be > 0".into(),
        });
    }
    if config.max_tenants_per_cycle == 0 {
        return Err(RepairError::InvalidConfig {
            reason: "max_tenants_per_cycle must be > 0".into(),
        });
    }
    Ok(())
}

/// Run a repair cycle with bounded work and fairness.
///
/// Algorithm:
/// 1. Group items by tenant, sort tenants deterministically (by tenant_id).
/// 2. First pass: allocate fairness_minimum to each tenant.
/// 3. Second pass: distribute remaining budget by priority.
///
/// INV-BRC-BOUNDED: total units <= max_units_per_cycle.
/// INV-BRC-FAIRNESS: every tenant with pending work gets at least fairness_minimum.
/// INV-BRC-AUDITABLE: returns a RepairCycleAudit.
/// INV-BRC-DETERMINISTIC: sorted by tenant_id, then by priority descending.
pub fn run_cycle(
    pending: &[RepairItem],
    config: &RepairConfig,
    cycle_id: &str,
    trace_id: &str,
    timestamp: &str,
) -> Result<(Vec<RepairAllocation>, RepairCycleAudit), RepairError> {
    validate_config(config)?;

    if pending.is_empty() {
        return Err(RepairError::NoPending);
    }

    let trimmed_cycle_id = cycle_id.trim();
    if trimmed_cycle_id.is_empty() || trimmed_cycle_id != cycle_id {
        return Err(RepairError::InvalidConfig {
            reason: "cycle_id must be non-empty and unpadded".into(),
        });
    }
    let trimmed_trace_id = trace_id.trim();
    if trimmed_trace_id.is_empty() || trimmed_trace_id != trace_id {
        return Err(RepairError::InvalidConfig {
            reason: "trace_id must be non-empty and unpadded".into(),
        });
    }
    let trimmed_timestamp = timestamp.trim();
    if trimmed_timestamp.is_empty() || trimmed_timestamp != timestamp {
        return Err(RepairError::InvalidConfig {
            reason: "timestamp must be non-empty and unpadded".into(),
        });
    }

    // Group by tenant, sorted by tenant_id for determinism
    let mut by_tenant: BTreeMap<String, Vec<&RepairItem>> = BTreeMap::new();
    let mut item_ids = BTreeSet::new();
    for item in pending {
        let item_id = item.item_id.as_str();
        if item_id.trim().is_empty() || item_id.trim() != item_id {
            return Err(RepairError::InvalidConfig {
                reason: "item_id must be non-empty and unpadded".into(),
            });
        }
        let tenant_id = item.tenant_id.as_str();
        if tenant_id.trim().is_empty() || tenant_id.trim() != tenant_id {
            return Err(RepairError::InvalidConfig {
                reason: "tenant_id must be non-empty and unpadded".into(),
            });
        }
        if !item_ids.insert(item_id) {
            return Err(RepairError::InvalidConfig {
                reason: format!("duplicate item_id: {item_id}"),
            });
        }
        by_tenant
            .entry(item.tenant_id.clone())
            .or_default()
            .push(item);
    }

    // Sort each tenant's items by priority descending, then item_id for determinism
    for items in by_tenant.values_mut() {
        items.sort_by(|a, b| b.priority.cmp(&a.priority).then(a.item_id.cmp(&b.item_id)));
    }

    let mut tenant_ids: Vec<String> = by_tenant.keys().cloned().collect();
    tenant_ids.sort();

    // Limit tenants per cycle
    let active_tenants: Vec<String> = tenant_ids
        .into_iter()
        .take(config.max_tenants_per_cycle)
        .collect();
    let skipped = by_tenant.len().saturating_sub(active_tenants.len());

    let mut allocations: BTreeMap<String, RepairAllocation> = BTreeMap::new();
    let mut total_used: u64 = 0;

    // First pass: fairness minimum for each tenant
    for tenant_id in &active_tenants {
        let items = by_tenant.get(tenant_id).ok_or(RepairError::InvalidConfig {
            reason: format!("missing tenant {tenant_id} in by_tenant map"),
        })?;
        let mut tenant_alloc = RepairAllocation {
            tenant_id: tenant_id.clone(),
            items_allocated: Vec::new(),
            units_used: 0,
        };

        let mut fairness_remaining = config.fairness_minimum;
        for item in items {
            if fairness_remaining == 0 || total_used >= config.max_units_per_cycle {
                break;
            }
            let can_use = item
                .size_units
                .min(fairness_remaining)
                .min(config.max_units_per_cycle.saturating_sub(total_used));
            if can_use > 0 {
                tenant_alloc.items_allocated.push(item.item_id.clone());
                tenant_alloc.units_used = tenant_alloc.units_used.saturating_add(can_use);
                total_used = total_used.saturating_add(can_use);
                fairness_remaining = fairness_remaining.saturating_sub(can_use);
            }
        }

        allocations.insert(tenant_id.clone(), tenant_alloc);
    }

    // Second pass: remaining budget by priority across all tenants
    if total_used < config.max_units_per_cycle {
        // Collect all unallocated items, sorted by priority desc then item_id
        let mut remaining_items: Vec<&RepairItem> = Vec::new();
        for tenant_id in &active_tenants {
            let items = by_tenant.get(tenant_id).ok_or(RepairError::InvalidConfig {
                reason: format!("missing tenant {tenant_id} in by_tenant map"),
            })?;
            let alloc = allocations
                .get(tenant_id)
                .ok_or(RepairError::InvalidConfig {
                    reason: format!("missing allocation for tenant {tenant_id}"),
                })?;
            for item in items {
                if !alloc.items_allocated.contains(&item.item_id) {
                    remaining_items.push(item);
                }
            }
        }
        remaining_items.sort_by(|a, b| b.priority.cmp(&a.priority).then(a.item_id.cmp(&b.item_id)));

        for item in remaining_items {
            if total_used >= config.max_units_per_cycle {
                break;
            }
            let can_use = item
                .size_units
                .min(config.max_units_per_cycle.saturating_sub(total_used));
            if can_use > 0 {
                let alloc =
                    allocations
                        .get_mut(&item.tenant_id)
                        .ok_or(RepairError::InvalidConfig {
                            reason: format!("missing allocation for tenant {}", item.tenant_id),
                        })?;
                alloc.items_allocated.push(item.item_id.clone());
                alloc.units_used = alloc.units_used.saturating_add(can_use);
                total_used = total_used.saturating_add(can_use);
            }
        }
    }

    let mut result: Vec<RepairAllocation> = allocations.into_values().collect();
    result.sort_by(|a, b| a.tenant_id.cmp(&b.tenant_id));

    let tenants_served = result
        .iter()
        .filter(|a| !a.items_allocated.is_empty())
        .count();

    let audit = RepairCycleAudit {
        cycle_id: cycle_id.to_string(),
        allocations: result.clone(),
        total_units_used: total_used,
        cap: config.max_units_per_cycle,
        tenants_served,
        tenants_skipped: skipped,
        trace_id: trace_id.to_string(),
        timestamp: timestamp.to_string(),
    };

    Ok((result, audit))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config() -> RepairConfig {
        RepairConfig {
            max_units_per_cycle: 100,
            fairness_minimum: 5,
            max_tenants_per_cycle: 10,
        }
    }

    fn item(id: &str, tenant: &str, priority: u32, size: u64) -> RepairItem {
        RepairItem {
            item_id: id.into(),
            tenant_id: tenant.into(),
            priority,
            size_units: size,
        }
    }

    #[test]
    fn single_tenant_allocation() {
        let items = vec![item("r1", "t1", 5, 10)];
        let (allocs, audit) =
            run_cycle(&items, &config(), "c1", "tr", "ts").expect("should succeed");
        assert_eq!(allocs.len(), 1);
        assert_eq!(allocs[0].tenant_id, "t1");
        assert!(allocs[0].units_used > 0);
        assert!(audit.total_units_used <= config().max_units_per_cycle);
    }

    #[test]
    fn bounded_by_cap() {
        let items: Vec<RepairItem> = (0..20)
            .map(|i| item(&format!("r{i}"), "t1", 5, 10))
            .collect();
        let (_, audit) = run_cycle(&items, &config(), "c1", "tr", "ts").expect("should succeed");
        assert!(audit.total_units_used <= config().max_units_per_cycle);
    }

    #[test]
    fn fairness_no_starvation() {
        let items = vec![
            item("r1", "t1", 10, 3),
            item("r2", "t1", 9, 3),
            item("r3", "t2", 1, 3),
        ];
        let (allocs, _) = run_cycle(&items, &config(), "c1", "tr", "ts").expect("should succeed");
        for alloc in &allocs {
            assert!(
                !alloc.items_allocated.is_empty(),
                "tenant {} got no work",
                alloc.tenant_id
            );
        }
    }

    #[test]
    fn deterministic_allocation() {
        let items = vec![
            item("r1", "t1", 5, 10),
            item("r2", "t2", 3, 10),
            item("r3", "t1", 8, 10),
        ];
        let (a1, _) = run_cycle(&items, &config(), "c1", "tr", "ts").expect("should succeed");
        let (a2, _) = run_cycle(&items, &config(), "c1", "tr", "ts").expect("should succeed");
        for (x, y) in a1.iter().zip(a2.iter()) {
            assert_eq!(x.tenant_id, y.tenant_id);
            assert_eq!(x.items_allocated, y.items_allocated);
            assert_eq!(x.units_used, y.units_used);
        }
    }

    #[test]
    fn audit_has_trace() {
        let items = vec![item("r1", "t1", 5, 10)];
        let (_, audit) =
            run_cycle(&items, &config(), "c1", "trace-x", "ts").expect("should succeed");
        assert_eq!(audit.trace_id, "trace-x");
        assert_eq!(audit.cycle_id, "c1");
    }

    #[test]
    fn no_pending_error() {
        let err = run_cycle(&[], &config(), "c1", "tr", "ts").unwrap_err();
        assert_eq!(err.code(), "BRC_NO_PENDING");
    }

    #[test]
    fn invalid_config_zero_cap() {
        let cfg = RepairConfig {
            max_units_per_cycle: 0,
            ..config()
        };
        let err = run_cycle(&[item("r1", "t1", 5, 10)], &cfg, "c1", "tr", "ts").unwrap_err();
        assert_eq!(err.code(), "BRC_INVALID_CONFIG");
    }

    #[test]
    fn invalid_config_zero_fairness() {
        let cfg = RepairConfig {
            fairness_minimum: 0,
            ..config()
        };
        let err = run_cycle(&[item("r1", "t1", 5, 10)], &cfg, "c1", "tr", "ts").unwrap_err();
        assert_eq!(err.code(), "BRC_INVALID_CONFIG");
    }

    #[test]
    fn invalid_config_zero_tenants() {
        let cfg = RepairConfig {
            max_tenants_per_cycle: 0,
            ..config()
        };
        let err = run_cycle(&[item("r1", "t1", 5, 10)], &cfg, "c1", "tr", "ts").unwrap_err();
        assert_eq!(err.code(), "BRC_INVALID_CONFIG");
    }

    #[test]
    fn max_tenants_limit() {
        let mut cfg = config();
        cfg.max_tenants_per_cycle = 2;
        let items = vec![
            item("r1", "t1", 5, 5),
            item("r2", "t2", 5, 5),
            item("r3", "t3", 5, 5),
        ];
        let (allocs, audit) = run_cycle(&items, &cfg, "c1", "tr", "ts").expect("should succeed");
        assert_eq!(allocs.len(), 2);
        assert_eq!(audit.tenants_skipped, 1);
    }

    #[test]
    fn priority_ordering() {
        let items = vec![item("low", "t1", 1, 5), item("high", "t1", 10, 5)];
        let mut cfg = config();
        cfg.max_units_per_cycle = 8; // only room for one + fairness
        let (allocs, _) = run_cycle(&items, &cfg, "c1", "tr", "ts").expect("should succeed");
        // High priority should be allocated first
        assert!(allocs[0].items_allocated.contains(&"high".to_string()));
    }

    #[test]
    fn error_codes_all_present() {
        assert_eq!(
            RepairError::CapExceeded { used: 0, cap: 0 }.code(),
            "BRC_CAP_EXCEEDED"
        );
        assert_eq!(
            RepairError::InvalidConfig { reason: "".into() }.code(),
            "BRC_INVALID_CONFIG"
        );
        assert_eq!(RepairError::NoPending.code(), "BRC_NO_PENDING");
        assert_eq!(
            RepairError::Starvation {
                tenant_id: "".into()
            }
            .code(),
            "BRC_STARVATION"
        );
    }

    #[test]
    fn error_display() {
        let e = RepairError::CapExceeded {
            used: 110,
            cap: 100,
        };
        assert!(e.to_string().contains("BRC_CAP_EXCEEDED"));
    }

    #[test]
    fn default_config_valid() {
        assert!(validate_config(&RepairConfig::default_config()).is_ok());
    }

    #[test]
    fn audit_tenants_served_count() {
        let items = vec![item("r1", "t1", 5, 5), item("r2", "t2", 5, 5)];
        let (_, audit) = run_cycle(&items, &config(), "c1", "tr", "ts").expect("should succeed");
        assert_eq!(audit.tenants_served, 2);
    }

    #[test]
    fn allocation_sorted_by_tenant() {
        let items = vec![item("r1", "z-tenant", 5, 5), item("r2", "a-tenant", 5, 5)];
        let (allocs, _) = run_cycle(&items, &config(), "c1", "tr", "ts").expect("should succeed");
        assert_eq!(allocs[0].tenant_id, "a-tenant");
        assert_eq!(allocs[1].tenant_id, "z-tenant");
    }

    #[test]
    fn validate_config_reports_zero_cap_reason() {
        let cfg = RepairConfig {
            max_units_per_cycle: 0,
            ..config()
        };

        let err = validate_config(&cfg).unwrap_err();

        assert_eq!(
            err,
            RepairError::InvalidConfig {
                reason: "max_units_per_cycle must be > 0".to_string()
            }
        );
    }

    #[test]
    fn validate_config_reports_zero_fairness_reason() {
        let cfg = RepairConfig {
            fairness_minimum: 0,
            ..config()
        };

        let err = validate_config(&cfg).unwrap_err();

        assert_eq!(
            err,
            RepairError::InvalidConfig {
                reason: "fairness_minimum must be > 0".to_string()
            }
        );
    }

    #[test]
    fn validate_config_reports_zero_tenant_limit_reason() {
        let cfg = RepairConfig {
            max_tenants_per_cycle: 0,
            ..config()
        };

        let err = validate_config(&cfg).unwrap_err();

        assert_eq!(
            err,
            RepairError::InvalidConfig {
                reason: "max_tenants_per_cycle must be > 0".to_string()
            }
        );
    }

    #[test]
    fn invalid_config_precedes_empty_pending_error() {
        let cfg = RepairConfig {
            max_units_per_cycle: 0,
            fairness_minimum: 0,
            max_tenants_per_cycle: 0,
        };

        let err = run_cycle(&[], &cfg, "c-invalid", "tr-invalid", "ts").unwrap_err();

        assert_eq!(err.code(), "BRC_INVALID_CONFIG");
        assert_ne!(err, RepairError::NoPending);
    }

    #[test]
    fn no_pending_does_not_emit_allocations_or_audit() {
        let err = run_cycle(&[], &config(), "c-empty", "tr-empty", "ts").unwrap_err();

        assert_eq!(err, RepairError::NoPending);
        assert_eq!(err.to_string(), "BRC_NO_PENDING");
    }

    #[test]
    fn zero_sized_items_are_not_counted_as_served() {
        let items = vec![item("zero-1", "tenant-zero", 10, 0)];

        let (allocs, audit) =
            run_cycle(&items, &config(), "c-zero", "tr-zero", "ts").expect("cycle succeeds");

        assert_eq!(allocs.len(), 1);
        assert!(allocs[0].items_allocated.is_empty());
        assert_eq!(allocs[0].units_used, 0);
        assert_eq!(audit.total_units_used, 0);
        assert_eq!(audit.tenants_served, 0);
    }

    #[test]
    fn tenant_limit_can_skip_high_priority_later_tenant() {
        let mut cfg = config();
        cfg.max_tenants_per_cycle = 1;
        let items = vec![
            item("low-a", "a-tenant", 1, 5),
            item("high-z", "z-tenant", u32::MAX, 5),
        ];

        let (allocs, audit) =
            run_cycle(&items, &cfg, "c-skip", "tr-skip", "ts").expect("cycle succeeds");

        assert_eq!(allocs.len(), 1);
        assert_eq!(allocs[0].tenant_id, "a-tenant");
        assert_eq!(allocs[0].items_allocated, vec!["low-a".to_string()]);
        assert_eq!(audit.tenants_skipped, 1);
    }

    #[test]
    fn cap_smaller_than_fairness_leaves_later_tenants_unserved() {
        let cfg = RepairConfig {
            max_units_per_cycle: 1,
            fairness_minimum: 5,
            max_tenants_per_cycle: 10,
        };
        let items = vec![item("a-work", "a", 10, 5), item("b-work", "b", 10, 5)];

        let (allocs, audit) =
            run_cycle(&items, &cfg, "c-cap-small", "tr-cap-small", "ts").expect("cycle succeeds");

        assert_eq!(audit.total_units_used, 1);
        assert_eq!(audit.tenants_served, 1);
        assert_eq!(allocs[0].tenant_id, "a");
        assert_eq!(allocs[0].units_used, 1);
        assert_eq!(allocs[1].tenant_id, "b");
        assert!(allocs[1].items_allocated.is_empty());
    }

    #[test]
    fn empty_cycle_id_rejected_before_audit_creation() {
        let err = run_cycle(&[item("r1", "t1", 5, 10)], &config(), "", "tr", "ts").unwrap_err();

        assert_eq!(
            err,
            RepairError::InvalidConfig {
                reason: "cycle_id must be non-empty and unpadded".to_string()
            }
        );
    }

    #[test]
    fn padded_cycle_id_rejected_before_audit_creation() {
        let err = run_cycle(&[item("r1", "t1", 5, 10)], &config(), " c1", "tr", "ts").unwrap_err();

        assert_eq!(
            err,
            RepairError::InvalidConfig {
                reason: "cycle_id must be non-empty and unpadded".to_string()
            }
        );
    }

    #[test]
    fn whitespace_trace_id_rejected_before_audit_creation() {
        let err = run_cycle(&[item("r1", "t1", 5, 10)], &config(), "c1", " \t", "ts").unwrap_err();

        assert_eq!(
            err,
            RepairError::InvalidConfig {
                reason: "trace_id must be non-empty and unpadded".to_string()
            }
        );
    }

    #[test]
    fn padded_trace_id_rejected_before_audit_creation() {
        let err = run_cycle(&[item("r1", "t1", 5, 10)], &config(), "c1", "tr ", "ts").unwrap_err();

        assert_eq!(
            err,
            RepairError::InvalidConfig {
                reason: "trace_id must be non-empty and unpadded".to_string()
            }
        );
    }

    #[test]
    fn empty_timestamp_rejected_before_audit_creation() {
        let err = run_cycle(&[item("r1", "t1", 5, 10)], &config(), "c1", "tr", "").unwrap_err();

        assert_eq!(
            err,
            RepairError::InvalidConfig {
                reason: "timestamp must be non-empty and unpadded".to_string()
            }
        );
    }

    #[test]
    fn padded_timestamp_rejected_before_audit_creation() {
        let err = run_cycle(&[item("r1", "t1", 5, 10)], &config(), "c1", "tr", " ts").unwrap_err();

        assert_eq!(
            err,
            RepairError::InvalidConfig {
                reason: "timestamp must be non-empty and unpadded".to_string()
            }
        );
    }

    #[test]
    fn empty_item_id_rejected_before_allocation() {
        let err = run_cycle(&[item("", "t1", 5, 10)], &config(), "c1", "tr", "ts").unwrap_err();

        assert_eq!(
            err,
            RepairError::InvalidConfig {
                reason: "item_id must be non-empty and unpadded".to_string()
            }
        );
    }

    #[test]
    fn padded_item_id_rejected_before_allocation() {
        let err = run_cycle(&[item(" r1 ", "t1", 5, 10)], &config(), "c1", "tr", "ts").unwrap_err();

        assert_eq!(
            err,
            RepairError::InvalidConfig {
                reason: "item_id must be non-empty and unpadded".to_string()
            }
        );
    }

    #[test]
    fn empty_tenant_id_rejected_before_allocation() {
        let err = run_cycle(&[item("r1", "", 5, 10)], &config(), "c1", "tr", "ts").unwrap_err();

        assert_eq!(
            err,
            RepairError::InvalidConfig {
                reason: "tenant_id must be non-empty and unpadded".to_string()
            }
        );
    }

    #[test]
    fn padded_tenant_id_rejected_before_allocation() {
        let err = run_cycle(&[item("r1", "\tt1", 5, 10)], &config(), "c1", "tr", "ts").unwrap_err();

        assert_eq!(
            err,
            RepairError::InvalidConfig {
                reason: "tenant_id must be non-empty and unpadded".to_string()
            }
        );
    }

    #[test]
    fn duplicate_item_id_rejected_before_allocation() {
        let items = vec![item("dup", "a", 10, 5), item("dup", "b", 1, 5)];
        let err = run_cycle(&items, &config(), "c1", "tr", "ts").unwrap_err();

        assert_eq!(
            err,
            RepairError::InvalidConfig {
                reason: "duplicate item_id: dup".to_string()
            }
        );
    }

    #[test]
    fn duplicate_item_id_same_tenant_rejected_before_allocation() {
        let items = vec![
            item("dup-same", "tenant", 10, 5),
            item("dup-same", "tenant", 1, 5),
        ];

        let err = run_cycle(&items, &config(), "c1", "tr", "ts").unwrap_err();

        assert_eq!(
            err,
            RepairError::InvalidConfig {
                reason: "duplicate item_id: dup-same".to_string()
            }
        );
    }

    #[test]
    fn zero_cap_config_precedes_blank_cycle_metadata() {
        let cfg = RepairConfig {
            max_units_per_cycle: 0,
            ..config()
        };

        let err = run_cycle(&[item("r1", "t1", 5, 10)], &cfg, "", "", "").unwrap_err();

        assert_eq!(
            err,
            RepairError::InvalidConfig {
                reason: "max_units_per_cycle must be > 0".to_string()
            }
        );
    }

    #[test]
    fn u64_max_item_size_is_clamped_to_fairness_allocation() {
        let items = vec![item("huge", "tenant-huge", 10, u64::MAX)];

        let (allocs, audit) =
            run_cycle(&items, &config(), "c-huge", "tr-huge", "ts").expect("cycle succeeds");

        assert_eq!(allocs.len(), 1);
        assert_eq!(allocs[0].units_used, config().fairness_minimum);
        assert_eq!(audit.total_units_used, config().fairness_minimum);
        assert_eq!(audit.cap, config().max_units_per_cycle);
    }

    #[test]
    fn negative_no_pending_precedes_blank_cycle_metadata() {
        let err = run_cycle(&[], &config(), "", "", "").unwrap_err();

        assert_eq!(err, RepairError::NoPending);
    }

    #[test]
    fn negative_invalid_config_precedes_duplicate_item_ids() {
        let cfg = RepairConfig {
            max_units_per_cycle: 0,
            ..config()
        };
        let items = vec![item("dup", "a", 10, 5), item("dup", "b", 1, 5)];

        let err = run_cycle(&items, &cfg, "c1", "tr", "ts").unwrap_err();

        assert_eq!(
            err,
            RepairError::InvalidConfig {
                reason: "max_units_per_cycle must be > 0".to_string()
            }
        );
    }

    #[test]
    fn negative_duplicate_item_id_in_skipped_tenant_is_rejected() {
        let cfg = RepairConfig {
            max_tenants_per_cycle: 1,
            ..config()
        };
        let items = vec![item("dup", "a-tenant", 10, 5), item("dup", "z-tenant", 1, 5)];

        let err = run_cycle(&items, &cfg, "c1", "tr", "ts").unwrap_err();

        assert_eq!(
            err,
            RepairError::InvalidConfig {
                reason: "duplicate item_id: dup".to_string()
            }
        );
    }

    #[test]
    fn negative_blank_item_id_in_skipped_tenant_is_rejected() {
        let cfg = RepairConfig {
            max_tenants_per_cycle: 1,
            ..config()
        };
        let items = vec![item("ok", "a-tenant", 10, 5), item("", "z-tenant", 1, 5)];

        let err = run_cycle(&items, &cfg, "c1", "tr", "ts").unwrap_err();

        assert_eq!(
            err,
            RepairError::InvalidConfig {
                reason: "item_id must be non-empty and unpadded".to_string()
            }
        );
    }

    #[test]
    fn negative_padded_tenant_id_in_late_item_is_rejected_before_tenant_limit() {
        let cfg = RepairConfig {
            max_tenants_per_cycle: 1,
            ..config()
        };
        let items = vec![item("ok", "a-tenant", 10, 5), item("late", " z-tenant", 1, 5)];

        let err = run_cycle(&items, &cfg, "c1", "tr", "ts").unwrap_err();

        assert_eq!(
            err,
            RepairError::InvalidConfig {
                reason: "tenant_id must be non-empty and unpadded".to_string()
            }
        );
    }

    #[test]
    fn negative_zero_sized_high_priority_item_does_not_block_billable_work() {
        let items = vec![
            item("zero-high", "tenant", u32::MAX, 0),
            item("billable-low", "tenant", 1, 5),
        ];

        let (allocs, audit) =
            run_cycle(&items, &config(), "c-zero-high", "tr-zero-high", "ts")
                .expect("cycle succeeds");

        assert_eq!(allocs.len(), 1);
        assert_eq!(allocs[0].items_allocated, vec!["billable-low".to_string()]);
        assert_eq!(allocs[0].units_used, 5);
        assert_eq!(audit.tenants_served, 1);
        assert_eq!(audit.total_units_used, 5);
    }

    #[test]
    fn negative_zero_sized_tenant_does_not_inflate_served_count() {
        let items = vec![item("zero", "a-zero", 10, 0), item("work", "b-work", 10, 5)];

        let (allocs, audit) =
            run_cycle(&items, &config(), "c-zero-tenant", "tr-zero-tenant", "ts")
                .expect("cycle succeeds");

        assert_eq!(allocs.len(), 2);
        assert!(allocs[0].items_allocated.is_empty());
        assert_eq!(allocs[0].units_used, 0);
        assert_eq!(allocs[1].items_allocated, vec!["work".to_string()]);
        assert_eq!(audit.tenants_served, 1);
        assert_eq!(audit.total_units_used, 5);
    }

    #[test]
    fn negative_extreme_fairness_minimum_still_respects_cycle_cap() {
        let cfg = RepairConfig {
            max_units_per_cycle: 3,
            fairness_minimum: u64::MAX,
            max_tenants_per_cycle: 10,
        };
        let items = vec![item("huge", "tenant", 10, u64::MAX)];

        let (allocs, audit) =
            run_cycle(&items, &cfg, "c-extreme-fair", "tr-extreme-fair", "ts")
                .expect("cycle succeeds");

        assert_eq!(allocs.len(), 1);
        assert_eq!(allocs[0].units_used, 3);
        assert_eq!(audit.total_units_used, cfg.max_units_per_cycle);
        assert_eq!(audit.cap, cfg.max_units_per_cycle);
    }
}
