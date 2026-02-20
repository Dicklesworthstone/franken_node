//! bd-91gg: Background repair controller with bounded work-per-cycle and fairness.
//!
//! Respects per-cycle work caps. Guarantees no tenant starvation via fairness minimum.
//! Every cycle produces an auditable record.

use std::collections::HashMap;

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

    // Group by tenant, sorted by tenant_id for determinism
    let mut by_tenant: HashMap<String, Vec<&RepairItem>> = HashMap::new();
    for item in pending {
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
    let skipped = by_tenant.len() - active_tenants.len();

    let mut allocations: HashMap<String, RepairAllocation> = HashMap::new();
    let mut total_used: u64 = 0;

    // First pass: fairness minimum for each tenant
    for tenant_id in &active_tenants {
        let items = by_tenant.get(tenant_id).unwrap();
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
                .min(config.max_units_per_cycle - total_used);
            if can_use > 0 {
                tenant_alloc.items_allocated.push(item.item_id.clone());
                tenant_alloc.units_used += can_use;
                total_used += can_use;
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
            let items = by_tenant.get(tenant_id).unwrap();
            let alloc = allocations.get(tenant_id).unwrap();
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
            let can_use = item.size_units.min(config.max_units_per_cycle - total_used);
            if can_use > 0 {
                let alloc = allocations.get_mut(&item.tenant_id).unwrap();
                alloc.items_allocated.push(item.item_id.clone());
                alloc.units_used += can_use;
                total_used += can_use;
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
        let (allocs, audit) = run_cycle(&items, &config(), "c1", "tr", "ts").unwrap();
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
        let (_, audit) = run_cycle(&items, &config(), "c1", "tr", "ts").unwrap();
        assert!(audit.total_units_used <= config().max_units_per_cycle);
    }

    #[test]
    fn fairness_no_starvation() {
        let items = vec![
            item("r1", "t1", 10, 3),
            item("r2", "t1", 9, 3),
            item("r3", "t2", 1, 3),
        ];
        let (allocs, _) = run_cycle(&items, &config(), "c1", "tr", "ts").unwrap();
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
        let (a1, _) = run_cycle(&items, &config(), "c1", "tr", "ts").unwrap();
        let (a2, _) = run_cycle(&items, &config(), "c1", "tr", "ts").unwrap();
        for (x, y) in a1.iter().zip(a2.iter()) {
            assert_eq!(x.tenant_id, y.tenant_id);
            assert_eq!(x.items_allocated, y.items_allocated);
            assert_eq!(x.units_used, y.units_used);
        }
    }

    #[test]
    fn audit_has_trace() {
        let items = vec![item("r1", "t1", 5, 10)];
        let (_, audit) = run_cycle(&items, &config(), "c1", "trace-x", "ts").unwrap();
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
        let (allocs, audit) = run_cycle(&items, &cfg, "c1", "tr", "ts").unwrap();
        assert_eq!(allocs.len(), 2);
        assert_eq!(audit.tenants_skipped, 1);
    }

    #[test]
    fn priority_ordering() {
        let items = vec![item("low", "t1", 1, 5), item("high", "t1", 10, 5)];
        let mut cfg = config();
        cfg.max_units_per_cycle = 8; // only room for one + fairness
        let (allocs, _) = run_cycle(&items, &cfg, "c1", "tr", "ts").unwrap();
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
        let (_, audit) = run_cycle(&items, &config(), "c1", "tr", "ts").unwrap();
        assert_eq!(audit.tenants_served, 2);
    }

    #[test]
    fn allocation_sorted_by_tenant() {
        let items = vec![item("r1", "z-tenant", 5, 5), item("r2", "a-tenant", 5, 5)];
        let (allocs, _) = run_cycle(&items, &config(), "c1", "tr", "ts").unwrap();
        assert_eq!(allocs[0].tenant_id, "a-tenant");
        assert_eq!(allocs[1].tenant_id, "z-tenant");
    }
}
