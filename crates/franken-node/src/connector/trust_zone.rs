// Zone/tenant trust segmentation engine (bd-1vp).
//
// Partitions the trust domain into isolated zones, each with its own policy
// namespace, key bindings, token scope, and delegation depth limit.  Cross-zone
// operations require explicit, auditable dual-owner bridge authorization.

use std::collections::HashMap;
use std::fmt;

// ---------------------------------------------------------------------------
// Event codes
// ---------------------------------------------------------------------------

/// ZTS-001: Zone registered.
pub const EVT_ZONE_REGISTERED: &str = "ZTS-001";
/// ZTS-002: Tenant bound to zone.
pub const EVT_TENANT_BOUND: &str = "ZTS-002";
/// ZTS-003: Cross-zone action authorized.
pub const EVT_CROSS_ZONE_AUTHORIZED: &str = "ZTS-003";
/// ZTS-004: Isolation violation detected.
pub const EVT_ISOLATION_VIOLATION: &str = "ZTS-004";

// ---------------------------------------------------------------------------
// Error codes (stable error taxonomy)
// ---------------------------------------------------------------------------

pub const ERR_ZTS_CROSS_ZONE_VIOLATION: &str = "ERR_ZTS_CROSS_ZONE_VIOLATION";
pub const ERR_ZTS_TENANT_NOT_BOUND: &str = "ERR_ZTS_TENANT_NOT_BOUND";
pub const ERR_ZTS_ZONE_NOT_FOUND: &str = "ERR_ZTS_ZONE_NOT_FOUND";
pub const ERR_ZTS_DELEGATION_EXCEEDED: &str = "ERR_ZTS_DELEGATION_EXCEEDED";
pub const ERR_ZTS_ISOLATION_VIOLATION: &str = "ERR_ZTS_ISOLATION_VIOLATION";
pub const ERR_ZTS_DUPLICATE_ZONE: &str = "ERR_ZTS_DUPLICATE_ZONE";
pub const ERR_ZTS_DUPLICATE_TENANT: &str = "ERR_ZTS_DUPLICATE_TENANT";
pub const ERR_ZTS_BRIDGE_INCOMPLETE: &str = "ERR_ZTS_BRIDGE_INCOMPLETE";
pub const ERR_ZTS_FRESHNESS_STALE: &str = "ERR_ZTS_FRESHNESS_STALE";
pub const ERR_ZTS_KEY_ZONE_MISMATCH: &str = "ERR_ZTS_KEY_ZONE_MISMATCH";

// ---------------------------------------------------------------------------
// Invariant constants
// ---------------------------------------------------------------------------

pub const INV_ZTS_ISOLATE: &str = "INV-ZTS-ISOLATE";
pub const INV_ZTS_CEILING: &str = "INV-ZTS-CEILING";
pub const INV_ZTS_DEPTH: &str = "INV-ZTS-DEPTH";
pub const INV_ZTS_BIND: &str = "INV-ZTS-BIND";

// ---------------------------------------------------------------------------
// IsolationLevel
// ---------------------------------------------------------------------------

/// Isolation enforcement level for a zone.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IsolationLevel {
    /// No cross-zone communication unless explicit bridge exists.
    Strict,
    /// Cross-zone reads allowed; writes require bridge authorization.
    Permissive,
    /// Operator-defined isolation rules.
    Custom,
}

impl fmt::Display for IsolationLevel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Strict => write!(f, "strict"),
            Self::Permissive => write!(f, "permissive"),
            Self::Custom => write!(f, "custom"),
        }
    }
}

// ---------------------------------------------------------------------------
// ZonePolicy
// ---------------------------------------------------------------------------

/// Per-zone trust configuration.
#[derive(Debug, Clone)]
pub struct ZonePolicy {
    /// Globally unique zone identifier (domain-separated).
    pub zone_id: String,
    /// Maximum trust score allowed in this zone (0-100).
    pub trust_ceiling: u32,
    /// Maximum delegation chain depth within zone.
    pub delegation_depth_limit: u32,
    /// Zone IDs this zone may bridge to.
    pub allowed_cross_zone_targets: Vec<String>,
    /// Isolation enforcement level.
    pub isolation_level: IsolationLevel,
    /// Zone owner identity.
    pub owner: String,
    /// Zone-scoped key bindings (key_id -> zone_id).
    pub key_bindings: Vec<String>,
}

// ---------------------------------------------------------------------------
// TenantBinding
// ---------------------------------------------------------------------------

/// Binds a tenant to exactly one zone.
#[derive(Debug, Clone)]
pub struct TenantBinding {
    /// Unique tenant identifier.
    pub tenant_id: String,
    /// Zone this tenant is bound to.
    pub zone_id: String,
    /// Scoped trust capabilities for this tenant.
    pub trust_scope: String,
    /// Maximum number of trust extensions allowed.
    pub max_extension_count: u32,
}

// ---------------------------------------------------------------------------
// CrossZoneRequest
// ---------------------------------------------------------------------------

/// Request to perform an action across zone boundaries.
#[derive(Debug, Clone)]
pub struct CrossZoneRequest {
    /// Zone originating the request.
    pub source_zone: String,
    /// Zone where the action will take effect.
    pub target_zone: String,
    /// Action descriptor.
    pub action: String,
    /// Identity of the requesting entity.
    pub requester: String,
    /// Dual-owner bridge token or authorization proof.
    pub authorization_proof: String,
}

// ---------------------------------------------------------------------------
// SegmentationError
// ---------------------------------------------------------------------------

/// Error enumeration for zone segmentation failures.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SegmentationError {
    /// Action crosses zone boundary without authorization.
    CrossZoneViolation {
        source_zone: String,
        target_zone: String,
    },
    /// Tenant has no zone binding.
    TenantNotBound { tenant_id: String },
    /// Referenced zone does not exist.
    ZoneNotFound { zone_id: String },
    /// Delegation chain depth exceeds zone's configured limit.
    DelegationDepthExceeded {
        zone_id: String,
        limit: u32,
        actual: u32,
    },
    /// Action violates zone isolation level policy.
    IsolationViolation {
        zone_id: String,
        level: IsolationLevel,
    },
    /// Attempted to register a zone with an existing zone_id.
    DuplicateZone { zone_id: String },
    /// Tenant is already bound to a zone.
    DuplicateTenant {
        tenant_id: String,
        existing_zone: String,
    },
    /// Cross-zone bridge lacks dual-owner authorization.
    BridgeAuthIncomplete { detail: String },
    /// Zone deletion blocked -- freshness proof is stale.
    FreshnessStale { zone_id: String },
    /// Key not bound to the target zone.
    KeyZoneMismatch {
        key_id: String,
        expected_zone: String,
    },
}

impl fmt::Display for SegmentationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::CrossZoneViolation {
                source_zone,
                target_zone,
            } => {
                write!(
                    f,
                    "{ERR_ZTS_CROSS_ZONE_VIOLATION}: {source_zone} -> {target_zone}"
                )
            }
            Self::TenantNotBound { tenant_id } => {
                write!(f, "{ERR_ZTS_TENANT_NOT_BOUND}: {tenant_id}")
            }
            Self::ZoneNotFound { zone_id } => {
                write!(f, "{ERR_ZTS_ZONE_NOT_FOUND}: {zone_id}")
            }
            Self::DelegationDepthExceeded {
                zone_id,
                limit,
                actual,
            } => {
                write!(
                    f,
                    "{ERR_ZTS_DELEGATION_EXCEEDED}: {zone_id} limit={limit} actual={actual}"
                )
            }
            Self::IsolationViolation { zone_id, level } => {
                write!(f, "{ERR_ZTS_ISOLATION_VIOLATION}: {zone_id} level={level}")
            }
            Self::DuplicateZone { zone_id } => {
                write!(f, "{ERR_ZTS_DUPLICATE_ZONE}: {zone_id}")
            }
            Self::DuplicateTenant {
                tenant_id,
                existing_zone,
            } => {
                write!(
                    f,
                    "{ERR_ZTS_DUPLICATE_TENANT}: {tenant_id} already in {existing_zone}"
                )
            }
            Self::BridgeAuthIncomplete { detail } => {
                write!(f, "{ERR_ZTS_BRIDGE_INCOMPLETE}: {detail}")
            }
            Self::FreshnessStale { zone_id } => {
                write!(f, "{ERR_ZTS_FRESHNESS_STALE}: {zone_id}")
            }
            Self::KeyZoneMismatch {
                key_id,
                expected_zone,
            } => {
                write!(
                    f,
                    "{ERR_ZTS_KEY_ZONE_MISMATCH}: key={key_id} zone={expected_zone}"
                )
            }
        }
    }
}

impl std::error::Error for SegmentationError {}

// ---------------------------------------------------------------------------
// ZoneSegmentationEngine
// ---------------------------------------------------------------------------

/// Core engine managing zone lifecycle and cross-zone authorization.
#[derive(Debug, Default)]
pub struct ZoneSegmentationEngine {
    zones: HashMap<String, ZonePolicy>,
    tenants: HashMap<String, TenantBinding>,
    resource_zone_map: HashMap<String, String>,
    events: Vec<ZoneEvent>,
}

/// Recorded zone event for audit trail.
#[derive(Debug, Clone)]
pub struct ZoneEvent {
    pub code: String,
    pub zone_id: String,
    pub detail: String,
}

impl ZoneSegmentationEngine {
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a new zone with its policy.
    pub fn register_zone(&mut self, policy: ZonePolicy) -> Result<(), SegmentationError> {
        if self.zones.contains_key(&policy.zone_id) {
            return Err(SegmentationError::DuplicateZone {
                zone_id: policy.zone_id.clone(),
            });
        }
        let zone_id = policy.zone_id.clone();
        self.zones.insert(zone_id.clone(), policy);
        self.events.push(ZoneEvent {
            code: EVT_ZONE_REGISTERED.to_string(),
            zone_id: zone_id.clone(),
            detail: format!("Zone registered: {zone_id}"),
        });
        Ok(())
    }

    /// Bind a tenant to a zone.
    pub fn bind_tenant(&mut self, binding: TenantBinding) -> Result<(), SegmentationError> {
        // INV-ZTS-BIND: Tenants bound to exactly one zone.
        if let Some(existing) = self.tenants.get(&binding.tenant_id) {
            return Err(SegmentationError::DuplicateTenant {
                tenant_id: binding.tenant_id.clone(),
                existing_zone: existing.zone_id.clone(),
            });
        }
        if !self.zones.contains_key(&binding.zone_id) {
            return Err(SegmentationError::ZoneNotFound {
                zone_id: binding.zone_id.clone(),
            });
        }
        let tenant_id = binding.tenant_id.clone();
        let zone_id = binding.zone_id.clone();
        self.tenants.insert(tenant_id.clone(), binding);
        self.events.push(ZoneEvent {
            code: EVT_TENANT_BOUND.to_string(),
            zone_id: zone_id.clone(),
            detail: format!("Tenant {tenant_id} bound to zone {zone_id}"),
        });
        Ok(())
    }

    /// Authorize a cross-zone action.
    ///
    /// INV-ZTS-ISOLATE: Zone actions cannot affect other zones without explicit
    /// cross-zone authorization.
    pub fn authorize_cross_zone(&self, req: &CrossZoneRequest) -> Result<(), SegmentationError> {
        // Verify both zones exist.
        let source =
            self.zones
                .get(&req.source_zone)
                .ok_or_else(|| SegmentationError::ZoneNotFound {
                    zone_id: req.source_zone.clone(),
                })?;
        if !self.zones.contains_key(&req.target_zone) {
            return Err(SegmentationError::ZoneNotFound {
                zone_id: req.target_zone.clone(),
            });
        }

        // Check isolation level.
        match source.isolation_level {
            IsolationLevel::Strict => {
                // Strict: requires explicit bridge.
                if !source.allowed_cross_zone_targets.contains(&req.target_zone) {
                    return Err(SegmentationError::IsolationViolation {
                        zone_id: req.source_zone.clone(),
                        level: IsolationLevel::Strict,
                    });
                }
            }
            IsolationLevel::Permissive => {
                // Permissive: reads allowed, writes require bridge.
                if (req.action.contains("write") || req.action.contains("delete"))
                    && !source.allowed_cross_zone_targets.contains(&req.target_zone)
                {
                    return Err(SegmentationError::IsolationViolation {
                        zone_id: req.source_zone.clone(),
                        level: IsolationLevel::Permissive,
                    });
                }
            }
            IsolationLevel::Custom => {
                // Custom isolation: check bridge list for any action.
                if !source.allowed_cross_zone_targets.contains(&req.target_zone) {
                    return Err(SegmentationError::IsolationViolation {
                        zone_id: req.source_zone.clone(),
                        level: IsolationLevel::Custom,
                    });
                }
            }
        }

        // Verify dual-owner authorization proof.
        if req.authorization_proof.is_empty() {
            return Err(SegmentationError::BridgeAuthIncomplete {
                detail: "empty authorization_proof".to_string(),
            });
        }
        // Convention: dual-owner proof contains both zone IDs separated by ":".
        if !req.authorization_proof.contains(&req.source_zone)
            || !req.authorization_proof.contains(&req.target_zone)
        {
            return Err(SegmentationError::BridgeAuthIncomplete {
                detail: format!(
                    "proof must reference both zones: {} and {}",
                    req.source_zone, req.target_zone
                ),
            });
        }

        Ok(())
    }

    /// Query isolation level for a zone.
    pub fn check_isolation(&self, zone_id: &str) -> Result<IsolationLevel, SegmentationError> {
        self.zones
            .get(zone_id)
            .map(|z| z.isolation_level)
            .ok_or_else(|| SegmentationError::ZoneNotFound {
                zone_id: zone_id.to_string(),
            })
    }

    /// Resolve which zone owns a resource.
    pub fn resolve_zone(&self, resource_id: &str) -> Result<String, SegmentationError> {
        self.resource_zone_map
            .get(resource_id)
            .cloned()
            .ok_or_else(|| SegmentationError::ZoneNotFound {
                zone_id: format!("no zone for resource {resource_id}"),
            })
    }

    /// Register a resource-to-zone mapping.
    pub fn register_resource(
        &mut self,
        resource_id: &str,
        zone_id: &str,
    ) -> Result<(), SegmentationError> {
        if !self.zones.contains_key(zone_id) {
            return Err(SegmentationError::ZoneNotFound {
                zone_id: zone_id.to_string(),
            });
        }
        self.resource_zone_map
            .insert(resource_id.to_string(), zone_id.to_string());
        Ok(())
    }

    /// Delete a zone (requires freshness proof).
    pub fn delete_zone(
        &mut self,
        zone_id: &str,
        freshness_proof: Option<&str>,
    ) -> Result<(), SegmentationError> {
        if !self.zones.contains_key(zone_id) {
            return Err(SegmentationError::ZoneNotFound {
                zone_id: zone_id.to_string(),
            });
        }
        // Freshness gate: deletion without proof is rejected.
        match freshness_proof {
            Some(proof) if !proof.is_empty() => {}
            _ => {
                return Err(SegmentationError::FreshnessStale {
                    zone_id: zone_id.to_string(),
                });
            }
        }
        self.zones.remove(zone_id);
        // Remove associated tenant bindings.
        self.tenants.retain(|_, b| b.zone_id != zone_id);
        // Remove resource mappings.
        self.resource_zone_map.retain(|_, z| z != zone_id);
        Ok(())
    }

    /// Check delegation depth against zone limit.
    ///
    /// INV-ZTS-DEPTH: Delegation chains deeper than `delegation_depth_limit`
    /// are rejected.
    pub fn check_delegation_depth(
        &self,
        zone_id: &str,
        depth: u32,
    ) -> Result<(), SegmentationError> {
        let zone = self
            .zones
            .get(zone_id)
            .ok_or_else(|| SegmentationError::ZoneNotFound {
                zone_id: zone_id.to_string(),
            })?;
        if depth > zone.delegation_depth_limit {
            return Err(SegmentationError::DelegationDepthExceeded {
                zone_id: zone_id.to_string(),
                limit: zone.delegation_depth_limit,
                actual: depth,
            });
        }
        Ok(())
    }

    /// Verify trust score against zone ceiling.
    ///
    /// INV-ZTS-CEILING: No entity within a zone may exceed the zone's
    /// configured trust ceiling score.
    pub fn check_trust_ceiling(&self, zone_id: &str, score: u32) -> Result<(), SegmentationError> {
        let zone = self
            .zones
            .get(zone_id)
            .ok_or_else(|| SegmentationError::ZoneNotFound {
                zone_id: zone_id.to_string(),
            })?;
        if score > zone.trust_ceiling {
            return Err(SegmentationError::IsolationViolation {
                zone_id: zone_id.to_string(),
                level: zone.isolation_level,
            });
        }
        Ok(())
    }

    /// Verify a key is bound to the target zone.
    pub fn check_key_binding(&self, zone_id: &str, key_id: &str) -> Result<(), SegmentationError> {
        let zone = self
            .zones
            .get(zone_id)
            .ok_or_else(|| SegmentationError::ZoneNotFound {
                zone_id: zone_id.to_string(),
            })?;
        if !zone.key_bindings.contains(&key_id.to_string()) {
            return Err(SegmentationError::KeyZoneMismatch {
                key_id: key_id.to_string(),
                expected_zone: zone_id.to_string(),
            });
        }
        Ok(())
    }

    /// Get tenant binding for a tenant.
    pub fn get_tenant(&self, tenant_id: &str) -> Result<&TenantBinding, SegmentationError> {
        self.tenants
            .get(tenant_id)
            .ok_or_else(|| SegmentationError::TenantNotBound {
                tenant_id: tenant_id.to_string(),
            })
    }

    /// Get all recorded events.
    pub fn events(&self) -> &[ZoneEvent] {
        &self.events
    }

    /// Get the number of registered zones.
    pub fn zone_count(&self) -> usize {
        self.zones.len()
    }

    /// Get the number of bound tenants.
    pub fn tenant_count(&self) -> usize {
        self.tenants.len()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn make_engine() -> ZoneSegmentationEngine {
        ZoneSegmentationEngine::new()
    }

    fn make_policy(zone_id: &str) -> ZonePolicy {
        ZonePolicy {
            zone_id: zone_id.to_string(),
            trust_ceiling: 90,
            delegation_depth_limit: 3,
            allowed_cross_zone_targets: vec![],
            isolation_level: IsolationLevel::Strict,
            owner: format!("owner-{zone_id}"),
            key_bindings: vec![format!("key-{zone_id}")],
        }
    }

    fn make_binding(tenant_id: &str, zone_id: &str) -> TenantBinding {
        TenantBinding {
            tenant_id: tenant_id.to_string(),
            zone_id: zone_id.to_string(),
            trust_scope: "full".to_string(),
            max_extension_count: 10,
        }
    }

    // -- Zone registration --

    #[test]
    fn test_register_zone() {
        let mut engine = make_engine();
        assert!(engine.register_zone(make_policy("zone-a")).is_ok());
        assert_eq!(engine.zone_count(), 1);
    }

    #[test]
    fn test_duplicate_zone_rejected() {
        let mut engine = make_engine();
        engine.register_zone(make_policy("zone-a")).unwrap();
        let err = engine.register_zone(make_policy("zone-a")).unwrap_err();
        assert!(matches!(err, SegmentationError::DuplicateZone { .. }));
    }

    #[test]
    fn test_register_multiple_zones() {
        let mut engine = make_engine();
        engine.register_zone(make_policy("zone-a")).unwrap();
        engine.register_zone(make_policy("zone-b")).unwrap();
        assert_eq!(engine.zone_count(), 2);
    }

    // -- Tenant binding --

    #[test]
    fn test_bind_tenant() {
        let mut engine = make_engine();
        engine.register_zone(make_policy("zone-a")).unwrap();
        assert!(
            engine
                .bind_tenant(make_binding("team-alpha", "zone-a"))
                .is_ok()
        );
        assert_eq!(engine.tenant_count(), 1);
    }

    #[test]
    fn test_duplicate_tenant_rejected() {
        let mut engine = make_engine();
        engine.register_zone(make_policy("zone-a")).unwrap();
        engine
            .bind_tenant(make_binding("team-alpha", "zone-a"))
            .unwrap();
        let err = engine
            .bind_tenant(make_binding("team-alpha", "zone-a"))
            .unwrap_err();
        assert!(matches!(err, SegmentationError::DuplicateTenant { .. }));
    }

    #[test]
    fn test_bind_tenant_to_nonexistent_zone() {
        let mut engine = make_engine();
        let err = engine
            .bind_tenant(make_binding("team-alpha", "nonexistent"))
            .unwrap_err();
        assert!(matches!(err, SegmentationError::ZoneNotFound { .. }));
    }

    #[test]
    fn test_get_tenant() {
        let mut engine = make_engine();
        engine.register_zone(make_policy("zone-a")).unwrap();
        engine
            .bind_tenant(make_binding("team-alpha", "zone-a"))
            .unwrap();
        let tenant = engine.get_tenant("team-alpha").unwrap();
        assert_eq!(tenant.zone_id, "zone-a");
    }

    #[test]
    fn test_get_unbound_tenant() {
        let engine = make_engine();
        let err = engine.get_tenant("nobody").unwrap_err();
        assert!(matches!(err, SegmentationError::TenantNotBound { .. }));
    }

    // -- Cross-zone authorization --

    #[test]
    fn test_cross_zone_authorized_with_bridge() {
        let mut engine = make_engine();
        let mut pa = make_policy("zone-a");
        pa.allowed_cross_zone_targets = vec!["zone-b".to_string()];
        engine.register_zone(pa).unwrap();
        engine.register_zone(make_policy("zone-b")).unwrap();

        let req = CrossZoneRequest {
            source_zone: "zone-a".to_string(),
            target_zone: "zone-b".to_string(),
            action: "read".to_string(),
            requester: "entity-1".to_string(),
            authorization_proof: "signed:zone-a:zone-b".to_string(),
        };
        assert!(engine.authorize_cross_zone(&req).is_ok());
    }

    #[test]
    fn test_cross_zone_violation_no_bridge() {
        let mut engine = make_engine();
        engine.register_zone(make_policy("zone-a")).unwrap();
        engine.register_zone(make_policy("zone-b")).unwrap();

        let req = CrossZoneRequest {
            source_zone: "zone-a".to_string(),
            target_zone: "zone-b".to_string(),
            action: "read".to_string(),
            requester: "entity-1".to_string(),
            authorization_proof: "signed:zone-a:zone-b".to_string(),
        };
        let err = engine.authorize_cross_zone(&req).unwrap_err();
        assert!(matches!(err, SegmentationError::IsolationViolation { .. }));
    }

    #[test]
    fn test_bridge_auth_incomplete_empty_proof() {
        let mut engine = make_engine();
        let mut pa = make_policy("zone-a");
        pa.allowed_cross_zone_targets = vec!["zone-b".to_string()];
        engine.register_zone(pa).unwrap();
        engine.register_zone(make_policy("zone-b")).unwrap();

        let req = CrossZoneRequest {
            source_zone: "zone-a".to_string(),
            target_zone: "zone-b".to_string(),
            action: "read".to_string(),
            requester: "entity-1".to_string(),
            authorization_proof: String::new(),
        };
        let err = engine.authorize_cross_zone(&req).unwrap_err();
        assert!(matches!(
            err,
            SegmentationError::BridgeAuthIncomplete { .. }
        ));
    }

    #[test]
    fn test_bridge_auth_incomplete_single_zone() {
        let mut engine = make_engine();
        let mut pa = make_policy("zone-a");
        pa.allowed_cross_zone_targets = vec!["zone-b".to_string()];
        engine.register_zone(pa).unwrap();
        engine.register_zone(make_policy("zone-b")).unwrap();

        let req = CrossZoneRequest {
            source_zone: "zone-a".to_string(),
            target_zone: "zone-b".to_string(),
            action: "read".to_string(),
            requester: "entity-1".to_string(),
            authorization_proof: "signed:zone-a".to_string(), // missing zone-b
        };
        let err = engine.authorize_cross_zone(&req).unwrap_err();
        assert!(matches!(
            err,
            SegmentationError::BridgeAuthIncomplete { .. }
        ));
    }

    #[test]
    fn test_cross_zone_nonexistent_source() {
        let mut engine = make_engine();
        engine.register_zone(make_policy("zone-b")).unwrap();
        let req = CrossZoneRequest {
            source_zone: "ghost".to_string(),
            target_zone: "zone-b".to_string(),
            action: "read".to_string(),
            requester: "entity-1".to_string(),
            authorization_proof: "signed:ghost:zone-b".to_string(),
        };
        let err = engine.authorize_cross_zone(&req).unwrap_err();
        assert!(matches!(err, SegmentationError::ZoneNotFound { .. }));
    }

    // -- Permissive isolation --

    #[test]
    fn test_permissive_read_allowed_without_bridge() {
        let mut engine = make_engine();
        let mut pa = make_policy("zone-a");
        pa.isolation_level = IsolationLevel::Permissive;
        engine.register_zone(pa).unwrap();
        engine.register_zone(make_policy("zone-b")).unwrap();

        let req = CrossZoneRequest {
            source_zone: "zone-a".to_string(),
            target_zone: "zone-b".to_string(),
            action: "read".to_string(),
            requester: "entity-1".to_string(),
            authorization_proof: "signed:zone-a:zone-b".to_string(),
        };
        assert!(engine.authorize_cross_zone(&req).is_ok());
    }

    #[test]
    fn test_permissive_write_requires_bridge() {
        let mut engine = make_engine();
        let mut pa = make_policy("zone-a");
        pa.isolation_level = IsolationLevel::Permissive;
        engine.register_zone(pa).unwrap();
        engine.register_zone(make_policy("zone-b")).unwrap();

        let req = CrossZoneRequest {
            source_zone: "zone-a".to_string(),
            target_zone: "zone-b".to_string(),
            action: "write".to_string(),
            requester: "entity-1".to_string(),
            authorization_proof: "signed:zone-a:zone-b".to_string(),
        };
        let err = engine.authorize_cross_zone(&req).unwrap_err();
        assert!(matches!(err, SegmentationError::IsolationViolation { .. }));
    }

    // -- Isolation level query --

    #[test]
    fn test_check_isolation() {
        let mut engine = make_engine();
        engine.register_zone(make_policy("zone-a")).unwrap();
        assert_eq!(
            engine.check_isolation("zone-a").unwrap(),
            IsolationLevel::Strict
        );
    }

    #[test]
    fn test_check_isolation_nonexistent() {
        let engine = make_engine();
        assert!(engine.check_isolation("ghost").is_err());
    }

    // -- Delegation depth --

    #[test]
    fn test_delegation_within_limit() {
        let mut engine = make_engine();
        engine.register_zone(make_policy("zone-a")).unwrap();
        assert!(engine.check_delegation_depth("zone-a", 2).is_ok());
    }

    #[test]
    fn test_delegation_at_limit() {
        let mut engine = make_engine();
        engine.register_zone(make_policy("zone-a")).unwrap();
        assert!(engine.check_delegation_depth("zone-a", 3).is_ok());
    }

    #[test]
    fn test_delegation_exceeded() {
        let mut engine = make_engine();
        engine.register_zone(make_policy("zone-a")).unwrap();
        let err = engine.check_delegation_depth("zone-a", 4).unwrap_err();
        assert!(matches!(
            err,
            SegmentationError::DelegationDepthExceeded {
                limit: 3,
                actual: 4,
                ..
            }
        ));
    }

    // -- Trust ceiling --

    #[test]
    fn test_trust_ceiling_within() {
        let mut engine = make_engine();
        engine.register_zone(make_policy("zone-a")).unwrap();
        assert!(engine.check_trust_ceiling("zone-a", 85).is_ok());
    }

    #[test]
    fn test_trust_ceiling_exceeded() {
        let mut engine = make_engine();
        engine.register_zone(make_policy("zone-a")).unwrap();
        let err = engine.check_trust_ceiling("zone-a", 95).unwrap_err();
        assert!(matches!(err, SegmentationError::IsolationViolation { .. }));
    }

    // -- Key binding --

    #[test]
    fn test_key_binding_valid() {
        let mut engine = make_engine();
        engine.register_zone(make_policy("zone-a")).unwrap();
        assert!(engine.check_key_binding("zone-a", "key-zone-a").is_ok());
    }

    #[test]
    fn test_key_binding_mismatch() {
        let mut engine = make_engine();
        engine.register_zone(make_policy("zone-a")).unwrap();
        let err = engine
            .check_key_binding("zone-a", "key-zone-b")
            .unwrap_err();
        assert!(matches!(err, SegmentationError::KeyZoneMismatch { .. }));
    }

    // -- Resource resolution --

    #[test]
    fn test_resolve_zone() {
        let mut engine = make_engine();
        engine.register_zone(make_policy("zone-a")).unwrap();
        engine.register_resource("res-1", "zone-a").unwrap();
        assert_eq!(engine.resolve_zone("res-1").unwrap(), "zone-a");
    }

    #[test]
    fn test_resolve_zone_not_found() {
        let engine = make_engine();
        assert!(engine.resolve_zone("unknown").is_err());
    }

    #[test]
    fn test_resolve_zone_deterministic() {
        let mut engine = make_engine();
        engine.register_zone(make_policy("zone-a")).unwrap();
        engine.register_resource("res-1", "zone-a").unwrap();
        let r1 = engine.resolve_zone("res-1").unwrap();
        let r2 = engine.resolve_zone("res-1").unwrap();
        assert_eq!(r1, r2);
    }

    // -- Zone deletion --

    #[test]
    fn test_delete_zone_with_proof() {
        let mut engine = make_engine();
        engine.register_zone(make_policy("zone-a")).unwrap();
        assert!(
            engine
                .delete_zone("zone-a", Some("fresh-proof-123"))
                .is_ok()
        );
        assert_eq!(engine.zone_count(), 0);
    }

    #[test]
    fn test_delete_zone_without_proof() {
        let mut engine = make_engine();
        engine.register_zone(make_policy("zone-a")).unwrap();
        let err = engine.delete_zone("zone-a", None).unwrap_err();
        assert!(matches!(err, SegmentationError::FreshnessStale { .. }));
    }

    #[test]
    fn test_delete_zone_empty_proof() {
        let mut engine = make_engine();
        engine.register_zone(make_policy("zone-a")).unwrap();
        let err = engine.delete_zone("zone-a", Some("")).unwrap_err();
        assert!(matches!(err, SegmentationError::FreshnessStale { .. }));
    }

    #[test]
    fn test_delete_zone_removes_tenants() {
        let mut engine = make_engine();
        engine.register_zone(make_policy("zone-a")).unwrap();
        engine.bind_tenant(make_binding("t1", "zone-a")).unwrap();
        engine.delete_zone("zone-a", Some("proof")).unwrap();
        assert_eq!(engine.tenant_count(), 0);
    }

    #[test]
    fn test_delete_nonexistent_zone() {
        let mut engine = make_engine();
        let err = engine.delete_zone("ghost", Some("proof")).unwrap_err();
        assert!(matches!(err, SegmentationError::ZoneNotFound { .. }));
    }

    // -- Events --

    #[test]
    fn test_zone_registered_event() {
        let mut engine = make_engine();
        engine.register_zone(make_policy("zone-a")).unwrap();
        let evts: Vec<_> = engine
            .events()
            .iter()
            .filter(|e| e.code == EVT_ZONE_REGISTERED)
            .collect();
        assert_eq!(evts.len(), 1);
        assert_eq!(evts[0].zone_id, "zone-a");
    }

    #[test]
    fn test_tenant_bound_event() {
        let mut engine = make_engine();
        engine.register_zone(make_policy("zone-a")).unwrap();
        engine.bind_tenant(make_binding("t1", "zone-a")).unwrap();
        let evts: Vec<_> = engine
            .events()
            .iter()
            .filter(|e| e.code == EVT_TENANT_BOUND)
            .collect();
        assert_eq!(evts.len(), 1);
    }

    // -- Error Display --

    #[test]
    fn test_error_display() {
        let err = SegmentationError::CrossZoneViolation {
            source_zone: "a".to_string(),
            target_zone: "b".to_string(),
        };
        let msg = format!("{err}");
        assert!(msg.contains(ERR_ZTS_CROSS_ZONE_VIOLATION));
    }

    #[test]
    fn test_isolation_level_display() {
        assert_eq!(format!("{}", IsolationLevel::Strict), "strict");
        assert_eq!(format!("{}", IsolationLevel::Permissive), "permissive");
        assert_eq!(format!("{}", IsolationLevel::Custom), "custom");
    }
}
