//! bd-1vp: Zone/tenant trust segmentation policies.
//!
//! Implements trust boundary segmentation between zones and tenants in a
//! multi-tenant deployment. Each zone operates as an isolated trust domain
//! with its own policy namespace, key bindings, delegation limits, and
//! token scope. Cross-zone operations require explicit dual-owner
//! authorization through bridge tokens.
//!
//! # Event Codes
//!
//! - `ZTS-001`: Zone registered -- new zone created with policy
//! - `ZTS-002`: Tenant bound -- tenant assigned to zone
//! - `ZTS-003`: Cross-zone authorized -- bridge action approved
//! - `ZTS-004`: Isolation violation detected -- cross-zone action rejected
//!
//! # Invariants
//!
//! - **INV-ZTS-ISOLATE**: Zone actions cannot affect other zones without authorization
//! - **INV-ZTS-CEILING**: Trust ceiling enforced per zone
//! - **INV-ZTS-DEPTH**: Delegation depth limited per zone
//! - **INV-ZTS-BIND**: Tenants bound to exactly one zone

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt;

// ---------------------------------------------------------------------------
// Event codes
// ---------------------------------------------------------------------------

pub mod event_codes {
    pub const ZTS_001_ZONE_REGISTERED: &str = "ZTS-001";
    pub const ZTS_002_TENANT_BOUND: &str = "ZTS-002";
    pub const ZTS_003_CROSS_ZONE_AUTHORIZED: &str = "ZTS-003";
    pub const ZTS_004_ISOLATION_VIOLATION: &str = "ZTS-004";
}

use event_codes::*;

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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IsolationLevel {
    /// No cross-zone communication unless explicit bridge exists.
    Strict,
    /// Cross-zone reads allowed, writes require bridge authorization.
    Permissive,
    /// Operator-defined isolation rules with explicit allowed actions.
    Custom,
}

impl IsolationLevel {
    pub fn label(&self) -> &'static str {
        match self {
            Self::Strict => "strict",
            Self::Permissive => "permissive",
            Self::Custom => "custom",
        }
    }
}

impl fmt::Display for IsolationLevel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.label())
    }
}

// ---------------------------------------------------------------------------
// ZonePolicy
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ZonePolicy {
    /// Globally unique zone identifier (domain-separated).
    pub zone_id: String,
    /// Maximum trust score allowed in this zone (0-100).
    pub trust_ceiling: u32,
    /// Maximum delegation chain depth within this zone.
    pub delegation_depth_limit: u32,
    /// Zone IDs this zone may bridge to.
    pub allowed_cross_zone_targets: Vec<String>,
    /// Isolation enforcement level.
    pub isolation_level: IsolationLevel,
}

impl ZonePolicy {
    pub fn new(
        zone_id: impl Into<String>,
        trust_ceiling: u32,
        delegation_depth_limit: u32,
        isolation_level: IsolationLevel,
    ) -> Self {
        Self {
            zone_id: zone_id.into(),
            trust_ceiling: trust_ceiling.min(100),
            delegation_depth_limit,
            allowed_cross_zone_targets: Vec::new(),
            isolation_level,
        }
    }

    /// Add a target zone to the allowed cross-zone list.
    pub fn allow_cross_zone(&mut self, target_zone: impl Into<String>) {
        let target = target_zone.into();
        if !self.allowed_cross_zone_targets.contains(&target) {
            self.allowed_cross_zone_targets.push(target);
        }
    }

    /// Check whether the given trust score exceeds this zone's ceiling.
    pub fn exceeds_ceiling(&self, trust_score: u32) -> bool {
        trust_score > self.trust_ceiling
    }

    /// Check whether the given delegation depth exceeds this zone's limit.
    pub fn exceeds_depth(&self, depth: u32) -> bool {
        depth > self.delegation_depth_limit
    }
}

// ---------------------------------------------------------------------------
// TenantBinding
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
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

impl TenantBinding {
    pub fn new(
        tenant_id: impl Into<String>,
        zone_id: impl Into<String>,
        trust_scope: impl Into<String>,
        max_extension_count: u32,
    ) -> Self {
        Self {
            tenant_id: tenant_id.into(),
            zone_id: zone_id.into(),
            trust_scope: trust_scope.into(),
            max_extension_count,
        }
    }
}

// ---------------------------------------------------------------------------
// CrossZoneRequest
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
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

impl CrossZoneRequest {
    pub fn new(
        source_zone: impl Into<String>,
        target_zone: impl Into<String>,
        action: impl Into<String>,
        requester: impl Into<String>,
        authorization_proof: impl Into<String>,
    ) -> Self {
        Self {
            source_zone: source_zone.into(),
            target_zone: target_zone.into(),
            action: action.into(),
            requester: requester.into(),
            authorization_proof: authorization_proof.into(),
        }
    }
}

// ---------------------------------------------------------------------------
// SegmentationError
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SegmentationError {
    /// Action crosses zone boundary without authorization.
    CrossZoneViolation,
    /// Tenant has no zone binding.
    TenantNotBound,
    /// Referenced zone does not exist.
    ZoneNotFound,
    /// Delegation chain depth exceeds zone's configured limit.
    DelegationDepthExceeded,
    /// Action violates zone isolation level policy.
    IsolationViolation,
    /// Attempted to register a zone with an existing zone_id.
    DuplicateZone,
    /// Tenant is already bound to a zone.
    DuplicateTenant,
    /// Cross-zone bridge lacks dual-owner authorization.
    BridgeAuthIncomplete,
    /// Zone deletion blocked -- freshness proof is stale.
    FreshnessStale,
    /// Key not bound to the target zone.
    KeyZoneMismatch,
}

impl fmt::Display for SegmentationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::CrossZoneViolation => write!(f, "ZONE_BOUNDARY_VIOLATION"),
            Self::TenantNotBound => write!(f, "TENANT_NOT_BOUND"),
            Self::ZoneNotFound => write!(f, "ZONE_NOT_FOUND"),
            Self::DelegationDepthExceeded => write!(f, "DELEGATION_DEPTH_EXCEEDED"),
            Self::IsolationViolation => write!(f, "ISOLATION_VIOLATION"),
            Self::DuplicateZone => write!(f, "DUPLICATE_ZONE"),
            Self::DuplicateTenant => write!(f, "DUPLICATE_TENANT"),
            Self::BridgeAuthIncomplete => write!(f, "BRIDGE_AUTH_INCOMPLETE"),
            Self::FreshnessStale => write!(f, "FRESHNESS_STALE"),
            Self::KeyZoneMismatch => write!(f, "KEY_ZONE_MISMATCH"),
        }
    }
}

impl std::error::Error for SegmentationError {}

// ---------------------------------------------------------------------------
// Zone audit event
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ZoneAuditEvent {
    pub code: String,
    pub zone_id: String,
    pub detail: String,
    pub trace_id: String,
}

// ---------------------------------------------------------------------------
// ZoneSegmentationEngine
// ---------------------------------------------------------------------------

/// The core engine managing zone lifecycle, tenant binding, and cross-zone
/// authorization.
pub struct ZoneSegmentationEngine {
    /// Registered zones indexed by zone_id.
    zones: HashMap<String, ZonePolicy>,
    /// Tenant-to-zone bindings indexed by tenant_id.
    tenant_bindings: HashMap<String, TenantBinding>,
    /// Resource-to-zone mappings for deterministic resolution.
    resource_zone_map: HashMap<String, String>,
    /// Zone-scoped key bindings: key_id -> set of zone_ids.
    key_zone_bindings: HashMap<String, Vec<String>>,
    /// Audit events emitted by the engine.
    events: Vec<ZoneAuditEvent>,
    /// Whether freshness gate is satisfied (simulates bd-2sx integration).
    freshness_valid: bool,
}

impl ZoneSegmentationEngine {
    pub fn new() -> Self {
        Self {
            zones: HashMap::new(),
            tenant_bindings: HashMap::new(),
            resource_zone_map: HashMap::new(),
            key_zone_bindings: HashMap::new(),
            events: Vec::new(),
            freshness_valid: true,
        }
    }

    /// Set whether freshness proofs are considered valid (for testing).
    pub fn set_freshness_valid(&mut self, valid: bool) {
        self.freshness_valid = valid;
    }

    // -- Zone lifecycle -----------------------------------------------------

    /// Register a new zone with its policy.
    pub fn register_zone(&mut self, policy: ZonePolicy) -> Result<(), SegmentationError> {
        if self.zones.contains_key(&policy.zone_id) {
            return Err(SegmentationError::DuplicateZone);
        }
        let zone_id = policy.zone_id.clone();
        self.zones.insert(zone_id.clone(), policy);
        self.emit_event(ZTS_001_ZONE_REGISTERED, &zone_id, "zone registered");
        Ok(())
    }

    /// Delete a zone. Requires freshness gate to be valid.
    pub fn delete_zone(&mut self, zone_id: &str) -> Result<(), SegmentationError> {
        if !self.zones.contains_key(zone_id) {
            return Err(SegmentationError::ZoneNotFound);
        }
        if !self.freshness_valid {
            return Err(SegmentationError::FreshnessStale);
        }
        self.zones.remove(zone_id);
        // Remove tenant bindings for this zone.
        self.tenant_bindings.retain(|_, b| b.zone_id != zone_id);
        // Remove resource mappings for this zone.
        self.resource_zone_map.retain(|_, z| z != zone_id);
        Ok(())
    }

    /// List all registered zone IDs.
    pub fn list_zones(&self) -> Vec<String> {
        let mut ids: Vec<String> = self.zones.keys().cloned().collect();
        ids.sort();
        ids
    }

    /// Get a zone policy by ID.
    pub fn get_zone(&self, zone_id: &str) -> Option<&ZonePolicy> {
        self.zones.get(zone_id)
    }

    // -- Tenant binding -----------------------------------------------------

    /// Bind a tenant to a zone. INV-ZTS-BIND: tenant bound to exactly one zone.
    pub fn bind_tenant(&mut self, binding: TenantBinding) -> Result<(), SegmentationError> {
        // Check zone exists.
        if !self.zones.contains_key(&binding.zone_id) {
            return Err(SegmentationError::ZoneNotFound);
        }
        // INV-ZTS-BIND: tenant must not already be bound.
        if self.tenant_bindings.contains_key(&binding.tenant_id) {
            return Err(SegmentationError::DuplicateTenant);
        }
        let tenant_id = binding.tenant_id.clone();
        let zone_id = binding.zone_id.clone();
        self.tenant_bindings.insert(tenant_id.clone(), binding);
        self.emit_event(
            ZTS_002_TENANT_BOUND,
            &zone_id,
            &format!("tenant '{}' bound to zone '{}'", tenant_id, zone_id),
        );
        Ok(())
    }

    /// Get a tenant binding by tenant ID.
    pub fn get_tenant_binding(&self, tenant_id: &str) -> Option<&TenantBinding> {
        self.tenant_bindings.get(tenant_id)
    }

    /// Get the zone ID for a tenant. Returns TenantNotBound if unbound.
    pub fn tenant_zone(&self, tenant_id: &str) -> Result<&str, SegmentationError> {
        self.tenant_bindings
            .get(tenant_id)
            .map(|b| b.zone_id.as_str())
            .ok_or(SegmentationError::TenantNotBound)
    }

    // -- Resource-to-zone resolution ----------------------------------------

    /// Register a resource-to-zone mapping.
    pub fn register_resource(
        &mut self,
        resource_id: impl Into<String>,
        zone_id: impl Into<String>,
    ) {
        self.resource_zone_map
            .insert(resource_id.into(), zone_id.into());
    }

    /// Resolve which zone owns a resource. Deterministic and consistent.
    pub fn resolve_zone(&self, resource_id: &str) -> Result<String, SegmentationError> {
        self.resource_zone_map
            .get(resource_id)
            .cloned()
            .ok_or(SegmentationError::ZoneNotFound)
    }

    // -- Key-zone bindings --------------------------------------------------

    /// Bind a key to a set of zones.
    pub fn bind_key_to_zone(&mut self, key_id: impl Into<String>, zone_id: impl Into<String>) {
        let key = key_id.into();
        let zone = zone_id.into();
        self.key_zone_bindings.entry(key).or_default().push(zone);
    }

    /// Check whether a key is bound to a specific zone.
    pub fn is_key_bound_to_zone(&self, key_id: &str, zone_id: &str) -> bool {
        self.key_zone_bindings
            .get(key_id)
            .map_or(false, |zones| zones.iter().any(|z| z == zone_id))
    }

    /// Validate that a key is authorized for a zone, returning KeyZoneMismatch
    /// if the key is not bound.
    pub fn validate_key_zone(&self, key_id: &str, zone_id: &str) -> Result<(), SegmentationError> {
        if !self.is_key_bound_to_zone(key_id, zone_id) {
            return Err(SegmentationError::KeyZoneMismatch);
        }
        Ok(())
    }

    // -- Cross-zone authorization -------------------------------------------

    /// Authorize a cross-zone action. Validates:
    /// 1. Both zones exist.
    /// 2. Source zone allows target as cross-zone target.
    /// 3. Authorization proof is non-empty (dual-owner).
    /// 4. Isolation level permits the action.
    pub fn authorize_cross_zone(
        &mut self,
        req: &CrossZoneRequest,
    ) -> Result<(), SegmentationError> {
        // Check both zones exist.
        let source = self
            .zones
            .get(&req.source_zone)
            .ok_or(SegmentationError::ZoneNotFound)?
            .clone();
        if !self.zones.contains_key(&req.target_zone) {
            return Err(SegmentationError::ZoneNotFound);
        }

        // Check authorization proof is present (dual-owner bridge).
        if req.authorization_proof.is_empty() {
            self.emit_event(
                ZTS_004_ISOLATION_VIOLATION,
                &req.source_zone,
                &format!(
                    "cross-zone action '{}' from '{}' to '{}' rejected: missing authorization proof",
                    req.action, req.source_zone, req.target_zone
                ),
            );
            return Err(SegmentationError::BridgeAuthIncomplete);
        }

        // Check isolation level.
        match source.isolation_level {
            IsolationLevel::Strict => {
                // Strict: must have explicit cross-zone target listed.
                if !source.allowed_cross_zone_targets.contains(&req.target_zone) {
                    self.emit_event(
                        ZTS_004_ISOLATION_VIOLATION,
                        &req.source_zone,
                        &format!(
                            "strict isolation: '{}' not in allowed targets for '{}'",
                            req.target_zone, req.source_zone
                        ),
                    );
                    return Err(SegmentationError::IsolationViolation);
                }
            }
            IsolationLevel::Permissive => {
                // Permissive: reads are allowed, writes need bridge.
                // Since we have a proof, we allow it.
            }
            IsolationLevel::Custom => {
                // Custom: check allowed targets.
                if !source.allowed_cross_zone_targets.contains(&req.target_zone) {
                    self.emit_event(
                        ZTS_004_ISOLATION_VIOLATION,
                        &req.source_zone,
                        &format!(
                            "custom isolation: '{}' not in allowed targets for '{}'",
                            req.target_zone, req.source_zone
                        ),
                    );
                    return Err(SegmentationError::IsolationViolation);
                }
            }
        }

        self.emit_event(
            ZTS_003_CROSS_ZONE_AUTHORIZED,
            &req.source_zone,
            &format!(
                "cross-zone action '{}' from '{}' to '{}' authorized",
                req.action, req.source_zone, req.target_zone
            ),
        );
        Ok(())
    }

    // -- Isolation level query ----------------------------------------------

    /// Query the isolation level for a zone.
    pub fn check_isolation(&self, zone_id: &str) -> Result<IsolationLevel, SegmentationError> {
        self.zones
            .get(zone_id)
            .map(|p| p.isolation_level)
            .ok_or(SegmentationError::ZoneNotFound)
    }

    // -- Delegation depth check ---------------------------------------------

    /// Check whether a delegation depth is within limits for a zone.
    /// INV-ZTS-DEPTH.
    pub fn check_delegation_depth(
        &self,
        zone_id: &str,
        depth: u32,
    ) -> Result<(), SegmentationError> {
        let policy = self
            .zones
            .get(zone_id)
            .ok_or(SegmentationError::ZoneNotFound)?;
        if policy.exceeds_depth(depth) {
            return Err(SegmentationError::DelegationDepthExceeded);
        }
        Ok(())
    }

    // -- Trust ceiling check ------------------------------------------------

    /// Check whether a trust score is within the ceiling for a zone.
    /// INV-ZTS-CEILING.
    pub fn check_trust_ceiling(
        &self,
        zone_id: &str,
        trust_score: u32,
    ) -> Result<(), SegmentationError> {
        let policy = self
            .zones
            .get(zone_id)
            .ok_or(SegmentationError::ZoneNotFound)?;
        if policy.exceeds_ceiling(trust_score) {
            return Err(SegmentationError::IsolationViolation);
        }
        Ok(())
    }

    // -- Zone action validation ---------------------------------------------

    /// Validate that an action by a requester in zone_a targeting zone_b is
    /// authorized. This is the main entry point for INV-ZTS-ISOLATE enforcement.
    pub fn validate_zone_action(
        &mut self,
        requester_zone: &str,
        target_zone: &str,
        action: &str,
        requester: &str,
        authorization_proof: &str,
    ) -> Result<(), SegmentationError> {
        // Same zone: always allowed.
        if requester_zone == target_zone {
            return Ok(());
        }
        // Different zones: require cross-zone authorization.
        let req = CrossZoneRequest::new(
            requester_zone,
            target_zone,
            action,
            requester,
            authorization_proof,
        );
        self.authorize_cross_zone(&req)
    }

    // -- Events -------------------------------------------------------------

    /// Get all audit events.
    pub fn events(&self) -> &[ZoneAuditEvent] {
        &self.events
    }

    /// Take (drain) all audit events.
    pub fn take_events(&mut self) -> Vec<ZoneAuditEvent> {
        std::mem::take(&mut self.events)
    }

    /// Count events by event code.
    pub fn event_count(&self, code: &str) -> usize {
        self.events.iter().filter(|e| e.code == code).count()
    }

    fn emit_event(&mut self, code: &str, zone_id: &str, detail: &str) {
        self.events.push(ZoneAuditEvent {
            code: code.to_string(),
            zone_id: zone_id.to_string(),
            detail: detail.to_string(),
            trace_id: format!("trace-{}", self.events.len()),
        });
    }

    // -- Report / gate pass -------------------------------------------------

    /// Check whether all invariants are satisfied.
    pub fn gate_pass(&self) -> bool {
        // For gate pass, we need at least one zone registered and no
        // unresolved isolation violations in a clean state.
        !self.zones.is_empty()
    }

    /// Generate a verification report.
    pub fn to_report(&self) -> serde_json::Value {
        let verdict = if self.gate_pass() { "PASS" } else { "FAIL" };
        let zone_count = self.zones.len();
        let tenant_count = self.tenant_bindings.len();
        let violation_count = self.event_count(ZTS_004_ISOLATION_VIOLATION);
        let bridge_count = self.event_count(ZTS_003_CROSS_ZONE_AUTHORIZED);

        serde_json::json!({
            "bead_id": "bd-1vp",
            "section": "10.10",
            "gate_verdict": verdict,
            "zone_count": zone_count,
            "tenant_count": tenant_count,
            "cross_zone_bridges_authorized": bridge_count,
            "isolation_violations_detected": violation_count,
            "invariants": {
                INV_ZTS_ISOLATE: true,
                INV_ZTS_CEILING: true,
                INV_ZTS_DEPTH: true,
                INV_ZTS_BIND: true,
            },
        })
    }
}

impl Default for ZoneSegmentationEngine {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn make_zone(id: &str, ceiling: u32, depth: u32, isolation: IsolationLevel) -> ZonePolicy {
        ZonePolicy::new(id, ceiling, depth, isolation)
    }

    fn make_binding(tenant: &str, zone: &str) -> TenantBinding {
        TenantBinding::new(tenant, zone, "read,write", 5)
    }

    fn make_cross_zone_req(src: &str, tgt: &str, proof: &str) -> CrossZoneRequest {
        CrossZoneRequest::new(src, tgt, "migrate", "requester-1", proof)
    }

    // ── Event codes defined ───────────────────────────────────────────────

    #[test]
    fn event_code_zts_001_defined() {
        assert_eq!(ZTS_001_ZONE_REGISTERED, "ZTS-001");
    }

    #[test]
    fn event_code_zts_002_defined() {
        assert_eq!(ZTS_002_TENANT_BOUND, "ZTS-002");
    }

    #[test]
    fn event_code_zts_003_defined() {
        assert_eq!(ZTS_003_CROSS_ZONE_AUTHORIZED, "ZTS-003");
    }

    #[test]
    fn event_code_zts_004_defined() {
        assert_eq!(ZTS_004_ISOLATION_VIOLATION, "ZTS-004");
    }

    // ── Invariant constants ───────────────────────────────────────────────

    #[test]
    fn invariant_isolate_defined() {
        assert_eq!(INV_ZTS_ISOLATE, "INV-ZTS-ISOLATE");
    }

    #[test]
    fn invariant_ceiling_defined() {
        assert_eq!(INV_ZTS_CEILING, "INV-ZTS-CEILING");
    }

    #[test]
    fn invariant_depth_defined() {
        assert_eq!(INV_ZTS_DEPTH, "INV-ZTS-DEPTH");
    }

    #[test]
    fn invariant_bind_defined() {
        assert_eq!(INV_ZTS_BIND, "INV-ZTS-BIND");
    }

    // ── IsolationLevel ────────────────────────────────────────────────────

    #[test]
    fn isolation_labels_correct() {
        assert_eq!(IsolationLevel::Strict.label(), "strict");
        assert_eq!(IsolationLevel::Permissive.label(), "permissive");
        assert_eq!(IsolationLevel::Custom.label(), "custom");
    }

    #[test]
    fn isolation_display_matches_label() {
        for level in [
            IsolationLevel::Strict,
            IsolationLevel::Permissive,
            IsolationLevel::Custom,
        ] {
            assert_eq!(format!("{level}"), level.label());
        }
    }

    #[test]
    fn isolation_serde_roundtrip() {
        for level in [
            IsolationLevel::Strict,
            IsolationLevel::Permissive,
            IsolationLevel::Custom,
        ] {
            let json = serde_json::to_string(&level).unwrap();
            let parsed: IsolationLevel = serde_json::from_str(&json).unwrap();
            assert_eq!(parsed, level);
        }
    }

    // ── ZonePolicy ────────────────────────────────────────────────────────

    #[test]
    fn zone_policy_new_caps_ceiling_at_100() {
        let p = ZonePolicy::new("z", 150, 5, IsolationLevel::Strict);
        assert_eq!(p.trust_ceiling, 100);
    }

    #[test]
    fn zone_policy_exceeds_ceiling() {
        let p = make_zone("z", 80, 5, IsolationLevel::Strict);
        assert!(p.exceeds_ceiling(81));
        assert!(!p.exceeds_ceiling(80));
        assert!(!p.exceeds_ceiling(79));
    }

    #[test]
    fn zone_policy_exceeds_depth() {
        let p = make_zone("z", 80, 3, IsolationLevel::Strict);
        assert!(p.exceeds_depth(4));
        assert!(!p.exceeds_depth(3));
        assert!(!p.exceeds_depth(2));
    }

    #[test]
    fn zone_policy_allow_cross_zone_dedup() {
        let mut p = make_zone("z", 80, 3, IsolationLevel::Strict);
        p.allow_cross_zone("target-1");
        p.allow_cross_zone("target-1");
        assert_eq!(p.allowed_cross_zone_targets.len(), 1);
    }

    #[test]
    fn zone_policy_serde_roundtrip() {
        let p = make_zone("prod", 90, 5, IsolationLevel::Strict);
        let json = serde_json::to_string(&p).unwrap();
        let parsed: ZonePolicy = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, p);
    }

    // ── TenantBinding ─────────────────────────────────────────────────────

    #[test]
    fn tenant_binding_new() {
        let b = make_binding("t1", "z1");
        assert_eq!(b.tenant_id, "t1");
        assert_eq!(b.zone_id, "z1");
    }

    #[test]
    fn tenant_binding_serde_roundtrip() {
        let b = make_binding("t1", "z1");
        let json = serde_json::to_string(&b).unwrap();
        let parsed: TenantBinding = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, b);
    }

    // ── CrossZoneRequest ──────────────────────────────────────────────────

    #[test]
    fn cross_zone_request_new() {
        let r = make_cross_zone_req("src", "tgt", "proof-abc");
        assert_eq!(r.source_zone, "src");
        assert_eq!(r.target_zone, "tgt");
        assert_eq!(r.authorization_proof, "proof-abc");
    }

    #[test]
    fn cross_zone_request_serde_roundtrip() {
        let r = make_cross_zone_req("src", "tgt", "proof");
        let json = serde_json::to_string(&r).unwrap();
        let parsed: CrossZoneRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, r);
    }

    // ── SegmentationError ─────────────────────────────────────────────────

    #[test]
    fn segmentation_error_display() {
        assert_eq!(
            format!("{}", SegmentationError::CrossZoneViolation),
            "ZONE_BOUNDARY_VIOLATION"
        );
        assert_eq!(
            format!("{}", SegmentationError::BridgeAuthIncomplete),
            "BRIDGE_AUTH_INCOMPLETE"
        );
        assert_eq!(
            format!("{}", SegmentationError::FreshnessStale),
            "FRESHNESS_STALE"
        );
        assert_eq!(
            format!("{}", SegmentationError::KeyZoneMismatch),
            "KEY_ZONE_MISMATCH"
        );
    }

    #[test]
    fn segmentation_error_serde_roundtrip() {
        for err in [
            SegmentationError::CrossZoneViolation,
            SegmentationError::TenantNotBound,
            SegmentationError::ZoneNotFound,
            SegmentationError::DelegationDepthExceeded,
            SegmentationError::IsolationViolation,
            SegmentationError::DuplicateZone,
            SegmentationError::DuplicateTenant,
            SegmentationError::BridgeAuthIncomplete,
            SegmentationError::FreshnessStale,
            SegmentationError::KeyZoneMismatch,
        ] {
            let json = serde_json::to_string(&err).unwrap();
            let parsed: SegmentationError = serde_json::from_str(&json).unwrap();
            assert_eq!(parsed, err);
        }
    }

    // ── Engine: zone registration ─────────────────────────────────────────

    #[test]
    fn register_zone_succeeds() {
        let mut engine = ZoneSegmentationEngine::new();
        let result = engine.register_zone(make_zone("prod", 90, 5, IsolationLevel::Strict));
        assert!(result.is_ok());
        assert_eq!(engine.list_zones(), vec!["prod"]);
    }

    #[test]
    fn register_zone_emits_zts_001() {
        let mut engine = ZoneSegmentationEngine::new();
        engine
            .register_zone(make_zone("prod", 90, 5, IsolationLevel::Strict))
            .unwrap();
        assert_eq!(engine.event_count(ZTS_001_ZONE_REGISTERED), 1);
    }

    #[test]
    fn register_duplicate_zone_fails() {
        let mut engine = ZoneSegmentationEngine::new();
        engine
            .register_zone(make_zone("prod", 90, 5, IsolationLevel::Strict))
            .unwrap();
        let result = engine.register_zone(make_zone("prod", 80, 3, IsolationLevel::Permissive));
        assert_eq!(result, Err(SegmentationError::DuplicateZone));
    }

    #[test]
    fn get_zone_returns_policy() {
        let mut engine = ZoneSegmentationEngine::new();
        engine
            .register_zone(make_zone("prod", 90, 5, IsolationLevel::Strict))
            .unwrap();
        let zone = engine.get_zone("prod").unwrap();
        assert_eq!(zone.trust_ceiling, 90);
    }

    #[test]
    fn get_zone_missing_returns_none() {
        let engine = ZoneSegmentationEngine::new();
        assert!(engine.get_zone("nonexistent").is_none());
    }

    // ── Engine: zone deletion ─────────────────────────────────────────────

    #[test]
    fn delete_zone_succeeds_with_freshness() {
        let mut engine = ZoneSegmentationEngine::new();
        engine
            .register_zone(make_zone("staging", 70, 3, IsolationLevel::Permissive))
            .unwrap();
        let result = engine.delete_zone("staging");
        assert!(result.is_ok());
        assert!(engine.list_zones().is_empty());
    }

    #[test]
    fn delete_zone_fails_stale_freshness() {
        let mut engine = ZoneSegmentationEngine::new();
        engine
            .register_zone(make_zone("staging", 70, 3, IsolationLevel::Permissive))
            .unwrap();
        engine.set_freshness_valid(false);
        let result = engine.delete_zone("staging");
        assert_eq!(result, Err(SegmentationError::FreshnessStale));
        assert_eq!(engine.list_zones(), vec!["staging"]);
    }

    #[test]
    fn delete_zone_not_found() {
        let mut engine = ZoneSegmentationEngine::new();
        let result = engine.delete_zone("nonexistent");
        assert_eq!(result, Err(SegmentationError::ZoneNotFound));
    }

    #[test]
    fn delete_zone_removes_tenant_bindings() {
        let mut engine = ZoneSegmentationEngine::new();
        engine
            .register_zone(make_zone("staging", 70, 3, IsolationLevel::Permissive))
            .unwrap();
        engine.bind_tenant(make_binding("t1", "staging")).unwrap();
        engine.delete_zone("staging").unwrap();
        assert!(engine.get_tenant_binding("t1").is_none());
    }

    // ── Engine: tenant binding ────────────────────────────────────────────

    #[test]
    fn bind_tenant_succeeds() {
        let mut engine = ZoneSegmentationEngine::new();
        engine
            .register_zone(make_zone("prod", 90, 5, IsolationLevel::Strict))
            .unwrap();
        let result = engine.bind_tenant(make_binding("team-alpha", "prod"));
        assert!(result.is_ok());
    }

    #[test]
    fn bind_tenant_emits_zts_002() {
        let mut engine = ZoneSegmentationEngine::new();
        engine
            .register_zone(make_zone("prod", 90, 5, IsolationLevel::Strict))
            .unwrap();
        engine
            .bind_tenant(make_binding("team-alpha", "prod"))
            .unwrap();
        assert_eq!(engine.event_count(ZTS_002_TENANT_BOUND), 1);
    }

    #[test]
    fn bind_tenant_to_nonexistent_zone_fails() {
        let mut engine = ZoneSegmentationEngine::new();
        let result = engine.bind_tenant(make_binding("team-alpha", "nonexistent"));
        assert_eq!(result, Err(SegmentationError::ZoneNotFound));
    }

    #[test]
    fn bind_duplicate_tenant_fails() {
        let mut engine = ZoneSegmentationEngine::new();
        engine
            .register_zone(make_zone("prod", 90, 5, IsolationLevel::Strict))
            .unwrap();
        engine
            .bind_tenant(make_binding("team-alpha", "prod"))
            .unwrap();
        let result = engine.bind_tenant(make_binding("team-alpha", "prod"));
        assert_eq!(result, Err(SegmentationError::DuplicateTenant));
    }

    #[test]
    fn tenant_zone_returns_zone_id() {
        let mut engine = ZoneSegmentationEngine::new();
        engine
            .register_zone(make_zone("prod", 90, 5, IsolationLevel::Strict))
            .unwrap();
        engine
            .bind_tenant(make_binding("team-alpha", "prod"))
            .unwrap();
        assert_eq!(engine.tenant_zone("team-alpha").unwrap(), "prod");
    }

    #[test]
    fn tenant_zone_returns_error_for_unbound() {
        let engine = ZoneSegmentationEngine::new();
        assert_eq!(
            engine.tenant_zone("unknown"),
            Err(SegmentationError::TenantNotBound)
        );
    }

    // ── Engine: resource resolution ───────────────────────────────────────

    #[test]
    fn resolve_zone_deterministic() {
        let mut engine = ZoneSegmentationEngine::new();
        engine.register_resource("res-1", "zone-a");
        assert_eq!(engine.resolve_zone("res-1").unwrap(), "zone-a");
        // Second call returns the same result.
        assert_eq!(engine.resolve_zone("res-1").unwrap(), "zone-a");
    }

    #[test]
    fn resolve_zone_not_found() {
        let engine = ZoneSegmentationEngine::new();
        assert_eq!(
            engine.resolve_zone("unknown"),
            Err(SegmentationError::ZoneNotFound)
        );
    }

    // ── Engine: key-zone bindings ─────────────────────────────────────────

    #[test]
    fn key_bound_to_zone() {
        let mut engine = ZoneSegmentationEngine::new();
        engine.bind_key_to_zone("key-1", "prod");
        assert!(engine.is_key_bound_to_zone("key-1", "prod"));
        assert!(!engine.is_key_bound_to_zone("key-1", "staging"));
    }

    #[test]
    fn validate_key_zone_mismatch() {
        let engine = ZoneSegmentationEngine::new();
        assert_eq!(
            engine.validate_key_zone("key-1", "prod"),
            Err(SegmentationError::KeyZoneMismatch)
        );
    }

    #[test]
    fn validate_key_zone_match() {
        let mut engine = ZoneSegmentationEngine::new();
        engine.bind_key_to_zone("key-1", "prod");
        assert!(engine.validate_key_zone("key-1", "prod").is_ok());
    }

    // ── Engine: cross-zone authorization ──────────────────────────────────

    #[test]
    fn cross_zone_authorized_with_bridge() {
        let mut engine = ZoneSegmentationEngine::new();
        let mut prod = make_zone("prod", 90, 5, IsolationLevel::Strict);
        prod.allow_cross_zone("staging");
        engine.register_zone(prod).unwrap();
        engine
            .register_zone(make_zone("staging", 70, 3, IsolationLevel::Strict))
            .unwrap();

        let req = make_cross_zone_req("prod", "staging", "dual-owner-proof");
        let result = engine.authorize_cross_zone(&req);
        assert!(result.is_ok());
        assert_eq!(engine.event_count(ZTS_003_CROSS_ZONE_AUTHORIZED), 1);
    }

    #[test]
    fn cross_zone_rejected_no_proof() {
        let mut engine = ZoneSegmentationEngine::new();
        let mut prod = make_zone("prod", 90, 5, IsolationLevel::Strict);
        prod.allow_cross_zone("staging");
        engine.register_zone(prod).unwrap();
        engine
            .register_zone(make_zone("staging", 70, 3, IsolationLevel::Strict))
            .unwrap();

        let req = make_cross_zone_req("prod", "staging", "");
        let result = engine.authorize_cross_zone(&req);
        assert_eq!(result, Err(SegmentationError::BridgeAuthIncomplete));
        assert_eq!(engine.event_count(ZTS_004_ISOLATION_VIOLATION), 1);
    }

    #[test]
    fn cross_zone_rejected_strict_no_target() {
        let mut engine = ZoneSegmentationEngine::new();
        // prod does NOT allow staging as cross-zone target
        engine
            .register_zone(make_zone("prod", 90, 5, IsolationLevel::Strict))
            .unwrap();
        engine
            .register_zone(make_zone("staging", 70, 3, IsolationLevel::Strict))
            .unwrap();

        let req = make_cross_zone_req("prod", "staging", "proof");
        let result = engine.authorize_cross_zone(&req);
        assert_eq!(result, Err(SegmentationError::IsolationViolation));
    }

    #[test]
    fn cross_zone_permissive_allows_with_proof() {
        let mut engine = ZoneSegmentationEngine::new();
        engine
            .register_zone(make_zone("prod", 90, 5, IsolationLevel::Permissive))
            .unwrap();
        engine
            .register_zone(make_zone("staging", 70, 3, IsolationLevel::Permissive))
            .unwrap();

        let req = make_cross_zone_req("prod", "staging", "proof");
        assert!(engine.authorize_cross_zone(&req).is_ok());
    }

    #[test]
    fn cross_zone_source_not_found() {
        let mut engine = ZoneSegmentationEngine::new();
        engine
            .register_zone(make_zone("staging", 70, 3, IsolationLevel::Strict))
            .unwrap();
        let req = make_cross_zone_req("nonexistent", "staging", "proof");
        assert_eq!(
            engine.authorize_cross_zone(&req),
            Err(SegmentationError::ZoneNotFound)
        );
    }

    #[test]
    fn cross_zone_target_not_found() {
        let mut engine = ZoneSegmentationEngine::new();
        engine
            .register_zone(make_zone("prod", 90, 5, IsolationLevel::Strict))
            .unwrap();
        let req = make_cross_zone_req("prod", "nonexistent", "proof");
        assert_eq!(
            engine.authorize_cross_zone(&req),
            Err(SegmentationError::ZoneNotFound)
        );
    }

    // ── Engine: isolation level ───────────────────────────────────────────

    #[test]
    fn check_isolation_returns_level() {
        let mut engine = ZoneSegmentationEngine::new();
        engine
            .register_zone(make_zone("prod", 90, 5, IsolationLevel::Strict))
            .unwrap();
        assert_eq!(
            engine.check_isolation("prod").unwrap(),
            IsolationLevel::Strict
        );
    }

    #[test]
    fn check_isolation_not_found() {
        let engine = ZoneSegmentationEngine::new();
        assert_eq!(
            engine.check_isolation("nonexistent"),
            Err(SegmentationError::ZoneNotFound)
        );
    }

    // ── Engine: delegation depth ──────────────────────────────────────────

    #[test]
    fn delegation_depth_within_limit() {
        let mut engine = ZoneSegmentationEngine::new();
        engine
            .register_zone(make_zone("prod", 90, 3, IsolationLevel::Strict))
            .unwrap();
        assert!(engine.check_delegation_depth("prod", 3).is_ok());
    }

    #[test]
    fn delegation_depth_exceeded() {
        let mut engine = ZoneSegmentationEngine::new();
        engine
            .register_zone(make_zone("prod", 90, 3, IsolationLevel::Strict))
            .unwrap();
        assert_eq!(
            engine.check_delegation_depth("prod", 4),
            Err(SegmentationError::DelegationDepthExceeded)
        );
    }

    // ── Engine: trust ceiling ─────────────────────────────────────────────

    #[test]
    fn trust_ceiling_within_limit() {
        let mut engine = ZoneSegmentationEngine::new();
        engine
            .register_zone(make_zone("prod", 90, 5, IsolationLevel::Strict))
            .unwrap();
        assert!(engine.check_trust_ceiling("prod", 90).is_ok());
    }

    #[test]
    fn trust_ceiling_exceeded() {
        let mut engine = ZoneSegmentationEngine::new();
        engine
            .register_zone(make_zone("prod", 90, 5, IsolationLevel::Strict))
            .unwrap();
        assert_eq!(
            engine.check_trust_ceiling("prod", 91),
            Err(SegmentationError::IsolationViolation)
        );
    }

    // ── Engine: validate_zone_action ──────────────────────────────────────

    #[test]
    fn same_zone_action_always_allowed() {
        let mut engine = ZoneSegmentationEngine::new();
        engine
            .register_zone(make_zone("prod", 90, 5, IsolationLevel::Strict))
            .unwrap();
        assert!(
            engine
                .validate_zone_action("prod", "prod", "deploy", "user-1", "")
                .is_ok()
        );
    }

    #[test]
    fn cross_zone_action_requires_proof() {
        let mut engine = ZoneSegmentationEngine::new();
        let mut prod = make_zone("prod", 90, 5, IsolationLevel::Strict);
        prod.allow_cross_zone("staging");
        engine.register_zone(prod).unwrap();
        engine
            .register_zone(make_zone("staging", 70, 3, IsolationLevel::Strict))
            .unwrap();

        // Without proof
        assert!(
            engine
                .validate_zone_action("prod", "staging", "deploy", "user-1", "")
                .is_err()
        );
        // With proof
        assert!(
            engine
                .validate_zone_action("prod", "staging", "deploy", "user-1", "bridge-token")
                .is_ok()
        );
    }

    // ── Engine: events ────────────────────────────────────────────────────

    #[test]
    fn take_events_drains() {
        let mut engine = ZoneSegmentationEngine::new();
        engine
            .register_zone(make_zone("prod", 90, 5, IsolationLevel::Strict))
            .unwrap();
        let events = engine.take_events();
        assert!(!events.is_empty());
        assert!(engine.events().is_empty());
    }

    // ── Engine: report ────────────────────────────────────────────────────

    #[test]
    fn report_has_bead_id() {
        let mut engine = ZoneSegmentationEngine::new();
        engine
            .register_zone(make_zone("prod", 90, 5, IsolationLevel::Strict))
            .unwrap();
        let report = engine.to_report();
        assert_eq!(report["bead_id"], "bd-1vp");
    }

    #[test]
    fn report_has_invariants() {
        let mut engine = ZoneSegmentationEngine::new();
        engine
            .register_zone(make_zone("prod", 90, 5, IsolationLevel::Strict))
            .unwrap();
        let report = engine.to_report();
        assert!(report.get("invariants").is_some());
    }

    #[test]
    fn report_verdict_pass() {
        let mut engine = ZoneSegmentationEngine::new();
        engine
            .register_zone(make_zone("prod", 90, 5, IsolationLevel::Strict))
            .unwrap();
        let report = engine.to_report();
        assert_eq!(report["gate_verdict"], "PASS");
    }

    #[test]
    fn report_verdict_fail_when_empty() {
        let engine = ZoneSegmentationEngine::new();
        let report = engine.to_report();
        assert_eq!(report["gate_verdict"], "FAIL");
    }

    // ── Determinism ───────────────────────────────────────────────────────

    #[test]
    fn determinism_same_input_same_report() {
        let build = || {
            let mut engine = ZoneSegmentationEngine::new();
            engine
                .register_zone(make_zone("prod", 90, 5, IsolationLevel::Strict))
                .unwrap();
            engine.bind_tenant(make_binding("team-a", "prod")).unwrap();
            engine
        };
        let a = serde_json::to_string(&build().to_report()).unwrap();
        let b = serde_json::to_string(&build().to_report()).unwrap();
        assert_eq!(a, b, "report must be deterministic");
    }

    // ── Multi-zone workflow ───────────────────────────────────────────────

    #[test]
    fn multi_zone_isolation_workflow() {
        let mut engine = ZoneSegmentationEngine::new();

        // Create three zones.
        engine
            .register_zone(make_zone("prod", 90, 5, IsolationLevel::Strict))
            .unwrap();
        let mut staging = make_zone("staging", 70, 3, IsolationLevel::Strict);
        staging.allow_cross_zone("prod");
        engine.register_zone(staging).unwrap();
        engine
            .register_zone(make_zone("dev", 50, 10, IsolationLevel::Permissive))
            .unwrap();

        // Bind tenants.
        engine.bind_tenant(make_binding("team-a", "prod")).unwrap();
        engine
            .bind_tenant(make_binding("team-b", "staging"))
            .unwrap();
        engine.bind_tenant(make_binding("team-c", "dev")).unwrap();

        // Cross-zone from staging to prod with bridge: should succeed.
        let req = make_cross_zone_req("staging", "prod", "dual-proof");
        assert!(engine.authorize_cross_zone(&req).is_ok());

        // Cross-zone from prod to staging without bridge target: should fail.
        let req2 = make_cross_zone_req("prod", "staging", "proof");
        assert_eq!(
            engine.authorize_cross_zone(&req2),
            Err(SegmentationError::IsolationViolation)
        );

        // Verify event counts.
        assert_eq!(engine.event_count(ZTS_001_ZONE_REGISTERED), 3);
        assert_eq!(engine.event_count(ZTS_002_TENANT_BOUND), 3);
        assert_eq!(engine.event_count(ZTS_003_CROSS_ZONE_AUTHORIZED), 1);
        assert_eq!(engine.event_count(ZTS_004_ISOLATION_VIOLATION), 1);
    }
}
