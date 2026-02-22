//! Intent-aware remote effects firewall for extension-originated traffic (bd-3l2p).
//!
//! Classifies every outbound remote effect by intent category, applies traffic
//! policy rules, and issues deterministic decision receipts. Risky intent
//! categories (exfiltration, credential forwarding, side-channel probing)
//! default to deny/quarantine pathways. Unclassifiable traffic is denied
//! (fail-closed).

use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

// ── Schema version ──────────────────────────────────────────────────

/// Schema version for the intent firewall module.
pub const SCHEMA_VERSION: &str = "fw-v1.0";

// ── Event codes ─────────────────────────────────────────────────────

/// Remote effect request received for classification.
pub const FW_001: &str = "FW_001";
/// Intent classification completed.
pub const FW_002: &str = "FW_002";
/// Traffic policy matched; verdict issued.
pub const FW_003: &str = "FW_003";
/// Decision receipt generated.
pub const FW_004: &str = "FW_004";
/// Risky intent category detected; non-allow pathway triggered.
pub const FW_005: &str = "FW_005";
/// Challenge pathway initiated for ambiguous intent.
pub const FW_006: &str = "FW_006";
/// Simulate pathway initiated for sandboxed evaluation.
pub const FW_007: &str = "FW_007";
/// Quarantine pathway initiated for suspicious traffic.
pub const FW_008: &str = "FW_008";
/// Unclassifiable traffic denied (fail-closed).
pub const FW_009: &str = "FW_009";
/// Policy override applied with justification.
pub const FW_010: &str = "FW_010";

// ── Error codes ─────────────────────────────────────────────────────

/// Request could not be classified into any intent category.
pub const ERR_FW_UNCLASSIFIED: &str = "ERR_FW_UNCLASSIFIED";
/// No traffic policy found for the classified intent category.
pub const ERR_FW_NO_POLICY: &str = "ERR_FW_NO_POLICY";
/// Remote effect descriptor is malformed or missing fields.
pub const ERR_FW_INVALID_EFFECT: &str = "ERR_FW_INVALID_EFFECT";
/// Decision receipt generation failed.
pub const ERR_FW_RECEIPT_FAILED: &str = "ERR_FW_RECEIPT_FAILED";
/// Conflicting policy rules for the same intent category.
pub const ERR_FW_POLICY_CONFLICT: &str = "ERR_FW_POLICY_CONFLICT";
/// Extension origin identifier is not registered.
pub const ERR_FW_EXTENSION_UNKNOWN: &str = "ERR_FW_EXTENSION_UNKNOWN";
/// Policy override lacks required justification.
pub const ERR_FW_OVERRIDE_UNAUTHORIZED: &str = "ERR_FW_OVERRIDE_UNAUTHORIZED";
/// Quarantine capacity exceeded; traffic denied.
pub const ERR_FW_QUARANTINE_FULL: &str = "ERR_FW_QUARANTINE_FULL";

// ── Invariants ──────────────────────────────────────────────────────

/// INV-FW-FAIL-CLOSED: Unclassifiable traffic is denied.
pub const INV_FW_FAIL_CLOSED: &str = "INV-FW-FAIL-CLOSED";
/// INV-FW-RECEIPT-EVERY-DECISION: Every decision produces a receipt.
pub const INV_FW_RECEIPT_EVERY_DECISION: &str = "INV-FW-RECEIPT-EVERY-DECISION";
/// INV-FW-RISKY-DEFAULT-DENY: Risky categories default to deny/quarantine.
pub const INV_FW_RISKY_DEFAULT_DENY: &str = "INV-FW-RISKY-DEFAULT-DENY";
/// INV-FW-DETERMINISTIC: Identical inputs produce identical outputs.
pub const INV_FW_DETERMINISTIC: &str = "INV-FW-DETERMINISTIC";
/// INV-FW-EXTENSION-SCOPED: Firewall applies only to extension traffic.
pub const INV_FW_EXTENSION_SCOPED: &str = "INV-FW-EXTENSION-SCOPED";

// ── Intent classification ───────────────────────────────────────────

/// Classification of the intent behind a remote effect.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IntentClassification {
    /// Standard data fetch (read-only, non-sensitive).
    DataFetch,
    /// Data mutation on remote system.
    DataMutation,
    /// Webhook or notification dispatch.
    WebhookDispatch,
    /// Analytics or telemetry export.
    AnalyticsExport,
    /// Data exfiltration attempt (risky).
    Exfiltration,
    /// Credential forwarding to external system (risky).
    CredentialForward,
    /// Side-channel probing or fingerprinting (risky).
    SideChannel,
    /// Service discovery or enumeration.
    ServiceDiscovery,
    /// Health check or heartbeat.
    HealthCheck,
    /// Configuration synchronization.
    ConfigSync,
}

impl IntentClassification {
    /// Whether this intent category is considered risky.
    pub fn is_risky(&self) -> bool {
        matches!(
            self,
            Self::Exfiltration | Self::CredentialForward | Self::SideChannel
        )
    }

    /// All known intent categories.
    pub fn all() -> &'static [IntentClassification] {
        &[
            Self::DataFetch,
            Self::DataMutation,
            Self::WebhookDispatch,
            Self::AnalyticsExport,
            Self::Exfiltration,
            Self::CredentialForward,
            Self::SideChannel,
            Self::ServiceDiscovery,
            Self::HealthCheck,
            Self::ConfigSync,
        ]
    }
}

impl fmt::Display for IntentClassification {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::DataFetch => "data_fetch",
            Self::DataMutation => "data_mutation",
            Self::WebhookDispatch => "webhook_dispatch",
            Self::AnalyticsExport => "analytics_export",
            Self::Exfiltration => "exfiltration",
            Self::CredentialForward => "credential_forward",
            Self::SideChannel => "side_channel",
            Self::ServiceDiscovery => "service_discovery",
            Self::HealthCheck => "health_check",
            Self::ConfigSync => "config_sync",
        };
        write!(f, "{}", s)
    }
}

// ── Traffic origin ──────────────────────────────────────────────────

/// Origin of a remote effect request.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TrafficOrigin {
    /// From a registered extension.
    Extension { extension_id: String },
    /// From the node's internal subsystems.
    NodeInternal { subsystem: String },
}

impl TrafficOrigin {
    /// Whether this traffic originates from an extension.
    pub fn is_extension(&self) -> bool {
        matches!(self, Self::Extension { .. })
    }
}

// ── Remote effect ───────────────────────────────────────────────────

/// Descriptor for a remote effect that an extension wants to execute.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RemoteEffect {
    /// Unique identifier for this effect request.
    pub effect_id: String,
    /// Origin of the request.
    pub origin: TrafficOrigin,
    /// Target host or endpoint.
    pub target_host: String,
    /// Target port.
    pub target_port: u16,
    /// HTTP method or protocol action.
    pub method: String,
    /// Path or resource identifier.
    pub path: String,
    /// Whether the payload contains sensitive data markers.
    pub has_sensitive_payload: bool,
    /// Whether the request carries credentials.
    pub carries_credentials: bool,
    /// Additional metadata for classification.
    pub metadata: BTreeMap<String, String>,
}

impl RemoteEffect {
    /// Validate that the effect descriptor is well-formed.
    pub fn validate(&self) -> Result<(), FirewallError> {
        if self.effect_id.is_empty() {
            return Err(FirewallError::InvalidEffect("empty effect_id".into()));
        }
        if self.target_host.is_empty() {
            return Err(FirewallError::InvalidEffect("empty target_host".into()));
        }
        if self.method.is_empty() {
            return Err(FirewallError::InvalidEffect("empty method".into()));
        }
        Ok(())
    }
}

// ── Firewall verdict ────────────────────────────────────────────────

/// Verdict issued by the effects firewall.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FirewallVerdict {
    /// Traffic is permitted.
    Allow,
    /// Traffic requires interactive challenge before proceeding.
    Challenge,
    /// Traffic is sandboxed for simulated evaluation.
    Simulate,
    /// Traffic is denied.
    Deny,
    /// Traffic is quarantined for later review.
    Quarantine,
}

impl fmt::Display for FirewallVerdict {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Allow => write!(f, "allow"),
            Self::Challenge => write!(f, "challenge"),
            Self::Simulate => write!(f, "simulate"),
            Self::Deny => write!(f, "deny"),
            Self::Quarantine => write!(f, "quarantine"),
        }
    }
}

// ── Traffic policy ──────────────────────────────────────────────────

/// A single traffic policy rule mapping intent category to verdict.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TrafficPolicyRule {
    /// Intent category this rule applies to.
    pub intent: IntentClassification,
    /// Verdict to issue when this rule matches.
    pub verdict: FirewallVerdict,
    /// Optional host pattern filter (empty = all hosts).
    pub host_pattern: Option<String>,
    /// Priority (lower = higher priority).
    pub priority: u32,
    /// Human-readable rationale.
    pub rationale: String,
}

/// Complete traffic policy for the effects firewall.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrafficPolicy {
    /// Policy ID.
    pub policy_id: String,
    /// Schema version.
    pub schema_version: String,
    /// Ordered rules (BTreeMap by priority for determinism).
    pub rules: BTreeMap<u32, TrafficPolicyRule>,
    /// Registered extension IDs.
    pub registered_extensions: BTreeSet<String>,
    /// Maximum quarantine capacity.
    pub quarantine_capacity: usize,
}

impl TrafficPolicy {
    /// Create a default policy with risky-deny defaults.
    pub fn default_policy() -> Self {
        let mut rules = BTreeMap::new();
        let mut priority = 0u32;

        // Risky categories: deny by default (INV-FW-RISKY-DEFAULT-DENY).
        for &intent in &[
            IntentClassification::Exfiltration,
            IntentClassification::CredentialForward,
            IntentClassification::SideChannel,
        ] {
            rules.insert(
                priority,
                TrafficPolicyRule {
                    intent,
                    verdict: FirewallVerdict::Deny,
                    host_pattern: None,
                    priority,
                    rationale: format!("risky category {} denied by default", intent),
                },
            );
            priority += 1;
        }

        // Non-risky categories: allow by default.
        for &intent in &[
            IntentClassification::DataFetch,
            IntentClassification::DataMutation,
            IntentClassification::WebhookDispatch,
            IntentClassification::AnalyticsExport,
            IntentClassification::ServiceDiscovery,
            IntentClassification::HealthCheck,
            IntentClassification::ConfigSync,
        ] {
            rules.insert(
                priority,
                TrafficPolicyRule {
                    intent,
                    verdict: FirewallVerdict::Allow,
                    host_pattern: None,
                    priority,
                    rationale: format!("non-risky category {} allowed by default", intent),
                },
            );
            priority += 1;
        }

        Self {
            policy_id: "default-fw-policy".into(),
            schema_version: SCHEMA_VERSION.into(),
            rules,
            registered_extensions: BTreeSet::new(),
            quarantine_capacity: 1000,
        }
    }

    /// Look up the highest-priority rule for a given intent category.
    pub fn match_rule(&self, intent: IntentClassification) -> Option<&TrafficPolicyRule> {
        // BTreeMap iterates in key order (ascending priority = highest priority first).
        self.rules.values().find(|r| r.intent == intent)
    }
}

// ── Decision receipt ────────────────────────────────────────────────

/// Deterministic receipt for every firewall decision.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FirewallDecision {
    /// Unique receipt ID.
    pub receipt_id: String,
    /// Trace correlation ID.
    pub trace_id: String,
    /// The effect that was evaluated.
    pub effect_id: String,
    /// Extension or origin identifier.
    pub origin: TrafficOrigin,
    /// Classified intent (None if unclassifiable).
    pub intent: Option<IntentClassification>,
    /// Verdict issued.
    pub verdict: FirewallVerdict,
    /// Event code associated with this decision.
    pub event_code: String,
    /// Matched rule priority (if any).
    pub matched_rule_priority: Option<u32>,
    /// Rationale for the decision.
    pub rationale: String,
    /// ISO-8601 timestamp.
    pub timestamp: String,
    /// Schema version.
    pub schema_version: String,
}

// ── Firewall error ──────────────────────────────────────────────────

/// Errors produced by the effects firewall.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum FirewallError {
    /// ERR_FW_UNCLASSIFIED
    Unclassified(String),
    /// ERR_FW_NO_POLICY
    NoPolicy(String),
    /// ERR_FW_INVALID_EFFECT
    InvalidEffect(String),
    /// ERR_FW_RECEIPT_FAILED
    ReceiptFailed(String),
    /// ERR_FW_POLICY_CONFLICT
    PolicyConflict(String),
    /// ERR_FW_EXTENSION_UNKNOWN
    ExtensionUnknown(String),
    /// ERR_FW_OVERRIDE_UNAUTHORIZED
    OverrideUnauthorized(String),
    /// ERR_FW_QUARANTINE_FULL
    QuarantineFull(String),
}

impl fmt::Display for FirewallError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unclassified(d) => write!(f, "{}: {}", ERR_FW_UNCLASSIFIED, d),
            Self::NoPolicy(d) => write!(f, "{}: {}", ERR_FW_NO_POLICY, d),
            Self::InvalidEffect(d) => write!(f, "{}: {}", ERR_FW_INVALID_EFFECT, d),
            Self::ReceiptFailed(d) => write!(f, "{}: {}", ERR_FW_RECEIPT_FAILED, d),
            Self::PolicyConflict(d) => write!(f, "{}: {}", ERR_FW_POLICY_CONFLICT, d),
            Self::ExtensionUnknown(d) => write!(f, "{}: {}", ERR_FW_EXTENSION_UNKNOWN, d),
            Self::OverrideUnauthorized(d) => write!(f, "{}: {}", ERR_FW_OVERRIDE_UNAUTHORIZED, d),
            Self::QuarantineFull(d) => write!(f, "{}: {}", ERR_FW_QUARANTINE_FULL, d),
        }
    }
}

impl FirewallError {
    /// Return the stable error code string.
    pub fn code(&self) -> &'static str {
        match self {
            Self::Unclassified(_) => ERR_FW_UNCLASSIFIED,
            Self::NoPolicy(_) => ERR_FW_NO_POLICY,
            Self::InvalidEffect(_) => ERR_FW_INVALID_EFFECT,
            Self::ReceiptFailed(_) => ERR_FW_RECEIPT_FAILED,
            Self::PolicyConflict(_) => ERR_FW_POLICY_CONFLICT,
            Self::ExtensionUnknown(_) => ERR_FW_EXTENSION_UNKNOWN,
            Self::OverrideUnauthorized(_) => ERR_FW_OVERRIDE_UNAUTHORIZED,
            Self::QuarantineFull(_) => ERR_FW_QUARANTINE_FULL,
        }
    }
}

// ── Audit event ─────────────────────────────────────────────────────

/// Structured audit event emitted by the firewall.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FirewallAuditEvent {
    pub event_code: String,
    pub effect_id: String,
    pub trace_id: String,
    pub detail: String,
    pub timestamp: String,
}

// ── Intent classifier ───────────────────────────────────────────────

/// Classifies a remote effect into an intent category.
pub struct IntentClassifier;

impl IntentClassifier {
    /// Classify the intent of a remote effect.
    ///
    /// Returns `None` if the effect cannot be classified (triggering fail-closed).
    pub fn classify(effect: &RemoteEffect) -> Option<IntentClassification> {
        // Rule 1: Credential forwarding detection.
        if effect.carries_credentials {
            return Some(IntentClassification::CredentialForward);
        }

        // Rule 2: Exfiltration detection (sensitive payload to external host).
        if effect.has_sensitive_payload {
            return Some(IntentClassification::Exfiltration);
        }

        // Rule 3: Side-channel probing (many enumeration-style requests).
        if effect.metadata.get("probe_mode").is_some() {
            return Some(IntentClassification::SideChannel);
        }

        // Rule 4: Health check.
        if effect.path.contains("/health") || effect.path.contains("/ping") {
            return Some(IntentClassification::HealthCheck);
        }

        // Rule 5: Config sync.
        if effect.path.contains("/config") || effect.path.contains("/settings") {
            return Some(IntentClassification::ConfigSync);
        }

        // Rule 6: Webhook dispatch.
        if effect.path.contains("/webhook") || effect.path.contains("/hook") {
            return Some(IntentClassification::WebhookDispatch);
        }

        // Rule 7: Analytics export.
        if effect.path.contains("/analytics") || effect.path.contains("/telemetry") {
            return Some(IntentClassification::AnalyticsExport);
        }

        // Rule 8: Service discovery.
        if effect.path.contains("/discover") || effect.path.contains("/services") {
            return Some(IntentClassification::ServiceDiscovery);
        }

        // Rule 9: Data mutation (POST/PUT/PATCH/DELETE).
        let method_upper = effect.method.to_uppercase();
        if matches!(
            method_upper.as_str(),
            "POST" | "PUT" | "PATCH" | "DELETE"
        ) {
            return Some(IntentClassification::DataMutation);
        }

        // Rule 10: Data fetch (GET/HEAD/OPTIONS).
        if matches!(method_upper.as_str(), "GET" | "HEAD" | "OPTIONS") {
            return Some(IntentClassification::DataFetch);
        }

        // Unclassifiable: fail-closed (INV-FW-FAIL-CLOSED).
        None
    }
}

// ── Policy override ─────────────────────────────────────────────────

/// A policy override that changes the verdict for a specific extension+intent.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicyOverride {
    pub extension_id: String,
    pub intent: IntentClassification,
    pub new_verdict: FirewallVerdict,
    pub justification: String,
    pub approved_by: String,
}

// ── Effects firewall ────────────────────────────────────────────────

/// The intent-aware remote effects firewall.
pub struct EffectsFirewall {
    /// Current traffic policy.
    policy: TrafficPolicy,
    /// Active policy overrides (keyed by extension_id + intent).
    overrides: BTreeMap<(String, IntentClassification), PolicyOverride>,
    /// Quarantined effect IDs.
    quarantine: BTreeSet<String>,
    /// Audit log.
    audit_log: Vec<FirewallAuditEvent>,
}

impl EffectsFirewall {
    /// Create a new firewall with the given policy.
    pub fn new(policy: TrafficPolicy) -> Self {
        Self {
            policy,
            overrides: BTreeMap::new(),
            quarantine: BTreeSet::new(),
            audit_log: Vec::new(),
        }
    }

    /// Create a firewall with the default policy.
    pub fn with_default_policy() -> Self {
        Self::new(TrafficPolicy::default_policy())
    }

    /// Register an extension as known to the firewall.
    pub fn register_extension(&mut self, extension_id: &str) {
        self.policy
            .registered_extensions
            .insert(extension_id.to_string());
    }

    /// Add a policy override for a specific extension and intent.
    pub fn add_override(
        &mut self,
        ovr: PolicyOverride,
    ) -> Result<(), FirewallError> {
        if ovr.justification.is_empty() {
            return Err(FirewallError::OverrideUnauthorized(
                "override requires non-empty justification".into(),
            ));
        }
        self.overrides
            .insert((ovr.extension_id.clone(), ovr.intent), ovr);
        Ok(())
    }

    /// Evaluate a remote effect and issue a firewall decision.
    ///
    /// This is the main entry point. Every call produces a `FirewallDecision`.
    pub fn evaluate(
        &mut self,
        effect: &RemoteEffect,
        trace_id: &str,
        timestamp: &str,
    ) -> Result<FirewallDecision, FirewallError> {
        // Validate the effect descriptor.
        effect.validate()?;

        // Emit FW_001: request received.
        self.emit_event(FW_001, &effect.effect_id, trace_id, "request received", timestamp);

        // INV-FW-EXTENSION-SCOPED: only filter extension traffic.
        if !effect.origin.is_extension() {
            // Node-internal traffic bypasses the firewall.
            let decision = FirewallDecision {
                receipt_id: format!("rcpt-{}-bypass", effect.effect_id),
                trace_id: trace_id.to_string(),
                effect_id: effect.effect_id.clone(),
                origin: effect.origin.clone(),
                intent: None,
                verdict: FirewallVerdict::Allow,
                event_code: FW_003.to_string(),
                matched_rule_priority: None,
                rationale: "node-internal traffic bypasses firewall".into(),
                timestamp: timestamp.to_string(),
                schema_version: SCHEMA_VERSION.into(),
            };
            self.emit_event(FW_004, &effect.effect_id, trace_id, "bypass receipt generated", timestamp);
            return Ok(decision);
        }

        // Check extension registration.
        let ext_id = match &effect.origin {
            TrafficOrigin::Extension { extension_id } => extension_id.clone(),
            _ => unreachable!(), // Already checked is_extension above.
        };
        if !self.policy.registered_extensions.contains(&ext_id) {
            return Err(FirewallError::ExtensionUnknown(ext_id));
        }

        // Classify intent.
        let intent = IntentClassifier::classify(effect);
        self.emit_event(
            FW_002,
            &effect.effect_id,
            trace_id,
            &format!("classified as {:?}", intent),
            timestamp,
        );

        // INV-FW-FAIL-CLOSED: deny unclassifiable traffic.
        let intent = match intent {
            Some(i) => i,
            None => {
                self.emit_event(FW_009, &effect.effect_id, trace_id, "unclassifiable traffic denied", timestamp);
                let decision = FirewallDecision {
                    receipt_id: format!("rcpt-{}-denied", effect.effect_id),
                    trace_id: trace_id.to_string(),
                    effect_id: effect.effect_id.clone(),
                    origin: effect.origin.clone(),
                    intent: None,
                    verdict: FirewallVerdict::Deny,
                    event_code: FW_009.to_string(),
                    matched_rule_priority: None,
                    rationale: "unclassifiable traffic denied (fail-closed)".into(),
                    timestamp: timestamp.to_string(),
                    schema_version: SCHEMA_VERSION.into(),
                };
                self.emit_event(FW_004, &effect.effect_id, trace_id, "deny receipt generated", timestamp);
                return Ok(decision);
            }
        };

        // Check for policy override.
        let override_key = (ext_id.clone(), intent);
        if let Some(ovr) = self.overrides.get(&override_key) {
            self.emit_event(FW_010, &effect.effect_id, trace_id, &format!("override applied: {}", ovr.justification), timestamp);
            let verdict = ovr.new_verdict;

            // Apply quarantine check if verdict is quarantine.
            if verdict == FirewallVerdict::Quarantine {
                self.try_quarantine(&effect.effect_id)?;
            }

            let decision = FirewallDecision {
                receipt_id: format!("rcpt-{}-ovr", effect.effect_id),
                trace_id: trace_id.to_string(),
                effect_id: effect.effect_id.clone(),
                origin: effect.origin.clone(),
                intent: Some(intent),
                verdict,
                event_code: FW_010.to_string(),
                matched_rule_priority: None,
                rationale: format!("override: {}", ovr.justification),
                timestamp: timestamp.to_string(),
                schema_version: SCHEMA_VERSION.into(),
            };
            self.emit_event(FW_004, &effect.effect_id, trace_id, "override receipt generated", timestamp);
            return Ok(decision);
        }

        // Match policy rule.
        let rule = self.policy.match_rule(intent);
        let (verdict, rule_priority, rationale) = match rule {
            Some(r) => (r.verdict, Some(r.priority), r.rationale.clone()),
            None => {
                // No policy → deny (fail-closed).
                (
                    FirewallVerdict::Deny,
                    None,
                    "no policy rule found; denied (fail-closed)".into(),
                )
            }
        };

        // Emit risky-category event if applicable (INV-FW-RISKY-DEFAULT-DENY).
        if intent.is_risky() {
            self.emit_event(
                FW_005,
                &effect.effect_id,
                trace_id,
                &format!("risky category {} detected", intent),
                timestamp,
            );
        }

        // Emit pathway-specific events.
        match verdict {
            FirewallVerdict::Challenge => {
                self.emit_event(FW_006, &effect.effect_id, trace_id, "challenge pathway", timestamp);
            }
            FirewallVerdict::Simulate => {
                self.emit_event(FW_007, &effect.effect_id, trace_id, "simulate pathway", timestamp);
            }
            FirewallVerdict::Quarantine => {
                self.try_quarantine(&effect.effect_id)?;
                self.emit_event(FW_008, &effect.effect_id, trace_id, "quarantine pathway", timestamp);
            }
            _ => {}
        }

        // Emit FW_003: verdict issued.
        self.emit_event(
            FW_003,
            &effect.effect_id,
            trace_id,
            &format!("verdict {} for intent {}", verdict, intent),
            timestamp,
        );

        // Build decision receipt (INV-FW-RECEIPT-EVERY-DECISION).
        let decision = FirewallDecision {
            receipt_id: format!("rcpt-{}", effect.effect_id),
            trace_id: trace_id.to_string(),
            effect_id: effect.effect_id.clone(),
            origin: effect.origin.clone(),
            intent: Some(intent),
            verdict,
            event_code: FW_003.to_string(),
            matched_rule_priority: rule_priority,
            rationale,
            timestamp: timestamp.to_string(),
            schema_version: SCHEMA_VERSION.into(),
        };

        // Emit FW_004: receipt generated.
        self.emit_event(FW_004, &effect.effect_id, trace_id, "receipt generated", timestamp);

        Ok(decision)
    }

    /// Attempt to quarantine an effect. Fails if quarantine is full.
    fn try_quarantine(&mut self, effect_id: &str) -> Result<(), FirewallError> {
        if self.quarantine.len() >= self.policy.quarantine_capacity {
            return Err(FirewallError::QuarantineFull(format!(
                "capacity {} reached",
                self.policy.quarantine_capacity
            )));
        }
        self.quarantine.insert(effect_id.to_string());
        Ok(())
    }

    /// Emit a structured audit event.
    fn emit_event(
        &mut self,
        event_code: &str,
        effect_id: &str,
        trace_id: &str,
        detail: &str,
        timestamp: &str,
    ) {
        self.audit_log.push(FirewallAuditEvent {
            event_code: event_code.to_string(),
            effect_id: effect_id.to_string(),
            trace_id: trace_id.to_string(),
            detail: detail.to_string(),
            timestamp: timestamp.to_string(),
        });
    }

    /// Return the audit log.
    pub fn audit_log(&self) -> &[FirewallAuditEvent] {
        &self.audit_log
    }

    /// Return the set of quarantined effect IDs.
    pub fn quarantined(&self) -> &BTreeSet<String> {
        &self.quarantine
    }

    /// Generate a summary report of the firewall state.
    pub fn generate_report(&self) -> BTreeMap<String, String> {
        let mut report = BTreeMap::new();
        report.insert("schema_version".into(), SCHEMA_VERSION.into());
        report.insert("policy_id".into(), self.policy.policy_id.clone());
        report.insert(
            "registered_extensions".into(),
            format!("{}", self.policy.registered_extensions.len()),
        );
        report.insert(
            "quarantine_count".into(),
            format!("{}", self.quarantine.len()),
        );
        report.insert(
            "quarantine_capacity".into(),
            format!("{}", self.policy.quarantine_capacity),
        );
        report.insert(
            "audit_events".into(),
            format!("{}", self.audit_log.len()),
        );
        report.insert(
            "rule_count".into(),
            format!("{}", self.policy.rules.len()),
        );
        report
    }
}

// ── Tests ───────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_effect(effect_id: &str, ext_id: &str) -> RemoteEffect {
        RemoteEffect {
            effect_id: effect_id.into(),
            origin: TrafficOrigin::Extension {
                extension_id: ext_id.into(),
            },
            target_host: "api.example.com".into(),
            target_port: 443,
            method: "GET".into(),
            path: "/data".into(),
            has_sensitive_payload: false,
            carries_credentials: false,
            metadata: BTreeMap::new(),
        }
    }

    fn make_firewall() -> EffectsFirewall {
        let mut fw = EffectsFirewall::with_default_policy();
        fw.register_extension("ext-001");
        fw
    }

    #[test]
    fn test_schema_version() {
        assert_eq!(SCHEMA_VERSION, "fw-v1.0");
    }

    #[test]
    fn test_event_codes_exist() {
        // Verify all event code constants are defined.
        let codes = [FW_001, FW_002, FW_003, FW_004, FW_005, FW_006, FW_007, FW_008, FW_009, FW_010];
        for code in &codes {
            assert!(code.starts_with("FW_"));
        }
    }

    #[test]
    fn test_error_codes_exist() {
        let codes = [
            ERR_FW_UNCLASSIFIED,
            ERR_FW_NO_POLICY,
            ERR_FW_INVALID_EFFECT,
            ERR_FW_RECEIPT_FAILED,
            ERR_FW_POLICY_CONFLICT,
            ERR_FW_EXTENSION_UNKNOWN,
            ERR_FW_OVERRIDE_UNAUTHORIZED,
            ERR_FW_QUARANTINE_FULL,
        ];
        for code in &codes {
            assert!(code.starts_with("ERR_FW_"));
        }
    }

    #[test]
    fn test_invariants_exist() {
        let invs = [
            INV_FW_FAIL_CLOSED,
            INV_FW_RECEIPT_EVERY_DECISION,
            INV_FW_RISKY_DEFAULT_DENY,
            INV_FW_DETERMINISTIC,
            INV_FW_EXTENSION_SCOPED,
        ];
        for inv in &invs {
            assert!(inv.starts_with("INV-FW-"));
        }
    }

    #[test]
    fn test_data_fetch_classification() {
        let effect = make_effect("e1", "ext-001");
        let intent = IntentClassifier::classify(&effect);
        assert_eq!(intent, Some(IntentClassification::DataFetch));
    }

    #[test]
    fn test_data_mutation_classification() {
        let mut effect = make_effect("e2", "ext-001");
        effect.method = "POST".into();
        let intent = IntentClassifier::classify(&effect);
        assert_eq!(intent, Some(IntentClassification::DataMutation));
    }

    #[test]
    fn test_credential_forward_classification() {
        let mut effect = make_effect("e3", "ext-001");
        effect.carries_credentials = true;
        let intent = IntentClassifier::classify(&effect);
        assert_eq!(intent, Some(IntentClassification::CredentialForward));
    }

    #[test]
    fn test_exfiltration_classification() {
        let mut effect = make_effect("e4", "ext-001");
        effect.has_sensitive_payload = true;
        let intent = IntentClassifier::classify(&effect);
        assert_eq!(intent, Some(IntentClassification::Exfiltration));
    }

    #[test]
    fn test_side_channel_classification() {
        let mut effect = make_effect("e5", "ext-001");
        effect.metadata.insert("probe_mode".into(), "true".into());
        let intent = IntentClassifier::classify(&effect);
        assert_eq!(intent, Some(IntentClassification::SideChannel));
    }

    #[test]
    fn test_health_check_classification() {
        let mut effect = make_effect("e6", "ext-001");
        effect.path = "/health/live".into();
        let intent = IntentClassifier::classify(&effect);
        assert_eq!(intent, Some(IntentClassification::HealthCheck));
    }

    #[test]
    fn test_webhook_classification() {
        let mut effect = make_effect("e7", "ext-001");
        effect.path = "/webhook/notify".into();
        let intent = IntentClassifier::classify(&effect);
        assert_eq!(intent, Some(IntentClassification::WebhookDispatch));
    }

    #[test]
    fn test_analytics_classification() {
        let mut effect = make_effect("e8", "ext-001");
        effect.path = "/analytics/report".into();
        let intent = IntentClassifier::classify(&effect);
        assert_eq!(intent, Some(IntentClassification::AnalyticsExport));
    }

    #[test]
    fn test_config_sync_classification() {
        let mut effect = make_effect("e9", "ext-001");
        effect.path = "/config/reload".into();
        let intent = IntentClassifier::classify(&effect);
        assert_eq!(intent, Some(IntentClassification::ConfigSync));
    }

    #[test]
    fn test_service_discovery_classification() {
        let mut effect = make_effect("e10", "ext-001");
        effect.path = "/services/list".into();
        let intent = IntentClassifier::classify(&effect);
        assert_eq!(intent, Some(IntentClassification::ServiceDiscovery));
    }

    #[test]
    fn test_risky_categories() {
        assert!(IntentClassification::Exfiltration.is_risky());
        assert!(IntentClassification::CredentialForward.is_risky());
        assert!(IntentClassification::SideChannel.is_risky());
        assert!(!IntentClassification::DataFetch.is_risky());
        assert!(!IntentClassification::HealthCheck.is_risky());
    }

    #[test]
    fn test_inv_fail_closed_unclassifiable() {
        // INV-FW-FAIL-CLOSED: unknown method + no path hints → deny.
        let mut effect = make_effect("e-unk", "ext-001");
        effect.method = "XYZZY".into();
        effect.path = "/unknown".into();
        let intent = IntentClassifier::classify(&effect);
        assert_eq!(intent, None, "unclassifiable traffic should return None");

        let mut fw = make_firewall();
        let decision = fw.evaluate(&effect, "trace-1", "2026-01-01T00:00:00Z").unwrap();
        assert_eq!(decision.verdict, FirewallVerdict::Deny);
        assert_eq!(decision.event_code, FW_009);
    }

    #[test]
    fn test_inv_risky_default_deny() {
        // INV-FW-RISKY-DEFAULT-DENY: exfiltration is denied by default policy.
        let mut fw = make_firewall();
        let mut effect = make_effect("e-risky", "ext-001");
        effect.has_sensitive_payload = true;
        let decision = fw
            .evaluate(&effect, "trace-2", "2026-01-01T00:00:00Z")
            .unwrap();
        assert_eq!(decision.verdict, FirewallVerdict::Deny);
    }

    #[test]
    fn test_inv_receipt_every_decision_allow() {
        // INV-FW-RECEIPT-EVERY-DECISION: allow decisions produce receipts.
        let mut fw = make_firewall();
        let effect = make_effect("e-allow", "ext-001");
        let decision = fw
            .evaluate(&effect, "trace-3", "2026-01-01T00:00:00Z")
            .unwrap();
        assert_eq!(decision.verdict, FirewallVerdict::Allow);
        assert!(!decision.receipt_id.is_empty());
        assert_eq!(decision.trace_id, "trace-3");
    }

    #[test]
    fn test_inv_extension_scoped_bypass() {
        // INV-FW-EXTENSION-SCOPED: node-internal traffic bypasses the firewall.
        let mut fw = make_firewall();
        let effect = RemoteEffect {
            effect_id: "e-internal".into(),
            origin: TrafficOrigin::NodeInternal {
                subsystem: "core".into(),
            },
            target_host: "api.example.com".into(),
            target_port: 443,
            method: "GET".into(),
            path: "/data".into(),
            has_sensitive_payload: false,
            carries_credentials: false,
            metadata: BTreeMap::new(),
        };
        let decision = fw
            .evaluate(&effect, "trace-4", "2026-01-01T00:00:00Z")
            .unwrap();
        assert_eq!(decision.verdict, FirewallVerdict::Allow);
        assert!(decision.rationale.contains("node-internal"));
    }

    #[test]
    fn test_inv_deterministic() {
        // INV-FW-DETERMINISTIC: same inputs → same outputs.
        let effect = make_effect("e-det", "ext-001");

        let mut fw1 = make_firewall();
        let d1 = fw1.evaluate(&effect, "trace-d", "2026-01-01T00:00:00Z").unwrap();

        let mut fw2 = make_firewall();
        let d2 = fw2.evaluate(&effect, "trace-d", "2026-01-01T00:00:00Z").unwrap();

        assert_eq!(d1.receipt_id, d2.receipt_id);
        assert_eq!(d1.verdict, d2.verdict);
        assert_eq!(d1.intent, d2.intent);
        assert_eq!(d1.rationale, d2.rationale);
    }

    #[test]
    fn test_extension_unknown_error() {
        let mut fw = EffectsFirewall::with_default_policy();
        // Do not register "ext-unknown".
        let effect = make_effect("e-unk-ext", "ext-unknown");
        let result = fw.evaluate(&effect, "trace-5", "2026-01-01T00:00:00Z");
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert_eq!(err.code(), ERR_FW_EXTENSION_UNKNOWN);
    }

    #[test]
    fn test_invalid_effect_empty_id() {
        let mut fw = make_firewall();
        let mut effect = make_effect("", "ext-001");
        effect.effect_id = String::new();
        let result = fw.evaluate(&effect, "trace-6", "2026-01-01T00:00:00Z");
        assert!(result.is_err());
        match result.unwrap_err() {
            FirewallError::InvalidEffect(_) => {}
            other => panic!("expected InvalidEffect, got {:?}", other),
        }
    }

    #[test]
    fn test_invalid_effect_empty_host() {
        let mut fw = make_firewall();
        let mut effect = make_effect("e-bad-host", "ext-001");
        effect.target_host = String::new();
        let result = fw.evaluate(&effect, "trace-7", "2026-01-01T00:00:00Z");
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().code(), ERR_FW_INVALID_EFFECT);
    }

    #[test]
    fn test_quarantine_capacity() {
        let mut policy = TrafficPolicy::default_policy();
        policy.quarantine_capacity = 1;
        policy.registered_extensions.insert("ext-001".into());

        // Add a rule that quarantines data_mutation.
        let rule = TrafficPolicyRule {
            intent: IntentClassification::DataMutation,
            verdict: FirewallVerdict::Quarantine,
            host_pattern: None,
            priority: 100,
            rationale: "quarantine mutations for testing".into(),
        };
        policy.rules.insert(100, rule);

        let mut fw = EffectsFirewall::new(policy);

        // First quarantine succeeds.
        let mut e1 = make_effect("eq-1", "ext-001");
        e1.method = "POST".into();
        let d1 = fw.evaluate(&e1, "t1", "2026-01-01T00:00:00Z").unwrap();
        assert_eq!(d1.verdict, FirewallVerdict::Quarantine);

        // Second quarantine fails (capacity = 1).
        let mut e2 = make_effect("eq-2", "ext-001");
        e2.method = "PUT".into();
        let result = fw.evaluate(&e2, "t2", "2026-01-01T00:00:00Z");
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().code(), ERR_FW_QUARANTINE_FULL);
    }

    #[test]
    fn test_policy_override() {
        let mut fw = make_firewall();
        let ovr = PolicyOverride {
            extension_id: "ext-001".into(),
            intent: IntentClassification::DataFetch,
            new_verdict: FirewallVerdict::Challenge,
            justification: "manual review required".into(),
            approved_by: "admin".into(),
        };
        fw.add_override(ovr).unwrap();

        let effect = make_effect("e-ovr", "ext-001");
        let decision = fw.evaluate(&effect, "trace-o", "2026-01-01T00:00:00Z").unwrap();
        assert_eq!(decision.verdict, FirewallVerdict::Challenge);
        assert!(decision.rationale.contains("manual review required"));
    }

    #[test]
    fn test_override_requires_justification() {
        let mut fw = make_firewall();
        let ovr = PolicyOverride {
            extension_id: "ext-001".into(),
            intent: IntentClassification::DataFetch,
            new_verdict: FirewallVerdict::Deny,
            justification: String::new(), // Empty justification.
            approved_by: "admin".into(),
        };
        let result = fw.add_override(ovr);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().code(), ERR_FW_OVERRIDE_UNAUTHORIZED);
    }

    #[test]
    fn test_audit_log_emitted() {
        let mut fw = make_firewall();
        let effect = make_effect("e-audit", "ext-001");
        fw.evaluate(&effect, "trace-a", "2026-01-01T00:00:00Z").unwrap();
        let log = fw.audit_log();
        assert!(!log.is_empty());
        // Should have at least FW_001, FW_002, FW_003, FW_004.
        let codes: Vec<&str> = log.iter().map(|e| e.event_code.as_str()).collect();
        assert!(codes.contains(&FW_001));
        assert!(codes.contains(&FW_002));
        assert!(codes.contains(&FW_003));
        assert!(codes.contains(&FW_004));
    }

    #[test]
    fn test_default_policy_has_all_intents() {
        let policy = TrafficPolicy::default_policy();
        let covered: BTreeSet<IntentClassification> =
            policy.rules.values().map(|r| r.intent).collect();
        for intent in IntentClassification::all() {
            assert!(
                covered.contains(intent),
                "default policy missing rule for {:?}",
                intent
            );
        }
    }

    #[test]
    fn test_generate_report() {
        let fw = make_firewall();
        let report = fw.generate_report();
        assert_eq!(report.get("schema_version").unwrap(), SCHEMA_VERSION);
        assert!(report.contains_key("policy_id"));
        assert!(report.contains_key("quarantine_count"));
        assert!(report.contains_key("rule_count"));
    }

    #[test]
    fn test_challenge_pathway_event() {
        let mut policy = TrafficPolicy::default_policy();
        policy.registered_extensions.insert("ext-001".into());
        // Override data_fetch to challenge.
        policy.rules.insert(
            200,
            TrafficPolicyRule {
                intent: IntentClassification::DataFetch,
                verdict: FirewallVerdict::Challenge,
                host_pattern: None,
                priority: 200,
                rationale: "challenge all fetches".into(),
            },
        );
        // Remove conflicting lower-priority rule for data_fetch.
        let fetch_priority = policy
            .rules
            .iter()
            .find(|(_, r)| r.intent == IntentClassification::DataFetch && r.priority != 200)
            .map(|(k, _)| *k);
        if let Some(p) = fetch_priority {
            policy.rules.remove(&p);
        }
        let mut fw = EffectsFirewall::new(policy);
        fw.register_extension("ext-001");
        let effect = make_effect("e-ch", "ext-001");
        let decision = fw.evaluate(&effect, "t-ch", "2026-01-01T00:00:00Z").unwrap();
        assert_eq!(decision.verdict, FirewallVerdict::Challenge);
        let codes: Vec<&str> = fw.audit_log().iter().map(|e| e.event_code.as_str()).collect();
        assert!(codes.contains(&FW_006));
    }

    #[test]
    fn test_simulate_pathway_event() {
        let mut policy = TrafficPolicy::default_policy();
        policy.registered_extensions.insert("ext-001".into());
        let fetch_priority = policy
            .rules
            .iter()
            .find(|(_, r)| r.intent == IntentClassification::DataFetch)
            .map(|(k, _)| *k);
        if let Some(p) = fetch_priority {
            policy.rules.remove(&p);
        }
        policy.rules.insert(
            300,
            TrafficPolicyRule {
                intent: IntentClassification::DataFetch,
                verdict: FirewallVerdict::Simulate,
                host_pattern: None,
                priority: 300,
                rationale: "simulate for sandboxed eval".into(),
            },
        );
        let mut fw = EffectsFirewall::new(policy);
        fw.register_extension("ext-001");
        let effect = make_effect("e-sim", "ext-001");
        let decision = fw.evaluate(&effect, "t-sim", "2026-01-01T00:00:00Z").unwrap();
        assert_eq!(decision.verdict, FirewallVerdict::Simulate);
        let codes: Vec<&str> = fw.audit_log().iter().map(|e| e.event_code.as_str()).collect();
        assert!(codes.contains(&FW_007));
    }

    #[test]
    fn test_intent_classification_all_categories() {
        let all = IntentClassification::all();
        assert_eq!(all.len(), 10, "should have 10 intent categories");
    }

    #[test]
    fn test_firewall_error_display() {
        let err = FirewallError::Unclassified("test".into());
        let s = format!("{}", err);
        assert!(s.contains(ERR_FW_UNCLASSIFIED));
        assert!(s.contains("test"));
    }

    #[test]
    fn test_traffic_origin_is_extension() {
        let ext = TrafficOrigin::Extension {
            extension_id: "ext-001".into(),
        };
        assert!(ext.is_extension());
        let internal = TrafficOrigin::NodeInternal {
            subsystem: "core".into(),
        };
        assert!(!internal.is_extension());
    }

    #[test]
    fn test_btreemap_deterministic_ordering() {
        // INV-FW-DETERMINISTIC: BTreeMap iteration order is deterministic.
        let policy = TrafficPolicy::default_policy();
        let keys1: Vec<u32> = policy.rules.keys().copied().collect();
        let keys2: Vec<u32> = policy.rules.keys().copied().collect();
        assert_eq!(keys1, keys2);
    }

    #[test]
    fn test_risky_deny_credential_forward() {
        let mut fw = make_firewall();
        let mut effect = make_effect("e-cred", "ext-001");
        effect.carries_credentials = true;
        let decision = fw.evaluate(&effect, "trace-cf", "2026-01-01T00:00:00Z").unwrap();
        assert_eq!(decision.verdict, FirewallVerdict::Deny);
        assert_eq!(decision.intent, Some(IntentClassification::CredentialForward));
    }

    #[test]
    fn test_risky_deny_side_channel() {
        let mut fw = make_firewall();
        let mut effect = make_effect("e-sc", "ext-001");
        effect.metadata.insert("probe_mode".into(), "true".into());
        let decision = fw.evaluate(&effect, "trace-sc", "2026-01-01T00:00:00Z").unwrap();
        assert_eq!(decision.verdict, FirewallVerdict::Deny);
        assert_eq!(decision.intent, Some(IntentClassification::SideChannel));
    }
}
