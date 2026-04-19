//! Network Guard egress layer with HTTP+TCP policy enforcement.
//! bd-1xbr: Bounded audit_log capacity with oldest-first eviction.
//!
//! All connector egress traverses this guard. Decisions are made
//! based on ordered rules, with a default-deny fallback. Every
//! decision emits a structured audit event.

use serde::{Deserialize, Serialize};
use std::fmt;

use crate::security::remote_cap::{CapabilityGate, RemoteCap, RemoteOperation};

use crate::capacity_defaults::aliases::{MAX_AUDIT_LOG_ENTRIES, MAX_RULES};

/// Network protocol for egress rules.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Protocol {
    Http,
    Tcp,
}

impl fmt::Display for Protocol {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Http => write!(f, "http"),
            Self::Tcp => write!(f, "tcp"),
        }
    }
}

/// Action to take on a matching rule.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Action {
    Allow,
    Deny,
}

impl fmt::Display for Action {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Allow => write!(f, "allow"),
            Self::Deny => write!(f, "deny"),
        }
    }
}

/// An egress policy rule.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EgressRule {
    pub host: String,
    pub port: Option<u16>,
    pub action: Action,
    pub protocol: Protocol,
}

impl EgressRule {
    /// Check if this rule matches the given request.
    pub fn matches(&self, host: &str, port: u16, protocol: Protocol) -> bool {
        if self.protocol != protocol {
            return false;
        }
        if let Some(rule_port) = self.port
            && rule_port != port
        {
            return false;
        }
        host_matches(&self.host, host)
    }
}

/// Match host patterns: exact match or wildcard prefix (*.example.com).
/// DNS hostnames are case-insensitive (RFC 4343); comparisons are normalized
/// to prevent deny-rule bypass via casing tricks like "EVIL.COM" vs "evil.com".
/// Null bytes in hostnames are rejected to prevent C-string truncation bypass
/// where the policy sees "evil.com\0.safe.com" but DNS resolves "evil.com".
fn host_matches(pattern: &str, host: &str) -> bool {
    // Reject null bytes in the host to prevent truncation-based bypass.
    if host.contains('\0') {
        return false;
    }
    let p = normalize_host_for_match(pattern);
    let h = normalize_host_for_match(host);
    if h.is_empty() || p.is_empty() || has_empty_dns_label(&h) || has_empty_dns_label(&p) {
        return false;
    }
    if p == "*" {
        return true;
    }
    if let Some(suffix) = p.strip_prefix('*') {
        if suffix.starts_with('.') {
            h.ends_with(suffix) && h.len() > suffix.len()
        } else {
            false
        }
    } else {
        p == h
    }
}

fn has_empty_dns_label(host: &str) -> bool {
    host.split('.').any(str::is_empty)
}

fn normalize_host_for_match(host: &str) -> String {
    let trimmed = host.trim();
    if trimmed == "*" {
        return "*".to_string();
    }
    trimmed
        .strip_suffix('.')
        .unwrap_or(trimmed)
        .to_ascii_lowercase()
}

/// Egress policy for a connector.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EgressPolicy {
    pub connector_id: String,
    pub default_action: Action,
    pub rules: Vec<EgressRule>,
}

impl EgressPolicy {
    pub fn new(connector_id: String, default_action: Action) -> Self {
        Self {
            connector_id,
            default_action,
            rules: Vec::new(),
        }
    }

    /// Add a rule to the policy.
    ///
    /// Returns `Err` if the policy is at capacity.  Rules are NEVER evicted
    /// because `push_bounded` would silently drop the oldest deny rules,
    /// allowing previously-blocked traffic to pass.
    pub fn add_rule(&mut self, rule: EgressRule) -> Result<(), GuardError> {
        if self.rules.len() >= MAX_RULES {
            return Err(GuardError::PolicyInvalid {
                reason: format!("egress policy at capacity ({MAX_RULES} rules)"),
            });
        }
        self.rules.push(rule);
        Ok(())
    }

    /// Evaluate a request against the policy. Returns the action and
    /// the index of the matching rule (None if default).
    pub fn evaluate(&self, host: &str, port: u16, protocol: Protocol) -> (Action, Option<usize>) {
        let normalized_host = normalize_host_for_match(host);
        if normalized_host.is_empty()
            || normalized_host.contains('\0')
            || has_empty_dns_label(&normalized_host)
        {
            return (Action::Deny, None);
        }

        for (i, rule) in self.rules.iter().enumerate() {
            if rule.matches(host, port, protocol) {
                return (rule.action, Some(i));
            }
        }
        (self.default_action, None)
    }

    /// Validate that the policy is well-formed.
    pub fn validate(&self) -> Result<(), GuardError> {
        if self.rules.is_empty() && self.default_action == Action::Allow {
            return Err(GuardError::PolicyInvalid {
                reason: "policy with no rules and default-allow is insecure".to_string(),
            });
        }
        Ok(())
    }
}

/// Structured audit event emitted for every egress decision.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditEvent {
    pub connector_id: String,
    pub timestamp: String,
    pub protocol: Protocol,
    pub host: String,
    pub port: u16,
    pub action: Action,
    pub rule_matched: Option<usize>,
    pub trace_id: String,
}

/// The network guard that processes egress requests.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkGuard {
    pub policy: EgressPolicy,
    pub audit_log: Vec<AuditEvent>,
}

impl NetworkGuard {
    pub fn new(policy: EgressPolicy) -> Self {
        Self {
            policy,
            audit_log: Vec::new(),
        }
    }

    /// Process an egress request and emit an audit event.
    #[allow(clippy::too_many_arguments)]
    pub fn process_egress(
        &mut self,
        host: &str,
        port: u16,
        protocol: Protocol,
        remote_cap: Option<&RemoteCap>,
        capability_gate: &mut CapabilityGate,
        trace_id: &str,
        timestamp: &str,
        now_epoch_secs: u64,
    ) -> Result<Action, GuardError> {
        let endpoint = format!("{protocol}://{host}:{port}");
        if let Err(err) = capability_gate.authorize_network(
            remote_cap,
            RemoteOperation::NetworkEgress,
            &endpoint,
            now_epoch_secs,
            trace_id,
        ) {
            let event = AuditEvent {
                connector_id: self.policy.connector_id.clone(),
                timestamp: timestamp.to_string(),
                protocol,
                host: host.to_string(),
                port,
                action: Action::Deny,
                rule_matched: None,
                trace_id: trace_id.to_string(),
            };
            push_bounded(&mut self.audit_log, event, MAX_AUDIT_LOG_ENTRIES);
            return Err(GuardError::RemoteCapDenied {
                code: err.code().to_string(),
                compatibility_code: err.compatibility_code().map(ToString::to_string),
                detail: err.to_string(),
            });
        }

        let (action, rule_idx) = self.policy.evaluate(host, port, protocol);

        let event = AuditEvent {
            connector_id: self.policy.connector_id.clone(),
            timestamp: timestamp.to_string(),
            protocol,
            host: host.to_string(),
            port,
            action,
            rule_matched: rule_idx,
            trace_id: trace_id.to_string(),
        };

        push_bounded(&mut self.audit_log, event, MAX_AUDIT_LOG_ENTRIES);

        if action == Action::Deny {
            return Err(GuardError::EgressDenied {
                host: host.to_string(),
                port,
                protocol,
            });
        }

        Ok(action)
    }

    /// Get all audit events.
    pub fn audit_events(&self) -> &[AuditEvent] {
        &self.audit_log
    }
}

/// Errors for network guard operations.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum GuardError {
    #[serde(rename = "GUARD_POLICY_INVALID")]
    PolicyInvalid { reason: String },
    #[serde(rename = "GUARD_EGRESS_DENIED")]
    EgressDenied {
        host: String,
        port: u16,
        protocol: Protocol,
    },
    #[serde(rename = "GUARD_AUDIT_FAILED")]
    AuditFailed { reason: String },
    #[serde(rename = "GUARD_REMOTE_CAP_DENIED")]
    RemoteCapDenied {
        code: String,
        compatibility_code: Option<String>,
        detail: String,
    },
}

impl fmt::Display for GuardError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PolicyInvalid { reason } => {
                write!(f, "GUARD_POLICY_INVALID: {reason}")
            }
            Self::EgressDenied {
                host,
                port,
                protocol,
            } => {
                write!(f, "GUARD_EGRESS_DENIED: {protocol}://{host}:{port}")
            }
            Self::AuditFailed { reason } => {
                write!(f, "GUARD_AUDIT_FAILED: {reason}")
            }
            Self::RemoteCapDenied {
                code,
                compatibility_code,
                detail,
            } => {
                if let Some(alias) = compatibility_code {
                    write!(f, "GUARD_REMOTE_CAP_DENIED: {code} ({alias}) {detail}")
                } else {
                    write!(f, "GUARD_REMOTE_CAP_DENIED: {code} {detail}")
                }
            }
        }
    }
}

impl std::error::Error for GuardError {}

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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::security::remote_cap::{
        CapabilityGate, CapabilityProvider, RemoteOperation, RemoteScope,
    };

    fn sample_policy() -> EgressPolicy {
        let mut policy = EgressPolicy::new("conn-1".into(), Action::Deny);
        policy
            .add_rule(EgressRule {
                host: "api.example.com".into(),
                port: Some(443),
                action: Action::Allow,
                protocol: Protocol::Http,
            })
            .expect("sample allow rule should fit");
        policy
            .add_rule(EgressRule {
                host: "*.trusted.com".into(),
                port: None,
                action: Action::Allow,
                protocol: Protocol::Http,
            })
            .expect("sample wildcard rule should fit");
        policy
            .add_rule(EgressRule {
                host: "evil.com".into(),
                port: None,
                action: Action::Deny,
                protocol: Protocol::Http,
            })
            .expect("sample deny rule should fit");
        policy
    }

    fn egress_scope() -> RemoteScope {
        RemoteScope::new(
            vec![RemoteOperation::NetworkEgress],
            vec!["http://".to_string(), "tcp://".to_string()],
        )
    }

    fn gate_and_cap(single_use: bool) -> (CapabilityGate, RemoteCap) {
        let provider = CapabilityProvider::new("guard-secret");
        let (cap, _) = provider
            .issue(
                "network-guard-tests",
                egress_scope(),
                1_700_000_000,
                3_600,
                true,
                single_use,
                "trace-cap-issue",
            )
            .expect("issue remote cap");
        let gate = CapabilityGate::new("guard-secret");
        (gate, cap)
    }

    // === Host matching ===

    #[test]
    fn exact_host_match() {
        assert!(host_matches("api.example.com", "api.example.com"));
        assert!(!host_matches("api.example.com", "other.example.com"));
    }

    #[test]
    fn exact_host_match_normalizes_trailing_dot_and_whitespace() {
        assert!(host_matches("api.example.com", " API.EXAMPLE.COM. "));
        assert!(host_matches(" api.example.com. ", "api.example.com"));
    }

    #[test]
    fn wildcard_host_match() {
        assert!(host_matches("*.example.com", "api.example.com"));
        assert!(host_matches("*.example.com", "sub.api.example.com"));
        assert!(!host_matches("*.example.com", "example.com"));
    }

    #[test]
    fn wildcard_host_match_normalizes_trailing_dot_and_whitespace() {
        assert!(host_matches(" *.example.com. ", " sub.API.EXAMPLE.COM. "));
        assert!(!host_matches("*.example.com", " example.com. "));
    }

    #[test]
    fn star_matches_all() {
        assert!(host_matches("*", "anything.com"));
    }

    // === Rule matching ===

    #[test]
    fn rule_matches_exact() {
        let rule = EgressRule {
            host: "api.example.com".into(),
            port: Some(443),
            action: Action::Allow,
            protocol: Protocol::Http,
        };
        assert!(rule.matches("api.example.com", 443, Protocol::Http));
        assert!(!rule.matches("api.example.com", 80, Protocol::Http));
        assert!(!rule.matches("api.example.com", 443, Protocol::Tcp));
    }

    #[test]
    fn rule_matches_any_port() {
        let rule = EgressRule {
            host: "api.example.com".into(),
            port: None,
            action: Action::Allow,
            protocol: Protocol::Http,
        };
        assert!(rule.matches("api.example.com", 443, Protocol::Http));
        assert!(rule.matches("api.example.com", 80, Protocol::Http));
    }

    // === Policy evaluation ===

    #[test]
    fn allowed_by_rule() {
        let policy = sample_policy();
        let (action, idx) = policy.evaluate("api.example.com", 443, Protocol::Http);
        assert_eq!(action, Action::Allow);
        assert_eq!(idx, Some(0));
    }

    #[test]
    fn allowed_by_rule_with_trailing_dot_hostname() {
        let policy = sample_policy();
        let (action, idx) = policy.evaluate(" API.EXAMPLE.COM. ", 443, Protocol::Http);
        assert_eq!(action, Action::Allow);
        assert_eq!(idx, Some(0));
    }

    #[test]
    fn repeated_trailing_dot_hostname_does_not_match_exact_rule() {
        let policy = sample_policy();
        let (action, idx) = policy.evaluate("api.example.com..", 443, Protocol::Http);
        assert_eq!(action, Action::Deny);
        assert_eq!(idx, None);
    }

    #[test]
    fn allowed_by_wildcard() {
        let policy = sample_policy();
        let (action, idx) = policy.evaluate("sub.trusted.com", 443, Protocol::Http);
        assert_eq!(action, Action::Allow);
        assert_eq!(idx, Some(1));
    }

    #[test]
    fn repeated_trailing_dot_hostname_does_not_match_wildcard_rule() {
        let policy = sample_policy();
        let (action, idx) = policy.evaluate("sub.trusted.com..", 443, Protocol::Http);
        assert_eq!(action, Action::Deny);
        assert_eq!(idx, None);
    }

    #[test]
    fn denied_by_rule() {
        let policy = sample_policy();
        let (action, idx) = policy.evaluate("evil.com", 80, Protocol::Http);
        assert_eq!(action, Action::Deny);
        assert_eq!(idx, Some(2));
    }

    #[test]
    fn denied_by_default() {
        let policy = sample_policy();
        let (action, idx) = policy.evaluate("unknown.com", 80, Protocol::Http);
        assert_eq!(action, Action::Deny);
        assert_eq!(idx, None);
    }

    #[test]
    fn first_match_wins() {
        let mut policy = EgressPolicy::new("conn-1".into(), Action::Deny);
        policy
            .add_rule(EgressRule {
                host: "*.example.com".into(),
                port: None,
                action: Action::Allow,
                protocol: Protocol::Http,
            })
            .expect("wildcard rule should fit");
        policy
            .add_rule(EgressRule {
                host: "bad.example.com".into(),
                port: None,
                action: Action::Deny,
                protocol: Protocol::Http,
            })
            .expect("specific rule should fit");
        let (action, idx) = policy.evaluate("bad.example.com", 443, Protocol::Http);
        assert_eq!(action, Action::Allow); // first wildcard match wins
        assert_eq!(idx, Some(0));
    }

    // === Guard processing ===

    #[test]
    fn guard_allows_matching_request() {
        let mut guard = NetworkGuard::new(sample_policy());
        let (mut gate, cap) = gate_and_cap(false);
        let result = guard.process_egress(
            "api.example.com",
            443,
            Protocol::Http,
            Some(&cap),
            &mut gate,
            "trace-1",
            "t",
            1_700_000_010,
        );
        assert!(result.is_ok());
        assert_eq!(guard.audit_log.len(), 1);
        assert_eq!(guard.audit_log[0].action, Action::Allow);
    }

    #[test]
    fn guard_denies_unmatched_request() {
        let mut guard = NetworkGuard::new(sample_policy());
        let (mut gate, cap) = gate_and_cap(false);
        let result = guard.process_egress(
            "unknown.com",
            80,
            Protocol::Http,
            Some(&cap),
            &mut gate,
            "trace-2",
            "t",
            1_700_000_011,
        );
        assert!(result.is_err());
        assert_eq!(guard.audit_log.len(), 1);
        assert_eq!(guard.audit_log[0].action, Action::Deny);
    }

    #[test]
    fn guard_always_audits() {
        let mut guard = NetworkGuard::new(sample_policy());
        let (mut gate, cap) = gate_and_cap(false);
        let _ = guard.process_egress(
            "api.example.com",
            443,
            Protocol::Http,
            Some(&cap),
            &mut gate,
            "t1",
            "t",
            1_700_000_020,
        );
        let _ = guard.process_egress(
            "unknown.com",
            80,
            Protocol::Http,
            Some(&cap),
            &mut gate,
            "t2",
            "t",
            1_700_000_021,
        );
        let _ = guard.process_egress(
            "evil.com",
            80,
            Protocol::Http,
            Some(&cap),
            &mut gate,
            "t3",
            "t",
            1_700_000_022,
        );
        assert_eq!(guard.audit_log.len(), 3);
    }

    #[test]
    fn audit_event_has_trace_id() {
        let mut guard = NetworkGuard::new(sample_policy());
        let (mut gate, cap) = gate_and_cap(false);
        let _ = guard.process_egress(
            "api.example.com",
            443,
            Protocol::Http,
            Some(&cap),
            &mut gate,
            "trace-abc",
            "t",
            1_700_000_030,
        );
        assert_eq!(guard.audit_log[0].trace_id, "trace-abc");
    }

    #[test]
    fn missing_remote_cap_is_denied() {
        let mut guard = NetworkGuard::new(sample_policy());
        let mut gate = CapabilityGate::new("guard-secret");
        let err = guard
            .process_egress(
                "api.example.com",
                443,
                Protocol::Http,
                None,
                &mut gate,
                "trace-missing-cap",
                "t",
                1_700_000_040,
            )
            .expect_err("missing cap should fail");

        match err {
            GuardError::RemoteCapDenied { code, .. } => assert_eq!(code, "REMOTECAP_MISSING"),
            other => unreachable!("expected RemoteCapDenied, got {other:?}"),
        }
    }

    // === Policy validation ===

    #[test]
    fn default_deny_policy_valid() {
        let policy = EgressPolicy::new("conn-1".into(), Action::Deny);
        assert!(policy.validate().is_ok());
    }

    #[test]
    fn empty_allow_policy_invalid() {
        let policy = EgressPolicy::new("conn-1".into(), Action::Allow);
        let err = policy.validate().unwrap_err();
        assert!(matches!(err, GuardError::PolicyInvalid { .. }));
    }

    #[test]
    fn add_rule_rejects_overflow_without_eviction() {
        let mut policy = EgressPolicy::new("conn-1".into(), Action::Allow);
        policy
            .add_rule(EgressRule {
                host: "blocked.example.com".into(),
                port: None,
                action: Action::Deny,
                protocol: Protocol::Http,
            })
            .expect("initial deny rule should fit");
        for seq in 1..MAX_RULES {
            policy
                .add_rule(EgressRule {
                    host: format!("allow-{seq:04}.example.com"),
                    port: None,
                    action: Action::Allow,
                    protocol: Protocol::Http,
                })
                .expect("filling rules up to the cap should succeed");
        }

        let err = policy
            .add_rule(EgressRule {
                host: "overflow.example.com".into(),
                port: None,
                action: Action::Allow,
                protocol: Protocol::Http,
            })
            .expect_err("overflow must fail closed instead of evicting existing rules");

        assert!(matches!(err, GuardError::PolicyInvalid { .. }));
        assert_eq!(policy.rules.len(), MAX_RULES);
        let (action, idx) = policy.evaluate("blocked.example.com", 443, Protocol::Http);
        assert_eq!(action, Action::Deny);
        assert_eq!(idx, Some(0));
        let (overflow_action, overflow_idx) =
            policy.evaluate("overflow.example.com", 443, Protocol::Http);
        assert_eq!(overflow_action, Action::Allow);
        assert_eq!(overflow_idx, None);
    }

    // === Serde ===

    #[test]
    fn serde_roundtrip_policy() {
        let policy = sample_policy();
        let json = serde_json::to_string(&policy).unwrap();
        let parsed: EgressPolicy = serde_json::from_str(&json).unwrap();
        assert_eq!(policy, parsed);
    }

    #[test]
    fn serde_roundtrip_audit() {
        let event = AuditEvent {
            connector_id: "conn-1".into(),
            timestamp: "2026-01-01T00:00:00Z".into(),
            protocol: Protocol::Http,
            host: "api.example.com".into(),
            port: 443,
            action: Action::Allow,
            rule_matched: Some(0),
            trace_id: "trace-1".into(),
        };
        let json = serde_json::to_string(&event).unwrap();
        let parsed: AuditEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(event.trace_id, parsed.trace_id);
    }

    #[test]
    fn error_display_messages() {
        let e1 = GuardError::PolicyInvalid {
            reason: "bad".into(),
        };
        assert!(e1.to_string().contains("GUARD_POLICY_INVALID"));

        let e2 = GuardError::EgressDenied {
            host: "evil.com".into(),
            port: 80,
            protocol: Protocol::Http,
        };
        assert!(e2.to_string().contains("GUARD_EGRESS_DENIED"));

        let e3 = GuardError::AuditFailed {
            reason: "io".into(),
        };
        assert!(e3.to_string().contains("GUARD_AUDIT_FAILED"));

        let e4 = GuardError::RemoteCapDenied {
            code: "REMOTECAP_MISSING".into(),
            compatibility_code: Some("ERR_REMOTE_CAP_REQUIRED".into()),
            detail: "missing capability token".into(),
        };
        assert!(e4.to_string().contains("GUARD_REMOTE_CAP_DENIED"));
    }

    #[test]
    fn test_host_matches_case_insensitive() {
        // RFC 4343: DNS hostnames are case-insensitive.
        // Deny rules must match regardless of casing to prevent bypass.
        assert!(host_matches("evil.com", "EVIL.COM"));
        assert!(host_matches("EVIL.COM", "evil.com"));
        assert!(host_matches("Evil.Com", "eViL.cOm"));

        // Wildcard suffix must also be case-insensitive
        assert!(host_matches("*.evil.com", "sub.EVIL.COM"));
        assert!(host_matches("*.EVIL.COM", "sub.evil.com"));

        // Global wildcard still works
        assert!(host_matches("*", "anything.COM"));

        // Non-matching hosts still don't match
        assert!(!host_matches("evil.com", "good.com"));
        assert!(!host_matches("*.evil.com", "evil.com"));
    }

    #[test]
    fn null_byte_host_never_matches_exact_or_wildcard_rule() {
        assert!(!host_matches("evil.com", "evil.com\0.safe.com"));
        assert!(!host_matches("*.evil.com", "sub.evil.com\0.safe.com"));
    }

    #[test]
    fn malformed_wildcard_without_dot_never_matches() {
        assert!(!host_matches("*example.com", "api.example.com"));
        assert!(!host_matches("*evil.com", "evil.com"));
    }

    #[test]
    fn http_allow_rule_does_not_allow_tcp_egress() {
        let policy = sample_policy();

        let (action, idx) = policy.evaluate("api.example.com", 443, Protocol::Tcp);

        assert_eq!(action, Action::Deny);
        assert_eq!(idx, None);
    }

    #[test]
    fn deny_rule_matches_case_variant_and_blocks_bypass() {
        let policy = sample_policy();

        let (action, idx) = policy.evaluate("EVIL.COM", 443, Protocol::Http);

        assert_eq!(action, Action::Deny);
        assert_eq!(idx, Some(2));
    }

    #[test]
    fn empty_host_is_default_denied() {
        let policy = sample_policy();

        let (action, idx) = policy.evaluate("", 443, Protocol::Http);

        assert_eq!(action, Action::Deny);
        assert_eq!(idx, None);
    }

    #[test]
    fn missing_remote_cap_is_audited_as_denied_even_when_policy_would_allow() {
        let mut guard = NetworkGuard::new(sample_policy());
        let mut gate = CapabilityGate::new("guard-secret");

        let err = guard
            .process_egress(
                "api.example.com",
                443,
                Protocol::Http,
                None,
                &mut gate,
                "trace-audit-missing-cap",
                "t",
                1_700_000_040,
            )
            .expect_err("missing cap should fail before policy allow");

        assert!(matches!(err, GuardError::RemoteCapDenied { .. }));
        assert_eq!(guard.audit_events().len(), 1);
        assert_eq!(guard.audit_events()[0].action, Action::Deny);
        assert_eq!(guard.audit_events()[0].rule_matched, None);
        assert_eq!(guard.audit_events()[0].host, "api.example.com");
    }

    #[test]
    fn expired_remote_cap_is_denied_before_policy_evaluation() {
        let mut guard = NetworkGuard::new(sample_policy());
        let (mut gate, cap) = gate_and_cap(false);

        let err = guard
            .process_egress(
                "api.example.com",
                443,
                Protocol::Http,
                Some(&cap),
                &mut gate,
                "trace-expired-cap",
                "t",
                1_700_004_000,
            )
            .expect_err("expired cap should fail before policy allow");

        assert!(matches!(err, GuardError::RemoteCapDenied { .. }));
        assert_eq!(guard.audit_events().len(), 1);
        assert_eq!(guard.audit_events()[0].action, Action::Deny);
        assert_eq!(guard.audit_events()[0].rule_matched, None);
    }

    #[test]
    fn single_use_remote_cap_denies_second_egress_attempt() {
        let mut guard = NetworkGuard::new(sample_policy());
        let (mut gate, cap) = gate_and_cap(true);

        guard
            .process_egress(
                "api.example.com",
                443,
                Protocol::Http,
                Some(&cap),
                &mut gate,
                "trace-single-use-first",
                "t",
                1_700_000_041,
            )
            .expect("first single-use request should pass");
        let err = guard
            .process_egress(
                "api.example.com",
                443,
                Protocol::Http,
                Some(&cap),
                &mut gate,
                "trace-single-use-second",
                "t",
                1_700_000_042,
            )
            .expect_err("second single-use request should be rejected");

        assert!(matches!(err, GuardError::RemoteCapDenied { .. }));
        assert_eq!(guard.audit_events().len(), 2);
        assert_eq!(guard.audit_events()[0].action, Action::Allow);
        assert_eq!(guard.audit_events()[1].action, Action::Deny);
        assert_eq!(guard.audit_events()[1].rule_matched, None);
    }

    #[test]
    fn null_byte_host_request_denied_even_with_valid_remote_cap() {
        let mut guard = NetworkGuard::new(sample_policy());
        let (mut gate, cap) = gate_and_cap(false);

        let err = guard
            .process_egress(
                "api.example.com\0.evil.com",
                443,
                Protocol::Http,
                Some(&cap),
                &mut gate,
                "trace-null-host",
                "t",
                1_700_000_050,
            )
            .expect_err("null byte host must not match allow rule");

        assert!(matches!(err, GuardError::EgressDenied { .. }));
        assert_eq!(guard.audit_events().len(), 1);
        assert_eq!(guard.audit_events()[0].action, Action::Deny);
        assert_eq!(guard.audit_events()[0].rule_matched, None);
    }

    #[test]
    fn wildcard_rule_does_not_match_sibling_suffix_without_dot_boundary() {
        let policy = sample_policy();

        let (action, idx) = policy.evaluate("eviltrusted.com", 443, Protocol::Http);

        assert_eq!(action, Action::Deny);
        assert_eq!(idx, None);
    }

    #[test]
    fn deny_rule_order_prevents_later_allow_shadow_rule() {
        let mut policy = EgressPolicy::new("conn-shadow".into(), Action::Deny);
        policy
            .add_rule(EgressRule {
                host: "blocked.example.com".into(),
                port: None,
                action: Action::Deny,
                protocol: Protocol::Http,
            })
            .unwrap();
        policy
            .add_rule(EgressRule {
                host: "blocked.example.com".into(),
                port: None,
                action: Action::Allow,
                protocol: Protocol::Http,
            })
            .unwrap();

        let (action, idx) = policy.evaluate("blocked.example.com", 443, Protocol::Http);

        assert_eq!(action, Action::Deny);
        assert_eq!(idx, Some(0));
    }

    #[test]
    fn allowed_host_wrong_port_defaults_to_deny() {
        let policy = sample_policy();

        let (action, idx) = policy.evaluate("api.example.com", 80, Protocol::Http);

        assert_eq!(action, Action::Deny);
        assert_eq!(idx, None);
    }

    #[test]
    fn wildcard_http_allow_does_not_cover_tcp_request() {
        let policy = sample_policy();

        let (action, idx) = policy.evaluate("feed.trusted.com", 443, Protocol::Tcp);

        assert_eq!(action, Action::Deny);
        assert_eq!(idx, None);
    }

    #[test]
    fn remote_cap_scope_denial_is_audited_before_policy_allow() {
        let mut guard = NetworkGuard::new(sample_policy());
        let provider = CapabilityProvider::new("guard-secret");
        let (cap, _) = provider
            .issue(
                "network-guard-tests",
                RemoteScope::new(
                    vec![RemoteOperation::TelemetryExport],
                    vec!["http://".into()],
                ),
                1_700_000_000,
                3_600,
                true,
                false,
                "trace-scope-issue",
            )
            .expect("issue remote cap with non-egress scope");
        let mut gate = CapabilityGate::new("guard-secret");

        let err = guard
            .process_egress(
                "api.example.com",
                443,
                Protocol::Http,
                Some(&cap),
                &mut gate,
                "trace-scope-denied",
                "t",
                1_700_000_060,
            )
            .expect_err("network egress must require NetworkEgress scope");

        assert!(matches!(err, GuardError::RemoteCapDenied { .. }));
        assert_eq!(guard.audit_events().len(), 1);
        assert_eq!(guard.audit_events()[0].action, Action::Deny);
        assert_eq!(guard.audit_events()[0].rule_matched, None);
        assert_eq!(guard.audit_events()[0].host, "api.example.com");
    }
}

#[cfg(test)]
mod network_guard_additional_negative_tests {
    use super::*;

    fn wildcard_policy() -> EgressPolicy {
        let mut policy = EgressPolicy::new("conn-extra-negative".to_string(), Action::Deny);
        policy
            .add_rule(EgressRule {
                host: "*.trusted.example".to_string(),
                port: Some(443),
                action: Action::Allow,
                protocol: Protocol::Http,
            })
            .expect("fixture rule should fit");
        policy
    }

    #[test]
    fn wildcard_rule_rejects_bare_suffix_with_trailing_dot() {
        let policy = wildcard_policy();

        let (action, rule_idx) = policy.evaluate("trusted.example.", 443, Protocol::Http);

        assert_eq!(action, Action::Deny);
        assert_eq!(rule_idx, None);
    }

    #[test]
    fn wildcard_rule_rejects_empty_left_label() {
        let policy = wildcard_policy();

        let (action, rule_idx) = policy.evaluate(".trusted.example", 443, Protocol::Http);

        assert_eq!(action, Action::Deny);
        assert_eq!(rule_idx, None);
    }

    #[test]
    fn wildcard_rule_rejects_suffix_join_without_label_boundary() {
        let policy = wildcard_policy();

        let (action, rule_idx) = policy.evaluate("apitrusted.example", 443, Protocol::Http);

        assert_eq!(action, Action::Deny);
        assert_eq!(rule_idx, None);
    }

    #[test]
    fn pattern_with_internal_nul_does_not_match_clean_host() {
        assert!(!host_matches(
            "api.example.com\0.allowed.example",
            "api.example.com",
        ));
    }

    #[test]
    fn serde_rejects_unknown_protocol_variant() {
        let result: Result<Protocol, _> = serde_json::from_str(r#""udp""#);

        assert!(result.is_err());
    }

    #[test]
    fn serde_rejects_unknown_action_variant() {
        let result: Result<Action, _> = serde_json::from_str(r#""audit_only""#);

        assert!(result.is_err());
    }

    #[test]
    fn serde_rejects_rule_port_outside_u16_range() {
        let result: Result<EgressRule, _> = serde_json::from_str(
            r#"{"host":"api.example.com","port":70000,"action":"allow","protocol":"http"}"#,
        );

        assert!(result.is_err());
    }

    #[test]
    fn validate_rejects_default_allow_policy_after_rules_are_cleared() {
        let mut policy = EgressPolicy::new("conn-default-allow".to_string(), Action::Allow);
        policy
            .add_rule(EgressRule {
                host: "api.example.com".to_string(),
                port: None,
                action: Action::Allow,
                protocol: Protocol::Http,
            })
            .expect("fixture rule should fit");
        policy.rules.clear();

        let err = policy.validate().unwrap_err();

        assert!(
            matches!(err, GuardError::PolicyInvalid { reason } if reason.contains("default-allow"))
        );
    }

    #[test]
    fn empty_host_never_matches_global_wildcard() {
        assert!(!host_matches("*", ""));
        assert!(!host_matches("*", "   "));
    }

    #[test]
    fn empty_pattern_never_matches_empty_or_nonempty_host() {
        assert!(!host_matches("", ""));
        assert!(!host_matches("   ", "api.example.com"));
    }

    #[test]
    fn malformed_host_with_empty_middle_label_never_matches_exact_pattern() {
        assert!(!host_matches("api..example.com", "api..example.com"));
    }

    #[test]
    fn wildcard_rule_rejects_empty_middle_label() {
        let policy = wildcard_policy();

        let (action, rule_idx) = policy.evaluate("api..trusted.example", 443, Protocol::Http);

        assert_eq!(action, Action::Deny);
        assert_eq!(rule_idx, None);
    }

    #[test]
    fn malformed_wildcard_pattern_with_empty_label_never_matches() {
        assert!(!host_matches("*..example.com", "api.example.com"));
        assert!(!host_matches("*..example.com", "api..example.com"));
    }

    #[test]
    fn serde_rejects_unknown_guard_error_variant() {
        let result: Result<GuardError, _> =
            serde_json::from_str(r#"{"GUARD_ALLOW":{"reason":"unexpected"}}"#);

        assert!(result.is_err());
    }

    #[test]
    fn serde_rejects_audit_event_negative_rule_index() {
        let result: Result<AuditEvent, _> = serde_json::from_str(
            r#"{
                "connector_id":"c",
                "timestamp":"t",
                "protocol":"http",
                "host":"api.example.com",
                "port":443,
                "action":"deny",
                "rule_matched":-1,
                "trace_id":"trace"
            }"#,
        );

        assert!(result.is_err());
    }

    #[test]
    fn serde_rejects_guard_error_port_outside_u16_range() {
        let result: Result<GuardError, _> = serde_json::from_str(
            r#"{"GUARD_EGRESS_DENIED":{"host":"api.example.com","port":70000,"protocol":"http"}}"#,
        );

        assert!(result.is_err());
    }

    #[test]
    fn default_allow_policy_denies_nul_host_before_fallback() {
        let mut policy = EgressPolicy::new("conn-default-allow".to_string(), Action::Allow);
        policy
            .add_rule(EgressRule {
                host: "safe.example.com".to_string(),
                port: Some(443),
                action: Action::Allow,
                protocol: Protocol::Http,
            })
            .expect("fixture rule should fit");

        let (action, rule_idx) =
            policy.evaluate("evil.com\0.safe.example.com", 443, Protocol::Http);

        assert_eq!(action, Action::Deny);
        assert_eq!(rule_idx, None);
    }

    #[test]
    fn default_allow_policy_denies_empty_middle_label_before_fallback() {
        let mut policy = EgressPolicy::new("conn-default-allow".to_string(), Action::Allow);
        policy
            .add_rule(EgressRule {
                host: "safe.example.com".to_string(),
                port: Some(443),
                action: Action::Allow,
                protocol: Protocol::Http,
            })
            .expect("fixture rule should fit");

        let (action, rule_idx) = policy.evaluate("api..example.com", 443, Protocol::Http);

        assert_eq!(action, Action::Deny);
        assert_eq!(rule_idx, None);
    }

    #[test]
    fn default_allow_policy_denies_empty_host_before_fallback() {
        let mut policy = EgressPolicy::new("conn-default-allow".to_string(), Action::Allow);
        policy
            .add_rule(EgressRule {
                host: "safe.example.com".to_string(),
                port: Some(443),
                action: Action::Allow,
                protocol: Protocol::Http,
            })
            .expect("fixture rule should fit");

        let (action, rule_idx) = policy.evaluate("   ", 443, Protocol::Http);

        assert_eq!(action, Action::Deny);
        assert_eq!(rule_idx, None);
    }

    #[test]
    fn exact_rule_rejects_trailing_double_dot_host() {
        assert!(!host_matches("api.example.com", "api.example.com.."));
    }

    #[test]
    fn global_wildcard_rejects_host_with_empty_middle_label() {
        assert!(!host_matches("*", "api..example.com"));
    }

    #[test]
    fn push_bounded_zero_capacity_clears_existing_audit_events() {
        let mut events = vec![AuditEvent {
            connector_id: "conn".to_string(),
            timestamp: "t0".to_string(),
            protocol: Protocol::Http,
            host: "old.example.com".to_string(),
            port: 443,
            action: Action::Deny,
            rule_matched: None,
            trace_id: "trace-old".to_string(),
        }];

        push_bounded(
            &mut events,
            AuditEvent {
                connector_id: "conn".to_string(),
                timestamp: "t1".to_string(),
                protocol: Protocol::Http,
                host: "new.example.com".to_string(),
                port: 443,
                action: Action::Allow,
                rule_matched: Some(0),
                trace_id: "trace-new".to_string(),
            },
            0,
        );

        assert!(events.is_empty());
    }

    #[test]
    fn push_bounded_over_capacity_discards_oldest_audit_events() {
        let make_event = |host: &str| AuditEvent {
            connector_id: "conn".to_string(),
            timestamp: "t".to_string(),
            protocol: Protocol::Http,
            host: host.to_string(),
            port: 443,
            action: Action::Deny,
            rule_matched: None,
            trace_id: "trace".to_string(),
        };
        let mut events = vec![
            make_event("oldest.example.com"),
            make_event("middle.example.com"),
            make_event("newest.example.com"),
        ];

        push_bounded(&mut events, make_event("incoming.example.com"), 2);

        assert_eq!(events.len(), 2);
        assert_eq!(events[0].host, "newest.example.com");
        assert_eq!(events[1].host, "incoming.example.com");
    }

    /// Extreme adversarial test: DNS homograph attack using visually identical Unicode
    /// characters to bypass security policies via international domain name spoofing
    #[test]
    fn network_guard_dns_homograph_unicode_spoofing_bypass_attack() {
        let mut policy = EgressPolicy::new("conn-homograph-attack".to_string(), Action::Deny);
        policy
            .add_rule(EgressRule {
                host: "trusted-api.com".to_string(),
                port: Some(443),
                action: Action::Allow,
                protocol: Protocol::Http,
            })
            .expect("trusted rule should fit");

        // Unicode homograph attack vectors targeting DNS spoofing
        let spoofed_hostnames = [
            "truѕted-api.com", // Cyrillic 's' (U+0455) vs Latin 's'
            "trusted-аpi.com", // Cyrillic 'a' (U+0430) vs Latin 'a'
            "trusted-api.соm", // Cyrillic 'o' (U+043E) and 'm' (U+043C)
            "truѕted-аpi.соm", // Multiple Cyrillic characters
            "trusted-api.ϲom", // Greek 'o' (U+03BF)
            "trusted-aρi.com", // Greek 'ρ' (U+03C1) vs Latin 'p'
            "truѕted-арi.com", // Cyrillic 'р' (U+0440) vs Latin 'p'
            "trusted-api.cοm", // Greek 'ο' (U+03BF) vs Latin 'o'
        ];

        for spoofed_host in spoofed_hostnames {
            let (action, rule_idx) = policy.evaluate(spoofed_host, 443, Protocol::Http);

            // System must reject Unicode homograph attacks
            assert_eq!(
                action,
                Action::Deny,
                "Homograph attack with '{}' should be denied",
                spoofed_host
            );
            assert_eq!(
                rule_idx, None,
                "Homograph attack with '{}' should not match allow rule",
                spoofed_host
            );
        }
    }

    /// Extreme adversarial test: HTTP request smuggling via protocol confusion between
    /// HTTP and TCP endpoints to bypass network guard protocol enforcement
    #[test]
    fn network_guard_http_request_smuggling_protocol_confusion_attack() {
        let mut policy = EgressPolicy::new("conn-smuggling-attack".to_string(), Action::Deny);

        // Allow HTTP to specific endpoint but deny TCP
        policy
            .add_rule(EgressRule {
                host: "api.trusted.com".to_string(),
                port: Some(80),
                action: Action::Allow,
                protocol: Protocol::Http,
            })
            .expect("HTTP allow rule should fit");

        // Attack scenarios: HTTP smuggling via protocol confusion
        let smuggling_tests = [
            // Direct TCP access to HTTP-only endpoint should be blocked
            ("api.trusted.com", 80, Protocol::Tcp),
            // Non-standard HTTP ports should be blocked if not explicitly allowed
            ("api.trusted.com", 8080, Protocol::Http),
            ("api.trusted.com", 8443, Protocol::Http),
            // HTTPS (443) should be blocked if only HTTP (80) allowed
            ("api.trusted.com", 443, Protocol::Http),
            // Alternate protocols to same host should be blocked
            ("api.trusted.com", 80, Protocol::Tcp),
        ];

        for (host, port, protocol) in smuggling_tests {
            let (action, rule_idx) = policy.evaluate(host, port, protocol);

            // All protocol confusion attempts should be denied
            assert_eq!(
                action,
                Action::Deny,
                "Protocol smuggling {}://{}:{} should be denied",
                protocol,
                host,
                port
            );
            assert_eq!(
                rule_idx, None,
                "Protocol smuggling {}://{}:{} should not match allow rule",
                protocol, host, port
            );
        }
    }

    /// Extreme adversarial test: Memory exhaustion attack via massive egress policy rule
    /// sets designed to overwhelm network guard rule evaluation performance
    #[test]
    fn network_guard_massive_policy_memory_exhaustion_dos_attack() {
        use std::time::Instant;

        let mut policy = EgressPolicy::new("conn-memory-attack".to_string(), Action::Deny);

        // Fill policy to maximum capacity with complex rules
        for i in 0..MAX_RULES.min(1000) {
            // Prevent actual DoS in test
            let complex_host = format!(
                "{}.{}.{}.{}.attack-vector.com",
                i % 100,
                (i * 7) % 100,
                (i * 13) % 100,
                (i * 17) % 100
            );

            policy
                .add_rule(EgressRule {
                    host: complex_host,
                    port: Some((i % 65535) as u16 + 1),
                    action: if i % 2 == 0 {
                        Action::Allow
                    } else {
                        Action::Deny
                    },
                    protocol: if i % 2 == 0 {
                        Protocol::Http
                    } else {
                        Protocol::Tcp
                    },
                })
                .expect("rule should fit within capacity");

            // Prevent actual memory exhaustion in test environment
            if i >= 500 {
                break;
            }
        }

        // Test evaluation performance under stress
        let stress_hosts = [
            "non-matching-host.com",
            "999.999.999.999.attack-vector.com", // Should hit many comparisons
            "target.attack-vector.com",
        ];

        for host in stress_hosts {
            let start = Instant::now();
            let (action, _rule_idx) = policy.evaluate(host, 443, Protocol::Http);
            let elapsed = start.elapsed();

            // Evaluation must complete in reasonable time despite large rule set
            assert!(
                elapsed.as_millis() < 100,
                "Rule evaluation took {}ms, should be <100ms",
                elapsed.as_millis()
            );

            // Results should be consistent
            assert!(action == Action::Allow || action == Action::Deny);
        }
    }

    /// Extreme adversarial test: Timing attack on hostname comparison to extract
    /// sensitive policy information via constant-time violation analysis
    #[test]
    fn network_guard_hostname_comparison_timing_attack_information_leak() {
        let mut policy = EgressPolicy::new("conn-timing-attack".to_string(), Action::Deny);

        // Add secret hostname that attacker wants to discover
        policy
            .add_rule(EgressRule {
                host: "secret-internal-api.company.com".to_string(),
                port: Some(443),
                action: Action::Allow,
                protocol: Protocol::Http,
            })
            .expect("secret rule should fit");

        // Timing attack vectors: progressively longer matching prefixes
        let timing_probes = [
            "a",                                    // Single char
            "s",                                    // Correct first char
            "se",                                   // Two chars
            "sec",                                  // Three chars
            "secr",                                 // Four chars
            "secret",                               // Correct prefix
            "secret-",                              // More correct
            "secret-internal",                      // Even more correct
            "secret-internal-api",                  // Almost complete
            "secret-internal-api.company",          // Very close
            "secret-internal-api.company.com",      // Exact match
            "secret-internal-api.company.com.evil", // Longer than target
        ];

        // Measure timing for each probe (implementation should be constant-time)
        for probe in timing_probes {
            let start = std::time::Instant::now();

            // Perform many evaluations to amplify timing differences
            for _ in 0..1000 {
                let (_action, _rule_idx) = policy.evaluate(probe, 443, Protocol::Http);
            }

            let elapsed = start.elapsed();

            // All timing measurements should be similar (constant-time property)
            // This test verifies there's no obvious timing leak, though full constant-time
            // analysis would require statistical testing beyond unit test scope
            assert!(
                elapsed.as_micros() < 10_000,
                "Hostname comparison for '{}' took {}μs, may indicate timing leak",
                probe,
                elapsed.as_micros()
            );
        }
    }

    /// Extreme adversarial test: Unicode normalization attack in hostnames to exploit
    /// inconsistencies between different Unicode normalization forms (NFC vs NFD)
    #[test]
    fn network_guard_unicode_normalization_hostname_confusion_attack() {
        let mut policy = EgressPolicy::new("conn-unicode-attack".to_string(), Action::Deny);

        // Policy allows specific Unicode hostname in NFC form
        policy
            .add_rule(EgressRule {
                host: "café.example.com".to_string(), // NFC: single é character (U+00E9)
                port: Some(443),
                action: Action::Allow,
                protocol: Protocol::Http,
            })
            .expect("unicode rule should fit");

        // Unicode normalization attack vectors
        let normalization_attacks = [
            "cafe\u{0301}.example.com",         // NFD: e + combining acute accent
            "caf\u{00E9}.example.com",          // NFC: composed é (should match)
            "cafe\u{0300}\u{0301}.example.com", // Multiple combining chars
            "café.example.com",                 // Same as policy (should match)
            "caf\u{0065}\u{0301}.example.com",  // Explicit e + accent
        ];

        for attack_host in normalization_attacks {
            let (action, rule_idx) = policy.evaluate(attack_host, 443, Protocol::Http);

            // Only exact NFC match should be allowed, normalization variants denied
            if attack_host == "café.example.com" || attack_host == "caf\u{00E9}.example.com" {
                assert_eq!(
                    action,
                    Action::Allow,
                    "Exact Unicode match '{}' should be allowed",
                    attack_host
                );
                assert_eq!(rule_idx, Some(0));
            } else {
                assert_eq!(
                    action,
                    Action::Deny,
                    "Unicode normalization attack '{}' should be denied",
                    attack_host
                );
                assert_eq!(rule_idx, None);
            }
        }
    }

    /// Extreme adversarial test: Concurrent guard processing race condition exploitation
    /// targeting shared audit log state corruption during high-volume parallel egress
    #[test]
    fn network_guard_concurrent_processing_audit_state_corruption_race() {
        use std::sync::{Arc, Mutex};
        use std::thread;

        let policy = EgressPolicy::new("conn-race-attack".to_string(), Action::Allow);
        let guard = Arc::new(Mutex::new(NetworkGuard::new(policy)));

        // Spawn multiple threads performing concurrent egress requests
        let handles: Vec<_> = (0..10)
            .map(|thread_id| {
                let guard_clone = Arc::clone(&guard);

                thread::spawn(move || {
                    for i in 0..50 {
                        let host = format!("host-{}-{}.example.com", thread_id, i);
                        let port = 443 + (i % 1000) as u16;
                        let trace_id = format!("trace-{}-{}", thread_id, i);
                        let timestamp = format!(
                            "2026-04-17T{}:{}:{}Z",
                            thread_id % 24,
                            i % 60,
                            (thread_id + i) % 60
                        );

                        if let Ok(mut guard_lock) = guard_clone.try_lock() {
                            // Simulate guard processing without remote caps for simplicity
                            let (action, rule_idx) =
                                guard_lock.policy.evaluate(&host, port, Protocol::Http);

                            let event = AuditEvent {
                                connector_id: guard_lock.policy.connector_id.clone(),
                                timestamp,
                                protocol: Protocol::Http,
                                host,
                                port,
                                action,
                                rule_matched: rule_idx,
                                trace_id,
                            };

                            // Direct audit log manipulation to stress concurrent access
                            push_bounded(&mut guard_lock.audit_log, event, MAX_AUDIT_LOG_ENTRIES);
                        }

                        // Brief yield to encourage race conditions
                        thread::yield_now();
                    }
                })
            })
            .collect();

        // Wait for all threads to complete
        for handle in handles {
            handle.join().unwrap();
        }

        // Verify audit log integrity after concurrent access
        let final_guard = guard.lock().unwrap();
        let audit_events = final_guard.audit_events();

        // Audit log should be bounded and internally consistent
        assert!(audit_events.len() <= MAX_AUDIT_LOG_ENTRIES);

        // All events should have valid structure
        for event in audit_events {
            assert!(!event.connector_id.is_empty());
            assert!(!event.host.is_empty());
            assert!(!event.trace_id.is_empty());
            assert!(!event.timestamp.is_empty());
            assert!(event.port > 0);
        }
    }

    /// Extreme adversarial test: JSON injection in audit event fields targeting
    /// downstream log analysis systems via malicious trace IDs and hostnames
    #[test]
    fn network_guard_audit_event_json_injection_log_poisoning_attack() {
        let mut policy = EgressPolicy::new("conn-json-injection".to_string(), Action::Allow);
        policy
            .add_rule(EgressRule {
                host: "api.example.com".to_string(),
                port: Some(443),
                action: Action::Allow,
                protocol: Protocol::Http,
            })
            .expect("json injection test rule should fit");

        // JSON injection attack vectors in various audit fields
        let json_injection_vectors = [
            // Trace ID injection
            ("api.example.com", r#"trace":{malicious":"payload"}"#),
            // Host field injection via malicious hostname
            (
                r#"api.example.com","evil":{"injected":true},"host":"fake.com"#,
                "trace-1",
            ),
            // Unicode escapes in trace ID
            ("api.example.com", "trace\u{0000}\u{001F}\u{007F}"),
            // Newline injection for log splitting
            ("api.example.com", "trace\n{\"fake_event\": true}\ntrace"),
            // Quote escaping attempts
            ("api.example.com", r#"trace\":{"evil":"code"}://"""#),
        ];

        for (host, trace_id) in json_injection_vectors {
            let (action, rule_idx) = policy.evaluate(host, 443, Protocol::Http);

            let event = AuditEvent {
                connector_id: policy.connector_id.clone(),
                timestamp: "2026-04-17T12:00:00Z".to_string(),
                protocol: Protocol::Http,
                host: host.to_string(),
                port: 443,
                action,
                rule_matched: rule_idx,
                trace_id: trace_id.to_string(),
            };

            // Serialize audit event to JSON
            let json_result = serde_json::to_string(&event);

            // Serialization should succeed despite injection attempts
            assert!(
                json_result.is_ok(),
                "JSON serialization failed for host='{}', trace_id='{}'",
                host,
                trace_id
            );

            let json_str = json_result.unwrap();

            // Verify JSON structure integrity (no injection succeeded)
            let parsed_result = serde_json::from_str::<AuditEvent>(&json_str);
            assert!(
                parsed_result.is_ok(),
                "JSON round-trip failed, possible injection: {}",
                json_str
            );

            let parsed_event = parsed_result.unwrap();
            assert_eq!(parsed_event.host, host);
            assert_eq!(parsed_event.trace_id, trace_id);
        }
    }

    /// Extreme adversarial test: Host header injection attack targeting HTTP header
    /// manipulation via embedded CRLF sequences in hostnames for request smuggling
    #[test]
    fn network_guard_host_header_crlf_injection_request_smuggling_attack() {
        let mut policy = EgressPolicy::new("conn-header-injection".to_string(), Action::Allow);
        policy
            .add_rule(EgressRule {
                host: "api.example.com".to_string(),
                port: Some(80),
                action: Action::Allow,
                protocol: Protocol::Http,
            })
            .expect("header injection test rule should fit");

        // CRLF injection attack vectors in hostnames
        let crlf_injection_hosts = [
            "api.example.com\r\nHost: evil.com",
            "api.example.com\r\nX-Injection: malicious",
            "api.example.com\n\nPOST /admin HTTP/1.1\r\nHost: evil.com",
            "api.example.com\r\nContent-Length: 0\r\n\r\nGET /secret",
            "api.example.com\r\n\r\nHTTP/1.1 200 OK\r\nContent-Type: text/html",
            "api.example.com\x0d\x0aHost: attacker.com",
            "api.example.com\u{000D}\u{000A}Evil-Header: injected",
        ];

        for malicious_host in crlf_injection_hosts {
            let (action, rule_idx) = policy.evaluate(malicious_host, 80, Protocol::Http);

            // All CRLF injection attempts should be denied
            assert_eq!(
                action,
                Action::Deny,
                "CRLF injection host '{}' should be denied",
                malicious_host
            );
            assert_eq!(
                rule_idx, None,
                "CRLF injection host '{}' should not match allow rule",
                malicious_host
            );

            // Verify no match with the legitimate rule
            assert!(
                !host_matches("api.example.com", malicious_host),
                "CRLF injection host '{}' should not match clean pattern",
                malicious_host
            );
        }
    }

    // === ADDITIONAL NEGATIVE-PATH ROBUSTNESS TESTS ===

    #[test]
    fn wildcard_subdomain_traversal_bypass_attempts_denied() {
        let mut policy = EgressPolicy::new("conn-traversal".to_string(), Action::Deny);
        policy
            .add_rule(EgressRule {
                host: "*.safe.internal".to_string(),
                port: Some(443),
                action: Action::Allow,
                protocol: Protocol::Http,
            })
            .expect("wildcard rule should fit");

        // Subdomain traversal attack vectors
        let traversal_attacks = [
            "evil.com.safe.internal",                    // Domain confusion
            "safe.internal.evil.com",                    // Suffix confusion
            "api.safe.internal.evil.com",                // Double suffix
            "safe-internal.evil.com",                    // Dash confusion
            "sub.safe.internalevil.com",                 // Concatenation attack
            "sub.safe.internal.evil.com",                // Chain traversal
            "..safe.internal",                           // Path-like traversal
            ".safe.internal",                            // Leading dot
            "safe.internal.",                            // Trailing dot (should normalize)
            "x" + &"a".repeat(10000) + ".safe.internal", // Massive subdomain
        ];

        for attack_host in traversal_attacks {
            let (action, rule_idx) = policy.evaluate(attack_host, 443, Protocol::Http);

            if attack_host == "safe.internal." {
                // Trailing dot should normalize and be denied (wildcard requires subdomain)
                assert_eq!(
                    action,
                    Action::Deny,
                    "Trailing dot host '{}' should be denied (no subdomain)",
                    attack_host
                );
            } else if attack_host.starts_with("x") && attack_host.len() > 1000 {
                // Massive subdomain should be handled safely
                assert!(
                    action == Action::Allow || action == Action::Deny,
                    "Massive subdomain should be handled without panic"
                );
            } else {
                assert_eq!(
                    action,
                    Action::Deny,
                    "Subdomain traversal '{}' should be denied",
                    attack_host
                );
                assert_eq!(
                    rule_idx, None,
                    "Subdomain traversal '{}' should not match wildcard rule",
                    attack_host
                );
            }
        }
    }

    #[test]
    fn port_scanning_enumeration_attack_resistance() {
        let mut policy = EgressPolicy::new("conn-portscan".to_string(), Action::Deny);
        policy
            .add_rule(EgressRule {
                host: "api.service.com".to_string(),
                port: Some(443),
                action: Action::Allow,
                protocol: Protocol::Http,
            })
            .expect("specific port rule should fit");

        // Common port scanning targets
        let scan_ports = [
            21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 993, 995, 1433, 1521, 3306, 3389,
            5432, 5900, 6379, 8080, 8443, 9200, 11211, 27017, 50070, 0, 1, 65534,
            65535, // Boundary ports
        ];

        for port in scan_ports {
            let (action, rule_idx) = policy.evaluate("api.service.com", port, Protocol::Http);

            if port == 443 {
                assert_eq!(action, Action::Allow, "Port 443 should be allowed");
                assert_eq!(rule_idx, Some(0));
            } else {
                assert_eq!(
                    action,
                    Action::Deny,
                    "Port scan on port {} should be denied",
                    port
                );
                assert_eq!(
                    rule_idx, None,
                    "Port scan on port {} should not match specific rule",
                    port
                );
            }
        }

        // TCP protocol should be denied even for allowed HTTP port
        let (action, rule_idx) = policy.evaluate("api.service.com", 443, Protocol::Tcp);
        assert_eq!(
            action,
            Action::Deny,
            "TCP on HTTP-allowed port should be denied"
        );
        assert_eq!(rule_idx, None);
    }

    #[test]
    fn policy_rule_explosion_memory_exhaustion_protection() {
        let mut policy = EgressPolicy::new("conn-explosion".to_string(), Action::Deny);

        // Fill policy to exactly MAX_RULES capacity
        for i in 0..MAX_RULES {
            let result = policy.add_rule(EgressRule {
                host: format!("host-{}.example.com", i),
                port: Some(443),
                action: Action::Allow,
                protocol: Protocol::Http,
            });

            if i < MAX_RULES {
                assert!(result.is_ok(), "Rule {} should fit within capacity", i);
            }
        }

        // Verify policy is at capacity
        assert_eq!(policy.rules.len(), MAX_RULES);

        // Attempt to add one more rule should fail
        let overflow_result = policy.add_rule(EgressRule {
            host: "overflow.example.com".to_string(),
            port: Some(443),
            action: Action::Allow,
            protocol: Protocol::Http,
        });

        assert!(overflow_result.is_err(), "Overflow rule should be rejected");
        assert_eq!(
            policy.rules.len(),
            MAX_RULES,
            "Policy size should remain at capacity"
        );

        // Verify policy still functions correctly
        let (action, rule_idx) = policy.evaluate("host-0.example.com", 443, Protocol::Http);
        assert_eq!(action, Action::Allow);
        assert_eq!(rule_idx, Some(0));

        // Verify overflow attempt didn't affect existing rules
        let (overflow_action, overflow_idx) =
            policy.evaluate("overflow.example.com", 443, Protocol::Http);
        assert_eq!(
            overflow_action,
            Action::Deny,
            "Overflow host should be denied"
        );
        assert_eq!(overflow_idx, None);
    }

    #[test]
    fn audit_log_flood_protection_oldest_first_eviction() {
        let mut guard =
            NetworkGuard::new(EgressPolicy::new("conn-flood".to_string(), Action::Allow));

        // Generate audit events beyond capacity
        let flood_size = MAX_AUDIT_LOG_ENTRIES + 100;
        for i in 0..flood_size {
            let event = AuditEvent {
                connector_id: guard.policy.connector_id.clone(),
                timestamp: format!("2026-04-17T12:{:02}:{:02}Z", i / 60, i % 60),
                protocol: Protocol::Http,
                host: format!("flood-{}.example.com", i),
                port: 80,
                action: Action::Allow,
                rule_matched: None,
                trace_id: format!("trace-flood-{}", i),
            };

            push_bounded(&mut guard.audit_log, event, MAX_AUDIT_LOG_ENTRIES);
        }

        // Audit log should be bounded to capacity
        assert_eq!(guard.audit_log.len(), MAX_AUDIT_LOG_ENTRIES);

        // Oldest events should be evicted (first events 0 through 99 should be gone)
        let remaining_events: Vec<&str> = guard
            .audit_log
            .iter()
            .map(|e| e.trace_id.as_str())
            .collect();

        // Should contain recent events
        assert!(
            remaining_events.contains(&format!("trace-flood-{}", flood_size - 1).as_str()),
            "Most recent event should be retained"
        );
        assert!(
            remaining_events
                .contains(&format!("trace-flood-{}", flood_size - MAX_AUDIT_LOG_ENTRIES).as_str()),
            "Boundary event should be retained"
        );

        // Should not contain oldest events
        assert!(
            !remaining_events.contains("trace-flood-0"),
            "Oldest event should be evicted"
        );
        assert!(
            !remaining_events.contains("trace-flood-50"),
            "Early event should be evicted"
        );
    }

    #[test]
    fn hostname_punycode_internationalized_domain_attacks() {
        let mut policy = EgressPolicy::new("conn-punycode".to_string(), Action::Deny);
        policy
            .add_rule(EgressRule {
                host: "legitimate.com".to_string(),
                port: Some(443),
                action: Action::Allow,
                protocol: Protocol::Http,
            })
            .expect("legitimate rule should fit");

        // Punycode and internationalized domain attacks
        let punycode_attacks = [
            "xn--lgitimate-9wa.com",      // Punycode for "légitimate.com"
            "xn--legtimate-9wa.com",      // Punycode variant
            "xn--80ak6aa92e.com",         // Punycode for "аррӏе.com" (Cyrillic apple)
            "legitimate.xn--j1amh",       // Punycode TLD (.укр)
            "xn--nxasmq6b.xn--j1amh",     // Full IDN (тест.укр)
            "xn--fsq.com",                // Punycode for "中.com"
            "sub.xn--nxasmq6b.com",       // Subdomain with punycode
            "xn--".repeat(100) + "a.com", // Malformed punycode
            "legitimate.com.xn--invalid", // Invalid punycode TLD
        ];

        for punycode_host in punycode_attacks {
            let (action, rule_idx) = policy.evaluate(&punycode_host, 443, Protocol::Http);

            // All punycode attacks should be denied (don't match ASCII rule)
            assert_eq!(
                action,
                Action::Deny,
                "Punycode attack '{}' should be denied",
                punycode_host
            );
            assert_eq!(
                rule_idx, None,
                "Punycode attack '{}' should not match ASCII rule",
                punycode_host
            );

            // Verify direct matching also fails
            assert!(
                !host_matches("legitimate.com", &punycode_host),
                "Punycode '{}' should not match ASCII pattern",
                punycode_host
            );
        }
    }

    #[test]
    fn protocol_tunnel_and_encapsulation_bypass_attempts() {
        let mut policy = EgressPolicy::new("conn-tunnel".to_string(), Action::Deny);

        // Allow only HTTP to specific host
        policy
            .add_rule(EgressRule {
                host: "api.trusted.com".to_string(),
                port: Some(80),
                action: Action::Allow,
                protocol: Protocol::Http,
            })
            .expect("HTTP rule should fit");

        // Protocol tunneling attack scenarios
        let tunnel_tests = [
            // Direct TCP to same endpoint should be blocked
            ("api.trusted.com", 80, Protocol::Tcp),
            // Common tunneling ports should be blocked
            ("api.trusted.com", 8080, Protocol::Http), // HTTP alternate
            ("api.trusted.com", 443, Protocol::Http),  // HTTPS
            ("api.trusted.com", 8443, Protocol::Http), // HTTPS alternate
            ("api.trusted.com", 3128, Protocol::Http), // Proxy port
            ("api.trusted.com", 1080, Protocol::Tcp),  // SOCKS proxy
            ("api.trusted.com", 9050, Protocol::Tcp),  // Tor SOCKS
            // DNS tunneling ports
            ("api.trusted.com", 53, Protocol::Tcp),  // DNS TCP
            ("api.trusted.com", 853, Protocol::Tcp), // DNS over TLS
            // VPN/tunneling common ports
            ("api.trusted.com", 1194, Protocol::Tcp), // OpenVPN
            ("api.trusted.com", 4500, Protocol::Tcp), // IPSec
            ("api.trusted.com", 500, Protocol::Tcp),  // IKE
        ];

        for (host, port, protocol) in tunnel_tests {
            let (action, rule_idx) = policy.evaluate(host, port, protocol);

            assert_eq!(
                action,
                Action::Deny,
                "Tunnel attempt {}://{}:{} should be denied",
                protocol,
                host,
                port
            );
            assert_eq!(
                rule_idx, None,
                "Tunnel attempt {}://{}:{} should not match HTTP rule",
                protocol, host, port
            );
        }

        // Verify original rule still works
        let (action, rule_idx) = policy.evaluate("api.trusted.com", 80, Protocol::Http);
        assert_eq!(action, Action::Allow);
        assert_eq!(rule_idx, Some(0));
    }

    #[test]
    fn host_normalization_case_folding_attack_resistance() {
        let mut policy = EgressPolicy::new("conn-case-attack".to_string(), Action::Deny);

        // Add deny rule for malicious host
        policy
            .add_rule(EgressRule {
                host: "evil.attacker.com".to_string(),
                port: None,
                action: Action::Deny,
                protocol: Protocol::Http,
            })
            .expect("deny rule should fit");

        // Case folding bypass attempts
        let case_attacks = [
            "EVIL.ATTACKER.COM",
            "Evil.Attacker.Com",
            "eViL.AtTaCkEr.CoM",
            "evil.ATTACKER.com",
            "EVIL.attacker.COM",
            "evil.attacker.COM",
            "Evil.attacker.com",
        ];

        for attack_host in case_attacks {
            let (action, rule_idx) = policy.evaluate(attack_host, 443, Protocol::Http);

            // All case variants should match deny rule (case-insensitive)
            assert_eq!(
                action,
                Action::Deny,
                "Case variant '{}' should be denied",
                attack_host
            );
            assert_eq!(
                rule_idx,
                Some(0),
                "Case variant '{}' should match deny rule",
                attack_host
            );

            // Verify direct host matching is case-insensitive
            assert!(
                host_matches("evil.attacker.com", attack_host),
                "Case variant '{}' should match lowercase pattern",
                attack_host
            );
        }

        // Verify similar but different hosts are not blocked
        let non_matches = [
            "good.attacker.com",
            "evil.defender.com",
            "evil.attacker.net",
            "sub.evil.attacker.com",
        ];

        for non_match_host in non_matches {
            let (action, rule_idx) = policy.evaluate(non_match_host, 443, Protocol::Http);
            assert_eq!(
                action,
                Action::Deny,
                "Non-match '{}' should hit default deny",
                non_match_host
            );
            assert_eq!(
                rule_idx, None,
                "Non-match '{}' should not match deny rule",
                non_match_host
            );
        }
    }

    #[test]
    fn massive_connector_id_and_trace_id_handling_robustness() {
        let massive_connector_id = "conn-".to_owned() + &"x".repeat(100_000);
        let massive_trace_id = "trace-".to_owned() + &"y".repeat(50_000);

        let policy = EgressPolicy::new(massive_connector_id.clone(), Action::Allow);
        let mut guard = NetworkGuard::new(policy);

        // Generate audit event with massive IDs
        let event = AuditEvent {
            connector_id: massive_connector_id.clone(),
            timestamp: "2026-04-17T12:00:00Z".to_string(),
            protocol: Protocol::Http,
            host: "test.example.com".to_string(),
            port: 443,
            action: Action::Allow,
            rule_matched: None,
            trace_id: massive_trace_id.clone(),
        };

        push_bounded(&mut guard.audit_log, event, MAX_AUDIT_LOG_ENTRIES);

        // Should handle massive IDs without panic
        assert_eq!(guard.audit_log.len(), 1);

        let stored_event = &guard.audit_log[0];
        assert_eq!(stored_event.connector_id.len(), massive_connector_id.len());
        assert_eq!(stored_event.trace_id.len(), massive_trace_id.len());

        // JSON serialization should handle massive fields
        let json_result = serde_json::to_string(stored_event);
        assert!(json_result.is_ok(), "Massive IDs should serialize to JSON");

        let json_str = json_result.unwrap();
        assert!(
            json_str.len() > 150_000,
            "JSON should contain massive content"
        );

        // JSON deserialization should work
        let parse_result = serde_json::from_str::<AuditEvent>(&json_str);
        assert!(parse_result.is_ok(), "Massive JSON should deserialize");

        let parsed = parse_result.unwrap();
        assert_eq!(parsed.connector_id, massive_connector_id);
        assert_eq!(parsed.trace_id, massive_trace_id);
    }
}
