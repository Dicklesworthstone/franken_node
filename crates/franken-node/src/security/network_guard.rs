//! Network Guard egress layer with HTTP+TCP policy enforcement.
//!
//! All connector egress traverses this guard. Decisions are made
//! based on ordered rules, with a default-deny fallback. Every
//! decision emits a structured audit event.

use serde::{Deserialize, Serialize};
use std::fmt;

use crate::security::remote_cap::{CapabilityGate, RemoteCap, RemoteOperation};

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
fn host_matches(pattern: &str, host: &str) -> bool {
    if pattern == "*" {
        return true;
    }
    if let Some(suffix) = pattern.strip_prefix("*.") {
        host.ends_with(suffix) && host.len() > suffix.len()
    } else {
        pattern == host
    }
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

    pub fn add_rule(&mut self, rule: EgressRule) {
        self.rules.push(rule);
    }

    /// Evaluate a request against the policy. Returns the action and
    /// the index of the matching rule (None if default).
    pub fn evaluate(&self, host: &str, port: u16, protocol: Protocol) -> (Action, Option<usize>) {
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
            self.audit_log.push(event);
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

        self.audit_log.push(event);

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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::security::remote_cap::{
        CapabilityGate, CapabilityProvider, RemoteOperation, RemoteScope,
    };

    fn sample_policy() -> EgressPolicy {
        let mut policy = EgressPolicy::new("conn-1".into(), Action::Deny);
        policy.add_rule(EgressRule {
            host: "api.example.com".into(),
            port: Some(443),
            action: Action::Allow,
            protocol: Protocol::Http,
        });
        policy.add_rule(EgressRule {
            host: "*.trusted.com".into(),
            port: None,
            action: Action::Allow,
            protocol: Protocol::Http,
        });
        policy.add_rule(EgressRule {
            host: "evil.com".into(),
            port: None,
            action: Action::Deny,
            protocol: Protocol::Http,
        });
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
    fn wildcard_host_match() {
        assert!(host_matches("*.example.com", "api.example.com"));
        assert!(host_matches("*.example.com", "sub.api.example.com"));
        assert!(!host_matches("*.example.com", "example.com"));
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
    fn allowed_by_wildcard() {
        let policy = sample_policy();
        let (action, idx) = policy.evaluate("sub.trusted.com", 443, Protocol::Http);
        assert_eq!(action, Action::Allow);
        assert_eq!(idx, Some(1));
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
        policy.add_rule(EgressRule {
            host: "*.example.com".into(),
            port: None,
            action: Action::Allow,
            protocol: Protocol::Http,
        });
        policy.add_rule(EgressRule {
            host: "bad.example.com".into(),
            port: None,
            action: Action::Deny,
            protocol: Protocol::Http,
        });
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
            other => panic!("expected RemoteCapDenied, got {other:?}"),
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
}
