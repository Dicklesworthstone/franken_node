//! SSRF-deny default policy template (bd-1nk5).
//!
//! Blocks localhost, private CIDRs, link-local, cloud metadata, and
//! tailnet ranges by default. Explicit allowlist exceptions require a
//! PolicyReceipt with reason and trace_id.

use serde::{Deserialize, Serialize};
use std::fmt;

use super::network_guard::{Action, EgressPolicy, EgressRule, Protocol};

// ── CIDR range ──────────────────────────────────────────────────────

/// An IPv4 CIDR range.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CidrRange {
    pub network: [u8; 4],
    pub prefix_len: u8,
    pub label: String,
}

impl CidrRange {
    pub fn new(network: [u8; 4], prefix_len: u8, label: &str) -> Self {
        Self {
            network,
            prefix_len,
            label: label.to_string(),
        }
    }

    /// Check whether `ip` falls within this CIDR range.
    pub fn contains(&self, ip: [u8; 4]) -> bool {
        if self.prefix_len == 0 {
            // 0.0.0.0/0 matches everything — but we use /8 for "this" network
            return true;
        }
        let net = u32::from_be_bytes(self.network);
        let addr = u32::from_be_bytes(ip);
        let mask = if self.prefix_len >= 32 {
            u32::MAX
        } else {
            u32::MAX << (32 - self.prefix_len)
        };
        (addr & mask) == (net & mask)
    }
}

impl fmt::Display for CidrRange {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}.{}.{}.{}/{}",
            self.network[0], self.network[1], self.network[2], self.network[3], self.prefix_len
        )
    }
}

// ── Policy receipt ──────────────────────────────────────────────────

/// Receipt issued when an allowlist exception is granted.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicyReceipt {
    pub receipt_id: String,
    pub connector_id: String,
    pub host: String,
    pub issued_at: String,
    pub reason: String,
    pub trace_id: String,
}

// ── Allowlist entry ─────────────────────────────────────────────────

/// An explicit exception to the SSRF deny list.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AllowlistEntry {
    pub host: String,
    pub port: Option<u16>,
    pub reason: String,
    pub receipt: PolicyReceipt,
}

// ── SSRF audit record ───────────────────────────────────────────────

/// Structured audit record for SSRF checks.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SsrfAuditRecord {
    pub connector_id: String,
    pub timestamp: String,
    pub host: String,
    pub port: u16,
    pub action: Action,
    pub cidr_matched: Option<String>,
    pub allowlisted: bool,
    pub trace_id: String,
}

// ── SSRF policy template ────────────────────────────────────────────

/// Default SSRF-deny policy template.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SsrfPolicyTemplate {
    pub connector_id: String,
    pub blocked_cidrs: Vec<CidrRange>,
    pub allowlist: Vec<AllowlistEntry>,
    pub audit_log: Vec<SsrfAuditRecord>,
}

/// Standard blocked CIDR ranges for SSRF prevention.
fn standard_blocked_cidrs() -> Vec<CidrRange> {
    vec![
        CidrRange::new([127, 0, 0, 0], 8, "ipv4_loopback"),
        CidrRange::new([10, 0, 0, 0], 8, "rfc1918_class_a"),
        CidrRange::new([172, 16, 0, 0], 12, "rfc1918_class_b"),
        CidrRange::new([192, 168, 0, 0], 16, "rfc1918_class_c"),
        CidrRange::new([169, 254, 0, 0], 16, "link_local"),
        CidrRange::new([100, 64, 0, 0], 10, "cgnat_tailnet"),
        CidrRange::new([0, 0, 0, 0], 8, "this_network"),
    ]
}

/// Parse an IPv4 address string into bytes.
fn parse_ipv4(ip: &str) -> Option<[u8; 4]> {
    let parts: Vec<&str> = ip.split('.').collect();
    if parts.len() != 4 {
        return None;
    }
    let mut octets = [0u8; 4];
    for (i, part) in parts.iter().enumerate() {
        if part.starts_with('0') && part.len() > 1 {
            return None;
        }
        octets[i] = part.parse::<u8>().ok()?;
    }
    Some(octets)
}

fn parse_ipv4_lax(ip: &str) -> Option<[u8; 4]> {
    let parts: Vec<&str> = ip.split('.').collect();
    if parts.len() > 4 || parts.is_empty() {
        return None;
    }
    let mut parsed_parts = Vec::new();
    for part in &parts {
        let val = if part.starts_with("0x") || part.starts_with("0X") {
            u32::from_str_radix(&part[2..], 16).ok()?
        } else if part.starts_with('0') && part.len() > 1 {
            u32::from_str_radix(part, 8).ok()?
        } else {
            part.parse::<u32>().ok()?
        };
        parsed_parts.push(val);
    }
    match parsed_parts.len() {
        1 => {
            let val = parsed_parts[0];
            Some([
                (val >> 24) as u8,
                (val >> 16) as u8,
                (val >> 8) as u8,
                val as u8,
            ])
        }
        2 => {
            let (a, b) = (parsed_parts[0], parsed_parts[1]);
            if a > 255 || b > 0xFFFFFF {
                return None;
            }
            Some([a as u8, (b >> 16) as u8, (b >> 8) as u8, b as u8])
        }
        3 => {
            let (a, b, c) = (parsed_parts[0], parsed_parts[1], parsed_parts[2]);
            if a > 255 || b > 255 || c > 0xFFFF {
                return None;
            }
            Some([a as u8, b as u8, (c >> 8) as u8, c as u8])
        }
        4 => {
            let (a, b, c, d) = (
                parsed_parts[0],
                parsed_parts[1],
                parsed_parts[2],
                parsed_parts[3],
            );
            if a > 255 || b > 255 || c > 255 || d > 255 {
                return None;
            }
            Some([a as u8, b as u8, c as u8, d as u8])
        }
        _ => None,
    }
}

impl SsrfPolicyTemplate {
    /// Create the default template with all standard blocked CIDRs.
    pub fn default_template(connector_id: String) -> Self {
        Self {
            connector_id,
            blocked_cidrs: standard_blocked_cidrs(),
            allowlist: Vec::new(),
            audit_log: Vec::new(),
        }
    }

    /// Check if an IP string falls within any blocked CIDR.
    pub fn is_private_ip(ip: &str) -> bool {
        // Handle IPv6 loopback
        if ip == "::1" || ip == "[::1]" {
            return true;
        }
        let octets = match parse_ipv4(ip) {
            Some(o) => o,
            None => {
                if parse_ipv4_lax(ip).is_some() {
                    return true; // Treat as private to deny invalid IP formats
                }
                let clean_ip = ip.trim_start_matches('[').trim_end_matches(']');
                if clean_ip.parse::<std::net::IpAddr>().is_ok() {
                    return true; // Deny unsupported IP literals (like IPv6) by treating them as private
                }
                return false;
            }
        };
        let cidrs = standard_blocked_cidrs();
        cidrs.iter().any(|cidr| cidr.contains(octets))
    }

    /// Check if a host is in the allowlist.
    fn find_allowlist(&self, host: &str, port: u16) -> Option<&AllowlistEntry> {
        self.allowlist
            .iter()
            .find(|e| e.host == host && e.port.is_none_or(|p| p == port))
    }

    /// Evaluate a request against the SSRF policy.
    pub fn check_ssrf(
        &mut self,
        host: &str,
        port: u16,
        _protocol: Protocol,
        trace_id: &str,
        timestamp: &str,
    ) -> Result<Action, SsrfError> {
        // Handle IPv6 loopback
        if host == "::1" || host == "[::1]" {
            if let Some(_entry) = self.find_allowlist(host, port) {
                self.emit_audit(host, port, Action::Allow, None, true, trace_id, timestamp);
                return Ok(Action::Allow);
            }
            self.emit_audit(
                host,
                port,
                Action::Deny,
                Some("::1/128"),
                false,
                trace_id,
                timestamp,
            );
            return Err(SsrfError::SsrfDenied {
                host: host.to_string(),
                cidr: "::1/128".to_string(),
            });
        }

        // Parse IPv4
        let octets = match parse_ipv4(host) {
            Some(o) => o,
            None => {
                let clean_host = host.trim_start_matches('[').trim_end_matches(']');
                if clean_host.parse::<std::net::IpAddr>().is_ok() {
                    self.emit_audit(
                        host,
                        port,
                        Action::Deny,
                        Some("ipv6_unsupported"),
                        false,
                        trace_id,
                        timestamp,
                    );
                    return Err(SsrfError::SsrfDenied {
                        host: host.to_string(),
                        cidr: "ipv6_unsupported".to_string(),
                    });
                }
                if parse_ipv4_lax(host).is_some() {
                    self.emit_audit(
                        host,
                        port,
                        Action::Deny,
                        Some("invalid_ip_format"),
                        false,
                        trace_id,
                        timestamp,
                    );
                    return Err(SsrfError::SsrfInvalidIp {
                        host: host.to_string(),
                    });
                }
                // Not an IP literal — allow through (DNS names handled by network guard)
                self.emit_audit(host, port, Action::Allow, None, false, trace_id, timestamp);
                return Ok(Action::Allow);
            }
        };

        // Check each blocked CIDR — collect the match first to avoid
        // borrowing self.blocked_cidrs while calling &mut self methods.
        let matched_cidr = self
            .blocked_cidrs
            .iter()
            .find(|cidr| cidr.contains(octets))
            .map(|cidr| cidr.to_string());

        if let Some(cidr_str) = matched_cidr {
            // Check allowlist
            if self.find_allowlist(host, port).is_some() {
                self.emit_audit(
                    host,
                    port,
                    Action::Allow,
                    Some(&cidr_str),
                    true,
                    trace_id,
                    timestamp,
                );
                return Ok(Action::Allow);
            }
            self.emit_audit(
                host,
                port,
                Action::Deny,
                Some(&cidr_str),
                false,
                trace_id,
                timestamp,
            );
            return Err(SsrfError::SsrfDenied {
                host: host.to_string(),
                cidr: cidr_str,
            });
        }

        // Public IP — allow
        self.emit_audit(host, port, Action::Allow, None, false, trace_id, timestamp);
        Ok(Action::Allow)
    }

    /// Add an allowlist exception with a receipt.
    pub fn add_allowlist(
        &mut self,
        host: &str,
        port: Option<u16>,
        reason: &str,
        trace_id: &str,
        timestamp: &str,
    ) -> Result<PolicyReceipt, SsrfError> {
        if reason.is_empty() {
            return Err(SsrfError::SsrfReceiptMissing {
                detail: "reason is required".to_string(),
            });
        }

        let receipt_id = format!("rcpt-{}-{}", self.connector_id, self.allowlist.len());
        let receipt = PolicyReceipt {
            receipt_id: receipt_id.clone(),
            connector_id: self.connector_id.clone(),
            host: host.to_string(),
            issued_at: timestamp.to_string(),
            reason: reason.to_string(),
            trace_id: trace_id.to_string(),
        };

        self.allowlist.push(AllowlistEntry {
            host: host.to_string(),
            port,
            reason: reason.to_string(),
            receipt: receipt.clone(),
        });

        Ok(receipt)
    }

    /// Convert this SSRF template into a standard EgressPolicy for the
    /// network guard. All blocked CIDRs become deny rules; allowlist
    /// entries become allow rules inserted before them.
    pub fn to_egress_policy(&self) -> EgressPolicy {
        let mut policy = EgressPolicy::new(self.connector_id.clone(), Action::Deny);

        // Add allowlist entries first (higher priority)
        for entry in &self.allowlist {
            policy.add_rule(EgressRule {
                host: entry.host.clone(),
                port: entry.port,
                action: Action::Allow,
                protocol: Protocol::Http,
            });
            policy.add_rule(EgressRule {
                host: entry.host.clone(),
                port: entry.port,
                action: Action::Allow,
                protocol: Protocol::Tcp,
            });
        }

        policy
    }

    /// Validate that the template is well-formed.
    pub fn validate(&self) -> Result<(), SsrfError> {
        if self.blocked_cidrs.is_empty() {
            return Err(SsrfError::SsrfTemplateInvalid {
                reason: "template has no blocked CIDRs".to_string(),
            });
        }
        for entry in &self.allowlist {
            if entry.reason.is_empty() || entry.receipt.trace_id.is_empty() {
                return Err(SsrfError::SsrfReceiptMissing {
                    detail: format!("allowlist entry for {} lacks receipt fields", entry.host),
                });
            }
        }
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    fn emit_audit(
        &mut self,
        host: &str,
        port: u16,
        action: Action,
        cidr: Option<&str>,
        allowlisted: bool,
        trace_id: &str,
        timestamp: &str,
    ) {
        self.audit_log.push(SsrfAuditRecord {
            connector_id: self.connector_id.clone(),
            timestamp: timestamp.to_string(),
            host: host.to_string(),
            port,
            action,
            cidr_matched: cidr.map(|s| s.to_string()),
            allowlisted,
            trace_id: trace_id.to_string(),
        });
    }
}

// ── Errors ──────────────────────────────────────────────────────────

/// Errors for SSRF policy operations.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SsrfError {
    #[serde(rename = "SSRF_DENIED")]
    SsrfDenied { host: String, cidr: String },
    #[serde(rename = "SSRF_INVALID_IP")]
    SsrfInvalidIp { host: String },
    #[serde(rename = "SSRF_RECEIPT_MISSING")]
    SsrfReceiptMissing { detail: String },
    #[serde(rename = "SSRF_TEMPLATE_INVALID")]
    SsrfTemplateInvalid { reason: String },
}

impl fmt::Display for SsrfError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SsrfDenied { host, cidr } => {
                write!(f, "SSRF_DENIED: {host} matched {cidr}")
            }
            Self::SsrfInvalidIp { host } => {
                write!(f, "SSRF_INVALID_IP: cannot parse {host}")
            }
            Self::SsrfReceiptMissing { detail } => {
                write!(f, "SSRF_RECEIPT_MISSING: {detail}")
            }
            Self::SsrfTemplateInvalid { reason } => {
                write!(f, "SSRF_TEMPLATE_INVALID: {reason}")
            }
        }
    }
}

impl std::error::Error for SsrfError {}

// ── Tests ───────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // === CidrRange ===

    #[test]
    fn cidr_contains_loopback() {
        let cidr = CidrRange::new([127, 0, 0, 0], 8, "loopback");
        assert!(cidr.contains([127, 0, 0, 1]));
        assert!(cidr.contains([127, 255, 255, 255]));
        assert!(!cidr.contains([128, 0, 0, 1]));
    }

    #[test]
    fn cidr_contains_10_network() {
        let cidr = CidrRange::new([10, 0, 0, 0], 8, "rfc1918_a");
        assert!(cidr.contains([10, 0, 0, 1]));
        assert!(cidr.contains([10, 255, 255, 255]));
        assert!(!cidr.contains([11, 0, 0, 1]));
    }

    #[test]
    fn cidr_contains_172_16() {
        let cidr = CidrRange::new([172, 16, 0, 0], 12, "rfc1918_b");
        assert!(cidr.contains([172, 16, 0, 1]));
        assert!(cidr.contains([172, 31, 255, 255]));
        assert!(!cidr.contains([172, 32, 0, 0]));
    }

    #[test]
    fn cidr_contains_192_168() {
        let cidr = CidrRange::new([192, 168, 0, 0], 16, "rfc1918_c");
        assert!(cidr.contains([192, 168, 0, 1]));
        assert!(cidr.contains([192, 168, 255, 255]));
        assert!(!cidr.contains([192, 169, 0, 0]));
    }

    #[test]
    fn cidr_contains_link_local() {
        let cidr = CidrRange::new([169, 254, 0, 0], 16, "link_local");
        assert!(cidr.contains([169, 254, 169, 254])); // cloud metadata
        assert!(cidr.contains([169, 254, 0, 1]));
        assert!(!cidr.contains([169, 255, 0, 1]));
    }

    #[test]
    fn cidr_contains_tailnet() {
        let cidr = CidrRange::new([100, 64, 0, 0], 10, "cgnat_tailnet");
        assert!(cidr.contains([100, 64, 0, 1]));
        assert!(cidr.contains([100, 127, 255, 255]));
        assert!(!cidr.contains([100, 128, 0, 0]));
    }

    #[test]
    fn cidr_display() {
        let cidr = CidrRange::new([10, 0, 0, 0], 8, "test");
        assert_eq!(cidr.to_string(), "10.0.0.0/8");
    }

    // === parse_ipv4 ===

    #[test]
    fn parse_valid_ipv4() {
        assert_eq!(parse_ipv4("192.168.1.1"), Some([192, 168, 1, 1]));
        assert_eq!(parse_ipv4("0.0.0.0"), Some([0, 0, 0, 0]));
    }

    #[test]
    fn parse_invalid_ipv4() {
        assert_eq!(parse_ipv4("not-an-ip"), None);
        assert_eq!(parse_ipv4("256.0.0.1"), None);
        assert_eq!(parse_ipv4("1.2.3"), None);
    }

    // === is_private_ip ===

    #[test]
    fn private_ip_localhost() {
        assert!(SsrfPolicyTemplate::is_private_ip("127.0.0.1"));
        assert!(SsrfPolicyTemplate::is_private_ip("127.255.255.255"));
    }

    #[test]
    fn private_ip_rfc1918() {
        assert!(SsrfPolicyTemplate::is_private_ip("10.0.0.1"));
        assert!(SsrfPolicyTemplate::is_private_ip("172.16.0.1"));
        assert!(SsrfPolicyTemplate::is_private_ip("192.168.1.1"));
    }

    #[test]
    fn private_ip_metadata() {
        assert!(SsrfPolicyTemplate::is_private_ip("169.254.169.254"));
    }

    #[test]
    fn private_ip_tailnet() {
        assert!(SsrfPolicyTemplate::is_private_ip("100.100.100.100"));
    }

    #[test]
    fn private_ip_ipv6_loopback() {
        assert!(SsrfPolicyTemplate::is_private_ip("::1"));
    }

    #[test]
    fn public_ip_not_private() {
        assert!(!SsrfPolicyTemplate::is_private_ip("8.8.8.8"));
        assert!(!SsrfPolicyTemplate::is_private_ip("1.1.1.1"));
        assert!(!SsrfPolicyTemplate::is_private_ip("203.0.113.1"));
    }

    // === default_template ===

    #[test]
    fn default_template_has_7_cidrs() {
        let t = SsrfPolicyTemplate::default_template("conn-1".into());
        assert_eq!(t.blocked_cidrs.len(), 7);
    }

    #[test]
    fn default_template_validates() {
        let t = SsrfPolicyTemplate::default_template("conn-1".into());
        assert!(t.validate().is_ok());
    }

    // === check_ssrf ===

    #[test]
    fn check_ssrf_blocks_localhost() {
        let mut t = SsrfPolicyTemplate::default_template("conn-1".into());
        let result = t.check_ssrf("127.0.0.1", 80, Protocol::Http, "t1", "ts");
        assert!(result.is_err());
        match result.unwrap_err() {
            SsrfError::SsrfDenied { host, cidr } => {
                assert_eq!(host, "127.0.0.1");
                assert!(cidr.contains("127.0.0.0/8"));
            }
            other => panic!("expected SsrfDenied, got {:?}", other),
        }
    }

    #[test]
    fn check_ssrf_blocks_metadata() {
        let mut t = SsrfPolicyTemplate::default_template("conn-1".into());
        let result = t.check_ssrf("169.254.169.254", 80, Protocol::Http, "t2", "ts");
        assert!(result.is_err());
    }

    #[test]
    fn check_ssrf_blocks_ipv6_loopback() {
        let mut t = SsrfPolicyTemplate::default_template("conn-1".into());
        let result = t.check_ssrf("::1", 80, Protocol::Http, "t3", "ts");
        assert!(result.is_err());
    }

    #[test]
    fn check_ssrf_allows_public_ip() {
        let mut t = SsrfPolicyTemplate::default_template("conn-1".into());
        let result = t.check_ssrf("8.8.8.8", 443, Protocol::Http, "t4", "ts");
        assert!(result.is_ok());
    }

    #[test]
    fn check_ssrf_allows_hostname() {
        let mut t = SsrfPolicyTemplate::default_template("conn-1".into());
        let result = t.check_ssrf("api.example.com", 443, Protocol::Http, "t5", "ts");
        assert!(result.is_ok());
    }

    #[test]
    fn check_ssrf_emits_audit() {
        let mut t = SsrfPolicyTemplate::default_template("conn-1".into());
        let _ = t.check_ssrf("127.0.0.1", 80, Protocol::Http, "t6", "ts");
        let _ = t.check_ssrf("8.8.8.8", 443, Protocol::Http, "t7", "ts");
        assert_eq!(t.audit_log.len(), 2);
        assert_eq!(t.audit_log[0].action, Action::Deny);
        assert_eq!(t.audit_log[1].action, Action::Allow);
    }

    // === Allowlist ===

    #[test]
    fn allowlist_permits_blocked_ip() {
        let mut t = SsrfPolicyTemplate::default_template("conn-1".into());
        let receipt = t
            .add_allowlist("10.0.0.5", Some(8080), "internal API", "t8", "ts")
            .unwrap();
        assert!(receipt.receipt_id.starts_with("rcpt-"));

        let result = t.check_ssrf("10.0.0.5", 8080, Protocol::Http, "t9", "ts");
        assert!(result.is_ok());
    }

    #[test]
    fn allowlist_requires_reason() {
        let mut t = SsrfPolicyTemplate::default_template("conn-1".into());
        let result = t.add_allowlist("10.0.0.5", None, "", "t10", "ts");
        assert!(result.is_err());
    }

    #[test]
    fn allowlist_receipt_has_fields() {
        let mut t = SsrfPolicyTemplate::default_template("conn-1".into());
        let receipt = t
            .add_allowlist(
                "192.168.1.1",
                None,
                "needed for health checks",
                "trace-abc",
                "2026-01-01",
            )
            .unwrap();
        assert_eq!(receipt.connector_id, "conn-1");
        assert_eq!(receipt.host, "192.168.1.1");
        assert_eq!(receipt.trace_id, "trace-abc");
        assert!(!receipt.reason.is_empty());
    }

    // === to_egress_policy ===

    #[test]
    fn to_egress_policy_has_allowlist_rules() {
        let mut t = SsrfPolicyTemplate::default_template("conn-1".into());
        let _ = t.add_allowlist("10.0.0.5", Some(8080), "api", "t11", "ts");
        let policy = t.to_egress_policy();
        assert_eq!(policy.default_action, Action::Deny);
        assert_eq!(policy.rules.len(), 2); // HTTP + TCP per allowlist entry
    }

    // === Validation ===

    #[test]
    fn empty_template_invalid() {
        let t = SsrfPolicyTemplate {
            connector_id: "conn-1".into(),
            blocked_cidrs: vec![],
            allowlist: vec![],
            audit_log: vec![],
        };
        assert!(t.validate().is_err());
    }

    // === Serde ===

    #[test]
    fn serde_roundtrip_template() {
        let t = SsrfPolicyTemplate::default_template("conn-1".into());
        let json = serde_json::to_string(&t).unwrap();
        let parsed: SsrfPolicyTemplate = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.blocked_cidrs.len(), 7);
    }

    #[test]
    fn serde_roundtrip_receipt() {
        let receipt = PolicyReceipt {
            receipt_id: "rcpt-1".into(),
            connector_id: "conn-1".into(),
            host: "10.0.0.1".into(),
            issued_at: "2026-01-01".into(),
            reason: "test".into(),
            trace_id: "t-1".into(),
        };
        let json = serde_json::to_string(&receipt).unwrap();
        let parsed: PolicyReceipt = serde_json::from_str(&json).unwrap();
        assert_eq!(receipt.receipt_id, parsed.receipt_id);
    }

    // === Error display ===

    #[test]
    fn error_display_messages() {
        let e1 = SsrfError::SsrfDenied {
            host: "127.0.0.1".into(),
            cidr: "127.0.0.0/8".into(),
        };
        assert!(e1.to_string().contains("SSRF_DENIED"));

        let e2 = SsrfError::SsrfInvalidIp { host: "bad".into() };
        assert!(e2.to_string().contains("SSRF_INVALID_IP"));

        let e3 = SsrfError::SsrfReceiptMissing {
            detail: "missing".into(),
        };
        assert!(e3.to_string().contains("SSRF_RECEIPT_MISSING"));

        let e4 = SsrfError::SsrfTemplateInvalid {
            reason: "empty".into(),
        };
        assert!(e4.to_string().contains("SSRF_TEMPLATE_INVALID"));
    }
}
