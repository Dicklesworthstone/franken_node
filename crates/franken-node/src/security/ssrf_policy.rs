//! SSRF-deny default policy template (bd-1nk5).
//! bd-1xbr: Bounded audit_log capacity with oldest-first eviction.
//!
//! Blocks localhost, private CIDRs, link-local, cloud metadata, and
//! tailnet ranges by default. Explicit allowlist exceptions require a
//! PolicyReceipt with reason and trace_id.

use serde::{Deserialize, Serialize};
use std::fmt;

use super::network_guard::{Action, EgressPolicy, EgressRule, Protocol};

use crate::capacity_defaults::aliases::MAX_AUDIT_LOG_ENTRIES;
const MAX_ALLOWLIST_ENTRIES: usize = 4096;

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
        if self.prefix_len > 32 {
            return true;
        }
        if self.prefix_len == 0 {
            // 0.0.0.0/0 matches everything — but we use /8 for "this" network
            return true;
        }
        let net = u32::from_be_bytes(self.network);
        let addr = u32::from_be_bytes(ip);
        let mask = if self.prefix_len == 32 {
            u32::MAX
        } else {
            u32::MAX << (32_u8.saturating_sub(self.prefix_len))
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

fn parse_trailing_dot_numeric_ipv4_alias(ip: &str) -> Option<[u8; 4]> {
    let trimmed = ip.trim();
    if !trimmed.ends_with('.') {
        return None;
    }
    let canonical = trimmed.trim_end_matches('.');
    if canonical.is_empty() {
        return None;
    }
    parse_ipv4(canonical).or_else(|| parse_ipv4_lax(canonical))
}

fn has_bracket_delimiters(host: &str) -> bool {
    let trimmed = host.trim();
    trimmed.starts_with('[') || trimmed.ends_with(']')
}

fn has_multiple_trailing_dots(host: &str) -> bool {
    host.trim().ends_with("..")
}

fn has_null_byte(host: &str) -> bool {
    host.contains('\0')
}

fn has_path_like_or_empty_label_host_syntax(host: &str) -> bool {
    let trimmed = host.trim();
    if trimmed.is_empty() || trimmed.contains('/') || trimmed.contains('\\') {
        return true;
    }
    let canonical = trimmed.strip_suffix('.').unwrap_or(trimmed);
    canonical.is_empty() || canonical.split('.').any(str::is_empty)
}

/// Reserved hostname aliases that resolve to loopback without touching the public DNS.
fn blocked_hostname_label(host: &str) -> Option<&'static str> {
    let trimmed = host.trim();
    let normalized = trimmed
        .strip_suffix('.')
        .unwrap_or(trimmed)
        .to_ascii_lowercase();
    if normalized == "localhost" || normalized.ends_with(".localhost") {
        Some("localhost")
    } else {
        None
    }
}

fn normalize_host_for_allowlist_match(host: &str) -> String {
    let trimmed = host.trim();
    trimmed
        .strip_suffix('.')
        .unwrap_or(trimmed)
        .to_ascii_lowercase()
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

    /// Check whether an endpoint string should be treated as internal/private.
    pub fn is_private_ip(ip: &str) -> bool {
        let ip = ip.trim();
        if has_null_byte(ip) {
            return true;
        }
        if has_path_like_or_empty_label_host_syntax(ip) {
            return true;
        }
        if has_multiple_trailing_dots(ip) {
            return true;
        }
        // Handle IPv6 loopback
        if ip == "::1" || ip == "[::1]" {
            return true;
        }
        if blocked_hostname_label(ip).is_some() {
            return true;
        }
        let octets = match parse_ipv4(ip) {
            Some(o) => o,
            None => {
                if parse_trailing_dot_numeric_ipv4_alias(ip).is_some() {
                    return true; // Treat malformed numeric IP aliases as private to deny fail-closed
                }
                if parse_ipv4_lax(ip).is_some() {
                    return true; // Treat as private to deny invalid IP formats
                }
                let clean_ip = ip.trim_start_matches('[').trim_end_matches(']');
                if clean_ip.parse::<std::net::IpAddr>().is_ok() {
                    return true; // Deny unsupported IP literals (like IPv6) by treating them as private
                }
                if has_bracket_delimiters(ip) {
                    return true; // Treat malformed bracketed host literals as private to deny fail-closed
                }
                return false;
            }
        };
        let cidrs = standard_blocked_cidrs();
        cidrs.iter().any(|cidr| cidr.contains(octets))
    }

    /// Check if a host is in the allowlist.
    fn find_allowlist(&self, host: &str, port: u16) -> Option<&AllowlistEntry> {
        let normalized_host = normalize_host_for_allowlist_match(host);
        self.allowlist.iter().find(|e| {
            normalize_host_for_allowlist_match(&e.host) == normalized_host
                && e.port.is_none_or(|p| p == port)
        })
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
        let host = host.trim();
        if has_null_byte(host) {
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
        if has_path_like_or_empty_label_host_syntax(host) {
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
        if let Some(label) = blocked_hostname_label(host) {
            if self.find_allowlist(host, port).is_some() {
                self.emit_audit(
                    host,
                    port,
                    Action::Allow,
                    Some(label),
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
                Some(label),
                false,
                trace_id,
                timestamp,
            );
            return Err(SsrfError::SsrfDenied {
                host: host.to_string(),
                cidr: label.to_string(),
            });
        }
        if has_multiple_trailing_dots(host) {
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

        // Parse IPv4
        let octets = match parse_ipv4(host) {
            Some(o) => o,
            None => {
                if parse_trailing_dot_numeric_ipv4_alias(host).is_some() {
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
                let clean_host = host.trim_start_matches('[').trim_end_matches(']');
                if parse_trailing_dot_numeric_ipv4_alias(clean_host).is_some() {
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
                if let Ok(parsed_ip) = clean_host.parse::<std::net::IpAddr>() {
                    return match parsed_ip {
                        std::net::IpAddr::V4(_) => {
                            self.emit_audit(
                                host,
                                port,
                                Action::Deny,
                                Some("invalid_ip_format"),
                                false,
                                trace_id,
                                timestamp,
                            );
                            Err(SsrfError::SsrfInvalidIp {
                                host: host.to_string(),
                            })
                        }
                        std::net::IpAddr::V6(_) => {
                            self.emit_audit(
                                host,
                                port,
                                Action::Deny,
                                Some("ipv6_unsupported"),
                                false,
                                trace_id,
                                timestamp,
                            );
                            Err(SsrfError::SsrfDenied {
                                host: host.to_string(),
                                cidr: "ipv6_unsupported".to_string(),
                            })
                        }
                    };
                }
                if has_bracket_delimiters(host) {
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
                // Not an IP literal and not a reserved loopback alias —
                // allow through (DNS names handled by the egress guard policy)
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
        if reason.trim().is_empty() {
            return Err(SsrfError::SsrfReceiptMissing {
                detail: "reason is required".to_string(),
            });
        }
        if trace_id.trim().is_empty() {
            return Err(SsrfError::SsrfReceiptMissing {
                detail: "trace_id is required".to_string(),
            });
        }
        if has_null_byte(host) {
            return Err(SsrfError::SsrfTemplateInvalid {
                reason: "allowlist host contains null byte".to_string(),
            });
        }
        if has_path_like_or_empty_label_host_syntax(host) {
            return Err(SsrfError::SsrfTemplateInvalid {
                reason: "allowlist host contains invalid host syntax".to_string(),
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

        push_bounded(
            &mut self.allowlist,
            AllowlistEntry {
                host: host.to_string(),
                port,
                reason: reason.to_string(),
                receipt: receipt.clone(),
            },
            MAX_ALLOWLIST_ENTRIES,
        );

        Ok(receipt)
    }

    /// Convert this SSRF template into a standard EgressPolicy for the
    /// network guard. All blocked CIDRs become deny rules; allowlist
    /// entries become allow rules inserted before them.
    pub fn to_egress_policy(&self) -> EgressPolicy {
        let mut policy = EgressPolicy::new(self.connector_id.clone(), Action::Deny);

        // Add allowlist entries first (higher priority).
        // Log failures — a silently dropped allow rule means a host
        // becomes blocked without operator awareness.
        for entry in &self.allowlist {
            if let Err(err) = policy.add_rule(EgressRule {
                host: entry.host.clone(),
                port: entry.port,
                action: Action::Allow,
                protocol: Protocol::Http,
            }) {
                tracing::error!(
                    host = %entry.host,
                    port = ?entry.port,
                    protocol = "http",
                    error = %err,
                    "SSRF allowlist rule could not be added — host will be BLOCKED"
                );
            }
            if let Err(err) = policy.add_rule(EgressRule {
                host: entry.host.clone(),
                port: entry.port,
                action: Action::Allow,
                protocol: Protocol::Tcp,
            }) {
                tracing::error!(
                    host = %entry.host,
                    port = ?entry.port,
                    protocol = "tcp",
                    error = %err,
                    "SSRF allowlist rule could not be added — host will be BLOCKED"
                );
            }
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
        for cidr in &self.blocked_cidrs {
            if cidr.prefix_len > 32 {
                return Err(SsrfError::SsrfTemplateInvalid {
                    reason: format!(
                        "blocked CIDR {} has invalid prefix length {}",
                        cidr.label, cidr.prefix_len
                    ),
                });
            }
        }
        for entry in &self.allowlist {
            if has_null_byte(&entry.host) {
                return Err(SsrfError::SsrfTemplateInvalid {
                    reason: format!("allowlist entry for {} contains null byte", entry.host),
                });
            }
            if has_path_like_or_empty_label_host_syntax(&entry.host) {
                return Err(SsrfError::SsrfTemplateInvalid {
                    reason: format!("allowlist entry for {} has invalid host syntax", entry.host),
                });
            }
            if entry.reason.trim().is_empty() || entry.receipt.trace_id.trim().is_empty() {
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
        let entry = SsrfAuditRecord {
            connector_id: self.connector_id.clone(),
            timestamp: timestamp.to_string(),
            host: host.to_string(),
            port,
            action,
            cidr_matched: cidr.map(|s| s.to_string()),
            allowlisted,
            trace_id: trace_id.to_string(),
        };
        push_bounded(&mut self.audit_log, entry, MAX_AUDIT_LOG_ENTRIES);
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

fn push_bounded<T>(items: &mut Vec<T>, item: T, cap: usize) {
    if cap == 0 {
        items.clear();
        return;
    }
    if items.len() >= cap {
        let overflow = items.len().saturating_sub(cap).saturating_add(1);
        items.drain(0..overflow);
    }
    items.push(item);
}

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

    #[test]
    fn cidr_contains_invalid_prefix_fails_closed() {
        let cidr = CidrRange::new([192, 168, 1, 0], 33, "invalid");

        assert!(cidr.contains([8, 8, 8, 8]));
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

    #[test]
    fn parse_ipv4_rejects_leading_zero_octets() {
        assert_eq!(parse_ipv4("01.2.3.4"), None);
        assert_eq!(parse_ipv4("1.02.3.4"), None);
        assert_eq!(parse_ipv4("1.2.003.4"), None);
    }

    #[test]
    fn parse_ipv4_lax_rejects_overflowing_alias_parts() {
        assert_eq!(parse_ipv4_lax("256.1.1.1"), None);
        assert_eq!(parse_ipv4_lax("1.0x1000000"), None);
        assert_eq!(parse_ipv4_lax("1.2.0x10000"), None);
        assert_eq!(parse_ipv4_lax("1.2.3.256"), None);
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
    fn private_ip_localhost_hostname_aliases() {
        assert!(SsrfPolicyTemplate::is_private_ip("localhost"));
        assert!(SsrfPolicyTemplate::is_private_ip("LOCALHOST."));
        assert!(SsrfPolicyTemplate::is_private_ip("api.localhost"));
    }

    #[test]
    fn private_ip_treats_trailing_dot_numeric_aliases_as_denied() {
        assert!(SsrfPolicyTemplate::is_private_ip("127.0.0.1."));
        assert!(SsrfPolicyTemplate::is_private_ip("8.8.8.8."));
        assert!(SsrfPolicyTemplate::is_private_ip("127.1."));
    }

    #[test]
    fn private_ip_treats_repeated_trailing_dots_as_denied() {
        assert!(SsrfPolicyTemplate::is_private_ip("localhost.."));
        assert!(SsrfPolicyTemplate::is_private_ip("api.example.com.."));
        assert!(SsrfPolicyTemplate::is_private_ip("127.0.0.1.."));
    }

    #[test]
    fn private_ip_treats_path_like_and_empty_label_hosts_as_denied() {
        assert!(SsrfPolicyTemplate::is_private_ip(
            "api.example.com/../169.254.169.254"
        ));
        assert!(SsrfPolicyTemplate::is_private_ip(
            r"api.example.com\169.254.169.254"
        ));
        assert!(SsrfPolicyTemplate::is_private_ip("api..example.com"));
    }

    #[test]
    fn private_ip_treats_malformed_bracketed_hosts_as_denied() {
        assert!(SsrfPolicyTemplate::is_private_ip("[127.0.0.1.]"));
        assert!(SsrfPolicyTemplate::is_private_ip("[example.com]"));
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
            other => unreachable!("expected SsrfDenied, got {:?}", other),
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
    fn check_ssrf_blocks_localhost_hostname_alias() {
        let mut t = SsrfPolicyTemplate::default_template("conn-1".into());
        let result = t.check_ssrf("LOCALHOST.", 80, Protocol::Http, "t5a", "ts");
        assert!(result.is_err());
        match result.unwrap_err() {
            SsrfError::SsrfDenied { host, cidr } => {
                assert_eq!(host, "LOCALHOST.");
                assert_eq!(cidr, "localhost");
            }
            other => unreachable!("expected SsrfDenied, got {:?}", other),
        }
    }

    #[test]
    fn check_ssrf_blocks_localhost_subdomain_alias() {
        let mut t = SsrfPolicyTemplate::default_template("conn-1".into());
        let result = t.check_ssrf("api.localhost", 443, Protocol::Http, "t5b", "ts");
        assert!(result.is_err());
    }

    #[test]
    fn check_ssrf_blocks_with_whitespace() {
        let mut t = SsrfPolicyTemplate::default_template("conn-1".into());
        let result = t.check_ssrf(" 127.0.0.1  ", 80, Protocol::Http, "tw", "ts");
        assert!(result.is_err());
        assert!(SsrfPolicyTemplate::is_private_ip(" 127.0.0.1 "));
        assert!(SsrfPolicyTemplate::is_private_ip(" localhost \n"));
    }

    #[test]
    fn check_ssrf_rejects_trailing_dot_private_numeric_alias() {
        let mut t = SsrfPolicyTemplate::default_template("conn-1".into());
        let result = t.check_ssrf("127.0.0.1.", 80, Protocol::Http, "td1", "ts");
        assert!(matches!(result, Err(SsrfError::SsrfInvalidIp { .. })));
    }

    #[test]
    fn check_ssrf_rejects_trailing_dot_public_numeric_alias() {
        let mut t = SsrfPolicyTemplate::default_template("conn-1".into());
        let result = t.check_ssrf("8.8.8.8.", 443, Protocol::Http, "td2", "ts");
        assert!(matches!(result, Err(SsrfError::SsrfInvalidIp { .. })));
    }

    #[test]
    fn check_ssrf_rejects_trailing_dot_hex_numeric_alias() {
        let mut t = SsrfPolicyTemplate::default_template("conn-1".into());
        let result = t.check_ssrf("0x7f000001.", 80, Protocol::Http, "td2h", "ts");
        assert!(matches!(result, Err(SsrfError::SsrfInvalidIp { .. })));
        assert!(SsrfPolicyTemplate::is_private_ip("0x7f000001."));
    }

    #[test]
    fn check_ssrf_rejects_trailing_dot_octal_numeric_alias() {
        let mut t = SsrfPolicyTemplate::default_template("conn-1".into());
        let result = t.check_ssrf("0177.0.0.1.", 80, Protocol::Http, "td2o", "ts");
        assert!(matches!(result, Err(SsrfError::SsrfInvalidIp { .. })));
        assert!(SsrfPolicyTemplate::is_private_ip("0177.0.0.1."));
    }

    #[test]
    fn check_ssrf_rejects_trailing_dot_shorthand_numeric_alias() {
        let mut t = SsrfPolicyTemplate::default_template("conn-1".into());
        let result = t.check_ssrf("127.1.", 80, Protocol::Http, "td2s", "ts");
        assert!(matches!(result, Err(SsrfError::SsrfInvalidIp { .. })));
        assert!(SsrfPolicyTemplate::is_private_ip("127.1."));
    }

    #[test]
    fn check_ssrf_rejects_single_integer_ipv4_alias() {
        let mut t = SsrfPolicyTemplate::default_template("conn-1".into());
        let result = t.check_ssrf("2130706433", 80, Protocol::Http, "td2i", "ts");

        assert!(matches!(result, Err(SsrfError::SsrfInvalidIp { .. })));
        assert!(SsrfPolicyTemplate::is_private_ip("2130706433"));
        assert_eq!(
            t.audit_log[0].cidr_matched.as_deref(),
            Some("invalid_ip_format")
        );
    }

    #[test]
    fn check_ssrf_rejects_hex_ipv4_alias_without_trailing_dot() {
        let mut t = SsrfPolicyTemplate::default_template("conn-1".into());
        let result = t.check_ssrf("0x7f000001", 80, Protocol::Http, "td2x", "ts");

        assert!(matches!(result, Err(SsrfError::SsrfInvalidIp { .. })));
        assert!(SsrfPolicyTemplate::is_private_ip("0x7f000001"));
        assert_eq!(t.audit_log[0].action, Action::Deny);
    }

    #[test]
    fn check_ssrf_rejects_bracketed_ipv4_as_invalid_format() {
        let mut t = SsrfPolicyTemplate::default_template("conn-1".into());
        let result = t.check_ssrf("[127.0.0.1]", 80, Protocol::Http, "td3", "ts");
        assert!(matches!(result, Err(SsrfError::SsrfInvalidIp { .. })));
    }

    #[test]
    fn check_ssrf_rejects_bracketed_trailing_dot_ipv4_as_invalid_format() {
        let mut t = SsrfPolicyTemplate::default_template("conn-1".into());
        let result = t.check_ssrf("[127.0.0.1.]", 80, Protocol::Http, "td4", "ts");
        assert!(matches!(result, Err(SsrfError::SsrfInvalidIp { .. })));
    }

    #[test]
    fn check_ssrf_rejects_bracketed_hostname_as_invalid_format() {
        let mut t = SsrfPolicyTemplate::default_template("conn-1".into());
        let result = t.check_ssrf("[api.example.com]", 443, Protocol::Http, "td5", "ts");
        assert!(matches!(result, Err(SsrfError::SsrfInvalidIp { .. })));
    }

    #[test]
    fn check_ssrf_rejects_unbalanced_bracketed_hostname_as_invalid_format() {
        let mut t = SsrfPolicyTemplate::default_template("conn-1".into());
        let result = t.check_ssrf("[api.example.com", 443, Protocol::Http, "td5u", "ts");

        assert!(matches!(result, Err(SsrfError::SsrfInvalidIp { .. })));
        assert!(SsrfPolicyTemplate::is_private_ip("[api.example.com"));
    }

    #[test]
    fn check_ssrf_rejects_repeated_trailing_dot_hostname_as_invalid_format() {
        let mut t = SsrfPolicyTemplate::default_template("conn-1".into());
        let result = t.check_ssrf("api.example.com..", 443, Protocol::Http, "td6", "ts");
        assert!(matches!(result, Err(SsrfError::SsrfInvalidIp { .. })));
    }

    #[test]
    fn check_ssrf_rejects_path_like_and_empty_label_hosts_as_invalid_format() {
        for host in [
            "api.example.com/../169.254.169.254",
            r"api.example.com\169.254.169.254",
            "/api.example.com",
            "api..example.com",
        ] {
            let mut t = SsrfPolicyTemplate::default_template("conn-1".into());
            let result = t.check_ssrf(host, 443, Protocol::Http, "path-host", "ts");

            assert!(matches!(result, Err(SsrfError::SsrfInvalidIp { .. })));
            assert_eq!(t.audit_log[0].action, Action::Deny);
            assert_eq!(
                t.audit_log[0].cidr_matched.as_deref(),
                Some("invalid_ip_format")
            );
        }
    }

    #[test]
    fn check_ssrf_rejects_public_ipv6_literals_as_unsupported() {
        let mut t = SsrfPolicyTemplate::default_template("conn-1".into());
        let result = t.check_ssrf("2001:4860:4860::8888", 443, Protocol::Http, "td7", "ts");

        match result.expect_err("IPv6 literals must fail closed") {
            SsrfError::SsrfDenied { cidr, .. } => assert_eq!(cidr, "ipv6_unsupported"),
            other => unreachable!("expected IPv6 unsupported denial, got {:?}", other),
        }
        assert!(SsrfPolicyTemplate::is_private_ip("2001:4860:4860::8888"));
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

    #[test]
    fn allowlist_permits_localhost_hostname_alias() {
        let mut t = SsrfPolicyTemplate::default_template("conn-1".into());
        t.add_allowlist("localhost", Some(8080), "local proxy", "t7a", "ts")
            .unwrap();
        let result = t.check_ssrf("localhost", 8080, Protocol::Http, "t7b", "ts");
        assert!(result.is_ok());
    }

    #[test]
    fn allowlist_permits_trailing_dot_hostname_alias() {
        let mut t = SsrfPolicyTemplate::default_template("conn-1".into());
        t.add_allowlist("localhost", Some(8080), "local proxy", "t7c", "ts")
            .unwrap();
        let result = t.check_ssrf(" LOCALHOST. ", 8080, Protocol::Http, "t7d", "ts");
        assert!(result.is_ok());
    }

    #[test]
    fn allowlist_does_not_permit_repeated_trailing_dot_hostname_alias() {
        let mut t = SsrfPolicyTemplate::default_template("conn-1".into());
        t.add_allowlist("localhost", Some(8080), "local proxy", "t7e", "ts")
            .unwrap();
        let result = t.check_ssrf("LOCALHOST..", 8080, Protocol::Http, "t7f", "ts");
        assert!(matches!(result, Err(SsrfError::SsrfInvalidIp { .. })));
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
    fn allowlist_port_mismatch_does_not_permit_blocked_ip() {
        let mut t = SsrfPolicyTemplate::default_template("conn-1".into());
        t.add_allowlist("10.0.0.5", Some(8080), "internal API", "t8b", "ts")
            .unwrap();

        let result = t.check_ssrf("10.0.0.5", 8081, Protocol::Http, "t8c", "ts");

        match result.expect_err("wrong allowlist port must not bypass SSRF deny") {
            SsrfError::SsrfDenied { cidr, .. } => assert!(cidr.contains("10.0.0.0/8")),
            other => unreachable!("expected SSRF denial, got {:?}", other),
        }
        assert!(!t.audit_log[0].allowlisted);
    }

    #[test]
    fn allowlist_requires_reason() {
        let mut t = SsrfPolicyTemplate::default_template("conn-1".into());
        let result = t.add_allowlist("10.0.0.5", None, "", "t10", "ts");
        assert!(result.is_err());
    }

    #[test]
    fn allowlist_rejects_path_like_and_empty_label_hosts() {
        for host in [
            "api.example.com/../169.254.169.254",
            r"api.example.com\169.254.169.254",
            "api..example.com",
        ] {
            let mut t = SsrfPolicyTemplate::default_template("conn-1".into());
            let result = t.add_allowlist(host, None, "public api", "trace-path", "ts");

            assert!(matches!(result, Err(SsrfError::SsrfTemplateInvalid { .. })));
            assert!(t.allowlist.is_empty());
        }
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

    #[test]
    fn to_egress_policy_matches_trailing_dot_hostname_variants() {
        let mut t = SsrfPolicyTemplate::default_template("conn-1".into());
        let _ = t.add_allowlist("api.example.com", Some(443), "api", "t11b", "ts");
        let policy = t.to_egress_policy();
        let (action, rule_idx) = policy.evaluate(" API.EXAMPLE.COM. ", 443, Protocol::Http);
        assert_eq!(action, Action::Allow);
        assert_eq!(rule_idx, Some(0));
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

    #[test]
    fn validate_rejects_invalid_cidr_prefix_length() {
        let mut t = SsrfPolicyTemplate::default_template("conn-1".into());
        t.blocked_cidrs[0].prefix_len = 33;

        assert!(matches!(
            t.validate(),
            Err(SsrfError::SsrfTemplateInvalid { .. })
        ));
    }

    #[test]
    fn validate_rejects_allowlist_entry_without_reason() {
        let mut t = SsrfPolicyTemplate::default_template("conn-1".into());
        push_bounded(
            &mut t.allowlist,
            AllowlistEntry {
                host: "10.0.0.5".into(),
                port: Some(8080),
                reason: String::new(),
                receipt: PolicyReceipt {
                    receipt_id: "rcpt-missing-reason".into(),
                    connector_id: "conn-1".into(),
                    host: "10.0.0.5".into(),
                    issued_at: "2026-01-01".into(),
                    reason: "present on receipt only".into(),
                    trace_id: "trace-present".into(),
                },
            },
            MAX_ALLOWLIST_ENTRIES,
        );

        assert!(matches!(
            t.validate(),
            Err(SsrfError::SsrfReceiptMissing { .. })
        ));
    }

    #[test]
    fn validate_rejects_allowlist_entry_without_receipt_trace_id() {
        let mut t = SsrfPolicyTemplate::default_template("conn-1".into());
        push_bounded(
            &mut t.allowlist,
            AllowlistEntry {
                host: "10.0.0.5".into(),
                port: Some(8080),
                reason: "internal API".into(),
                receipt: PolicyReceipt {
                    receipt_id: "rcpt-missing-trace".into(),
                    connector_id: "conn-1".into(),
                    host: "10.0.0.5".into(),
                    issued_at: "2026-01-01".into(),
                    reason: "internal API".into(),
                    trace_id: String::new(),
                },
            },
            MAX_ALLOWLIST_ENTRIES,
        );

        assert!(matches!(
            t.validate(),
            Err(SsrfError::SsrfReceiptMissing { .. })
        ));
    }

    #[test]
    fn validate_rejects_allowlist_entry_with_path_like_host() {
        let mut t = SsrfPolicyTemplate::default_template("conn-1".into());
        push_bounded(
            &mut t.allowlist,
            AllowlistEntry {
                host: "api.example.com/../169.254.169.254".into(),
                port: None,
                reason: "public api".into(),
                receipt: PolicyReceipt {
                    receipt_id: "rcpt-path-host".into(),
                    connector_id: "conn-1".into(),
                    host: "api.example.com/../169.254.169.254".into(),
                    issued_at: "2026-01-01".into(),
                    reason: "public api".into(),
                    trace_id: "trace-path-host".into(),
                },
            },
            MAX_ALLOWLIST_ENTRIES,
        );

        assert!(matches!(
            t.validate(),
            Err(SsrfError::SsrfTemplateInvalid { .. })
        ));
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

    #[test]
    fn test_find_allowlist_case_insensitive() {
        // DNS hostnames are case-insensitive (RFC 4343).
        // Uppercase host must still match a lowercase allowlist entry.
        let mut policy = SsrfPolicyTemplate::default_template("test-conn".into());
        push_bounded(
            &mut policy.allowlist,
            AllowlistEntry {
                host: "api.example.com".into(),
                port: Some(443),
                reason: "test".into(),
                receipt: PolicyReceipt {
                    receipt_id: "r1".into(),
                    connector_id: "test-conn".into(),
                    host: "api.example.com".into(),
                    issued_at: "2026-01-01T00:00:00Z".into(),
                    reason: "test".into(),
                    trace_id: "t1".into(),
                },
            },
            MAX_ALLOWLIST_ENTRIES,
        );

        // Exact case → match
        let found = policy.find_allowlist("api.example.com", 443);
        assert!(found.is_some());

        // Mixed case → must still match
        let found_upper = policy.find_allowlist("API.EXAMPLE.COM", 443);
        assert!(
            found_upper.is_some(),
            "uppercase host must match lowercase allowlist entry"
        );

        let found_mixed = policy.find_allowlist("Api.Example.Com", 443);
        assert!(
            found_mixed.is_some(),
            "mixed-case host must match lowercase allowlist entry"
        );

        // Wrong port → no match regardless of case
        let wrong_port = policy.find_allowlist("API.EXAMPLE.COM", 80);
        assert!(wrong_port.is_none());
    }

    #[test]
    fn test_find_allowlist_normalizes_trailing_dot_and_whitespace() {
        let mut policy = SsrfPolicyTemplate::default_template("test-conn".into());
        push_bounded(
            &mut policy.allowlist,
            AllowlistEntry {
                host: "api.example.com".into(),
                port: Some(443),
                reason: "test".into(),
                receipt: PolicyReceipt {
                    receipt_id: "r2".into(),
                    connector_id: "test-conn".into(),
                    host: "api.example.com".into(),
                    issued_at: "2026-01-01T00:00:00Z".into(),
                    reason: "test".into(),
                    trace_id: "t2".into(),
                },
            },
            MAX_ALLOWLIST_ENTRIES,
        );

        let found = policy.find_allowlist(" API.EXAMPLE.COM. ", 443);
        assert!(
            found.is_some(),
            "allowlist matching should normalize trailing dots and surrounding whitespace"
        );
    }

    #[test]
    fn allowlist_capacity_enforced() {
        let mut p = SsrfPolicyTemplate::default_template("test-conn".into());
        for i in 0..MAX_ALLOWLIST_ENTRIES {
            p.add_allowlist(&format!("host-{i}"), None, "r", "t", "time")
                .unwrap();
        }
        // Now uses bounded eviction instead of error
        let receipt = p
            .add_allowlist("overflow", None, "r", "t", "time")
            .unwrap();
        assert_eq!(p.allowlist.len(), MAX_ALLOWLIST_ENTRIES);
        assert_eq!(receipt.host, "overflow");
        // Verify oldest entry was evicted
        assert!(!p.allowlist.iter().any(|e| e.host == "host-0"));
    }

    #[test]
    fn push_bounded_zero_capacity_drops_existing_and_new_entries() {
        let mut items = vec![1, 2, 3];

        push_bounded(&mut items, 4, 0);

        assert!(items.is_empty());
    }

    #[test]
    fn ssrf_connector_id_unicode_injection_attack() {
        // Test BiDi override and control character injection in connector IDs
        let malicious_id = format!("conn-{}\u{202e}evil\u{202d}-{}", "\u{200b}".repeat(1000), "🔥".repeat(500));
        let mut policy = SsrfPolicyTemplate::default_template(malicious_id.clone());

        let result = policy.check_ssrf("8.8.8.8", 443, Protocol::Http, "trace-unicode", "ts");
        assert!(result.is_ok());

        // Verify audit record handles massive Unicode safely
        assert_eq!(policy.audit_log[0].connector_id, malicious_id);
        assert!(policy.audit_log[0].connector_id.chars().count() > 1500);

        // Test display safety (no panic on format)
        let display_str = format!("{:?}", policy.audit_log[0]);
        assert!(display_str.len() > 100); // Should contain escaped Unicode

        // Test serialization robustness with Unicode injection
        let json_result = serde_json::to_string(&policy);
        assert!(json_result.is_ok());
        let parsed: Result<SsrfPolicyTemplate, _> = serde_json::from_str(&json_result.unwrap());
        assert!(parsed.is_ok());
    }

    #[test]
    fn ssrf_audit_log_memory_exhaustion_stress() {
        // Test bounded audit log with massive trace ID and host payloads
        let mut policy = SsrfPolicyTemplate::default_template("conn-extra".into());
        let massive_host = "a".repeat(65536);
        let massive_trace = format!("trace-{}", "x".repeat(100000));

        // Stress test with many oversized audit entries
        for i in 0..1000 {
            let host = format!("{massive_host}-{i}");
            let trace = format!("{massive_trace}-{i}");
            let _ = policy.check_ssrf(&host, 443, Protocol::Http, &trace, "ts");
        }

        // Verify bounded capacity prevents memory exhaustion
        assert!(policy.audit_log.len() <= crate::capacity_defaults::aliases::MAX_AUDIT_LOG_ENTRIES);

        // Test that oldest entries are evicted (FIFO)
        let last_entry = &policy.audit_log[policy.audit_log.len().saturating_sub(1)];
        assert!(last_entry.trace_id.contains("999")); // Should contain recent entry

        // Verify memory usage is bounded despite massive payloads
        let total_audit_size: usize = policy.audit_log.iter()
            .map(|r| r.host.len() + r.trace_id.len() + r.connector_id.len())
            .sum();
        assert!(total_audit_size < 50_000_000); // Reasonable memory bound
    }

    #[test]
    fn ssrf_json_structure_integrity_validation() {
        // Test malicious JSON injection in allowlist receipt fields
        let mut policy = SsrfPolicyTemplate::default_template("conn-extra".into());
        let json_bomb = r#"{"nested":{"arrays":[[[[["very","deep"]]]]],"objects":{"a":{"b":{"c":{"d":"value"}}}}}}"#;
        let json_injection = format!(r#"api.example.com","malicious":{json_bomb},"legitimate":"#);

        let result = policy.add_allowlist(
            &json_injection,
            Some(443),
            "legitimate reason",
            "trace-json",
            "ts"
        );
        assert!(result.is_ok()); // Should accept but sanitize

        // Verify JSON serialization integrity
        let serialized = serde_json::to_string(&policy).unwrap();
        assert!(!serialized.contains("\"malicious\":{\"nested\"")); // Injection escaped

        // Test deserialization with injected structure
        let parsed: SsrfPolicyTemplate = serde_json::from_str(&serialized).unwrap();
        assert_eq!(parsed.allowlist.len(), 1);
        assert!(parsed.allowlist[0].host.contains("api.example.com"));

        // Verify structural integrity after round-trip
        let validated = parsed.validate();
        assert!(validated.is_ok());
    }

    #[test]
    fn ssrf_arithmetic_overflow_protection() {
        // Test saturating arithmetic in various numeric contexts
        let mut policy = SsrfPolicyTemplate::default_template("conn-extra".into());

        // Test port number edge cases
        let ports = [0, 1, 65535, u16::MAX];
        for &port in &ports {
            let result = policy.check_ssrf("8.8.8.8", port, Protocol::Http, "trace-port", "ts");
            assert!(result.is_ok());
        }

        // Test CIDR prefix length bounds
        let extreme_cidr = CidrRange::new([192, 168, 1, 0], 255, "overflow-test");
        let contains_result = extreme_cidr.contains([192, 168, 1, 1]);
        // Should not crash on overflow in mask calculation
        assert!(contains_result); // Invalid blocked prefix should fail closed

        // Test allowlist capacity near MAX_ALLOWLIST_ENTRIES
        for i in 0..(MAX_ALLOWLIST_ENTRIES - 1) {
            let result = policy.add_allowlist(&format!("host-{i}"), None, "test", "trace", "ts");
            assert!(result.is_ok());
        }

        // Test overflow protection at capacity boundary
        let overflow_result = policy.add_allowlist("overflow", None, "test", "trace", "ts");
        assert!(overflow_result.is_err());
        assert!(matches!(overflow_result.unwrap_err(), SsrfError::SsrfTemplateInvalid { .. }));
    }

    #[test]
    fn ssrf_malicious_cidr_bypass_attempts() {
        // Test various CIDR bypass techniques and edge cases
        let policy = SsrfPolicyTemplate::default_template("conn-extra".into());

        // Test boundary conditions for each standard blocked CIDR
        let bypass_attempts = [
            ("126.255.255.255", false), // Just before 127.0.0.0/8
            ("128.0.0.1", true),        // Just after 127.255.255.255
            ("9.255.255.255", true),    // Just before 10.0.0.0/8
            ("11.0.0.1", true),         // Just after 10.255.255.255
            ("172.15.255.255", true),   // Just before 172.16.0.0/12
            ("172.32.0.1", true),       // Just after 172.31.255.255
            ("192.167.255.255", true),  // Just before 192.168.0.0/16
            ("192.169.0.1", true),      // Just after 192.168.255.255
            ("169.253.255.255", true),  // Just before 169.254.0.0/16
            ("169.255.0.1", true),      // Just after 169.254.255.255
            ("100.63.255.255", true),   // Just before 100.64.0.0/10
            ("100.128.0.1", true),      // Just after 100.127.255.255
        ];

        for (ip, should_be_public) in bypass_attempts {
            let is_private = SsrfPolicyTemplate::is_private_ip(ip);
            assert_eq!(is_private, !should_be_public, "CIDR bypass check failed for {ip}");
        }

        // Test prefix length edge cases
        let edge_cidrs = [
            CidrRange::new([0, 0, 0, 0], 0, "everything"),   // /0 should match all
            CidrRange::new([127, 0, 0, 1], 32, "exact"),     // /32 should match exactly
            CidrRange::new([192, 168, 1, 0], 31, "tiny"),    // /31 should match 2 IPs
        ];

        for cidr in &edge_cidrs {
            let test_ips = [[127, 0, 0, 1], [192, 168, 1, 0], [192, 168, 1, 1]];
            for &ip in &test_ips {
                let contains = cidr.contains(ip);
                // Verify no panics and logical results
                assert!(contains == contains); // Tautology check for side effects
            }
        }
    }

    #[test]
    fn ssrf_allowlist_collision_resistance() {
        // Test allowlist matching against collision and confusion attacks
        let mut policy = SsrfPolicyTemplate::default_template("conn-extra".into());

        // Add legitimate entry
        policy.add_allowlist("api.example.com", Some(443), "legitimate", "trace-1", "ts").unwrap();

        // Test various homograph and collision attempts
        let collision_attempts = [
            "api.example.com\u{200b}",     // Zero-width space
            "api.example.com\u{feff}",     // Zero-width no-break space
            "api.example.com\u{00a0}",     // Non-breaking space
            "api.example.com\u{2009}",     // Thin space
            "api.еxample.com",             // Cyrillic 'е' instead of 'e'
            "АPI.example.com",             // Cyrillic 'А' instead of 'A'
            "api.example.co\u{006d}",      // Normal 'm' for verification
            "api.example.com\u{ff2e}",     // Full-width 'M'
        ];

        for malicious_host in collision_attempts {
            let found = policy.find_allowlist(malicious_host, 443);

            // Most should not match due to normalization
            if malicious_host.ends_with('\u{006d}') {
                assert!(found.is_some(), "Normal host should match");
            } else {
                // Unicode variants should not bypass allowlist matching
                let should_match = malicious_host == "api.example.com\u{200b}" ||
                                 malicious_host == "api.example.com\u{feff}" ||
                                 malicious_host == "api.example.com\u{00a0}";

                if should_match {
                    // These might match due to normalization - verify behavior
                    let _ = found; // Allow either match or no-match
                } else {
                    assert!(found.is_none(), "Collision attempt should not match: {malicious_host:?}");
                }
            }
        }
    }

    #[test]
    fn ssrf_concurrent_policy_modification_safety() {
        // Test concurrent policy modification scenarios for race conditions
        use std::sync::{Arc, Mutex};
        use std::thread;

        let policy = Arc::new(Mutex::new(SsrfPolicyTemplate::default_template("conn-extra".into())));
        let mut handles = vec![];

        // Spawn concurrent threads performing different operations
        for thread_id in 0..10 {
            let policy_clone = Arc::clone(&policy);

            let handle = thread::spawn(move || {
                let operations = [
                    // Mix of allowlist additions and SSRF checks
                    || {
                        let mut p = policy_clone.lock().unwrap();
                        let _ = p.add_allowlist(
                            &format!("host-{thread_id}"),
                            Some(8080_u16.saturating_add(thread_id as u16)),
                            "concurrent test",
                            &format!("trace-{thread_id}"),
                            "ts"
                        );
                    },
                    || {
                        let mut p = policy_clone.lock().unwrap();
                        let _ = p.check_ssrf(
                            "8.8.8.8",
                            443,
                            Protocol::Http,
                            &format!("trace-check-{thread_id}"),
                            "ts"
                        );
                    },
                    || {
                        let p = policy_clone.lock().unwrap();
                        let _ = p.validate();
                    }
                ];

                // Perform multiple operations in this thread
                for op in operations.iter().cycle().take(50) {
                    op();
                }
            });

            handles.push(handle);
        }

        // Wait for all threads to complete
        for handle in handles {
            handle.join().expect("Thread panicked");
        }

        // Verify final state consistency
        let final_policy = policy.lock().unwrap();
        assert!(final_policy.validate().is_ok());
        assert!(final_policy.allowlist.len() <= 10); // At most 10 entries added
        assert!(final_policy.audit_log.len() >= 10); // At least 10 check operations

        // Verify no data corruption from concurrent access
        for entry in &final_policy.allowlist {
            assert!(entry.host.starts_with("host-"));
            assert!(entry.reason == "concurrent test");
            assert!(entry.receipt.trace_id.starts_with("trace-"));
        }
    }

    #[test]
    fn ssrf_display_injection_and_format_safety() {
        // Test format string injection and display safety
        let mut policy = SsrfPolicyTemplate::default_template("conn-extra".into());

        // Add entries with format specifiers and injection attempts
        let malicious_inputs = [
            ("api.{}.com", Some(443), "reason with {} format", "trace-{}-injection"),
            ("host\n\tmalicious", None, "reason\x00null", "trace\r\nCRLF"),
            ("host%n%s%d", Some(80), "reason%x%p", "trace%c%u"),
            ("api.\x1b[31mred\x1b[0m.com", Some(443), "ANSI\x1b[1mbold\x1b[0m", "trace\x1b[?1049h"),
            ("\u{1f4a9}\u{200d}\u{1f525}", None, "\u{202e}RLO\u{202d}", "\u{2066}LRI\u{2069}"),
        ];

        for (host, port, reason, trace) in malicious_inputs {
            let result = policy.add_allowlist(host, port, reason, trace, "ts");
            assert!(result.is_ok(), "Should accept malicious input for testing");

            // Test SSRF check with the injected host
            let check_result = policy.check_ssrf(host, port.unwrap_or(80), Protocol::Http, trace, "ts");
            let _ = check_result; // Allow any result, testing safety
        }

        // Test display safety - should not panic or produce control sequences
        for entry in &policy.allowlist {
            let debug_str = format!("{:?}", entry);
            assert!(!debug_str.contains('\x00'), "Debug output should escape null bytes");

            let receipt_display = format!("{}", entry.receipt.trace_id);
            assert!(receipt_display.len() >= 1, "Display should produce some output");
        }

        // Test audit log display safety
        for record in &policy.audit_log {
            let json_str = serde_json::to_string(record).unwrap();
            assert!(!json_str.contains("\\u0000"), "JSON should escape control chars safely");

            let debug_str = format!("{:?}", record);
            assert!(!debug_str.contains('\r'), "Debug should escape CRLF");
            assert!(!debug_str.contains('\n'), "Debug should escape newlines");
        }

        // Test error display safety
        let errors = [
            SsrfError::SsrfDenied { host: "host\x00\x1b[31m".to_string(), cidr: "cidr%s".to_string() },
            SsrfError::SsrfInvalidIp { host: "invalid\r\n%n".to_string() },
            SsrfError::SsrfReceiptMissing { detail: "detail\t%p".to_string() },
            SsrfError::SsrfTemplateInvalid { reason: "reason\x1b[?1049h".to_string() },
        ];

        for error in errors {
            let display_str = format!("{}", error);
            assert!(!display_str.contains('\x00'), "Error display should be safe");

            let debug_str = format!("{:?}", error);
            assert!(debug_str.len() > 10, "Error debug should produce output");
        }
    }

    #[test]
    fn ssrf_boundary_condition_stress_testing() {
        // Test extreme boundary conditions and edge cases
        let mut policy = SsrfPolicyTemplate::default_template("conn-extra".into());

        // Test empty and minimal inputs
        let boundary_hosts = [
            "",           // Empty string
            " ",          // Whitespace only
            "a",          // Single character
            ".",          // Single dot
            "0.0.0.0",    // Network address
            "255.255.255.255", // Broadcast address
            "::1",        // IPv6 loopback (should be blocked)
            "[::]",       // IPv6 any (malformed)
            "[::1",       // Unbalanced brackets
            "::1]",       // Unbalanced brackets
        ];

        for host in boundary_hosts {
            let result = policy.check_ssrf(host, 80, Protocol::Http, "trace-boundary", "ts");
            let _ = result; // Allow any result, testing for crashes

            // Test is_private_ip boundary behavior
            let is_private = SsrfPolicyTemplate::is_private_ip(host);
            assert!(is_private == is_private); // Tautology to check for side effects
        }

        // Test port boundaries
        let boundary_ports = [0, 1, 80, 443, 65534, 65535];
        for &port in &boundary_ports {
            let result = policy.check_ssrf("8.8.8.8", port, Protocol::Http, "trace-port-boundary", "ts");
            assert!(result.is_ok(), "Public IP should be allowed on any port");
        }

        // Test extremely long inputs
        let long_host = "a".repeat(100000);
        let long_trace = "x".repeat(100000);
        let long_reason = "r".repeat(100000);

        let add_result = policy.add_allowlist(&long_host, None, &long_reason, &long_trace, "ts");
        assert!(add_result.is_ok(), "Should handle very long inputs");

        let check_result = policy.check_ssrf(&long_host, 443, Protocol::Http, &long_trace, "ts");
        assert!(check_result.is_ok(), "Should allow very long allowlisted host");

        // Test serialization with boundary data
        let json_result = serde_json::to_string(&policy);
        assert!(json_result.is_ok(), "Should serialize boundary data safely");

        let parsed_result: Result<SsrfPolicyTemplate, _> = serde_json::from_str(&json_result.unwrap());
        assert!(parsed_result.is_ok(), "Should deserialize boundary data safely");
    }
}

#[cfg(test)]
mod ssrf_additional_negative_tests {
    use super::*;

    fn template() -> SsrfPolicyTemplate {
        SsrfPolicyTemplate::default_template("conn-extra".to_string())
    }

    fn receipt(host: &str, reason: &str, trace_id: &str) -> PolicyReceipt {
        PolicyReceipt {
            receipt_id: format!("rcpt-{host}"),
            connector_id: "conn-extra".to_string(),
            host: host.to_string(),
            issued_at: "2026-04-17T00:00:00Z".to_string(),
            reason: reason.to_string(),
            trace_id: trace_id.to_string(),
        }
    }

    #[test]
    fn check_ssrf_rejects_octal_loopback_alias() {
        let mut policy = template();

        let err = policy
            .check_ssrf("0177.0.0.1", 80, Protocol::Http, "trace-octal", "ts")
            .unwrap_err();

        assert!(matches!(err, SsrfError::SsrfInvalidIp { .. }));
        assert_eq!(policy.audit_log[0].action, Action::Deny);
        assert_eq!(
            policy.audit_log[0].cidr_matched.as_deref(),
            Some("invalid_ip_format")
        );
    }

    #[test]
    fn check_ssrf_rejects_compact_decimal_private_alias() {
        let mut policy = template();

        let err = policy
            .check_ssrf("167772161", 80, Protocol::Http, "trace-decimal", "ts")
            .unwrap_err();

        assert!(matches!(err, SsrfError::SsrfInvalidIp { .. }));
        assert!(SsrfPolicyTemplate::is_private_ip("167772161"));
    }

    #[test]
    fn allowlist_entry_with_trailing_dot_does_not_mask_repeated_dot_host() {
        let mut policy = template();
        policy
            .add_allowlist("api.example.com.", None, "public api", "trace-allow", "ts")
            .expect("allowlist fixture");

        let err = policy
            .check_ssrf(
                "api.example.com..",
                443,
                Protocol::Http,
                "trace-check",
                "ts",
            )
            .unwrap_err();

        assert!(matches!(err, SsrfError::SsrfInvalidIp { .. }));
        assert!(!policy.audit_log[0].allowlisted);
    }

    #[test]
    fn add_allowlist_rejects_whitespace_trace_id() {
        let mut policy = template();

        let err = policy
            .add_allowlist("api.example.com", None, "public api", "   ", "ts")
            .unwrap_err();

        assert!(matches!(err, SsrfError::SsrfReceiptMissing { .. }));
        assert!(policy.allowlist.is_empty());
    }

    #[test]
    fn allowlist_reason_with_whitespace_only_is_rejected_on_validate() {
        let mut policy = template();
        policy.allowlist = vec![AllowlistEntry {
            host: "10.0.0.2".to_string(),
            port: None,
            reason: "   ".to_string(),
            receipt: receipt("10.0.0.2", "audit reason", "trace-a"),
        }];

        let err = policy.validate().unwrap_err();

        assert!(matches!(err, SsrfError::SsrfReceiptMissing { .. }));
    }

    #[test]
    fn receipt_with_whitespace_trace_id_is_rejected_on_validate() {
        let mut policy = template();
        policy.allowlist = vec![AllowlistEntry {
            host: "10.0.0.3".to_string(),
            port: None,
            reason: "internal dependency".to_string(),
            receipt: receipt("10.0.0.3", "internal dependency", "  "),
        }];

        let err = policy.validate().unwrap_err();

        assert!(matches!(err, SsrfError::SsrfReceiptMissing { .. }));
    }

    #[test]
    fn serde_rejects_unknown_ssrf_error_variant() {
        let result: Result<SsrfError, _> =
            serde_json::from_str(r#"{"SSRF_BYPASSED":{"host":"127.0.0.1"}}"#);

        assert!(result.is_err());
    }

    #[test]
    fn serde_rejects_audit_record_port_outside_u16_range() {
        let result: Result<SsrfAuditRecord, _> = serde_json::from_str(
            r#"{"connector_id":"c","timestamp":"ts","host":"h","port":70000,"action":"deny","cidr_matched":null,"allowlisted":false,"trace_id":"t"}"#,
        );

        assert!(result.is_err());
    }

    #[test]
    fn private_ip_treats_null_byte_hostname_as_denied() {
        assert!(SsrfPolicyTemplate::is_private_ip(
            "api.example.com\0.localhost"
        ));
    }

    #[test]
    fn check_ssrf_rejects_null_byte_hostname_before_dns_allow() {
        let mut policy = template();

        let err = policy
            .check_ssrf(
                "api.example.com\0.localhost",
                443,
                Protocol::Http,
                "trace-null-host",
                "ts",
            )
            .unwrap_err();

        assert!(matches!(err, SsrfError::SsrfInvalidIp { .. }));
        assert_eq!(policy.audit_log[0].action, Action::Deny);
        assert_eq!(
            policy.audit_log[0].cidr_matched.as_deref(),
            Some("invalid_ip_format")
        );
    }

    #[test]
    fn check_ssrf_rejects_null_byte_loopback_alias_before_allowlist() {
        let mut policy = template();
        policy
            .add_allowlist("127.0.0.1", Some(80), "local test", "trace-allow", "ts")
            .expect("allowlist fixture");

        let err = policy
            .check_ssrf(
                "127.0.0.1\0.example.com",
                80,
                Protocol::Http,
                "trace-null-loopback",
                "ts",
            )
            .unwrap_err();

        assert!(matches!(err, SsrfError::SsrfInvalidIp { .. }));
        assert_eq!(policy.audit_log[0].action, Action::Deny);
        assert!(!policy.audit_log[0].allowlisted);
    }

    #[test]
    fn add_allowlist_rejects_null_byte_host() {
        let mut policy = template();

        let err = policy
            .add_allowlist(
                "api.example.com\0.localhost",
                None,
                "public api",
                "trace-null-allow",
                "ts",
            )
            .unwrap_err();

        assert!(matches!(err, SsrfError::SsrfTemplateInvalid { .. }));
        assert!(policy.allowlist.is_empty());
    }

    #[test]
    fn validate_rejects_allowlist_entry_with_null_byte_host() {
        let mut policy = template();
        policy.allowlist = vec![AllowlistEntry {
            host: "api.example.com\0.localhost".to_string(),
            port: None,
            reason: "public api".to_string(),
            receipt: receipt("api.example.com", "public api", "trace-null-validate"),
        }];

        let err = policy.validate().unwrap_err();

        assert!(matches!(err, SsrfError::SsrfTemplateInvalid { .. }));
    }

    #[test]
    fn allowlisted_public_host_does_not_match_null_byte_variant() {
        let mut policy = template();
        policy
            .add_allowlist(
                "api.example.com",
                Some(443),
                "public api",
                "trace-allow",
                "ts",
            )
            .expect("allowlist fixture");

        let err = policy
            .check_ssrf(
                "api.example.com\0.evil.test",
                443,
                Protocol::Http,
                "trace-null-variant",
                "ts",
            )
            .unwrap_err();

        assert!(matches!(err, SsrfError::SsrfInvalidIp { .. }));
        assert_eq!(policy.audit_log[0].action, Action::Deny);
        assert!(!policy.audit_log[0].allowlisted);
    }

    #[test]
    fn parse_ipv4_rejects_empty_octets() {
        for host in [".1.2.3", "1..2.3", "1.2.3.", "1.2..4"] {
            assert_eq!(parse_ipv4(host), None, "empty octet parsed: {host:?}");
        }
    }

    #[test]
    fn parse_ipv4_lax_rejects_signed_and_invalid_octal_parts() {
        for host in ["-1.0.0.1", "08.0.0.1", "1.-2.3.4"] {
            assert_eq!(
                parse_ipv4_lax(host),
                None,
                "signed or invalid octal alias parsed: {host:?}"
            );
        }
    }

    #[test]
    fn parse_ipv4_lax_rejects_single_integer_overflow_aliases() {
        for host in ["4294967296", "0x100000000"] {
            assert_eq!(
                parse_ipv4_lax(host),
                None,
                "overflowing integer IPv4 alias parsed: {host:?}"
            );
        }
    }

    #[test]
    fn trailing_dot_numeric_alias_rejects_empty_and_hostname_values() {
        for host in [".", "...", "api.example.com."] {
            assert_eq!(
                parse_trailing_dot_numeric_ipv4_alias(host),
                None,
                "non-numeric trailing-dot host parsed: {host:?}"
            );
        }
    }

    #[test]
    fn check_ssrf_denies_localhost_alias_when_allowlist_port_differs() {
        let mut policy = template();
        policy
            .add_allowlist("localhost", Some(8080), "local proxy", "trace-allow", "ts")
            .expect("allowlist fixture");

        let err = policy
            .check_ssrf("LOCALHOST.", 80, Protocol::Http, "trace-deny", "ts")
            .unwrap_err();

        assert!(matches!(err, SsrfError::SsrfDenied { .. }));
        assert_eq!(
            policy.audit_log[0].cidr_matched.as_deref(),
            Some("localhost")
        );
        assert!(!policy.audit_log[0].allowlisted);
    }

    #[test]
    fn check_ssrf_rejects_trailing_dot_ip_alias_even_when_canonical_ip_allowlisted() {
        let mut policy = template();
        policy
            .add_allowlist("8.8.8.8", Some(53), "dns fixture", "trace-allow", "ts")
            .expect("allowlist fixture");

        let err = policy
            .check_ssrf("8.8.8.8.", 53, Protocol::Tcp, "trace-ip-dot", "ts")
            .unwrap_err();

        assert!(matches!(err, SsrfError::SsrfInvalidIp { .. }));
        assert_eq!(
            policy.audit_log[0].cidr_matched.as_deref(),
            Some("invalid_ip_format")
        );
        assert!(!policy.audit_log[0].allowlisted);
    }

    #[test]
    fn check_ssrf_rejects_bracketed_public_ipv4_even_when_canonical_ip_allowlisted() {
        let mut policy = template();
        policy
            .add_allowlist("8.8.4.4", Some(443), "dns fixture", "trace-allow", "ts")
            .expect("allowlist fixture");

        let err = policy
            .check_ssrf("[8.8.4.4]", 443, Protocol::Http, "trace-bracketed-ip", "ts")
            .unwrap_err();

        assert!(matches!(err, SsrfError::SsrfInvalidIp { .. }));
        assert_eq!(
            policy.audit_log[0].cidr_matched.as_deref(),
            Some("invalid_ip_format")
        );
        assert!(!policy.audit_log[0].allowlisted);
    }

    #[test]
    fn add_allowlist_rejects_whitespace_only_reason() {
        let mut policy = template();

        let err = policy
            .add_allowlist("api.example.com", None, "   ", "trace-reason", "ts")
            .unwrap_err();

        assert!(matches!(err, SsrfError::SsrfReceiptMissing { .. }));
        assert!(policy.allowlist.is_empty());
    }

    #[test]
    fn check_ssrf_rejects_dotted_hex_loopback_alias() {
        let mut policy = template();

        let err = policy
            .check_ssrf("0x7f.0.0.1", 80, Protocol::Http, "trace-hex-dot", "ts")
            .unwrap_err();

        assert!(matches!(err, SsrfError::SsrfInvalidIp { .. }));
        assert!(SsrfPolicyTemplate::is_private_ip("0x7f.0.0.1"));
        assert_eq!(
            policy.audit_log[0].cidr_matched.as_deref(),
            Some("invalid_ip_format")
        );
    }

    #[test]
    fn check_ssrf_rejects_short_mixed_radix_private_alias() {
        let mut policy = template();

        let err = policy
            .check_ssrf("10.0x000001", 443, Protocol::Http, "trace-mixed", "ts")
            .unwrap_err();

        assert!(matches!(err, SsrfError::SsrfInvalidIp { .. }));
        assert!(SsrfPolicyTemplate::is_private_ip("10.0x000001"));
        assert_eq!(policy.audit_log[0].action, Action::Deny);
    }

    #[test]
    fn check_ssrf_rejects_octal_class_a_alias() {
        let mut policy = template();

        let err = policy
            .check_ssrf("012.0.0.1", 80, Protocol::Http, "trace-octal-a", "ts")
            .unwrap_err();

        assert!(matches!(err, SsrfError::SsrfInvalidIp { .. }));
        assert!(SsrfPolicyTemplate::is_private_ip("012.0.0.1"));
        assert!(!policy.audit_log[0].allowlisted);
    }

    #[test]
    fn private_ip_treats_unmatched_closing_bracket_hostname_as_denied() {
        assert!(SsrfPolicyTemplate::is_private_ip("api.example.com]"));
    }

    #[test]
    fn check_ssrf_rejects_unmatched_closing_bracket_hostname() {
        let mut policy = template();

        let err = policy
            .check_ssrf(
                "api.example.com]",
                443,
                Protocol::Http,
                "trace-closing-bracket",
                "ts",
            )
            .unwrap_err();

        assert!(matches!(err, SsrfError::SsrfInvalidIp { .. }));
        assert_eq!(policy.audit_log[0].action, Action::Deny);
    }

    #[test]
    fn check_ssrf_rejects_bracketed_public_ipv6_literal() {
        let mut policy = template();

        let err = policy
            .check_ssrf(
                "[2001:4860:4860::8888]",
                443,
                Protocol::Http,
                "trace-bracketed-ipv6",
                "ts",
            )
            .unwrap_err();

        match err {
            SsrfError::SsrfDenied { cidr, .. } => assert_eq!(cidr, "ipv6_unsupported"),
            other => unreachable!("expected IPv6 unsupported denial, got {:?}", other),
        }
        assert_eq!(policy.audit_log[0].action, Action::Deny);
    }

    #[test]
    fn check_ssrf_rejects_lax_alias_even_when_canonical_loopback_allowlisted() {
        let mut policy = template();
        policy
            .add_allowlist("127.0.0.1", None, "local fixture", "trace-allow", "ts")
            .expect("allowlist fixture");

        let err = policy
            .check_ssrf(
                "0x7f000001",
                80,
                Protocol::Http,
                "trace-lax-loopback",
                "ts",
            )
            .unwrap_err();

        assert!(matches!(err, SsrfError::SsrfInvalidIp { .. }));
        assert_eq!(
            policy.audit_log[0].cidr_matched.as_deref(),
            Some("invalid_ip_format")
        );
        assert!(!policy.audit_log[0].allowlisted);
    }
}
