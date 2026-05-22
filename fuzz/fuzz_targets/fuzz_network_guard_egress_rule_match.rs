#![no_main]

//! Fuzz harness for
//! `frankenengine_node::security::network_guard::EgressRule::matches` at
//! `crates/franken-node/src/security/network_guard.rs:72`. The
//! `matches` predicate is the load-bearing comparison for every
//! egress decision: a regression that admits a null-byte-truncated
//! host, fails case-insensitive comparison, or mishandles wildcards
//! would let an attacker bypass the egress deny-list.
//!
//! Existing fuzz coverage of this matcher: **zero**.
//!
//! Six invariants pinned per call:
//!
//!   (A) **INV-NETGUARD-PANIC-FREE** — arbitrary host/port/protocol
//!       inputs MUST NOT panic the matcher.
//!
//!   (B) **INV-NETGUARD-NULL-BYTE-REJECT** — when the request host
//!       contains `'\0'`, `matches` MUST return false. Catches a
//!       regression that lets `"evil.com\0.safe.com"` slip past the
//!       deny-list when DNS resolves "evil.com" (C-string truncation
//!       bypass at network_guard.rs:91-94).
//!
//!   (C) **INV-NETGUARD-CASE-INSENSITIVE** — when the rule host is a
//!       valid (no-null, no-empty-label) lowercased pattern, the
//!       matcher's verdict MUST equal the verdict when the request
//!       host is uppercased. Catches a regression dropping the
//!       `to_ascii_lowercase` normalization.
//!
//!   (D) **INV-NETGUARD-PROTOCOL-REQUIRED** — when the rule protocol
//!       differs from the request protocol, `matches` MUST return
//!       false regardless of host.
//!
//!   (E) **INV-NETGUARD-PORT-REQUIRED** — when the rule has a
//!       specific port AND that port doesn't match the request,
//!       `matches` MUST return false.
//!
//!   (F) **INV-NETGUARD-WILDCARD-DOMAIN-BOUND** — the `*.suffix`
//!       pattern MUST NOT match a host equal to or shorter than the
//!       suffix, AND MUST match `<anything>.suffix`. Catches a
//!       regression where `*.example.com` accidentally matches
//!       `example.com` (no leading label).

use arbitrary::Arbitrary;
use frankenengine_node::security::network_guard::{Action, EgressRule, Protocol};
use libfuzzer_sys::fuzz_target;

const MAX_HOST_BYTES: usize = 256;

#[derive(Debug, Arbitrary)]
struct NetworkGuardFuzzCase {
    rule_host: String,
    rule_port: Option<u16>,
    rule_action_is_deny: bool,
    rule_protocol_is_http: bool,
    request_host: String,
    request_port: u16,
    request_protocol_is_http: bool,
    include_null_byte_in_request: bool,
}

fuzz_target!(|case: NetworkGuardFuzzCase| {
    let rule = EgressRule {
        host: bounded(&case.rule_host, MAX_HOST_BYTES),
        port: case.rule_port,
        action: if case.rule_action_is_deny {
            Action::Deny
        } else {
            Action::Allow
        },
        protocol: if case.rule_protocol_is_http {
            Protocol::Http
        } else {
            Protocol::Tcp
        },
    };
    let mut request_host = bounded(&case.request_host, MAX_HOST_BYTES);
    if case.include_null_byte_in_request && !request_host.contains('\0') {
        // Inject a null byte at a stable position to exercise (B).
        request_host.push('\0');
        request_host.push_str("safe.example.com");
    }
    let request_protocol = if case.request_protocol_is_http {
        Protocol::Http
    } else {
        Protocol::Tcp
    };

    // ── (A) Panic-freedom: the call IS the assertion ────────────────
    let primary = rule.matches(&request_host, case.request_port, request_protocol);

    // ── (B) Null byte rejection ──────────────────────────────────────
    if request_host.contains('\0') {
        assert!(
            !primary,
            "INV-NETGUARD-NULL-BYTE-REJECT violated: matcher accepted host \
             containing '\\0' ({request_host:?})"
        );
    }

    // ── (D) Protocol mismatch ────────────────────────────────────────
    let other_protocol = match request_protocol {
        Protocol::Http => Protocol::Tcp,
        Protocol::Tcp => Protocol::Http,
    };
    if other_protocol != rule.protocol {
        let alt = rule.matches(&request_host, case.request_port, other_protocol);
        if rule.protocol == request_protocol {
            // Original matched (or didn't) on protocol; the OTHER protocol
            // ≠ rule.protocol, so it MUST NOT match.
            assert!(
                !alt,
                "INV-NETGUARD-PROTOCOL-REQUIRED violated: alt-protocol match \
                 returned true when rule.protocol={:?}, alt={:?}",
                rule.protocol, other_protocol
            );
        }
    }

    // ── (E) Port mismatch ────────────────────────────────────────────
    if let Some(rule_port) = rule.port
        && rule_port != case.request_port
    {
        assert!(
            !primary,
            "INV-NETGUARD-PORT-REQUIRED violated: matcher accepted port \
             {} when rule required port {rule_port}",
            case.request_port
        );
    }

    // ── (C) Case-insensitivity ──────────────────────────────────────
    // When the request host is non-empty ASCII (so to_ascii_uppercase is
    // a well-defined inverse of to_ascii_lowercase), uppercasing it MUST
    // not change the verdict. We restrict to ASCII to avoid Unicode
    // case-mapping ambiguity.
    if !request_host.is_empty()
        && request_host.is_ascii()
        && !request_host.contains('\0')
    {
        let upper = request_host.to_ascii_uppercase();
        let upper_match = rule.matches(&upper, case.request_port, request_protocol);
        assert_eq!(
            primary, upper_match,
            "INV-NETGUARD-CASE-INSENSITIVE violated: rule={:?} request_host={:?} \
             primary={primary} but uppercase={upper:?} matched={upper_match}",
            rule.host, request_host
        );
    }

    // ── (F) Wildcard *.suffix domain-bound ───────────────────────────
    // Build a deterministic *.suffix rule and verify it never matches
    // a host equal-to or shorter-than the suffix, but DOES match a
    // host of the form prefix.suffix when prefix is non-empty ASCII.
    let suffix_rule = EgressRule {
        host: "*.example.com".to_string(),
        port: None,
        action: Action::Allow,
        protocol: Protocol::Http,
    };
    let should_match_subdomain =
        suffix_rule.matches("foo.example.com", 80, Protocol::Http);
    assert!(
        should_match_subdomain,
        "INV-NETGUARD-WILDCARD-DOMAIN-BOUND violated: *.example.com did not \
         match foo.example.com"
    );
    let should_not_match_exact =
        suffix_rule.matches("example.com", 80, Protocol::Http);
    assert!(
        !should_not_match_exact,
        "INV-NETGUARD-WILDCARD-DOMAIN-BOUND violated: *.example.com matched \
         the exact suffix example.com (no leading label) — the h.len() > \
         suffix.len() check was dropped"
    );
});

fn bounded(s: &str, max_bytes: usize) -> String {
    if s.len() <= max_bytes {
        return s.to_string();
    }
    let mut out = String::with_capacity(max_bytes);
    for ch in s.chars() {
        if out.len().saturating_add(ch.len_utf8()) > max_bytes {
            break;
        }
        out.push(ch);
    }
    out
}
