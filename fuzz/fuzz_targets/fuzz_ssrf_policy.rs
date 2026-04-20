#![no_main]

use libfuzzer_sys::fuzz_target;
use arbitrary::{Arbitrary, Unstructured, Result as ArbitraryResult};
use std::hint::black_box;

use frankenengine_node::security::ssrf_policy::{
    SsrfPolicyTemplate, CidrRange, AllowlistEntry, PolicyReceipt
};
use frankenengine_node::security::network_guard::{Protocol, Action};

/// Maximum reasonable string length for fuzzing inputs to prevent OOM.
const MAX_STRING_LEN: usize = 1024;

/// Maximum CIDR ranges to prevent excessive computation.
const MAX_CIDR_RANGES: usize = 100;

/// Maximum allowlist entries to prevent excessive memory usage.
const MAX_ALLOWLIST_ENTRIES: usize = 50;

// Custom Arbitrary implementation for Protocol enum
impl<'a> Arbitrary<'a> for Protocol {
    fn arbitrary(u: &mut Unstructured<'a>) -> ArbitraryResult<Self> {
        let choice = u.int_in_range(0..=2)?;
        Ok(match choice {
            0 => Protocol::Tcp,
            1 => Protocol::Udp,
            _ => Protocol::Http, // Assuming these are the Protocol variants
        })
    }
}

#[derive(Arbitrary, Debug)]
struct FuzzCidrRange {
    network_a: u8,
    network_b: u8,
    network_c: u8,
    network_d: u8,
    prefix_len: u8,
    label: String,
}

#[derive(Arbitrary, Debug)]
struct FuzzPolicyReceipt {
    receipt_id: String,
    connector_id: String,
    host: String,
    issued_at: String,
    reason: String,
    trace_id: String,
}

#[derive(Arbitrary, Debug)]
struct FuzzAllowlistEntry {
    host: String,
    port: Option<u16>,
    reason: String,
    receipt: FuzzPolicyReceipt,
}

#[derive(Arbitrary, Debug)]
struct FuzzSsrfPolicyTemplate {
    connector_id: String,
    blocked_cidrs: Vec<FuzzCidrRange>,
    allowlist: Vec<FuzzAllowlistEntry>,
}

#[derive(Arbitrary, Debug)]
enum FuzzIpAddress {
    /// Standard IPv4 dotted decimal
    StandardIpv4 { a: u8, b: u8, c: u8, d: u8 },
    /// Hexadecimal IPv4 (0x notation)
    HexIpv4 { a: u8, b: u8, c: u8, d: u8 },
    /// Octal IPv4 (leading zero notation)
    OctalIpv4 { a: u8, b: u8, c: u8, d: u8 },
    /// Compressed IPv4 formats (1-4 parts)
    CompressedIpv4 { parts: Vec<u32> },
    /// IPv6 addresses
    Ipv6 { address: String },
    /// Malicious hostnames
    MaliciousHostname { hostname: String },
    /// Raw string (for edge case testing)
    RawString { data: String },
}

#[derive(Arbitrary, Debug)]
enum SsrfAttackVector {
    /// Null byte injection
    NullByteInjection { base_host: String },
    /// Path traversal in hostname
    PathTraversal { base_host: String },
    /// Unicode normalization attacks
    UnicodeAttack { base_host: String },
    /// Trailing dot manipulation
    TrailingDotAttack { host: String, dot_count: u8 },
    /// IP address confusion
    IpAddressConfusion { ip: FuzzIpAddress },
    /// CIDR range boundary testing
    CidrBoundaryTest { cidr: FuzzCidrRange, test_ips: Vec<FuzzIpAddress> },
    /// Allowlist bypass attempts
    AllowlistBypass { allowed_host: String, malicious_host: String, port: u16 },
    /// Private range bypass attempts
    PrivateRangeBypass { ip: FuzzIpAddress },
    /// DNS rebinding simulation
    DnsRebinding { hostname: String, resolved_ip: FuzzIpAddress },
}

#[derive(Arbitrary, Debug)]
enum FuzzOperation {
    /// Test SSRF checking with various attack vectors
    SsrfCheck {
        attack: SsrfAttackVector,
        port: u16,
        protocol: Protocol,
        trace_id: String,
        timestamp: String,
    },
    /// Test CIDR range matching edge cases
    CidrRangeMatching {
        cidr: FuzzCidrRange,
        test_ips: Vec<FuzzIpAddress>,
    },
    /// Test serialization round-trip attacks
    SerializationRoundTrip {
        policy: FuzzSsrfPolicyTemplate,
    },
    /// Test allowlist manipulation
    AllowlistManipulation {
        policy: FuzzSsrfPolicyTemplate,
        new_entries: Vec<FuzzAllowlistEntry>,
    },
    /// Test IP parsing edge cases
    IpParsingEdgeCases {
        ip_variants: Vec<FuzzIpAddress>,
    },
}

impl FuzzCidrRange {
    fn to_real(self) -> CidrRange {
        CidrRange::new(
            [self.network_a, self.network_b, self.network_c, self.network_d],
            self.prefix_len.min(32), // Clamp to valid range
            &Self::bound_string(self.label)
        )
    }

    fn bound_string(s: String) -> String {
        if s.len() > MAX_STRING_LEN {
            s[..MAX_STRING_LEN].to_string()
        } else {
            s
        }
    }
}

impl FuzzPolicyReceipt {
    fn to_real(self) -> PolicyReceipt {
        PolicyReceipt {
            receipt_id: FuzzCidrRange::bound_string(self.receipt_id),
            connector_id: FuzzCidrRange::bound_string(self.connector_id),
            host: FuzzCidrRange::bound_string(self.host),
            issued_at: FuzzCidrRange::bound_string(self.issued_at),
            reason: FuzzCidrRange::bound_string(self.reason),
            trace_id: FuzzCidrRange::bound_string(self.trace_id),
        }
    }
}

impl FuzzAllowlistEntry {
    fn to_real(self) -> AllowlistEntry {
        AllowlistEntry {
            host: FuzzCidrRange::bound_string(self.host),
            port: self.port,
            reason: FuzzCidrRange::bound_string(self.reason),
            receipt: self.receipt.to_real(),
        }
    }
}

impl FuzzSsrfPolicyTemplate {
    fn to_real(self) -> SsrfPolicyTemplate {
        let bounded_cidrs: Vec<CidrRange> = self.blocked_cidrs
            .into_iter()
            .take(MAX_CIDR_RANGES)
            .map(|c| c.to_real())
            .collect();

        let bounded_allowlist: Vec<AllowlistEntry> = self.allowlist
            .into_iter()
            .take(MAX_ALLOWLIST_ENTRIES)
            .map(|a| a.to_real())
            .collect();

        SsrfPolicyTemplate::new(
            &FuzzCidrRange::bound_string(self.connector_id),
            bounded_cidrs,
            bounded_allowlist
        )
    }
}

impl FuzzIpAddress {
    fn to_string(self) -> String {
        match self {
            Self::StandardIpv4 { a, b, c, d } => format!("{}.{}.{}.{}", a, b, c, d),
            Self::HexIpv4 { a, b, c, d } => format!("0x{:02x}.0x{:02x}.0x{:02x}.0x{:02x}", a, b, c, d),
            Self::OctalIpv4 { a, b, c, d } => format!("0{:o}.0{:o}.0{:o}.0{:o}", a, b, c, d),
            Self::CompressedIpv4 { parts } => {
                match parts.len() {
                    1 => format!("{}", parts.get(0).unwrap_or(&0)),
                    2 => format!("{}.{}", parts.get(0).unwrap_or(&0), parts.get(1).unwrap_or(&0)),
                    3 => format!("{}.{}.{}", parts.get(0).unwrap_or(&0), parts.get(1).unwrap_or(&0), parts.get(2).unwrap_or(&0)),
                    _ => format!("{}.{}.{}.{}",
                               parts.get(0).unwrap_or(&0),
                               parts.get(1).unwrap_or(&0),
                               parts.get(2).unwrap_or(&0),
                               parts.get(3).unwrap_or(&0)),
                }
            },
            Self::Ipv6 { address } => FuzzCidrRange::bound_string(address),
            Self::MaliciousHostname { hostname } => FuzzCidrRange::bound_string(hostname),
            Self::RawString { data } => FuzzCidrRange::bound_string(data),
        }
    }

    fn to_bytes(self) -> Option<[u8; 4]> {
        match self {
            Self::StandardIpv4 { a, b, c, d } => Some([a, b, c, d]),
            Self::HexIpv4 { a, b, c, d } => Some([a, b, c, d]),
            Self::OctalIpv4 { a, b, c, d } => Some([a, b, c, d]),
            Self::CompressedIpv4 { parts } => {
                if parts.is_empty() { return None; }
                let first = parts[0];
                if parts.len() == 1 {
                    Some([
                        (first >> 24) as u8,
                        (first >> 16) as u8,
                        (first >> 8) as u8,
                        first as u8,
                    ])
                } else {
                    None // Would need proper compressed IP logic
                }
            },
            _ => None, // Non-IPv4 addresses
        }
    }
}

fuzz_target!(|data: &[u8]| {
    let mut u = Unstructured::new(data);

    if let Ok(op) = FuzzOperation::arbitrary(&mut u) {
        match op {
            FuzzOperation::SsrfCheck { attack, port, protocol, trace_id, timestamp } => {
                let bounded_trace = FuzzCidrRange::bound_string(trace_id);
                let bounded_timestamp = FuzzCidrRange::bound_string(timestamp);

                let test_host = match attack {
                    SsrfAttackVector::NullByteInjection { base_host } => {
                        format!("{}\0evil.com", FuzzCidrRange::bound_string(base_host))
                    },
                    SsrfAttackVector::PathTraversal { base_host } => {
                        format!("{}/../../../etc/passwd", FuzzCidrRange::bound_string(base_host))
                    },
                    SsrfAttackVector::UnicodeAttack { base_host } => {
                        // Mix NFC and NFD Unicode normalization
                        format!("{}é", FuzzCidrRange::bound_string(base_host)) // NFC
                    },
                    SsrfAttackVector::TrailingDotAttack { host, dot_count } => {
                        let dots = ".".repeat((dot_count % 10) as usize);
                        format!("{}{}", FuzzCidrRange::bound_string(host), dots)
                    },
                    SsrfAttackVector::IpAddressConfusion { ip } => ip.to_string(),
                    SsrfAttackVector::AllowlistBypass { malicious_host, .. } => {
                        FuzzCidrRange::bound_string(malicious_host)
                    },
                    SsrfAttackVector::PrivateRangeBypass { ip } => ip.to_string(),
                    SsrfAttackVector::DnsRebinding { hostname, .. } => {
                        FuzzCidrRange::bound_string(hostname)
                    },
                    _ => "127.0.0.1".to_string(),
                };

                let mut policy = SsrfPolicyTemplate::new("test-connector", vec![], vec![]);

                // Test SSRF checking - should not panic on any input
                let _result = black_box(policy.check_ssrf(
                    &test_host,
                    port,
                    protocol,
                    &bounded_trace,
                    &bounded_timestamp
                ));
            },

            FuzzOperation::CidrRangeMatching { cidr, test_ips } => {
                let real_cidr = cidr.to_real();

                // Test CIDR range matching edge cases
                for ip in test_ips.into_iter().take(20) {
                    if let Some(ip_bytes) = ip.to_bytes() {
                        let _contains = black_box(real_cidr.contains(ip_bytes));

                        // Test consistency - same IP should always give same result
                        let contains1 = real_cidr.contains(ip_bytes);
                        let contains2 = real_cidr.contains(ip_bytes);
                        assert_eq!(contains1, contains2, "CIDR matching must be consistent");
                    }
                }

                // Test boundary conditions for prefix length
                if real_cidr.prefix_len <= 32 {
                    // Test edge IPs at network boundaries
                    let network = u32::from_be_bytes(real_cidr.network);
                    if real_cidr.prefix_len > 0 {
                        let mask = u32::MAX << (32_u8.saturating_sub(real_cidr.prefix_len));
                        let network_start = network & mask;
                        let network_end = network_start | !mask;

                        let _start_contains = black_box(real_cidr.contains(network_start.to_be_bytes()));
                        let _end_contains = black_box(real_cidr.contains(network_end.to_be_bytes()));
                    }
                }
            },

            FuzzOperation::SerializationRoundTrip { policy } => {
                let real_policy = policy.to_real();

                // Test serialization attacks on SSRF policy structures
                if let Ok(policy_json) = black_box(serde_json::to_string(&real_policy)) {
                    let _: Result<SsrfPolicyTemplate, _> = black_box(serde_json::from_str(&policy_json));
                }
            },

            FuzzOperation::AllowlistManipulation { mut policy, new_entries } => {
                let mut real_policy = policy.to_real();

                // Test allowlist manipulation and capacity limits
                for entry in new_entries.into_iter().take(20) {
                    let real_entry = entry.to_real();
                    real_policy.add_allowlist(real_entry);
                }

                // Test that allowlist operations don't cause crashes
                let _allowlist_size = real_policy.allowlist.len();
            },

            FuzzOperation::IpParsingEdgeCases { ip_variants } => {
                // Test various IP address parsing edge cases
                for ip in ip_variants.into_iter().take(50) {
                    let ip_string = ip.to_string();

                    // Test that IP parsing doesn't panic on malformed input
                    if let Ok(parsed_ip) = black_box(ip_string.parse::<std::net::IpAddr>()) {
                        // If it parsed successfully, test consistency
                        let parsed_again = ip_string.parse::<std::net::IpAddr>();
                        if let Ok(parsed_again) = parsed_again {
                            assert_eq!(parsed_ip, parsed_again, "IP parsing must be consistent");
                        }
                    }

                    // Test edge cases that should be rejected
                    if ip_string.contains("\0") ||
                       ip_string.contains("..") ||
                       ip_string.len() > MAX_STRING_LEN {
                        // These should be handled safely
                        let _parsed = black_box(ip_string.parse::<std::net::IpAddr>());
                    }
                }
            },
        }
    }
});