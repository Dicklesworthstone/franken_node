//! IPv6 destination classification shared by literal and resolved SSRF checks.
//!
//! This is an egress policy, not a routing-table probe. Ordinary allocated
//! global unicast is admitted; local, reserved, documentation and transition
//! destinations require an explicit literal-address exception. IPv4-mapped
//! sockets and the well-known NAT64 /96 must also pass the caller's IPv4 CIDRs.
//! Network-specific NAT64 prefixes cannot be inferred from an address alone.
//!
//! Allocation baseline: IANA IPv6 Address Space and IPv6 Special-Purpose Address
//! Registry, revisions 2025-10-23 and 2025-10-09 respectively:
//! https://www.iana.org/assignments/ipv6-address-space/
//! https://www.iana.org/assignments/iana-ipv6-special-registry/
//! The IETF-assignment /23 is deliberately conservative: specialized anycast,
//! overlay and transition uses are not silently granted general guest egress.

use std::net::{Ipv4Addr, Ipv6Addr};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Destination {
    PublicUnicast,
    EmbeddedIpv4(Ipv4Addr),
    Denied(&'static str),
}

/// Accept bare IPv6 or exactly one matching bracket pair. Never strip repeated
/// brackets or accept a zone/scope suffix: interfaces are ambient host state.
pub(crate) fn parse_literal(host: &str) -> Option<Ipv6Addr> {
    let address = if host.starts_with('[') || host.ends_with(']') {
        host.strip_prefix('[')?.strip_suffix(']')?
    } else {
        host
    };
    address.parse().ok()
}

/// Classify using numeric prefixes, never spelling, DNS or platform-dependent
/// `is_global` behavior. Callers must check EmbeddedIpv4 against their own
/// configured IPv4 restrictions, not automatically treat it as public IPv6.
pub(crate) fn classify(ip: Ipv6Addr) -> Destination {
    if ip.is_unspecified() {
        return Destination::Denied("::/128");
    }
    if ip.is_loopback() {
        return Destination::Denied("::1/128");
    }
    if let Some(v4) = ip.to_ipv4_mapped() {
        return Destination::EmbeddedIpv4(v4);
    }
    let s = ip.segments();
    // RFC 6052's well-known /96 has exactly 32 embedded IPv4 bits.
    if s[..6] == [0x64, 0xff9b, 0, 0, 0, 0] {
        let bytes = ip.octets();
        return Destination::EmbeddedIpv4(Ipv4Addr::new(
            bytes[12], bytes[13], bytes[14], bytes[15],
        ));
    }
    if s[0] & 0xfe00 == 0xfc00 {
        return Destination::Denied("fc00::/7");
    }
    if s[0] & 0xffc0 == 0xfe80 {
        return Destination::Denied("fe80::/10");
    }
    if s[0] & 0xffc0 == 0xfec0 {
        return Destination::Denied("fec0::/10");
    }
    if s[0] & 0xff00 == 0xff00 {
        return Destination::Denied("ff00::/8");
    }
    // Only 2000::/3 is currently allocated for ordinary global unicast.
    // This also rejects compatible IPv4 (::/96), local-use NAT64, discard,
    // dummy, SRv6 and unassigned address space instead of guessing reachability.
    if s[0] & 0xe000 != 0x2000 {
        return Destination::Denied("ipv6_reserved_or_special");
    }
    if s[0] == 0x2001 && s[1] & 0xfe00 == 0 {
        return Destination::Denied("2001::/23");
    }
    if s[0] == 0x2001 && s[1] == 0x0db8 {
        return Destination::Denied("2001:db8::/32");
    }
    // 6to4 embeds an IPv4 routing endpoint. Do not authorize this transition
    // mechanism as if it were an ordinary IPv6 origin.
    if s[0] == 0x2002 {
        return Destination::Denied("2002::/16");
    }
    if s[0] == 0x3ffe {
        return Destination::Denied("3ffe::/16");
    }
    if s[0] == 0x3fff && s[1] & 0xf000 == 0 {
        return Destination::Denied("3fff::/20");
    }
    Destination::PublicUnicast
}

#[cfg(test)]
mod tests {
    use super::*;

    fn classified(address: &str) -> Destination {
        classify(address.parse().expect("valid test address"))
    }

    #[test]
    fn ordinary_public_ipv6_is_not_confused_with_private_or_special_space() {
        for address in [
            "2001:4860:4860::8888", "2606:4700:4700::1111",
            "2620:fe::fe", "2a00:1450:4001::200e", "2400:cb00::1",
            "2000::", "2001:200::", "2001:db7:ffff:ffff:ffff:ffff:ffff:ffff",
            "2001:db9::", "2003::", "3ffd:ffff:ffff:ffff:ffff:ffff:ffff:ffff",
            "3fff:1000::", "3fff:ffff:ffff:ffff:ffff:ffff:ffff:ffff",
        ] {
            assert_eq!(classified(address), Destination::PublicUnicast, "{address}");
        }
    }

    #[test]
    fn local_special_documentation_and_transition_ranges_stay_denied() {
        for address in [
            "::", "::1", "::127.0.0.1", "::8.8.8.8",
            "64:ff9b:1::1", "64:ff9b:0:0:0:1::", "100::1", "100:0:0:1::1",
            "2001::", "2001:0:4136:e378:8000:63bf:3fff:fdd2",
            "2001:1::1", "2001:2::1", "2001:10::1", "2001:20::1",
            "2001:1ff:ffff:ffff:ffff:ffff:ffff:ffff", "2001:db8::",
            "2001:db8:ffff:ffff:ffff:ffff:ffff:ffff", "2002:7f00:1::1",
            "2002:808:808::1", "3ffe::1", "3fff::", "3fff:fff:ffff:ffff:ffff:ffff:ffff:ffff",
            "4000::1", "5f00::1", "fc00::", "fdff:ffff:ffff:ffff:ffff:ffff:ffff:ffff",
            "fe80::1", "febf:ffff:ffff:ffff:ffff:ffff:ffff:ffff",
            "fec0::1", "feff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", "ff02::1", "ffff::1",
        ] {
            assert!(matches!(classified(address), Destination::Denied(_)), "{address}");
        }
    }

    #[test]
    fn mapped_and_well_known_nat64_addresses_require_the_embedded_ipv4_policy() {
        for address in [
            Ipv4Addr::UNSPECIFIED, Ipv4Addr::LOCALHOST,
            Ipv4Addr::new(10, 0, 0, 1), Ipv4Addr::new(169, 254, 169, 254),
            Ipv4Addr::new(100, 100, 100, 100), Ipv4Addr::new(8, 8, 8, 8),
            Ipv4Addr::BROADCAST,
        ] {
            let [a, b, c, d] = address.octets();
            let nat64 = Ipv6Addr::new(0x64, 0xff9b, 0, 0, 0, 0,
                u16::from_be_bytes([a, b]), u16::from_be_bytes([c, d]));
            for ip in [address.to_ipv6_mapped(), nat64] {
                assert_eq!(classify(ip), Destination::EmbeddedIpv4(address));
            }
        }
        // A similar-looking translation prefix is not the well-known /96.
        assert!(matches!(classified("64:ff9b:1::808:808"), Destination::Denied(_)));
    }

    #[test]
    fn numeric_classification_is_independent_of_ipv6_spelling() {
        for (short, expanded) in [
            ("2001:4860::1", "2001:4860:0000:0000:0000:0000:0000:0001"),
            ("fd00::1", "FD00:0:0:0:0:0:0:1"),
            ("::ffff:127.0.0.1", "0:0:0:0:0:FFFF:7F00:0001"),
        ] {
            assert_eq!(classified(short), classified(expanded));
            assert_eq!(parse_literal(short), parse_literal(&format!("[{expanded}]")));
        }
    }

    #[test]
    fn literal_parser_never_repairs_malformed_brackets_scopes_or_hostnames() {
        for host in [
            "", "host.example", "127.0.0.1", "[127.0.0.1]", "[[::1]]", "[::1",
            "::1]", "[::1]:443", "[::1].", "::1%3", "[fe80::1%eth0]",
            " ::1", "::1 ", "[::1\0]", "[2001:4860::1]]",
        ] {
            assert!(parse_literal(host).is_none(), "{host:?}");
        }
        for host in ["::1", "[::1]", "[2001:4860::1]", "::ffff:127.0.0.1"] {
            assert!(parse_literal(host).is_some(), "{host}");
        }
    }

    #[test]
    fn every_leading_segment_obeys_the_allocated_global_unicast_envelope() {
        // Broad boundary/property check without nondeterministic sampling or a
        // new dependency. Reserved space must never become ordinary unicast.
        for first in 0..=u16::MAX {
            let ip = Ipv6Addr::new(first, 0x4860, 1, 2, 3, 4, 5, 6);
            if classify(ip) == Destination::PublicUnicast {
                assert_eq!(first & 0xe000, 0x2000, "{ip}");
                assert_ne!(first, 0x2002);
                assert_ne!(first, 0x3ffe);
            }
        }
    }
}
