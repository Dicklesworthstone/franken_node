#![no_main]

use libfuzzer_sys::fuzz_target;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

fuzz_target!(|data: &[u8]| {
    // Convert bytes to string, handling invalid UTF-8 gracefully
    if let Ok(ip_input) = std::str::from_utf8(data) {
        // Guard against excessively long IP strings
        if ip_input.len() > 256 {
            return;
        }

        // Test IPv4 parsing
        if let Ok(ipv4) = ip_input.parse::<Ipv4Addr>() {
            // Valid IPv4 - verify invariants
            let octets = ipv4.octets();

            // All octets should be valid (0-255)
            for &octet in &octets {
                assert!(octet <= 255, "IPv4 octets should be 0-255");
            }

            // Round-trip should be consistent
            let formatted = ipv4.to_string();
            let reparsed = formatted.parse::<Ipv4Addr>();
            assert!(reparsed.is_ok(), "IPv4 round-trip should succeed");
            assert_eq!(ipv4, reparsed.unwrap(), "IPv4 round-trip should preserve value");

            // Test special address classifications
            if ipv4.is_loopback() {
                assert!(octets[0] == 127, "Loopback should start with 127");
            }

            if ipv4.is_private() {
                // Should be in private ranges: 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16
                assert!(
                    octets[0] == 10 ||
                    (octets[0] == 172 && octets[1] >= 16 && octets[1] <= 31) ||
                    (octets[0] == 192 && octets[1] == 168),
                    "Private IP should be in correct ranges"
                );
            }

            if ipv4.is_multicast() {
                assert!(octets[0] >= 224 && octets[0] <= 239, "Multicast should be 224-239");
            }
        }

        // Test IPv6 parsing
        if let Ok(ipv6) = ip_input.parse::<Ipv6Addr>() {
            // Valid IPv6 - verify invariants
            let segments = ipv6.segments();

            // All segments should be valid (0-65535)
            for &segment in &segments {
                assert!(segment <= 65535, "IPv6 segments should be 0-65535");
            }

            // Round-trip should be consistent
            let formatted = ipv6.to_string();
            let reparsed = formatted.parse::<Ipv6Addr>();
            assert!(reparsed.is_ok(), "IPv6 round-trip should succeed");
            assert_eq!(ipv6, reparsed.unwrap(), "IPv6 round-trip should preserve value");

            // Test special address classifications
            if ipv6.is_loopback() {
                assert_eq!(ipv6, Ipv6Addr::LOCALHOST, "IPv6 loopback should be ::1");
            }

            if ipv6.is_unspecified() {
                assert_eq!(ipv6, Ipv6Addr::UNSPECIFIED, "IPv6 unspecified should be ::");
            }
        }

        // Test generic IP parsing
        if let Ok(ip) = ip_input.parse::<IpAddr>() {
            // Valid IP address - test common operations

            // Should be either IPv4 or IPv6
            match ip {
                IpAddr::V4(v4) => {
                    assert_eq!(v4, ip_input.parse::<Ipv4Addr>().unwrap());
                }
                IpAddr::V6(v6) => {
                    assert_eq!(v6, ip_input.parse::<Ipv6Addr>().unwrap());
                }
            }

            // Round-trip consistency
            let formatted = ip.to_string();
            let reparsed = formatted.parse::<IpAddr>();
            assert!(reparsed.is_ok(), "IP round-trip should succeed");
        }

        // Test edge cases and security boundaries

        // Null bytes should be rejected
        if ip_input.contains('\0') {
            assert!(ip_input.parse::<IpAddr>().is_err(), "Null bytes should be rejected");
        }

        // Control characters should be rejected
        if ip_input.chars().any(|c| c.is_control()) {
            assert!(ip_input.parse::<IpAddr>().is_err(), "Control chars should be rejected");
        }

        // Test IPv4 specific validations
        if ip_input.contains('.') {
            let parts: Vec<&str> = ip_input.split('.').collect();
            if parts.len() == 4 {
                // Could be valid IPv4 format
                for part in &parts {
                    if let Ok(num) = part.parse::<u32>() {
                        if num > 255 {
                            // Out of range octet should be rejected
                            assert!(ip_input.parse::<Ipv4Addr>().is_err());
                        }
                    }
                }
            }
        }

        // Test IPv6 specific validations
        if ip_input.contains(':') {
            // Potential IPv6
            let colon_count = ip_input.matches(':').count();

            // Too many colons should be rejected
            if colon_count > 8 {
                assert!(ip_input.parse::<Ipv6Addr>().is_err());
            }

            // Multiple :: should be rejected
            if ip_input.matches("::").count() > 1 {
                assert!(ip_input.parse::<Ipv6Addr>().is_err());
            }
        }

        // Test common valid IPs
        match ip_input {
            "127.0.0.1" => {
                let ip = ip_input.parse::<Ipv4Addr>().unwrap();
                assert!(ip.is_loopback());
            }
            "0.0.0.0" => {
                let ip = ip_input.parse::<Ipv4Addr>().unwrap();
                assert!(ip.is_unspecified());
            }
            "255.255.255.255" => {
                let ip = ip_input.parse::<Ipv4Addr>().unwrap();
                assert!(ip.is_broadcast());
            }
            "::1" => {
                let ip = ip_input.parse::<Ipv6Addr>().unwrap();
                assert!(ip.is_loopback());
            }
            "::" => {
                let ip = ip_input.parse::<Ipv6Addr>().unwrap();
                assert!(ip.is_unspecified());
            }
            _ => {}
        }

        // Test invalid formats
        if ip_input.contains("...") || ip_input.contains(":::") {
            assert!(ip_input.parse::<IpAddr>().is_err(), "Invalid punctuation should be rejected");
        }

        // Test leading zeros (some implementations may reject)
        if ip_input.contains("01.") || ip_input.contains("001.") {
            // Leading zeros behavior is implementation-specific
            let _result = ip_input.parse::<Ipv4Addr>();
            // Don't assert specific behavior, just ensure no panic
        }

        // Test extremely long octets
        if ip_input.split('.').any(|part| part.len() > 10) {
            assert!(ip_input.parse::<Ipv4Addr>().is_err(), "Extremely long octets should be rejected");
        }
    }
});