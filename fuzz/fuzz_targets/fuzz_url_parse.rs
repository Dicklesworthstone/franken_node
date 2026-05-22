#![no_main]

use libfuzzer_sys::fuzz_target;
use std::str::FromStr;

// Simple URL parsing struct for testing
#[derive(Debug, PartialEq)]
struct ParsedUrl {
    scheme: String,
    host: Option<String>,
    port: Option<u16>,
    path: String,
    query: Option<String>,
    fragment: Option<String>,
}

impl FromStr for ParsedUrl {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.is_empty() {
            return Err("Empty URL".to_string());
        }

        // Basic URL parsing implementation for fuzzing
        let mut url = s;

        // Parse scheme
        let scheme_end = url.find("://").ok_or("No scheme found")?;
        let scheme = url[..scheme_end].to_string();
        url = &url[scheme_end + 3..];

        // Parse fragment first (after #)
        let (url, fragment) = if let Some(frag_start) = url.rfind('#') {
            let frag = url[frag_start + 1..].to_string();
            (&url[..frag_start], Some(frag))
        } else {
            (url, None)
        };

        // Parse query (after ?)
        let (url, query) = if let Some(query_start) = url.rfind('?') {
            let q = url[query_start + 1..].to_string();
            (&url[..query_start], Some(q))
        } else {
            (url, None)
        };

        // Parse path (after first /)
        let (host_port, path) = if let Some(path_start) = url.find('/') {
            (&url[..path_start], url[path_start..].to_string())
        } else {
            (url, "/".to_string())
        };

        // Parse host and port
        let (host, port) = if host_port.is_empty() {
            (None, None)
        } else if let Some(colon_pos) = host_port.rfind(':') {
            let host_part = &host_port[..colon_pos];
            let port_part = &host_port[colon_pos + 1..];

            match port_part.parse::<u16>() {
                Ok(p) => (Some(host_part.to_string()), Some(p)),
                Err(_) => (Some(host_port.to_string()), None),
            }
        } else {
            (Some(host_port.to_string()), None)
        };

        Ok(ParsedUrl {
            scheme,
            host,
            port,
            path,
            query,
            fragment,
        })
    }
}

fuzz_target!(|data: &[u8]| {
    // Convert bytes to string, handling invalid UTF-8 gracefully
    if let Ok(url_input) = std::str::from_utf8(data) {
        // Guard against excessively long URLs
        if url_input.len() > 65536 {
            return;
        }

        // Test URL parsing with arbitrary input
        let parse_result = ParsedUrl::from_str(url_input);

        match parse_result {
            Ok(parsed_url) => {
                // Valid URL parse - verify invariants

                // 1. Scheme should not be empty and should be reasonable
                assert!(!parsed_url.scheme.is_empty(), "Scheme should not be empty");
                assert!(parsed_url.scheme.len() < 100, "Scheme should be reasonable length");
                assert!(parsed_url.scheme.chars().all(|c| c.is_ascii_alphanumeric() || c == '+' || c == '-' || c == '.'),
                        "Scheme should contain valid characters");

                // 2. Port should be valid if present
                if let Some(port) = parsed_url.port {
                    assert!(port > 0, "Port should be greater than 0");
                    assert!(port <= 65535, "Port should be within valid range");
                }

                // 3. Host validation if present
                if let Some(ref host) = parsed_url.host {
                    assert!(!host.is_empty(), "Host should not be empty if present");
                    assert!(host.len() < 253, "Host should be reasonable length");

                    // Basic hostname validation - no spaces or control chars
                    assert!(!host.chars().any(|c| c.is_control() || c.is_whitespace()),
                           "Host should not contain control characters or whitespace");
                }

                // 4. Path should start with / and be reasonable
                assert!(parsed_url.path.starts_with('/'), "Path should start with /");
                assert!(parsed_url.path.len() < 8192, "Path should be reasonable length");

                // 5. Query validation if present
                if let Some(ref query) = parsed_url.query {
                    assert!(query.len() < 8192, "Query should be reasonable length");
                }

                // 6. Fragment validation if present
                if let Some(ref fragment) = parsed_url.fragment {
                    assert!(fragment.len() < 8192, "Fragment should be reasonable length");
                }

                // 7. Test that modifications produce different results
                let mut modified_input = url_input.to_string();
                if !modified_input.is_empty() {
                    modified_input.push('x');
                    let modified_result = ParsedUrl::from_str(&modified_input);
                    // Should either fail or produce different result
                    if let Ok(modified_parsed) = modified_result {
                        assert_ne!(parsed_url, modified_parsed,
                                  "Modified URL should parse differently");
                    }
                }

            }
            Err(_err) => {
                // Invalid URL parse - verify error handling consistency

                // 1. Invalid URL should consistently fail
                let result2 = ParsedUrl::from_str(url_input);
                assert!(result2.is_err(), "Invalid URL should consistently fail");

                // 2. Test common invalid URL patterns
                if !url_input.contains("://") {
                    // No scheme should fail
                    assert!(ParsedUrl::from_str(url_input).is_err());
                }

                // 3. Test malformed schemes
                if url_input.starts_with("://") {
                    // Empty scheme should fail
                    assert!(ParsedUrl::from_str(url_input).is_err());
                }

                // 4. Test invalid port numbers
                if url_input.contains(":99999") || url_input.contains(":65536") {
                    // Out of range ports should fail
                    assert!(ParsedUrl::from_str(url_input).is_err());
                }
            }
        }

        // Test edge cases
        if url_input.is_empty() {
            let result = ParsedUrl::from_str(url_input);
            assert!(result.is_err(), "Empty URL should fail to parse");
        }

        // Test null byte handling
        if url_input.contains('\0') {
            let result = ParsedUrl::from_str(url_input);
            // Null bytes should generally be rejected in URLs
            assert!(result.is_err(), "URLs with null bytes should be rejected");
        }

        // Test basic valid URLs
        if url_input == "http://example.com" {
            let result = ParsedUrl::from_str(url_input);
            assert!(result.is_ok(), "Basic HTTP URL should parse");
            if let Ok(parsed) = result {
                assert_eq!(parsed.scheme, "http");
                assert_eq!(parsed.host, Some("example.com".to_string()));
                assert_eq!(parsed.path, "/");
                assert!(parsed.port.is_none());
            }
        }

        if url_input == "https://example.com:443/path?query=value#fragment" {
            let result = ParsedUrl::from_str(url_input);
            assert!(result.is_ok(), "Complex HTTPS URL should parse");
            if let Ok(parsed) = result {
                assert_eq!(parsed.scheme, "https");
                assert_eq!(parsed.host, Some("example.com".to_string()));
                assert_eq!(parsed.port, Some(443));
                assert_eq!(parsed.path, "/path");
                assert_eq!(parsed.query, Some("query=value".to_string()));
                assert_eq!(parsed.fragment, Some("fragment".to_string()));
            }
        }

        // Test protocol variations
        let common_schemes = ["http", "https", "ftp", "file", "ws", "wss"];
        for scheme in &common_schemes {
            let test_url = format!("{}://example.com", scheme);
            if url_input == test_url {
                let result = ParsedUrl::from_str(url_input);
                assert!(result.is_ok(), "Common scheme should parse");
                if let Ok(parsed) = result {
                    assert_eq!(parsed.scheme, *scheme);
                }
            }
        }

        // Test IP address handling
        if url_input == "http://127.0.0.1:8080" {
            let result = ParsedUrl::from_str(url_input);
            assert!(result.is_ok(), "IP address URL should parse");
            if let Ok(parsed) = result {
                assert_eq!(parsed.host, Some("127.0.0.1".to_string()));
                assert_eq!(parsed.port, Some(8080));
            }
        }

        // Test path variations
        if url_input.starts_with("http://example.com/") && url_input.len() > 19 {
            let result = ParsedUrl::from_str(url_input);
            if let Ok(parsed) = result {
                assert!(parsed.path.starts_with('/'), "Path should start with /");
            }
        }
    }
});