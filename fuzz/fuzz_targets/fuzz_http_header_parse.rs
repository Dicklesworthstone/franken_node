#![no_main]

use libfuzzer_sys::fuzz_target;

#[derive(Debug, PartialEq, Clone)]
struct HttpHeader {
    name: String,
    value: String,
}

// HTTP header parsing function
fn parse_http_header(header_line: &str) -> Result<HttpHeader, String> {
    if header_line.is_empty() {
        return Err("Header line cannot be empty".to_string());
    }

    if header_line.len() > 8192 {
        return Err("Header line too long (limit 8192 chars)".to_string());
    }

    // Check for null bytes and dangerous control chars
    if header_line.contains('\0') {
        return Err("Header cannot contain null bytes".to_string());
    }

    // Check for CRLF injection
    if header_line.contains('\r') || header_line.contains('\n') {
        return Err("Header cannot contain CR or LF characters".to_string());
    }

    // Find the colon separator
    let colon_pos = header_line.find(':')
        .ok_or("Header must contain a colon separator".to_string())?;

    let name = &header_line[..colon_pos];
    let value = &header_line[colon_pos + 1..];

    // Validate header name
    if name.is_empty() {
        return Err("Header name cannot be empty".to_string());
    }

    if name.len() > 256 {
        return Err("Header name too long (limit 256 chars)".to_string());
    }

    // Header name must be valid token characters (RFC 7230)
    if !name.chars().all(|c| c.is_ascii_alphanumeric() || "!#$%&'*+-.^_`|~".contains(c)) {
        return Err("Header name contains invalid characters".to_string());
    }

    // Header name cannot start with whitespace or special chars
    if name.starts_with(' ') || name.starts_with('\t') {
        return Err("Header name cannot start with whitespace".to_string());
    }

    // Validate header value
    let trimmed_value = value.trim();

    if trimmed_value.len() > 4096 {
        return Err("Header value too long (limit 4096 chars)".to_string());
    }

    // Check for dangerous characters in value
    if trimmed_value.chars().any(|c| c.is_control() && c != '\t') {
        return Err("Header value contains invalid control characters".to_string());
    }

    // Check for injection patterns
    if trimmed_value.contains('\r') || trimmed_value.contains('\n') {
        return Err("Header value cannot contain CRLF".to_string());
    }

    Ok(HttpHeader {
        name: name.to_string(),
        value: trimmed_value.to_string(),
    })
}

fn validate_header_security(header: &HttpHeader) -> Result<(), String> {
    // Security validations for specific header types

    match header.name.to_ascii_lowercase().as_str() {
        "content-length" => {
            if let Err(_) = header.value.parse::<u64>() {
                return Err("Content-Length must be a valid number".to_string());
            }
        }
        "host" => {
            if header.value.is_empty() {
                return Err("Host header cannot be empty".to_string());
            }
            if header.value.contains(' ') {
                return Err("Host header cannot contain spaces".to_string());
            }
        }
        "content-type" => {
            if header.value.contains('\0') {
                return Err("Content-Type cannot contain null bytes".to_string());
            }
        }
        "authorization" => {
            if header.value.len() > 8192 {
                return Err("Authorization header too long".to_string());
            }
        }
        "cookie" => {
            if header.value.contains('\n') || header.value.contains('\r') {
                return Err("Cookie header cannot contain CRLF".to_string());
            }
        }
        "location" => {
            if header.value.contains('\n') || header.value.contains('\r') {
                return Err("Location header cannot contain CRLF".to_string());
            }
        }
        _ => {}
    }

    Ok(())
}

fuzz_target!(|data: &[u8]| {
    if let Ok(header_input) = std::str::from_utf8(data) {
        if header_input.len() > 50000 {
            return;
        }

        let parse_result = parse_http_header(header_input);

        match parse_result {
            Ok(header) => {
                // Valid header - verify security invariants
                assert!(!header.name.is_empty(), "Valid header name should not be empty");
                assert!(header.name.len() <= 256, "Valid header name should respect length limit");
                assert!(header.value.len() <= 4096, "Valid header value should respect length limit");

                // Validate character sets
                assert!(header.name.chars().all(|c| c.is_ascii_alphanumeric() || "!#$%&'*+-.^_`|~".contains(c)),
                       "Header name should only contain valid token characters");

                assert!(!header.value.contains('\r') && !header.value.contains('\n'),
                       "Header value should not contain CRLF");

                // Test round-trip consistency
                let reconstructed = format!("{}: {}", header.name, header.value);
                let reparsed = parse_http_header(&reconstructed);
                assert!(reparsed.is_ok(), "Round-trip parsing should succeed");

                if let Ok(reparsed_header) = reparsed {
                    assert_eq!(header.name, reparsed_header.name);
                    assert_eq!(header.value.trim(), reparsed_header.value);
                }

                // Test security validation
                let security_result = validate_header_security(&header);
                // Security validation may pass or fail depending on header content

                // Test case insensitive name handling
                let lowercase_name = header.name.to_ascii_lowercase();
                let uppercase_name = header.name.to_ascii_uppercase();
                // Names should be treated case-insensitively in HTTP
            }
            Err(_) => {
                // Invalid header - verify security checks
                if header_input.is_empty() {
                    assert!(parse_http_header(header_input).is_err());
                }
                if header_input.len() > 8192 {
                    assert!(parse_http_header(header_input).is_err());
                }
                if header_input.contains('\0') {
                    assert!(parse_http_header(header_input).is_err());
                }
                if header_input.contains('\r') || header_input.contains('\n') {
                    assert!(parse_http_header(header_input).is_err());
                }
                if !header_input.contains(':') {
                    assert!(parse_http_header(header_input).is_err());
                }
            }
        }

        // Test specific valid patterns
        if header_input == "Content-Type: text/html" {
            let result = parse_http_header(header_input);
            assert!(result.is_ok());
            if let Ok(h) = result {
                assert_eq!(h.name, "Content-Type");
                assert_eq!(h.value, "text/html");
            }
        }

        if header_input == "User-Agent: Mozilla/5.0" {
            let result = parse_http_header(header_input);
            assert!(result.is_ok());
        }

        // Test invalid patterns
        if header_input == ": value" || header_input == "name:" {
            let result = parse_http_header(header_input);
            if header_input == ": value" {
                assert!(result.is_err(), "Empty header name should be rejected");
            }
        }

        // Test CRLF injection attempts
        if header_input.contains("\\r\\n") || header_input.contains("\r\n") {
            assert!(parse_http_header(header_input).is_err(), "CRLF injection should be rejected");
        }

        // Test header injection
        if header_input.contains("Set-Cookie:") && header_input.contains("\nSet-Cookie:") {
            assert!(parse_http_header(header_input).is_err(), "Header injection should be rejected");
        }

        // Test XSS in headers
        if header_input.contains("<script>") || header_input.contains("javascript:") {
            let result = parse_http_header(header_input);
            // XSS patterns should be detectable but parsing may still succeed
        }

        // Test extremely long values
        if header_input.len() > 8192 {
            assert!(parse_http_header(header_input).is_err());
        }

        // Test colon edge cases
        if header_input == ":" {
            assert!(parse_http_header(header_input).is_err());
        }

        if header_input.matches(':').count() > 1 {
            // Multiple colons - first one should be the separator
            let result = parse_http_header(header_input);
            // May be valid if properly formatted
        }

        // Test whitespace handling
        if header_input == "Name : Value" {
            let result = parse_http_header(header_input);
            // Whitespace around colon handling
        }

        if header_input == "Name:  Value  " {
            let result = parse_http_header(header_input);
            if result.is_ok() {
                let h = result.unwrap();
                assert_eq!(h.value, "Value", "Value should be trimmed");
            }
        }

        // Test case sensitivity
        if header_input == "content-type: text/html" {
            let result = parse_http_header(header_input);
            assert!(result.is_ok());
        }

        // Test special header names
        let special_headers = ["Host", "Content-Length", "Authorization", "Cookie", "Location"];
        for &special in &special_headers {
            if header_input.starts_with(special) && header_input.contains(':') {
                let result = parse_http_header(header_input);
                if let Ok(h) = result {
                    let security_check = validate_header_security(&h);
                    // Security validation depends on header content
                }
            }
        }

        // Test control character injection
        if header_input.chars().any(|c| c.is_control() && c != '\t') {
            assert!(parse_http_header(header_input).is_err(),
                   "Control characters should be rejected");
        }

        // Test Unicode handling
        if header_input.chars().any(|c| !c.is_ascii()) {
            let result = parse_http_header(header_input);
            // Non-ASCII handling depends on implementation
        }

        // Test buffer boundaries
        if let Some(colon_pos) = header_input.find(':') {
            if colon_pos > 256 {
                // Header name too long
                assert!(parse_http_header(header_input).is_err());
            }
            if header_input.len() - colon_pos > 4096 {
                // Header value too long
                assert!(parse_http_header(header_input).is_err());
            }
        }
    }
});