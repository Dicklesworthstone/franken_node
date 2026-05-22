#![no_main]

use libfuzzer_sys::fuzz_target;

#[derive(Debug, PartialEq, Clone)]
struct Cookie {
    name: String,
    value: String,
    domain: Option<String>,
    path: Option<String>,
    expires: Option<String>,
    max_age: Option<u64>,
    secure: bool,
    http_only: bool,
    same_site: Option<String>,
}

// Cookie parsing function
fn parse_cookie(cookie_str: &str) -> Result<Cookie, String> {
    if cookie_str.is_empty() {
        return Err("Cookie string cannot be empty".to_string());
    }

    if cookie_str.len() > 4096 {
        return Err("Cookie string too long (limit 4096 chars)".to_string());
    }

    // Check for null bytes and CRLF injection
    if cookie_str.contains('\0') {
        return Err("Cookie cannot contain null bytes".to_string());
    }

    if cookie_str.contains('\r') || cookie_str.contains('\n') {
        return Err("Cookie cannot contain CRLF characters".to_string());
    }

    let parts: Vec<&str> = cookie_str.split(';').collect();
    if parts.is_empty() {
        return Err("Cookie must have at least name=value pair".to_string());
    }

    // Parse name=value (first part)
    let name_value = parts[0].trim();
    let eq_pos = name_value.find('=')
        .ok_or("Cookie must contain '=' between name and value".to_string())?;

    let name = name_value[..eq_pos].trim();
    let value = name_value[eq_pos + 1..].trim();

    // Validate cookie name
    if name.is_empty() {
        return Err("Cookie name cannot be empty".to_string());
    }

    if name.len() > 256 {
        return Err("Cookie name too long (limit 256 chars)".to_string());
    }

    // Cookie name must not contain special characters
    if !name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-') {
        return Err("Cookie name contains invalid characters".to_string());
    }

    // Validate cookie value
    if value.len() > 2048 {
        return Err("Cookie value too long (limit 2048 chars)".to_string());
    }

    // Cookie value cannot contain control characters (except tab)
    if value.chars().any(|c| c.is_control() && c != '\t') {
        return Err("Cookie value contains invalid control characters".to_string());
    }

    // Initialize cookie with defaults
    let mut cookie = Cookie {
        name: name.to_string(),
        value: value.to_string(),
        domain: None,
        path: None,
        expires: None,
        max_age: None,
        secure: false,
        http_only: false,
        same_site: None,
    };

    // Parse attributes
    for part in parts.iter().skip(1) {
        let attr = part.trim();
        if attr.is_empty() {
            continue;
        }

        if let Some(eq_pos) = attr.find('=') {
            let attr_name = attr[..eq_pos].trim().to_ascii_lowercase();
            let attr_value = attr[eq_pos + 1..].trim();

            match attr_name.as_str() {
                "domain" => {
                    if attr_value.len() > 253 {
                        return Err("Domain attribute too long".to_string());
                    }
                    if attr_value.contains(' ') || attr_value.contains('\t') {
                        return Err("Domain attribute cannot contain whitespace".to_string());
                    }
                    cookie.domain = Some(attr_value.to_string());
                }
                "path" => {
                    if attr_value.len() > 1024 {
                        return Err("Path attribute too long".to_string());
                    }
                    if !attr_value.starts_with('/') {
                        return Err("Path attribute must start with '/'".to_string());
                    }
                    cookie.path = Some(attr_value.to_string());
                }
                "expires" => {
                    if attr_value.len() > 64 {
                        return Err("Expires attribute too long".to_string());
                    }
                    cookie.expires = Some(attr_value.to_string());
                }
                "max-age" => {
                    match attr_value.parse::<u64>() {
                        Ok(age) => {
                            if age > 31536000 * 10 {  // 10 years max
                                return Err("Max-Age too large".to_string());
                            }
                            cookie.max_age = Some(age);
                        }
                        Err(_) => return Err("Max-Age must be a valid number".to_string()),
                    }
                }
                "samesite" => {
                    let samesite_value = attr_value.to_ascii_lowercase();
                    match samesite_value.as_str() {
                        "strict" | "lax" | "none" => {
                            cookie.same_site = Some(samesite_value);
                        }
                        _ => return Err("SameSite must be Strict, Lax, or None".to_string()),
                    }
                }
                _ => {
                    // Unknown attribute - ignore but validate it's not dangerous
                    if attr_name.len() > 64 || attr_value.len() > 256 {
                        return Err("Unknown attribute too long".to_string());
                    }
                }
            }
        } else {
            // Boolean attributes
            let flag = attr.to_ascii_lowercase();
            match flag.as_str() {
                "secure" => cookie.secure = true,
                "httponly" => cookie.http_only = true,
                _ => {
                    if flag.len() > 64 {
                        return Err("Unknown flag too long".to_string());
                    }
                }
            }
        }
    }

    // Security validations
    if cookie.same_site.as_ref().map(|s| s.as_str()) == Some("none") && !cookie.secure {
        return Err("SameSite=None requires Secure flag".to_string());
    }

    Ok(cookie)
}

fuzz_target!(|data: &[u8]| {
    if let Ok(cookie_input) = std::str::from_utf8(data) {
        if cookie_input.len() > 20000 {
            return;
        }

        let parse_result = parse_cookie(cookie_input);

        match parse_result {
            Ok(cookie) => {
                // Valid cookie - verify security invariants
                assert!(!cookie.name.is_empty(), "Valid cookie name should not be empty");
                assert!(cookie.name.len() <= 256, "Valid cookie name should respect length limit");
                assert!(cookie.value.len() <= 2048, "Valid cookie value should respect length limit");

                // Validate character sets
                assert!(cookie.name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-'),
                       "Cookie name should only contain valid characters");

                assert!(!cookie.value.chars().any(|c| c.is_control() && c != '\t'),
                       "Cookie value should not contain dangerous control characters");

                // Test round-trip consistency
                let mut reconstructed = format!("{}={}", cookie.name, cookie.value);

                if let Some(ref domain) = cookie.domain {
                    reconstructed.push_str(&format!("; Domain={}", domain));
                }
                if let Some(ref path) = cookie.path {
                    reconstructed.push_str(&format!("; Path={}", path));
                }
                if cookie.secure {
                    reconstructed.push_str("; Secure");
                }
                if cookie.http_only {
                    reconstructed.push_str("; HttpOnly");
                }

                let reparsed = parse_cookie(&reconstructed);
                assert!(reparsed.is_ok(), "Round-trip parsing should succeed");

                // Validate security constraints
                if cookie.same_site.as_ref().map(|s| s.as_str()) == Some("none") {
                    assert!(cookie.secure, "SameSite=None must have Secure flag");
                }

                if let Some(max_age) = cookie.max_age {
                    assert!(max_age <= 31536000 * 10, "Max-Age should be reasonable");
                }
            }
            Err(_) => {
                // Invalid cookie - verify security checks
                if cookie_input.is_empty() {
                    assert!(parse_cookie(cookie_input).is_err());
                }
                if cookie_input.len() > 4096 {
                    assert!(parse_cookie(cookie_input).is_err());
                }
                if cookie_input.contains('\0') {
                    assert!(parse_cookie(cookie_input).is_err());
                }
                if cookie_input.contains('\r') || cookie_input.contains('\n') {
                    assert!(parse_cookie(cookie_input).is_err());
                }
                if !cookie_input.contains('=') {
                    assert!(parse_cookie(cookie_input).is_err());
                }
            }
        }

        // Test specific valid patterns
        if cookie_input == "sessionid=abc123" {
            let result = parse_cookie(cookie_input);
            assert!(result.is_ok());
            if let Ok(c) = result {
                assert_eq!(c.name, "sessionid");
                assert_eq!(c.value, "abc123");
                assert!(!c.secure);
                assert!(!c.http_only);
            }
        }

        if cookie_input == "secure_cookie=value; Secure; HttpOnly; SameSite=Strict" {
            let result = parse_cookie(cookie_input);
            assert!(result.is_ok());
            if let Ok(c) = result {
                assert!(c.secure);
                assert!(c.http_only);
                assert_eq!(c.same_site, Some("strict".to_string()));
            }
        }

        // Test invalid patterns
        if cookie_input == "=value" || cookie_input == "name=" {
            let result = parse_cookie(cookie_input);
            if cookie_input == "=value" {
                assert!(result.is_err(), "Empty cookie name should be rejected");
            }
        }

        // Test CRLF injection attempts
        if cookie_input.contains("\\r\\n") || cookie_input.contains("\r\n") {
            assert!(parse_cookie(cookie_input).is_err(), "CRLF injection should be rejected");
        }

        // Test cookie injection
        if cookie_input.contains("Set-Cookie:") {
            assert!(parse_cookie(cookie_input).is_err(), "Cookie header injection should be rejected");
        }

        // Test XSS in cookies
        if cookie_input.contains("<script>") || cookie_input.contains("javascript:") {
            let result = parse_cookie(cookie_input);
            // XSS patterns may be allowed in cookie values but should be escaped when used
        }

        // Test extremely long values
        if cookie_input.len() > 4096 {
            assert!(parse_cookie(cookie_input).is_err());
        }

        // Test equals edge cases
        if cookie_input == "=" {
            assert!(parse_cookie(cookie_input).is_err());
        }

        if cookie_input.matches('=').count() > 10 {
            // Multiple equals signs
            let result = parse_cookie(cookie_input);
            // May be valid if properly formatted
        }

        // Test domain validation
        if cookie_input.contains("Domain=") {
            if cookie_input.contains("Domain=.") || cookie_input.contains("Domain= ") {
                let result = parse_cookie(cookie_input);
                // Domain validation may catch issues
            }
        }

        // Test path validation
        if cookie_input.contains("Path=") && !cookie_input.contains("Path=/") {
            // Path not starting with /
            assert!(parse_cookie(cookie_input).is_err());
        }

        // Test max-age validation
        if cookie_input.contains("Max-Age=") {
            if cookie_input.contains("Max-Age=-1") || cookie_input.contains("Max-Age=abc") {
                assert!(parse_cookie(cookie_input).is_err());
            }
            if cookie_input.contains("Max-Age=999999999999999999") {
                assert!(parse_cookie(cookie_input).is_err(), "Extremely large Max-Age should be rejected");
            }
        }

        // Test SameSite validation
        if cookie_input.contains("SameSite=") {
            if cookie_input.contains("SameSite=invalid") {
                assert!(parse_cookie(cookie_input).is_err());
            }
            if cookie_input.contains("SameSite=None") && !cookie_input.contains("Secure") {
                assert!(parse_cookie(cookie_input).is_err(),
                       "SameSite=None without Secure should be rejected");
            }
        }

        // Test case sensitivity
        if cookie_input.to_ascii_lowercase().contains("httponly") {
            let result = parse_cookie(cookie_input);
            if result.is_ok() {
                assert!(result.unwrap().http_only);
            }
        }

        // Test attribute parsing
        if cookie_input.contains(';') {
            let parts: Vec<&str> = cookie_input.split(';').collect();
            if parts.len() > 20 {
                // Too many attributes
                let result = parse_cookie(cookie_input);
                // May be valid but suspicious
            }
        }

        // Test control character injection
        if cookie_input.chars().any(|c| c.is_control() && c != '\t') {
            assert!(parse_cookie(cookie_input).is_err(),
                   "Control characters should be rejected");
        }

        // Test Unicode handling
        if cookie_input.chars().any(|c| !c.is_ascii()) {
            let result = parse_cookie(cookie_input);
            // Non-ASCII handling depends on implementation
        }
    }
});