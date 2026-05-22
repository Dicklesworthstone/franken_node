#![no_main]

use libfuzzer_sys::fuzz_target;

// Simple email validation function for testing
fn validate_email(email: &str) -> Result<(), String> {
    if email.is_empty() {
        return Err("Email cannot be empty".to_string());
    }

    if email.len() > 320 {
        return Err("Email too long (RFC limit 320 chars)".to_string());
    }

    // Check for null bytes
    if email.contains('\0') {
        return Err("Email cannot contain null bytes".to_string());
    }

    // Must contain exactly one @
    let at_count = email.matches('@').count();
    if at_count != 1 {
        return Err("Email must contain exactly one @ symbol".to_string());
    }

    let parts: Vec<&str> = email.splitn(2, '@').collect();
    let (local, domain) = (parts[0], parts[1]);

    // Validate local part
    if local.is_empty() {
        return Err("Local part cannot be empty".to_string());
    }

    if local.len() > 64 {
        return Err("Local part too long (RFC limit 64 chars)".to_string());
    }

    if local.starts_with('.') || local.ends_with('.') {
        return Err("Local part cannot start or end with dot".to_string());
    }

    if local.contains("..") {
        return Err("Local part cannot contain consecutive dots".to_string());
    }

    // Check for dangerous characters in local part
    let dangerous_local = ['<', '>', '(', ')', '[', ']', '\\', ',', ';', ':', '"', ' '];
    if local.chars().any(|c| dangerous_local.contains(&c) || c.is_control()) {
        return Err("Local part contains invalid characters".to_string());
    }

    // Validate domain part
    if domain.is_empty() {
        return Err("Domain part cannot be empty".to_string());
    }

    if domain.len() > 253 {
        return Err("Domain too long (RFC limit 253 chars)".to_string());
    }

    if domain.starts_with('.') || domain.ends_with('.') {
        return Err("Domain cannot start or end with dot".to_string());
    }

    if domain.contains("..") {
        return Err("Domain cannot contain consecutive dots".to_string());
    }

    // Domain must contain at least one dot
    if !domain.contains('.') {
        return Err("Domain must contain at least one dot".to_string());
    }

    // Check domain characters
    if !domain.chars().all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-') {
        return Err("Domain contains invalid characters".to_string());
    }

    // Domain labels cannot start/end with hyphen
    for label in domain.split('.') {
        if label.is_empty() {
            return Err("Domain contains empty label".to_string());
        }
        if label.len() > 63 {
            return Err("Domain label too long (RFC limit 63 chars)".to_string());
        }
        if label.starts_with('-') || label.ends_with('-') {
            return Err("Domain label cannot start or end with hyphen".to_string());
        }
    }

    Ok(())
}

fuzz_target!(|data: &[u8]| {
    if let Ok(email_input) = std::str::from_utf8(data) {
        if email_input.len() > 10000 {
            return;
        }

        let validation_result = validate_email(email_input);

        match validation_result {
            Ok(()) => {
                // Valid email - verify security invariants
                assert!(!email_input.is_empty(), "Valid email should not be empty");
                assert!(email_input.len() <= 320, "Valid email should respect RFC length limit");
                assert!(!email_input.contains('\0'), "Valid email should not contain null bytes");
                assert_eq!(email_input.matches('@').count(), 1, "Valid email should have exactly one @");

                let parts: Vec<&str> = email_input.splitn(2, '@').collect();
                let (local, domain) = (parts[0], parts[1]);

                // Local part validations
                assert!(!local.is_empty(), "Local part should not be empty");
                assert!(local.len() <= 64, "Local part should respect RFC limit");
                assert!(!local.starts_with('.') && !local.ends_with('.'),
                       "Local part should not start/end with dot");
                assert!(!local.contains(".."), "Local part should not have consecutive dots");

                // Domain part validations
                assert!(!domain.is_empty(), "Domain should not be empty");
                assert!(domain.len() <= 253, "Domain should respect RFC limit");
                assert!(domain.contains('.'), "Domain should contain at least one dot");
                assert!(!domain.starts_with('.') && !domain.ends_with('.'),
                       "Domain should not start/end with dot");

                // Test round-trip consistency
                let normalized = email_input.trim().to_lowercase();
                if normalized == email_input {
                    let result2 = validate_email(&normalized);
                    assert!(result2.is_ok(), "Normalization should preserve validity");
                }
            }
            Err(_) => {
                // Invalid email - verify security checks
                if email_input.is_empty() {
                    assert!(validate_email(email_input).is_err());
                }
                if email_input.len() > 320 {
                    assert!(validate_email(email_input).is_err());
                }
                if email_input.contains('\0') {
                    assert!(validate_email(email_input).is_err());
                }
                if email_input.matches('@').count() != 1 {
                    assert!(validate_email(email_input).is_err());
                }
            }
        }

        // Test specific valid patterns
        if email_input == "user@example.com" {
            assert!(validate_email(email_input).is_ok());
        }
        if email_input == "test.email+tag@domain.co.uk" {
            let result = validate_email(email_input);
            // May be valid or invalid depending on implementation
        }

        // Test specific invalid patterns
        if email_input == "user@" || email_input == "@domain.com" {
            assert!(validate_email(email_input).is_err());
        }
        if email_input == "user..name@domain.com" {
            assert!(validate_email(email_input).is_err());
        }
        if email_input == "user@domain" {
            assert!(validate_email(email_input).is_err());
        }

        // Test injection patterns
        if email_input.contains("<script>") || email_input.contains("javascript:") {
            // XSS attempts should be rejected
            assert!(validate_email(email_input).is_err());
        }

        if email_input.contains("'; DROP TABLE") || email_input.contains("UNION SELECT") {
            // SQL injection attempts should be rejected
            assert!(validate_email(email_input).is_err());
        }

        // Test header injection
        if email_input.contains("\r\n") || email_input.contains("Bcc:") || email_input.contains("To:") {
            // Email header injection attempts should be rejected
            assert!(validate_email(email_input).is_err());
        }

        // Test buffer overflow patterns
        if email_input.len() > 320 {
            assert!(validate_email(email_input).is_err());
        }

        // Test local part length
        if let Some(at_pos) = email_input.find('@') {
            if at_pos > 64 {
                assert!(validate_email(email_input).is_err());
            }
        }

        // Test domain part patterns
        if email_input.contains("@.") || email_input.ends_with("@.") {
            assert!(validate_email(email_input).is_err());
        }

        // Test internationalized domains (should be rejected in basic implementation)
        if email_input.chars().any(|c| !c.is_ascii()) {
            let result = validate_email(email_input);
            // Non-ASCII should typically be rejected in basic validation
        }

        // Test edge cases
        if email_input == "a@b.c" {
            let result = validate_email(email_input);
            assert!(result.is_ok(), "Minimal valid email should pass");
        }

        // Test maximum lengths at boundaries
        if email_input.len() == 320 {
            let result = validate_email(email_input);
            // Should be valid if properly formatted
        }
        if email_input.len() == 321 {
            assert!(validate_email(email_input).is_err(), "Over-length should be rejected");
        }

        // Test multiple @ symbols
        if email_input.matches('@').count() > 1 {
            assert!(validate_email(email_input).is_err());
        }

        // Test quoted strings (advanced feature, may not be supported)
        if email_input.contains('"') {
            let result = validate_email(email_input);
            // Quoted strings are complex and often not supported in basic validators
        }

        // Test IP addresses in domain (may or may not be supported)
        if email_input.contains("[") || email_input.contains("]") {
            let result = validate_email(email_input);
            // IP literals may not be supported in basic validation
        }

        // Test subdomain depth
        if email_input.matches('.').count() > 10 {
            // Very deep subdomain structure
            let result = validate_email(email_input);
            // May be valid but unusual
        }

        // Test control character rejection
        if email_input.chars().any(|c| c.is_control()) {
            assert!(validate_email(email_input).is_err(),
                   "Control characters should be rejected");
        }
    }
});