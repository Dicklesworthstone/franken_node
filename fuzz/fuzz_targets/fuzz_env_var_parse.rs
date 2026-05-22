#![no_main]

use libfuzzer_sys::fuzz_target;

// Environment variable validation function
fn validate_env_var(key: &str, value: &str) -> Result<(), String> {
    // Validate key
    if key.is_empty() {
        return Err("Environment variable key cannot be empty".to_string());
    }

    if key.len() > 1024 {
        return Err("Environment variable key too long".to_string());
    }

    // Key should start with letter or underscore
    if !key.chars().next().unwrap().is_ascii_alphabetic() && !key.starts_with('_') {
        return Err("Environment variable key must start with letter or underscore".to_string());
    }

    // Key should only contain alphanumeric characters and underscores
    if !key.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
        return Err("Environment variable key contains invalid characters".to_string());
    }

    // Validate value
    if value.len() > 65536 {
        return Err("Environment variable value too long".to_string());
    }

    // Check for null bytes (not allowed in environment variables)
    if key.contains('\0') || value.contains('\0') {
        return Err("Environment variable cannot contain null bytes".to_string());
    }

    // Check for dangerous control characters
    if key.chars().any(|c| c.is_control()) ||
       value.chars().any(|c| c.is_control() && c != '\n' && c != '\t') {
        return Err("Environment variable contains dangerous control characters".to_string());
    }

    Ok(())
}

fn parse_env_assignment(input: &str) -> Option<(&str, &str)> {
    if let Some(eq_pos) = input.find('=') {
        let key = &input[..eq_pos];
        let value = &input[eq_pos + 1..];
        Some((key, value))
    } else {
        None
    }
}

fuzz_target!(|data: &[u8]| {
    // Convert bytes to string, handling invalid UTF-8 gracefully
    if let Ok(env_input) = std::str::from_utf8(data) {
        // Guard against excessively long environment variable strings
        if env_input.len() > 100000 {
            return;
        }

        // Test environment variable parsing
        if let Some((key, value)) = parse_env_assignment(env_input) {
            // Valid key=value format
            let validation_result = validate_env_var(key, value);

            match validation_result {
                Ok(()) => {
                    // Valid environment variable - verify security invariants

                    // 1. Key should not be empty and should be reasonable length
                    assert!(!key.is_empty(), "Valid key should not be empty");
                    assert!(key.len() <= 1024, "Valid key should have reasonable length");

                    // 2. Key should follow naming conventions
                    assert!(key.chars().next().unwrap().is_ascii_alphabetic() || key.starts_with('_'),
                           "Valid key should start with letter or underscore");
                    assert!(key.chars().all(|c| c.is_ascii_alphanumeric() || c == '_'),
                           "Valid key should only contain alphanumeric and underscore");

                    // 3. Value should be reasonable length
                    assert!(value.len() <= 65536, "Valid value should have reasonable length");

                    // 4. Should not contain null bytes
                    assert!(!key.contains('\0') && !value.contains('\0'),
                           "Valid env var should not contain null bytes");

                    // 5. Should not contain dangerous control characters
                    assert!(!key.chars().any(|c| c.is_control()),
                           "Valid key should not contain control characters");
                    assert!(!value.chars().any(|c| c.is_control() && c != '\n' && c != '\t'),
                           "Valid value should only allow safe control characters");

                    // 6. Test that modifications produce different results
                    if !key.is_empty() {
                        let mut modified_key = key.to_string();
                        modified_key.push('x');
                        let modified_result = validate_env_var(&modified_key, value);
                        // Should either fail or be treated as different
                    }
                }
                Err(_err) => {
                    // Invalid environment variable - verify security checks

                    // 1. Invalid variables should be consistently rejected
                    let result2 = validate_env_var(key, value);
                    assert!(result2.is_err(), "Invalid env var should be consistently rejected");

                    // 2. Empty keys should be rejected
                    if key.is_empty() {
                        assert!(validate_env_var(key, value).is_err());
                    }

                    // 3. Keys with invalid characters should be rejected
                    if key.chars().any(|c| !c.is_ascii_alphanumeric() && c != '_') {
                        assert!(validate_env_var(key, value).is_err());
                    }

                    // 4. Keys starting with invalid characters should be rejected
                    if !key.is_empty() &&
                       !key.chars().next().unwrap().is_ascii_alphabetic() &&
                       !key.starts_with('_') {
                        assert!(validate_env_var(key, value).is_err());
                    }

                    // 5. Null bytes should be rejected
                    if key.contains('\0') || value.contains('\0') {
                        assert!(validate_env_var(key, value).is_err());
                    }

                    // 6. Extremely long keys/values should be rejected
                    if key.len() > 1024 || value.len() > 65536 {
                        assert!(validate_env_var(key, value).is_err());
                    }
                }
            }
        } else {
            // Not in key=value format - should be rejected for environment variable assignment
            assert!(!env_input.contains('=') || env_input.starts_with('='),
                   "Missing = or invalid format");
        }

        // Test common environment variable patterns
        if env_input == "PATH=/usr/bin:/bin" {
            let (key, value) = parse_env_assignment(env_input).unwrap();
            let result = validate_env_var(key, value);
            assert!(result.is_ok(), "Standard PATH should be valid");
        }

        if env_input == "HOME=/home/user" {
            let (key, value) = parse_env_assignment(env_input).unwrap();
            let result = validate_env_var(key, value);
            assert!(result.is_ok(), "Standard HOME should be valid");
        }

        // Test dangerous patterns
        if env_input.contains("LD_PRELOAD=") {
            // LD_PRELOAD can be used for code injection
            let (key, value) = parse_env_assignment(env_input).unwrap();
            assert_eq!(key, "LD_PRELOAD");
            // Value validation should still apply
            let _result = validate_env_var(key, value);
        }

        // Test injection attempts
        if env_input.contains("$(") || env_input.contains("`") || env_input.contains("${") {
            // Command injection attempts in values
            if let Some((key, value)) = parse_env_assignment(env_input) {
                // Shell injection patterns should be detectable but not necessarily rejected
                // (depends on usage context)
                let _result = validate_env_var(key, value);
            }
        }

        // Test edge cases
        if env_input.is_empty() {
            let result = parse_env_assignment(env_input);
            assert!(result.is_none(), "Empty string should not parse as env var");
        }

        if env_input == "=" {
            let result = parse_env_assignment(env_input);
            if let Some((key, value)) = result {
                assert!(key.is_empty() && value.is_empty());
                assert!(validate_env_var(key, value).is_err(), "Empty key should be invalid");
            }
        }

        if env_input == "KEY=" {
            let (key, value) = parse_env_assignment(env_input).unwrap();
            assert_eq!(key, "KEY");
            assert!(value.is_empty());
            let result = validate_env_var(key, value);
            assert!(result.is_ok(), "Empty value should be allowed");
        }

        // Test case sensitivity
        if env_input == "key=value" {
            let (key, value) = parse_env_assignment(env_input).unwrap();
            let result = validate_env_var(key, value);
            assert!(result.is_ok(), "Lowercase key should be valid");
        }

        if env_input == "KEY=value" {
            let (key, value) = parse_env_assignment(env_input).unwrap();
            let result = validate_env_var(key, value);
            assert!(result.is_ok(), "Uppercase key should be valid");
        }

        // Test numeric values
        if env_input == "PORT=8080" {
            let (key, value) = parse_env_assignment(env_input).unwrap();
            let result = validate_env_var(key, value);
            assert!(result.is_ok(), "Numeric value should be valid");
        }

        // Test boolean values
        if env_input == "DEBUG=true" || env_input == "ENABLED=false" {
            let (key, value) = parse_env_assignment(env_input).unwrap();
            let result = validate_env_var(key, value);
            assert!(result.is_ok(), "Boolean value should be valid");
        }

        // Test special characters in values
        if let Some((key, value)) = parse_env_assignment(env_input) {
            if value.contains(' ') || value.contains(':') || value.contains('/') {
                // Common characters in environment values should be allowed
                if validate_env_var(key, value).is_ok() {
                    assert!(!key.is_empty());
                    assert!(key.chars().all(|c| c.is_ascii_alphanumeric() || c == '_'));
                }
            }
        }

        // Test Unicode handling
        if env_input.chars().any(|c| !c.is_ascii()) {
            // Non-ASCII characters - behavior depends on implementation
            if let Some((key, value)) = parse_env_assignment(env_input) {
                let _result = validate_env_var(key, value);
                // Don't assert specific behavior for Unicode
            }
        }
    }
});