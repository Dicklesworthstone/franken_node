#![no_main]

use libfuzzer_sys::fuzz_target;

// Command-line argument validation function
fn validate_cmdline_arg(arg: &str) -> Result<(), String> {
    if arg.len() > 32768 {
        return Err("Command-line argument too long".to_string());
    }

    // Check for null bytes
    if arg.contains('\0') {
        return Err("Command-line argument cannot contain null bytes".to_string());
    }

    // Check for dangerous shell characters
    let dangerous_chars = ['|', '&', ';', '`', '$', '(', ')', '<', '>', '"', '\''];
    if arg.chars().any(|c| dangerous_chars.contains(&c)) {
        return Err("Command-line argument contains shell metacharacters".to_string());
    }

    // Check for control characters (except tab and newline)
    if arg.chars().any(|c| c.is_control() && c != '\t' && c != '\n') {
        return Err("Command-line argument contains control characters".to_string());
    }

    Ok(())
}

fuzz_target!(|data: &[u8]| {
    if let Ok(arg_input) = std::str::from_utf8(data) {
        if arg_input.len() > 100000 {
            return;
        }

        let validation_result = validate_cmdline_arg(arg_input);

        match validation_result {
            Ok(()) => {
                // Valid argument - verify security invariants
                assert!(arg_input.len() <= 32768, "Valid arg should have reasonable length");
                assert!(!arg_input.contains('\0'), "Valid arg should not contain null bytes");

                let dangerous_chars = ['|', '&', ';', '`', '$', '(', ')', '<', '>', '"', '\''];
                assert!(!arg_input.chars().any(|c| dangerous_chars.contains(&c)),
                       "Valid arg should not contain shell metacharacters");

                assert!(!arg_input.chars().any(|c| c.is_control() && c != '\t' && c != '\n'),
                       "Valid arg should not contain dangerous control chars");
            }
            Err(_) => {
                // Invalid argument - verify security checks
                if arg_input.len() > 32768 {
                    assert!(validate_cmdline_arg(arg_input).is_err());
                }
                if arg_input.contains('\0') {
                    assert!(validate_cmdline_arg(arg_input).is_err());
                }
                let dangerous_chars = ['|', '&', ';', '`', '$', '(', ')', '<', '>', '"', '\''];
                if arg_input.chars().any(|c| dangerous_chars.contains(&c)) {
                    assert!(validate_cmdline_arg(arg_input).is_err());
                }
            }
        }

        // Test specific injection patterns
        if arg_input == "--help" {
            assert!(validate_cmdline_arg(arg_input).is_ok());
        }
        if arg_input.contains("; rm -rf /") {
            assert!(validate_cmdline_arg(arg_input).is_err());
        }
        if arg_input.contains("$(") {
            assert!(validate_cmdline_arg(arg_input).is_err());
        }
    }
});