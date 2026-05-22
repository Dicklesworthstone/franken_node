#![no_main]

use libfuzzer_sys::fuzz_target;
use frankenengine_node::migration::{AuditOutputFormat, ValidateOutputFormat};

fuzz_target!(|data: &[u8]| {
    // Convert bytes to string, handling invalid UTF-8 gracefully
    if let Ok(input) = std::str::from_utf8(data) {
        // Guard against excessively long strings
        if input.len() > 1000 {
            return;
        }

        // Test AuditOutputFormat parsing
        let audit_result = AuditOutputFormat::parse(input);
        match audit_result {
            Ok(format) => {
                // Valid parse - check invariants
                match format {
                    AuditOutputFormat::Json => {
                        // Should be able to re-parse the canonical forms
                        assert!(AuditOutputFormat::parse("json").is_ok());
                        assert!(AuditOutputFormat::parse("JSON").is_ok());
                    }
                    AuditOutputFormat::Text => {
                        assert!(AuditOutputFormat::parse("text").is_ok());
                        assert!(AuditOutputFormat::parse("TEXT").is_ok());
                    }
                    AuditOutputFormat::Sarif => {
                        assert!(AuditOutputFormat::parse("sarif").is_ok());
                        assert!(AuditOutputFormat::parse("SARIF").is_ok());
                    }
                }
            }
            Err(err_msg) => {
                // Error case - check error message format
                assert!(err_msg.contains("unsupported migrate audit format"));
                assert!(err_msg.contains("expected one of: json, text, sarif"));
            }
        }

        // Test ValidateOutputFormat parsing
        let validate_result = ValidateOutputFormat::parse(input);
        match validate_result {
            Ok(format) => {
                // Valid parse - check invariants
                match format {
                    ValidateOutputFormat::Json => {
                        assert!(ValidateOutputFormat::parse("json").is_ok());
                        assert!(ValidateOutputFormat::parse("JSON").is_ok());
                    }
                    ValidateOutputFormat::Text => {
                        assert!(ValidateOutputFormat::parse("text").is_ok());
                        assert!(ValidateOutputFormat::parse("TEXT").is_ok());
                    }
                }
            }
            Err(err_msg) => {
                // Error case - check error message format
                assert!(err_msg.contains("unsupported migrate validate format"));
                assert!(err_msg.contains("expected one of: json, text"));
            }
        }

        // Test case-insensitive parsing consistency
        let lowercase = input.to_ascii_lowercase();
        let uppercase = input.to_ascii_uppercase();

        let audit_lower = AuditOutputFormat::parse(&lowercase);
        let audit_upper = AuditOutputFormat::parse(&uppercase);

        // Both should succeed or both should fail
        match (audit_lower, audit_upper) {
            (Ok(lower_fmt), Ok(upper_fmt)) => {
                assert_eq!(lower_fmt, upper_fmt, "Case insensitive parsing must be consistent");
            }
            (Err(_), Err(_)) => {
                // Both failed - this is expected for invalid inputs
            }
            _ => panic!("Case insensitive parsing inconsistency"),
        }
    }
});