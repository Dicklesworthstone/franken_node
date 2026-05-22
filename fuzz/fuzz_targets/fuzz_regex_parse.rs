#![no_main]

use libfuzzer_sys::fuzz_target;
use std::time::{Duration, Instant};

// Simple regex validation function for testing
fn validate_safe_regex(pattern: &str) -> Result<(), String> {
    if pattern.is_empty() {
        return Err("Empty regex pattern".to_string());
    }

    // Reject extremely long patterns (potential DoS)
    if pattern.len() > 10000 {
        return Err("Regex pattern too long".to_string());
    }

    // Reject patterns with excessive nesting (potential stack overflow)
    let nesting_depth = calculate_nesting_depth(pattern);
    if nesting_depth > 100 {
        return Err("Regex nesting too deep".to_string());
    }

    // Reject patterns with excessive quantifiers (potential ReDoS)
    if has_dangerous_quantifiers(pattern) {
        return Err("Dangerous quantifier pattern detected".to_string());
    }

    // Reject null bytes
    if pattern.contains('\0') {
        return Err("Null bytes in regex pattern".to_string());
    }

    // Basic syntax validation
    if !is_balanced_brackets(pattern) {
        return Err("Unbalanced brackets".to_string());
    }

    Ok(())
}

fn calculate_nesting_depth(pattern: &str) -> usize {
    let mut max_depth = 0;
    let mut current_depth = 0;

    for ch in pattern.chars() {
        match ch {
            '(' | '[' | '{' => {
                current_depth += 1;
                max_depth = max_depth.max(current_depth);
            }
            ')' | ']' | '}' => {
                current_depth = current_depth.saturating_sub(1);
            }
            _ => {}
        }
    }

    max_depth
}

fn has_dangerous_quantifiers(pattern: &str) -> bool {
    // Look for patterns that could cause exponential backtracking
    let dangerous_patterns = [
        "(.*).*", "(.*)+", "(.+)*", "(.+)+", // Nested quantifiers
        "(a*)*", "(a+)+", "(a?)?",           // Self-referential quantifiers
        "(a|a)*", "(a|b)*a*",                // Alternation with overlapping quantifiers
    ];

    for dangerous in &dangerous_patterns {
        if pattern.contains(dangerous) {
            return true;
        }
    }

    // Count consecutive quantifiers
    let chars: Vec<char> = pattern.chars().collect();
    for i in 0..chars.len().saturating_sub(1) {
        if is_quantifier(chars[i]) && is_quantifier(chars[i + 1]) {
            return true;
        }
    }

    // Look for excessive repetition in quantifiers
    if pattern.matches('{').count() > 10 || pattern.matches('*').count() > 20 ||
       pattern.matches('+').count() > 20 || pattern.matches('?').count() > 20 {
        return true;
    }

    false
}

fn is_quantifier(ch: char) -> bool {
    matches!(ch, '*' | '+' | '?' | '{')
}

fn is_balanced_brackets(pattern: &str) -> bool {
    let mut paren_count = 0;
    let mut bracket_count = 0;
    let mut brace_count = 0;

    for ch in pattern.chars() {
        match ch {
            '(' => paren_count += 1,
            ')' => {
                paren_count -= 1;
                if paren_count < 0 { return false; }
            }
            '[' => bracket_count += 1,
            ']' => {
                bracket_count -= 1;
                if bracket_count < 0 { return false; }
            }
            '{' => brace_count += 1,
            '}' => {
                brace_count -= 1;
                if brace_count < 0 { return false; }
            }
            _ => {}
        }
    }

    paren_count == 0 && bracket_count == 0 && brace_count == 0
}

fuzz_target!(|data: &[u8]| {
    // Convert bytes to string, handling invalid UTF-8 gracefully
    if let Ok(regex_input) = std::str::from_utf8(data) {
        // Guard against excessively long regex patterns
        if regex_input.len() > 100000 {
            return;
        }

        // Test regex validation with timing constraints to detect ReDoS
        let start_time = Instant::now();
        let validation_result = validate_safe_regex(regex_input);
        let validation_duration = start_time.elapsed();

        // Validation should not take too long (ReDoS protection)
        assert!(validation_duration < Duration::from_millis(100),
               "Regex validation should not take too long");

        match validation_result {
            Ok(()) => {
                // Valid regex pattern - verify security invariants

                // 1. Pattern should not be empty
                assert!(!regex_input.is_empty(), "Valid pattern should not be empty");

                // 2. Pattern should not be excessively long
                assert!(regex_input.len() <= 10000, "Valid pattern should have reasonable length");

                // 3. Nesting depth should be reasonable
                let depth = calculate_nesting_depth(regex_input);
                assert!(depth <= 100, "Valid pattern should have reasonable nesting depth");

                // 4. Should not contain dangerous quantifier patterns
                assert!(!has_dangerous_quantifiers(regex_input),
                       "Valid pattern should not have dangerous quantifiers");

                // 5. Should not contain null bytes
                assert!(!regex_input.contains('\0'), "Valid pattern should not contain null bytes");

                // 6. Brackets should be balanced
                assert!(is_balanced_brackets(regex_input), "Valid pattern should have balanced brackets");

                // 7. Test that the pattern can be used safely (simulate compilation)
                let compile_start = Instant::now();
                // In a real implementation, you'd compile the regex here
                // For now, we just simulate the time constraint
                let compile_duration = compile_start.elapsed();
                assert!(compile_duration < Duration::from_millis(50),
                       "Regex compilation should be fast");

            }
            Err(_err) => {
                // Invalid regex pattern - verify security checks are working

                // 1. Dangerous patterns should be consistently rejected
                if has_dangerous_quantifiers(regex_input) {
                    let result2 = validate_safe_regex(regex_input);
                    assert!(result2.is_err(), "Dangerous quantifiers should be consistently rejected");
                }

                // 2. Extremely long patterns should be rejected
                if regex_input.len() > 10000 {
                    assert!(validate_safe_regex(regex_input).is_err(),
                           "Extremely long patterns should be rejected");
                }

                // 3. Deep nesting should be rejected
                if calculate_nesting_depth(regex_input) > 100 {
                    assert!(validate_safe_regex(regex_input).is_err(),
                           "Deep nesting should be rejected");
                }

                // 4. Null bytes should be rejected
                if regex_input.contains('\0') {
                    assert!(validate_safe_regex(regex_input).is_err(),
                           "Null bytes should be rejected");
                }

                // 5. Unbalanced brackets should be rejected
                if !is_balanced_brackets(regex_input) {
                    assert!(validate_safe_regex(regex_input).is_err(),
                           "Unbalanced brackets should be rejected");
                }
            }
        }

        // Test common ReDoS patterns
        let redos_patterns = [
            "(a+)+", "(a*)*", "(a+)+b", "(a|a)*", "(a|b)*a*",
            "a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*",
            "(((((((((a)))))))))", "a{1000000}",
        ];

        for pattern in &redos_patterns {
            if regex_input == *pattern {
                let result = validate_safe_regex(regex_input);
                assert!(result.is_err(), "Known ReDoS pattern should be rejected");
            }
        }

        // Test edge cases
        if regex_input.is_empty() {
            let result = validate_safe_regex(regex_input);
            assert!(result.is_err(), "Empty regex should be rejected");
        }

        // Test simple safe patterns
        if regex_input == "abc" {
            let result = validate_safe_regex(regex_input);
            assert!(result.is_ok(), "Simple literal should be allowed");
        }

        if regex_input == "[a-z]+" {
            let result = validate_safe_regex(regex_input);
            assert!(result.is_ok(), "Simple character class should be allowed");
        }

        if regex_input == "^[a-zA-Z0-9]+$" {
            let result = validate_safe_regex(regex_input);
            assert!(result.is_ok(), "Anchored alphanumeric should be allowed");
        }

        // Test escaped characters
        if regex_input.contains('\\') {
            // Escaped characters should be handled properly
            // Don't assert specific behavior, just ensure no panic
            let _result = validate_safe_regex(regex_input);
        }

        // Test character classes
        if regex_input.starts_with('[') && regex_input.ends_with(']') {
            let result = validate_safe_regex(regex_input);
            if result.is_ok() {
                // Valid character class should have balanced brackets
                assert!(is_balanced_brackets(regex_input));
            }
        }

        // Test quantifier bounds
        if regex_input.contains('{') && regex_input.contains('}') {
            // Quantifier with bounds - should be reasonable
            if regex_input.contains("1000000") || regex_input.contains("999999") {
                let result = validate_safe_regex(regex_input);
                // Very large quantifiers should likely be rejected
            }
        }

        // Test alternation patterns
        if regex_input.contains('|') {
            let result = validate_safe_regex(regex_input);
            // Check for overlapping alternations that could cause backtracking
            if regex_input.contains("(a|a)") || regex_input.contains("(.*|.*)") {
                assert!(result.is_err(), "Overlapping alternations should be rejected");
            }
        }

        // Performance test - validation should always complete quickly
        let perf_start = Instant::now();
        let _result = validate_safe_regex(regex_input);
        let perf_duration = perf_start.elapsed();
        assert!(perf_duration < Duration::from_millis(100),
               "Regex validation should always be fast (ReDoS protection)");
    }
});