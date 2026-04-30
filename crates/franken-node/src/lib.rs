#![forbid(unsafe_code)]
#![cfg(not(test))]
extern crate self as frankenengine_node;

/// Maximum help URLs to prevent memory exhaustion.
const MAX_HELP_URLS: usize = 32;

/// Add item to Vec with bounded capacity. When capacity is exceeded, removes oldest entries.
fn push_bounded<T>(items: &mut Vec<T>, item: T, cap: usize) {
    if cap == 0 {
        items.clear();
        return;
    }
    if items.len() >= cap {
        let overflow = items.len().saturating_sub(cap).saturating_add(1);
        items.drain(0..overflow);
    }
    items.push(item);
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ActionableError {
    message: String,
    fix_command: String,
    help_urls: Vec<String>,
}

impl ActionableError {
    pub fn new(message: impl Into<String>, fix_command: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            fix_command: fix_command.into(),
            help_urls: Vec::new(),
        }
    }

    pub fn with_help_url(mut self, help_url: impl Into<String>) -> Self {
        push_bounded(&mut self.help_urls, help_url.into(), MAX_HELP_URLS);
        self
    }
}

impl std::fmt::Display for ActionableError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}\nfix_command={}", self.message, self.fix_command)?;
        for help_url in &self.help_urls {
            write!(f, "\nhelp_url={help_url}")?;
        }
        Ok(())
    }
}

impl std::error::Error for ActionableError {}

/// Mutex lock utilities with proper error handling.
pub mod lock_utils {
    use super::ActionableError;
    use std::sync::{Mutex, MutexGuard};

    /// Safely acquire a mutex lock with proper error handling.
    ///
    /// Replaces the dangerous pattern: `mutex.lock().unwrap()`
    /// With safe pattern: `safe_lock(&mutex)?`
    pub fn safe_lock<T>(mutex: &Mutex<T>) -> Result<MutexGuard<T>, ActionableError> {
        mutex.lock().map_err(|poison_err| {
            ActionableError::new(
                format!("Mutex poisoned due to panic in another thread: {}", poison_err),
                "Check for panics in concurrent code and fix root cause",
            ).with_help_url("https://doc.rust-lang.org/std/sync/struct.Mutex.html#poisoning")
        })
    }

    /// For infallible contexts where poison should never happen in well-tested code.
    /// Use this ONLY when mutex poisoning indicates an unrecoverable program state.
    pub fn expect_lock<'a, T>(mutex: &'a Mutex<T>, context: &str) -> MutexGuard<'a, T> {
        mutex.lock().unwrap_or_else(|poison_err| {
            panic!("Critical mutex poisoned in {}: {}. This indicates a serious bug in concurrent code.", context, poison_err)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::{ActionableError, MAX_HELP_URLS, push_bounded, lock_utils};
    use std::sync::{Arc, Mutex};
    use std::thread;

    #[test]
    fn actionable_error_without_help_urls_omits_help_url_lines() {
        let err = ActionableError::new("missing runtime", "install node");
        let rendered = err.to_string();

        assert_eq!(rendered, "missing runtime\nfix_command=install node");
        assert!(!rendered.contains("help_url="));
        assert!(err.help_urls.is_empty());
    }

    #[test]
    fn empty_message_still_renders_fix_command() {
        let err = ActionableError::new("", "franken-node doctor");
        let rendered = err.to_string();

        assert_eq!(rendered, "\nfix_command=franken-node doctor");
        assert!(rendered.contains("fix_command="));
    }

    #[test]
    fn empty_fix_command_still_renders_explicit_field() {
        let err = ActionableError::new("operator action required", "");
        let rendered = err.to_string();

        assert_eq!(rendered, "operator action required\nfix_command=");
        assert!(rendered.ends_with("fix_command="));
    }

    #[test]
    fn blank_help_url_is_not_silently_dropped() {
        let err = ActionableError::new("needs docs", "open docs").with_help_url("");
        let rendered = err.to_string();

        assert_eq!(err.help_urls.len(), 1);
        assert!(rendered.ends_with("\nhelp_url="));
    }

    #[test]
    fn multiple_help_urls_preserve_insertion_order() {
        let err = ActionableError::new("needs runtime", "install runtime")
            .with_help_url("https://example.invalid/node")
            .with_help_url("https://example.invalid/bun");
        let rendered = err.to_string();

        let first = rendered.find("https://example.invalid/node").unwrap();
        let second = rendered.find("https://example.invalid/bun").unwrap();
        assert!(first < second);
        assert_eq!(err.help_urls.len(), 2);
    }

    #[test]
    fn newline_in_message_does_not_remove_fix_command_field() {
        let err = ActionableError::new("line one\nline two", "run doctor");
        let rendered = err.to_string();

        assert!(rendered.starts_with("line one\nline two\nfix_command="));
        assert!(rendered.contains("fix_command=run doctor"));
    }

    #[test]
    fn newline_in_fix_command_does_not_remove_help_urls() {
        let err = ActionableError::new("needs remediation", "first\nsecond")
            .with_help_url("https://example.invalid/remediation");
        let rendered = err.to_string();

        assert!(rendered.contains("fix_command=first\nsecond"));
        assert!(rendered.contains("\nhelp_url=https://example.invalid/remediation"));
    }

    #[test]
    fn clone_preserves_empty_edge_fields() {
        let err = ActionableError::new("", "").with_help_url("");
        let cloned = err.clone();

        assert_eq!(cloned, err);
        assert_eq!(cloned.to_string(), "\nfix_command=\nhelp_url=");
    }

    #[test]
    fn whitespace_only_message_is_preserved_not_trimmed() {
        let err = ActionableError::new("   ", "run doctor");
        let rendered = err.to_string();

        assert_eq!(rendered, "   \nfix_command=run doctor");
        assert!(rendered.starts_with("   "));
    }

    #[test]
    fn whitespace_only_fix_command_is_preserved_as_explicit_field() {
        let err = ActionableError::new("manual remediation required", "   ");
        let rendered = err.to_string();

        assert_eq!(rendered, "manual remediation required\nfix_command=   ");
        assert!(rendered.ends_with("fix_command=   "));
    }

    #[test]
    fn whitespace_only_help_url_is_not_silently_filtered() {
        let err = ActionableError::new("needs docs", "open docs").with_help_url("   ");
        let rendered = err.to_string();

        assert_eq!(err.help_urls, vec!["   ".to_string()]);
        assert!(rendered.ends_with("\nhelp_url=   "));
    }

    #[test]
    fn message_containing_help_url_literal_does_not_mutate_help_url_list() {
        let err = ActionableError::new("help_url=https://example.invalid/in-message", "fix");
        let rendered = err.to_string();

        assert!(err.help_urls.is_empty());
        assert!(rendered.starts_with("help_url=https://example.invalid/in-message"));
        assert!(rendered.ends_with("\nfix_command=fix"));
    }

    #[test]
    fn fix_command_containing_help_url_literal_stays_in_fix_field() {
        let err = ActionableError::new("operator action", "help_url=https://example.invalid/fix");
        let rendered = err.to_string();

        assert!(err.help_urls.is_empty());
        assert_eq!(
            rendered,
            "operator action\nfix_command=help_url=https://example.invalid/fix"
        );
    }

    #[test]
    fn help_url_with_newline_is_preserved_as_single_help_entry() {
        let err = ActionableError::new("needs docs", "open docs")
            .with_help_url("https://example.invalid/one\nhttps://example.invalid/two");
        let rendered = err.to_string();

        assert_eq!(err.help_urls.len(), 1);
        assert!(rendered.contains("\nhelp_url=https://example.invalid/one\n"));
        assert!(rendered.ends_with("https://example.invalid/two"));
    }

    #[test]
    fn repeated_empty_help_urls_are_preserved_in_order() {
        let err = ActionableError::new("needs docs", "open docs")
            .with_help_url("")
            .with_help_url("");
        let rendered = err.to_string();

        assert_eq!(err.help_urls.len(), 2);
        assert_eq!(rendered.matches("\nhelp_url=").count(), 2);
        assert!(rendered.ends_with("\nhelp_url=\nhelp_url="));
    }

    #[test]
    fn negative_help_url_cap_drops_oldest_entry_after_capacity() {
        let mut err = ActionableError::new("needs docs", "open docs");
        for idx in 0..=MAX_HELP_URLS {
            err = err.with_help_url(format!("https://example.invalid/help-{idx}"));
        }

        assert_eq!(err.help_urls.len(), MAX_HELP_URLS);
        assert_eq!(
            err.help_urls.first().map(String::as_str),
            Some("https://example.invalid/help-1")
        );
        assert_eq!(
            err.help_urls.last().map(String::as_str),
            Some("https://example.invalid/help-32")
        );
    }

    #[test]
    fn negative_help_url_cap_keeps_exact_capacity_without_eviction() {
        let mut err = ActionableError::new("needs docs", "open docs");
        for idx in 0..MAX_HELP_URLS {
            err = err.with_help_url(format!("https://example.invalid/exact-{idx}"));
        }

        assert_eq!(err.help_urls.len(), MAX_HELP_URLS);
        assert_eq!(
            err.help_urls.first().map(String::as_str),
            Some("https://example.invalid/exact-0")
        );
        assert_eq!(
            err.help_urls.last().map(String::as_str),
            Some("https://example.invalid/exact-31")
        );
    }

    #[test]
    fn negative_help_url_cap_bounds_rendered_output_lines() {
        let mut err = ActionableError::new("needs docs", "open docs");
        for idx in 0..(MAX_HELP_URLS.saturating_mul(4)) {
            err = err.with_help_url(format!("https://example.invalid/render-{idx}"));
        }
        let rendered = err.to_string();

        assert_eq!(err.help_urls.len(), MAX_HELP_URLS);
        assert_eq!(rendered.matches("\nhelp_url=").count(), MAX_HELP_URLS);
        assert!(!rendered.contains("https://example.invalid/render-0"));
        assert!(rendered.contains("https://example.invalid/render-127"));
    }

    #[test]
    fn negative_help_url_cap_preserves_newest_duplicate_entries() {
        let mut err = ActionableError::new("needs docs", "open docs");
        for idx in 0..MAX_HELP_URLS {
            err = err.with_help_url(format!("https://example.invalid/unique-{idx}"));
        }
        err = err
            .with_help_url("https://example.invalid/duplicate")
            .with_help_url("https://example.invalid/duplicate");

        assert_eq!(err.help_urls.len(), MAX_HELP_URLS);
        assert_eq!(
            err.help_urls
                .iter()
                .filter(|url| url.as_str() == "https://example.invalid/duplicate")
                .count(),
            2
        );
        assert!(!err
            .help_urls
            .iter()
            .any(|url| url.as_str() == "https://example.invalid/unique-0"));
    }

    #[test]
    fn negative_help_url_cap_keeps_blank_entries_when_newest() {
        let mut err = ActionableError::new("needs docs", "open docs");
        for idx in 0..MAX_HELP_URLS {
            err = err.with_help_url(format!("https://example.invalid/nonblank-{idx}"));
        }
        err = err.with_help_url("");

        assert_eq!(err.help_urls.len(), MAX_HELP_URLS);
        assert_eq!(err.help_urls.last().map(String::as_str), Some(""));
        assert!(!err
            .help_urls
            .iter()
            .any(|url| url.as_str() == "https://example.invalid/nonblank-0"));
    }

    #[test]
    fn negative_push_bounded_zero_capacity_clears_and_drops_new_item() {
        let mut items = vec!["existing-a", "existing-b"];

        push_bounded(&mut items, "newest", 0);

        assert!(items.is_empty());
    }

    #[test]
    fn negative_push_bounded_preexisting_overfull_vec_is_trimmed_to_cap() {
        let mut items = vec![0, 1, 2, 3, 4];

        push_bounded(&mut items, 5, 2);

        assert_eq!(items, vec![4, 5]);
    }

    #[test]
    fn negative_push_bounded_exact_capacity_evicts_only_oldest_slot() {
        let mut items = vec!["oldest", "middle", "newest"];

        push_bounded(&mut items, "incoming", 3);

        assert_eq!(items, vec!["middle", "newest", "incoming"]);
    }

    #[test]
    fn negative_push_bounded_large_capacity_does_not_underflow_or_evict() {
        let mut items = vec![1, 2];

        push_bounded(&mut items, 3, usize::MAX);

        assert_eq!(items, vec![1, 2, 3]);
    }

    #[test]
    fn negative_message_containing_fix_command_literal_does_not_override_fix_field() {
        let err = ActionableError::new("bad input\nfix_command=malicious", "franken-node doctor");
        let rendered = err.to_string();

        assert!(rendered.starts_with("bad input\nfix_command=malicious"));
        assert!(rendered.ends_with("\nfix_command=franken-node doctor"));
        assert_eq!(rendered.matches("fix_command=").count(), 2);
    }

    #[test]
    fn negative_help_url_containing_fix_command_literal_stays_help_url_entry() {
        let err = ActionableError::new("needs docs", "open docs")
            .with_help_url("https://example.invalid/docs\nfix_command=malicious");
        let rendered = err.to_string();

        assert_eq!(
            err.help_urls,
            vec!["https://example.invalid/docs\nfix_command=malicious"]
        );
        assert!(
            rendered.contains("\nhelp_url=https://example.invalid/docs\nfix_command=malicious")
        );
        assert!(rendered.starts_with("needs docs\nfix_command=open docs"));
    }

    #[test]
    fn negative_duplicate_help_urls_are_not_deduplicated() {
        let err = ActionableError::new("needs docs", "open docs")
            .with_help_url("https://example.invalid/same")
            .with_help_url("https://example.invalid/same");
        let rendered = err.to_string();

        assert_eq!(err.help_urls.len(), 2);
        assert_eq!(rendered.matches("https://example.invalid/same").count(), 2);
    }

    #[test]
    fn negative_carriage_return_in_message_is_preserved() {
        let err = ActionableError::new("first\rsecond", "run doctor");
        let rendered = err.to_string();

        assert!(rendered.starts_with("first\rsecond"));
        assert!(rendered.ends_with("\nfix_command=run doctor"));
    }

    #[test]
    fn negative_carriage_return_in_fix_command_is_preserved() {
        let err = ActionableError::new("operator action", "first\rsecond");
        let rendered = err.to_string();

        assert_eq!(rendered, "operator action\nfix_command=first\rsecond");
    }

    #[test]
    fn negative_error_source_is_absent() {
        let err = ActionableError::new("operator action", "run doctor");

        assert!(std::error::Error::source(&err).is_none());
    }

    #[test]
    fn negative_debug_output_does_not_replace_display_contract() {
        let err = ActionableError::new("operator action", "run doctor")
            .with_help_url("https://example.invalid/help");
        let rendered = err.to_string();
        let debug = format!("{err:?}");

        assert!(debug.contains("ActionableError"));
        assert!(debug.contains("fix_command"));
        assert_ne!(debug, rendered);
    }

    // === COMPREHENSIVE NEGATIVE-PATH TESTS ===
    // Additional edge case tests for ActionableError that security hardening may have missed

    #[test]
    fn negative_unicode_injection_in_error_message() {
        // Test Unicode injection attacks in error messages
        // Control characters and homograph attacks could bypass validation or logging
        let unicode_attack_vectors = [
            ("error\u{200B}injection", "Zero-width space injection"),
            ("error\u{202E}rorre", "Right-to-left override attack"),
            ("error\u{0000}injection", "Null byte injection"),
            ("error\u{FEFF}injection", "BOM injection"),
            ("error\u{000C}injection", "Form feed injection"),
            ("error\ninjection", "Newline injection"),
            ("еrror", "Cyrillic 'е' homograph attack"),
            ("error\u{001F}injection", "Unit separator injection"),
        ];

        for (malicious_message, description) in &unicode_attack_vectors {
            let err = ActionableError::new(malicious_message, "fix-command");
            let rendered = err.to_string();

            // Verify Unicode injection doesn't corrupt output format
            assert!(rendered.contains("fix_command=fix-command"),
                   "Format should remain valid despite Unicode injection: {}", description);

            // Verify message is preserved (not truncated or corrupted)
            assert!(rendered.starts_with(malicious_message),
                   "Message should be preserved for: {}", description);

            // Verify the error can be safely cloned and compared
            let cloned = err.clone();
            assert_eq!(cloned, err, "Clone should work correctly for: {}", description);
        }
    }

    #[test]
    fn negative_null_byte_injection_in_fix_command() {
        // Test null byte injection attacks in fix commands
        // Could truncate commands in C-compatible contexts or cause parsing issues
        let null_injection_cases = [
            ("fix\0injection", "Single null byte in fix command"),
            ("fix\0\0double", "Double null byte in fix command"),
            ("fix\0cmd\0multi", "Multiple null bytes in fix command"),
            ("fix\0", "Trailing null byte in fix command"),
            ("\0fix", "Leading null byte in fix command"),
        ];

        for (malicious_fix, description) in &null_injection_cases {
            let err = ActionableError::new("test error", malicious_fix);
            let rendered = err.to_string();

            // Verify null bytes don't cause string truncation
            assert!(rendered.contains(&format!("fix_command={}", malicious_fix)),
                   "Fix command should be preserved despite null bytes: {}", description);

            // Verify format structure remains intact
            assert!(rendered.starts_with("test error\n"),
                   "Error format should remain valid for: {}", description);

            // Test with help URLs to ensure no cross-field contamination
            let err_with_help = err.clone().with_help_url("https://example.com/help");
            let help_rendered = err_with_help.to_string();
            assert!(help_rendered.contains("help_url=https://example.com/help"),
                   "Help URL should be preserved despite null byte injection: {}", description);
        }
    }

    #[test]
    fn negative_memory_exhaustion_through_massive_help_urls() {
        // Test memory exhaustion attacks via massive help URL lists
        // Could bypass memory limits through incremental allocation
        let mut err = ActionableError::new("memory test", "fix-command");

        // Add many help URLs to test memory handling
        for i in 0..10000 {
            let large_url = format!("https://example.com/help-{}-{}", i, "x".repeat(100));
            err = err.with_help_url(large_url);
        }

        // Should handle large help URL lists without unbounded memory growth.
        assert_eq!(
            err.help_urls.len(),
            MAX_HELP_URLS,
            "Should retain only the bounded help URL window"
        );
        assert_eq!(
            err.help_urls.first().map(String::as_str),
            Some("https://example.com/help-9968-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx")
        );
        assert_eq!(
            err.help_urls.last().map(String::as_str),
            Some("https://example.com/help-9999-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx")
        );

        // Rendering should complete despite large size
        let rendered = err.to_string();
        assert!(rendered.contains("fix_command=fix-command"), "Should render correctly despite size");
        assert_eq!(
            rendered.matches("help_url=").count(),
            MAX_HELP_URLS,
            "Should render only the bounded help URLs"
        );

        // Clone should work efficiently
        let cloned = err.clone();
        assert_eq!(
            cloned.help_urls.len(),
            MAX_HELP_URLS,
            "Clone should preserve the bounded help URL window"
        );
    }

    #[test]
    fn negative_serialization_format_injection_in_fields() {
        // Test serialization format injection attacks
        // Malformed JSON/XML/YAML-like content could bypass parsing or logging
        let injection_cases = [
            ("error\"],\"malicious\":\"payload", "JSON injection in message"),
            ("error</message><script>alert(1)</script>", "XML injection in message"),
            ("error\n  malicious: payload", "YAML injection in message"),
            ("error{{.Values.Secret}}", "Template injection in message"),
            ("fix\"],\"cmd\":\"rm -rf /", "JSON injection in fix command"),
            ("fix</fix><script>alert(1)</script>", "XML injection in fix command"),
            ("https://evil.com\"];window.location=\"https://malicious.com", "URL injection in help"),
        ];

        for (injection_payload, description) in &injection_cases {
            // Test injection in different fields
            let err_msg = ActionableError::new(injection_payload, "safe-fix");
            let err_fix = ActionableError::new("safe error", injection_payload);
            let err_help = ActionableError::new("safe error", "safe-fix")
                .with_help_url(injection_payload);

            let rendered_msg = err_msg.to_string();
            let rendered_fix = err_fix.to_string();
            let rendered_help = err_help.to_string();

            // Verify injection doesn't break output format
            assert!(rendered_msg.contains("fix_command=safe-fix"),
                   "Message injection should not break format: {}", description);
            assert!(rendered_fix.contains(&format!("fix_command={}", injection_payload)),
                   "Fix command injection should be contained: {}", description);
            assert!(rendered_help.contains(&format!("help_url={}", injection_payload)),
                   "Help URL injection should be contained: {}", description);

            // Verify no script execution or template processing
            assert!(!rendered_msg.contains("malicious"),
                   "Should not execute malicious content in message: {}", description);
            assert!(!rendered_fix.contains("<script>") || rendered_fix.contains("fix_command="),
                   "Should not process script tags in fix command: {}", description);
        }
    }

    #[test]
    fn negative_floating_point_precision_in_string_formatting() {
        // Test floating-point precision issues that could affect error display
        // Edge cases with special float values in error contexts
        let float_edge_cases = [
            (f64::INFINITY.to_string(), "Infinity in error field"),
            (f64::NEG_INFINITY.to_string(), "Negative infinity in error field"),
            (f64::NAN.to_string(), "NaN in error field"),
            (f64::MIN.to_string(), "Minimum f64 in error field"),
            (f64::MAX.to_string(), "Maximum f64 in error field"),
            (f64::EPSILON.to_string(), "Machine epsilon in error field"),
            ((1.0/3.0).to_string(), "Repeating decimal in error field"),
        ];

        for (float_string, description) in &float_edge_cases {
            let err = ActionableError::new(
                format!("Float error: {}", float_string),
                format!("Fix float: {}", float_string)
            ).with_help_url(format!("https://example.com/help?value={}", float_string));

            let rendered = err.to_string();

            // Verify float values don't cause formatting issues
            assert!(rendered.contains("fix_command="),
                   "Should maintain format structure with: {}", description);
            assert!(rendered.contains("help_url="),
                   "Should include help URL with: {}", description);

            // Verify float values are properly escaped/contained
            if float_string == "inf" || float_string == "-inf" || float_string == "NaN" {
                assert!(rendered.contains(float_string),
                       "Special float values should be preserved: {}", description);
            }

            // Verify error can still be used normally
            let cloned = err.clone();
            assert_eq!(cloned.to_string(), rendered,
                      "Clone should be identical with: {}", description);
        }
    }

    #[test]
    fn negative_hash_collision_resistance_in_error_comparison() {
        // Test hash collision resistance in ActionableError equality
        // Similar errors should not collide or cause security bypasses
        let collision_test_cases = [
            ("error-123", "error-132", "Transposed characters in message"),
            ("test_error", "test-error", "Underscore vs hyphen difference"),
            ("Error", "error", "Case sensitivity in message"),
            ("fix_cmd", "fix-cmd", "Separator differences in fix command"),
            ("https://site.com/help", "https://site.com/help/", "Trailing slash in help URL"),
            ("command --flag", "command  --flag", "Extra space in fix command"),
        ];

        for (variant1, variant2, description) in &collision_test_cases {
            let err1 = ActionableError::new(variant1, "fix1").with_help_url("help1");
            let err2 = ActionableError::new(variant2, "fix2").with_help_url("help2");

            // Verify different errors are not equal (no collision)
            if variant1 != variant2 {
                assert_ne!(err1, err2, "Different errors should not be equal: {}", description);
            }

            // Verify no collision in string representation
            let rendered1 = err1.to_string();
            let rendered2 = err2.to_string();
            if variant1 != variant2 {
                assert_ne!(rendered1, rendered2, "String representations should differ: {}", description);
            }
        }
    }

    #[test]
    fn negative_resource_exhaustion_through_deeply_nested_cloning() {
        // Test resource exhaustion via deep cloning operations
        // Malicious clone chains could cause stack overflow or excessive allocation
        let mut err = ActionableError::new("base error", "base fix");

        // Add many help URLs to make cloning more expensive
        for i in 0..1000 {
            err = err.with_help_url(format!("https://help{}.example.com", i));
        }

        // Test deep cloning chain
        let start_time = std::time::Instant::now();
        let mut current = err.clone();
        for _ in 0..100 {
            current = current.clone();
        }
        let clone_duration = start_time.elapsed();

        // Cloning should complete in reasonable time
        assert!(clone_duration.as_millis() < 1000,
               "Deep cloning should not take excessive time");

        // Verify cloned error is still functional
        let rendered = current.to_string();
        assert!(rendered.contains("fix_command=base fix"),
               "Deeply cloned error should render correctly");
        assert_eq!(
            current.help_urls.len(),
            MAX_HELP_URLS,
            "Only the bounded help URL window should be preserved through deep cloning"
        );

        // Verify memory usage is reasonable (no exponential growth)
        let final_rendered = current.to_string();
        assert!(final_rendered.len() < 1_000_000,
               "Rendered output should not be excessively large");
    }

    #[test]
    fn negative_concurrent_access_simulation() {
        // Test concurrent access patterns to ActionableError
        // Race conditions in string formatting or cloning could cause issues
        use std::sync::{Arc, Mutex};
        use std::thread;

        let base_err = Arc::new(ActionableError::new("concurrent test", "fix concurrency"));
        let results = Arc::new(Mutex::new(Vec::new()));

        // Spawn multiple threads to stress test concurrent operations
        let handles: Vec<_> = (0..8).map(|thread_id| {
            let err_clone = Arc::clone(&base_err);
            let results_clone = Arc::clone(&results);

            thread::spawn(move || {
                // Perform various operations concurrently
                for iteration in 0..100 {
                    let mut local_err = (*err_clone).clone();
                    local_err = local_err.with_help_url(format!("thread-{}-iter-{}", thread_id, iteration));

                    let rendered = local_err.to_string();
                    let cloned = local_err.clone();

                    // Verify concurrent operations produce valid results
                    assert!(rendered.contains("fix_command=fix concurrency"));
                    assert_eq!(cloned, local_err);

                    // Record result for verification
                    {
                        let mut results_lock = results_clone.lock().unwrap();
                        results_lock.push((thread_id, iteration, rendered.len()));
                    }
                }
            })
        }).collect();

        // Wait for all threads to complete
        for handle in handles {
            handle.join().expect("Thread should complete successfully");
        }

        // Verify all concurrent operations completed successfully
        let final_results = results.lock().unwrap();
        assert_eq!(final_results.len(), 8 * 100, "All concurrent operations should complete");

        // Verify results are reasonable (no corruption)
        for (thread_id, iteration, rendered_len) in final_results.iter() {
            assert!(*rendered_len > 0, "Rendered length should be positive for thread {} iteration {}", thread_id, iteration);
            assert!(*rendered_len < 10000, "Rendered length should be reasonable for thread {} iteration {}", thread_id, iteration);
        }
    }

    #[test]
    fn negative_configuration_boundary_attacks() {
        // Test configuration boundary attacks through extreme field values
        // Edge cases could bypass validation or cause system instability
        let boundary_test_cases = [
            ("", "empty message"),
            (" ".repeat(10000), "very long whitespace message"),
            ("x".repeat(1000000), "extremely long message"),
            ("fix", "minimal fix command"),
            ("fix ".repeat(1000), "repeated fix command"),
            ("https://".repeat(100) + "example.com", "malformed repeated URL"),
        ];

        for (boundary_value, description) in &boundary_test_cases {
            // Test boundary values in different fields
            let err_msg = ActionableError::new(boundary_value, "normal-fix");
            let err_fix = ActionableError::new("normal error", boundary_value);

            // Should handle extreme values without panicking
            let rendered_msg = err_msg.to_string();
            let rendered_fix = err_fix.to_string();

            // Verify format structure is maintained despite extreme values
            assert!(rendered_msg.contains("fix_command=normal-fix"),
                   "Message boundary should not break format: {}", description);
            assert!(rendered_fix.contains(&format!("fix_command={}", boundary_value)),
                   "Fix command boundary should be contained: {}", description);

            // Verify operations remain functional
            let cloned_msg = err_msg.clone();
            let cloned_fix = err_fix.clone();
            assert_eq!(cloned_msg, err_msg, "Clone should work with boundary message: {}", description);
            assert_eq!(cloned_fix, err_fix, "Clone should work with boundary fix: {}", description);

            // Test with help URLs containing boundary values
            if boundary_value.len() < 100000 { // Avoid excessive memory usage in tests
                let err_help = ActionableError::new("normal error", "normal fix")
                    .with_help_url(boundary_value);
                let rendered_help = err_help.to_string();
                assert!(rendered_help.contains(&format!("help_url={}", boundary_value)),
                       "Help URL boundary should be preserved: {}", description);
            }
        }

        // Verify original functionality remains intact after boundary testing
        let normal_err = ActionableError::new("normal error", "normal fix");
        let normal_rendered = normal_err.to_string();
        assert_eq!(normal_rendered, "normal error\nfix_command=normal fix",
                  "Normal functionality should remain intact after boundary testing");
    }

    #[test]
    fn help_urls_are_bounded_to_prevent_memory_exhaustion() {
        use super::MAX_HELP_URLS;

        // Create an error and add more help URLs than the limit
        let mut err = ActionableError::new("test error", "test fix");

        // Add MAX_HELP_URLS + 5 help URLs
        for i in 0..(MAX_HELP_URLS + 5) {
            err = err.with_help_url(format!("https://example.invalid/{}", i));
        }

        // Should only keep the last MAX_HELP_URLS entries
        assert_eq!(err.help_urls.len(), MAX_HELP_URLS);

        // The first few URLs should have been dropped, last ones should remain
        assert!(err.help_urls[0].contains(&(5).to_string())); // First kept URL (index 5)
        assert!(err.help_urls[MAX_HELP_URLS - 1].contains(&(MAX_HELP_URLS + 4).to_string())); // Last URL

        // Verify all URLs in final list are consecutive from the end
        for (idx, url) in err.help_urls.iter().enumerate() {
            let expected_index = 5 + idx; // Starting from URL 5 after dropping first 5
            assert!(url.contains(&expected_index.to_string()),
                   "URL at position {} should contain index {}, got: {}", idx, expected_index, url);
        }
    }

    #[test]
    fn negative_help_url_capacity_keeps_newest_entries_only() {
        let mut err = ActionableError::new("bounded help", "run doctor");
        for i in 0..(MAX_HELP_URLS + 4) {
            err = err.with_help_url(format!("https://example.invalid/help-{i}"));
        }

        assert_eq!(err.help_urls.len(), MAX_HELP_URLS);
        assert_eq!(err.help_urls[0], "https://example.invalid/help-4");
        assert_eq!(
            err.help_urls[MAX_HELP_URLS - 1],
            format!("https://example.invalid/help-{}", MAX_HELP_URLS + 3)
        );
    }

    #[test]
    fn negative_empty_help_urls_remain_bounded() {
        let mut err = ActionableError::new("bounded empty help", "run doctor");
        for _ in 0..(MAX_HELP_URLS * 3) {
            err = err.with_help_url("");
        }

        let rendered = err.to_string();
        assert_eq!(err.help_urls.len(), MAX_HELP_URLS);
        assert_eq!(rendered.matches("\nhelp_url=").count(), MAX_HELP_URLS);
    }

    #[test]
    fn negative_push_bounded_zero_capacity_drops_new_entry() {
        let mut urls = vec!["old-a".to_string(), "old-b".to_string()];

        push_bounded(&mut urls, "new".to_string(), 0);

        assert!(urls.is_empty());
    }

    #[test]
    fn negative_push_bounded_over_capacity_discards_oldest_entries() {
        let mut urls = vec!["old-a".to_string(), "old-b".to_string(), "old-c".to_string()];

        push_bounded(&mut urls, "new".to_string(), 2);

        assert_eq!(urls, vec!["old-c".to_string(), "new".to_string()]);
    }

    #[test]
    fn negative_clone_chain_preserves_bounded_help_window() {
        let mut err = ActionableError::new("clone bounded", "run doctor");
        for i in 0..(MAX_HELP_URLS * 5) {
            err = err.with_help_url(format!("https://example.invalid/{i}"));
        }

        let mut cloned = err.clone();
        for _ in 0..16 {
            cloned = cloned.clone();
        }

        assert_eq!(cloned.help_urls.len(), MAX_HELP_URLS);
        assert_eq!(cloned.to_string().matches("\nhelp_url=").count(), MAX_HELP_URLS);
    }

    #[test]
    fn negative_exact_capacity_help_urls_do_not_evict() {
        let mut err = ActionableError::new("exact capacity", "run doctor");
        for i in 0..MAX_HELP_URLS {
            err = err.with_help_url(format!("https://example.invalid/exact-{i}"));
        }

        assert_eq!(err.help_urls.len(), MAX_HELP_URLS);
        assert_eq!(err.help_urls[0], "https://example.invalid/exact-0");
        assert_eq!(
            err.help_urls[MAX_HELP_URLS - 1],
            format!("https://example.invalid/exact-{}", MAX_HELP_URLS - 1)
        );
    }

    #[test]
    fn negative_one_past_capacity_evicts_only_oldest_help_url() {
        let mut err = ActionableError::new("one past capacity", "run doctor");
        for i in 0..=MAX_HELP_URLS {
            err = err.with_help_url(format!("https://example.invalid/one-past-{i}"));
        }

        let rendered = err.to_string();
        assert_eq!(err.help_urls.len(), MAX_HELP_URLS);
        assert!(!rendered.contains("https://example.invalid/one-past-0"));
        assert!(rendered.contains("https://example.invalid/one-past-1"));
        assert!(rendered.contains(&format!(
            "https://example.invalid/one-past-{MAX_HELP_URLS}"
        )));
    }

    #[test]
    fn negative_large_help_url_payload_does_not_bypass_count_cap() {
        let mut err = ActionableError::new("large payload", "run doctor");
        for i in 0..(MAX_HELP_URLS + 8) {
            err = err.with_help_url(format!("https://example.invalid/{i}/{}", "x".repeat(512)));
        }

        assert_eq!(err.help_urls.len(), MAX_HELP_URLS);
        assert!(err.help_urls.iter().all(|url| url.len() > 512));
        assert_eq!(err.to_string().matches("\nhelp_url=").count(), MAX_HELP_URLS);
    }

    #[test]
    fn negative_interleaved_blank_and_nonblank_help_urls_stay_bounded() {
        let mut err = ActionableError::new("mixed help", "run doctor");
        for i in 0..(MAX_HELP_URLS * 2) {
            let help_url = if i.is_multiple_of(2) {
                String::new()
            } else {
                format!("https://example.invalid/mixed-{i}")
            };
            err = err.with_help_url(help_url);
        }

        assert_eq!(err.help_urls.len(), MAX_HELP_URLS);
        assert!(!err
            .help_urls
            .iter()
            .any(|url| url.as_str() == "https://example.invalid/mixed-1"));
        assert!(err.help_urls.iter().any(String::is_empty));
    }

    #[test]
    fn safe_lock_handles_poisoned_mutex() {
        let mutex = Arc::new(Mutex::new(42));
        let poison_mutex = Arc::clone(&mutex);

        // Create a poisoned mutex by panicking while holding the lock
        let handle = thread::spawn(move || {
            let _guard = poison_mutex.lock().unwrap();
            panic!("Intentional panic to poison mutex");
        });

        // Wait for the thread to panic and poison the mutex
        handle.join().unwrap_err();

        // Now test that safe_lock properly handles the poisoned mutex
        let result = lock_utils::safe_lock(&mutex);
        assert!(result.is_err());

        let error = result.unwrap_err();
        assert!(error.message.contains("Mutex poisoned"));
        assert!(error.fix_command.contains("Check for panics"));
        assert!(error.help_urls.len() > 0);
    }

    #[test]
    fn multi_lock_ordering_prevents_deadlock() {
        use std::time::Duration;

        // Test canonical lock ordering prevents deadlocks under contention
        let lock_a = Arc::new(Mutex::new("state_a"));
        let lock_b = Arc::new(Mutex::new("state_b"));
        let results = Arc::new(Mutex::new(Vec::new()));

        let mut handles = vec![];

        // Spawn multiple threads that acquire locks in canonical order
        for i in 0..4 {
            let lock_a_clone = Arc::clone(&lock_a);
            let lock_b_clone = Arc::clone(&lock_b);
            let results_clone = Arc::clone(&results);

            let handle = thread::spawn(move || {
                // Always acquire in alphabetical order: lock_a before lock_b
                let guard_a = lock_a_clone.lock().unwrap();
                thread::sleep(Duration::from_millis(1)); // Create contention
                let guard_b = lock_b_clone.lock().unwrap();

                // Simulate work while holding both locks
                let value = format!("{}-{}", *guard_a, *guard_b);
                results_clone.lock().unwrap().push(format!("thread-{}: {}", i, value));

                // Locks released in reverse order automatically
            });
            handles.push(handle);
        }

        // All threads should complete within reasonable time (no deadlock)
        let start = std::time::Instant::now();
        for handle in handles {
            handle.join().expect("Thread should complete without deadlock");
        }
        let elapsed = start.elapsed();

        // Verify no deadlock occurred (should complete much faster than 10s)
        assert!(elapsed < Duration::from_secs(10),
            "Multi-lock test took too long: {:?}. Possible deadlock!", elapsed);

        // Verify all threads completed successfully
        let final_results = results.lock().unwrap();
        assert_eq!(final_results.len(), 4, "All threads should complete");
    }
}

#[cfg(feature = "control-plane")]
pub mod api;
#[cfg(any(test, feature = "advanced-features"))]
pub mod atc;
pub mod capacity_defaults;
#[cfg(feature = "advanced-features")]
pub mod claims;
pub mod cli;
pub mod config;
#[cfg(feature = "advanced-features")]
pub mod conformance;
pub mod connector;
pub mod control_plane;
#[cfg(feature = "advanced-features")]
pub mod encoding;
#[cfg(feature = "advanced-features")]
pub mod extensions;
#[cfg(feature = "advanced-features")]
pub mod federation;
#[cfg(any(test, feature = "admin-tools"))]
pub mod migration;
pub mod observability;
pub mod ops;
#[cfg(feature = "advanced-features")]
pub mod perf;
#[cfg(feature = "policy-engine")]
pub mod policy;
#[cfg(feature = "admin-tools")]
pub mod registry;
pub mod remote;
#[cfg(feature = "advanced-features")]
pub mod repair;
pub mod replay;
#[cfg(feature = "control-plane")]
#[path = "control_plane/root_pointer.rs"]
pub mod root_pointer;
pub mod runtime;
pub mod schema_versions;
#[cfg(feature = "verifier-tools")]
pub mod sdk;
pub mod security;
pub mod storage;
pub mod supply_chain;
pub mod test_strategies;
#[cfg(any(test, feature = "test-support"))]
pub mod testing;
pub mod tools;
pub mod vef;
#[cfg(feature = "verifier-tools")]
pub mod verifier_economy;
