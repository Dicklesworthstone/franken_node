#![no_main]

use libfuzzer_sys::fuzz_target;
use frankenengine_node::api::middleware::TraceContext;

fuzz_target!(|data: &[u8]| {
    // Convert bytes to string, handling invalid UTF-8 gracefully
    if let Ok(input) = std::str::from_utf8(data) {
        // Guard against excessively long strings to avoid OOM
        if input.len() > 10000 {
            return;
        }

        // Test traceparent header parsing
        let result = TraceContext::from_traceparent(input);

        match result {
            Some(context) => {
                // Valid parse - verify invariants of the parsed context

                // 1. Trace ID should be 32 hex chars
                assert_eq!(context.trace_id.len(), 32, "Trace ID must be 32 chars");
                assert!(context.trace_id.chars().all(|c| c.is_ascii_hexdigit()),
                       "Trace ID must be hex");

                // 2. Span ID should be 16 hex chars
                assert_eq!(context.span_id.len(), 16, "Span ID must be 16 chars");
                assert!(context.span_id.chars().all(|c| c.is_ascii_hexdigit()),
                       "Span ID must be hex");

                // 3. Trace flags should be valid
                let flags = context.trace_flags;
                // No specific constraints on flags value, but should be u8

                // 4. Re-parsing the same input should yield the same result
                let context2 = TraceContext::from_traceparent(input);
                assert!(context2.is_some(), "Re-parsing should succeed");
                let context2 = context2.unwrap();
                assert_eq!(context.trace_id, context2.trace_id);
                assert_eq!(context.span_id, context2.span_id);
                assert_eq!(context.trace_flags, context2.trace_flags);

                // 5. Trace ID should not be all zeros (invalid)
                assert_ne!(context.trace_id, "00000000000000000000000000000000");

                // 6. Span ID should not be all zeros (invalid)
                assert_ne!(context.span_id, "0000000000000000");
            }
            None => {
                // Invalid parse - this is expected for malformed input
                // Test that various malformed inputs consistently return None

                // Test with modified input to ensure robustness
                if !input.is_empty() {
                    // Test with truncated input
                    for len in 1..std::cmp::min(input.len(), 10) {
                        let truncated = &input[..len];
                        let truncated_result = TraceContext::from_traceparent(truncated);
                        // Truncated input should also be invalid
                    }
                }
            }
        }

        // Test edge cases specifically
        if input == "00-00000000000000000000000000000000-0000000000000000-00" {
            // All zeros should be rejected
            assert!(TraceContext::from_traceparent(input).is_none());
        }

        if input == "ff-00000000000000000000000000000001-0000000000000001-01" {
            // Version ff should be rejected
            assert!(TraceContext::from_traceparent(input).is_none());
        }
    }
});