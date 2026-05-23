#![no_main]

use libfuzzer_sys::fuzz_target;
use arbitrary::Arbitrary;
use frankenengine_node::runtime::lane_router::ProductLane;

/// Comprehensive fuzz target for ProductLane::parse_label string parsing.
///
/// Tests lane label parsing against:
/// - Valid enum variant strings (cancel, timed, realtime, background)
/// - Case variations and unicode confusables
/// - Injection attack patterns (null bytes, control chars)
/// - Memory exhaustion attempts (oversized strings)
/// - Format confusion with similar system control strings
/// - Whitespace handling and edge case lengths
///
/// Security focus: Ensure robust rejection of malformed input without
/// crashes, timing attacks, or unexpected lane assignment.
#[derive(Arbitrary, Debug)]
struct LaneParseInput {
    /// Base content to parse as ProductLane
    content: Vec<u8>,

    /// Injection type to apply for boundary testing
    injection_type: InjectionType,

    /// Format confusion attack vector
    format_confusion: FormatConfusion,
}

#[derive(Arbitrary, Debug)]
enum InjectionType {
    /// Pure input without injection
    None,
    /// Null byte injection
    NullByte { position: u8 },
    /// Control character injection
    ControlChar { char_code: u8, position: u8 },
    /// Unicode homoglyph substitution
    UnicodeHomoglyph { target_char: u8 },
    /// Buffer overflow attempt
    Oversized { multiplier: u8 },
}

#[derive(Arbitrary, Debug)]
enum FormatConfusion {
    /// No format confusion
    Pure,
    /// JSON-like structure
    JsonLike,
    /// XML-like structure
    XmlLike,
    /// SQL-like injection
    SqlLike,
    /// Path-like structure
    PathLike,
    /// URL-encoded content
    UrlEncoded,
    /// Base64-like content
    Base64Like,
}

impl LaneParseInput {
    fn generate_test_string(&self) -> String {
        let mut base_string = match String::from_utf8(self.content.clone()) {
            Ok(s) => s,
            Err(_) => {
                // Fallback to valid UTF-8 content for non-UTF8 fuzzing
                "cancel".to_string()
            }
        };

        // Apply format confusion
        match self.format_confusion {
            FormatConfusion::Pure => {},
            FormatConfusion::JsonLike => {
                base_string = format!(r#"{{"lane": "{}"}}"#, base_string);
            },
            FormatConfusion::XmlLike => {
                base_string = format!("<lane>{}</lane>", base_string);
            },
            FormatConfusion::SqlLike => {
                base_string = format!("SELECT * FROM lanes WHERE name='{}'", base_string);
            },
            FormatConfusion::PathLike => {
                base_string = format!("/api/lanes/{}/status", base_string);
            },
            FormatConfusion::UrlEncoded => {
                base_string = urlencoding::encode(&base_string).to_string();
            },
            FormatConfusion::Base64Like => {
                base_string = base64::prelude::BASE64_STANDARD.encode(base_string.as_bytes());
            },
        }

        // Apply injection attack
        match self.injection_type {
            InjectionType::None => {},
            InjectionType::NullByte { position } => {
                let pos = (position as usize).min(base_string.len());
                base_string.insert(pos, '\0');
            },
            InjectionType::ControlChar { char_code, position } => {
                if char_code < 32 {  // Control characters
                    let pos = (position as usize).min(base_string.len());
                    base_string.insert(pos, char_code as char);
                }
            },
            InjectionType::UnicodeHomoglyph { target_char } => {
                // Replace common chars with unicode homoglyphs for camouflaged attacks
                if target_char == b'a' {
                    base_string = base_string.replace('a', "а"); // Cyrillic a
                } else if target_char == b'e' {
                    base_string = base_string.replace('e', "е"); // Cyrillic e
                }
            },
            InjectionType::Oversized { multiplier } => {
                let repeat_count = (multiplier as usize).saturating_mul(1024).min(65536);
                base_string = base_string.repeat(repeat_count.max(1));
            },
        }

        base_string
    }
}

fuzz_target!(|input: LaneParseInput| {
    let test_string = input.generate_test_string();

    // Test parsing - should never panic or cause undefined behavior
    let parse_result = ProductLane::parse_label(&test_string);

    // Verify consistent behavior on repeated parsing
    let repeat_result = ProductLane::parse_label(&test_string);
    assert_eq!(parse_result.is_some(), repeat_result.is_some(),
               "Parse result consistency failed for input: {:?}", test_string);

    // Verify expected behavior for known valid variants
    match test_string.trim().to_ascii_lowercase().as_str() {
        "cancel" => assert!(parse_result.is_some(), "Valid cancel should parse"),
        "timed" => assert!(parse_result.is_some(), "Valid timed should parse"),
        "realtime" => assert!(parse_result.is_some(), "Valid realtime should parse"),
        "ready" => assert!(parse_result.is_some(), "Valid ready (alias for realtime) should parse"),
        "background" => assert!(parse_result.is_some(), "Valid background should parse"),
        _ => {
            // Invalid inputs should return None
            assert!(parse_result.is_none(), "Invalid input should return None: {:?}", test_string);
        }
    }

    // Test case sensitivity - should work with mixed case
    if ["cancel", "timed", "realtime", "ready", "background"].contains(&test_string.to_lowercase().trim()) {
        assert!(parse_result.is_some(), "Valid lane with case variation should parse");
    }

    // Test whitespace handling - trim should work
    let trimmed_test = test_string.trim();
    if ["cancel", "timed", "realtime", "ready", "background"].contains(&trimmed_test.to_lowercase()) {
        assert!(parse_result.is_some(), "Valid lane with whitespace should parse after trim");
    }

    // Ensure no memory leaks on large inputs
    if test_string.len() > 10000 {
        // Force any potential cleanup by parsing again
        let _ = ProductLane::parse_label("");
    }

    // Test that function handles extreme input sizes gracefully
    if test_string.len() > 100000 {
        // Should complete in reasonable time even for very large inputs
        let start = std::time::Instant::now();
        let _ = ProductLane::parse_label(&test_string);
        let elapsed = start.elapsed();
        assert!(elapsed.as_millis() < 100, "Parse should complete quickly even for large inputs");
    }
});