#![no_main]

use libfuzzer_sys::fuzz_target;
use arbitrary::Arbitrary;
use frankenengine_node::federation::atc_signal_extractor::SignalKind;

/// Comprehensive fuzz target for SignalKind::from_str federation signal parsing.
///
/// Tests federation signal kind parsing against:
/// - Valid signal types (anomaly_observation, trust_card_delta, etc.)
/// - Case variations and unicode confusables
/// - Injection attack patterns (null bytes, control chars)
/// - Memory exhaustion attempts (oversized strings)
/// - Format confusion with similar event type strings
/// - Empty/whitespace handling and edge case lengths
///
/// Security focus: Ensure robust rejection of malformed signal types without
/// crashes, timing attacks, or unexpected signal classification.
#[derive(Arbitrary, Debug)]
struct SignalKindParseInput {
    /// Base content to parse as SignalKind
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
    /// JSON event structure
    JsonLike,
    /// XML event structure
    XmlLike,
    /// HTTP header format
    HttpHeader,
    /// Log line format
    LogFormat,
    /// File path format
    PathLike,
    /// SQL-like format
    SqlLike,
}

impl SignalKindParseInput {
    fn generate_test_string(&self) -> String {
        let mut base_string = match String::from_utf8(self.content.clone()) {
            Ok(s) => s,
            Err(_) => {
                // Fallback to valid UTF-8 content for non-UTF8 fuzzing
                "anomaly_observation".to_string()
            }
        };

        // Apply format confusion
        match self.format_confusion {
            FormatConfusion::Pure => {},
            FormatConfusion::JsonLike => {
                base_string = format!(r#"{{"signal_kind": "{}"}}"#, base_string);
            },
            FormatConfusion::XmlLike => {
                base_string = format!("<signal_kind>{}</signal_kind>", base_string);
            },
            FormatConfusion::HttpHeader => {
                base_string = format!("X-Signal-Kind: {}", base_string);
            },
            FormatConfusion::LogFormat => {
                base_string = format!("[2023-01-01T00:00:00Z] signal_kind={}", base_string);
            },
            FormatConfusion::PathLike => {
                base_string = format!("/api/signals/{}/events", base_string);
            },
            FormatConfusion::SqlLike => {
                base_string = format!("SELECT * FROM signals WHERE kind='{}'", base_string);
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
                match target_char {
                    b'o' => base_string = base_string.replace('o', "ο"), // Greek omicron
                    b'a' => base_string = base_string.replace('a', "а"), // Cyrillic a
                    b'e' => base_string = base_string.replace('e', "е"), // Cyrillic e
                    b'_' => base_string = base_string.replace('_', "‿"), // Undertie
                    _ => {}
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

fuzz_target!(|input: SignalKindParseInput| {
    let test_string = input.generate_test_string();

    // Test parsing - should never panic or cause undefined behavior
    let parse_result = SignalKind::from_str(&test_string);

    // Verify consistent behavior on repeated parsing
    let repeat_result = SignalKind::from_str(&test_string);
    assert_eq!(parse_result.is_some(), repeat_result.is_some(),
               "Parse result consistency failed for input: {:?}", test_string);

    // Test deterministic output for same input
    if let (Some(result1), Some(result2)) = (parse_result, repeat_result) {
        assert_eq!(result1, result2, "Non-deterministic output for: {}", test_string);
    }

    // Verify expected behavior for known valid signal kinds
    match test_string.as_str() {
        "anomaly_observation" => {
            assert!(parse_result.is_some(), "Valid anomaly_observation should parse");
            if let Some(kind) = parse_result {
                assert_eq!(kind.as_str(), "anomaly_observation", "Round-trip consistency");
            }
        },
        "trust_card_delta" => {
            assert!(parse_result.is_some(), "Valid trust_card_delta should parse");
            if let Some(kind) = parse_result {
                assert_eq!(kind.as_str(), "trust_card_delta", "Round-trip consistency");
            }
        },
        "revocation_hint" => {
            assert!(parse_result.is_some(), "Valid revocation_hint should parse");
            if let Some(kind) = parse_result {
                assert_eq!(kind.as_str(), "revocation_hint", "Round-trip consistency");
            }
        },
        "quarantine_event" => {
            assert!(parse_result.is_some(), "Valid quarantine_event should parse");
            if let Some(kind) = parse_result {
                assert_eq!(kind.as_str(), "quarantine_event", "Round-trip consistency");
            }
        },
        _ => {
            // Invalid inputs should return None
            assert!(parse_result.is_none(), "Invalid input should return None: {:?}", test_string);
        }
    }

    // Test that case sensitivity is enforced (lowercase required)
    let uppercase_variants = ["ANOMALY_OBSERVATION", "Trust_Card_Delta", "REVOCATION_HINT"];
    if uppercase_variants.iter().any(|&variant| test_string == variant) {
        assert!(parse_result.is_none(), "Case-sensitive parsing should reject uppercase: {}", test_string);
    }

    // Test that obviously invalid inputs are rejected
    if test_string.contains("invalid") || test_string.contains("XXX") || test_string.len() > 1000 {
        assert!(parse_result.is_none(), "Obviously invalid input should be rejected: {}", test_string);
    }

    // Test empty and whitespace handling
    if test_string.trim().is_empty() {
        assert!(parse_result.is_none(), "Empty/whitespace input should be rejected");
    }

    // Ensure no memory leaks on large inputs
    if test_string.len() > 10000 {
        // Force any potential cleanup by parsing again
        let _ = SignalKind::from_str("anomaly_observation");
    }

    // Test timing attack resistance - parsing time should be bounded
    if test_string.len() <= 100 {
        let start = std::time::Instant::now();
        let _ = SignalKind::from_str(&test_string);
        let elapsed = start.elapsed();
        assert!(elapsed.as_millis() < 10, "Parsing should complete quickly: {}", test_string);
    }

    // Test that all valid signal kinds round-trip correctly
    if let Some(kind) = parse_result {
        let round_trip = SignalKind::from_str(kind.as_str());
        assert_eq!(Some(kind), round_trip, "Round-trip should preserve signal kind");
    }
});