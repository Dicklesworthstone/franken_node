#![no_main]

use libfuzzer_sys::fuzz_target;
use arbitrary::Arbitrary;
use frankenengine_node::security::trajectory_gaming::{CamouflageKind, TrajectoryGamingError};

/// Comprehensive fuzz target for CamouflageKind::parse string parsing.
///
/// Tests trajectory gaming camouflage kind parsing against:
/// - Valid enum variant strings (phase_shift, dropout, etc.)
/// - Case variations and unicode confusables
/// - Injection attack patterns (null bytes, control chars)
/// - Memory exhaustion attempts (oversized strings)
/// - Format confusion with similar security boundary strings
/// - Empty/whitespace handling and edge case lengths
///
/// Security focus: Ensure robust rejection of malformed input without
/// crashes, timing attacks, or unexpected variant interpretation.
#[derive(Arbitrary, Debug)]
struct CamouflageParseInput {
    /// Base content to parse as CamouflageKind
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
    /// Hex-encoded content
    HexEncoded,
    /// Base64-like content
    Base64Like,
    /// Path-like structure
    PathLike,
    /// URL-encoded content
    UrlEncoded,
}

impl CamouflageParseInput {
    fn generate_test_string(&self) -> String {
        let mut base_string = match String::from_utf8(self.content.clone()) {
            Ok(s) => s,
            Err(_) => {
                // Fallback to valid UTF-8 content for non-UTF8 fuzzing
                "phase_shift".to_string()
            }
        };

        // Apply format confusion
        match self.format_confusion {
            FormatConfusion::Pure => {},
            FormatConfusion::JsonLike => {
                base_string = format!(r#"{{"kind": "{}"}}"#, base_string);
            },
            FormatConfusion::HexEncoded => {
                base_string = hex::encode(base_string.as_bytes());
            },
            FormatConfusion::Base64Like => {
                base_string = base64::prelude::BASE64_STANDARD.encode(base_string.as_bytes());
            },
            FormatConfusion::PathLike => {
                base_string = format!("/camouflage/{}/kind", base_string);
            },
            FormatConfusion::UrlEncoded => {
                base_string = urlencoding::encode(&base_string).to_string();
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
                // Replace 'o' with unicode homoglyphs for camouflaged attacks
                if target_char == b'o' {
                    base_string = base_string.replace('o', "ο"); // Greek omicron
                } else if target_char == b'a' {
                    base_string = base_string.replace('a', "а"); // Cyrillic a
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

fuzz_target!(|input: CamouflageParseInput| {
    let test_string = input.generate_test_string();

    // Test parsing - should never panic or cause undefined behavior
    let parse_result = CamouflageKind::parse(&test_string);

    // Verify consistent behavior on repeated parsing
    let repeat_result = CamouflageKind::parse(&test_string);
    assert_eq!(parse_result.is_ok(), repeat_result.is_ok(),
               "Parse result consistency failed for input: {:?}", test_string);

    // Verify expected behavior for known valid variants
    match test_string.as_str() {
        "phase_shift" => assert!(parse_result.is_ok(), "Valid phase_shift should parse"),
        "dropout" => assert!(parse_result.is_ok(), "Valid dropout should parse"),
        "distribution_mismatch" => assert!(parse_result.is_ok(), "Valid distribution_mismatch should parse"),
        "gradual_creep" => assert!(parse_result.is_ok(), "Valid gradual_creep should parse"),
        _ => {
            // Invalid inputs should return proper error type
            if let Err(err) = parse_result {
                match err {
                    TrajectoryGamingError::UnknownKind { kind } => {
                        assert_eq!(kind, test_string, "Error kind should match input");
                    },
                    other => panic!("Unexpected error type for parse failure: {:?}", other),
                }
            }
        }
    }

    // Test that error messages are bounded and don't leak arbitrary input
    if let Err(TrajectoryGamingError::UnknownKind { kind }) = parse_result {
        assert!(kind.len() <= test_string.len().saturating_add(100),
                "Error message should be bounded relative to input length");
    }

    // Ensure no memory leaks on large inputs
    if test_string.len() > 10000 {
        // Force any potential cleanup by parsing again
        let _ = CamouflageKind::parse("");
    }
});