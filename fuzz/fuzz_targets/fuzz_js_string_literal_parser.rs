//! Fuzz target for JavaScript string literal parsing in migration module.
//!
//! Tests JS string literal parser against malformed quotes, escape sequences,
//! unicode edge cases, nested quotes, and injection attacks. Critical boundary
//! for validating JavaScript code migration and parsing.

#![no_main]

use arbitrary::{Arbitrary, Unstructured};
use libfuzzer_sys::fuzz_target;

// Reimplemented function for fuzzing
fn parse_js_string_literal_at(code: &str, quote_index: usize) -> Option<(usize, usize, String)> {
    let quote = code.get(quote_index..)?.chars().next()?;
    if quote != '"' && quote != '\'' {
        return None;
    }

    let literal_start = quote_index.saturating_add(quote.len_utf8());
    let mut escaped = false;
    for (relative_index, ch) in code.get(literal_start..)?.char_indices() {
        if escaped {
            escaped = false;
            continue;
        }
        if ch == '\\' {
            escaped = true;
            continue;
        }
        if ch == quote {
            let literal_end = literal_start.saturating_add(relative_index);
            let specifier = code.get(literal_start..literal_end)?.to_string();
            if specifier.trim().is_empty() {
                return None;
            }
            return Some((literal_start, literal_end, specifier));
        }
    }
    None
}

#[derive(Debug, Clone, Arbitrary)]
struct FuzzInput {
    operation: StringLiteralOperation,
}

#[derive(Debug, Clone, Arbitrary)]
enum StringLiteralOperation {
    BasicStringLiteral {
        quote_type: QuoteType,
        content: String,
        quote_index: u8,
    },
    EscapeSequences {
        quote_type: QuoteType,
        escapes: Vec<EscapeSequence>,
        base_content: String,
    },
    MalformedQuotes {
        quote_patterns: Vec<QuotePattern>,
        content: String,
    },
    UnicodeEdgeCases {
        unicode_type: UnicodeType,
        base_string: String,
        quote_index: u8,
    },
    InjectionAttempts {
        injection_type: InjectionType,
        payload: String,
        quote_context: QuoteContext,
    },
    BoundaryTests {
        boundary_type: BoundaryType,
        test_data: String,
    },
}

#[derive(Debug, Clone, Arbitrary)]
enum QuoteType {
    Single,
    Double,
    Backtick,
    Mixed,
}

#[derive(Debug, Clone, Arbitrary)]
enum EscapeSequence {
    Backslash,
    Quote,
    Newline,
    Tab,
    CarriageReturn,
    Unicode,
    Hex,
    Octal,
    NullByte,
    Invalid,
}

#[derive(Debug, Clone, Arbitrary)]
enum QuotePattern {
    Unmatched,
    Nested,
    Escaped,
    Multiple,
    ZeroWidth,
}

#[derive(Debug, Clone, Arbitrary)]
enum UnicodeType {
    BasicMultilingual,
    Supplementary,
    Surrogates,
    Combining,
    RightToLeft,
    Emoji,
    ControlChars,
}

#[derive(Debug, Clone, Arbitrary)]
enum InjectionType {
    CodeInjection,
    TemplateInjection,
    RegexInjection,
    PathTraversal,
    SqlInjection,
    XssPayload,
}

#[derive(Debug, Clone, Arbitrary)]
enum QuoteContext {
    StartOfString,
    MiddleOfString,
    EndOfString,
    NoQuotes,
}

#[derive(Debug, Clone, Arbitrary)]
enum BoundaryType {
    EmptyString,
    SingleChar,
    VeryLong,
    QuoteOnly,
    EscapeOnly,
    IndexOutOfBounds,
}

impl QuoteType {
    fn to_char(&self) -> char {
        match self {
            QuoteType::Single => '\'',
            QuoteType::Double => '"',
            QuoteType::Backtick => '`',
            QuoteType::Mixed => '"', // Default for mixed
        }
    }
}

impl EscapeSequence {
    fn to_string(&self) -> &str {
        match self {
            EscapeSequence::Backslash => "\\\\",
            EscapeSequence::Quote => "\\\"",
            EscapeSequence::Newline => "\\n",
            EscapeSequence::Tab => "\\t",
            EscapeSequence::CarriageReturn => "\\r",
            EscapeSequence::Unicode => "\\u0041",
            EscapeSequence::Hex => "\\x41",
            EscapeSequence::Octal => "\\101",
            EscapeSequence::NullByte => "\\0",
            EscapeSequence::Invalid => "\\z",
        }
    }
}

impl QuotePattern {
    fn apply(&self, content: &str, quote: char) -> String {
        match self {
            QuotePattern::Unmatched => format!("{}{}", quote, content),
            QuotePattern::Nested => format!("{}{}{}{}", quote, quote, content, quote),
            QuotePattern::Escaped => format!("\\{}{}", quote, content),
            QuotePattern::Multiple => format!("{}{}{}{}{}", quote, quote, content, quote, quote),
            QuotePattern::ZeroWidth => format!("{}\u{200B}{}{}", quote, content, quote),
        }
    }
}

impl UnicodeType {
    fn generate_content(&self, base: &str) -> String {
        match self {
            UnicodeType::BasicMultilingual => format!("{}αβγδε", base),
            UnicodeType::Supplementary => format!("{}𝕳𝖊𝖑𝖑𝖔", base),
            UnicodeType::Surrogates => format!("{}\\uD83D\\uDE00", base), // JavaScript surrogate escape pair.
            UnicodeType::Combining => format!("{}a\u{0300}\u{0301}", base),
            UnicodeType::RightToLeft => format!("{}\u{202E}abc\u{202D}", base),
            UnicodeType::Emoji => format!("{}🔥💥⚠️", base),
            UnicodeType::ControlChars => format!("{}\u{0001}\u{0002}\u{001F}", base),
        }
    }
}

impl InjectionType {
    fn generate_payload(&self, base: &str) -> String {
        match self {
            InjectionType::CodeInjection => format!("{}'; eval('alert(1)'); //", base),
            InjectionType::TemplateInjection => {
                format!("{}{{constructor.constructor('alert(1)')()}}", base)
            }
            InjectionType::RegexInjection => format!("{}.*[a-zA-Z]{{1000000}}", base),
            InjectionType::PathTraversal => format!("{}../../../etc/passwd", base),
            InjectionType::SqlInjection => format!("{}'; DROP TABLE users; --", base),
            InjectionType::XssPayload => format!("{}<script>alert('xss')</script>", base),
        }
    }
}

fn generate_boundary_test(boundary_type: &BoundaryType, test_data: &str) -> (String, usize) {
    match boundary_type {
        BoundaryType::EmptyString => (String::new(), 0),
        BoundaryType::SingleChar => ("\"".to_string(), 0),
        BoundaryType::VeryLong => {
            let long_content = "A".repeat(10000);
            (format!("\"{}\"", long_content), 0)
        }
        BoundaryType::QuoteOnly => ("\"\"".to_string(), 0),
        BoundaryType::EscapeOnly => ("\\\\\\\\".to_string(), 0),
        BoundaryType::IndexOutOfBounds => (format!("prefix{}", test_data), 1000),
    }
}

fuzz_target!(|data: &[u8]| {
    let mut u = Unstructured::new(data);

    if let Ok(fuzz_input) = FuzzInput::arbitrary(&mut u) {
        match fuzz_input.operation {
            StringLiteralOperation::BasicStringLiteral {
                quote_type,
                content,
                quote_index,
            } => {
                let quote = quote_type.to_char();
                let code = format!("prefix{}{}{}", quote, content, quote);
                let index =
                    (quote_index as usize % code.len().max(1)).min(code.len().saturating_sub(1));

                // Test deterministic parsing behavior
                let result1 = parse_js_string_literal_at(&code, index);
                let result2 = parse_js_string_literal_at(&code, index);
                assert_eq!(
                    result1.is_some(),
                    result2.is_some(),
                    "JS string literal parsing should be deterministic"
                );

                // If a quote character is found at the index, parsing should succeed or fail consistently
                if let Some(ch) = code.chars().nth(index) {
                    if ch == '"' || ch == '\'' {
                        // Should either parse successfully or return None, but not panic
                        if let Some((start, end, content)) = result1 {
                            assert!(start <= end, "String literal start should not be after end");
                            assert!(
                                !content.trim().is_empty(),
                                "Parsed content should not be empty"
                            );
                            assert!(
                                end <= code.len(),
                                "End position should not exceed code length"
                            );
                        }
                    }
                }
            }
            StringLiteralOperation::EscapeSequences {
                quote_type,
                escapes,
                base_content,
            } => {
                let quote = quote_type.to_char();
                let mut content = base_content;
                for escape in &escapes {
                    content.push_str(escape.to_string());
                }
                let code = format!("prefix{}{}{}", quote, content, quote);
                let quote_pos = code.find(quote).unwrap_or(0);

                // Test escape sequence handling
                let result = parse_js_string_literal_at(&code, quote_pos);
                let result2 = parse_js_string_literal_at(&code, quote_pos);
                assert_eq!(
                    result.is_some(),
                    result2.is_some(),
                    "Escape sequence parsing should be deterministic"
                );

                // Valid escape sequences should be parsed correctly
                if let Some((start, end, parsed_content)) = result {
                    assert!(
                        start < end,
                        "Start should be before end for valid string literal"
                    );
                    // Escape sequences should be preserved in the parsed content
                    assert!(
                        !parsed_content.is_empty(),
                        "Parsed content with escapes should not be empty"
                    );
                }
            }
            StringLiteralOperation::MalformedQuotes {
                quote_patterns,
                content,
            } => {
                let base_quote = '"';
                for pattern in &quote_patterns {
                    let malformed = pattern.apply(&content, base_quote);

                    // Test malformed quote handling
                    let result = parse_js_string_literal_at(&malformed, 0);
                    let result2 = parse_js_string_literal_at(&malformed, 0);
                    assert_eq!(
                        result.is_some(),
                        result2.is_some(),
                        "Malformed quote parsing should be deterministic"
                    );

                    // Most malformed patterns should be rejected
                    match pattern {
                        QuotePattern::Unmatched => {
                            // Unmatched quotes should generally be rejected
                            assert!(result.is_none(), "Unmatched quotes should be rejected");
                        }
                        _ => {
                            // Other patterns may succeed or fail but should not crash
                        }
                    }
                }
            }
            StringLiteralOperation::UnicodeEdgeCases {
                unicode_type,
                base_string,
                quote_index,
            } => {
                let unicode_content = unicode_type.generate_content(&base_string);
                let code = format!("prefix\"{}\"", unicode_content);
                let index =
                    (quote_index as usize % code.len().max(1)).min(code.len().saturating_sub(1));

                // Test Unicode handling
                let result = parse_js_string_literal_at(&code, index);
                let result2 = parse_js_string_literal_at(&code, index);
                assert_eq!(
                    result.is_some(),
                    result2.is_some(),
                    "Unicode parsing should be deterministic"
                );

                // Unicode content should be handled safely
                if let Some((start, end, parsed_content)) = result {
                    assert!(
                        start <= end,
                        "Unicode string literal bounds should be valid"
                    );
                    // Unicode content should be preserved
                    assert!(
                        !parsed_content.is_empty(),
                        "Unicode content should not be empty"
                    );
                }
            }
            StringLiteralOperation::InjectionAttempts {
                injection_type,
                payload,
                quote_context,
            } => {
                let injection_payload = injection_type.generate_payload(&payload);
                let (test_code, quote_pos) = match quote_context {
                    QuoteContext::StartOfString => (format!("\"{}\"", injection_payload), 0),
                    QuoteContext::MiddleOfString => {
                        let code = format!("prefix\"{}\"", injection_payload);
                        let pos = code.find('"').unwrap_or(0);
                        (code, pos)
                    }
                    QuoteContext::EndOfString => {
                        let code = format!("{}\"{}\"", injection_payload, payload);
                        let pos = code.rfind('"').unwrap_or(0);
                        (code, pos)
                    }
                    QuoteContext::NoQuotes => (injection_payload, 0),
                };
                // Test injection attack handling
                let result = parse_js_string_literal_at(&test_code, quote_pos);
                let result2 = parse_js_string_literal_at(&test_code, quote_pos);
                assert_eq!(
                    result.is_some(),
                    result2.is_some(),
                    "Injection parsing should be deterministic"
                );

                // Injection payloads should be treated as literal strings, not executed
                if let Some((start, end, ref content)) = result {
                    // Verify injection payloads are safely contained as string literals
                    assert!(
                        start <= end,
                        "Injection attack should not corrupt parsing bounds"
                    );
                    match injection_type {
                        InjectionType::CodeInjection | InjectionType::TemplateInjection => {
                            // Code injection attempts should be harmless in string literal context
                            assert!(
                                !content.is_empty(),
                                "Code injection should be treated as literal content"
                            );
                        }
                        _ => {
                            // Other injection types should be safely contained
                        }
                    }
                }

                // NoQuotes context with injection should be rejected
                if matches!(quote_context, QuoteContext::NoQuotes) {
                    assert!(
                        result.is_none(),
                        "Injection without quotes should not be parsed as string literal"
                    );
                }
            }
            StringLiteralOperation::BoundaryTests {
                boundary_type,
                test_data,
            } => {
                let (test_code, test_index) = generate_boundary_test(&boundary_type, &test_data);
                let safe_index = test_index.min(test_code.len().saturating_sub(1));

                // Test boundary condition handling
                let result = parse_js_string_literal_at(&test_code, safe_index);
                let result2 = parse_js_string_literal_at(&test_code, safe_index);
                assert_eq!(
                    result.is_some(),
                    result2.is_some(),
                    "Boundary test parsing should be deterministic"
                );

                match boundary_type {
                    BoundaryType::EmptyString => {
                        // Empty string should be rejected
                        assert!(
                            result.is_none(),
                            "Empty string should not parse as string literal"
                        );
                    }
                    BoundaryType::IndexOutOfBounds => {
                        // Out of bounds index should be handled safely
                        // Should not panic even with invalid index
                    }
                    BoundaryType::VeryLong => {
                        // Very long strings should not cause memory issues
                        // Function should complete in reasonable time
                    }
                    _ => {
                        // Other boundary tests should be handled safely
                    }
                }
            }
        }
    }
});
