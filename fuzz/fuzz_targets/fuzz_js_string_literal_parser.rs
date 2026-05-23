//! Fuzz target for JavaScript string literal parsing in migration module.
//!
//! Tests JS string literal parser against malformed quotes, escape sequences,
//! unicode edge cases, nested quotes, and injection attacks. Critical boundary
//! for validating JavaScript code migration and parsing.

#![no_main]

use libfuzzer_sys::fuzz_target;
use arbitrary::{Arbitrary, Unstructured};

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
            UnicodeType::Surrogates => format!("{}\u{D83D}\u{DE00}", base), // Valid surrogate pair (emoji)
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
            InjectionType::TemplateInjection => format!("{}{{constructor.constructor('alert(1)')()}}", base),
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
        },
        BoundaryType::QuoteOnly => ("\"\"".to_string(), 0),
        BoundaryType::EscapeOnly => ("\\\\\\\\".to_string(), 0),
        BoundaryType::IndexOutOfBounds => (format!("prefix{}", test_data), 1000),
    }
}

fuzz_target!(|data: &[u8]| {
    let mut u = Unstructured::new(data);

    if let Ok(fuzz_input) = FuzzInput::arbitrary(&mut u) {
        match fuzz_input.operation {
            StringLiteralOperation::BasicStringLiteral { quote_type, content, quote_index } => {
                let quote = quote_type.to_char();
                let code = format!("prefix{}{}{}", quote, content, quote);
                let index = (quote_index as usize % code.len().max(1)).min(code.len().saturating_sub(1));
                let _ = parse_js_string_literal_at(&code, index);
            },
            StringLiteralOperation::EscapeSequences { quote_type, escapes, base_content } => {
                let quote = quote_type.to_char();
                let mut content = base_content;
                for escape in &escapes {
                    content.push_str(escape.to_string());
                }
                let code = format!("prefix{}{}{}", quote, content, quote);
                let quote_pos = code.find(quote).unwrap_or(0);
                let _ = parse_js_string_literal_at(&code, quote_pos);
            },
            StringLiteralOperation::MalformedQuotes { quote_patterns, content } => {
                let base_quote = '"';
                for pattern in &quote_patterns {
                    let malformed = pattern.apply(&content, base_quote);
                    let _ = parse_js_string_literal_at(&malformed, 0);
                }
            },
            StringLiteralOperation::UnicodeEdgeCases { unicode_type, base_string, quote_index } => {
                let unicode_content = unicode_type.generate_content(&base_string);
                let code = format!("prefix\"{}\"", unicode_content);
                let index = (quote_index as usize % code.len().max(1)).min(code.len().saturating_sub(1));
                let _ = parse_js_string_literal_at(&code, index);
            },
            StringLiteralOperation::InjectionAttempts { injection_type, payload, quote_context } => {
                let injection_payload = injection_type.generate_payload(&payload);
                let (test_code, quote_pos) = match quote_context {
                    QuoteContext::StartOfString => (format!("\"{}\"", injection_payload), 0),
                    QuoteContext::MiddleOfString => {
                        let code = format!("prefix\"{}\"", injection_payload);
                        let pos = code.find('"').unwrap_or(0);
                        (code, pos)
                    },
                    QuoteContext::EndOfString => {
                        let code = format("{}\"{}\"", injection_payload, payload);
                        let pos = code.rfind('"').unwrap_or(0);
                        (code, pos)
                    },
                    QuoteContext::NoQuotes => (injection_payload, 0),
                };
                let _ = parse_js_string_literal_at(&test_code, quote_pos);
            },
            StringLiteralOperation::BoundaryTests { boundary_type, test_data } => {
                let (test_code, test_index) = generate_boundary_test(&boundary_type, &test_data);
                let safe_index = test_index.min(test_code.len().saturating_sub(1));
                let _ = parse_js_string_literal_at(&test_code, safe_index);
            },
        }
    }
});