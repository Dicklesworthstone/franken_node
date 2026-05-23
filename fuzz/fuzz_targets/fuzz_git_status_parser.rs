//! Fuzz target for git status output parsing.
//!
//! Tests git status parser robustness against malformed status output,
//! unicode edge cases, line format variations, and malicious input.
//! Critical boundary for validating external git command output.

#![no_main]

use libfuzzer_sys::fuzz_target;
use arbitrary::{Arbitrary, Unstructured};

#[derive(Debug, Clone)]
struct GitStatusResult {
    modified_count: u32,
    untracked_count: u32,
    conflicted_count: u32,
    staged_count: u32,
}

// Reimplemented parse_git_status function for fuzzing
fn parse_git_status(status_output: &str) -> Result<GitStatusResult, String> {
    let mut result = GitStatusResult {
        modified_count: 0,
        untracked_count: 0,
        conflicted_count: 0,
        staged_count: 0,
    };

    for line in status_output.lines() {
        if line.len() < 2 {
            continue;
        }

        let index_status = line.chars().next();
        let worktree_status = line.chars().nth(1);

        match (index_status, worktree_status) {
            (Some(' '), Some('M')) => {
                result.modified_count = result.modified_count.saturating_add(1)
            }
            (Some('?'), Some('?')) => {
                result.untracked_count = result.untracked_count.saturating_add(1)
            }
            (Some('U'), _) | (_, Some('U')) => {
                result.conflicted_count = result.conflicted_count.saturating_add(1)
            }
            (Some(c), _) if c != ' ' && c != '?' => {
                result.staged_count = result.staged_count.saturating_add(1)
            }
            _ => {}
        }
    }

    Ok(result)
}

#[derive(Debug, Clone, Arbitrary)]
struct FuzzInput {
    operation: GitStatusParsingOperation,
}

#[derive(Debug, Clone, Arbitrary)]
enum GitStatusParsingOperation {
    SingleStatus(GitStatusInput),
    MultipleLines {
        lines: Vec<GitStatusInput>,
        separator: LineSeparator,
    },
    EdgeCases {
        base_input: GitStatusInput,
        transformations: Vec<StatusTransformation>,
    },
    MaliciousInputs {
        attack_type: AttackType,
        payload: String,
    },
    UnicodeEdgeCases {
        base: String,
        unicode_variants: Vec<UnicodeVariant>,
    },
}

#[derive(Debug, Clone, Arbitrary)]
enum AttackType {
    BufferOverflow,
    FormatString,
    ControlChars,
    NullBytes,
    LongLines,
    DeepNesting,
}

#[derive(Debug, Clone, Arbitrary)]
enum UnicodeVariant {
    Emoji,
    HighSurrogates,
    NonAscii,
    Combining,
    Rtl,
    Zalgo,
}

#[derive(Debug, Clone, Arbitrary)]
enum LineSeparator {
    Unix,
    Windows,
    Mac,
    Mixed,
    Custom(char),
}

#[derive(Debug, Clone, Arbitrary)]
struct GitStatusInput {
    index_status: char,
    worktree_status: char,
    filename: String,
}

#[derive(Debug, Clone, Arbitrary)]
enum StatusTransformation {
    TruncateAt(u8),
    AddControlChars,
    AddNullBytes,
    RepeatLine(u8),
    AddInvalidUtf8,
    MixCaseCharacters,
    AddExtraSpaces,
    SwapStatusChars,
}

impl GitStatusInput {
    fn to_line(&self) -> String {
        format!("{}{} {}", self.index_status, self.worktree_status, self.filename)
    }
}

impl LineSeparator {
    fn to_string(&self) -> &str {
        match self {
            LineSeparator::Unix => "\n",
            LineSeparator::Windows => "\r\n",
            LineSeparator::Mac => "\r",
            LineSeparator::Mixed => "\n\r\n",
            LineSeparator::Custom(_) => "\n", // Fallback to unix for custom
        }
    }
}

impl UnicodeVariant {
    fn apply(&self, base: &str) -> String {
        match self {
            UnicodeVariant::Emoji => format!("{}🔥💥⚠️", base),
            UnicodeVariant::HighSurrogates => format!("{}\u{10000}\u{10001}", base),
            UnicodeVariant::NonAscii => format!("{}ñ€αβγδ", base),
            UnicodeVariant::Combining => format!("{}a\u{0300}\u{0301}", base),
            UnicodeVariant::Rtl => format!("{}\u{202E}abc\u{202D}", base),
            UnicodeVariant::Zalgo => format!("{}z̴̡̢̬̘̰̱̻̘̟̞̼̯̝͙̹͍̹͕̟͌̽̊̿a̸̡̨̞̰̝̲̤̲̤̰̝̞̰̝̞l̸̡̨̞̰̝̲̤̲̤̰̝̞̰̝̞g̸̡̨̞̰̝̲̤̲̤̰̝̞̰̝̞o̸̡̨̞̰̝̲̤̲̤̰̝̞̰̝̞", base),
        }
    }
}

fn apply_transformations(input: &GitStatusInput, transformations: &[StatusTransformation]) -> String {
    let mut result = input.to_line();

    for transform in transformations {
        match transform {
            StatusTransformation::TruncateAt(n) => {
                let len = (*n as usize).min(result.len());
                result.truncate(len);
            },
            StatusTransformation::AddControlChars => {
                result.push_str("\x00\x01\x02\x03\x04\x05\x06\x07\x08\x0B\x0C\x0E\x0F");
            },
            StatusTransformation::AddNullBytes => {
                result.push('\0');
                result.push_str("after_null");
            },
            StatusTransformation::RepeatLine(n) => {
                let original = result.clone();
                for _ in 0..(*n as usize).min(10) {
                    result.push('\n');
                    result.push_str(&original);
                }
            },
            StatusTransformation::AddInvalidUtf8 => {
                // Simulate invalid UTF-8 by adding replacement chars
                result.push('\u{FFFD}');
            },
            StatusTransformation::MixCaseCharacters => {
                result = result.chars().enumerate().map(|(i, c)| {
                    if i % 2 == 0 { c.to_uppercase().collect::<String>() }
                    else { c.to_lowercase().collect::<String>() }
                }).collect();
            },
            StatusTransformation::AddExtraSpaces => {
                result = format!("    {}    ", result);
            },
            StatusTransformation::SwapStatusChars => {
                if result.len() >= 2 {
                    let mut chars: Vec<char> = result.chars().collect();
                    if chars.len() >= 2 {
                        chars.swap(0, 1);
                        result = chars.into_iter().collect();
                    }
                }
            },
        }
    }

    result
}

fuzz_target!(|data: &[u8]| {
    let mut u = Unstructured::new(data);

    if let Ok(fuzz_input) = FuzzInput::arbitrary(&mut u) {
        match fuzz_input.operation {
            GitStatusParsingOperation::SingleStatus(status_input) => {
                let line = status_input.to_line();
                let _ = parse_git_status(&line);
            },
            GitStatusParsingOperation::MultipleLines { lines, separator } => {
                let sep = separator.to_string();
                let combined = lines.iter()
                    .map(|line| line.to_line())
                    .collect::<Vec<_>>()
                    .join(sep);
                let _ = parse_git_status(&combined);
            },
            GitStatusParsingOperation::EdgeCases { base_input, transformations } => {
                let transformed = apply_transformations(&base_input, &transformations);
                let _ = parse_git_status(&transformed);
            },
            GitStatusParsingOperation::MaliciousInputs { attack_type, payload } => {
                let malicious = match attack_type {
                    AttackType::BufferOverflow => "A".repeat(100000),
                    AttackType::FormatString => format!("{}%s%n%x", payload),
                    AttackType::ControlChars => format!("{}\x1b[31m\x07\x08\x0c", payload),
                    AttackType::NullBytes => format!("{}\0\0\0evil", payload),
                    AttackType::LongLines => format!("{}{}", payload, "X".repeat(10000)),
                    AttackType::DeepNesting => "\n".repeat(1000) + &payload,
                };
                let _ = parse_git_status(&malicious);
            },
            GitStatusParsingOperation::UnicodeEdgeCases { base, unicode_variants } => {
                let mut test_input = base;
                for variant in &unicode_variants {
                    test_input = variant.apply(&test_input);
                }
                let _ = parse_git_status(&test_input);
            },
        }
    }
});