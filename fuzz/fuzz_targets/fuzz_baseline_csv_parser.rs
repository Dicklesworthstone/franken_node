//! Fuzz target for baseline CSV parsing in profile tuning harness.
//!
//! Tests CSV parser robustness against malformed CSV data, numeric overflow,
//! delimiter confusion, empty fields, and injection attacks. Critical boundary
//! for validating performance baseline data input.

#![no_main]

use libfuzzer_sys::fuzz_target;
use arbitrary::{Arbitrary, Unstructured};

#[derive(Debug, Clone)]
pub struct BaselineRow {
    pub class_id: String,
    pub symbol_size_bytes: u64,
    pub overhead_ratio: f64,
    pub fetch_priority: String,
    pub prefetch_policy: String,
}

// Reimplemented function for fuzzing
pub fn parse_baseline_csv(csv: &str) -> Vec<BaselineRow> {
    csv.lines()
        .skip(1) // skip header
        .filter(|line| !line.trim().is_empty())
        .filter_map(|line| {
            let cols: Vec<&str> = line.split(',').collect();
            if cols.len() >= 5 {
                Some(BaselineRow {
                    class_id: cols[0].trim().to_string(),
                    symbol_size_bytes: cols[1].trim().parse().unwrap_or(0),
                    overhead_ratio: cols[2]
                        .trim()
                        .parse::<f64>()
                        .ok()
                        .filter(|value| value.is_finite())
                        .unwrap_or(0.0),
                    fetch_priority: cols[3].trim().to_string(),
                    prefetch_policy: cols[4].trim().to_string(),
                })
            } else {
                None
            }
        })
        .collect()
}

#[derive(Debug, Clone, Arbitrary)]
struct FuzzInput {
    operation: CsvParsingOperation,
}

#[derive(Debug, Clone, Arbitrary)]
enum CsvParsingOperation {
    BasicCsv {
        rows: Vec<CsvRow>,
        headers: bool,
        delimiter: CsvDelimiter,
    },
    MalformedCsv {
        attack_type: CsvAttack,
        payload: String,
    },
    NumericEdgeCases {
        base_rows: Vec<CsvRow>,
        numeric_attacks: Vec<NumericAttack>,
    },
    DelimiterConfusion {
        content: String,
        delimiter_mix: Vec<char>,
    },
    InjectionAttempts {
        injection_type: InjectionType,
        target_field: FieldTarget,
        payload: String,
    },
}

#[derive(Debug, Clone, Arbitrary)]
enum CsvAttack {
    QuotingIssues,
    FieldOverflow,
    NewlineInjection,
    NullByteInjection,
    UnicodeNormalization,
    MemoryExhaustion,
}

#[derive(Debug, Clone, Arbitrary)]
enum NumericAttack {
    Overflow,
    Underflow,
    Infinity,
    NaN,
    Denormal,
    ScientificNotation,
    HexNotation,
}

#[derive(Debug, Clone, Arbitrary)]
enum InjectionType {
    CsvInjection,
    FormulaInjection,
    PathTraversal,
    CommandInjection,
    SqlInjection,
}

#[derive(Debug, Clone, Arbitrary)]
enum FieldTarget {
    ClassId,
    SymbolSize,
    OverheadRatio,
    FetchPriority,
    PrefetchPolicy,
}

#[derive(Debug, Clone, Arbitrary)]
enum CsvDelimiter {
    Comma,
    Semicolon,
    Tab,
    Pipe,
    Mixed,
}

#[derive(Debug, Clone, Arbitrary)]
struct CsvRow {
    class_id: String,
    symbol_size: String,
    overhead_ratio: String,
    fetch_priority: String,
    prefetch_policy: String,
}

impl CsvDelimiter {
    fn to_char(&self) -> char {
        match self {
            CsvDelimiter::Comma => ',',
            CsvDelimiter::Semicolon => ';',
            CsvDelimiter::Tab => '\t',
            CsvDelimiter::Pipe => '|',
            CsvDelimiter::Mixed => ',', // Default for mixed case
        }
    }
}

impl CsvRow {
    fn to_csv_line(&self, delimiter: &CsvDelimiter) -> String {
        let delim = delimiter.to_char();
        format!("{}{}{}{}{}{}{}{}{}",
            self.class_id, delim,
            self.symbol_size, delim,
            self.overhead_ratio, delim,
            self.fetch_priority, delim,
            self.prefetch_policy
        )
    }
}

fn generate_malformed_csv(attack_type: &CsvAttack, payload: &str) -> String {
    match attack_type {
        CsvAttack::QuotingIssues => {
            format!("\"class1\",\"123\",\"0.5\",\"high\",\"\"prefetch\"\"\n{},456,\"broken\"quote,low,none", payload)
        },
        CsvAttack::FieldOverflow => {
            let huge_field = "A".repeat(100000);
            format!("class1,{},0.5,high,prefetch\n{}", huge_field, payload)
        },
        CsvAttack::NewlineInjection => {
            format!("class1\n{}\n,123,0.5,high,prefetch", payload)
        },
        CsvAttack::NullByteInjection => {
            format!("class\0{}\0,123,0.5,high,prefetch", payload)
        },
        CsvAttack::UnicodeNormalization => {
            format!("class🔥{},123,0.5,high,prefetch", payload)
        },
        CsvAttack::MemoryExhaustion => {
            let huge_csv = format!("class1,123,0.5,high,prefetch\n").repeat(10000);
            format!("{}{}", huge_csv, payload)
        },
    }
}

fn generate_numeric_attack(attack: &NumericAttack) -> String {
    match attack {
        NumericAttack::Overflow => "999999999999999999999999999999",
        NumericAttack::Underflow => "-999999999999999999999999999999",
        NumericAttack::Infinity => "inf",
        NumericAttack::NaN => "nan",
        NumericAttack::Denormal => "1e-400",
        NumericAttack::ScientificNotation => "1.23e+100",
        NumericAttack::HexNotation => "0xDEADBEEF",
    }.to_string()
}

fn generate_injection_payload(injection_type: &InjectionType, payload: &str) -> String {
    match injection_type {
        InjectionType::CsvInjection => format!("=cmd|'/c calc'!{}", payload),
        InjectionType::FormulaInjection => format!("=SUM(1+1)*cmd|'/c calc'!{}", payload),
        InjectionType::PathTraversal => format!("../../../etc/passwd{}", payload),
        InjectionType::CommandInjection => format!("; ls -la; echo {}", payload),
        InjectionType::SqlInjection => format!("'; DROP TABLE users; --{}", payload),
    }
}

fuzz_target!(|data: &[u8]| {
    let mut u = Unstructured::new(data);

    if let Ok(fuzz_input) = FuzzInput::arbitrary(&mut u) {
        match fuzz_input.operation {
            CsvParsingOperation::BasicCsv { rows, headers, delimiter } => {
                let mut csv = if headers {
                    String::from("class_id,symbol_size_bytes,overhead_ratio,fetch_priority,prefetch_policy\n")
                } else {
                    String::new()
                };

                for row in &rows {
                    csv.push_str(&row.to_csv_line(&delimiter));
                    csv.push('\n');
                }

                let _ = parse_baseline_csv(&csv);
            },
            CsvParsingOperation::MalformedCsv { attack_type, payload } => {
                let malformed_csv = generate_malformed_csv(&attack_type, &payload);
                let _ = parse_baseline_csv(&malformed_csv);
            },
            CsvParsingOperation::NumericEdgeCases { base_rows, numeric_attacks } => {
                let header = "class_id,symbol_size_bytes,overhead_ratio,fetch_priority,prefetch_policy\n";
                let mut csv = String::from(header);

                for row in &base_rows {
                    csv.push_str(&row.to_csv_line(&CsvDelimiter::Comma));
                    csv.push('\n');
                }

                // Add numeric attack rows
                for attack in &numeric_attacks {
                    let attack_value = generate_numeric_attack(attack);
                    let attack_row = format!("attack_class,{},{},high,prefetch\n", attack_value, attack_value);
                    csv.push_str(&attack_row);
                }

                let _ = parse_baseline_csv(&csv);
            },
            CsvParsingOperation::DelimiterConfusion { content, delimiter_mix } => {
                let mut confused_content = content;
                for &delim in &delimiter_mix {
                    confused_content = confused_content.replace(',', &delim.to_string());
                }
                let _ = parse_baseline_csv(&confused_content);
            },
            CsvParsingOperation::InjectionAttempts { injection_type, target_field, payload } => {
                let injection_payload = generate_injection_payload(&injection_type, &payload);

                let (class_id, symbol_size, overhead_ratio, fetch_priority, prefetch_policy) = match target_field {
                    FieldTarget::ClassId => (injection_payload, "123".to_string(), "0.5".to_string(), "high".to_string(), "prefetch".to_string()),
                    FieldTarget::SymbolSize => ("class1".to_string(), injection_payload, "0.5".to_string(), "high".to_string(), "prefetch".to_string()),
                    FieldTarget::OverheadRatio => ("class1".to_string(), "123".to_string(), injection_payload, "high".to_string(), "prefetch".to_string()),
                    FieldTarget::FetchPriority => ("class1".to_string(), "123".to_string(), "0.5".to_string(), injection_payload, "prefetch".to_string()),
                    FieldTarget::PrefetchPolicy => ("class1".to_string(), "123".to_string(), "0.5".to_string(), "high".to_string(), injection_payload),
                };

                let csv = format!("class_id,symbol_size_bytes,overhead_ratio,fetch_priority,prefetch_policy\n{},{},{},{},{}\n",
                    class_id, symbol_size, overhead_ratio, fetch_priority, prefetch_policy);

                let _ = parse_baseline_csv(&csv);
            },
        }
    }
});