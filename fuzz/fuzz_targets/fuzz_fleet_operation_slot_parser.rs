//! Fuzz target for fleet operation slot parsing in quarantine API.
//!
//! Tests operation ID parsing against malformed formats, hex injection,
//! integer overflow, format confusion, and edge cases in epoch/sequence
//! extraction. Critical security boundary for fleet operation validation.

#![no_main]

use libfuzzer_sys::fuzz_target;
use arbitrary::{Arbitrary, Unstructured};

// Mock OperationSlot for fuzzing
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OperationSlot {
    pub epoch: u64,
    pub sequence: u64,
}

// Reimplemented function for fuzzing
fn parse_operation_slot(operation_id: &str) -> Option<OperationSlot> {
    let raw = operation_id.strip_prefix("fleet-op-")?;
    match raw.split_once('-') {
        Some((epoch, sequence)) => Some(OperationSlot {
            epoch: u64::from_str_radix(epoch, 16).ok()?,
            sequence: u64::from_str_radix(sequence, 16).ok()?,
        }),
        None => Some(OperationSlot {
            epoch: 0,
            sequence: raw.parse().ok()?,
        }),
    }
}

#[derive(Debug, Clone, Arbitrary)]
struct FuzzInput {
    operation: FleetOperationParseTest,
}

#[derive(Debug, Clone, Arbitrary)]
enum FleetOperationParseTest {
    ValidFormat {
        epoch: u64,
        sequence: u64,
        format_variant: FormatVariant,
    },
    InvalidPrefix {
        prefix: String,
        payload: String,
    },
    HexInjection {
        epoch_str: String,
        sequence_str: String,
        injection_type: HexInjectionType,
    },
    IntegerAttacks {
        attack_type: IntegerAttackType,
        target: IntegerTarget,
    },
    FormatConfusion {
        confusion_type: FormatConfusionType,
        raw_input: String,
    },
    EdgeCases {
        edge_type: EdgeCaseType,
        modifier: String,
    },
    LengthAttacks {
        attack_type: LengthAttackType,
        base_format: String,
    },
    EncodingAttacks {
        encoding_type: EncodingAttackType,
        base_value: u64,
    },
}

#[derive(Debug, Clone, Arbitrary)]
enum FormatVariant {
    Standard,
    Uppercase,
    Mixed,
    PaddedZeros,
}

#[derive(Debug, Clone, Arbitrary)]
enum HexInjectionType {
    NonHexChars,
    UnicodeDigits,
    OverflowPrefix,
    NegativeSign,
    ScientificNotation,
    FloatingPoint,
    Base64Confusion,
}

#[derive(Debug, Clone, Arbitrary)]
enum IntegerAttackType {
    MaxU64,
    MaxU64Plus1,
    NearOverflow,
    LeadingZeros,
    SignedOverflow,
    DoubleMaxValue,
}

#[derive(Debug, Clone, Arbitrary)]
enum IntegerTarget {
    Epoch,
    Sequence,
    Both,
}

#[derive(Debug, Clone, Arbitrary)]
enum FormatConfusionType {
    MissingDash,
    MultipleDashes,
    TrailingDash,
    LeadingDash,
    EmptyComponents,
    OnlyPrefix,
    NoPrefix,
    PartialPrefix,
}

#[derive(Debug, Clone, Arbitrary)]
enum EdgeCaseType {
    Empty,
    OnlyPrefix,
    OnlyDash,
    Unicode,
    Whitespace,
    ControlChars,
    NullBytes,
}

#[derive(Debug, Clone, Arbitrary)]
enum LengthAttackType {
    VeryLong,
    MaxLength,
    EmptyAfterPrefix,
    SingleChar,
    RepeatedPatterns,
}

#[derive(Debug, Clone, Arbitrary)]
enum EncodingAttackType {
    UrlEncoded,
    DoubleEncoded,
    MixedCase,
    WithWhitespace,
    WithSeparators,
}

impl FormatVariant {
    fn apply(&self, epoch: u64, sequence: u64) -> String {
        match self {
            FormatVariant::Standard => format!("fleet-op-{:016x}-{:016x}", epoch, sequence),
            FormatVariant::Uppercase => format!("fleet-op-{:016X}-{:016X}", epoch, sequence),
            FormatVariant::Mixed => {
                let epoch_str = format!("{:016x}", epoch);
                let sequence_str = format!("{:016X}", sequence);
                format!("fleet-op-{}-{}", epoch_str, sequence_str)
            },
            FormatVariant::PaddedZeros => format!("fleet-op-{:020x}-{:020x}", epoch, sequence),
        }
    }
}

impl HexInjectionType {
    fn inject(&self, epoch_str: &str, sequence_str: &str) -> String {
        match self {
            HexInjectionType::NonHexChars => {
                format!("fleet-op-{}G-{}Z", epoch_str, sequence_str)
            },
            HexInjectionType::UnicodeDigits => {
                format!("fleet-op-{}１-{}２", epoch_str, sequence_str)  // Fullwidth digits
            },
            HexInjectionType::OverflowPrefix => {
                format!("fleet-op-0x{}-0x{}", epoch_str, sequence_str)
            },
            HexInjectionType::NegativeSign => {
                format!("fleet-op--{}-{}", epoch_str, sequence_str)
            },
            HexInjectionType::ScientificNotation => {
                format!("fleet-op-{}e10-{}", epoch_str, sequence_str)
            },
            HexInjectionType::FloatingPoint => {
                format!("fleet-op-{}.5-{}", epoch_str, sequence_str)
            },
            HexInjectionType::Base64Confusion => {
                // Mix hex with base64-like chars
                format!("fleet-op-{}==-{}+/", epoch_str, sequence_str)
            },
        }
    }
}

impl IntegerAttackType {
    fn generate_epoch(&self) -> String {
        match self {
            IntegerAttackType::MaxU64 => "ffffffffffffffff".to_string(),
            IntegerAttackType::MaxU64Plus1 => "10000000000000000".to_string(),
            IntegerAttackType::NearOverflow => "fffffffffffffffe".to_string(),
            IntegerAttackType::LeadingZeros => "0000000000000001".to_string(),
            IntegerAttackType::SignedOverflow => "8000000000000000".to_string(),
            IntegerAttackType::DoubleMaxValue => "1ffffffffffffffff".to_string(),
        }
    }

    fn generate_sequence(&self) -> String {
        match self {
            IntegerAttackType::MaxU64 => "ffffffffffffffff".to_string(),
            IntegerAttackType::MaxU64Plus1 => "10000000000000000".to_string(),
            IntegerAttackType::NearOverflow => "fffffffffffffffd".to_string(),
            IntegerAttackType::LeadingZeros => "0000000000000002".to_string(),
            IntegerAttackType::SignedOverflow => "7fffffffffffffff".to_string(),
            IntegerAttackType::DoubleMaxValue => "1fffffffffffffffe".to_string(),
        }
    }
}

impl FormatConfusionType {
    fn apply(&self, raw_input: &str) -> String {
        match self {
            FormatConfusionType::MissingDash => format!("fleet-op-{}", raw_input.replace('-', "")),
            FormatConfusionType::MultipleDashes => format!("fleet-op-{}", raw_input.replace('-', "---")),
            FormatConfusionType::TrailingDash => format!("fleet-op-{}-", raw_input),
            FormatConfusionType::LeadingDash => format!("fleet-op--{}", raw_input),
            FormatConfusionType::EmptyComponents => "fleet-op--".to_string(),
            FormatConfusionType::OnlyPrefix => "fleet-op-".to_string(),
            FormatConfusionType::NoPrefix => raw_input.to_string(),
            FormatConfusionType::PartialPrefix => format!("fleet-{}", raw_input),
        }
    }
}

impl EdgeCaseType {
    fn generate(&self, modifier: &str) -> String {
        match self {
            EdgeCaseType::Empty => String::new(),
            EdgeCaseType::OnlyPrefix => "fleet-op-".to_string(),
            EdgeCaseType::OnlyDash => "-".to_string(),
            EdgeCaseType::Unicode => format!("fleet-op-{}\u{1F4A5}{}", modifier, modifier),  // Explosion emoji
            EdgeCaseType::Whitespace => format!("fleet-op- {} - {} ", modifier, modifier),
            EdgeCaseType::ControlChars => format!("fleet-op-\x00{}\x1F{}", modifier, modifier),
            EdgeCaseType::NullBytes => format!("fleet-op-{}\0{}", modifier, modifier),
        }
    }
}

impl LengthAttackType {
    fn generate(&self, base_format: &str) -> String {
        match self {
            LengthAttackType::VeryLong => {
                format!("fleet-op-{}-{}", "a".repeat(10000), "b".repeat(10000))
            },
            LengthAttackType::MaxLength => {
                format!("fleet-op-{}-{}", "f".repeat(1000), "e".repeat(1000))
            },
            LengthAttackType::EmptyAfterPrefix => "fleet-op-".to_string(),
            LengthAttackType::SingleChar => "fleet-op-a".to_string(),
            LengthAttackType::RepeatedPatterns => {
                format!("fleet-op-{}", "abc-".repeat(1000))
            },
        }
    }
}

impl EncodingAttackType {
    fn apply(&self, base_value: u64) -> String {
        let hex_str = format!("{:x}", base_value);
        match self {
            EncodingAttackType::UrlEncoded => {
                format!("fleet-op-%7B{hex_str}%7D-%7B{hex_str}%7D")
            },
            EncodingAttackType::DoubleEncoded => {
                format!("fleet-op-%257B{hex_str}%257D-%257B{hex_str}%257D")
            },
            EncodingAttackType::MixedCase => {
                let mixed: String = hex_str.chars().enumerate().map(|(i, c)| {
                    if i % 2 == 0 { c.to_uppercase().collect() } else { c.to_string() }
                }).collect();
                format!("fleet-op-{mixed}-{mixed}")
            },
            EncodingAttackType::WithWhitespace => {
                format!("fleet-op-  {hex_str}  -  {hex_str}  ")
            },
            EncodingAttackType::WithSeparators => {
                format!("fleet-op-{}_{}:{hex_str}", hex_str, hex_str)
            },
        }
    }
}

fuzz_target!(|data: &[u8]| {
    let mut u = Unstructured::new(data);

    if let Ok(fuzz_input) = FuzzInput::arbitrary(&mut u) {
        match fuzz_input.operation {
            FleetOperationParseTest::ValidFormat { epoch, sequence, format_variant } => {
                let operation_id = format_variant.apply(epoch, sequence);
                let _ = parse_operation_slot(&operation_id);
            },
            FleetOperationParseTest::InvalidPrefix { prefix, payload } => {
                let operation_id = format!("{}{}", prefix, payload);
                let _ = parse_operation_slot(&operation_id);
            },
            FleetOperationParseTest::HexInjection { epoch_str, sequence_str, injection_type } => {
                let operation_id = injection_type.inject(&epoch_str, &sequence_str);
                let _ = parse_operation_slot(&operation_id);
            },
            FleetOperationParseTest::IntegerAttacks { attack_type, target } => {
                let operation_id = match target {
                    IntegerTarget::Epoch => {
                        format!("fleet-op-{}-deadbeef", attack_type.generate_epoch())
                    },
                    IntegerTarget::Sequence => {
                        format!("fleet-op-deadbeef-{}", attack_type.generate_sequence())
                    },
                    IntegerTarget::Both => {
                        format!("fleet-op-{}-{}", attack_type.generate_epoch(), attack_type.generate_sequence())
                    },
                };
                let _ = parse_operation_slot(&operation_id);
            },
            FleetOperationParseTest::FormatConfusion { confusion_type, raw_input } => {
                let operation_id = confusion_type.apply(&raw_input);
                let _ = parse_operation_slot(&operation_id);
            },
            FleetOperationParseTest::EdgeCases { edge_type, modifier } => {
                let operation_id = edge_type.generate(&modifier);
                let _ = parse_operation_slot(&operation_id);
            },
            FleetOperationParseTest::LengthAttacks { attack_type, base_format } => {
                let operation_id = attack_type.generate(&base_format);
                let _ = parse_operation_slot(&operation_id);
            },
            FleetOperationParseTest::EncodingAttacks { encoding_type, base_value } => {
                let operation_id = encoding_type.apply(base_value);
                let _ = parse_operation_slot(&operation_id);
            },
        }
    }
});