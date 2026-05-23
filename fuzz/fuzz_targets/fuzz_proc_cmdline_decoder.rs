//! Fuzz target for proc cmdline decoder in resource governor.
//!
//! Tests decode_proc_cmdline() against malformed cmdline formats, null byte
//! injection, unicode attacks, buffer boundary conditions, and edge cases.
//! Critical boundary for process command line parsing in resource governance.

#![no_main]

use libfuzzer_sys::fuzz_target;
use arbitrary::{Arbitrary, Unstructured};

// Reimplemented function for fuzzing
fn decode_proc_cmdline(raw: &[u8]) -> String {
    raw.split(|byte| *byte == 0)
        .filter(|part| !part.is_empty())
        .map(|part| String::from_utf8_lossy(part))
        .collect::<Vec<_>>()
        .join(" ")
}

#[derive(Debug, Clone, Arbitrary)]
struct FuzzInput {
    operation: ProcCmdlineDecodeTest,
}

#[derive(Debug, Clone, Arbitrary)]
enum ProcCmdlineDecodeTest {
    ValidCmdlines {
        args: Vec<String>,
        separator_variant: SeparatorVariant,
    },
    NullByteAttacks {
        attack_type: NullByteAttackType,
        base_args: Vec<String>,
    },
    BoundaryConditions {
        boundary_type: BoundaryType,
        size: u16,
    },
    UnicodeAttacks {
        unicode_type: UnicodeAttackType,
        payload: String,
    },
    InjectionAttacks {
        injection_type: InjectionType,
        target_arg: String,
    },
    EdgeCases {
        edge_type: EdgeCaseType,
        repetition: u8,
    },
    EncodingTests {
        encoding_type: EncodingType,
        base_data: Vec<u8>,
    },
    FormatConfusion {
        confusion_type: FormatConfusionType,
        modifier: u8,
    },
}

#[derive(Debug, Clone, Arbitrary)]
enum SeparatorVariant {
    Standard,
    Multiple,
    Leading,
    Trailing,
    Embedded,
    Mixed,
}

#[derive(Debug, Clone, Arbitrary)]
enum NullByteAttackType {
    SingleNull,
    MultipleNulls,
    ConsecutiveNulls,
    NullAtStart,
    NullAtEnd,
    NullInMiddle,
    OnlyNulls,
    NullEscape,
}

#[derive(Debug, Clone, Arbitrary)]
enum BoundaryType {
    Empty,
    SingleByte,
    TwoByte,
    Tiny,
    Medium,
    Large,
    Massive,
    PowerOfTwo,
}

#[derive(Debug, Clone, Arbitrary)]
enum UnicodeAttackType {
    InvalidUtf8,
    Homoglyphs,
    RightToLeft,
    CombiningChars,
    ZeroWidth,
    Normalization,
    BidiOverride,
    FullwidthChars,
    ControlChars,
}

#[derive(Debug, Clone, Arbitrary)]
enum InjectionType {
    ShellMetaChars,
    PathTraversal,
    CommandInjection,
    FormatString,
    SqlInjection,
    XssPayload,
    RegexEscape,
    BufferOverflow,
}

#[derive(Debug, Clone, Arbitrary)]
enum EdgeCaseType {
    AllZeros,
    AllOnes,
    AlternatingBytes,
    IncrementingBytes,
    DecrementingBytes,
    RandomPattern,
    SpecialValues,
    RepeatedPattern,
}

#[derive(Debug, Clone, Arbitrary)]
enum EncodingType {
    ValidUtf8,
    InvalidUtf8,
    MixedEncoding,
    Latin1,
    Windows1252,
    BinaryData,
    AsciiOnly,
}

#[derive(Debug, Clone, Arbitrary)]
enum FormatConfusionType {
    SpaceDelimited,
    TabDelimited,
    NewlineDelimited,
    JsonLike,
    QuotedArgs,
    EscapedChars,
    MixedDelimiters,
}

impl SeparatorVariant {
    fn apply(&self, args: &[String]) -> Vec<u8> {
        match self {
            SeparatorVariant::Standard => {
                args.iter()
                    .flat_map(|arg| [arg.as_bytes(), &[0]].concat())
                    .collect()
            },
            SeparatorVariant::Multiple => {
                args.iter()
                    .flat_map(|arg| [arg.as_bytes(), &[0, 0]].concat())
                    .collect()
            },
            SeparatorVariant::Leading => {
                let mut result = vec![0];
                for arg in args {
                    result.extend_from_slice(arg.as_bytes());
                    result.push(0);
                }
                result
            },
            SeparatorVariant::Trailing => {
                let mut result = Vec::new();
                for arg in args {
                    result.extend_from_slice(arg.as_bytes());
                    result.push(0);
                }
                result.extend_from_slice(&[0, 0, 0]);
                result
            },
            SeparatorVariant::Embedded => {
                args.iter()
                    .flat_map(|arg| {
                        let mid = arg.len() / 2;
                        [&arg.as_bytes()[..mid], &[0], &arg.as_bytes()[mid..], &[0]].concat()
                    })
                    .collect()
            },
            SeparatorVariant::Mixed => {
                let mut result = Vec::new();
                for (i, arg) in args.iter().enumerate() {
                    result.extend_from_slice(arg.as_bytes());
                    match i % 3 {
                        0 => result.push(0),
                        1 => result.extend_from_slice(&[0, 0]),
                        _ => result.extend_from_slice(&[0, 0, 0]),
                    }
                }
                result
            },
        }
    }
}

impl NullByteAttackType {
    fn generate(&self, base_args: &[String]) -> Vec<u8> {
        match self {
            NullByteAttackType::SingleNull => vec![0],
            NullByteAttackType::MultipleNulls => vec![0, 0, 0, 0, 0],
            NullByteAttackType::ConsecutiveNulls => {
                let mut result = Vec::new();
                for arg in base_args {
                    result.extend_from_slice(arg.as_bytes());
                    result.extend_from_slice(&[0, 0, 0, 0]);
                }
                result
            },
            NullByteAttackType::NullAtStart => {
                let mut result = vec![0, 0, 0];
                for arg in base_args {
                    result.extend_from_slice(arg.as_bytes());
                    result.push(0);
                }
                result
            },
            NullByteAttackType::NullAtEnd => {
                let mut result = Vec::new();
                for arg in base_args {
                    result.extend_from_slice(arg.as_bytes());
                    result.push(0);
                }
                result.extend_from_slice(&[0, 0, 0, 0]);
                result
            },
            NullByteAttackType::NullInMiddle => {
                base_args.iter()
                    .flat_map(|arg| {
                        let mid = arg.len() / 2;
                        [&arg.as_bytes()[..mid], &[0, 0], &arg.as_bytes()[mid..], &[0]].concat()
                    })
                    .collect()
            },
            NullByteAttackType::OnlyNulls => vec![0; 100],
            NullByteAttackType::NullEscape => {
                let mut result = Vec::new();
                for arg in base_args {
                    for byte in arg.as_bytes() {
                        result.push(*byte);
                        if *byte == b'\\' {
                            result.extend_from_slice(&[b'0', 0]);
                        }
                    }
                    result.push(0);
                }
                result
            },
        }
    }
}

impl BoundaryType {
    fn generate(&self, size: u16) -> Vec<u8> {
        let len = match self {
            BoundaryType::Empty => 0,
            BoundaryType::SingleByte => 1,
            BoundaryType::TwoByte => 2,
            BoundaryType::Tiny => (size % 10) as usize,
            BoundaryType::Medium => (size % 1000) as usize,
            BoundaryType::Large => (size % 10000) as usize,
            BoundaryType::Massive => 100000,
            BoundaryType::PowerOfTwo => 1 << (size % 16),
        };

        if len == 0 {
            Vec::new()
        } else {
            let pattern = b"arg";
            let mut result = Vec::new();
            let mut pos = 0;
            while pos < len {
                let remaining = len - pos;
                if remaining >= pattern.len() + 1 {
                    result.extend_from_slice(pattern);
                    result.push(0);
                    pos += pattern.len() + 1;
                } else if remaining > 1 {
                    result.extend_from_slice(&pattern[..remaining - 1]);
                    result.push(0);
                    pos = len;
                } else {
                    result.push(0);
                    pos = len;
                }
            }
            result
        }
    }
}

impl UnicodeAttackType {
    fn inject(&self, payload: &str) -> Vec<u8> {
        let attack_data = match self {
            UnicodeAttackType::InvalidUtf8 => vec![0xC0, 0x80, 0xFE, 0xFF, 0xED, 0xA0, 0x80],
            UnicodeAttackType::Homoglyphs => "Αrg".as_bytes().to_vec(), // Greek Alpha
            UnicodeAttackType::RightToLeft => format!("arg\u{202E}{}", payload).as_bytes().to_vec(),
            UnicodeAttackType::CombiningChars => "arg\u{0300}\u{0301}".as_bytes().to_vec(),
            UnicodeAttackType::ZeroWidth => format!("arg\u{200B}\u{FEFF}{}", payload).as_bytes().to_vec(),
            UnicodeAttackType::Normalization => "café".as_bytes().to_vec(), // NFC vs NFD
            UnicodeAttackType::BidiOverride => format!("\u{202D}arg{}\u{202C}", payload).as_bytes().to_vec(),
            UnicodeAttackType::FullwidthChars => "ａｒｇ".as_bytes().to_vec(),
            UnicodeAttackType::ControlChars => {
                let mut result = b"arg".to_vec();
                result.extend_from_slice(&[0x01, 0x02, 0x03, 0x1F, 0x7F]);
                result
            },
        };

        let mut result = attack_data;
        result.push(0);
        result.extend_from_slice(payload.as_bytes());
        result.push(0);
        result
    }
}

impl InjectionType {
    fn inject(&self, target_arg: &str) -> Vec<u8> {
        let injection = match self {
            InjectionType::ShellMetaChars => format!("{};|&<>$()`", target_arg),
            InjectionType::PathTraversal => format!("{}../../../etc/passwd", target_arg),
            InjectionType::CommandInjection => format!("{};rm -rf /", target_arg),
            InjectionType::FormatString => format!("{}%s%x%p%n", target_arg),
            InjectionType::SqlInjection => format!("{}'; DROP TABLE processes; --", target_arg),
            InjectionType::XssPayload => format!("{}<script>alert(1)</script>", target_arg),
            InjectionType::RegexEscape => format!("{}.*+?{{}}[]()^$", target_arg),
            InjectionType::BufferOverflow => format!("{}{}", target_arg, "A".repeat(10000)),
        };

        let mut result = injection.as_bytes().to_vec();
        result.push(0);
        result
    }
}

impl EdgeCaseType {
    fn generate(&self, repetition: u8) -> Vec<u8> {
        let size = (repetition as usize % 100) + 1;
        match self {
            EdgeCaseType::AllZeros => vec![0; size],
            EdgeCaseType::AllOnes => vec![0xFF; size],
            EdgeCaseType::AlternatingBytes => {
                (0..size).map(|i| if i % 2 == 0 { 0xAA } else { 0x55 }).collect()
            },
            EdgeCaseType::IncrementingBytes => {
                (0..size).map(|i| (i % 256) as u8).collect()
            },
            EdgeCaseType::DecrementingBytes => {
                (0..size).map(|i| (255 - (i % 256)) as u8).collect()
            },
            EdgeCaseType::RandomPattern => {
                (0..size).map(|i| ((i * 17 + 13) % 256) as u8).collect()
            },
            EdgeCaseType::SpecialValues => {
                let special = [0x00, 0x01, 0x20, 0x7F, 0x80, 0xFE, 0xFF];
                special.iter().cycle().take(size).copied().collect()
            },
            EdgeCaseType::RepeatedPattern => {
                b"cmd\0"
                    .iter()
                    .cycle()
                    .take(size)
                    .copied()
                    .collect()
            },
        }
    }
}

impl EncodingType {
    fn apply(&self, base_data: &[u8]) -> Vec<u8> {
        match self {
            EncodingType::ValidUtf8 => {
                let utf8_args = ["程序", "🚀", "测试", "args"];
                utf8_args
                    .iter()
                    .flat_map(|arg| [arg.as_bytes(), &[0]].concat())
                    .collect()
            },
            EncodingType::InvalidUtf8 => {
                [base_data, &[0xC0, 0x80, 0xFE, 0xFF, 0]].concat()
            },
            EncodingType::MixedEncoding => {
                [b"valid", &[0], &[0xC0, 0x80], &[0], b"more", &[0]].concat()
            },
            EncodingType::Latin1 => {
                // Latin-1 encoded text
                [&[0xE9, 0xE8, 0xE7], &[0], b"latin1", &[0]].concat()
            },
            EncodingType::Windows1252 => {
                // Windows-1252 specific bytes
                [&[0x80, 0x81, 0x8D], &[0], b"win1252", &[0]].concat()
            },
            EncodingType::BinaryData => {
                [&[0xDE, 0xAD, 0xBE, 0xEF], &[0], &[0xCA, 0xFE, 0xBA, 0xBE], &[0]].concat()
            },
            EncodingType::AsciiOnly => {
                [b"ascii", &[0], b"only", &[0], b"args", &[0]].concat()
            },
        }
    }
}

impl FormatConfusionType {
    fn apply(&self, modifier: u8) -> Vec<u8> {
        match self {
            FormatConfusionType::SpaceDelimited => {
                b"prog arg1 arg2 arg3".to_vec()
            },
            FormatConfusionType::TabDelimited => {
                b"prog\targ1\targ2\targ3".to_vec()
            },
            FormatConfusionType::NewlineDelimited => {
                b"prog\narg1\narg2\narg3".to_vec()
            },
            FormatConfusionType::JsonLike => {
                br#"{"cmd":"prog","args":["arg1","arg2"]}"#.to_vec()
            },
            FormatConfusionType::QuotedArgs => {
                b"prog \"arg with spaces\" 'single quoted' arg".to_vec()
            },
            FormatConfusionType::EscapedChars => {
                b"prog\\x20arg\\n\\t\\r".to_vec()
            },
            FormatConfusionType::MixedDelimiters => {
                let delim = match modifier % 4 {
                    0 => b"\0",
                    1 => b" ",
                    2 => b"\t",
                    _ => b"\n",
                };
                [b"prog", delim, b"arg1", delim, b"arg2", delim].concat()
            },
        }
    }
}

fuzz_target!(|data: &[u8]| {
    let mut u = Unstructured::new(data);

    if let Ok(fuzz_input) = FuzzInput::arbitrary(&mut u) {
        match fuzz_input.operation {
            ProcCmdlineDecodeTest::ValidCmdlines { args, separator_variant } => {
                let cmdline_bytes = separator_variant.apply(&args);
                let _ = decode_proc_cmdline(&cmdline_bytes);
            },
            ProcCmdlineDecodeTest::NullByteAttacks { attack_type, base_args } => {
                let attack_bytes = attack_type.generate(&base_args);
                let _ = decode_proc_cmdline(&attack_bytes);
            },
            ProcCmdlineDecodeTest::BoundaryConditions { boundary_type, size } => {
                let boundary_bytes = boundary_type.generate(size);
                let _ = decode_proc_cmdline(&boundary_bytes);
            },
            ProcCmdlineDecodeTest::UnicodeAttacks { unicode_type, payload } => {
                let attack_bytes = unicode_type.inject(&payload);
                let _ = decode_proc_cmdline(&attack_bytes);
            },
            ProcCmdlineDecodeTest::InjectionAttacks { injection_type, target_arg } => {
                let injection_bytes = injection_type.inject(&target_arg);
                let _ = decode_proc_cmdline(&injection_bytes);
            },
            ProcCmdlineDecodeTest::EdgeCases { edge_type, repetition } => {
                let edge_bytes = edge_type.generate(repetition);
                let _ = decode_proc_cmdline(&edge_bytes);
            },
            ProcCmdlineDecodeTest::EncodingTests { encoding_type, base_data } => {
                let encoding_bytes = encoding_type.apply(&base_data);
                let _ = decode_proc_cmdline(&encoding_bytes);
            },
            ProcCmdlineDecodeTest::FormatConfusion { confusion_type, modifier } => {
                let confused_bytes = confusion_type.apply(modifier);
                let _ = decode_proc_cmdline(&confused_bytes);
            },
        }
    }
});