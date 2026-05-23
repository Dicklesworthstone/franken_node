//! Fuzz target for swarm scenario base timestamp parsing.
//!
//! Tests RFC3339 timestamp parsing against malformed timestamps, timezone
//! injection, overflow attacks, format confusion, and edge cases. Critical
//! boundary for swarm scenario temporal coordination and replay validation.

#![no_main]

use libfuzzer_sys::fuzz_target;
use arbitrary::{Arbitrary, Unstructured};
use chrono::{DateTime, Utc};

// Mock error type for fuzzing
#[derive(Debug)]
pub enum SwarmScenarioError {
    TimestampParse {
        timestamp: String,
        source: chrono::ParseError,
    },
}

// Reimplemented function for fuzzing
fn parse_base_timestamp(timestamp: &str) -> Result<DateTime<Utc>, SwarmScenarioError> {
    DateTime::parse_from_rfc3339(timestamp)
        .map(|parsed| parsed.with_timezone(&Utc))
        .map_err(|source| SwarmScenarioError::TimestampParse {
            timestamp: timestamp.to_string(),
            source,
        })
}

#[derive(Debug, Clone, Arbitrary)]
struct FuzzInput {
    operation: TimestampParseTest,
}

#[derive(Debug, Clone, Arbitrary)]
enum TimestampParseTest {
    ValidTimestamp {
        base_time: ValidTimestamp,
        timezone_variant: TimezoneVariant,
    },
    MalformedFormat {
        format_attack: FormatAttackType,
        base_content: String,
    },
    TimezoneInjection {
        injection_type: TimezoneInjectionType,
        base_timestamp: String,
    },
    OverflowAttacks {
        overflow_type: OverflowType,
        magnitude: u16,
    },
    BoundaryTests {
        boundary_type: BoundaryType,
        year: i32,
    },
    EncodingAttacks {
        encoding_type: EncodingType,
        payload: String,
    },
    FormatConfusion {
        confusion_type: FormatConfusionType,
        modifier: u8,
    },
    InjectionAttacks {
        injection_type: InjectionType,
        position: u8,
    },
}

#[derive(Debug, Clone, Arbitrary)]
struct ValidTimestamp {
    year: u16,
    month: u8,
    day: u8,
    hour: u8,
    minute: u8,
    second: u8,
    nanos: u32,
}

#[derive(Debug, Clone, Arbitrary)]
enum TimezoneVariant {
    Utc,
    Offset,
    Named,
    Military,
    Fractional,
}

#[derive(Debug, Clone, Arbitrary)]
enum FormatAttackType {
    MissingComponents,
    ExtraComponents,
    WrongSeparators,
    InvalidNumbers,
    MixedFormats,
    TrailingGarbage,
    LeadingGarbage,
    MiddleGarbage,
}

#[derive(Debug, Clone, Arbitrary)]
enum TimezoneInjectionType {
    MultipleTimezones,
    InvalidOffset,
    TimezoneOverflow,
    NegativeTimezone,
    FractionalTimezone,
    TimezoneInjection,
    UnicodeTimezone,
}

#[derive(Debug, Clone, Arbitrary)]
enum OverflowType {
    YearOverflow,
    MonthOverflow,
    DayOverflow,
    HourOverflow,
    MinuteOverflow,
    SecondOverflow,
    NanosOverflow,
    CombinedOverflow,
}

#[derive(Debug, Clone, Arbitrary)]
enum BoundaryType {
    EpochStart,
    EpochEnd,
    LeapYear,
    MaxDateTime,
    MinDateTime,
    Y2K,
    UnixEpoch,
}

#[derive(Debug, Clone, Arbitrary)]
enum EncodingType {
    UrlEncoded,
    JsonEscaped,
    UnicodeNormalization,
    DoubleEncoded,
    HtmlEntities,
    Base64,
    Mixed,
}

#[derive(Debug, Clone, Arbitrary)]
enum FormatConfusionType {
    Iso8601Variants,
    UnixTimestamp,
    MicrosoftFormat,
    CustomFormat,
    RelativeFormat,
    AmbiguousFormat,
}

#[derive(Debug, Clone, Arbitrary)]
enum InjectionType {
    SqlInjection,
    CommandInjection,
    FormatString,
    PathTraversal,
    XssPayload,
    RegexEscape,
}

impl ValidTimestamp {
    fn to_rfc3339(&self, timezone_variant: &TimezoneVariant) -> String {
        let year = 2000 + (self.year % 100);
        let month = 1 + (self.month % 12);
        let day = 1 + (self.day % 28); // Safe day range
        let hour = self.hour % 24;
        let minute = self.minute % 60;
        let second = self.second % 60;
        let nanos = self.nanos % 1_000_000_000;

        let base = format!(
            "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}",
            year, month, day, hour, minute, second
        );

        let with_nanos = if nanos > 0 {
            format!("{}.{:09}", base, nanos)
        } else {
            base
        };

        match timezone_variant {
            TimezoneVariant::Utc => format!("{}Z", with_nanos),
            TimezoneVariant::Offset => {
                let offset_hours = (self.hour % 12) as i8;
                let offset_mins = (self.minute % 60) as i8;
                format!("{}+{:02}:{:02}", with_nanos, offset_hours, offset_mins)
            },
            TimezoneVariant::Named => format!("{} UTC", with_nanos),
            TimezoneVariant::Military => format!("{}Z", with_nanos),
            TimezoneVariant::Fractional => {
                format!("{}+05:30", with_nanos)
            },
        }
    }
}

impl FormatAttackType {
    fn apply(&self, base_content: &str) -> String {
        match self {
            FormatAttackType::MissingComponents => "2023-01-01",
            FormatAttackType::ExtraComponents => "2023-01-01T12:00:00Z-extra",
            FormatAttackType::WrongSeparators => "2023/01/01 12-00-00",
            FormatAttackType::InvalidNumbers => "202X-0A-0BT12:0C:0DZ",
            FormatAttackType::MixedFormats => "2023-01-01 12:00:00 +0000",
            FormatAttackType::TrailingGarbage => "2023-01-01T12:00:00Z<script>alert(1)</script>",
            FormatAttackType::LeadingGarbage => "/**/2023-01-01T12:00:00Z",
            FormatAttackType::MiddleGarbage => "2023-01/**/01T12:00:00Z",
        }.to_string()
    }
}

impl TimezoneInjectionType {
    fn apply(&self, base_timestamp: &str) -> String {
        match self {
            TimezoneInjectionType::MultipleTimezones => {
                format!("{}+05:00-08:00", base_timestamp.trim_end_matches('Z'))
            },
            TimezoneInjectionType::InvalidOffset => {
                format!("{}+25:70", base_timestamp.trim_end_matches('Z'))
            },
            TimezoneInjectionType::TimezoneOverflow => {
                format!("{}+999999:999999", base_timestamp.trim_end_matches('Z'))
            },
            TimezoneInjectionType::NegativeTimezone => {
                format!("{}-99:-99", base_timestamp.trim_end_matches('Z'))
            },
            TimezoneInjectionType::FractionalTimezone => {
                format!("{}+05:30.5", base_timestamp.trim_end_matches('Z'))
            },
            TimezoneInjectionType::TimezoneInjection => {
                format!("{}+00:00'; DROP TABLE timestamps;--", base_timestamp.trim_end_matches('Z'))
            },
            TimezoneInjectionType::UnicodeTimezone => {
                format!("{}+０５:３０", base_timestamp.trim_end_matches('Z')) // Fullwidth digits
            },
        }
    }
}

impl OverflowType {
    fn generate(&self, magnitude: u16) -> String {
        let mag = magnitude as u64;
        match self {
            OverflowType::YearOverflow => format!("{}9999-01-01T00:00:00Z", mag),
            OverflowType::MonthOverflow => format!("2023-{}-01T00:00:00Z", mag + 100),
            OverflowType::DayOverflow => format!("2023-01-{}T00:00:00Z", mag + 100),
            OverflowType::HourOverflow => format!("2023-01-01T{}:00:00Z", mag + 100),
            OverflowType::MinuteOverflow => format!("2023-01-01T00:{}:00Z", mag + 100),
            OverflowType::SecondOverflow => format!("2023-01-01T00:00:{}Z", mag + 100),
            OverflowType::NanosOverflow => format!("2023-01-01T00:00:00.{}Z", "9".repeat((mag % 20 + 10) as usize)),
            OverflowType::CombinedOverflow => format!(
                "{}-{}-{}T{}:{}:{}Z",
                mag + 10000, mag + 50, mag + 50, mag + 50, mag + 100, mag + 100
            ),
        }
    }
}

impl BoundaryType {
    fn generate(&self, year: i32) -> String {
        match self {
            BoundaryType::EpochStart => "1970-01-01T00:00:00Z".to_string(),
            BoundaryType::EpochEnd => "2038-01-19T03:14:07Z".to_string(),
            BoundaryType::LeapYear => "2000-02-29T23:59:59Z".to_string(),
            BoundaryType::MaxDateTime => "9999-12-31T23:59:59.999999999Z".to_string(),
            BoundaryType::MinDateTime => "0001-01-01T00:00:00Z".to_string(),
            BoundaryType::Y2K => "1999-12-31T23:59:59Z".to_string(),
            BoundaryType::UnixEpoch => "1970-01-01T00:00:00Z".to_string(),
        }
    }
}

impl EncodingType {
    fn apply(&self, payload: &str) -> String {
        let base = "2023-01-01T12:00:00Z";
        match self {
            EncodingType::UrlEncoded => payload.chars().map(|c| format!("%{:02X}", c as u8)).collect(),
            EncodingType::JsonEscaped => format!("\\\"{}\\\"", payload),
            EncodingType::UnicodeNormalization => "２０２３-０１-０１Ｔ１２:００:００Ｚ".to_string(), // Fullwidth
            EncodingType::DoubleEncoded => {
                let url_encoded = payload.chars().map(|c| format!("%{:02X}", c as u8)).collect::<String>();
                url_encoded.chars().map(|c| format!("%{:02X}", c as u8)).collect()
            },
            EncodingType::HtmlEntities => "2023&#45;01&#45;01T12&#58;00&#58;00Z".to_string(),
            EncodingType::Base64 => base64::encode(base),
            EncodingType::Mixed => format!("2023%2D01-01T12%3A00%3A00Z"),
        }
    }
}

impl FormatConfusionType {
    fn generate(&self, modifier: u8) -> String {
        match self {
            FormatConfusionType::Iso8601Variants => "20230101T120000Z".to_string(),
            FormatConfusionType::UnixTimestamp => format!("{}", 1672574400 + modifier as u64),
            FormatConfusionType::MicrosoftFormat => "/Date(1672574400000)/".to_string(),
            FormatConfusionType::CustomFormat => "01/01/2023 12:00:00 PM".to_string(),
            FormatConfusionType::RelativeFormat => "2 days ago".to_string(),
            FormatConfusionType::AmbiguousFormat => "01-01-23".to_string(),
        }
    }
}

impl InjectionType {
    fn inject(&self, position: u8) -> String {
        let base = "2023-01-01T12:00:00";
        let payload = match self {
            InjectionType::SqlInjection => "'; DROP TABLE logs; --",
            InjectionType::CommandInjection => "; rm -rf /",
            InjectionType::FormatString => "%s%x%p%n",
            InjectionType::PathTraversal => "../../../etc/passwd",
            InjectionType::XssPayload => "<script>alert(1)</script>",
            InjectionType::RegexEscape => ".*+?{}[]()^$",
        };

        let pos = (position as usize) % base.len();
        format!("{}{}{}Z", &base[..pos], payload, &base[pos..])
    }
}

fuzz_target!(|data: &[u8]| {
    let mut u = Unstructured::new(data);

    if let Ok(fuzz_input) = FuzzInput::arbitrary(&mut u) {
        match fuzz_input.operation {
            TimestampParseTest::ValidTimestamp { base_time, timezone_variant } => {
                let timestamp = base_time.to_rfc3339(&timezone_variant);
                let _ = parse_base_timestamp(&timestamp);
            },
            TimestampParseTest::MalformedFormat { format_attack, base_content } => {
                let attack_input = format_attack.apply(&base_content);
                let _ = parse_base_timestamp(&attack_input);
            },
            TimestampParseTest::TimezoneInjection { injection_type, base_timestamp } => {
                let attack_input = injection_type.apply(&base_timestamp);
                let _ = parse_base_timestamp(&attack_input);
            },
            TimestampParseTest::OverflowAttacks { overflow_type, magnitude } => {
                let overflow_input = overflow_type.generate(magnitude);
                let _ = parse_base_timestamp(&overflow_input);
            },
            TimestampParseTest::BoundaryTests { boundary_type, year } => {
                let boundary_input = boundary_type.generate(year);
                let _ = parse_base_timestamp(&boundary_input);
            },
            TimestampParseTest::EncodingAttacks { encoding_type, payload } => {
                let encoded_input = encoding_type.apply(&payload);
                let _ = parse_base_timestamp(&encoded_input);
            },
            TimestampParseTest::FormatConfusion { confusion_type, modifier } => {
                let confused_input = confusion_type.generate(modifier);
                let _ = parse_base_timestamp(&confused_input);
            },
            TimestampParseTest::InjectionAttacks { injection_type, position } => {
                let injection_input = injection_type.inject(position);
                let _ = parse_base_timestamp(&injection_input);
            },
        }
    }
});