//! Fuzz target for DGIS fragility fixture JSON deserialization.
//!
//! Tests load_fixture_from_json() against malformed JSON, injection attacks,
//! nested object confusion, validation bypass attempts, and edge cases.
//! Critical security boundary for SPOF detection fixture ingestion.

#![no_main]

use libfuzzer_sys::fuzz_target;
use arbitrary::{Arbitrary, Unstructured};
use serde_json::json;

// Mock types for fuzzing
use frankenengine_node::dgis::fragility_fixtures::{load_fixture_from_json, SpofKindLabel, ExpectedFinding};
use frankenengine_node::dgis::fragility_model::{MaintainerProfile, PublisherProfile};
use frankenengine_node::dgis::graph_ingestion::{GraphNode, GraphEdge};
use frankenengine_node::dgis::spof_detection::SpofDetectorConfig;

#[derive(Debug, Clone, Arbitrary)]
struct FuzzInput {
    operation: FragilityFixtureTest,
}

#[derive(Debug, Clone, Arbitrary)]
enum FragilityFixtureTest {
    ValidFixture {
        fixture_data: MockFragilityFixture,
        serialization_variant: SerializationVariant,
    },
    MalformedJson {
        attack_type: JsonMalformationType,
        base_content: String,
    },
    InjectionAttacks {
        injection_type: InjectionType,
        target_field: String,
        payload: String,
    },
    ValidationBypass {
        bypass_type: ValidationBypassType,
        invalid_data: String,
    },
    StructureConfusion {
        confusion_type: StructureConfusionType,
        modifier: u8,
    },
    BoundaryTests {
        boundary_type: BoundaryType,
        magnitude: u32,
    },
    EncodingAttacks {
        encoding_type: EncodingType,
        payload: String,
    },
    NestedObjectAttacks {
        nesting_type: NestingType,
        depth: u8,
    },
}

#[derive(Debug, Clone, Arbitrary)]
struct MockFragilityFixture {
    name: String,
    description: String,
    now_ms: i64,
    num_maintainers: u8,
    num_publishers: u8,
    num_nodes: u8,
    num_edges: u8,
    has_config_overrides: bool,
    num_expected_findings: u8,
}

#[derive(Debug, Clone, Arbitrary)]
enum SerializationVariant {
    Standard,
    Pretty,
    Compact,
    WithNulls,
    MixedSpacing,
    ExtraFields,
}

#[derive(Debug, Clone, Arbitrary)]
enum JsonMalformationType {
    UnterminatedString,
    UnterminatedObject,
    UnterminatedArray,
    MissingCommas,
    ExtraCommas,
    WrongBrackets,
    InvalidEscapes,
    TrailingGarbage,
    LeadingGarbage,
    MiddleGarbage,
    ControlChars,
    UnicodeErrors,
}

#[derive(Debug, Clone, Arbitrary)]
enum InjectionType {
    SqlInjection,
    CommandInjection,
    FormatString,
    PathTraversal,
    XssPayload,
    JsonEscape,
    RegexEscape,
    UnicodeHomoglyphs,
    NullByteInjection,
}

#[derive(Debug, Clone, Arbitrary)]
enum ValidationBypassType {
    CountBounds,
    NegativeValues,
    InfiniteValues,
    NanValues,
    EmptyRequired,
    DuplicateKeys,
    CircularReferences,
    OverflowAttacks,
}

#[derive(Debug, Clone, Arbitrary)]
enum StructureConfusionType {
    TypeConfusion,
    NestedArrays,
    ObjectAsArray,
    ArrayAsObject,
    StringAsNumber,
    NumberAsString,
    BoolAsString,
    NullConfusion,
}

#[derive(Debug, Clone, Arbitrary)]
enum BoundaryType {
    MaxI64,
    MinI64,
    MaxU32,
    MinU32,
    ZeroValues,
    PowerOfTwo,
    NearOverflow,
    ExactLimits,
}

#[derive(Debug, Clone, Arbitrary)]
enum EncodingType {
    UrlEncoded,
    Base64Encoded,
    HtmlEntities,
    UnicodeNormalization,
    DoubleEncoded,
    MixedEncoding,
    BinaryData,
}

#[derive(Debug, Clone, Arbitrary)]
enum NestingType {
    DeepObjects,
    DeepArrays,
    MixedNesting,
    CyclicalStructure,
    WideFanout,
    LinearChain,
}

impl MockFragilityFixture {
    fn to_json(&self, variant: &SerializationVariant) -> String {
        let maintainers: serde_json::Value = (0..self.num_maintainers % 10)
            .map(|i| {
                (
                    format!("maintainer_{}", i),
                    json!({
                        "trust_score": (i as f64) * 0.1,
                        "verification_status": "verified",
                        "last_activity_days": i * 10
                    })
                )
            })
            .collect();

        let publishers: serde_json::Value = (0..self.num_publishers % 10)
            .map(|i| {
                (
                    format!("publisher_{}", i),
                    json!({
                        "trust_score": (i as f64) * 0.15,
                        "package_count": i * 5,
                        "verification_status": "verified"
                    })
                )
            })
            .collect();

        let nodes: Vec<serde_json::Value> = (0..self.num_nodes % 20)
            .map(|i| {
                json!({
                    "package_id": format!("pkg_{}", i),
                    "package_name": format!("package_{}", i),
                    "version": format!("1.{}.0", i),
                    "maintainer_id": format!("maintainer_{}", i % 3)
                })
            })
            .collect();

        let edges: Vec<serde_json::Value> = (0..self.num_edges % 30)
            .map(|i| {
                json!({
                    "from_package": format!("pkg_{}", i % 10),
                    "to_package": format!("pkg_{}", (i + 1) % 10),
                    "dependency_type": "direct",
                    "version_constraint": "^1.0.0"
                })
            })
            .collect();

        let expected_findings: Vec<serde_json::Value> = (0..self.num_expected_findings % 5)
            .map(|i| {
                let kind = match i % 5 {
                    0 => "SingleMaintainer",
                    1 => "KeyPerson",
                    2 => "DependencyChain",
                    3 => "OrgConcentration",
                    _ => "OrphanedPackage",
                };
                json!({
                    "kind": kind,
                    "min_count": i,
                    "max_count": i + 5
                })
            })
            .collect();

        let config_overrides = if self.has_config_overrides {
            Some(json!({
                "max_dependency_depth": 10,
                "min_trust_score": 0.5
            }))
        } else {
            None
        };

        let fixture = json!({
            "name": self.name,
            "description": self.description,
            "now_ms": self.now_ms,
            "maintainers": maintainers,
            "publishers": publishers,
            "nodes": nodes,
            "edges": edges,
            "config_overrides": config_overrides,
            "expected_findings": expected_findings
        });

        match variant {
            SerializationVariant::Standard => serde_json::to_string(&fixture).unwrap(),
            SerializationVariant::Pretty => serde_json::to_string_pretty(&fixture).unwrap(),
            SerializationVariant::Compact => serde_json::to_string(&fixture).unwrap().replace(" ", ""),
            SerializationVariant::WithNulls => {
                let mut s = serde_json::to_string(&fixture).unwrap();
                s.insert_str(10, "null,");
                s
            },
            SerializationVariant::MixedSpacing => {
                serde_json::to_string(&fixture).unwrap().replace(":", " : ").replace(",", " , ")
            },
            SerializationVariant::ExtraFields => {
                let mut obj = fixture.as_object().unwrap().clone();
                obj.insert("extra_field".to_string(), json!("extra_value"));
                obj.insert("unknown_config".to_string(), json!(42));
                serde_json::to_string(&obj).unwrap()
            },
        }
    }
}

impl JsonMalformationType {
    fn apply(&self, base_content: &str) -> String {
        match self {
            JsonMalformationType::UnterminatedString => {
                format!("{{\"name\":\"test\"")
            },
            JsonMalformationType::UnterminatedObject => {
                format!("{{\"name\":\"test\",\"description\":\"test\"")
            },
            JsonMalformationType::UnterminatedArray => {
                format!("{{\"nodes\":[{{\"id\":1}}")
            },
            JsonMalformationType::MissingCommas => {
                base_content.replace(",", "")
            },
            JsonMalformationType::ExtraCommas => {
                base_content.replace(":", ":,").replace("}", ",}")
            },
            JsonMalformationType::WrongBrackets => {
                base_content.replace("{", "[").replace("}", "]")
            },
            JsonMalformationType::InvalidEscapes => {
                base_content.replace("\"", "\\\"\\x").replace("\\", "\\\\\\")
            },
            JsonMalformationType::TrailingGarbage => {
                format!("{}<script>alert(1)</script>", base_content)
            },
            JsonMalformationType::LeadingGarbage => {
                format!("/*comment*/{}", base_content)
            },
            JsonMalformationType::MiddleGarbage => {
                let mid = base_content.len() / 2;
                format!("{}/**/garbage/**/{}", &base_content[..mid], &base_content[mid..])
            },
            JsonMalformationType::ControlChars => {
                format!("{}\x00\x01\x02", base_content)
            },
            JsonMalformationType::UnicodeErrors => {
                format!("{}\u{202E}\u{FEFF}", base_content)
            },
        }
    }
}

impl InjectionType {
    fn inject(&self, target_field: &str, payload: &str) -> String {
        let injection_payload = match self {
            InjectionType::SqlInjection => "'; DROP TABLE fixtures; --",
            InjectionType::CommandInjection => "; rm -rf /",
            InjectionType::FormatString => "%s%x%p%n",
            InjectionType::PathTraversal => "../../../etc/passwd",
            InjectionType::XssPayload => "<script>alert(1)</script>",
            InjectionType::JsonEscape => "\\\",\\\"injected\\\":\\\"evil",
            InjectionType::RegexEscape => ".*+?{}[]()^$",
            InjectionType::UnicodeHomoglyphs => "Α", // Greek capital alpha
            InjectionType::NullByteInjection => "test\0injection",
        };

        json!({
            "name": "test_fixture",
            "description": "test description",
            "now_ms": 1672531200000i64,
            "maintainers": {},
            "publishers": {},
            "nodes": [],
            "edges": [],
            "config_overrides": null,
            "expected_findings": [],
            target_field: format!("{}{}", payload, injection_payload)
        }).to_string()
    }
}

impl ValidationBypassType {
    fn generate(&self, invalid_data: &str) -> String {
        match self {
            ValidationBypassType::CountBounds => json!({
                "name": "bypass_test",
                "description": "test",
                "now_ms": 1672531200000i64,
                "maintainers": {},
                "publishers": {},
                "nodes": [],
                "edges": [],
                "config_overrides": null,
                "expected_findings": [{
                    "kind": "SingleMaintainer",
                    "min_count": 999999,
                    "max_count": 1
                }]
            }).to_string(),
            ValidationBypassType::NegativeValues => json!({
                "name": "negative_test",
                "description": "test",
                "now_ms": -9223372036854775808i64,
                "maintainers": {},
                "publishers": {},
                "nodes": [],
                "edges": [],
                "config_overrides": null,
                "expected_findings": []
            }).to_string(),
            ValidationBypassType::InfiniteValues => json!({
                "name": "infinite_test",
                "description": "test",
                "now_ms": "Infinity",
                "maintainers": {},
                "publishers": {},
                "nodes": [],
                "edges": [],
                "config_overrides": null,
                "expected_findings": []
            }).to_string(),
            ValidationBypassType::NanValues => json!({
                "name": "nan_test",
                "description": "test",
                "now_ms": "NaN",
                "maintainers": {},
                "publishers": {},
                "nodes": [],
                "edges": [],
                "config_overrides": null,
                "expected_findings": []
            }).to_string(),
            ValidationBypassType::EmptyRequired => json!({
                "name": "",
                "description": "",
                "now_ms": 1672531200000i64,
                "maintainers": {},
                "publishers": {},
                "nodes": [],
                "edges": [],
                "config_overrides": null,
                "expected_findings": []
            }).to_string(),
            ValidationBypassType::DuplicateKeys => {
                r#"{"name":"test","name":"duplicate","description":"test","now_ms":1672531200000,"maintainers":{},"publishers":{},"nodes":[],"edges":[],"config_overrides":null,"expected_findings":[]}"#.to_string()
            },
            ValidationBypassType::CircularReferences => json!({
                "name": "circular",
                "description": "test",
                "now_ms": 1672531200000i64,
                "maintainers": {},
                "publishers": {},
                "nodes": [{
                    "package_id": "pkg1",
                    "package_name": "package1",
                    "version": "1.0.0",
                    "maintainer_id": "maintainer1"
                }],
                "edges": [{
                    "from_package": "pkg1",
                    "to_package": "pkg1",
                    "dependency_type": "direct",
                    "version_constraint": "^1.0.0"
                }],
                "config_overrides": null,
                "expected_findings": []
            }).to_string(),
            ValidationBypassType::OverflowAttacks => json!({
                "name": "A".repeat(100000),
                "description": "test",
                "now_ms": 1672531200000i64,
                "maintainers": {},
                "publishers": {},
                "nodes": [],
                "edges": [],
                "config_overrides": null,
                "expected_findings": []
            }).to_string(),
        }
    }
}

impl StructureConfusionType {
    fn apply(&self, modifier: u8) -> String {
        match self {
            StructureConfusionType::TypeConfusion => json!({
                "name": 42,
                "description": true,
                "now_ms": "not_a_number",
                "maintainers": [],
                "publishers": "not_an_object",
                "nodes": {},
                "edges": null,
                "config_overrides": "invalid",
                "expected_findings": 123
            }).to_string(),
            StructureConfusionType::NestedArrays => json!({
                "name": "nested_test",
                "description": "test",
                "now_ms": 1672531200000i64,
                "maintainers": [[[[[{}]]]]],
                "publishers": {},
                "nodes": [],
                "edges": [],
                "config_overrides": null,
                "expected_findings": []
            }).to_string(),
            StructureConfusionType::ObjectAsArray => json!([
                "name", "test",
                "description", "test",
                "now_ms", 1672531200000i64
            ]).to_string(),
            StructureConfusionType::ArrayAsObject => json!({
                "0": "name",
                "1": "test",
                "2": "description",
                "length": 3
            }).to_string(),
            StructureConfusionType::StringAsNumber => json!({
                "name": "123.456e7",
                "description": "test",
                "now_ms": "0x1a2b3c4d",
                "maintainers": {},
                "publishers": {},
                "nodes": [],
                "edges": [],
                "config_overrides": null,
                "expected_findings": []
            }).to_string(),
            StructureConfusionType::NumberAsString => json!({
                "name": "test",
                "description": "test",
                "now_ms": 1672531200000i64,
                "maintainers": {},
                "publishers": {},
                "nodes": [],
                "edges": [],
                "config_overrides": null,
                "expected_findings": [{
                    "kind": 0,
                    "min_count": "5",
                    "max_count": true
                }]
            }).to_string(),
            StructureConfusionType::BoolAsString => json!({
                "name": "test",
                "description": "test",
                "now_ms": 1672531200000i64,
                "maintainers": {},
                "publishers": {},
                "nodes": [],
                "edges": [],
                "config_overrides": "true",
                "expected_findings": []
            }).to_string(),
            StructureConfusionType::NullConfusion => json!({
                "name": null,
                "description": null,
                "now_ms": null,
                "maintainers": null,
                "publishers": null,
                "nodes": null,
                "edges": null,
                "config_overrides": null,
                "expected_findings": null
            }).to_string(),
        }
    }
}

impl BoundaryType {
    fn generate(&self, magnitude: u32) -> String {
        let mag = magnitude as i64;
        match self {
            BoundaryType::MaxI64 => json!({
                "name": "boundary_test",
                "description": "test",
                "now_ms": 9223372036854775807i64,
                "maintainers": {},
                "publishers": {},
                "nodes": [],
                "edges": [],
                "config_overrides": null,
                "expected_findings": []
            }).to_string(),
            BoundaryType::MinI64 => json!({
                "name": "boundary_test",
                "description": "test",
                "now_ms": -9223372036854775808i64,
                "maintainers": {},
                "publishers": {},
                "nodes": [],
                "edges": [],
                "config_overrides": null,
                "expected_findings": []
            }).to_string(),
            BoundaryType::MaxU32 => json!({
                "name": "boundary_test",
                "description": "test",
                "now_ms": 4294967295i64,
                "maintainers": {},
                "publishers": {},
                "nodes": [],
                "edges": [],
                "config_overrides": null,
                "expected_findings": []
            }).to_string(),
            BoundaryType::MinU32 => json!({
                "name": "boundary_test",
                "description": "test",
                "now_ms": 0i64,
                "maintainers": {},
                "publishers": {},
                "nodes": [],
                "edges": [],
                "config_overrides": null,
                "expected_findings": []
            }).to_string(),
            BoundaryType::ZeroValues => json!({
                "name": "zero_test",
                "description": "test",
                "now_ms": 0i64,
                "maintainers": {},
                "publishers": {},
                "nodes": [],
                "edges": [],
                "config_overrides": null,
                "expected_findings": [{
                    "kind": "SingleMaintainer",
                    "min_count": 0,
                    "max_count": 0
                }]
            }).to_string(),
            BoundaryType::PowerOfTwo => json!({
                "name": "power_of_two_test",
                "description": "test",
                "now_ms": 1i64 << (mag % 32),
                "maintainers": {},
                "publishers": {},
                "nodes": [],
                "edges": [],
                "config_overrides": null,
                "expected_findings": []
            }).to_string(),
            BoundaryType::NearOverflow => json!({
                "name": "near_overflow_test",
                "description": "test",
                "now_ms": 9223372036854775806i64 + mag,
                "maintainers": {},
                "publishers": {},
                "nodes": [],
                "edges": [],
                "config_overrides": null,
                "expected_findings": []
            }).to_string(),
            BoundaryType::ExactLimits => json!({
                "name": "exact_limits_test",
                "description": "test",
                "now_ms": 1672531200000i64,
                "maintainers": {},
                "publishers": {},
                "nodes": [],
                "edges": [],
                "config_overrides": null,
                "expected_findings": [{
                    "kind": "SingleMaintainer",
                    "min_count": u32::MAX,
                    "max_count": u32::MAX
                }]
            }).to_string(),
        }
    }
}

impl EncodingType {
    fn apply(&self, payload: &str) -> String {
        let base_fixture = json!({
            "name": "encoding_test",
            "description": "test",
            "now_ms": 1672531200000i64,
            "maintainers": {},
            "publishers": {},
            "nodes": [],
            "edges": [],
            "config_overrides": null,
            "expected_findings": []
        });

        match self {
            EncodingType::UrlEncoded => {
                payload.chars().map(|c| format!("%{:02X}", c as u8)).collect::<String>()
            },
            EncodingType::Base64Encoded => {
                base64::prelude::BASE64_STANDARD.encode(base_fixture.to_string().as_bytes())
            },
            EncodingType::HtmlEntities => {
                base_fixture.to_string().replace("\"", "&quot;").replace("<", "&lt;").replace(">", "&gt;")
            },
            EncodingType::UnicodeNormalization => {
                "{\u{FF02}name\u{FF02}:\u{FF02}test\u{FF02}}".to_string() // Fullwidth quotes
            },
            EncodingType::DoubleEncoded => {
                let url_encoded = payload.chars().map(|c| format!("%{:02X}", c as u8)).collect::<String>();
                url_encoded.chars().map(|c| format!("%{:02X}", c as u8)).collect()
            },
            EncodingType::MixedEncoding => {
                format!("data:application/json;base64,{}", base64::prelude::BASE64_STANDARD.encode(base_fixture.to_string().as_bytes()))
            },
            EncodingType::BinaryData => {
                base_fixture.to_string().bytes().map(|b| format!("\\x{:02x}", b)).collect()
            },
        }
    }
}

impl NestingType {
    fn apply(&self, depth: u8) -> String {
        let max_depth = (depth % 20) + 1;
        match self {
            NestingType::DeepObjects => {
                let mut nested = "{}".to_string();
                for i in 0..max_depth {
                    nested = format!("{{\"level_{}\":{}}}", i, nested);
                }
                nested
            },
            NestingType::DeepArrays => {
                let mut nested = "[]".to_string();
                for _ in 0..max_depth {
                    nested = format!("[{}]", nested);
                }
                nested
            },
            NestingType::MixedNesting => {
                let mut nested = "{}".to_string();
                for i in 0..max_depth {
                    if i % 2 == 0 {
                        nested = format!("{{\"obj_{}\":{}}}", i, nested);
                    } else {
                        nested = format!("[{}]", nested);
                    }
                }
                nested
            },
            NestingType::CyclicalStructure => {
                // Attempt to create a self-referencing structure (will fail in JSON)
                json!({
                    "name": "cyclical",
                    "description": "test",
                    "now_ms": 1672531200000i64,
                    "maintainers": {
                        "self": "$$REF_TO_ROOT$$"
                    },
                    "publishers": {},
                    "nodes": [],
                    "edges": [],
                    "config_overrides": null,
                    "expected_findings": []
                }).to_string()
            },
            NestingType::WideFanout => {
                let maintainers: serde_json::Value = (0..max_depth)
                    .map(|i| (format!("maintainer_{}", i), json!({"id": i})))
                    .collect();
                json!({
                    "name": "wide_fanout",
                    "description": "test",
                    "now_ms": 1672531200000i64,
                    "maintainers": maintainers,
                    "publishers": {},
                    "nodes": [],
                    "edges": [],
                    "config_overrides": null,
                    "expected_findings": []
                }).to_string()
            },
            NestingType::LinearChain => {
                let nodes: Vec<serde_json::Value> = (0..max_depth)
                    .map(|i| json!({
                        "package_id": format!("pkg_{}", i),
                        "package_name": format!("package_{}", i),
                        "version": "1.0.0",
                        "maintainer_id": format!("maintainer_{}", i)
                    }))
                    .collect();
                json!({
                    "name": "linear_chain",
                    "description": "test",
                    "now_ms": 1672531200000i64,
                    "maintainers": {},
                    "publishers": {},
                    "nodes": nodes,
                    "edges": [],
                    "config_overrides": null,
                    "expected_findings": []
                }).to_string()
            },
        }
    }
}

fuzz_target!(|data: &[u8]| {
    let mut u = Unstructured::new(data);

    if let Ok(fuzz_input) = FuzzInput::arbitrary(&mut u) {
        match fuzz_input.operation {
            FragilityFixtureTest::ValidFixture { fixture_data, serialization_variant } => {
                let json_str = fixture_data.to_json(&serialization_variant);
                // Test deterministic fixture loading
                let result1 = load_fixture_from_json(&json_str);
                let result2 = load_fixture_from_json(&json_str);
                assert_eq!(result1.is_ok(), result2.is_ok(), "Fixture loading should be deterministic");
            },
            FragilityFixtureTest::MalformedJson { attack_type, base_content } => {
                let malformed_json = attack_type.apply(&base_content);
                let _ = load_fixture_from_json(&malformed_json);
            },
            FragilityFixtureTest::InjectionAttacks { injection_type, target_field, payload } => {
                let attack_json = injection_type.inject(&target_field, &payload);
                let _ = load_fixture_from_json(&attack_json);
            },
            FragilityFixtureTest::ValidationBypass { bypass_type, invalid_data } => {
                let bypass_json = bypass_type.generate(&invalid_data);
                let _ = load_fixture_from_json(&bypass_json);
            },
            FragilityFixtureTest::StructureConfusion { confusion_type, modifier } => {
                let confused_json = confusion_type.apply(modifier);
                let _ = load_fixture_from_json(&confused_json);
            },
            FragilityFixtureTest::BoundaryTests { boundary_type, magnitude } => {
                let boundary_json = boundary_type.generate(magnitude);
                let _ = load_fixture_from_json(&boundary_json);
            },
            FragilityFixtureTest::EncodingAttacks { encoding_type, payload } => {
                let encoded_json = encoding_type.apply(&payload);
                let _ = load_fixture_from_json(&encoded_json);
            },
            FragilityFixtureTest::NestedObjectAttacks { nesting_type, depth } => {
                let nested_json = nesting_type.apply(depth);
                let _ = load_fixture_from_json(&nested_json);
            },
        }
    }
});