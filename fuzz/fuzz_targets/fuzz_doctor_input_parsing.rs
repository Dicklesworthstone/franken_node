#![no_main]

use arbitrary::Arbitrary;
use clap::Parser;
use frankenengine_node::cli::{
    parse_doctor_policy_activation_input_bytes, Cli, Command, DoctorCommand,
    DoctorPolicyActivationInput,
};
use libfuzzer_sys::fuzz_target;
use serde_json::{json, Value};

const MAX_RAW_JSON_BYTES: usize = 256 * 1024;
const MAX_TEXT_CHARS: usize = 128;
const MAX_EXTRA_ARGS: usize = 8;
const MAX_CANDIDATES: usize = 8;
const MAX_OBSERVATIONS: usize = 16;

fuzz_target!(|input: DoctorInputFuzz| {
    fuzz_doctor_cli(&input);
    fuzz_raw_policy_activation_json(&input.raw_json);
    fuzz_structured_policy_activation_json(&input);
});

fn fuzz_doctor_cli(input: &DoctorInputFuzz) {
    for args in doctor_cli_variants(input) {
        match Cli::try_parse_from(args) {
            Ok(cli) => assert_doctor_cli_shape(&cli),
            Err(err) => assert_clean_cli_error(&err.to_string()),
        }
    }
}

fn doctor_cli_variants(input: &DoctorInputFuzz) -> Vec<Vec<String>> {
    let mut doctor = vec!["franken-node".to_string(), "doctor".to_string()];
    if input.json_flag {
        doctor.push("--json".to_string());
    }
    if input.structured_logs_jsonl {
        doctor.push("--structured-logs-jsonl".to_string());
    }
    if input.verbose {
        doctor.push("--verbose".to_string());
    }
    doctor.push("--trace-id".to_string());
    doctor.push(bounded_text(&input.trace_id, "doctor-fuzz-trace"));
    if let Some(profile) = &input.profile {
        doctor.push("--profile".to_string());
        doctor.push(bounded_text(profile, "balanced"));
    }
    if let Some(config) = &input.config_path {
        doctor.push("--config".to_string());
        doctor.push(bounded_text(config, "franken_node.toml"));
    }
    if let Some(policy_input_path) = &input.policy_activation_input_path {
        doctor.push("--policy-activation-input".to_string());
        doctor.push(bounded_text(
            policy_input_path,
            "fixtures/policy_activation/doctor_policy_activation_pass.json",
        ));
    }

    let mut close_condition = vec![
        "franken-node".to_string(),
        "doctor".to_string(),
        "close-condition".to_string(),
    ];
    if input.json_flag {
        close_condition.push("--json".to_string());
    }
    if let Some(receipt_signing_key) = &input.receipt_signing_key {
        close_condition.push("--receipt-signing-key".to_string());
        close_condition.push(bounded_text(
            receipt_signing_key,
            "fixtures/keys/test-receipt-signing-key.hex",
        ));
    }

    let mut malformed = doctor.clone();
    match input.invalid_cli_variant % 4 {
        0 => malformed.push("--definitely-unknown-flag".to_string()),
        1 => {
            malformed.push("--json".to_string());
            malformed.push("trailing-positional".to_string());
        }
        2 => {
            malformed.push("--trace-id".to_string());
        }
        _ => {
            malformed.push("close-condition".to_string());
            malformed.push("--structured-logs-jsonl".to_string());
        }
    }
    for extra in input.extra_args.iter().take(MAX_EXTRA_ARGS) {
        malformed.push(bounded_text(extra, "extra-doctor-arg"));
    }

    vec![doctor, close_condition, malformed]
}

fn assert_doctor_cli_shape(cli: &Cli) {
    match &cli.command {
        Command::Doctor(args) => match &args.command {
            Some(DoctorCommand::CloseCondition(close_condition)) => {
                if let Some(path) = &close_condition.receipt_signing_key {
                    assert!(
                        !path.as_os_str().is_empty(),
                        "receipt signing key path should remain non-empty when parsed"
                    );
                }
            }
            None => {
                assert!(
                    !args.trace_id.trim().is_empty(),
                    "doctor trace_id should remain non-empty when parsed"
                );
            }
        },
        other => panic!("expected doctor command, got {other:?}"),
    }
}

fn assert_clean_cli_error(message: &str) {
    assert!(
        !message.trim().is_empty(),
        "doctor CLI errors should be non-empty"
    );
    assert!(
        message.contains("doctor")
            || message.contains("Usage:")
            || message.contains("error:")
            || message.contains("unexpected argument"),
        "doctor CLI errors should remain contextual: {message}"
    );
}

fn fuzz_raw_policy_activation_json(bytes: &[u8]) {
    if bytes.len() > MAX_RAW_JSON_BYTES {
        return;
    }

    fuzz_policy_activation_json_variant(bytes, "raw-doctor-policy.json");

    if !bytes.is_empty() {
        fuzz_policy_activation_json_variant(&bytes[..1], "raw-doctor-policy-single-byte.json");
        let midpoint = bytes.len() / 2;
        if midpoint > 0 {
            fuzz_policy_activation_json_variant(
                &bytes[..midpoint],
                "raw-doctor-policy-truncated.json",
            );
        }
    }
}

fn fuzz_structured_policy_activation_json(input: &DoctorInputFuzz) {
    let base = input.policy_activation.to_json_value();
    let base_bytes =
        serde_json::to_vec(&base).expect("structure-aware doctor policy JSON should encode");
    fuzz_policy_activation_json_variant(&base_bytes, "structured-doctor-policy.json");

    let pretty =
        serde_json::to_vec_pretty(&base).expect("pretty structure-aware doctor JSON should encode");
    fuzz_policy_activation_json_variant(&pretty, "structured-doctor-policy-pretty.json");

    let wrapped = format!(
        " \n\t{}\n\t ",
        serde_json::to_string(&base).expect("structure-aware doctor JSON string should encode")
    );
    fuzz_policy_activation_json_variant(
        wrapped.as_bytes(),
        "structured-doctor-policy-whitespace.json",
    );

    let mutated = mutate_doctor_policy_json(base, input.invalid_json_variant);
    let mutated_bytes =
        serde_json::to_vec(&mutated).expect("mutated structure-aware doctor JSON should encode");
    fuzz_policy_activation_json_variant(&mutated_bytes, "structured-doctor-policy-mutated.json");
}

fn fuzz_policy_activation_json_variant(bytes: &[u8], source: &str) {
    let result = parse_doctor_policy_activation_input_bytes(bytes, source);
    match result {
        Ok(parsed) => assert_policy_activation_roundtrip(&parsed),
        Err(err) => assert_clean_policy_activation_error(&err.to_string(), source),
    }

    let _ = serde_json::from_slice::<Value>(bytes);
}

fn assert_policy_activation_roundtrip(input: &DoctorPolicyActivationInput) {
    let encoded =
        serde_json::to_vec(input).expect("parsed doctor policy activation input should encode");
    let reparsed = parse_doctor_policy_activation_input_bytes(&encoded, "roundtrip-doctor.json")
        .expect("roundtrip doctor policy activation input should decode");
    assert_eq!(&reparsed, input);
}

fn assert_clean_policy_activation_error(message: &str, source: &str) {
    assert!(
        !message.trim().is_empty(),
        "doctor JSON parse errors should be non-empty"
    );
    assert!(
        message.contains("failed parsing policy activation input"),
        "doctor JSON parse errors should preserve parser context: {message}"
    );
    assert!(
        message.contains(source),
        "doctor JSON parse errors should preserve source context: {message}"
    );
}

fn mutate_doctor_policy_json(mut base: Value, selector: u8) -> Value {
    let Some(root) = base.as_object_mut() else {
        return Value::Null;
    };

    match selector % 7 {
        0 => {
            root.remove("system_state");
        }
        1 => {
            root.insert("system_state".to_string(), json!("not-an-object"));
        }
        2 => {
            root.insert("candidates".to_string(), json!("not-an-array"));
        }
        3 => {
            root.insert(
                "observations".to_string(),
                json!([{"candidate": 17, "success": "yes"}]),
            );
        }
        4 => {
            if let Some(system_state) = root
                .get_mut("system_state")
                .and_then(serde_json::Value::as_object_mut)
            {
                system_state.insert("memory_used_bytes".to_string(), json!("a-lot"));
            }
        }
        5 => {
            root.insert("epoch_id".to_string(), json!("not-a-u64"));
        }
        _ => {
            return Value::Array(vec![Value::Object(root.clone())]);
        }
    }

    base
}

fn bounded_text(raw: &str, fallback: &str) -> String {
    let text = raw.chars().take(MAX_TEXT_CHARS).collect::<String>();
    if text.trim().is_empty() {
        fallback.to_string()
    } else {
        text
    }
}

fn bounded_candidates(values: &[String], fallback: &str) -> Vec<String> {
    let mut candidates = values
        .iter()
        .take(MAX_CANDIDATES)
        .map(|value| bounded_text(value, fallback))
        .collect::<Vec<_>>();
    if candidates.is_empty() {
        candidates.push(fallback.to_string());
    }
    candidates
}

fn bounded_ratio(raw: u32, upper_bound: f64) -> f64 {
    (f64::from(raw % 10_000) / 10_000.0) * upper_bound
}

#[derive(Debug, Arbitrary)]
struct DoctorInputFuzz {
    raw_json: Vec<u8>,
    trace_id: String,
    profile: Option<String>,
    config_path: Option<String>,
    policy_activation_input_path: Option<String>,
    receipt_signing_key: Option<String>,
    extra_args: Vec<String>,
    json_flag: bool,
    structured_logs_jsonl: bool,
    verbose: bool,
    invalid_cli_variant: u8,
    invalid_json_variant: u8,
    policy_activation: StructuredDoctorPolicyActivationInput,
}

#[derive(Debug, Arbitrary)]
struct StructuredDoctorPolicyActivationInput {
    epoch_id: Option<u64>,
    memory_used_bytes: u64,
    memory_budget_bytes: u64,
    durability_raw: u32,
    hardening_level: FuzzHardeningLevel,
    proposed_hardening_level: Option<FuzzHardeningLevel>,
    evidence_emission_active: bool,
    memory_tail_risk: Option<StructuredDoctorPolicyMemoryTailRiskInput>,
    reliability_telemetry: Option<StructuredDoctorPolicyReliabilityTelemetryInput>,
    candidates: Vec<String>,
    prefiltered_candidates: Vec<String>,
    observations: Vec<StructuredDoctorPolicyObservationInput>,
}

impl StructuredDoctorPolicyActivationInput {
    fn to_json_value(&self) -> Value {
        let candidates = bounded_candidates(&self.candidates, "candidate-a");
        let prefiltered_candidates = self
            .prefiltered_candidates
            .iter()
            .take(MAX_CANDIDATES)
            .map(|value| bounded_text(value, "candidate-prefiltered"))
            .collect::<Vec<_>>();
        let observations = self
            .observations
            .iter()
            .take(MAX_OBSERVATIONS)
            .map(|observation| observation.to_json_value())
            .collect::<Vec<_>>();

        json!({
            "epoch_id": self.epoch_id,
            "system_state": {
                "memory_used_bytes": self.memory_used_bytes,
                "memory_budget_bytes": self.memory_budget_bytes.max(1),
                "durability_level": bounded_ratio(self.durability_raw, 1.0),
                "hardening_level": self.hardening_level.as_str(),
                "proposed_hardening_level": self.proposed_hardening_level.map(FuzzHardeningLevel::as_str),
                "evidence_emission_active": self.evidence_emission_active,
                "memory_tail_risk": self.memory_tail_risk.as_ref().map(StructuredDoctorPolicyMemoryTailRiskInput::to_json_value),
                "reliability_telemetry": self.reliability_telemetry.as_ref().map(StructuredDoctorPolicyReliabilityTelemetryInput::to_json_value)
            },
            "candidates": candidates,
            "prefiltered_candidates": prefiltered_candidates,
            "observations": observations
        })
    }
}

#[derive(Debug, Arbitrary)]
struct StructuredDoctorPolicyMemoryTailRiskInput {
    sample_count: u64,
    mean_raw: u32,
    variance_raw: u32,
    peak_raw: u32,
}

impl StructuredDoctorPolicyMemoryTailRiskInput {
    fn to_json_value(&self) -> Value {
        json!({
            "sample_count": self.sample_count,
            "mean_utilization": bounded_ratio(self.mean_raw, 1.0),
            "variance_utilization": bounded_ratio(self.variance_raw, 0.5),
            "peak_utilization": bounded_ratio(self.peak_raw, 1.5),
        })
    }
}

#[derive(Debug, Arbitrary)]
struct StructuredDoctorPolicyReliabilityTelemetryInput {
    sample_count: u64,
    nonconforming_count: u64,
}

impl StructuredDoctorPolicyReliabilityTelemetryInput {
    fn to_json_value(&self) -> Value {
        json!({
            "sample_count": self.sample_count,
            "nonconforming_count": self.nonconforming_count,
        })
    }
}

#[derive(Debug, Arbitrary)]
struct StructuredDoctorPolicyObservationInput {
    candidate: String,
    success: bool,
    epoch_id: Option<u64>,
}

impl StructuredDoctorPolicyObservationInput {
    fn to_json_value(&self) -> Value {
        json!({
            "candidate": bounded_text(&self.candidate, "candidate-observation"),
            "success": self.success,
            "epoch_id": self.epoch_id,
        })
    }
}

#[derive(Debug, Clone, Copy, Arbitrary)]
enum FuzzHardeningLevel {
    Baseline,
    Standard,
    Enhanced,
    Maximum,
    Critical,
    Unknown,
    Padded,
    Empty,
}

impl FuzzHardeningLevel {
    fn as_str(self) -> String {
        match self {
            Self::Baseline => "baseline".to_string(),
            Self::Standard => "standard".to_string(),
            Self::Enhanced => "enhanced".to_string(),
            Self::Maximum => "maximum".to_string(),
            Self::Critical => "critical".to_string(),
            Self::Unknown => "mystery-hardening".to_string(),
            Self::Padded => " enhanced ".to_string(),
            Self::Empty => String::new(),
        }
    }
}
