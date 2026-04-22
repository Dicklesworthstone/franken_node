use frankenengine_node::replay::time_travel_engine::{
    EnvironmentSnapshot, SCHEMA_VERSION, SideEffect, TraceStep, WorkflowTrace,
};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

type TestResult = Result<(), String>;

const TRACE_DIGEST_DOMAIN: &[u8] = b"replay_trace_digest_v1:";
const STEP_OUTPUT_DOMAIN: &[u8] = b"replay_step_output_v1:";
const STEP_EFFECTS_DOMAIN: &[u8] = b"replay_step_effects_v1:";

#[derive(Debug, Clone, Copy)]
struct CoverageRow {
    spec_section: &'static str,
    invariant: &'static str,
    level: &'static str,
    tested: bool,
}

#[derive(Debug)]
struct StepVector {
    step: TraceStep,
    expected_output_preimage_hex: &'static str,
    expected_output_digest: &'static str,
    expected_effects_preimage_hex: &'static str,
    expected_effects_digest: &'static str,
}

#[derive(Debug)]
struct TraceVector {
    name: &'static str,
    steps: Vec<StepVector>,
    expected_trace_preimage_hex: &'static str,
    expected_trace_digest: &'static str,
}

const COVERAGE: &[CoverageRow] = &[
    CoverageRow {
        spec_section: "src/replay/time_travel_engine.rs",
        invariant: "INV-TTR-TRACE-DIGEST-DOMAIN-SEPARATED",
        level: "MUST",
        tested: true,
    },
    CoverageRow {
        spec_section: "src/replay/time_travel_engine.rs",
        invariant: "INV-TTR-TRACE-DIGEST-LENGTH-PREFIXED",
        level: "MUST",
        tested: true,
    },
    CoverageRow {
        spec_section: "src/replay/time_travel_engine.rs",
        invariant: "INV-TTR-STEP-DIGEST-BYTE-STABLE",
        level: "MUST",
        tested: true,
    },
];

fn push_len_prefixed(bytes: &mut Vec<u8>, field: &[u8]) {
    bytes.extend_from_slice(&(u64::try_from(field.len()).unwrap_or(u64::MAX)).to_le_bytes());
    bytes.extend_from_slice(field);
}

fn step_output_preimage(step: &TraceStep) -> Vec<u8> {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(STEP_OUTPUT_DOMAIN);
    push_len_prefixed(&mut bytes, &step.output);
    bytes
}

fn step_effects_preimage(step: &TraceStep) -> Vec<u8> {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(STEP_EFFECTS_DOMAIN);
    bytes.extend_from_slice(
        &(u64::try_from(step.side_effects.len()).unwrap_or(u64::MAX)).to_le_bytes(),
    );
    for effect in &step.side_effects {
        push_len_prefixed(&mut bytes, effect.kind.as_bytes());
        push_len_prefixed(&mut bytes, &effect.payload);
    }
    bytes
}

fn trace_digest_preimage(steps: &[TraceStep]) -> Vec<u8> {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(TRACE_DIGEST_DOMAIN);
    bytes.extend_from_slice(&(u64::try_from(steps.len()).unwrap_or(u64::MAX)).to_le_bytes());
    for step in steps {
        bytes.extend_from_slice(&step.seq.to_le_bytes());
        bytes.extend_from_slice(&step.timestamp_ns.to_le_bytes());
        push_len_prefixed(&mut bytes, &step.input);
        push_len_prefixed(&mut bytes, &step.output);
        bytes.extend_from_slice(
            &(u64::try_from(step.side_effects.len()).unwrap_or(u64::MAX)).to_le_bytes(),
        );
        for effect in &step.side_effects {
            push_len_prefixed(&mut bytes, effect.kind.as_bytes());
            push_len_prefixed(&mut bytes, &effect.payload);
        }
    }
    bytes
}

fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

fn unframed_step_payload(step: &TraceStep) -> Vec<u8> {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&step.seq.to_le_bytes());
    bytes.extend_from_slice(&step.timestamp_ns.to_le_bytes());
    bytes.extend_from_slice(&step.input);
    bytes.extend_from_slice(&step.output);
    for effect in &step.side_effects {
        bytes.extend_from_slice(effect.kind.as_bytes());
        bytes.extend_from_slice(&effect.payload);
    }
    bytes
}

fn environment() -> EnvironmentSnapshot {
    let mut env_vars = BTreeMap::new();
    env_vars.insert(
        "FRANKEN_NODE_PROFILE".to_string(),
        "strict-conformance".to_string(),
    );
    EnvironmentSnapshot::new(
        1_700_000_000_000,
        env_vars,
        "linux-x86_64",
        "franken-node-conformance",
    )
}

fn vectors() -> Vec<TraceVector> {
    vec![
        TraceVector {
            name: "operator_release_trace",
            steps: vec![
                StepVector {
                    step: TraceStep::new(
                        0,
                        b"fleet:quarantine:zone-a".to_vec(),
                        br#"{"decision":"quarantine","risk":91}"#.to_vec(),
                        vec![
                            SideEffect::new("fleet.quarantine", b"zone-a\0ext-alpha".to_vec()),
                            SideEffect::new("audit.append", b"TTR-002:quarantine".to_vec()),
                        ],
                        1_700_000_000_000_000_100,
                    ),
                    expected_output_preimage_hex: "7265706c61795f737465705f6f75747075745f76313a23000000000000007b226465636973696f6e223a2271756172616e74696e65222c227269736b223a39317d",
                    expected_output_digest: "32e98112befd0690146cbd45afd85ca47fefaf8f993275d8e293dd795a9bfed7",
                    expected_effects_preimage_hex: "7265706c61795f737465705f656666656374735f76313a02000000000000001000000000000000666c6565742e71756172616e74696e6510000000000000007a6f6e652d61006578742d616c7068610c0000000000000061756469742e617070656e6412000000000000005454522d3030323a71756172616e74696e65",
                    expected_effects_digest: "f867edfce72c004f459de989ae1d1bf226e97ce87500e0b51b34f119723752a5",
                },
                StepVector {
                    step: TraceStep::new(
                        1,
                        b"fleet:release:inc-001".to_vec(),
                        br#"{"decision":"release","risk":12}"#.to_vec(),
                        vec![
                            SideEffect::new("fleet.release", b"inc-001".to_vec()),
                            SideEffect::new("audit.append", b"TTR-003:release".to_vec()),
                        ],
                        1_700_000_000_000_000_200,
                    ),
                    expected_output_preimage_hex: "7265706c61795f737465705f6f75747075745f76313a20000000000000007b226465636973696f6e223a2272656c65617365222c227269736b223a31327d",
                    expected_output_digest: "684b825aa1bae32aa54a26479aff710c05df3170c2de58e1e3522518e1dec089",
                    expected_effects_preimage_hex: "7265706c61795f737465705f656666656374735f76313a02000000000000000d00000000000000666c6565742e72656c656173650700000000000000696e632d3030310c0000000000000061756469742e617070656e640f000000000000005454522d3030333a72656c65617365",
                    expected_effects_digest: "40aaec57e5c6388bef6dbea5861ebfab2c93e27e8e706c5535039592c4b64829",
                },
            ],
            expected_trace_preimage_hex: "7265706c61795f74726163655f6469676573745f76313a0200000000000000000000000000000064002a36fe9c97171700000000000000666c6565743a71756172616e74696e653a7a6f6e652d6123000000000000007b226465636973696f6e223a2271756172616e74696e65222c227269736b223a39317d02000000000000001000000000000000666c6565742e71756172616e74696e6510000000000000007a6f6e652d61006578742d616c7068610c0000000000000061756469742e617070656e6412000000000000005454522d3030323a71756172616e74696e650100000000000000c8002a36fe9c97171500000000000000666c6565743a72656c656173653a696e632d30303120000000000000007b226465636973696f6e223a2272656c65617365222c227269736b223a31327d02000000000000000d00000000000000666c6565742e72656c656173650700000000000000696e632d3030310c0000000000000061756469742e617070656e640f000000000000005454522d3030333a72656c65617365",
            expected_trace_digest: "845970535feec6490ecbb7f95e6c7c4b4b54c84b705adcbacaa7e3cc27a3b0f6",
        },
        TraceVector {
            name: "boundary_split_ab_c",
            steps: vec![StepVector {
                step: TraceStep::new(
                    0,
                    b"ab".to_vec(),
                    b"c".to_vec(),
                    vec![SideEffect::new("de", b"f".to_vec())],
                    42,
                ),
                expected_output_preimage_hex: "7265706c61795f737465705f6f75747075745f76313a010000000000000063",
                expected_output_digest: "d7b5ae8a3c854b363a431afd6df556982e231fcc52dbb6595de28b03c10e4e66",
                expected_effects_preimage_hex: "7265706c61795f737465705f656666656374735f76313a010000000000000002000000000000006465010000000000000066",
                expected_effects_digest: "8365ab4666a218ea7a8398b68af67ae05ac10696289022b8acf2d16146df3a4d",
            }],
            expected_trace_preimage_hex: "7265706c61795f74726163655f6469676573745f76313a010000000000000000000000000000002a0000000000000002000000000000006162010000000000000063010000000000000002000000000000006465010000000000000066",
            expected_trace_digest: "e0dcc5b8a95b0c8960f57a2c4f397301b37011f652cfddb00b2f7a41ea1dd58c",
        },
        TraceVector {
            name: "boundary_split_a_bc",
            steps: vec![StepVector {
                step: TraceStep::new(
                    0,
                    b"a".to_vec(),
                    b"bc".to_vec(),
                    vec![SideEffect::new("d", b"ef".to_vec())],
                    42,
                ),
                expected_output_preimage_hex: "7265706c61795f737465705f6f75747075745f76313a02000000000000006263",
                expected_output_digest: "92e421a6929d2bf993d6ae02134ff1c2b87dfd1bd034b91cda303f671347bcb1",
                expected_effects_preimage_hex: "7265706c61795f737465705f656666656374735f76313a010000000000000001000000000000006402000000000000006566",
                expected_effects_digest: "7ace257276e99228c13503cd9c0a48ebf1a7ed8df95c4f530474fbd1c0d53a33",
            }],
            expected_trace_preimage_hex: "7265706c61795f74726163655f6469676573745f76313a010000000000000000000000000000002a0000000000000001000000000000006102000000000000006263010000000000000001000000000000006402000000000000006566",
            expected_trace_digest: "fed71fdcb9ed9672810026783c21ca303fe59f0df6143c45af3615f9137384c6",
        },
    ]
}

#[test]
fn replay_trace_canonical_vectors_cover_required_contract() {
    for required in [
        "INV-TTR-TRACE-DIGEST-DOMAIN-SEPARATED",
        "INV-TTR-TRACE-DIGEST-LENGTH-PREFIXED",
        "INV-TTR-STEP-DIGEST-BYTE-STABLE",
    ] {
        assert!(
            COVERAGE.iter().any(|row| {
                row.spec_section == "src/replay/time_travel_engine.rs"
                    && row.invariant == required
                    && row.level == "MUST"
                    && row.tested
            }),
            "{required} must be covered by the replay trace conformance matrix"
        );
    }
}

#[test]
fn replay_trace_canonical_digest_vectors_match_exact_bytes() -> TestResult {
    for vector in vectors() {
        let steps = vector
            .steps
            .iter()
            .map(|step_vector| step_vector.step.clone())
            .collect::<Vec<_>>();
        let trace_preimage = trace_digest_preimage(&steps);
        assert_eq!(
            hex::encode(&trace_preimage),
            vector.expected_trace_preimage_hex,
            "{} trace digest preimage bytes drifted",
            vector.name
        );
        assert_eq!(
            sha256_hex(&trace_preimage),
            vector.expected_trace_digest,
            "{} reference trace digest drifted",
            vector.name
        );
        assert_eq!(
            WorkflowTrace::compute_digest(&steps),
            vector.expected_trace_digest,
            "{} production trace digest drifted",
            vector.name
        );

        for step_vector in &vector.steps {
            let output_preimage = step_output_preimage(&step_vector.step);
            assert_eq!(
                hex::encode(&output_preimage),
                step_vector.expected_output_preimage_hex,
                "{} output digest preimage bytes drifted",
                vector.name
            );
            assert_eq!(
                sha256_hex(&output_preimage),
                step_vector.expected_output_digest,
                "{} reference output digest drifted",
                vector.name
            );
            assert_eq!(
                step_vector.step.output_digest(),
                step_vector.expected_output_digest,
                "{} production output digest drifted",
                vector.name
            );

            let effects_preimage = step_effects_preimage(&step_vector.step);
            assert_eq!(
                hex::encode(&effects_preimage),
                step_vector.expected_effects_preimage_hex,
                "{} side-effect digest preimage bytes drifted",
                vector.name
            );
            assert_eq!(
                sha256_hex(&effects_preimage),
                step_vector.expected_effects_digest,
                "{} reference side-effect digest drifted",
                vector.name
            );
            assert_eq!(
                step_vector.step.side_effects_digest(),
                step_vector.expected_effects_digest,
                "{} production side-effect digest drifted",
                vector.name
            );
        }

        let trace = WorkflowTrace {
            trace_id: format!("trace-{}", vector.name),
            workflow_name: "replay-trace-canonical-conformance".to_string(),
            steps,
            environment: environment(),
            trace_digest: vector.expected_trace_digest.to_string(),
            schema_version: SCHEMA_VERSION.to_string(),
        };
        trace
            .validate()
            .map_err(|err| format!("{} exact vector must validate: {err}", vector.name))?;
    }
    Ok(())
}

#[test]
fn replay_trace_length_framing_splits_ambiguous_boundaries() {
    let vectors = vectors();
    let ab_c = vectors
        .iter()
        .find(|vector| vector.name == "boundary_split_ab_c")
        .expect("ab/c boundary vector exists");
    let a_bc = vectors
        .iter()
        .find(|vector| vector.name == "boundary_split_a_bc")
        .expect("a/bc boundary vector exists");
    let left_step = &ab_c.steps[0].step;
    let right_step = &a_bc.steps[0].step;

    assert_eq!(
        unframed_step_payload(left_step),
        unframed_step_payload(right_step),
        "fixture must model two tuples that collide without length framing"
    );
    assert_ne!(
        ab_c.expected_trace_preimage_hex, a_bc.expected_trace_preimage_hex,
        "length-prefixed trace preimages must split ambiguous tuples"
    );
    assert_ne!(
        ab_c.expected_trace_digest, a_bc.expected_trace_digest,
        "length-prefixed trace digests must split ambiguous tuples"
    );
}
