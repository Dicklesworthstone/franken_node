use frankenengine_node::replay::time_travel_engine::{
    EnvironmentSnapshot, SCHEMA_VERSION, SideEffect, TraceBuilder, TraceStep, WorkflowTrace,
    event_codes,
};
use frankenengine_node::storage::cas::ContentHash;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

type TestResult = Result<(), String>;

const TRACE_DIGEST_DOMAIN: &[u8] = b"replay_trace_digest_v1:";
const STEP_OUTPUT_DOMAIN: &[u8] = b"replay_step_output_v1:";
const STEP_EFFECTS_DOMAIN: &[u8] = b"replay_step_effects_v2:";

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
        push_len_prefixed(&mut bytes, effect.effect_kind.as_bytes());
        push_len_prefixed(&mut bytes, effect.capability_ref.as_bytes());
        push_len_prefixed(&mut bytes, effect.pre_state_hash.as_str().as_bytes());
        push_len_prefixed(&mut bytes, effect.result_hash.as_str().as_bytes());
        push_len_prefixed(&mut bytes, effect.post_state_hash.as_str().as_bytes());
        push_len_prefixed(&mut bytes, &effect.payload);
    }
    bytes
}

fn trace_digest_preimage(trace: &WorkflowTrace) -> Vec<u8> {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(TRACE_DIGEST_DOMAIN);
    push_len_prefixed(&mut bytes, trace.trace_id.as_bytes());
    push_len_prefixed(&mut bytes, trace.workflow_name.as_bytes());
    push_len_prefixed(&mut bytes, trace.schema_version.as_bytes());
    push_len_prefixed(&mut bytes, trace.environment.schema_version.as_bytes());
    bytes.extend_from_slice(&trace.environment.clock_seed_ns.to_le_bytes());
    bytes.extend_from_slice(
        &(u64::try_from(trace.environment.env_vars.len()).unwrap_or(u64::MAX)).to_le_bytes(),
    );
    for (key, value) in &trace.environment.env_vars {
        push_len_prefixed(&mut bytes, key.as_bytes());
        push_len_prefixed(&mut bytes, value.as_bytes());
    }
    push_len_prefixed(&mut bytes, trace.environment.platform.as_bytes());
    push_len_prefixed(&mut bytes, trace.environment.runtime_version.as_bytes());
    bytes.extend_from_slice(&(u64::try_from(trace.steps.len()).unwrap_or(u64::MAX)).to_le_bytes());
    for step in &trace.steps {
        bytes.extend_from_slice(&step.seq.to_le_bytes());
        bytes.extend_from_slice(&step.timestamp_ns.to_le_bytes());
        push_len_prefixed(&mut bytes, &step.input);
        push_len_prefixed(&mut bytes, &step.output);
        bytes.extend_from_slice(
            &(u64::try_from(step.side_effects.len()).unwrap_or(u64::MAX)).to_le_bytes(),
        );
        for effect in &step.side_effects {
            push_len_prefixed(&mut bytes, effect.effect_kind.as_bytes());
            push_len_prefixed(&mut bytes, effect.capability_ref.as_bytes());
            push_len_prefixed(&mut bytes, effect.pre_state_hash.as_str().as_bytes());
            push_len_prefixed(&mut bytes, effect.result_hash.as_str().as_bytes());
            push_len_prefixed(&mut bytes, effect.post_state_hash.as_str().as_bytes());
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
        bytes.extend_from_slice(effect.effect_kind.as_bytes());
        bytes.extend_from_slice(effect.capability_ref.as_bytes());
        bytes.extend_from_slice(effect.pre_state_hash.as_str().as_bytes());
        bytes.extend_from_slice(effect.result_hash.as_str().as_bytes());
        bytes.extend_from_slice(effect.post_state_hash.as_str().as_bytes());
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

fn vector_hash(hex_digit: char) -> ContentHash {
    let digest = hex_digit.to_string().repeat(64);
    ContentHash::parse(&format!("sha256:{digest}")).expect("vector hash is valid")
}

fn boundary_side_effect(effect_kind: &str, capability_ref: &str, payload: &[u8]) -> SideEffect {
    SideEffect::recorded(
        effect_kind,
        capability_ref,
        vector_hash('1'),
        vector_hash('2'),
        vector_hash('3'),
        payload.to_vec(),
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
                    expected_effects_preimage_hex: "7265706c61795f737465705f656666656374735f76323a02000000000000001000000000000000666c6565742e71756172616e74696e651000000000000000666c6565742e71756172616e74696e6547000000000000007368613235363a3935613239343261346437343132393837363633336633613333646666313865343839613235633730366564643930613366386433306433383338643863343147000000000000007368613235363a3334396137323965633361653662616233306433353666343064613336353661623739313164626665343662366465613339393764353137626431363262653347000000000000007368613235363a3334396137323965633361653662616233306433353666343064613336353661623739313164626665343662366465613339393764353137626431363262653310000000000000007a6f6e652d61006578742d616c7068610c0000000000000061756469742e617070656e640c0000000000000061756469742e617070656e6447000000000000007368613235363a3935613239343261346437343132393837363633336633613333646666313865343839613235633730366564643930613366386433306433383338643863343147000000000000007368613235363a6539303338613433613661333139633236356363326261356661363164313961333432353434613430363134633664626339323565626537373935643731613847000000000000007368613235363a6539303338613433613661333139633236356363326261356661363164313961333432353434613430363134633664626339323565626537373935643731613812000000000000005454522d3030323a71756172616e74696e65",
                    expected_effects_digest: "e0e840bd9723e14d387add830b6dadc9ab9c26ae43423dd4f2e77ee9471797d5",
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
                    expected_effects_preimage_hex: "7265706c61795f737465705f656666656374735f76323a02000000000000000d00000000000000666c6565742e72656c656173650d00000000000000666c6565742e72656c6561736547000000000000007368613235363a3935613239343261346437343132393837363633336633613333646666313865343839613235633730366564643930613366386433306433383338643863343147000000000000007368613235363a3932383361656462323533303964363266373438323866643438613134303464326538343634613431653637396264656362623734373363316232313336643447000000000000007368613235363a393238336165646232353330396436326637343832386664343861313430346432653834363461343165363739626465636262373437336331623231333664340700000000000000696e632d3030310c0000000000000061756469742e617070656e640c0000000000000061756469742e617070656e6447000000000000007368613235363a3935613239343261346437343132393837363633336633613333646666313865343839613235633730366564643930613366386433306433383338643863343147000000000000007368613235363a3063306363633739393135396661633636643162396234663330633330333736386465623966333430643037346263363535613033326561313130316235393947000000000000007368613235363a306330636363373939313539666163363664316239623466333063333033373638646562396633343064303734626336353561303332656131313031623539390f000000000000005454522d3030333a72656c65617365",
                    expected_effects_digest: "7710d9546433a3df9219449e2f513c9e669870de1933c13370fcdfae507e00db",
                },
            ],
            expected_trace_preimage_hex: "7265706c61795f74726163655f6469676573745f76313a1c0000000000000074726163652d6f70657261746f725f72656c656173655f747261636522000000000000007265706c61792d74726163652d63616e6f6e6963616c2d636f6e666f726d616e636508000000000000007474722d76312e3108000000000000007474722d76312e310068e5cf8b010000010000000000000014000000000000004652414e4b454e5f4e4f44455f50524f46494c4512000000000000007374726963742d636f6e666f726d616e63650c000000000000006c696e75782d7838365f363418000000000000006672616e6b656e2d6e6f64652d636f6e666f726d616e63650200000000000000000000000000000064002a36fe9c97171700000000000000666c6565743a71756172616e74696e653a7a6f6e652d6123000000000000007b226465636973696f6e223a2271756172616e74696e65222c227269736b223a39317d02000000000000001000000000000000666c6565742e71756172616e74696e651000000000000000666c6565742e71756172616e74696e6547000000000000007368613235363a3935613239343261346437343132393837363633336633613333646666313865343839613235633730366564643930613366386433306433383338643863343147000000000000007368613235363a3334396137323965633361653662616233306433353666343064613336353661623739313164626665343662366465613339393764353137626431363262653347000000000000007368613235363a3334396137323965633361653662616233306433353666343064613336353661623739313164626665343662366465613339393764353137626431363262653310000000000000007a6f6e652d61006578742d616c7068610c0000000000000061756469742e617070656e640c0000000000000061756469742e617070656e6447000000000000007368613235363a3935613239343261346437343132393837363633336633613333646666313865343839613235633730366564643930613366386433306433383338643863343147000000000000007368613235363a6539303338613433613661333139633236356363326261356661363164313961333432353434613430363134633664626339323565626537373935643731613847000000000000007368613235363a6539303338613433613661333139633236356363326261356661363164313961333432353434613430363134633664626339323565626537373935643731613812000000000000005454522d3030323a71756172616e74696e650100000000000000c8002a36fe9c97171500000000000000666c6565743a72656c656173653a696e632d30303120000000000000007b226465636973696f6e223a2272656c65617365222c227269736b223a31327d02000000000000000d00000000000000666c6565742e72656c656173650d00000000000000666c6565742e72656c6561736547000000000000007368613235363a3935613239343261346437343132393837363633336633613333646666313865343839613235633730366564643930613366386433306433383338643863343147000000000000007368613235363a3932383361656462323533303964363266373438323866643438613134303464326538343634613431653637396264656362623734373363316232313336643447000000000000007368613235363a393238336165646232353330396436326637343832386664343861313430346432653834363461343165363739626465636262373437336331623231333664340700000000000000696e632d3030310c0000000000000061756469742e617070656e640c0000000000000061756469742e617070656e6447000000000000007368613235363a3935613239343261346437343132393837363633336633613333646666313865343839613235633730366564643930613366386433306433383338643863343147000000000000007368613235363a3063306363633739393135396661633636643162396234663330633330333736386465623966333430643037346263363535613033326561313130316235393947000000000000007368613235363a306330636363373939313539666163363664316239623466333063333033373638646562396633343064303734626336353561303332656131313031623539390f000000000000005454522d3030333a72656c65617365",
            expected_trace_digest: "6f2a9fdea934cf14241e52bb97e6ffd6d22caf75ac117e4f45b0e51db129e03e",
        },
        TraceVector {
            name: "boundary_split_ab_c",
            steps: vec![StepVector {
                step: TraceStep::new(
                    0,
                    b"ab".to_vec(),
                    b"c".to_vec(),
                    vec![boundary_side_effect("de", "", b"f")],
                    42,
                ),
                expected_output_preimage_hex: "7265706c61795f737465705f6f75747075745f76313a010000000000000063",
                expected_output_digest: "d7b5ae8a3c854b363a431afd6df556982e231fcc52dbb6595de28b03c10e4e66",
                expected_effects_preimage_hex: "7265706c61795f737465705f656666656374735f76323a010000000000000002000000000000006465000000000000000047000000000000007368613235363a3131313131313131313131313131313131313131313131313131313131313131313131313131313131313131313131313131313131313131313131313131313147000000000000007368613235363a3232323232323232323232323232323232323232323232323232323232323232323232323232323232323232323232323232323232323232323232323232323247000000000000007368613235363a33333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333010000000000000066",
                expected_effects_digest: "42dc0e51ca98b525f67aa21a82e030e7a1cfc864959708268ef1919f5a6b07d1",
            }],
            expected_trace_preimage_hex: "7265706c61795f74726163655f6469676573745f76313a190000000000000074726163652d626f756e646172795f73706c69745f61625f6322000000000000007265706c61792d74726163652d63616e6f6e6963616c2d636f6e666f726d616e636508000000000000007474722d76312e3108000000000000007474722d76312e310068e5cf8b010000010000000000000014000000000000004652414e4b454e5f4e4f44455f50524f46494c4512000000000000007374726963742d636f6e666f726d616e63650c000000000000006c696e75782d7838365f363418000000000000006672616e6b656e2d6e6f64652d636f6e666f726d616e6365010000000000000000000000000000002a0000000000000002000000000000006162010000000000000063010000000000000002000000000000006465000000000000000047000000000000007368613235363a3131313131313131313131313131313131313131313131313131313131313131313131313131313131313131313131313131313131313131313131313131313147000000000000007368613235363a3232323232323232323232323232323232323232323232323232323232323232323232323232323232323232323232323232323232323232323232323232323247000000000000007368613235363a33333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333010000000000000066",
            expected_trace_digest: "c62d5768c3cf25a31052eeee17340a9b2697bcab169bdd5436b6f17255fd4377",
        },
        TraceVector {
            name: "boundary_split_a_bc",
            steps: vec![StepVector {
                step: TraceStep::new(
                    0,
                    b"a".to_vec(),
                    b"bc".to_vec(),
                    vec![boundary_side_effect("d", "e", b"f")],
                    42,
                ),
                expected_output_preimage_hex: "7265706c61795f737465705f6f75747075745f76313a02000000000000006263",
                expected_output_digest: "92e421a6929d2bf993d6ae02134ff1c2b87dfd1bd034b91cda303f671347bcb1",
                expected_effects_preimage_hex: "7265706c61795f737465705f656666656374735f76323a010000000000000001000000000000006401000000000000006547000000000000007368613235363a3131313131313131313131313131313131313131313131313131313131313131313131313131313131313131313131313131313131313131313131313131313147000000000000007368613235363a3232323232323232323232323232323232323232323232323232323232323232323232323232323232323232323232323232323232323232323232323232323247000000000000007368613235363a33333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333010000000000000066",
                expected_effects_digest: "5bd3e7bb357e523a3f5aa805ee8061357116ed9328807ab81a5f6f0ea552985a",
            }],
            expected_trace_preimage_hex: "7265706c61795f74726163655f6469676573745f76313a190000000000000074726163652d626f756e646172795f73706c69745f615f626322000000000000007265706c61792d74726163652d63616e6f6e6963616c2d636f6e666f726d616e636508000000000000007474722d76312e3108000000000000007474722d76312e310068e5cf8b010000010000000000000014000000000000004652414e4b454e5f4e4f44455f50524f46494c4512000000000000007374726963742d636f6e666f726d616e63650c000000000000006c696e75782d7838365f363418000000000000006672616e6b656e2d6e6f64652d636f6e666f726d616e6365010000000000000000000000000000002a0000000000000001000000000000006102000000000000006263010000000000000001000000000000006401000000000000006547000000000000007368613235363a3131313131313131313131313131313131313131313131313131313131313131313131313131313131313131313131313131313131313131313131313131313147000000000000007368613235363a3232323232323232323232323232323232323232323232323232323232323232323232323232323232323232323232323232323232323232323232323232323247000000000000007368613235363a33333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333010000000000000066",
            expected_trace_digest: "f31b40b0c4e50aba3fe517eff63d10079e9f85b6721c82c0becae3e5b3f38d50",
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
        let trace = WorkflowTrace {
            trace_id: format!("trace-{}", vector.name),
            workflow_name: "replay-trace-canonical-conformance".to_string(),
            steps,
            environment: environment(),
            trace_digest: vector.expected_trace_digest.to_string(),
            schema_version: SCHEMA_VERSION.to_string(),
        };
        let trace_preimage = trace_digest_preimage(&trace);
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
            trace.canonical_digest(),
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

        trace
            .validate()
            .map_err(|err| format!("{} exact vector must validate: {err}", vector.name))?;
    }
    Ok(())
}

#[test]
fn replay_trace_builder_build_preserves_canonical_digest_validation() -> TestResult {
    let mut builder = TraceBuilder::new(
        "trace-builder-conformance",
        "replay-trace-canonical-conformance",
        environment(),
    );
    for step_vector in &vectors()[0].steps {
        builder.record_step(
            step_vector.step.input.clone(),
            step_vector.step.output.clone(),
            step_vector.step.side_effects.clone(),
            step_vector.step.timestamp_ns,
        );
    }

    let (trace, audit) = builder
        .build()
        .map_err(|err| format!("trace builder should build canonical vector: {err}"))?;

    assert_eq!(
        trace.trace_digest,
        trace.canonical_digest(),
        "builder must store the canonical digest it validated"
    );
    assert!(
        audit
            .iter()
            .any(|entry| entry.event_code.as_str().eq(event_codes::TTR_009)),
        "builder audit must record integrity validation success"
    );
    trace
        .validate()
        .map_err(|err| format!("builder trace should remain publicly valid: {err}"))
}

#[test]
fn replay_trace_builder_build_reuses_precomputed_digest_but_output_still_validates() -> TestResult {
    let mut builder = TraceBuilder::new(
        "trace-builder-precomputed-digest",
        "replay-trace-canonical-conformance",
        environment(),
    );
    let step_vector = &vectors()[0].steps[0];
    builder.record_step(
        step_vector.step.input.clone(),
        step_vector.step.output.clone(),
        step_vector.step.side_effects.clone(),
        step_vector.step.timestamp_ns,
    );

    let (mut trace, audit) = builder
        .build()
        .map_err(|err| format!("trace builder should validate with precomputed digest: {err}"))?;

    assert_eq!(
        trace.trace_digest,
        trace.canonical_digest(),
        "builder must persist the same digest it validated during build"
    );
    assert!(
        audit
            .iter()
            .any(|entry| entry.event_code.as_str().eq(event_codes::TTR_009)),
        "builder audit must still record integrity validation success"
    );

    trace.steps[0].output.push(0xff);
    assert!(
        trace.validate().is_err(),
        "public validation must still catch post-build payload mutation"
    );
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
