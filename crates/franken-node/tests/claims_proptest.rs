use frankenengine_node::claims::claim_compiler::{
    ClaimCompiler, CompilationResult, CompiledContract, CompilerConfig, ExternalClaim,
    ScoreboardConfig, ScoreboardPipeline, ScoreboardSnapshot,
};
use frankenengine_node::connector::claim_compiler as connector_claims;
use proptest::{collection::vec, prelude::*};

fn bounded_text() -> impl Strategy<Value = String> {
    "[A-Za-z0-9_.:/= -]{1,48}"
}

fn evidence_uri() -> impl Strategy<Value = String> {
    "[A-Za-z0-9_.-]{1,32}".prop_map(|path| format!("https://evidence.example.com/{path}"))
}

fn external_claim_strategy() -> impl Strategy<Value = ExternalClaim> {
    (
        bounded_text(),
        bounded_text(),
        vec(evidence_uri(), 1..8),
        bounded_text(),
    )
        .prop_map(
            |(claim_id, claim_text, evidence_uris, source_id)| ExternalClaim {
                claim_id,
                claim_text,
                evidence_uris,
                source_id,
            },
        )
}

fn compiled_contract_from_claim(
    claim: &ExternalClaim,
    now_epoch_ms: u64,
) -> Option<CompiledContract> {
    let compiler = ClaimCompiler::new(CompilerConfig::new(
        "proptest-signer",
        "proptest-key",
        now_epoch_ms,
    ));
    match compiler.compile(claim) {
        CompilationResult::Compiled { contract, .. } => Some(contract),
        CompilationResult::Rejected { .. } => None,
    }
}

fn connector_text(max_len: usize) -> impl Strategy<Value = String> {
    vec(
        prop_oneof![
            Just('a'),
            Just('Z'),
            Just('0'),
            Just('_'),
            Just('-'),
            Just('/'),
            Just(':'),
            Just(' '),
            Just('\t'),
            Just('\n'),
        ],
        0..max_len,
    )
    .prop_map(|chars| chars.into_iter().collect())
}

fn connector_claim_text() -> impl Strategy<Value = String> {
    prop_oneof![
        Just(String::new()),
        Just(" \t\n ".to_string()),
        connector_text(192),
    ]
}

fn connector_schema_version() -> impl Strategy<Value = String> {
    prop_oneof![
        Just(connector_claims::SCHEMA_VERSION.to_string()),
        Just(format!("{} ", connector_claims::SCHEMA_VERSION)),
        Just(String::new()),
        connector_text(32),
    ]
}

fn connector_source() -> impl Strategy<Value = Option<connector_claims::ClaimSource>> {
    prop_oneof![
        Just(None),
        (connector_text(48), connector_text(32), any::<u64>()).prop_map(
            |(submitter_id, origin, received_at_ms)| Some(connector_claims::ClaimSource {
                submitter_id,
                origin,
                received_at_ms,
            }),
        ),
    ]
}

fn connector_evidence_uri() -> impl Strategy<Value = String> {
    prop_oneof![
        Just(String::new()),
        Just(" \t\n ".to_string()),
        connector_text(32).prop_map(|path| format!("https://evidence.example.com/{path}")),
        connector_text(32).prop_map(|name| format!("urn:claim:{name}")),
        connector_text(32).prop_map(|path| format!("missing-scheme-{path}")),
    ]
}

fn connector_evidence_link() -> impl Strategy<Value = connector_claims::EvidenceLink> {
    (
        connector_text(32),
        connector_evidence_uri(),
        connector_text(80),
    )
        .prop_map(
            |(label, uri, content_digest)| connector_claims::EvidenceLink {
                label,
                uri,
                content_digest,
            },
        )
}

fn connector_raw_claim() -> impl Strategy<Value = connector_claims::RawClaim> {
    (
        connector_text(48),
        connector_claim_text(),
        connector_source(),
        vec(connector_evidence_link(), 0..5),
        connector_schema_version(),
        connector_text(48),
    )
        .prop_map(
            |(claim_id, claim_text, source, evidence_links, schema_version, trace_id)| {
                connector_claims::RawClaim {
                    claim_id,
                    claim_text,
                    source,
                    evidence_links,
                    schema_version,
                    trace_id,
                }
            },
        )
}

fn connector_uri_valid(uri: &str) -> bool {
    let trimmed = uri.trim();
    !trimmed.is_empty() && (trimmed.contains("://") || trimmed.starts_with("urn:"))
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    #[test]
    fn external_claim_json_roundtrip(claim in external_claim_strategy()) {
        let encoded = serde_json::to_string(&claim).expect("external claim should encode");
        let decoded: ExternalClaim = serde_json::from_str(&encoded)
            .expect("encoded external claim should decode");

        prop_assert_eq!(&decoded, &claim);
        prop_assert_eq!(serde_json::to_string(&decoded).expect("re-encode"), encoded);
    }

    #[test]
    fn compilation_result_json_roundtrip(
        claim in external_claim_strategy(),
        now_epoch_ms in 1_u64..1_000_000_u64,
    ) {
        let compiler = ClaimCompiler::new(CompilerConfig::new(
            "proptest-signer",
            "proptest-key",
            now_epoch_ms,
        ));
        let result = compiler.compile(&claim);
        let encoded = serde_json::to_string(&result).expect("compilation result should encode");
        let decoded: CompilationResult = serde_json::from_str(&encoded)
            .expect("encoded compilation result should decode");

        prop_assert_eq!(&decoded, &result);
        prop_assert_eq!(serde_json::to_string(&decoded).expect("re-encode"), encoded);
    }

    #[test]
    fn compiled_contract_json_roundtrip(
        claim in external_claim_strategy(),
        now_epoch_ms in 1_u64..1_000_000_u64,
    ) {
        let Some(contract) = compiled_contract_from_claim(&claim, now_epoch_ms) else {
            return Ok(());
        };
        let encoded = serde_json::to_string(&contract).expect("compiled contract should encode");
        let decoded: CompiledContract = serde_json::from_str(&encoded)
            .expect("encoded compiled contract should decode");

        prop_assert_eq!(&decoded, &contract);
        prop_assert_eq!(serde_json::to_string(&decoded).expect("re-encode"), encoded);
    }

    #[test]
    fn scoreboard_snapshot_json_roundtrip(
        claim in external_claim_strategy(),
        compiled_at_epoch_ms in 1_u64..1_000_000_u64,
    ) {
        let Some(contract) = compiled_contract_from_claim(&claim, compiled_at_epoch_ms) else {
            return Ok(());
        };
        let scoreboard = ScoreboardPipeline::new(ScoreboardConfig::new(
            "proptest-signer",
            "proptest-key",
            compiled_at_epoch_ms + 1,
            60_000,
        ));
        let Some(snapshot) = scoreboard.build_snapshot("proptest-snapshot", &[contract]) else {
            return Ok(());
        };

        let encoded = serde_json::to_string(&snapshot)
            .expect("scoreboard snapshot should encode");
        let decoded: ScoreboardSnapshot = serde_json::from_str(&encoded)
            .expect("encoded scoreboard snapshot should decode");

        prop_assert_eq!(&decoded, &snapshot);
        prop_assert_eq!(serde_json::to_string(&decoded).expect("re-encode"), encoded);
    }

    #[test]
    fn connector_claim_compiler_fuzz_generated_inputs_fail_closed_or_publish_atomically(
        raw in connector_raw_claim(),
        scoreboard_capacity in 0_usize..4,
        max_claim_text_bytes in 0_usize..128,
    ) {
        let config = connector_claims::ClaimCompilerConfig {
            scoreboard_capacity,
            max_claim_text_bytes,
        };
        let mut compiler = connector_claims::ClaimCompiler::new(config.clone());
        let first = compiler.compile_claim(&raw);
        let mut repeat_compiler = connector_claims::ClaimCompiler::new(config);
        let repeat = repeat_compiler.compile_claim(&raw);

        prop_assert_eq!(
            &first,
            &repeat,
            "compilation must be deterministic for identical generated claims"
        );

        match first {
            Ok(compiled) => {
                prop_assert!(!compiled.normalised_text.is_empty());
                prop_assert_eq!(compiled.normalised_text.as_str(), raw.claim_text.trim());
                prop_assert!(compiled.normalised_text.len() <= max_claim_text_bytes);
                prop_assert_eq!(
                    compiled.schema_version.as_str(),
                    connector_claims::SCHEMA_VERSION
                );
                prop_assert!(!compiled.evidence_links.is_empty());
                prop_assert!(
                    compiled
                        .evidence_links
                        .iter()
                        .all(|link| connector_uri_valid(&link.uri))
                );

                let source = raw.source.as_ref().expect("compiled claim must have source");
                prop_assert!(!source.submitter_id.trim().is_empty());
                prop_assert!(!source.origin.trim().is_empty());

                let mut duplicate_batch =
                    connector_claims::ClaimCompiler::new(connector_claims::ClaimCompilerConfig {
                        scoreboard_capacity: 2,
                        max_claim_text_bytes,
                    });
                let duplicate_err = duplicate_batch
                    .publish_batch(&[compiled.clone(), compiled.clone()])
                    .expect_err("duplicate claim IDs must roll back the whole batch");
                let duplicate_rejected = matches!(
                    duplicate_err,
                    connector_claims::ClaimCompilerError::DuplicateClaimId { .. }
                );
                prop_assert!(duplicate_rejected);
                prop_assert_eq!(duplicate_batch.entry_count(), 0);

                let mut tampered = compiled.clone();
                tampered.normalised_text.push_str("-tampered");
                let mut tampered_batch =
                    connector_claims::ClaimCompiler::new(connector_claims::ClaimCompilerConfig {
                        scoreboard_capacity: 1,
                        max_claim_text_bytes,
                    });
                let tampered_err = tampered_batch
                    .publish_batch(&[tampered])
                    .expect_err("tampered compiled claim must fail digest verification");
                let digest_rejected = matches!(
                    tampered_err,
                    connector_claims::ClaimCompilerError::DigestMismatch { .. }
                );
                prop_assert!(digest_rejected);
                prop_assert_eq!(tampered_batch.entry_count(), 0);

                let mut publisher =
                    connector_claims::ClaimCompiler::new(connector_claims::ClaimCompilerConfig {
                        scoreboard_capacity,
                        max_claim_text_bytes,
                    });
                if scoreboard_capacity == 0 {
                    let err = publisher
                        .publish_batch(std::slice::from_ref(&compiled))
                        .expect_err("zero-capacity scoreboard must reject compiled claims");
                    let capacity_rejected = matches!(
                        err,
                        connector_claims::ClaimCompilerError::ScoreboardFull { capacity: 0 }
                    );
                    prop_assert!(capacity_rejected);
                    prop_assert_eq!(publisher.entry_count(), 0);
                } else {
                    let snapshot = publisher
                        .publish_batch(std::slice::from_ref(&compiled))
                        .expect("nonempty capacity must publish one compiled claim");
                    prop_assert_eq!(snapshot.entry_count, 1);
                    prop_assert!(publisher.verify_snapshot_digest(&snapshot).expect(
                        "fresh snapshot digest should verify against committed entries"
                    ));
                }
            }
            Err(_) => {
                prop_assert_eq!(compiler.entry_count(), 0);
                prop_assert!(
                    compiler.events().iter().any(|event| {
                        event.event_code == connector_claims::event_codes::CLMC_003
                            || event.event_code == connector_claims::event_codes::CLMC_008
                    }),
                    "rejected generated claims must emit a fail-closed audit event"
                );
            }
        }
    }
}
