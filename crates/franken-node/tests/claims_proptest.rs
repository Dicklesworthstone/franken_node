use frankenengine_node::claims::claim_compiler::{
    ClaimCompiler, CompilationResult, CompiledContract, CompilerConfig, ExternalClaim,
    ScoreboardConfig, ScoreboardPipeline, ScoreboardSnapshot,
};
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
}
