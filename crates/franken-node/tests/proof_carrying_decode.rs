//! Determinism property tests for proof-carrying decode repair artifacts.

use frankenengine_node::repair::proof_carrying_decode::{
    AlgorithmId, Fragment, ProofCarryingDecodeError, ProofCarryingDecoder, ProofMode,
};
use proptest::prelude::*;
use proptest::string::string_regex;

const MAX_ALGORITHM_ID_BYTES: usize = 256;

fn deterministic_decoder() -> ProofCarryingDecoder {
    ProofCarryingDecoder::new(ProofMode::Mandatory, "test-signer", "test-secret")
}

#[test]
fn register_algorithm_rejects_overlong_and_control_ids() {
    let mut decoder = deterministic_decoder();
    let overlong_id = "x".repeat(MAX_ALGORITHM_ID_BYTES + 1);
    let overlong_err = decoder
        .register_algorithm(AlgorithmId::new(&overlong_id))
        .expect_err("overlong algorithm_id must fail closed");

    assert!(matches!(
        overlong_err,
        ProofCarryingDecodeError::ReconstructionFailed { .. }
    ));
    assert!(overlong_err.to_string().contains("exceeds maximum length"));

    let mut decoder = deterministic_decoder();
    let control_err = decoder
        .register_algorithm(AlgorithmId::new("algo\r\nINJECT"))
        .expect_err("control-character algorithm_id must fail closed");

    assert!(matches!(
        control_err,
        ProofCarryingDecodeError::ReconstructionFailed { .. }
    ));
    assert!(control_err.to_string().contains("control characters"));
    assert!(!control_err.to_string().contains("INJECT"));

    let mut decoder = deterministic_decoder();
    let at_limit_id = "y".repeat(MAX_ALGORITHM_ID_BYTES);
    decoder
        .register_algorithm(AlgorithmId::new(&at_limit_id))
        .expect("algorithm_id at length limit should be accepted");
    assert!(
        decoder
            .registered_algorithms()
            .iter()
            .any(|algorithm| algorithm.as_str() == at_limit_id)
    );
}

proptest! {
    #![proptest_config(proptest::test_runner::Config::with_cases(100))]

    #[test]
    fn proof_deterministic_across_random_valid_inputs(
        object_id in string_regex("obj-[a-z0-9_-]{1,24}").expect("object id regex should compile"),
        trace_id in string_regex("trace-[a-z0-9_-]{1,24}").expect("trace id regex should compile"),
        timestamp_epoch_secs in any::<u64>(),
        algorithm_id in prop_oneof![
            Just(AlgorithmId::new("reed_solomon_8_4")),
            Just(AlgorithmId::new("xor_parity_2")),
            Just(AlgorithmId::new("simple_concat")),
        ],
        fragments in prop::collection::vec(
            (
                string_regex("frag-[a-z0-9_-]{1,24}")
                    .expect("fragment id regex should compile"),
                prop::collection::vec(any::<u8>(), 0..=128),
            ),
            1..=8,
        ),
    ) {
        let fragments = fragments
            .into_iter()
            .map(|(fragment_id, data)| Fragment { fragment_id, data })
            .collect::<Vec<_>>();
        let mut first_decoder = deterministic_decoder();
        let mut second_decoder = deterministic_decoder();
        let first = first_decoder
            .decode(
                &object_id,
                &fragments,
                &algorithm_id,
                timestamp_epoch_secs,
                &trace_id,
            )
            .map_err(|err| {
                TestCaseError::fail(format!(
                    "first decode unexpectedly failed for deterministic case: {err}"
                ))
            })?;
        let second = second_decoder
            .decode(
                &object_id,
                &fragments,
                &algorithm_id,
                timestamp_epoch_secs,
                &trace_id,
            )
            .map_err(|err| {
                TestCaseError::fail(format!(
                    "second decode unexpectedly failed for deterministic case: {err}"
                ))
            })?;

        prop_assert_eq!(
            &first.output_data,
            &second.output_data,
            "decode output bytes changed across identical inputs"
        );
        prop_assert_eq!(
            first.proof.as_ref(),
            second.proof.as_ref(),
            "repair proof structure changed across identical inputs"
        );

        let first_bytes = serde_json::to_vec(&first).map_err(|err| {
            TestCaseError::fail(format!(
                "failed serializing first decode result for deterministic comparison: {err}"
            ))
        })?;
        let second_bytes = serde_json::to_vec(&second).map_err(|err| {
            TestCaseError::fail(format!(
                "failed serializing second decode result for deterministic comparison: {err}"
            ))
        })?;
        prop_assert_eq!(
            first_bytes,
            second_bytes,
            "serialized decode result bytes changed across identical inputs"
        );
    }
}
