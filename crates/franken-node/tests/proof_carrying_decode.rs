//! Determinism property tests for proof-carrying decode repair artifacts.

use frankenengine_node::repair::proof_carrying_decode::{
    AlgorithmId, Fragment, ProofCarryingDecoder, ProofMode,
};
use proptest::prelude::*;
use proptest::string::string_regex;

fn deterministic_decoder() -> ProofCarryingDecoder {
    ProofCarryingDecoder::new(ProofMode::Mandatory, "test-signer", "test-secret")
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
