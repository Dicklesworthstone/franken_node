#![no_main]

use arbitrary::Arbitrary;
use frankenengine_node::tools::replay_bundle::{
    replay_bundle_adversarial_fuzz_one, replay_bundle_batch_adversarial_fuzz_one,
};
use frankenengine_node::tools::replay_bundle_adversarial_fuzz::{
    replay_bundle_adversarial_fuzz_corpus, ReplayBundleAdversarialCase,
    ReplayBundleAdversarialTarget,
};
use libfuzzer_sys::fuzz_target;
use std::sync::LazyLock;

const MAX_REPLAY_BUNDLE_BYTES: usize = 512 * 1024;

static ADVERSARIAL_CORPUS: LazyLock<Vec<ReplayBundleAdversarialCase>> =
    LazyLock::new(replay_bundle_adversarial_fuzz_corpus);

fuzz_target!(|input: FuzzInput| {
    fuzz_raw_adversarial_input(&input);
    fuzz_seeded_adversarial_case(input.seed_selector);
});

fn fuzz_raw_adversarial_input(input: &FuzzInput) {
    if input.raw_json.len() > MAX_REPLAY_BUNDLE_BYTES {
        return;
    }

    if input.use_batch_entrypoint {
        let _ = replay_bundle_batch_adversarial_fuzz_one(&input.raw_json);
    } else {
        let _ = replay_bundle_adversarial_fuzz_one(&input.raw_json);
    }
}

fn fuzz_seeded_adversarial_case(seed_selector: u8) {
    if ADVERSARIAL_CORPUS.is_empty() {
        return;
    }
    let index = usize::from(seed_selector) % ADVERSARIAL_CORPUS.len();
    let case = &ADVERSARIAL_CORPUS[index];
    let result = match &case.target {
        ReplayBundleAdversarialTarget::Single(input) => replay_bundle_adversarial_fuzz_one(input),
        ReplayBundleAdversarialTarget::Batch(input) => {
            replay_bundle_batch_adversarial_fuzz_one(input)
        }
    };
    match result {
        Ok(()) => assert!(
            false,
            "adversarial replay bundle case unexpectedly passed: {}",
            case.name
        ),
        Err(error) => assert!(
            case.expected_error.matches_error(&error),
            "adversarial replay bundle case {} returned unexpected error: {error}",
            case.name
        ),
    }
}

#[derive(Arbitrary, Debug)]
struct FuzzInput {
    raw_json: Vec<u8>,
    use_batch_entrypoint: bool,
    seed_selector: u8,
}
