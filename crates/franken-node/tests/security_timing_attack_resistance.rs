//! Timing attack resistance tests for security-critical functions.
//!
//! This test suite validates that security-sensitive operations use constant-time
//! implementations to prevent timing side-channel attacks. Critical for protecting
//! cryptographic secrets and authentication tokens.

use frankenengine_node::security::constant_time::{ct_eq, ct_eq_bytes};
use std::hint::black_box;
use std::time::{Duration, Instant};

const MEDIAN_ROUNDS: usize = 7;

fn median_duration(mut samples: [Duration; MEDIAN_ROUNDS]) -> Duration {
    samples.sort_unstable();
    samples[MEDIAN_ROUNDS / 2]
}

fn measure_str_batch(left: &str, right: &str, expected: bool, trials: usize) -> Duration {
    let start = Instant::now();
    for _ in 0..trials {
        assert_eq!(ct_eq(black_box(left), black_box(right)), expected);
    }
    start.elapsed()
}

fn measure_bytes_batch(left: &[u8], right: &[u8], expected: bool, trials: usize) -> Duration {
    let start = Instant::now();
    for _ in 0..trials {
        assert_eq!(ct_eq_bytes(black_box(left), black_box(right)), expected);
    }
    start.elapsed()
}

fn alternating_str_medians<const N: usize>(
    base: &str,
    candidates: [(&str, bool); N],
    trials: usize,
) -> [Duration; N] {
    for _ in 0..1000 {
        for (candidate, _) in candidates {
            let _ = black_box(ct_eq(black_box(base), black_box(candidate)));
        }
    }
    let mut rounds = [[Duration::ZERO; MEDIAN_ROUNDS]; N];
    for round in 0..MEDIAN_ROUNDS {
        for step in 0..N {
            let idx = (step + round) % N;
            let (candidate, expected) = candidates[idx];
            rounds[idx][round] = measure_str_batch(base, candidate, expected, trials);
        }
    }
    std::array::from_fn(|idx| median_duration(rounds[idx]))
}

fn alternating_bytes_medians<const N: usize>(
    base: &[u8],
    candidates: [(&[u8], bool); N],
    trials: usize,
) -> [Duration; N] {
    for _ in 0..1000 {
        for (candidate, _) in candidates {
            let _ = black_box(ct_eq_bytes(black_box(base), black_box(candidate)));
        }
    }
    let mut rounds = [[Duration::ZERO; MEDIAN_ROUNDS]; N];
    for round in 0..MEDIAN_ROUNDS {
        for step in 0..N {
            let idx = (step + round) % N;
            let (candidate, expected) = candidates[idx];
            rounds[idx][round] = measure_bytes_batch(base, candidate, expected, trials);
        }
    }
    std::array::from_fn(|idx| median_duration(rounds[idx]))
}

// ──────────────────────────────────────────────────────────────────────────────
// Constant-Time Comparison Tests
// ──────────────────────────────────────────────────────────────────────────────

#[test]
fn test_ct_eq_timing_independence() {
    let secret = "supersecret_authentication_token_1234567890";
    let correct = "supersecret_authentication_token_1234567890";
    let incorrect_early = "differently_authentication_token_1234567890";
    let incorrect_late = "supersecret_authentication_token_9876543210";
    assert_eq!(secret.len(), correct.len());
    assert_eq!(secret.len(), incorrect_early.len());
    assert_eq!(secret.len(), incorrect_late.len());

    let [correct_time, early_time, late_time] = alternating_str_medians(
        secret,
        [
            (correct, true),
            (incorrect_early, false),
            (incorrect_late, false),
        ],
        10_000,
    );

    let max_time = correct_time.max(early_time).max(late_time);
    let min_time = correct_time.min(early_time).min(late_time);
    let variance_ratio = max_time.as_nanos() as f64 / min_time.as_nanos().max(1) as f64;

    assert!(
        variance_ratio < 1.5,
        "Timing variance too high: {variance_ratio:.2}, correct: {correct_time:?}, early: {early_time:?}, late: {late_time:?}"
    );
}

#[test]
fn test_ct_eq_bytes_timing_independence() {
    let secret_hash = b"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
    let correct_hash = b"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
    let incorrect_start = b"f3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
    let incorrect_end = b"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b856";

    let [correct_time, start_time, end_time] = alternating_bytes_medians(
        secret_hash,
        [
            (correct_hash, true),
            (incorrect_start, false),
            (incorrect_end, false),
        ],
        10_000,
    );

    let max_time = correct_time.max(start_time).max(end_time);
    let min_time = correct_time.min(start_time).min(end_time);
    let variance_ratio = max_time.as_nanos() as f64 / min_time.as_nanos().max(1) as f64;

    assert!(
        variance_ratio < 1.5,
        "Byte comparison timing variance too high: {variance_ratio:.2}"
    );
}

#[test]
fn test_ct_eq_different_lengths() {
    let short = "short";
    let long = "this_is_a_much_longer_string";

    let mut samples = [Duration::ZERO; MEDIAN_ROUNDS];
    for sample in &mut samples {
        let start = Instant::now();
        for _ in 0..10_000 {
            assert!(!ct_eq(black_box(short), black_box(long)));
            assert!(!ct_eq(black_box(long), black_box(short)));
        }
        *sample = start.elapsed();
    }
    let duration = median_duration(samples);

    assert!(duration < Duration::from_millis(10));
}

#[test]
fn test_ct_eq_empty_strings() {
    let empty1 = "";
    let empty2 = "";
    let non_empty = "not empty";

    let mut samples = [Duration::ZERO; MEDIAN_ROUNDS];
    for sample in &mut samples {
        let start = Instant::now();
        for _ in 0..10_000 {
            assert!(ct_eq(black_box(empty1), black_box(empty2)));
            assert!(!ct_eq(black_box(empty1), black_box(non_empty)));
            assert!(!ct_eq(black_box(non_empty), black_box(empty1)));
        }
        *sample = start.elapsed();
    }
    let duration = median_duration(samples);

    assert!(duration < Duration::from_millis(5));
}

// ──────────────────────────────────────────────────────────────────────────────
// Security Property Tests
// ──────────────────────────────────────────────────────────────────────────────

#[test]
fn test_no_early_termination_on_mismatch() {
    let base = "authentication_token_base_value_1234567890abcdef";
    let mut variants = Vec::new();

    for pos in [
        0,
        base.len() / 4,
        base.len() / 2,
        3 * base.len() / 4,
        base.len() - 1,
    ] {
        let mut bytes = base.as_bytes().to_vec();
        bytes[pos] ^= 1;
        variants.push(String::from_utf8(bytes).expect("valid ascii variant"));
    }

    let timings = alternating_str_medians(
        base,
        [
            (&variants[0], false),
            (&variants[1], false),
            (&variants[2], false),
            (&variants[3], false),
            (&variants[4], false),
        ],
        5_000,
    );

    let max_time = timings.iter().max().expect("max timing");
    let min_time = timings.iter().min().expect("min timing");
    let variance = max_time.as_nanos() as f64 / min_time.as_nanos().max(1) as f64;

    assert!(
        variance < 2.0,
        "Position-dependent timing detected: variance {variance:.2}, timings: {timings:?}"
    );
}

#[test]
fn test_consistent_timing_under_load() {
    let secret = "critical_security_token_must_be_constant_time";
    let candidate1 = "critical_security_token_must_be_constant_time";
    let candidate2 = "altered__security_token_must_be_constant_time";
    assert_eq!(secret.len(), candidate1.len());
    assert_eq!(secret.len(), candidate2.len());

    let load_thread = std::thread::spawn(|| {
        let mut acc = 0_u64;
        for idx in 0..100_000_u64 {
            acc = acc.wrapping_add(black_box(idx).rotate_left(7));
        }
        black_box(acc)
    });

    let [match_time, mismatch_time] =
        alternating_str_medians(secret, [(candidate1, true), (candidate2, false)], 5_000);
    let _ = load_thread.join();

    let ratio = match_time.as_nanos() as f64 / mismatch_time.as_nanos().max(1) as f64;
    assert!(
        ratio > 0.5 && ratio < 2.0,
        "Timing not consistent under load: match={match_time:?}, mismatch={mismatch_time:?}, ratio={ratio:.2}"
    );
}

#[test]
fn test_cache_timing_resistance() {
    let secret = "sensitive_data_should_not_leak_via_cache_timing";
    let correct = "sensitive_data_should_not_leak_via_cache_timing";
    let incorrect = "different_data_should_not_leak_via_cache_timing";

    let [cold_correct, cold_incorrect] =
        alternating_str_medians(secret, [(correct, true), (incorrect, false)], 1_000);
    let [warm_correct, warm_incorrect] =
        alternating_str_medians(secret, [(correct, true), (incorrect, false)], 1_000);

    let cold_ratio = cold_correct.as_nanos() as f64 / cold_incorrect.as_nanos().max(1) as f64;
    let warm_ratio = warm_correct.as_nanos() as f64 / warm_incorrect.as_nanos().max(1) as f64;

    assert!(
        (cold_ratio - warm_ratio).abs() < 0.5,
        "Cache timing differences detected: cold_ratio={cold_ratio:.2}, warm_ratio={warm_ratio:.2}"
    );
}

#[test]
fn test_memory_access_pattern_independence() {
    let patterns = [
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaxxxx",
        "ababababababababababababababababababababxxxx",
        "abcdefghijklmnopqrstuvwxyz1234567890abcdefxx",
        "zyxwvutsrqponmlkjihgfedcba0987654321fedcbaxx",
    ];
    let target = "this_is_the_target_string_to_compare_against";
    for pattern in patterns {
        assert_eq!(pattern.len(), target.len());
    }

    let timings = alternating_str_medians(
        target,
        [
            (patterns[0], false),
            (patterns[1], false),
            (patterns[2], false),
            (patterns[3], false),
        ],
        2_000,
    );

    let max_time = timings.iter().max().expect("max timing");
    let min_time = timings.iter().min().expect("min timing");
    let variance = max_time.as_nanos() as f64 / min_time.as_nanos().max(1) as f64;

    assert!(
        variance < 1.8,
        "Memory access pattern timing detected: variance {variance:.2}, timings: {timings:?}"
    );
}

#[test]
fn test_harness_exposes_planted_early_exit_leak() {
    fn early_exit_fault(left: &[u8], right: &[u8]) -> bool {
        if left.len() != right.len() {
            return false;
        }
        for (&a, &b) in left.iter().zip(right) {
            if black_box(a) != black_box(b) {
                return false;
            }
        }
        true
    }

    let secret = vec![0x5A_u8; 4096];
    let same = secret.clone();
    let mut first_byte_mismatch = secret.clone();
    first_byte_mismatch[0] ^= 1;

    let mut same_samples = [Duration::ZERO; MEDIAN_ROUNDS];
    let mut diff_samples = [Duration::ZERO; MEDIAN_ROUNDS];
    for round in 0..MEDIAN_ROUNDS {
        let start = Instant::now();
        for _ in 0..1_000 {
            assert!(early_exit_fault(black_box(&secret), black_box(&same)));
        }
        same_samples[round] = start.elapsed();

        let start = Instant::now();
        for _ in 0..1_000 {
            assert!(!early_exit_fault(
                black_box(&secret),
                black_box(&first_byte_mismatch)
            ));
        }
        diff_samples[round] = start.elapsed();
    }
    let ratio =
        median_duration(same_samples).as_nanos() / median_duration(diff_samples).as_nanos().max(1);
    assert!(
        ratio >= 10,
        "timing harness must detect planted early-exit leak (ratio={ratio})"
    );
}
