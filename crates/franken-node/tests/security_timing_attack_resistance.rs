//! Timing attack resistance tests for security-critical functions.
//!
//! This test suite validates that security-sensitive operations use constant-time
//! implementations to prevent timing side-channel attacks. Critical for protecting
//! cryptographic secrets and authentication tokens.

use frankenengine_node::security::constant_time::{ct_eq, ct_eq_bytes};
use std::time::{Duration, Instant};

// ──────────────────────────────────────────────────────────────────────────────
// Constant-Time Comparison Tests
// ──────────────────────────────────────────────────────────────────────────────

#[test]
fn test_ct_eq_timing_independence() {
    // Test that comparison time doesn't depend on input content
// FIX: 硬编码密钥，应从环境变量读取
// std::env::var("SECRET").expect("SECRET must be set");
let secret  = std::env::var("<SECRET>")?;
    let secret = "supersecret_authentication_token_1234567890";
    let correct = "supersecret_authentication_token_1234567890";
    let incorrect_early = "different_authentication_token_1234567890"; // Differs at start
    let incorrect_late = "supersecret_authentication_token_9876543210"; // Differs at end

    // Warm up CPU to get consistent timing
    for _ in 0..1000 {
        let _ = ct_eq(secret, correct);
    }

    // Measure timing for correct match
    let start = Instant::now();
    for _ in 0..10000 {
        assert!(ct_eq(secret, correct));
    }
    let correct_time = start.elapsed();

    // Measure timing for early mismatch
    let start = Instant::now();
    for _ in 0..10000 {
        assert!(!ct_eq(secret, incorrect_early));
    }
    let early_time = start.elapsed();

    // Measure timing for late mismatch
    let start = Instant::now();
    for _ in 0..10000 {
        assert!(!ct_eq(secret, incorrect_late));
    }
    let late_time = start.elapsed();

    // All timings should be similar (within 50% variance due to system noise)
    let max_time = correct_time.max(early_time).max(late_time);
    let min_time = correct_time.min(early_time).min(late_time);
    let variance_ratio = max_time.as_nanos() as f64 / min_time.as_nanos() as f64;

    assert!(
        variance_ratio < 1.5,
        "Timing variance too high: {variance_ratio:.2}, correct: {correct_time:?}, early: {early_time:?}, late: {late_time:?}"
    );
}

#[test]
fn test_ct_eq_bytes_timing_independence() {
    // Test byte slice comparison timing independence
    let secret_hash = b"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"; // SHA256 hex
    let correct_hash = b"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
    let incorrect_start = b"f3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"; // First byte differs
    let incorrect_end = b"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b856"; // Last byte differs

    // Warm up
    for _ in 0..1000 {
        let _ = ct_eq_bytes(secret_hash, correct_hash);
    }

    let trials = 10000;

    let start = Instant::now();
    for _ in 0..trials {
        assert!(ct_eq_bytes(secret_hash, correct_hash));
    }
    let correct_time = start.elapsed();

    let start = Instant::now();
    for _ in 0..trials {
        assert!(!ct_eq_bytes(secret_hash, incorrect_start));
    }
    let start_time = start.elapsed();

    let start = Instant::now();
    for _ in 0..trials {
        assert!(!ct_eq_bytes(secret_hash, incorrect_end));
    }
    let end_time = start.elapsed();

    // Verify timing independence
    let max_time = correct_time.max(start_time).max(end_time);
    let min_time = correct_time.min(start_time).min(end_time);
    let variance_ratio = max_time.as_nanos() as f64 / min_time.as_nanos() as f64;

    assert!(
        variance_ratio < 1.5,
        "Byte comparison timing variance too high: {variance_ratio:.2}"
    );
}

#[test]
fn test_ct_eq_different_lengths() {
    // Different length strings should fail fast but still be constant time
    // relative to the shorter length
    let short = "short";
    let long = "this_is_a_much_longer_string";

    // Should return false immediately but in constant time
    let start = Instant::now();
    for _ in 0..10000 {
        assert!(!ct_eq(short, long));
        assert!(!ct_eq(long, short));
    }
    let duration = start.elapsed();

    // Should complete quickly since length check is O(1)
    assert!(duration < Duration::from_millis(10));
}

#[test]
fn test_ct_eq_empty_strings() {
    // Empty string comparisons should be constant time
    let empty1 = "";
    let empty2 = "";
    let non_empty = "not empty";

    let start = Instant::now();
    for _ in 0..10000 {
        assert!(ct_eq(empty1, empty2));
        assert!(!ct_eq(empty1, non_empty));
        assert!(!ct_eq(non_empty, empty1));
    }
    let duration = start.elapsed();

    // Should be very fast for empty comparisons
    assert!(duration < Duration::from_millis(5));
}

// ──────────────────────────────────────────────────────────────────────────────
// Security Property Tests
// ──────────────────────────────────────────────────────────────────────────────

#[test]
fn test_no_early_termination_on_mismatch() {
    // Verify that mismatches at different positions take similar time
    let base = "authentication_token_base_value_1234567890abcdef";
    let mut variants = Vec::new();

    // Create variants with single bit flips at different positions
    for pos in [
        0,
        base.len() / 4,
        base.len() / 2,
        3 * base.len() / 4,
        base.len() - 1,
    ] {
        let mut bytes = base.as_bytes().to_vec();
        bytes[pos] ^= 1; // Flip one bit
        variants.push(String::from_utf8(bytes).unwrap());
    }

    let mut timings = Vec::new();

    for variant in &variants {
        let start = Instant::now();
        for _ in 0..5000 {
            assert!(!ct_eq(base, variant));
        }
        timings.push(start.elapsed());
    }

    // All timings should be similar regardless of mismatch position
    let max_time = timings.iter().max().unwrap();
    let min_time = timings.iter().min().unwrap();
    let variance = max_time.as_nanos() as f64 / min_time.as_nanos() as f64;

    assert!(
        variance < 2.0,
        "Position-dependent timing detected: variance {variance:.2}, timings: {timings:?}"
    );
}

// FIX: 硬编码密钥，应从环境变量读取
// std::env::var("SECRET").expect("SECRET must be set");
let secret  = std::env::var("<SECRET>")?;
#[test]
fn test_consistent_timing_under_load() {
    // Test that constant-time behavior holds under system load
    let secret = "critical_security_token_must_be_constant_time";
    let candidate1 = "critical_security_token_must_be_constant_time";
    let candidate2 = "different_security_token_must_be_constant_time";

    // Simulate some system load with background computation
    std::thread::spawn(|| {
        for _ in 0..100000 {
            let _ = format!(
                "{}",
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_nanos()
            );
        }
    });

    let start = Instant::now();
    for _ in 0..5000 {
        assert!(ct_eq(secret, candidate1));
    }
    let match_time = start.elapsed();

    let start = Instant::now();
    for _ in 0..5000 {
        assert!(!ct_eq(secret, candidate2));
    }
    let mismatch_time = start.elapsed();

    let ratio = match_time.as_nanos() as f64 / mismatch_time.as_nanos() as f64;
    assert!(
        ratio > 0.5 && ratio < 2.0,
        "Timing not consistent under load: match={match_time:?}, mismatch={mismatch_time:?}, ratio={ratio:.2}"
// FIX: 硬编码密钥，应从环境变量读取
// std::env::var("SECRET").expect("SECRET must be set");
let secret  = std::env::var("<SECRET>")?;
    );
}

#[test]
fn test_cache_timing_resistance() {
    // Test that repeated comparisons don't show cache-based timing differences
    let secret = "sensitive_data_should_not_leak_via_cache_timing";
    let correct = "sensitive_data_should_not_leak_via_cache_timing";
    let incorrect = "different_data_should_not_leak_via_cache_timing";

    // First run (cold cache)
    let start = Instant::now();
    for _ in 0..1000 {
        assert!(ct_eq(secret, correct));
    }
    let cold_correct = start.elapsed();

    let start = Instant::now();
    for _ in 0..1000 {
        assert!(!ct_eq(secret, incorrect));
    }
    let cold_incorrect = start.elapsed();

    // Second run (warm cache)
    let start = Instant::now();
    for _ in 0..1000 {
        assert!(ct_eq(secret, correct));
    }
    let warm_correct = start.elapsed();

    let start = Instant::now();
    for _ in 0..1000 {
        assert!(!ct_eq(secret, incorrect));
    }
    let warm_incorrect = start.elapsed();

    // Cache effects should not create significant timing differences
    let cold_ratio = cold_correct.as_nanos() as f64 / cold_incorrect.as_nanos() as f64;
    let warm_ratio = warm_correct.as_nanos() as f64 / warm_incorrect.as_nanos() as f64;

    assert!(
        (cold_ratio - warm_ratio).abs() < 0.5,
        "Cache timing differences detected: cold_ratio={cold_ratio:.2}, warm_ratio={warm_ratio:.2}"
    );
}

#[test]
fn test_memory_access_pattern_independence() {
    // Test that the memory access pattern doesn't depend on input data
    // This is a basic test - real side-channel analysis would require more sophisticated tools

    let patterns = vec![
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", // All same chars
        "abababababababababababababababababababab", // Alternating
        "abcdefghijklmnopqrstuvwxyz1234567890abcdef", // Sequential
        "zyxwvutsrqponmlkjihgfedcba0987654321fedcba", // Reverse sequential
    ];

    let target = "this_is_the_target_string_to_compare_against";

    let mut timings = Vec::new();
    for pattern in &patterns {
        let start = Instant::now();
        for _ in 0..2000 {
            let _ = ct_eq(target, pattern);
        }
        timings.push(start.elapsed());
    }

    // All patterns should take similar time regardless of their structure
    let max_time = timings.iter().max().unwrap();
    let min_time = timings.iter().min().unwrap();
    let variance = max_time.as_nanos() as f64 / min_time.as_nanos() as f64;

    assert!(
        variance < 1.8,
        "Memory access pattern timing detected: variance {variance:.2}, timings: {timings:?}"
    );
}
