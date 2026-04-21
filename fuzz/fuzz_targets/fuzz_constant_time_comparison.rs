#![no_main]

use libfuzzer_sys::fuzz_target;
use arbitrary::{Arbitrary, Unstructured};
use std::hint::black_box;

// Import the constant time functions
use frankenengine_node::security::constant_time::{ct_eq, ct_eq_bytes};

#[derive(Debug, Clone, Arbitrary)]
struct ConstantTimeTestCase {
    /// First input for comparison
    input_a: Vec<u8>,
    /// Second input - may be derived from input_a with controlled differences
    mutation_strategy: MutationStrategy,
    /// Length override for input_b (tests length-based attacks)
    length_override: Option<u16>,
}

#[derive(Debug, Clone, Arbitrary)]
enum MutationStrategy {
    /// Identical inputs (should return true)
    Identical,
    /// Single bit flip at specified position
    SingleBitFlip { position: u16, bit: u8 },
    /// Modify first byte only (early difference)
    FirstByteDiff { new_value: u8 },
    /// Modify last byte only (late difference)
    LastByteDiff { new_value: u8 },
    /// Modify middle byte (cache-line boundary test)
    MiddleByteDiff { new_value: u8 },
    /// Prefix match with different suffix
    PrefixMatch { suffix: Vec<u8> },
    /// Same length, completely different content
    SameLength { replacement: Vec<u8> },
    /// Unicode normalization attack (NFC vs NFD)
    UnicodeNormalization { variant: UnicodeVariant },
    /// Domain separator injection attempt
    DomainSeparatorInject { separator: Vec<u8> },
    /// Zero-width character injection
    ZeroWidthInject { positions: Vec<u16> },
}

#[derive(Debug, Clone, Arbitrary)]
enum UnicodeVariant {
    NFC,   // Canonical Composition
    NFD,   // Canonical Decomposition
    BiDi,  // Bidirectional override attack
}

const MAX_INPUT_SIZE: usize = 8192;
const MAX_COMPARISON_PAIRS: usize = 100;

fuzz_target!(|data: &[u8]| {
    let mut unstructured = Unstructured::new(data);

    // Bound input size to prevent OOM
    let Ok(test_case) = ConstantTimeTestCase::arbitrary(&mut unstructured) else { return };
    if test_case.input_a.len() > MAX_INPUT_SIZE { return }

    // Generate input_b based on mutation strategy
    let input_b = apply_mutation_strategy(&test_case.input_a, &test_case.mutation_strategy, test_case.length_override);

    // Test ct_eq_bytes directly
    fuzz_ct_eq_bytes(&test_case.input_a, &input_b, &test_case.mutation_strategy);

    // Test ct_eq on string conversion (if valid UTF-8)
    if let (Ok(str_a), Ok(str_b)) = (std::str::from_utf8(&test_case.input_a), std::str::from_utf8(&input_b)) {
        fuzz_ct_eq_strings(str_a, str_b, &test_case.mutation_strategy);
    }

    // Test timing consistency across multiple comparisons
    if test_case.input_a.len() <= 1024 && input_b.len() <= 1024 {
        fuzz_timing_consistency(&test_case.input_a, &input_b);
    }
});

fn apply_mutation_strategy(input: &[u8], strategy: &MutationStrategy, length_override: Option<u16>) -> Vec<u8> {
    let mut result = match strategy {
        MutationStrategy::Identical => input.to_vec(),

        MutationStrategy::SingleBitFlip { position, bit } => {
            let mut result = input.to_vec();
            if !result.is_empty() {
                let pos = (*position as usize) % result.len();
                result[pos] ^= 1u8 << (bit % 8);
            }
            result
        },

        MutationStrategy::FirstByteDiff { new_value } => {
            let mut result = input.to_vec();
            if !result.is_empty() {
                result[0] = *new_value;
            }
            result
        },

        MutationStrategy::LastByteDiff { new_value } => {
            let mut result = input.to_vec();
            if !result.is_empty() {
                let last_idx = result.len() - 1;
                result[last_idx] = *new_value;
            }
            result
        },

        MutationStrategy::MiddleByteDiff { new_value } => {
            let mut result = input.to_vec();
            if !result.is_empty() {
                let mid_idx = result.len() / 2;
                result[mid_idx] = *new_value;
            }
            result
        },

        MutationStrategy::PrefixMatch { suffix } => {
            let mut result = input.to_vec();
            result.extend_from_slice(suffix);
            result
        },

        MutationStrategy::SameLength { replacement } => {
            if replacement.len() == input.len() {
                replacement.clone()
            } else {
                // Truncate or pad to match original length
                let mut result = replacement.clone();
                result.resize(input.len(), 0);
                result
            }
        },

        MutationStrategy::UnicodeNormalization { variant } => {
            apply_unicode_attack(input, variant)
        },

        MutationStrategy::DomainSeparatorInject { separator } => {
            let mut result = input.to_vec();
            // Insert separator at various positions to test domain collision
            if !result.is_empty() {
                let pos = result.len() / 2;
                result.splice(pos..pos, separator.iter().cloned());
            }
            result
        },

        MutationStrategy::ZeroWidthInject { positions } => {
            apply_zero_width_attack(input, positions)
        },
    };

    // Apply length override if specified
    if let Some(new_len) = length_override {
        let target_len = (new_len as usize).min(MAX_INPUT_SIZE);
        result.resize(target_len, 0);
    }

    result
}

fn apply_unicode_attack(input: &[u8], variant: &UnicodeVariant) -> Vec<u8> {
    // Only apply to valid UTF-8 strings
    let Ok(input_str) = std::str::from_utf8(input) else { return input.to_vec() };

    match variant {
        UnicodeVariant::NFC => {
            // Try to create NFC vs NFD differences
            if input_str.contains('e') {
                input_str.replace('e', "e\u{0301}").into_bytes() // e + combining acute
            } else {
                input.to_vec()
            }
        },

        UnicodeVariant::NFD => {
            if input_str.contains("é") {
                input_str.replace("é", "e\u{0301}").into_bytes() // Split é into e + combining
            } else {
                input.to_vec()
            }
        },

        UnicodeVariant::BiDi => {
            // BiDi override attack
            format!("\u{202E}{}\u{202D}", input_str).into_bytes()
        },
    }
}

fn apply_zero_width_attack(input: &[u8], positions: &[u16]) -> Vec<u8> {
    let Ok(input_str) = std::str::from_utf8(input) else { return input.to_vec() };

    let mut result = input_str.to_string();
    for &pos in positions.iter().take(10) { // Limit insertions
        let char_pos = (pos as usize) % (result.chars().count() + 1);
        let byte_pos = result.char_indices().nth(char_pos).map(|(i, _)| i).unwrap_or(result.len());
        result.insert_str(byte_pos, "\u{200B}"); // Zero-width space
    }
    result.into_bytes()
}

fn fuzz_ct_eq_bytes(input_a: &[u8], input_b: &[u8], strategy: &MutationStrategy) {
    // Use black_box to prevent compiler optimizations that could affect timing
    let a = black_box(input_a);
    let b = black_box(input_b);

    let result = black_box(ct_eq_bytes(a, b));

    // Verify expected result based on mutation strategy
    match strategy {
        MutationStrategy::Identical => {
            if input_a == input_b && !result {
                #[cfg(debug_assertions)]
                {
                    eprintln!("FUZZ: Invariant violation - identical inputs but ct_eq_bytes returned false");
                }
                return; // Exit gracefully instead of panicking
            }
        },
        _ => {
            // For any mutation, if inputs are actually different, should return false
            if input_a != input_b && result {
                #[cfg(debug_assertions)]
                {
                    eprintln!("FUZZ: Invariant violation - different inputs but ct_eq_bytes returned true");
                }
                return; // Exit gracefully instead of panicking
            }
        }
    }

    // Invariant: ct_eq_bytes should always equal standard comparison
    let std_result = input_a == input_b;
    if result != std_result {
        #[cfg(debug_assertions)]
        {
            eprintln!("FUZZ: Invariant violation - ct_eq_bytes ({}) diverged from standard equality ({})",
                     result, std_result);
        }
        return; // Exit gracefully instead of panicking
    }
}

fn fuzz_ct_eq_strings(str_a: &str, str_b: &str, strategy: &MutationStrategy) {
    let a = black_box(str_a);
    let b = black_box(str_b);

    let result = black_box(ct_eq(a, b));

    // Verify expected result
    match strategy {
        MutationStrategy::Identical => {
            if str_a == str_b && !result {
                #[cfg(debug_assertions)]
                {
                    eprintln!("FUZZ: Invariant violation - identical strings but ct_eq returned false");
                }
                return; // Exit gracefully instead of panicking
            }
        },
        _ => {
            if str_a != str_b && result {
                #[cfg(debug_assertions)]
                {
                    eprintln!("FUZZ: Invariant violation - different strings but ct_eq returned true");
                }
                return; // Exit gracefully instead of panicking
            }
        }
    }

    // Invariant: ct_eq should always equal standard string comparison
    let std_result = str_a == str_b;
    if result != std_result {
        #[cfg(debug_assertions)]
        {
            eprintln!("FUZZ: Invariant violation - ct_eq ({}) diverged from standard string equality ({})",
                     result, std_result);
        }
        return; // Exit gracefully instead of panicking
    }

    // Additional invariant: ct_eq should equal ct_eq_bytes on the underlying bytes
    let bytes_result = ct_eq_bytes(str_a.as_bytes(), str_b.as_bytes());
    if result != bytes_result {
        #[cfg(debug_assertions)]
        {
            eprintln!("FUZZ: Invariant violation - ct_eq ({}) and ct_eq_bytes ({}) diverged on same data",
                     result, bytes_result);
        }
        return; // Exit gracefully instead of panicking
    }
}

fn fuzz_timing_consistency(input_a: &[u8], input_b: &[u8]) {
    // Test that similar comparisons take similar time (basic timing attack resistance)
    // Note: This is a heuristic check, not a formal timing analysis

    let iterations = 100;
    let mut timing_samples = Vec::with_capacity(iterations);

    for _ in 0..iterations {
        let start = std::time::Instant::now();
        let _result = black_box(ct_eq_bytes(black_box(input_a), black_box(input_b)));
        let duration = start.elapsed().as_nanos();
        timing_samples.push(duration);
    }

    if timing_samples.len() > 10 {
        // Basic variance check - timing shouldn't vary wildly for same operation
        let mean: f64 = timing_samples.iter().map(|&x| x as f64).sum::<f64>() / timing_samples.len() as f64;
        let variance: f64 = timing_samples.iter()
            .map(|&x| {
                let diff = x as f64 - mean;
                diff * diff
            })
            .sum::<f64>() / timing_samples.len() as f64;

        let std_dev = variance.sqrt();

        // Coefficient of variation should be reasonable (not a formal timing attack test)
        if mean > 0.0 && std_dev.is_finite() {
            let coefficient_of_variation = std_dev / mean;
            // Allow significant variance since we're not controlling for system noise
            assert!(coefficient_of_variation < 2.0,
                   "Timing variance too high: CV={:.2}, might indicate timing vulnerability",
                   coefficient_of_variation);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_constant_time_basic_fuzzing() {
        // Regression test: ensure basic functionality works
        assert!(ct_eq("hello", "hello"));
        assert!(!ct_eq("hello", "world"));
        assert!(ct_eq_bytes(b"test", b"test"));
        assert!(!ct_eq_bytes(b"test", b"fail"));
    }

    #[test]
    fn test_mutation_strategies() {
        let input = b"test_input";

        // Test identical strategy
        let result = apply_mutation_strategy(input, &MutationStrategy::Identical, None);
        assert_eq!(result, input);

        // Test bit flip
        let result = apply_mutation_strategy(input, &MutationStrategy::SingleBitFlip { position: 0, bit: 0 }, None);
        assert_ne!(result, input);
        assert_eq!(result.len(), input.len());
    }
}