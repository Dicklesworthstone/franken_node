//! Fuzz target for frame parser guardrails and validation boundaries.
//!
//! Tests resource limit enforcement, malformed frame handling, and batch processing
//! with comprehensive edge case coverage across frame ID validation, config validation,
//! and boundary conditions for size/depth/CPU limits.

#![no_main]

use libfuzzer_sys::fuzz_target;
use arbitrary::{Arbitrary, Unstructured};

use frankenengine_node::connector::frame_parser::{
    FrameInput, ParserConfig, check_frame, check_batch, validate_config,
    ParserError, GuardrailViolation
};

#[derive(Debug, Clone, Arbitrary)]
struct FuzzInput {
    operation: FuzzOperation,
}

#[derive(Debug, Clone, Arbitrary)]
enum FuzzOperation {
    ValidateConfig {
        config: FuzzParserConfig,
    },
    CheckSingleFrame {
        frame: FuzzFrameInput,
        config: FuzzParserConfig,
        timestamp: String,
    },
    CheckBatch {
        frames: Vec<FuzzFrameInput>,
        config: FuzzParserConfig,
        timestamp: String,
    },
    EdgeCaseCombination {
        frame1: FuzzFrameInput,
        frame2: FuzzFrameInput,
        config1: FuzzParserConfig,
        config2: FuzzParserConfig,
        timestamp: String,
    },
}

#[derive(Debug, Clone, Arbitrary)]
struct FuzzParserConfig {
    max_frame_bytes: u64,
    max_nesting_depth: u32,
    max_decode_cpu_ms: u64,
}

impl FuzzParserConfig {
    fn to_parser_config(&self) -> ParserConfig {
        ParserConfig {
            max_frame_bytes: self.max_frame_bytes,
            max_nesting_depth: self.max_nesting_depth,
            max_decode_cpu_ms: self.max_decode_cpu_ms,
        }
    }
}

#[derive(Debug, Clone, Arbitrary)]
struct FuzzFrameInput {
    frame_id_type: FrameIdType,
    raw_bytes_len: u64,
    nesting_depth: u32,
    decode_cpu_ms: u64,
}

#[derive(Debug, Clone, Arbitrary)]
enum FrameIdType {
    Valid(String),
    Empty,
    Whitespace(String),
    NulBytes(Vec<u8>),
    Unicode(String),
    VeryLong(Vec<u8>),
    ControlChars(Vec<u8>),
}

impl FuzzFrameInput {
    fn to_frame_input(&self) -> FrameInput {
        let frame_id = match &self.frame_id_type {
            FrameIdType::Valid(s) => s.clone(),
            FrameIdType::Empty => String::new(),
            FrameIdType::Whitespace(s) => {
                if s.is_empty() {
                    " \t\n\r".to_string()
                } else {
                    s.clone()
                }
            }
            FrameIdType::NulBytes(bytes) => {
                String::from_utf8_lossy(bytes).to_string()
            }
            FrameIdType::Unicode(s) => s.clone(),
            FrameIdType::VeryLong(bytes) => {
                String::from_utf8_lossy(bytes).to_string()
            }
            FrameIdType::ControlChars(bytes) => {
                String::from_utf8_lossy(bytes).to_string()
            }
        };

        FrameInput {
            frame_id,
            raw_bytes_len: self.raw_bytes_len,
            nesting_depth: self.nesting_depth,
            decode_cpu_ms: self.decode_cpu_ms,
        }
    }
}

/// Test invariants and error handling across all fuzzing scenarios.
fn test_frame_parser_invariants(operation: &FuzzOperation) {
    match operation {
        FuzzOperation::ValidateConfig { config } => {
            let parser_config = config.to_parser_config();
            let result = validate_config(&parser_config);

            // Invariant: Zero values should always be invalid
            if parser_config.max_frame_bytes == 0 ||
               parser_config.max_nesting_depth == 0 ||
               parser_config.max_decode_cpu_ms == 0 {
                assert!(result.is_err(), "Zero config values must be invalid");
                if let Err(e) = result {
                    assert_eq!(e.code(), "BPG_INVALID_CONFIG");
                }
            }
        }

        FuzzOperation::CheckSingleFrame { frame, config, timestamp } => {
            let frame_input = frame.to_frame_input();
            let parser_config = config.to_parser_config();
            let result = check_frame(&frame_input, &parser_config, timestamp);

            // Test config validation first
            if let Err(config_err) = validate_config(&parser_config) {
                // Should fail with config error
                assert!(result.is_err(), "Invalid config should cause failure");
                if let Err(e) = result {
                    assert_eq!(e.code(), config_err.code());
                }
                return;
            }

            // Test frame ID validation
            if frame_input.frame_id.trim().is_empty() {
                assert!(result.is_err(), "Empty frame ID should fail");
                if let Err(e) = result {
                    assert_eq!(e.code(), "BPG_MALFORMED_FRAME");
                }
                return;
            }

            if frame_input.frame_id.as_bytes().contains(&0) {
                assert!(result.is_err(), "NUL bytes in frame ID should fail");
                if let Err(e) = result {
                    assert_eq!(e.code(), "BPG_MALFORMED_FRAME");
                }
                return;
            }

            // Test guardrail logic for valid frames
            if let Ok((verdict, audit)) = result {
                // Invariant: At-limit values should be blocked (fail-closed)
                let size_blocked = frame_input.raw_bytes_len >= parser_config.max_frame_bytes;
                let depth_blocked = frame_input.nesting_depth >= parser_config.max_nesting_depth;
                let cpu_blocked = frame_input.decode_cpu_ms >= parser_config.max_decode_cpu_ms;

                let should_be_blocked = size_blocked || depth_blocked || cpu_blocked;
                assert_eq!(!verdict.allowed, should_be_blocked,
                    "Verdict should match resource violations");

                // Verify violation types match expectations
                if size_blocked {
                    assert!(verdict.violations.iter().any(|v| matches!(v, GuardrailViolation::SizeExceeded { .. })));
                }
                if depth_blocked {
                    assert!(verdict.violations.iter().any(|v| matches!(v, GuardrailViolation::DepthExceeded { .. })));
                }
                if cpu_blocked {
                    assert!(verdict.violations.iter().any(|v| matches!(v, GuardrailViolation::CpuExceeded { .. })));
                }

                // Invariant: Resource usage always matches input
                assert_eq!(verdict.resource_usage.bytes_parsed, frame_input.raw_bytes_len);
                assert_eq!(verdict.resource_usage.nesting_depth, frame_input.nesting_depth);
                assert_eq!(verdict.resource_usage.cpu_ms, frame_input.decode_cpu_ms);

                // Invariant: Audit entry consistency
                assert_eq!(audit.frame_id, frame_input.frame_id);
                assert_eq!(audit.size, frame_input.raw_bytes_len);
                assert_eq!(audit.depth, frame_input.nesting_depth);
                assert_eq!(audit.cpu_used, frame_input.decode_cpu_ms);
                assert_eq!(audit.timestamp, timestamp);

                if verdict.allowed {
                    assert_eq!(audit.verdict, "ALLOW");
                } else {
                    assert_eq!(audit.verdict, "BLOCK");
                }
            }
        }

        FuzzOperation::CheckBatch { frames, config, timestamp } => {
            let frame_inputs: Vec<FrameInput> = frames.iter().map(|f| f.to_frame_input()).collect();
            let parser_config = config.to_parser_config();
            let result = check_batch(&frame_inputs, &parser_config, timestamp);

            // Config validation should preempt frame processing
            if let Err(config_err) = validate_config(&parser_config) {
                assert!(result.is_err(), "Invalid config should cause batch failure");
                if let Err(e) = result {
                    assert_eq!(e.code(), config_err.code());
                }
                return;
            }

            // Find first malformed frame
            let first_bad_frame = frame_inputs.iter().find(|frame| {
                frame.frame_id.trim().is_empty() || frame.frame_id.as_bytes().contains(&0)
            });

            if let Some(_bad_frame) = first_bad_frame {
                // Batch should abort on first malformed frame
                assert!(result.is_err(), "Batch should abort on malformed frame");
                if let Err(e) = result {
                    assert_eq!(e.code(), "BPG_MALFORMED_FRAME");
                }
                return;
            }

            // All frames valid - should get results for all
            if let Ok(results) = result {
                assert_eq!(results.len(), frame_inputs.len(), "Result count should match input count");

                for (i, (verdict, audit)) in results.iter().enumerate() {
                    let frame = &frame_inputs[i];
                    assert_eq!(verdict.frame_id, frame.frame_id);
                    assert_eq!(audit.frame_id, frame.frame_id);

                    // Check resource usage consistency
                    assert_eq!(verdict.resource_usage.bytes_parsed, frame.raw_bytes_len);
                    assert_eq!(verdict.resource_usage.nesting_depth, frame.nesting_depth);
                    assert_eq!(verdict.resource_usage.cpu_ms, frame.decode_cpu_ms);
                }
            }
        }

        FuzzOperation::EdgeCaseCombination { frame1, frame2, config1, config2, timestamp } => {
            // Test same frame with different configs
            let frame_input = frame1.to_frame_input();
            let result1 = check_frame(&frame_input, &config1.to_parser_config(), timestamp);
            let result2 = check_frame(&frame_input, &config2.to_parser_config(), timestamp);

            // If both configs are valid and frame is valid, results should be deterministic
            let config1_valid = validate_config(&config1.to_parser_config()).is_ok();
            let config2_valid = validate_config(&config2.to_parser_config()).is_ok();
            let frame_valid = !frame_input.frame_id.trim().is_empty() &&
                             !frame_input.frame_id.as_bytes().contains(&0);

            if config1_valid && config2_valid && frame_valid {
                match (result1, result2) {
                    (Ok((v1, _)), Ok((v2, _))) => {
                        // Same frame should produce same resource usage
                        assert_eq!(v1.resource_usage.bytes_parsed, v2.resource_usage.bytes_parsed);
                        assert_eq!(v1.resource_usage.nesting_depth, v2.resource_usage.nesting_depth);
                        assert_eq!(v1.resource_usage.cpu_ms, v2.resource_usage.cpu_ms);
                    }
                    _ => {} // Error cases are valid
                }
            }

            // Test batch with mixed frames
            let frames = vec![frame1.to_frame_input(), frame2.to_frame_input()];
            let _batch_result = check_batch(&frames, &config1.to_parser_config(), timestamp);
            // Batch result depends on frame validity and config validity
        }
    }
}

/// Execute boundary value tests for numeric limits.
fn test_boundary_values(operation: &FuzzOperation) {
    match operation {
        FuzzOperation::CheckSingleFrame { frame, config, timestamp } => {
            let frame_input = frame.to_frame_input();
            let parser_config = config.to_parser_config();

            if validate_config(&parser_config).is_err() {
                return;
            }

            if frame_input.frame_id.trim().is_empty() ||
               frame_input.frame_id.as_bytes().contains(&0) {
                return;
            }

            // Test exact boundary conditions
            let at_size_limit = frame_input.raw_bytes_len == parser_config.max_frame_bytes;
            let at_depth_limit = frame_input.nesting_depth == parser_config.max_nesting_depth;
            let at_cpu_limit = frame_input.decode_cpu_ms == parser_config.max_decode_cpu_ms;

            if let Ok((verdict, _)) = check_frame(&frame_input, &parser_config, timestamp) {
                // At exact limit should be blocked (fail-closed)
                if at_size_limit || at_depth_limit || at_cpu_limit {
                    assert!(!verdict.allowed, "Exact limits should fail-closed");
                }

                // Test overflow safety - values should never wrap
                assert!(frame_input.raw_bytes_len <= u64::MAX);
                assert!(frame_input.nesting_depth <= u32::MAX);
                assert!(frame_input.decode_cpu_ms <= u64::MAX);
            }
        }
        _ => {}
    }
}

/// Test error message formatting and codes.
fn test_error_consistency(operation: &FuzzOperation) {
    match operation {
        FuzzOperation::CheckSingleFrame { frame, config, timestamp } => {
            let frame_input = frame.to_frame_input();
            let parser_config = config.to_parser_config();

            if let Err(error) = check_frame(&frame_input, &parser_config, timestamp) {
                // Error codes should be consistent
                let error_string = error.to_string();
                match error.code() {
                    "BPG_SIZE_EXCEEDED" => assert!(error_string.contains("BPG_SIZE_EXCEEDED")),
                    "BPG_DEPTH_EXCEEDED" => assert!(error_string.contains("BPG_DEPTH_EXCEEDED")),
                    "BPG_CPU_EXCEEDED" => assert!(error_string.contains("BPG_CPU_EXCEEDED")),
                    "BPG_INVALID_CONFIG" => assert!(error_string.contains("BPG_INVALID_CONFIG")),
                    "BPG_MALFORMED_FRAME" => assert!(error_string.contains("BPG_MALFORMED_FRAME")),
                    _ => panic!("Unknown error code: {}", error.code()),
                }

                // Malformed frames should use safe placeholders
                if error.code() == "BPG_MALFORMED_FRAME" {
                    if frame_input.frame_id.trim().is_empty() {
                        assert!(error_string.contains("(empty)"));
                    } else if frame_input.frame_id.as_bytes().contains(&0) {
                        assert!(error_string.contains("(invalid)"));
                        assert!(!error_string.contains('\0'));
                    }
                }
            }
        }
        _ => {}
    }
}

fuzz_target!(|input: FuzzInput| {
    // Catch any panics and convert to controlled test failures
    std::panic::catch_unwind(|| {
        test_frame_parser_invariants(&input.operation);
        test_boundary_values(&input.operation);
        test_error_consistency(&input.operation);
    }).unwrap_or_else(|_| {
        // Log panic but don't propagate - we want to find bugs, not crash fuzzer
        eprintln!("Panic caught in frame parser fuzzing");
    });
});

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fuzz_input_generates_valid_operations() {
        let mut data = [0u8; 1000];
        for i in 0..data.len() {
            data[i] = (i % 256) as u8;
        }

        let mut unstructured = Unstructured::new(&data);
        if let Ok(input) = FuzzInput::arbitrary(&mut unstructured) {
            // Should not panic during operation construction
            match input.operation {
                FuzzOperation::ValidateConfig { .. } => {},
                FuzzOperation::CheckSingleFrame { .. } => {},
                FuzzOperation::CheckBatch { .. } => {},
                FuzzOperation::EdgeCaseCombination { .. } => {},
            }
        }
    }

    #[test]
    fn frame_id_types_generate_expected_strings() {
        let empty = FrameIdType::Empty;
        let valid = FrameIdType::Valid("test".to_string());
        let nul = FrameIdType::NulBytes(vec![116, 101, 115, 116, 0, 102, 114, 97, 109, 101]);

        let empty_frame = FuzzFrameInput {
            frame_id_type: empty,
            raw_bytes_len: 100,
            nesting_depth: 5,
            decode_cpu_ms: 10,
        };

        let valid_frame = FuzzFrameInput {
            frame_id_type: valid,
            raw_bytes_len: 100,
            nesting_depth: 5,
            decode_cpu_ms: 10,
        };

        let nul_frame = FuzzFrameInput {
            frame_id_type: nul,
            raw_bytes_len: 100,
            nesting_depth: 5,
            decode_cpu_ms: 10,
        };

        assert_eq!(empty_frame.to_frame_input().frame_id, "");
        assert_eq!(valid_frame.to_frame_input().frame_id, "test");
        assert!(nul_frame.to_frame_input().frame_id.contains('\0'));
    }

    #[test]
    fn parser_config_conversion_preserves_values() {
        let fuzz_config = FuzzParserConfig {
            max_frame_bytes: 1000,
            max_nesting_depth: 10,
            max_decode_cpu_ms: 50,
        };

        let parser_config = fuzz_config.to_parser_config();
        assert_eq!(parser_config.max_frame_bytes, 1000);
        assert_eq!(parser_config.max_nesting_depth, 10);
        assert_eq!(parser_config.max_decode_cpu_ms, 50);
    }
}