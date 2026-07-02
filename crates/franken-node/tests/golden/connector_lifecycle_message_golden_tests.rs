//! Golden artifact tests for connector lifecycle message canonical forms
//!
//! Tests the deterministic serialization and validation output for:
//! - FrameInput structures with resource limit validation
//! - ParserConfig boundary enforcement patterns
//! - DecodeVerdict and GuardrailViolation canonical forms
//! - Frame validation audit trails and error handling

use crate::golden;
use frankenengine_node::connector::frame_parser::{
    DecodeAuditEntry, DecodeVerdict, FrameInput, GuardrailViolation, ParserConfig, ParserError,
    ResourceUsage, check_batch, check_frame, validate_config,
};
use serde_json::json;

#[test]
fn test_frame_input_basic_structure() {
    // Test basic FrameInput structure serialization
    let frame = FrameInput {
        frame_id: "test-frame-001".to_string(),
        raw_bytes_len: 1024,
        nesting_depth: 5,
        decode_cpu_ms: 25,
    };

    let frame_json = serde_json::to_value(&frame).expect("Should serialize FrameInput");
    golden::assert_scrubbed_json_golden(
        "connector_lifecycle_message/frame_input_basic",
        &frame_json,
    );
}

#[test]
fn test_parser_config_variations() {
    // Test different ParserConfig variations
    let configs = vec![
        ("default_config", ParserConfig::default_config()),
        (
            "minimal_limits",
            ParserConfig {
                max_frame_bytes: 1,
                max_nesting_depth: 1,
                max_decode_cpu_ms: 1,
            },
        ),
        (
            "permissive_limits",
            ParserConfig {
                max_frame_bytes: 100_000_000,
                max_nesting_depth: 1000,
                max_decode_cpu_ms: 10000,
            },
        ),
        (
            "zero_nesting_depth",
            ParserConfig {
                max_frame_bytes: 1_000_000,
                max_nesting_depth: 0, // Zero depth allowed
                max_decode_cpu_ms: 100,
            },
        ),
    ];

    for (config_name, config) in configs {
        let config_json = serde_json::to_value(&config).expect("Should serialize config");
        golden::assert_json_golden(
            &format!("connector_lifecycle_message/parser_configs/{}", config_name),
            &config_json,
        );
    }
}

#[test]
fn test_frame_validation_verdicts() {
    let config = ParserConfig::default_config();
    let timestamp = "2026-04-20T12:00:00Z";

    // Test various frame validation scenarios
    let test_frames = vec![
        (
            "within_all_limits",
            FrameInput {
                frame_id: "valid-frame".to_string(),
                raw_bytes_len: 500_000, // Under 1MB limit
                nesting_depth: 16,      // Under 32 limit
                decode_cpu_ms: 50,      // Under 100ms limit
            },
        ),
        (
            "at_size_limit",
            FrameInput {
                frame_id: "at-size-limit".to_string(),
                raw_bytes_len: 1_000_000, // Exactly at limit
                nesting_depth: 5,
                decode_cpu_ms: 10,
            },
        ),
        (
            "over_size_limit",
            FrameInput {
                frame_id: "over-size-limit".to_string(),
                raw_bytes_len: 1_000_001, // Over size limit
                nesting_depth: 5,
                decode_cpu_ms: 10,
            },
        ),
        (
            "at_depth_limit",
            FrameInput {
                frame_id: "at-depth-limit".to_string(),
                raw_bytes_len: 1000,
                nesting_depth: 31, // Just under limit (32 is limit)
                decode_cpu_ms: 10,
            },
        ),
        (
            "over_depth_limit",
            FrameInput {
                frame_id: "over-depth-limit".to_string(),
                raw_bytes_len: 1000,
                nesting_depth: 32, // At or over limit
                decode_cpu_ms: 10,
            },
        ),
        (
            "at_cpu_limit",
            FrameInput {
                frame_id: "at-cpu-limit".to_string(),
                raw_bytes_len: 1000,
                nesting_depth: 5,
                decode_cpu_ms: 99, // Just under limit
            },
        ),
        (
            "over_cpu_limit",
            FrameInput {
                frame_id: "over-cpu-limit".to_string(),
                raw_bytes_len: 1000,
                nesting_depth: 5,
                decode_cpu_ms: 100, // At or over limit
            },
        ),
        (
            "multiple_violations",
            FrameInput {
                frame_id: "multiple-violations".to_string(),
                raw_bytes_len: 2_000_000, // Over size
                nesting_depth: 50,        // Over depth
                decode_cpu_ms: 200,       // Over CPU
            },
        ),
        (
            "zero_values",
            FrameInput {
                frame_id: "zero-values".to_string(),
                raw_bytes_len: 0,
                nesting_depth: 0,
                decode_cpu_ms: 0,
            },
        ),
    ];

    for (test_name, frame) in test_frames {
        match check_frame(&frame, &config, timestamp) {
            Ok((verdict, audit)) => {
                let result_json = json!({
                    "success": true,
                    "verdict": {
                        "frame_id": verdict.frame_id,
                        "allowed": verdict.allowed,
                        "violations": verdict.violations.iter().map(|v| {
                            match v {
                                GuardrailViolation::SizeExceeded { actual, limit } => {
                                    json!({
                                        "type": "SizeExceeded",
                                        "actual": actual,
                                        "limit": limit
                                    })
                                }
                                GuardrailViolation::DepthExceeded { actual, limit } => {
                                    json!({
                                        "type": "DepthExceeded",
                                        "actual": actual,
                                        "limit": limit
                                    })
                                }
                                GuardrailViolation::CpuExceeded { actual, limit } => {
                                    json!({
                                        "type": "CpuExceeded",
                                        "actual": actual,
                                        "limit": limit
                                    })
                                }
                                GuardrailViolation::MalformedFrame { reason } => {
                                    json!({
                                        "type": "MalformedFrame",
                                        "reason": reason
                                    })
                                }
                            }
                        }).collect::<Vec<_>>(),
                        "resource_usage": {
                            "bytes_parsed": verdict.resource_usage.bytes_parsed,
                            "nesting_depth": verdict.resource_usage.nesting_depth,
                            "cpu_ms": verdict.resource_usage.cpu_ms,
                        }
                    },
                    "audit": {
                        "frame_id": audit.frame_id,
                        "size": audit.size,
                        "depth": audit.depth,
                        "cpu_used": audit.cpu_used,
                        "size_limit": audit.size_limit,
                        "depth_limit": audit.depth_limit,
                        "cpu_limit": audit.cpu_limit,
                        "verdict": audit.verdict,
                        "timestamp": audit.timestamp,
                    },
                    "test_case": test_name,
                });

                golden::assert_scrubbed_json_golden(
                    &format!("connector_lifecycle_message/frame_validation/{}", test_name),
                    &result_json,
                );
            }
            Err(err) => {
                let error_json = json!({
                    "success": false,
                    "error": {
                        "code": err.code(),
                        "message": format!("{}", err),
                    },
                    "test_case": test_name,
                });

                golden::assert_scrubbed_json_golden(
                    &format!(
                        "connector_lifecycle_message/frame_validation/{}_error",
                        test_name
                    ),
                    &error_json,
                );
            }
        }
    }
}

#[test]
fn test_batch_frame_processing() {
    let config = ParserConfig::default_config();
    let timestamp = "2026-04-20T12:00:00Z";

    // Test batch processing with mixed valid/invalid frames
    let batch_frames = vec![
        FrameInput {
            frame_id: "batch-frame-1".to_string(),
            raw_bytes_len: 1000,
            nesting_depth: 5,
            decode_cpu_ms: 10,
        },
        FrameInput {
            frame_id: "batch-frame-2-oversized".to_string(),
            raw_bytes_len: 2_000_000, // Over limit
            nesting_depth: 3,
            decode_cpu_ms: 5,
        },
        FrameInput {
            frame_id: "batch-frame-3".to_string(),
            raw_bytes_len: 500,
            nesting_depth: 2,
            decode_cpu_ms: 8,
        },
        FrameInput {
            frame_id: "batch-frame-4-deep".to_string(),
            raw_bytes_len: 100,
            nesting_depth: 50, // Over depth limit
            decode_cpu_ms: 20,
        },
    ];

    match check_batch(&batch_frames, &config, timestamp) {
        Ok(results) => {
            let batch_results: Vec<_> = results
                .into_iter()
                .map(|(verdict, audit)| {
                    json!({
                        "verdict": {
                            "frame_id": verdict.frame_id,
                            "allowed": verdict.allowed,
                            "violation_count": verdict.violations.len(),
                            "violations": verdict.violations.iter().map(|v| {
                                match v {
                                    GuardrailViolation::SizeExceeded { .. } => "SizeExceeded",
                                    GuardrailViolation::DepthExceeded { .. } => "DepthExceeded",
                                    GuardrailViolation::CpuExceeded { .. } => "CpuExceeded",
                                    GuardrailViolation::MalformedFrame { .. } => "MalformedFrame",
                                }
                            }).collect::<Vec<_>>(),
                        },
                        "audit": {
                            "frame_id": audit.frame_id,
                            "verdict": audit.verdict,
                        },
                    })
                })
                .collect();

            let batch_json = json!({
                "success": true,
                "frame_count": batch_frames.len(),
                "results": batch_results,
            });

            golden::assert_scrubbed_json_golden(
                "connector_lifecycle_message/batch_processing",
                &batch_json,
            );
        }
        Err(err) => {
            let error_json = json!({
                "success": false,
                "error": {
                    "code": err.code(),
                    "message": format!("{}", err),
                },
            });

            golden::assert_scrubbed_json_golden(
                "connector_lifecycle_message/batch_processing_error",
                &error_json,
            );
        }
    }
}

#[test]
fn test_parser_config_validation() {
    // Test ParserConfig validation boundary conditions
    let config_test_cases = vec![
        (
            "valid_config",
            ParserConfig {
                max_frame_bytes: 1_000_000,
                max_nesting_depth: 32,
                max_decode_cpu_ms: 100,
            },
        ),
        (
            "zero_frame_bytes", // Invalid
            ParserConfig {
                max_frame_bytes: 0,
                max_nesting_depth: 32,
                max_decode_cpu_ms: 100,
            },
        ),
        (
            "zero_cpu_limit", // Invalid
            ParserConfig {
                max_frame_bytes: 1_000_000,
                max_nesting_depth: 32,
                max_decode_cpu_ms: 0,
            },
        ),
        (
            "max_values",
            ParserConfig {
                max_frame_bytes: u64::MAX,
                max_nesting_depth: u32::MAX,
                max_decode_cpu_ms: u64::MAX,
            },
        ),
    ];

    for (test_name, config) in config_test_cases {
        let validation_result = validate_config(&config);

        let result_json = match validation_result {
            Ok(()) => json!({
                "valid": true,
                "config": {
                    "max_frame_bytes": config.max_frame_bytes,
                    "max_nesting_depth": config.max_nesting_depth,
                    "max_decode_cpu_ms": config.max_decode_cpu_ms,
                },
                "test_case": test_name,
            }),
            Err(err) => json!({
                "valid": false,
                "error": {
                    "code": err.code(),
                    "message": format!("{}", err),
                },
                "config": {
                    "max_frame_bytes": config.max_frame_bytes,
                    "max_nesting_depth": config.max_nesting_depth,
                    "max_decode_cpu_ms": config.max_decode_cpu_ms,
                },
                "test_case": test_name,
            }),
        };

        golden::assert_scrubbed_json_golden(
            &format!(
                "connector_lifecycle_message/config_validation/{}",
                test_name
            ),
            &result_json,
        );
    }
}

#[test]
fn test_frame_id_handling() {
    let config = ParserConfig::default_config();
    let timestamp = "2026-04-20T12:00:00Z";

    // Test various frame ID patterns
    let frame_id_test_cases = vec![
        ("normal_frame_id", "normal-frame-123"),
        ("empty_frame_id", ""),
        ("very_long_frame_id", &"x".repeat(1000)),
        ("special_characters", "frame-with-!@#$%^&*()_+{}[]"),
        ("unicode_frame_id", "frame-🚀-test-🔒"),
        ("whitespace_frame_id", "  frame with spaces  "),
        ("newline_frame_id", "frame\nwith\nnewlines"),
        ("null_byte_frame_id", "frame\0with\0nulls"),
    ];

    for (test_name, frame_id) in frame_id_test_cases {
        let frame = FrameInput {
            frame_id: frame_id.to_string(),
            raw_bytes_len: 1000,
            nesting_depth: 5,
            decode_cpu_ms: 10,
        };

        match check_frame(&frame, &config, timestamp) {
            Ok((verdict, audit)) => {
                let result_json = json!({
                    "success": true,
                    "frame_id_preserved": verdict.frame_id == frame_id,
                    "frame_id_length": frame_id.len(),
                    "verdict_allowed": verdict.allowed,
                    "audit_frame_id_match": audit.frame_id == frame_id,
                    "test_case": test_name,
                });

                golden::assert_scrubbed_json_golden(
                    &format!(
                        "connector_lifecycle_message/frame_id_handling/{}",
                        test_name
                    ),
                    &result_json,
                );
            }
            Err(err) => {
                let error_json = json!({
                    "success": false,
                    "error": format!("{}", err),
                    "frame_id_length": frame_id.len(),
                    "test_case": test_name,
                });

                golden::assert_scrubbed_json_golden(
                    &format!(
                        "connector_lifecycle_message/frame_id_handling/{}_error",
                        test_name
                    ),
                    &error_json,
                );
            }
        }
    }
}

#[test]
fn test_resource_usage_boundary_values() {
    let config = ParserConfig::default_config();
    let timestamp = "2026-04-20T12:00:00Z";

    // Test boundary values for resource usage
    let boundary_test_cases = vec![
        (
            "min_values",
            FrameInput {
                frame_id: "min-values".to_string(),
                raw_bytes_len: 0,
                nesting_depth: 0,
                decode_cpu_ms: 0,
            },
        ),
        (
            "max_safe_values",
            FrameInput {
                frame_id: "max-safe-values".to_string(),
                raw_bytes_len: 999_999, // Just under limit
                nesting_depth: 31,      // Just under limit
                decode_cpu_ms: 99,      // Just under limit
            },
        ),
        (
            "u32_max_depth",
            FrameInput {
                frame_id: "u32-max-depth".to_string(),
                raw_bytes_len: 1000,
                nesting_depth: u32::MAX,
                decode_cpu_ms: 10,
            },
        ),
        (
            "u64_max_bytes",
            FrameInput {
                frame_id: "u64-max-bytes".to_string(),
                raw_bytes_len: u64::MAX,
                nesting_depth: 5,
                decode_cpu_ms: 10,
            },
        ),
        (
            "u64_max_cpu",
            FrameInput {
                frame_id: "u64-max-cpu".to_string(),
                raw_bytes_len: 1000,
                nesting_depth: 5,
                decode_cpu_ms: u64::MAX,
            },
        ),
    ];

    for (test_name, frame) in boundary_test_cases {
        match check_frame(&frame, &config, timestamp) {
            Ok((verdict, audit)) => {
                let result_json = json!({
                    "success": true,
                    "input": {
                        "raw_bytes_len": frame.raw_bytes_len,
                        "nesting_depth": frame.nesting_depth,
                        "decode_cpu_ms": frame.decode_cpu_ms,
                    },
                    "resource_usage": {
                        "bytes_parsed": verdict.resource_usage.bytes_parsed,
                        "nesting_depth": verdict.resource_usage.nesting_depth,
                        "cpu_ms": verdict.resource_usage.cpu_ms,
                    },
                    "allowed": verdict.allowed,
                    "violation_count": verdict.violations.len(),
                    "test_case": test_name,
                });

                golden::assert_scrubbed_json_golden(
                    &format!("connector_lifecycle_message/boundary_values/{}", test_name),
                    &result_json,
                );
            }
            Err(err) => {
                let error_json = json!({
                    "success": false,
                    "error": format!("{}", err),
                    "input": {
                        "raw_bytes_len": frame.raw_bytes_len,
                        "nesting_depth": frame.nesting_depth,
                        "decode_cpu_ms": frame.decode_cpu_ms,
                    },
                    "test_case": test_name,
                });

                golden::assert_scrubbed_json_golden(
                    &format!(
                        "connector_lifecycle_message/boundary_values/{}_error",
                        test_name
                    ),
                    &error_json,
                );
            }
        }
    }
}
