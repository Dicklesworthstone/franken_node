//! bd-3tzl: Bounded parser/resource-accounting guardrails on control-channel frame decode.
//!
//! Prevents decode-DoS via frame size limits, nesting depth limits, and CPU budget.

/// Parser configuration with resource limits.
#[derive(Debug, Clone)]
pub struct ParserConfig {
    pub max_frame_bytes: u64,
    pub max_nesting_depth: u32,
    pub max_decode_cpu_ms: u64,
}

impl ParserConfig {
    pub fn default_config() -> Self {
        Self {
            max_frame_bytes: 1_000_000,
            max_nesting_depth: 32,
            max_decode_cpu_ms: 100,
        }
    }
}

/// Incoming frame to decode.
#[derive(Debug, Clone)]
pub struct FrameInput {
    pub frame_id: String,
    pub raw_bytes_len: u64,
    pub nesting_depth: u32,
    pub decode_cpu_ms: u64,
}

/// Which guardrail was violated.
#[derive(Debug, Clone, PartialEq)]
pub enum GuardrailViolation {
    SizeExceeded { actual: u64, limit: u64 },
    DepthExceeded { actual: u32, limit: u32 },
    CpuExceeded { actual: u64, limit: u64 },
    MalformedFrame { reason: String },
}

/// Result of a decode attempt.
#[derive(Debug, Clone)]
pub struct DecodeVerdict {
    pub frame_id: String,
    pub allowed: bool,
    pub violations: Vec<GuardrailViolation>,
    pub resource_usage: ResourceUsage,
}

/// Resource usage for a decode.
#[derive(Debug, Clone)]
pub struct ResourceUsage {
    pub bytes_parsed: u64,
    pub nesting_depth: u32,
    pub cpu_ms: u64,
}

/// Audit record for a decode attempt.
#[derive(Debug, Clone)]
pub struct DecodeAuditEntry {
    pub frame_id: String,
    pub size: u64,
    pub depth: u32,
    pub cpu_used: u64,
    pub size_limit: u64,
    pub depth_limit: u32,
    pub cpu_limit: u64,
    pub verdict: String,
    pub timestamp: String,
}

/// Errors from parser operations.
#[derive(Debug, Clone, PartialEq)]
pub enum ParserError {
    SizeExceeded {
        frame_id: String,
        actual: u64,
        limit: u64,
    },
    DepthExceeded {
        frame_id: String,
        actual: u32,
        limit: u32,
    },
    CpuExceeded {
        frame_id: String,
        actual: u64,
        limit: u64,
    },
    InvalidConfig {
        reason: String,
    },
    MalformedFrame {
        frame_id: String,
        reason: String,
    },
}

impl ParserError {
    pub fn code(&self) -> &'static str {
        match self {
            Self::SizeExceeded { .. } => "BPG_SIZE_EXCEEDED",
            Self::DepthExceeded { .. } => "BPG_DEPTH_EXCEEDED",
            Self::CpuExceeded { .. } => "BPG_CPU_EXCEEDED",
            Self::InvalidConfig { .. } => "BPG_INVALID_CONFIG",
            Self::MalformedFrame { .. } => "BPG_MALFORMED_FRAME",
        }
    }
}

impl std::fmt::Display for ParserError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::SizeExceeded {
                frame_id,
                actual,
                limit,
            } => write!(
                f,
                "BPG_SIZE_EXCEEDED: {frame_id} actual={actual} limit={limit}"
            ),
            Self::DepthExceeded {
                frame_id,
                actual,
                limit,
            } => write!(
                f,
                "BPG_DEPTH_EXCEEDED: {frame_id} actual={actual} limit={limit}"
            ),
            Self::CpuExceeded {
                frame_id,
                actual,
                limit,
            } => write!(
                f,
                "BPG_CPU_EXCEEDED: {frame_id} actual={actual}ms limit={limit}ms"
            ),
            Self::InvalidConfig { reason } => write!(f, "BPG_INVALID_CONFIG: {reason}"),
            Self::MalformedFrame { frame_id, reason } => {
                write!(f, "BPG_MALFORMED_FRAME: {frame_id} {reason}")
            }
        }
    }
}

/// Validate parser config.
pub fn validate_config(config: &ParserConfig) -> Result<(), ParserError> {
    if config.max_frame_bytes == 0 {
        return Err(ParserError::InvalidConfig {
            reason: "max_frame_bytes must be > 0".into(),
        });
    }
    if config.max_nesting_depth == 0 {
        return Err(ParserError::InvalidConfig {
            reason: "max_nesting_depth must be > 0".into(),
        });
    }
    if config.max_decode_cpu_ms == 0 {
        return Err(ParserError::InvalidConfig {
            reason: "max_decode_cpu_ms must be > 0".into(),
        });
    }
    Ok(())
}

/// Check a frame against parser guardrails.
///
/// INV-BPG-SIZE-BOUNDED: size checked first.
/// INV-BPG-DEPTH-BOUNDED: nesting depth checked.
/// INV-BPG-CPU-BOUNDED: CPU budget checked.
/// INV-BPG-AUDITABLE: audit record emitted.
pub fn check_frame(
    frame: &FrameInput,
    config: &ParserConfig,
    timestamp: &str,
) -> Result<(DecodeVerdict, DecodeAuditEntry), ParserError> {
    validate_config(config)?;

    if frame.frame_id.trim().is_empty() {
        return Err(ParserError::MalformedFrame {
            frame_id: "(empty)".into(),
            reason: "frame_id must not be empty".into(),
        });
    }
    if frame.frame_id.as_bytes().contains(&0) {
        return Err(ParserError::MalformedFrame {
            frame_id: "(invalid)".into(),
            reason: "frame_id must not contain NUL bytes".into(),
        });
    }

    let mut violations = Vec::new();

    // Check 1: size (INV-BPG-SIZE-BOUNDED)
    if frame.raw_bytes_len >= config.max_frame_bytes {
        violations.push(GuardrailViolation::SizeExceeded {
            actual: frame.raw_bytes_len,
            limit: config.max_frame_bytes,
        });
    }

    // Check 2: nesting depth (INV-BPG-DEPTH-BOUNDED)
    if frame.nesting_depth >= config.max_nesting_depth {
        violations.push(GuardrailViolation::DepthExceeded {
            actual: frame.nesting_depth,
            limit: config.max_nesting_depth,
        });
    }

    // Check 3: CPU budget (INV-BPG-CPU-BOUNDED)
    if frame.decode_cpu_ms >= config.max_decode_cpu_ms {
        violations.push(GuardrailViolation::CpuExceeded {
            actual: frame.decode_cpu_ms,
            limit: config.max_decode_cpu_ms,
        });
    }

    let allowed = violations.is_empty();

    let verdict = DecodeVerdict {
        frame_id: frame.frame_id.clone(),
        allowed,
        violations,
        resource_usage: ResourceUsage {
            bytes_parsed: frame.raw_bytes_len,
            nesting_depth: frame.nesting_depth,
            cpu_ms: frame.decode_cpu_ms,
        },
    };

    let audit = DecodeAuditEntry {
        frame_id: frame.frame_id.clone(),
        size: frame.raw_bytes_len,
        depth: frame.nesting_depth,
        cpu_used: frame.decode_cpu_ms,
        size_limit: config.max_frame_bytes,
        depth_limit: config.max_nesting_depth,
        cpu_limit: config.max_decode_cpu_ms,
        verdict: if allowed {
            "ALLOW".to_string()
        } else {
            "BLOCK".to_string()
        },
        timestamp: timestamp.to_string(),
    };

    Ok((verdict, audit))
}

/// Batch check frames. Returns verdicts in order.
pub fn check_batch(
    frames: &[FrameInput],
    config: &ParserConfig,
    timestamp: &str,
) -> Result<Vec<(DecodeVerdict, DecodeAuditEntry)>, ParserError> {
    validate_config(config)?;
    let mut results = Vec::with_capacity(frames.len());
    for frame in frames {
        let (verdict, audit) = check_frame(frame, config, timestamp)?;
        results.push((verdict, audit));
    }
    Ok(results)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config() -> ParserConfig {
        ParserConfig {
            max_frame_bytes: 1000,
            max_nesting_depth: 10,
            max_decode_cpu_ms: 50,
        }
    }

    fn frame(id: &str, bytes: u64, depth: u32, cpu: u64) -> FrameInput {
        FrameInput {
            frame_id: id.into(),
            raw_bytes_len: bytes,
            nesting_depth: depth,
            decode_cpu_ms: cpu,
        }
    }

    #[test]
    fn allow_within_limits() {
        let f = frame("f1", 500, 5, 20);
        let (v, a) = check_frame(&f, &config(), "ts").unwrap();
        assert!(v.allowed);
        assert!(v.violations.is_empty());
        assert_eq!(a.verdict, "ALLOW");
    }

    #[test]
    fn block_size_exceeded() {
        let f = frame("f1", 1001, 5, 20);
        let (v, _) = check_frame(&f, &config(), "ts").unwrap();
        assert!(!v.allowed);
        assert!(
            v.violations
                .iter()
                .any(|v| matches!(v, GuardrailViolation::SizeExceeded { .. }))
        );
    }

    #[test]
    fn exact_size_limit_blocks_with_payload() {
        let f = frame("f1", 1000, 5, 20);
        let (v, audit) = check_frame(&f, &config(), "ts").unwrap();

        assert!(!v.allowed);
        assert_eq!(
            v.violations,
            vec![GuardrailViolation::SizeExceeded {
                actual: 1000,
                limit: 1000,
            }]
        );
        assert_eq!(audit.verdict, "BLOCK");
    }

    #[test]
    fn block_depth_exceeded() {
        let f = frame("f1", 500, 11, 20);
        let (v, _) = check_frame(&f, &config(), "ts").unwrap();
        assert!(!v.allowed);
        assert!(
            v.violations
                .iter()
                .any(|v| matches!(v, GuardrailViolation::DepthExceeded { .. }))
        );
    }

    #[test]
    fn exact_depth_limit_blocks_with_payload() {
        let f = frame("f1", 500, 10, 20);
        let (v, audit) = check_frame(&f, &config(), "ts").unwrap();

        assert!(!v.allowed);
        assert_eq!(
            v.violations,
            vec![GuardrailViolation::DepthExceeded {
                actual: 10,
                limit: 10,
            }]
        );
        assert_eq!(audit.verdict, "BLOCK");
    }

    #[test]
    fn block_cpu_exceeded() {
        let f = frame("f1", 500, 5, 51);
        let (v, _) = check_frame(&f, &config(), "ts").unwrap();
        assert!(!v.allowed);
        assert!(
            v.violations
                .iter()
                .any(|v| matches!(v, GuardrailViolation::CpuExceeded { .. }))
        );
    }

    #[test]
    fn exact_cpu_limit_blocks_with_payload() {
        let f = frame("f1", 500, 5, 50);
        let (v, audit) = check_frame(&f, &config(), "ts").unwrap();

        assert!(!v.allowed);
        assert_eq!(
            v.violations,
            vec![GuardrailViolation::CpuExceeded {
                actual: 50,
                limit: 50,
            }]
        );
        assert_eq!(audit.verdict, "BLOCK");
    }

    #[test]
    fn multiple_violations() {
        let f = frame("f1", 1001, 11, 51);
        let (v, _) = check_frame(&f, &config(), "ts").unwrap();
        assert!(!v.allowed);
        assert_eq!(v.violations.len(), 3);
    }

    #[test]
    fn exact_all_limits_emit_all_blocking_violations() {
        let f = frame("f1", 1000, 10, 50);
        let (v, audit) = check_frame(&f, &config(), "ts").unwrap();

        assert!(!v.allowed);
        assert_eq!(v.violations.len(), 3);
        assert_eq!(
            v.violations,
            vec![
                GuardrailViolation::SizeExceeded {
                    actual: 1000,
                    limit: 1000,
                },
                GuardrailViolation::DepthExceeded {
                    actual: 10,
                    limit: 10,
                },
                GuardrailViolation::CpuExceeded {
                    actual: 50,
                    limit: 50,
                },
            ]
        );
        assert_eq!(audit.verdict, "BLOCK");
    }

    #[test]
    fn malformed_empty_id() {
        let f = frame("", 100, 5, 20);
        let err = check_frame(&f, &config(), "ts").unwrap_err();
        assert_eq!(err.code(), "BPG_MALFORMED_FRAME");
    }

    #[test]
    fn malformed_empty_id_reports_placeholder_and_reason() {
        let f = frame("", 100, 5, 20);
        let err = check_frame(&f, &config(), "ts").unwrap_err();

        assert!(matches!(
            err,
            ParserError::MalformedFrame { ref frame_id, ref reason }
                if frame_id == "(empty)" && reason == "frame_id must not be empty"
        ));
    }

    #[test]
    fn audit_entry_complete() {
        let f = frame("f1", 500, 5, 20);
        let (_, audit) = check_frame(&f, &config(), "2026-01-01").unwrap();
        assert_eq!(audit.frame_id, "f1");
        assert_eq!(audit.size, 500);
        assert_eq!(audit.depth, 5);
        assert_eq!(audit.cpu_used, 20);
        assert_eq!(audit.timestamp, "2026-01-01");
    }

    #[test]
    fn resource_usage_tracked() {
        let f = frame("f1", 500, 5, 20);
        let (v, _) = check_frame(&f, &config(), "ts").unwrap();
        assert_eq!(v.resource_usage.bytes_parsed, 500);
        assert_eq!(v.resource_usage.nesting_depth, 5);
        assert_eq!(v.resource_usage.cpu_ms, 20);
    }

    #[test]
    fn batch_check() {
        let frames = vec![
            frame("f1", 500, 5, 20),  // ok
            frame("f2", 1001, 5, 20), // size exceeded
            frame("f3", 500, 5, 20),  // ok
        ];
        let results = check_batch(&frames, &config(), "ts").unwrap();
        assert_eq!(results.len(), 3);
        assert!(results[0].0.allowed);
        assert!(!results[1].0.allowed);
        assert!(results[2].0.allowed);
    }

    #[test]
    fn batch_rejects_invalid_config_before_frame_validation() {
        let mut cfg = config();
        cfg.max_frame_bytes = 0;
        let frames = vec![frame("", 100, 5, 20)];
        let err = check_batch(&frames, &cfg, "ts").unwrap_err();

        assert!(matches!(
            err,
            ParserError::InvalidConfig { ref reason }
                if reason == "max_frame_bytes must be > 0"
        ));
    }

    #[test]
    fn batch_aborts_on_malformed_frame_after_valid_prefix() {
        let frames = vec![frame("f1", 500, 5, 20), frame("", 500, 5, 20)];
        let err = check_batch(&frames, &config(), "ts").unwrap_err();

        assert!(matches!(
            err,
            ParserError::MalformedFrame { ref frame_id, .. } if frame_id == "(empty)"
        ));
    }

    #[test]
    fn deterministic_check() {
        let f = frame("f1", 500, 5, 20);
        let (v1, a1) = check_frame(&f, &config(), "ts").unwrap();
        let (v2, a2) = check_frame(&f, &config(), "ts").unwrap();
        assert_eq!(v1.allowed, v2.allowed);
        assert_eq!(a1.verdict, a2.verdict);
    }

    #[test]
    fn invalid_config_zero_bytes() {
        let mut cfg = config();
        cfg.max_frame_bytes = 0;
        let err = check_frame(&frame("f1", 100, 5, 20), &cfg, "ts").unwrap_err();
        assert_eq!(err.code(), "BPG_INVALID_CONFIG");
    }

    #[test]
    fn invalid_config_zero_depth() {
        let mut cfg = config();
        cfg.max_nesting_depth = 0;
        let err = check_frame(&frame("f1", 100, 5, 20), &cfg, "ts").unwrap_err();
        assert_eq!(err.code(), "BPG_INVALID_CONFIG");
    }

    #[test]
    fn invalid_config_zero_cpu() {
        let mut cfg = config();
        cfg.max_decode_cpu_ms = 0;
        let err = check_frame(&frame("f1", 100, 5, 20), &cfg, "ts").unwrap_err();
        assert_eq!(err.code(), "BPG_INVALID_CONFIG");
    }

    #[test]
    fn error_codes_all_present() {
        assert_eq!(
            ParserError::SizeExceeded {
                frame_id: "".into(),
                actual: 0,
                limit: 0
            }
            .code(),
            "BPG_SIZE_EXCEEDED"
        );
        assert_eq!(
            ParserError::DepthExceeded {
                frame_id: "".into(),
                actual: 0,
                limit: 0
            }
            .code(),
            "BPG_DEPTH_EXCEEDED"
        );
        assert_eq!(
            ParserError::CpuExceeded {
                frame_id: "".into(),
                actual: 0,
                limit: 0
            }
            .code(),
            "BPG_CPU_EXCEEDED"
        );
        assert_eq!(
            ParserError::InvalidConfig { reason: "".into() }.code(),
            "BPG_INVALID_CONFIG"
        );
        assert_eq!(
            ParserError::MalformedFrame {
                frame_id: "".into(),
                reason: "".into()
            }
            .code(),
            "BPG_MALFORMED_FRAME"
        );
    }

    #[test]
    fn error_display() {
        let e = ParserError::SizeExceeded {
            frame_id: "f1".into(),
            actual: 2000,
            limit: 1000,
        };
        assert!(e.to_string().contains("BPG_SIZE_EXCEEDED"));
    }

    #[test]
    fn default_config_valid() {
        assert!(validate_config(&ParserConfig::default_config()).is_ok());
    }

    #[test]
    fn boundary_exact_limits() {
        // Exactly at limit is fail-closed (rejected)
        let f = frame("f1", 1000, 10, 50);
        let (v, _) = check_frame(&f, &config(), "ts").unwrap();
        assert!(!v.allowed);

        // One below limit passes
        let f = frame("f2", 999, 9, 49);
        let (v, _) = check_frame(&f, &config(), "ts").unwrap();
        assert!(v.allowed);
    }
}

#[cfg(test)]
mod frame_parser_additional_negative_tests {
    use super::*;

    fn config() -> ParserConfig {
        ParserConfig {
            max_frame_bytes: 1000,
            max_nesting_depth: 10,
            max_decode_cpu_ms: 50,
        }
    }

    fn frame(id: &str, bytes: u64, depth: u32, cpu: u64) -> FrameInput {
        FrameInput {
            frame_id: id.to_string(),
            raw_bytes_len: bytes,
            nesting_depth: depth,
            decode_cpu_ms: cpu,
        }
    }

    #[test]
    fn whitespace_frame_id_is_malformed() {
        let err = check_frame(&frame("   ", 100, 2, 10), &config(), "ts")
            .expect_err("blank frame ID must fail closed");

        assert!(matches!(
            err,
            ParserError::MalformedFrame { ref frame_id, ref reason }
                if frame_id == "(empty)" && reason == "frame_id must not be empty"
        ));
    }

    #[test]
    fn tab_newline_frame_id_is_malformed_with_placeholder() {
        let err = check_frame(&frame("\t\n ", 100, 2, 10), &config(), "ts")
            .expect_err("control-whitespace frame ID must fail closed");

        assert_eq!(err.code(), "BPG_MALFORMED_FRAME");
        assert!(err.to_string().contains("(empty)"));
    }

    #[test]
    fn malformed_frame_id_precedes_resource_guardrails() {
        let err = check_frame(&frame(" ", 1000, 10, 50), &config(), "ts")
            .expect_err("malformed frame ID should fail before guardrail verdicts");

        assert!(matches!(
            err,
            ParserError::MalformedFrame { ref frame_id, .. } if frame_id == "(empty)"
        ));
    }

    #[test]
    fn batch_rejects_blank_frame_id_after_valid_prefix() {
        let frames = vec![frame("ok", 100, 2, 10), frame(" \t", 100, 2, 10)];
        let err = check_batch(&frames, &config(), "ts")
            .expect_err("batch must abort when a later frame ID is blank");

        assert!(matches!(
            err,
            ParserError::MalformedFrame { ref frame_id, .. } if frame_id == "(empty)"
        ));
    }

    #[test]
    fn invalid_config_reports_zero_depth_before_zero_cpu() {
        let cfg = ParserConfig {
            max_frame_bytes: 1,
            max_nesting_depth: 0,
            max_decode_cpu_ms: 0,
        };
        let err = validate_config(&cfg).expect_err("zero depth must be invalid");

        assert!(matches!(
            err,
            ParserError::InvalidConfig { ref reason }
                if reason == "max_nesting_depth must be > 0"
        ));
    }

    #[test]
    fn invalid_zero_cpu_config_rejects_before_frame_guardrails() {
        let cfg = ParserConfig {
            max_frame_bytes: 1,
            max_nesting_depth: 1,
            max_decode_cpu_ms: 0,
        };
        let err = check_frame(&frame("", 1, 1, 0), &cfg, "ts")
            .expect_err("invalid config must be reported before malformed frame");

        assert!(matches!(
            err,
            ParserError::InvalidConfig { ref reason }
                if reason == "max_decode_cpu_ms must be > 0"
        ));
    }

    #[test]
    fn max_u64_frame_size_at_limit_is_blocked() {
        let cfg = ParserConfig {
            max_frame_bytes: u64::MAX,
            max_nesting_depth: u32::MAX,
            max_decode_cpu_ms: u64::MAX,
        };
        let (verdict, audit) =
            check_frame(&frame("huge", u64::MAX, 1, 1), &cfg, "ts").expect("verdict");

        assert!(!verdict.allowed);
        assert_eq!(
            verdict.violations,
            vec![GuardrailViolation::SizeExceeded {
                actual: u64::MAX,
                limit: u64::MAX,
            }]
        );
        assert_eq!(audit.verdict, "BLOCK");
    }

    #[test]
    fn max_u32_depth_at_limit_is_blocked() {
        let cfg = ParserConfig {
            max_frame_bytes: u64::MAX,
            max_nesting_depth: u32::MAX,
            max_decode_cpu_ms: u64::MAX,
        };
        let (verdict, audit) =
            check_frame(&frame("deep", 1, u32::MAX, 1), &cfg, "ts").expect("verdict");

        assert!(!verdict.allowed);
        assert_eq!(
            verdict.violations,
            vec![GuardrailViolation::DepthExceeded {
                actual: u32::MAX,
                limit: u32::MAX,
            }]
        );
        assert_eq!(audit.depth_limit, u32::MAX);
        assert_eq!(audit.verdict, "BLOCK");
    }

    #[test]
    fn max_u64_cpu_at_limit_is_blocked() {
        let cfg = ParserConfig {
            max_frame_bytes: u64::MAX,
            max_nesting_depth: u32::MAX,
            max_decode_cpu_ms: u64::MAX,
        };
        let (verdict, audit) =
            check_frame(&frame("cpu", 1, 1, u64::MAX), &cfg, "ts").expect("verdict");

        assert!(!verdict.allowed);
        assert_eq!(
            verdict.violations,
            vec![GuardrailViolation::CpuExceeded {
                actual: u64::MAX,
                limit: u64::MAX,
            }]
        );
        assert_eq!(audit.cpu_limit, u64::MAX);
        assert_eq!(audit.verdict, "BLOCK");
    }

    #[test]
    fn blocked_frame_preserves_resource_usage_and_audit_limits() {
        let (verdict, audit) =
            check_frame(&frame("blocked", 1000, 10, 50), &config(), "ts-blocked")
                .expect("blocked verdict");

        assert!(!verdict.allowed);
        assert_eq!(verdict.resource_usage.bytes_parsed, 1000);
        assert_eq!(verdict.resource_usage.nesting_depth, 10);
        assert_eq!(verdict.resource_usage.cpu_ms, 50);
        assert_eq!(audit.size_limit, 1000);
        assert_eq!(audit.depth_limit, 10);
        assert_eq!(audit.cpu_limit, 50);
        assert_eq!(audit.timestamp, "ts-blocked");
    }

    #[test]
    fn batch_preserves_blocked_verdict_order_for_guardrail_violations() {
        let frames = vec![
            frame("size-block", 1000, 1, 1),
            frame("depth-block", 1, 10, 1),
            frame("cpu-block", 1, 1, 50),
        ];

        let results = check_batch(&frames, &config(), "ts").expect("batch verdicts");

        assert_eq!(results.len(), 3);
        assert_eq!(results[0].0.frame_id, "size-block");
        assert_eq!(results[1].0.frame_id, "depth-block");
        assert_eq!(results[2].0.frame_id, "cpu-block");
        assert!(results.iter().all(|(verdict, _)| !verdict.allowed));
        assert!(matches!(
            results[0].0.violations.as_slice(),
            [GuardrailViolation::SizeExceeded { .. }]
        ));
        assert!(matches!(
            results[1].0.violations.as_slice(),
            [GuardrailViolation::DepthExceeded { .. }]
        ));
        assert!(matches!(
            results[2].0.violations.as_slice(),
            [GuardrailViolation::CpuExceeded { .. }]
        ));
    }

    #[test]
    fn invalid_config_reports_zero_bytes_before_other_zero_limits() {
        let cfg = ParserConfig {
            max_frame_bytes: 0,
            max_nesting_depth: 0,
            max_decode_cpu_ms: 0,
        };

        let err = validate_config(&cfg).expect_err("zero byte limit must be invalid first");

        assert!(matches!(
            err,
            ParserError::InvalidConfig { ref reason }
                if reason == "max_frame_bytes must be > 0"
        ));
    }

    #[test]
    fn invalid_zero_bytes_config_rejects_before_malformed_frame() {
        let cfg = ParserConfig {
            max_frame_bytes: 0,
            max_nesting_depth: 1,
            max_decode_cpu_ms: 1,
        };

        let err = check_frame(&frame(" ", 1, 1, 1), &cfg, "ts")
            .expect_err("invalid config must be reported before malformed frame");

        assert!(matches!(
            err,
            ParserError::InvalidConfig { ref reason }
                if reason == "max_frame_bytes must be > 0"
        ));
    }

    #[test]
    fn unicode_whitespace_frame_id_is_malformed() {
        let err = check_frame(&frame("\u{2003}\u{2009}", 1, 1, 1), &config(), "ts")
            .expect_err("unicode-whitespace frame ID must fail closed");

        assert!(matches!(
            err,
            ParserError::MalformedFrame { ref frame_id, ref reason }
                if frame_id == "(empty)" && reason == "frame_id must not be empty"
        ));
    }

    #[test]
    fn size_and_depth_violations_do_not_include_cpu() {
        let (verdict, audit) = check_frame(&frame("size-depth", 1000, 10, 49), &config(), "ts")
            .expect("guardrail verdict");

        assert!(!verdict.allowed);
        assert_eq!(verdict.violations.len(), 2);
        assert!(matches!(
            verdict.violations.as_slice(),
            [
                GuardrailViolation::SizeExceeded { .. },
                GuardrailViolation::DepthExceeded { .. }
            ]
        ));
        assert_eq!(audit.cpu_used, 49);
        assert_eq!(audit.verdict, "BLOCK");
    }

    #[test]
    fn size_and_cpu_violations_do_not_include_depth() {
        let (verdict, audit) = check_frame(&frame("size-cpu", 1000, 9, 50), &config(), "ts")
            .expect("guardrail verdict");

        assert!(!verdict.allowed);
        assert_eq!(verdict.violations.len(), 2);
        assert!(matches!(
            verdict.violations.as_slice(),
            [
                GuardrailViolation::SizeExceeded { .. },
                GuardrailViolation::CpuExceeded { .. }
            ]
        ));
        assert_eq!(audit.depth, 9);
        assert_eq!(audit.verdict, "BLOCK");
    }

    #[test]
    fn depth_and_cpu_violations_do_not_include_size() {
        let (verdict, audit) = check_frame(&frame("depth-cpu", 999, 10, 50), &config(), "ts")
            .expect("guardrail verdict");

        assert!(!verdict.allowed);
        assert_eq!(verdict.violations.len(), 2);
        assert!(matches!(
            verdict.violations.as_slice(),
            [
                GuardrailViolation::DepthExceeded { .. },
                GuardrailViolation::CpuExceeded { .. }
            ]
        ));
        assert_eq!(audit.size, 999);
        assert_eq!(audit.verdict, "BLOCK");
    }

    #[test]
    fn batch_aborts_on_first_malformed_frame_before_later_resource_blocks() {
        let frames = vec![frame(" \t", 1, 1, 1), frame("later-size-block", 1000, 1, 1)];

        let err = check_batch(&frames, &config(), "ts")
            .expect_err("first malformed frame must abort batch");

        assert!(matches!(
            err,
            ParserError::MalformedFrame { ref frame_id, .. } if frame_id == "(empty)"
        ));
    }

    #[test]
    fn batch_zero_depth_config_preempts_valid_frames() {
        let cfg = ParserConfig {
            max_frame_bytes: 1,
            max_nesting_depth: 0,
            max_decode_cpu_ms: 1,
        };
        let frames = vec![frame("valid-looking", 0, 0, 0)];

        let err = check_batch(&frames, &cfg, "ts")
            .expect_err("invalid config must fail before frame processing");

        assert!(matches!(
            err,
            ParserError::InvalidConfig { ref reason }
                if reason == "max_nesting_depth must be > 0"
        ));
    }

    #[test]
    fn malformed_frame_display_includes_placeholder_and_reason() {
        let err = check_frame(&frame("", 1, 1, 1), &config(), "ts")
            .expect_err("empty frame ID must fail");
        let rendered = err.to_string();

        assert!(rendered.contains("BPG_MALFORMED_FRAME"));
        assert!(rendered.contains("(empty)"));
        assert!(rendered.contains("frame_id must not be empty"));
    }
}

#[cfg(test)]
mod frame_parser_nul_frame_id_tests {
    use super::*;

    fn config() -> ParserConfig {
        ParserConfig {
            max_frame_bytes: 1000,
            max_nesting_depth: 10,
            max_decode_cpu_ms: 50,
        }
    }

    fn frame(id: &str, bytes: u64, depth: u32, cpu: u64) -> FrameInput {
        FrameInput {
            frame_id: id.to_string(),
            raw_bytes_len: bytes,
            nesting_depth: depth,
            decode_cpu_ms: cpu,
        }
    }

    fn assert_nul_frame_error(err: ParserError) {
        assert_eq!(err.code(), "BPG_MALFORMED_FRAME");
        assert!(matches!(
            err,
            ParserError::MalformedFrame { ref frame_id, ref reason }
                if frame_id == "(invalid)" && reason == "frame_id must not contain NUL bytes"
        ));
    }

    #[test]
    fn nul_only_frame_id_is_malformed() {
        let err = check_frame(&frame("\0", 1, 1, 1), &config(), "ts")
            .expect_err("NUL-only frame ID must fail closed");

        assert_nul_frame_error(err);
    }

    #[test]
    fn embedded_nul_frame_id_is_malformed() {
        let err = check_frame(&frame("frame\0id", 1, 1, 1), &config(), "ts")
            .expect_err("embedded NUL frame ID must fail closed");

        assert_nul_frame_error(err);
    }

    #[test]
    fn trailing_nul_frame_id_is_malformed_even_with_valid_resources() {
        let err = check_frame(&frame("frame-id\0", 999, 9, 49), &config(), "ts")
            .expect_err("trailing NUL frame ID must fail closed");

        assert_nul_frame_error(err);
    }

    #[test]
    fn nul_frame_id_error_display_uses_sanitized_placeholder() {
        let err = check_frame(&frame("raw\0frame", 1, 1, 1), &config(), "ts")
            .expect_err("NUL frame ID must fail");
        let rendered = err.to_string();

        assert!(rendered.contains("(invalid)"));
        assert!(rendered.contains("frame_id must not contain NUL bytes"));
        assert!(!rendered.contains("raw"));
        assert!(!rendered.contains('\0'));
    }

    #[test]
    fn nul_frame_id_precedes_resource_guardrail_violations() {
        let err = check_frame(&frame("bad\0id", 1000, 10, 50), &config(), "ts")
            .expect_err("malformed frame ID must preempt resource checks");

        assert_nul_frame_error(err);
    }

    #[test]
    fn batch_aborts_on_nul_frame_id_after_valid_prefix() {
        let frames = vec![frame("ok", 1, 1, 1), frame("bad\0id", 1, 1, 1)];
        let err = check_batch(&frames, &config(), "ts")
            .expect_err("batch must abort on later NUL frame ID");

        assert_nul_frame_error(err);
    }

    #[test]
    fn batch_nul_frame_id_preempts_later_resource_blocks() {
        let frames = vec![
            frame("bad\0id", 1, 1, 1),
            frame("later-size-block", 1000, 1, 1),
            frame("later-depth-block", 1, 10, 1),
        ];
        let err = check_batch(&frames, &config(), "ts")
            .expect_err("malformed frame ID must abort before later blocks");

        assert_nul_frame_error(err);
    }
}
