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

    if frame.frame_id.is_empty() {
        return Err(ParserError::MalformedFrame {
            frame_id: "(empty)".into(),
            reason: "frame_id must not be empty".into(),
        });
    }

    let mut violations = Vec::new();

    // Check 1: size (INV-BPG-SIZE-BOUNDED)
    if frame.raw_bytes_len > config.max_frame_bytes {
        violations.push(GuardrailViolation::SizeExceeded {
            actual: frame.raw_bytes_len,
            limit: config.max_frame_bytes,
        });
    }

    // Check 2: nesting depth (INV-BPG-DEPTH-BOUNDED)
    if frame.nesting_depth > config.max_nesting_depth {
        violations.push(GuardrailViolation::DepthExceeded {
            actual: frame.nesting_depth,
            limit: config.max_nesting_depth,
        });
    }

    // Check 3: CPU budget (INV-BPG-CPU-BOUNDED)
    if frame.decode_cpu_ms > config.max_decode_cpu_ms {
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
    fn multiple_violations() {
        let f = frame("f1", 1001, 11, 51);
        let (v, _) = check_frame(&f, &config(), "ts").unwrap();
        assert!(!v.allowed);
        assert_eq!(v.violations.len(), 3);
    }

    #[test]
    fn malformed_empty_id() {
        let f = frame("", 100, 5, 20);
        let err = check_frame(&f, &config(), "ts").unwrap_err();
        assert_eq!(err.code(), "BPG_MALFORMED_FRAME");
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
        // Exactly at limit should pass
        let f = frame("f1", 1000, 10, 50);
        let (v, _) = check_frame(&f, &config(), "ts").unwrap();
        assert!(v.allowed);
    }
}
