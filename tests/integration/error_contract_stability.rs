//! Integration tests for bd-novi: Stable error code namespace.

use frankenengine_node::connector::error_code_registry::*;

fn make_registry() -> ErrorCodeRegistry {
    let mut r = ErrorCodeRegistry::new();
    let codes = vec![
        ("FRANKEN_PROTOCOL_AUTH_FAILED", Severity::Transient, true, Some(1000), "retry with backoff"),
        ("FRANKEN_SECURITY_KEY_COMPROMISED", Severity::Fatal, false, None, ""),
        ("FRANKEN_EGRESS_TIMEOUT", Severity::Transient, true, Some(2000), "retry"),
        ("FRANKEN_CONNECTOR_LEASE_EXPIRED", Severity::Transient, true, Some(5000), "renegotiate"),
    ];
    for (code, sev, retryable, retry_ms, hint) in codes {
        r.register(&ErrorCodeRegistration {
            code: code.to_string(),
            severity: sev,
            recovery: RecoveryInfo {
                retryable,
                retry_after_ms: retry_ms,
                recovery_hint: hint.to_string(),
            },
            description: format!("Test: {code}"),
            version: 1,
        })
        .unwrap();
        r.freeze(code).unwrap();
    }
    r
}

#[test]
fn inv_ecr_namespaced() {
    let mut r = ErrorCodeRegistry::new();
    let err = r
        .register(&ErrorCodeRegistration {
            code: "BAD_PREFIX_FOO".into(),
            severity: Severity::Transient,
            recovery: RecoveryInfo {
                retryable: true,
                retry_after_ms: None,
                recovery_hint: "hint".into(),
            },
            description: "test".into(),
            version: 1,
        })
        .unwrap_err();
    assert_eq!(err.code(), "ECR_INVALID_NAMESPACE");
}

#[test]
fn inv_ecr_unique() {
    let mut r = ErrorCodeRegistry::new();
    r.register(&ErrorCodeRegistration {
        code: "FRANKEN_PROTOCOL_DUP".into(),
        severity: Severity::Transient,
        recovery: RecoveryInfo {
            retryable: true,
            retry_after_ms: None,
            recovery_hint: "hint".into(),
        },
        description: "first".into(),
        version: 1,
    })
    .unwrap();
    let err = r
        .register(&ErrorCodeRegistration {
            code: "FRANKEN_PROTOCOL_DUP".into(),
            severity: Severity::Transient,
            recovery: RecoveryInfo {
                retryable: true,
                retry_after_ms: None,
                recovery_hint: "hint".into(),
            },
            description: "second".into(),
            version: 1,
        })
        .unwrap_err();
    assert_eq!(err.code(), "ECR_DUPLICATE_CODE");
}

#[test]
fn inv_ecr_recovery_present() {
    let r = make_registry();
    let transient = r.get("FRANKEN_PROTOCOL_AUTH_FAILED").unwrap();
    assert!(transient.recovery.retryable);
    assert!(transient.recovery.retry_after_ms.is_some());
    assert!(!transient.recovery.recovery_hint.is_empty());

    let fatal = r.get("FRANKEN_SECURITY_KEY_COMPROMISED").unwrap();
    assert!(!fatal.recovery.retryable);
}

#[test]
fn inv_ecr_frozen() {
    let mut r = make_registry();
    let err = r
        .register(&ErrorCodeRegistration {
            code: "FRANKEN_PROTOCOL_AUTH_FAILED".into(),
            severity: Severity::Fatal,
            recovery: RecoveryInfo {
                retryable: false,
                retry_after_ms: None,
                recovery_hint: "".into(),
            },
            description: "changed".into(),
            version: 2,
        })
        .unwrap_err();
    assert_eq!(err.code(), "ECR_FROZEN_CONFLICT");
}
