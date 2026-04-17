//! bd-3cm3: Schema-gated quarantine promotion rules and provenance receipts.
//!
//! Promotion requires reachability + authenticated request + schema validation.
//! Provenance receipt emitted on every successful promotion. Invalid promotions fail closed.

/// Promotion rule configuration.
#[derive(Debug, Clone)]
pub struct PromotionRule {
    pub required_schema_version: String,
    pub require_reachability: bool,
    pub require_pin: bool,
}

impl PromotionRule {
    pub fn default_rule() -> Self {
        Self {
            required_schema_version: "1.0".into(),
            require_reachability: true,
            require_pin: false,
        }
    }
}

/// Request to promote an object from quarantine.
#[derive(Debug, Clone)]
pub struct PromotionRequest {
    pub object_id: String,
    pub requester_id: String,
    pub authenticated: bool,
    pub schema_version: String,
    pub reachable: bool,
    pub pinned: bool,
    pub reason: String,
}

/// Provenance receipt for a successful promotion.
#[derive(Debug, Clone)]
pub struct ProvenanceReceipt {
    pub object_id: String,
    pub promoted_at: String,
    pub requester_id: String,
    pub reason: String,
    pub schema_version: String,
    pub validator_id: String,
    pub trace_id: String,
}

/// Rejection reason for a failed promotion.
#[derive(Debug, Clone, PartialEq)]
pub enum RejectionReason {
    SchemaFailed { expected: String, got: String },
    NotAuthenticated,
    NotReachable,
    NotPinned,
}

/// Result of a promotion attempt.
#[derive(Debug, Clone)]
pub struct PromotionResult {
    pub object_id: String,
    pub promoted: bool,
    pub receipt: Option<ProvenanceReceipt>,
    pub rejection_reasons: Vec<RejectionReason>,
}

/// Errors from promotion operations.
#[derive(Debug, Clone, PartialEq)]
pub enum PromotionError {
    SchemaFailed {
        object_id: String,
        expected: String,
        got: String,
    },
    NotAuthenticated {
        object_id: String,
        requester_id: String,
    },
    NotReachable {
        object_id: String,
    },
    NotPinned {
        object_id: String,
    },
    InvalidRequest {
        reason: String,
    },
    InvalidRule {
        reason: String,
    },
}

impl PromotionError {
    pub fn code(&self) -> &'static str {
        match self {
            Self::SchemaFailed { .. } => "QPR_SCHEMA_FAILED",
            Self::NotAuthenticated { .. } => "QPR_NOT_AUTHENTICATED",
            Self::NotReachable { .. } => "QPR_NOT_REACHABLE",
            Self::NotPinned { .. } => "QPR_NOT_PINNED",
            Self::InvalidRequest { .. } => "QPR_INVALID_REQUEST",
            Self::InvalidRule { .. } => "QPR_INVALID_RULE",
        }
    }
}

impl std::fmt::Display for PromotionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::SchemaFailed {
                object_id,
                expected,
                got,
            } => write!(
                f,
                "QPR_SCHEMA_FAILED: {object_id} expected={expected} got={got}"
            ),
            Self::NotAuthenticated {
                object_id,
                requester_id,
            } => write!(
                f,
                "QPR_NOT_AUTHENTICATED: {object_id} requester={requester_id}"
            ),
            Self::NotReachable { object_id } => write!(f, "QPR_NOT_REACHABLE: {object_id}"),
            Self::NotPinned { object_id } => write!(f, "QPR_NOT_PINNED: {object_id}"),
            Self::InvalidRequest { reason } => write!(f, "QPR_INVALID_REQUEST: {reason}"),
            Self::InvalidRule { reason } => write!(f, "QPR_INVALID_RULE: {reason}"),
        }
    }
}

/// Validate a promotion rule.
pub fn validate_rule(rule: &PromotionRule) -> Result<(), PromotionError> {
    if rule.required_schema_version.trim().is_empty() {
        return Err(PromotionError::InvalidRule {
            reason: "required_schema_version must not be empty".into(),
        });
    }
    Ok(())
}

fn validate_request(
    request: &PromotionRequest,
    validator_id: &str,
    trace_id: &str,
    timestamp: &str,
) -> Result<(), PromotionError> {
    for (field, value) in [
        ("object_id", request.object_id.as_str()),
        ("requester_id", request.requester_id.as_str()),
        ("reason", request.reason.as_str()),
        ("validator_id", validator_id),
        ("trace_id", trace_id),
        ("timestamp", timestamp),
    ] {
        if value.trim().is_empty() {
            return Err(PromotionError::InvalidRequest {
                reason: format!("{field} must not be empty"),
            });
        }
    }
    Ok(())
}

/// Evaluate a promotion request against a rule.
///
/// INV-QPR-SCHEMA-GATED: schema version must match.
/// INV-QPR-AUTHENTICATED: request must be authenticated.
/// INV-QPR-FAIL-CLOSED: any failure → object stays quarantined.
/// INV-QPR-RECEIPT: success → provenance receipt emitted.
pub fn evaluate_promotion(
    request: &PromotionRequest,
    rule: &PromotionRule,
    validator_id: &str,
    trace_id: &str,
    timestamp: &str,
) -> Result<PromotionResult, PromotionError> {
    validate_rule(rule)?;
    validate_request(request, validator_id, trace_id, timestamp)?;

    let mut rejections = Vec::new();

    // Check authentication (INV-QPR-AUTHENTICATED)
    if !request.authenticated {
        rejections.push(RejectionReason::NotAuthenticated);
    }

    // Check schema version (INV-QPR-SCHEMA-GATED)
    if request.schema_version != rule.required_schema_version {
        rejections.push(RejectionReason::SchemaFailed {
            expected: rule.required_schema_version.clone(),
            got: request.schema_version.clone(),
        });
    }

    // Check reachability
    if rule.require_reachability && !request.reachable {
        rejections.push(RejectionReason::NotReachable);
    }

    // Check pin
    if rule.require_pin && !request.pinned {
        rejections.push(RejectionReason::NotPinned);
    }

    // INV-QPR-FAIL-CLOSED: any rejection → not promoted
    if !rejections.is_empty() {
        return Ok(PromotionResult {
            object_id: request.object_id.clone(),
            promoted: false,
            receipt: None,
            rejection_reasons: rejections,
        });
    }

    // All checks passed → emit provenance receipt (INV-QPR-RECEIPT)
    let receipt = ProvenanceReceipt {
        object_id: request.object_id.clone(),
        promoted_at: timestamp.to_string(),
        requester_id: request.requester_id.clone(),
        reason: request.reason.clone(),
        schema_version: request.schema_version.clone(),
        validator_id: validator_id.to_string(),
        trace_id: trace_id.to_string(),
    };

    Ok(PromotionResult {
        object_id: request.object_id.clone(),
        promoted: true,
        receipt: Some(receipt),
        rejection_reasons: Vec::new(),
    })
}

/// Batch evaluate promotions. Returns results in order.
pub fn evaluate_batch(
    requests: &[PromotionRequest],
    rule: &PromotionRule,
    validator_id: &str,
    trace_id: &str,
    timestamp: &str,
) -> Result<Vec<PromotionResult>, PromotionError> {
    validate_rule(rule)?;
    let mut results = Vec::with_capacity(requests.len());
    for req in requests {
        let result = evaluate_promotion(req, rule, validator_id, trace_id, timestamp)?;
        results.push(result);
    }
    Ok(results)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rule() -> PromotionRule {
        PromotionRule {
            required_schema_version: "1.0".into(),
            require_reachability: true,
            require_pin: false,
        }
    }

    fn req(id: &str, auth: bool, schema: &str, reachable: bool, pinned: bool) -> PromotionRequest {
        PromotionRequest {
            object_id: id.into(),
            requester_id: "admin".into(),
            authenticated: auth,
            schema_version: schema.into(),
            reachable,
            pinned,
            reason: "test promotion".into(),
        }
    }

    #[test]
    fn promote_valid_object() {
        let r = req("obj1", true, "1.0", true, false);
        let result = evaluate_promotion(&r, &rule(), "v1", "tr", "ts").unwrap();
        assert!(result.promoted);
        assert!(result.receipt.is_some());
        assert!(result.rejection_reasons.is_empty());
    }

    #[test]
    fn reject_unauthenticated() {
        let r = req("obj1", false, "1.0", true, false);
        let result = evaluate_promotion(&r, &rule(), "v1", "tr", "ts").unwrap();
        assert!(!result.promoted);
        assert!(
            result
                .rejection_reasons
                .contains(&RejectionReason::NotAuthenticated)
        );
    }

    #[test]
    fn reject_wrong_schema() {
        let r = req("obj1", true, "2.0", true, false);
        let result = evaluate_promotion(&r, &rule(), "v1", "tr", "ts").unwrap();
        assert!(!result.promoted);
        assert!(
            result
                .rejection_reasons
                .iter()
                .any(|r| matches!(r, RejectionReason::SchemaFailed { .. }))
        );
    }

    #[test]
    fn reject_unreachable() {
        let r = req("obj1", true, "1.0", false, false);
        let result = evaluate_promotion(&r, &rule(), "v1", "tr", "ts").unwrap();
        assert!(!result.promoted);
        assert!(
            result
                .rejection_reasons
                .contains(&RejectionReason::NotReachable)
        );
    }

    #[test]
    fn reject_not_pinned_when_required() {
        let mut rl = rule();
        rl.require_pin = true;
        let r = req("obj1", true, "1.0", true, false);
        let result = evaluate_promotion(&r, &rl, "v1", "tr", "ts").unwrap();
        assert!(!result.promoted);
        assert!(
            result
                .rejection_reasons
                .contains(&RejectionReason::NotPinned)
        );
    }

    #[test]
    fn pinned_passes_when_required() {
        let mut rl = rule();
        rl.require_pin = true;
        let r = req("obj1", true, "1.0", true, true);
        let result = evaluate_promotion(&r, &rl, "v1", "tr", "ts").unwrap();
        assert!(result.promoted);
    }

    #[test]
    fn multiple_rejections() {
        let r = req("obj1", false, "2.0", false, false);
        let result = evaluate_promotion(&r, &rule(), "v1", "tr", "ts").unwrap();
        assert!(!result.promoted);
        assert_eq!(result.rejection_reasons.len(), 3);
    }

    #[test]
    fn receipt_has_provenance() {
        let r = req("obj1", true, "1.0", true, false);
        let result =
            evaluate_promotion(&r, &rule(), "validator-1", "trace-x", "2026-01-01").unwrap();
        let receipt = result.receipt.unwrap();
        assert_eq!(receipt.object_id, "obj1");
        assert_eq!(receipt.requester_id, "admin");
        assert_eq!(receipt.validator_id, "validator-1");
        assert_eq!(receipt.trace_id, "trace-x");
        assert_eq!(receipt.promoted_at, "2026-01-01");
        assert_eq!(receipt.schema_version, "1.0");
    }

    #[test]
    fn no_receipt_on_rejection() {
        let r = req("obj1", false, "1.0", true, false);
        let result = evaluate_promotion(&r, &rule(), "v1", "tr", "ts").unwrap();
        assert!(result.receipt.is_none());
    }

    #[test]
    fn fail_closed_on_any_error() {
        // Even if only one check fails, promotion is denied
        let r = req("obj1", true, "1.0", false, false); // only reachability fails
        let result = evaluate_promotion(&r, &rule(), "v1", "tr", "ts").unwrap();
        assert!(!result.promoted);
    }

    #[test]
    fn batch_evaluation() {
        let requests = vec![
            req("obj1", true, "1.0", true, false),  // should pass
            req("obj2", false, "1.0", true, false), // fail auth
            req("obj3", true, "1.0", true, false),  // should pass
        ];
        let results = evaluate_batch(&requests, &rule(), "v1", "tr", "ts").unwrap();
        assert_eq!(results.len(), 3);
        assert!(results[0].promoted);
        assert!(!results[1].promoted);
        assert!(results[2].promoted);
    }

    #[test]
    fn deterministic_evaluation() {
        let r = req("obj1", true, "1.0", true, false);
        let r1 = evaluate_promotion(&r, &rule(), "v1", "tr", "ts").unwrap();
        let r2 = evaluate_promotion(&r, &rule(), "v1", "tr", "ts").unwrap();
        assert_eq!(r1.promoted, r2.promoted);
        assert_eq!(r1.rejection_reasons, r2.rejection_reasons);
    }

    #[test]
    fn invalid_rule_empty_schema() {
        let rl = PromotionRule {
            required_schema_version: "".into(),
            require_reachability: true,
            require_pin: false,
        };
        let r = req("obj1", true, "1.0", true, false);
        let err = evaluate_promotion(&r, &rl, "v1", "tr", "ts").unwrap_err();
        assert_eq!(err.code(), "QPR_INVALID_RULE");
    }

    #[test]
    fn schema_rejection_preserves_expected_and_got_versions() {
        let mut rl = rule();
        rl.required_schema_version = "schema-2026".into();
        let r = req("obj-schema", true, "schema-2025", true, false);
        let result = evaluate_promotion(&r, &rl, "v1", "tr", "ts").unwrap();

        assert!(!result.promoted);
        assert_eq!(
            result.rejection_reasons,
            vec![RejectionReason::SchemaFailed {
                expected: "schema-2026".into(),
                got: "schema-2025".into(),
            }]
        );
        assert!(result.receipt.is_none());
    }

    #[test]
    fn rejected_result_preserves_object_id_for_audit() {
        let r = req("quarantined-object-7", false, "1.0", true, false);
        let result = evaluate_promotion(&r, &rule(), "v1", "tr", "ts").unwrap();

        assert!(!result.promoted);
        assert_eq!(result.object_id, "quarantined-object-7");
        assert!(result.receipt.is_none());
    }

    #[test]
    fn all_required_gates_can_fail_together() {
        let mut rl = rule();
        rl.require_pin = true;
        let r = req("obj-all-fail", false, "0.9", false, false);
        let result = evaluate_promotion(&r, &rl, "v1", "tr", "ts").unwrap();

        assert!(!result.promoted);
        assert_eq!(result.rejection_reasons.len(), 4);
        assert!(
            result
                .rejection_reasons
                .contains(&RejectionReason::NotAuthenticated)
        );
        assert!(
            result
                .rejection_reasons
                .contains(&RejectionReason::NotReachable)
        );
        assert!(
            result
                .rejection_reasons
                .contains(&RejectionReason::NotPinned)
        );
        assert!(
            result
                .rejection_reasons
                .iter()
                .any(|reason| matches!(reason, RejectionReason::SchemaFailed { .. }))
        );
        assert!(result.receipt.is_none());
    }

    #[test]
    fn invalid_rule_short_circuits_before_request_rejections() {
        let rl = PromotionRule {
            required_schema_version: "".into(),
            require_reachability: true,
            require_pin: true,
        };
        let r = req("obj-short-circuit", false, "bad-schema", false, false);
        let err = evaluate_promotion(&r, &rl, "v1", "tr", "ts").unwrap_err();

        assert_eq!(
            err,
            PromotionError::InvalidRule {
                reason: "required_schema_version must not be empty".into(),
            }
        );
    }

    #[test]
    fn batch_rejects_invalid_rule_for_empty_input() {
        let rl = PromotionRule {
            required_schema_version: "".into(),
            require_reachability: true,
            require_pin: false,
        };
        let err = evaluate_batch(&[], &rl, "v1", "tr", "ts").unwrap_err();

        assert_eq!(err.code(), "QPR_INVALID_RULE");
    }

    #[test]
    fn batch_preserves_rejected_items_without_receipts() {
        let requests = vec![
            req("obj-auth", false, "1.0", true, false),
            req("obj-reach", true, "1.0", false, false),
        ];
        let results = evaluate_batch(&requests, &rule(), "v1", "tr", "ts").unwrap();

        assert_eq!(results.len(), 2);
        assert!(!results[0].promoted);
        assert!(!results[1].promoted);
        assert!(results[0].receipt.is_none());
        assert!(results[1].receipt.is_none());
        assert_eq!(
            results[0].rejection_reasons,
            vec![RejectionReason::NotAuthenticated]
        );
        assert_eq!(
            results[1].rejection_reasons,
            vec![RejectionReason::NotReachable]
        );
    }

    #[test]
    fn batch_keeps_rejection_order_for_mixed_failures() {
        let requests = vec![
            req("obj-schema", true, "2.0", true, false),
            req("obj-auth", false, "1.0", true, false),
            req("obj-reach", true, "1.0", false, false),
        ];
        let results = evaluate_batch(&requests, &rule(), "v1", "tr", "ts").unwrap();

        assert_eq!(
            results
                .iter()
                .map(|result| result.object_id.as_str())
                .collect::<Vec<_>>(),
            vec!["obj-schema", "obj-auth", "obj-reach"]
        );
        assert!(
            results[0]
                .rejection_reasons
                .iter()
                .any(|reason| matches!(reason, RejectionReason::SchemaFailed { .. }))
        );
        assert_eq!(
            results[1].rejection_reasons,
            vec![RejectionReason::NotAuthenticated]
        );
        assert_eq!(
            results[2].rejection_reasons,
            vec![RejectionReason::NotReachable]
        );
    }

    #[test]
    fn pin_rejection_is_not_reported_when_pin_gate_disabled() {
        let r = req("obj-pin-disabled", true, "1.0", true, false);
        let result = evaluate_promotion(&r, &rule(), "v1", "tr", "ts").unwrap();

        assert!(result.promoted);
        assert!(
            !result
                .rejection_reasons
                .contains(&RejectionReason::NotPinned)
        );
    }

    #[test]
    fn error_codes_all_present() {
        assert_eq!(
            PromotionError::SchemaFailed {
                object_id: "".into(),
                expected: "".into(),
                got: "".into()
            }
            .code(),
            "QPR_SCHEMA_FAILED"
        );
        assert_eq!(
            PromotionError::NotAuthenticated {
                object_id: "".into(),
                requester_id: "".into()
            }
            .code(),
            "QPR_NOT_AUTHENTICATED"
        );
        assert_eq!(
            PromotionError::NotReachable {
                object_id: "".into()
            }
            .code(),
            "QPR_NOT_REACHABLE"
        );
        assert_eq!(
            PromotionError::NotPinned {
                object_id: "".into()
            }
            .code(),
            "QPR_NOT_PINNED"
        );
        assert_eq!(
            PromotionError::InvalidRequest { reason: "".into() }.code(),
            "QPR_INVALID_REQUEST"
        );
        assert_eq!(
            PromotionError::InvalidRule { reason: "".into() }.code(),
            "QPR_INVALID_RULE"
        );
    }

    #[test]
    fn error_display() {
        let e = PromotionError::SchemaFailed {
            object_id: "obj1".into(),
            expected: "1.0".into(),
            got: "2.0".into(),
        };
        assert!(e.to_string().contains("QPR_SCHEMA_FAILED"));
    }

    #[test]
    fn default_rule_valid() {
        assert!(validate_rule(&PromotionRule::default_rule()).is_ok());
    }
}

#[cfg(test)]
mod quarantine_promotion_additional_negative_tests {
    use super::*;

    fn rule() -> PromotionRule {
        PromotionRule::default_rule()
    }

    fn request(object_id: &str) -> PromotionRequest {
        PromotionRequest {
            object_id: object_id.to_string(),
            requester_id: "operator-a".to_string(),
            authenticated: true,
            schema_version: "1.0".to_string(),
            reachable: true,
            pinned: false,
            reason: "validated quarantine release".to_string(),
        }
    }

    fn expect_invalid_request(err: PromotionError, field: &str) {
        assert!(matches!(
            err,
            PromotionError::InvalidRequest { ref reason } if reason.contains(field)
        ));
    }

    #[test]
    fn whitespace_schema_rule_is_invalid() {
        let invalid = PromotionRule {
            required_schema_version: " \t\n ".to_string(),
            require_reachability: true,
            require_pin: false,
        };
        let err = validate_rule(&invalid).expect_err("blank schema must fail closed");

        assert_eq!(err.code(), "QPR_INVALID_RULE");
    }

    #[test]
    fn blank_object_id_is_invalid_request() {
        let err = evaluate_promotion(&request(" "), &rule(), "validator-a", "trace-a", "ts-a")
            .expect_err("blank object ID must fail closed");

        expect_invalid_request(err, "object_id");
    }

    #[test]
    fn blank_requester_id_is_invalid_request() {
        let mut req = request("object-a");
        req.requester_id = "\t ".to_string();

        let err = evaluate_promotion(&req, &rule(), "validator-a", "trace-a", "ts-a")
            .expect_err("blank requester ID must fail closed");

        expect_invalid_request(err, "requester_id");
    }

    #[test]
    fn blank_reason_is_invalid_request() {
        let mut req = request("object-a");
        req.reason.clear();

        let err = evaluate_promotion(&req, &rule(), "validator-a", "trace-a", "ts-a")
            .expect_err("blank promotion reason must fail closed");

        expect_invalid_request(err, "reason");
    }

    #[test]
    fn blank_validator_id_is_invalid_request() {
        let err = evaluate_promotion(&request("object-a"), &rule(), " ", "trace-a", "ts-a")
            .expect_err("blank validator ID must fail closed");

        expect_invalid_request(err, "validator_id");
    }

    #[test]
    fn blank_trace_id_is_invalid_request() {
        let err = evaluate_promotion(&request("object-a"), &rule(), "validator-a", "\n", "ts-a")
            .expect_err("blank trace ID must fail closed");

        expect_invalid_request(err, "trace_id");
    }

    #[test]
    fn blank_timestamp_is_invalid_request() {
        let err = evaluate_promotion(&request("object-a"), &rule(), "validator-a", "trace-a", "")
            .expect_err("blank timestamp must fail closed");

        expect_invalid_request(err, "timestamp");
    }

    #[test]
    fn batch_aborts_on_invalid_request_without_receipt() {
        let requests = vec![request("valid-a"), request(" ")];

        let err = evaluate_batch(&requests, &rule(), "validator-a", "trace-a", "ts-a")
            .expect_err("batch should fail closed on invalid request metadata");

        expect_invalid_request(err, "object_id");
    }
}

#[cfg(test)]
mod quarantine_promotion_comprehensive_negative_tests {
    use super::*;

    fn default_rule() -> PromotionRule {
        PromotionRule::default_rule()
    }

    fn malicious_request(object_id: &str) -> PromotionRequest {
        PromotionRequest {
            object_id: object_id.to_string(),
            requester_id: "admin".to_string(),
            authenticated: true,
            schema_version: "1.0".to_string(),
            reachable: true,
            pinned: false,
            reason: "test promotion".to_string(),
        }
    }

    #[test]
    fn negative_promotion_request_with_unicode_injection_attacks() {
        // Test with malicious Unicode patterns in all string fields
        let mut req = malicious_request("obj\u{202E}spoofed\u{202D}");
        req.requester_id = "admin\u{0000}injected\r\n\t\x1b[31mred\x1b[0m".to_string();
        req.schema_version = "1.\u{FEFF}0\u{200B}".to_string(); // Zero-width chars
        req.reason = "test\u{10FFFF}\u{E000}\u{FDD0}promotion".to_string(); // Private use + non-chars

        let result = evaluate_promotion(&req, &default_rule(), "validator\u{202A}bidi", "trace\u{2066}isolate", "2026\u{200C}04\u{200D}17");

        // Should either reject due to schema mismatch or succeed with malicious content preserved
        assert!(result.is_ok());
        let promotion_result = result.unwrap();
        if promotion_result.promoted {
            // Verify malicious Unicode is preserved in receipt
            let receipt = promotion_result.receipt.unwrap();
            assert!(receipt.object_id.contains("\u{202E}"));
            assert!(receipt.requester_id.contains("\u{0000}"));
        }
    }

    #[test]
    fn negative_promotion_rule_with_extreme_schema_version_length() {
        // Test with maliciously long schema version
        let extreme_rule = PromotionRule {
            required_schema_version: "schema.".repeat(100000) + "v1", // ~700KB string
            require_reachability: true,
            require_pin: false,
        };

        let req = malicious_request("obj-extreme-schema");
        let result = evaluate_promotion(&req, &extreme_rule, "validator", "trace", "ts");

        // Should handle large schema version without panic
        assert!(result.is_ok());
        let promotion_result = result.unwrap();
        assert!(!promotion_result.promoted); // Should fail schema match
        assert!(promotion_result.rejection_reasons.iter().any(|r| matches!(r, RejectionReason::SchemaFailed { .. })));
    }

    #[test]
    fn negative_batch_evaluation_with_malformed_json_escape_sequences() {
        // Test with object IDs containing JSON escape sequences that might break serialization
        let malicious_objects = [
            "obj\"\\\r\n\t\x08\x0c",  // JSON control chars
            "obj\\u0000\\x00\\n\\r\\t", // Escaped null and control
            "obj\u{D800}\u{DFFF}",      // Surrogate pairs
            "obj\\\"quotes\\\"",         // Escaped quotes
            "obj\\\\backslashes\\\\",    // Escaped backslashes
        ];

        let requests: Vec<_> = malicious_objects.iter().map(|&id| malicious_request(id)).collect();
        let results = evaluate_batch(&requests, &default_rule(), "validator", "trace", "ts");

        assert!(results.is_ok());
        let batch_results = results.unwrap();
        assert_eq!(batch_results.len(), malicious_objects.len());

        // All should succeed with malicious content preserved
        for (i, result) in batch_results.iter().enumerate() {
            assert!(result.promoted);
            assert_eq!(result.object_id, malicious_objects[i]);
        }
    }

    #[test]
    fn negative_schema_version_collision_attack() {
        // Test schema versions designed to cause collisions or bypasses
        let collision_patterns = [
            "1.0\u{0000}malicious", // Null byte injection
            "1.0\r\n2.0",           // CRLF injection
            "1.0 \t\n 1.0",         // Whitespace confusion
            "\u{FEFF}1.0",          // BOM prefix
            "1.0\u{200B}\u{200C}\u{200D}", // Zero-width chars
        ];

        let mut rule = default_rule();
        for pattern in collision_patterns {
            rule.required_schema_version = pattern.to_string();
            let req = malicious_request("collision-test");

            let result = evaluate_promotion(&req, &rule, "validator", "trace", "ts");
            assert!(result.is_ok());

            let promotion_result = result.unwrap();
            assert!(!promotion_result.promoted); // Should fail due to schema mismatch with "1.0"
        }
    }

    #[test]
    fn negative_massive_batch_memory_exhaustion_attack() {
        // Test with extremely large batch to check memory handling
        let massive_requests: Vec<_> = (0..10000).map(|i| {
            let mut req = malicious_request(&format!("obj-massive-{}", i));
            req.reason = "x".repeat(10000); // 10KB reason per request = 100MB total
            req
        }).collect();

        let result = evaluate_batch(&massive_requests, &default_rule(), "validator", "trace", "ts");

        // Should handle large batches without panic
        assert!(result.is_ok());
        let batch_results = result.unwrap();
        assert_eq!(batch_results.len(), 10000);

        // Verify all succeeded and have massive reasons preserved
        for (i, result) in batch_results.iter().enumerate() {
            assert!(result.promoted);
            assert_eq!(result.object_id, format!("obj-massive-{}", i));
            assert_eq!(result.receipt.as_ref().unwrap().reason.len(), 10000);
        }
    }

    #[test]
    fn negative_promotion_error_display_with_injection_resistant_formatting() {
        // Test error display with malicious content that might break formatting
        let malicious_patterns = [
            ("obj\r\n\t\x1b[31mREDTEXT\x1b[0m", "admin\x00injected"),
            ("obj\"quotes'apostrophe", "admin\\escaped"),
            ("obj\u{202E}spoofed", "admin\u{FEFF}bom"),
        ];

        for (object_id, requester_id) in malicious_patterns {
            let error = PromotionError::NotAuthenticated {
                object_id: object_id.to_string(),
                requester_id: requester_id.to_string(),
            };

            let display_string = format!("{}", error);

            // Verify error display is safe and contains expected prefix
            assert!(display_string.contains("QPR_NOT_AUTHENTICATED"));
            assert!(display_string.contains(object_id));
            assert!(display_string.contains(requester_id));
        }
    }

    #[test]
    fn negative_concurrent_rule_validation_race_conditions() {
        // Test potential race conditions by rapidly switching rule validity
        let valid_rule = default_rule();
        let invalid_rule = PromotionRule {
            required_schema_version: "".to_string(),
            require_reachability: true,
            require_pin: false,
        };

        // Simulate concurrent validation attempts
        for i in 0..1000 {
            let rule = if i % 2 == 0 { &valid_rule } else { &invalid_rule };
            let req = malicious_request(&format!("concurrent-obj-{}", i));

            let result = evaluate_promotion(&req, rule, "validator", &format!("trace-{}", i), "ts");

            if i % 2 == 0 {
                assert!(result.is_ok());
                assert!(result.unwrap().promoted);
            } else {
                assert!(result.is_err());
                assert_eq!(result.unwrap_err().code(), "QPR_INVALID_RULE");
            }
        }
    }

    #[test]
    fn negative_provenance_receipt_with_adversarial_timestamp_formats() {
        // Test with various timestamp injection patterns
        let adversarial_timestamps = [
            "2026-04-17T00:00:00Z\r\nInjected: malicious",
            "2026-04-17\x00null\x00injection",
            "\u{202E}6202-71-40\u{202D}T00:00:00Z", // BiDi spoofed
            "2026-04-17T00:00:00Z\u{FEFF}\u{200B}", // Invisible chars
            "' OR '1'='1' --", // SQL injection pattern
        ];

        for timestamp in adversarial_timestamps {
            let req = malicious_request("timestamp-attack");
            let result = evaluate_promotion(&req, &default_rule(), "validator", "trace", timestamp);

            assert!(result.is_ok());
            let promotion_result = result.unwrap();
            assert!(promotion_result.promoted);

            // Verify timestamp is preserved exactly in receipt
            let receipt = promotion_result.receipt.unwrap();
            assert_eq!(receipt.promoted_at, timestamp);
        }
    }

    #[test]
    fn negative_rejection_reason_exhaustive_combination_testing() {
        // Test all possible combinations of rejection reasons
        let test_cases = [
            (false, "wrong", false, false, 4), // All failures
            (false, "1.0", false, false, 3),   // Auth, reach, pin (if required)
            (true, "wrong", false, false, 3),  // Schema, reach, pin (if required)
            (false, "wrong", true, false, 3),  // Auth, schema, pin (if required)
            (false, "wrong", false, true, 3),  // Auth, schema, reach
        ];

        let mut rule = default_rule();
        rule.require_pin = true; // Enable pin requirement for comprehensive testing

        for (i, (auth, schema, reachable, pinned, expected_rejections)) in test_cases.iter().enumerate() {
            let mut req = malicious_request(&format!("combo-test-{}", i));
            req.authenticated = *auth;
            req.schema_version = schema.to_string();
            req.reachable = *reachable;
            req.pinned = *pinned;

            let result = evaluate_promotion(&req, &rule, "validator", "trace", "ts");
            assert!(result.is_ok());

            let promotion_result = result.unwrap();
            assert!(!promotion_result.promoted);
            assert_eq!(promotion_result.rejection_reasons.len(), *expected_rejections);
            assert!(promotion_result.receipt.is_none());
        }
    }

    #[test]
    fn negative_promotion_rule_validation_with_unicode_normalization_attacks() {
        // Test with Unicode normalization attacks in schema versions
        let normalization_attacks = [
            ("café", "cafe\u{0301}"),      // NFC vs NFD
            ("résumé", "re\u{0301}sume\u{0301}"), // Multiple combining chars
            ("℁", "a/s"),                   // Compatibility equivalence
            ("＜script＞", "<script>"),      // Fullwidth to ASCII
        ];

        for (nfc_version, attack_version) in normalization_attacks {
            let rule = PromotionRule {
                required_schema_version: nfc_version.to_string(),
                require_reachability: true,
                require_pin: false,
            };

            let mut req = malicious_request("normalization-attack");
            req.schema_version = attack_version.to_string();

            let result = evaluate_promotion(&req, &rule, "validator", "trace", "ts");
            assert!(result.is_ok());

            let promotion_result = result.unwrap();
            // Should fail due to byte-level inequality despite visual similarity
            assert!(!promotion_result.promoted);
            assert!(promotion_result.rejection_reasons.iter().any(|r| matches!(r, RejectionReason::SchemaFailed { .. })));
        }
    }

    #[test]
    fn negative_batch_evaluation_with_heterogeneous_malicious_requests() {
        // Test batch with diverse malicious request patterns
        let heterogeneous_requests = vec![
            {
                let mut req = malicious_request("obj-control\x00\r\n\t");
                req.requester_id = "\x1b[31mred\x1b[0m".to_string();
                req
            },
            {
                let mut req = malicious_request("obj-unicode\u{10FFFF}\u{E000}");
                req.reason = "reason\u{202E}spoofed\u{202D}".to_string();
                req
            },
            {
                let mut req = malicious_request("obj-massive");
                req.reason = "x".repeat(1000000); // 1MB reason
                req
            },
            {
                let mut req = malicious_request("obj-json\"\\escape");
                req.requester_id = "admin\\\"escaped".to_string();
                req
            },
            {
                let mut req = malicious_request("obj-bidi\u{202A}\u{202B}\u{202C}");
                req.schema_version = "\u{FEFF}1.0\u{200B}".to_string();
                req
            },
        ];

        let result = evaluate_batch(&heterogeneous_requests, &default_rule(), "validator", "trace", "ts");
        assert!(result.is_ok());

        let batch_results = result.unwrap();
        assert_eq!(batch_results.len(), 5);

        // Most should succeed with malicious content preserved, except schema mismatch
        for (i, result) in batch_results.iter().enumerate() {
            if i == 4 {
                // Schema version with zero-width chars should fail
                assert!(!result.promoted);
            } else {
                assert!(result.promoted);
                assert!(result.receipt.is_some());
            }
        }
    }

    #[test]
    fn negative_edge_case_empty_collections_and_boundary_values() {
        // Test edge cases with empty collections and boundary values
        let empty_batch_result = evaluate_batch(&[], &default_rule(), "validator", "trace", "ts");
        assert!(empty_batch_result.is_ok());
        assert!(empty_batch_result.unwrap().is_empty());

        // Test with single character fields
        let mut minimal_req = malicious_request("x");
        minimal_req.requester_id = "y".to_string();
        minimal_req.reason = "z".to_string();

        let result = evaluate_promotion(&minimal_req, &default_rule(), "v", "t", "s");
        assert!(result.is_ok());
        assert!(result.unwrap().promoted);

        // Test with maximum length Unicode characters
        let max_unicode_req = malicious_request("\u{10FFFF}");
        let result = evaluate_promotion(&max_unicode_req, &default_rule(), "validator", "trace", "ts");
        assert!(result.is_ok());
        assert!(result.unwrap().promoted);
    }
}
