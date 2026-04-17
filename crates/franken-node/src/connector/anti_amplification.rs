//! bd-3b8m: Anti-amplification response bounds for retrieval/sync traffic.
//!
//! Response payloads never exceed request-declared bounds under adversarial inputs.
//! Unauthenticated limits are stricter and enforced. Harness reproduces attacks deterministically.

/// Global anti-amplification policy.
#[derive(Debug, Clone)]
pub struct AmplificationPolicy {
    /// Maximum ratio of response_bytes / request_bytes.
    pub max_response_ratio: f64,
    /// Hard cap for unauthenticated peers (bytes).
    pub unauth_max_bytes: u64,
    /// Hard cap for authenticated peers (bytes).
    pub auth_max_bytes: u64,
    /// Maximum items per response.
    pub max_items_per_response: u32,
}

impl AmplificationPolicy {
    pub fn default_policy() -> Self {
        Self {
            max_response_ratio: 10.0,
            unauth_max_bytes: 1_000,
            auth_max_bytes: 100_000,
            max_items_per_response: 100,
        }
    }
}

/// Per-request declared bound from the requester.
#[derive(Debug, Clone)]
pub struct ResponseBound {
    pub max_bytes: u64,
    pub max_items: u32,
}

/// Request to check against anti-amplification bounds.
#[derive(Debug, Clone)]
pub struct BoundCheckRequest {
    pub request_id: String,
    pub peer_id: String,
    pub authenticated: bool,
    pub request_bytes: u64,
    pub declared_bound: ResponseBound,
    pub actual_response_bytes: u64,
    pub actual_items: u32,
}

/// Which bound was violated.
#[derive(Debug, Clone, PartialEq)]
pub enum BoundViolation {
    ResponseTooLarge { actual: u64, limit: u64 },
    RatioExceeded { ratio: f64, max_ratio: f64 },
    UnauthLimit { actual: u64, limit: u64 },
    ItemsExceeded { actual: u32, limit: u32 },
}

/// Result of a bound check.
#[derive(Debug, Clone)]
pub struct BoundCheckVerdict {
    pub request_id: String,
    pub allowed: bool,
    pub violations: Vec<BoundViolation>,
    pub enforced_limit: u64,
    pub trace_id: String,
}

/// Audit record for a bound check.
#[derive(Debug, Clone)]
pub struct AmplificationAuditEntry {
    pub request_id: String,
    pub peer_id: String,
    pub timestamp: String,
    pub authenticated: bool,
    pub declared_bound_bytes: u64,
    pub actual_bytes: u64,
    pub enforced_limit: u64,
    pub ratio: f64,
    pub verdict: String,
}

/// Errors from anti-amplification operations.
#[derive(Debug, Clone, PartialEq)]
pub enum AmplificationError {
    ResponseTooLarge {
        request_id: String,
        actual: u64,
        limit: u64,
    },
    RatioExceeded {
        request_id: String,
        ratio: f64,
        max_ratio: f64,
    },
    UnauthLimit {
        request_id: String,
        actual: u64,
        limit: u64,
    },
    ItemsExceeded {
        request_id: String,
        actual: u32,
        limit: u32,
    },
    InvalidPolicy {
        reason: String,
    },
}

impl AmplificationError {
    pub fn code(&self) -> &'static str {
        match self {
            Self::ResponseTooLarge { .. } => "AAR_RESPONSE_TOO_LARGE",
            Self::RatioExceeded { .. } => "AAR_RATIO_EXCEEDED",
            Self::UnauthLimit { .. } => "AAR_UNAUTH_LIMIT",
            Self::ItemsExceeded { .. } => "AAR_ITEMS_EXCEEDED",
            Self::InvalidPolicy { .. } => "AAR_INVALID_POLICY",
        }
    }
}

impl std::fmt::Display for AmplificationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ResponseTooLarge {
                request_id,
                actual,
                limit,
            } => write!(
                f,
                "AAR_RESPONSE_TOO_LARGE: req={request_id} actual={actual} limit={limit}"
            ),
            Self::RatioExceeded {
                request_id,
                ratio,
                max_ratio,
            } => write!(
                f,
                "AAR_RATIO_EXCEEDED: req={request_id} ratio={ratio:.2} max={max_ratio:.2}"
            ),
            Self::UnauthLimit {
                request_id,
                actual,
                limit,
            } => write!(
                f,
                "AAR_UNAUTH_LIMIT: req={request_id} actual={actual} limit={limit}"
            ),
            Self::ItemsExceeded {
                request_id,
                actual,
                limit,
            } => write!(
                f,
                "AAR_ITEMS_EXCEEDED: req={request_id} actual={actual} limit={limit}"
            ),
            Self::InvalidPolicy { reason } => write!(f, "AAR_INVALID_POLICY: {reason}"),
        }
    }
}

/// Validate an amplification policy.
pub fn validate_policy(policy: &AmplificationPolicy) -> Result<(), AmplificationError> {
    if !policy.max_response_ratio.is_finite() || policy.max_response_ratio <= 0.0 {
        return Err(AmplificationError::InvalidPolicy {
            reason: "max_response_ratio must be > 0".into(),
        });
    }
    if policy.unauth_max_bytes == 0 {
        return Err(AmplificationError::InvalidPolicy {
            reason: "unauth_max_bytes must be > 0".into(),
        });
    }
    if policy.auth_max_bytes == 0 {
        return Err(AmplificationError::InvalidPolicy {
            reason: "auth_max_bytes must be > 0".into(),
        });
    }
    if policy.unauth_max_bytes > policy.auth_max_bytes {
        return Err(AmplificationError::InvalidPolicy {
            reason: "unauth_max_bytes must be <= auth_max_bytes".into(),
        });
    }
    if policy.max_items_per_response == 0 {
        return Err(AmplificationError::InvalidPolicy {
            reason: "max_items_per_response must be > 0".into(),
        });
    }
    Ok(())
}

/// Compute the enforced byte limit for a request given policy and auth status.
///
/// INV-AAR-UNAUTH-STRICT: unauth limit <= auth limit.
pub fn enforced_limit(
    policy: &AmplificationPolicy,
    declared: &ResponseBound,
    authenticated: bool,
) -> u64 {
    let auth_cap = if authenticated {
        policy.auth_max_bytes
    } else {
        policy.unauth_max_bytes
    };
    // Enforced limit is the minimum of declared bound and auth-appropriate cap
    declared.max_bytes.min(auth_cap)
}

/// Check a response against anti-amplification bounds.
///
/// INV-AAR-BOUNDED: response size <= enforced limit.
/// INV-AAR-AUDITABLE: produces audit entry.
/// INV-AAR-DETERMINISTIC: same inputs → same output.
pub fn check_response_bound(
    request: &BoundCheckRequest,
    policy: &AmplificationPolicy,
    trace_id: &str,
    timestamp: &str,
) -> Result<(BoundCheckVerdict, AmplificationAuditEntry), AmplificationError> {
    validate_policy(policy)?;

    let limit = enforced_limit(policy, &request.declared_bound, request.authenticated);
    let mut violations = Vec::new();

    // Check 1: response size vs enforced limit
    if request.actual_response_bytes > limit {
        violations.push(BoundViolation::ResponseTooLarge {
            actual: request.actual_response_bytes,
            limit,
        });
    }

    // Check 2: amplification ratio
    let ratio = if request.request_bytes > 0 {
        request.actual_response_bytes as f64 / request.request_bytes as f64
    } else if request.actual_response_bytes > 0 {
        f64::INFINITY
    } else {
        0.0
    };
    if ratio > policy.max_response_ratio {
        violations.push(BoundViolation::RatioExceeded {
            ratio,
            max_ratio: policy.max_response_ratio,
        });
    }

    // Check 3: unauthenticated strict limit
    if !request.authenticated && request.actual_response_bytes > policy.unauth_max_bytes {
        violations.push(BoundViolation::UnauthLimit {
            actual: request.actual_response_bytes,
            limit: policy.unauth_max_bytes,
        });
    }

    // Check 4: items per response
    let items_limit = request
        .declared_bound
        .max_items
        .min(policy.max_items_per_response);
    if request.actual_items > items_limit {
        violations.push(BoundViolation::ItemsExceeded {
            actual: request.actual_items,
            limit: items_limit,
        });
    }

    let allowed = violations.is_empty();

    let verdict = BoundCheckVerdict {
        request_id: request.request_id.clone(),
        allowed,
        violations,
        enforced_limit: limit,
        trace_id: trace_id.to_string(),
    };

    let audit = AmplificationAuditEntry {
        request_id: request.request_id.clone(),
        peer_id: request.peer_id.clone(),
        timestamp: timestamp.to_string(),
        authenticated: request.authenticated,
        declared_bound_bytes: request.declared_bound.max_bytes,
        actual_bytes: request.actual_response_bytes,
        enforced_limit: limit,
        ratio,
        verdict: if allowed {
            "ALLOW".to_string()
        } else {
            "BLOCK".to_string()
        },
    };

    Ok((verdict, audit))
}

/// Run adversarial traffic harness: a batch of requests, returns all verdicts.
///
/// Deterministic: processes in order, no random choices.
pub fn run_adversarial_harness(
    requests: &[BoundCheckRequest],
    policy: &AmplificationPolicy,
    trace_id: &str,
    timestamp: &str,
) -> Result<Vec<(BoundCheckVerdict, AmplificationAuditEntry)>, AmplificationError> {
    validate_policy(policy)?;
    let mut results = Vec::with_capacity(requests.len());
    for req in requests {
        let (verdict, audit) = check_response_bound(req, policy, trace_id, timestamp)?;
        results.push((verdict, audit));
    }
    Ok(results)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy() -> AmplificationPolicy {
        AmplificationPolicy {
            max_response_ratio: 10.0,
            unauth_max_bytes: 1_000,
            auth_max_bytes: 10_000,
            max_items_per_response: 50,
        }
    }

    fn bound(bytes: u64, items: u32) -> ResponseBound {
        ResponseBound {
            max_bytes: bytes,
            max_items: items,
        }
    }

    fn req(
        id: &str,
        peer: &str,
        auth: bool,
        req_bytes: u64,
        declared_bytes: u64,
        actual_bytes: u64,
        items: u32,
    ) -> BoundCheckRequest {
        BoundCheckRequest {
            request_id: id.into(),
            peer_id: peer.into(),
            authenticated: auth,
            request_bytes: req_bytes,
            declared_bound: bound(declared_bytes, 50),
            actual_response_bytes: actual_bytes,
            actual_items: items,
        }
    }

    #[test]
    fn allow_within_bounds() {
        let r = req("r1", "p1", true, 100, 5000, 500, 10);
        let (v, a) = check_response_bound(&r, &policy(), "tr", "ts").expect("should succeed");
        assert!(v.allowed);
        assert!(v.violations.is_empty());
        assert_eq!(a.verdict, "ALLOW");
    }

    #[test]
    fn block_response_too_large() {
        let r = req("r1", "p1", true, 100, 5000, 6000, 10);
        let (v, _) = check_response_bound(&r, &policy(), "tr", "ts").expect("should succeed");
        assert!(!v.allowed);
        assert!(
            v.violations
                .iter()
                .any(|v| matches!(v, BoundViolation::ResponseTooLarge { .. }))
        );
    }

    #[test]
    fn block_ratio_exceeded() {
        let r = req("r1", "p1", true, 10, 10000, 200, 10);
        let (v, _) = check_response_bound(&r, &policy(), "tr", "ts").expect("should succeed");
        assert!(!v.allowed);
        assert!(
            v.violations
                .iter()
                .any(|v| matches!(v, BoundViolation::RatioExceeded { .. }))
        );
    }

    #[test]
    fn block_unauth_strict_limit() {
        let r = req("r1", "p1", false, 100, 5000, 1500, 10);
        let (v, _) = check_response_bound(&r, &policy(), "tr", "ts").expect("should succeed");
        assert!(!v.allowed);
        assert!(
            v.violations
                .iter()
                .any(|v| matches!(v, BoundViolation::UnauthLimit { .. }))
        );
    }

    #[test]
    fn unauth_stricter_than_auth() {
        let p = policy();
        let unauth_limit = enforced_limit(&p, &bound(50000, 50), false);
        let auth_limit = enforced_limit(&p, &bound(50000, 50), true);
        assert!(unauth_limit < auth_limit);
    }

    #[test]
    fn block_items_exceeded() {
        let mut r = req("r1", "p1", true, 100, 5000, 500, 60);
        r.declared_bound.max_items = 50;
        let (v, _) = check_response_bound(&r, &policy(), "tr", "ts").expect("should succeed");
        assert!(!v.allowed);
        assert!(
            v.violations
                .iter()
                .any(|v| matches!(v, BoundViolation::ItemsExceeded { .. }))
        );
    }

    #[test]
    fn enforced_limit_uses_minimum() {
        let p = policy();
        // Declared < auth cap → declared wins
        assert_eq!(enforced_limit(&p, &bound(5000, 50), true), 5000);
        // Declared > auth cap → auth cap wins
        assert_eq!(enforced_limit(&p, &bound(50000, 50), true), 10000);
        // Unauth cap always stricter
        assert_eq!(enforced_limit(&p, &bound(50000, 50), false), 1000);
    }

    #[test]
    fn zero_request_bytes_infinity_ratio() {
        // Zero request bytes with nonzero response → infinite ratio → blocked
        let r = req("r1", "p1", true, 0, 5000, 500, 10);
        let (v, _) = check_response_bound(&r, &policy(), "tr", "ts").expect("should succeed");
        assert!(!v.allowed);
    }

    #[test]
    fn zero_request_zero_response_ok() {
        let r = req("r1", "p1", true, 0, 5000, 0, 0);
        let (v, _) = check_response_bound(&r, &policy(), "tr", "ts").expect("should succeed");
        assert!(v.allowed);
    }

    #[test]
    fn multiple_violations() {
        // Unauth, oversized, high ratio, too many items
        let mut r = req("r1", "p1", false, 10, 50000, 5000, 100);
        r.declared_bound.max_items = 50;
        let (v, _) = check_response_bound(&r, &policy(), "tr", "ts").expect("should succeed");
        assert!(!v.allowed);
        assert_eq!(v.violations.len(), 4); // response too large, ratio, unauth, items
    }

    #[test]
    fn deterministic_check() {
        let r = req("r1", "p1", true, 100, 5000, 500, 10);
        let (v1, a1) = check_response_bound(&r, &policy(), "tr", "ts").expect("should succeed");
        let (v2, a2) = check_response_bound(&r, &policy(), "tr", "ts").expect("should succeed");
        assert_eq!(v1.allowed, v2.allowed);
        assert_eq!(v1.violations.len(), v2.violations.len());
        assert_eq!(a1.verdict, a2.verdict);
        assert_eq!(a1.enforced_limit, a2.enforced_limit);
    }

    #[test]
    fn audit_entry_complete() {
        let r = req("r1", "p1", true, 100, 5000, 500, 10);
        let (_, audit) =
            check_response_bound(&r, &policy(), "trace-123", "2026-01-01").expect("should succeed");
        assert_eq!(audit.request_id, "r1");
        assert_eq!(audit.peer_id, "p1");
        assert_eq!(audit.timestamp, "2026-01-01");
        assert!(audit.authenticated);
        assert_eq!(audit.actual_bytes, 500);
    }

    #[test]
    fn adversarial_harness_batch() {
        let requests = vec![
            req("r1", "p1", true, 100, 5000, 500, 10),
            req("r2", "p2", false, 10, 5000, 1500, 10), // should fail
            req("r3", "p3", true, 100, 5000, 400, 10),
        ];
        let results =
            run_adversarial_harness(&requests, &policy(), "tr", "ts").expect("should succeed");
        assert_eq!(results.len(), 3);
        assert!(results[0].0.allowed);
        assert!(!results[1].0.allowed);
        assert!(results[2].0.allowed);
    }

    #[test]
    fn invalid_policy_zero_ratio() {
        let mut p = policy();
        p.max_response_ratio = 0.0;
        let r = req("r1", "p1", true, 100, 5000, 500, 10);
        let err = check_response_bound(&r, &p, "tr", "ts").unwrap_err();
        assert_eq!(err.code(), "AAR_INVALID_POLICY");
    }

    #[test]
    fn invalid_policy_zero_unauth() {
        let mut p = policy();
        p.unauth_max_bytes = 0;
        let err = validate_policy(&p).unwrap_err();
        assert_eq!(err.code(), "AAR_INVALID_POLICY");
    }

    #[test]
    fn invalid_policy_zero_auth() {
        let mut p = policy();
        p.auth_max_bytes = 0;
        let err = validate_policy(&p).unwrap_err();
        assert_eq!(err.code(), "AAR_INVALID_POLICY");
    }

    #[test]
    fn invalid_policy_unauth_exceeds_auth() {
        let mut p = policy();
        p.unauth_max_bytes = 20_000;
        p.auth_max_bytes = 10_000;
        let err = validate_policy(&p).unwrap_err();
        assert_eq!(err.code(), "AAR_INVALID_POLICY");
    }

    #[test]
    fn invalid_policy_zero_items() {
        let mut p = policy();
        p.max_items_per_response = 0;
        let err = validate_policy(&p).unwrap_err();
        assert_eq!(err.code(), "AAR_INVALID_POLICY");
    }

    #[test]
    fn error_codes_all_present() {
        assert_eq!(
            AmplificationError::ResponseTooLarge {
                request_id: "".into(),
                actual: 0,
                limit: 0
            }
            .code(),
            "AAR_RESPONSE_TOO_LARGE"
        );
        assert_eq!(
            AmplificationError::RatioExceeded {
                request_id: "".into(),
                ratio: 0.0,
                max_ratio: 0.0
            }
            .code(),
            "AAR_RATIO_EXCEEDED"
        );
        assert_eq!(
            AmplificationError::UnauthLimit {
                request_id: "".into(),
                actual: 0,
                limit: 0
            }
            .code(),
            "AAR_UNAUTH_LIMIT"
        );
        assert_eq!(
            AmplificationError::ItemsExceeded {
                request_id: "".into(),
                actual: 0,
                limit: 0
            }
            .code(),
            "AAR_ITEMS_EXCEEDED"
        );
        assert_eq!(
            AmplificationError::InvalidPolicy { reason: "".into() }.code(),
            "AAR_INVALID_POLICY"
        );
    }

    #[test]
    fn error_display() {
        let e = AmplificationError::ResponseTooLarge {
            request_id: "r1".into(),
            actual: 5000,
            limit: 1000,
        };
        assert!(e.to_string().contains("AAR_RESPONSE_TOO_LARGE"));
        assert!(e.to_string().contains("r1"));
    }

    #[test]
    fn default_policy_valid() {
        assert!(validate_policy(&AmplificationPolicy::default_policy()).is_ok());
    }

    #[test]
    fn nan_max_response_ratio_rejected() {
        let mut p = policy();
        p.max_response_ratio = f64::NAN;
        let err = validate_policy(&p).unwrap_err();
        assert_eq!(err.code(), "AAR_INVALID_POLICY");
    }

    #[test]
    fn inf_max_response_ratio_rejected() {
        let mut p = policy();
        p.max_response_ratio = f64::INFINITY;
        let err = validate_policy(&p).unwrap_err();
        assert_eq!(err.code(), "AAR_INVALID_POLICY");
    }

    #[test]
    fn neg_inf_max_response_ratio_rejected() {
        let mut p = policy();
        p.max_response_ratio = f64::NEG_INFINITY;
        let err = validate_policy(&p).unwrap_err();
        assert_eq!(err.code(), "AAR_INVALID_POLICY");
    }

    #[test]
    fn negative_max_response_ratio_rejected() {
        let mut p = policy();
        p.max_response_ratio = -0.01;

        let err = validate_policy(&p).unwrap_err();

        assert_eq!(err.code(), "AAR_INVALID_POLICY");
        assert!(err.to_string().contains("max_response_ratio"));
    }

    #[test]
    fn declared_zero_byte_bound_blocks_nonzero_response() {
        let r = req("r-zero-bound", "p1", true, 100, 0, 1, 0);

        let (v, audit) = check_response_bound(&r, &policy(), "tr", "ts").expect("valid policy");

        assert!(!v.allowed);
        assert_eq!(v.enforced_limit, 0);
        assert_eq!(audit.verdict, "BLOCK");
        assert!(v.violations.iter().any(|v| matches!(
            v,
            BoundViolation::ResponseTooLarge {
                actual: 1,
                limit: 0
            }
        )));
    }

    #[test]
    fn declared_zero_item_bound_blocks_nonzero_items() {
        let mut r = req("r-zero-items", "p1", true, 100, 500, 0, 1);
        r.declared_bound.max_items = 0;

        let (v, _) = check_response_bound(&r, &policy(), "tr", "ts").expect("valid policy");

        assert!(!v.allowed);
        assert!(v.violations.iter().any(|v| matches!(
            v,
            BoundViolation::ItemsExceeded {
                actual: 1,
                limit: 0
            }
        )));
    }

    #[test]
    fn authenticated_response_over_auth_cap_blocks_even_when_declared_allows() {
        let r = req("r-auth-cap", "p1", true, 2_000, 50_000, 10_001, 1);

        let (v, audit) = check_response_bound(&r, &policy(), "tr", "ts").expect("valid policy");

        assert!(!v.allowed);
        assert_eq!(v.enforced_limit, 10_000);
        assert_eq!(audit.enforced_limit, 10_000);
        assert!(v.violations.iter().any(|v| matches!(
            v,
            BoundViolation::ResponseTooLarge {
                actual: 10_001,
                limit: 10_000
            }
        )));
    }

    #[test]
    fn declared_item_bound_below_policy_limit_is_enforced() {
        let mut r = req("r-item-declared", "p1", true, 100, 500, 100, 6);
        r.declared_bound.max_items = 5;

        let (v, _) = check_response_bound(&r, &policy(), "tr", "ts").expect("valid policy");

        assert!(!v.allowed);
        assert!(v.violations.iter().any(|v| matches!(
            v,
            BoundViolation::ItemsExceeded {
                actual: 6,
                limit: 5
            }
        )));
    }

    #[test]
    fn zero_request_with_nonzero_response_records_infinite_ratio_violation() {
        let r = req("r-inf-ratio", "p1", true, 0, 5_000, 1, 0);

        let (v, audit) = check_response_bound(&r, &policy(), "tr", "ts").expect("valid policy");

        assert!(!v.allowed);
        assert!(audit.ratio.is_infinite());
        assert!(v.violations.iter().any(|v| {
            matches!(
                v,
                BoundViolation::RatioExceeded {
                    ratio,
                    max_ratio: 10.0
                } if ratio.is_infinite()
            )
        }));
    }

    #[test]
    fn unauthenticated_oversize_response_reports_both_size_and_unauth_limits() {
        let r = req("r-unauth-both", "p1", false, 500, 50_000, 1_001, 1);

        let (v, _) = check_response_bound(&r, &policy(), "tr", "ts").expect("valid policy");

        assert!(!v.allowed);
        assert_eq!(v.enforced_limit, 1_000);
        assert!(v.violations.iter().any(|v| {
            matches!(
                v,
                BoundViolation::ResponseTooLarge {
                    actual: 1_001,
                    limit: 1_000
                }
            )
        }));
        assert!(v.violations.iter().any(|v| {
            matches!(
                v,
                BoundViolation::UnauthLimit {
                    actual: 1_001,
                    limit: 1_000
                }
            )
        }));
    }

    #[test]
    fn harness_rejects_invalid_policy_without_processing_batch() {
        let mut p = policy();
        p.auth_max_bytes = 0;
        let requests = vec![req("r-invalid-policy", "p1", true, 100, 500, 100, 1)];

        let err = run_adversarial_harness(&requests, &p, "tr", "ts").unwrap_err();

        assert_eq!(err.code(), "AAR_INVALID_POLICY");
    }

    #[test]
    fn negative_unauth_declared_bound_below_policy_cap_is_enforced() {
        let r = req("r-unauth-declared", "p1", false, 1_000, 400, 401, 1);

        let (v, audit) = check_response_bound(&r, &policy(), "tr", "ts").expect("valid policy");

        assert!(!v.allowed);
        assert_eq!(v.enforced_limit, 400);
        assert_eq!(audit.enforced_limit, 400);
        assert!(v.violations.iter().any(|v| matches!(
            v,
            BoundViolation::ResponseTooLarge {
                actual: 401,
                limit: 400
            }
        )));
        assert!(
            !v.violations
                .iter()
                .any(|v| matches!(v, BoundViolation::UnauthLimit { .. }))
        );
    }

    #[test]
    fn negative_policy_item_cap_applies_when_declared_item_bound_is_larger() {
        let mut r = req("r-policy-items", "p1", true, 1_000, 5_000, 100, 51);
        r.declared_bound.max_items = 500;

        let (v, _) = check_response_bound(&r, &policy(), "tr", "ts").expect("valid policy");

        assert!(!v.allowed);
        assert!(v.violations.iter().any(|v| matches!(
            v,
            BoundViolation::ItemsExceeded {
                actual: 51,
                limit: 50
            }
        )));
    }

    #[test]
    fn negative_ratio_exceeded_by_one_byte_over_exact_limit() {
        let r = req("r-ratio-over", "p1", true, 100, 10_000, 1_001, 1);

        let (v, audit) = check_response_bound(&r, &policy(), "tr", "ts").expect("valid policy");

        assert!(!v.allowed);
        assert_eq!(v.violations.len(), 1);
        assert!(audit.ratio > 10.0);
        assert!(v.violations.iter().any(|v| matches!(
            v,
            BoundViolation::RatioExceeded {
                ratio,
                max_ratio: 10.0
            } if *ratio > 10.0
        )));
    }

    #[test]
    fn negative_exact_ratio_limit_allowed_but_next_byte_rejected() {
        let exact = req("r-ratio-exact", "p1", true, 100, 10_000, 1_000, 1);
        let over = req("r-ratio-next-byte", "p1", true, 100, 10_000, 1_001, 1);

        let (exact_v, _) =
            check_response_bound(&exact, &policy(), "tr", "ts").expect("valid policy");
        let (over_v, _) = check_response_bound(&over, &policy(), "tr", "ts").expect("valid policy");

        assert!(exact_v.allowed);
        assert!(!over_v.allowed);
        assert!(
            over_v
                .violations
                .iter()
                .any(|v| matches!(v, BoundViolation::RatioExceeded { .. }))
        );
    }

    #[test]
    fn negative_harness_preserves_blocked_verdict_order() {
        let mut item_block = req("r-order-items", "p3", true, 100, 500, 100, 51);
        item_block.declared_bound.max_items = 50;
        let requests = vec![
            req("r-order-ok", "p1", true, 100, 5_000, 500, 1),
            req("r-order-ratio", "p2", true, 100, 10_000, 1_001, 1),
            item_block,
        ];

        let results =
            run_adversarial_harness(&requests, &policy(), "tr", "ts").expect("valid policy");

        assert_eq!(results.len(), 3);
        assert_eq!(results[0].0.request_id, "r-order-ok");
        assert_eq!(results[1].0.request_id, "r-order-ratio");
        assert_eq!(results[2].0.request_id, "r-order-items");
        assert!(results[0].0.allowed);
        assert!(!results[1].0.allowed);
        assert!(!results[2].0.allowed);
        assert!(
            results[1]
                .0
                .violations
                .iter()
                .any(|v| matches!(v, BoundViolation::RatioExceeded { .. }))
        );
        assert!(
            results[2]
                .0
                .violations
                .iter()
                .any(|v| matches!(v, BoundViolation::ItemsExceeded { .. }))
        );
    }

    #[test]
    fn negative_blocked_verdict_preserves_request_and_trace_metadata() {
        let r = req("r-meta-block", "peer-meta", false, 500, 50_000, 1_001, 1);

        let (v, audit) =
            check_response_bound(&r, &policy(), "trace-meta", "2026-04-17").expect("valid policy");

        assert!(!v.allowed);
        assert_eq!(v.request_id, "r-meta-block");
        assert_eq!(v.trace_id, "trace-meta");
        assert_eq!(audit.request_id, "r-meta-block");
        assert_eq!(audit.peer_id, "peer-meta");
        assert_eq!(audit.timestamp, "2026-04-17");
        assert_eq!(audit.verdict, "BLOCK");
    }

    #[test]
    fn negative_empty_harness_still_rejects_invalid_policy() {
        let mut p = policy();
        p.max_items_per_response = 0;

        let err = run_adversarial_harness(&[], &p, "tr", "ts").unwrap_err();

        assert_eq!(err.code(), "AAR_INVALID_POLICY");
        assert!(err.to_string().contains("max_items_per_response"));
    }

    #[test]
    fn negative_zero_request_unauth_large_response_reports_three_violations() {
        let r = req("r-zero-unauth-large", "p1", false, 0, 50_000, 1_001, 0);

        let (v, audit) = check_response_bound(&r, &policy(), "tr", "ts").expect("valid policy");

        assert!(!v.allowed);
        assert!(audit.ratio.is_infinite());
        assert_eq!(v.violations.len(), 3);
        assert!(v.violations.iter().any(|v| {
            matches!(
                v,
                BoundViolation::ResponseTooLarge {
                    actual: 1_001,
                    limit: 1_000
                }
            )
        }));
        assert!(v.violations.iter().any(|v| {
            matches!(
                v,
                BoundViolation::RatioExceeded {
                    ratio,
                    max_ratio: 10.0
                } if ratio.is_infinite()
            )
        }));
        assert!(v.violations.iter().any(|v| {
            matches!(
                v,
                BoundViolation::UnauthLimit {
                    actual: 1_001,
                    limit: 1_000
                }
            )
        }));
    }

    #[test]
    fn negative_zero_declared_bytes_and_items_report_independent_violations() {
        let mut r = req("r-zero-both", "p1", true, 1_000, 0, 1, 1);
        r.declared_bound.max_items = 0;

        let (v, audit) = check_response_bound(&r, &policy(), "tr", "ts").expect("valid policy");

        assert!(!v.allowed);
        assert_eq!(audit.enforced_limit, 0);
        assert_eq!(v.violations.len(), 2);
        assert!(v.violations.iter().any(|v| matches!(
            v,
            BoundViolation::ResponseTooLarge {
                actual: 1,
                limit: 0
            }
        )));
        assert!(v.violations.iter().any(|v| matches!(
            v,
            BoundViolation::ItemsExceeded {
                actual: 1,
                limit: 0
            }
        )));
    }

    #[test]
    fn negative_invalid_policy_preempts_malicious_request_values() {
        let mut p = policy();
        p.max_response_ratio = f64::NAN;
        let r = req("r-malicious", "p1", false, 0, u64::MAX, u64::MAX, u32::MAX);

        let err = check_response_bound(&r, &p, "tr", "ts").unwrap_err();

        assert_eq!(err.code(), "AAR_INVALID_POLICY");
        assert!(err.to_string().contains("max_response_ratio"));
    }

    #[test]
    fn negative_policy_with_unauth_equal_to_auth_still_enforces_declared_bound() {
        let mut p = policy();
        p.unauth_max_bytes = p.auth_max_bytes;
        let r = req("r-equal-caps", "p1", false, 1_000, 100, 101, 1);

        let (v, audit) = check_response_bound(&r, &p, "tr", "ts").expect("valid policy");

        assert!(!v.allowed);
        assert_eq!(v.enforced_limit, 100);
        assert_eq!(audit.enforced_limit, 100);
        assert!(v.violations.iter().any(|v| matches!(
            v,
            BoundViolation::ResponseTooLarge {
                actual: 101,
                limit: 100
            }
        )));
    }

    #[test]
    fn negative_invalid_policy_in_batch_prevents_later_block_verdicts() {
        let mut p = policy();
        p.unauth_max_bytes = 20_000;
        p.auth_max_bytes = 10_000;
        let requests = vec![
            req("r-would-block", "p1", false, 0, 50_000, 1_001, 0),
            req("r-would-allow", "p2", true, 1_000, 2_000, 100, 1),
        ];

        let err = run_adversarial_harness(&requests, &p, "tr", "ts").unwrap_err();

        assert_eq!(err.code(), "AAR_INVALID_POLICY");
        assert!(err.to_string().contains("unauth_max_bytes"));
    }

    #[test]
    fn negative_declared_byte_bound_one_below_actual_blocks_without_ratio_noise() {
        let r = req("r-declared-byte-edge", "p1", true, 10_000, 999, 1_000, 1);

        let (v, audit) = check_response_bound(&r, &policy(), "tr", "ts").expect("valid policy");

        assert!(!v.allowed);
        assert_eq!(v.enforced_limit, 999);
        assert_eq!(audit.enforced_limit, 999);
        assert_eq!(v.violations.len(), 1);
        assert!(v.violations.iter().any(|v| matches!(
            v,
            BoundViolation::ResponseTooLarge {
                actual: 1_000,
                limit: 999
            }
        )));
    }

    #[test]
    fn negative_declared_item_bound_one_below_actual_blocks_without_byte_noise() {
        let mut r = req("r-declared-item-edge", "p1", true, 10_000, 5_000, 100, 11);
        r.declared_bound.max_items = 10;

        let (v, audit) = check_response_bound(&r, &policy(), "tr", "ts").expect("valid policy");

        assert!(!v.allowed);
        assert_eq!(audit.verdict, "BLOCK");
        assert_eq!(v.violations.len(), 1);
        assert!(v.violations.iter().any(|v| matches!(
            v,
            BoundViolation::ItemsExceeded {
                actual: 11,
                limit: 10
            }
        )));
    }

    #[test]
    fn negative_tiny_positive_ratio_policy_rejects_nonzero_response_ratio() {
        let mut p = policy();
        p.max_response_ratio = f64::MIN_POSITIVE;
        let r = req("r-min-positive-ratio", "p1", true, 1_000, 5_000, 1, 0);

        let (v, audit) = check_response_bound(&r, &p, "tr", "ts").expect("valid policy");

        assert!(!v.allowed);
        assert_eq!(v.violations.len(), 1);
        assert_eq!(audit.verdict, "BLOCK");
        assert!(v.violations.iter().any(|v| matches!(
            v,
            BoundViolation::RatioExceeded {
                ratio,
                max_ratio
            } if *ratio > 0.0 && *max_ratio == f64::MIN_POSITIVE
        )));
    }

    #[test]
    fn negative_default_policy_unauth_cap_plus_one_reports_size_and_unauth_limits() {
        let p = AmplificationPolicy::default_policy();
        let r = BoundCheckRequest {
            request_id: "r-default-unauth-cap".into(),
            peer_id: "p1".into(),
            authenticated: false,
            request_bytes: 10_000,
            declared_bound: ResponseBound {
                max_bytes: p.unauth_max_bytes.saturating_add(1),
                max_items: 1,
            },
            actual_response_bytes: p.unauth_max_bytes.saturating_add(1),
            actual_items: 1,
        };

        let (v, audit) = check_response_bound(&r, &p, "tr", "ts").expect("valid policy");

        assert!(!v.allowed);
        assert_eq!(v.enforced_limit, p.unauth_max_bytes);
        assert_eq!(audit.verdict, "BLOCK");
        assert!(v.violations.iter().any(|v| matches!(
            v,
            BoundViolation::ResponseTooLarge { actual, limit }
                if *actual == p.unauth_max_bytes.saturating_add(1)
                    && *limit == p.unauth_max_bytes
        )));
        assert!(v.violations.iter().any(|v| matches!(
            v,
            BoundViolation::UnauthLimit { actual, limit }
                if *actual == p.unauth_max_bytes.saturating_add(1)
                    && *limit == p.unauth_max_bytes
        )));
    }

    #[test]
    fn negative_zero_request_zero_declared_nonzero_response_reports_size_and_ratio() {
        let r = req("r-zero-request-zero-bound", "p1", true, 0, 0, 1, 0);

        let (v, audit) = check_response_bound(&r, &policy(), "tr", "ts").expect("valid policy");

        assert!(!v.allowed);
        assert_eq!(v.enforced_limit, 0);
        assert!(audit.ratio.is_infinite());
        assert_eq!(v.violations.len(), 2);
        assert!(v.violations.iter().any(|v| matches!(
            v,
            BoundViolation::ResponseTooLarge {
                actual: 1,
                limit: 0
            }
        )));
        assert!(v.violations.iter().any(|v| {
            matches!(
                v,
                BoundViolation::RatioExceeded {
                    ratio,
                    max_ratio: 10.0
                } if ratio.is_infinite()
            )
        }));
    }

    #[test]
    fn negative_harness_preserves_multiple_block_reasons_per_request() {
        let mut item_and_ratio = req("r-harness-multi", "p1", true, 10, 10_000, 101, 51);
        item_and_ratio.declared_bound.max_items = 50;
        let requests = vec![item_and_ratio];

        let results =
            run_adversarial_harness(&requests, &policy(), "tr", "ts").expect("valid policy");

        assert_eq!(results.len(), 1);
        let verdict = &results[0].0;
        assert!(!verdict.allowed);
        assert_eq!(verdict.violations.len(), 2);
        assert!(
            verdict
                .violations
                .iter()
                .any(|v| matches!(v, BoundViolation::RatioExceeded { .. }))
        );
        assert!(
            verdict
                .violations
                .iter()
                .any(|v| matches!(v, BoundViolation::ItemsExceeded { .. }))
        );
    }

    #[test]
    fn negative_error_display_variants_include_request_id_and_limits() {
        let errors = [
            AmplificationError::ResponseTooLarge {
                request_id: "r-display".into(),
                actual: 11,
                limit: 10,
            },
            AmplificationError::RatioExceeded {
                request_id: "r-display".into(),
                ratio: 11.0,
                max_ratio: 10.0,
            },
            AmplificationError::UnauthLimit {
                request_id: "r-display".into(),
                actual: 1_001,
                limit: 1_000,
            },
            AmplificationError::ItemsExceeded {
                request_id: "r-display".into(),
                actual: 51,
                limit: 50,
            },
        ];

        for err in errors {
            let rendered = err.to_string();
            assert!(rendered.contains("r-display"));
            assert!(rendered.contains(err.code()));
        }
    }
}
