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
    if policy.max_response_ratio <= 0.0 {
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
        let (v, a) = check_response_bound(&r, &policy(), "tr", "ts").unwrap();
        assert!(v.allowed);
        assert!(v.violations.is_empty());
        assert_eq!(a.verdict, "ALLOW");
    }

    #[test]
    fn block_response_too_large() {
        let r = req("r1", "p1", true, 100, 5000, 6000, 10);
        let (v, _) = check_response_bound(&r, &policy(), "tr", "ts").unwrap();
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
        let (v, _) = check_response_bound(&r, &policy(), "tr", "ts").unwrap();
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
        let (v, _) = check_response_bound(&r, &policy(), "tr", "ts").unwrap();
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
        let (v, _) = check_response_bound(&r, &policy(), "tr", "ts").unwrap();
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
        let (v, _) = check_response_bound(&r, &policy(), "tr", "ts").unwrap();
        assert!(!v.allowed);
    }

    #[test]
    fn zero_request_zero_response_ok() {
        let r = req("r1", "p1", true, 0, 5000, 0, 0);
        let (v, _) = check_response_bound(&r, &policy(), "tr", "ts").unwrap();
        assert!(v.allowed);
    }

    #[test]
    fn multiple_violations() {
        // Unauth, oversized, high ratio, too many items
        let mut r = req("r1", "p1", false, 10, 50000, 5000, 100);
        r.declared_bound.max_items = 50;
        let (v, _) = check_response_bound(&r, &policy(), "tr", "ts").unwrap();
        assert!(!v.allowed);
        assert!(v.violations.len() >= 3); // response too large, ratio, unauth, items
    }

    #[test]
    fn deterministic_check() {
        let r = req("r1", "p1", true, 100, 5000, 500, 10);
        let (v1, a1) = check_response_bound(&r, &policy(), "tr", "ts").unwrap();
        let (v2, a2) = check_response_bound(&r, &policy(), "tr", "ts").unwrap();
        assert_eq!(v1.allowed, v2.allowed);
        assert_eq!(v1.violations.len(), v2.violations.len());
        assert_eq!(a1.verdict, a2.verdict);
        assert_eq!(a1.enforced_limit, a2.enforced_limit);
    }

    #[test]
    fn audit_entry_complete() {
        let r = req("r1", "p1", true, 100, 5000, 500, 10);
        let (_, audit) = check_response_bound(&r, &policy(), "trace-123", "2026-01-01").unwrap();
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
        let results = run_adversarial_harness(&requests, &policy(), "tr", "ts").unwrap();
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
}
