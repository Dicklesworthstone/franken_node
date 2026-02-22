//! bd-ck2h: MVP vs Full conformance profile matrix and publication claim rules.
//!
//! Each profile lists required capabilities.  A profile evaluator compares
//! measured test results against the matrix and produces publication metadata.
//! Unsupported claims are blocked.

use std::collections::{HashMap, HashSet};
use std::fmt;

// ── Profile ─────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Profile {
    Mvp,
    Full,
}

impl fmt::Display for Profile {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Profile::Mvp => write!(f, "MVP"),
            Profile::Full => write!(f, "Full"),
        }
    }
}

// ── Capability result ───────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct CapabilityResult {
    pub capability: String,
    pub passed: bool,
    pub details: String,
}

// ── Profile matrix ──────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct ProfileMatrix {
    required: HashMap<Profile, Vec<String>>,
}

impl ProfileMatrix {
    /// Build the standard matrix.
    pub fn standard() -> Self {
        let mvp = vec![
            "serialization",
            "auth",
            "lifecycle",
            "fencing",
            "frame_parsing",
        ]
        .into_iter()
        .map(String::from)
        .collect::<Vec<_>>();

        let mut full = mvp.clone();
        full.extend(
            [
                "crdt",
                "lease_coordination",
                "quarantine",
                "retention",
                "anti_amplification",
                "trace_correlation",
                "telemetry",
                "error_codes",
            ]
            .iter()
            .map(|s| s.to_string()),
        );

        let mut required = HashMap::new();
        required.insert(Profile::Mvp, mvp);
        required.insert(Profile::Full, full);
        Self { required }
    }

    /// Validate matrix consistency.
    pub fn validate(&self) -> Result<(), ProfileError> {
        for (profile, caps) in &self.required {
            if caps.is_empty() {
                return Err(ProfileError::InvalidMatrix(format!(
                    "{profile} has no required capabilities"
                )));
            }
            let unique: HashSet<_> = caps.iter().collect();
            if unique.len() != caps.len() {
                return Err(ProfileError::InvalidMatrix(format!(
                    "{profile} has duplicate capabilities"
                )));
            }
        }
        Ok(())
    }

    /// Get required capabilities for a profile.
    pub fn required_for(&self, profile: Profile) -> Result<&[String], ProfileError> {
        self.required
            .get(&profile)
            .map(|v| v.as_slice())
            .ok_or(ProfileError::UnknownProfile(profile.to_string()))
    }
}

// ── Claim evaluation ────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct ClaimEvaluation {
    pub profile: Profile,
    pub results: Vec<CapabilityResult>,
    pub verdict: String,
    pub can_publish: bool,
    pub metadata: PublicationMetadata,
}

#[derive(Debug, Clone)]
pub struct PublicationMetadata {
    pub profile_name: String,
    pub version: u32,
    pub capabilities_passed: usize,
    pub capabilities_total: usize,
}

// ── Errors ──────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProfileError {
    /// CPM_UNKNOWN_PROFILE
    UnknownProfile(String),
    /// CPM_MISSING_RESULT
    MissingResult(String),
    /// CPM_CAPABILITY_FAILED
    CapabilityFailed(String),
    /// CPM_CLAIM_BLOCKED
    ClaimBlocked(String),
    /// CPM_INVALID_MATRIX
    InvalidMatrix(String),
}

impl ProfileError {
    pub fn code(&self) -> &'static str {
        match self {
            ProfileError::UnknownProfile(_) => "CPM_UNKNOWN_PROFILE",
            ProfileError::MissingResult(_) => "CPM_MISSING_RESULT",
            ProfileError::CapabilityFailed(_) => "CPM_CAPABILITY_FAILED",
            ProfileError::ClaimBlocked(_) => "CPM_CLAIM_BLOCKED",
            ProfileError::InvalidMatrix(_) => "CPM_INVALID_MATRIX",
        }
    }
}

impl fmt::Display for ProfileError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ProfileError::UnknownProfile(p) => write!(f, "CPM_UNKNOWN_PROFILE: {p}"),
            ProfileError::MissingResult(c) => write!(f, "CPM_MISSING_RESULT: {c}"),
            ProfileError::CapabilityFailed(c) => write!(f, "CPM_CAPABILITY_FAILED: {c}"),
            ProfileError::ClaimBlocked(p) => write!(f, "CPM_CLAIM_BLOCKED: {p}"),
            ProfileError::InvalidMatrix(d) => write!(f, "CPM_INVALID_MATRIX: {d}"),
        }
    }
}

// ── Evaluator ───────────────────────────────────────────────────────────────

/// Evaluate a profile claim against measured results.
pub fn evaluate_claim(
    matrix: &ProfileMatrix,
    profile: Profile,
    measured: &[CapabilityResult],
    version: u32,
) -> Result<ClaimEvaluation, ProfileError> {
    let required = matrix.required_for(profile)?;
    let result_map: HashMap<&str, &CapabilityResult> = measured
        .iter()
        .map(|r| (r.capability.as_str(), r))
        .collect();

    let mut per_cap = Vec::new();
    let mut all_pass = true;

    for cap in required {
        match result_map.get(cap.as_str()) {
            None => {
                per_cap.push(CapabilityResult {
                    capability: cap.clone(),
                    passed: false,
                    details: "no test result".into(),
                });
                all_pass = false;
            }
            Some(r) => {
                per_cap.push((*r).clone());
                if !r.passed {
                    all_pass = false;
                }
            }
        }
    }

    let passed_count = per_cap.iter().filter(|r| r.passed).count();
    let total = per_cap.len();

    Ok(ClaimEvaluation {
        profile,
        results: per_cap,
        verdict: if all_pass {
            "PASS".into()
        } else {
            "FAIL".into()
        },
        can_publish: all_pass,
        metadata: PublicationMetadata {
            profile_name: profile.to_string(),
            version,
            capabilities_passed: passed_count,
            capabilities_total: total,
        },
    })
}

/// Gate: attempt to publish a claim.  Returns Err if blocked.
pub fn publish_claim(
    matrix: &ProfileMatrix,
    profile: Profile,
    measured: &[CapabilityResult],
    version: u32,
) -> Result<ClaimEvaluation, ProfileError> {
    let eval = evaluate_claim(matrix, profile, measured, version)?;
    if !eval.can_publish {
        return Err(ProfileError::ClaimBlocked(format!(
            "{}: {}/{} capabilities passed",
            profile, eval.metadata.capabilities_passed, eval.metadata.capabilities_total
        )));
    }
    Ok(eval)
}

// ── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn cap(name: &str, passed: bool) -> CapabilityResult {
        CapabilityResult {
            capability: name.to_string(),
            passed,
            details: if passed { "ok" } else { "failed" }.to_string(),
        }
    }

    fn mvp_results(all_pass: bool) -> Vec<CapabilityResult> {
        vec![
            cap("serialization", all_pass),
            cap("auth", all_pass),
            cap("lifecycle", all_pass),
            cap("fencing", all_pass),
            cap("frame_parsing", all_pass),
        ]
    }

    fn full_results(all_pass: bool) -> Vec<CapabilityResult> {
        let mut r = mvp_results(all_pass);
        r.extend(vec![
            cap("crdt", all_pass),
            cap("lease_coordination", all_pass),
            cap("quarantine", all_pass),
            cap("retention", all_pass),
            cap("anti_amplification", all_pass),
            cap("trace_correlation", all_pass),
            cap("telemetry", all_pass),
            cap("error_codes", all_pass),
        ]);
        r
    }

    #[test]
    fn standard_matrix_valid() {
        let m = ProfileMatrix::standard();
        m.validate().unwrap();
    }

    #[test]
    fn mvp_all_pass() {
        let m = ProfileMatrix::standard();
        let eval = evaluate_claim(&m, Profile::Mvp, &mvp_results(true), 1).unwrap();
        assert_eq!(eval.verdict, "PASS");
        assert!(eval.can_publish);
        assert_eq!(eval.metadata.capabilities_passed, 5);
    }

    #[test]
    fn mvp_one_fail() {
        let m = ProfileMatrix::standard();
        let mut results = mvp_results(true);
        results[2].passed = false; // lifecycle fails
        let eval = evaluate_claim(&m, Profile::Mvp, &results, 1).unwrap();
        assert_eq!(eval.verdict, "FAIL");
        assert!(!eval.can_publish);
    }

    #[test]
    fn mvp_missing_result() {
        let m = ProfileMatrix::standard();
        let results = vec![cap("serialization", true), cap("auth", true)];
        let eval = evaluate_claim(&m, Profile::Mvp, &results, 1).unwrap();
        assert_eq!(eval.verdict, "FAIL");
        assert!(!eval.can_publish);
    }

    #[test]
    fn full_all_pass() {
        let m = ProfileMatrix::standard();
        let eval = evaluate_claim(&m, Profile::Full, &full_results(true), 1).unwrap();
        assert_eq!(eval.verdict, "PASS");
        assert!(eval.can_publish);
        assert_eq!(eval.metadata.capabilities_passed, 13);
    }

    #[test]
    fn publish_blocks_on_failure() {
        let m = ProfileMatrix::standard();
        let mut results = mvp_results(true);
        results[0].passed = false;
        let err = publish_claim(&m, Profile::Mvp, &results, 1).unwrap_err();
        assert_eq!(err.code(), "CPM_CLAIM_BLOCKED");
    }

    #[test]
    fn publish_succeeds_on_pass() {
        let m = ProfileMatrix::standard();
        let eval = publish_claim(&m, Profile::Mvp, &mvp_results(true), 1).unwrap();
        assert!(eval.can_publish);
    }

    #[test]
    fn metadata_generated() {
        let m = ProfileMatrix::standard();
        let eval = evaluate_claim(&m, Profile::Full, &full_results(true), 3).unwrap();
        assert_eq!(eval.metadata.profile_name, "Full");
        assert_eq!(eval.metadata.version, 3);
        assert_eq!(eval.metadata.capabilities_total, 13);
    }

    #[test]
    fn profile_display() {
        assert_eq!(Profile::Mvp.to_string(), "MVP");
        assert_eq!(Profile::Full.to_string(), "Full");
    }

    #[test]
    fn error_display() {
        let e = ProfileError::UnknownProfile("bad".into());
        assert!(e.to_string().contains("CPM_UNKNOWN_PROFILE"));
    }

    #[test]
    fn all_error_codes_present() {
        let errors = [
            ProfileError::UnknownProfile("x".into()),
            ProfileError::MissingResult("x".into()),
            ProfileError::CapabilityFailed("x".into()),
            ProfileError::ClaimBlocked("x".into()),
            ProfileError::InvalidMatrix("x".into()),
        ];
        let codes: Vec<_> = errors.iter().map(|e| e.code()).collect();
        assert!(codes.contains(&"CPM_UNKNOWN_PROFILE"));
        assert!(codes.contains(&"CPM_MISSING_RESULT"));
        assert!(codes.contains(&"CPM_CAPABILITY_FAILED"));
        assert!(codes.contains(&"CPM_CLAIM_BLOCKED"));
        assert!(codes.contains(&"CPM_INVALID_MATRIX"));
    }

    #[test]
    fn matrix_full_is_superset_of_mvp() {
        let m = ProfileMatrix::standard();
        let mvp_caps: HashSet<_> = m.required_for(Profile::Mvp).unwrap().iter().collect();
        let full_caps: HashSet<_> = m.required_for(Profile::Full).unwrap().iter().collect();
        assert!(mvp_caps.is_subset(&full_caps));
    }

    #[test]
    fn evaluate_extra_results_ignored() {
        let m = ProfileMatrix::standard();
        let mut results = mvp_results(true);
        results.push(cap("extra_not_in_matrix", true));
        let eval = evaluate_claim(&m, Profile::Mvp, &results, 1).unwrap();
        assert_eq!(eval.verdict, "PASS");
        assert_eq!(eval.metadata.capabilities_total, 5);
    }
}
