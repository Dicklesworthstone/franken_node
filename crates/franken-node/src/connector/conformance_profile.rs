//! bd-ck2h: MVP vs Full conformance profile matrix and publication claim rules.
//!
//! Each profile lists required capabilities.  A profile evaluator compares
//! measured test results against the matrix and produces publication metadata.
//! Unsupported claims are blocked.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

const MAX_CAPABILITY_RESULTS: usize = 4096;

fn push_bounded<T>(items: &mut Vec<T>, item: T, cap: usize) {
    if cap == 0 {
        items.clear();
        return;
    }

    if items.len() >= cap {
        let overflow = items.len().saturating_sub(cap).saturating_add(1);
        items.drain(0..overflow.min(items.len()));
    }
    items.push(item);
}

fn contains_nul(value: &str) -> bool {
    value.as_bytes().contains(&0)
}

// ── Profile ─────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
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
    required: BTreeMap<Profile, Vec<String>>,
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

        let mut required = BTreeMap::new();
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
            if caps
                .iter()
                .any(|capability| {
                    capability.trim().is_empty()
                        || capability.trim() != capability
                        || contains_nul(capability)
                })
            {
                return Err(ProfileError::InvalidMatrix(format!(
                    "{profile} has empty or non-canonical required capabilities"
                )));
            }
            let unique: BTreeSet<_> = caps.iter().collect();
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
    let result_map: BTreeMap<&str, &CapabilityResult> = measured
        .iter()
        .map(|r| (r.capability.as_str(), r))
        .collect();

    let mut per_cap = Vec::new();
    let mut all_pass = true;

    for cap in required {
        match result_map.get(cap.as_str()) {
            None => {
                push_bounded(
                    &mut per_cap,
                    CapabilityResult {
                        capability: cap.clone(),
                        passed: false,
                        details: "no test result".into(),
                    },
                    MAX_CAPABILITY_RESULTS,
                );
                all_pass = false;
            }
            Some(r) => {
                push_bounded(&mut per_cap, (*r).clone(), MAX_CAPABILITY_RESULTS);
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
        let mvp_caps: BTreeSet<_> = m.required_for(Profile::Mvp).unwrap().iter().collect();
        let full_caps: BTreeSet<_> = m.required_for(Profile::Full).unwrap().iter().collect();
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

    #[test]
    fn matrix_validation_rejects_empty_required_capability_list() {
        let matrix = ProfileMatrix {
            required: BTreeMap::from([(Profile::Mvp, Vec::new())]),
        };

        let err = matrix.validate().unwrap_err();

        assert_eq!(err.code(), "CPM_INVALID_MATRIX");
        assert!(err.to_string().contains("MVP has no required capabilities"));
    }

    #[test]
    fn matrix_validation_rejects_duplicate_required_capabilities() {
        let matrix = ProfileMatrix {
            required: BTreeMap::from([(
                Profile::Full,
                vec!["auth".to_string(), "auth".to_string()],
            )]),
        };

        let err = matrix.validate().unwrap_err();

        assert_eq!(err.code(), "CPM_INVALID_MATRIX");
        assert!(err.to_string().contains("Full has duplicate capabilities"));
    }

    #[test]
    fn required_for_missing_profile_returns_unknown_profile() {
        let matrix = ProfileMatrix {
            required: BTreeMap::from([(Profile::Mvp, vec!["serialization".to_string()])]),
        };

        let err = matrix.required_for(Profile::Full).unwrap_err();

        assert_eq!(err.code(), "CPM_UNKNOWN_PROFILE");
        assert!(err.to_string().contains("Full"));
    }

    #[test]
    fn empty_measured_results_mark_all_required_capabilities_missing() {
        let matrix = ProfileMatrix::standard();

        let eval = evaluate_claim(&matrix, Profile::Mvp, &[], 7).unwrap();

        assert_eq!(eval.verdict, "FAIL");
        assert!(!eval.can_publish);
        assert_eq!(eval.metadata.capabilities_passed, 0);
        assert_eq!(eval.metadata.capabilities_total, 5);
        assert!(
            eval.results
                .iter()
                .all(|result| { !result.passed && result.details == "no test result" })
        );
    }

    #[test]
    fn failed_required_capability_blocks_publish_and_preserves_detail() {
        let matrix = ProfileMatrix::standard();
        let mut results = mvp_results(true);
        results[3] = CapabilityResult {
            capability: "fencing".to_string(),
            passed: false,
            details: "fencing proof missing".to_string(),
        };

        let eval = evaluate_claim(&matrix, Profile::Mvp, &results, 1).unwrap();
        let err = publish_claim(&matrix, Profile::Mvp, &results, 1).unwrap_err();

        assert_eq!(eval.verdict, "FAIL");
        assert!(!eval.can_publish);
        assert_eq!(eval.metadata.capabilities_passed, 4);
        assert_eq!(err.code(), "CPM_CLAIM_BLOCKED");
        assert!(eval.results.iter().any(|result| {
            result.capability == "fencing"
                && !result.passed
                && result.details == "fencing proof missing"
        }));
    }

    #[test]
    fn duplicate_measured_capability_last_failure_wins() {
        let matrix = ProfileMatrix::standard();
        let mut results = mvp_results(true);
        results.push(CapabilityResult {
            capability: "auth".to_string(),
            passed: false,
            details: "latest auth run failed".to_string(),
        });

        let eval = evaluate_claim(&matrix, Profile::Mvp, &results, 1).unwrap();

        assert_eq!(eval.verdict, "FAIL");
        assert!(!eval.can_publish);
        assert!(eval.results.iter().any(|result| {
            result.capability == "auth"
                && !result.passed
                && result.details == "latest auth run failed"
        }));
    }

    #[test]
    fn full_profile_publish_blocks_when_only_mvp_results_are_present() {
        let matrix = ProfileMatrix::standard();

        let err = publish_claim(&matrix, Profile::Full, &mvp_results(true), 1).unwrap_err();
        let eval = evaluate_claim(&matrix, Profile::Full, &mvp_results(true), 1).unwrap();

        assert_eq!(err.code(), "CPM_CLAIM_BLOCKED");
        assert_eq!(eval.verdict, "FAIL");
        assert_eq!(eval.metadata.capabilities_passed, 5);
        assert_eq!(eval.metadata.capabilities_total, 13);
        assert!(eval.results.iter().any(|result| {
            result.capability == "crdt" && !result.passed && result.details == "no test result"
        }));
    }

    #[test]
    fn evaluate_claim_with_empty_matrix_returns_unknown_profile() {
        let matrix = ProfileMatrix {
            required: BTreeMap::new(),
        };

        let err = evaluate_claim(&matrix, Profile::Mvp, &mvp_results(true), 1).unwrap_err();

        assert_eq!(err.code(), "CPM_UNKNOWN_PROFILE");
        assert!(err.to_string().contains("MVP"));
    }

    #[test]
    fn publish_claim_with_empty_matrix_returns_unknown_profile() {
        let matrix = ProfileMatrix {
            required: BTreeMap::new(),
        };

        let err = publish_claim(&matrix, Profile::Full, &full_results(true), 1).unwrap_err();

        assert_eq!(err.code(), "CPM_UNKNOWN_PROFILE");
        assert!(err.to_string().contains("Full"));
    }

    #[test]
    fn measured_capability_with_trailing_space_is_treated_as_missing() {
        let matrix = ProfileMatrix::standard();
        let results = mvp_results(true)
            .into_iter()
            .map(|mut result| {
                if result.capability == "auth" {
                    result.capability = "auth ".to_string();
                }
                result
            })
            .collect::<Vec<_>>();

        let eval = evaluate_claim(&matrix, Profile::Mvp, &results, 1).unwrap();

        assert_eq!(eval.verdict, "FAIL");
        assert!(!eval.can_publish);
        assert_eq!(eval.metadata.capabilities_passed, 4);
        assert!(eval.results.iter().any(|result| {
            result.capability == "auth" && !result.passed && result.details == "no test result"
        }));
    }

    #[test]
    fn measured_capability_name_is_case_sensitive() {
        let matrix = ProfileMatrix::standard();
        let results = mvp_results(true)
            .into_iter()
            .map(|mut result| {
                if result.capability == "lifecycle" {
                    result.capability = "Lifecycle".to_string();
                }
                result
            })
            .collect::<Vec<_>>();

        let eval = evaluate_claim(&matrix, Profile::Mvp, &results, 1).unwrap();

        assert_eq!(eval.verdict, "FAIL");
        assert_eq!(eval.metadata.capabilities_passed, 4);
        assert!(eval.results.iter().any(|result| {
            result.capability == "lifecycle" && !result.passed && result.details == "no test result"
        }));
    }

    #[test]
    fn matrix_with_padded_required_capability_blocks_publish() {
        let matrix = ProfileMatrix {
            required: BTreeMap::from([(Profile::Mvp, vec!["auth ".to_string()])]),
        };

        let err = publish_claim(&matrix, Profile::Mvp, &[cap("auth", true)], 1).unwrap_err();
        let eval = evaluate_claim(&matrix, Profile::Mvp, &[cap("auth", true)], 1).unwrap();

        assert_eq!(err.code(), "CPM_CLAIM_BLOCKED");
        assert_eq!(eval.verdict, "FAIL");
        assert_eq!(eval.metadata.capabilities_passed, 0);
        assert!(eval.results.iter().any(|result| {
            result.capability == "auth " && !result.passed && result.details == "no test result"
        }));
    }

    #[test]
    fn full_profile_extra_capability_failure_blocks_despite_mvp_pass() {
        let matrix = ProfileMatrix::standard();
        let results = full_results(true)
            .into_iter()
            .map(|mut result| {
                if result.capability == "telemetry" {
                    result.passed = false;
                    result.details = "telemetry report missing".to_string();
                }
                result
            })
            .collect::<Vec<_>>();

        let err = publish_claim(&matrix, Profile::Full, &results, 9).unwrap_err();
        let eval = evaluate_claim(&matrix, Profile::Full, &results, 9).unwrap();

        assert_eq!(err.code(), "CPM_CLAIM_BLOCKED");
        assert_eq!(eval.metadata.capabilities_passed, 12);
        assert_eq!(eval.metadata.capabilities_total, 13);
        assert!(eval.results.iter().any(|result| {
            result.capability == "telemetry"
                && !result.passed
                && result.details == "telemetry report missing"
        }));
    }

    #[test]
    fn full_profile_empty_results_blocked_message_reports_zero_of_total() {
        let matrix = ProfileMatrix::standard();

        let err = publish_claim(&matrix, Profile::Full, &[], 1).unwrap_err();

        assert_eq!(err.code(), "CPM_CLAIM_BLOCKED");
        assert!(err.to_string().contains("Full: 0/13 capabilities passed"));
    }

    #[test]
    fn push_bounded_zero_capacity_clears_existing_results_without_pushing_new_item() {
        let mut results = vec![cap("serialization", true), cap("auth", true)];

        push_bounded(&mut results, cap("lifecycle", true), 0);

        assert!(results.is_empty());
    }

    #[test]
    fn push_bounded_zero_capacity_on_empty_result_set_stays_empty() {
        let mut results: Vec<CapabilityResult> = Vec::new();

        push_bounded(&mut results, cap("serialization", true), 0);

        assert!(results.is_empty());
    }

    #[test]
    fn push_bounded_over_capacity_discards_oldest_result_only() {
        let mut results = vec![
            cap("serialization", true),
            cap("auth", true),
            cap("lifecycle", true),
        ];

        push_bounded(&mut results, cap("fencing", false), 3);

        assert_eq!(
            results
                .iter()
                .map(|result| result.capability.as_str())
                .collect::<Vec<_>>(),
            vec!["auth", "lifecycle", "fencing"]
        );
        assert!(!results.last().expect("latest result").passed);
    }

    #[test]
    fn matrix_with_only_full_profile_rejects_mvp_lookup() {
        let matrix = ProfileMatrix {
            required: BTreeMap::from([(Profile::Full, vec!["serialization".to_string()])]),
        };

        let err = evaluate_claim(&matrix, Profile::Mvp, &[cap("serialization", true)], 1)
            .expect_err("MVP claim must fail when matrix only defines Full");

        assert_eq!(err.code(), "CPM_UNKNOWN_PROFILE");
        assert!(err.to_string().contains("MVP"));
    }

    #[test]
    fn duplicate_required_capabilities_are_not_silently_deduplicated() {
        let matrix = ProfileMatrix {
            required: BTreeMap::from([(
                Profile::Mvp,
                vec!["auth".to_string(), "auth".to_string()],
            )]),
        };

        let err = matrix
            .validate()
            .expect_err("duplicate requirements must invalidate matrix");

        assert_eq!(err.code(), "CPM_INVALID_MATRIX");
        assert!(err.to_string().contains("duplicate capabilities"));
    }

    #[test]
    fn duplicate_required_capability_without_validation_counts_twice_and_blocks() {
        let matrix = ProfileMatrix {
            required: BTreeMap::from([(
                Profile::Mvp,
                vec!["auth".to_string(), "auth".to_string()],
            )]),
        };

        let eval = evaluate_claim(&matrix, Profile::Mvp, &[cap("auth", false)], 1)
            .expect("evaluator reports supplied matrix contents");

        assert_eq!(eval.verdict, "FAIL");
        assert_eq!(eval.metadata.capabilities_total, 2);
        assert_eq!(eval.metadata.capabilities_passed, 0);
        assert_eq!(eval.results.len(), 2);
    }

    #[test]
    fn duplicate_measured_capability_last_pass_cannot_publish_missing_required_peer() {
        let matrix = ProfileMatrix {
            required: BTreeMap::from([(
                Profile::Mvp,
                vec!["auth".to_string(), "lifecycle".to_string()],
            )]),
        };
        let results = vec![cap("auth", false), cap("auth", true)];

        let err = publish_claim(&matrix, Profile::Mvp, &results, 1)
            .expect_err("missing lifecycle must still block publication");
        let eval = evaluate_claim(&matrix, Profile::Mvp, &results, 1)
            .expect("evaluation should report mixed duplicate/missing status");

        assert_eq!(err.code(), "CPM_CLAIM_BLOCKED");
        assert_eq!(eval.metadata.capabilities_passed, 1);
        assert_eq!(eval.metadata.capabilities_total, 2);
        assert!(eval.results.iter().any(|result| {
            result.capability == "lifecycle" && !result.passed && result.details == "no test result"
        }));
    }

    #[test]
    fn matrix_validation_rejects_blank_required_capability() {
        let matrix = ProfileMatrix {
            required: BTreeMap::from([(Profile::Mvp, vec![String::new()])]),
        };

        let err = matrix.validate().unwrap_err();

        assert_eq!(err.code(), "CPM_INVALID_MATRIX");
        assert!(err.to_string().contains("empty or non-canonical"));
    }

    #[test]
    fn matrix_validation_rejects_whitespace_required_capability() {
        let matrix = ProfileMatrix {
            required: BTreeMap::from([(Profile::Full, vec![" \t ".to_string()])]),
        };

        let err = matrix.validate().unwrap_err();

        assert_eq!(err.code(), "CPM_INVALID_MATRIX");
        assert!(err.to_string().contains("Full"));
        assert!(err.to_string().contains("empty or non-canonical"));
    }

    #[test]
    fn matrix_validation_rejects_padded_required_capability() {
        let matrix = ProfileMatrix {
            required: BTreeMap::from([(Profile::Mvp, vec![" auth".to_string()])]),
        };

        let err = matrix.validate().unwrap_err();

        assert_eq!(err.code(), "CPM_INVALID_MATRIX");
        assert!(err.to_string().contains("MVP"));
        assert!(err.to_string().contains("empty or non-canonical"));
    }

    #[test]
    fn leading_space_measured_capability_is_treated_as_missing() {
        let matrix = ProfileMatrix::standard();
        let results = mvp_results(true)
            .into_iter()
            .map(|mut result| {
                if result.capability == "serialization" {
                    result.capability = " serialization".to_string();
                }
                result
            })
            .collect::<Vec<_>>();

        let eval = evaluate_claim(&matrix, Profile::Mvp, &results, 1).unwrap();

        assert_eq!(eval.verdict, "FAIL");
        assert_eq!(eval.metadata.capabilities_passed, 4);
        assert!(eval.results.iter().any(|result| {
            result.capability == "serialization"
                && !result.passed
                && result.details == "no test result"
        }));
    }

    #[test]
    fn empty_measured_capability_name_does_not_satisfy_required_capability() {
        let matrix = ProfileMatrix {
            required: BTreeMap::from([(Profile::Mvp, vec!["auth".to_string()])]),
        };
        let results = vec![CapabilityResult {
            capability: String::new(),
            passed: true,
            details: "empty name should be ignored".to_string(),
        }];

        let err = publish_claim(&matrix, Profile::Mvp, &results, 1).unwrap_err();
        let eval = evaluate_claim(&matrix, Profile::Mvp, &results, 1).unwrap();

        assert_eq!(err.code(), "CPM_CLAIM_BLOCKED");
        assert_eq!(eval.metadata.capabilities_passed, 0);
        assert!(eval.results.iter().any(|result| {
            result.capability == "auth" && !result.passed && result.details == "no test result"
        }));
    }

    #[test]
    fn extra_failed_capability_does_not_mask_missing_required_capability() {
        let matrix = ProfileMatrix {
            required: BTreeMap::from([(Profile::Mvp, vec!["auth".to_string()])]),
        };
        let results = vec![CapabilityResult {
            capability: "not_required".to_string(),
            passed: false,
            details: "irrelevant failure".to_string(),
        }];

        let err = publish_claim(&matrix, Profile::Mvp, &results, 1).unwrap_err();
        let eval = evaluate_claim(&matrix, Profile::Mvp, &results, 1).unwrap();

        assert_eq!(err.code(), "CPM_CLAIM_BLOCKED");
        assert_eq!(eval.metadata.capabilities_total, 1);
        assert_eq!(eval.metadata.capabilities_passed, 0);
        assert!(eval.results.iter().any(|result| {
            result.capability == "auth" && !result.passed && result.details == "no test result"
        }));
    }

    #[test]
    fn matrix_validation_rejects_nul_required_capability() {
        let matrix = ProfileMatrix {
            required: BTreeMap::from([(Profile::Mvp, vec!["auth\0shadow".to_string()])]),
        };

        let err = matrix.validate().unwrap_err();

        assert_eq!(err.code(), "CPM_INVALID_MATRIX");
        assert!(err.to_string().contains("empty or non-canonical"));
    }

    #[test]
    fn matrix_validation_rejects_nul_after_canonical_prefix() {
        let matrix = ProfileMatrix {
            required: BTreeMap::from([(
                Profile::Full,
                vec!["serialization".to_string(), "fencing\0".to_string()],
            )]),
        };

        let err = matrix.validate().unwrap_err();

        assert_eq!(err.code(), "CPM_INVALID_MATRIX");
        assert!(err.to_string().contains("Full"));
    }

    #[test]
    fn measured_capability_with_nul_suffix_is_treated_as_missing() {
        let matrix = ProfileMatrix {
            required: BTreeMap::from([(Profile::Mvp, vec!["auth".to_string()])]),
        };
        let results = vec![cap("auth\0shadow", true)];

        let eval = evaluate_claim(&matrix, Profile::Mvp, &results, 1).unwrap();

        assert_eq!(eval.verdict, "FAIL");
        assert!(!eval.can_publish);
        assert_eq!(eval.metadata.capabilities_passed, 0);
        assert!(eval.results.iter().any(|result| {
            result.capability == "auth" && !result.passed && result.details == "no test result"
        }));
    }

    #[test]
    fn publish_blocks_when_only_nul_prefixed_measured_capability_is_present() {
        let matrix = ProfileMatrix {
            required: BTreeMap::from([(Profile::Mvp, vec!["auth".to_string()])]),
        };
        let results = vec![cap("\0auth", true)];

        let err = publish_claim(&matrix, Profile::Mvp, &results, 1).unwrap_err();

        assert_eq!(err.code(), "CPM_CLAIM_BLOCKED");
        assert!(err.to_string().contains("0/1 capabilities passed"));
    }

    #[test]
    fn duplicate_nul_measured_capability_does_not_override_valid_failure() {
        let matrix = ProfileMatrix {
            required: BTreeMap::from([(Profile::Mvp, vec!["auth".to_string()])]),
        };
        let results = vec![cap("auth", false), cap("auth\0shadow", true)];

        let eval = evaluate_claim(&matrix, Profile::Mvp, &results, 1).unwrap();

        assert_eq!(eval.verdict, "FAIL");
        assert_eq!(eval.metadata.capabilities_passed, 0);
        assert!(eval.results.iter().any(|result| {
            result.capability == "auth" && !result.passed && result.details == "failed"
        }));
    }

    #[test]
    fn matrix_with_nul_required_capability_without_validation_still_blocks_clean_result() {
        let matrix = ProfileMatrix {
            required: BTreeMap::from([(Profile::Mvp, vec!["auth\0shadow".to_string()])]),
        };

        let err = publish_claim(&matrix, Profile::Mvp, &[cap("auth", true)], 1).unwrap_err();
        let eval = evaluate_claim(&matrix, Profile::Mvp, &[cap("auth", true)], 1).unwrap();

        assert_eq!(err.code(), "CPM_CLAIM_BLOCKED");
        assert_eq!(eval.metadata.capabilities_passed, 0);
        assert_eq!(eval.metadata.capabilities_total, 1);
    }
}
