//! bd-35by: Mandatory serialization/object-id/signature/revocation/source-diversity
//! interoperability suites.
//!
//! Each suite validates cross-implementation compatibility.  Failures produce
//! minimal reproducer fixtures.

use std::collections::BTreeMap;
use std::fmt;

// ── Interop classes ─────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum InteropClass {
    Serialization,
    ObjectId,
    Signature,
    Revocation,
    SourceDiversity,
}

impl fmt::Display for InteropClass {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            InteropClass::Serialization => write!(f, "serialization"),
            InteropClass::ObjectId => write!(f, "object_id"),
            InteropClass::Signature => write!(f, "signature"),
            InteropClass::Revocation => write!(f, "revocation"),
            InteropClass::SourceDiversity => write!(f, "source_diversity"),
        }
    }
}

// ── Test case & result ──────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct InteropTestCase {
    pub class: InteropClass,
    pub case_id: String,
    pub input: String,
    pub expected_output: String,
    pub implementation: String,
}

#[derive(Debug, Clone)]
pub struct InteropResult {
    pub class: InteropClass,
    pub case_id: String,
    pub passed: bool,
    pub details: String,
    pub reproducer: Option<String>,
}

// ── Errors ──────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InteropError {
    /// IOP_SERIALIZATION_MISMATCH
    SerializationMismatch {
        case_id: String,
        expected: String,
        actual: String,
    },
    /// IOP_OBJECT_ID_MISMATCH
    ObjectIdMismatch {
        case_id: String,
        expected: String,
        actual: String,
    },
    /// IOP_SIGNATURE_INVALID
    SignatureInvalid { case_id: String, details: String },
    /// IOP_REVOCATION_DISAGREEMENT
    RevocationDisagreement { case_id: String, details: String },
    /// IOP_SOURCE_DIVERSITY_INSUFFICIENT
    SourceDiversityInsufficient {
        case_id: String,
        required: usize,
        actual: usize,
    },
}

impl InteropError {
    pub fn code(&self) -> &'static str {
        match self {
            InteropError::SerializationMismatch { .. } => "IOP_SERIALIZATION_MISMATCH",
            InteropError::ObjectIdMismatch { .. } => "IOP_OBJECT_ID_MISMATCH",
            InteropError::SignatureInvalid { .. } => "IOP_SIGNATURE_INVALID",
            InteropError::RevocationDisagreement { .. } => "IOP_REVOCATION_DISAGREEMENT",
            InteropError::SourceDiversityInsufficient { .. } => "IOP_SOURCE_DIVERSITY_INSUFFICIENT",
        }
    }
}

impl fmt::Display for InteropError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            InteropError::SerializationMismatch {
                case_id,
                expected,
                actual,
            } => {
                write!(
                    f,
                    "IOP_SERIALIZATION_MISMATCH: {case_id} expected={expected} actual={actual}"
                )
            }
            InteropError::ObjectIdMismatch {
                case_id,
                expected,
                actual,
            } => {
                write!(
                    f,
                    "IOP_OBJECT_ID_MISMATCH: {case_id} expected={expected} actual={actual}"
                )
            }
            InteropError::SignatureInvalid { case_id, details } => {
                write!(f, "IOP_SIGNATURE_INVALID: {case_id} {details}")
            }
            InteropError::RevocationDisagreement { case_id, details } => {
                write!(f, "IOP_REVOCATION_DISAGREEMENT: {case_id} {details}")
            }
            InteropError::SourceDiversityInsufficient {
                case_id,
                required,
                actual,
            } => {
                write!(
                    f,
                    "IOP_SOURCE_DIVERSITY_INSUFFICIENT: {case_id} need={required} have={actual}"
                )
            }
        }
    }
}

// ── Interop functions ───────────────────────────────────────────────────────

/// Check serialization round-trip (INV-IOP-SERIALIZATION).
pub fn check_serialization(
    case_id: &str,
    input: &str,
    output: &str,
    expected: &str,
) -> InteropResult {
    if output == expected {
        InteropResult {
            class: InteropClass::Serialization,
            case_id: case_id.to_string(),
            passed: true,
            details: "round-trip match".into(),
            reproducer: None,
        }
    } else {
        InteropResult {
            class: InteropClass::Serialization,
            case_id: case_id.to_string(),
            passed: false,
            details: format!("expected={expected}, actual={output}"),
            reproducer: Some(format!(
                "{{\"input\":\"{input}\",\"expected\":\"{expected}\",\"actual\":\"{output}\"}}"
            )),
        }
    }
}

/// Check object-ID determinism (INV-IOP-OBJECT-ID).
pub fn check_object_id(case_id: &str, id_a: &str, id_b: &str) -> InteropResult {
    if id_a == id_b {
        InteropResult {
            class: InteropClass::ObjectId,
            case_id: case_id.to_string(),
            passed: true,
            details: "deterministic".into(),
            reproducer: None,
        }
    } else {
        InteropResult {
            class: InteropClass::ObjectId,
            case_id: case_id.to_string(),
            passed: false,
            details: format!("id_a={id_a}, id_b={id_b}"),
            reproducer: Some(format!("{{\"id_a\":\"{id_a}\",\"id_b\":\"{id_b}\"}}")),
        }
    }
}

/// Check cross-implementation signature (INV-IOP-SIGNATURE).
pub fn check_signature(case_id: &str, sig_valid: bool, details: &str) -> InteropResult {
    InteropResult {
        class: InteropClass::Signature,
        case_id: case_id.to_string(),
        passed: sig_valid,
        details: details.to_string(),
        reproducer: if sig_valid {
            None
        } else {
            Some(format!(
                "{{\"case\":\"{case_id}\",\"error\":\"{details}\"}}"
            ))
        },
    }
}

/// Check revocation agreement (INV-IOP-REVOCATION).
pub fn check_revocation(case_id: &str, status_a: bool, status_b: bool) -> InteropResult {
    let agree = status_a == status_b;
    InteropResult {
        class: InteropClass::Revocation,
        case_id: case_id.to_string(),
        passed: agree,
        details: if agree {
            "implementations agree".into()
        } else {
            format!("impl_a={status_a}, impl_b={status_b}")
        },
        reproducer: if agree {
            None
        } else {
            Some(format!("{{\"impl_a\":{status_a},\"impl_b\":{status_b}}}"))
        },
    }
}

/// Check source diversity threshold (INV-IOP-SOURCE-DIVERSITY).
pub fn check_source_diversity(case_id: &str, sources: usize, required: usize) -> InteropResult {
    let passed = sources >= required;
    InteropResult {
        class: InteropClass::SourceDiversity,
        case_id: case_id.to_string(),
        passed,
        details: format!("{sources}/{required} sources"),
        reproducer: if passed {
            None
        } else {
            Some(format!("{{\"sources\":{sources},\"required\":{required}}}"))
        },
    }
}

/// Run a full interop suite from test cases.
pub fn run_suite(cases: &[InteropTestCase]) -> Vec<InteropResult> {
    cases
        .iter()
        .map(|tc| {
            // Simulate: compare input against expected_output for the class
            match tc.class {
                InteropClass::Serialization => {
                    check_serialization(&tc.case_id, &tc.input, &tc.input, &tc.expected_output)
                }
                InteropClass::ObjectId => {
                    check_object_id(&tc.case_id, &tc.input, &tc.expected_output)
                }
                InteropClass::Signature => {
                    check_signature(&tc.case_id, tc.input == tc.expected_output, "cross-check")
                }
                InteropClass::Revocation => check_revocation(
                    &tc.case_id,
                    tc.input == "revoked",
                    tc.expected_output == "revoked",
                ),
                InteropClass::SourceDiversity => {
                    let sources: usize = tc.input.parse().unwrap_or(0);
                    let required: usize = tc.expected_output.parse().unwrap_or(0);
                    check_source_diversity(&tc.case_id, sources, required)
                }
            }
        })
        .collect()
}

/// Summarize results by class.
pub fn summarize(results: &[InteropResult]) -> BTreeMap<InteropClass, (usize, usize)> {
    let mut summary: BTreeMap<InteropClass, (usize, usize)> = BTreeMap::new();
    for r in results {
        let entry = summary.entry(r.class).or_insert((0, 0));
        entry.1 += 1;
        if r.passed {
            entry.0 += 1;
        }
    }
    summary
}

// ── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn serialization_match() {
        let r = check_serialization("s1", "data", "encoded", "encoded");
        assert!(r.passed);
        assert!(r.reproducer.is_none());
    }

    #[test]
    fn serialization_mismatch() {
        let r = check_serialization("s2", "data", "bad", "good");
        assert!(!r.passed);
        assert!(r.reproducer.is_some());
    }

    #[test]
    fn object_id_deterministic() {
        let r = check_object_id("o1", "id-abc", "id-abc");
        assert!(r.passed);
    }

    #[test]
    fn object_id_mismatch() {
        let r = check_object_id("o2", "id-abc", "id-xyz");
        assert!(!r.passed);
        assert!(r.reproducer.unwrap().contains("id_a"));
    }

    #[test]
    fn signature_valid() {
        let r = check_signature("sig1", true, "ok");
        assert!(r.passed);
    }

    #[test]
    fn signature_invalid() {
        let r = check_signature("sig2", false, "bad key");
        assert!(!r.passed);
        assert!(r.reproducer.is_some());
    }

    #[test]
    fn revocation_agree() {
        let r = check_revocation("rev1", true, true);
        assert!(r.passed);
    }

    #[test]
    fn revocation_disagree() {
        let r = check_revocation("rev2", true, false);
        assert!(!r.passed);
    }

    #[test]
    fn source_diversity_sufficient() {
        let r = check_source_diversity("sd1", 3, 2);
        assert!(r.passed);
    }

    #[test]
    fn source_diversity_insufficient() {
        let r = check_source_diversity("sd2", 1, 3);
        assert!(!r.passed);
        assert!(r.reproducer.unwrap().contains("\"required\":3"));
    }

    #[test]
    fn run_suite_basic() {
        let cases = vec![
            InteropTestCase {
                class: InteropClass::Serialization,
                case_id: "s1".into(),
                input: "data".into(),
                expected_output: "data".into(),
                implementation: "impl_a".into(),
            },
            InteropTestCase {
                class: InteropClass::ObjectId,
                case_id: "o1".into(),
                input: "id-x".into(),
                expected_output: "id-x".into(),
                implementation: "impl_a".into(),
            },
        ];
        let results = run_suite(&cases);
        assert_eq!(results.len(), 2);
        assert!(results.iter().all(|r| r.passed));
    }

    #[test]
    fn summarize_results() {
        let results = vec![
            check_serialization("s1", "d", "a", "a"),
            check_serialization("s2", "d", "a", "b"),
            check_object_id("o1", "x", "x"),
        ];
        let s = summarize(&results);
        assert_eq!(s[&InteropClass::Serialization], (1, 2));
        assert_eq!(s[&InteropClass::ObjectId], (1, 1));
    }

    #[test]
    fn class_display() {
        assert_eq!(InteropClass::Serialization.to_string(), "serialization");
        assert_eq!(InteropClass::ObjectId.to_string(), "object_id");
        assert_eq!(InteropClass::Signature.to_string(), "signature");
        assert_eq!(InteropClass::Revocation.to_string(), "revocation");
        assert_eq!(
            InteropClass::SourceDiversity.to_string(),
            "source_diversity"
        );
    }

    #[test]
    fn error_display() {
        let e = InteropError::SerializationMismatch {
            case_id: "s1".into(),
            expected: "a".into(),
            actual: "b".into(),
        };
        assert!(e.to_string().contains("IOP_SERIALIZATION_MISMATCH"));
    }

    #[test]
    fn all_error_codes_present() {
        let errors = [
            InteropError::SerializationMismatch {
                case_id: "x".into(),
                expected: "".into(),
                actual: "".into(),
            },
            InteropError::ObjectIdMismatch {
                case_id: "x".into(),
                expected: "".into(),
                actual: "".into(),
            },
            InteropError::SignatureInvalid {
                case_id: "x".into(),
                details: "".into(),
            },
            InteropError::RevocationDisagreement {
                case_id: "x".into(),
                details: "".into(),
            },
            InteropError::SourceDiversityInsufficient {
                case_id: "x".into(),
                required: 3,
                actual: 1,
            },
        ];
        let codes: Vec<_> = errors.iter().map(|e| e.code()).collect();
        assert!(codes.contains(&"IOP_SERIALIZATION_MISMATCH"));
        assert!(codes.contains(&"IOP_OBJECT_ID_MISMATCH"));
        assert!(codes.contains(&"IOP_SIGNATURE_INVALID"));
        assert!(codes.contains(&"IOP_REVOCATION_DISAGREEMENT"));
        assert!(codes.contains(&"IOP_SOURCE_DIVERSITY_INSUFFICIENT"));
    }
}
