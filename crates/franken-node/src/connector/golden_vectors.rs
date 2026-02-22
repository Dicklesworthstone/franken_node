//! bd-3n2u: Formal schema spec files and golden vectors for serialization,
//! signatures, and control-channel frames.
//!
//! Schemas and vectors are versioned.  A verification runner validates
//! implementations against the full vector suite.

use std::collections::HashMap;
use std::fmt;

// ── Schema categories ───────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SchemaCategory {
    Serialization,
    Signature,
    ControlFrame,
}

impl fmt::Display for SchemaCategory {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SchemaCategory::Serialization => write!(f, "serialization"),
            SchemaCategory::Signature => write!(f, "signature"),
            SchemaCategory::ControlFrame => write!(f, "control_frame"),
        }
    }
}

// ── Schema spec ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct ChangelogEntry {
    pub version: u32,
    pub description: String,
}

#[derive(Debug, Clone)]
pub struct SchemaSpec {
    pub category: SchemaCategory,
    pub version: u32,
    pub content_hash: String,
    pub changelog: Vec<ChangelogEntry>,
}

// ── Golden vectors ──────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct GoldenVector {
    pub category: SchemaCategory,
    pub vector_id: String,
    pub input: String,
    pub expected_output: String,
    pub description: String,
}

// ── Verification result ─────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct VectorVerificationResult {
    pub vector_id: String,
    pub passed: bool,
    pub details: String,
}

// ── Errors ──────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SchemaError {
    /// GSV_MISSING_SCHEMA
    MissingSchema(String),
    /// GSV_MISSING_VECTOR
    MissingVector(String),
    /// GSV_VECTOR_MISMATCH
    VectorMismatch {
        vector_id: String,
        expected: String,
        actual: String,
    },
    /// GSV_NO_CHANGELOG
    NoChangelog(String),
    /// GSV_INVALID_VERSION
    InvalidVersion(String),
}

impl SchemaError {
    pub fn code(&self) -> &'static str {
        match self {
            SchemaError::MissingSchema(_) => "GSV_MISSING_SCHEMA",
            SchemaError::MissingVector(_) => "GSV_MISSING_VECTOR",
            SchemaError::VectorMismatch { .. } => "GSV_VECTOR_MISMATCH",
            SchemaError::NoChangelog(_) => "GSV_NO_CHANGELOG",
            SchemaError::InvalidVersion(_) => "GSV_INVALID_VERSION",
        }
    }
}

impl fmt::Display for SchemaError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SchemaError::MissingSchema(c) => write!(f, "GSV_MISSING_SCHEMA: {c}"),
            SchemaError::MissingVector(c) => write!(f, "GSV_MISSING_VECTOR: {c}"),
            SchemaError::VectorMismatch {
                vector_id,
                expected,
                actual,
            } => {
                write!(
                    f,
                    "GSV_VECTOR_MISMATCH: {vector_id} expected={expected} actual={actual}"
                )
            }
            SchemaError::NoChangelog(c) => write!(f, "GSV_NO_CHANGELOG: {c}"),
            SchemaError::InvalidVersion(c) => write!(f, "GSV_INVALID_VERSION: {c}"),
        }
    }
}

// ── Schema & vector registry ────────────────────────────────────────────────

#[derive(Debug, Default)]
pub struct SchemaRegistry {
    schemas: HashMap<SchemaCategory, SchemaSpec>,
    vectors: HashMap<SchemaCategory, Vec<GoldenVector>>,
}

impl SchemaRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a schema spec.
    pub fn register_schema(&mut self, spec: SchemaSpec) -> Result<(), SchemaError> {
        if spec.version == 0 {
            return Err(SchemaError::InvalidVersion(spec.category.to_string()));
        }
        if spec.changelog.is_empty() {
            return Err(SchemaError::NoChangelog(spec.category.to_string()));
        }
        self.schemas.insert(spec.category, spec);
        Ok(())
    }

    /// Add a golden vector.
    pub fn add_vector(&mut self, vector: GoldenVector) -> Result<(), SchemaError> {
        if !self.schemas.contains_key(&vector.category) {
            return Err(SchemaError::MissingSchema(vector.category.to_string()));
        }
        self.vectors
            .entry(vector.category)
            .or_default()
            .push(vector);
        Ok(())
    }

    /// Validate that all three categories have schemas and vectors.
    pub fn validate(&self) -> Result<(), SchemaError> {
        let required = [
            SchemaCategory::Serialization,
            SchemaCategory::Signature,
            SchemaCategory::ControlFrame,
        ];

        for cat in &required {
            if !self.schemas.contains_key(cat) {
                return Err(SchemaError::MissingSchema(cat.to_string()));
            }
            let count = self.vectors.get(cat).map_or(0, |v| v.len());
            if count == 0 {
                return Err(SchemaError::MissingVector(cat.to_string()));
            }
        }

        Ok(())
    }

    /// Verify all vectors against a provided implementation function.
    pub fn verify_vectors<F>(&self, eval: F) -> Vec<VectorVerificationResult>
    where
        F: Fn(&GoldenVector) -> String,
    {
        let mut results = Vec::new();
        for vectors in self.vectors.values() {
            for v in vectors {
                let actual = eval(v);
                let passed = actual == v.expected_output;
                results.push(VectorVerificationResult {
                    vector_id: v.vector_id.clone(),
                    passed,
                    details: if passed {
                        "match".into()
                    } else {
                        format!("expected={}, actual={actual}", v.expected_output)
                    },
                });
            }
        }
        results
    }

    pub fn schema_count(&self) -> usize {
        self.schemas.len()
    }

    pub fn vector_count(&self, category: SchemaCategory) -> usize {
        self.vectors.get(&category).map_or(0, |v| v.len())
    }
}

// ── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_spec(cat: SchemaCategory, version: u32) -> SchemaSpec {
        SchemaSpec {
            category: cat,
            version,
            content_hash: format!("sha256:{cat}_{version}"),
            changelog: vec![ChangelogEntry {
                version,
                description: "initial".into(),
            }],
        }
    }

    fn make_vector(cat: SchemaCategory, id: &str) -> GoldenVector {
        GoldenVector {
            category: cat,
            vector_id: id.to_string(),
            input: format!("input_{id}"),
            expected_output: format!("output_{id}"),
            description: format!("test vector {id}"),
        }
    }

    fn populated_registry() -> SchemaRegistry {
        let mut r = SchemaRegistry::new();
        for cat in [
            SchemaCategory::Serialization,
            SchemaCategory::Signature,
            SchemaCategory::ControlFrame,
        ] {
            r.register_schema(make_spec(cat, 1)).unwrap();
            r.add_vector(make_vector(cat, &format!("{cat}_v1")))
                .unwrap();
        }
        r
    }

    #[test]
    fn register_valid_schema() {
        let mut r = SchemaRegistry::new();
        r.register_schema(make_spec(SchemaCategory::Serialization, 1))
            .unwrap();
        assert_eq!(r.schema_count(), 1);
    }

    #[test]
    fn reject_version_zero() {
        let mut r = SchemaRegistry::new();
        let err = r
            .register_schema(make_spec(SchemaCategory::Serialization, 0))
            .unwrap_err();
        assert_eq!(err.code(), "GSV_INVALID_VERSION");
    }

    #[test]
    fn reject_no_changelog() {
        let mut r = SchemaRegistry::new();
        let spec = SchemaSpec {
            category: SchemaCategory::Serialization,
            version: 1,
            content_hash: "hash".into(),
            changelog: vec![],
        };
        let err = r.register_schema(spec).unwrap_err();
        assert_eq!(err.code(), "GSV_NO_CHANGELOG");
    }

    #[test]
    fn add_vector_requires_schema() {
        let mut r = SchemaRegistry::new();
        let err = r
            .add_vector(make_vector(SchemaCategory::Serialization, "v1"))
            .unwrap_err();
        assert_eq!(err.code(), "GSV_MISSING_SCHEMA");
    }

    #[test]
    fn validate_complete_registry() {
        let r = populated_registry();
        r.validate().unwrap();
    }

    #[test]
    fn validate_missing_schema() {
        let mut r = SchemaRegistry::new();
        r.register_schema(make_spec(SchemaCategory::Serialization, 1))
            .unwrap();
        r.add_vector(make_vector(SchemaCategory::Serialization, "v1"))
            .unwrap();
        let err = r.validate().unwrap_err();
        assert_eq!(err.code(), "GSV_MISSING_SCHEMA");
    }

    #[test]
    fn validate_missing_vectors() {
        let mut r = SchemaRegistry::new();
        for cat in [
            SchemaCategory::Serialization,
            SchemaCategory::Signature,
            SchemaCategory::ControlFrame,
        ] {
            r.register_schema(make_spec(cat, 1)).unwrap();
        }
        // No vectors added
        let err = r.validate().unwrap_err();
        assert_eq!(err.code(), "GSV_MISSING_VECTOR");
    }

    #[test]
    fn verify_vectors_all_pass() {
        let r = populated_registry();
        let results = r.verify_vectors(|v| v.expected_output.clone());
        assert_eq!(results.len(), 3);
        assert!(results.iter().all(|r| r.passed));
    }

    #[test]
    fn verify_vectors_mismatch() {
        let r = populated_registry();
        let results = r.verify_vectors(|_v| "wrong".to_string());
        assert!(results.iter().all(|r| !r.passed));
    }

    #[test]
    fn vector_count_per_category() {
        let r = populated_registry();
        assert_eq!(r.vector_count(SchemaCategory::Serialization), 1);
        assert_eq!(r.vector_count(SchemaCategory::Signature), 1);
        assert_eq!(r.vector_count(SchemaCategory::ControlFrame), 1);
    }

    #[test]
    fn category_display() {
        assert_eq!(SchemaCategory::Serialization.to_string(), "serialization");
        assert_eq!(SchemaCategory::Signature.to_string(), "signature");
        assert_eq!(SchemaCategory::ControlFrame.to_string(), "control_frame");
    }

    #[test]
    fn error_display() {
        let e = SchemaError::MissingSchema("ser".into());
        assert!(e.to_string().contains("GSV_MISSING_SCHEMA"));
    }

    #[test]
    fn all_error_codes_present() {
        let errors = [
            SchemaError::MissingSchema("x".into()),
            SchemaError::MissingVector("x".into()),
            SchemaError::VectorMismatch {
                vector_id: "x".into(),
                expected: "a".into(),
                actual: "b".into(),
            },
            SchemaError::NoChangelog("x".into()),
            SchemaError::InvalidVersion("x".into()),
        ];
        let codes: Vec<_> = errors.iter().map(|e| e.code()).collect();
        assert!(codes.contains(&"GSV_MISSING_SCHEMA"));
        assert!(codes.contains(&"GSV_MISSING_VECTOR"));
        assert!(codes.contains(&"GSV_VECTOR_MISMATCH"));
        assert!(codes.contains(&"GSV_NO_CHANGELOG"));
        assert!(codes.contains(&"GSV_INVALID_VERSION"));
    }
}
