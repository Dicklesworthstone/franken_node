//! bd-3n2u: Formal schema spec files and golden vectors for serialization,
//! signatures, and control-channel frames.
//!
//! Schemas and vectors are versioned.  A verification runner validates
//! implementations against the full vector suite.

use std::collections::BTreeMap;
use std::fmt;

const MAX_VECTORS_PER_CATEGORY: usize = 1024;

fn push_bounded<T>(items: &mut Vec<T>, item: T, cap: usize) {
    if cap == 0 {
        items.clear();
        return;
    }
    if items.len() >= cap {
        let overflow = items.len().saturating_sub(cap).saturating_add(1);
        items.drain(0..overflow);
    }
    items.push(item);
}

// ── Schema categories ───────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
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

/// A changelog entry describing changes in a specific schema version.
///
/// Used to track the evolution of schemas over time, providing human-readable
/// descriptions of what changed between versions.
///
/// # Examples
///
/// ```
/// use frankenengine_node::connector::golden_vectors::ChangelogEntry;
///
/// let entry = ChangelogEntry {
///     version: 2,
///     description: "Added support for nested objects".to_string(),
/// };
/// ```
#[derive(Debug, Clone)]
pub struct ChangelogEntry {
    /// The schema version this entry describes.
    pub version: u32,
    /// Human-readable description of changes in this version.
    pub description: String,
}

/// A complete schema specification for a particular category.
///
/// Defines the structure and version history of a data schema used throughout
/// the connector system. Each schema has a unique category, version number,
/// content hash for integrity verification, and changelog tracking evolution.
///
/// # Examples
///
/// ```
/// use frankenengine_node::connector::golden_vectors::{
///     SchemaSpec, ChangelogEntry, SchemaCategory
/// };
///
/// let spec = SchemaSpec {
///     category: SchemaCategory::Connector,
///     version: 2,
///     content_hash: "abc123...".to_string(),
///     changelog: vec![
///         ChangelogEntry {
///             version: 1,
///             description: "Initial schema".to_string(),
///         },
///         ChangelogEntry {
///             version: 2,
///             description: "Added validation rules".to_string(),
///         },
///     ],
/// };
/// ```
#[derive(Debug, Clone)]
pub struct SchemaSpec {
    /// The category this schema specification belongs to.
    pub category: SchemaCategory,
    /// The current version number of this schema.
    pub version: u32,
    /// Hash of the schema content for integrity verification.
    pub content_hash: String,
    /// Complete changelog tracking evolution across versions.
    pub changelog: Vec<ChangelogEntry>,
}

// ── Golden vectors ──────────────────────────────────────────────────────────

/// A golden vector test case for schema validation.
///
/// Contains a known input/output pair used to verify that schema processing
/// produces consistent, expected results. Golden vectors serve as regression
/// tests ensuring that schema changes don't break existing functionality.
///
/// # Examples
///
/// ```
/// use frankenengine_node::connector::golden_vectors::{
///     GoldenVector, SchemaCategory
/// };
///
/// let vector = GoldenVector {
///     category: SchemaCategory::Connector,
///     vector_id: "basic_transform_001".to_string(),
///     input: r#"{"name": "test", "value": 42}"#.to_string(),
///     expected_output: r#"{"processed_name": "test", "doubled_value": 84}"#.to_string(),
///     description: "Basic transformation with name and doubled value".to_string(),
/// };
/// ```
#[derive(Debug, Clone)]
pub struct GoldenVector {
    /// The schema category this vector tests.
    pub category: SchemaCategory,
    /// Unique identifier for this test vector.
    pub vector_id: String,
    /// Input data for the test case.
    pub input: String,
    /// Expected output that should be produced from the input.
    pub expected_output: String,
    /// Human-readable description of what this vector tests.
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
    schemas: BTreeMap<SchemaCategory, SchemaSpec>,
    vectors: BTreeMap<SchemaCategory, Vec<GoldenVector>>,
}

impl SchemaRegistry {
    /// Creates a new empty schema registry.
    ///
    /// # Examples
    ///
    /// ```
    /// use frankenengine_node::connector::golden_vectors::SchemaRegistry;
    ///
    /// let registry = SchemaRegistry::new();
    /// ```
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a schema specification for a given category.
    ///
    /// # Arguments
    ///
    /// * `spec` - The schema specification to register
    ///
    /// # Returns
    ///
    /// * `Ok(())` if the schema was successfully registered
    /// * `Err(SchemaError)` if the schema has invalid version (0) or missing changelog
    ///
    /// # Examples
    ///
    /// ```
    /// use frankenengine_node::connector::golden_vectors::{
    ///     SchemaRegistry, SchemaSpec, SchemaCategory
    /// };
    ///
    /// let mut registry = SchemaRegistry::new();
    /// let spec = SchemaSpec {
    ///     category: SchemaCategory::Connector,
    ///     version: 1,
    ///     changelog: "Initial version".to_string(),
    ///     canonical_example: vec![1, 2, 3],
    /// };
    ///
    /// registry.register_schema(spec).unwrap();
    /// ```
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

    /// Add a golden vector to the registry.
    ///
    /// The vector's category must have a corresponding schema registered first.
    ///
    /// # Arguments
    ///
    /// * `vector` - The golden vector to add
    ///
    /// # Returns
    ///
    /// * `Ok(())` if the vector was successfully added
    /// * `Err(SchemaError::UnknownCategory)` if no schema is registered for the vector's category
    ///
    /// # Examples
    ///
    /// ```
    /// use frankenengine_node::connector::golden_vectors::{
    ///     SchemaRegistry, SchemaSpec, GoldenVector, SchemaCategory
    /// };
    ///
    /// let mut registry = SchemaRegistry::new();
    ///
    /// // Register schema first
    /// let spec = SchemaSpec {
    ///     category: SchemaCategory::Connector,
    ///     version: 1,
    ///     changelog: "Initial version".to_string(),
    ///     canonical_example: vec![1, 2, 3],
    /// };
    /// registry.register_schema(spec).unwrap();
    ///
    /// // Add golden vector
    /// let vector = GoldenVector {
    ///     category: SchemaCategory::Connector,
    ///     input: vec![4, 5, 6],
    ///     expected_output: vec![7, 8, 9],
    /// };
    /// registry.add_vector(vector).unwrap();
    /// ```
    pub fn add_vector(&mut self, vector: GoldenVector) -> Result<(), SchemaError> {
        if !self.schemas.contains_key(&vector.category) {
            return Err(SchemaError::MissingSchema(vector.category.to_string()));
        }
        let vectors = self.vectors.entry(vector.category).or_default();
        push_bounded(vectors, vector, MAX_VECTORS_PER_CATEGORY);
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
    fn reject_zero_version_before_no_changelog() {
        let mut r = SchemaRegistry::new();
        let spec = SchemaSpec {
            category: SchemaCategory::Signature,
            version: 0,
            content_hash: "hash".into(),
            changelog: vec![],
        };

        let err = r.register_schema(spec).unwrap_err();

        assert_eq!(err.code(), "GSV_INVALID_VERSION");
    }

    #[test]
    fn failed_schema_registration_does_not_replace_existing_schema() {
        let mut r = SchemaRegistry::new();
        r.register_schema(make_spec(SchemaCategory::Serialization, 1))
            .expect("initial schema");

        let err = r
            .register_schema(make_spec(SchemaCategory::Serialization, 0))
            .expect_err("zero version rejected");

        assert_eq!(err.code(), "GSV_INVALID_VERSION");
        assert_eq!(r.schema_count(), 1);
        r.add_vector(make_vector(SchemaCategory::Serialization, "still-valid"))
            .expect("existing schema remains usable");
        assert_eq!(r.vector_count(SchemaCategory::Serialization), 1);
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
    fn failed_add_vector_does_not_create_vector_bucket() {
        let mut r = SchemaRegistry::new();

        let err = r
            .add_vector(make_vector(SchemaCategory::ControlFrame, "missing-schema"))
            .expect_err("schema is required before vectors");

        assert_eq!(err.code(), "GSV_MISSING_SCHEMA");
        assert_eq!(r.vector_count(SchemaCategory::ControlFrame), 0);
    }

    #[test]
    fn validate_complete_registry() {
        let r = populated_registry();
        r.validate().unwrap();
    }

    #[test]
    fn validate_empty_registry_reports_missing_serialization_schema_first() {
        let r = SchemaRegistry::new();

        let err = r.validate().unwrap_err();

        assert_eq!(err, SchemaError::MissingSchema("serialization".to_string()));
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
    fn validate_reports_first_schema_without_vector() {
        let mut r = SchemaRegistry::new();
        for cat in [
            SchemaCategory::Serialization,
            SchemaCategory::Signature,
            SchemaCategory::ControlFrame,
        ] {
            r.register_schema(make_spec(cat, 1)).expect("schema");
        }
        r.add_vector(make_vector(SchemaCategory::Signature, "sig-v1"))
            .expect("signature vector");
        r.add_vector(make_vector(SchemaCategory::ControlFrame, "ctrl-v1"))
            .expect("control vector");

        let err = r.validate().unwrap_err();

        assert_eq!(err, SchemaError::MissingVector("serialization".to_string()));
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
    fn verify_vectors_empty_registry_returns_no_results() {
        let r = SchemaRegistry::new();

        let results = r.verify_vectors(|v| v.expected_output.clone());

        assert!(results.is_empty());
    }

    #[test]
    fn verify_vectors_mismatch_details_include_expected_and_actual() {
        let r = populated_registry();

        let results = r.verify_vectors(|_v| "actual-output".to_string());

        assert!(results.iter().all(|result| !result.passed));
        assert!(
            results
                .iter()
                .all(|result| result.details.contains("actual=actual-output"))
        );
        assert!(
            results
                .iter()
                .all(|result| result.details.contains("expected=output_"))
        );
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
    fn vector_mismatch_display_preserves_id_expected_and_actual() {
        let err = SchemaError::VectorMismatch {
            vector_id: "vec-1".into(),
            expected: "expected-bytes".into(),
            actual: "actual-bytes".into(),
        };
        let rendered = err.to_string();

        assert!(rendered.contains("GSV_VECTOR_MISMATCH"));
        assert!(rendered.contains("vec-1"));
        assert!(rendered.contains("expected=expected-bytes"));
        assert!(rendered.contains("actual=actual-bytes"));
    }

    #[test]
    fn push_bounded_zero_capacity_drops_item_without_panic() {
        let mut values = vec![1, 2, 3];

        push_bounded(&mut values, 4, 0);

        assert!(values.is_empty());
    }

    #[test]
    fn validate_reports_missing_signature_schema_after_serialization_complete() {
        let mut r = SchemaRegistry::new();
        r.register_schema(make_spec(SchemaCategory::Serialization, 1))
            .expect("serialization schema");
        r.add_vector(make_vector(SchemaCategory::Serialization, "ser-v1"))
            .expect("serialization vector");

        let err = r.validate().expect_err("signature schema is required");

        assert_eq!(err, SchemaError::MissingSchema("signature".to_string()));
    }

    #[test]
    fn validate_reports_missing_control_frame_schema_after_prior_categories_complete() {
        let mut r = SchemaRegistry::new();
        for cat in [SchemaCategory::Serialization, SchemaCategory::Signature] {
            r.register_schema(make_spec(cat, 1)).expect("schema");
            r.add_vector(make_vector(cat, &format!("{cat}-v1")))
                .expect("vector");
        }

        let err = r.validate().expect_err("control frame schema is required");

        assert_eq!(err, SchemaError::MissingSchema("control_frame".to_string()));
    }

    #[test]
    fn validate_reports_missing_signature_vector_before_control_frame_vector() {
        let mut r = SchemaRegistry::new();
        for cat in [
            SchemaCategory::Serialization,
            SchemaCategory::Signature,
            SchemaCategory::ControlFrame,
        ] {
            r.register_schema(make_spec(cat, 1)).expect("schema");
        }
        r.add_vector(make_vector(SchemaCategory::Serialization, "ser-v1"))
            .expect("serialization vector");
        r.add_vector(make_vector(SchemaCategory::ControlFrame, "ctrl-v1"))
            .expect("control vector");

        let err = r.validate().expect_err("signature vector is required");

        assert_eq!(err, SchemaError::MissingVector("signature".to_string()));
    }

    #[test]
    fn failed_no_changelog_registration_does_not_replace_existing_schema() {
        let mut r = SchemaRegistry::new();
        r.register_schema(make_spec(SchemaCategory::Signature, 1))
            .expect("initial schema");
        let invalid = SchemaSpec {
            category: SchemaCategory::Signature,
            version: 2,
            content_hash: "sha256:new-signature".into(),
            changelog: vec![],
        };

        let err = r
            .register_schema(invalid)
            .expect_err("empty changelog is rejected");

        assert_eq!(err.code(), "GSV_NO_CHANGELOG");
        assert_eq!(r.schema_count(), 1);
        assert_eq!(
            r.schemas
                .get(&SchemaCategory::Signature)
                .expect("original schema remains")
                .version,
            1
        );
    }

    #[test]
    fn failed_signature_schema_registration_keeps_vector_add_rejected() {
        let mut r = SchemaRegistry::new();
        let invalid = SchemaSpec {
            category: SchemaCategory::Signature,
            version: 0,
            content_hash: "sha256:bad-signature".into(),
            changelog: vec![ChangelogEntry {
                version: 0,
                description: "invalid".into(),
            }],
        };

        let schema_err = r
            .register_schema(invalid)
            .expect_err("zero version is rejected");
        let vector_err = r
            .add_vector(make_vector(SchemaCategory::Signature, "sig-after-reject"))
            .expect_err("rejected schema must not create a category");

        assert_eq!(schema_err.code(), "GSV_INVALID_VERSION");
        assert_eq!(
            vector_err,
            SchemaError::MissingSchema("signature".to_string())
        );
        assert_eq!(r.schema_count(), 0);
        assert_eq!(r.vector_count(SchemaCategory::Signature), 0);
    }

    #[test]
    fn verify_vectors_mismatch_preserves_vector_ids() {
        let r = populated_registry();

        let results = r.verify_vectors(|_v| "wrong-output".to_string());
        let ids: Vec<_> = results
            .iter()
            .map(|result| result.vector_id.as_str())
            .collect();

        assert_eq!(results.len(), 3);
        assert!(results.iter().all(|result| !result.passed));
        assert!(ids.contains(&"serialization_v1"));
        assert!(ids.contains(&"signature_v1"));
        assert!(ids.contains(&"control_frame_v1"));
    }

    #[test]
    fn push_bounded_retains_latest_items_when_over_capacity() {
        let mut values = Vec::new();

        for value in 0..5 {
            push_bounded(&mut values, value, 2);
        }

        assert_eq!(values, vec![3, 4]);
    }

    #[test]
    fn invalid_control_frame_schema_does_not_satisfy_validate() {
        let mut r = SchemaRegistry::new();
        for cat in [SchemaCategory::Serialization, SchemaCategory::Signature] {
            r.register_schema(make_spec(cat, 1)).expect("schema");
            r.add_vector(make_vector(cat, &format!("{cat}-v1")))
                .expect("vector");
        }
        let invalid = SchemaSpec {
            category: SchemaCategory::ControlFrame,
            version: 0,
            content_hash: "sha256:bad-control-frame".into(),
            changelog: vec![ChangelogEntry {
                version: 0,
                description: "invalid".into(),
            }],
        };

        let schema_err = r
            .register_schema(invalid)
            .expect_err("zero version is rejected");
        let validate_err = r.validate().expect_err("control frame schema is absent");

        assert_eq!(schema_err.code(), "GSV_INVALID_VERSION");
        assert_eq!(
            validate_err,
            SchemaError::MissingSchema("control_frame".to_string())
        );
        assert_eq!(r.schema_count(), 2);
        assert_eq!(r.vector_count(SchemaCategory::ControlFrame), 0);
    }

    #[test]
    fn negative_zero_version_rejected_for_each_category_without_insert() {
        let mut r = SchemaRegistry::new();

        for cat in [
            SchemaCategory::Serialization,
            SchemaCategory::Signature,
            SchemaCategory::ControlFrame,
        ] {
            let err = r.register_schema(make_spec(cat, 0)).unwrap_err();

            assert_eq!(err, SchemaError::InvalidVersion(cat.to_string()));
            assert_eq!(r.schema_count(), 0);
            assert_eq!(r.vector_count(cat), 0);
        }
    }

    #[test]
    fn negative_empty_changelog_rejected_for_each_category_without_insert() {
        let mut r = SchemaRegistry::new();

        for cat in [
            SchemaCategory::Serialization,
            SchemaCategory::Signature,
            SchemaCategory::ControlFrame,
        ] {
            let spec = SchemaSpec {
                category: cat,
                version: 1,
                content_hash: format!("sha256:{cat}:empty-changelog"),
                changelog: Vec::new(),
            };
            let err = r.register_schema(spec).unwrap_err();

            assert_eq!(err, SchemaError::NoChangelog(cat.to_string()));
            assert!(!r.schemas.contains_key(&cat));
            assert_eq!(r.schema_count(), 0);
        }
    }

    #[test]
    fn negative_invalid_schema_update_preserves_existing_schema_and_vectors() {
        let mut r = SchemaRegistry::new();
        r.register_schema(make_spec(SchemaCategory::ControlFrame, 1))
            .expect("initial schema");
        r.add_vector(make_vector(SchemaCategory::ControlFrame, "ctrl-v1"))
            .expect("initial vector");

        let err = r
            .register_schema(make_spec(SchemaCategory::ControlFrame, 0))
            .unwrap_err();

        assert_eq!(err.code(), "GSV_INVALID_VERSION");
        assert_eq!(r.schema_count(), 1);
        assert_eq!(r.vector_count(SchemaCategory::ControlFrame), 1);
        assert_eq!(
            r.schemas
                .get(&SchemaCategory::ControlFrame)
                .expect("original schema remains")
                .version,
            1
        );
    }

    #[test]
    fn negative_no_changelog_update_preserves_existing_content_hash() {
        let mut r = SchemaRegistry::new();
        r.register_schema(make_spec(SchemaCategory::Serialization, 1))
            .expect("initial schema");
        let original_hash = r
            .schemas
            .get(&SchemaCategory::Serialization)
            .expect("schema exists")
            .content_hash
            .clone();
        let invalid = SchemaSpec {
            category: SchemaCategory::Serialization,
            version: 2,
            content_hash: "sha256:replacement-should-not-land".to_string(),
            changelog: Vec::new(),
        };

        let err = r.register_schema(invalid).unwrap_err();

        assert_eq!(err.code(), "GSV_NO_CHANGELOG");
        assert_eq!(
            r.schemas
                .get(&SchemaCategory::Serialization)
                .expect("original schema remains")
                .content_hash,
            original_hash
        );
    }

    #[test]
    fn negative_add_vector_missing_schema_preserves_other_category_vectors() {
        let mut r = SchemaRegistry::new();
        r.register_schema(make_spec(SchemaCategory::Signature, 1))
            .expect("signature schema");
        r.add_vector(make_vector(SchemaCategory::Signature, "sig-v1"))
            .expect("signature vector");

        let err = r
            .add_vector(make_vector(SchemaCategory::ControlFrame, "ctrl-missing"))
            .unwrap_err();

        assert_eq!(err, SchemaError::MissingSchema("control_frame".to_string()));
        assert_eq!(r.vector_count(SchemaCategory::Signature), 1);
        assert_eq!(r.vector_count(SchemaCategory::ControlFrame), 0);
    }

    #[test]
    fn negative_verify_vectors_empty_actual_fails_every_vector() {
        let r = populated_registry();

        let results = r.verify_vectors(|_vector| String::new());

        assert_eq!(results.len(), 3);
        assert!(results.iter().all(|result| !result.passed));
        assert!(
            results
                .iter()
                .all(|result| result.details.contains("expected="))
        );
        assert!(
            results
                .iter()
                .all(|result| result.details.contains("actual="))
        );
    }

    #[test]
    fn negative_verify_vectors_category_only_output_does_not_match_golden() {
        let r = populated_registry();

        let results = r.verify_vectors(|vector| format!("output_{}", vector.category));

        assert_eq!(results.len(), 3);
        assert!(results.iter().all(|result| !result.passed));
        assert!(
            results
                .iter()
                .all(|result| result.details.contains("actual=output_"))
        );
    }

    #[test]
    fn negative_push_bounded_overfull_input_drops_oldest_entries() {
        let mut values = vec![0, 1, 2, 3];

        push_bounded(&mut values, 4, 2);

        assert_eq!(values, vec![3, 4]);
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
