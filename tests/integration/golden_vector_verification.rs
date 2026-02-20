//! Integration tests for bd-3n2u: Golden vector verification.

use frankenengine_node::connector::golden_vectors::*;

fn populated_registry() -> SchemaRegistry {
    let mut r = SchemaRegistry::new();
    for cat in [SchemaCategory::Serialization, SchemaCategory::Signature, SchemaCategory::ControlFrame] {
        r.register_schema(SchemaSpec {
            category: cat,
            version: 1,
            content_hash: format!("sha256:{cat}_1"),
            changelog: vec![ChangelogEntry {
                version: 1,
                description: "initial".into(),
            }],
        })
        .unwrap();
        r.add_vector(GoldenVector {
            category: cat,
            vector_id: format!("{cat}_v1"),
            input: "test_input".into(),
            expected_output: "test_output".into(),
            description: format!("golden vector for {cat}"),
        })
        .unwrap();
    }
    r
}

#[test]
fn inv_gsv_schema() {
    let r = populated_registry();
    assert_eq!(r.schema_count(), 3);
    r.validate().unwrap();
}

#[test]
fn inv_gsv_vectors() {
    let r = populated_registry();
    for cat in [SchemaCategory::Serialization, SchemaCategory::Signature, SchemaCategory::ControlFrame] {
        assert!(r.vector_count(cat) >= 1);
    }
}

#[test]
fn inv_gsv_verified() {
    let r = populated_registry();
    let results = r.verify_vectors(|v| v.expected_output.clone());
    assert!(results.iter().all(|r| r.passed));
    let bad_results = r.verify_vectors(|_v| "wrong".to_string());
    assert!(bad_results.iter().all(|r| !r.passed));
}

#[test]
fn inv_gsv_changelog() {
    let mut r = SchemaRegistry::new();
    let err = r
        .register_schema(SchemaSpec {
            category: SchemaCategory::Serialization,
            version: 1,
            content_hash: "hash".into(),
            changelog: vec![],
        })
        .unwrap_err();
    assert_eq!(err.code(), "GSV_NO_CHANGELOG");
}
