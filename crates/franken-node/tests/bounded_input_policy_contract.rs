use frankenengine_node::{
    capacity_defaults::bounded_input::{
        AUDIT_BOUNDED_INPUT_REJECTED, BoundedInputPolicy, ERR_BOUNDED_INPUT_CAP_EXCEEDED,
    },
    control_plane::{
        audience_token::{
            ERR_ABT_TOKEN_TOO_LARGE, TOKEN_AUDIENCE_INPUT_POLICY, TOKEN_FIELD_INPUT_POLICY,
            TOKEN_PREIMAGE_INPUT_POLICY, TOKEN_SIGNATURE_INPUT_POLICY,
        },
        fleet_transport::{ERR_FLEET_JSONL_LINE_TOO_LARGE, FLEET_ACTION_RECORD_LINE_POLICY},
    },
    extensions::artifact_contract::{
        ARTIFACT_CAPABILITY_LIST_POLICY, ARTIFACT_TOKEN_INPUT_POLICY, error_codes,
    },
};

fn representative_policies() -> [BoundedInputPolicy; 7] {
    [
        TOKEN_FIELD_INPUT_POLICY,
        TOKEN_AUDIENCE_INPUT_POLICY,
        TOKEN_PREIMAGE_INPUT_POLICY,
        TOKEN_SIGNATURE_INPUT_POLICY,
        ARTIFACT_TOKEN_INPUT_POLICY,
        ARTIFACT_CAPABILITY_LIST_POLICY,
        FLEET_ACTION_RECORD_LINE_POLICY,
    ]
}

#[test]
fn bounded_input_policy_registry_names_representative_caps() {
    let policies = representative_policies();

    for policy in policies {
        assert!(!policy.surface.is_empty());
        assert!(!policy.field.is_empty());
        assert!(policy.max_bytes > 0);
        assert!(!policy.error_code.is_empty());
        assert_eq!(policy.audit_code, AUDIT_BOUNDED_INPUT_REJECTED);
        assert!(!policy.rationale.is_empty());
    }

    assert_eq!(TOKEN_FIELD_INPUT_POLICY.error_code, ERR_ABT_TOKEN_TOO_LARGE);
    assert_eq!(
        ARTIFACT_CAPABILITY_LIST_POLICY.error_code,
        error_codes::ERR_ARTIFACT_INVALID_CONTRACT
    );
    assert_eq!(
        FLEET_ACTION_RECORD_LINE_POLICY.error_code,
        ERR_FLEET_JSONL_LINE_TOO_LARGE
    );
    assert_eq!(
        ERR_FLEET_JSONL_LINE_TOO_LARGE,
        ERR_BOUNDED_INPUT_CAP_EXCEEDED
    );
}

#[test]
fn bounded_input_policies_fail_closed_at_one_past_cap() {
    for policy in representative_policies() {
        policy
            .validate_len(policy.max_bytes)
            .expect("boundary length must be accepted");

        let err = policy
            .validate_len(policy.max_bytes.saturating_add(1))
            .expect_err("one-past-cap length must fail closed");

        assert_eq!(err.surface, policy.surface);
        assert_eq!(err.field, policy.field);
        assert_eq!(err.max_bytes, policy.max_bytes);
        assert_eq!(err.actual_bytes, policy.max_bytes + 1);
        assert_eq!(err.error_code, policy.error_code);
        assert_eq!(err.audit_code, AUDIT_BOUNDED_INPUT_REJECTED);
        assert!(err.to_string().contains(policy.error_code));
        assert!(err.to_string().contains(policy.audit_code));
    }
}

#[test]
fn bounded_input_policies_cover_three_independent_surfaces() {
    let surfaces: std::collections::BTreeSet<_> = representative_policies()
        .iter()
        .map(|policy| policy.surface)
        .collect();

    assert!(surfaces.contains("control_plane.audience_token"));
    assert!(surfaces.contains("extensions.artifact_contract"));
    assert!(surfaces.contains("control_plane.fleet_transport"));
    assert_eq!(surfaces.len(), 3);
}
