use frankenengine_node::connector::capability_artifact::{
    build_extension_artifact, compute_artifact_provenance_signature, ArtifactError,
    ArtifactIdentity, ArtifactProvenance, CapabilityRequirement, ExtensionArtifactInput,
};

fn signed_input(capabilities: Vec<CapabilityRequirement>) -> ExtensionArtifactInput {
    let identity = ArtifactIdentity::new(
        "ext-real-builder",
        "publisher-alpha",
        "2026-02-21T00:00:00Z",
    );
    let source_digest = format!("sha256:{}", "a".repeat(64));
    let signature = compute_artifact_provenance_signature(
        &identity,
        &capabilities,
        "publisher-alpha",
        &source_digest,
    );

    ExtensionArtifactInput::new(
        identity,
        capabilities,
        ArtifactProvenance::new("publisher-alpha", source_digest, signature),
    )
}

#[test]
fn builds_artifact_from_signed_caller_supplied_metadata() {
    let input = signed_input(vec![
        CapabilityRequirement::new("cap:fs:read", "read project manifest", true),
        CapabilityRequirement::new("cap:trust:read", "read trust policy", true),
    ]);

    let artifact = build_extension_artifact(input).expect("signed input should build");

    assert_eq!(artifact.identity.author, "publisher-alpha");
    assert_eq!(artifact.identity.created_at, "2026-02-21T00:00:00Z");
    let envelope = artifact.envelope.expect("capability envelope");
    assert_eq!(envelope.capability_count(), 2);
    assert!(envelope.verify_digest(&artifact.identity));
}

#[test]
fn rejects_artifact_when_provenance_signature_is_not_bound_to_inputs() {
    let mut input = signed_input(vec![CapabilityRequirement::new(
        "cap:fs:read",
        "read project manifest",
        true,
    )]);
    input.identity.author = "publisher-beta".to_string();

    let err = build_extension_artifact(input).expect_err("tampered identity should fail");

    assert!(matches!(
        err,
        ArtifactError::InvalidEnvelope { ref detail, .. }
            if detail == "artifact provenance signature mismatch"
    ));
}

#[test]
fn rejects_duplicate_capabilities_instead_of_overwriting_envelope_entries() {
    let input = signed_input(vec![
        CapabilityRequirement::new("cap:fs:read", "read project manifest", true),
        CapabilityRequirement::new("cap:fs:read", "shadow original capability", true),
    ]);

    let err = build_extension_artifact(input).expect_err("duplicate capability should fail");

    assert!(matches!(
        err,
        ArtifactError::InvalidEnvelope { ref detail, .. }
            if detail == "duplicate capability requirement: cap:fs:read"
    ));
}
