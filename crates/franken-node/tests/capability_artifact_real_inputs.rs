use frankenengine_node::connector::capability_artifact::{
    ArtifactError, ArtifactIdentity, ArtifactProvenance, CapabilityRequirement,
    ExtensionArtifactInput, build_extension_artifact, compute_artifact_provenance_signature,
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
    )
    .expect("provenance signature");

    ExtensionArtifactInput::new(
        identity,
        capabilities,
        ArtifactProvenance::new("publisher-alpha", source_digest, signature),
    )
}

fn fixture_capabilities() -> Vec<CapabilityRequirement> {
    vec![
        CapabilityRequirement::new("cap:fs:read", "read project manifest", true),
        CapabilityRequirement::new("cap:trust:read", "read trust policy", true),
    ]
}

#[test]
fn builds_artifact_from_signed_caller_supplied_metadata() {
    let input = signed_input(fixture_capabilities());

    let artifact = build_extension_artifact(input).expect("signed input should build");

    assert_eq!(artifact.identity.author, "publisher-alpha");
    assert_eq!(artifact.identity.created_at, "2026-02-21T00:00:00Z");
    let envelope = artifact.envelope.expect("capability envelope");
    assert_eq!(envelope.capability_count(), 2);
    assert!(envelope.verify_digest(&artifact.identity));
}

#[test]
fn artifact_identity_display_sanitizes_author_control_chars() {
    let identity = ArtifactIdentity::new(
        "ext-real-builder",
        "publisher\r\nINJECTED",
        "2026-02-21T00:00:00Z",
    );

    let display = format!("{identity}");

    assert!(!display.contains('\r'));
    assert!(!display.contains('\n'));
    assert!(display.contains('\u{FFFD}'));
}

#[test]
fn capability_artifact_length_prefixed_hashes_match_golden_vectors() {
    let identity = ArtifactIdentity::new(
        "ext-real-builder",
        "publisher-alpha",
        "2026-02-21T00:00:00Z",
    );
    let capabilities = fixture_capabilities();
    let source_digest = format!("sha256:{}", "a".repeat(64));

    let signature = compute_artifact_provenance_signature(
        &identity,
        &capabilities,
        "publisher-alpha",
        &source_digest,
    )
    .expect("golden provenance signature");

    assert_eq!(
        signature,
        "sha256:7a94dae6ac3bb141e8be85ea0a656ed12957d7b03baafa55d6d32ecdfdb263c9"
    );

    let artifact = build_extension_artifact(ExtensionArtifactInput::new(
        identity.clone(),
        capabilities,
        ArtifactProvenance::new("publisher-alpha", source_digest, signature),
    ))
    .expect("golden capability artifact should build");
    let envelope = artifact.envelope.expect("golden capability envelope");

    assert_eq!(
        envelope.digest,
        "sha256:4b78c363e6712ccd7da094837fde6aab12ba15b047e39e42e17326fd17ffeb8f"
    );
    assert!(envelope.verify_digest(&identity));
}

#[test]
fn rejects_artifact_when_provenance_publisher_differs_from_author() {
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
            if matches!(detail.as_str(), "publisher must match artifact author")
    ));
}

#[test]
fn rejects_artifact_when_provenance_signature_is_not_bound_to_inputs() {
    let mut input = signed_input(vec![CapabilityRequirement::new(
        "cap:fs:read",
        "read project manifest",
        true,
    )]);
    input.provenance.signature = format!("sha256:{}", "b".repeat(64));

    let err = build_extension_artifact(input).expect_err("tampered signature should fail");

    assert!(matches!(
        err,
        ArtifactError::InvalidEnvelope { ref detail, .. }
            if matches!(detail.as_str(), "artifact provenance signature mismatch")
    ));
}

#[test]
fn rejects_duplicate_capabilities_instead_of_overwriting_envelope_entries() {
    let identity = ArtifactIdentity::new(
        "ext-real-builder",
        "publisher-alpha",
        "2026-02-21T00:00:00Z",
    );
    let source_digest = format!("sha256:{}", "a".repeat(64));
    let input = ExtensionArtifactInput::new(
        identity,
        vec![
            CapabilityRequirement::new("cap:fs:read", "read project manifest", true),
            CapabilityRequirement::new("cap:fs:read", "shadow original capability", true),
        ],
        ArtifactProvenance::new(
            "publisher-alpha",
            source_digest,
            format!("sha256:{}", "b".repeat(64)),
        ),
    );

    let err = build_extension_artifact(input).expect_err("duplicate capability should fail");

    assert!(matches!(
        err,
        ArtifactError::InvalidEnvelope { ref detail, .. }
            if detail == "duplicate capability requirement: cap:fs:read"
    ));
}

#[test]
fn provenance_signature_fails_closed_for_duplicate_capabilities() {
    let identity = ArtifactIdentity::new(
        "ext-real-builder",
        "publisher-alpha",
        "2026-02-21T00:00:00Z",
    );
    let source_digest = format!("sha256:{}", "a".repeat(64));
    let err = compute_artifact_provenance_signature(
        &identity,
        &[
            CapabilityRequirement::new("cap:fs:read", "read project manifest", true),
            CapabilityRequirement::new("cap:fs:read", "shadow original capability", true),
        ],
        "publisher-alpha",
        &source_digest,
    )
    .expect_err("duplicate capability preimage must fail closed");

    assert!(matches!(
        err,
        ArtifactError::InvalidEnvelope { ref detail, .. }
            if detail == "duplicate capability requirement: cap:fs:read"
    ));
}

#[test]
fn provenance_signature_frames_ambiguous_identity_fields() {
    let source_digest = format!("sha256:{}", "a".repeat(64));
    let capabilities = vec![CapabilityRequirement::new(
        "cap:fs:read",
        "read project manifest",
        true,
    )];

    let left = compute_artifact_provenance_signature(
        &ArtifactIdentity::new("ab", "c", "2026-02-21T00:00:00Z"),
        &capabilities,
        "publisher-alpha",
        &source_digest,
    )
    .expect("left provenance signature");
    let right = compute_artifact_provenance_signature(
        &ArtifactIdentity::new("a", "bc", "2026-02-21T00:00:00Z"),
        &capabilities,
        "publisher-alpha",
        &source_digest,
    )
    .expect("right provenance signature");

    assert_ne!(left, right);
}
