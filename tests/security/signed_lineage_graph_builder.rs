use frankenengine_node::security::lineage_tracker::{
    ERR_SIGNED_LINEAGE_INVALID, SIGNED_LINEAGE_SCHEMA_VERSION, SignedLineageDependency,
    SignedLineageGraphBuilder, SignedLineageGraphInput, SignedLineageMaintainer,
    SignedLineagePipelineTransition, SignedLineageVersion,
};

fn sample_signed_lineage_input() -> SignedLineageGraphInput {
    SignedLineageGraphInput {
        root_version: SignedLineageVersion {
            package: "franken-widget".to_string(),
            version: "1.2.3".to_string(),
            artifact_digest: "sha256:artifact-root".to_string(),
            published_at_ms: 1_710_000_000,
        },
        maintainers: vec![
            SignedLineageMaintainer {
                maintainer_id: "maintainer-b".to_string(),
                key_fingerprint: "key-b".to_string(),
                role: "reviewer".to_string(),
            },
            SignedLineageMaintainer {
                maintainer_id: "maintainer-a".to_string(),
                key_fingerprint: "key-a".to_string(),
                role: "publisher".to_string(),
            },
        ],
        dependencies: vec![
            SignedLineageDependency {
                package: "left-pad".to_string(),
                version_req: "^1.0.0".to_string(),
                resolved_digest: "sha256:left-pad".to_string(),
            },
            SignedLineageDependency {
                package: "colorize".to_string(),
                version_req: "2.4.0".to_string(),
                resolved_digest: "sha256:colorize".to_string(),
            },
        ],
        pipeline_transitions: vec![
            SignedLineagePipelineTransition {
                stage: "build".to_string(),
                runner_id: "runner-a".to_string(),
                input_digest: "sha256:source-tree".to_string(),
                output_digest: "sha256:build-output".to_string(),
                timestamp_ms: 1_710_000_100,
            },
            SignedLineagePipelineTransition {
                stage: "publish".to_string(),
                runner_id: "runner-b".to_string(),
                input_digest: "sha256:build-output".to_string(),
                output_digest: "sha256:artifact-root".to_string(),
                timestamp_ms: 1_710_000_200,
            },
        ],
    }
}

#[test]
fn signed_lineage_graph_builder_links_all_supply_chain_domains()
-> Result<(), Box<dyn std::error::Error>> {
    let builder = SignedLineageGraphBuilder::new("release-bot", "key-release", b"test-secret")?;
    let artifact = builder.build(sample_signed_lineage_input())?;

    assert_eq!(artifact.schema_version, SIGNED_LINEAGE_SCHEMA_VERSION);
    assert!(
        artifact
            .graph_id
            .starts_with("signed-lineage:franken-widget@1.2.3:")
    );
    assert_eq!(artifact.nodes.len(), 7);
    assert_eq!(artifact.edges.len(), 7);
    assert_eq!(artifact.signature.algorithm, "hmac-sha256");
    assert_eq!(artifact.signature.signer_id, "release-bot");

    assert!(artifact.edges.iter().any(|edge| {
        edge.source.as_str().eq("maintainer:maintainer-a")
            && edge.target.as_str().eq("version:franken-widget@1.2.3")
            && edge.relation.as_str().eq("maintains:publisher")
    }));
    assert!(artifact.edges.iter().any(|edge| {
        edge.source.as_str().eq("version:franken-widget@1.2.3")
            && edge.target.as_str().eq("dependency:left-pad@^1.0.0")
            && edge.relation.as_str().eq("depends_on")
    }));
    assert!(artifact.edges.iter().any(|edge| {
        edge.source
            .as_str()
            .eq("pipeline:build:runner-a:1710000100")
            && edge
                .target
                .as_str()
                .eq("pipeline:publish:runner-b:1710000200")
            && edge.relation.as_str().eq("pipeline_transition")
    }));
    assert!(artifact.edges.iter().any(|edge| {
        edge.source
            .as_str()
            .eq("pipeline:publish:runner-b:1710000200")
            && edge.target.as_str().eq("version:franken-widget@1.2.3")
            && edge.relation.as_str().eq("produces_version")
    }));
    Ok(())
}

#[test]
fn signed_lineage_graph_builder_is_deterministic_for_unordered_inputs()
-> Result<(), Box<dyn std::error::Error>> {
    let builder = SignedLineageGraphBuilder::new("release-bot", "key-release", b"test-secret")?;
    let mut left = sample_signed_lineage_input();
    let right = sample_signed_lineage_input();
    left.maintainers.reverse();
    left.dependencies.reverse();

    let left_artifact = builder.build(left)?;
    let right_artifact = builder.build(right)?;

    assert_eq!(
        left_artifact.canonical_digest,
        right_artifact.canonical_digest
    );
    assert_eq!(
        left_artifact.signature.value,
        right_artifact.signature.value
    );
    assert_eq!(left_artifact.nodes, right_artifact.nodes);
    assert_eq!(left_artifact.edges, right_artifact.edges);
    Ok(())
}

#[test]
fn signed_lineage_graph_builder_rejects_missing_dependency_links()
-> Result<(), Box<dyn std::error::Error>> {
    let builder = SignedLineageGraphBuilder::new("release-bot", "key-release", b"test-secret")?;
    let mut input = sample_signed_lineage_input();
    input.dependencies.clear();

    let result = builder.build(input);
    assert!(result.is_err());
    let err_text = match result {
        Ok(_) => String::new(),
        Err(err) => err.to_string(),
    };

    assert!(err_text.contains(ERR_SIGNED_LINEAGE_INVALID));
    assert!(err_text.contains("dependency"));
    Ok(())
}

#[test]
fn signed_lineage_graph_signature_changes_when_dependency_digest_changes()
-> Result<(), Box<dyn std::error::Error>> {
    let builder = SignedLineageGraphBuilder::new("release-bot", "key-release", b"test-secret")?;
    let baseline = builder.build(sample_signed_lineage_input())?;
    let mut changed = sample_signed_lineage_input();
    let mut changed_dependency = false;
    for dependency in &mut changed.dependencies {
        if dependency.package.as_str().eq("left-pad") {
            dependency.resolved_digest = "sha256:left-pad-v2".to_string();
            changed_dependency = true;
        }
    }
    assert!(changed_dependency);
    let changed = builder.build(changed)?;

    assert_ne!(baseline.canonical_digest, changed.canonical_digest);
    assert_ne!(baseline.signature.value, changed.signature.value);
    Ok(())
}
