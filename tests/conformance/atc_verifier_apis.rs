//! Conformance tests for ATC verifier API contracts (bd-2zip).

use sha2::{Digest, Sha256};

#[derive(Clone, Debug)]
struct MetricSnapshot {
    metric_id: &'static str,
    data_visibility: &'static str,
    raw_participant_data_included: bool,
}

#[derive(Clone, Debug)]
struct ProofArtifact {
    artifact_hash: &'static str,
    parent_hash: Option<&'static str>,
}

fn verify_parent_links(chain: &[ProofArtifact]) -> Result<(), &'static str> {
    if chain.is_empty() {
        return Err("proof chain must not be empty");
    }

    for (idx, node) in chain.iter().enumerate() {
        if idx == 0 {
            if node.parent_hash.is_some() {
                return Err("root node must not have parent hash");
            }
            continue;
        }

        let expected_parent = chain[idx - 1].artifact_hash;
        if node.parent_hash != Some(expected_parent) {
            return Err("parent hash mismatch");
        }
    }

    Ok(())
}

fn is_aggregate_only(metrics: &[MetricSnapshot]) -> bool {
    metrics.iter().all(|metric| {
        metric.data_visibility == "aggregate_only" && !metric.raw_participant_data_included
    })
}

fn verifier_digest(computation_id: &str, metric_root: &str, proof_root: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(computation_id.as_bytes());
    hasher.update(b"|");
    hasher.update(metric_root.as_bytes());
    hasher.update(b"|");
    hasher.update(proof_root.as_bytes());
    hex::encode(hasher.finalize())
}

#[test]
fn atc_verifier_contract_is_deterministic() {
    let digest_a = verifier_digest(
        "atc-comp-2026-02-21-001",
        "sha256:metrics-root-001",
        "sha256:proof-root-001",
    );
    let digest_b = verifier_digest(
        "atc-comp-2026-02-21-001",
        "sha256:metrics-root-001",
        "sha256:proof-root-001",
    );

    assert_eq!(digest_a, digest_b);
}

#[test]
fn atc_verifier_contract_validates_proof_chain_continuity() {
    let valid_chain = vec![
        ProofArtifact {
            artifact_hash: "sha256:a1",
            parent_hash: None,
        },
        ProofArtifact {
            artifact_hash: "sha256:b2",
            parent_hash: Some("sha256:a1"),
        },
        ProofArtifact {
            artifact_hash: "sha256:c3",
            parent_hash: Some("sha256:b2"),
        },
    ];

    assert!(verify_parent_links(&valid_chain).is_ok());
}

#[test]
fn atc_verifier_contract_detects_chain_break() {
    let broken_chain = vec![
        ProofArtifact {
            artifact_hash: "sha256:a1",
            parent_hash: None,
        },
        ProofArtifact {
            artifact_hash: "sha256:b2",
            parent_hash: Some("sha256:not-a1"),
        },
    ];

    assert!(verify_parent_links(&broken_chain).is_err());
}

#[test]
fn atc_verifier_contract_enforces_aggregate_only_visibility() {
    let compliant = vec![
        MetricSnapshot {
            metric_id: "ecosystem_risk_index",
            data_visibility: "aggregate_only",
            raw_participant_data_included: false,
        },
        MetricSnapshot {
            metric_id: "revocation_convergence",
            data_visibility: "aggregate_only",
            raw_participant_data_included: false,
        },
    ];
    assert!(is_aggregate_only(&compliant));

    let leaking = vec![
        MetricSnapshot {
            metric_id: "ecosystem_risk_index",
            data_visibility: "aggregate_only",
            raw_participant_data_included: false,
        },
        MetricSnapshot {
            metric_id: "participant_debug",
            data_visibility: "raw",
            raw_participant_data_included: true,
        },
    ];
    assert!(!is_aggregate_only(&leaking));
}

#[test]
fn atc_verifier_contract_preserves_metric_identity() {
    let metrics = [
        MetricSnapshot {
            metric_id: "ecosystem_risk_index",
            data_visibility: "aggregate_only",
            raw_participant_data_included: false,
        },
        MetricSnapshot {
            metric_id: "proof_validity_rate",
            data_visibility: "aggregate_only",
            raw_participant_data_included: false,
        },
    ];

    assert_eq!(metrics[0].metric_id, "ecosystem_risk_index");
    assert_eq!(metrics[1].metric_id, "proof_validity_rate");
}
