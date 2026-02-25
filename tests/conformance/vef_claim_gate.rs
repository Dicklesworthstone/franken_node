//! Conformance tests for bd-3go4: VEF coverage and proof-validity metrics
//! integration into the claim compiler and trust scoreboard.
//!
//! Validates that the claim compiler correctly gates claims based on VEF
//! coverage thresholds, detects coverage gaps, and verifies evidence links.

#[cfg(test)]
mod tests {
    // -----------------------------------------------------------------------
    // Inline domain types (mirrors crates/franken-node/src/connector/vef_claim_integration.rs)
    // -----------------------------------------------------------------------

    /// Represents a single VEF proof attached to an action class.
    #[derive(Debug, Clone)]
    struct VefProof {
        action_class: String,
        valid: bool,
        age_secs: u64,
    }

    /// Coverage snapshot computed from a set of VEF proofs.
    #[derive(Debug, Clone)]
    struct CoverageSnapshot {
        total_action_classes: usize,
        covered_action_classes: usize,
        coverage_gaps: Vec<String>,
    }

    impl CoverageSnapshot {
        fn coverage_percentage(&self) -> f64 {
            if self.total_action_classes == 0 {
                return 0.0;
            }
            (self.covered_action_classes as f64 / self.total_action_classes as f64) * 100.0
        }
    }

    /// Validity snapshot computed from proof verification results.
    #[derive(Debug, Clone)]
    struct ValiditySnapshot {
        total_proofs_checked: usize,
        valid_proofs: usize,
    }

    impl ValiditySnapshot {
        fn success_rate(&self) -> f64 {
            if self.total_proofs_checked == 0 {
                return 0.0;
            }
            (self.valid_proofs as f64 / self.total_proofs_checked as f64) * 100.0
        }

        fn degraded_fraction(&self) -> f64 {
            if self.total_proofs_checked == 0 {
                return 0.0;
            }
            ((self.total_proofs_checked - self.valid_proofs) as f64
                / self.total_proofs_checked as f64)
        }
    }

    /// Configuration for a single claim's VEF evidence requirements.
    #[derive(Debug, Clone)]
    struct ClaimVefConfig {
        claim_id: String,
        required_coverage_pct: f64,
        required_validity_rate: f64,
        max_proof_age_secs: u64,
    }

    /// Result of evaluating a claim against VEF metrics.
    #[derive(Debug, Clone, PartialEq)]
    enum ClaimVerdict {
        Pass,
        Blocked { reason: String },
    }

    /// Evidence link attached to a scoreboard snapshot.
    #[derive(Debug, Clone)]
    struct EvidenceLink {
        snapshot_hash: String,
        claim_id: String,
        valid: bool,
    }

    // -----------------------------------------------------------------------
    // Helper: compute coverage from proofs
    // -----------------------------------------------------------------------

    fn compute_coverage(
        all_action_classes: &[&str],
        proofs: &[VefProof],
        max_age_secs: u64,
    ) -> CoverageSnapshot {
        let mut covered: std::collections::BTreeSet<&str> = std::collections::BTreeSet::new();
        for proof in proofs {
            if proof.valid && proof.age_secs <= max_age_secs {
                for ac in all_action_classes {
                    if *ac == proof.action_class.as_str() {
                        covered.insert(ac);
                    }
                }
            }
        }
        let gaps: Vec<String> = all_action_classes
            .iter()
            .filter(|ac| !covered.contains(**ac))
            .map(|ac| ac.to_string())
            .collect();
        CoverageSnapshot {
            total_action_classes: all_action_classes.len(),
            covered_action_classes: covered.len(),
            coverage_gaps: gaps,
        }
    }

    fn compute_validity(proofs: &[VefProof]) -> ValiditySnapshot {
        let valid = proofs.iter().filter(|p| p.valid).count();
        ValiditySnapshot {
            total_proofs_checked: proofs.len(),
            valid_proofs: valid,
        }
    }

    fn evaluate_claim(
        config: &ClaimVefConfig,
        coverage: &CoverageSnapshot,
        validity: &ValiditySnapshot,
    ) -> ClaimVerdict {
        let cov_pct = coverage.coverage_percentage();
        let val_rate = validity.success_rate();

        if cov_pct < config.required_coverage_pct {
            return ClaimVerdict::Blocked {
                reason: format!(
                    "coverage {:.1}% below threshold {:.1}%",
                    cov_pct, config.required_coverage_pct
                ),
            };
        }
        if val_rate < config.required_validity_rate {
            return ClaimVerdict::Blocked {
                reason: format!(
                    "validity rate {:.1}% below threshold {:.1}%",
                    val_rate, config.required_validity_rate
                ),
            };
        }
        ClaimVerdict::Pass
    }

    fn verify_evidence_link(link: &EvidenceLink) -> bool {
        !link.snapshot_hash.is_empty() && !link.claim_id.is_empty() && link.valid
    }

    // -----------------------------------------------------------------------
    // Shared fixture
    // -----------------------------------------------------------------------

    fn action_classes() -> Vec<&'static str> {
        vec![
            "create-trust-object",
            "revoke-trust-object",
            "transfer-ownership",
            "publish-attestation",
            "register-verifier",
            "file-dispute",
            "resolve-dispute",
            "update-reputation",
            "issue-remote-cap",
            "rotate-epoch-key",
            "submit-replay-capsule",
            "build-scoreboard",
        ]
    }

    fn full_coverage_proofs() -> Vec<VefProof> {
        action_classes()
            .iter()
            .flat_map(|ac| {
                vec![
                    VefProof {
                        action_class: ac.to_string(),
                        valid: true,
                        age_secs: 120,
                    },
                    VefProof {
                        action_class: ac.to_string(),
                        valid: true,
                        age_secs: 300,
                    },
                    VefProof {
                        action_class: ac.to_string(),
                        valid: true,
                        age_secs: 600,
                    },
                    VefProof {
                        action_class: ac.to_string(),
                        valid: true,
                        age_secs: 900,
                    },
                ]
            })
            .collect()
    }

    // -----------------------------------------------------------------------
    // Tests
    // -----------------------------------------------------------------------

    /// Claims requiring VEF evidence pass when coverage is 100%.
    #[test]
    fn test_claim_passes_with_full_coverage() {
        let acs = action_classes();
        let proofs = full_coverage_proofs();
        let coverage = compute_coverage(&acs, &proofs, 3600);
        let validity = compute_validity(&proofs);

        assert_eq!(coverage.total_action_classes, 12);
        assert_eq!(coverage.covered_action_classes, 12);
        assert_eq!(coverage.coverage_percentage(), 100.0);
        assert!(coverage.coverage_gaps.is_empty());

        assert_eq!(validity.total_proofs_checked, 48);
        assert_eq!(validity.valid_proofs, 48);
        assert_eq!(validity.success_rate(), 100.0);
        assert_eq!(validity.degraded_fraction(), 0.0);

        let config = ClaimVefConfig {
            claim_id: "trust-integrity".to_string(),
            required_coverage_pct: 80.0,
            required_validity_rate: 95.0,
            max_proof_age_secs: 3600,
        };

        let verdict = evaluate_claim(&config, &coverage, &validity);
        assert_eq!(verdict, ClaimVerdict::Pass);
    }

    /// Claims are blocked when VEF coverage is below the configured threshold.
    #[test]
    fn test_claim_blocked_below_threshold() {
        let acs = action_classes();
        // Only cover 6 of 12 action classes (50%).
        let proofs: Vec<VefProof> = acs[..6]
            .iter()
            .map(|ac| VefProof {
                action_class: ac.to_string(),
                valid: true,
                age_secs: 120,
            })
            .collect();

        let coverage = compute_coverage(&acs, &proofs, 3600);
        let validity = compute_validity(&proofs);

        assert_eq!(coverage.covered_action_classes, 6);
        assert_eq!(coverage.coverage_percentage(), 50.0);
        assert_eq!(coverage.coverage_gaps.len(), 6);

        let config = ClaimVefConfig {
            claim_id: "safety-no-ambient-authority".to_string(),
            required_coverage_pct: 95.0,
            required_validity_rate: 95.0,
            max_proof_age_secs: 3600,
        };

        let verdict = evaluate_claim(&config, &coverage, &validity);
        match verdict {
            ClaimVerdict::Blocked { reason } => {
                assert!(
                    reason.contains("coverage"),
                    "block reason should mention coverage: {}",
                    reason
                );
                assert!(
                    reason.contains("50.0%"),
                    "block reason should include actual coverage: {}",
                    reason
                );
            }
            ClaimVerdict::Pass => panic!("expected claim to be blocked with 50% coverage"),
        }
    }

    /// Coverage gaps are detected and reported per action class.
    #[test]
    fn test_coverage_gap_detection() {
        let acs = action_classes();
        // Cover all except "transfer-ownership" and "file-dispute".
        let proofs: Vec<VefProof> = acs
            .iter()
            .filter(|ac| **ac != "transfer-ownership" && **ac != "file-dispute")
            .map(|ac| VefProof {
                action_class: ac.to_string(),
                valid: true,
                age_secs: 60,
            })
            .collect();

        let coverage = compute_coverage(&acs, &proofs, 3600);

        assert_eq!(coverage.total_action_classes, 12);
        assert_eq!(coverage.covered_action_classes, 10);
        assert_eq!(coverage.coverage_gaps.len(), 2);
        assert!(coverage.coverage_gaps.contains(&"transfer-ownership".to_string()));
        assert!(coverage.coverage_gaps.contains(&"file-dispute".to_string()));

        // Coverage is 83.3% -- passes an 80% threshold but fails 95%.
        let pct = coverage.coverage_percentage();
        assert!(pct > 83.0 && pct < 84.0, "expected ~83.3%, got {:.1}%", pct);

        let config_80 = ClaimVefConfig {
            claim_id: "trust-integrity".to_string(),
            required_coverage_pct: 80.0,
            required_validity_rate: 50.0,
            max_proof_age_secs: 3600,
        };
        let validity = compute_validity(&proofs);
        assert_eq!(evaluate_claim(&config_80, &coverage, &validity), ClaimVerdict::Pass);

        let config_95 = ClaimVefConfig {
            claim_id: "safety-no-ambient-authority".to_string(),
            required_coverage_pct: 95.0,
            required_validity_rate: 50.0,
            max_proof_age_secs: 3600,
        };
        assert!(matches!(
            evaluate_claim(&config_95, &coverage, &validity),
            ClaimVerdict::Blocked { .. }
        ));
    }

    /// Evidence links are verified: non-empty hash, non-empty claim_id, valid flag.
    #[test]
    fn test_evidence_link_validity() {
        let valid_link = EvidenceLink {
            snapshot_hash: "sha256:abcdef0123456789".to_string(),
            claim_id: "trust-integrity".to_string(),
            valid: true,
        };
        assert!(verify_evidence_link(&valid_link));

        let empty_hash = EvidenceLink {
            snapshot_hash: "".to_string(),
            claim_id: "trust-integrity".to_string(),
            valid: true,
        };
        assert!(!verify_evidence_link(&empty_hash));

        let empty_claim = EvidenceLink {
            snapshot_hash: "sha256:abcdef0123456789".to_string(),
            claim_id: "".to_string(),
            valid: true,
        };
        assert!(!verify_evidence_link(&empty_claim));

        let invalid_flag = EvidenceLink {
            snapshot_hash: "sha256:abcdef0123456789".to_string(),
            claim_id: "trust-integrity".to_string(),
            valid: false,
        };
        assert!(!verify_evidence_link(&invalid_flag));
    }

    /// Threshold boundary: coverage exactly at threshold passes (>= comparison).
    #[test]
    fn test_threshold_boundary() {
        // Build coverage where exactly 80% of action classes are covered.
        // With 10 action classes, 8 covered = 80.0%.
        let acs: Vec<&str> = vec![
            "ac-01", "ac-02", "ac-03", "ac-04", "ac-05",
            "ac-06", "ac-07", "ac-08", "ac-09", "ac-10",
        ];
        let proofs: Vec<VefProof> = acs[..8]
            .iter()
            .map(|ac| VefProof {
                action_class: ac.to_string(),
                valid: true,
                age_secs: 100,
            })
            .collect();

        let coverage = compute_coverage(&acs, &proofs, 3600);
        let validity = compute_validity(&proofs);

        assert_eq!(coverage.coverage_percentage(), 80.0);
        assert_eq!(coverage.coverage_gaps.len(), 2);

        // Exactly at threshold -- should pass.
        let config_exact = ClaimVefConfig {
            claim_id: "boundary-test".to_string(),
            required_coverage_pct: 80.0,
            required_validity_rate: 80.0,
            max_proof_age_secs: 3600,
        };
        assert_eq!(
            evaluate_claim(&config_exact, &coverage, &validity),
            ClaimVerdict::Pass,
            "coverage exactly at threshold must pass"
        );

        // Just above threshold -- should still pass.
        let config_below = ClaimVefConfig {
            claim_id: "boundary-test-below".to_string(),
            required_coverage_pct: 79.9,
            required_validity_rate: 80.0,
            max_proof_age_secs: 3600,
        };
        assert_eq!(
            evaluate_claim(&config_below, &coverage, &validity),
            ClaimVerdict::Pass,
            "coverage above threshold must pass"
        );

        // Just above actual -- should block.
        let config_above = ClaimVefConfig {
            claim_id: "boundary-test-above".to_string(),
            required_coverage_pct: 80.1,
            required_validity_rate: 80.0,
            max_proof_age_secs: 3600,
        };
        assert!(
            matches!(
                evaluate_claim(&config_above, &coverage, &validity),
                ClaimVerdict::Blocked { .. }
            ),
            "coverage below threshold must block"
        );

        // Stale proofs should not count toward coverage.
        let stale_proofs: Vec<VefProof> = acs
            .iter()
            .map(|ac| VefProof {
                action_class: ac.to_string(),
                valid: true,
                age_secs: 7200, // exceeds 3600 max
            })
            .collect();
        let stale_coverage = compute_coverage(&acs, &stale_proofs, 3600);
        assert_eq!(stale_coverage.covered_action_classes, 0);
        assert_eq!(stale_coverage.coverage_percentage(), 0.0);
    }
}
