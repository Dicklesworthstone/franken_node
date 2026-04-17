//! Behavioral Phenotype Evolution Tracker (BPET) subsystem.
//!
//! Provides longitudinal phenotype intelligence for pre-compromise
//! trajectory detection with economic trust layer integration.

pub mod economic_integration;

#[cfg(test)]
mod negative_path_tests {
    use super::economic_integration::{
        BpetEconError, BpetEconomicEngine, CompromiseMotif, CompromisePricing, InterventionRoi,
        MotifIndicator, PhenotypeObservation, PhenotypeTrajectory, ThresholdDirection,
        match_motifs,
    };

    fn observation() -> PhenotypeObservation {
        PhenotypeObservation {
            timestamp: "2026-04-17T00:00:00Z".to_string(),
            maintainer_activity_score: 0.9,
            commit_velocity: 12.0,
            issue_response_time_hours: 8.0,
            dependency_churn_rate: 0.05,
            security_patch_latency_hours: 24.0,
            contributor_diversity_index: 0.8,
        }
    }

    fn trajectory_with_observation(obs: PhenotypeObservation) -> PhenotypeTrajectory {
        PhenotypeTrajectory {
            package_name: "bpet-negative-case".to_string(),
            observations: vec![obs],
        }
    }

    #[test]
    fn pricing_rejects_empty_trajectory() {
        let trajectory = PhenotypeTrajectory {
            package_name: "empty-package".to_string(),
            observations: Vec::new(),
        };

        let err = CompromisePricing::compute(&trajectory, 50_000.0, 0.8)
            .expect_err("empty trajectory must fail closed");

        assert!(
            matches!(err, BpetEconError::InvalidTrajectory(message) if message.contains("no observations"))
        );
    }

    #[test]
    fn guidance_rejects_empty_trajectory_without_audit_side_effect() {
        let trajectory = PhenotypeTrajectory {
            package_name: "empty-package".to_string(),
            observations: Vec::new(),
        };
        let mut engine = BpetEconomicEngine::new(Vec::new());

        let err = engine
            .generate_guidance(&trajectory, 50_000.0, 0.8, "trace-empty")
            .expect_err("empty guidance trajectory must fail closed");

        assert!(matches!(err, BpetEconError::InvalidTrajectory(_)));
        assert!(
            engine.audit_log().is_empty(),
            "failed guidance should not emit success audit records"
        );
    }

    #[test]
    fn intervention_roi_rejects_zero_cost() {
        let err = InterventionRoi::compute("zero-cost", 0.0, 0.5, 10_000.0)
            .expect_err("zero-cost intervention must fail closed");

        assert!(matches!(err, BpetEconError::InvalidCost(cost) if cost == 0.0));
    }

    #[test]
    fn intervention_roi_rejects_negative_cost() {
        let err = InterventionRoi::compute("negative-cost", -1.0, 0.5, 10_000.0)
            .expect_err("negative-cost intervention must fail closed");

        assert!(matches!(err, BpetEconError::InvalidCost(cost) if cost < 0.0));
    }

    #[test]
    fn intervention_roi_rejects_non_finite_cost() {
        let err = InterventionRoi::compute("nan-cost", f64::NAN, 0.5, 10_000.0)
            .expect_err("NaN intervention cost must fail closed");

        assert!(matches!(err, BpetEconError::InvalidCost(cost) if cost.is_nan()));
    }

    #[test]
    fn motif_matching_rejects_empty_trajectory_by_returning_no_matches() {
        let motif = CompromiseMotif {
            motif_id: "motif-empty-trajectory".to_string(),
            name: "Should Not Match".to_string(),
            description: "Empty trajectories have no latest observation".to_string(),
            indicators: vec![MotifIndicator {
                indicator_name: "maintainer_activity".to_string(),
                threshold: 0.5,
                direction: ThresholdDirection::Below,
            }],
            historical_frequency: 0.2,
            typical_time_to_compromise_days: 30.0,
        };
        let trajectory = PhenotypeTrajectory {
            package_name: "empty-package".to_string(),
            observations: Vec::new(),
        };

        assert!(
            match_motifs(&trajectory, &[motif]).is_empty(),
            "empty trajectories must not produce motif matches"
        );
    }

    #[test]
    fn motif_matching_ignores_unknown_indicator_names() {
        let motif = CompromiseMotif {
            motif_id: "motif-unknown-indicator".to_string(),
            name: "Unknown Indicator".to_string(),
            description: "Unknown indicators should not count as hits".to_string(),
            indicators: vec![MotifIndicator {
                indicator_name: "unmodeled_signal".to_string(),
                threshold: 0.0,
                direction: ThresholdDirection::Above,
            }],
            historical_frequency: 0.9,
            typical_time_to_compromise_days: 7.0,
        };
        let trajectory = trajectory_with_observation(observation());

        assert!(
            match_motifs(&trajectory, &[motif]).is_empty(),
            "unknown motif indicators must fail closed to no match"
        );
    }

    #[test]
    fn non_finite_expected_loss_and_confidence_are_clamped() {
        let trajectory = trajectory_with_observation(observation());

        let pricing = CompromisePricing::compute(&trajectory, f64::INFINITY, f64::NAN)
            .expect("non-finite economic inputs are sanitized");

        assert_eq!(pricing.expected_loss_if_compromised, 0.0);
        assert_eq!(pricing.risk_adjusted_cost, 0.0);
        assert_eq!(pricing.insurance_premium_equivalent, 0.0);
        assert_eq!(pricing.confidence, 0.0);
    }
}

#[cfg(test)]
mod bpet_root_additional_negative_tests {
    use super::economic_integration::{
        BpetEconError, BpetEconomicEngine, CompromiseMotif, CompromisePricing, InterventionRoi,
        MotifIndicator, PhenotypeObservation, PhenotypeTrajectory, ThresholdDirection,
        default_motif_library, match_motifs,
    };

    fn healthy_observation() -> PhenotypeObservation {
        PhenotypeObservation {
            timestamp: "2026-04-17T12:00:00Z".to_string(),
            maintainer_activity_score: 0.9,
            commit_velocity: 12.0,
            issue_response_time_hours: 10.0,
            dependency_churn_rate: 0.05,
            security_patch_latency_hours: 20.0,
            contributor_diversity_index: 0.8,
        }
    }

    fn risky_observation() -> PhenotypeObservation {
        PhenotypeObservation {
            timestamp: "2026-04-17T12:00:00Z".to_string(),
            maintainer_activity_score: 0.1,
            commit_velocity: 0.2,
            issue_response_time_hours: 600.0,
            dependency_churn_rate: 0.9,
            security_patch_latency_hours: 720.0,
            contributor_diversity_index: 0.05,
        }
    }

    fn trajectory(observations: Vec<PhenotypeObservation>) -> PhenotypeTrajectory {
        PhenotypeTrajectory {
            package_name: "bpet-boundary-package".to_string(),
            observations,
        }
    }

    #[test]
    fn negative_bpet_pricing_rejects_empty_trajectory_at_subsystem_boundary() {
        let empty = trajectory(Vec::new());

        let err = CompromisePricing::compute(&empty, 100_000.0, 0.8)
            .expect_err("empty trajectory must not price risk");

        assert!(matches!(err, BpetEconError::InvalidTrajectory(_)));
    }

    #[test]
    fn negative_bpet_guidance_rejects_empty_trajectory_without_audit_record() {
        let empty = trajectory(Vec::new());
        let mut engine = BpetEconomicEngine::default();

        let err = engine
            .generate_guidance(&empty, 100_000.0, 0.8, "trace-empty")
            .expect_err("empty trajectory must not produce guidance");

        assert!(matches!(err, BpetEconError::InvalidTrajectory(_)));
        assert!(engine.audit_log().is_empty());
    }

    #[test]
    fn negative_bpet_intervention_rejects_zero_cost() {
        let err = InterventionRoi::compute("zero-cost", 0.0, 0.5, 50_000.0)
            .expect_err("zero cost must be rejected");

        assert!(matches!(err, BpetEconError::InvalidCost(value) if value.abs() < f64::EPSILON));
    }

    #[test]
    fn negative_bpet_intervention_rejects_negative_cost() {
        let err = InterventionRoi::compute("negative-cost", -1.0, 0.5, 50_000.0)
            .expect_err("negative cost must be rejected");

        assert!(matches!(err, BpetEconError::InvalidCost(value) if value < 0.0));
    }

    #[test]
    fn negative_bpet_intervention_rejects_nan_cost() {
        let err = InterventionRoi::compute("nan-cost", f64::NAN, 0.5, 50_000.0)
            .expect_err("NaN cost must be rejected");

        assert!(matches!(err, BpetEconError::InvalidCost(value) if value.is_nan()));
    }

    #[test]
    fn negative_bpet_motif_matching_rejects_empty_observation_set() {
        let empty = trajectory(Vec::new());

        let matches = match_motifs(&empty, &default_motif_library());

        assert!(matches.is_empty());
    }

    #[test]
    fn negative_bpet_motif_matching_rejects_empty_library() {
        let candidate = trajectory(vec![healthy_observation(), risky_observation()]);

        let matches = match_motifs(&candidate, &[]);

        assert!(matches.is_empty());
    }

    #[test]
    fn negative_bpet_motif_matching_ignores_unknown_indicator_names() {
        let candidate = trajectory(vec![risky_observation()]);
        let unknown_only = vec![CompromiseMotif {
            motif_id: "unknown-indicator".to_string(),
            name: "Unknown Indicator".to_string(),
            description: "Unsupported signal should not be treated as evidence".to_string(),
            indicators: vec![MotifIndicator {
                indicator_name: "unregistered_signal".to_string(),
                threshold: 0.0,
                direction: ThresholdDirection::Above,
            }],
            historical_frequency: 1.0,
            typical_time_to_compromise_days: 1.0,
        }];

        let matches = match_motifs(&candidate, &unknown_only);

        assert!(matches.is_empty());
    }

    #[test]
    fn negative_bpet_non_finite_observation_remains_bounded() {
        let mut broken = healthy_observation();
        broken.maintainer_activity_score = f64::NAN;
        broken.commit_velocity = f64::INFINITY;
        broken.issue_response_time_hours = f64::NEG_INFINITY;
        broken.contributor_diversity_index = f64::NAN;
        let candidate = trajectory(vec![broken]);

        let propensity = candidate.compromise_propensity();

        assert!(propensity.is_finite());
        assert!((0.0..=1.0).contains(&propensity));
    }
}

#[cfg(test)]
mod bpet_root_negative_tests {
    use super::economic_integration::{
        BpetEconError, BpetEconomicEngine, CompromiseMotif, CompromisePricing, InterventionRoi,
        MotifIndicator, PhenotypeObservation, PhenotypeTrajectory, ThresholdDirection,
        match_motifs,
    };

    fn bpet_observation() -> PhenotypeObservation {
        PhenotypeObservation {
            timestamp: "2026-04-17T00:00:00Z".to_string(),
            maintainer_activity_score: 0.75,
            commit_velocity: 8.0,
            issue_response_time_hours: 12.0,
            dependency_churn_rate: 0.05,
            security_patch_latency_hours: 24.0,
            contributor_diversity_index: 0.7,
        }
    }

    fn bpet_trajectory(package_name: &str) -> PhenotypeTrajectory {
        PhenotypeTrajectory {
            package_name: package_name.to_string(),
            observations: vec![bpet_observation()],
        }
    }

    fn bpet_empty_trajectory() -> PhenotypeTrajectory {
        PhenotypeTrajectory {
            package_name: "bpet-empty".to_string(),
            observations: Vec::new(),
        }
    }

    fn bpet_three_indicator_motif() -> CompromiseMotif {
        CompromiseMotif {
            motif_id: "bpet-root-motif".to_string(),
            name: "Root module motif".to_string(),
            description: "Requires more than one weak signal".to_string(),
            indicators: vec![
                MotifIndicator {
                    indicator_name: "maintainer_activity".to_string(),
                    threshold: 0.9,
                    direction: ThresholdDirection::Below,
                },
                MotifIndicator {
                    indicator_name: "commit_velocity".to_string(),
                    threshold: 1.0,
                    direction: ThresholdDirection::Below,
                },
                MotifIndicator {
                    indicator_name: "dependency_churn".to_string(),
                    threshold: 0.8,
                    direction: ThresholdDirection::Above,
                },
            ],
            historical_frequency: 0.01,
            typical_time_to_compromise_days: 90.0,
        }
    }

    #[test]
    fn bpet_root_pricing_rejects_empty_trajectory() {
        let err = CompromisePricing::compute(&bpet_empty_trajectory(), 50_000.0, 0.8)
            .expect_err("empty trajectory should be invalid");

        assert!(matches!(err, BpetEconError::InvalidTrajectory(_)));
    }

    #[test]
    fn bpet_root_guidance_rejects_empty_trajectory_and_keeps_audit_empty() {
        let mut engine = BpetEconomicEngine::default();
        let err = engine
            .generate_guidance(&bpet_empty_trajectory(), 50_000.0, 0.8, "trace-empty")
            .expect_err("empty trajectory should not produce guidance");

        assert!(matches!(err, BpetEconError::InvalidTrajectory(_)));
        assert!(engine.audit_log().is_empty());
    }

    #[test]
    fn bpet_root_intervention_rejects_zero_cost() {
        let err = InterventionRoi::compute("zero-cost", 0.0, 0.3, 50_000.0)
            .expect_err("zero cost should be invalid");

        assert!(matches!(err, BpetEconError::InvalidCost(value) if value == 0.0));
    }

    #[test]
    fn bpet_root_intervention_rejects_infinite_cost() {
        let err = InterventionRoi::compute("infinite-cost", f64::INFINITY, 0.3, 50_000.0)
            .expect_err("infinite cost should be invalid");

        assert!(matches!(err, BpetEconError::InvalidCost(value) if value.is_infinite()));
    }

    #[test]
    fn bpet_root_intervention_rejects_negative_infinite_cost() {
        let err =
            InterventionRoi::compute("negative-infinite-cost", f64::NEG_INFINITY, 0.3, 50_000.0)
                .expect_err("negative infinite cost should be invalid");

        assert!(matches!(err, BpetEconError::InvalidCost(value) if value.is_infinite()));
    }

    #[test]
    fn bpet_root_motif_matching_returns_empty_for_empty_library() {
        let matches = match_motifs(&bpet_trajectory("bpet-no-library"), &[]);

        assert!(matches.is_empty());
    }

    #[test]
    fn bpet_root_motif_matching_filters_below_half_signal() {
        let trajectory = bpet_trajectory("bpet-weak-signal");
        let motif = bpet_three_indicator_motif();

        let matches = match_motifs(&trajectory, &[motif]);

        assert!(matches.is_empty());
    }

    #[test]
    fn bpet_root_motif_matching_ignores_unknown_indicators() {
        let motif = CompromiseMotif {
            motif_id: "bpet-root-unknown".to_string(),
            name: "Unknown indicators".to_string(),
            description: "Should not match unrecognized telemetry names".to_string(),
            indicators: vec![MotifIndicator {
                indicator_name: "not_a_bpet_metric".to_string(),
                threshold: 0.0,
                direction: ThresholdDirection::Above,
            }],
            historical_frequency: 0.01,
            typical_time_to_compromise_days: 30.0,
        };

        let matches = match_motifs(&bpet_trajectory("bpet-unknown-indicator"), &[motif]);

        assert!(matches.is_empty());
    }
}

#[cfg(test)]
mod bpet_module_negative_tests {
    use super::economic_integration::{
        BpetEconError, BpetEconomicEngine, CompromiseMotif, CompromisePricing,
        InterventionRecommendation, InterventionRoi, MotifIndicator, PhenotypeObservation,
        PhenotypeTrajectory, PlaybookUrgency, ThresholdDirection, match_motifs,
    };

    fn observation() -> PhenotypeObservation {
        PhenotypeObservation {
            timestamp: "2026-04-17T00:00:00Z".to_string(),
            maintainer_activity_score: 0.8,
            commit_velocity: 8.0,
            issue_response_time_hours: 24.0,
            dependency_churn_rate: 0.1,
            security_patch_latency_hours: 48.0,
            contributor_diversity_index: 0.7,
        }
    }

    fn trajectory() -> PhenotypeTrajectory {
        PhenotypeTrajectory {
            package_name: "bpet-negative-fixture".to_string(),
            observations: vec![observation()],
        }
    }

    #[test]
    fn negative_pricing_rejects_empty_trajectory() {
        let empty = PhenotypeTrajectory {
            package_name: "empty".to_string(),
            observations: Vec::new(),
        };

        let err = CompromisePricing::compute(&empty, 100_000.0, 0.9)
            .expect_err("empty trajectories cannot be priced");

        assert!(matches!(err, BpetEconError::InvalidTrajectory(_)));
    }

    #[test]
    fn negative_intervention_rejects_zero_cost() {
        let err = InterventionRoi::compute("zero-cost", 0.0, 0.5, 100_000.0)
            .expect_err("zero-cost interventions must be rejected");

        assert!(matches!(err, BpetEconError::InvalidCost(value) if value == 0.0));
    }

    #[test]
    fn negative_intervention_rejects_infinite_cost() {
        let err = InterventionRoi::compute("infinite-cost", f64::INFINITY, 0.5, 100_000.0)
            .expect_err("infinite intervention costs must be rejected");

        assert!(matches!(err, BpetEconError::InvalidCost(value) if value.is_infinite()));
    }

    #[test]
    fn negative_empty_motif_library_produces_no_matches() {
        let matches = match_motifs(&trajectory(), &[]);

        assert!(matches.is_empty());
    }

    #[test]
    fn negative_unknown_motif_indicator_is_ignored() {
        let motif = CompromiseMotif {
            motif_id: "unknown-indicator".to_string(),
            name: "Unknown Indicator".to_string(),
            description: "indicator should not map to phenotype fields".to_string(),
            indicators: vec![MotifIndicator {
                indicator_name: "not_a_real_indicator".to_string(),
                threshold: 0.0,
                direction: ThresholdDirection::Above,
            }],
            historical_frequency: 0.5,
            typical_time_to_compromise_days: 30.0,
        };

        let matches = match_motifs(&trajectory(), &[motif]);

        assert!(matches.is_empty());
    }

    #[test]
    fn negative_engine_rejects_empty_trajectory_without_audit_log() {
        let mut engine = BpetEconomicEngine::default();
        let empty = PhenotypeTrajectory {
            package_name: "empty".to_string(),
            observations: Vec::new(),
        };

        let err = engine
            .generate_guidance(&empty, 100_000.0, 0.9, "trace-empty")
            .expect_err("empty trajectories must not generate guidance");

        assert!(matches!(err, BpetEconError::InvalidTrajectory(_)));
        assert!(engine.audit_log().is_empty());
    }

    #[test]
    fn negative_threshold_direction_rejects_unknown_json_variant() {
        let result: Result<ThresholdDirection, _> = serde_json::from_str(r#""sideways""#);

        assert!(result.is_err());
    }

    #[test]
    fn negative_recommendation_rejects_unknown_json_variant() {
        let result: Result<InterventionRecommendation, _> = serde_json::from_str(r#""definitely""#);

        assert!(result.is_err());
    }

    #[test]
    fn negative_playbook_urgency_rejects_unknown_json_variant() {
        let result: Result<PlaybookUrgency, _> = serde_json::from_str(r#""panic_now""#);

        assert!(result.is_err());
    }
}

#[cfg(test)]
mod bpet_mod_extra_negative_cases {
    use super::economic_integration::{
        CompromiseMotif, CompromisePricing, InterventionRecommendation, InterventionRoi,
        MotifIndicator, PhenotypeObservation, PhenotypeTrajectory, ThresholdDirection,
        match_motifs,
    };

    fn observation() -> PhenotypeObservation {
        PhenotypeObservation {
            timestamp: "2026-04-17T18:00:00Z".to_string(),
            maintainer_activity_score: 0.1,
            commit_velocity: 0.2,
            issue_response_time_hours: 600.0,
            dependency_churn_rate: 0.8,
            security_patch_latency_hours: 720.0,
            contributor_diversity_index: 0.1,
        }
    }

    fn trajectory() -> PhenotypeTrajectory {
        PhenotypeTrajectory {
            package_name: "bpet-extra-negative".to_string(),
            observations: vec![observation()],
        }
    }

    #[test]
    fn extra_negative_trajectory_json_missing_observations_is_rejected() {
        let decoded: Result<PhenotypeTrajectory, _> =
            serde_json::from_str(r#"{"package_name":"missing-observations"}"#);

        assert!(decoded.is_err());
    }

    #[test]
    fn extra_negative_observation_json_rejects_non_numeric_metric() {
        let decoded: Result<PhenotypeObservation, _> = serde_json::from_str(
            r#"{
                "timestamp":"2026-04-17T18:00:00Z",
                "maintainer_activity_score":"low",
                "commit_velocity":1.0,
                "issue_response_time_hours":1.0,
                "dependency_churn_rate":0.1,
                "security_patch_latency_hours":1.0,
                "contributor_diversity_index":0.5
            }"#,
        );

        assert!(decoded.is_err());
    }

    #[test]
    fn extra_negative_zero_indicator_motif_never_matches() {
        let motif = CompromiseMotif {
            motif_id: "zero-indicators".to_string(),
            name: "Zero Indicator Motif".to_string(),
            description: "A motif without indicators must not match".to_string(),
            indicators: Vec::new(),
            historical_frequency: 1.0,
            typical_time_to_compromise_days: 1.0,
        };

        let matches = match_motifs(&trajectory(), &[motif]);

        assert!(matches.is_empty());
    }

    #[test]
    fn extra_negative_partial_motif_below_half_threshold_is_dropped() {
        let motif = CompromiseMotif {
            motif_id: "below-half".to_string(),
            name: "Below Half".to_string(),
            description: "Only one of three indicators should match".to_string(),
            indicators: vec![
                MotifIndicator {
                    indicator_name: "maintainer_activity".to_string(),
                    threshold: 0.2,
                    direction: ThresholdDirection::Below,
                },
                MotifIndicator {
                    indicator_name: "commit_velocity".to_string(),
                    threshold: 100.0,
                    direction: ThresholdDirection::Above,
                },
                MotifIndicator {
                    indicator_name: "issue_response_time".to_string(),
                    threshold: 1_000.0,
                    direction: ThresholdDirection::Above,
                },
            ],
            historical_frequency: 1.0,
            typical_time_to_compromise_days: 1.0,
        };

        let matches = match_motifs(&trajectory(), &[motif]);

        assert!(matches.is_empty());
    }

    #[test]
    fn extra_negative_nan_risk_reduction_clamps_to_no_roi() {
        let roi = InterventionRoi::compute("nan-risk", 100.0, f64::NAN, 10_000.0)
            .expect("non-finite risk reduction should be sanitized");

        assert_eq!(roi.risk_reduction, 0.0);
        assert_eq!(roi.expected_loss_avoided, 0.0);
        assert_eq!(roi.roi_ratio, 0.0);
        assert!(roi.payback_period_days.is_infinite());
        assert_eq!(
            roi.recommendation,
            InterventionRecommendation::NotRecommended
        );
    }

    #[test]
    fn extra_negative_infinite_expected_loss_clamps_to_no_roi() {
        let roi = InterventionRoi::compute("infinite-loss", 100.0, 0.5, f64::INFINITY)
            .expect("non-finite expected loss should be sanitized");

        assert_eq!(roi.expected_loss_avoided, 0.0);
        assert_eq!(roi.roi_ratio, 0.0);
        assert!(roi.payback_period_days.is_infinite());
        assert_eq!(
            roi.recommendation,
            InterventionRecommendation::NotRecommended
        );
    }

    #[test]
    fn extra_negative_nan_expected_loss_does_not_propagate_into_pricing() {
        let pricing = CompromisePricing::compute(&trajectory(), f64::NAN, 0.8)
            .expect("non-finite expected loss should be sanitized");

        assert_eq!(pricing.expected_loss_if_compromised, 0.0);
        assert_eq!(pricing.risk_adjusted_cost, 0.0);
        assert_eq!(pricing.insurance_premium_equivalent, 0.0);
    }

    #[test]
    fn extra_negative_infinite_confidence_clamps_to_zero() {
        let pricing = CompromisePricing::compute(&trajectory(), 100_000.0, f64::INFINITY)
            .expect("non-finite confidence should be sanitized");

        assert_eq!(pricing.confidence, 0.0);
        assert!(pricing.risk_adjusted_cost.is_finite());
    }
}
