use frankenengine_node::ops::mitigation_synthesis::{
    LabDecision, build_trace, mitigation_synthesis_length_frame_for_tests,
};

#[test]
fn mitigation_length_frame_preserves_u32_boundary_without_saturation() {
    assert_eq!(
        mitigation_synthesis_length_frame_for_tests(0),
        0u64.to_le_bytes()
    );
    assert_eq!(
        mitigation_synthesis_length_frame_for_tests(1),
        1u64.to_le_bytes()
    );

    if usize::BITS > u32::BITS {
        let u32_max = usize::try_from(u32::MAX).expect("u32 max fits usize on this target");
        let just_over_u32 = u32_max + 1;

        assert_eq!(
            mitigation_synthesis_length_frame_for_tests(u32_max),
            u64::from(u32::MAX).to_le_bytes()
        );
        assert_eq!(
            mitigation_synthesis_length_frame_for_tests(just_over_u32),
            (u64::from(u32::MAX) + 1).to_le_bytes()
        );
        assert_ne!(
            mitigation_synthesis_length_frame_for_tests(just_over_u32),
            mitigation_synthesis_length_frame_for_tests(u32_max)
        );
    }
}

#[test]
fn mitigation_trace_hash_still_separates_adjacent_action_boundaries() {
    let left = build_trace(
        "INC-LEN-LEFT",
        vec![
            LabDecision {
                sequence_number: 1,
                action: "ab".to_string(),
                expected_loss: 10,
                rationale: "left first".to_string(),
            },
            LabDecision {
                sequence_number: 2,
                action: "c".to_string(),
                expected_loss: 5,
                rationale: "left second".to_string(),
            },
        ],
        "policy-v1",
    );
    let right = build_trace(
        "INC-LEN-RIGHT",
        vec![
            LabDecision {
                sequence_number: 1,
                action: "a".to_string(),
                expected_loss: 10,
                rationale: "right first".to_string(),
            },
            LabDecision {
                sequence_number: 2,
                action: "bc".to_string(),
                expected_loss: 5,
                rationale: "right second".to_string(),
            },
        ],
        "policy-v1",
    );

    assert_ne!(left.trace_hash, right.trace_hash);
    left.validate_integrity().expect("left trace remains valid");
    right
        .validate_integrity()
        .expect("right trace remains valid");
}
