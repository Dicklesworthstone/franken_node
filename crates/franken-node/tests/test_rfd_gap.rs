#[cfg(test)]
mod tests {
    use frankenengine_node::control_plane::fork_detection::{
        ForkDetectionError, RollbackDetector, StateVector,
    };

    #[test]
    fn test_rollback_detector_recovers_after_gap() {
        let mut detector = RollbackDetector::new();
        let sv1 = StateVector {
            epoch: 1,
            marker_id: "m1".into(),
            state_hash: "h1".into(),
            parent_state_hash: "h0".into(),
            timestamp: 1000,
            node_id: "node".into(),
        };
        detector.feed(sv1).unwrap();

        // Gap: epoch 3 (skipped 2)
        let sv3 = StateVector {
            epoch: 3,
            marker_id: "m3".into(),
            state_hash: "h3".into(),
            parent_state_hash: "h2".into(),
            timestamp: 1000,
            node_id: "node".into(),
        };
        let err = detector.feed(sv3.clone()).unwrap_err();
        assert!(matches!(err, ForkDetectionError::RfdGapDetected { .. }));

        // Next is epoch 4, parent hash matches epoch 3
        let sv4 = StateVector {
            epoch: 4,
            marker_id: "m4".into(),
            state_hash: "h4".into(),
            parent_state_hash: "h3".into(), // matches sv3's state_hash
            timestamp: 1000,
            node_id: "node".into(),
        };

        // This will fail because last_known is still 1!
        let result = detector.feed(sv4);
        println!("{:?}", result);
        assert!(result.is_ok(), "Expected OK, got {:?}", result);
    }
}
