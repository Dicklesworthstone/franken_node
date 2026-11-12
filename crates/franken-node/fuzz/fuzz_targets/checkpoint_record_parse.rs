#![no_main]
#![forbid(unsafe_code)]

use frankenengine_node::runtime::checkpoint::{
    CheckpointBackend, CheckpointContract, CheckpointEvent, CheckpointMeta, CheckpointRecord,
    CheckpointWriter, InMemoryCheckpointBackend,
};
use libfuzzer_sys::fuzz_target;

/// Fuzz harness for checkpoint record deserialization and chain-validation robustness.
fuzz_target!(|data: &[u8]| {
    if data.len() > 100_000 {
        return;
    }

    if let Ok(record) = serde_json::from_slice::<CheckpointRecord>(data) {
        let reserialized =
            serde_json::to_string(&record).expect("parsed CheckpointRecord must serialize");
        let reparsed = serde_json::from_str::<CheckpointRecord>(&reserialized)
            .expect("serialized CheckpointRecord must reparse");
        assert_eq!(
            record, reparsed,
            "CheckpointRecord round-trip must be lossless"
        );

        let derived_meta = CheckpointMeta::from(&record);
        assert_eq!(derived_meta.checkpoint_id, record.checkpoint_id);
        assert_eq!(derived_meta.orchestration_id, record.orchestration_id);

        let mut writer = CheckpointWriter::new(InMemoryCheckpointBackend::default());
        let _ = writer.backend_mut().save(record.clone());
        let _ = writer.list_checkpoints(&record.orchestration_id);
        let _ = writer.read_latest_valid("fuzz-record-parse", &record.orchestration_id);
    }

    if let Ok(meta) = serde_json::from_slice::<CheckpointMeta>(data) {
        let encoded = serde_json::to_string(&meta).expect("CheckpointMeta must serialize");
        let decoded =
            serde_json::from_str::<CheckpointMeta>(&encoded).expect("CheckpointMeta must reparse");
        assert_eq!(meta, decoded);
    }

    if let Ok(event) = serde_json::from_slice::<CheckpointEvent>(data) {
        let encoded = serde_json::to_string(&event).expect("CheckpointEvent must serialize");
        let decoded = serde_json::from_str::<CheckpointEvent>(&encoded)
            .expect("CheckpointEvent must reparse");
        assert_eq!(event, decoded);
    }
});
