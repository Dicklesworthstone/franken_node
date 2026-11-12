#![no_main]
#![forbid(unsafe_code)]

use frankenengine_node::runtime::checkpoint::{
    CheckpointBackend, CheckpointContract, CheckpointEvent, CheckpointMeta, CheckpointRecord,
    CheckpointWriter, InMemoryCheckpointBackend,
};
use libfuzzer_sys::fuzz_target;

/// Adversarial fuzz harness for checkpoint serialization and hash-chain verification.
fuzz_target!(|data: &[u8]| {
    if data.len() > 100_000 {
        return;
    }

    if let Ok(record) = serde_json::from_slice::<CheckpointRecord>(data) {
        let reserialized =
            serde_json::to_vec(&record).expect("parsed CheckpointRecord must serialize");
        let reparsed = serde_json::from_slice::<CheckpointRecord>(&reserialized)
            .expect("serialized CheckpointRecord must reparse");
        assert_eq!(record, reparsed, "CheckpointRecord round-trip failure");

        let orchestration_id = record.orchestration_id.clone();
        let mut writer = CheckpointWriter::new(InMemoryCheckpointBackend::default());
        let first_insert = writer
            .backend_mut()
            .save(record.clone())
            .expect("in-memory save must succeed");
        assert!(first_insert, "initial save in empty backend must insert");
        let duplicate_insert = writer
            .backend_mut()
            .save(record.clone())
            .expect("duplicate save must succeed idempotently");
        assert!(
            !duplicate_insert,
            "duplicate checkpoint_id must be idempotent"
        );

        let read_a = writer
            .read_latest_valid("fuzz-trace", &orchestration_id)
            .expect("read_latest_valid must not error on in-memory backend");
        let read_b = writer
            .read_latest_valid("fuzz-trace", &orchestration_id)
            .expect("read_latest_valid must be deterministic");
        assert_eq!(read_a.latest, read_b.latest);
        let _ = writer.restore_checkpoint::<serde_json::Value>("fuzz-trace", &orchestration_id);
    }

    if let Ok(meta) = serde_json::from_slice::<CheckpointMeta>(data) {
        let serialized = serde_json::to_vec(&meta).expect("CheckpointMeta must serialize");
        let reparsed = serde_json::from_slice::<CheckpointMeta>(&serialized)
            .expect("CheckpointMeta must reparse");
        assert_eq!(meta, reparsed, "CheckpointMeta round-trip failure");
    }

    if let Ok(event) = serde_json::from_slice::<CheckpointEvent>(data) {
        let serialized = serde_json::to_vec(&event).expect("CheckpointEvent must serialize");
        let reparsed = serde_json::from_slice::<CheckpointEvent>(&serialized)
            .expect("CheckpointEvent must reparse");
        assert_eq!(event, reparsed, "CheckpointEvent round-trip failure");
    }
});
