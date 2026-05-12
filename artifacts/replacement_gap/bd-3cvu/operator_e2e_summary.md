# bd-3cvu Operator E2E Summary

**Verdict:** PASS
**Trace:** `trace-bd-3cvu-control-channel-operator-e2e`

Scenarios:
- `valid_control_traffic`: ACCEPT (fresh_epoch_nonce)
- `guessed_token_injection_failure`: REJECT_AUTH (forged_mac)
- `replay_failure_after_restart_boundary`: REJECT_REPLAY (sequence_seen_in_replay_window)
- `capability_attenuation_failure`: REJECT_AUTH (attenuated_audience_or_direction_caveat_mismatch)

Log: `artifacts/replacement_gap/bd-3cvu/operator_e2e_log.jsonl`
Protocol vector index: `artifacts/replacement_gap/bd-3cvu/protocol_vector_index.json`
