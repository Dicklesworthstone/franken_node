# bd-1z5a.3 Operator E2E Summary

- Trace ID: `trace-bd-1z5a-operator-e2e-final`
- Verdict: **PASS**
- Build IDs: `4270, 4271, 4266, 4268, 4269`
- Build ID Kind: `daemon_build_id` when retained by `rch status --jobs`; otherwise persisted `telemetry_test_run_id` from `~/.local/share/rch/telemetry/telemetry.db`

| Stage | Event | Decision | Reason | Status | Exit | Build ID | Kind | Worker | Completed | Duration ms |
|---|---|---|---|---|---:|---|---|---|---|---:|
| capsule_verify_success | `CAPSULE_VERIFY_PASSED` | `allow` | `CAPSULE_REPLAY_MATCH` | pass | 0 | `4270` | `telemetry_test_run_id` | `vmi1264463` | `2026-03-09T19:25:24Z` | 849796 |
| capsule_verify_reject_tampered | `CAPSULE_VERIFY_REJECTED` | `deny` | `ERR_VEP_INVALID_CAPSULE` | pass | 0 | `4271` | `telemetry_test_run_id` | `vmi1149989` | `2026-03-09T19:27:17Z` | 324934 |
| capsule_verify_fraud_proof | `CAPSULE_VERIFY_FRAUD_PROOF_EXTRACTED` | `deny` | `ERR_PIPE_VALIDATION_FAILURE` | pass | 0 | `4266` | `telemetry_test_run_id` | `vmi1264463` | `2026-03-09T19:12:43Z` | 748318 |
| capsule_verify_quarantine_replay | `CAPSULE_VERIFY_QUARANTINE_REPLAYED` | `quarantine` | `QUARANTINE_REPRODUCED` | pass | 0 | `4268` | `telemetry_test_run_id` | `vmi1149989` | `2026-03-09T19:18:29Z` | 292656 |
| verifier_score_update | `VERIFIER_SCORE_UPDATED` | `score_update` | `EVT_SCOREBOARD_UPDATED` | pass | 0 | `4269` | `telemetry_test_run_id` | `vmi1149989` | `2026-03-09T19:19:20Z` | 1763 |
