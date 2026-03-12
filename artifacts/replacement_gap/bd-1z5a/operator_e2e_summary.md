# bd-1z5a.3 Operator E2E Summary

- Trace ID: `trace-bd-1z5a-operator-e2e-final`
- Verdict: **PASS**
- Build IDs: `4270, 4271, 4266, 4268, 4269`

| Stage | Event | Decision | Reason | Status | Exit | Build ID |
|---|---|---|---|---|---:|---|
| capsule_verify_success | `CAPSULE_VERIFY_PASSED` | `allow` | `CAPSULE_REPLAY_MATCH` | pass | 0 | `4270` |
| capsule_verify_reject_tampered | `CAPSULE_VERIFY_REJECTED` | `deny` | `ERR_VEP_INVALID_CAPSULE` | pass | 0 | `4271` |
| capsule_verify_fraud_proof | `CAPSULE_VERIFY_FRAUD_PROOF_EXTRACTED` | `deny` | `ERR_PIPE_VALIDATION_FAILURE` | pass | 0 | `4266` |
| capsule_verify_quarantine_replay | `CAPSULE_VERIFY_QUARANTINE_REPLAYED` | `quarantine` | `QUARANTINE_REPRODUCED` | pass | 0 | `4268` |
| verifier_score_update | `VERIFIER_SCORE_UPDATED` | `score_update` | `EVT_SCOREBOARD_UPDATED` | pass | 0 | `4269` |
