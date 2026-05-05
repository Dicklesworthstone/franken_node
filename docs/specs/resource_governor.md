# Resource Governor Telemetry

`franken-node ops resource-governor` emits a deterministic advisory report before agents launch expensive validation proof work.

The command supports live process observation through `/proc` and fixture-driven replay through `--process-snapshot <path>`. Snapshot JSON uses the same observation fields as the report:

```json
{
  "observed_at": "2026-05-05T12:00:00Z",
  "source": "fixture",
  "processes": [
    {"pid": 31, "command": "cargo check -p frankenengine-node"},
    {"pid": 32, "command": "rustc --crate-name frankenengine_node"}
  ],
  "rch_queue_depth": 2,
  "active_proof_classes": ["cargo-check"],
  "target_dir_usage_mb": 8192,
  "memory_used_mb": 64000,
  "cpu_load_permyriad": 7500
}
```

Typical agent preflight:

```bash
franken-node ops resource-governor \
  --requested-proof-class cargo-check \
  --active-proof-class cargo-test \
  --rch-queue-depth 2 \
  --source-only-allowed \
  --trace-id bd-ksb41 \
  --json
```

The JSON report schema is `franken-node/resource-governor/report/v1`. The decision is one of:

| Decision | Meaning |
|---|---|
| `allow` | Cargo/RCH validation may run. |
| `allow_low_priority` | Validation may run only as low-priority remote work or after the reported backoff. |
| `dedupe_only` | An equivalent proof class is already active; wait for or reuse that receipt. |
| `source_only` | Validation pressure is high, but source-only work may continue with the emitted reason code. |
| `defer` | Do not start cargo/RCH validation until the reported backoff has elapsed and telemetry has been refreshed. |

Every report includes `trace_id`, process counts, optional RCH queue depth, active proof classes, thresholds, `recommended_backoff_ms`, and a structured log object with event code `RG-002` and the decision reason code.
