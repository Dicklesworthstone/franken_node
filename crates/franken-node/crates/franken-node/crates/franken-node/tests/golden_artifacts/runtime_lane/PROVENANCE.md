# Runtime Lane Golden Artifacts Provenance

## Generation Method

These golden artifacts capture the canonical JSON output of runtime lane CLI commands:

- `runtime lane status --json` - Lane policy and telemetry snapshot
- `runtime lane assign <task_class> --json` - Task assignment results

## Commands Used

```bash
# Status output
franken-node runtime lane status --json

# Basic assignment 
franken-node runtime lane assign epoch_transition --json

# Assignment with timestamp
franken-node runtime lane assign log_rotation --json --timestamp-ms 1698768000000

# Assignment with custom trace ID
franken-node runtime lane assign log_rotation --json --trace-id test-custom-trace-123 --timestamp-ms 1698768000000
```

## Scrubbing Rules

Dynamic values are canonicalized for stability:

- `timestamp`, `created_at`, `updated_at` → `[TIMESTAMP]`
- `assignment_id` → `[ASSIGNMENT_ID]` 
- `task_id` → `[TASK_ID]`
- `session_id` → `[SESSION_ID]`
- `memory_usage_bytes` → `[MEMORY_USAGE]`
- `cpu_time_ns` → `[CPU_TIME]`

## Update Process

To regenerate these golden artifacts:

```bash
cd crates/franken-node
UPDATE_GOLDENS=1 cargo test runtime_lane_.*_golden
git diff tests/golden_artifacts/runtime_lane/
# Review changes, then commit
```

## Schema Stability

These artifacts ensure the JSON schema remains stable for:
- External monitoring tools parsing CLI output
- CI/CD pipelines consuming structured runtime data
- Integration tests expecting specific JSON shapes

Breaking changes to the JSON structure should be reviewed carefully and documented.