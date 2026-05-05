# Concurrency Lock Ordering Convention

## Overview

To prevent deadlocks, all code MUST acquire locks in the canonical order specified below. This enforces a strict hierarchy that prevents AB-BA deadlock scenarios.

## Lock Hierarchy (acquire in this order)

1. **File system locks** (`flock`, `try_lock()` on files)
2. **Process-level static locks** (global `OnceLock<Mutex<()>>` instances)
3. **Module-level locks** (component state, e.g., `fleet_transport`, `compaction`)  
4. **Object-level locks** (per-instance data, local mutexes)

Within the same level, acquire locks in **alphabetical order** by variable/field name.

## Examples

### ✅ Correct ordering
```rust
// File system lock FIRST
let file_lock = acquire_file_lock(path)?;

// Then process-level lock  
let process_guard = global_process_lock().lock()?;

// Then module locks (alphabetical)
let compaction_guard = compaction_state.lock()?;
let shared_state_guard = shared_state.lock()?;

// Finally object locks (alphabetical)
let metrics_guard = self.metrics.lock()?;
let results_guard = self.results.lock()?;
```

### ❌ Incorrect ordering (deadlock risk)
```rust
// WRONG: object lock before module lock
let results_guard = self.results.lock()?;
let shared_state_guard = shared_state.lock()?; // Deadlock risk!
```

## Enforcement

- All multi-lock code MUST follow this hierarchy
- Use `try_lock()` with timeout for lock contention detection
- Add regression tests for multi-lock paths under contention
- Document lock ordering decisions in comments

## References

- fleet_transport.rs:717-718: compaction → shared_state ordering
- trust_card.rs:1347-1348: file flock → process mutex ordering