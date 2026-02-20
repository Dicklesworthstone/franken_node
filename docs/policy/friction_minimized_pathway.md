# Friction-Minimized Install-to-Production Pathway Policy

**Bead:** bd-34d5
**Section:** 13 -- Friction-Minimized Install-to-Production Pathway
**Status:** In Progress

---

## 1. Pathway Definition

The friction-minimized pathway is a four-step sequence that takes a user from
having no franken_node installation to running their first policy-governed
production operation.  The balanced profile is the default and must require
**zero manual file edits**.

### Steps

```
install --> init --> configure --> run --policy balanced
```

| Step        | Command                                          | Purpose                                  |
|-------------|--------------------------------------------------|------------------------------------------|
| **Install** | `curl -fsSL https://get.frankennode.dev \| sh`   | Download and place binary on PATH        |
| **Init**    | `franken-node init`                              | Auto-detect archetype, scaffold config   |
| **Configure** | `franken-node configure --profile balanced`   | Apply balanced policy without manual edits |
| **Run**     | `franken-node run --policy balanced`             | Start first policy-governed operation    |

---

## 2. Archetypes

Five representative project archetypes cover the breadth of the Node.js
ecosystem.  Each archetype has an expected minimum compatibility score that
the pathway must achieve.

| ID  | Archetype         | Marker Files                               | Expected Compat Score |
|-----|-------------------|--------------------------------------------|----------------------|
| A-1 | Express API       | `package.json` with `express` dep          | >= 0.90              |
| A-2 | React SPA         | `package.json` with `react-scripts`/`vite` | >= 0.85              |
| A-3 | CLI Tool          | `package.json` with `bin` field            | >= 0.92              |
| A-4 | Monorepo          | `turbo.json` or `nx.json` at root          | >= 0.80              |
| A-5 | Serverless        | `serverless.yml` or `vercel.json`          | >= 0.88              |

### Archetype Detection

`franken-node init` inspects the project root for marker files and selects the
matching archetype.  If no archetype matches, the generic archetype is used
with a compatibility score floor of 0.75.

---

## 3. Time Budget Enforcement

Each step has a hard wall-clock cap.  If a step exceeds its cap the pathway
emits FMP-004 and aborts with a clear error.

| Step      | Max Duration | Cumulative Max |
|-----------|-------------|----------------|
| Install   | 60 s        | 60 s           |
| Init      | 30 s        | 90 s           |
| Configure | 30 s        | 120 s          |
| Run       | 180 s       | 300 s          |

**INV-FMP-TIME:** Total pathway wall-clock time MUST be < 300 seconds for every
archetype in CI testing.

---

## 4. Zero-Edit Requirement

**INV-FMP-ZERO-EDIT:** The balanced-profile onboarding MUST require zero manual
file edits.  This means:

- `franken-node init` generates all necessary configuration files.
- `franken-node configure --profile balanced` applies sensible defaults.
- The user does not need to open an editor, modify JSON/YAML, or create any
  file by hand before `franken-node run --policy balanced` succeeds.

If a project's structure requires non-default settings, the init step must
detect this and scaffold the correct configuration automatically.

---

## 5. Progress Telemetry Requirements

**INV-FMP-TELEMETRY:** Every pathway step MUST emit a structured telemetry
event.  Events are JSON objects written to stdout (when `--json` is active) or
to the telemetry sink.

### Event Schema

```json
{
  "code": "FMP-001",
  "step": "install",
  "archetype": "express_api",
  "elapsed_ms": 12345,
  "timestamp_utc": "2026-02-20T12:00:00Z",
  "metadata": {}
}
```

### Event Codes

| Code    | Name              | When Emitted                                         |
|---------|-------------------|------------------------------------------------------|
| FMP-001 | pathway_started   | Install command begins execution                     |
| FMP-002 | step_completed    | Any pathway step finishes successfully               |
| FMP-003 | pathway_succeeded | Final run step completes with policy active          |
| FMP-004 | pathway_failed    | Any step fails, times out, or budget is exceeded     |

### Rules

- FMP-001 is emitted exactly once per pathway execution.
- FMP-002 is emitted once per successfully completed step (up to 4 times).
- FMP-003 is emitted exactly once on full success.
- FMP-004 is emitted at most once; it terminates the pathway.
- FMP-003 and FMP-004 are mutually exclusive within a single pathway run.

---

## 6. Error Handling

### Principles

1. **No silent failures.** Every non-zero exit code MUST emit FMP-004 with a
   descriptive message.
2. **Clear messages.** Error output MUST include:
   - Which step failed.
   - What went wrong (human-readable description).
   - The elapsed time at failure.
3. **Recovery suggestions.** Every FMP-004 event MUST include a `recovery`
   field in its metadata with an actionable suggestion, e.g.:
   ```json
   {
     "code": "FMP-004",
     "step": "init",
     "metadata": {
       "error": "No package.json found in current directory",
       "recovery": "Run 'npm init -y' first, then re-run 'franken-node init'"
     }
   }
   ```
4. **Idempotency.** Re-running a failed pathway from the beginning MUST NOT
   corrupt state created by earlier successful steps.

---

## 7. CI Gate

**INV-FMP-ARCHETYPES:** All 5 archetypes MUST be tested in CI on every merge
to main.

### CI Job Structure

```yaml
friction-pathway-gate:
  strategy:
    matrix:
      archetype: [express_api, react_spa, cli_tool, monorepo, serverless]
  steps:
    - scaffold archetype fixture
    - run full pathway (install -> init -> configure -> run)
    - assert total elapsed < 300s
    - assert zero manual edits required
    - assert all telemetry events emitted
    - collect verification evidence
```

### Gate Failure

If any archetype fails the pathway gate, the merge is blocked.  The gate
produces a JSON report compatible with `scripts/check_friction_pathway.py
--json`.

---

## 8. Verification

The verification script `scripts/check_friction_pathway.py` checks:

1. Spec file exists and contains required sections.
2. Policy file exists and contains required sections.
3. All 5 archetypes are defined with compatibility scores.
4. Time budget is specified (< 300s total).
5. Zero-edit requirement is documented.
6. All 4 event codes (FMP-001 through FMP-004) are defined.
7. All 4 invariants (INV-FMP-*) are present.
8. Error handling policy covers clear messages, recovery suggestions, no silent
   failures.

Evidence is recorded at `artifacts/section_13/bd-34d5/verification_evidence.json`.
