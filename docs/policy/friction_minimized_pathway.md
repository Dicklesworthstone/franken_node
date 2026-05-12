# Friction-Minimized Install-to-Production Pathway Policy

**Bead:** bd-34d5
**Section:** 13 -- Friction-Minimized Install-to-Production Pathway
**Status:** Reality-Checked

---

## 1. Current Shipped Surface

The repository does **not** currently ship the full friction-minimized pathway
described in bd-34d5. What is live today is a narrower operator bootstrap
surface:

```
raw GitHub install.sh --> init bootstrap/report --> run ./my-app --policy balanced
```

| Step        | Command                                                                 | Repository Reality |
|-------------|-------------------------------------------------------------------------|--------------------|
| **Install** | `curl -fsSL https://raw.githubusercontent.com/Dicklesworthstone/franken_node/main/install.sh \| bash` | The shipped installer is the raw GitHub `install.sh` flow. There is no `get.frankennode.dev` installer alias in the checked-in product surface. |
| **Init**    | `franken-node init --profile balanced`                                  | Bootstraps `.franken-node/` state, optionally runs `--scan`, and prints the resolved config TOML to stdout by default unless `--out-dir` is supplied. |
| **Run**     | `franken-node run ./my-app --policy balanced`                           | Requires an explicit application path. The current CLI does not support a zero-argument `run --policy balanced` first-run path. |

### Current Limitations

- `franken-node init` does **not** auto-detect archetypes during onboarding.
- The five archetypes documented below exist as migration-kit concepts, not as
  live init-time detection behavior.
- Current command-local reporting surfaces are `franken-node init --json`,
  `franken-node init --structured-logs-jsonl`, `franken-node run --json`, and
  `franken-node run --structured-logs-jsonl`.
- FMP-001 through FMP-004 pathway telemetry events are **not** emitted by the
  current CLI or test surface.
- The balanced onboarding path does **not** currently guarantee zero manual
  file edits because config is emitted to stdout unless the operator supplies
  `--out-dir`.

## 2. Planned Target Pathway

The section-13 target remains a three-step install-to-first-policy path with
no manual edits and stable step telemetry. That target is not yet shipped and
must not be described as current behavior.

```
install --> init --profile balanced --> run ./my-app --policy balanced
```

| Step        | Target Command                                      | Intended Purpose |
|-------------|-----------------------------------------------------|------------------|
| **Install** | `curl -fsSL https://get.frankennode.dev \| sh`      | Stable vanity installer URL and PATH bootstrap |
| **Init**    | `franken-node init --profile balanced`              | Future archetype-aware onboarding with generated config and defaults |
| **Run**     | `franken-node run ./my-app --policy balanced`       | First policy-governed operation on an explicit application entrypoint |

---

## 3. Archetypes

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

### Archetype Detection Status

The migration kit defines these archetypes and their compatibility expectations,
but `franken-node init` does **not** currently inspect marker files or bind the
selected archetype into onboarding output. A future friction-minimized pathway
may adopt archetype-aware init behavior, but that is not a shipped invariant.

---

## 4. Time Budget Enforcement

Each step has a hard wall-clock cap.  If a step exceeds its cap the pathway
emits FMP-004 and aborts with a clear error.

| Step      | Max Duration | Cumulative Max |
|-----------|-------------|----------------|
| Install   | 60 s        | 60 s           |
| Init      | 60 s        | 120 s          |
| Run       | 180 s       | 300 s          |

**INV-FMP-TIME:** Total pathway wall-clock time MUST be < 300 seconds for every
archetype in CI testing once the full target pathway is implemented. The
current repository gate documents this target but does not prove it against a
live end-to-end onboarding flow.

---

## 5. Zero-Edit Requirement

**INV-FMP-ZERO-EDIT:** The target balanced-profile onboarding MUST require zero
manual file edits.  This means:

- `franken-node init --profile balanced` generates all necessary configuration files and applies sensible defaults.
- The user does not need to open an editor, modify JSON/YAML, or create any
  file by hand before `franken-node run --policy balanced` succeeds.

If a project's structure requires non-default settings, the future init step
must detect this and scaffold the correct configuration automatically.

Current reality: `franken-node init --profile balanced` prints resolved config
to stdout by default and therefore does not yet satisfy the full zero-edit
claim without additional operator choices such as `--out-dir`.

---

## 6. Progress Telemetry Requirements

**INV-FMP-TELEMETRY:** Every pathway step in the future friction-minimized path
MUST emit a structured telemetry event. Events are JSON objects written to
stdout (when `--json` is active) or to the telemetry sink.

Current reality: repository search over `crates/franken-node/src/`,
`crates/franken-node/tests/`, and `sdk/verifier/src/` shows no live FMP-001,
FMP-002, FMP-003, or FMP-004 emission path today. The codes below are reserved
target semantics and are not emitted by the current CLI.

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
- FMP-002 is emitted once per successfully completed step (up to 3 times).
- FMP-003 is emitted exactly once on full success.
- FMP-004 is emitted at most once; it terminates the pathway.
- FMP-003 and FMP-004 are mutually exclusive within a single pathway run.

---

## 7. Error Handling

### Principles

1. **No silent failures.** Every non-zero exit code in the future pathway MUST
   emit FMP-004 with a descriptive message.
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

Current shipped `init` and `run` behavior already expose human-readable and
JSON reports, but they do not currently wrap failures in the FMP telemetry
contract above.

---

## 8. CI Gate

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
    - run full pathway (install -> init -> run)
    - assert total elapsed < 300s
    - assert zero manual edits required
    - assert all telemetry events emitted
    - collect verification evidence
```

### Gate Failure

If any archetype fails the pathway gate, the merge is blocked. The current gate
is documentation- and contract-oriented: it verifies the docs distinguish the
current shipped surface from the future target pathway instead of pretending
the target flow is already live.

The current-reality sentinel is checked by
`tests/e2e/install_to_production_pathway.sh`. It runs the section verifier and
confirms `artifacts/13/onboarding_timing_report.json` has
`target_pathway_shipped=false`; it must not be cited as full end-to-end success.

---

## 9. Verification

The verification script `scripts/check_friction_pathway.py` checks:

1. Spec file exists and contains required sections.
2. Policy file exists and contains required sections.
3. Current shipped pathway steps are documented with the raw GitHub installer,
   explicit `run ./my-app`, and `init` stdout behavior.
4. All 5 archetypes are defined with compatibility scores.
5. Time budget and zero-edit targets remain documented as future contract.
6. All 4 event codes (FMP-001 through FMP-004) remain defined as reserved
   target semantics.
7. All 4 invariants (INV-FMP-*) are present.
8. The docs explicitly state that archetype auto-detection and FMP telemetry
   are not yet implemented in the shipped CLI.
9. Error handling policy covers clear messages, recovery suggestions, and the
   no-silent-failure rule for the future pathway contract.

Evidence is recorded at `artifacts/section_13/bd-34d5/verification_evidence.json`.
The named onboarding timing artifact is recorded at
`artifacts/13/onboarding_timing_report.json`; until the target pathway ships,
it is boundary evidence rather than a passing timing claim.
