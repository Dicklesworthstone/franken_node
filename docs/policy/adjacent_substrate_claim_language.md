# Adjacent Substrate Claim Language Policy

**Bead:** bd-2ji2 | **Section:** 10.16

## Purpose

Every claim about franken_node's TUI, API, storage, or model capabilities in
documentation, README, release notes, or marketing materials must be backed by
a specific substrate conformance artifact. Unlinked or aspirational claims are
blocked at the gate.

## Claim Categories

| Category | Description | Required Evidence |
|----------|-------------|-------------------|
| TUI | Any assertion about interactive display, rendering, or terminal behavior | frankentui snapshot test or migration inventory |
| API | Any assertion about HTTP endpoints, request handling, or service behavior | fastapi_rust endpoint conformance report |
| Storage | Any assertion about persistence, durability, crash-safety, or data retention | frankensqlite adapter conformance report or persistence matrix |
| Model | Any assertion about typed schema, query safety, or data model guarantees | sqlmodel_rust contract test results |

## What Constitutes a "Claim"

A claim is any statement in documentation that asserts a verifiable capability:
- "franken_node provides persistent audit logging" (Storage claim)
- "operators can view connector health in an interactive dashboard" (TUI claim)
- "the fleet API supports batch rollout operations" (API claim)
- "all config is stored in typed, schema-validated tables" (Model claim)

## Evidence Linking Rules

Each claim must include a reference to one or more conformance artifacts:

```markdown
franken_node provides persistent audit logging.
<!-- claim:storage artifact:artifacts/10.16/frankensqlite_conformance.json -->
```

### Linking Syntax

Claims are linked via HTML comments in markdown:
```
<!-- claim:<category> artifact:<path> -->
```

Where `<category>` is one of: `tui`, `api`, `storage`, `model`.

## Scanned Files

The claim gate scans the following file patterns for claims:
- `README.md`
- `docs/**/*.md`
- `CHANGELOG.md`
- Release notes

## Blocking Behavior

| Condition | Gate Result |
|-----------|-------------|
| All claims linked with valid artifacts | PASS |
| Unlinked claim (no artifact reference) | FAIL |
| Broken link (artifact file missing) | FAIL |
| Failed artifact (test did not pass) | FAIL |

## Language Standards

- Use verifiable language: "verified by artifact X", "validated in conformance test Y"
- Avoid aspirational language: "planned", "designed to", "will support"
- Every claim must be present-tense and evidence-backed

## Event Codes

| Code | Level | Meaning |
|------|-------|---------|
| `CLAIM_GATE_SCAN_START` | info | Claim gate scan initiated |
| `CLAIM_LINKED` | debug | Claim successfully linked to artifact |
| `CLAIM_UNLINKED` | error | Claim found without artifact reference |
| `CLAIM_LINK_BROKEN` | error | Claim references non-existent artifact |
| `CLAIM_GATE_PASS` | info | All claims verified |
| `CLAIM_GATE_FAIL` | error | Gate blocked due to unlinked/broken claims |
