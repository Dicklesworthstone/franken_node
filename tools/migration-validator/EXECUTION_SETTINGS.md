# Captured test execution settings

The native migration suite supports package-local working directories, application environment overrides, and binary stdin fixtures. These settings extend the explicit test manifest described in [README.md](README.md). With no `execution` entries, the existing behavior remains: project-root working directory, inherited application environment, and EOF-only stdin.

## Configure a package-local harness

Create `.franken-node/migration-tests.json` in the project root:

```json
{
  "schema_version": "franken-node/migration-tests/v1",
  "tests": [
    "packages/api/check.cjs",
    "packages/worker/check.mjs"
  ],
  "execution": {
    "packages/api/check.cjs": {
      "cwd": "packages/api",
      "stdin": "fixtures/request.bin",
      "environment": {
        "APP_MODE": "migration-test",
        "NODE_ENV": "test",
        "OPTIONAL_API_TOKEN": null
      }
    },
    "packages/worker/check.mjs": {
      "cwd": "packages/worker"
    }
  }
}
```

Every `execution` key must exactly name a selected test. `cwd` and `stdin` are relative to the **project root**, not to one another. The referenced directories and files must already exist in the captured project. The example therefore requires `packages/api/check.cjs`, `packages/worker/check.mjs`, and `fixtures/request.bin`.

`cwd` changes the child process's working directory. The entrypoint must be inside that directory: the API harness above is invoked as `./check.cjs` from the staged `packages/api` directory. This preserves the primary runtime's refusal of absolute and parent-traversal script arguments. Omit `cwd` or use `"."` for the project root. Imports inside the harness remain subject to each runtime's normal module-resolution semantics.

`stdin` selects captured file bytes, including NUL, invalid UTF-8 and trailing newlines. Each runtime and each case receives a fresh anonymous regular-file descriptor at offset zero. A preceding guest cannot consume or change the next guest's input. This models redirected file input, **not a terminal, interactive input, or pipe timing**. There is no stdin writer thread to deadlock when a child does not read or exits early. Omitting `stdin` keeps EOF-only input.

Environment strings set values for that child; `null` removes a variable. Overrides do not leak to other cases or modify the operator's environment. `NODE_ENV` is explicitly supported. Runtime/loader/operator controls such as `NODE_OPTIONS`, `BUN_OPTIONS`, `LD_PRELOAD`, `PATH`, and `FRANKEN_NODE_ALLOW_DEGRADED_RUNTIME_FALLBACK` cannot be set through the manifest. These restrictions do not sanitize or capture the rest of the inherited environment; run only trusted projects in an appropriately controlled environment.

## Inspect and execute

Inspect selection and validate settings without executing project code:

```bash
franken-migration-suite ./project --list-tests
```

Compare original and rewritten projects using both references:

```bash
franken-migration-suite ./project \
  --migrated-project ./rewritten-project \
  --native-bin /trusted/bin/franken-node \
  --bun-bin /trusted/bin/bun \
  --compare-filesystem --execute \
  --capture-capsule ./failure-capsule.json \
  --out ./comparison-report.json
```

Omit `--bun-bin` for Node/native comparison. Omit `--migrated-project` to run the same captured tree on every role. The existing explicit execution-consent requirement remains. Settings do not invoke package installation, infer `package.json` shell scripts, inject test-framework globals, or forward arbitrary runtime arguments.

## Evidence and refusal behavior

The original and candidate must select the same tests with the same normalized execution settings and identical selected stdin bytes. A candidate cannot obtain approval by changing the request, environment, or working directory. Mismatches are refused before runtime resolution or dispatch, not reported as skipped tests or rescued by smoke fallback. Declaring `cwd: "."` is equivalent to omitting it; an explicit environment removal remains distinct from inheriting that variable.

Both comparison modes, primary suite validation, and checked rewrite preparation use the shared captured inventory. Node and Bun receive the original snapshot; native receives the candidate. Filesystem observation still covers the **entire staged project**, not merely the declared working directory. For example, an API harness writing `artifact` reports a change to `packages/api/artifact`.

Manifest settings and fixture bytes are included in the complete input hashes and capsule snapshots. Replay uses those captured settings, not a subsequently edited manifest or request file. Non-source fixtures remain captured data when selected source files are minimized. Reduced capsules retain their original pair/product format and can be replayed and exported normally. The execution-settings implementation is included in the replay implementation fingerprint; retain the producing validator revision.

Only explicitly declared environment overrides are captured. Clocks, network services, dynamic libraries and undeclared ambient environment can still drift. `environment_reproduced` and `release_certification` remain false. Successful reference tests do not establish successful native Franken compatibility.

## Bounds and privacy

The manifest retains its 64 KiB and 1,024-test bounds. A stdin fixture is at most 1 MiB. Per test, at most 64 environment names are permitted, each name at most 128 ASCII identifier bytes, each value at most 4,096 UTF-8 bytes without NUL, and the combined names/values at most 16 KiB. Existing runtime deadlines, output caps and process cleanup remain mandatory.

Working directories, stdin files and their parents must be ordinary captured paths. Escapes, noncanonical spellings, symlinks, missing paths, dependency directories and reserved metadata selections are rejected. Unknown fields and duplicate execution/environment keys are errors, never last-value-wins configuration.

Manifests and fixtures can contain secrets. Capsule storage retains those bytes privately, and offline export reconstructs them: treat both as sensitive source material. Settings diagnostics omit environment values. Workspace copies and private descriptors are not an OS sandbox; guest code still runs with the operator's ambient authority.
