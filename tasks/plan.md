# Implementation Plan: Kona Guard CI Scan Projection

## Overview

Kona v1 captures a local process. v2 adds an evidence contract so an Agent run
can be evaluated against explicit acceptance checks and handed off as a
reviewable report. The contract stays local and dependency-free: it runs one
argv command, snapshots selected workspace files before and after the run,
evaluates bounded assertions, and emits JSON plus Markdown evidence.

## Architecture decisions

- Keep the existing `run_capture` primitive and build contract evaluation as a
  separate module; ordinary users keep the v1 command unchanged.
- Use JSON arrays for commands rather than shell strings so Kona does not add a
  hidden shell interpretation layer.
- Observe only relative paths inside the declared working directory. Record
  file metadata and bounded directory-tree hashes, never file contents in the report.
- Make stdout/stderr and exit status assertions explicit and make a successful
  exit code the default safety assertion when no exit assertion is supplied.
- Redact the stored contract summary and Markdown report, while hashing the
  original contract file so the source can be verified separately.
- Return `0` only when the evidence package is intact and every assertion passes;
  return `1` for a valid but failed contract and `2` for an invalid contract.

## Task list

### Phase 1: Contract foundation

#### Task 1: Define and validate the contract schema

**Acceptance criteria:**

- [x] Load a JSON contract with command, cwd, timeout, observations, and assertions.
- [x] Reject malformed commands, unsafe paths, unknown assertion types, and invalid values.
- [x] Preserve v1 `kona run` behavior.

**Verification:** Unit tests for valid and invalid contracts.

**Dependencies:** None

**Estimated scope:** Medium

#### Task 2: Snapshot workspace evidence

**Acceptance criteria:**

- [x] Record safe relative paths, existence, kind, byte count, and SHA-256 before and after execution.
- [x] Detect created, deleted, modified, and unchanged files.
- [x] Reject path traversal and symlink escapes.

**Verification:** Unit tests for file lifecycle and unsafe paths.

**Dependencies:** Task 1

**Estimated scope:** Medium

### Checkpoint: Foundation

- [x] Existing v1 tests pass.
- [x] Contract schema and snapshot tests pass.

### Phase 2: Outcome evaluation

#### Task 3: Evaluate assertions and generate reports

**Acceptance criteria:**

- [x] Support exit/status, stdout/stderr, file existence/content/change, and file hash assertions.
- [x] Write redacted `report.json` and human-readable `report.md` inside the run directory.
- [x] Include an honest evidence boundary and contract-file hash.

**Verification:** Passing and failing contract tests, including secret redaction.

**Dependencies:** Tasks 1-2

**Estimated scope:** Large

#### Task 4: Expose `kona contract run`

**Acceptance criteria:**

- [x] Run a contract with a bounded timeout and preserve child output.
- [x] Return `0` for fully passing evidence, `1` for failed assertions, and `2` for invalid contracts.
- [x] Print the report location and concise summary.

**Verification:** CLI subprocess tests and manual round trip.

**Dependencies:** Task 3

**Estimated scope:** Medium

### Checkpoint: Core feature

- [x] A sample Agent task can produce a passing report and a failing report.
- [x] `report.json` contains no known credential values.

### Phase 3: Adoption surface

#### Task 5: Document and teach the contract workflow

**Acceptance criteria:**

- [x] README explains why process logs are insufficient and shows a contract example.
- [x] `kona-capture` teaches define → run → inspect → hand off and stop conditions.
- [x] Version and CI metadata reflect v2.

**Verification:** Documentation review, Skill validators, build and CI tests.

**Dependencies:** Tasks 3-4

**Estimated scope:** Medium

## Risks and mitigations

| Risk | Impact | Mitigation |
| --- | --- | --- |
| A report is mistaken for proof of semantic correctness | High | State the evidence boundary and require task-specific assertions. |
| Snapshotting leaks workspace content | High | Persist metadata and hashes only; never copy observed file contents. |
| A contract observes a path outside the workspace | High | Accept relative paths only and reject traversal/symlink escapes. |
| Redaction misses an unusual secret | High | Reuse v1 best-effort redaction, redact reports, and warn users to review before sharing. |
| Different environments produce different results | Medium | Record cwd, command, timeout, file hashes, and contract hash; keep claims local to the run. |

## Definition of done

- All acceptance criteria pass.
- Existing v1 behavior remains covered.
- Local tests, compile, package, Skill validators, contract smoke tests, and CI pass.
- The PR is merged and the live `main` state is checked by `mergedAt` and commit SHA.

## Next increment: SARIF and standalone scan Action

The v2 contract plan above is historical and complete. The active plan is to
project only location-bearing deterministic scanner findings into SARIF 2.1.0
and expose that projection through a separate `scan/action.yml` entry point.

### Acceptance criteria

- [x] `kona scan --format sarif` emits valid SARIF with stable rule IDs,
  levels, relative locations, and deterministic partial fingerprints.
- [x] SARIF never contains secret evidence, absolute paths, contract results,
  or AI advisory output; `kona.findings/v1` JSON remains authoritative.
- [x] The standalone scan Action uploads SARIF before enforcing the threshold
  exit code and leaves the existing contract Action backward-compatible.
- [x] README, ADR, tests, package verification, and cross-platform CI coverage
  reflect the new adoption path.
- [x] The v0.9.0 PR is merged, v0.9.1 hardening is on `main`, and the live
  `main` state is verified.

### Work order

1. [x] Add the renderer and focused scanner/CLI tests.
2. [x] Add the standalone Action and clean/rejected smoke coverage.
3. [x] Document the SARIF projection boundary and official sources.
4. [x] Run independent review, full verification, release, merge/direct-main
   push, and live audit.

## Next increment: baseline adoption and scan accounting

The v0.9 scanner is useful for new repositories, but an existing repository
with known findings cannot adopt a blocking CI threshold without either fixing
everything at once or disabling the check. This increment adds a deterministic
baseline so teams can ratchet toward a clean scan while preserving the
authoritative finding boundary.

### Architecture decisions

- Keep baseline parsing and filtering in a separate dependency-free module;
  the scanner continues to discover the complete raw finding set.
- Store only schema, rule ID, severity, and stable SHA-256 finding fingerprints;
  never store paths, evidence previews, source, or credentials in a baseline.
- Apply a baseline explicitly from the CLI or standalone Action. A malformed,
  oversized, symlinked, or unreadable baseline fails closed.
- Keep active findings in `findings`; expose suppression and stale-entry counts
  as explicit metadata. SARIF and CI thresholds operate on active findings.

### Acceptance criteria

- [ ] `kona scan --write-baseline PATH` creates a deterministic, non-overwriting
  `kona.baseline/v1` file without evidence or secret values.
- [ ] `kona scan --baseline PATH` suppresses only matching fingerprints,
  reports suppression/stale counts, and still fails on newly introduced risks.
- [ ] The standalone scan Action accepts a workspace-relative baseline and
  exposes the number of suppressed findings without weakening path checks.
- [ ] Local and cross-platform CI tests cover malformed baselines, secret
  redaction, deterministic output, and the ratchet workflow.

### Work order

1. [ ] Add the baseline module and CLI integration.
2. [ ] Add Action support, documentation, and an ADR.
3. [ ] Run the full release gate, publish the next verified release, and audit
   the live `main` state.
