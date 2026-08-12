# ADR 0001: Use a local evidence contract as the Agent acceptance seam

## Status

Accepted

## Context

Kona v1 captured a bounded command and preserved redacted process evidence. A
process can exit successfully while producing the wrong artifact, omitting a
required section, or making an unreviewed workspace change. Adding an Agent
orchestrator or hosted service would enlarge permissions and make the core
evidence harder to reproduce locally.

## Decision

Keep `run_capture` as the low-level process module and add a separate contract
module. A contract uses an argv array, a workspace-relative path set, and
declarative assertions. The module snapshots metadata before and after the
run, evaluates bounded checks, and emits JSON plus Markdown reports with a
local digest.

## Alternatives considered

### Shell command strings

Rejected because implicit shell parsing would add platform-specific behavior
and make the authorization surface harder to review.

### Full Agent orchestration

Deferred because orchestration is a different product boundary. Kona earns its
value by making the execution-to-acceptance seam small, local, and composable
with any Agent or CI runner.

### Copy observed files into the report

Rejected because reports are often handed to other people or CI systems. Hash
and metadata evidence is useful for change detection without duplicating
potentially sensitive workspace content.

### Treating a passing process as task success

Rejected because it collapses operational evidence and semantic correctness.
Contracts require task-specific assertions and reports state their evidence
boundary explicitly.

## Consequences

- The same contract can be run by a human, an Agent Skill, or CI.
- The core runtime remains dependency-free and offline-capable.
- Authors must state what is observable; semantic review remains separate.
- A future attestation or remote adapter can sit above this seam without
  changing the local contract semantics.
