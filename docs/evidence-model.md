# Evidence model

Kona reports are local evidence packages, not claims of universal correctness.
The distinction is central to how an Agent should use the tool.

## What is evidenced

For one run, a report can establish:

- the redacted command display, working directory, timeout, and local runtime;
- captured stdout/stderr and the child process status; each stream is capped at
  8 MiB and records whether truncation occurred;
- before/after metadata and SHA-256 hashes for declared paths;
- when `workspace_policy` is enabled, the complete bounded set of filesystem
  changes attributable between the pre-command baseline and final snapshot,
  classified as allowed, denied, or unexpected;
- the exact assertion results written by the contract;
- that the stream files, Markdown report, and report digest still agree at
  inspection time.

## What is not evidenced

A passing report does not establish that:

- the Agent's hidden reasoning or plan was good;
- an unasserted file, side effect, or requirement was correct when no
  `workspace_policy` was enabled;
- generated prose, code, or data is semantically high quality;
- a remote API, pull request, deployment, or reviewer accepted the result;
- the report is an adversary-resistant signed attestation.

Those claims need their own tests, source review, external API state, human
approval, or a stronger attestation system. Kona should be paired with those
checks, not used to imply they happened.

## Handoff protocol

1. Show the user the authorized command and working directory.
2. Validate the contract before execution.
3. Run with a bounded timeout unless the user explicitly accepts unbounded work.
4. Inspect the report after execution.
5. Stop on a timeout, failed assertion, changed contract, missing artifact, or
   failed integrity check.
6. Handoff the report path, summary, and evidence boundary together.

The protocol is designed for Agent stop conditions: a failed local check is a
reason to investigate, not a reason to narrate success.

## Portable bundle workflow

ADR 0003 accepts a second, offline handoff workflow for Evidence Bundle v1:

```text
completed run
-> create canonical logical bundle
-> serialize deterministic ZIP when needed
-> copy or upload
-> verify offline
-> interpret valid, accepted, and authenticated separately
```

This workflow is implemented in Kona 0.4.0. The
bundle contains the exact contract bytes used for the run, `run.json`, both
redacted stream artifacts, `report.json`, `report.md`, and an authoritative
manifest. The normal directory is the canonical logical form; deterministic
ZIP is only its transport serialization.

Offline verification may use only bundle bytes and supported schema rules. It
must not consult the original contract path, `run.cwd`, workspace, repository,
network, clock, or environment. It verifies artifact sizes and SHA-256
digests, contract identity, report and stream consistency, assertion summary,
and the recorded acceptance semantics.

Verification reports three independent properties:

| Property | Meaning in Bundle v1 |
| --- | --- |
| `valid` | The input is safe, complete, supported, and internally consistent. |
| `accepted` | A valid bundle records that the contract outcome passed. |
| `authenticated` | Producer identity was cryptographically authenticated; always `false` in v1. |

A valid bundle can record rejection. Automation therefore returns `0` for
valid and accepted, `1` for valid but rejected, and `2` for unsafe, malformed,
unsupported, inconsistent, over-limit, or unverifiable input.

Bundle readers treat ZIPs and directories as hostile input. Unsafe paths,
normalization collisions, duplicate or unexpected entries, links and special
files, unsupported compression, excessive expansion, limit violations, and
unstable reads fail closed. The exact finite limits are part of the Bundle v1
implementation contract and are enforced by the verifier.

Portability does not widen the evidence claim. Observed workspace contents are
not copied into the bundle. Verification confirms the integrity and internal
consistency of recorded metadata and digests; it does not reconstruct the
workspace, replay the command, authenticate a producer, provide a signature or
attestation, prove semantic correctness, or establish remote or human
acceptance.

Bundle v1 is unsigned. It detects corruption, partial edits, unsafe input, and
internal contradictions, but not a party that rewrites every artifact and
recomputes every digest. Producer identity and resistance to coordinated
whole-bundle rewriting require a future signing and trust-policy layer;
verification therefore reports `authenticated: false`.

## Workspace policy evidence boundary

The filesystem policy compares two bounded workspace states. Existing dirty
paths are part of the baseline and are not automatically blamed on the child
command. A second change to an already dirty path is attributable to the run.
Kona's own selected evidence output is excluded to prevent self-observation,
and the report identifies that exclusion.

A policy result is evidence about observable filesystem state, not intent or
authorship. It does not prove that the Agent made every change personally, that
allowed changes are correct, or that external side effects did not occur. It
also does not copy changed content: reviewers receive normalized paths,
lifecycle classifications, metadata, and digests. If complete discovery cannot
be established within safety and resource limits, there is no partial passing
result; evaluation fails closed.
