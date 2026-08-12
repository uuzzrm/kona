# Evidence model

Kona reports are local evidence packages, not claims of universal correctness.
The distinction is central to how an Agent should use the tool.

## What is evidenced

For one run, a report can establish:

- the redacted command display, working directory, timeout, and local runtime;
- captured stdout/stderr and the child process status; each stream is capped at
  8 MiB and records whether truncation occurred;
- before/after metadata and SHA-256 hashes for declared paths;
- the exact assertion results written by the contract;
- that the stream files, Markdown report, and report digest still agree at
  inspection time.

## What is not evidenced

A passing report does not establish that:

- the Agent's hidden reasoning or plan was good;
- an unasserted file, side effect, or requirement was correct;
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
