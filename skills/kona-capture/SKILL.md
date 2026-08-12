---
name: kona-capture
description: Capture bounded, redacted evidence from a locally authorized Agent command with Kona, then inspect the run manifest and report the exact evidence boundary. Use when a user asks to observe, reproduce, compare, or hand off a local Agent/tool run without changing the Agent's configuration, especially when stdout, stderr, exit status, timeout behavior, and tamper checks matter.
---

# Capture an Agent run with Kona

## Purpose

Use Kona as a transparent local hop around one explicitly authorized command.
It tees text output to the terminal, persists redacted stdout/stderr, records
the exit state and timeout boundary, and writes a manifest with artifact hashes.
Kona captures process evidence; it does not prove that the command's semantic
result is correct.

## Before running

1. Confirm the user has authorized the exact command, working directory, and
   any external side effects. Do not add flags that broaden the command.
2. Keep credentials out of command arguments when possible. Kona redacts common
   credential shapes before persistence, but redaction is conservative and is
   not a guarantee that arbitrary secrets will be detected.
3. Choose a bounded timeout. Use the default five minutes for ordinary local
   work; choose a smaller limit for a diagnostic probe. Use `--timeout 0` only
   when the user explicitly accepts an unbounded process.

## Run and inspect

From the Kona repository, run:

```text
python -m kona run --label "short-purpose" --output .kona/runs --timeout 60 -- <authorized-command> <args>
```

Preserve the reported exit status. The run folder contains:

- `stdout.log`: redacted stdout captured from the child;
- `stderr.log`: redacted stderr and spawn errors;
- `run.json`: timestamps, redacted command display, status, exit code, timeout,
  redaction counts, and SHA-256 metadata for both streams.

Then verify the handoff:

```text
python -m kona inspect .kona/runs/<run-id>
```

Use `--json` when another tool needs the report. If integrity fails, stop and
report that the evidence changed; do not silently recreate or overwrite the
run.

## Reporting rules

Report these fields explicitly:

- command display and working directory;
- `success`, `failed`, or `timed_out` status and the child exit code;
- captured artifact paths and inspection result;
- redaction count and any missing evidence;
- what was observed versus what remains unproven.

Do not claim that a passing exit code means the Agent completed its goal. Pair
the Kona report with task-specific tests, diffs, source links, screenshots, or
user acceptance as appropriate.

## Stop conditions

Stop before running when authorization, command scope, or working directory is
ambiguous. Stop after a timeout, unexpected nonzero exit, missing artifact, or
integrity failure and ask whether to investigate or retry. Never use Kona as a
way to bypass an approval, conceal a destructive command, or capture another
person's private output.
