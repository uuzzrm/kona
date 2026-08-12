---
name: kona-capture
description: Define, run, and inspect a bounded local Agent task with Kona evidence contracts. Use when an Agent needs a reviewable record of an authorized command, declared workspace changes, acceptance assertions, redacted streams, and explicit stop conditions before handoff.
---

# Verify an Agent task with Kona

## Purpose

Kona is a local acceptance seam around one explicitly authorized command. It
captures process evidence and evaluates declared observable checks. It does
not orchestrate Agents, inspect hidden reasoning, or prove semantic quality
that the contract does not assert.

Use the workflow in this order:

```text
define -> validate -> run -> inspect -> hand off (or stop)
```

## Define the contract

Before executing anything, confirm the exact command, working directory,
timeout, and external side effects with the user. Use an argv array rather than
a shell string. Declare only the files that matter to the handoff and write
assertions for the observable acceptance conditions.

Start a new contract without overwriting an existing file:

```text
python -m kona contract init task.contract.json
```

Useful assertion combinations include:

- `exit_code` or `status` for the process boundary;
- `file_exists`, `file_created`, `file_changed`, or `file_unchanged` for the
  artifact boundary;
- `file_content_contains` for a small required marker;
- `stdout_contains` or `stderr_not_contains` for a declared diagnostic.

Avoid asserting only that a command exited successfully when the task has a
more meaningful artifact or test result.

## Validate before execution

```text
python -m kona contract validate task.contract.json
```

Stop if validation fails. Paths must be relative to the contract directory,
use `/`, remain inside the workspace, and not traverse symlinks. Do not put
credentials in command arguments. Kona's redaction is best effort, not a
secret-management system.

## Run with a bounded timeout

```text
python -m kona contract run task.contract.json --output .kona/runs --quiet
```

Use the default five-minute limit or choose a smaller explicit timeout in the
contract. Use an unbounded timeout only when the user explicitly accepts that
risk. The command is not passed through an implicit shell.

The run creates redacted `stdout.log` and `stderr.log` (capped at 8 MiB per
stream), a process `run.json`,
and a contract `report.json`, `report.md`, and `report.sha256`. Observed file
contents are not copied into the report; only bounded assertion reads and
metadata/hashes are retained. Directory observations use a bounded recursive
tree hash and never follow symlinks.

## Inspect before handoff

```text
python -m kona contract inspect .kona/runs/<run-id>
```

Use `--json` for another local tool. Inspection checks stream artifact hashes,
the Markdown companion, the report digest, stored process integrity, and report
summary semantics. A passing inspection means the declared local evidence is
intact; it does not mean the Agent's plan or unasserted output is correct.

## Stop conditions

Stop and report the failure instead of narrating success when any of these
occurs:

- the user has not authorized the exact command, cwd, or external effects;
- contract validation returns exit code `2`;
- execution times out, cannot start, or returns an unexpected nonzero status;
- an assertion fails or the contract changes during the run;
- an observed path is missing, unsafe, or outside the declared workspace;
- `contract inspect` reports failed integrity or a tampered artifact.

Do not silently retry over a failed evidence directory or overwrite a report.
Ask whether to investigate or create a new explicitly identified run.

## Handoff format

Report all of the following:

- contract name and redacted command display;
- run/report path and working directory;
- `passed` or `failed` summary and assertion counts;
- process status, exit code, timeout, and redaction count;
- changed/created/deleted observed files;
- inspection result;
- what the report establishes and what remains unproven.

The exit-code contract is:

- `0`: every assertion and integrity check passed;
- `1`: the contract was valid but the task or an assertion failed;
- `2`: the contract/report was invalid or unsafe to evaluate.

Never use Kona to bypass approval, conceal a destructive command, capture
another person's private output, or imply remote acceptance that was not
verified separately.
