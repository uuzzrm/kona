# kona

> A transparent local hop for capturing bounded, redacted Agent command evidence.

Kona wraps one command without changing the Agent's configuration. It streams
the child output back to the terminal, writes redacted logs and a JSON run
manifest, preserves the child exit status, and lets you verify whether captured
files were changed after the run.

It is deliberately small and local: no service, account, network call, or
runtime dependency is required. Kona is useful when you need a reproducible
record of what a tool actually emitted, without confusing that record with proof
that an AI Agent reached the right conclusion.

## Quick start

Requires Python 3.10 or newer. From a clone:

```bash
python -m kona run --label smoke-test --output .kona/runs -- python -c "print('hello from kona')"
```

On Windows, the same command works in PowerShell. The last line reports the
evidence directory. Inspect it with:

```bash
python -m kona inspect .kona/runs/<run-id>
```

For a machine-readable report:

```bash
python -m kona inspect --json .kona/runs/<run-id>
```

Install the console command locally when preferred:

```bash
python -m pip install -e .
kona run --timeout 30 --quiet -- your-agent-command --safe-flag
```

## What a run contains

```text
.kona/runs/<run-id>/
├── stdout.log   # redacted child stdout
├── stderr.log   # redacted child stderr or spawn error
└── run.json     # status, exit code, timestamps, redaction counts, SHA-256 hashes
```

The command is executed with its original arguments. Kona redacts common forms
such as `token=...`, `password: ...`, Bearer credentials, OpenAI-style keys,
GitHub tokens, Slack tokens, and AWS access-key IDs before displaying or saving
them. This is a best-effort boundary, not a perfect secret scanner; avoid
putting credentials in arguments and review the captured output before sharing.

Timeouts are bounded by default at five minutes. A timed-out process returns
exit code `124` and status `timed_out`. A missing executable returns `127`.
Other child exit codes are preserved.

## Agent Skill example

[`skills/kona-capture/SKILL.md`](skills/kona-capture/SKILL.md) is a portable
skill that teaches an Agent how to use Kona with explicit authorization,
bounded timeouts, redaction limits, integrity inspection, and honest evidence
reporting. It is an example of a skill that adds a repeatable workflow without
silently expanding tool permissions.

## Evidence boundary

Kona can establish that:

- a particular local process was started with a displayed command and working
  directory;
- redacted stdout and stderr were captured until exit or timeout;
- the child returned a particular status;
- the saved stream files still match the hashes in the manifest.

Kona cannot establish that an AI Agent's plan was wise, that a generated patch
is correct, that an external service accepted a change, or that a user accepts
the result. Add task-specific verification for those claims.

## Development

```bash
python -m unittest discover -s tests -v
python -m compileall -q kona tests
```

The repository's CI runs the test suite on Python 3.10 through 3.13 and checks
the bundled Skill metadata with a dependency-free repository validator. Before
publishing a Skill, also run the official validator from your Agent environment.

## License

MIT. See [`LICENSE`](LICENSE).
