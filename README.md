# Kona

> Local acceptance gates and evidence packages for AI Agent work.

AI Agents can produce a green process exit code while still changing the
wrong file, omitting a required section, or leaving a reviewer with no clear
record of what happened. Kona adds a small, local verification layer around
one authorized command:

```text
contract → bounded execution → redacted streams → declared workspace snapshots
         → acceptance assertions → inspectable report → handoff
```

Kona is intentionally not an Agent orchestrator, semantic judge, or hosted
observability service. It is the narrow seam between Agent activity and a
reviewable delivery decision. It has no account, network call, daemon, or
runtime dependency beyond Python 3.10+.

## Why it exists

Logs answer “what did the process print?”. They do not answer “did this task
meet its acceptance conditions?” A Kona contract makes that question explicit
and gives the next person or CI job a bounded package of evidence.

This is useful when an Agent is asked to:

- generate or update a file with required sections;
- run a migration or formatter and prove the expected artifact changed;
- execute a local test/build command and preserve its exact outcome;
- hand work from one Agent to another without silently widening permissions;
- stop on a failed assertion instead of narrating success.

## Quick start

Requires Python 3.10 or newer.

### 1. Create or validate a contract

Generate a non-destructive starter template:

```bash
python -m kona contract init task.contract.json
python -m kona contract validate task.contract.json
```

Edit the command, observations, and assertions before running it. A contract
uses an argv array, never a shell string:

For a safer task-specific starting point, compile an explicit template. This
does not inspect the repository, infer permission, or execute the command:

```bash
kona contract templates
kona contract init agent-task.json --template coding-agent \
  --name verify-agent-change \
  --allow "src/**" --allow "tests/**" \
  --observe src --observe tests \
  -- python -m unittest discover -s tests -v
kona contract explain agent-task.json
```

Built-in templates cover read-only checks, explicitly scoped coding changes,
and declared artifact generation. `coding-agent` refuses to generate without
an `--allow`; `artifact-generator` refuses without an `--output`. The expanded
file is an ordinary contract v1 and remains the complete runtime authority.
Workspace policy does not observe `.git` metadata and is not an operating-
system, process, or network sandbox.

```json
{
  "version": 1,
  "name": "create-release-note",
  "description": "Generate a release note with the required handoff section.",
  "cwd": ".",
  "command": ["python", "examples/contracts/release_note_task.py"],
  "timeout": 60,
  "workspace_policy": {
    "mode": "filesystem",
    "allow": ["examples/contracts/RELEASE.md"],
    "deny": [".github/**", "**/.env", "pyproject.toml"],
    "max_changed_paths": 10
  },
  "observations": ["examples/contracts/RELEASE.md"],
  "assertions": [
    {"type": "exit_code", "equals": 0},
    {"type": "status", "equals": "success"},
    {"type": "file_exists", "path": "examples/contracts/RELEASE.md"},
    {"type": "file_content_contains", "path": "examples/contracts/RELEASE.md", "value": "## Highlights"},
    {"type": "stdout_contains", "value": "release note written"}
  ]
}
```

By default, `cwd` and observed paths are resolved from the directory
containing the contract. Put a repository-level contract at the repository
root when it needs repository-level paths; Kona does not guess a project root.

### 2. Run the authorized task

```bash
python -m kona contract run task.contract.json --output .kona/runs --quiet
```

Exit codes are designed for automation:

- `0`: every assertion passed and the evidence package is intact;
- `1`: the contract was valid, but the task or one or more assertions failed;
- `2`: the contract or report could not be safely loaded or evaluated.

### 3. Inspect before handoff

```bash
python -m kona contract inspect .kona/runs/<run-id>
python -m kona contract inspect --json .kona/runs/<run-id>
```

The inspect step checks the captured stream artifacts, Markdown report, report
digest, and report summary semantics. A failed inspection is a stop condition;
do not recreate the run and overwrite the evidence silently.

### 4. Portable handoff

Evidence Bundle v1 turns a completed run into a deterministic `.kona.zip`
that can be copied and verified without the original workspace:

```text
kona bundle create .kona/runs/<run-id> --output task.kona.zip
kona bundle verify task.kona.zip --json
```

The canonical bundle is a logical directory containing the exact contract
bytes, run and report artifacts, redacted streams, and an authoritative digest
manifest. Verification is offline and separates three results: byte-and-
semantic `valid`, the recorded contract `accepted`, and producer
`authenticated`. Bundle v1 is unsigned, so `authenticated` is always false.
It does not include observed workspace contents, replay the command, or claim
that a digest authenticates its producer. See
[`ADR 0003`](docs/decisions/0003-portable-evidence-bundle.md) for the accepted
interface and security limits.

## GitHub Actions

Use Kona as a pull-request gate without assembling custom CI plumbing:

```yaml
permissions:
  contents: read

steps:
  - uses: actions/checkout@v4
  - uses: uuzzrm/kona@v0
    id: kona
    with:
      contract: .kona/contracts/agent-task.json
      artifact-name: kona-agent-evidence
```

The Action runs the contract, creates and independently verifies a portable
bundle, writes a job summary and failure annotation, uploads the bundle, then
fails the check when the task is rejected. Outputs include `outcome`,
`accepted`, `bundle`, and `run-id`. It requires only `contents: read`; Bundle v1
remains unsigned and reports no producer authentication.

Pin a full commit SHA instead of `v0` where your supply-chain policy requires
immutable third-party Actions. See [ADR 0004](docs/decisions/0004-github-action-adapter.md)
for official GitHub sources and the adapter trust boundary.

## Evidence package

Each contract run creates a normal Kona run plus:

```text
.kona/runs/<run-id>/
├── stdout.log       # redacted child stdout, capped at 8 MiB
├── stderr.log       # redacted child stderr or spawn error, capped at 8 MiB
├── run.json         # process status, timing, command display, and stream hashes
├── report.json      # machine-readable contract result
├── report.md        # reviewer-friendly result and evidence boundary
└── report.sha256    # local digest for detecting later report edits
```

Declared workspace files and directories are represented by before/after
metadata and SHA-256 tree hashes. Their contents and directory entry names are
not copied into the report. File content assertions read a bounded maximum of
4 MiB, while stream assertions can read the full 8 MiB capture limit; both
record only whether the check passed.

An optional `workspace_policy` discovers the bounded set of filesystem changes
made between the pre-command baseline and final snapshot. `allow` declares the
permitted path globs, `deny` overrides them, and `max_changed_paths` prevents an
unbounded result. Existing dirty paths are preserved as baseline state; if the
command changes one again, that new change is evaluated. Kona excludes only its
selected evidence output for the current run. An incomplete scan, unsafe path,
or exceeded limit fails closed instead of producing a partial green report.
Reports contain changed paths, lifecycle classifications, metadata, and hashes,
not copies of changed file contents.

Captured streams are capped at 8 MiB per stream. If a noisy command reaches the
limit, Kona records a truncation marker and marks the stream in `run.json`.

## Supported assertions

| Assertion | Meaning |
| --- | --- |
| `exit_code` | Compare the child process exit code. |
| `status` | Compare `success`, `failed`, or `timed_out`. |
| `stdout_contains` / `stdout_not_contains` | Search captured stdout. |
| `stderr_contains` / `stderr_not_contains` | Search captured stderr. |
| `file_exists` | Require a regular file after the run. |
| `file_content_contains` / `file_content_not_contains` | Search a bounded UTF-8 file. |
| `file_sha256` | Compare the final regular-file hash. |
| `file_changed` / `file_unchanged` | Compare declared file metadata before and after. |
| `file_created` / `file_deleted` | Check regular-file lifecycle transitions. |

If no process assertion is written, Kona adds an implicit `exit_code == 0`
check. A missing file is unavailable evidence, not a successful
`file_content_not_contains` result.

## Safety and trust boundary

- Commands are executed from an argv array with no implicit shell.
- `cwd` and observed paths must be relative, use `/` separators, remain under
  the contract directory, and cannot traverse symlinks.
- Workspace policy globs follow the same relative-path rules. Denied or
  unexpected changes fail the contract; incomplete discovery is an evaluation
  error rather than a warning.
- The contract is hashed before and after execution; a changed or deleted
  contract fails the run.
- Common token, password, Bearer, GitHub, OpenAI, Slack, and AWS credential
  shapes are redacted before stream persistence and report display.
- Redaction is best effort, not a guarantee. Keep credentials out of command
  arguments and review evidence before sharing it.
- `report.sha256` detects later edits to the report in the same local evidence
  directory. It is not a signed attestation and does not protect against an
  attacker who can rewrite every artifact.

Kona can establish local process and declared-check evidence. It cannot prove
that an Agent chose the best plan, that the generated content is semantically
correct beyond the assertions, that a remote service accepted a change, or
that a human approved the result.

## Repository map

| Path | Purpose |
| --- | --- |
| `kona/capture.py` | Bounded process execution, stream capture, and v1 manifests. |
| `kona/contract.py` | Contract loading, workspace snapshots, assertions, and reports. |
| `kona/authoring.py` | Deterministic, explicit contract template compiler. |
| `kona/explanation.py` | Read-only authority, evidence, warning, and limitation view. |
| `kona/cli.py` | Stable command-line seam for capture and contract workflows. |
| `schemas/` | Editor-facing JSON Schema for contract authors. |
| `examples/contracts/` | Reproducible end-to-end examples. |
| `skills/kona-capture/` | Portable Agent instructions and stop conditions. |
| `docs/contract-spec.md` | Contract authoring and evaluation semantics. |
| `docs/evidence-model.md` | Evidence claims, handoff workflows, and trust boundaries. |
| `docs/decisions/` | Accepted architecture and public-interface decisions. |
| `docs/research/` | Dated primary-source research behind product decisions. |

Read [`docs/contract-spec.md`](docs/contract-spec.md) before authoring a
contract and [`docs/evidence-model.md`](docs/evidence-model.md) before making
claims from a report.

The local workflow is `validate -> run -> inspect`. Kona adds the
portable workflow `bundle create -> copy/upload -> bundle verify` after a run,
without consulting the source workspace at the destination.

## Example

The repository contains a release-note workflow and a realistic coding-Agent
policy example:

```bash
python -m kona contract validate examples/contracts/release-note.json
python -m kona contract run examples/contracts/release-note.json --output .kona/runs --quiet
python -m kona contract inspect .kona/runs/<run-id>
```

See [`examples/contracts/coding-agent.json`](examples/contracts/coding-agent.json)
for a contract that permits source, test, and documentation edits while
protecting CI, packaging, secrets, and repository policy files. It documents
the accepted interface. Workspace policy is implemented and fail-closed;
adapt the example command and paths to the repository before running it.

See [`examples/contracts/README.md`](examples/contracts/README.md) for what the
example proves and what it deliberately leaves to a semantic review.

## Development

```bash
python -m unittest discover -s tests -v
python -m compileall -q kona tests scripts
python scripts/validate_skill_metadata.py skills/kona-capture
python scripts/run_contract_examples.py
python -m pip wheel . --no-deps
python -m pip download --no-deps --no-binary=:all: --dest dist .
python scripts/verify_distribution.py
```

The CI matrix runs these checks on Python 3.10 through 3.13, including isolated
passing and failing contract examples, a wheel install smoke test, and a source
distribution build. The project uses only the Python standard library at
runtime. The wheel contains the runtime CLI; the source distribution also
contains the schema, examples, Skill, and documentation assets.

## License

MIT. See [`LICENSE`](LICENSE).
