# Contract specification

Kona contracts are versioned JSON documents that define one authorized local
command and the observable conditions that make its run acceptable. The
contract is deliberately narrower than an Agent plan: it describes the
execution seam and the acceptance evidence, not hidden model reasoning.

## Lifecycle

```text
load + validate → snapshot declared paths → execute argv
               → capture redacted streams → snapshot again
               → evaluate assertions → write report → inspect
```

The contract file's SHA-256 is captured before execution and checked again
afterwards. A contract that is changed, deleted, or replaced by a symlink
cannot produce a passing result.

## Fields

| Field | Required | Semantics |
| --- | --- | --- |
| `version` | yes | Must be `1`. |
| `name` | no | Human-readable run label; defaults to the contract filename. |
| `description` | no | Short explanation of the intended handoff. |
| `cwd` | no | Relative directory under the contract directory; defaults to `.`. |
| `command` | yes | Non-empty argv array. Kona never joins it into a shell command. |
| `timeout` | no | Non-negative seconds; `null` or `0` means unbounded. Default is 300 seconds. |
| `observations` | no | Relative files or paths whose metadata is snapshotted before and after. |
| `workspace_policy` | no | Optional fail-closed policy for all filesystem changes attributable to the command. |
| `assertions` | no | Ordered checks. If no process check is present, `exit_code == 0` is added implicitly. |

All paths must use `/`, cannot contain `..`, cannot be absolute (including
Windows drive or UNC paths), and cannot traverse an existing symlink. Unknown
top-level fields are rejected so a typo cannot silently weaken a gate. File
content checks are bounded to 4 MiB and stream checks can read the full 8 MiB
capture limit; both use UTF-8 with replacement for invalid bytes.

The contract directory is the workspace root by design. Kona does not discover
a repository root from the current shell or Git metadata. Put a contract at
the repository root when its command needs repository-root paths, or keep the
command and observations relative to the contract directory.

## Workspace change policy

`workspace_policy` closes the gap between declared observations and the full
set of filesystem changes caused by the authorized command:

```json
{
  "workspace_policy": {
    "mode": "filesystem",
    "allow": ["src/**", "tests/**", "docs/agent-output.md"],
    "deny": [".github/**", "**/.env", "pyproject.toml"],
    "max_changed_paths": 50
  }
}
```

`mode` must be `filesystem`. Patterns are workspace-relative globs written
with `/` separators. They must not be absolute, contain `..`, or use `\`.
`allow` identifies paths the command may change. A changed path that matches no
allow pattern is unexpected. `deny` takes precedence when a path matches both
lists. Empty arrays are valid: an empty `allow` permits no attributable
workspace changes, while an empty `deny` adds no explicit exclusions.
`max_changed_paths` bounds the normalized set of created, modified, deleted,
and renamed paths.

Kona establishes a baseline immediately before starting the command and a
final snapshot after the command has stopped. Policy evaluation concerns the
delta between those states, not whether the workspace was clean before the
run. A path already dirty at baseline is not attributed to the command merely
because it was dirty; if the command changes that path again, the new state is
attributable and must satisfy the policy. A rename is represented as removal of
the old path plus creation of the new path unless the filesystem adapter can
establish a stronger identity without weakening portability.

The selected evidence output directory for the current run is excluded from
workspace policy discovery. This exclusion is narrow: it covers only Kona's
own artifacts for that run and does not exempt a general `.kona/**` tree or an
output path modified by the child command. Excluded evidence paths are named in
the report so the omission is reviewable.

The policy fails closed. If Kona cannot take a complete baseline or final
snapshot, encounters an unsafe path or symlink traversal, reaches a filesystem
scan budget, or observes more than `max_changed_paths`, the run is unable to be
safely evaluated and exits with code `2`. It must not truncate the change set
and then report success.

Workspace change evidence records normalized paths, lifecycle classifications,
bounded metadata, and hashes needed for comparison. It does not copy changed
file contents into the evidence package. Content assertions remain explicit,
bounded checks and record only their result.

## Assertion semantics

Every result has a stable `assertion-N` ID. File assertions automatically add
their path to the observation set, so the author cannot accidentally assert a
file without collecting before/after evidence.

`file_exists` means a regular file exists after the command. A directory,
special file, or symlink does not satisfy it. `file_created` means the path was
missing before and is a regular file after. `file_deleted` means it was a
regular file before and is missing after. `file_changed` requires metadata to
change; `file_unchanged` requires it not to change. For an observed directory,
the metadata includes a bounded recursive tree hash and entry count; symlinks
inside the tree are recorded as opaque entries and are never followed. A
missing content input is reported as unavailable and fails both content
assertion forms. `file_sha256` applies only to a regular file; directory tree
hashes are used for directory lifecycle assertions, not file hash assertions.

## Exit codes

| Code | Meaning |
| --- | --- |
| `0` | Valid contract; all assertions and artifact checks passed. |
| `1` | Valid contract; at least one assertion or contract-stability check failed. |
| `2` | Invalid contract, unsafe path, malformed report, or unable to evaluate safely. |

## Authoring guidance

Write assertions around the smallest observable outcome that matters. Pair a
process assertion with an artifact assertion and, where useful, a bounded
content marker. Do not use a broad “command succeeded” check as a substitute
for reviewing the generated result.

The editor-facing [JSON Schema](../schemas/contract.schema.json) helps with
shape and enum completion, but the Python loader remains authoritative for
runtime safety checks such as symlink traversal and workspace containment.
