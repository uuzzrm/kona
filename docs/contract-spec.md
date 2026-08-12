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
| `assertions` | no | Ordered checks. If no process check is present, `exit_code == 0` is added implicitly. |

All paths must use `/`, cannot contain `..`, cannot be absolute (including
Windows drive or UNC paths), and cannot traverse an existing symlink. Unknown
top-level fields are rejected so a typo cannot silently weaken a gate. File
content checks are bounded to 4 MiB and use UTF-8 with replacement for invalid
bytes.

The contract directory is the workspace root by design. Kona does not discover
a repository root from the current shell or Git metadata. Put a contract at
the repository root when its command needs repository-root paths, or keep the
command and observations relative to the contract directory.

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
assertion forms.

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
