# ADR 0002: Add a fail-closed filesystem workspace change policy

## Status

Accepted and implemented.

## Context

Declared observations prove what happened to named paths, but they do not
detect an authorized command changing an undeclared file. That gap weakens the
central coding-Agent use case: proving both that the intended result exists and
that the command stayed inside its permitted workspace scope.

The policy must work without Git, must not require a clean workspace, and must
preserve Kona's privacy boundary. It also must not turn the contract into an
orchestration language.

## Decision

Add one optional top-level `workspace_policy` object:

```json
{
  "mode": "filesystem",
  "allow": ["src/**", "tests/**"],
  "deny": [".github/**", "**/.env", "pyproject.toml"],
  "max_changed_paths": 50
}
```

The contract directory remains the workspace root. The filesystem adapter
captures a baseline immediately before command execution and a final state
after the command stops. It reports changes between those states, including a
second change to a path that was already dirty at baseline. `deny` takes
precedence over `allow`; a changed path matching neither is unexpected.

Kona excludes only the selected evidence artifacts for the current run, and
records that exclusion. It records paths, lifecycle classifications, bounded
metadata, and hashes, but does not copy workspace file contents.

Discovery is fail-closed. Unsafe traversal, incomplete snapshots, resource
limits, or exceeding `max_changed_paths` produce an evaluation error rather
than a truncated passing result.

## Alternatives considered

### Require a clean workspace

Rejected because real Agent and CI handoffs often begin with intentional local
changes. A before/after baseline gives more useful attribution without erasing
or misclassifying existing work.

### Use Git status as the only mode

Deferred. Git can provide richer rename, index, and ignore semantics, but would
exclude non-Git workspaces and add repository-state concepts to the first
interface. A later Git adapter may produce the same normalized policy result.

### Add more individual file assertions

Rejected because enumerating expected files cannot establish that no other
path changed. The workspace policy earns its place by hiding complete bounded
discovery behind a small declarative interface.

### Copy changed files into evidence

Rejected because changed files may contain source code, credentials, customer
data, or generated secrets. Digests and metadata preserve the evidence boundary
without expanding disclosure by default.

## Consequences

- Coding-Agent contracts can express both positive acceptance checks and a
  negative permission boundary.
- Existing dirty paths remain usable and must be represented honestly in the
  baseline.
- Filesystem discovery and matching must behave consistently on Windows and
  POSIX systems.
- Reports need explicit allowed, denied, unexpected, excluded, and limit/error
  outcomes.
- The policy does not judge the semantic quality of an allowed change or cover
  network, process, database, or other external side effects.
