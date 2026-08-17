# ADR 0006: Ratchet existing repositories with finding fingerprints

## Status

Accepted for Kona Guard 0.10 development.

## Date

2026-08-17

## Context

Kona Guard is most useful when it can be enabled in an existing repository,
not only in a new clean repository. A blocking scan against an old codebase
otherwise forces a team to fix every historical issue in one change or disable
the check. Both choices reduce adoption and hide whether new risk is being
introduced.

The scanner's deterministic finding fingerprint is already the stable identity
used for SARIF correlation. A baseline can use that identity to suppress only
known findings while keeping new findings visible and blocking at the selected
threshold.

## Decision

Add an explicit, dependency-free `kona.baseline/v1` format and two opt-in CLI
operations:

- `kona scan --write-baseline PATH` records the current finding fingerprints.
- `kona scan --baseline PATH` applies a validated baseline before rendering or
  evaluating the threshold.

The baseline stores exactly `schema`, minimal tool metadata, and an array of
`fingerprint`, `rule_id`, and `severity`. It never stores paths, source,
evidence previews, repository metadata, or credentials. Creation is
non-overwriting; loading rejects invalid JSON/UTF-8, unknown fields, invalid
identifiers, duplicates, symlinks, changing files, oversized files, and
oversized entry counts.

Suppression is exact fingerprint matching. Active findings remain in the
authoritative report's `findings` array; the report separately records applied,
suppressed, and unmatched (stale) baseline counts. SARIF and CI outputs expose
active findings only. Stale entries are reported for review rather than
silently deleted or treated as evidence of safety.

The standalone scan Action accepts only an existing workspace-relative baseline
file and exposes `baseline-suppressed`; it retains the same fail-closed path
checks and does not accept credentials or network configuration.

## Alternatives considered

### Suppress by path and line

Rejected. Paths and line numbers are unstable under refactors and would make a
baseline easy to apply to the wrong code. Finding fingerprints preserve the
scanner's existing identity contract.

### Put evidence previews in the baseline

Rejected. Evidence may contain sensitive material even after best-effort
redaction. A baseline needs identity, not duplicated evidence.

### Automatically update the baseline after every scan

Rejected. Automatic updates would convert newly discovered risk into an
accepted state without an explicit review or commit. The write operation is
explicit and refuses to overwrite an existing file.

### Make baselines the canonical scan result

Rejected. The raw deterministic scan remains the source of discovery; baseline
application is an explicit presentation and threshold adapter. A clean result
with a baseline still does not prove that a repository has no vulnerabilities.

## Consequences

- Existing repositories can adopt a blocking threshold and ratchet toward zero
  new findings.
- New findings remain actionable in JSON, SARIF, text output, and Action exit
  status.
- Teams must review baseline files as code and periodically remove stale
  entries.
- A compromised or intentionally overbroad baseline can hide known findings;
  code review and the explicit stale/suppression counts remain necessary.

