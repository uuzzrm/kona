# ADR 0005: Project scanner findings into SARIF for CI

## Status

Accepted for Kona Guard 0.9.0 development.

## Date

2026-08-17

## Context

Kona Guard's offline scanner produces a stable `kona.findings/v1` JSON report,
but teams already review security findings through GitHub Code Scanning and
other SARIF consumers. Without a standard projection, users must parse Kona's
JSON or ignore the scanner in CI. The existing contract Action is focused on
portable Agent evidence and must not silently change semantics.

## Decision

Add a dependency-free SARIF 2.1.0 renderer for location-bearing scanner
findings and expose it through `kona scan --format sarif`. Add a separate
`scan/action.yml` entry point for GitHub Actions. The canonical JSON report
remains authoritative; SARIF is a lossy presentation and alert-correlation
adapter.

Only findings with a stable rule ID and repository-relative file/line location
are projected. Rule metadata uses fixed Kona-owned descriptions, levels map
from Kona severity, and the existing deterministic finding fingerprint is
carried as a SARIF partial fingerprint. Contract assertions, run evidence,
AI explanations, absolute paths, and secret previews are not projected.

## Alternatives considered

### Make SARIF the canonical scan format

Rejected. SARIF does not preserve Kona's scan completeness, offline/read-only
claims, limits, skipped inventory, or exact finding boundary.

### Add SARIF to the existing contract Action

Rejected. The root Action's contract/bundle contract is already consumed by
users and has different acceptance semantics. A separate action provides an
explicit adoption path without breaking existing consumers.

### Upload every contract assertion as a code-scanning result

Rejected. A contract assertion may have no source location and is not a static
analysis result. Manufacturing a location would mislead reviewers.

## Consequences

- A repository can use Kona findings in existing SARIF-based CI workflows.
- GitHub alert correlation can use stable rule IDs and partial fingerprints.
- Consumers must retain the JSON report when they need Kona's complete trust
  boundary and scan metadata.
- The standalone Action must upload SARIF before enforcing a threshold.

## Sources

- OASIS, *Static Analysis Results Interchange Format (SARIF) Version 2.1.0*,
  https://docs.oasis-open.org/sarif/sarif/v2.1.0/os/sarif-v2.1.0-os.html,
  accessed 2026-08-17.
- GitHub, *SARIF support for code scanning*,
  https://docs.github.com/en/code-security/code-scanning/integrating-with-code-scanning/sarif-support-for-code-scanning,
  accessed 2026-08-17.
