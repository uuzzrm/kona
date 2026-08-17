# Kona Guard CI scan projection checklist

- [x] Read the merged v1 and identify the process-evidence gap.
- [x] Define the evidence contract, snapshot, and report boundaries.
- [x] Implement contract validation and file snapshots.
- [x] Implement assertions and JSON/Markdown reports.
- [x] Add the `kona contract run` CLI flow.
- [x] Update README, Skill, version, and CI.
- [x] Run local and GitHub checks, review, merge, and verify `main`.

## Active v0.9 work

- [x] Audit the merged scanner, existing Action, and SARIF research.
- [x] Implement deterministic SARIF rendering.
- [x] Add `kona scan --format sarif` CLI coverage.
- [x] Add standalone `scan/action.yml` integration.
- [x] Add cross-platform scan Action smoke coverage.
- [x] Update README and ADR with the projection boundary.
- [x] Run full release gate and live main audit.

## v0.9.1 review hardening

- [x] Preserve repository-root SARIF paths for subdirectory scans.
- [x] Harden Action workspace boundaries, artifact publication, and Code
  Scanning correlation.
- [x] Verify the installed wheel against a real high-severity finding.

## v0.10 baseline adoption

- [x] Add deterministic `kona.baseline/v1` creation and validation.
- [x] Add explicit CLI baseline application and ratchet exit behavior.
- [x] Add workspace-relative baseline support to `scan/action.yml`.
- [x] Document the adoption workflow, stale baseline behavior, and privacy
  boundary.
- [x] Run local, package, cross-platform CI, and Action smoke verification.
