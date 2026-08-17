# Kona Guard CI scan projection checklist

- [x] Read the merged v1 and identify the process-evidence gap.
- [x] Define the evidence contract, snapshot, and report boundaries.
- [x] Implement contract validation and file snapshots.
- [x] Implement assertions and JSON/Markdown reports.
- [x] Add the `kona contract run` CLI flow.
- [x] Update README, Skill, version, and CI.
- [ ] Run local and GitHub checks, review, merge, and verify `main`.

## Active v0.9 work

- [x] Audit the merged scanner, existing Action, and SARIF research.
- [x] Implement deterministic SARIF rendering.
- [x] Add `kona scan --format sarif` CLI coverage.
- [x] Add standalone `scan/action.yml` integration.
- [x] Add cross-platform scan Action smoke coverage.
- [x] Update README and ADR with the projection boundary.
- [ ] Run full release gate and live main audit.
