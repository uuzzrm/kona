# ADR 0004: Ship a thin GitHub Action adapter

## Status

Accepted and implemented in Kona 0.5.0.

## Context

Kona contracts and portable bundles solve the local evidence problem, but a
team should not need to assemble installation, execution, verification,
summaries, annotations, and artifact upload for every repository. The useful
adoption seam is a repository-local Action that turns one explicit contract
into a normal pull-request check while preserving the same evidence semantics.

## Decision

Publish `action.yml` as a composite Action. It sets up Python, installs the
checked-out Kona source, calls the testable `kona.github` adapter, uploads the
already self-verified `.kona.zip`, and finally enforces the recorded exit code.
The adapter always writes outputs before enforcement so rejected tasks still
retain reviewable evidence.

Inputs are passed to shell steps through environment variables. GitHub warns
that contexts may contain attacker-controlled data; expressions are therefore
not interpolated directly into executable shell text.

The Action exposes `outcome`, `accepted`, `bundle`, and `run-id`. It writes a
Markdown job summary to `GITHUB_STEP_SUMMARY`, machine outputs to
`GITHUB_OUTPUT`, and a redacted error annotation through workflow commands.
Evidence upload uses `actions/upload-artifact@v4` with `if-no-files-found:
error` and configurable retention.

The Action requests no write permission. A consuming workflow normally needs
only `contents: read`. Bundle v1 remains unsigned and the summary says so.

## Official sources

Accessed 2026-08-12:

- Composite Action metadata, inputs, outputs, and `runs.using: composite`:
  https://docs.github.com/en/actions/reference/workflows-and-actions/metadata-syntax
- Job summaries, output parameters, and workflow-command annotations:
  https://docs.github.com/en/actions/reference/workflows-and-actions/workflow-commands
- Script-injection guidance for untrusted contexts and intermediate
  environment variables:
  https://docs.github.com/en/actions/concepts/security/script-injections
- Artifact upload inputs and behavior:
  https://github.com/actions/upload-artifact

These sources define volatile platform behavior. Owner: Kona maintainers.
Next review: before changing Action major versions or by 2027-02-01.

## Consequences

- Consumers adopt Kona with one `uses:` step and one contract path.
- Rejected Agent work appears in the existing Checks interface and preserves
  a downloadable offline-verifiable bundle.
- The adapter remains thin: all acceptance and bundle semantics stay in Kona's
  existing deep modules and are testable without a GitHub runner.
- `actions/setup-python@v5` and `actions/upload-artifact@v4` are platform
  dependencies of the adapter, not runtime dependencies of the Python CLI.
