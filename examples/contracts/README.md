# Contract examples

These examples show the smallest useful Kona loop:

1. define an authorized command and observable acceptance checks;
2. run it through `kona contract run`;
3. inspect the JSON and Markdown evidence package;
4. hand off the report only with its evidence boundary.

The examples represent different handoff states:

- `release-note.json` proves a generated file exists and contains a required
  section; it does not prove the writing is semantically good.
- `quality-gate.json` proves a local gate created its report and emitted the
  expected marker; it does not replace a full test suite.
- `quality-gate-failing.json` is expected to return exit code `1`. The command
  succeeds, but the contract's required marker is absent. That is a stop
  condition for an Agent, not a success story.

Run from the repository root:

```bash
python -m kona contract validate examples/contracts/release-note.json
python -m kona contract run examples/contracts/release-note.json --output .kona/runs
python -m kona contract inspect .kona/runs/<run-id>
```

The example intentionally observes one generated file and stores only its
metadata and hash in the report. It does not claim that the release note is
good writing; add a separate review or test for that semantic question.

To run the intentional failure:

```bash
python -m kona contract run examples/contracts/quality-gate-failing.json --output .kona/failing-runs --quiet
```
