# ADR 0003: Define a portable Evidence Bundle v1

## Status

Accepted and implemented in Kona 0.4.0.

## Context

Kona run directories are useful local evidence, but inspection currently
depends on the original workspace. That prevents a CI artifact, downloaded
handoff, or archived run from being independently checked after the workspace
has moved, changed, or disappeared.

The primary-source research in
[`docs/research/2026-08-12-agent-evidence-needs.md`](../research/2026-08-12-agent-evidence-needs.md)
found that transport integrity, acceptance semantics, and producer
authentication are separate concerns. GitHub Actions can transport artifacts;
in-toto, SLSA, and DSSE provide useful provenance and signing vocabulary; and
JUnit or SARIF can project results into CI interfaces. None of those formats
alone defines a portable Kona acceptance record.

Kona therefore needs a self-contained object whose integrity and recorded
acceptance result can be verified offline without enlarging the claims made by
the existing evidence model.

## Decision

Add Evidence Bundle v1 as a deterministic transport for one completed Kona
contract run. The canonical logical form is a directory rooted at `bundle/`:

```text
bundle/
|-- kona.bundle.json
|-- contract.json
|-- report.json
|-- report.md
|-- run.json
|-- stdout.log
`-- stderr.log
```

The directory model is authoritative. A `.kona.zip` file is a deterministic
serialization of that logical directory, not a second bundle format. Bundle
creation and verification will use an original Kona-owned manifest and schema;
v1 does not claim conformance with in-toto, SLSA, DSSE, JUnit, or SARIF.

The intended interface is:

```text
kona bundle create <run-directory> --output <name>.kona.zip
kona bundle verify <bundle-directory-or-zip> [--json]
```

### Manifest and artifact identity

`kona.bundle.json` is the authoritative manifest. It records:

- the supported bundle schema version and Kona media type;
- the producer's Kona version and stable run identifier;
- every required logical artifact path, byte length, and SHA-256 digest;
- the digest of the exact bundled contract bytes;
- report and stream identities needed to cross-check existing Kona semantics;
- a typed acceptance summary and the evidence boundary recorded by the run;
- an explicit unsigned/authentication state.

The manifest does not digest itself. Its own bytes are validated by strict
schema and canonical-encoding rules. Required artifacts are a closed set in
v1: missing, duplicate, or unexpected logical entries are invalid.

`contract.json` contains the exact bytes validated and used by the original
run. Bundle creation must not parse and reserialize the contract. The manifest
digest, run record, and report must agree on those bytes. Absolute source paths
may be retained only as non-portable diagnostic metadata and never as an input
to offline verification.

Observed workspace contents are not bundled. Reports continue to contain only
the bounded paths, lifecycle states, metadata, and digests produced by the
original run. Verification proves that those recorded observations are
internally consistent and unchanged; it does not independently reconstruct
the original workspace.

### Deterministic ZIP serialization

Given identical logical artifact bytes and metadata, bundle creation must emit
byte-for-byte identical ZIP output across supported platforms. The serializer
must define and fix:

- UTF-8 logical names using `/` separators under the single `bundle/` root;
- lexicographic entry order by normalized logical path;
- one documented timestamp for every entry;
- regular-file entry type and normalized permission bits;
- one compression method, level, and implementation settings;
- no host-specific owner, group, absolute path, comment, extra field, or
  filesystem timestamp metadata.

The manifest is generated from the canonical logical artifacts before ZIP
serialization. ZIP container metadata must not alter bundle meaning.

### Offline verification

Verification depends only on the bytes supplied in the bundle and the
verifier's supported Bundle v1 rules. It must not access the original contract
path, `run.cwd`, workspace, Git repository, network, current clock, environment
variables, or external trust service.

The verifier checks every artifact length and digest, exact contract identity,
the report digest, stream digests, run/report/contract references, assertion
counts, timeout and process semantics, Markdown identity, and the recorded
acceptance summary. Derived fields are recomputed rather than trusted merely
because the manifest contains them.

Machine-readable and human-readable results keep three claims separate:

- `valid`: the bundle is safe to read and its bytes and Kona semantics are
  internally consistent;
- `accepted`: the valid bundle records a passing contract outcome;
- `authenticated`: the producer identity is cryptographically authenticated.

For Bundle v1, `authenticated` is always `false`. A valid rejected bundle is
useful evidence and must not be described as corrupt.

CLI exit codes are:

- `0`: the bundle is valid and records an accepted outcome;
- `1`: the bundle is valid and records a rejected outcome;
- `2`: the bundle is malformed, unsafe, unsupported, inconsistent, over a
  limit, or otherwise unverifiable.

### Limits and hostile-input handling

Both directory and ZIP verification are strict parsers for untrusted input.
The implementation must publish finite limits for archive bytes, extracted
bytes, per-entry bytes, entry count, path length, JSON bytes and nesting,
compression ratio, and verifier work. Crossing any limit returns exit code 2;
there is no partial verification or best-effort green result.

Verification rejects at least:

- absolute paths, `..` traversal, empty segments, backslash aliases, drive or
  UNC paths, Windows device names, NULs, and non-canonical names;
- Unicode or case-normalization collisions under the defined portable path
  rules;
- duplicate entries, multiple logical roots, missing or unexpected entries;
- symlinks, hard links, junction/reparse representations, devices, FIFOs,
  sockets, and any non-regular artifact;
- encrypted entries, unsupported compression methods, data that exceeds
  expansion limits, and excessive compression ratios;
- local/central ZIP header disagreement, ambiguous sizes, trailing data where
  prohibited, and malformed ZIP structures.

Directory verification applies equivalent path, type, size, and closed-set
checks and does not follow links. Reading an entry that changes during
verification is indeterminate and fails closed.

### Claim boundary

Bundle v1 is a portable integrity and recorded-acceptance format. It does not:

- include observed workspace file contents;
- replay the command or reproduce its environment;
- prove that recorded observations correspond to an independently available
  workspace;
- authenticate the Agent, human, machine, CI runner, or Kona producer;
- provide a signature, attestation, timestamp authority, transparency log, or
  non-repudiation;
- prove semantic quality, human approval, remote acceptance, or correctness of
  unobserved state and external side effects.

Future signature or provenance support must be specified separately and bind
the deterministic bundle digest to an explicit identity and trust policy. It
must not redefine `valid` or `accepted` as authentication.

## Alternatives considered

### Continue copying raw run directories

Rejected because their verification can depend on the original workspace and
their filesystem metadata is not a deterministic transport contract.

### Include observed workspace contents

Rejected because source files, customer data, generated credentials, and other
sensitive material could be disclosed. Content-carrying replay packages need a
separate opt-in privacy and authorization design.

### Replay the command during verification

Rejected because Kona does not capture complete inputs, toolchains, services,
network responses, clocks, randomness, or external side effects. Calling the
bundle replayable would overstate its evidence.

### Add DSSE signatures or SLSA provenance in v1

Deferred. Deterministic bytes and stable semantics must exist before choosing
signer identity, trust roots, key discovery, revocation, and CI identity policy.

### Use JUnit, SARIF, or a GitHub artifact as the bundle

Rejected as the canonical format. They are useful future projections or
transports but do not preserve Kona's complete evidence and trust boundary.

## Consequences

- A run can become a CI artifact or Agent handoff that is independently
  verifiable after the original workspace is unavailable.
- Passing, failing, and malformed evidence have distinct automation semantics.
- Determinism creates a stable digest target for later attestations.
- The verifier becomes a security boundary and requires hostile-archive tests,
  strict resource budgets, and cross-platform byte-for-byte fixtures.
- Bundle creation must preserve exact contract bytes and existing privacy
  boundaries.
- Local run inspection and portable bundle verification remain different
  workflows: the former may revalidate live workspace state; the latter only
  validates the self-contained historical record.
- Bundle v1 is unsigned. A party able to rewrite every artifact and recompute
  every digest can author a new internally consistent bundle. Resistance to
  that attacker requires a future signature or attestation trust policy and is
  represented honestly by `authenticated: false`.
