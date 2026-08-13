# Research: the next high-value increment for Kona

- Status: product recommendation
- Access date for all external sources: 2026-08-12
- Scope: local AI Agent task acceptance, evidence, and CI handoff
- Method: primary sources only: official specifications, official product documentation, and source repositories owned by the relevant projects

## Recommendation

Build **portable evidence bundles with independent offline verification** as the next increment.

The narrow product promise should be:

> A Kona run can be copied, uploaded as a CI artifact, downloaded on another machine, and verified without the original workspace. Verification establishes artifact integrity, report consistency, contract identity, and the declared after-state evidence captured at run time. It does not replay the command, re-read the original workspace, authenticate the producer, or prove semantic correctness.

This is the highest-value next step because Kona already calls its output an evidence package and positions it as an Agent-to-reviewer or Agent-to-CI handoff. Today, however, `kona contract inspect` reopens the absolute `run.cwd` and compares current workspace paths with the recorded after-state. A copied run therefore cannot be independently inspected when the original workspace is absent, moved, or intentionally changed after the task. The product has local integrity checks, but not yet portable evidence.

The proposed feature converts the existing run directory into a content-addressed, self-contained verification unit. That creates a clean foundation for later GitHub Actions upload, attestations, and report adapters without making the core dependent on a hosting platform or signing service.

## What the primary sources show

### 1. Portable evidence needs immutable subjects and explicit predicates

The in-toto Attestation Framework defines a Statement with a required `_type`, a `subject` array, a `predicateType`, and a predicate. Subjects are matched by digest, and the specification says subject artifacts are assumed to be immutable. This is a strong fit for identifying a Kona evidence bundle by the digests of its files rather than by the producer's absolute filesystem paths. The framework also separates the generic statement envelope from the domain-specific predicate, which supports a future Kona predicate without claiming that the first implementation is signed or SLSA-compliant. [in-toto Statement specification](https://github.com/in-toto/attestation/blob/main/spec/v1/statement.md) (accessed 2026-08-12).

SLSA provenance similarly separates the output artifact subject from `buildDefinition` and `runDetails`. Its model is useful for vocabulary and future interoperability, but SLSA provenance is about build provenance and builder identity, not a drop-in schema for local Agent acceptance results. Kona should preserve enough stable identity to map into an attestation later, while keeping its acceptance predicate distinct. [SLSA Provenance](https://slsa.dev/spec/v1.2/provenance) (accessed 2026-08-12).

DSSE specifies how a payload type and serialized body are bound for signing through pre-authentication encoding. It is deliberately a signing envelope, not a content manifest or trust policy. Therefore a portable Kona v1 bundle should define deterministic bytes and digests now, but defer DSSE signatures until Kona can also define signer identity, key discovery, and verification policy. [DSSE protocol](https://github.com/secure-systems-lab/dsse/blob/master/protocol.md) (accessed 2026-08-12).

### 2. CI artifacts are transport, not sufficient evidence semantics

GitHub Actions supports uploading files or directories as workflow artifacts and downloading them in later jobs or workflows. GitHub documents artifact digests and validation during upload/download, making Actions an obvious transport for a Kona bundle. Transport-level validation does not define what a Kona report means, whether all expected files are present, or whether report fields agree. Kona still needs its own manifest and verifier. [Storing and sharing data from a workflow](https://docs.github.com/en/actions/using-workflows/storing-workflow-data-as-artifacts) (accessed 2026-08-12).

GitHub artifact attestations can establish build provenance and use GitHub's signing and identity infrastructure. The official workflow requires permissions such as `id-token: write` and `attestations: write` and is coupled to a GitHub workflow identity. That is valuable as an optional publisher layer, but it would violate Kona's local-first boundary if required by the core. A portable digest-addressed bundle is the prerequisite object that a later GitHub integration can attest. [Using artifact attestations to establish provenance for builds](https://docs.github.com/en/actions/security-for-github-actions/using-artifact-attestations/using-artifact-attestations-to-establish-provenance-for-builds) (accessed 2026-08-12).

### 3. JUnit and SARIF solve narrower presentation problems

SARIF 2.1.0 is an OASIS interchange format for static-analysis results. Its model centers on tool runs, rules, results, levels, and source locations. GitHub code scanning consumes a supported SARIF subset, expects stable `ruleId` values, and uses fingerprints to avoid duplicate alerts. Kona assertion failures are acceptance-gate outcomes and often have no source location or static-analysis rule. SARIF can later expose selected file-located policy failures, but it is a lossy and sometimes misleading primary representation of a Kona run. [SARIF 2.1.0](https://docs.oasis-open.org/sarif/sarif/v2.1.0/os/sarif-v2.1.0-os.html) and [GitHub SARIF support](https://docs.github.com/en/code-security/code-scanning/integrating-with-code-scanning/sarif-support-for-code-scanning) (accessed 2026-08-12).

JUnit Platform's own repository describes its legacy XML reporting as legacy-format output. JUnit-style XML is widely consumed, but the format is test-suite oriented and does not carry Kona's workspace snapshots, contract digest, stream integrity, or evidence boundary. It is useful as an adapter for CI test panes after portable verification exists, not as the evidence container. [JUnit Platform legacy XML report documentation](https://github.com/junit-team/junit5/blob/main/documentation/src/docs/asciidoc/advanced-topics/legacy-xml-report.adoc) (accessed 2026-08-12).

GitHub workflow commands can create annotations and job summaries, but these are runner-side presentation mechanisms. They improve visibility while a workflow is running; they do not produce a platform-independent object that another Agent or reviewer can verify offline. [Workflow commands for GitHub Actions](https://docs.github.com/en/actions/using-workflows/workflow-commands-for-github-actions) (accessed 2026-08-12).

### 4. Composition and discovery are useful only after the handoff object is sound

Reusable workflows and workflow templates provide composition and discovery at the GitHub automation layer. They do not define how local acceptance policies merge, how conflicts are resolved, or how a resulting policy is identified. Introducing contract imports prematurely would add policy-resolution semantics before Kona has a portable result for one contract. [Reusing workflows](https://docs.github.com/en/actions/using-workflows/reusing-workflows) and [Creating workflow templates for your organization](https://docs.github.com/en/actions/using-workflows/creating-workflow-templates-for-your-organization) (accessed 2026-08-12).

`AGENTS.md` offers a predictable repository location for Agent instructions, illustrating real demand for convention-based discovery. It does not define acceptance contracts, inheritance, or evidence. Kona can later add explicit discovery such as `kona contract find`, but implicit execution must remain out of scope: discovery may locate contracts, never authorize one. [AGENTS.md source repository](https://github.com/agentsmd/agents.md) (accessed 2026-08-12).

### 5. Workspace change safety needs Git-aware semantics, not another generic file assertion

Git's porcelain status format is intended for scripts and covers tracked and untracked working-tree state. `git diff` provides name/status, raw, binary, and exit-code modes, but different comparisons cover different state: working tree versus index, index versus `HEAD`, and untracked files require status rather than ordinary diff. A credible “only these files changed” policy therefore needs an explicit Git baseline and treatment of staged, unstaged, untracked, ignored, renamed, submodule, and binary states. [git-status](https://git-scm.com/docs/git-status) and [git-diff](https://git-scm.com/docs/git-diff) (accessed 2026-08-12).

This is valuable, but it should follow portable bundles. First, a workspace-safety result needs to survive handoff. Second, coupling the next increment to Git would narrow Kona's current filesystem-agnostic contract model. A later Git policy provider can emit a normalized change set into the same bundle predicate.

## Proposed feature: Kona Evidence Bundle v1

### User workflow

```text
kona contract run task.contract.json --output .kona/runs
kona bundle create .kona/runs/<run-id> --output task.kona.zip
kona bundle verify task.kona.zip
```

`bundle verify` must also accept an unpacked bundle directory. Verification must be offline and must not consult the original contract path, original `cwd`, Git repository, network, clock, or environment variables.

### Bundle shape

Use a deterministic ZIP as a transport convenience, with a normal directory as the canonical logical form:

```text
bundle/
├── kona.bundle.json
├── contract.json
├── report.json
├── report.md
├── run.json
├── stdout.log
└── stderr.log
```

`kona.bundle.json` is the authoritative manifest. It should include:

- bundle schema version and media type;
- Kona producer version;
- a stable run identifier;
- normalized logical artifact paths;
- byte length and SHA-256 digest for every artifact except the manifest itself;
- the contract digest and report digest;
- a typed Kona acceptance predicate containing the recorded summary and evidence boundary;
- an explicit statement that the bundle is unsigned unless a future attestation envelope is present.

The bundle must include the exact contract bytes used for the run. A filename plus digest is insufficient for a reviewer who does not possess the original contract. Absolute host paths should not be required for verification; if retained for diagnostics, they must be marked non-portable metadata and must not affect verification.

Do not copy observed workspace contents into v1. Kona's current privacy boundary intentionally records metadata and hashes rather than file content. The portable verifier should validate that the report consistently records those after-state observations, not claim that it independently reconstructed them. Replay is a separate future feature because deterministic replay requires source inputs, toolchains, environment, network policy, and side-effect controls that Kona does not currently capture.

### Verification semantics

The verifier should fail closed when:

- an expected artifact is missing, duplicated, symlinked, unexpectedly present under a reserved path, or exceeds documented limits;
- a logical path is absolute, traverses upward, uses an unsafe Windows path form, or has a normalization collision;
- an artifact byte length or SHA-256 digest differs;
- `run.json`, `report.json`, contract digest, assertion counts, pass/fail status, Markdown digest, or stream digests disagree;
- a timed-out run is represented as passing;
- the schema version or media type is unsupported;
- a ZIP contains duplicate names, links, device entries, path traversal, decompression beyond limits, or an excessive compression ratio.

Verification output should distinguish:

- `valid`: bundle bytes and Kona semantics are internally consistent;
- `accepted`: the recorded contract outcome passed;
- `authenticated`: always `false` in v1 unless and until a separately specified signature verifier exists.

This separation prevents “digest verified” from being misread as “trusted producer” or “task semantically correct.”

## Narrow acceptance definition

The increment is accepted only when all of the following are demonstrated on Windows and Linux with Python 3.10–3.13:

1. A passing and a failing existing contract can each be bundled, copied to a temporary directory with no original workspace, and verified offline.
2. Directory and ZIP inputs produce the same verification result and stable machine-readable JSON output.
3. Repacking identical logical inputs produces byte-for-byte identical ZIP output, including fixed entry order, normalized timestamps, permissions, and compression settings.
4. The verifier checks every bundled artifact against one manifest and cross-checks current Kona report semantics without accessing `run.cwd`.
5. Tampering with any artifact, contract bytes, assertion summary, stream, digest, or manifest causes a non-zero verification result.
6. Tests reject ZIP Slip paths, absolute and Windows device paths, duplicate entries, symlinks, decompression bombs beyond documented limits, and Unicode/path-normalization collisions.
7. CLI exit codes remain automation-friendly: `0` for valid and accepted, `1` for valid but recorded rejection, and `2` for malformed, unsafe, inconsistent, or unverifiable bundles.
8. Documentation states that portability is not replay, signatures, producer authentication, semantic review, or proof about unobserved workspace paths.
9. The runtime remains offline-capable and dependency-free unless a dependency is separately justified by a security and maintenance review.

## Rejected or deferred alternatives

### JUnit export as the next feature

Deferred. It would make failures visible in many CI products, but it cannot carry the evidence needed to independently inspect a run. Implement it later as a deterministic projection from a verified bundle, one test case per assertion, with explicit information-loss documentation.

### SARIF export as the next feature

Deferred. SARIF is excellent for file-located analysis findings, but many Kona assertions have no meaningful source region. Mapping every failed acceptance check to a security/code-scanning alert would distort both products. Add it only for policy checks that have stable rule IDs and real locations.

### GitHub Action as the next feature

Deferred. A thin action today would upload a run that cannot be independently inspected away from its original workspace. After bundles exist, an action can run a contract, verify the bundle, upload it, add a job summary, and optionally request a GitHub artifact attestation.

### Signed provenance or DSSE first

Deferred. Signing inconsistent or non-portable evidence only authenticates the wrong object more strongly. Kona first needs deterministic bundle bytes and a stable predicate. A later attestation ADR must define signer identities, trust roots, keyless/OIDC behavior, verification policy, revocation expectations, and the exact relationship to SLSA levels.

### Contract imports, profiles, and composition first

Deferred. Composition has high authoring value but introduces merge order, override, cycle, path-base, version, and policy-identity questions. It also increases the blast radius of a mistaken policy. Solve portable evidence for one explicit contract, then design composition so the fully resolved contract bytes and dependency digests are embedded in the bundle.

### Automatic contract discovery first

Deferred. Discovery improves ergonomics but not evidence quality. It can also accidentally turn convention into authorization. A future command should list candidates and explain scope; execution should still require an explicit selected contract or an unambiguous opt-in policy.

### Git workspace allowlist first

Deferred one increment. It is likely the strongest follow-up feature because it answers a concrete Agent safety question: “did the task touch only authorized paths?” It should be designed as a Git-aware policy provider with explicit baseline semantics, and its normalized change-set evidence should be portable in Bundle v1.

### Full replayable environments

Rejected for the near term. Replaying arbitrary Agent tasks safely requires captured inputs, dependency and toolchain identity, environment variables, services, network responses, clocks, randomness, and external side effects. That is a sandbox/build-reproducibility product. Kona should describe bundles as independently verifiable records, not replay capsules.

## Product sequence after this increment

1. Portable bundle and offline verifier.
2. Git-aware workspace change policy with allowed/required/forbidden path rules and a recorded baseline.
3. Official GitHub Action that uploads the bundle, publishes a job summary, and optionally emits JUnit.
4. Optional GitHub artifact attestation over the bundle digest.
5. Contract profiles/composition with a fully resolved, embedded contract.
6. Selective SARIF export for location-bearing policy failures.

This sequence keeps Kona's differentiator narrow: it is the acceptance and evidence seam underneath Agent runners and CI, not another Agent orchestrator, test framework, static analyzer, or hosted observability service.

## Source and license boundary

This note paraphrases interoperability requirements from the cited primary sources; it does not copy their schemas, prose, code, examples, or trademarks into Kona.

- Kona's proposed bundle schema and predicate must be original MIT-licensed work.
- in-toto Statement, DSSE, and SLSA are referenced as interoperability models. Any future direct schema reuse must first record the exact source revision and license notice from the owning repository.
- SARIF is an OASIS standard. Any implementation should generate compatible data from Kona's own code and consult the specification; do not vendor specification text or third-party generators without a separate license decision.
- GitHub Actions, artifact attestations, annotations, and code scanning are optional platform integrations. Documentation must not imply GitHub endorsement or that a local Kona digest is a GitHub attestation.
- JUnit names and legacy XML behavior are interoperability references. Kona should not claim a normative universal JUnit XML standard where implementations differ.
- Git command output may be consumed through the installed Git executable in a later provider; no Git source code needs to be copied.
- `AGENTS.md` is evidence of a discovery convention, not a Kona contract format and not permission to import that repository's content.

Before implementing any borrowed JSON Schema fragment, test corpus, sample document, action code, or cryptographic envelope, add the exact artifact, repository revision, license, and reuse decision to Kona's source/asset register if the repository adopts one.

## Decision

Proceed with a Bundle v1 ADR and implementation design. The central invariant should be:

> Verification of a copied Kona bundle depends only on the bytes inside the bundle and the verifier's supported schema, while every trust claim remains explicitly bounded.

That increment turns Kona's existing local report into a real handoff object and creates the minimum trustworthy substrate for the CI, policy, and attestation features users will expect next.
