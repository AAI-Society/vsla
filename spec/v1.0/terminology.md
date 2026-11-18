# Terminology

**Finding.** A claim that a specific codebase at a specific revision contains a specific vulnerability,
together with the evidence for the claim. In VSLA the evidence is executable: a test that fails on the
vulnerable revision with an assertion, which the receiver re-executes before believing.

**Patch.** A change to the codebase that makes the finding's test pass without breaking the rest of the
project's test suite.

**Disclosure.** The act of delivering a finding (and optionally a patch) to the party that is authoritative
for the codebase, under an embargo the receiving party's policy sets.

**Finder.** The agent that produced the finding: a scanner, a fuzzer, an always-on hunter, a researcher's
agent, a model-provider's internal tool. The finder has a stable cryptographic identity. The **operator** is the
organisation that runs the finder and is accountable for it.

**Disclosure platform.** The machine endpoint that receives disclosures for a codebase on the maintainer's
behalf, verifies them, acts on them, and records the outcome. qudisclose is one; a vendor PSIRT's intake can
be another. The platform is *authoritative* for a codebase when the codebase's maintainers declare it so
(in `SECURITY.md`, `security.txt`, or the package registry's metadata).

**Maintainer.** The party with the authority to accept a patch into the codebase's authoritative
distribution channel and to publish an advisory for it. May be a person, a team, or their operator agent.

**Statement.** An [in-toto Statement v1](https://github.com/in-toto/attestation) whose predicate type is
`https://vsla.dev/provenance/v1`, carried in a [DSSE](https://github.com/secure-systems-lab/dsse) envelope.
"Attestation" is used loosely for the signed statement.

**Model bill of materials (MBOM).** The list of every model that took part in producing the finding or
patch, with provider, name, version, serving mode, and (when known) weight digest and quantization. The
analogue of an SBOM for the thinking that went into the disclosure.

**Transcript.** The ordered sequence of model turns and tool calls that produced the finding. VSLA commits
to it with a Merkle root; the leaf bodies may be sealed to one party.

**Track.** A separate ladder for a separate claim. v1.0 defines the **Finding track** ("the bug is real") and
the **Patch track** ("the fix is correct"). See [tracks](tracks.md).

**Pillar.** One of the three questions every level answers: **Evidence** (is the bug real?), **Identity**
(who says so, and what is their record?), **Environment** (could anyone have tampered with the sayer?). See
[levels](levels.md).

**Claimed level / verified level.** The level a finder asserts in a statement, and the level a receiver was
able to confirm. The verified level is never higher than the claimed one. See [verification](verification.md).

**Trust ledger.** An append-only, Merkle-logged record of a finder's past disclosures and their
countersigned outcomes. See [provenance](provenance.md#trust-ledger).

**Receipt.** The platform's countersignature on receipt of a statement: a separate signed object binding the
statement digest, channel, time and the platform's own re-execution result. See [provenance](provenance.md#receipt-the-platform-countersignature).

**Expectation.** A reference value the verifier obtained independently of the statement (a harness digest
for a named version; an allowlisted environment measurement). A check that compares the statement to an
expectation, a pinned key or the receiver's own execution is **external**; one that compares the statement to
itself is **structural**. Only external checks separate the levels. See [verification](verification.md).

**Countersigner allowlist.** The set of `platform:` and `maintainer:` keys a verifier has pinned. Ledger
entries countersigned by any other key contribute nothing to the score. See [trust rubric](trust-rubric.md).

**Profile.** The `published` or `embargoed` form of a statement; in the embargoed form the fields that would
describe the bug (test path, command, files touched) are digests. See [provenance](provenance.md#profiles).
