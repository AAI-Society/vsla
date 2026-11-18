# VSLA specification v1.0

**VSLA** (Vulnerability-disclosure Supply-chain Levels for Agents, said "vee-salsa") is a graded framework for
the trustworthiness of a vulnerability disclosure that a machine produced and a machine will consume. It is to
machine-to-machine coordinated vulnerability disclosure what [SLSA](https://slsa.dev) is to builds: a ladder of
levels, a set of requirements per level and per role, a provenance format, a threat model that says which
level does what against which attack, and a verification procedure that turns a *claimed* level into a
*verified* one.

| Document | What it defines |
|---|---|
| [Terminology](terminology.md) | finder, disclosure platform, maintainer, statement, track, pillar, expectation, countersigner allowlist |
| [Levels](levels.md) | L0 Unattested · L1 Attested · L2 Trusted · L3 Hardened, the three pillars, and where the SLSA analogy breaks |
| [Tracks](tracks.md) | the Finding track and the Patch track |
| [Requirements](requirements.md) | normative requirements with stable ids (`VSLA-F-*`, `VSLA-P-*`, `VSLA-V-*`) |
| [Provenance](provenance.md) | the `https://vsla.dev/provenance/v1` predicate, profiles, the DSSE envelopes (statement, receipt, ledger entry, weight attestation), the Merkle transcript, the trust ledger, the environment quote |
| [Verification](verification.md) | how a receiver computes a verified level, which checks are external and which structural, and why claimed ≠ verified |
| [Threats](threats.md) | the threat table: defeated, mitigated or recorded, at which level, and what no level fixes |
| [Trust rubric](trust-rubric.md) | the score within a level, how it is computed, the floors, and the known ways to game it |
| [FAQ](faq.md) | why not just sign the report, what L1 proves, why a TEE, why not a bounty, what about humans |

The JSON Schema for the predicate is at [`/schema/vsla-provenance-v1.schema.json`](../../schema/vsla-provenance-v1.schema.json);
signed example statements on both tracks at every level are under [`/schema/examples`](../../schema/examples), and
[`/tools/vsla_verify.py`](../../tools/vsla_verify.py) is the reference verifier that checks them.

Key words MUST, MUST NOT, SHOULD, SHOULD NOT and MAY are to be read as in RFC 2119.

## Status

Version 1.0, draft of 2026-10-30, revised 2026-10-31 after two adversarial reviews, again after a second-round review,
and again after a third round. Revision 4 gives the finder's operator
ownership of the ledger index (platforms check inclusion of their entries, not position, so honest concurrency never
forks), judges every window at one evaluation instant `t_eval` fixed by the anchor, names two anchor forms and
requires log inclusion for a required anchor, implements `successor` and `revoke`, and stops consulting the
self-reported score. Revision 3 binds the receipt to the platform key the
statement names and reads it only after it verifies, binds ledger entries to the finder key and the track and to
`seq` order, includes the platform's own entries in the consistency root, counts countersigners per operator,
requires distinct two-operator co-signers, enforces canonical payloads, adds the `signed-anchor` reference form and
`require_anchor`/`require_isolation` policy knobs, and states what the classifier and coverage check do and do
not prove. The revision changed what the levels mean in several places: the
threat table now distinguishes defeated from mitigated from recorded; a self-reported ledger summary no longer
counts; the receiver's own classifier, coverage check and review replace the finder's flags at L2; the rubric
is v1.1; the receipt and ledger entry are DSSE envelopes over RFC 8785 JSON; the enclave key is derived from
the quote rather than pinned; API-served models cap the Environment pillar at L2; and isolation, admission,
scope, authorization, profile and key-lifecycle requirements were added. Nothing has been measured yet.

The first implementation is [qudisclose](https://github.com/quome-cloud/qudisclose). The design rationale is in
the [paper](../../paper/vsla.pdf).
