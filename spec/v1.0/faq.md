# FAQ

**Why not just sign the report?**
A signature proves who sent a report, not that the bug is real, not that the model named did the work, not
that the account of the work is complete, and not when the maintainer received it. L1 binds all of those; L2
adds the receipt and the record; L3 adds the environment. A signed report is L0 with a signature.

**Does L1 prove the bug is real?**
No. L1 proves that a finder-authored test fails reproducibly at the named revision and that the finder signed
a complete account of the run. A finder can write a test that fails on demand. The first check that speaks to
whether the bug is real is the receiver's own re-execution at L2, with the receiver's own classifier and a
check that the test actually exercised the code the report names, and even that proves "this test fails for
an assertion in this code", not "this is exploitable". The semantic judgement is still the receiver's.

**Why a model bill of materials?**
Because the model is a dependency of the finding in exactly the way a library is a dependency of a build, and
for the same reasons: when a model turns out to be bad (a backdoored fine-tune, a quantization that breaks
security reasoning), every finding it touched needs to be found. An SBOM answers "which builds used log4j";
an MBOM answers "which disclosures used that model". It is a traceability device, not a detector.

**Why a Merkle tree over the transcript rather than one hash?**
A finder can reveal one leaf (the verification step) with an inclusion proof and keep the prompts private;
a platform can check a partial release; and editing, reordering or dropping a turn after the root is signed
is as visible as forging one. One hash gives tamper evidence only when the whole transcript is released.
Neither a tree nor a hash proves the finder committed every turn it ran; that is a property of the recorder,
and only a recorder inside a measured harness (L3) can attest it.

**Why does L2 need a platform countersignature? Isn't the finder's signature enough?**
The finder's signature proves what the finder said. It cannot prove when the maintainer heard it or through
what channel, and those are the facts that disputes are about: who disclosed first, whether the embargo was
respected, whether the fix went out through the authoritative distribution. Only the receiver can sign those,
and the receiver's clock is only as good as the transparency log it anchors the receipt in.

**If the receiver re-runs the test anyway, what does the statement give it?**
Less on the Evidence pillar than a SLSA consumer gets from build provenance, and the spec does not pretend
otherwise. The platform that re-executes learns from Evidence L2 what it did itself. What it could not produce is the
transcript commitment, the MBOM and the countersigned ledger, so for a direct receiver the statement's value is mostly
on the Identity pillar: whom to re-execute first, how much admission to grant, which lane. The Evidence pillar pays off
downstream: a maintainer who reads a platform's receipt instead of running the test, a coordinator without the code,
an auditor later.

**Who has to adopt VSLA before L2 means anything?**
Three parties: codebases that declare a machine intake as the authoritative channel (VSLA-F-10), platforms that
re-execute with VM isolation and countersign, and readers that pin those platforms. Until a second independent
platform is pinned, a finder's ledger has one countersigner and, under the two-countersigner floor, cannot reach L2
except through a maintainer's direct countersignature. That is the bootstrap cost of the design.

**Why a trust ledger instead of a bounty?**
Bounties pay for findings and so reward volume and first-to-file. Maintainers of core infrastructure have
rejected bounty programs for their projects because of the arguments they generate over breaking fixes and
the way they distort volunteer pipelines. A ledger pays in nothing except trust, which is what a maintainer
actually wants to know about a finder: do its findings tend to be real, and does it behave. A ledger is also
only as good as the countersigners the reader has pinned; presented to a bounty triager who pins none, it is a
list of claims.

**Can't a finder just build a ledger with two keys it controls, or borrow someone else's?**
It can build the entries. A verifier counts only countersigners it has pinned, per operator, so those entries
count for nothing at any platform that did not choose to trust those keys; the floor also has a minimum age.
A borrowed ledger counts for nothing either: every entry names the finder key and the track it was earned on,
and a verifier drops entries for any other key or track. The first
version of this rubric let two colluding keys reach L2 on day zero; the revision closes that and says plainly
that "two countersigners" is a floor on distinct pinned keys, not on independence.

**Why a TEE at L3? Weights are public for open models.**
Public weights can still be swapped, fine-tuned or quantized by the operator between download and inference,
and the operator's harness decides what the model sees. L3 is not about secrecy of the weights; it is about
the receiver being able to check that *these* weights, in *this* harness, under *this* policy produced the
statement, with a signing key that could not have been used anywhere else. A TEE proves which bytes ran. It
does not prove the harness is honest (the receiver's measurement allowlist is where that judgement lives), it
does not prove the operator fed the harness honest inputs, and it does not prove the weights behave well.

**Can a pipeline that calls a model through an API reach L3?**
No. An API-served model cannot be measured by anyone but its provider, so any `serving: api` model in the
MBOM caps the Environment pillar at L2. L3 is available to operators that serve open weights themselves, and
to model providers that run their own finders inside an attested environment.

**What if the hardware TEE vendor is in the threat model?**
Use the two-operator form. It splits inference across two
independently owned hosts with a 2-of-2 signing group, so no single operator, and no single vendor, can read,
alter or sign alone; a verifier requires the two co-signers to be distinct pinned roots, because one root listed
twice is one operator. That is a different trust statement from a hardware enclave ("neither of two operators"
rather than "not the operator"), and VSLA treats either as satisfying the Environment pillar at L3 while
requiring the verifier to record which one it accepted.

**Does the receiver's classifier stop a finder that fails on demand?**
No. The classifier reads the test runner's own report and rejects honest non-security failures (a missing
import, a fixture error, a timeout). A hostile test runs inside the runner's process and can in principle forge
that report, and `import subject; assert False` satisfies both the classifier and the coverage check without
forging anything. That is why L2 says "somebody other than the finder reproduced it" and nothing stronger, and
why the Patch track, whose test must pass after the fix, is the track with a differential check.

**What stops the receiving platform from executing a hostile proof of concept?**
Nothing but its own isolation, which is why the spec now requires it: no network egress, no access to the
signing keys, token issuer, database or other cases, resource caps, a distinct principal, and VM-level
isolation in production, with the isolation class written into every receipt. The platform's signing key is
the whole of L2 and a sandbox beside it is the attacker's target.

**Is a human allowed anywhere?**
Everywhere the policy wants one. VSLA constrains what the machines must prove to each other; it does not
forbid a maintainer from pausing a case, requiring approval before a PR opens, or reading every diff. A level
is an input to triage ordering, never to review depth on a security-sensitive surface. What it changes is that
the human's attention is spent on the cases that earned it, instead of on the inbox.

**Does a high ledger score mean a finder's next patch is safe?**
No. A level is evidence about this disclosure; a score is a record of past ones. The long-game compromise
(earn trust, spend it once) is the attack the Patch track's reviewer-diversity and source-only rules exist for,
and `retracted` is disqualifying and retroactive for the finder that does it.

**Does VSLA replace CVSS, CWE, CVE or OSV?**
No. A VSLA statement is carried alongside an OSV advisory and references the CVE; the level says how much to
trust the disclosure, not how bad the bug is. CNAs and bounty programs will still ask who the legal reporter
is; the statement names an operator, which is the accountable party.

**Does VSLA do anything about a hunter that never discloses?**
No, and it says so. Every lever VSLA has acts on an identity that submits statements. The authorization basis
in every statement is recorded so an unauthorised disclosure is attributable; it is not enforced, and the
reference hunter refuses to start without an explicit allowlist of targets for the operator's sake, not the
framework's.

**Who is the authority on a level?**
Nobody central. A level is computed by whoever verifies, from evidence anyone can re-check, against keys and
expectations the verifier chose. Two verifiers with the same inputs and the same pinned keys get the same
level; a verifier without the code, or without expectations, gets a lower, honest one.

**What does "Hardened" protect the finder's operator against?**
Being blamed for something its model did not do. An L3 statement is also the operator's proof that the run
was the run, which matters when a model provider is accused of leaking a zero-day it found.
