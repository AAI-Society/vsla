"""The reference verifier against the generated examples: each example verifies at its claimed level with full
inputs, and degrades honestly when inputs are missing, tampered, self-reported, borrowed, reordered or Sybil-built.

Requirement ids pinned here: VSLA-F-1 (canonical DSSE), VSLA-F-4 (verify leaf), VSLA-F-20 (successor and revoke
entries), VSLA-P-3 / P-16 (receipt, anchor forms), VSLA-P-4 (re-execution at the subject revision), VSLA-P-10
(receiver review), VSLA-P-11 (isolation class), VSLA-P-14 (consistency by prefix root and inclusion of the verifier's
own entries), VSLA-V-1 (pinned keys; enclave key from the quote), VSLA-V-2 (per-pillar minimum), VSLA-V-3 (missing
or malformed input fails the check), VSLA-V-4 (someone other than the finder re-executed), VSLA-V-5 (countersigner
allowlist; finder- and track-bound entries), VSLA-V-6 (expectations), VSLA-V-7 (one evaluation instant)."""

import base64
import json
import subprocess
import sys
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "tools"))
import vsla_verify as v  # noqa: E402

EX = ROOT / "schema" / "examples"
T0_DAYS = 20756.583333  # 2026-10-30T14:00Z, the examples' "now"
INTAKE = "https://cvd.example.org/mcp"
ALL = [("finding-l1", 1), ("finding-l2", 2), ("finding-l3", 3), ("patch-l1", 1), ("patch-l2", 2), ("patch-l3", 3)]


@pytest.fixture(scope="session", autouse=True)
def examples():
    subprocess.run([sys.executable, str(ROOT / "tools" / "make_examples.py")], check=True, capture_output=True)


def load(name):
    return json.loads((EX / name).read_text())


def inputs(name, ring=None):
    ring = ring or v.Keyring.load(EX / "keyring.json")
    patch = "patch" in name
    kw = dict(keyring=ring, expectations=load("expectations.json"), report=load("report.json"), leaves=load("leaves.json"),
              ledger_entries=load("ledger-patch.json" if patch else "ledger.json"), reexecution=load("reexecution-patch.json" if patch else "reexecution.json"),
              expected_intake=INTAKE, quote_verifier=v.signed_quote_verifier(ring), now_days=T0_DAYS)
    if (EX / f"{name}.receipt.dsse.json").exists():
        kw["receipt"] = load(f"{name}.receipt.dsse.json")
    return kw


def resign(env, stmt, key=None, kid="finder:agent:researcher-1"):
    """Re-sign a modified statement with a fresh (unpinned) key unless a key is given: tests tamper, then check."""
    payload = v.canonical(stmt)
    k = key or Ed25519PrivateKey.generate()
    return {**env, "payload": base64.b64encode(payload).decode(),
            "signatures": [{"keyid": kid, "sig": base64.b64encode(k.sign(v.pae(v.PAYLOAD_TYPE, payload))).decode()}]}


def pinned_finder(name="finding-l2", identity="agent:researcher-1"):
    """A fresh finder key pinned in a copy of the keyring, and the example statement re-keyed to it: for tests that
    need to modify the predicate and still pass E2."""
    fk = Ed25519PrivateKey.generate()
    ring_json = load("keyring.json"); ring_json[f"finder:{identity}"] = "ed25519:" + v.public_hex(fk.public_key())
    env = load(f"{name}.dsse.json"); stmt = v.envelope_payload(env)
    stmt["predicate"]["finder"]["identity"] = identity
    stmt["predicate"]["finder"]["publicKey"] = ring_json[f"finder:{identity}"]
    return fk, v.Keyring(ring_json), env, stmt


def fresh_ledger(ring_json, finder_pub_hex, track, n=6):
    """A ledger for a test-pinned finder: n accepted entries, 100 days old, countersigned by two pinned test maintainers
    (added to ring_json). Returns (entries, history) with history matching root and score, as a real finder would carry."""
    ka, kb = Ed25519PrivateKey.generate(), Ed25519PrivateKey.generate()
    ring_json["maintainer:test/a"] = "ed25519:" + v.public_hex(ka.public_key()); ring_json["maintainer:test/b"] = "ed25519:" + v.public_hex(kb.public_key())
    entries = []
    for i in range(n):
        at = f"2026-0{7 if i < 3 else 8}-{10 + i:02d}T00:00:00Z"
        body = {"at": at, "finder": "ed25519:" + finder_pub_hex, "statement": {"sha256": "%064x" % (i + 1)}, "platform": "test",
                "track": track, "outcome": "accepted", "claimed": 2, "verified": 2}
        kid, k = [("maintainer:test/a", ka), ("maintainer:test/b", kb)][i % 2]
        entries.append(v.make_ledger_entry(body, [(kid, k)]))
    bodies, _ = v.verified_ledger(entries, v.Keyring(ring_json), finder="ed25519:" + finder_pub_hex, track=track)
    ts = v.trust_score(bodies, now_days=T0_DAYS)
    history = {"ledger": "https://ledger.test/x", "root": v.ledger_root(entries), "entries": ts["n"], "accepted": ts["accepted"], "rejected": 0,
               "countersigners": ts["countersigners"], "score": ts["score"], "floor": 0.6, "oldestAt": bodies[0]["at"]}
    return entries, history


def check(res, cid):
    return next(c for p in res.pillars.values() for c in p.checks if c.id == cid)


# ----------------------------------------------------------------------------- canonical JSON (RFC 8785)

def test_canonical_is_jcs():
    """VSLA-F-1."""
    assert v.canonical({"b": 1, "a": [True, None, "xé\n"]}) == '{"a":[true,null,"xé\\n"],"b":1}'.encode()
    assert v.canonical({"n": 1.0}) == b'{"n":1}' and v.canonical({"n": 0.1}) == b'{"n":0.1}'
    assert v.canonical(1e21) == b"1e+21" and v.canonical(1e-7) == b"1e-7" and v.canonical(0.00001) == b"0.00001" and v.canonical(1e16) == b"10000000000000000"
    assert v.canonical(-1.5e-10) == b"-1.5e-10" and v.canonical(123456789012345680.0) == b"123456789012345680"
    assert v.canonical({"€": 1, "\U0001d11e": 2, "z": 3}) == '{"z":3,"€":1,"\U0001d11e":2}'.encode()  # UTF-16 code-unit order
    # integers are IEEE-754 doubles in JCS: beyond 2^53 they serialise as the double they parse to
    assert v.canonical(2**63) == b"9223372036854776000" and v.canonical(2**53 + 1) == b"9007199254740992" and v.canonical(10**22) == b"1e+22"
    assert v.canonical(2**53) == b"9007199254740992" and v.canonical(-0.0) == b"0"
    with pytest.raises(ValueError):
        v.canonical(float("nan"))
    with pytest.raises(ValueError):
        v.canonical({"s": "\ud800"})          # a lone surrogate is not UTF-8
    with pytest.raises(TypeError):
        v.canonical({"x": object()})


def test_parse_canonical_rejects_duplicate_keys_and_non_canonical_bytes():
    assert v.parse_canonical(b'{"a":1,"b":[2,3]}') == {"a": 1, "b": [2, 3]}
    for bad in (b'{"a":1,"a":2}', b'{"b":1,"a":2}', b'{"a": 1}', b'{"a":1.0}', b'[1,2'):
        with pytest.raises(ValueError):
            v.parse_canonical(bad)


def test_signed_payload_must_be_canonical():
    """A payload with two `claimedLevel` keys parses differently in different JSON parsers; it is rejected at E1 (VSLA-F-1)."""
    fk, ring, env, stmt = pinned_finder("finding-l1")
    raw = v.canonical(stmt).decode()
    i = raw.rfind('"vslaVersion":"1.0"')
    payload = (raw[:i] + '"vslaVersion":"1.0","claimedLevel":3' + raw[i + len('"vslaVersion":"1.0"'):]).encode()
    env = {**env, "payload": base64.b64encode(payload).decode(), "signatures": [{"keyid": "finder:agent:researcher-1", "sig": base64.b64encode(fk.sign(v.pae(v.PAYLOAD_TYPE, payload))).decode()}]}
    res = v.verify(env, **inputs("finding-l1", ring))
    assert res.verified == 0 and res.pillars["evidence"].failed == "E1" and "canonical" in check(res, "E1").detail


def test_malformed_inputs_fail_checks_instead_of_raising():
    """VSLA-V-3: a lone surrogate in a leaf, a ledger entry or the report is a failed check, not an exception."""
    kw = inputs("finding-l2")
    leaves = load("leaves.json"); leaves[2]["name"] = "\ud800"
    res = v.verify(load("finding-l2.dsse.json"), **{**kw, "leaves": leaves})
    assert res.pillars["evidence"].failed == "E5"
    res = v.verify(load("finding-l2.dsse.json"), **{**kw, "report": {"title": "\udfff"}})
    assert res.pillars["evidence"].failed == "E3"
    ledger = load("ledger.json"); ledger[3] = {**ledger[3], "payload": base64.b64encode(b'{"kind":"outcome","seq":3,"x":"\\ud800"}').decode()}
    res = v.verify(load("finding-l2.dsse.json"), **{**kw, "ledger_entries": ledger})
    assert res.pillars["identity"].failed == "I4"


# ----------------------------------------------------------------------------- the examples

@pytest.mark.parametrize("name,level", ALL)
def test_examples_verify_at_claimed_level(name, level):
    res = v.verify(load(f"{name}.dsse.json"), **inputs(name))
    assert res.claimed == level and res.verified == level, res.to_dict()


@pytest.mark.parametrize("name", ["finding-l2", "finding-l3", "patch-l2", "patch-l3"])
def test_examples_verify_with_receipt_only_and_anchor_required(name):
    """VSLA-P-3/P-16: the receipt alone (no own re-execution) carries Evidence to L2, and its anchor verifies under the pinned log key."""
    kw = inputs(name); kw["reexecution"] = None; kw["require_anchor"] = True
    res = v.verify(load(f"{name}.dsse.json"), **kw)
    assert res.pillars["evidence"].level >= 2 and check(res, "I3").ok and "log-inclusion in" in check(res, "I3").detail, res.to_dict()


def test_merkle_tamper_and_inclusion():
    """VSLA-F-4."""
    leaves = v.transcript_leaves(load("leaves.json"))
    root = v.merkle_root(leaves)
    proof = v.inclusion_proof(leaves, 4)
    assert v.verify_inclusion(leaves[4], proof, root)
    bad = list(leaves); bad[4] = bad[4].replace(b'"exit":1', b'"exit":0')
    assert v.merkle_root(bad) != root
    assert v.merkle_root(leaves[:-1]) != root and v.merkle_root(leaves[::-1]) != root


def test_tampered_payload_fails_signature():
    env = load("finding-l1.dsse.json")
    stmt = v.envelope_payload(env)
    stmt["predicate"]["claimedLevel"] = 3
    env["payload"] = base64.b64encode(v.canonical(stmt)).decode()
    res = v.verify(env, **inputs("finding-l1"))
    assert res.verified == 0 and res.pillars["evidence"].failed == "E2"


def test_missing_claimed_level_fails_e1():
    env = load("finding-l1.dsse.json")
    stmt = v.envelope_payload(env); del stmt["predicate"]["claimedLevel"]
    res = v.verify(resign(env, stmt), **inputs("finding-l1"))
    assert res.verified == 0 and res.pillars["evidence"].failed == "E1"


def test_check_kinds_are_recorded():
    """VSLA-V-2: E5 compares finder-written leaves with a finder-written section, so it is structural; the level-separating checks are external."""
    res = v.verify(load("finding-l2.dsse.json"), **inputs("finding-l2"))
    kinds = {c.id: c.kind for p in res.pillars.values() for c in p.checks}
    assert kinds["E5"] == "structural" and kinds["E6"] == "structural" and kinds["E1"] == "structural"
    assert all(kinds[c] == "external" for c in ("E2", "E7", "I1", "I2", "I3", "I4", "I5", "N2", "N3"))


# ----------------------------------------------------------------------------- evidence

def test_verify_leaf_must_match_reproduction():
    """VSLA-F-4."""
    kw = inputs("finding-l1")
    leaves = load("leaves.json"); leaves[6]["exit"] = 0                     # the verify leaf disagrees with the statement
    kw["leaves"] = leaves
    res = v.verify(load("finding-l1.dsse.json"), **kw)
    assert res.pillars["evidence"].failed == "E5"


def test_reproduction_must_run_at_subject_revision():
    """VSLA-P-4 / VSLA-F-2: a pinned finder whose reproduction names another revision fails E3; a re-execution at another revision fails E7."""
    fk, ring, env, stmt = pinned_finder("finding-l1")
    stmt["predicate"]["reproduction"]["revision"] = "0" * 40
    res = v.verify(resign(env, stmt, fk), **inputs("finding-l1", ring))
    assert res.verified == 0 and res.pillars["evidence"].failed == "E3"
    kw = inputs("finding-l2"); kw["reexecution"] = {**load("reexecution.json"), "revision": "0" * 40}; kw.pop("receipt")
    res = v.verify(load("finding-l2.dsse.json"), **kw)
    assert res.verified == 1 and res.pillars["evidence"].failed == "E7"


def test_coordinator_without_code_lands_at_l1():
    """VSLA-V-3 / V-4."""
    kw = inputs("finding-l2"); kw["reexecution"] = None; kw.pop("receipt")
    res = v.verify(load("finding-l2.dsse.json"), **kw)
    assert res.verified == 1 and res.pillars["evidence"].failed == "E7"


def test_receiver_classifier_and_subject_coverage_gate_l2():
    """VSLA-P-4."""
    kw = inputs("finding-l2"); kw.pop("receipt")
    kw["reexecution"] = {**load("reexecution.json"), "touchedSubject": False}   # the test never imported the subject package
    res = v.verify(load("finding-l2.dsse.json"), **kw)
    assert res.verified == 1 and res.pillars["evidence"].failed == "E7"
    kw["reexecution"] = {**load("reexecution.json"), "securityFailure": False}  # the platform's own classifier disagrees with the finder's flag
    res = v.verify(load("finding-l2.dsse.json"), **kw)
    assert res.verified == 1 and res.pillars["evidence"].failed == "E7"


def test_required_isolation_class_gates_e7():
    """VSLA-P-11: a policy that requires vm isolation does not accept a re-execution in a process sandbox."""
    kw = inputs("finding-l2"); kw.pop("receipt")
    kw["reexecution"] = {**load("reexecution.json"), "sandbox": {"backend": "local", "isolation": "process"}}
    assert v.verify(load("finding-l2.dsse.json"), **kw).pillars["evidence"].level == 3        # no policy: accepted, and the class is in the detail
    assert "isolation=process" in check(v.verify(load("finding-l2.dsse.json"), **kw), "E7").detail
    res = v.verify(load("finding-l2.dsse.json"), **{**kw, "require_isolation": "vm"})
    assert res.verified == 1 and res.pillars["evidence"].failed == "E7"
    assert v.verify(load("finding-l2.dsse.json"), **{**inputs("finding-l2"), "require_isolation": "vm"}).verified == 2   # the example ran in a vm


def test_finder_asserted_review_does_not_satisfy_e8():
    """VSLA-P-10."""
    kw = inputs("patch-l2"); kw.pop("receipt")
    rx = load("reexecution-patch.json"); rx.pop("review")              # the statement still says review.approved; the receiver did none
    kw["reexecution"] = rx
    res = v.verify(load("patch-l2.dsse.json"), **kw)
    assert res.verified == 1 and res.pillars["evidence"].failed == "E8"
    kw["reexecution"] = {**load("reexecution-patch.json"), "review": {**load("reexecution-patch.json")["review"], "distinctFamily": False}}
    assert v.verify(load("patch-l2.dsse.json"), **kw).pillars["evidence"].failed == "E8"
    kw["reexecution"] = {**load("reexecution-patch.json"), "scope": "mixed"}   # touches CI/build/fixtures: capped at L1
    assert v.verify(load("patch-l2.dsse.json"), **kw).pillars["evidence"].failed == "E8"


def test_non_source_paths():
    """VSLA-F-18."""
    assert v.non_source_paths(["src/a.py", ".github/workflows/ci.yml", "tests/fixtures/blob.bin", "pyproject.toml", "Makefile", ".gitmodules", "conftest.py", "vulnpkg/site.pth"]) == \
        [".github/workflows/ci.yml", "tests/fixtures/blob.bin", "pyproject.toml", "Makefile", ".gitmodules", "conftest.py", "vulnpkg/site.pth"]


# ----------------------------------------------------------------------------- identity: the receipt

def test_self_signed_receipt_does_not_count():
    """VSLA-P-3 / V-1: a receipt signed by the finder's own pinned key is not a receipt, and E7 does not read it (round 2, probe P1)."""
    fk, ring, env, stmt = pinned_finder("finding-l2")
    env = resign(env, stmt, fk)
    rx = {k: x for k, x in load("reexecution.json").items() if k != "command"} | {"commandDigest": {"sha256": "0" * 64}}
    fake = v.make_receipt(env, keyid="finder:agent:researcher-1", key=fk, channel=INTAKE, received_at="2026-10-30T14:05:00Z", reexecution=rx)
    kw = inputs("finding-l2", ring); kw["receipt"] = fake; kw["reexecution"] = None
    res = v.verify(env, **kw)
    assert res.verified == 1 and res.pillars["identity"].failed == "I3" and res.pillars["evidence"].failed == "E7"
    assert "ignored" in check(res, "E7").detail
    # a receipt under a pinned maintainer: key is not a platform receipt either
    mk = Ed25519PrivateKey.generate(); ring_json = load("keyring.json"); ring_json["maintainer:x"] = "ed25519:" + v.public_hex(mk.public_key())
    ring_json["finder:agent:researcher-1"] = "ed25519:" + v.public_hex(fk.public_key()); ring = v.Keyring(ring_json)
    fake = v.make_receipt(env, keyid="maintainer:x", key=mk, channel=INTAKE, received_at="2026-10-30T14:05:00Z", reexecution=rx)
    res = v.verify(env, **{**inputs("finding-l2", ring), "receipt": fake, "reexecution": None})
    assert res.pillars["identity"].failed == "I3" and res.pillars["evidence"].failed == "E7"


def test_receipt_must_come_from_the_platform_the_statement_names():
    """I3: the receipt signer is the pinned platform key equal to channel.intakeKey; a second pinned platform's receipt does not count."""
    other = Ed25519PrivateKey.generate()
    ring_json = load("keyring.json"); ring_json["platform:other.example"] = "ed25519:" + v.public_hex(other.public_key()); ring = v.Keyring(ring_json)
    env = load("finding-l2.dsse.json")
    rx = v.envelope_payload(load("finding-l2.receipt.dsse.json"))["reexecution"]
    fake = v.make_receipt(env, keyid="platform:other.example", key=other, channel=INTAKE, received_at="2026-10-30T14:05:00Z", reexecution=rx)
    res = v.verify(env, **{**inputs("finding-l2", ring), "receipt": fake, "reexecution": None})
    assert res.pillars["identity"].failed == "I3" and res.pillars["evidence"].failed == "E7"
    # the genuine receipt still verifies with several platforms pinned (the key is chosen from channel.intakeKey), and with --platform-key
    assert v.verify(env, **{**inputs("finding-l2", ring), "reexecution": None}).verified == 2
    assert v.verify(env, **{**inputs("finding-l2", ring), "reexecution": None, "platform_key": "platform:cvd.example.org"}).verified == 2
    res = v.verify(env, **{**inputs("finding-l2", ring), "reexecution": None, "platform_key": "platform:other.example"})
    assert res.pillars["identity"].level == 1 and not check(res, "I2").ok and not check(res, "I3").ok


def test_receipt_tamper_detected():
    """VSLA-P-3."""
    kw = inputs("finding-l2"); rc = load("finding-l2.receipt.dsse.json")
    body = v.envelope_payload(rc); body["receivedAt"] = "2026-01-01T00:00:00Z"   # backdating breaks the platform signature
    rc["payload"] = base64.b64encode(v.canonical(body)).decode()
    res = v.verify(load("finding-l2.dsse.json"), **{**kw, "receipt": rc, "reexecution": None})
    assert res.verified == 1 and res.pillars["identity"].failed == "I3" and res.pillars["evidence"].failed == "E7"
    res = v.verify(load("finding-l1.dsse.json"), **{**inputs("finding-l1"), "receipt": load("finding-l2.receipt.dsse.json")})   # a receipt for another statement
    assert res.pillars["identity"].failed in ("I2", "I3")
    # a receipt whose payload type is not the receipt type is not a receipt, even with a valid platform signature
    bad = v.dsse_sign(v.envelope_payload(load("finding-l2.receipt.dsse.json")), v.PAYLOAD_TYPE, [("platform:cvd.example.org", Ed25519PrivateKey.generate())])
    assert v.verify(load("finding-l2.dsse.json"), **{**kw, "receipt": bad}).pillars["identity"].failed == "I3"


def test_receipt_time_is_bounded_on_both_sides():
    """I3: receivedAt may not precede the run nor lie beyond the verifier's clock plus skew."""
    kw = inputs("finding-l2")
    env = load("finding-l2.dsse.json")
    # we do not hold the platform's private key: build a parallel keyring whose platform key we control
    pk = Ed25519PrivateKey.generate(); fk = Ed25519PrivateKey.generate()
    ring_json = load("keyring.json"); ring_json["platform:cvd.example.org"] = "ed25519:" + v.public_hex(pk.public_key())
    ring_json["finder:agent:researcher-1"] = "ed25519:" + v.public_hex(fk.public_key())
    stmt = v.envelope_payload(env); stmt["predicate"]["finder"]["publicKey"] = ring_json["finder:agent:researcher-1"]; stmt["predicate"]["channel"]["intakeKey"] = ring_json["platform:cvd.example.org"]
    env = resign(env, stmt, fk); ring = v.Keyring(ring_json)
    rx = v.envelope_payload(load("finding-l2.receipt.dsse.json"))["reexecution"]
    for at, ok in (("2026-10-30T14:05:00Z", True), ("2026-10-30T14:03:00Z", False), ("2026-10-30T13:00:00Z", False), ("2099-01-01T00:00:00Z", False)):   # 14:03 precedes finishedAt 14:04
        rc = v.make_receipt(env, keyid="platform:cvd.example.org", key=pk, channel=INTAKE, received_at=at, reexecution=rx)
        res = v.verify(env, **{**kw, "keyring": ring, "receipt": rc, "reexecution": None})
        assert check(res, "I3").ok is ok, (at, check(res, "I3").detail)


def test_anchor_is_verified_and_can_be_required():
    """VSLA-P-16: the signed-anchor must verify under a pinned log key and commit to this receipt; a third-party verifier can require one."""
    env = load("finding-l2.dsse.json"); kw = inputs("finding-l2"); kw["reexecution"] = None
    rc = load("finding-l2.receipt.dsse.json")
    assert "log-inclusion in log.example.org" in check(v.verify(env, **kw), "I3").detail
    anc = v.envelope_payload(rc)["anchor"]
    assert anc["form"] == "log-inclusion" and anc["treeSize"] == 3 and anc["leafIndex"] == 1
    # unpinned log: the receipt still counts, the anchor does not; required -> I3 and E7 both fail (the receipt is the evidence)
    ring_json = load("keyring.json"); ring_json.pop("log:log.example.org")
    res = v.verify(env, **{**kw, "keyring": v.Keyring(ring_json), "quote_verifier": None})
    assert check(res, "I3").ok and "not pinned" in check(res, "I3").detail
    res = v.verify(env, **{**kw, "keyring": v.Keyring(ring_json), "quote_verifier": None, "require_anchor": True})
    assert res.pillars["identity"].failed == "I3" and res.pillars["evidence"].failed == "E7" and "anchor required" in check(res, "I3").detail
    # a tampered inclusion proof fails
    bad = json.loads(json.dumps(rc)); b = v.envelope_payload(bad); b["anchor"]["inclusionProof"][0][1] = "0" * 64
    bad["payload"] = base64.b64encode(v.canonical(b)).decode()        # platform signature now breaks too; check the anchor verifier directly
    ok, form, why = v.verify_anchor(b, v.Keyring.load(EX / "keyring.json"), now_s=T0_DAYS * 86400)
    assert not ok and form == "log-inclusion" and "inclusion proof" in why
    # anchor stripped from the body breaks the platform signature; a receipt with no anchor at all fails only when required
    pk = Ed25519PrivateKey.generate(); fk = Ed25519PrivateKey.generate()
    ring_json = load("keyring.json"); ring_json["platform:cvd.example.org"] = "ed25519:" + v.public_hex(pk.public_key()); ring_json["finder:agent:researcher-1"] = "ed25519:" + v.public_hex(fk.public_key())
    stmt = v.envelope_payload(env); stmt["predicate"]["finder"]["publicKey"] = ring_json["finder:agent:researcher-1"]; stmt["predicate"]["channel"]["intakeKey"] = ring_json["platform:cvd.example.org"]
    ledger, stmt["predicate"]["history"] = fresh_ledger(ring_json, v.public_hex(fk.public_key()), "finding")
    kw["ledger_entries"] = ledger
    env2 = resign(env, stmt, fk); ring = v.Keyring(ring_json)
    plain = v.make_receipt(env2, keyid="platform:cvd.example.org", key=pk, channel=INTAKE, received_at="2026-10-30T14:05:00Z", reexecution=v.envelope_payload(rc)["reexecution"])
    assert v.verify(env2, **{**kw, "keyring": ring, "receipt": plain}).verified == 2
    res = v.verify(env2, **{**kw, "keyring": ring, "receipt": plain, "require_anchor": True})
    assert res.verified == 1 and res.pillars["identity"].failed == "I3" and "no anchor" in check(res, "I3").detail
    # the signed-timestamp form: a pinned log key's timestamp, accepted for --require-anchor only when the policy says so
    lk = Ed25519PrivateKey.generate(); ring_json["log:log.example.org"] = "ed25519:" + v.public_hex(lk.public_key()); ring = v.Keyring(ring_json)
    stamped = v.make_receipt(env2, keyid="platform:cvd.example.org", key=pk, channel=INTAKE, received_at="2026-10-30T14:05:00Z",
                             reexecution=v.envelope_payload(rc)["reexecution"], anchor_log=("log.example.org", lk, "e1", "2026-10-30T14:06:00Z"))
    assert v.envelope_payload(stamped)["anchor"]["form"] == "signed-timestamp"
    res = v.verify(env2, **{**kw, "keyring": ring, "receipt": stamped, "require_anchor": True})
    assert res.pillars["identity"].failed == "I3" and "signed-timestamp" in check(res, "I3").detail
    assert v.verify(env2, **{**kw, "keyring": ring, "receipt": stamped, "require_anchor": True, "accept_timestamp_anchor": True}).verified == 2
    # a timestamp signed by the log over a different receipt does not transfer
    body = v.envelope_payload(plain)
    foreign = v.make_anchor({**body, "receivedAt": "2026-10-30T14:04:00Z"}, log="log.example.org", key=lk, entry_id="e1", integrated_time="2026-10-30T14:06:00Z")
    rc2 = v.dsse_sign({**body, "anchor": foreign}, v.RECEIPT_PAYLOAD_TYPE, [("platform:cvd.example.org", pk)])
    res = v.verify(env2, **{**kw, "keyring": ring, "receipt": rc2, "require_anchor": True, "accept_timestamp_anchor": True})
    assert res.pillars["identity"].failed == "I3" and "different receipt" in check(res, "I3").detail


def test_wrong_intake_blocks_l2():
    kw = inputs("finding-l2"); kw["expected_intake"] = "https://other.example/mcp"
    res = v.verify(load("finding-l2.dsse.json"), **kw)
    assert res.verified == 1 and res.pillars["identity"].failed == "I2"


# ----------------------------------------------------------------------------- identity: the ledger

def test_self_reported_history_is_not_evidence():
    """VSLA-V-3."""
    kw = inputs("finding-l2"); kw["ledger_entries"] = None               # only the finder's summary is available
    res = v.verify(load("finding-l2.dsse.json"), **kw)
    assert res.verified == 1 and res.pillars["identity"].failed == "I4"


def test_ledger_countersignatures_are_verified():
    """VSLA-V-5."""
    kw = inputs("finding-l2")
    ledger = load("ledger.json")
    bad = [{**e, "signatures": [{"keyid": e["signatures"][0]["keyid"], "sig": base64.b64encode(b"A" * 64).decode()}]} for e in ledger]
    bodies, dropped = v.verified_ledger(bad, kw["keyring"])
    assert dropped == len(ledger) and bodies == []
    ring = v.Keyring.load(EX / "keyring.json")
    ring._keys.pop("maintainer:acme/app")                              # an unpinned countersigner contributes nothing
    bodies, dropped = v.verified_ledger(ledger, ring)
    assert dropped == 3 and len({b["countersigner"] for b in bodies}) == 2


def test_ledger_entries_are_bound_to_the_finder_key():
    """VSLA-V-5: another finder's countersigned ledger counts for nothing under a different key (round 2, probe P3)."""
    fk, ring, env, stmt = pinned_finder("finding-l2", identity="agent:thief")
    env = resign(env, stmt, fk, kid="finder:agent:thief")
    kw = inputs("finding-l2", ring); kw.pop("receipt")
    res = v.verify(env, **kw)
    assert res.verified == 1 and not check(res, "I4").ok and "13 outcome entries dropped" in check(res, "I4").detail
    bodies, dropped = v.verified_ledger(load("ledger.json"), ring, finder="ed25519:" + v.public_hex(fk.public_key()))
    assert bodies == [] and dropped == 13


def test_ledger_entries_are_bound_to_the_track():
    """A Finding-track ledger buys no Patch trust (round 2, probe P4)."""
    kw = inputs("patch-l2"); kw["ledger_entries"] = load("ledger.json")
    res = v.verify(load("patch-l2.dsse.json"), **kw)
    assert res.verified == 1 and res.pillars["identity"].failed == "I4"
    kw = inputs("finding-l2"); kw["ledger_entries"] = load("ledger-patch.json")
    assert v.verify(load("finding-l2.dsse.json"), **kw).pillars["identity"].failed == "I4"
    assert {v.envelope_payload(e)["track"] for e in load("ledger-patch.json")} == {"patch"}


def test_presented_order_cannot_move_the_score_and_omission_is_a_fork():
    """VSLA-P-14 / V-5 (round 3): the finder owns the order; the rubric window is by countersigned `at`, so reordering a
    60-entry history changes nothing; a ledger that omits an entry this verifier countersigned is a ledger-fork."""
    first = [{"outcome": "rejected", "countersigner": "platform:a", "at": T0_DAYS - 5, "claimed": 1, "verified": 1} for _ in range(10)] + \
            [{"outcome": "accepted", "countersigner": ["platform:a", "platform:b"][i % 2], "at": T0_DAYS - 100 + i, "claimed": 1, "verified": 1} for i in range(50)]
    assert v.trust_score(first, now_days=T0_DAYS)["score"] == v.trust_score(first[10:] + first[:10], now_days=T0_DAYS)["score"]
    kw = inputs("finding-l2"); ledger = load("ledger.json")
    reordered = ledger[5:] + ledger[:5]                                    # presented order is part of the root the statement commits to
    res = v.verify(load("finding-l2.dsse.json"), **{**kw, "ledger_entries": reordered})
    assert res.pillars["identity"].failed == "I4" and "history.root mismatch" in check(res, "I4").detail
    assert v.ledger_well_formed(ledger)[0] and v.ledger_well_formed(ledger[:4] + ledger[5:])[0]   # no seq: any order is well formed
    # the verifier's own entry must be included somewhere; its position is the finder's business
    res = v.verify(load("finding-l2.dsse.json"), **{**kw, "required_entries": [ledger[9]]})
    assert check(res, "I4").ok
    res = v.verify(load("finding-l2.dsse.json"), **{**kw, "required_entries": [ledger[9]], "ledger_entries": ledger[:9] + ledger[10:]})
    assert not check(res, "I4").ok and "omits 1 entry this verifier countersigned" in check(res, "I4").detail
    assert v.missing_entries(ledger, [ledger[0], {"payloadType": "x", "payload": "AA==", "signatures": []}]) == 1


def test_ledger_fork_detected():
    """VSLA-P-14."""
    kw = inputs("finding-l2"); ledger = load("ledger.json")
    kw["last_seen"] = (v.ledger_root(ledger[:8]), 8)                        # what this platform saw last time
    assert v.verify(load("finding-l2.dsse.json"), **kw).verified == 2
    kw["last_seen"] = (v.ledger_root(ledger[:7] + [ledger[9]]), 8)         # a different history of the same length
    res = v.verify(load("finding-l2.dsse.json"), **kw)
    assert res.verified == 1 and res.pillars["identity"].failed == "I4" and "ledger-fork" in check(res, "I4").detail
    kw = inputs("finding-l2"); kw["ledger_entries"] = ledger[:-1]           # trimmed: root in the statement no longer matches
    res = v.verify(load("finding-l2.dsse.json"), **kw)
    assert res.pillars["identity"].failed == "I4"


def test_sybil_ledger_fails_floor():
    """Two colluding keys, five accepted entries, day zero: v1.0 scored this 0.733 and granted L2."""
    ents = [{"outcome": "accepted", "countersigner": ["platform:a", "platform:b"][i % 2], "at": T0_DAYS, "claimed": 2, "verified": 2} for i in range(5)]
    ts = v.trust_score(ents, now_days=T0_DAYS)
    ok, why = v.meets_floor(ts)
    assert not ok and ts["age_days"] == 0 and "age" in why
    aged = [{**e, "at": T0_DAYS - 40} for e in ents]
    assert v.meets_floor(v.trust_score(aged, now_days=T0_DAYS))[0]      # same ledger 40 days later meets the floor


def test_countersigners_are_counted_per_operator():
    """trust-rubric.md: a keyid names an operator; platform:acme and maintainer:acme are one countersigner (round 2, probe P11)."""
    ents = [{"outcome": "accepted", "countersigner": ["platform:acme.example", "maintainer:acme.example"][i % 2], "at": T0_DAYS - 40, "claimed": 1, "verified": 1} for i in range(6)]
    ts = v.trust_score(ents, now_days=T0_DAYS)
    assert ts["countersigners"] == 1 and not v.meets_floor(ts)[0]
    ents[1]["countersigner"] = "maintainer:other.example"
    assert v.trust_score(ents, now_days=T0_DAYS)["countersigners"] == 2


def test_trust_score_rubric_v11():
    ring = v.Keyring.load(EX / "keyring.json")
    bodies, _ = v.verified_ledger(load("ledger.json"), ring)
    ts = v.trust_score(bodies, now_days=T0_DAYS)
    assert ts["n"] == 11 and ts["accepted"] == 10 and ts["rejected"] == 1 and ts["countersigners"] == 3 and ts["over_claims"] == 1
    assert abs(ts["score"] - 0.8671) < 1e-3
    assert v.trust_score([], now_days=T0_DAYS)["score"] == 0.0
    # neutral outcomes neither pump nor sink; disqualifying outcomes zero the score; withdrawing is not penalised
    dup = [*bodies, *[{**bodies[0], "outcome": "duplicate"} for _ in range(20)]]
    assert v.trust_score(dup, now_days=T0_DAYS)["score"] == ts["score"]
    assert v.trust_score([*bodies, {**bodies[-1], "outcome": "withdrawn"}], now_days=T0_DAYS)["score"] == ts["score"]
    for o in ("non-authoritative-release", "retracted", "ledger-fork"):
        assert v.trust_score([*bodies, {**bodies[-1], "outcome": o}], now_days=T0_DAYS)["score"] == 0.0
    # repeated over-claims disqualify; many recent rejections hurt more than one
    over = [{**b, "claimed": 3, "verified": 1} for b in bodies]
    assert v.trust_score(over, now_days=T0_DAYS)["score"] == 0.0
    one = [*bodies, {**bodies[-1], "outcome": "rejected"}]
    ten = [*bodies, *[{**bodies[-1], "outcome": "rejected"} for _ in range(10)]]
    assert v.trust_score(ten, now_days=T0_DAYS)["score"] < v.trust_score(one, now_days=T0_DAYS)["score"]
    # a vouch adds a countersigner (m) but is not an outcome: it neither counts toward n nor lowers precision
    vouched = [{**bodies[0], "vouched": True, "countersigner": "maintainer:new/project"}]
    assert v.trust_score(vouched, now_days=T0_DAYS)["accepted"] == 0 and v.trust_score(vouched, now_days=T0_DAYS)["n"] == 0
    two = [b for b in bodies if b["countersigner"] == bodies[0]["countersigner"] and b["outcome"] == "accepted"]
    with_vouch = v.trust_score([*two, *vouched], now_days=T0_DAYS)
    assert with_vouch["countersigners"] == v.trust_score(two, now_days=T0_DAYS)["countersigners"] + 1
    assert with_vouch["components"]["P"] == 1.0


def test_one_rejection_weighs_by_history_size():
    """Recency is scaled by n: one fresh rejection against 49 acceptances must not drop an established finder below the
    floor (it did: score 0.49), while one against four still does, and ten recent rejections still hurt more than one."""
    base = {"outcome": "accepted", "track": "finding", "claimed": 2, "verified": 2}
    cs = ["platform:a.example", "maintainer:b.example", "platform:c.example"]
    def ledger(n_acc):
        return [{**base, "countersigner": cs[i % 3], "at": T0_DAYS - 200 + i} for i in range(n_acc)]
    fresh = {**base, "outcome": "rejected", "countersigner": cs[0], "at": T0_DAYS}
    assert v.meets_floor(v.trust_score([*ledger(49), fresh], now_days=T0_DAYS))[0]
    assert not v.meets_floor(v.trust_score([*ledger(4), fresh], now_days=T0_DAYS))[0]
    ten = v.trust_score([*ledger(49), *[fresh] * 10], now_days=T0_DAYS)["score"]
    assert ten < v.trust_score([*ledger(49), fresh], now_days=T0_DAYS)["score"]


def test_revoked_finder_key_fails_i1():
    """VSLA-F-20 / V-1 / V-7: with no receipt the evaluation instant is the verifier's clock; a key revoked at 14:02 verifies a
    statement at 14:00 and fails it from 14:02 on, whatever the finder wrote in finishedAt."""
    kw = inputs("finding-l1")
    ring_json = load("keyring.json")
    ring_json["finder:agent:researcher-1"] = {"public": ring_json["finder:agent:researcher-1"], "revokedAt": "2026-10-30T14:02:00Z"}
    kw["keyring"] = v.Keyring(ring_json)
    assert check(v.verify(load("finding-l1.dsse.json"), **kw), "I1").ok                      # verifier clock 14:00: not yet revoked
    res = v.verify(load("finding-l1.dsse.json"), **{**kw, "now_days": T0_DAYS + 1})
    assert res.pillars["identity"].failed == "I1" and res.verified == 0


# ----------------------------------------------------------------------------- environment

def test_no_expectations_caps_environment_at_l1():
    """VSLA-V-6."""
    kw = inputs("finding-l2"); kw["expectations"] = None
    res = v.verify(load("finding-l2.dsse.json"), **kw)
    assert res.verified == 1 and res.pillars["environment"].failed == "N2"


def test_weight_attestation_is_verified():
    fk, ring, env, stmt = pinned_finder("finding-l2")
    att = stmt["predicate"]["mbom"]["models"][0]["weights"]["attestation"]
    body = v.envelope_payload(att); body["weights"] = {"sha256": "ab" * 32}; att["payload"] = base64.b64encode(v.canonical(body)).decode()
    res = v.verify(resign(env, stmt, fk), **inputs("finding-l2", ring))
    assert res.pillars["environment"].failed == "N2"


def test_claimed_l3_verifies_lower_without_adapter_or_ledger():
    """VSLA-V-2."""
    kw = inputs("finding-l3"); kw["quote_verifier"] = None               # a verifier without an environment adapter
    res = v.verify(load("finding-l3.dsse.json"), **kw)
    assert res.claimed == 3 and res.verified == 2 and res.pillars["environment"].failed == "N3" and res.pillars["identity"].failed == "I5"
    kw = inputs("finding-l3"); kw["ledger_entries"] = kw["ledger_entries"][:3]   # too thin for L2 (and the root no longer matches)
    res = v.verify(load("finding-l3.dsse.json"), **kw)
    assert res.verified == 1 and res.pillars["identity"].failed == "I4"


def test_measurement_must_be_allowlisted_and_enclave_key_comes_from_quote():
    """VSLA-V-1 / V-6 / F-16."""
    kw = inputs("finding-l3"); kw["expectations"] = {**load("expectations.json"), "measurements": []}
    res = v.verify(load("finding-l3.dsse.json"), **kw)
    assert res.verified == 2 and res.pillars["environment"].failed == "N3"
    assert not any(k.startswith("enclave:") for k in load("keyring.json"))         # the enclave key is never pinned; it comes from the verified quote
    fk, ring, env, stmt = pinned_finder("finding-l3")
    stmt["predicate"]["environment"]["enclaveKey"] = "ed25519:" + "ab" * 32   # a different key than the quote signed
    res = v.verify(resign(env, stmt, fk), **inputs("finding-l3", ring))
    i5 = check(res, "I5")
    assert res.pillars["environment"].failed == "N3" and not i5.ok and "no enclave key" in i5.detail


def test_two_operator_needs_two_distinct_cosigners():
    """A two-operator quote whose two co-signers are one root is one operator, not two (round 2, probe P5)."""
    root = Ed25519PrivateKey.generate(); root2 = Ed25519PrivateKey.generate(); enclave = Ed25519PrivateKey.generate()
    fk, ring, env, stmt = pinned_finder("finding-l3")
    ring_json = {k: ("ed25519:" + v.public_hex(ring._keys[k][0])) for k in ring._keys}
    ring_json["root:solo"] = "ed25519:" + v.public_hex(root.public_key()); ring_json["root:second"] = "ed25519:" + v.public_hex(root2.public_key())
    pred = stmt["predicate"]; e3 = pred["environment"]
    e3["type"] = "two-operator"; e3["rootOfTrust"] = "solo"; e3["enclaveKey"] = "ed25519:" + v.public_hex(enclave.public_key())
    harness_d = pred["finder"]["harness"]["digest"]["sha256"]
    binding = {"enclaveKey": v.public_hex(enclave.public_key()), "harness": harness_d,
               "weights": [m["weights"]["digest"]["sha256"] for m in pred["mbom"]["models"]], "sandbox": pred["reproduction"]["sandbox"]["digest"]["sha256"]}

    def attempt(cos, keys, allow_cos=None):
        e3["coSigners"] = cos
        e3["quote"] = ";".join(base64.b64encode(k.sign(v.quote_body(e3, binding))).decode() for k in keys)
        env2 = v.add_signature(resign(env, stmt, fk), f"enclave:two-operator:{e3['measurement']['value'][:16]}", enclave)
        exp = load("expectations.json"); exp["measurements"] = [{"type": "two-operator", "value": e3["measurement"]["value"], "harness": harness_d, **({"coSigners": allow_cos} if allow_cos else {})}]
        r = v.Keyring(ring_json)
        kw = inputs("finding-l3", r); kw["expectations"] = exp; kw["receipt"] = None; kw["quote_verifier"] = v.signed_quote_verifier(r)
        return v.verify(env2, **kw)

    assert attempt(["solo", "solo"], [root, root]).pillars["environment"].level == 2
    assert attempt(["solo"], [root]).pillars["environment"].level == 2
    assert attempt(["solo", "second"], [root, root2]).pillars["environment"].level == 3
    assert attempt(["solo", "second"], [root, root2], allow_cos=["solo", "third"]).pillars["environment"].level == 2   # the allowlist names the pair


def test_api_served_model_caps_environment_at_l2():
    """VSLA-F-15."""
    fk, ring, env, stmt = pinned_finder("finding-l3")
    stmt["predicate"]["mbom"]["models"][1] = {"role": "reproducer", "provider": "anthropic", "name": "claude-opus-5-5", "family": "claude", "serving": "api"}
    res = v.verify(resign(env, stmt, fk), **inputs("finding-l3", ring))
    assert res.pillars["environment"].level == 2 and "api-served" in check(res, "N3").detail


# ----------------------------------------------------------------------------- CLI

def test_cli_runs():
    out = subprocess.run([sys.executable, str(ROOT / "tools" / "vsla_verify.py"), str(EX / "finding-l2.dsse.json"), "--keyring", str(EX / "keyring.json"),
                          "--expectations", str(EX / "expectations.json"), "--report", str(EX / "report.json"), "--leaves", str(EX / "leaves.json"),
                          "--ledger", str(EX / "ledger.json"), "--receipt", str(EX / "finding-l2.receipt.dsse.json"), "--require-anchor",
                          "--intake", INTAKE, "--platform-key", "platform:cvd.example.org"], capture_output=True, text=True)
    assert out.returncode == 0 and "verified L2" in out.stderr, out.stderr
    out = subprocess.run([sys.executable, str(ROOT / "tools" / "vsla_verify.py"), str(EX / "patch-l2.dsse.json"), "--keyring", str(EX / "keyring.json"),
                          "--expectations", str(EX / "expectations.json"), "--ledger", str(EX / "ledger.json"), "--receipt", str(EX / "patch-l2.receipt.dsse.json"),
                          "--intake", INTAKE], capture_output=True, text=True)
    assert out.returncode == 0 and "verified L1" in out.stderr, out.stderr     # a finding ledger on a patch statement


# ----------------------------------------------------------------------------- round 3: one evaluation instant, key lifecycle, DSSE, depth

def rekeyed(name="finding-l2"):
    """The example statement re-keyed to a finder, platform and log key the test controls, with a fresh ledger of its own.
    Returns (keys, ring_json, env, stmt, ledger); `receipt(keys, ring, env, received_at, anchor_at=None)` signs a receipt."""
    fk, pk, lk = (Ed25519PrivateKey.generate() for _ in range(3))
    ring_json = load("keyring.json")
    ring_json["finder:agent:researcher-1"] = "ed25519:" + v.public_hex(fk.public_key())
    ring_json["platform:cvd.example.org"] = "ed25519:" + v.public_hex(pk.public_key())
    ring_json["log:log.example.org"] = "ed25519:" + v.public_hex(lk.public_key())
    env = load(f"{name}.dsse.json"); stmt = v.envelope_payload(env)
    stmt["predicate"]["finder"]["publicKey"] = ring_json["finder:agent:researcher-1"]
    stmt["predicate"]["channel"]["intakeKey"] = ring_json["platform:cvd.example.org"]
    ledger, stmt["predicate"]["history"] = fresh_ledger(ring_json, v.public_hex(fk.public_key()), "patch" if "patch" in name else "finding")
    return {"finder": fk, "platform": pk, "log": lk}, ring_json, env, stmt, ledger


def receipt_for(keys, env, received_at, *, anchor_at=None, reexec=None):
    rx = reexec or load("reexecution.json")
    fn = None
    if anchor_at:
        def fn(body):
            leaves = [v.canonical({"n": 1}), v.canonical(v.anchor_body(body))]
            return v.make_inclusion_anchor(body, log="log.example.org", key=keys["log"], leaves=leaves, leaf_index=1, integrated_time=anchor_at)
    return v.make_receipt(env, keyid="platform:cvd.example.org", key=keys["platform"], channel=INTAKE, received_at=received_at, reexecution=rx, anchor_fn=fn)


def test_key_windows_are_evaluated_at_the_anchor_time():
    """VSLA-V-7 / F-20 (round 3): a finder key revoked in September does not verify a statement whose finder-written finishedAt is
    August when the receipt was anchored in October; the same for a platform key revoked before the anchor."""
    keys, ring_json, env, stmt, ledger = rekeyed()
    stmt["predicate"]["timestamps"] = {"startedAt": "2026-08-01T00:00:00Z", "finishedAt": "2026-08-01T01:00:00Z"}
    stmt["predicate"]["reproduction"]["startedAt"] = "2026-08-01T00:10:00Z"; stmt["predicate"]["reproduction"]["finishedAt"] = "2026-08-01T00:20:00Z"
    env = resign(env, stmt, keys["finder"])
    rc = receipt_for(keys, env, "2026-10-30T14:05:00Z", anchor_at="2026-10-30T14:06:00Z")
    base = dict(inputs("finding-l2"), ledger_entries=ledger, receipt=rc, reexecution=None)
    assert v.verify(env, **{**base, "keyring": v.Keyring(ring_json)}).verified == 2
    revoked = dict(ring_json); revoked["finder:agent:researcher-1"] = {"public": ring_json["finder:agent:researcher-1"], "revokedAt": "2026-09-01T00:00:00Z"}
    res = v.verify(env, **{**base, "keyring": v.Keyring(revoked)})
    assert res.verified == 0 and res.pillars["identity"].failed == "I1" and "t_eval=2026-10-30T14:06" in check(res, "I1").detail
    revoked = dict(ring_json); revoked["platform:cvd.example.org"] = {"public": ring_json["platform:cvd.example.org"], "revokedAt": "2026-10-30T14:05:30Z"}
    res = v.verify(env, **{**base, "keyring": v.Keyring(revoked)})
    assert res.pillars["identity"].failed == "I3" and res.pillars["evidence"].failed == "E7"
    # without a receipt the instant is the verifier's clock: a key revoked before now fails even with a backdated finishedAt
    res = v.verify(env, **{**base, "keyring": v.Keyring({**ring_json, "finder:agent:researcher-1": {"public": ring_json["finder:agent:researcher-1"], "revokedAt": "2026-09-01T00:00:00Z"}}), "receipt": None})
    assert res.pillars["identity"].failed == "I1"
    # finishedAt in the future fails E3; finishedAt after receivedAt fails I3
    keys, ring_json, env, stmt, ledger = rekeyed()
    stmt["predicate"]["timestamps"]["finishedAt"] = "2099-01-01T00:00:00Z"
    assert v.verify(resign(env, stmt, keys["finder"]), **{**inputs("finding-l2"), "keyring": v.Keyring(ring_json), "ledger_entries": ledger}).pillars["evidence"].failed == "E3"


def test_rubric_is_evaluated_at_t_eval_not_the_verifier_clock():
    """VSLA-V-7: the same anchored statement verifies identically today and in ninety days."""
    keys, ring_json, env, stmt, ledger = rekeyed()
    env = resign(env, stmt, keys["finder"])
    rc = receipt_for(keys, env, "2026-10-30T14:05:00Z", anchor_at="2026-10-30T14:06:00Z")
    kw = dict(inputs("finding-l2"), keyring=v.Keyring(ring_json), ledger_entries=ledger, receipt=rc, reexecution=None)
    a = v.verify(env, **{**kw, "now_days": T0_DAYS}); b = v.verify(env, **{**kw, "now_days": T0_DAYS + 90})
    assert a.verified == b.verified == 2 and check(a, "I4").detail == check(b, "I4").detail


def test_successor_chain_keeps_history_and_revoke_ends_it():
    """VSLA-F-20: outcomes earned under the old key count for its successor; an operator-signed revoke fails I1 at t_eval; a
    revoke signed by a log or provider key is ignored."""
    old, new, op = (Ed25519PrivateKey.generate() for _ in range(3))
    ring_json = load("keyring.json"); ring_json["finder:agent:researcher-1"] = "ed25519:" + v.public_hex(new.public_key())
    ring_json["operator:quome.com"] = "ed25519:" + v.public_hex(op.public_key())
    ledger, history = fresh_ledger(ring_json, v.public_hex(old.public_key()), "finding")       # history under the OLD key
    env = load("finding-l2.dsse.json"); stmt = v.envelope_payload(env)
    stmt["predicate"]["finder"]["publicKey"] = ring_json["finder:agent:researcher-1"]
    rot = v.make_successor_entry(at="2026-09-01T00:00:00Z", old=old, new=new, old_keyid="finder:agent:researcher-1")
    rotated = ledger + [rot]
    stmt["predicate"]["history"] = {**history, "root": v.ledger_root(rotated)}
    env2 = resign(env, stmt, new)
    kw = dict(inputs("finding-l2"), keyring=v.Keyring(ring_json), reexecution=load("reexecution.json")); kw.pop("receipt")
    res = v.verify(env2, **{**kw, "ledger_entries": ledger})                    # no successor entry: the old key's history is someone else's
    assert not check(res, "I4").ok and "6 outcome entries dropped" in check(res, "I4").detail
    res = v.verify(env2, **{**kw, "ledger_entries": rotated})
    assert check(res, "I4").ok and "chain of 2 key(s)" in check(res, "I4").detail and res.pillars["identity"].level >= 1
    # a successor entry missing the new key's signature proves nothing
    half = v.dsse_sign(v.envelope_payload(rot), v.LEDGER_PAYLOAD_TYPE, [("finder:agent:researcher-1", old)])
    assert v.successor_chain(ledger + [half], "ed25519:" + v.public_hex(new.public_key())) == ["ed25519:" + v.public_hex(new.public_key())]
    # revoke
    rev = v.make_revoke_entry(at="2026-10-01T00:00:00Z", finder_key_hex=v.public_hex(new.public_key()), operator_keyid="operator:quome.com", operator=op, reason="laptop stolen")
    stmt["predicate"]["history"]["root"] = v.ledger_root(rotated + [rev]); env3 = resign(env, stmt, new)
    res = v.verify(env3, **{**kw, "ledger_entries": rotated + [rev]})
    assert res.verified == 0 and res.pillars["identity"].failed == "I1" and "operator:quome.com" in check(res, "I1").detail
    # a revoke dated after t_eval (the verifier's clock here, T0) does not apply yet
    late = v.make_revoke_entry(at="2026-12-01T00:00:00Z", finder_key_hex=v.public_hex(new.public_key()), operator_keyid="operator:quome.com", operator=op)
    stmt["predicate"]["history"]["root"] = v.ledger_root(rotated + [late]); env4 = resign(env, stmt, new)
    assert check(v.verify(env4, **{**kw, "ledger_entries": rotated + [late]}), "I1").ok
    # a revoke under a non-operator pinned key is ignored
    lk = Ed25519PrivateKey.generate(); ring_json["log:x"] = "ed25519:" + v.public_hex(lk.public_key())
    bogus = v.dsse_sign({"kind": "revoke", "at": "2026-10-01T00:00:00Z", "finder": "ed25519:" + v.public_hex(new.public_key()), "revokedBy": "log:x"}, v.LEDGER_PAYLOAD_TYPE, [("log:x", lk)])
    assert v.revocations(rotated + [bogus], v.Keyring(ring_json), ["ed25519:" + v.public_hex(new.public_key())]) == []


def test_junk_signature_does_not_veto_a_valid_one():
    """DSSE: a verifier accepts if any signature under the keyid verifies; a relay cannot break E2 by prepending garbage."""
    env = load("finding-l1.dsse.json")
    env["signatures"] = [{"keyid": "finder:agent:researcher-1", "sig": base64.b64encode(b"A" * 64).decode()}, *env["signatures"]]
    assert v.verify(env, **inputs("finding-l1")).verified == 1


def test_deeply_nested_payload_fails_a_check():
    """VSLA-V-3: 100 000 nested arrays in a ledger entry is a failed I4, not a RecursionError out of verify()."""
    kw = inputs("finding-l2"); ledger = load("ledger.json")
    deep = {"payloadType": v.LEDGER_PAYLOAD_TYPE, "payload": base64.b64encode(("[" * 100000 + "]" * 100000).encode()).decode(), "signatures": [{"keyid": "platform:cvd.example.org", "sig": "AA=="}]}
    res = v.verify(load("finding-l2.dsse.json"), **{**kw, "ledger_entries": ledger + [deep]})
    assert res.pillars["identity"].failed == "I4" and "not a canonical" in check(res, "I4").detail
    big = {**deep, "payload": base64.b64encode(b'"' + b"x" * (v.MAX_PAYLOAD_BYTES + 1) + b'"').decode()}
    assert not check(v.verify(load("finding-l2.dsse.json"), **{**kw, "ledger_entries": ledger + [big]}), "I4").ok
