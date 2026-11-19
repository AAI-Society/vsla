#!/usr/bin/env python3
"""Generate the signed example statements under schema/examples (both tracks, every level) plus the keyring,
expectations and side files (report, transcript leaves, per-track ledgers, receipts with anchors, re-execution) a
verifier needs. Keys are generated fresh each run; every signature is real.

Run: python tools/make_examples.py"""

from __future__ import annotations

import base64
import json
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

sys.path.insert(0, str(Path(__file__).parent))
from vsla_verify import (add_signature, anchor_body, canonical, ledger_root, make_inclusion_anchor, make_ledger_entry, make_receipt,  # noqa: E402
                         make_weights_attestation, merkle_root, public_hex, quote_body, report_digest, sha256_hex, sign_envelope, statement,
                         transcript_leaves, trust_score, verified_ledger, Keyring)

OUT = Path(__file__).resolve().parent.parent / "schema" / "examples"
T0 = datetime(2026, 10, 30, 14, 0, 0, tzinfo=UTC)
INTAKE = "https://cvd.example.org/mcp"
LOG = "log.example.org"


def d(s: str) -> dict[str, str]:
    return {"sha256": sha256_hex(s.encode())}


def iso(t: datetime) -> str:
    return t.isoformat().replace("+00:00", "Z")


def main() -> None:
    OUT.mkdir(parents=True, exist_ok=True)
    finder, platform, enclave, root, maint_a, maint_b, prov, log = (Ed25519PrivateKey.generate() for _ in range(8))
    pk = lambda k: "ed25519:" + public_hex(k.public_key())
    report = {"title": "Path traversal in vulnpkg.files.resolve_path allows reading arbitrary files",
              "description": "resolve_path joins the caller-controlled user_path onto storage_root with no normalization; ../ and absolute paths escape the storage root.",
              "repo": "example/vulnpkg", "package": "vulnpkg", "affected_versions": ["<1.4.3"],
              "proof_of_concept": "read_user_file('/srv/storage/alice', '../../etc/passwd')", "cwe": "CWE-22",
              "cvss_vector": "CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N",
              "reporter_contact": "researcher@example.org", "wants_credit": True}
    commit = "9b2e7c1d4f0a6b3e8c5d2a1f7e9b4c6d8a0f1e2b"
    harness = {"name": "qudisclose", "version": "0.2.0", "digest": d("qudisclose-0.2.0")}
    sandbox_digest = d("sandbox-image-firecracker-2026-10")
    sandbox = {"backend": "quome", "isolation": "vm", "digest": sandbox_digest}
    command = "python -m pytest -q tests/test_qud_cwe22.py"
    output = d("AssertionError: path escaped")
    subject = [{"name": "finding:" + report_digest(report)[:4], "digest": {"sha256": report_digest(report)}},
               {"name": "git+https://github.com/example/vulnpkg", "digest": {"gitCommit": commit, "sha256": sha256_hex(b"tree")}}]
    leaves = [
        {"seq": 0, "kind": "measure", "harness": harness["digest"], "sandbox": sandbox_digest},
        {"seq": 1, "kind": "turn", "role": "hunter", "model": "qwen3.8:27b", "system": d("sys-hunter"), "user": d("user-hunter"), "output": d("out-hunter")},
        {"seq": 2, "kind": "tool", "role": "reproducer", "name": "read", "input": d("vulnpkg/files.py"), "output": d("files.py body")},
        {"seq": 3, "kind": "tool", "role": "reproducer", "name": "write", "input": d("tests/test_qud_cwe22.py"), "output": d("ok")},
        {"seq": 4, "kind": "tool", "role": "reproducer", "name": "run", "input": d(command), "output": d("1 failed"), "exit": 1},
        {"seq": 5, "kind": "turn", "role": "reproducer", "model": "claude-opus-5-5", "system": d("sys-repro"), "user": d("user-repro"), "output": d("out-repro")},
        {"seq": 6, "kind": "verify", "what": "reproduction", "command": command, "exit": 1, "securityFailure": True, "output": output},
    ]
    qwen_digest = d("qwen3.8-27b-q8-weights")
    qwen_att = make_weights_attestation({"model": "qwen3.8:27b", "weights": qwen_digest, "quantization": "q8", "issuedAt": iso(T0 - timedelta(days=40))}, "provider:qwen", prov)
    mbom = {"models": [
        {"role": "hunter", "provider": "qwen", "name": "qwen3.8:27b", "family": "qwen", "serving": "self-hosted", "weights": {"digest": qwen_digest, "quantization": "q8", "attestation": qwen_att}},
        {"role": "reproducer", "provider": "anthropic", "name": "claude-opus-5-5", "family": "claude", "serving": "api"}],
        "tools": [{"name": "pytest", "digest": d("pytest-8")}]}
    repro = {"test": {"path": "tests/test_qud_cwe22.py", "digest": d("test body")}, "command": command,
             "expectedExit": 1, "observedExit": 1, "securityFailure": True, "revision": commit, "executor": "code",
             "sandbox": sandbox, "outputDigest": output, "startedAt": iso(T0 + timedelta(minutes=2)), "finishedAt": iso(T0 + timedelta(minutes=3))}
    base = {
        "vslaVersion": "1.0", "track": "finding", "claimedLevel": 1, "profile": "published",
        "finder": {"identity": "agent:researcher-1", "publicKey": pk(finder), "operator": "quome.com", "harness": harness},
        "authorization": {"basis": "program", "ref": "https://github.com/example/vulnpkg/blob/main/SECURITY.md"},
        "mbom": mbom,
        "transcript": {"algorithm": "rfc6962-sha256", "root": merkle_root(transcript_leaves(leaves)), "leafCount": len(leaves), "firstLeaf": leaves[0], "sealedTo": pk(platform)},
        "reproduction": repro,
        "injection": {"scannerFlags": [], "modelFlagged": False},
        "timestamps": {"startedAt": iso(T0), "finishedAt": iso(T0 + timedelta(minutes=4))},
    }

    # ledgers for L2, one per track: DSSE entries countersigned by the platform and two maintainers, all pinned, each
    # naming this finder's key and its track (a verifier drops entries for another finder or another track). No entry
    # carries an index: the finder's operator owns the order; the rubric window is by countersigned time.
    keyring_obj = {"finder:agent:researcher-1": pk(finder), "platform:cvd.example.org": pk(platform),
                   "maintainer:example/libparse": pk(maint_a), "maintainer:acme/app": pk(maint_b),
                   "provider:qwen": pk(prov), "root:example-root-of-trust": pk(root), f"log:{LOG}": pk(log)}
    signers = [("platform:cvd.example.org", platform), ("maintainer:example/libparse", maint_a), ("platform:cvd.example.org", platform), ("maintainer:acme/app", maint_b)]
    outcomes = ["accepted", "accepted", "duplicate", "accepted", "accepted", "rejected", "accepted", "accepted", "accepted", "duplicate", "accepted", "accepted", "accepted"]
    ring = Keyring(keyring_obj)

    def build_ledger(track: str) -> tuple[list[dict], dict, dict]:
        ledger = []
        for i, o in enumerate(outcomes):
            at = T0 - timedelta(days=138 - i * 11)
            body = {"at": iso(at), "finder": pk(finder), "statement": d(f"{track}-stmt-{i}"), "platform": "cvd.example.org",
                    "track": track, "outcome": o, "claimed": 2 if i != 5 else 3, "verified": 2 if i != 5 else 1}
            if o == "rejected":
                body["reason"] = "test fails for a non-security reason (fixture error)" if track == "finding" else "suite failed after the diff was applied"
            kid, key = signers[i % 4]
            ledger.append(make_ledger_entry(body, [(kid, key)]))
        bodies, dropped = verified_ledger(ledger, ring, finder=pk(finder), track=track)
        assert dropped == 0
        ts = trust_score(bodies, now_days=T0.timestamp() / 86400)
        history = {"ledger": f"https://ledger.example.org/agent:researcher-1/{track}", "root": ledger_root(ledger), "entries": ts["n"], "accepted": ts["accepted"],
                   "rejected": ts["rejected"], "countersigners": ts["countersigners"], "score": ts["score"], "floor": 0.6, "oldestAt": bodies[0]["at"]}
        return ledger, history, ts

    ledger_f, history_f, ts = build_ledger("finding")
    ledger_p, history_p, _ = build_ledger("patch")
    channel = {"intake": INTAKE, "intakeKey": pk(platform), "declaredIn": "SECURITY.md"}
    reexec = {"status": "matched", "revision": commit, "command": command, "testDigest": d("test body"), "sandbox": sandbox, "attempts": 1,
              "observedExit": 1, "securityFailure": True, "touchedSubject": True, "outputDigest": output}
    # the control: the unchanged test passes with a candidate fix applied, so its verdict depends on the subject (VSLA-P-4)
    control = {"kind": "candidate-fix", "diffDigest": d("candidate fix"), "testUnchanged": True, "passed": True}
    reexec_patch = {**reexec, "applied": True, "reproductionPasses": True, "suitePasses": True, "scope": "source-only",
                    "review": {"approved": True, "reviewerFamily": "qwen", "distinctFamily": True, "verdictDigest": d("approved")}}
    reexec = {**reexec, "control": control}

    def finish(pred: dict, name: str, *, subj: list | None = None, receipt_reexec: dict | None = None, enclave_sign: bool = False) -> dict:
        env = sign_envelope(statement(subj or subject, pred), [("finder:agent:researcher-1", finder)])
        if enclave_sign:
            env = add_signature(env, f"enclave:{pred['environment']['type']}:{pred['environment']['measurement']['value'][:16]}", enclave)
        (OUT / f"{name}.dsse.json").write_text(json.dumps(env, indent=2))
        if receipt_reexec is not None:
            # the receipt is anchored in a log (log-inclusion form): the receipt body is leaf 1 of a three-leaf RFC 6962 log whose
            # checkpoint the pinned log key signed, so its time and existence are a third party's word, not the platform's
            def anchor(body: dict) -> dict:
                leaves = [canonical({"kind": "other", "n": 1}), canonical(anchor_body(body)), canonical({"kind": "other", "n": 3})]
                return make_inclusion_anchor(body, log=LOG, key=log, leaves=leaves, leaf_index=1, integrated_time=iso(T0 + timedelta(minutes=6)))
            rc = make_receipt(env, keyid="platform:cvd.example.org", key=platform, channel=INTAKE, received_at=iso(T0 + timedelta(minutes=5)),
                              reexecution=receipt_reexec, anchor_fn=anchor)
            (OUT / f"{name}.receipt.dsse.json").write_text(json.dumps(rc, indent=2))
        return env

    # Finding L1: finder signature only
    finish(json.loads(json.dumps(base)), "finding-l1")

    # Finding L2, embargoed profile: command and test path are digests; declared channel and history; the receipt is separate
    l2 = json.loads(json.dumps(base)); l2["claimedLevel"] = 2; l2["profile"] = "embargoed"
    l2["reproduction"].pop("command"); l2["reproduction"]["commandDigest"] = d(command); l2["reproduction"]["test"].pop("path")
    l2["channel"] = dict(channel); l2["history"] = history_f
    finish(l2, "finding-l2", receipt_reexec={k: v for k, v in reexec.items() if k != "command"} | {"commandDigest": d(command)})

    # Finding L3: every model served from the attested environment and attested by its provider; the quote binds the
    # enclave key, harness, weights and sandbox; the enclave key signs the envelope; the measurement is in expectations
    l3 = json.loads(json.dumps(base)); l3["channel"] = dict(channel); l3["history"] = history_f; l3["claimedLevel"] = 3
    repro_digest = d("example-lab-repro-13b-weights")
    repro_att = make_weights_attestation({"model": "repro-13b", "weights": repro_digest, "issuedAt": iso(T0 - timedelta(days=20))}, "provider:qwen", prov)
    l3["mbom"]["models"] = [
        {**mbom["models"][0], "serving": "tee"},
        {"role": "reproducer", "provider": "qwen", "name": "repro-13b", "family": "qwen", "serving": "tee", "weights": {"digest": repro_digest, "attestation": repro_att}}]
    measurement = {"algorithm": "sha384", "value": sha256_hex(b"guest-image-2026-10") + sha256_hex(b"x")[:32]}
    env3 = {"type": "signed-quote", "measurement": measurement, "measures": ["weights", "harness", "policy", "sandbox", "signingKey"],
            "rootOfTrust": "example-root-of-trust", "enclaveKey": pk(enclave)}
    binding = {"enclaveKey": public_hex(enclave.public_key()), "harness": harness["digest"]["sha256"], "weights": [qwen_digest["sha256"], repro_digest["sha256"]], "sandbox": sandbox_digest["sha256"]}
    env3["quote"] = base64.b64encode(root.sign(quote_body(env3, binding))).decode()
    l3["environment"] = env3
    finish(l3, "finding-l3", receipt_reexec=reexec, enclave_sign=True)

    # Patch track: L1 (finder's own three executions), L2 (receiver re-executes, reviews on a distinct family, scope
    # source-only; the ledger is the finder's PATCH-track ledger), L3
    diff = "--- a/vulnpkg/files.py\n+++ b/vulnpkg/files.py\n@@ -1 +1 @@\n-vulnerable\n+fixed\n"
    psubj = [*subject, {"name": "patch:" + report_digest(report)[:4], "digest": d(diff)}]
    patch = {"diffDigest": d(diff), "filesTouched": ["vulnpkg/files.py"], "scope": "source-only", "applied": True, "reproductionPasses": True, "suitePasses": True, "attempts": 1,
             "review": {"approved": True, "reviewerRole": "reviewer", "reviewerFamily": "claude", "verdictDigest": d("approved")}}
    p1 = json.loads(json.dumps(base)); p1["track"] = "patch"; p1["patch"] = dict(patch)
    finish(p1, "patch-l1", subj=psubj)
    p2 = json.loads(json.dumps(base)); p2["track"] = "patch"; p2["claimedLevel"] = 2; p2["patch"] = dict(patch); p2["channel"] = dict(channel); p2["history"] = history_p
    finish(p2, "patch-l2", subj=psubj, receipt_reexec=reexec_patch)
    p3 = json.loads(json.dumps(l3)); p3["track"] = "patch"; p3["patch"] = dict(patch); p3["history"] = history_p
    finish(p3, "patch-l3", subj=psubj, receipt_reexec=reexec_patch, enclave_sign=True)

    expectations = {"harness": {"qudisclose": {"0.2.0": harness["digest"]["sha256"]}},
                    "measurements": [{"type": "signed-quote", "value": measurement["value"], "harness": harness["digest"]["sha256"]}]}
    (OUT / "keyring.json").write_text(json.dumps(keyring_obj, indent=2))
    (OUT / "expectations.json").write_text(json.dumps(expectations, indent=2))
    (OUT / "report.json").write_text(json.dumps(report, indent=2))
    (OUT / "leaves.json").write_text(json.dumps(leaves, indent=2))
    (OUT / "ledger.json").write_text(json.dumps(ledger_f, indent=2))
    (OUT / "ledger-patch.json").write_text(json.dumps(ledger_p, indent=2))
    (OUT / "reexecution.json").write_text(json.dumps(reexec, indent=2))
    (OUT / "reexecution-patch.json").write_text(json.dumps(reexec_patch, indent=2))
    (OUT / "README.md").write_text(
        "# Examples\n\nGenerated by `tools/make_examples.py` with fresh keys; every signature is real.\n\n"
        "| File | What |\n|---|---|\n"
        "| `finding-l1.dsse.json` | Finding track, claimed L1, finder signature only |\n"
        "| `finding-l2.dsse.json` + `.receipt.dsse.json` | claimed L2 in the **embargoed profile** (command and test path are digests); declared channel and history; the platform's receipt is a separate DSSE envelope with a `log-inclusion` anchor (signed checkpoint + inclusion proof under a pinned log key) |\n"
        "| `finding-l3.dsse.json` + `.receipt.dsse.json` | claimed L3: every model served from the attested environment with a provider-signed weight attestation; `signed-quote` environment whose quote binds enclave key, harness, weights and sandbox; enclave signature |\n"
        "| `patch-l1.dsse.json` | Patch track, claimed L1: the finder's own three executions |\n"
        "| `patch-l2.dsse.json` + `.receipt.dsse.json` | claimed L2: the receipt carries the platform's re-execution, its own review on a distinct model family, and the computed scope; the ledger is the finder's Patch-track ledger |\n"
        "| `patch-l3.dsse.json` + `.receipt.dsse.json` | claimed L3 |\n"
        "| `keyring.json` | pinned keys by `role:name` (finder, platform, maintainer, provider, root, log) |\n"
        "| `expectations.json` | the receiver's reference values: harness digests per version, allowlisted measurements |\n"
        "| `report.json` | the report the subject digest is computed from |\n"
        "| `leaves.json` | the transcript leaves behind the Merkle root (leaf 0 measures, leaf 6 verifies) |\n"
        "| `ledger.json`, `ledger-patch.json` | the finder's ledgers, one per track: DSSE entries countersigned by three pinned keys, each naming the finder's key and the track; no entry carries an index (the finder's operator owns the order) |\n"
        "| `reexecution.json`, `reexecution-patch.json` | a verifier's own re-execution result, per track |\n\n"
        "```bash\npython tools/vsla_verify.py schema/examples/finding-l3.dsse.json --keyring schema/examples/keyring.json \\\n"
        "    --expectations schema/examples/expectations.json --report schema/examples/report.json --leaves schema/examples/leaves.json \\\n"
        "    --ledger schema/examples/ledger.json --receipt schema/examples/finding-l3.receipt.dsse.json \\\n"
        "    --reexec schema/examples/reexecution.json --intake https://cvd.example.org/mcp --require-anchor\n```\n\n"
        "Drop `--ledger` and Identity stops at L1 (a self-reported summary is not evidence). Drop `--expectations` and\n"
        "Environment stops at L1 (nothing to compare the measured harness to). Drop `--reexec` and `--receipt` and Evidence\n"
        "stops at L1 (nobody but the finder ran the test). Pass `ledger.json` to a `patch-*` statement and Identity stops at\n"
        "L1 (a Finding record buys no Patch trust). Sign a receipt with any key but the pinned platform key and I3 fails.\n"
        "Pass `--required-entries` with an entry the ledger omits and I4 says `ledger-fork`; reorder the ledger and the root\n"
        "no longer matches `history.root`, while the score (a window by countersigned time) does not move.\n")
    print("wrote", sorted(p.name for p in OUT.iterdir()))
    print("trust score", json.dumps(ts))


if __name__ == "__main__":
    main()
