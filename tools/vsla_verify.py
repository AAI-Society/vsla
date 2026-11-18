#!/usr/bin/env python3
"""VSLA reference verifier and primitives (spec v1.0, revision 4).

Library: RFC 8785 canonical JSON, RFC 6962 Merkle tree, DSSE signing/verification with Ed25519 (statements,
receipts, ledger entries, weight attestations and receipt anchors each have their own payload type), the trust rubric,
and `verify()` which runs the checks in spec/v1.0/verification.md and returns a claimed/verified level with per-pillar
detail. Every check is marked *external* (compares against something the finder did not write: a pinned key, an
expectation, the receiver's own execution) or *structural* (self-consistency).

Revision 3 (after the second review): a receipt must be signed by the pinned `platform:` key the statement names in
`channel.intakeKey`, and E7 reads a receipt only after I3 verified it; ledger entries count only when they name this
finder's key and this statement's track, and must be presented in `seq` order; `m` counts operators, not keyids;
two-operator needs two distinct co-signers; every signed payload must be byte-canonical (duplicate keys rejected); integers
outside the IEEE-754 exact range are serialised as doubles, as JCS requires; a malformed input fails a check instead
of raising; receipts may carry a `signed-anchor` the verifier checks under a pinned `log:` key, and a third-party
verifier can require it; a policy can require an isolation class for the re-execution it accepts.

Revision 4 (after the third review): the finder's operator owns the ledger index, so countersigned entries carry no
platform-assigned `seq`; a platform checks the prefix root over what it was shown and that every entry it wrote is
*included* in the presented ledger (`required_entries`), so honest concurrency never forks; the rubric window is
ordered by countersigned `at`; one evaluation instant `t_eval` (anchor time, else receipt time, else the verifier's
clock) governs every key window, `revoke` entries and the rubric's decay, and the time chain startedAt <= finishedAt
<= receivedAt <= integratedTime <= now is enforced; the anchor has two forms, `signed-timestamp` (a pinned log key's
timestamp) and `log-inclusion` (a signed checkpoint plus an RFC 6962 inclusion proof), and `require_anchor` accepts
only the latter unless `accept_timestamp_anchor`; `successor` and `revoke` ledger entries are processed; DSSE
verification accepts any verifying signature under the keyid; a deeply nested payload fails a check.

CLI:  python tools/vsla_verify.py statement.dsse.json --keyring keys.json [--expectations exp.json]
      [--report report.json] [--leaves leaves.json] [--intake URL] [--platform-key platform:NAME]
      [--receipt receipt.dsse.json] [--reexec result.json] [--ledger ledger.json] [--last-seen ROOT:COUNT]
      [--required-entries own.json] [--floor 0.6] [--require-anchor] [--accept-timestamp-anchor]
      [--require-isolation vm|container] [--require-leaves]

Depends on `cryptography` (Ed25519) and `jsonschema` (the predicate schema is enforced, not optional)."""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import math
import re
import sys
import time
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Callable

import jsonschema
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

STATEMENT_TYPE = "https://in-toto.io/Statement/v1"
PREDICATE_TYPE = "https://vsla.dev/provenance/v1"
PAYLOAD_TYPE = "application/vnd.in-toto+json"
RECEIPT_PAYLOAD_TYPE = "application/vnd.vsla.receipt+json"
LEDGER_PAYLOAD_TYPE = "application/vnd.vsla.ledger-entry+json"
WEIGHTS_PAYLOAD_TYPE = "application/vnd.vsla.weights-attestation+json"
TIMESTAMP_PAYLOAD_TYPE = "application/vnd.vsla.receipt-timestamp+json"
CHECKPOINT_PAYLOAD_TYPE = "application/vnd.vsla.log-checkpoint+json"
ANCHOR_PAYLOAD_TYPE = TIMESTAMP_PAYLOAD_TYPE   # the signed-timestamp form
SCHEMA_PATH = Path(__file__).resolve().parent.parent / "schema" / "vsla-provenance-v1.schema.json"

REPORT_FIELDS = ("title", "description", "repo", "package", "affected_versions", "proof_of_concept", "cwe", "cvss_vector", "suggested_fix")
REQUIRED_MEASURES = {"weights", "harness", "policy", "sandbox", "signingKey"}
ISOLATION_RANK = {"process": 0, "container": 1, "vm": 2}
CLOCK_SKEW_S = 600.0       # a receipt or anchor may be at most this far ahead of the verifier's clock
MAX_SAFE_INT = 2**53       # RFC 8785: numbers are IEEE-754 doubles; integers beyond this are serialised as doubles
MAX_PAYLOAD_BYTES = 4 * 1024 * 1024   # a signed payload larger than this fails the check that reads it
# Paths a Patch-track L2 statement may not touch (VSLA-F-18): where real supply-chain compromises have landed.
NON_SOURCE_PATTERNS = (r"(^|/)\.github/", r"(^|/)\.gitlab-ci", r"(^|/)Makefile$", r"(^|/)CMakeLists\.txt$", r"(^|/)configure(\.ac)?$",
                       r"(^|/)setup\.(py|cfg)$", r"(^|/)pyproject\.toml$", r"(^|/)package(-lock)?\.json$", r"(^|/)Cargo\.(toml|lock)$",
                       r"(^|/)go\.(mod|sum)$", r"(^|/)requirements[^/]*\.txt$", r"(^|/)Dockerfile", r"(^|/)tests?/fixtures?/",
                       r"(^|/)testdata/", r"\.(bin|so|dll|dylib|exe|jar|wasm|gz|xz|zip|tar|7z|png|jpg|pdf|pth)$", r"(^|/)scripts?/release",
                       r"(^|/)\.pre-commit", r"(^|/)tox\.ini$", r"(^|/)noxfile\.py$", r"(^|/)conftest\.py$", r"(^|/)MANIFEST\.in$",
                       r"(^|/)\.gitmodules$", r"(^|/)\.gitattributes$", r"(^|/)sitecustomize\.py$", r"(^|/)usercustomize\.py$")


# ----------------------------------------------------------------------------- RFC 8785 canonical JSON

def _es6_number(x: float) -> str:
    """Number serialisation per ECMAScript Number::toString, as RFC 8785 requires."""
    if x != x or x in (math.inf, -math.inf):
        raise ValueError("NaN and Infinity are not JSON")
    if x == 0:
        return "0"
    sign, x = ("-" if x < 0 else ""), abs(x)
    r = repr(x)
    mant, exp = (r.split("e") + ["0"])[:2] if "e" in r else (r, "0")
    ip, fp = (mant.split(".") + [""])[:2]
    if ip.strip("0") == "":
        n = -(len(fp) - len(fp.lstrip("0"))) + int(exp)
    else:
        n = len(ip.lstrip("0")) + int(exp)
    digits = (ip + fp).lstrip("0").rstrip("0") or "0"
    k = len(digits)
    if k <= n <= 21:
        return sign + digits + "0" * (n - k)
    if 0 < n <= 21:
        return sign + digits[:n] + "." + digits[n:]
    if -6 < n <= 0:
        return sign + "0." + "0" * (-n) + digits
    e = n - 1
    es = ("+" if e >= 0 else "-") + str(abs(e))
    return sign + (digits if k == 1 else digits[0] + "." + digits[1:]) + "e" + es


def _jcs(obj: Any, out: list[str]) -> None:
    if obj is None:
        out.append("null")
    elif obj is True:
        out.append("true")
    elif obj is False:
        out.append("false")
    elif isinstance(obj, int):
        # JCS numbers are IEEE-754 doubles: an integer outside the exact range is serialised as the double it parses to.
        out.append(str(obj) if abs(obj) <= MAX_SAFE_INT else _es6_number(float(obj)))
    elif isinstance(obj, float):
        out.append(_es6_number(obj))
    elif isinstance(obj, str):
        out.append(json.dumps(obj, ensure_ascii=False))
    elif isinstance(obj, (list, tuple)):
        out.append("[")
        for i, v in enumerate(obj):
            if i:
                out.append(",")
            _jcs(v, out)
        out.append("]")
    elif isinstance(obj, dict):
        out.append("{")
        for i, k in enumerate(sorted(obj, key=lambda s: s.encode("utf-16-be", "surrogatepass"))):
            if not isinstance(k, str):
                raise TypeError("object keys must be strings")
            if i:
                out.append(",")
            out.append(json.dumps(k, ensure_ascii=False))
            out.append(":")
            _jcs(obj[k], out)
        out.append("}")
    else:
        raise TypeError(f"not JSON-serialisable: {type(obj).__name__}")


def canonical(obj: Any) -> bytes:
    """RFC 8785 (JCS): sorted keys by UTF-16 code units, no whitespace, ES6 number formatting, UTF-8.
    Raises ValueError/TypeError on NaN, lone surrogates and non-JSON values; `verify()` treats that as a failed check."""
    out: list[str] = []
    _jcs(obj, out)
    try:
        return "".join(out).encode("utf-8")
    except UnicodeEncodeError as exc:
        raise ValueError("lone surrogate is not valid UTF-8") from exc


def _no_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    d: dict[str, Any] = {}
    for k, v in pairs:
        if k in d:
            raise ValueError(f"duplicate key {k!r}")
        d[k] = v
    return d


def parse_canonical(data: bytes) -> Any:
    """Parse bytes that MUST be RFC 8785 canonical JSON: duplicate keys are rejected and the bytes must re-serialise to
    themselves, so two conforming parsers cannot read different values from one signed payload. Raises ValueError."""
    if len(data) > MAX_PAYLOAD_BYTES:
        raise ValueError("payload too large")
    try:
        obj = json.loads(data.decode("utf-8"), object_pairs_hook=_no_duplicate_keys)
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError) as exc:
        raise ValueError(f"not JSON: {exc}") from exc
    if canonical(obj) != data:
        raise ValueError("payload is not RFC 8785 canonical")
    return obj


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def report_digest(report: dict[str, Any]) -> str:
    """Subject[0] digest: the fields that describe the bug, never contact or credit (spec: Provenance / Subject).
    It identifies *this report*; it is not a dedup key, because two finders describe one bug differently."""
    return sha256_hex(canonical({k: report.get(k) for k in REPORT_FIELDS if report.get(k) not in (None, [], "")}))


def _ts(v: Any) -> float | None:
    """ISO-8601 (or epoch seconds) to epoch seconds, or None."""
    if isinstance(v, bool):
        return None
    if isinstance(v, (int, float)):
        return float(v)
    try:
        return datetime.fromisoformat(str(v).replace("Z", "+00:00")).timestamp()
    except (TypeError, ValueError):
        return None


def _try(fn: Callable[[], Any], default: Any = None) -> Any:
    """Run a canonicalisation/parsing step; a malformed input is a failed check, never an exception out of `verify()` (VSLA-V-3)."""
    try:
        return fn()
    except (ValueError, TypeError, KeyError, IndexError, AttributeError, RecursionError):
        return default


# ----------------------------------------------------------------------------- RFC 6962 Merkle tree

def leaf_hash(leaf: bytes) -> bytes:
    return hashlib.sha256(b"\x00" + leaf).digest()


def node_hash(left: bytes, right: bytes) -> bytes:
    return hashlib.sha256(b"\x01" + left + right).digest()


def merkle_root(leaves: list[bytes]) -> str:
    """Root over leaves in order. An odd node is promoted unchanged (RFC 6962 §2.1 shape)."""
    if not leaves:
        return sha256_hex(b"")
    level = [leaf_hash(x) for x in leaves]
    while len(level) > 1:
        level = [node_hash(level[i], level[i + 1]) if i + 1 < len(level) else level[i] for i in range(0, len(level), 2)]
    return level[0].hex()


def inclusion_proof(leaves: list[bytes], index: int) -> list[tuple[str, str]]:
    """Audit path for leaf `index`: [(side, hex)], side in {"L","R"} = sibling position."""
    level = [leaf_hash(x) for x in leaves]
    path: list[tuple[str, str]] = []
    i = index
    while len(level) > 1:
        sib = i ^ 1
        if sib < len(level):
            path.append(("L" if sib < i else "R", level[sib].hex()))
        level = [node_hash(level[j], level[j + 1]) if j + 1 < len(level) else level[j] for j in range(0, len(level), 2)]
        i //= 2
    return path


def verify_inclusion(leaf: bytes, proof: list[tuple[str, str]], root: str) -> bool:
    h = leaf_hash(leaf)
    for side, sib in proof:
        s = bytes.fromhex(sib)
        h = node_hash(s, h) if side == "L" else node_hash(h, s)
    return h.hex() == root


def transcript_leaves(leaves: list[dict[str, Any]]) -> list[bytes]:
    return [canonical(x) for x in leaves]


# ----------------------------------------------------------------------------- DSSE

def pae(payload_type: str, payload: bytes) -> bytes:
    pt = payload_type.encode()
    return b"DSSEv1 %d %s %d %s" % (len(pt), pt, len(payload), payload)


def statement(subject: list[dict[str, Any]], predicate: dict[str, Any]) -> dict[str, Any]:
    return {"_type": STATEMENT_TYPE, "subject": subject, "predicateType": PREDICATE_TYPE, "predicate": predicate}


def dsse_sign(body: dict[str, Any], payload_type: str, signers: list[tuple[str, Ed25519PrivateKey]]) -> dict[str, Any]:
    """A DSSE envelope over the canonical body. Every signed VSLA object uses this with its own payload type."""
    payload = canonical(body)
    return {"payloadType": payload_type, "payload": base64.b64encode(payload).decode(),
            "signatures": [{"keyid": kid, "sig": base64.b64encode(k.sign(pae(payload_type, payload))).decode()} for kid, k in signers]}


def sign_envelope(stmt: dict[str, Any], signers: list[tuple[str, Ed25519PrivateKey]]) -> dict[str, Any]:
    return dsse_sign(stmt, PAYLOAD_TYPE, signers)


def add_signature(envelope: dict[str, Any], keyid: str, key: Ed25519PrivateKey) -> dict[str, Any]:
    payload = base64.b64decode(envelope["payload"])
    return {**envelope, "signatures": [*envelope["signatures"], {"keyid": keyid, "sig": base64.b64encode(key.sign(pae(envelope["payloadType"], payload))).decode()}]}


def envelope_payload(envelope: dict[str, Any]) -> dict[str, Any]:
    """The parsed payload. Lenient (any JSON); `canonical_payload` is the strict form `verify()` uses."""
    return json.loads(base64.b64decode(envelope["payload"]))


def canonical_payload(envelope: dict[str, Any]) -> dict[str, Any]:
    """The payload, which MUST be RFC 8785 canonical with no duplicate keys. Raises ValueError otherwise."""
    try:
        raw = base64.b64decode(envelope["payload"], validate=True)
    except (KeyError, TypeError, ValueError) as exc:
        raise ValueError("envelope has no decodable payload") from exc
    obj = parse_canonical(raw)
    if not isinstance(obj, dict):
        raise ValueError("payload is not an object")
    return obj


def statement_digest(envelope: dict[str, Any]) -> str:
    return sha256_hex(base64.b64decode(envelope["payload"]))


def verify_signature(envelope: dict[str, Any], keyid: str, pub: Ed25519PublicKey, payload_type: str | None = None) -> bool:
    """True iff a signature with `keyid` verifies over PAE(payloadType, payload) and the payload type is as expected."""
    try:
        if payload_type is not None and envelope.get("payloadType") != payload_type:
            return False
        payload = base64.b64decode(envelope["payload"])
    except (ValueError, KeyError, TypeError):
        return False
    for s in envelope.get("signatures", []):
        if not isinstance(s, dict) or s.get("keyid") != keyid:
            continue
        try:
            pub.verify(base64.b64decode(s["sig"]), pae(envelope["payloadType"], payload))
            return True          # DSSE: any verifying signature under the keyid is enough; a junk one beside it does not veto
        except (InvalidSignature, ValueError, KeyError, TypeError):
            continue
    return False


def signer_keyids(envelope: dict[str, Any]) -> list[str]:
    return [s.get("keyid", "") for s in envelope.get("signatures", [])]


# receipts --------------------------------------------------------------------

def anchor_body(receipt_body: dict[str, Any]) -> dict[str, Any]:
    """What a log witnesses: the receipt body without its own anchor."""
    return {k: v for k, v in receipt_body.items() if k != "anchor"}


def make_anchor(receipt_body: dict[str, Any], *, log: str, key: Ed25519PrivateKey, entry_id: str, integrated_time: str) -> dict[str, Any]:
    """The `signed-timestamp` form (VSLA-P-16): a pinned `log:<name>` key signs, with the timestamp payload type, the
    canonical body {log, entryId, integratedTime, receipt: {sha256 over the anchor-less receipt body}}. It proves that
    this receipt body existed by `integratedTime` on the word of the pinned key, and nothing about append-only-ness;
    it is an RFC 3161-style timestamp, not log inclusion."""
    body = {"log": log, "entryId": entry_id, "integratedTime": integrated_time, "receipt": {"sha256": sha256_hex(canonical(anchor_body(receipt_body)))}}
    sig = key.sign(pae(TIMESTAMP_PAYLOAD_TYPE, canonical(body)))
    return {"form": "signed-timestamp", **body, "signature": base64.b64encode(sig).decode()}


make_timestamp_anchor = make_anchor


def checkpoint_body(log: str, tree_size: int, root_hash: str, integrated_time: str) -> dict[str, Any]:
    return {"log": log, "treeSize": tree_size, "rootHash": root_hash, "integratedTime": integrated_time}


def make_inclusion_anchor(receipt_body: dict[str, Any], *, log: str, key: Ed25519PrivateKey, leaves: list[bytes], leaf_index: int,
                          integrated_time: str) -> dict[str, Any]:
    """The `log-inclusion` form (VSLA-P-16): the canonical anchor-less receipt body is a leaf of an RFC 6962 log; the
    anchor carries the log's signed checkpoint (tree size, root hash, time) and the inclusion proof for the leaf. A
    verifier recomputes the leaf, verifies the proof against the root and the checkpoint signature under the pinned
    `log:<name>` key. This is what Rekor and SCITT inclusion proofs give, in the smallest interoperable shape."""
    leaf = canonical(anchor_body(receipt_body))
    if leaves[leaf_index] != leaf:
        raise ValueError("leaf_index does not point at this receipt")
    root = merkle_root(leaves)
    cp = checkpoint_body(log, len(leaves), root, integrated_time)
    sig = key.sign(pae(CHECKPOINT_PAYLOAD_TYPE, canonical(cp)))
    return {"form": "log-inclusion", "log": log, "treeSize": len(leaves), "rootHash": root, "leafIndex": leaf_index,
            "inclusionProof": [[side, h] for side, h in inclusion_proof(leaves, leaf_index)], "integratedTime": integrated_time,
            "checkpointSignature": base64.b64encode(sig).decode()}


def verify_anchor(receipt_body: dict[str, Any], keyring: Keyring, *, now_s: float | None = None) -> tuple[bool, str, str]:
    """(ok, form, why). ok iff the anchor verifies under the pinned `log:<name>` key, commits to this receipt body, and
    its integratedTime is not before receivedAt nor ahead of the verifier's clock. `form` is `log-inclusion`,
    `signed-timestamp` or `none`; the caller decides which forms its policy accepts."""
    anc = receipt_body.get("anchor")
    if not isinstance(anc, dict):
        return False, "none", "no anchor"
    form = str(anc.get("form") or ("log-inclusion" if "inclusionProof" in anc else "signed-timestamp"))
    try:
        pub = keyring.get(f"log:{anc.get('log')}", at=anc.get("integratedTime"))
        if pub is None:
            return False, form, f"log {anc.get('log')!r} not pinned"
        leaf = canonical(anchor_body(receipt_body))
        if form == "log-inclusion":
            proof = [(str(side), str(h)) for side, h in anc["inclusionProof"]]
            if not verify_inclusion(leaf, proof, str(anc["rootHash"])):
                return False, form, "inclusion proof does not reach the checkpoint root for this receipt"
            cp = checkpoint_body(str(anc["log"]), int(anc["treeSize"]), str(anc["rootHash"]), str(anc["integratedTime"]))
            pub.verify(base64.b64decode(anc["checkpointSignature"]), pae(CHECKPOINT_PAYLOAD_TYPE, canonical(cp)))
        elif form == "signed-timestamp":
            body = {k: anc[k] for k in ("log", "entryId", "integratedTime", "receipt")}
            if body["receipt"] != {"sha256": sha256_hex(leaf)}:
                return False, form, "timestamp commits to a different receipt"
            pub.verify(base64.b64decode(anc["signature"]), pae(TIMESTAMP_PAYLOAD_TYPE, canonical(body)))
        else:
            return False, form, f"unknown anchor form {form!r}"
    except (InvalidSignature, ValueError, KeyError, TypeError):
        return False, form, "anchor signature or proof invalid"
    t_int, t_rcv = _ts(anc.get("integratedTime")), _ts(receipt_body.get("receivedAt"))
    now = time.time() if now_s is None else now_s
    if t_int is None or t_rcv is None or t_int < t_rcv or t_int > now + CLOCK_SKEW_S:
        return False, form, "anchor time is before receipt or in the future"
    return True, form, f"{form} in {anc.get('log')}"


def make_receipt(envelope: dict[str, Any], *, keyid: str, key: Ed25519PrivateKey, channel: str, received_at: str,
                 reexecution: dict[str, Any] | None, anchor: dict[str, Any] | None = None,
                 anchor_log: tuple[str, Ed25519PrivateKey, str, str] | None = None,
                 anchor_fn: Callable[[dict[str, Any]], dict[str, Any]] | None = None) -> dict[str, Any]:
    """The platform's countersignature (VSLA-P-3/P-4): a DSSE envelope with its own payload type, separate from
    the statement so the finder's payload is untouched. `reexecution` is the platform's own result (see spec:
    Provenance / Receipt) and is never null when the platform attempted anything; `status: "not-attempted"` says why.
    `anchor_log = (log name, log key, entry id, integrated time)` produces a signed-timestamp over the body; `anchor_fn`
    (body -> anchor) produces any other form, e.g. `make_inclusion_anchor` with a log's leaves."""
    body = {"vslaVersion": "1.0", "statementDigest": statement_digest(envelope), "channel": channel, "receivedAt": received_at,
            "reexecution": reexecution or {"status": "not-attempted"}}
    if anchor_fn is not None:
        anchor = anchor_fn(body)
    elif anchor_log is not None:
        log, lkey, entry_id, at = anchor_log
        anchor = make_anchor(body, log=log, key=lkey, entry_id=entry_id, integrated_time=at)
    if anchor:
        body["anchor"] = anchor
    return dsse_sign(body, RECEIPT_PAYLOAD_TYPE, [(keyid, key)])


def verify_receipt(receipt: dict[str, Any], keyid: str, pub: Ed25519PublicKey) -> bool:
    return verify_signature(receipt, keyid, pub, RECEIPT_PAYLOAD_TYPE)


# ledger ----------------------------------------------------------------------

OUTCOMES = ("accepted", "duplicate", "rejected", "false-positive", "reproduced-unresolved", "withdrawn",
            "non-authoritative-release", "retracted", "ledger-fork")
ENTRY_KINDS = ("outcome", "successor", "revoke")


def make_ledger_entry(body: dict[str, Any], signers: list[tuple[str, Ed25519PrivateKey]]) -> dict[str, Any]:
    """A countersigned ledger entry: DSSE over the canonical body. `signatures[0].keyid` is the countersigner.
    Body: {at, finder, statement:{sha256}, platform, track, outcome, claimed?, verified?, kind?, vouched?, reason?}.
    No `seq`: the index into the ledger belongs to the finder's operator, who appends; a countersigner never assigns it."""
    return dsse_sign({"kind": "outcome", **body}, LEDGER_PAYLOAD_TYPE, signers)


def make_successor_entry(*, at: str, old: Ed25519PrivateKey, new: Ed25519PrivateKey, old_keyid: str) -> dict[str, Any]:
    """Key rotation (VSLA-F-20): {kind: successor, at, finder: old key, successor: new key}, signed by both keys. A
    verifier follows the chain backwards from the pinned current key, so outcome entries earned under the old key
    still count for the new one."""
    body = {"kind": "successor", "at": at, "finder": "ed25519:" + public_hex(old.public_key()), "successor": "ed25519:" + public_hex(new.public_key())}
    return dsse_sign(body, LEDGER_PAYLOAD_TYPE, [(old_keyid, old), ("successor", new)])


def make_revoke_entry(*, at: str, finder_key_hex: str, operator_keyid: str, operator: Ed25519PrivateKey, reason: str = "") -> dict[str, Any]:
    """Key revocation (VSLA-F-20): {kind: revoke, at, finder, revokedBy}, signed by the pinned operator key it names."""
    body = {"kind": "revoke", "at": at, "finder": "ed25519:" + finder_key_hex, "revokedBy": operator_keyid}
    if reason:
        body["reason"] = reason[:500]
    return dsse_sign(body, LEDGER_PAYLOAD_TYPE, [(operator_keyid, operator)])


def ledger_root(entries: list[dict[str, Any]]) -> str:
    """The ledger is an RFC 6962 log whose leaves are the canonical bytes of each entry's DSSE envelope."""
    return merkle_root([canonical(e) for e in entries])


def ledger_well_formed(entries: list[dict[str, Any]]) -> tuple[bool, str]:
    """Every presented entry parses as a canonical DSSE payload. Order is the finder's own (it owns the index); the rubric
    window is ordered by countersigned `at`, which the finder cannot choose, so presented order cannot move the score."""
    if not isinstance(entries, list):
        return False, "ledger is not a list"
    for i, env in enumerate(entries):
        if _try(lambda: canonical_payload(env)) is None:
            return False, f"entry {i} is not a canonical DSSE payload"
    return True, "ok"


def _raw_pub(hexkey: Any) -> Ed25519PublicKey | None:
    try:
        return Ed25519PublicKey.from_public_bytes(bytes.fromhex(str(hexkey).removeprefix("ed25519:")))
    except (ValueError, TypeError):
        return None


def _sig_verifies(env: dict[str, Any], pub: Ed25519PublicKey, keyid: str | None = None) -> bool:
    """A signature in `env` (under `keyid`, or any keyid when None) that verifies under `pub`."""
    try:
        payload = base64.b64decode(env["payload"])
    except (KeyError, TypeError, ValueError):
        return False
    for s in env.get("signatures", []):
        if not isinstance(s, dict) or (keyid is not None and s.get("keyid") != keyid):
            continue
        try:
            pub.verify(base64.b64decode(s["sig"]), pae(env["payloadType"], payload))
            return True
        except (InvalidSignature, ValueError, KeyError, TypeError):
            continue
    return False


def successor_chain(entries: list[dict[str, Any]], finder: str) -> list[str]:
    """Keys this finder's history may be recorded under: `finder` and, following valid `successor` entries backwards,
    every predecessor. A successor entry is valid when it is a canonical ledger-entry payload signed by BOTH the old key
    (`finder`) and the new key (`successor`), each verified under the raw key the body names; the chain is acyclic."""
    succ: dict[str, str] = {}
    for env in entries:
        body = _try(lambda: canonical_payload(env))
        if not body or body.get("kind") != "successor" or env.get("payloadType") != LEDGER_PAYLOAD_TYPE:
            continue
        old, new = _raw_pub(body.get("finder")), _raw_pub(body.get("successor"))
        if old is None or new is None or not _sig_verifies(env, old) or not _sig_verifies(env, new):
            continue
        succ[str(body["successor"])] = str(body["finder"])
    chain = [finder]
    while chain[-1] in succ and succ[chain[-1]] not in chain and len(chain) < 64:
        chain.append(succ[chain[-1]])
    return chain


def revocations(entries: list[dict[str, Any]], keyring: Keyring, keys: list[str]) -> list[tuple[str, float, str]]:
    """(key, at seconds, revokedBy) for every valid `revoke` entry naming one of `keys`: a canonical ledger-entry payload
    signed under the pinned `operator:` keyid it names in `revokedBy`."""
    out = []
    for env in entries:
        body = _try(lambda: canonical_payload(env))
        if not body or body.get("kind") != "revoke" or env.get("payloadType") != LEDGER_PAYLOAD_TYPE or body.get("finder") not in keys:
            continue
        kid = str(body.get("revokedBy", ""))
        pub = keyring.get(kid) if kid.startswith("operator:") else None
        at = _ts(body.get("at"))
        if pub is None or at is None or not verify_signature(env, kid, pub, LEDGER_PAYLOAD_TYPE):
            continue
        out.append((str(body["finder"]), at, kid))
    return out


def verified_ledger(entries: list[dict[str, Any]], keyring: Keyring, *, finder: str | list[str] | None = None, track: str | None = None) -> tuple[list[dict[str, Any]], int]:
    """Bodies of the outcome entries whose countersignature verifies under a pinned `platform:`/`maintainer:` key, each
    with `countersigner` set; and how many were dropped. Unpinned countersigners contribute to neither n nor m
    (VSLA-V-5). With `finder` (an `ed25519:<hex>` key, or the list `successor_chain` returns) and `track`, outcome
    entries that name another finder or another track are dropped too: a ledger is evidence about *this* key (and its
    predecessors) on *this* track, never a credential another key can present or a Finding record that buys Patch
    trust. `successor` and `revoke` entries are not outcomes; they are read by `successor_chain` and `revocations`."""
    keys = None if finder is None else ([finder] if isinstance(finder, str) else list(finder))
    kept, dropped = [], 0
    for env in entries:
        body = _try(lambda: canonical_payload(env))
        kids = signer_keyids(env) if isinstance(env, dict) else []
        if body is None or not kids:
            dropped += 1
            continue
        if body.get("kind", "outcome") != "outcome":
            continue                                   # lifecycle entries neither count nor are "dropped"
        kid = kids[0]
        pub = keyring.get(kid, at=body.get("at"))
        role_ok = kid.split(":", 1)[0] in ("platform", "maintainer")
        finder_ok = keys is None or body.get("finder") in keys
        track_ok = track is None or body.get("track") == track
        if pub is None or not role_ok or not finder_ok or not track_ok or not verify_signature(env, kid, pub, LEDGER_PAYLOAD_TYPE):
            dropped += 1
            continue
        kept.append({**body, "countersigner": kid})
    return kept, dropped


def missing_entries(entries: list[dict[str, Any]], required: list[dict[str, Any]]) -> int:
    """How many of `required` (entries this verifier countersigned for the finder) are absent from the presented ledger,
    compared by canonical bytes. A platform's own entry must be *included*; its position is the finder's business."""
    present = {_try(lambda: canonical(e)) for e in entries}
    return sum(1 for r in required if _try(lambda: canonical(r)) not in present)


def ledger_consistent(entries: list[dict[str, Any]], last_seen_root: str, last_seen_count: int) -> bool:
    """A platform that stored (root, count) over the ledger it was *shown* last time checks that the new ledger
    extends it: the root over the first `count` entries must equal the stored root (VSLA-P-14). The platform's own
    entries are checked by inclusion (`missing_entries`), never by position."""
    if last_seen_count > len(entries):
        return False
    return _try(lambda: ledger_root(entries[:last_seen_count]) == last_seen_root, False)


# weight attestations ---------------------------------------------------------

def make_weights_attestation(body: dict[str, Any], keyid: str, key: Ed25519PrivateKey) -> dict[str, Any]:
    """A provider-signed attestation over base weights: DSSE with its own payload type, signed by `provider:<name>`.
    Body: {model, weights: {sha256}, quantization?, issuedAt}."""
    return dsse_sign(body, WEIGHTS_PAYLOAD_TYPE, [(keyid, key)])


def verify_weights_attestation(att: dict[str, Any], keyring: Keyring, expected_sha256: str | None) -> bool:
    try:
        kid = signer_keyids(att)[0]
        pub = keyring.get(kid)
        body = canonical_payload(att)
    except (KeyError, IndexError, ValueError, TypeError):
        return False
    return (pub is not None and kid.startswith("provider:") and verify_signature(att, kid, pub, WEIGHTS_PAYLOAD_TYPE)
            and body.get("weights", {}).get("sha256") == expected_sha256)


# ----------------------------------------------------------------------------- keys

class Keyring:
    """Pinned keys, obtained out of band (VSLA-V-1). {keyid: "ed25519:<hex>" | {"public": "ed25519:<hex>",
    "validFrom"?: iso, "revokedAt"?: iso}}. A key is usable at time `at` only inside its validity window.
    Roles: finder:, platform:, maintainer:, provider:, root:, operator:, log:. Never enclave: (derived from the quote)."""

    def __init__(self, keys: dict[str, Any] | None = None) -> None:
        self._keys: dict[str, tuple[Ed25519PublicKey, float | None, float | None]] = {}
        for kid, v in (keys or {}).items():
            self.add(kid, v)

    def add(self, keyid: str, public: str | dict[str, Any]) -> None:
        meta = public if isinstance(public, dict) else {"public": public}
        hexkey = str(meta["public"]).removeprefix("ed25519:")
        self._keys[keyid] = (Ed25519PublicKey.from_public_bytes(bytes.fromhex(hexkey)), _ts(meta.get("validFrom")), _ts(meta.get("revokedAt")))

    def get(self, keyid: str, at: Any = None) -> Ed25519PublicKey | None:
        rec = self._keys.get(keyid)
        if rec is None:
            return None
        pub, valid_from, revoked_at = rec
        t = _ts(at) if at is not None else None
        if t is not None and ((valid_from is not None and t < valid_from) or (revoked_at is not None and t >= revoked_at)):
            return None
        return pub

    def revoked(self, keyid: str) -> bool:
        rec = self._keys.get(keyid)
        return rec is not None and rec[2] is not None

    def role(self, role: str) -> list[str]:
        return [k for k in self._keys if k.startswith(role + ":")]

    def find(self, role: str, hexkey: str) -> str | None:
        """The pinned keyid of `role` whose public key is `hexkey`, if any."""
        for k in self.role(role):
            if hexkey and hexkey == public_hex(self._keys[k][0]):
                return k
        return None

    @classmethod
    def load(cls, path: str | Path) -> Keyring:
        return cls(json.loads(Path(path).read_text()))


def public_hex(pub: Ed25519PublicKey) -> str:
    from cryptography.hazmat.primitives import serialization
    return pub.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex()


# ----------------------------------------------------------------------------- trust rubric (v1.1)

DISQUALIFYING = {"non-authoritative-release", "ledger-fork", "retracted"}
NEGATIVE = {"rejected", "false-positive"}
NEUTRAL = {"duplicate", "withdrawn", "reproduced-unresolved"}


def countersigner_operator(keyid: str) -> str:
    """A keyid is `<role>:<operator name>`; two keys of one operator (platform:acme and maintainer:acme) are one countersigner."""
    return keyid.split(":", 1)[1] if ":" in keyid else keyid


def trust_score(entries: list[dict[str, Any]], *, window: int = 50, now_days: float | None = None) -> dict[str, Any]:
    """spec/v1.0/trust-rubric.md (v1.1). `entries` are verified ledger bodies ({outcome, at, countersigner, claimed?,
    verified?, kind?, vouched?}); the caller has already dropped entries whose countersignature did not verify. The
    window is the last W entries by countersigned `at`, so presented order cannot move the score. Neutral outcomes
    (duplicate, withdrawn, reproduced-unresolved) are excluded from the window entirely so they can neither pump nor
    sink the score. `m` counts distinct operators, not keyids. `now_days` is the evaluation instant (a verifier passes
    `t_eval`, so the score is a function of the inputs, not of the verifier's clock). `at` may be a day number (tests)
    or an ISO timestamp."""

    def days(v: Any) -> float:
        if isinstance(v, (int, float)):
            return float(v)
        return datetime.fromisoformat(str(v).replace("Z", "+00:00")).timestamp() / 86400

    ents = [e for e in entries if e.get("countersigner") and e.get("kind", "outcome") == "outcome" and e.get("outcome") not in NEUTRAL]
    ents = sorted(enumerate(ents), key=lambda ie: (days(ie[1]["at"]), ie[0]))      # window by countersigned time, not presented order
    ents = [e for _, e in ents][-window:]
    n = len(ents)
    if n == 0:
        return {"score": 0.0, "n": 0, "accepted": 0, "rejected": 0, "disqualifying": 0, "countersigners": 0, "over_claims": 0,
                "age_days": 0.0, "components": {}, "reason": "no countersigned entries"}
    now = now_days if now_days is not None else datetime.now(UTC).timestamp() / 86400
    a = sum(e["outcome"] == "accepted" and not e.get("vouched") for e in ents)
    x = sum(e["outcome"] in DISQUALIFYING for e in ents)
    m = len({countersigner_operator(e["countersigner"]) for e in ents})
    o = sum(1 for e in ents if e.get("claimed") is not None and e.get("verified") is not None and e["claimed"] > e["verified"])
    age = max(0.0, now - min(days(e["at"]) for e in ents))
    neg_ages = [max(0.0, now - days(e["at"])) for e in ents if e["outcome"] in NEGATIVE]
    P = a / n
    B = min(1.0, m / 3)
    S = min(1.0, age / 90) * min(1.0, n / 10)
    C = max(0.0, 1 - 2 * o / n)
    R = 1 - 0.5 * min(1.0, sum(math.exp(-d / 30) for d in neg_ages))
    disqualified = x > 0 or o / n >= 0.5
    score = 0.0 if disqualified else P * (0.5 + 0.2 * B + 0.2 * S + 0.1 * C) * R
    return {"score": round(score, 4), "n": n, "accepted": a, "rejected": len(neg_ages), "disqualifying": x,
            "countersigners": m, "over_claims": o, "age_days": round(age, 1),
            "components": {"P": round(P, 4), "B": round(B, 4), "S": round(S, 4), "C": round(C, 4), "R": round(R, 4)}}


def meets_floor(ts: dict[str, Any], *, floor: float = 0.6, min_entries: int = 5, min_countersigners: int = 2, min_age_days: float = 30) -> tuple[bool, str]:
    ok = (ts["n"] >= min_entries and ts["countersigners"] >= min_countersigners and ts["age_days"] >= min_age_days and ts["score"] >= floor)
    return ok, f"score {ts['score']} n={ts['n']} m={ts['countersigners']} age={ts['age_days']}d (floor {floor}, n>={min_entries}, m>={min_countersigners}, age>={min_age_days}d)"


# ----------------------------------------------------------------------------- verification

@dataclass
class Check:
    id: str
    level: int
    ok: bool
    detail: str = ""
    kind: str = "external"   # "external" (vs a pinned key, an expectation or the receiver's own execution) or "structural"


@dataclass
class Pillar:
    name: str
    level: int = 0
    failed: str | None = None
    checks: list[Check] = field(default_factory=list)


@dataclass
class Result:
    claimed: int
    verified: int
    pillars: dict[str, Pillar]

    def to_dict(self) -> dict[str, Any]:
        return {"claimed": self.claimed, "verified": self.verified,
                "pillars": {k: {"level": p.level, "failed": p.failed, "checks": [c.__dict__ for c in p.checks]} for k, p in self.pillars.items()}}

    def detail(self, cid: str) -> str:
        for p in self.pillars.values():
            for c in p.checks:
                if c.id == cid:
                    return c.detail
        return ""


# An environment adapter verifies a quote against the pinned root(s) and returns True iff the quote binds exactly
# the `binding` the verifier derived from the statement: {enclaveKey, harness, weights[], sandbox}.
QuoteVerifier = Callable[[dict[str, Any], dict[str, Any]], bool]


def quote_body(env: dict[str, Any], binding: dict[str, Any]) -> bytes:
    """The canonical binding body. Hardware adapters derive REPORT_DATA / REPORTDATA / user_data as SHA-256 of these bytes."""
    return canonical({"type": env.get("type"), "measurement": env.get("measurement"), "measures": sorted(env.get("measures", [])),
                      "enclaveKey": binding.get("enclaveKey"), "harness": binding.get("harness"), "weights": sorted(binding.get("weights", [])),
                      "sandbox": binding.get("sandbox")})


def signed_quote_verifier(roots: Keyring) -> QuoteVerifier:
    """The reference environment adapter (`signed-quote` form): the quote is base64(Ed25519 signature by the pinned
    root-of-trust key over `quote_body`). It stands in for a hardware quote so the rest of the procedure can be
    tested; it proves only that the root's key signed these bindings. Hardware adapters (SEV-SNP, TDX, Nitro)
    replace this callable and must derive the same bindings from REPORT_DATA/HOST_DATA and the launch digest.
    two-operator supplies one signature per co-signer over the same body, `;`-joined; co-signers MUST be at least two
    distinct pinned roots, or "neither operator alone" is one operator twice."""

    def _verify(env: dict[str, Any], binding: dict[str, Any]) -> bool:
        body = quote_body(env, binding)
        if env.get("type") == "two-operator":
            cos = [str(c) for c in env.get("coSigners", [])]
            if len(cos) < 2 or len(set(cos)) != len(cos):
                return False
            keys = [roots.get(f"root:{c}") for c in cos]
            sigs = [s for s in (env.get("quote") or "").split(";") if s]
        else:
            keys = [roots.get(f"root:{env.get('rootOfTrust')}")]
            sigs = [env.get("quote")]
        if not sigs or not keys or any(k is None for k in keys) or len(sigs) != len(keys):
            return False
        try:
            for sig, key in zip(sigs, keys, strict=True):
                key.verify(base64.b64decode(sig), body)
            return True
        except (InvalidSignature, ValueError, TypeError):
            return False

    return _verify


def _run(p: Pillar, cid: str, level: int, cond: bool, detail: str = "", kind: str = "external") -> bool:
    """Record a check. The pillar's level is computed afterwards by `_finalize` (VSLA-V-2)."""
    p.checks.append(Check(cid, level, bool(cond), detail, kind))
    return bool(cond)


def _finalize(p: Pillar) -> Pillar:
    """Level = highest n such that every check at level <= n passed; `failed` = the first failing check in order."""
    p.level = 0
    for n in (1, 2, 3):
        if all(c.ok for c in p.checks if c.level <= n):
            p.level = n
        else:
            break
    p.failed = next((c.id for c in p.checks if not c.ok and c.level <= p.level + 1), None)
    return p


_SCHEMA: dict[str, Any] | None = None


def _schema_ok(predicate: dict[str, Any]) -> tuple[bool, str]:
    global _SCHEMA
    if _SCHEMA is None:
        _SCHEMA = json.loads(SCHEMA_PATH.read_text())
    try:
        jsonschema.validate(predicate, _SCHEMA, format_checker=jsonschema.FormatChecker())
        return True, "schema valid"
    except jsonschema.ValidationError as e:
        return False, f"schema: {e.message[:160]} at {'/'.join(str(p) for p in e.absolute_path)}"


def non_source_paths(paths: list[str]) -> list[str]:
    return [p for p in paths if any(re.search(pat, p) for pat in NON_SOURCE_PATTERNS)]


def _models_with_weights(models: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [m for m in models if m.get("serving") in ("self-hosted", "tee")]


def _isolation_ok(rx: dict[str, Any], required: str | None) -> bool:
    if required is None:
        return True
    have = (rx.get("sandbox") or {}).get("isolation")
    return have in ISOLATION_RANK and required in ISOLATION_RANK and ISOLATION_RANK[have] >= ISOLATION_RANK[required]


def verify(envelope: dict[str, Any], keyring: Keyring, *, expectations: dict[str, Any] | None = None,
           report: dict[str, Any] | None = None, leaves: list[dict[str, Any]] | None = None, require_leaves: bool = False,
           expected_intake: str | None = None, platform_key: str | None = None, receipt: dict[str, Any] | None = None,
           reexecution: dict[str, Any] | None = None, ledger_entries: list[dict[str, Any]] | None = None,
           last_seen: tuple[str, int] | None = None, floor: float = 0.6, min_entries: int = 5, min_countersigners: int = 2,
           min_age_days: float = 30, quote_verifier: QuoteVerifier | None = None, now_days: float | None = None,
           require_anchor: bool = False, accept_timestamp_anchor: bool = False, require_isolation: str | None = None,
           required_entries: list[dict[str, Any]] | None = None) -> Result:
    """spec/v1.0/verification.md. Every input other than the envelope and keyring is optional; a missing input fails
    the checks that need it (VSLA-V-3), which is how a coordinator without the code honestly lands at L1.

    `expectations` = {"harness": {name: {version: sha256}}, "measurements": [{"type", "value", "harness", "coSigners"?}]}:
    the receiver's independently obtained reference values (VSLA-V-6). Without them the Environment pillar cannot
    pass an external check above L1. `last_seen` = (root, count) of this finder's ledger as this platform last saw it.
    `require_anchor` makes I3 (and E7, which reads the receipt) demand a verified `log-inclusion` anchor (VSLA-P-16,
    REQUIRED for a third-party verifier); `accept_timestamp_anchor` lets the `signed-timestamp` form satisfy it.
    `require_isolation` ("vm" | "container") makes E7 accept only re-executions in at least that isolation class (VSLA-P-11).
    `required_entries` are the ledger entries this verifier itself countersigned for the finder; each must be included
    in the presented ledger or I4 records `ledger-fork`. Every key window, `revoke` entry and the rubric's decay are
    evaluated at one instant, `t_eval`: the anchor's integratedTime, else the receipt's receivedAt, else the verifier's clock."""
    E, I, N = Pillar("evidence"), Pillar("identity"), Pillar("environment")
    exp = expectations or {}
    now_s = now_days * 86400 if now_days is not None else time.time()
    try:
        stmt = canonical_payload(envelope)
        pred = stmt["predicate"]
        if not isinstance(pred, dict):
            raise TypeError("predicate is not an object")
        claimed = int(pred["claimedLevel"])
    except Exception as exc:
        for p in (E, I, N):
            _run(p, "E1", 1, False, f"envelope unreadable, payload not canonical, or claimedLevel missing: {exc!s}"[:200], "structural")
            _finalize(p)
        return Result(claimed=0, verified=0, pillars={"evidence": E, "identity": I, "environment": N})
    track = str(pred.get("track") or "finding")
    profile = pred.get("profile", "published")
    fin = pred.get("finder", {}) or {}
    rp = pred.get("reproduction", {}) or {}
    tr = pred.get("transcript", {}) or {}
    models = (pred.get("mbom", {}) or {}).get("models", []) or []
    env = pred.get("environment")
    ts = pred.get("timestamps", {}) or {}
    subj = stmt.get("subject", []) or []
    revision = (subj[1].get("digest", {}).get("gitCommit") if len(subj) > 1 and isinstance(subj[1], dict) else None)
    finder_key_hex = str(fin.get("publicKey", "")).removeprefix("ed25519:")

    # ---------------------------------------------------------------- the receipt (I3), verified before anything reads it
    ch = pred.get("channel") or {}
    intake_hex = str(ch.get("intakeKey", "")).removeprefix("ed25519:")
    pkid = platform_key or keyring.find("platform", intake_hex) or (keyring.role("platform")[0] if keyring.role("platform") else None)
    pkey = keyring.get(pkid) if pkid else None
    rbody = (_try(lambda: canonical_payload(receipt), {}) if receipt else {}) or {}
    rkid = signer_keyids(receipt)[0] if receipt and signer_keyids(receipt) else None
    received = _ts(rbody.get("receivedAt"))
    t_start, t_end = _ts(ts.get("startedAt")), _ts(ts.get("finishedAt"))
    # One evaluation instant for every window: the anchor's time (a third party's), else the receipt's, else our clock.
    anchor_ok, anchor_form, anchor_why = verify_anchor(rbody, keyring, now_s=now_s) if rbody else (False, "none", "no receipt")
    t_anchor = _ts((rbody.get("anchor") or {}).get("integratedTime")) if anchor_ok else None
    t_eval = t_anchor if t_anchor is not None else (received if received is not None else now_s)
    rkey = keyring.get(rkid, at=t_eval) if rkid else None
    anchor_accepted = anchor_ok and (anchor_form == "log-inclusion" or (anchor_form == "signed-timestamp" and accept_timestamp_anchor))
    receipt_ok = (bool(ch) and bool(receipt) and bool(rbody) and rkid is not None and rkid.startswith("platform:") and rkey is not None
                  and pkid is not None and rkid == pkid and public_hex(rkey) == intake_hex
                  and verify_receipt(receipt, rkid, rkey) and rbody.get("statementDigest") == _try(lambda: statement_digest(envelope))
                  and rbody.get("channel") == ch.get("intake") and received is not None and t_start is not None and t_end is not None
                  and t_start <= t_end <= received <= now_s + CLOCK_SKEW_S and bool((rbody.get("reexecution") or {}).get("status"))
                  and (anchor_accepted or not require_anchor))

    # ---------------------------------------------------------------- Evidence
    ok_schema, why = _schema_ok(pred)
    _run(E, "E1", 1, envelope.get("payloadType") == PAYLOAD_TYPE and stmt.get("_type") == STATEMENT_TYPE
         and stmt.get("predicateType") == PREDICATE_TYPE and ok_schema, f"{why}; payload canonical", "structural")
    fkid = f"finder:{fin.get('identity')}"
    fkey = keyring.get(fkid)
    _run(E, "E2", 1, fkey is not None and verify_signature(envelope, fkid, fkey, PAYLOAD_TYPE) and public_hex(fkey) == finder_key_hex, fkid)
    # E3: subject binds the report and a revision; the reproduction ran at that revision; times are ordered
    r_start, r_end = _ts(rp.get("startedAt")), _ts(rp.get("finishedAt"))
    ordered = (t_start is not None and t_end is not None and t_start <= t_end <= now_s + CLOCK_SKEW_S
               and (r_start is None or r_end is None or (t_start <= r_start <= r_end <= t_end)))
    bound = len(subj) > 1 and bool(revision) and rp.get("revision") == revision
    if report is not None:
        rd = _try(lambda: report_digest(report))
        _run(E, "E3", 1, bound and ordered and rd is not None and subj[0].get("digest", {}).get("sha256") == rd, "subject[0] vs report; revision binding; time order")
    else:
        _run(E, "E3", 1, bound and ordered, "report not supplied: revision binding and time order only", "structural")
    # E4: MBOM complete; self-hosted/tee models carry a weight digest or say they are unmeasured
    weights_ok = all(("digest" in (m.get("weights") or {})) or (m.get("weights") or {}).get("unmeasured") is True for m in _models_with_weights(models))
    _run(E, "E4", 1, bool(models) and all(m.get("serving") in ("api", "self-hosted", "tee") for m in models) and weights_ok, f"{len(models)} models", "structural")
    # E5: Merkle root, measured first leaf, and a verify leaf that matches the reproduction section. Structural: the finder
    # wrote both the leaves and the section; the check rejects an inconsistent statement, it does not separate levels.
    sup = leaves if leaves is not None else tr.get("leaves")
    if sup is not None:
        vleaf = next((x for x in sup if isinstance(x, dict) and x.get("kind") == "verify" and x.get("what") == "reproduction"), None)
        cmd_match = (vleaf is not None and ((rp.get("command") is not None and vleaf.get("command") == rp.get("command"))
                                             or (rp.get("commandDigest") is not None and sha256_hex(str(vleaf.get("command", "")).encode()) == rp["commandDigest"].get("sha256"))))
        vleaf_ok = (vleaf is not None and cmd_match and vleaf.get("exit") == rp.get("observedExit")
                    and vleaf.get("securityFailure") == rp.get("securityFailure") and vleaf.get("output") == rp.get("outputDigest"))
        root = _try(lambda: merkle_root(transcript_leaves(sup)))
        _run(E, "E5", 1, root is not None and root == tr.get("root") and len(sup) == tr.get("leafCount")
             and bool(sup) and isinstance(sup[0], dict) and sup[0].get("kind") == "measure" and vleaf_ok,
             f"{len(sup)} leaves; verify leaf {'matches' if vleaf_ok else 'missing or mismatched'}", "structural")
    else:
        _run(E, "E5", 1, not require_leaves and tr.get("algorithm") == "rfc6962-sha256" and bool(tr.get("root")), "leaves not supplied: root only", "structural")
    # E6: reproduction executed by code with the right outcome (the finder's own account; structural)
    cmd_profile_ok = (profile == "published" and "command" in rp and "commandDigest" not in rp) or (profile == "embargoed" and "commandDigest" in rp and "command" not in rp)
    if track == "patch":
        pt = pred.get("patch", {}) or {}
        _run(E, "E6", 1, rp.get("executor") == "code" and cmd_profile_ok and pt.get("applied") is True and pt.get("reproductionPasses") is True and pt.get("suitePasses") is True,
             "patch: applied, repro passes, suite passes", "structural")
    else:
        _run(E, "E6", 1, rp.get("executor") == "code" and cmd_profile_ok and rp.get("observedExit") == rp.get("expectedExit") == 1 and rp.get("securityFailure") is True,
             f"exit {rp.get('observedExit')}", "structural")
    # E7: re-executed by someone other than the finder, at the subject revision, with the receiver's own classifier.
    # A receipt is evidence only once I3 verified it (a receipt anyone could have signed is not a re-execution).
    rx = reexecution or ((rbody.get("reexecution") or {}) if receipt_ok else {}) or {}
    who = "verifier" if reexecution else ("platform receipt" if receipt_ok else ("unverified receipt (ignored)" if receipt else "nobody"))
    iso = (rx.get("sandbox") or {}).get("isolation")
    rx_at_rev = rx.get("status") == "matched" and rx.get("revision") == revision and _isolation_ok(rx, require_isolation)
    if track == "patch":
        _run(E, "E7", 2, rx_at_rev and rx.get("applied") is True and rx.get("reproductionPasses") is True and rx.get("suitePasses") is True,
             f"re-execution status={rx.get('status')!r} isolation={iso} by {who}")
        # E8: the receiver's own adversarial review on a different model family, over a source-only diff
        rv = rx.get("review") or {}
        scope_ok = rx.get("scope") == "source-only"
        _run(E, "E8", 2, rx_at_rev and rv.get("approved") is True and rv.get("distinctFamily") is True and scope_ok,
             f"receiver review approved={rv.get('approved')} distinctFamily={rv.get('distinctFamily')} scope={rx.get('scope')}; finder-asserted review is informational")
    else:
        _run(E, "E7", 2, rx_at_rev and rx.get("observedExit") == 1 and rx.get("securityFailure") is True and rx.get("touchedSubject") is True,
             f"re-execution status={rx.get('status')!r} touchedSubject={rx.get('touchedSubject')} isolation={iso} by {who}")

    # ---------------------------------------------------------------- Identity
    auth = pred.get("authorization", {}) or {}
    finder_key = f"ed25519:{finder_key_hex}"
    chain = successor_chain(ledger_entries or [], finder_key)
    revoked = [r for r in revocations(ledger_entries or [], keyring, chain) if r[1] <= t_eval]
    key_valid = fkey is not None and keyring.get(fkid, at=t_eval) is not None and not revoked
    _run(I, "I1", 1, key_valid and bool(fin.get("operator")) and bool((fin.get("harness") or {}).get("digest")) and bool(auth.get("basis")),
         f"{fkid} {'valid' if key_valid else 'revoked or outside its window'} at t_eval={datetime.fromtimestamp(t_eval, UTC).isoformat()}"
         f"{' (' + ', '.join(r[2] for r in revoked) + ')' if revoked else ''}; authorization={auth.get('basis')}")
    _run(I, "I2", 2, bool(ch) and (expected_intake is None or ch.get("intake") == expected_intake)
         and pkey is not None and intake_hex == public_hex(pkey), ch.get("intake") or "no channel")
    _run(I, "I3", 2, receipt_ok,
         (f"{rkid}; {anchor_why}" if receipt_ok else
          f"{rkid or 'no receipt'}: " + ("anchor required: " + anchor_why if receipt and require_anchor and not anchor_accepted else
                                          "not a verified receipt from the pinned platform key the statement names, with finishedAt <= receivedAt <= now")))
    hist = pred.get("history") or {}
    if ledger_entries is None:
        _run(I, "I4", 2, False, "ledger not supplied: a self-reported summary is not evidence (VSLA-V-3)")
    else:
        formed, why_formed = ledger_well_formed(ledger_entries)
        bodies, dropped = verified_ledger(ledger_entries, keyring, finder=chain, track=track)
        root_ok = _try(lambda: ledger_root(ledger_entries) == hist.get("root"), False)
        consistent = last_seen is None or ledger_consistent(ledger_entries, *last_seen)
        omitted = missing_entries(ledger_entries, required_entries or [])
        tscore = _try(lambda: trust_score(bodies, now_days=t_eval / 86400), trust_score([]))   # evaluated at t_eval; a malformed `at` fails, never crashes
        floor_ok, why_floor = meets_floor(tscore, floor=floor, min_entries=min_entries, min_countersigners=min_countersigners, min_age_days=min_age_days)
        reason = ("ledger-fork: does not extend the ledger this verifier was shown" if not consistent
                  else f"ledger-fork: omits {omitted} entr{'y' if omitted == 1 else 'ies'} this verifier countersigned" if omitted
                  else why_formed if not formed else "history.root mismatch" if not root_ok else "" if floor_ok else "below floor")
        _run(I, "I4", 2, consistent and not omitted and formed and root_ok and floor_ok,
             f"{reason or 'ok'}; {why_floor}; {dropped} outcome entries dropped (unverifiable, other finder or other track); chain of {len(chain)} key(s)")
    # I5 is computed with the environment (the enclave key comes from the quote, not the keyring)

    # ---------------------------------------------------------------- Environment
    _run(N, "N1", 1, bool(models) and all(m.get("serving") for m in models), "serving modes declared", "structural")
    harness = fin.get("harness", {}) or {}
    harness_d = (harness.get("digest") or {}).get("sha256")
    sb_d = ((rp.get("sandbox") or {}).get("digest") or {}).get("sha256")
    first = (sup[0] if sup else None) if sup is not None else tr.get("firstLeaf")
    first_ok = isinstance(first, dict) and first.get("kind") == "measure" and (first.get("harness") or {}).get("sha256") == harness_d and (sb_d is None or (first.get("sandbox") or {}).get("sha256") == sb_d)
    expected_h = (exp.get("harness", {}) or {}).get(str(harness.get("name", "")), {}).get(str(harness.get("version", "")))
    att_ok = all(verify_weights_attestation(m["weights"]["attestation"], keyring, (m["weights"].get("digest") or {}).get("sha256"))
                 for m in _models_with_weights(models) if (m.get("weights") or {}).get("attestation"))
    if expected_h is None:
        _run(N, "N2", 2, False, f"no expectation for harness {harness.get('name')} {harness.get('version')}: measured digest cannot be checked (VSLA-V-6)")
    else:
        _run(N, "N2", 2, first_ok and harness_d == expected_h and att_ok,
             f"measured first leaf vs expectation; weight attestations {'ok' if att_ok else 'failed'}. Below L3 the digest is the finder's own measurement and detects drift, not fraud")
    api_served = [m.get("name") for m in models if m.get("serving") == "api"]
    enclave_pub_hex = str((env or {}).get("enclaveKey", "")).removeprefix("ed25519:") or None
    binding = {"enclaveKey": enclave_pub_hex, "harness": harness_d, "weights": [m["weights"]["digest"]["sha256"] for m in _models_with_weights(models) if "digest" in (m.get("weights") or {})], "sandbox": sb_d}
    cos = sorted(str(c) for c in (env or {}).get("coSigners", []) or [])
    meas_allowed = any(x.get("type") == (env or {}).get("type") and x.get("value") == ((env or {}).get("measurement") or {}).get("value") and x.get("harness") == harness_d
                       and ("coSigners" not in x or sorted(str(c) for c in x["coSigners"]) == cos)
                       for x in exp.get("measurements", []) or [])
    all_attested = bool(_models_with_weights(models)) and all((m.get("weights") or {}).get("attestation") for m in _models_with_weights(models)) and att_ok
    quote_ok = bool(env) and env.get("type") != "none" and quote_verifier is not None and _try(lambda: quote_verifier(env, binding), False)
    if not env or env.get("type") == "none":
        n3_ok = _run(N, "N3", 3, False, "no environment")
    elif api_served:
        n3_ok = _run(N, "N3", 3, False, f"api-served models cannot be measured: {api_served}")
    elif quote_verifier is None:
        n3_ok = _run(N, "N3", 3, False, "no environment adapter for this verifier")
    else:
        n3_ok = _run(N, "N3", 3, quote_ok and REQUIRED_MEASURES <= set(env.get("measures", [])) and meas_allowed and all_attested and bool(sb_d),
             f"quote {'ok' if quote_ok else 'failed'}; measurement {'allowlisted' if meas_allowed else 'not in expectations'}; weights {'all attested' if all_attested else 'not all attested'}")
    # I5: the enclave signature verifies under the key the (verified) quote binds
    ekid = f"enclave:{(env or {}).get('type')}:{str(((env or {}).get('measurement') or {}).get('value', ''))[:16]}"
    try:
        epub = Ed25519PublicKey.from_public_bytes(bytes.fromhex(enclave_pub_hex)) if enclave_pub_hex else None
    except ValueError:
        epub = None
    _run(I, "I5", 3, n3_ok and epub is not None and verify_signature(envelope, ekid, epub, PAYLOAD_TYPE), ekid if n3_ok else "environment check failed, so no enclave key (if N3 fails, I5 fails)")

    for p in (E, I, N):
        _finalize(p)
    verified = min(E.level, I.level, N.level, claimed)
    return Result(claimed=claimed, verified=verified, pillars={"evidence": E, "identity": I, "environment": N})


# ----------------------------------------------------------------------------- CLI

def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Verify a VSLA statement and compute its verified level.")
    ap.add_argument("envelope")
    ap.add_argument("--keyring", required=True, help="json {keyid: 'ed25519:<hex>' | {public, validFrom?, revokedAt?}}; roles finder:, platform:, maintainer:, provider:, root:, operator:, log:")
    ap.add_argument("--expectations", help="json {harness: {name: {version: sha256}}, measurements: [{type, value, harness, coSigners?}]}")
    ap.add_argument("--report", help="the report json the statement is about (checks subject[0])")
    ap.add_argument("--leaves", help="json list of transcript leaves (checks the Merkle root and the verify leaf)")
    ap.add_argument("--require-leaves", action="store_true", help="fail E5 when leaves are not supplied")
    ap.add_argument("--intake", help="the authoritative intake URL this verifier represents")
    ap.add_argument("--platform-key", help="the pinned platform keyid (platform:NAME) whose receipt counts; default: the pinned platform key matching channel.intakeKey")
    ap.add_argument("--receipt", help="the platform's signed receipt (DSSE) for this statement")
    ap.add_argument("--require-anchor", action="store_true", help="I3 and E7 require a verified log-inclusion anchor (VSLA-P-16; a third-party verifier should set this)")
    ap.add_argument("--accept-timestamp-anchor", action="store_true", help="let the signed-timestamp form satisfy --require-anchor")
    ap.add_argument("--required-entries", help="json list of ledger entries (DSSE) this verifier countersigned for the finder; each must be included")
    ap.add_argument("--require-isolation", choices=["container", "vm"], help="E7 accepts a re-execution only in at least this isolation class (VSLA-P-11)")
    ap.add_argument("--reexec", help="json re-execution result from your own sandbox")
    ap.add_argument("--ledger", help="json list of the finder's countersigned ledger entries (DSSE envelopes)")
    ap.add_argument("--last-seen", help="ROOT:COUNT of this finder's ledger as you last saw it (consistency check)")
    ap.add_argument("--floor", type=float, default=0.6)
    a = ap.parse_args(argv)
    ring = Keyring.load(a.keyring)
    load = lambda p: json.loads(Path(p).read_text()) if p else None
    last = None
    if a.last_seen:
        r, c = a.last_seen.rsplit(":", 1)
        last = (r, int(c))
    res = verify(load(a.envelope), ring, expectations=load(a.expectations), report=load(a.report), leaves=load(a.leaves), require_leaves=a.require_leaves,
                 expected_intake=a.intake, platform_key=a.platform_key, receipt=load(a.receipt), reexecution=load(a.reexec), ledger_entries=load(a.ledger),
                 last_seen=last, floor=a.floor, quote_verifier=signed_quote_verifier(ring), require_anchor=a.require_anchor,
                 accept_timestamp_anchor=a.accept_timestamp_anchor, require_isolation=a.require_isolation, required_entries=load(a.required_entries))
    print(json.dumps(res.to_dict(), indent=2))
    print(f"\nVSLA {envelope_payload(load(a.envelope))['predicate']['track']}: claimed L{res.claimed}, verified L{res.verified}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
