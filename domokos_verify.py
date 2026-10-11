#!/usr/bin/env python3
"""
domokos-verify — independent verifier for Domokos evidence bundles.

Implements SPEC.md (format "domokos-bundle/1") and nothing else: no Domokos
code, no shared library, no third-party dependency. Python 3.9+ standard
library only, single file, no build step — runnable on a locked-down
corporate laptop:

    python3 domokos_verify.py bundle.zip
    python3 domokos_verify.py bundle.zip --json report.json
    python3 domokos_verify.py --charter CHARTER.md --version 1.0.0 bundle.zip

Exit code 0 iff every check passes. Every check runs even after a failure,
so one run reports everything.

Licensed under the Apache License, Version 2.0.
"""

from __future__ import annotations

import argparse
import hashlib
import io
import json
import re
import sys
import zipfile

SPEC = "domokos-bundle/1"
GENESIS = "0" * 64
LEGACY_SIGNATURE_MARKER = "LEGACY-UNSIGNED"
SUBJECT_TYPE_SCHEMA_VERSION = 3
IMPLEMENTED_SUBJECT_TYPES = {"work_product"}
SIGNING_MUTABLE_FIELDS = {"review", "regulatory_mappings", "misra_findings", "audit_state", "flags"}


# ===========================================================================
# Ed25519 verification — RFC 8032, self-contained.
# ===========================================================================

_p = 2**255 - 19
_q = 2**252 + 27742317777372353535851937790883648493
_d = (-121665 * pow(121666, _p - 2, _p)) % _p
_I = pow(2, (_p - 1) // 4, _p)

_By = (4 * pow(5, _p - 2, _p)) % _p


def _xrecover(y: int) -> int:
    xx = (y * y - 1) * pow(_d * y * y + 1, _p - 2, _p)
    x = pow(xx, (_p + 3) // 8, _p)
    if (x * x - xx) % _p != 0:
        x = (x * _I) % _p
    if (x * x - xx) % _p != 0:
        raise ValueError("point not on curve")
    if x % 2 != 0:
        x = _p - x
    return x


_Bx = _xrecover(_By)
_B = (_Bx, _By, 1, (_Bx * _By) % _p)  # extended coordinates (X, Y, Z, T)


def _pt_add(P, Q):
    (X1, Y1, Z1, T1), (X2, Y2, Z2, T2) = P, Q
    A = ((Y1 - X1) * (Y2 - X2)) % _p
    Bv = ((Y1 + X1) * (Y2 + X2)) % _p
    C = (2 * T1 * T2 * _d) % _p
    D = (2 * Z1 * Z2) % _p
    E, F, G, H = Bv - A, D - C, D + C, Bv + A
    return ((E * F) % _p, (G * H) % _p, (F * G) % _p, (E * H) % _p)


def _pt_mul(s: int, P):
    Q = (0, 1, 1, 0)  # neutral element
    while s > 0:
        if s & 1:
            Q = _pt_add(Q, P)
        P = _pt_add(P, P)
        s >>= 1
    return Q


def _pt_encode(P) -> bytes:
    X, Y, Z, _T = P
    zi = pow(Z, _p - 2, _p)
    x, y = (X * zi) % _p, (Y * zi) % _p
    return (y | ((x & 1) << 255)).to_bytes(32, "little")


def _pt_decode(s: bytes):
    if len(s) != 32:
        raise ValueError("bad point length")
    y = int.from_bytes(s, "little")
    sign = y >> 255
    y &= (1 << 255) - 1
    if y >= _p:
        raise ValueError("bad y")
    x = _xrecover(y)
    if x & 1 != sign:
        x = _p - x
    P = (x, y, 1, (x * y) % _p)
    # on-curve check: -x^2 + y^2 = 1 + d x^2 y^2
    if (-x * x + y * y - 1 - _d * x * x * y * y) % _p != 0:
        raise ValueError("point not on curve")
    return P


def ed25519_verify(public_key: bytes, signature: bytes, message: bytes) -> bool:
    try:
        if len(signature) != 64:
            return False
        R = _pt_decode(signature[:32])
        A = _pt_decode(public_key)
        S = int.from_bytes(signature[32:], "little")
        if S >= _q:
            return False
        h = int.from_bytes(
            hashlib.sha512(signature[:32] + public_key + message).digest(), "little"
        ) % _q
        left = _pt_mul(S, _B)
        right = _pt_add(R, _pt_mul(h, A))
        return _pt_encode(left) == _pt_encode(right)
    except ValueError:
        return False


# ===========================================================================
# Checks
# ===========================================================================


class Report:
    def __init__(self, bundle: str):
        self.bundle = bundle
        self.checks: list[dict] = []
        self.notes: list[str] = []

    def check(self, check_id: str, name: str, ok: bool, detail: str = "") -> None:
        self.checks.append({"id": check_id, "name": name, "ok": ok, "detail": detail})

    @property
    def ok(self) -> bool:
        return all(c["ok"] for c in self.checks)

    def to_dict(self) -> dict:
        return {
            "bundle": self.bundle,
            "spec": SPEC,
            "ok": self.ok,
            "checks": self.checks,
            "notes": self.notes,
        }


def _entry_hash(e: dict) -> str:
    joined = "|".join(
        [str(e["seq"]), e["captured_at"], e["actor_id"], e["event_type"],
         e["payload_json"], e["prev_hash"]]
    )
    return hashlib.sha256(joined.encode("utf-8")).hexdigest()


def check_manifest_files(zf: zipfile.ZipFile, manifest: dict, rep: Report) -> None:
    if manifest.get("bundle_format") != SPEC:
        rep.check("manifest-files", "Manifest and file integrity", False,
                  f"unknown bundle_format {manifest.get('bundle_format')!r}")
        return
    bad = []
    for name, meta in manifest.get("files", {}).items():
        try:
            digest = hashlib.sha256(zf.read(name)).hexdigest()
        except KeyError:
            bad.append(f"{name}: missing from archive")
            continue
        if digest != meta.get("sha256"):
            bad.append(f"{name}: sha256 mismatch")
    rep.check("manifest-files", "Manifest and file integrity", not bad, "; ".join(bad))


def check_chain(entries: list[dict], continuity: dict, rep: Report) -> None:
    problems = []
    prev = GENESIS if entries and entries[0]["seq"] == 1 else None
    for e in entries:
        if prev is not None and e["prev_hash"] != prev:
            problems.append(f"prev_hash break at seq {e['seq']}")
        recomputed = _entry_hash(e)
        if recomputed != e["content_hash"]:
            problems.append(
                f"content_hash mismatch at seq {e['seq']}: stored bytes were altered"
            )
            prev = e["content_hash"]  # keep walking with the recorded value
            continue
        prev = e["content_hash"]
    if entries and entries[-1]["content_hash"] != continuity.get("head_hash"):
        problems.append("last entry's hash does not equal the continuity head_hash")
    rep.check("chain-hashes", "Hash chain integrity", not problems, "; ".join(problems))


def check_sequence(entries: list[dict], continuity: dict, rep: Report) -> None:
    problems = []
    lo, hi = continuity.get("seq_range", [None, None])
    seqs = [e["seq"] for e in entries]
    if seqs != list(range(lo, hi + 1)):
        problems.append(f"entries are not contiguous over declared range {lo}..{hi}")
    if continuity.get("entries_in_bundle") != len(entries):
        problems.append("entries_in_bundle does not match ledger.jsonl line count")
    rendered = set(continuity.get("rendered_in_pdf", {}).get("seqs", []))
    omitted = set(continuity.get("omitted_from_pdf", {}).get("seqs", []))
    if rendered & omitted:
        problems.append("rendered and omitted sets overlap")
    if rendered | omitted != set(range(lo, hi + 1)):
        missing = sorted(set(range(lo, hi + 1)) - (rendered | omitted))
        problems.append(f"continuity statement does not account for seq {missing}")
    rep.check("sequence-continuity", "Sequence continuity accounting",
              not problems, "; ".join(problems))


def check_filter(entries: list[dict], continuity: dict, rep: Report) -> None:
    predicate = continuity.get("filter", {}).get("predicate", {})
    ptype = predicate.get("type")
    if ptype != "artefact_relevance":
        rep.check("declared-filter", "Declared filter is reproducible", False,
                  f"unknown filter predicate type {ptype!r} — an uncheckable filter is undeclared")
        return
    ids = set(predicate.get("artefact_ids", []))
    recomputed = []
    for e in entries:
        try:
            payload = json.loads(e["payload_json"])
        except json.JSONDecodeError:
            continue
        if payload.get("artefact_id") in ids:
            recomputed.append(e["seq"])
        elif e["event_type"] == "evidence.exported" and any(
            a in ids for a in payload.get("artefact_ids", [])
        ):
            recomputed.append(e["seq"])
    declared = continuity.get("rendered_in_pdf", {}).get("seqs", [])
    ok = recomputed == declared
    rep.check(
        "declared-filter", "Declared filter is reproducible", ok,
        "" if ok else f"re-evaluating the predicate renders {recomputed}, manifest declares {declared}",
    )


def check_void_entries(entries: list[dict], continuity: dict, rep: Report) -> None:
    declared = continuity.get("void_entries", {}).get("entries", [])
    problems = []
    by_seq = {e["seq"]: e for e in entries}
    for v in declared:
        entry = by_seq.get(v.get("seq"))
        if entry is None or entry["event_type"] != "sequence.voided":
            problems.append(
                f"void entry declared at seq {v.get('seq')} has no sequence.voided ledger entry"
            )
    rep.check("void-entries", "Void entries exist and explain themselves",
              not problems, "; ".join(problems))


def check_subject_type_boundary(entries: list[dict], rep: Report) -> None:
    problems = []
    last_version = 0
    for e in entries:
        if e["event_type"] != "artefact.captured":
            continue
        try:
            payload = json.loads(e["payload_json"])
        except json.JSONDecodeError:
            problems.append(f"seq {e['seq']}: unparseable payload")
            continue
        version = payload.get("schema_version", 1)
        if version < last_version:
            problems.append(
                f"seq {e['seq']}: schema_version regressed {last_version} -> {version}"
            )
        last_version = max(last_version, version)
        has_field = "subject_type" in payload
        if version >= SUBJECT_TYPE_SCHEMA_VERSION:
            if not has_field:
                problems.append(f"seq {e['seq']}: v{version} entry missing subject_type")
            elif payload["subject_type"] not in IMPLEMENTED_SUBJECT_TYPES:
                problems.append(
                    f"seq {e['seq']}: subject_type {payload['subject_type']!r} is reserved"
                )
        else:
            if has_field:
                problems.append(
                    f"seq {e['seq']}: pre-v3 entry carries subject_type — "
                    f"evidence of a rewritten payload"
                )
    rep.check("subject-type-boundary", "subject_type schema boundary",
              not problems, "; ".join(problems))


def _signing_payload(artefact: dict) -> bytes:
    data = {k: v for k, v in artefact.items() if k not in SIGNING_MUTABLE_FIELDS}
    data["actor"] = {k: v for k, v in data["actor"].items() if k != "signature"}
    if data.get("schema_version", 1) < SUBJECT_TYPE_SCHEMA_VERSION:
        data.pop("subject_type", None)
    return json.dumps(data, sort_keys=True, separators=(",", ":")).encode("utf-8")


def check_signatures(artefacts: list[dict], keys: dict, rep: Report) -> None:
    problems = []
    legacy = 0
    verified = 0
    for art in artefacts:
        sig = art.get("actor", {}).get("signature")
        identity = art.get("actor", {}).get("identity", "?")
        if sig == LEGACY_SIGNATURE_MARKER:
            legacy += 1
            continue
        if not sig:
            problems.append(f"{art.get('id')}: unsigned non-legacy artefact")
            continue
        pub_hex = keys.get(identity)
        if not pub_hex:
            problems.append(f"{art.get('id')}: no public key for actor {identity!r}")
            continue
        try:
            ok = ed25519_verify(bytes.fromhex(pub_hex), bytes.fromhex(sig), _signing_payload(art))
        except ValueError:
            ok = False
        if not ok:
            problems.append(f"{art.get('id')}: signature by {identity!r} does not verify")
        else:
            verified += 1
    detail = (
        f"{verified} verified, {legacy} legacy-unsigned (reported, not failed); "
        f"signatures are platform attestation (server-held key): they show the platform "
        f"bound the content to an identity string, not who authored or approved it"
    )
    if problems:
        detail = "; ".join(problems) + f" [{detail}]"
    rep.check("actor-signatures", "Actor signatures — platform attestation (server-held key)", not problems, detail)


def check_anchors(entries: list[dict], anchors: list[dict], continuity: dict, rep: Report) -> None:
    problems = []
    external = 0
    lo, hi = continuity.get("seq_range", [0, 0])

    running: dict[int, str] = {}
    prev = GENESIS if entries and entries[0]["seq"] == 1 else None
    for e in entries:
        if prev is None:
            break
        recomputed = _entry_hash(e)
        running[e["seq"]] = recomputed
        prev = recomputed

    for a in anchors:
        seq = a.get("ledger_seq")
        if not (lo <= seq <= hi):
            problems.append(f"anchor {a.get('id')}: anchored seq {seq} outside bundle range")
            continue
        recomputed_root = running.get(seq)
        if recomputed_root != a.get("ledger_hash"):
            problems.append(
                f"anchor {a.get('id')}: chain root at seq {seq} is "
                f"{(recomputed_root or 'unknown')[:16]}…, anchor claims "
                f"{a.get('ledger_hash', '')[:16]}… — forged anchor or rewritten chain"
            )
            continue
        if a.get("method") == "rfc3161":
            token_hex = a.get("tsa_token")
            if not token_hex:
                problems.append(f"anchor {a.get('id')}: rfc3161 anchor without a token")
                continue
            imprint = hashlib.sha256(a["ledger_hash"].encode("ascii")).digest()
            if imprint not in bytes.fromhex(token_hex):
                problems.append(
                    f"anchor {a.get('id')}: TSA token does not embed the root's imprint"
                )
                continue
            external += 1
    detail = f"{external} externally attested (rfc3161), {len(anchors) - external} local/advisory"
    if external == 0:
        detail += " — externally unanchored range"
    if problems:
        detail = "; ".join(problems) + f" [{detail}]"
    rep.check("anchors", "Anchor validity against chain root", not problems, detail)
    if external == 0 and not problems:
        rep.notes.append(
            "no RFC 3161 anchor covers this range: history is protected by the "
            "chain alone until an external anchor exists (see THREAT_MODEL)"
        )


def check_pdf_continuity(pdf_bytes: bytes, continuity: dict, rep: Report) -> None:
    m = re.search(rb"/Subject \((.*?)\)\s*/", pdf_bytes, re.DOTALL)
    if not m:
        rep.check("pdf-continuity", "PDF continuity statement matches bundle", False,
                  "PDF carries no machine-readable continuity statement (/Subject)")
        return
    raw = m.group(1).replace(b"\\(", b"(").replace(b"\\)", b")").replace(b"\\\\", b"\\")
    try:
        stated = json.loads(raw.decode("latin-1"))
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        rep.check("pdf-continuity", "PDF continuity statement matches bundle", False,
                  f"unparseable continuity statement in PDF: {exc}")
        return
    ok = stated == continuity
    rep.check(
        "pdf-continuity", "PDF continuity statement matches bundle", ok,
        "" if ok else "the PDF's continuity statement differs from the bundle manifest — "
                      "the human-readable document and the verifiable record disagree",
    )


# ===========================================================================
# Charter mode (--charter): verify a charter version against the ledger
# ===========================================================================


def check_charter(entries: list[dict], charter_path: str, version: str, rep: Report) -> None:
    try:
        with open(charter_path, "rb") as f:
            digest = hashlib.sha256(f.read()).hexdigest()
    except OSError as exc:
        rep.check("charter", "Charter version matches ledger record", False, str(exc))
        return
    found = None
    for e in entries:
        if e["event_type"] != "charter.published":
            continue
        try:
            payload = json.loads(e["payload_json"])
        except json.JSONDecodeError:
            continue
        if payload.get("version") == version:
            found = (e, payload)
    if found is None:
        rep.check("charter", "Charter version matches ledger record", False,
                  f"no charter.published entry for version {version}")
        return
    entry, payload = found
    ok = payload.get("charter_sha256") == digest
    rep.check(
        "charter", "Charter version matches ledger record", ok,
        f"version {version} at seq {entry['seq']}"
        if ok
        else f"charter file hash {digest[:16]}… does not match ledger record "
             f"{payload.get('charter_sha256', '')[:16]}… at seq {entry['seq']}",
    )


# ===========================================================================
# Driver
# ===========================================================================


def verify_bundle(path: str, charter: str | None = None,
                  charter_version: str | None = None) -> Report:
    rep = Report(path)
    try:
        zf = zipfile.ZipFile(path)
        manifest = json.loads(zf.read("manifest.json"))
        entries = [json.loads(l) for l in zf.read("ledger.jsonl").decode("utf-8").splitlines()]
        artefacts = json.loads(zf.read("artefacts.json"))
        keys = json.loads(zf.read("actor_keys.json"))
        anchors = json.loads(zf.read("anchors.json"))
        pdf = zf.read("evidence.pdf")
    except (OSError, KeyError, json.JSONDecodeError, zipfile.BadZipFile) as exc:
        rep.check("manifest-files", "Manifest and file integrity", False,
                  f"cannot read bundle: {exc}")
        return rep

    continuity = manifest.get("continuity", {})
    check_manifest_files(zf, manifest, rep)
    check_chain(entries, continuity, rep)
    check_sequence(entries, continuity, rep)
    check_filter(entries, continuity, rep)
    check_void_entries(entries, continuity, rep)
    check_subject_type_boundary(entries, rep)
    check_signatures(artefacts, keys, rep)
    check_anchors(entries, anchors, continuity, rep)
    check_pdf_continuity(pdf, continuity, rep)
    if charter is not None:
        check_charter(entries, charter, charter_version or "", rep)
    return rep


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="domokos-verify", description="Independent verifier for Domokos evidence bundles."
    )
    parser.add_argument("bundle", help="path to the bundle .zip")
    parser.add_argument("--json", metavar="FILE", help="also write the JSON report here ('-' = stdout)")
    parser.add_argument("--charter", metavar="CHARTER_MD",
                        help="verify this charter file against the ledger record")
    parser.add_argument("--version", metavar="X.Y.Z",
                        help="charter version to verify (with --charter)")
    args = parser.parse_args(argv)

    rep = verify_bundle(args.bundle, charter=args.charter, charter_version=args.version)

    for c in rep.checks:
        mark = "PASS" if c["ok"] else "FAIL"
        line = f"[{mark}] {c['name']}"
        if c["detail"]:
            line += f" — {c['detail']}"
        print(line)
    for note in rep.notes:
        print(f"[note] {note}")
    print(f"\n{'OK' if rep.ok else 'FAILED'}: {sum(c['ok'] for c in rep.checks)}/{len(rep.checks)} checks passed")

    if args.json:
        payload = json.dumps(rep.to_dict(), indent=2)
        if args.json == "-":
            print(payload)
        else:
            with open(args.json, "w", encoding="utf-8") as f:
                f.write(payload)

    return 0 if rep.ok else 1


if __name__ == "__main__":
    sys.exit(main())
