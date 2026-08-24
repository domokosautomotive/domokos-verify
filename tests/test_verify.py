"""
domokos-verify test suite (stdlib unittest — the zero-dependency rule covers
the tests too).

Exit-criteria scenarios: a valid bundle returns 0; altered entry, removed
entry, forged anchor, mismatched continuity statement, and a
rename-boundary chain whose historical name was rewritten each return
non-zero with a specific, comprehensible reason.
"""

from __future__ import annotations

import hashlib
import io
import json
import sys
import unittest
import zipfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import domokos_verify as dv

FIXTURE = Path(__file__).resolve().parent.parent / "fixtures" / "valid-bundle.zip"


def _load(path=FIXTURE) -> dict[str, bytes]:
    zf = zipfile.ZipFile(path)
    return {n: zf.read(n) for n in zf.namelist()}


def _rezip(files: dict[str, bytes], tmpdir: Path, name: str) -> Path:
    out = tmpdir / name
    with zipfile.ZipFile(out, "w") as zf:
        for n, data in files.items():
            zf.writestr(n, data)
    return out


def _entries(files: dict[str, bytes]) -> list[dict]:
    return [json.loads(l) for l in files["ledger.jsonl"].decode().splitlines()]


def _write_entries(files: dict[str, bytes], entries: list[dict]) -> None:
    files["ledger.jsonl"] = "\n".join(json.dumps(e, sort_keys=True) for e in entries).encode()
    manifest = json.loads(files["manifest.json"])
    manifest["files"]["ledger.jsonl"]["sha256"] = hashlib.sha256(files["ledger.jsonl"]).hexdigest()
    files["manifest.json"] = json.dumps(manifest).encode()


def _recompute_chain(entries: list[dict]) -> None:
    prev = dv.GENESIS
    for e in entries:
        e["prev_hash"] = prev
        e["content_hash"] = dv._entry_hash(e)
        prev = e["content_hash"]


class VerifierTest(unittest.TestCase):
    def setUp(self):
        import tempfile

        self.tmp = Path(tempfile.mkdtemp())

    def _failing(self, files: dict[str, bytes], check_id: str) -> str:
        path = _rezip(files, self.tmp, "case.zip")
        rep = dv.verify_bundle(str(path))
        self.assertFalse(rep.ok, "expected verification to fail")
        failing = {c["id"]: c for c in rep.checks if not c["ok"]}
        self.assertIn(check_id, failing, f"expected {check_id} to fail; got {sorted(failing)}")
        return failing[check_id]["detail"]

    # -- the happy path -----------------------------------------------------

    def test_valid_bundle_passes_and_exits_zero(self):
        rep = dv.verify_bundle(str(FIXTURE))
        self.assertTrue(rep.ok, rep.to_dict())
        self.assertEqual(dv.main([str(FIXTURE)]), 0)

    # -- exit-criteria tamper scenarios --------------------------------------

    def test_altered_entry_is_detected(self):
        files = _load()
        entries = _entries(files)
        entries[0]["payload_json"] = entries[0]["payload_json"].replace("a-one", "a-1")
        _write_entries(files, entries)
        detail = self._failing(files, "chain-hashes")
        self.assertIn("content_hash mismatch at seq 1", detail)

    def test_removed_entry_is_detected(self):
        files = _load()
        entries = _entries(files)
        del entries[1]
        _write_entries(files, entries)
        detail = self._failing(files, "sequence-continuity")
        self.assertIn("not contiguous", detail)

    def test_forged_anchor_is_detected(self):
        files = _load()
        anchors = json.loads(files["anchors.json"])
        anchors[0]["ledger_hash"] = "f" * 64
        files["anchors.json"] = json.dumps(anchors).encode()
        manifest = json.loads(files["manifest.json"])
        manifest["files"]["anchors.json"]["sha256"] = hashlib.sha256(files["anchors.json"]).hexdigest()
        files["manifest.json"] = json.dumps(manifest).encode()
        detail = self._failing(files, "anchors")
        self.assertIn("forged anchor or rewritten chain", detail)

    def test_mismatched_continuity_statement_is_detected(self):
        files = _load()
        manifest = json.loads(files["manifest.json"])
        # The manifest claims fewer omissions than the PDF was built with.
        omitted = manifest["continuity"]["omitted_from_pdf"]
        dropped = omitted["seqs"].pop()
        omitted["count"] -= 1
        manifest["continuity"]["rendered_in_pdf"]["seqs"].append(dropped)
        manifest["continuity"]["rendered_in_pdf"]["count"] += 1
        files["manifest.json"] = json.dumps(manifest).encode()
        detail = self._failing(files, "pdf-continuity")
        self.assertIn("disagree", detail)

    def test_rewritten_historical_name_across_rename_boundary_is_detected(self):
        """The rebranding rewrite: a payload's historical product name is
        'helpfully' updated. Naive version — hashes left alone."""
        files = _load()
        entries = _entries(files)
        # The fixture's first payload plays the role of the historical text.
        target = entries[0]
        self.assertIn("a-one", target["payload_json"])
        target["payload_json"] = target["payload_json"].replace("a-one", "NewBrand-one")
        _write_entries(files, entries)
        detail = self._failing(files, "chain-hashes")
        self.assertIn("stored bytes were altered", detail)

    def test_consistent_rewrite_across_rename_boundary_fails_against_anchor(self):
        """The competent rebranding rewrite: hashes recomputed for the whole
        chain. Self-consistent — only the anchor catches it."""
        files = _load()
        entries = _entries(files)
        entries[0]["payload_json"] = entries[0]["payload_json"].replace("a-one", "NewBrand-one")
        _recompute_chain(entries)
        _write_entries(files, entries)
        # Make the continuity statement + PDF consistent with the rewrite, as
        # the attacker controls the exporter. PDF /Subject is regenerated too.
        manifest = json.loads(files["manifest.json"])
        manifest["continuity"]["head_hash"] = entries[-1]["content_hash"]
        files["manifest.json"] = json.dumps(manifest).encode()
        subject = json.dumps(manifest["continuity"], sort_keys=True, separators=(",", ":"))
        files["evidence.pdf"] = (
            b"%PDF-1.4 minimal\n/Subject (" + subject.encode() + b")\n/Producer"
        )
        manifest["files"]["ledger.jsonl"]["sha256"] = hashlib.sha256(files["ledger.jsonl"]).hexdigest()
        manifest["files"]["evidence.pdf"]["sha256"] = hashlib.sha256(files["evidence.pdf"]).hexdigest()
        files["manifest.json"] = json.dumps(manifest).encode()

        detail = self._failing(files, "anchors")
        self.assertIn("forged anchor or rewritten chain", detail)

    # -- subject_type boundary ----------------------------------------------

    def test_pre_v3_entry_with_subject_type_is_flagged(self):
        files = _load()
        entries = _entries(files)
        captured = next(e for e in entries if e["event_type"] == "artefact.captured")
        payload = json.loads(captured["payload_json"])
        payload["schema_version"] = 2  # claim pre-boundary form but keep the field
        captured["payload_json"] = json.dumps(payload, sort_keys=True, separators=(",", ":"))
        _recompute_chain(entries)
        _write_entries(files, entries)
        detail = self._failing(files, "subject-type-boundary")
        self.assertIn("pre-v3 entry carries subject_type", detail)

    def test_v3_entry_missing_subject_type_is_flagged(self):
        files = _load()
        entries = _entries(files)
        captured = next(e for e in entries if e["event_type"] == "artefact.captured")
        payload = json.loads(captured["payload_json"])
        payload.pop("subject_type")
        captured["payload_json"] = json.dumps(payload, sort_keys=True, separators=(",", ":"))
        _recompute_chain(entries)
        _write_entries(files, entries)
        detail = self._failing(files, "subject-type-boundary")
        self.assertIn("missing subject_type", detail)

    # -- signatures ----------------------------------------------------------

    def test_tampered_artefact_content_fails_signature(self):
        files = _load()
        artefacts = json.loads(files["artefacts.json"])
        artefacts[0]["content"] = artefacts[0]["content"] + " /* tampered */"
        files["artefacts.json"] = json.dumps(artefacts).encode()
        manifest = json.loads(files["manifest.json"])
        manifest["files"]["artefacts.json"]["sha256"] = hashlib.sha256(files["artefacts.json"]).hexdigest()
        files["manifest.json"] = json.dumps(manifest).encode()
        detail = self._failing(files, "actor-signatures")
        self.assertIn("does not verify", detail)

    # -- undeclared filter ---------------------------------------------------

    def test_unknown_filter_predicate_fails(self):
        files = _load()
        manifest = json.loads(files["manifest.json"])
        manifest["continuity"]["filter"]["predicate"] = {"type": "secret-sauce"}
        files["manifest.json"] = json.dumps(manifest).encode()
        detail = self._failing(files, "declared-filter")
        self.assertIn("uncheckable", detail)


class Ed25519Test(unittest.TestCase):
    """RFC 8032 §7.1 test vectors."""

    def test_rfc8032_test1_empty_message(self):
        pub = bytes.fromhex(
            "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
        )
        sig = bytes.fromhex(
            "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155"
            "5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"
        )
        self.assertTrue(dv.ed25519_verify(pub, sig, b""))
        self.assertFalse(dv.ed25519_verify(pub, sig, b"x"))
        self.assertFalse(dv.ed25519_verify(pub, sig[:-1] + b"\x00", b""))

    def test_rfc8032_test2_one_byte(self):
        pub = bytes.fromhex(
            "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c"
        )
        sig = bytes.fromhex(
            "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da"
            "085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00"
        )
        self.assertTrue(dv.ed25519_verify(pub, sig, b"\x72"))


if __name__ == "__main__":
    unittest.main()
