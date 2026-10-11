"""Tests for domokos-verify (spec 2.0). Standard library unittest only.

    python -m unittest discover -s tests

The bundle vectors in fixtures/vectors/spec-2.0 are a copy of the vectors
the Domokos product generates (scripts/make_test_vectors.py). Tests that
need pyca/cryptography skip when it is absent; the stdlib-only behaviour has
its own tests.
"""

from __future__ import annotations

import contextlib
import hashlib
import io
import json
import os
import sys
import unittest
from unittest import mock

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)

import domokos_verify as dv  # noqa: E402

VECTORS = os.path.join(ROOT, "fixtures", "vectors", "spec-2.0")
with open(os.path.join(VECTORS, "expected.json"), encoding="utf-8") as _f:
    EXPECTED = json.load(_f)
ROOTS = [os.path.join(VECTORS, r) for r in EXPECTED["tsa_roots"]]
with open(os.path.join(ROOT, "fixtures", "sectigo_rfc3161_token.der"), "rb") as _f:
    SECTIGO_TOKEN = _f.read()
SECTIGO_HEAD = hashlib.sha256(b"domokos live probe").hexdigest()
SECTIGO_R46 = "4941b001b8a97e961b7817c9d9e960ec4b056bfc915a8c1aabf6ef6b3ac046a5"
HAVE_CRYPTO = dv._crypto() is not None
needs_crypto = unittest.skipUnless(HAVE_CRYPTO, "pyca/cryptography is not installed")


def vector(name: str) -> str:
    return os.path.join(VECTORS, name)


def run_cli(*args: str):
    out = io.StringIO()
    with contextlib.redirect_stdout(out):
        code = dv.main(list(args))
    return code, out.getvalue()


def failed(rep) -> list:
    return sorted(c["id"] for c in rep.checks if not c["ok"])


class CanonicalJSONTest(unittest.TestCase):
    def test_keys_sort_by_utf16_code_units(self):
        # RFC 8785 section 3.2.3 sorting example.
        value = {"€": "Euro Sign", "\r": "Carriage Return", "דּ": "Hebrew Letter Dalet With Dagesh",
                 "1": "One", "\U0001f600": "Emoji: Grinning Face", "\u0080": "Control", "ö": "Latin Small Letter O With Diaeresis"}
        keys = list(json.loads(dv.canonical(value)))
        self.assertEqual(keys, ["\r", "1", "\u0080", "ö", "€", "\U0001f600", "דּ"])

    def test_strings_escape_like_json_stringify(self):
        self.assertEqual(dv.canonical("a\"b\\c\b\t\n\f\r\x01\x1f\x7f é"),
                         '"a\\"b\\\\c\\b\\t\\n\\f\\r\\u0001\\u001f\x7f é"')

    def test_no_whitespace_and_nested_values(self):
        self.assertEqual(dv.canonical({"b": [1, True, None, {"a": "x"}], "a": -0}), '{"a":0,"b":[1,true,null,{"a":"x"}]}')

    def test_floats_large_integers_and_lone_surrogates_have_no_canonical_form(self):
        for bad in (1.5, 2**53, -(2**53), "\ud800", {1: "x"}):
            with self.assertRaises(dv.CanonicalError):
                dv.canonical(bad)

    def test_strict_parser_rejects_floats_constants_and_duplicate_keys(self):
        for text in ('{"a":1.0}', '{"a":1e3}', '{"a":NaN}', '{"a":1,"a":2}'):
            with self.assertRaises(dv.CanonicalError):
                dv.parse_strict(text)
        self.assertEqual(dv.parse_strict('{"a":[1,2]}'), {"a": [1, 2]})


class Ed25519Test(unittest.TestCase):
    def test_rfc8032_test_vector_1(self):
        pub = bytes.fromhex("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")
        sig = bytes.fromhex("e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155"
                            "5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b")
        self.assertTrue(dv.ed25519_verify(pub, sig, b""))
        self.assertFalse(dv.ed25519_verify(pub, sig, b"x"))


class DERAndTokenTest(unittest.TestCase):
    def test_malformed_tokens_are_rejected(self):
        for token in (b"", b"\x00\x01garbage", b"\x30\x03\x02\x01\x00", b"\x30\x82\xff\xff",
                      b"\x30\x80\x00\x00", b"\x30\x00\x00", b"\x30\x81\x05\x02\x01\x00\x02\x01\x00"):
            with self.assertRaises(dv.TokenError):
                dv.verify_token(token, SECTIGO_HEAD, dv.pinned_roots())

    def test_random_bytes_holding_the_imprint_are_rejected(self):
        imprint = hashlib.sha256(SECTIGO_HEAD.encode()).digest()
        with self.assertRaises(dv.TokenError):
            dv.verify_token(os.urandom(40) + imprint + os.urandom(40), SECTIGO_HEAD, dv.pinned_roots())

    def test_embedded_root_is_sectigo_r46(self):
        self.assertIn(SECTIGO_R46, dv.pinned_roots())

    @needs_crypto
    def test_real_sectigo_token_verifies_against_the_embedded_root(self):
        r = dv.verify_token(SECTIGO_TOKEN, SECTIGO_HEAD, dv.pinned_roots())
        self.assertTrue(r.cryptographically_verified)
        self.assertEqual(r.root_fingerprint, SECTIGO_R46)
        self.assertTrue(r.gen_time.startswith("2026-10-11T"))

    def test_real_sectigo_token_is_rejected_for_another_hash_or_without_its_root(self):
        with self.assertRaisesRegex(dv.TokenError, "imprint"):
            dv.verify_token(SECTIGO_TOKEN, "0" * 64, dv.pinned_roots())
        with self.assertRaisesRegex(dv.TokenError, "pinned root"):
            dv.verify_token(SECTIGO_TOKEN, SECTIGO_HEAD, {})

    @needs_crypto
    def test_one_flipped_byte_in_the_real_token_is_rejected(self):
        tampered = bytearray(SECTIGO_TOKEN)
        tampered[len(tampered) // 2] ^= 0x01
        with self.assertRaises(dv.TokenError):
            dv.verify_token(bytes(tampered), SECTIGO_HEAD, dv.pinned_roots())

    def test_without_cryptography_the_structure_is_checked_but_not_the_signatures(self):
        with mock.patch.object(dv, "_crypto", return_value=None):
            r = dv.verify_token(SECTIGO_TOKEN, SECTIGO_HEAD, dv.pinned_roots())
        self.assertFalse(r.cryptographically_verified)
        self.assertEqual(r.root_fingerprint, SECTIGO_R46)


class VectorTest(unittest.TestCase):
    """Spec 2.0 §11: the valid vector verifies, every tamper vector does not."""

    @needs_crypto
    def test_every_vector_matches_its_expectation(self):
        for name, spec in EXPECTED["vectors"].items():
            with self.subTest(vector=name):
                rep = dv.verify_bundle(vector(name), tsa_roots=ROOTS)
                want = spec["must_fail"]
                self.assertTrue(set(want) <= set(failed(rep)), f"{name}: {failed(rep)}")
                self.assertEqual(rep.ok, not want, f"{name}: {failed(rep)}")

    def test_review_probes_are_all_present(self):
        for probe in ("resign", "forged_attestation", "downgrade", "truncate", "rehash", "faketsa",
                      "pipe_collision"):
            self.assertTrue(EXPECTED["vectors"][f"{probe}.zip"]["must_fail"], probe)

    def test_hash_only_tamper_vectors_fail_without_cryptography(self):
        with mock.patch.object(dv, "_crypto", return_value=None):
            for name in ("pipe_collision.zip", "noncanonical.zip", "forged_attestation.zip", "rehash.zip",
                         "faketsa.zip", "truncate.zip"):
                with self.subTest(vector=name):
                    rep = dv.verify_bundle(vector(name), tsa_roots=ROOTS, strict=False)
                    self.assertFalse(rep.ok)

    @needs_crypto
    def test_test_roots_are_not_trusted_unless_pinned(self):
        rep = dv.verify_bundle(vector("valid.zip"))
        self.assertEqual(failed(rep), ["anchors"])
        detail = next(c["detail"] for c in rep.checks if c["id"] == "anchors")
        self.assertIn("pinned root", detail)


class StrictModeTest(unittest.TestCase):
    def test_strict_mode_fails_unverifiable_tokens(self):
        with mock.patch.object(dv, "_crypto", return_value=None):
            rep = dv.verify_bundle(vector("valid.zip"), tsa_roots=ROOTS)
        self.assertTrue(rep.strict)
        self.assertEqual(failed(rep), ["anchors"])

    def test_non_strict_mode_reports_them_instead(self):
        with mock.patch.object(dv, "_crypto", return_value=None):
            rep = dv.verify_bundle(vector("valid.zip"), tsa_roots=ROOTS, strict=False)
        self.assertTrue(rep.ok)
        self.assertTrue(any("non-strict" in n for n in rep.notes))
        self.assertIsNone(rep.timestamps["last_externally_timestamped_seq"])


class TimestampReportTest(unittest.TestCase):
    """REQ-VER-04: last externally timestamped seq and later entries."""

    @needs_crypto
    def test_valid_vector_is_fully_timestamped(self):
        rep = dv.verify_bundle(vector("valid.zip"), tsa_roots=ROOTS)
        head = rep.timestamps["last_externally_timestamped_seq"]
        self.assertIsInstance(head, int)
        self.assertEqual(rep.timestamps["not_yet_externally_timestamped"], [])
        self.assertEqual(rep.timestamps["timestamped_later_than_15_minutes"], [])

    def test_local_only_anchors_leave_every_entry_pending(self):
        rep = dv.verify_bundle(vector("anchor_downgrade.zip"), tsa_roots=ROOTS)
        self.assertIsNone(rep.timestamps["last_externally_timestamped_seq"])
        self.assertTrue(rep.timestamps["not_yet_externally_timestamped"])
        self.assertTrue(any("not yet externally timestamped" in n for n in rep.notes))


class OutputTest(unittest.TestCase):
    @needs_crypto
    def test_cli_exit_codes_and_wording(self):
        roots = sum((["--tsa-root", r] for r in ROOTS), [])
        code, out = run_cli(vector("valid.zip"), *roots)
        self.assertEqual(code, 0)
        self.assertIn("VERIFIED: every check", out)
        code, out = run_cli(vector("rehash.zip"), *roots)
        self.assertEqual(code, 1)
        self.assertIn("[NOT VERIFIED] Anchors", out)
        # Verdict labels are not used (Domokos boundary B-2).
        for word in ("PASS", "FAIL", "compliant"):
            self.assertNotIn(word, out)

    def test_json_report_shape(self):
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            dv.main([vector("anchor_downgrade.zip"), "--json", "-"])
        text = out.getvalue()
        report = json.loads(text[text.index("{\n"):])
        self.assertEqual(report["spec"], "domokos-bundle/2")
        self.assertEqual(set(report), {"bundle", "spec", "verifier_version", "strict", "ok", "checks",
                                       "timestamps", "notes"})
        self.assertEqual({c["id"] for c in report["checks"]},
                         {"manifest-files", "chain-hashes", "sequence-continuity", "declared-filter",
                          "void-entries", "projection", "subject-type-boundary", "signatures", "anchors",
                          "timestamps", "pdf-continuity", "gap-register"})

    def test_unreadable_bundle_is_reported(self):
        rep = dv.verify_bundle(os.path.join(VECTORS, "expected.json"))
        self.assertFalse(rep.ok)

    def test_charter_needs_a_version(self):
        with self.assertRaises(SystemExit) as cm, contextlib.redirect_stderr(io.StringIO()):
            dv.main([vector("valid.zip"), "--charter", "x.md"])
        self.assertEqual(cm.exception.code, 2)


class CharterTest(unittest.TestCase):
    def setUp(self):
        self.doc = os.path.join(VECTORS, EXPECTED["charter"]["file"])
        self.version = EXPECTED["charter"]["version"]

    def _charter_check(self, doc, version):
        rep = dv.verify_bundle(vector("valid.zip"), tsa_roots=ROOTS, charter=doc, charter_version=version)
        return next(c for c in rep.checks if c["id"] == "charter")

    def test_recorded_charter_matches(self):
        self.assertTrue(self._charter_check(self.doc, self.version)["ok"])

    def test_unknown_version_and_edited_text_are_reported(self):
        self.assertIn("no charter.recorded entry", self._charter_check(self.doc, "9.9.9")["detail"])
        import tempfile

        with open(self.doc, "rb") as src:
            text = src.read()
        with tempfile.NamedTemporaryFile("wb", suffix=".md", delete=False) as f:
            f.write(text + b"\nedited\n")
        try:
            check = self._charter_check(f.name, self.version)
        finally:
            os.unlink(f.name)
        self.assertFalse(check["ok"])
        self.assertIn("differs from the record", check["detail"])


if __name__ == "__main__":
    unittest.main()
