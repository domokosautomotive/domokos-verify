#!/usr/bin/env python3
"""
domokos-verify — independent verifier for Domokos evidence bundles.

Implements SPEC.md (format "domokos-bundle/2", spec 2.0.0) and nothing else:
no Domokos code and no shared library. The core is Python 3.9+ standard
library only, in one file. Verifying the signatures and certificate chains
of RFC 3161 timestamp tokens uses pyca/cryptography, the single documented
dependency; without it those tokens are reported as unverified, which fails
the run in strict mode (the default).

    python3 domokos_verify.py bundle.zip
    python3 domokos_verify.py bundle.zip --json report.json
    python3 domokos_verify.py bundle.zip --tsa-root extra-root.pem
    python3 domokos_verify.py bundle.zip --charter CHARTER.md --version 2.0.0

Exit code 0 iff every check is verified; 1 otherwise; 2 for usage errors.
Every check runs even after a problem, so one run reports everything.

Licensed under the Apache License, Version 2.0.
"""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
import re
import sys
import zipfile
from datetime import datetime, timedelta, timezone
from typing import Any, Callable, Dict, List, Optional, Tuple

__version__ = "2.0.0"
SPEC = "domokos-bundle/2"
SPEC_VERSION = "2.0.0"
HASH_SCHEME = 2
PROJECTION_VERSION = 2
LIFECYCLE_DEFAULTS: Dict[str, Any] = {
    "regulatory_mappings": [], "misra_findings": [], "flags": [], "review": None, "attestation": None,
    "audit_state": "draft", "provenance_amendments": [],
}
GENESIS = "0" * 64
LEGACY_SIGNATURE_MARKER = "LEGACY-UNSIGNED"
SIGNATURE_KIND = "platform attestation (server-held key)"
MAX_SAFE_INTEGER = 2**53 - 1
WINDOW = timedelta(minutes=15)
LEDGER_FIELDS = {"seq", "captured_at", "actor_id", "event_type", "payload_json", "prev_hash", "content_hash"}
CHARTER_EVENT_TYPES = ("charter.recorded", "charter.published")

# Pinned timestamp-authority roots (SPEC §6, rule 7). Additional roots, for
# example an engagement's second authority, are added with --tsa-root.
PINNED_ROOTS_PEM = {
    "Sectigo Public Time Stamping Root R46": """
-----BEGIN CERTIFICATE-----
MIIFejCCA2KgAwIBAgIQeD0FbPqDLn5p+FYidp8CuTANBgkqhkiG9w0BAQwFADBX
MQswCQYDVQQGEwJHQjEYMBYGA1UEChMPU2VjdGlnbyBMaW1pdGVkMS4wLAYDVQQD
EyVTZWN0aWdvIFB1YmxpYyBUaW1lIFN0YW1waW5nIFJvb3QgUjQ2MB4XDTIxMDMy
MjAwMDAwMFoXDTQ2MDMyMTIzNTk1OVowVzELMAkGA1UEBhMCR0IxGDAWBgNVBAoT
D1NlY3RpZ28gTGltaXRlZDEuMCwGA1UEAxMlU2VjdGlnbyBQdWJsaWMgVGltZSBT
dGFtcGluZyBSb290IFI0NjCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIB
AIid2LlFZ50d3ei5JoGaVFTAfEkFm8xaFQ/ZlBBEtEFAgXcUmanU5HYsyAhTXiDQ
kiUvpVdYqZ1uYoZEMgtHES1l1Cc6HaqZzEbOOp6YiTx63ywTon434aXVydmhx7Dx
4IBrAou7hNGsKioIBPy5GMN7KmgYmuu4f92sKKjbxqohUSfjk1mJlAjthgF7Hjx4
vvyVDQGsd5KarLW5d73E3ThobSkob2SL48LpUR/O627pDchxll+bTSv1gASn/hp6
IuHJorEu6EopoB1CNFp/+HpTXeNARXUmdRMKbnXWflq+/g36NJXB35ZvxQw6zid6
1qmrlD/IbKJA6COw/8lFSPQwBP1ityZdwuCysCKZ9ZjczMqbUcLFyq6KdOpuzVDR
3ZUwxDKL1wCAxgL2Mpz7eZbrb/JWXiOcNzDpQsmwGQ6Stw8tTCqPumhLRPb7YkzM
8/6NnWH3T9ClmcGSF22LEyJYNWCHrQqYubNeKolzqUbCqhSqmr/UdUeb49zYHr7A
LL8bAJyPDmubNqMtuaobKASBqP84uhqcRY/pjnYd+V5/dcu9ieERjiRKKsxCG1t6
tG9oj7liwPddXEcYGOUiWLm742st50jGwTzxbMpepmOP1mLnJskvZaN5e45NuzAH
teORlsSuDt5t4BBRCJL+5EZnnw0ezntk9R8QJyAkL6/bAgMBAAGjQjBAMB0GA1Ud
DgQWBBT2d2rdP/0BE/8WoWyCAi/QCj0UJTAOBgNVHQ8BAf8EBAMCAYYwDwYDVR0T
AQH/BAUwAwEB/zANBgkqhkiG9w0BAQwFAAOCAgEACv68sZqZvmHk7JoU7AfTEZ7b
X45u40OrLX/6vzHQAwDg1TB00bWbiwj+7+we60BP8AMsw1h5NCXWxeyvrEVC54Mi
rwVrcF6SFGjRwRoelRuiaZ5FDO4oWhaePjZx3/jkQ7j653CA5WscYqlneLXBEZiY
o6rRNqnsZHZTQ606mlkNpsy3TFMADv5whZmilVEZ83OvydfH2DNL3FTkpZG7+lHS
1DFHMSUB5UtSSeSRg2UWTXwU5oObGjFk/35fC/dlF+nJIXdqsw0TZSS86bi5GRCJ
VjqjnkpZ0Jut7ucEv4PNOIU8ijkMRj17QPjHMtdy+WxBDDSdas/UFTVB/GF+Fofn
OD3iZ4tXxFjPU3EWRcMWx8fcGyzlBfcjeoPNbNC7wfyV9Qkzfk2Bd48jGxG7OThY
Wolc56vmBHqDEfguDwYc9AeWirMVRDi+WYlsktzAEObiFoPqs+LWU5q7+Q1+nEcs
tNuDIedeBRcHmtjL2hV3luuEWwDSnRhSjhPLPXzqpJ1rG3r4yqm1NjKg5A5QO9Az
veHqRQldluTSKuu96oPEPusL2oF+4MxkJ+SQMGFWTw/PNCblUN8GXeL5+mR20diP
5LiJMq8U3IpM/0Q7OFFQ+lXuYFIuDvUprWBPsp5La2WhL2+iLVVXItSl7up5yQqX
XftzTXTX48FRiJ6PA9o=
-----END CERTIFICATE-----
""",
}


# ===========================================================================
# Canonical JSON (SPEC §1)
# ===========================================================================


class CanonicalError(ValueError):
    pass


def _reject_float(text: str) -> Any:
    raise CanonicalError(f"number {text} is not an integer (floats are not allowed)")


def _reject_constant(text: str) -> Any:
    raise CanonicalError(f"{text} is not JSON")


def _unique_object(pairs: List[Tuple[str, Any]]) -> Dict[str, Any]:
    out: Dict[str, Any] = {}
    for key, value in pairs:
        if key in out:
            raise CanonicalError(f"duplicate object key {key!r}")
        out[key] = value
    return out


def parse_strict(text: str) -> Any:
    """Parse JSON under the ledger's rules: integers only, unique keys."""
    return json.loads(text, parse_float=_reject_float, parse_constant=_reject_constant,
                      object_pairs_hook=_unique_object)


def _string(s: str) -> str:
    try:
        s.encode("utf-8")
    except UnicodeEncodeError as exc:
        raise CanonicalError("string contains a lone surrogate") from exc
    out = ['"']
    for ch in s:
        code = ord(ch)
        if ch == '"':
            out.append('\\"')
        elif ch == "\\":
            out.append("\\\\")
        elif ch == "\b":
            out.append("\\b")
        elif ch == "\t":
            out.append("\\t")
        elif ch == "\n":
            out.append("\\n")
        elif ch == "\f":
            out.append("\\f")
        elif ch == "\r":
            out.append("\\r")
        elif code < 0x20:
            out.append("\\u%04x" % code)
        else:
            out.append(ch)
    out.append('"')
    return "".join(out)


def canonical(value: Any) -> str:
    if value is None:
        return "null"
    if value is True:
        return "true"
    if value is False:
        return "false"
    if isinstance(value, int):
        if abs(value) > MAX_SAFE_INTEGER:
            raise CanonicalError("integer outside the I-JSON safe range")
        return str(value)
    if isinstance(value, float):
        raise CanonicalError("floats are not allowed")
    if isinstance(value, str):
        return _string(value)
    if isinstance(value, list):
        return "[" + ",".join(canonical(v) for v in value) + "]"
    if isinstance(value, dict):
        if not all(isinstance(k, str) for k in value):
            raise CanonicalError("object keys must be strings")
        keys = sorted(value, key=lambda k: k.encode("utf-16-be"))
        return "{" + ",".join(_string(k) + ":" + canonical(value[k]) for k in keys) + "}"
    raise CanonicalError(f"{type(value).__name__} has no canonical form")


def canonical_bytes(value: Any) -> bytes:
    return canonical(value).encode("utf-8")


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def entry_hash(e: Dict[str, Any], payload: Any) -> str:
    return sha256_hex(canonical_bytes({
        "actor": e["actor_id"], "captured_at": e["captured_at"], "event_type": e["event_type"],
        "payload": payload, "prev_hash": e["prev_hash"], "seq": e["seq"],
    }))


# ===========================================================================
# Ed25519 verification — RFC 8032, self-contained
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
_B = (_Bx, _By, 1, (_Bx * _By) % _p)


def _pt_add(P, Q):
    (X1, Y1, Z1, T1), (X2, Y2, Z2, T2) = P, Q
    A = ((Y1 - X1) * (Y2 - X2)) % _p
    Bv = ((Y1 + X1) * (Y2 + X2)) % _p
    C = (2 * T1 * T2 * _d) % _p
    D = (2 * Z1 * Z2) % _p
    E, F, G, H = Bv - A, D - C, D + C, Bv + A
    return ((E * F) % _p, (G * H) % _p, (F * G) % _p, (E * H) % _p)


def _pt_mul(s: int, P):
    Q = (0, 1, 1, 0)
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
    if (-x * x + y * y - 1 - _d * x * x * y * y) % _p != 0:
        raise ValueError("point not on curve")
    return (x, y, 1, (x * y) % _p)


def ed25519_verify(public_key: bytes, signature: bytes, message: bytes) -> bool:
    try:
        if len(signature) != 64:
            return False
        R = _pt_decode(signature[:32])
        A = _pt_decode(public_key)
        S = int.from_bytes(signature[32:], "little")
        if S >= _q:
            return False
        h = int.from_bytes(hashlib.sha512(signature[:32] + public_key + message).digest(), "little") % _q
        return _pt_encode(_pt_mul(S, _B)) == _pt_encode(_pt_add(R, _pt_mul(h, A)))
    except ValueError:
        return False


# ===========================================================================
# DER parser (standard library) for timestamp tokens and certificates
# ===========================================================================


class DERError(ValueError):
    pass


class Node:
    """One DER TLV. `raw` is the whole encoding, `value` the contents."""

    __slots__ = ("cls", "constructed", "number", "raw", "value")

    def __init__(self, cls: int, constructed: bool, number: int, raw: bytes, value: bytes):
        self.cls, self.constructed, self.number, self.raw, self.value = cls, constructed, number, raw, value

    @property
    def universal(self) -> bool:
        return self.cls == 0

    def is_tag(self, number: int, cls: int = 0) -> bool:
        return self.cls == cls and self.number == number

    def children(self) -> List["Node"]:
        if not self.constructed:
            raise DERError("primitive value has no children")
        return parse_all(self.value)

    def expect(self, number: int, cls: int = 0) -> "Node":
        if not self.is_tag(number, cls):
            raise DERError(f"expected tag {cls}:{number}, found {self.cls}:{self.number}")
        return self


def _read(data: bytes, pos: int) -> Tuple[Node, int]:
    if pos >= len(data):
        raise DERError("truncated")
    start = pos
    first = data[pos]
    pos += 1
    cls, constructed, number = first >> 6, bool(first & 0x20), first & 0x1F
    if number == 0x1F:
        number = 0
        while True:
            if pos >= len(data):
                raise DERError("truncated tag")
            b = data[pos]
            pos += 1
            number = (number << 7) | (b & 0x7F)
            if not b & 0x80:
                break
    if pos >= len(data):
        raise DERError("truncated length")
    length = data[pos]
    pos += 1
    if length & 0x80:
        n = length & 0x7F
        if n == 0 or n > 4:
            raise DERError("indefinite or oversized length")
        if pos + n > len(data):
            raise DERError("truncated length")
        length = int.from_bytes(data[pos:pos + n], "big")
        if length < 0x80 or data[pos] == 0:
            raise DERError("non-minimal length")
        pos += n
    end = pos + length
    if end > len(data):
        raise DERError("value runs past the end")
    return Node(cls, constructed, number, data[start:end], data[pos:end]), end


def parse_one(data: bytes) -> Node:
    node, end = _read(data, 0)
    if end != len(data):
        raise DERError("trailing bytes after DER value")
    return node


def parse_all(data: bytes) -> List[Node]:
    out, pos = [], 0
    while pos < len(data):
        node, pos = _read(data, pos)
        out.append(node)
    return out


def der_oid(node: Node) -> str:
    node.expect(6)
    v = node.value
    if not v:
        raise DERError("empty OID")
    parts, n = [], 0
    for b in v:
        n = (n << 7) | (b & 0x7F)
        if not b & 0x80:
            parts.append(n)
            n = 0
    first = parts[0]
    head = [0, first] if first < 40 else ([1, first - 40] if first < 80 else [2, first - 80])
    return ".".join(str(x) for x in head + parts[1:])


def der_int(node: Node) -> int:
    node.expect(2)
    return int.from_bytes(node.value, "big", signed=True)


def der_time(node: Node) -> datetime:
    text = node.value.decode("ascii")
    if node.is_tag(24):  # GeneralizedTime
        m = re.fullmatch(r"(\d{14})(?:\.(\d{1,6}))?Z", text)
        if not m:
            raise DERError(f"unsupported GeneralizedTime {text!r}")
        base = datetime.strptime(m.group(1), "%Y%m%d%H%M%S")
        micro = int((m.group(2) or "0").ljust(6, "0"))
        return base.replace(microsecond=micro, tzinfo=timezone.utc)
    if node.is_tag(23):  # UTCTime
        m = re.fullmatch(r"(\d{2})(\d{10})Z", text)
        if not m:
            raise DERError(f"unsupported UTCTime {text!r}")
        year = int(m.group(1))
        year += 2000 if year < 50 else 1900
        return datetime.strptime(str(year) + m.group(2), "%Y%m%d%H%M%S").replace(tzinfo=timezone.utc)
    raise DERError("expected a time value")


def format_time(t: datetime) -> str:
    return t.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def parse_time(text: str) -> datetime:
    return datetime.strptime(text, "%Y-%m-%dT%H:%M:%S.%fZ").replace(tzinfo=timezone.utc)


OID_SIGNED_DATA = "1.2.840.113549.1.7.2"
OID_TST_INFO = "1.2.840.113549.1.9.16.1.4"
OID_CONTENT_TYPE = "1.2.840.113549.1.9.3"
OID_MESSAGE_DIGEST = "1.2.840.113549.1.9.4"
OID_SIGNING_CERT = "1.2.840.113549.1.9.16.2.12"
OID_SIGNING_CERT_V2 = "1.2.840.113549.1.9.16.2.47"
OID_EKU = "2.5.29.37"
OID_SKI = "2.5.29.14"
OID_TIME_STAMPING = "1.3.6.1.5.5.7.3.8"
OID_RSASSA_PSS = "1.2.840.113549.1.1.10"
DIGESTS = {
    "1.3.14.3.2.26": "sha1",
    "2.16.840.1.101.3.4.2.1": "sha256",
    "2.16.840.1.101.3.4.2.2": "sha384",
    "2.16.840.1.101.3.4.2.3": "sha512",
}
IMPRINT_DIGESTS = ("sha256", "sha384", "sha512")


class TokenError(ValueError):
    pass


class Cert:
    """The fields of an X.509 certificate this verifier needs, parsed with
    the DER parser above."""

    def __init__(self, der: bytes):
        self.der = der
        top = parse_one(der).expect(16).children()
        tbs = top[0].expect(16).children()
        i = 1 if tbs[0].is_tag(0, 2) else 0
        self.serial = der_int(tbs[i])
        self.issuer = tbs[i + 2].expect(16).raw
        validity = tbs[i + 3].expect(16).children()
        self.not_before, self.not_after = der_time(validity[0]), der_time(validity[1])
        self.subject = tbs[i + 4].expect(16).raw
        self.extensions: Dict[str, Tuple[bool, bytes]] = {}
        for node in tbs[i + 6:]:
            if node.is_tag(3, 2):
                for ext in node.children()[0].expect(16).children():
                    parts = ext.children()
                    critical = len(parts) == 3 and parts[1].is_tag(1) and parts[1].value != b"\x00"
                    self.extensions[der_oid(parts[0])] = (critical, parts[-1].expect(4).value)
        self.fingerprint = sha256_hex(der)

    def valid_at(self, when: datetime) -> bool:
        return self.not_before <= when <= self.not_after

    def key_identifier(self) -> Optional[bytes]:
        ext = self.extensions.get(OID_SKI)
        return parse_one(ext[1]).expect(4).value if ext else None

    def eku(self) -> Tuple[bool, List[str]]:
        ext = self.extensions.get(OID_EKU)
        if ext is None:
            return False, []
        return ext[0], [der_oid(n) for n in parse_one(ext[1]).expect(16).children()]


def load_pem_certs(text: str) -> List[Cert]:
    import base64

    certs = []
    for block in re.findall(r"-----BEGIN CERTIFICATE-----(.*?)-----END CERTIFICATE-----", text, re.DOTALL):
        certs.append(Cert(base64.b64decode("".join(block.split()))))
    return certs


def _crypto():
    """pyca/cryptography, or None when it is not installed."""
    try:
        from cryptography import x509  # noqa: F401
        return True
    except ImportError:  # pragma: no cover - exercised by the stdlib-only test
        return None


def _hash_obj(name: str):
    from cryptography.hazmat.primitives import hashes

    return {"sha1": hashes.SHA1, "sha256": hashes.SHA256, "sha384": hashes.SHA384,
            "sha512": hashes.SHA512}[name]()


def _verify_signed_attrs(signer: Cert, digest_name: str, sig_alg: Node, signature: bytes, data: bytes) -> None:
    from cryptography import x509
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa

    pub = x509.load_der_x509_certificate(signer.der).public_key()
    try:
        if isinstance(pub, rsa.RSAPublicKey):
            alg = sig_alg.children()
            if der_oid(alg[0]) == OID_RSASSA_PSS:
                params = alg[1].children() if len(alg) > 1 else []
                pss_hash, salt = "sha1", 20
                for p in params:
                    if p.is_tag(0, 2):
                        pss_hash = DIGESTS[der_oid(p.children()[0].children()[0])]
                    elif p.is_tag(2, 2):
                        salt = der_int(p.children()[0])
                pub.verify(signature, data, padding.PSS(mgf=padding.MGF1(_hash_obj(pss_hash)), salt_length=salt),
                           _hash_obj(pss_hash))
            else:
                pub.verify(signature, data, padding.PKCS1v15(), _hash_obj(digest_name))
        elif isinstance(pub, ec.EllipticCurvePublicKey):
            pub.verify(signature, data, ec.ECDSA(_hash_obj(digest_name)))
        else:
            raise TokenError(f"unsupported signer key type {type(pub).__name__}")
    except InvalidSignature:
        raise TokenError("token signature does not verify") from None


def _issued_by(child: Cert, issuer: Cert) -> bool:
    from cryptography import x509
    from cryptography.exceptions import InvalidSignature

    try:
        x509.load_der_x509_certificate(child.der).verify_directly_issued_by(
            x509.load_der_x509_certificate(issuer.der))
        return True
    except (ValueError, TypeError, InvalidSignature):
        return False


class TokenResult:
    def __init__(self) -> None:
        self.gen_time: Optional[str] = None
        self.nonce: Optional[int] = None
        self.signer_fingerprint: Optional[str] = None
        self.root_fingerprint: Optional[str] = None
        self.cryptographically_verified = False


def verify_token(token: bytes, ledger_hash: str, roots: Dict[str, Cert]) -> TokenResult:
    """SPEC §6 rules 1-7. Raises TokenError for a token shown to be wrong.
    Without pyca/cryptography, rules 5 and the chain signatures of 7 are not
    checked and the result says so."""
    res = TokenResult()
    try:
        ci = parse_one(token).expect(16).children()
        if der_oid(ci[0]) != OID_SIGNED_DATA:
            raise TokenError("token is not CMS SignedData")
        sd = ci[1].expect(0, 2).children()[0].expect(16).children()
        encap = sd[2].expect(16).children()
        if der_oid(encap[0]) != OID_TST_INFO:
            raise TokenError("encapsulated content is not a TSTInfo")
        tst_bytes = encap[1].expect(0, 2).children()[0].expect(4).value
        certs: List[Cert] = []
        signer_infos: List[Node] = []
        for node in sd[3:]:
            if node.is_tag(0, 2):
                certs = [Cert(c.raw) for c in node.children() if c.is_tag(16)]
            elif node.is_tag(17):
                signer_infos = node.children()
        tst = parse_one(tst_bytes).expect(16).children()
        imprint = tst[2].expect(16).children()
        imprint_alg = DIGESTS.get(der_oid(imprint[0].children()[0]), "unknown")
        hashed = imprint[1].expect(4).value
        gen_time = der_time(tst[4].expect(24))
        nonce = None
        for node in tst[5:]:
            if node.is_tag(2):
                nonce = der_int(node)
    except TokenError:
        raise
    except (DERError, IndexError, ValueError, UnicodeDecodeError) as exc:
        raise TokenError(f"malformed timestamp token: {exc}") from None

    if imprint_alg not in IMPRINT_DIGESTS:
        raise TokenError(f"message imprint uses {imprint_alg}, not SHA-2")
    if hashed != hashlib.new(imprint_alg, ledger_hash.encode("ascii")).digest():
        raise TokenError("message imprint does not match the anchored hash")
    res.gen_time, res.nonce = format_time(gen_time), nonce
    if len(signer_infos) != 1:
        raise TokenError(f"expected exactly one SignerInfo, found {len(signer_infos)}")
    try:
        si = signer_infos[0].expect(16).children()
        sid = si[1]
        digest_name = DIGESTS.get(der_oid(si[2].children()[0]), "unknown")
        attrs_node = si[3]
        if not attrs_node.is_tag(0, 2):
            raise TokenError("SignerInfo has no signed attributes")
        sig_alg, signature = si[4].expect(16), si[5].expect(4).value
        attrs: Dict[str, List[Node]] = {}
        for a in attrs_node.children():
            parts = a.expect(16).children()
            attrs[der_oid(parts[0])] = parts[1].expect(17).children()
    except TokenError:
        raise
    except (DERError, IndexError, ValueError) as exc:
        raise TokenError(f"malformed SignerInfo: {exc}") from None
    if digest_name == "unknown":
        raise TokenError("unsupported SignerInfo digest algorithm")
    if OID_CONTENT_TYPE not in attrs or der_oid(attrs[OID_CONTENT_TYPE][0]) != OID_TST_INFO:
        raise TokenError("signed content-type attribute is not id-ct-TSTInfo")
    if OID_MESSAGE_DIGEST not in attrs or \
            attrs[OID_MESSAGE_DIGEST][0].expect(4).value != hashlib.new(digest_name, tst_bytes).digest():
        raise TokenError("messageDigest does not match the TSTInfo")

    signer = None
    for c in certs:
        if sid.is_tag(16):
            issuer_serial = sid.children()
            if c.issuer == issuer_serial[0].raw and c.serial == der_int(issuer_serial[1]):
                signer = c
        elif sid.is_tag(0, 2) and c.key_identifier() == sid.value:
            signer = c
    if signer is None:
        raise TokenError("signer certificate not included in the token")

    if OID_SIGNING_CERT_V2 in attrs:
        ess = attrs[OID_SIGNING_CERT_V2][0].children()[0].children()[0].children()
        if ess[0].is_tag(16):
            algo, expected = DIGESTS.get(der_oid(ess[0].children()[0]), "unknown"), ess[1].value
        else:
            algo, expected = "sha256", ess[0].value
    elif OID_SIGNING_CERT in attrs:
        ess = attrs[OID_SIGNING_CERT][0].children()[0].children()[0].children()
        algo, expected = "sha1", ess[0].value
    else:
        raise TokenError("no ESSCertID signing-certificate attribute")
    if algo == "unknown" or hashlib.new(algo, signer.der).digest() != expected:
        raise TokenError("ESSCertID does not match the signer certificate")

    critical, purposes = signer.eku()
    if purposes != [OID_TIME_STAMPING] or not critical:
        raise TokenError("signer certificate lacks a critical extended key usage of only timeStamping")
    if not signer.valid_at(gen_time):
        raise TokenError("signer certificate not valid at genTime")
    res.signer_fingerprint = signer.fingerprint

    have_crypto = _crypto() is not None
    if have_crypto:
        _verify_signed_attrs(signer, digest_name, sig_alg, signature, b"\x31" + attrs_node.raw[1:])

    # Chain to a pinned root: pinned roots are preferred over certificates in
    # the token (a token may carry a cross-certificate with a root's name).
    current, pool = signer, list(roots.values()) + certs
    for _ in range(8):
        if current.fingerprint in roots:
            res.root_fingerprint = current.fingerprint
            res.cryptographically_verified = have_crypto
            return res
        issuer = None
        for cand in pool:
            if cand.subject != current.issuer or cand.fingerprint == current.fingerprint:
                continue
            if have_crypto and not _issued_by(current, cand):
                continue
            issuer = cand
            break
        if issuer is None:
            raise TokenError("certificate chain does not reach a pinned root")
        if not issuer.valid_at(gen_time):
            raise TokenError("a certificate in the chain is not valid at genTime")
        current = issuer
    raise TokenError("certificate chain too long")


# ===========================================================================
# Artefact projection (SPEC §4) — the pure function, version 1
# ===========================================================================


class ProjectionError(ValueError):
    pass


def _subject(payload: Dict[str, Any]) -> Optional[str]:
    if "artefact_id" in payload:
        return payload["artefact_id"]
    artefact = payload.get("artefact")
    return artefact.get("id") if isinstance(artefact, dict) else None


def _text(text_for: Callable[[str], Optional[str]], sha: str, what: str) -> str:
    text = text_for(sha)
    if text is None:
        raise ProjectionError(f"{what}: no text with sha256 {sha}")
    if sha256_hex(text.encode("utf-8")) != sha:
        raise ProjectionError(f"{what}: text does not match sha256 {sha}")
    return text


def apply(records: Dict[str, Dict[str, Any]], e: Dict[str, Any], text_for: Callable[[str], Optional[str]]) -> None:
    """SPEC §4, projection version 2."""
    t, p, at = e["event_type"], e["payload"], e["captured_at"]
    if t == "artefact.captured":
        a = p["artefact"]
        if a["id"] in records:
            raise ProjectionError(f"artefact {a['id']} captured twice")
        rec = copy.deepcopy(a)
        rec["content"] = _text(text_for, a["content_sha256"], f"{a['id']} content")
        prov = rec["provenance"]
        prov["prompt"] = (json.loads(_text(text_for, prov["prompt_sha256"], f"{a['id']} prompt"))
                          if prov.get("prompt_sha256") else None)
        prov["raw_response"] = (_text(text_for, prov["raw_response_sha256"], f"{a['id']} raw response")
                                if prov.get("raw_response_sha256") else None)
        rec["captured_at"] = at
        rec["provenance_status"] = prov.get("status")
        rec.update(copy.deepcopy(LIFECYCLE_DEFAULTS))
        records[a["id"]] = rec
        return
    if t not in LIFECYCLE_EVENTS:
        return
    rec = records.get(p["artefact_id"])
    if rec is None:
        raise ProjectionError(f"{t} at seq {e['seq']} names unknown artefact {p['artefact_id']}")
    if t == "mapping.suggested":
        rec["regulatory_mappings"] = copy.deepcopy(p["mappings"])
    elif t == "artefact.flagged":
        f = p["finding"]
        rec["flags"].append({"code": f["code"], "detail": f["detail"], "blocking": f["blocking"],
                             "raised_at": at, "resolved_at": None, "waiver": None})
    elif t == "artefact.finding_resolved":
        for f in rec["flags"]:
            if f["code"] == p["code"] and f["resolved_at"] is None:
                f["resolved_at"] = at
    elif t == "finding.waived":
        for f in rec["flags"]:
            if f["code"] == p["code"] and f["resolved_at"] is None and f["waiver"] is None:
                f["waiver"] = {"waived_by": p["waived_by"], "waived_by_person_id": p["waived_by_person_id"],
                               "rationale": p["rationale"], "recorded_at": at}
    elif t == "artefact.reviewed":
        review = copy.deepcopy(p["review"])
        review["recorded_at"] = at
        review["independence"] = copy.deepcopy(p["independence"])
        review["signature"] = copy.deepcopy(p["signature"])
        rec["review"] = review
        rec["audit_state"] = p["audit_state"]
    elif t == "artefact.misra_scanned":
        rec["misra_findings"] = copy.deepcopy(p["findings"])
    elif t == "artefact.attested":
        rec["audit_state"] = "attested"
        rec["attestation"] = {k: copy.deepcopy(v) for k, v in p.items() if k != "artefact_id"}
        rec["attestation"]["recorded_at"] = at
    elif t == "provenance.amended":
        fields = copy.deepcopy(p["fields"])
        if fields.get("prompt_sha256"):
            fields["prompt"] = json.loads(_text(text_for, fields["prompt_sha256"], f"{rec['id']} amended prompt"))
        if fields.get("raw_response_sha256"):
            fields["raw_response"] = _text(text_for, fields["raw_response_sha256"], f"{rec['id']} amended raw response")
        rec["provenance_amendments"].append({"fields": fields, "reason": p["reason"], "amended_by": p["amended_by"],
                                             "amended_by_person_id": p["amended_by_person_id"], "recorded_at": at})
        rec["provenance_status"] = p["provenance_status"]


LIFECYCLE_EVENTS = ("mapping.suggested", "artefact.flagged", "artefact.finding_resolved", "finding.waived",
                    "artefact.reviewed", "artefact.misra_scanned", "artefact.attested", "provenance.amended")


# ===========================================================================
# Report
# ===========================================================================


class Report:
    def __init__(self, bundle: str, strict: bool):
        self.bundle, self.strict = bundle, strict
        self.checks: List[Dict[str, Any]] = []
        self.notes: List[str] = []
        self.timestamps: Dict[str, Any] = {}

    def check(self, check_id: str, name: str, ok: bool, detail: str = "") -> None:
        self.checks.append({"id": check_id, "name": name, "ok": ok, "detail": detail})

    @property
    def ok(self) -> bool:
        return bool(self.checks) and all(c["ok"] for c in self.checks)

    def to_dict(self) -> Dict[str, Any]:
        return {"bundle": self.bundle, "spec": SPEC, "verifier_version": __version__, "strict": self.strict,
                "ok": self.ok, "checks": self.checks, "timestamps": self.timestamps, "notes": self.notes}


def _short(items: List[Any], limit: int = 12) -> str:
    return ", ".join(str(i) for i in items[:limit]) + (f" … ({len(items)} in all)" if len(items) > limit else "")


# ===========================================================================
# Checks
# ===========================================================================


class Bundle:
    def __init__(self, zf: zipfile.ZipFile):
        self.zf = zf
        self.manifest = json.loads(zf.read("manifest.json"))
        self.lines = [json.loads(line) for line in zf.read("ledger.jsonl").decode("utf-8").splitlines() if line]
        self.artefacts = json.loads(zf.read("artefacts.json"))
        self.keys = json.loads(zf.read("actor_keys.json"))
        self.anchors = json.loads(zf.read("anchors.json"))
        self.pdf = zf.read("evidence.pdf")
        self.continuity = self.manifest.get("continuity", {})
        # Entries with parsed payloads (None when the payload has no canonical form).
        self.entries: List[Dict[str, Any]] = []
        self.payload_problems: Dict[int, str] = {}
        self.running: Dict[int, str] = {}
        for line in self.lines:
            try:
                payload = parse_strict(line["payload_json"])
                canonical(payload)
            except (ValueError, CanonicalError, TypeError, KeyError) as exc:
                self.payload_problems[line.get("seq", -1)] = str(exc)
                payload = None
            self.entries.append({**line, "payload": payload})
            if payload is not None:
                self.running[line["seq"]] = entry_hash(line, payload)


def check_manifest(b: Bundle, rep: Report) -> None:
    m, problems = b.manifest, []
    for key, want in (("bundle_format", SPEC), ("spec_version", SPEC_VERSION), ("hash_scheme", HASH_SCHEME),
                      ("projection_version", PROJECTION_VERSION)):
        if m.get(key) != want:
            problems.append(f"{key} is {m.get(key)!r}, expected {want!r}")
    for name, meta in m.get("files", {}).items():
        try:
            data = b.zf.read(name)
        except KeyError:
            problems.append(f"{name}: missing from archive")
            continue
        if sha256_hex(data) != meta.get("sha256"):
            problems.append(f"{name}: sha256 differs from the manifest")
    for required in ("ledger.jsonl", "artefacts.json", "actor_keys.json", "anchors.json", "evidence.pdf"):
        if required not in m.get("files", {}):
            problems.append(f"{required}: not listed in the manifest")
    rep.check("manifest-files", "Manifest and file integrity", not problems, "; ".join(problems))


def check_chain(b: Bundle, rep: Report) -> None:
    problems: List[str] = []
    prev, last_time, expected_seq = GENESIS, "", 1
    for e in b.entries:
        seq = e.get("seq")
        if set(e) - {"payload"} != LEDGER_FIELDS:
            problems.append(f"seq {seq}: entry fields differ from the spec")
        if seq != expected_seq:
            problems.append(f"seq {seq}: expected seq {expected_seq}")
        expected_seq = (seq if isinstance(seq, int) else expected_seq) + 1
        if e["prev_hash"] != prev:
            problems.append(f"seq {seq}: prev_hash does not link to the previous entry")
        if e["payload"] is None:
            problems.append(f"seq {seq}: payload has no canonical form ({b.payload_problems.get(seq)})")
        elif canonical(e["payload"]) != e["payload_json"]:
            problems.append(f"seq {seq}: stored payload is not in canonical form")
        elif b.running[seq] != e["content_hash"]:
            problems.append(f"seq {seq}: content_hash does not match the recomputed hash")
        if not e["captured_at"] > last_time:
            problems.append(f"seq {seq}: captured_at does not increase")
        prev, last_time = e["content_hash"], e["captured_at"]
    if b.entries and b.entries[-1]["content_hash"] != b.continuity.get("head_hash"):
        problems.append("the last entry's hash differs from the continuity head_hash")
    if not b.entries:
        problems.append("the ledger is empty")
    rep.check("chain-hashes", "Hash chain integrity (scheme 2, canonical JSON)", not problems, "; ".join(problems))


def check_sequence(b: Bundle, rep: Report) -> None:
    problems = []
    lo, hi = (b.continuity.get("seq_range") or [None, None])[:2]
    seqs = [e["seq"] for e in b.entries]
    if lo != 1 or seqs != list(range(1, (hi or 0) + 1)):
        problems.append(f"entries are not contiguous over the declared range {lo}..{hi} starting at 1")
    if b.continuity.get("entries_in_bundle") != len(b.entries):
        problems.append("entries_in_bundle differs from the ledger.jsonl line count")
    rendered = set(b.continuity.get("rendered_in_pdf", {}).get("seqs", []))
    omitted = set(b.continuity.get("omitted_from_pdf", {}).get("seqs", []))
    if rendered & omitted:
        problems.append("rendered and omitted sets overlap")
    if isinstance(hi, int) and rendered | omitted != set(range(1, hi + 1)):
        missing = sorted(set(range(1, hi + 1)) - (rendered | omitted))
        problems.append(f"the continuity statement does not account for seq {_short(missing)}")
    rep.check("sequence-continuity", "Sequence continuity accounting", not problems, "; ".join(problems))


def check_filter(b: Bundle, rep: Report) -> None:
    predicate = b.continuity.get("filter", {}).get("predicate", {})
    if predicate.get("type") != "artefact_relevance":
        rep.check("declared-filter", "Declared filter is reproducible", False,
                  f"unknown filter predicate type {predicate.get('type')!r}: a filter that cannot be checked is undeclared")
        return
    ids = set(predicate.get("artefact_ids", []))
    recomputed = []
    for e in b.entries:
        p = e["payload"]
        if not isinstance(p, dict):
            continue
        if _subject(p) in ids or (e["event_type"] == "evidence.exported"
                                  and any(a in ids for a in p.get("artefact_ids", []))):
            recomputed.append(e["seq"])
    declared = b.continuity.get("rendered_in_pdf", {}).get("seqs", [])
    ok = recomputed == declared
    rep.check("declared-filter", "Declared filter is reproducible", ok,
              "" if ok else f"re-evaluating the predicate renders {_short(recomputed)}; the manifest declares {_short(declared)}")


def check_void_entries(b: Bundle, rep: Report) -> None:
    by_seq = {e["seq"]: e for e in b.entries}
    problems = [f"void entry declared at seq {v.get('seq')} has no sequence.voided ledger entry"
                for v in b.continuity.get("void_entries", {}).get("entries", [])
                if by_seq.get(v.get("seq"), {}).get("event_type") != "sequence.voided"]
    rep.check("void-entries", "Void entries exist and explain themselves", not problems, "; ".join(problems))


def check_projection(b: Bundle, rep: Report) -> None:
    problems: List[str] = []
    texts: Dict[str, str] = {}
    try:
        for rec in b.artefacts:
            prov = rec["provenance"]
            candidates = [rec["content"], prov.get("prompt"), prov.get("raw_response")]
            for amendment in rec.get("provenance_amendments", []):
                candidates += [amendment["fields"].get("prompt"), amendment["fields"].get("raw_response")]
            for value in candidates:
                if value is None:
                    continue
                text = value if isinstance(value, str) else canonical(value)
                texts[sha256_hex(text.encode("utf-8"))] = text
        ids = {rec["id"] for rec in b.artefacts}
    except (KeyError, TypeError, CanonicalError, AttributeError) as exc:
        rep.check("projection", "Artefact records rebuild from the ledger", False,
                  f"artefacts.json is not a list of projection records: {exc}")
        return
    rebuilt: Dict[str, Dict[str, Any]] = {}
    try:
        for e in b.entries:
            if isinstance(e["payload"], dict) and _subject(e["payload"]) in ids:
                apply(rebuilt, e, texts.get)
    except (ProjectionError, KeyError, TypeError, ValueError) as exc:
        problems.append(f"the records cannot be rebuilt from the ledger: {exc}")
    if not problems:
        for rec in b.artefacts:
            got = rebuilt.get(rec["id"])
            if got is None:
                problems.append(f"{rec['id']}: no artefact.captured entry in the ledger")
            elif canonical(got) != canonical(rec):
                fields = sorted(k for k in set(got) | set(rec) if got.get(k) != rec.get(k))
                problems.append(f"{rec['id']}: record differs from the ledger in {', '.join(fields)}")
    # Scope completeness.
    requirement = b.manifest.get("scope", {}).get("requirement_id")
    linked = set()
    for e in b.entries:
        if e["event_type"] == "artefact.captured" and isinstance(e["payload"], dict):
            a = e["payload"].get("artefact", {})
            if any(link.get("requirement_id") == requirement for link in a.get("requirement_links", [])):
                linked.add(a.get("id"))
    declared = set(b.continuity.get("filter", {}).get("predicate", {}).get("artefact_ids", []))
    if not (ids == declared == linked):
        problems.append(f"scope is incomplete or inconsistent for requirement {requirement}: "
                        f"artefacts.json has {len(ids)}, the filter names {len(declared)}, "
                        f"the ledger links {len(linked)}")
    rep.check("projection", "Artefact records rebuild from the ledger (texts, lifecycle, scope)", not problems,
              "; ".join(problems) if problems else f"{len(ids)} records rebuilt and identical")


def check_subject_type(b: Bundle, rep: Report) -> None:
    problems, last = [], 0
    for e in b.entries:
        if e["event_type"] != "artefact.captured" or not isinstance(e["payload"], dict):
            continue
        a = e["payload"].get("artefact", {})
        version = a.get("schema_version", 0)
        if not isinstance(version, int) or version < 3:
            problems.append(f"seq {e['seq']}: schema_version {version!r} is below 3")
            continue
        if version < last:
            problems.append(f"seq {e['seq']}: schema_version went back from {last} to {version}")
        last = max(last, version)
        if a.get("subject_type") != "work_product":
            problems.append(f"seq {e['seq']}: subject_type {a.get('subject_type')!r} is not work_product")
    rep.check("subject-type-boundary", "subject_type schema boundary", not problems, "; ".join(problems))


def _ed25519(keys: Dict[str, str], identity: Optional[str], value: Any, sig: Any) -> str:
    if not isinstance(sig, str) or not sig:
        return "unsigned"
    key = keys.get(identity or "")
    if not key:
        return f"no public key for {identity!r}"
    try:
        ok = ed25519_verify(bytes.fromhex(key), bytes.fromhex(sig), canonical_bytes(value))
    except (ValueError, CanonicalError):
        ok = False
    return "ok" if ok else f"signature by {identity!r} does not verify"


def check_signatures(b: Bundle, rep: Report) -> None:
    problems, verified, legacy = [], 0, 0
    migrated: set = set()
    for e in b.entries:
        p = e["payload"]
        if not isinstance(p, dict):
            continue
        if e["event_type"] == "schema.migrated":
            migrated.update(p.get("artefact_ids", []))
            continue
        if e["event_type"] == "artefact.captured":
            a = p.get("artefact", {})
            actor = a.get("actor", {})
            sig = actor.get("signature")
            if sig == LEGACY_SIGNATURE_MARKER:
                if a.get("id") in migrated:
                    legacy += 1
                else:
                    problems.append(f"seq {e['seq']}: legacy marker on an artefact not listed in a schema.migrated entry")
                continue
            value = copy.deepcopy(a)
            value.get("actor", {}).pop("signature", None)
            status = _ed25519(b.keys, actor.get("identity"), value, sig)
        elif e["event_type"] in ("artefact.reviewed", "artefact.attested"):
            block = p.get("signature")
            if not isinstance(block, dict) or block.get("algorithm", "ed25519") != "ed25519":
                problems.append(f"seq {e['seq']}: {e['event_type']} carries no ed25519 signature block")
                continue
            value = {k: v for k, v in p.items() if k != "signature"}
            status = _ed25519(b.keys, block.get("identity"), value, block.get("value"))
        else:
            continue
        if status == "ok":
            verified += 1
        else:
            problems.append(f"seq {e['seq']} ({e['event_type']}): {status}")
    detail = (f"{verified} verified, {legacy} legacy-unsigned in a recorded migration. Signatures are {SIGNATURE_KIND}: "
              "they show the platform bound the payload to an identity string, not who authored or approved it")
    if problems:
        detail = "; ".join(problems) + f" [{detail}]"
    rep.check("signatures", f"Signatures — {SIGNATURE_KIND}", not problems, detail)


def check_anchors(b: Bundle, roots: Dict[str, Cert], rep: Report) -> List[Dict[str, Any]]:
    problems: List[str] = []
    unverified: List[str] = []
    results: List[Dict[str, Any]] = []
    lo, hi = (b.continuity.get("seq_range") or [1, 0])[:2]
    external = local = 0
    for a in b.anchors:
        aid, seq = a.get("id"), a.get("ledger_seq")
        result = {"id": aid, "ledger_seq": seq, "method": a.get("method"), "ok": False, "gen_times": []}
        results.append(result)
        if not isinstance(seq, int) or not (lo <= seq <= hi):
            problems.append(f"anchor {aid}: anchored seq {seq} is outside the bundle range {lo}..{hi} "
                            "(entries removed after the anchor was taken?)")
            continue
        if b.running.get(seq) != a.get("ledger_hash"):
            problems.append(f"anchor {aid}: the chain at seq {seq} no longer matches the anchored hash")
            continue
        if a.get("method") == "local":
            local += 1
            result["ok"] = True
            continue
        if a.get("method") != "rfc3161":
            problems.append(f"anchor {aid}: unknown method {a.get('method')!r}")
            continue
        tokens = a.get("tokens") or []
        signers, token_ok, crypto_ok = set(), True, True
        for t in tokens:
            name = t.get("tsa_name", "?")
            try:
                r = verify_token(bytes.fromhex(t.get("token", "")), a["ledger_hash"], roots)
            except (TokenError, ValueError) as exc:
                problems.append(f"anchor {aid}: token from {name} does not verify: {exc}")
                token_ok = False
                continue
            if str(r.nonce) != str(t.get("nonce")):
                problems.append(f"anchor {aid}: token from {name} carries a nonce other than the stored one")
                token_ok = False
            if r.gen_time != t.get("gen_time"):
                problems.append(f"anchor {aid}: token from {name} genTime {r.gen_time} differs from the stored {t.get('gen_time')}")
                token_ok = False
            signers.add(r.signer_fingerprint)
            crypto_ok = crypto_ok and r.cryptographically_verified
            result["gen_times"].append(r.gen_time)
        if len(tokens) < 2 or len(signers) < 2:
            problems.append(f"anchor {aid}: external anchors need tokens from two different TSA certificates")
            token_ok = False
        if token_ok and not crypto_ok:
            unverified.append(f"anchor {aid}")
            if rep.strict:
                problems.append(f"anchor {aid}: token signatures not checked (pyca/cryptography is not installed)")
                continue
        if token_ok:
            result["ok"] = crypto_ok
            external += 1 if crypto_ok else 0
    detail = f"{external} external (RFC 3161, two authorities each), {local} local (advisory, no external force)"
    if unverified and not rep.strict:
        detail += f"; unverified in non-strict mode: {', '.join(unverified)}"
        rep.notes.append("non-strict mode: some timestamp tokens were not cryptographically verified")
    if problems:
        detail = "; ".join(problems) + f" [{detail}]"
    rep.check("anchors", "Anchors and RFC 3161 timestamp tokens (pinned roots)", not problems, detail)
    if local:
        rep.notes.append(f"{local} local anchor(s): operator snapshots with no external force, not counted as timestamps")
    return results


def check_timestamps(b: Bundle, anchor_results: List[Dict[str, Any]], rep: Report) -> None:
    external = [a["ledger_seq"] for a in b.anchors if a.get("method") == "rfc3161" and isinstance(a.get("ledger_seq"), int)]
    last = max(external) if external else None
    claimed_list = [e["seq"] for e in b.entries if e["seq"] > (last or 0)]
    claimed = b.manifest.get("timestamps")
    want = {"last_externally_timestamped_seq": last, "not_yet_externally_timestamped": claimed_list}
    problems = [] if claimed == want else ["the manifest's timestamp summary differs from anchors.json"]

    verified = sorted((r for r in anchor_results if r["method"] == "rfc3161" and r["ok"]), key=lambda r: r["ledger_seq"])
    last_verified = verified[-1]["ledger_seq"] if verified else None
    pending = [e["seq"] for e in b.entries if e["seq"] > (last_verified or 0)]
    late = []
    for e in b.entries:
        cover = next((r for r in verified if r["ledger_seq"] >= e["seq"]), None)
        if cover is None or not cover["gen_times"]:
            continue
        stamped = max(parse_time(g) for g in cover["gen_times"])
        if stamped - parse_time(e["captured_at"]) > WINDOW:
            late.append(e["seq"])
    rep.timestamps = {"last_externally_timestamped_seq": last_verified,
                      "not_yet_externally_timestamped": pending,
                      "timestamped_later_than_15_minutes": late}
    detail = (f"last externally timestamped seq: {last_verified}; not yet externally timestamped: "
              f"{_short(pending) if pending else 'none'}; timestamped later than 15 minutes after capture: "
              f"{_short(late) if late else 'none'}")
    if problems:
        detail = "; ".join(problems) + f" [{detail}]"
    rep.check("timestamps", "External timestamp coverage", not problems, detail)
    if pending:
        rep.notes.append(f"{len(pending)} entr{'y is' if len(pending) == 1 else 'ies are'} not yet externally "
                         "timestamped and protected by the chain alone (SPEC §7)")


def check_pdf_continuity(b: Bundle, rep: Report) -> None:
    m = re.search(rb"/Subject \((.*?)\)\s*/", b.pdf, re.DOTALL)
    name = "PDF continuity statement matches the bundle"
    if not m:
        rep.check("pdf-continuity", name, False, "the PDF carries no machine-readable continuity statement (/Subject)")
        return
    raw = m.group(1).replace(b"\\(", b"(").replace(b"\\)", b")").replace(b"\\\\", b"\\")
    try:
        stated = json.loads(raw.decode("latin-1"))
    except (ValueError, UnicodeDecodeError) as exc:
        rep.check("pdf-continuity", name, False, f"unreadable continuity statement in the PDF: {exc}")
        return
    ok = stated == b.continuity
    rep.check("pdf-continuity", name, ok, "" if ok else
              "the PDF's continuity statement differs from the manifest: the document and the record disagree")


def check_charter(b: Bundle, charter_path: str, version: str, rep: Report) -> None:
    name = "Charter version matches its ledger record"
    try:
        with open(charter_path, "rb") as f:
            digest = sha256_hex(f.read())
    except OSError as exc:
        rep.check("charter", name, False, str(exc))
        return
    found = None
    for e in b.entries:
        p = e["payload"]
        if e["event_type"] in CHARTER_EVENT_TYPES and isinstance(p, dict) and p.get("version") == version:
            found = e
    if found is None:
        rep.check("charter", name, False, f"no charter.recorded entry for version {version}")
        return
    recorded = found["payload"].get("charter_sha256", "")
    ok = recorded == digest
    rep.check("charter", name, ok, f"version {version} at seq {found['seq']}" if ok else
              f"charter file hash {digest[:16]}… differs from the record {recorded[:16]}… at seq {found['seq']}")


# ===========================================================================
# Driver
# ===========================================================================


def pinned_roots(extra_paths: Optional[List[str]] = None) -> Dict[str, Cert]:
    roots: Dict[str, Cert] = {}
    texts = list(PINNED_ROOTS_PEM.values())
    for path in extra_paths or []:
        with open(path, encoding="ascii") as f:
            texts.append(f.read())
    for text in texts:
        for cert in load_pem_certs(text):
            roots[cert.fingerprint] = cert
    return roots


def verify_bundle(path: str, tsa_roots: Optional[List[str]] = None, strict: bool = True,
                  charter: Optional[str] = None, charter_version: Optional[str] = None) -> Report:
    rep = Report(path, strict)
    try:
        with zipfile.ZipFile(path) as zf:
            b = Bundle(zf)
            _run_checks(b, rep, tsa_roots, charter, charter_version)
    except (OSError, KeyError, ValueError, zipfile.BadZipFile) as exc:
        if not rep.checks:
            rep.check("manifest-files", "Manifest and file integrity", False, f"cannot read the bundle: {exc}")
            return rep
        raise
    return rep


def _run_checks(b: Bundle, rep: Report, tsa_roots: Optional[List[str]], charter: Optional[str],
                charter_version: Optional[str]) -> None:
    roots = pinned_roots(tsa_roots)
    check_manifest(b, rep)
    check_chain(b, rep)
    check_sequence(b, rep)
    check_filter(b, rep)
    check_void_entries(b, rep)
    check_projection(b, rep)
    check_subject_type(b, rep)
    check_signatures(b, rep)
    results = check_anchors(b, roots, rep)
    check_timestamps(b, results, rep)
    check_pdf_continuity(b, rep)
    if charter is not None:
        check_charter(b, charter, charter_version or "", rep)


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(prog="domokos-verify",
                                     description="Independent verifier for Domokos evidence bundles (spec 2.0).")
    parser.add_argument("bundle", help="path to the bundle .zip")
    parser.add_argument("--json", metavar="FILE", help="also write the JSON report here ('-' for stdout)")
    parser.add_argument("--tsa-root", metavar="PEM", action="append", default=[],
                        help="pin an additional timestamp-authority root certificate (repeatable)")
    parser.add_argument("--no-strict", action="store_true",
                        help="report RFC 3161 tokens that cannot be cryptographically checked instead of failing")
    parser.add_argument("--charter", metavar="CHARTER_MD", help="verify this charter file against its ledger record")
    parser.add_argument("--version", metavar="X.Y.Z", help="charter version to verify (with --charter)")
    parser.add_argument("-V", "--verifier-version", action="version", version=f"domokos-verify {__version__}")
    args = parser.parse_args(argv)
    if args.charter and not args.version:
        parser.error("--charter needs --version")

    try:
        rep = verify_bundle(args.bundle, tsa_roots=args.tsa_root, strict=not args.no_strict,
                            charter=args.charter, charter_version=args.version)
    except OSError as exc:
        print(f"domokos-verify: {exc}", file=sys.stderr)
        return 2

    for c in rep.checks:
        line = f"[{'verified' if c['ok'] else 'NOT VERIFIED'}] {c['name']}"
        if c["detail"]:
            line += f" — {c['detail']}"
        print(line)
    for note in rep.notes:
        print(f"[note] {note}")
    problems = sum(not c["ok"] for c in rep.checks)
    print("\nVERIFIED: every check" if rep.ok else
          f"\nNOT VERIFIED: {problems} of {len(rep.checks)} checks found problems")
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
