# Domokos evidence bundle specification

**Format id:** `domokos-bundle/1`
**Spec version:** 1.0.0 (2026-08-24)

This document is the published interface between the Domokos platform and any
independent verifier. A verifier implements THIS document, not Domokos
internals. If this spec is ambiguous, the spec is defective: fix the spec.

A bundle is a ZIP archive containing, at the archive root:

| File | Required | Content |
|---|---|---|
| `manifest.json` | yes | Bundle metadata, scope, declared filter, continuity statement, per-file SHA-256 |
| `ledger.jsonl` | yes | One JSON object per line: every ledger entry in the covered range, stored bytes verbatim |
| `artefacts.json` | yes | Full artefact records for the export scope |
| `actor_keys.json` | yes | `{actor_identity: ed25519_public_key_hex}` |
| `anchors.json` | yes | Every anchor covering the range (may be empty `[]`) |
| `evidence.pdf` | yes | Human-readable package; carries a machine-readable copy of the continuity statement |

All JSON is UTF-8. All hashes are lowercase hex SHA-256 unless stated.

## 1. Ledger entries and the chain rule

Each line of `ledger.jsonl` is an object with exactly these fields:

```json
{
  "seq": 7,
  "captured_at": "2026-07-10T06:21:29.612374+00:00",
  "actor_id": "eng-sebastian",
  "event_type": "artefact.captured",
  "payload_json": "{...}",
  "prev_hash": "64 hex chars",
  "content_hash": "64 hex chars",
  "signature": null
}
```

`payload_json` is the canonical payload **as stored** — a string, not an
object. Verifiers MUST NOT parse-and-reserialise it before hashing: the hash
covers the stored bytes.

**Hash rule.** For every entry:

```
content_hash = SHA256( "{seq}|{captured_at}|{actor_id}|{event_type}|{payload_json}|{prev_hash}" )
```

(the six fields joined with `|`, no trailing separator, UTF-8 encoded;
`seq` in decimal with no padding).

**Chain rule.** Entries are ordered by `seq`, strictly contiguous over the
covered range. The first entry's `prev_hash` is 64 zeros (genesis) when the
range starts at 1. Every subsequent entry's `prev_hash` equals the previous
entry's `content_hash`. The last entry's `content_hash` equals the
continuity statement's `head_hash`.

**Canonical payload JSON** (how Domokos produces `payload_json`; verifiers
need this only for filter re-evaluation, never for hashing): keys sorted,
separators `(",", ":")`, non-JSON values stringified.

## 2. Continuity statement

`manifest.json` carries `continuity`:

```json
{
  "seq_range": [1, 18],
  "entries_in_bundle": 18,
  "rendered_in_pdf": {"count": 10, "seqs": [1,2,3,4,5,11,12,13,15,18]},
  "omitted_from_pdf": {"count": 8, "seqs": [6,7,8,9,10,14,16,17], "reason": "..."},
  "void_entries": {"count": 0, "entries": []},
  "head_hash": "...",
  "filter": {"human": "...", "predicate": {...}},
  "verification_command": "domokos-verify <bundle.zip>"
}
```

Rules a verifier MUST enforce:

- `rendered ∪ omitted` = every seq in `seq_range`; the two sets are disjoint.
- `entries_in_bundle` equals the line count of `ledger.jsonl` and the size
  of the range.
- **Declared filter is reproducible.** For predicate type
  `artefact_relevance` (`{"type": "artefact_relevance", "requirement_id":
  R, "artefact_ids": [...]}`): an entry is rendered iff
  `parse(payload_json).artefact_id ∈ artefact_ids`, or `event_type ==
  "evidence.exported"` and `parse(payload_json).artefact_ids` intersects
  `artefact_ids`. Re-evaluating the predicate over `ledger.jsonl` MUST
  reproduce `rendered_in_pdf.seqs` exactly. Unknown predicate types are a
  verification failure (a filter that cannot be checked is undeclared).
- **Void entries.** Under Domokos's current sequence allocator, burned
  numbers are structurally impossible; `void_entries.count` MUST be 0. If a
  future allocator introduces them, each void entry listed here MUST
  correspond to a ledger entry of `event_type` `"sequence.voided"` at that
  seq carrying a reason code — an absent number is never acceptable.

## 3. The `subject_type` schema boundary

`EvidenceArtifact` gained a required `subject_type` field at artefact schema
version 3. The boundary is **checkable**, not defaulted:

- For every `artefact.captured` entry, parse `payload_json`:
  - `schema_version >= 3` ⇒ the payload MUST contain
    `"subject_type": "work_product"` (the only value implemented; reserved
    values `instance`, `configuration`, `population` in a payload are a
    failure until a future spec version implements them).
  - `schema_version < 3` (or absent — v0.1-era entries carry no
    schema_version key) ⇒ the payload MUST NOT contain `subject_type`.
    Its presence in a pre-v3 entry is evidence of a rewrite.
- `schema_version` MUST be non-decreasing across `artefact.captured`
  entries in seq order (a single upgraded writer never re-emits an older
  canonical form).

## 4. Actor signatures

`artefacts.json` holds full artefact records. For each record:

- `actor.signature` = `"LEGACY-UNSIGNED"` ⇒ the artefact predates signing;
  report it, do not fail it, and do not treat it as verified.
- Otherwise the signature is Ed25519 (RFC 8032), hex, by the key
  `actor_keys.json[actor.identity]` (32-byte public key, hex), over the
  **signing payload**:
  1. Take the artefact record; remove `review`, `regulatory_mappings`,
     `misra_findings`, `audit_state`.
  2. Remove `signature` from within `actor`.
  3. If `schema_version < 3`, remove `subject_type` (artefacts signed
     before the field existed are verified against the form they were
     authored under — datetimes and enums as ISO/value strings, exactly as
     serialised in `artefacts.json`).
  4. Serialise with sorted keys, separators `(",", ":")`; UTF-8 encode.
- Missing public key, malformed signature, or failed verification ⇒ failure.

## 5. Anchors

Each element of `anchors.json`:

```json
{
  "id": 1, "created_at": "...", "ledger_seq": 18, "ledger_hash": "...",
  "seq_start": 1, "method": "local" | "rfc3161",
  "tsa_url": null, "tsa_identity": null,
  "tsa_token": "hex or null", "anchor_time": "...", "nonce": "..."
}
```

Rules:

- `ledger_seq` MUST fall inside the bundle's `seq_range`, and the running
  chain hash recomputed at `ledger_seq` MUST equal `ledger_hash`. Any
  mismatch is a failure (a forged or stale anchor).
- `method == "rfc3161"` ⇒ `tsa_token` MUST be present; the DER token MUST
  embed the message imprint `SHA256(ascii_hex(ledger_hash))` (the
  timestamped message is the 64-char lowercase hex of the root hash).
  Verifiers SHOULD additionally validate the token's TSA signature chain
  with external tooling (`openssl ts -verify -digest <imprint-hex> -in
  token.der -CAfile <tsa-ca.pem>`); this spec's minimum is the imprint
  binding.
- `method == "local"` ⇒ the anchor is an operator snapshot with **no
  external force**; verifiers MUST report it as advisory and MUST NOT count
  it as external attestation.
- A bundle with zero rfc3161 anchors covering its range is valid but MUST
  be reported as "externally unanchored range".

## 6. PDF continuity statement

`evidence.pdf` embeds the continuity statement machine-readably: the PDF
Info dictionary's `/Subject` is the continuity object serialised as compact
JSON with sorted keys. A verifier extracts the `/Subject (...)` literal
(unescaping `\(`, `\)`, `\\`), parses it, and it MUST deep-equal
`manifest.continuity`. Any difference is a failure: the human-readable
document and the verifiable record must tell the same story.

## 7. Historical product names

The platform was renamed (Stoa → Domokos, 2026-08-24). Entries created
before the rename may embed the historical name inside hashed bytes. This is
correct and expected: verifiers MUST compare stored bytes and MUST NOT
normalise, re-brand, or otherwise "fix" historical text — a chain in which
the historical name has been rewritten fails the hash rule of §1, exactly
as any other tamper does. There is no allowlist at the byte layer.

## 8. Verifier output contract

A conforming verifier:

- runs every check even after a failure (report everything);
- prints one human-readable pass/fail line per check;
- emits a machine-readable JSON report
  (`{"bundle", "spec": "domokos-bundle/1", "ok", "checks": [{"id", "name",
  "ok", "detail"}]}`);
- exits 0 iff every check passes (legacy-unsigned artefacts and
  local-anchor advisories do not fail a run; they are reported).

Check ids: `manifest-files`, `chain-hashes`, `sequence-continuity`,
`declared-filter`, `void-entries`, `subject-type-boundary`,
`actor-signatures`, `anchors`, `pdf-continuity`.
