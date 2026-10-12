# Domokos evidence bundle specification

**Format id:** `domokos-bundle/2`
**Spec version:** 2.1.0 (2026-10-12)
**Supersedes:** `domokos-bundle/1` (spec 1.1.0). Version 2 ledgers start a new
genesis; version 1 bundles are not verified by this specification.

**Changes in 2.1.0.** All additive; a valid 2.0.0 bundle is a valid 2.1.0
bundle, and a verifier for 2.1.0 MUST accept `spec_version` "2.0.0".

- §5a user signatures (client-held keys) and key lifecycle entries.
- §4: a review record carries `user_signature` when its entry does.
- §6a Merkle anchors: an anchor may carry `merkle_root`; its tokens then
  sign the anchor digest instead of the head hash.
- §13 selective-disclosure bundles.

This document is the published interface between the Domokos platform and any
independent verifier. A verifier implements THIS document, not Domokos
internals. If this spec is ambiguous, the spec is defective: fix the spec.

The key words MUST, MUST NOT, SHOULD and MAY are used as in RFC 2119.

A bundle is a ZIP archive containing, at the archive root:

| File | Content |
|---|---|
| `manifest.json` | Format, versions, scope, declared filter, continuity statement, timestamp summary, per-file SHA-256 |
| `ledger.jsonl` | One JSON object per line: every ledger entry from seq 1 to the head at export time, stored bytes verbatim |
| `artefacts.json` | The projection records (§4) of every artefact in the export scope, texts included |
| `actor_keys.json` | `{identity: ed25519_public_key_hex}` |
| `anchors.json` | Every anchor at or below the head, with its timestamp tokens |
| `evidence.pdf` | Human-readable package carrying a machine-readable copy of the continuity statement |

All JSON is UTF-8. All hashes are lowercase hex SHA-256 unless stated.

## 0. Manifest

`manifest.json` MUST carry `"bundle_format": "domokos-bundle/2"`,
`"spec_version"` "2.0.0" or "2.1.0", `"hash_scheme": 2` and
`"projection_version": 2`.
`files` maps every other file name to `{"sha256", "bytes"}`; every listed
file MUST be present and match. `scope` is
`{"kind": "requirement", "requirement_id": R}`.

## 1. Canonical JSON

Hashes and signatures are computed over canonical JSON: RFC 8785 (JCS)
restricted to objects, arrays, strings, integers, `true`, `false` and `null`.

- **Floats are forbidden.** A number with a fraction or exponent is an error.
  Integers MUST satisfy |n| ≤ 2^53 − 1.
- **Object keys** are strings, unique, and sorted by their UTF-16 code units.
- **Strings** are serialised as ECMAScript `JSON.stringify` does: `"` and `\`
  are escaped as `\"` and `\\`; U+0008, U+0009, U+000A, U+000C and U+000D as
  `\b`, `\t`, `\n`, `\f`, `\r`; other code points below U+0020 as `\u00xx`
  with lowercase hex; everything else is emitted as UTF-8. A string holding a
  lone surrogate has no canonical form.
- No whitespace anywhere.

`canonical(v)` below means the UTF-8 bytes of that serialisation.

## 2. Ledger entries and the chain rule

Each line of `ledger.jsonl` is an object with exactly these members:

```json
{"seq": 7, "captured_at": "2026-10-11T19:21:29.612374Z", "actor_id": "eng-alpha",
 "event_type": "artefact.captured", "payload_json": "{...}",
 "prev_hash": "64 hex", "content_hash": "64 hex"}
```

- `payload_json` is the payload as stored, a string. It MUST equal
  `canonical(parse(payload_json))`: a stored payload that is not canonical is
  a failure.
- `captured_at` is the server time, `YYYY-MM-DDTHH:MM:SS.ffffffZ` (UTC,
  microseconds). It MUST strictly increase with `seq`.
- **Hash rule (scheme 2):**

  ```
  content_hash = SHA256(canonical({"actor": actor_id, "captured_at": captured_at,
                                    "event_type": event_type,
                                    "payload": parse(payload_json),
                                    "prev_hash": prev_hash, "seq": seq}))
  ```

- **Chain rule:** entries are ordered by `seq`, contiguous from 1. Entry 1 has
  `prev_hash` = 64 zeros. Every later entry's `prev_hash` equals the previous
  entry's `content_hash`. The last entry's `content_hash` equals the
  continuity statement's `head_hash`.

The running hash at seq n is the `content_hash` recomputed at n.

## 3. Continuity statement

`manifest.continuity`:

```json
{"seq_range": [1, 25], "entries_in_bundle": 25,
 "rendered_in_pdf": {"count": 10, "seqs": [...]},
 "omitted_from_pdf": {"count": 15, "seqs": [...], "reason": "..."},
 "void_entries": {"count": 0, "entries": []},
 "head_hash": "...", "filter": {"human": "...", "predicate": {...}},
 "verification_command": "domokos-verify <bundle.zip>"}
```

- `seq_range` is `[1, head_seq]`; `entries_in_bundle` equals the line count.
- `rendered ∪ omitted` is every seq in the range; the two sets are disjoint.
- **Declared filter is reproducible.** For predicate type
  `artefact_relevance` (`{"type", "requirement_id", "artefact_ids"}`) an entry
  is rendered iff its subject is in `artefact_ids`, or its `event_type` is
  `evidence.exported` and its payload's `artefact_ids` intersects
  `artefact_ids`. The subject is `payload.artefact_id`, or
  `payload.artefact.id` when the former is absent. Re-evaluating the predicate
  MUST reproduce `rendered_in_pdf.seqs` exactly. Any other predicate type is
  a failure.
- **Void entries:** `void_entries.count` MUST be 0, or each listed seq MUST be
  a `sequence.voided` entry.

## 4. Artefact projection

An artefact record is the result of folding ledger entries through the pure
function `apply(records, entry, text_for)` below, projection version 2.
`text_for(h)` returns the text whose SHA-256 over its UTF-8 bytes is `h`; a
missing text or a text with a different hash is an error. Copies are deep;
`at` is the entry's `captured_at`.

**`artefact.captured`** `{"artefact": A}` creates record `A.id` (an id
captured twice is an error). The record is A itself, plus:

- `content` = `text_for(A.content_sha256)`;
- `provenance.prompt` = `parse(text_for(A.provenance.prompt_sha256))`, or
  null when that hash is null or absent;
- `provenance.raw_response` = `text_for(A.provenance.raw_response_sha256)`,
  or null when that hash is null or absent;
- `captured_at` = `at`; `provenance_status` = `A.provenance.status` (null
  when absent);
- the lifecycle defaults: `regulatory_mappings` `[]`, `misra_findings` `[]`,
  `flags` `[]`, `review` null, `attestation` null, `audit_state` `"draft"`,
  `provenance_amendments` `[]`, `trace_links` `[]`, `mapping_history` `[]`.

Every other event below names `artefact_id`; an id not yet captured is an
error.

| `event_type` | Payload | Effect |
|---|---|---|
| `mapping.suggested` | `{"artefact_id", "mappings", "ruleset_digest", "reason"}` | each current suggestion gets `"superseded_at": at` and is appended to `mapping_history`; then `regulatory_mappings` = `mappings` |
| `mapping.decided` | `{"artefact_id", "mapping_id", "decision", "decided_by", "decided_by_person_id", "rationale"}` | on the current suggestion with that `mapping_id` (none is an error): `status` = `decision`; `decision` = `{"decided_by", "decided_by_person_id", "rationale", "recorded_at": at}` |
| `artefact.flagged` | `{"artefact_id", "finding": {"code", "detail", "blocking"}}` | appends `{"code", "detail", "blocking", "raised_at": at, "resolved_at": null, "waiver": null}` to `flags` |
| `artefact.finding_resolved` | `{"artefact_id", "code", "reason"}` | sets `resolved_at` = `at` on every flag with that code and `resolved_at` null |
| `finding.waived` | `{"artefact_id", "code", "waived_by", "waived_by_person_id", "rationale"}` | on every flag with that code, `resolved_at` null and `waiver` null: `waiver` = `{"waived_by", "waived_by_person_id", "rationale", "recorded_at": at}` |
| `artefact.reviewed` | `{"artefact_id", "review", "independence", "audit_state", "signature" or "user_signature"}` | `review` = payload `review` plus `"recorded_at": at`, `"independence"`, `"signature"` (payload `signature`, or null when absent) and, only when the payload has one, `"user_signature"` (§5a); `audit_state` = payload `audit_state` |
| `artefact.misra_scanned` | `{"artefact_id", "findings"}` | `misra_findings` = `findings` |
| `artefact.attested` | `{"artefact_id", "attester_id", ..., "signature"}` | `audit_state` = `"attested"`; `attestation` = the payload without `artefact_id`, plus `"recorded_at": at` |
| `link.added` | `{"artefact_id", "link_id", "link_type", "target_artefact_id", "target_requirement_id", "added_by", "added_by_person_id"}` | appends the payload without `artefact_id`, plus `"recorded_at": at`, to `trace_links` |
| `provenance.amended` | `{"artefact_id", "fields", "reason", "amended_by", "amended_by_person_id", "provenance_status"}` | appends `{"fields", "reason", "amended_by", "amended_by_person_id", "recorded_at": at}` to `provenance_amendments`, where `fields` also gets `prompt` = `parse(text_for(fields.prompt_sha256))` and `raw_response` = `text_for(fields.raw_response_sha256)` when those hashes are present; `provenance_status` = payload `provenance_status` |

Every other event type changes no record.

**Reconciliation.** For the bundle, `text_for` is built from `artefacts.json`
alone: for each record, its `content`, `canonical(provenance.prompt)`,
`provenance.raw_response` and the `prompt` (canonical) and `raw_response` of
each provenance amendment, keyed by their SHA-256; null values are skipped. The verifier folds every
entry whose subject (§3) is the id of a record in `artefacts.json`, then:

- every record in `artefacts.json` MUST equal the rebuilt record (compared as
  canonical JSON), so every text hashes to the value its `artefact.captured`
  entry recorded and every lifecycle field follows from the ledger;
- **scope is complete:** the ids in `artefacts.json`, the filter's
  `artefact_ids`, and the ids of every artefact linked to
  `scope.requirement_id` (an `artefact.captured` whose `requirement_links`
  include it, or the `artefact_id` of a `link.added` whose
  `target_requirement_id` is it) MUST be the same set.

**Schema boundary.** Every `artefact.captured` artefact MUST have
`schema_version` ≥ 3 and `subject_type` `"work_product"`; `schema_version`
MUST NOT decrease in seq order.

## 5. Signatures (platform attestation, server-held key)

Domokos holds the signing keys and signs on behalf of the identity a caller
names. A valid signature shows that the platform bound the payload to an
identity string. It does not show who authored or approved anything.

Signatures are Ed25519 (RFC 8032), hex, verified with
`actor_keys.json[identity]` (32-byte public key, hex). They are read from the
ledger, not from `artefacts.json`:

- `artefact.captured`: the signature is `A.actor.signature`, by
  `A.actor.identity`, over `canonical(A without actor.signature)`.
- `artefact.reviewed` and `artefact.attested`: `payload.signature` is
  `{"kind", "identity", "algorithm": "ed25519", "value"}`; the signature
  `value` is by `identity`, over `canonical(payload without "signature")`.

A missing key, a malformed value or a failed verification is a failure. The
marker `"LEGACY-UNSIGNED"` in place of an artefact signature is allowed only
for an artefact id listed in the `artefact_ids` of an earlier
`schema.migrated` entry; anywhere else it is a failure.

## 5a. User signatures (client-held keys) — 2.1

When a user holds their own key, the platform does not sign. The ledger
entry instead carries `payload.user_signature`:

    {"kind": "user signature (client-held key)", "algorithm": "ed25519",
     "key_id": K, "statement": S, "value": hex}

**Keys.** A `key.registered` entry `{key_id, user_id, person_id, algorithm,
public_key}` makes key K valid for entries with a greater seq. A
`key.retired` entry with `kind` "user" and `key_id` K ends that validity for
entries with a greater seq. A `key.retired` entry with `kind` "platform"
and `identity` I retires I's platform key: a platform signature (§5) by I
on an entry with a greater seq is a failure.

**Statements.** `S` is an object whose members are exactly those listed
below plus `signed_at` (a timestamp string) and `nonce` (a string). For
the entry it signs, each listed member MUST equal the value shown:

- `artefact.captured` (A = `payload.artefact`): `type` "artefact.capture",
  `identity` A.actor.identity, `engineer_id` A.provenance.engineer_id,
  `kind` A.kind, `title` A.title, `content_sha256` A.content_sha256,
  `prompt_sha256` A.provenance.prompt_sha256, `raw_response_sha256`
  A.provenance.raw_response_sha256, `model` `{vendor, name, version}` of
  A.provenance.model (or null), `requirement_ids` the sorted distinct
  `requirement_id`s of A.requirement_links.
- `artefact.reviewed`: `type` "artefact.review", `artefact_id`,
  `reviewer_id`, `decision`, `rationale`, `diff`, `independence_waiver`,
  `ai_assisted` (false when the review has no such member) and
  `ai_assistance` (from `payload.review`; `artefact_id` from the payload).
- `artefact.attested`: `type` "artefact.attest", `artefact_id`,
  `attester_id`.

**Check.** K MUST be valid for the entry, and `value` MUST be K's Ed25519
signature over `canonical(S)`. A captured artefact with a user signature
has `A.actor.signature` null; a reviewed or attested entry with one has no
`payload.signature`.

A user signature shows that the holder of a key the ledger registered to a
person signed that statement. Whether the key holder is that person rests
on the key registration, which the ledger records.

## 6. Anchors and timestamp tokens

Each element of `anchors.json`:

```json
{"id": 3, "created_at": "...", "ledger_seq": 25, "ledger_hash": "...",
 "method": "rfc3161",
 "tokens": [{"anchor_id": 3, "tsa_name": "...", "tsa_url": "...",
             "token": "DER hex", "gen_time": "...", "nonce": "decimal string"}]}
```

For every anchor:

- `ledger_seq` MUST be inside `seq_range` and the running hash at
  `ledger_seq` MUST equal `ledger_hash`. An anchor above the head means
  entries were removed after it was taken.
- `method` `"local"` is an operator snapshot with no external force. It is
  reported as advisory and never counted as an external timestamp.
- `method` `"rfc3161"` MUST carry at least two tokens whose signer
  certificates differ. Every token MUST verify:
  1. it is a CMS `ContentInfo` with `SignedData` whose encapsulated content
     type is `id-ct-TSTInfo` (1.2.840.113549.1.9.16.1.4), parsed with a real
     DER parser;
  2. the `TSTInfo` message imprint uses SHA-256, SHA-384 or SHA-512 and equals
     that hash of the ASCII bytes of `ledger_hash` (the 64-character hex);
  3. `TSTInfo.nonce` equals the stored `nonce`, and `genTime` equals the
     stored `gen_time`;
  4. there is exactly one `SignerInfo`; its signed attributes hold
     `content-type` = `id-ct-TSTInfo` and `message-digest` = the digest of
     the `TSTInfo` bytes, and a `signing-certificate` (ESSCertID, SHA-1) or
     `signing-certificate-v2` (ESSCertIDv2) attribute whose hash matches the
     signer certificate;
  5. the signature verifies over the DER of the signed attributes encoded as
     a SET (tag `0x31`) with the signer certificate's key;
  6. the signer certificate carries a critical extended key usage of exactly
     `id-kp-timeStamping`, and every certificate up to the root is valid at
     `genTime`;
  7. the chain reaches a **pinned root** held by the verifier. Certificates
     inside the bundle are never used as roots.

**Strict mode** is the default: an `rfc3161` anchor whose tokens could not
be fully verified (for example, the cryptography library is absent) fails
the run. A verifier MAY offer a non-strict mode that reports such anchors as
unverified without failing. A token that is shown to be wrong fails in every
mode.

A token MAY carry `"qualified": 1`: the operator declares that it comes from
an eIDAS-qualified timestamp authority configured for the engagement as a
third backend. It is verified like any other token. The verifier reports
the declaration and does not check qualified status against the EU trusted
list.

## 6a. Merkle anchors — 2.1

An anchor MAY carry `merkle_root` (hex). It is the RFC 6962 Merkle tree
hash over the entry hashes (`content_hash`) of seq 1..`ledger_seq`, in seq
order:

- leaf = SHA-256(0x00 || bytes of the entry hash);
- node = SHA-256(0x01 || left || right);
- a tree of n ≥ 2 leaves splits at the largest power of two k < n into the
  first k leaves and the rest; one leaf is its own root; the empty tree is
  SHA-256 of nothing.

The verifier MUST recompute the root from the recomputed entry hashes and
compare it. For such an anchor every token's message imprint is over the
**anchor digest** instead of the head hash:

    anchor_digest = lowercase hex SHA-256 of canonical({"ledger_hash": H, "ledger_seq": N, "merkle_root": R})

and the imprint is SHA-256 of the UTF-8 bytes of that hex string, exactly
as §6 states for a head hash. An anchor without `merkle_root` follows §6
unchanged.

## 7. Timestamp summary

`manifest.timestamps`:

```json
{"last_externally_timestamped_seq": 25, "not_yet_externally_timestamped": [26, 27]}
```

`last_externally_timestamped_seq` is the highest `ledger_seq` of an
`rfc3161` anchor (null when there is none); the list holds every later seq.
The verifier recomputes both from `anchors.json` and they MUST match. It
reports the last externally timestamped seq from verified anchors, lists
every later entry as "not yet externally timestamped", and lists entries
whose first covering external anchor's latest token `genTime` is more than
15 minutes after their `captured_at`.

**Limit.** Entries after the last external anchor are protected by the chain
alone. Removing them, together with any anchor taken over them, cannot be
detected from the bundle; the report names them instead. Removing entries at
or below an anchored seq while the anchor remains is detected (§6).

## 8. PDF continuity statement

The PDF Info dictionary's `/Subject` is the continuity object serialised as
compact JSON with sorted keys. A verifier extracts the `/Subject (...)`
literal (unescaping `\(`, `\)`, `\\`) and it MUST deep-equal
`manifest.continuity`.

## 9. Gap register

A bundle exported after an assessment scope was agreed carries the
engagement's gap register: `gap_register.csv` and `gap_register.pdf`, both
listed in `files`, and `manifest.gap_register` with `scope_hash`,
`scope_seq`, `programme`, `ruleset_digest`, `ledger_head`, `ledger_head_seq`,
`last_externally_timestamped_seq` and `last_external_timestamp_at`.

`gap_register.csv` starts with one `# key: value` line per header field
(plus `generated_at`), then a CSV table with the columns `gap_id`, `code`,
`wording`, `framework`, `clause`, `artefact_id`, `ledger_seqs` (seq numbers
joined by `;`), `suggested_cause`, `suggested_owner`, `assigned_cause`,
`assigned_owner`, `assignment_seq` and `status`. Gap codes: `GAP-EV-01`,
`GAP-PROV-01`, `GAP-IND-01`, `GAP-VER-01`, `GAP-TCR-01`, `GAP-MAP-01`,
`GAP-TS-01`.

A verifier MUST check, when a register is present:

- the CSV header equals `manifest.gap_register`;
- the entry at `scope_seq` is a `scope.agreed` entry whose `content_hash` is
  `scope_hash`;
- `ruleset_digest` is the digest of the latest `ruleset.published` entry;
- `ledger_head` and `ledger_head_seq` are the bundle's head;
- `last_externally_timestamped_seq` equals `manifest.timestamps`;
- every row cites only seqs present in the bundle, has a known code and
  wording starting "Evidence not found:"; a row naming an artefact cites an
  entry whose subject is that artefact; a row naming a clause cites the
  scope entry and the clause is in that scope;
- a row with `assignment_seq` matches the latest `gap.assigned` entry for its
  `gap_id` (same cause, status `assigned`); a row without one has no
  recorded assignment and status `unassigned`.

The verifier checks the rows against the ledger; it does not recompute the
register.

## 13. Selective-disclosure bundles — 2.1

A disclosure bundle reveals chosen ledger entries without the rest. Its
`manifest.json` carries `"bundle_format": "domokos-bundle/2"`,
`"spec_version": "2.1.0"`, `"hash_scheme": 2`, `"kind": "disclosure"` and

    "disclosure": {"seqs": [...], "anchor_id": A, "tree_size": N, "merkle_root": R, "reason": text}

and lists in `files`, with SHA-256, exactly:

| File | Content |
|---|---|
| `entries.jsonl` | the disclosed ledger entries, one per line, stored bytes verbatim (§2 fields) |
| `proofs.json` | `{seq: {"leaf_index": seq − 1, "tree_size": N, "path": [hex, ...]}}` |
| `anchors.json` | a list holding the one anchor A, with `merkle_root` R, `ledger_seq` N and its tokens |

A verifier MUST check:

1. **manifest-files**: the members above and their hashes.
2. **entry-hashes**: each entry's payload is canonical and its
   `content_hash` recomputes (§2, with the entry's own `prev_hash`); the
   entries are exactly `disclosure.seqs`.
3. **inclusion-proofs**: for each entry, the RFC 9162 §2.1.3.2 inclusion
   proof from leaf(content_hash) at `leaf_index` in a tree of `tree_size`
   leads to R; R, N and A equal the anchor's. If seq N is disclosed, its
   `content_hash` equals the anchor's `ledger_hash`.
4. **anchors**: A is `rfc3161` (a local anchor fails), and its tokens verify
   over the anchor digest (§6a) with the §6 rules, from two different TSA
   certificates.

A disclosure bundle shows that the disclosed entries were in the ledger at
the anchored position when the authorities timestamped the root. It says
nothing about entries it does not carry.

## 10. Charter mode

To verify a Neutrality Charter version: the bundle's ledger MUST hold a
`charter.recorded` entry (version 1 name: `charter.published`) whose payload
`version` is the requested version and whose `charter_sha256` equals the
SHA-256 of the charter file. The latest such entry counts.

## 11. Verifier output contract

A conforming verifier:

- runs every check even after a failure;
- prints one line per check, marked verified or not verified;
- emits a machine-readable JSON report
  `{"bundle", "spec": "domokos-bundle/2", "strict", "ok", "checks": [{"id",
  "name", "ok", "detail"}], "timestamps", "notes"}`;
- exits 0 iff every check is verified, 1 otherwise, 2 for usage errors.

Check ids: `manifest-files`, `chain-hashes`, `sequence-continuity`,
`declared-filter`, `void-entries`, `projection`, `subject-type-boundary`,
`signatures`, `anchors`, `timestamps`, `pdf-continuity`, `gap-register`, and
`charter` in charter mode.

## 12. Test vectors

The Domokos product generates the test vectors for this version: one valid
bundle and one bundle per operator-tamper probe, each rebuilt consistently
(manifest hashes recomputed), with the test TSA roots and an `expected.json`
naming the checks each vector must fail. A conforming verifier accepts the
valid bundle and rejects every tamper vector.
