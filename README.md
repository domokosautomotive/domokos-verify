# domokos-verify

Independent verifier for [Domokos](https://domokos-automotive.com) evidence
bundles. It exists so the platform's single claim — *this record was not
altered after the fact* — is checkable **without trusting the vendor**.

- **Zero dependency on Domokos.** No shared code, no imports. This tool is
  written against the published bundle specification ([SPEC.md](SPEC.md))
  and reads the exported bundle format, nothing else.
- **Zero third-party dependencies.** One file, Python 3.9+ standard library
  only (Ed25519 verification is embedded, per RFC 8032). No build step, no
  network access: it runs on a locked-down corporate laptop.
- **Apache-2.0.**

## Use

```bash
python3 domokos_verify.py bundle.zip
```

Exit code 0 iff every check passes. Add `--json report.json` for the
machine-readable report. Checks (all run, even after a failure):

| Check | What it proves |
|---|---|
| Manifest and file integrity | every file matches its manifest SHA-256 |
| Hash chain integrity | every entry's hash recomputes from its stored bytes; `prev_hash` links end to end |
| Sequence continuity accounting | no absent sequence number: rendered ∪ omitted covers the whole range |
| Declared filter is reproducible | re-evaluating the declared predicate reproduces exactly what the PDF rendered |
| Void entries | any declared void sequence number has a chain entry explaining itself |
| subject_type schema boundary | pre-v3 entries carry no `subject_type`; v3+ entries carry a valid one; the schema version never regresses |
| Actor identity signatures | each artefact's Ed25519 signature verifies against its actor's registered key (legacy pre-signing artefacts are reported, not failed) |
| Anchor validity | the chain root recomputed at each anchored sequence equals the anchored hash; RFC 3161 tokens embed the root's imprint |
| PDF continuity statement | the human-readable document and the verifiable record tell the same story |

To verify a Neutrality Charter version against the ledger record inside a
bundle:

```bash
python3 domokos_verify.py bundle.zip --charter NEUTRALITY_CHARTER.md --version 1.0.0
```

## What a pass does and does not mean

A pass means the bundle is internally consistent, the chain is unbroken from
genesis to head, nothing was filtered silently, and every anchored point in
history matches its anchor. For ranges covered by an RFC 3161 anchor, a pass
additionally means the operator could not have rewritten that history after
the anchor time without detection.

A pass does **not** mean every entry was true when written (a compromised
writer produces perfectly anchored lies), and ranges without an external
anchor are protected by the chain alone — the report says so explicitly.
Deeper TSA certificate-chain validation is available with standard tooling:

```bash
openssl ts -verify -digest <imprint-hex> -in token.der -CAfile tsa-ca.pem
```

## Development

```bash
python3 -m unittest discover -s tests
```

`fixtures/valid-bundle.zip` is a real bundle exported from a seeded Domokos
instance; the test suite mutates it to prove each tamper class is caught
(altered entry, removed entry, forged anchor, mismatched continuity
statement, rewritten historical product name — naive and
consistent-rewrite variants).

Found an ambiguity between this tool and SPEC.md? That is a spec defect —
file it against the spec, not the implementation.
