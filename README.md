# domokos-verify

Independent verifier for [Domokos](https://domokos-automotive.com) evidence
bundles. It lets anyone check, without relying on Domokos, that an exported
record was not changed, removed or reordered after it was externally
timestamped.

- **No Domokos code.** It implements the published bundle specification,
  [SPEC.md](SPEC.md) (format `domokos-bundle/2`, spec 2.0.0), and reads
  nothing but the exported bundle.
- **Small and auditable.** One file. The core uses the Python 3.9+ standard
  library only, including its own Ed25519 (RFC 8032), RFC 8785 canonical JSON
  and DER parser.
- **One documented dependency:** [pyca/cryptography](https://cryptography.io),
  used only to verify the signatures and certificate chains of RFC 3161
  timestamp tokens.
- **Apache-2.0.**

## Install and use

```bash
pipx install domokos-verify
domokos-verify bundle.zip
```

Until the first release is on PyPI, install from this repository instead:
`pipx install git+https://github.com/domokosautomotive/domokos-verify`.

Or, from a checkout:

```bash
pip install cryptography
python3 domokos_verify.py bundle.zip
```

Exit code 0 means every check was verified, 1 means at least one was not,
and 2 is a usage error. Options:

| Option | Effect |
|---|---|
| `--json FILE` | also write the machine-readable report (`-` for stdout) |
| `--tsa-root PEM` | pin an additional timestamp-authority root (repeatable) |
| `--no-strict` | report timestamp tokens that cannot be checked cryptographically instead of failing |
| `--charter FILE --version X.Y.Z` | check a Neutrality Charter file against its ledger record |

Every check runs even after a problem:

| Check | What it establishes |
|---|---|
| Manifest and file integrity | format and versions are spec 2.0; every file matches its manifest SHA-256 |
| Hash chain integrity | every payload is canonical JSON; every hash recomputes (scheme 2); entries link from genesis to the head; time never goes back |
| Sequence continuity accounting | no absent sequence number: what the PDF renders plus what it omits covers the whole range |
| Declared filter is reproducible | re-running the declared filter reproduces exactly what the PDF rendered |
| Void entries | any declared void sequence number has a ledger entry explaining it |
| Artefact records rebuild from the ledger | every record is rebuilt from ledger entries by the projection function in SPEC §4; every text matches the hash recorded at capture; no artefact of the requirement is left out |
| subject_type schema boundary | every captured artefact carries a valid subject type; the schema version never goes back |
| Signatures — platform attestation (server-held key) | every artefact, review and attestation signature in the ledger verifies with the key the platform registered. The platform holds these keys, so a valid signature shows the platform bound the content to an identity string. It does not show who authored or approved it |
| Anchors and RFC 3161 timestamp tokens | each anchor matches the chain; each external anchor holds tokens from two different timestamp authorities; each token is fully verified against a pinned root |
| External timestamp coverage | the last externally timestamped entry, every later entry, and any entry timestamped later than 15 minutes after capture |
| PDF continuity statement | the human-readable document and the verifiable record tell the same story |
| Gap register | when the bundle carries one, every row cites ledger entries that exist and concern its artefact or in-scope clause; the header's scope hash, ruleset digest, ledger head and latest external timestamp match the ledger; assignments match their ledger entries |

## Pinned roots and strict mode

Timestamp tokens are accepted only if their certificate chain reaches a root
the verifier pins. Certificates inside a bundle are never used as roots. The built-in pins
are the roots of the two authorities Domokos uses:

| Authority | Root | SHA-256 fingerprint |
|---|---|---|
| Sectigo, `http://timestamp.sectigo.com/rfc3161` | Sectigo Public Time Stamping Root R46 | `4941b001b8a97e961b7817c9d9e960ec4b056bfc915a8c1aabf6ef6b3ac046a5` |
| Sigstore, `https://timestamp.sigstore.dev/api/v1/timestamp` | sigstore-tsa-selfsigned (O=sigstore.dev) | `2aca8fea5d3ce48b01cc77076293c280e6c23ffe44034757ee7833ca9f45d633` |

Pin any other authority an engagement uses with `--tsa-root`.

Strict mode is the default. If an RFC 3161 token cannot be checked
cryptographically, for example because pyca/cryptography is not installed,
the run fails. `--no-strict` reports such tokens as unverified instead. A
token shown to be wrong fails in every mode.

## What a verified result means

A verified result means the bundle is internally consistent, the chain is
unbroken from genesis to head, every artefact record follows from the ledger,
nothing was filtered silently, and every anchored point in history matches
tokens from two independent timestamp authorities. History at or below the
last externally timestamped entry cannot have been changed, removed or
reordered after its timestamp without this verifier detecting it.

It does **not** mean every entry was true when written: a compromised writer
produces well-anchored false entries. Entries after the last external
timestamp are protected by the chain alone; the report lists them. Removing
those entries together with any anchor over them cannot be detected from the
bundle (SPEC §7).

## Development

```bash
pip install cryptography
python -m unittest discover -s tests
```

`fixtures/vectors/spec-2.1` is a copy of the test vectors the Domokos product
generates: one valid bundle and one bundle per operator-tamper probe, with
the test timestamp-authority roots and `expected.json`. The suite also checks
a real token from each pinned authority (`fixtures/sectigo_rfc3161_token.der`,
`fixtures/sigstore_rfc3161_token.der`) and the stdlib-only behaviour.

Found an ambiguity between this tool and SPEC.md? That is a spec defect:
file it against the spec, not the implementation.

## Release

Releases are built and published by `.github/workflows/release.yml` when a
signed tag `v*` is pushed. Publishing uses PyPI trusted publishing (OpenID
Connect) in the `pypi` environment; no API token exists anywhere.

### Publication steps (REQ-VER-06)

The package version is 2.1.0 because it implements bundle spec 2.1.0 (and
accepts 2.0.0 bundles).

1. Done on 2026-10-12: the public repository
   <https://github.com/domokosautomotive/domokos-verify> was created and
   `main` pushed.
2. On PyPI, add a pending trusted publisher for project `domokos-verify`:
   owner `domokosautomotive`, repository `domokos-verify`, workflow
   `release.yml`, environment `pypi`. In the GitHub repository settings,
   create the environment `pypi`.
3. Set up SSH tag signing once, add the same public key to your GitHub
   account as a signing key (so the tag shows as verified), and commit it to
   `.github/allowed_signers` (so the workflow checks it):

   ```bash
   git config gpg.format ssh
   git config user.signingkey ~/.ssh/id_ed25519.pub
   ```

4. Tag and push the release; the workflow builds, tests and publishes:

   ```bash
   git tag -s v2.1.0 -m "domokos-verify 2.1.0"
   git push origin v2.1.0
   ```

5. Check the release: `pipx install domokos-verify==2.1.0` then
   `domokos-verify --verifier-version` prints `domokos-verify 2.1.0`.
