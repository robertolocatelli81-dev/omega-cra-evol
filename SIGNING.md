# Signing and release verification

This file says which keys sign omega-cra-evol releases and how anyone can check them. Only **public** keys and
fingerprints are listed here; private keys are never published.

## 1. Release evidence pack (AWS KMS, Ed25519)

Each GitHub release carries an evidence pack of the release (`omega-cra-evol-<version>-cra_pack.json`, its ledger
`omega-cra-evol-<version>-cra.ledger.jsonl` and the signature `omega-cra-evol-<version>-cra_pack.json.sig.json`) signed
with an Ed25519 key held in AWS KMS. The private key is created inside KMS, is non-exportable and never leaves it.

- Signer id: `roberto-locatelli-aws-kms`
- Public key (raw Ed25519, hex): `86db2b7231930b37debf3c9bcd5baedcc12c430f8d7785a93212a6f83706440b`
- SHA-256 of the public key: `7a72250f64773c0577a38b2dc0d790246d134af5f73176d7811cacab72007092`
- The same public key is in every release's trust asset (`omega-cra-evol-<version>-trust.json`, before the rename
  `cra-evidence-<version>-trust.json`): the same key in all 19 releases from v0.1.0 to v0.12.0, read on 17/11/2026. A
  copy that differs from this file means something was altered.

To check a release (with the `sign` extra installed, `pip install 'omega-cra-evol[sign]'`):

```
cra verify omega-cra-evol-<version>-cra_pack.json --ledger omega-cra-evol-<version>-cra.ledger.jsonl \
  --trust-store omega-cra-evol-<version>-trust.json
```

It exits 0 with `"authenticity": "trusted-signed"` when the pack, its ledger and the signature agree and the key is the
one in the trust store (measured on the v0.12.0 assets on 17/11/2026). The trust store is the release's own asset: compare
its key with this file before trusting it.

## 2. Commits and tags (SSH signatures)

Commits and release tags are signed with an SSH Ed25519 key. Fingerprint: `SHA256:YTnE9PgWCm9XNiECrqk1Q645tWJUaRFO1WabYSJSfTo`
(the signing key registered on the author's GitHub account). GitHub shows them as "Verified"; locally,
`git verify-tag <tag>` and `git verify-commit <commit>` with an allowed-signers file (`gpg.ssh.allowedSignersFile`)
containing that key.

## 3. Build provenance (GitHub artifact attestations)

The wheel and the sdist are built by `.github/workflows/release-build.yml` on the release tag and attested by
GitHub. To check a downloaded file:

```
gh attestation verify <file> --repo robertolocatelli81-dev/omega-cra-evol \
  --cert-identity "https://github.com/robertolocatelli81-dev/omega-cra-evol/.github/workflows/release-build.yml@refs/tags/<tag>" \
  --source-ref refs/tags/<tag> --deny-self-hosted-runners
```

## 4. Checksums

Every release has a `SHA256SUMS` asset. It lists every other asset of the release, except in v0.1.0, v0.1.1 and v0.3.0,
where it lists the wheel and the sdist only (read on 17/11/2026). The files on PyPI must have the same SHA-256 as listed
there.

## 5. Key changes and compromise

- A planned key change is announced in the release notes and in this file at least 6 months before the old key
  stops being used; for that period both keys are listed.
- If a private key is suspected compromised, a GitHub security advisory is published on this repository, this file
  is updated the same day, and the affected releases are listed.

## 6. Post-quantum transition

The keys of §1 and §2 are Ed25519 (EdDSA). NIST IR 8547, *Transition to Post-Quantum Cryptography Standards* (final,
October 2026, https://doi.org/10.6028/NIST.IR.8547, §4.1.1 Table 2; read on 17/11/2026): ECDSA, EdDSA and RSA
signatures are "Deprecated after 2030" and "Disallowed after 2035" under NIST standards and guidelines.

The release verification of §1 (`cra verify`) does not date-limit the Ed25519 signature of the pack. The long-term seal
of this package does: by default `LongTermEvidence.verify` treats an Ed25519 record as no longer trusted from
2035-01-01T00:00:00Z (`AlgorithmPolicy.nist_ir_8547()`, one year earlier than the text's "after 2035"; see
`spec/LEGAL_BASIS.md`, re-check of 17/11/2026); a seal is to be renewed with another algorithm before that date
(`register_algorithm`; for example a hybrid Ed25519 and ML-DSA-65 signer). Moving the key of §1 to another algorithm is
a key change in the sense of §5.
