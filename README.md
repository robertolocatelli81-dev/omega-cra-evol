# omega-cra-evol

[![ci](https://github.com/robertolocatelli81-dev/omega-cra-evol/actions/workflows/ci.yml/badge.svg)](https://github.com/robertolocatelli81-dev/omega-cra-evol/actions/workflows/ci.yml)
[![PyPI](https://img.shields.io/pypi/v/omega-cra-evol)](https://pypi.org/project/omega-cra-evol/)
[![License: AGPL-3.0-or-later](https://img.shields.io/badge/license-AGPL--3.0--or--later-blue)](LICENSE)
[![DOI](https://zenodo.org/badge/DOI/10.5281/zenodo.24172960.svg)](https://doi.org/10.5281/zenodo.24172960)

_Renamed from `cra-evidence` to `omega-cra-evol` in 0.10.0 (13/11/2026). The name was changed on purpose, so that this project is not mistaken for other products with a similar name; it is not affiliated with any of them. The earlier name was also not available as a PyPI project name. Formats, exit codes and verification are unchanged; packs, ledgers and attestations made with earlier versions verify as before._

**Manufacturers of products with digital elements on the EU market now report in hours.** Under the Cyber Resilience
Act (Regulation (EU) 2024/2847), Article 14 applies since **11 September 2026**, also to products placed on the market
before 11 December 2027 (Art. 69(3)), and open-source software stewards report from 11 December 2027 (Art. 24(3), 71(2)).
On becoming aware of an actively exploited vulnerability or a severe incident, the manufacturer sends, through ENISA's
Single Reporting Platform (SRP):

- an **early warning within 24 hours**,
- a **notification within 72 hours**,
- a **final report** — no later than 14 days after a corrective or mitigating measure is available (vulnerability),
  within one month after the submission of the incident notification (severe incident).

The technical documentation stays at the disposal of market surveillance authorities for **at least 10 years** after
the product is placed on the market, or for the support period if longer (Art. 13(13)). Sources and re-reading dates:
[`spec/LEGAL_BASIS.md`](https://github.com/robertolocatelli81-dev/omega-cra-evol/blob/v0.13.1/spec/LEGAL_BASIS.md).

The SRP is a web portal. What was notified, under which ENISA field glossary, how complete, when the clock started and
when it was filed lives in the firm's own tools — and may have to be shown, years later, to someone who does not run them.
**omega-cra-evol** keeps it in one hash-chained ledger (SBOMs byte for byte, the Art. 14 clock, notices in the ENISA SRP
field vocabulary, signed evidence packs and renewable seals) and signs a notice as an in-toto attestation that
anyone can verify **offline**.

## Demo: from sbomify to a verified attestation

[sbomify](https://github.com/sbomify/sbomify) records CRA Art. 14 reports and their filings. The two documents below
are real responses of its API (`GET /api/v1/compliance/cra-reports/{id}` and `…/filings/{filing_id}`) at commit
4ef6128, on synthetic data, vendored byte for byte in `tests/fixtures/sbomify_4ef6128/`. From a checkout, after
`pip install ".[sign]"`:

```bash
F=tests/fixtures/sbomify_4ef6128
cra keygen psirt.key > psirt.pub.json
python3 -c 'import json; print(json.dumps({"acme-psirt": json.load(open("psirt.pub.json"))["public_key_hex"]}))' > trust.json
cra import sbomify --ledger cra.ledger.jsonl --product acme-d1 --version 1.0.7 \
    --report $F/report_JBuMp9bYI2aN.json --filing $F/filing_JBuMp9bYI2aN_early_warning_1.json \
    --drop-dir ./srp_drop --source-version 4ef61281e69d693e3560185bf81ec5474179ea98
cra attest srp_drop/vulnerability_early_warning_*.json --ledger cra.ledger.jsonl \
    --key psirt.key --signer-id acme-psirt --out ew.intoto.json
cra verify-attestation ew.intoto.json --trust-store trust.json \
    --drop srp_drop/vulnerability_early_warning_*.json --ledger cra.ledger.jsonl
```

Output (trimmed):

```
cra import sbomify        "imported": true,  "absent_at_source": ["1", "4", "7a", "41"],
                          "stage": "early_warning", "complete": false,
                          "missing_required": ["notification_type", "manufacturer_name"],
                          "deadline_utc": "2026-11-14T01:00:00+00:00",
                          "filing": "declared by sbomify: what it recorded about each filing, not a proof of submission"
cra attest                "attested": true, "keyid": "acme-psirt"
cra verify-attestation    "verified": true, "trusted": true, "statement": "accepted",
                          "drop": "PASS", "ledger": "PASS", "product": "PASS", "reasons": []      (exit 0)
```

The imported early warning is recorded as incomplete: glossary rows 1 (notification type) and 4 (manufacturer name),
required at the early warning, are not in sbomify's filing document (sbomify keeps the type as the report's `kind`,
which becomes the notice's `stream`); they are listed in `absent_at_source` with rows 7a and 41, never filled in. Change one byte of the drop file and `cra verify-attestation` exits 1 with
`"drop": "FAIL"` and reason `subject_digest`.

The same attestation for a notice built here, without sbomify:

```bash
cat > ew.json <<'EOF'
{"notification_type": "Vulnerability", "title": "Synthetic example (fictitious product Acme D1)",
 "summary": "Synthetic example: the CVE / EUVD identifiers are real public records, used here only for their form.",
 "manufacturer_name": "Acme (fictitious)", "member_states_available": ["IT"], "product_name": "Acme D1",
 "product_version": "1.0.7", "awareness_datetime_utc": "2026-11-12T08:00:00Z",
 "cve_id": "CVE-2024-3094", "euvd_id": "EUVD-2024-31700"}
EOF
cra notice --ledger cra.ledger.jsonl --product acme-d1 --version 1.0.7 --stage early_warning --fields ew.json --drop native_drop
cra attest native_drop/vulnerability_early_warning_*.json --ledger cra.ledger.jsonl --key psirt.key --signer-id acme-psirt \
    --case-reference example-csirt 2026-000123 --out native.intoto.json
cra verify-attestation native.intoto.json --trust-store trust.json --drop native_drop/vulnerability_early_warning_*.json --ledger cra.ledger.jsonl
```

Same folder, same key → `"complete": true`,
`"deadline_utc": "2026-11-13T08:00:00+00:00"`, `"status": "prepared_not_sent"`; then `"verified": true`, exit 0, and:

```
"vulnerability_ids": {"declared": [{"id": "CVE-2024-3094", "scheme": "cve"}, {"id": "EUVD-2024-31700", "scheme": "euvd"}],
                      "notice":   [{"id": "CVE-2024-3094", "scheme": "cve"}, {"id": "EUVD-2024-31700", "scheme": "euvd"}],
                      "result": "matched"},
"case_reference":    {"declared": {"id": "2026-000123", "issuer": "example-csirt"}, "result": "declared by the signer, not checkable"}
```

The statement is `art14-filing` v0.2: it carries the notice's CVE and EUVD identifiers (read from the notice, never
typed) and, if given, the reference a coordinator gave to the case. A coordinator can receive the statement **without**
the notice file — the statement names the notice by its digests, not its text: the same command without `--drop` still
verifies the signature and the ledger entry, and reports the identifiers as `"declared, not checked (no drop file
given)"`. With the notice file they must be exactly the notice's: one more, one fewer, or none while the notice has
some, and the statement is refused (`vulnerability_ids`). `--predicate v0.1` writes a v0.1 statement (the format of 0.8.0),
which says nothing about identifiers.
`cra schema --stream vulnerability --template early_warning` prints a fillable template of a stage.

## Proofs

- **Specification before code:** the attestation format is [`spec/art14-filing/v0.1/`](https://github.com/robertolocatelli81-dev/omega-cra-evol/blob/v0.13.1/spec/art14-filing/v0.1/README.md)
  (in-toto Statement v1 in a DSSE envelope, Ed25519, closed predicate) and its delta
  [`v0.2`](https://github.com/robertolocatelli81-dev/omega-cra-evol/blob/v0.13.1/spec/art14-filing/v0.2/README.md) (vulnerability identifiers, case reference); the notice rules and the sbomify mapping are in
  [`spec/SRP_FIELDS.md`](https://github.com/robertolocatelli81-dev/omega-cra-evol/blob/v0.13.1/spec/SRP_FIELDS.md); the receipt of `cra verify` in [`spec/RECEIPT.md`](https://github.com/robertolocatelli81-dev/omega-cra-evol/blob/v0.13.1/spec/RECEIPT.md).
- **Attestation vectors:** [`spec/art14-filing/v0.1/vectors/`](https://github.com/robertolocatelli81-dev/omega-cra-evol/tree/v0.13.1/spec/art14-filing/v0.1/vectors/) — 52 envelopes —
  and [`v0.2/vectors/`](https://github.com/robertolocatelli81-dev/omega-cra-evol/tree/v0.13.1/spec/art14-filing/v0.2/vectors/) — 53, with real CVE / EUVD identifiers in synthetic notices;
  each `manifest.json` gives every envelope's expected exit code and exact set of reason codes, for any other
  implementation to run.
- **Verifiers in other languages, by the same author:** [`verifiers/`](https://github.com/robertolocatelli81-dev/omega-cra-evol/blob/v0.13.1/verifiers/README.md) re-implements `cra verify`
  in JavaScript (Node, no dependencies), Go (standard library) and Rust; `verifiers/differential.py` builds intact and
  tampered packs and requires the same verdict and the same failing layers from all of them. The ledger also follows
  the profile of cryptovalid's verifiers (same author).
- **CI** ([`.github/workflows/ci.yml`](https://github.com/robertolocatelli81-dev/omega-cra-evol/blob/v0.13.1/.github/workflows/ci.yml)): the suites on Python 3.9, 3.11 and 3.12, with
  cryptography only and with no optional dependency; the differential oracle across Python, JS, Go and Rust; the
  official CycloneDX CLI and SPDX tools on the SBOM fixtures; gitleaks on the whole history. A weekly workflow
  re-reads ENISA's SRP glossary page and fails on any difference from the vendored snapshot.
- **Public demo:** [omega-cra-evol-demo](https://github.com/robertolocatelli81-dev/omega-cra-evol-demo) installs a release
  three ways (index, attested image, GitHub Action) on clean GitHub-hosted runners, every week, and verifies the
  release's signed evidence pack with each (the index job also requires a tampered copy to fail).
- **Attested container image and GitHub Action:** below, under Install.
- **Archived:** Zenodo concept DOI [10.5281/zenodo.24172960](https://doi.org/10.5281/zenodo.24172960) (resolves to the
  latest version); `CITATION.cff`.

## What is measured

Re-run on 15/11/2026 on the code of 0.11.0 (0.11.1 changes only the container's build context; a fresh clone of the
commit, fresh virtual environments, every job of `.github/workflows/ci.yml` run as written):

- The test suite: 525 tests, OK on Python 3.9.25, 3.11.2 and 3.12.15 with `[sign,schema]` and the cryptovalid wheel; 1
  skipped (the live feeds check, which needs the network). Also 525 with cryptography only and 525 with no optional
  dependency (the checks that need them are skipped and say why).
- The attestation vectors: v0.1, 52 (10 valid, 42 each breaking one rule), and v0.2, 53 (10 valid, 43 refused): each
  gives the exit code and exactly the set of reason codes its `manifest.json` expects.
- A v0.1 statement keeps its receipt: on the 52 v0.1 vectors of 0.8.0, the receipts of 0.8.0 and of this code are
  byte for byte the same on 41 and differ only in `predicate_type` on 10 (`"not_evaluated"` where the statement was
  not read from a trusted envelope; art14-filing v0.2 §5 as amended in 0.11.0); the 52nd used the v0.2 TypeURI as its
  "wrong" value and is judged as v0.2.
- The vendored sbomify documents (3 reports, 9 filings, all five stages: early warning, notification, intermediate,
  final report, users informed): every filing imports, and each of the 9 notices is attested (v0.2) and verifies with
  its drop file and ledger.
- The differential oracle: 186 intact and tampered cases, Python, JavaScript, Go and Rust verifiers, 0 divergences.
- The notice schema follows ENISA's SRP glossary "Version 1.6" of 21/10/2026: 49 table rows, 43 numbered fields, in
  `spec/sources/enisa_srp_glossary_20261112.json`.

Measured on 18/11/2026 on the code of 0.13.0 before its release with documents published on GitHub:

- 39 SBOM files attached to releases (28 of the most-starred repositories with an SBOM asset, 11 of Italian and EU
  public-sector organisations): 27 recorded with the floor met — one of them, docker/compose's, an SPDX document
  inside an in-toto Statement; 4 refused as not conformant, each confirmed with the official schema outside this tool
  (kitty: an empty checksum; etcher: 40 URLs that are not IRI references; grafana and loki: `SPDXID` values the SPDX
  2.3.1 schema does not admit); 8 refused by format (5 CycloneDX XML, 2 SPDX tag-value, 1 file that is not an SBOM).
  No crash.
- 13 documents found as OpenVEX: 8 accepted as OpenVEX, 5 refused (four with no statement, one file that is not a VEX);
  none accepted under another label.

URL, sha256 and expected verdict of 18 of the 39 SBOMs and of the 13 VEX documents are in
`tests/data/real_release_sboms_20261118/NETWORK.tsv` and `tests/data/real_vex_20261118/NETWORK.tsv` (read again with
`CRA_REAL_NET=1`); six documents under MIT, Apache-2.0 or CC0-1.0 are kept in the repository with their licences. The
other 18 SBOMs are not listed in the repository.

## Install

```
pip install omega-cra-evol==0.13.1   # PyPI: the wheel attached to the GitHub Release (also https://robertolocatelli81-dev.github.io/pypi/)
pip install ".[sign]"    # from a checkout; no runtime dependency, [sign] adds Ed25519 signatures / signed tips / seals
pip install ".[schema]"  # checks an ingested CycloneDX or SPDX document against the official schema of its version
```

Without `[schema]` (`jsonschema[format-nongpl]`) `cra sbom --from-cyclonedx` / `--from-spdx` records the document as
`schema_check: not checked`, and the record never meets the SBOM floor; a document that fails its official schema
(CycloneDX 1.2 … 1.7, SPDX 2.2, 2.3 and 3.0.1), or whose version has no schema here, is refused unless
`--allow-nonconformant` is given (then recorded, marked, never floor met). A refused document exits 2 with one line on
stderr and nothing is written; recorded with the floor not met exits 1. See the CHANGELOG, 0.11.0.

What `cra sbom` reads is JSON. Other serialisations are refused by name, with the conversion (`spec/SBOM_INGEST.md`,
rule 11):

| The file is | Convert it with |
|---|---|
| SPDX tag-value (`.spdx`) | `pyspdxtools -i F.spdx -o F.spdx.json --novalidation` ([spdx/tools-python](https://github.com/spdx/tools-python)); measured on 18/11/2026 with spdx-tools 0.8.5 on the release SBOMs of istio 1.32.0 and minikube v1.39.0: the converted documents are recorded, schema conformant |
| CycloneDX XML | `cyclonedx convert --input-file F.xml --output-file F.json` ([CycloneDX/cyclonedx-cli](https://github.com/CycloneDX/cyclonedx-cli), the command of its README; not run by this project) |
| Syft JSON | `syft convert F -o cyclonedx-json` (or `-o spdx-json`) |
| a zip or tar archive of SBOMs | extract it and record each document |

The stored bytes are then those of the converted file, not of the original.

The command is `cra` (also installed as `omega-cra-evol`, the name `pipx run` and `uvx` look for); the Python package is
`omega_cra_evol`.

Container image (Linux x86_64, `[sign]` included, and `[schema]` in the images of the releases after 0.10.0; build provenance attested by the release workflow):

```
gh attestation verify oci://ghcr.io/robertolocatelli81-dev/omega-cra-evol:0.13.1 --repo robertolocatelli81-dev/omega-cra-evol \
  --cert-identity https://github.com/robertolocatelli81-dev/omega-cra-evol/.github/workflows/container.yml@refs/tags/v0.13.1 \
  --source-ref refs/tags/v0.13.1 --deny-self-hosted-runners
docker run --rm --user "$(id -u):$(id -g)" -v "$PWD:/work" ghcr.io/robertolocatelli81-dev/omega-cra-evol:0.13.1 verify pack.json --ledger cra.ledger.jsonl
```

GitHub Action (verifies the provenance of the image digest it pulled, then runs `cra` in the workspace, without
network by default):

```yaml
- uses: robertolocatelli81-dev/omega-cra-evol@v0.13.1
  with:
    args: verify dist/pack.json --ledger evidence/cra.ledger.jsonl --trust-store evidence/trust.json
```

## Commands

| Command | What it does |
|---|---|
| `cra sbom --from-cyclonedx F` / `--from-spdx F` | records an SBOM (CycloneDX 1.2–1.7 JSON, SPDX 2.2 / 2.3 JSON, SPDX 3.0.1 JSON-LD, or one of them inside an in-toto Statement); the generator's document is checked against its official schema, hashed and stored byte for byte; a repeated `bom-ref` (1.4+) or `SPDXID` is refused; SPDX rules the schema does not express are reported with their section |
| `cra vuln --id ID --aware T [--exploited] [--incident] [--component Q] [--vex F --vex-format L]` | records a vulnerability or severe-incident event and computes the Art. 14 deadlines from the declared awareness instant; `--component` names the affected component of the recorded SBOM (purl, `NAME` or `NAME@VERSION`); `--vex` attaches a document checked for its declared format |
| `cra vex F --format L` | checks an OpenVEX 0.2.0, CycloneDX VEX, SPDX 3.0.1 or CSAF 2.0 (form only) document for the format it declares; records nothing |
| `cra schema --stream S --template STAGE` | prints the fields of a stage in the ENISA glossary vocabulary |
| `cra notice --stage STAGE --fields F --drop D [--strict]` | builds the notice payload, lists missing required fields, records it; says where it disagrees with the ledger (no vulnerability record for its CVE, deadline already passed, component not in the recorded SBOM); never submits it |
| `cra import sbomify --report R --filing F …` | imports the notices recorded in sbomify, documents kept byte for byte |
| `cra check-notice DROP [--ledger L]` | re-checks a notice under the glossary it records |
| `cra attest DROP` / `cra verify-attestation ENV` | signs / verifies the `art14-filing` attestation of a notice: v0.2 (default: with its CVE / EUVD identifiers and an optional case reference) or v0.1 |
| `cra pack`, `cra sign`, `cra seal`, `cra verify` | evidence pack anchored in the ledger, Ed25519 signature (seed file or AWS KMS), renewable seal, offline verification |
| `cra verify-seal --ledger L [--tsa-cert PEM]` | verifies the seals recorded in a ledger: signatures, order, algorithm policy, and with `--tsa-cert` the RFC 3161 time of every record |
| `cra feeds ID` | read-only network checks: OSV positive control, CISA KEV / ENISA EUVD exploitation signal |
| `cra obligations` | which obligations are in force for a role at an instant, and the horizons counted in years (Art. 13, 14, 24(3), 69, 71); both readings of a start date, 00:00 UTC and 00:00 Brussels; never reads the clock |

Every subcommand has `--help`. `cra verify` gives one authenticity verdict (`trusted-signed` > `signed` > `anchored` >
`FAIL`) and exits 0 verified, 1 a finding against the pack, 77 not assessed, 2 unusable input, 74 receipt not written
([`spec/RECEIPT.md`](https://github.com/robertolocatelli81-dev/omega-cra-evol/blob/v0.13.1/spec/RECEIPT.md)).

## Guarantees and assumptions

- **What a verified attestation guarantees** (with `--drop` and `--ledger`): these exact notice bytes, under this glossary and these rules, with this
  completeness and deadline, sit at this entry of an intact ledger, and a key in your trust store signed the statement.
- **Not a conformity assessment, not CE marking**, not legal advice.
- **"conformant" means conformant to the schema file named next to it** (`schema_check: conformant to
  bom-1.6.schema.json`), plus the uniqueness of `bom-ref` / `SPDXID` — not conformant to the whole CycloneDX or SPDX
  specification. Beyond the schema, an SPDX 2.x document is also refused for a `seeAlsos` value that is not a URL (§10.4), and up
  to four more rules are reported in `source.spec_rules` (§8.1, §8.4, §11.1, and for SPDX 2.2 the idstring); BSI
  TR-03183-2 is reported only as a format-version notice (`source.bsi_tr_03183_2`), no field of the TR is checked.
- **A VEX is checked for its format, not for its content:** its statements are not compared with the vulnerability
  record or with the SBOM. CSAF 2.0 is checked for its form only (the CSAF schema is not shipped). `--component` says
  which recorded component the manufacturer named, not that the product is affected.
- **Not the official CSIRT/ENISA channel.** The SRP is a web portal; ENISA's FAQ (re-read 12/11/2026) says no API is
  provided at its initial release. A person submits the notice; this tool prepares, records and verifies it.
- **The awareness instant is the manufacturer's declaration** (glossary rows v26 / i37): the evidence shows that it was
  recorded, and when, not that it is true. Whether a vulnerability is actively exploited is the manufacturer's
  determination; KEV and EUVD are surfaced as signals.
- **An imported filing record is the source tool's declaration, not proof of submission.** The same holds for a
  filing declared with `cra attest --filed-at`.
- **Identifiers and case reference (v0.2):** the CVE / EUVD identifiers are compared with the notice only when the
  notice file is given; a case reference is the signer's declaration, which no file can check.
- **Time:** the ledger orders records; it is an objective time anchor only with an attached RFC 3161 / OpenTimestamps
  token. An RFC 3161 token of a seal must stamp that seal record (`cra seal --print-imprint`; the digest, the chain
  before it and the record's own fields, `spec/TIME_ANCHOR.md`) and gives the record its time; it is verified —
  signature, binding, time, TSA, with the signer named either way RFC 5652 allows — only against a TSA certificate you pin (`cra seal --tsa-cert`, or
  `cra verify-seal --tsa-cert` later, or `omega_cra_evol.time_anchor.make_timestamp_trust_fn`); without a pin `temporal_trust` stays ASSUMED. Revocation of
  the TSA certificate is not checked. OpenTimestamps tokens are stored after a shape check and not verified.
- **Verifiers:** the JavaScript, Go and Rust verifiers and cryptovalid's are by the same author as this tool; they are
  separate implementations of a written profile, not separate parties.

## Contact, citation

- **Questions, interoperability reports, divergences found by your own verifier**: open a thread in this repository's
  [Discussions](https://github.com/robertolocatelli81-dev/omega-cra-evol/discussions) or an issue; e-mail: roberto.locatelli.81@gmail.com.
- **Citation**: concept DOI [10.5281/zenodo.24172960](https://doi.org/10.5281/zenodo.24172960) (resolves to the latest version; DOI of 0.13.1: [10.5281/zenodo.24393700](https://doi.org/10.5281/zenodo.24393700)); `CITATION.cff` in this repository.
- Author: Roberto Locatelli, 2026. Public interventions by his AI agent (Noûs) are signed as such.

## Licence

AGPL-3.0-or-later for this repository. Copyright Roberto Locatelli, 2026. No commercial licence, paid pilot or support
contract is offered at present: the project is free and open-source software, provided without warranty as the
licence states.
