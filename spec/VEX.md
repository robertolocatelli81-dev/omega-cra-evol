# VEX and other documents attached to a vulnerability record — version 0.13.0 (2026-11-18)

Status: normative for `EvidenceLocker.record_vulnerability(attachments=…)`, `omega_cra_evol.vex.check_attachment`,
`cra vex` and `cra vuln --vex` from 0.13.0. Written before the code (18/11/2026). Until 0.12.0 an attachment was kept
verbatim with its SHA3 and nothing else: measured on 18/11/2026 on 13 OpenVEX documents found on GitHub, 39 of 39
(document, label) pairs were accepted, the 26 with a wrong label and the 3 of a file that is not a VEX (the OpenVEX
JSON-LD context) among them, and 5 of the 13 fail the official OpenVEX schema.

## Rule — the declared format is checked; anything else is refused with its reason

The label is one of `openvex`, `cyclonedx-vex`, `cyclonedx-sbom`, `csaf-2.0`, `spdx-3.0` (unchanged); the document a
JSON object. Per label:

| label | what is checked | schema | source |
|---|---|---|---|
| `openvex` | `@context` is `https://openvex.dev/ns/v0.2.0` (the specification: "structured as https://openvex.dev/ns/v[version] … If the version is omitted, it defaults to v0.0.1"; another version is refused, naming it); valid for the schema. A value that does not meet a `format` keyword of the schema (`uri`, `iri`, `date-time`) is reported, not refused: the schema's dialect is JSON Schema 2020-12, where `format` is an annotation unless the schema asks for assertion (Validation §7.2.1), and this one does not; `format_not_met` is their number and `format_not_met_examples` the first three (measured: `pkg:deb/debian/libc6@>=0.0.0-0` as a product `@id` in one of the 13 documents, `>` is not an IRI character) | `omega_cra_evol/data/openvex/openvex_json_schema-0.2.0-93139bd.json` | openvex/spec commit `93139bd2c65390b504e47f82f11c50451289f93a` (2026-10-30), CC0-1.0 |
| `cyclonedx-vex` | `bomFormat` `CycloneDX`, conformant as `cra sbom` checks it (CycloneDX rules 1–5 of `SBOM_INGEST.md`), and a non-empty `vulnerabilities` array | the CycloneDX schemas already shipped | — |
| `cyclonedx-sbom` | `bomFormat` `CycloneDX`, conformant as above | as above | — |
| `spdx-3.0` | an SPDX 3.0.1 JSON-LD document conformant as `cra sbom` checks it | `spdx-json-schema-3.0.1.json` already shipped | — |
| `csaf-2.0` | form only: `document` an object, `document.csaf_version` exactly `"2.0"`, `document.category`, `document.title` strings, `document.publisher` and `document.tracking` objects (CSAF 2.0 §3.2.1, the five required properties of `document`) | **not shipped**: the CSAF repository (oasis-tcs/csaf) is under the OASIS IPR policy and gives no licence to redistribute the schema that we could read on 18/11/2026; `schema_check` says `form only (CSAF 2.0 schema not shipped)` | — |

A document that fails is refused (`ValueError` in the API, exit 2 in the CLI), nothing recorded, with the reason:
`attachment <i> (<label>): <why>`. Without `jsonschema` installed, the form checks run and the schema check is not made:
`schema_check` starts with `not checked: ` and gives the reason (`jsonschema is not installed …`) — never "conformant". The result kept next to the document
in the record adds `schema_check` (`conformant to <schema file>` or the text above) and, for OpenVEX,
`format_not_met` / `format_not_met_examples`; the verbatim document and its `document_sha3` are unchanged.

Measured on 18/11/2026 on the same 13 documents: 8 are accepted as `openvex` and 5 refused (four with an empty
`statements`, one of them also with members the schema does not admit; the JSON-LD context); under each of the four
other labels all 13 are refused (0.12.0: 39 of 39 pairs tried accepted).

This changes what the API accepts: a caller that attached a document under the wrong label, or a document that is not
valid for its schema, gets a refusal.

## `cra vex <file> --format <label>`

Reads one file (bounded as an SBOM source, read once, a duplicate key or a nesting the parser cannot read is a malformed
document), applies the rule above, prints `{"format", "schema_check", "sha256", "statements" (OpenVEX) or
"vulnerabilities" (CycloneDX), …}` and exits 0, or prints the reason and exits 2. It records nothing.

## `cra vuln … --vex <file> --vex-format <label>`

Attaches the file, checked as above, to the vulnerability record being written (the record is not written when the
attachment is refused).

Not done: VEX statements are not compared with the record's vulnerability id or with the product's SBOM; CSAF 2.1
(`csaf_version` `"2.1"`) is refused as a version this text does not read.
