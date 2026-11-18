# Checks on an ingested SBOM — version 0.13.0 (2026-11-18)

Status: normative for `omega_cra_evol.sbom` (`sbom_from_spdx`, `sbom_from_cyclonedx`, `cra sbom --from-spdx`,
`--from-cyclonedx`) from 0.13.0. Written before the code (18/11/2026). The rules of 0.11.0 (CHANGELOG, 0.11.0:
CycloneDX rules 1–4, SPDX rules 1–5) still apply; this text changes SPDX rule 1's table of schemas (rule 6) and adds
SPDX rule 7 and CycloneDX rules 5 and 6. Sources were read on 18/11/2026 on the projects' own repositories; where a
standard says what to do, it decides (a reading of ours is said to be one).

## SPDX rule 6 — the schema that checks an SPDX 2.x document

| the document declares | schema shipped in `omega_cra_evol/data/spdx/` | source |
|---|---|---|
| `"spdxVersion": "SPDX-2.2"` | `spdx-schema-v2.2.2-4694d1f.json` (draft-07) | spdx/spdx-spec, branch `development/v2.2.2`, commit `4694d1fe63ecd269262c26bd4370d4e11e6f7f8f` (2025-10-10), `schemas/spdx-schema.json` |
| `"spdxVersion": "SPDX-2.3"` | `spdx-schema-v2.3.1.json` (2019-09) | spdx/spdx-spec, tag `v2.3.1` (commit `6f2cb47d13db19b12c23885573b22ef32ec1ada5`), `schemas/spdx-schema.json` |
| SPDX 3.0.1 `@context` | `spdx-json-schema-3.0.1.json` (2020-12) | unchanged (same bytes, `Last-Modified` and `ETag` on 18/11/2026) |

Why SPDX 2.2 changes. 0.11.0 to 0.12.0 used the schema of the tag `v2.2.2`. That tag points at commit `a05c12a`
(2021-09-28), whose own `chapters/index.md` reads "Specification Version 2.2.1" and `mkdocs.yml` "specification
v2.2.1"; the 2.2.2 edition was written afterwards on the branch `development/v2.2.2` (51 commits ahead of the tag,
"Update spec to version 2.2.2" on 2022-03-22), and the GitHub release v2.2.2 (2022-04-27) gives its full changelog as
`v2.2.1...development/v2.2.2`. In the tag's schema `referenceCategory` is one of `OTHER`, `SECURITY`,
`PACKAGE_MANAGER`, while §7.21 of the text — at the tag and on the branch — says "`<category>` is `SECURITY` |
`PACKAGE-MANAGER` | `PERSISTENT-ID` | `OTHER`". SPDX recorded the contradiction (spdx/spdx-spec#798, opened 2022-10-08,
closed 2024-04-04 "now resolved") and corrected the schema on the branch (PR #836, merged 2023-03-10, commit
`e3a5c7b`): `OTHER`, `PERSISTENT-ID`, `PERSISTENT_ID`, `SECURITY`, `PACKAGE-MANAGER`, `PACKAGE_MANAGER`. The head of
the branch (`4694d1f`, 2025-10-10) differs from the tag's schema in more than the categories, each time as the text
says: it requires `documentNamespace` (§6.5 "Required: Yes"), `creationInfo.creators` (§6.8, 1..*), a file's
`checksums` (§8.4, SHA1 1..1) and `licenseInfoInFiles` (§8.6, 1..*), a snippet's `ranges` (§9.3, "Required: Yes"); it
no longer requires a snippet `name` (§9.10 "Required: No", cardinality 0..1) and adds the relationship type `AMENDS`.
An SPDX-2.2 document without one of the four newly required members is refused from 0.13.0. We use that head. **Both spellings of the categories are
accepted because the SPDX project's corrected schema accepts both**; we do not narrow it to the text's spelling.

Why SPDX 2.3 changes. 0.11.0 did not use `v2.3.1` ("no release"). On 18/11/2026: the tag exists, the repository's
CHANGELOG reads "2.3.1 (2026-10-30) — a maintenance release of V2.3", the specification site serves
`https://spdx.github.io/spdx-spec/v2.3.1/` and its aliases `v2.3`, `2.3` and `v2-latest` point to it
(`versions.json`); there is no GitHub Release object and the announcements of the release checklist
(spdx/spdx-spec#1472) are still open. A 2.3.1 document still declares `SPDX-2.3` (§6.1). The 2.3 schema contradicts
the 2.3 text where 2.3.1 corrects it: `primaryPackagePurpose` `OPERATING_SYSTEM` (text §7.24: `OPERATING-SYSTEM`,
which 0.12.0 refused) and `referenceCategory` (2.3.1 accepts `PERSISTENT_ID` and `PACKAGE_MANAGER` besides the text's
spellings). 2.3.1 also requires `documentNamespace` (text §6.5: "Required: Yes") and adds patterns to `SPDXID`, `checksumValue` and the
dates (text §6.9 "YYYY-MM-DDThh:mm:ssZ"; the leap second is accepted); it no longer requires a snippet `name` and allows a
top-level `$schema` member. A document written with the 2.3 schema's
`OPERATING_SYSTEM` is refused (the text never allowed it); `--allow-nonconformant` records it.

## SPDX rule 7 — license cross reference (`seeAlsos`), SPDX 2.2 and 2.3

The text (2.2.2 and 2.3.1, §10.4, Table 66) says of the license cross reference field: "Format: Uniform Resource
Locator", "a pointer to the official source of a license"; RFC 3986 is a normative reference (clause 2). The schemas
type each item as a string. After the schema check, each string of `hasExtractedLicensingInfos[i].seeAlsos[j]` is
read against the RFC 3986 `URI` rule (§3: `scheme ":" hier-part [ "?" query ] [ "#" fragment ]`, ASCII, matched whole):

1. Not a `URI` (empty, no scheme, a space, a non-ASCII character, a bad percent-encoding…): **not conformant**, the
   same as SPDX rule 1 — refused with `SPDX not conformant to SPDX 2.x §10.4 at hasExtractedLicensingInfos/<i>/seeAlsos/<j>:
   not a URL (RFC 3986 URI): <value>`, nothing recorded; with `--allow-nonconformant` recorded with that text in
   `source.schema_check`, floor not met.
2. A `URI` whose scheme is neither `http` nor `https` (compared case-insensitively, RFC 3986 §3.1): recorded, and
   reported: `source.see_also_not_web` (count) and `source.see_also_not_web_examples` (the first three, each cut at
   200 characters). Such a value is a URL by the grammar — Syft's `file://$GOPATH/pkg/mod/…` has the host `$GOPATH`,
   a reg-name made of sub-delims and letters (§3.2.2) — but it does not point at an official source anyone else can
   read. Whether a URL is "the official source" is not decidable here, so it is not a refusal and not a floor criterion.

SPDX 3 (`expandedlicensing_seeAlso`) is not read by this rule.

## CycloneDX rule 5 — `bom-ref` is unique within the BOM

What CycloneDX says, read on 18/11/2026: the JSON schemas of 1.4 and 1.5 "Every bom-ref MUST be unique within the BOM",
of 1.6 and 1.7 "Every bom-ref must be unique within the BOM"; ECMA-424 (CycloneDX as an Ecma standard), 2nd edition
(December 2025, the edition in force; its specVersion example is 1.7) "Every bom-ref shall be unique within the BOM"
(1st edition, June 2024: "must"), and its clause 2 (Conformance) says a consumer "should instantiate a warning or error condition when a
CycloneDX BOM is not conforming to this Standard". The JSON schemas of 1.2 and 1.3 say only "Every bom-ref should be
unique"; the XML schema of every version, 1.2 to 1.7, declares `<xs:unique name="bom-ref">` with selector `.//*` and
field `@bom-ref` (an XML BOM with a repeated `bom-ref` is invalid; CycloneDX/specification commit `6470e34`, the head of
`master` on 18/11/2026). The official test suite's JSON harnesses (Java and JavaScript, same commit) check a JSON file
with the JSON schema only, which cannot express uniqueness, so its `valid-*` JSON files say nothing on this rule.

So: in a 1.4–1.7 document a repeated value is an error condition (the standard's own words, and ECMA-424 allows the
error); in a 1.2–1.3 JSON document the JSON text says "should", the XML schema of the same version makes it a requirement
for XML only, and — as for `patentAssertions` below — where two texts of CycloneDX disagree we take the one that accepts
more: it is reported, not refused.

The identifiers are the string values of every member named `bom-ref` of an object anywhere in the document, except
in an item of a `patentAssertions` array — the 1.7 JSON schema describes that member as "A reference to the patent
or patent family object within the BOM. This must match the `bom-ref` of a `patent` or `patentFamily` object", the 1.7
XML schema as an identifier; with the two in contradiction it is not counted, which can only accept more (ECMA-424,
2nd edition, reads it as the JSON schema does: "shall match the bom-ref of a patent or patentFamily object"). (A JSF
`signature` cannot hold a `bom-ref` member in a document that passes the schema: `publicKey` refuses it.) Values are compared as exact strings. After the
schema check passes, a value that appears more than once makes a 1.4–1.7 document **not conformant**: refused with
`CycloneDX not conformant to bom-<v> (bom-ref unique within the BOM): '<value>' appears <n> times`, nothing recorded;
with `--allow-nonconformant` recorded with that text in `source.schema_check`, floor not met. In every version
`source.bom_ref_repeated` counts the distinct values that appear more than once and `source.bom_ref_repeated_examples`
gives the first three (document order, each cut at 200 characters); a 1.2–1.3 document is recorded with them, floor
unaffected.

Known consequences, measured on 18/11/2026: two `valid-*` JSON files of the official test suite repeat a `bom-ref`
whose XML twin does not (`valid-formulation-1.5.json`: `workspace-1` twice, the XML file has `workspace-2`;
`valid-citations-1.7.json`: `workflow-1` on the formulation and on its workflow, once in the XML file); they are
refused. cdxgen 12.8.4 writes its own tool component again as `annotations[0].annotator.component` with the same
`bom-ref`; those documents are refused.

## CycloneDX rule 6 — references that do not resolve are reported

`refLinkType` (1.5–1.7): "Descriptor for an element identified by the attribute 'bom-ref' in the same BOM document";
in 1.2–1.4 a dependency's `ref` "References a component by the components bom-ref attribute". Neither text, nor
ECMA-424 for these fields, has a requirement keyword and the XML schemas have no `xs:keyref`, so a reference to no
element is **reported, not refused**. (ECMA-424 does say a patent assertion's `bom-ref` "shall match the bom-ref of a
patent or patentFamily object"; that field is not read by this rule.) Read: `dependencies[].ref`, `dependencies[].dependsOn[]`, `dependencies[].provides[]`,
`compositions[].assemblies[]`, `compositions[].dependencies[]`, `compositions[].vulnerabilities[]`; a string matching
the BOM-Link form `urn:cdx:` points into another BOM and is not counted. The known identifiers are those of rule 5, of
every kind of object (0.12.0 knew only `components` and `metadata.component`, so an edge to a service was reported as
dangling). `source.dangling_edges` keeps its meaning (distinct `dependsOn` targets that resolve to nothing; a BOM-Link is not counted there either),
`source.dangling_refs` lists the first ten distinct unresolved values of all the fields above, and
`source.dangling_by_field` counts them per field (`{}` when every reference resolves).

## Not an ingest: PEP 508 markers of the installed floor (0.13.0, written before the code on 18/11/2026)

`sbom_from_installed(..., transitive=True)` (`cra sbom --installed`) follows the `Requires-Dist` of the installed
distributions and drops a requirement whose environment marker is false for this interpreter. `marker_applies(marker)`
answers `True`, `False`, or `None` (not evaluated: the requirement is kept and counted in
`source.markers_unevaluated_kept`). The grammar and the comparisons are those of the PyPA specification "Dependency
specifiers" (PEP 508 as amended; read on packaging.python.org on 18/11/2026, sha256 of the page `977f8427…`, its
history ending with the amendments of January and July 2026), and the reference is `packaging.markers` (26.3 measured),
used whenever it is importable.

1. **`packaging` importable:** its answer; `InvalidMarker`, `UndefinedEnvironmentName` and `UndefinedComparison` (an
   operator the specification does not define for that field, e.g. `os_name ~= "posix"`) are `None`. Until 0.13.0
   `UndefinedComparison` was not caught and ended the command with a traceback.
2. **`packaging` not importable — the fallback**, a parser of the specification's grammar, never a split of the text:
   a quoted string is one token whatever it contains (`and`, `or`, parentheses, the other quote); `and` binds tighter
   than `or`; parentheses nest. Its answer is always `True`, `False` or `None`, and where it is a boolean it is
   `packaging`'s:
   - the variables are the ten this package reads (`python_version`, `python_full_version`, `os_name`, `sys_platform`,
     `platform_release`, `platform_system`, `platform_version`, `platform_machine`, `platform_python_implementation`,
     `implementation_name`); any other name (`extra`, `implementation_version`, legacy dotted names), a comparison of two
     variables or of two strings, and any text outside the grammar are `None`; one `None` anywhere makes the whole
     marker `None` (as `packaging` raises on the first one);
   - `python_version`, `python_full_version` and `platform_release` (`packaging`'s version fields): with `in` / `not in`,
     string containment. With another operator, as `packaging` builds a specifier from the operator and the right-hand
     value and asks whether it contains the left-hand one: when both values, white space at the ends removed, are plain
     release versions (`N(.N)*`; for `==` and `!=` the right one may end in `.*`), they are compared as PEP 440 does —
     missing release segments are zeros (`3.11 == 3.11.0`), `.*` matches the prefix, `~=` needs two segments or more
     (else `None`), `===` is equality of the two strings; when the right-hand value cannot be a version at all (it has
     no digit, or a character no version or specifier has: anything but letters, digits, white space, `.`, `_`, `-`,
     `+`, `!`, `*`), the string field rules below apply, as in `packaging` when the specifier is invalid
     (`platform_release == 'a(b)'` is `False`); anything else (a pre-release, a post or local version, an epoch, a
     left-hand value that is not a plain release, such as Linux's `platform_release`) is `None`;
   - every other variable is a string field: `==`, `!=`, `in`, `not in` as Python strings (case-sensitive); `<` and `>`
     are false and `<=` and `>=` mean `==` (the specification's recommendation for installation tools, January 2026,
     and `packaging`'s); `~=` and `===` are `None`.

Until 0.13.0 the fallback split the text on ` and ` / ` or ` before reading the strings and compared versions as
tuples: measured on 18/11/2026 without `packaging`, `os_name == 'posix and linux'`, `os_name == 'nt or posix'` and
`platform_release == 'a(b)'` were `None` (kept and counted; `False` for `packaging`), `python_version == '3.9.0'` (on
3.9) and `python_version == '3.*'` were `False` where `packaging` says `True` (a dependency of this interpreter left
out of the SBOM), and `os_name ~= 'posix'` was `True`.
