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

## Amendment of 18/11/2026 (evening), written before the code — rules 8 to 11, the wrapper, the floor, the TR notice

Origin: 41 SBOMs and 13 VEX documents published on GitHub, measured with 0.12.0 on 18/11/2026 (repository, tag, URL and
sha256 of each kept outside this repository; no third-party document is copied here except where a test fixture names
its licence). Texts read on 18/11/2026: spdx/spdx-spec tag `v2.3.1` (`chapters/*.md`), in-toto/attestation `main`
(`50bf017`, `spec/predicates/{cyclonedx,spdx2,spdx3}.md`, Apache-2.0), BSI TR-03183-2 v2.1.0 (2025-08-20; the BSI page
lists it as the current version and 2.0.0 as "outdated"; PDF sha256 `dda0ccd9…845c`).

### SPDX rule 8 — an `SPDXID` is unique (SPDX 2.2 and 2.3; refused)

Text (2.3.1; 2.2.2 the same words): the document identifier (§6.3), a package's (§7.2), a file's (§8.2) and a
snippet's (§9.1) `SPDXRef-[idstring]` "where `[idstring]` is a unique string"; §7.2.2 "Each element needs to be able
to be referred to uniquely so that relationships between elements can be clearly articulated". The JSON schemas
cannot express it. The identifiers are the top-level `SPDXID` and the `SPDXID` string of every item of `packages`,
`files` and `snippets`, compared as exact strings. After the schema check passes, a value that appears more than once
makes the document **not conformant**: refused with `SPDX not conformant to SPDX-2.x §7.2 (SPDXID unique): '<value>'
appears <n> times`, nothing recorded; recorded with `--allow-nonconformant`, floor not met. A repeated identifier makes
every relationship naming it ambiguous: the graph the record keeps would not be the document's. (CycloneDX rule 5 is
the same rule for `bom-ref`.) SPDX 3 (`spdxId` of the JSON-LD graph) is not read by this rule.

### SPDX rule 9 — rules of the SPDX 2.x text the schema does not express (reported with their section, not refused)

After the schema check, `source.spec_rules` lists, for an SPDX 2.2 or 2.3 document, each rule below that the document
does not meet: `{"section": "SPDX-2.3 §8.4", "rule": <short text>, "count": <n>, "examples": <first three>}` (empty
list when every rule is met). `source.schema_check` keeps saying exactly what was checked (`conformant to
<schema file>`): "conformant" in this record never means "conformant to the SPDX specification".

1. **§8.1 a file name is relative** ("Format: A relative filename with the root of the package archive or
   directory"): a `files[].fileName` that starts with `/`, `\` or a drive letter followed by `:` and a slash.
2. **§8.4 a file has a SHA1 checksum** ("Cardinality: 1..1 for the SHA1 algorithm"): a `files[]` item whose
   `checksums` has no item with `algorithm` `SHA1`.
3. **§11.1, Table 68, DESCRIBES** ("mandatory if more than one package or set of files (not in a package) is
   present"): more than one item in `packages` and no DESCRIBES statement, where a DESCRIBES statement is a
   `relationships` item `SPDXRef-DOCUMENT DESCRIBES x`, an item `x DESCRIBED_BY SPDXRef-DOCUMENT`, or a non-empty
   `documentDescribes` (the JSON field the SPDX JSON serialisation uses for the same relationship). Our reading: the
   "set of files not in a package" case is not counted (the text does not say how sets are told apart).
4. **§7.2 / §8.2 / §9.1 / §6.3 the idstring** ("letters, numbers, `.` and/or `-`"), for SPDX 2.2 only: the 2.3.1
   schema already refuses such an identifier in a 2.3 document (pattern `^SPDXRef-[a-zA-Z0-9.-]+$`), the 2.2 schema
   SPDX corrected has no pattern.

Why reported and not refused: SPDX rule 1 refuses what the official schema refuses; SPDX 2.3.1, the release that aligns
the schema with the text, did not add these rules to the schema, and the rules are about the quality of the description,
not about its identity (rule 8). Measured on 18/11/2026: release SBOMs of derailed/k9s v0.51.0 (§8.1, §8.4) and
DeusData/codebase-memory-mcp v0.12.1 (§11.1) miss them, as `pyspdxtools` 0.8.5 says. Not taken from `pyspdxtools`:
undeclared `LicenseRef-`, `file://` cross references (SPDX rule 7 already decides), a licence identifier read as an
exception — three of its findings on the same documents that the text does not support.

### Rule 10 — an SBOM inside an in-toto Statement

in-toto/attestation defines the predicate types `https://cyclonedx.org/bom` (and `…/bom/v<version>`),
`https://spdx.dev/Document` (and `…/Document/v2.3`) and `https://spdx.dev/Document/v3`; "The `predicate` contains a
JSON-encoded CycloneDX BOM" (resp. SPDX document). A JSON object whose `_type` is `https://in-toto.io/Statement/v1` or
`https://in-toto.io/Statement/v0.1` and whose `predicateType` is one of those (exact strings, or the CycloneDX/SPDX
prefix followed by `/v` and a version) is read as follows: its `predicate` must be a JSON object and is checked by every
rule of this text as the document; the stored bytes are the Statement as given (its sha256 is the file's);
`source.wrapper` is `in-toto-statement`, `source.wrapper_predicate_type` the predicate type and
`source.wrapper_subjects` the number of subjects. The Statement is **not** a signature: nothing here says who made it
(a DSSE envelope is refused as before: give the Statement). Any other `_type` or `predicateType` is refused, naming
it.

### Rule 11 — formats refused by name

Unchanged, refused (exit 2, nothing recorded) with the reason naming the format: SPDX tag-value, CycloneDX XML, SPDX
RDF/XML. New: a Syft JSON document (top-level `artifacts`, `source`, `distro`, `descriptor` with `descriptor.name`
`syft`) is refused with `Syft JSON is not supported: convert it with "syft convert <file> -o cyclonedx-json" (or -o
spdx-json)`. Not done in 0.13.0: reading CycloneDX XML (it needs an XML Schema 1.0 validator with the official XSD: none
in the standard library) and SPDX tag-value (a grammar of its own); the README says how to convert them.

### The floor counts versions, not ranges, and not CI actions

`resolved_components` (what `floor_met` needs at least one of) no longer counts a component whose version is a range or
a constraint — a version string containing `<`, `>`, `=`, `,`, `|`, `^`, `*` or white space, or starting with `~` —
nor a component whose purl is `pkg:githubactions/…` (a CI workflow step is not a component of the product: Annex I part
II(1) asks for the product's dependencies). A version with `~` inside (`5.7-0.5~deb12u1`, Debian), `+` or `:` is a
version. `source.versions_not_resolved` counts the components left out as ranges and `source.ci_components` those left
out as CI actions (ingested documents only). Measured on 18/11/2026: the SPDX document GitHub's dependency graph gives
for psf/requests had `floor_met` true from 4 ranges (`>= 2.5,< 4`, …) and 10 GitHub Actions while none of its four
runtime dependencies had a version.

### The format version and BSI TR-03183-2 (a notice, never a refusal)

BSI TR-03183-2 v2.1.0 §4: "A newly generated or updated SBOM MUST be in JSON- or XML-format and a valid SBOM according to
one of the following specifications in one of the specified versions: CycloneDX, version 1.6 or higher; System Package
Data Exchange (SPDX), version 3.0.1 or higher". The CRA does not make the TR binding (no implementing act on the SBOM
format, Art. 13(24), as of 18/11/2026). `source.bsi_tr_03183_2` is `{"version": "2.1.0", "format_minimum_met": <bool>,
"note": …}`: false for CycloneDX 1.2–1.5 and SPDX 2.x. It decides nothing (floor, exit code, refusal), and no other
field of the TR is checked.

## Amendment of 20/11/2026, written before the code — rules 12 and 13, the markers (released in 0.13.1, 2026-11-20)

Origin: a security review of commit 034ed13 (0.13.0) on 20/11/2026. Two SPDX text fields were read with regular
expressions whose time grew with the square of the field's length: measured that day on 034ed13 (Python 3.11.2), a
`creationInfo.creators` item `Tool: ` + `1.1` × 16,000 + `!` (48 kB) took 22.7 s and a `supplier` of
`Organization: (` + `@` × 100,000 + `x(` (100 kB) took 15.1 s, where 24 kB and 200 kB of ordinary text took 0.004 s and
0.021 s. The other expressions of the package that meet text of a third party were then measured the same way
(52 expressions and procedures, 20 of them the distinct `pattern` values of the bundled schemas; a search with
generated strings, not a proof): one more was quadratic (point 3 of rule 13) and the fallback of the markers had two
defects of the same kind (last section). Text read on 20/11/2026: spdx/spdx-spec tag `v2.3.1`, the latest 2.x tag that day
(`chapters/package-information.md`, `chapters/document-creation-information.md`).

### Rule 12 — a text field is read in time proportional to its length

Every procedure of this package that reads a text field of an ingested document (SPDX or CycloneDX) takes a time at
most proportional to the length of the field. No field is refused for its length by this rule: the bound on the
document stays the one on its bytes (`MAX_SOURCE_BYTES`). The rule is on our procedures; the `pattern` values of the
official schemas are the schemas' (what was measured on them is in the CHANGELOG entry, with its date). A procedure
that changes to meet this rule gives the same result as before on every input: rule 13 states those results.

### SPDX rule 13 — the name of a supplier or originator, the name and the version of the tool (SPDX 2.2 and 2.3)

The results are those of 0.13.0; they are written here because the code no longer says them with an expression.

1. **Supplier, originator** (§7.5 Table 17 and §7.6 Table 18: "`Person:` person name and optional `(<email>)`",
   "`Organization:` organization name and optional `(<email>)`", or `NOASSERTION`). A value that is not a string, or
   that is empty, `NOASSERTION` or `NONE` once the white space around it is removed, is no name. Otherwise: the white
   space around it is removed; a leading `Organization:` and then a leading `Person:` are removed, each with the white
   space that follows; then, if the text ends with `)`, and between the last `(` before that `)` and that `)` there is
   an `@` and no other `)`, the text from that `(` on is removed together with the white space before it. Nothing else
   is removed: `Acme (Bar) Ltd` keeps its name, `Acme (Bar) Ltd (x@y.z)` is `Acme (Bar) Ltd`. White space is what
   Python's `str.isspace()` says.
2. **Tool** (§6.8 Table 9: "`Tool: toolidentifier-version`"). The first item of `creationInfo.creators` that starts
   with `Tool:` is taken, every `Tool:` in it is removed and the rest is read as in point 1; `source.generator` is that
   text up to its first `:` (the whole text when it has none; this holds when `spdxVersion` has no `:` itself); when
   no item starts with `Tool:`, or that text is empty, `source.generator` is `unknown-tool` and the version is empty. The version is split off where, reading from the left,
   the text is for the first time one or more decimal digits, a `.`, a decimal digit, and from there to the end only
   letters, digits, `_`, `.` and `-`: `source.generator_version` is the text from that point, and the name is the text
   before it without one `-` or one white-space character immediately before the version, and then without the `-` at
   its end (`syft-1.52.0` is `syft` and `1.52.0`; `LicenseFind-1.0`, the example of §6.8, is `LicenseFind` and `1.0`).
   When there is no such point, or the name would contain a line feed, the whole text is the name and the version is
   empty. A line feed at the very end of the text belongs to neither. Letters and digits are what Python's
   `str.isalnum()` says, decimal digits what `str.isdecimal()` says.
3. **Licence expression** (what `is_spdx_expression` splits; the licence of a component of an ingested document
   reaches it when the record is written). The operators are `OR`, `AND` and `WITH` in capitals, each with white space
   immediately before and after it; reading from the left, a run of white space followed by one of the three words
   and by white space is an operator, and the white space after the word belongs to it (`A OR AND B` is `A` and
   `AND B`). The parts are the text between the operators, as it is. A value is an expression when it has more than
   one part and every part, without the `(`, `)` and spaces at its ends, is an identifier of the SPDX list or ends
   with `-exception` or `-exception-` and digits or dots (a line feed at the very end of the part aside).

### Markers of the installed floor: nesting and length (amends "PEP 508 markers of the installed floor", above)

`marker_applies` answers `True`, `False` or `None` for every text: a marker whose parentheses nest deeper than the
interpreter follows (`RecursionError`, in `packaging` or in the fallback) is `None`, kept and counted like every
marker not evaluated, and so is a marker on which `packaging` raises any other exception (measured on 2482485 on
20/11/2026 with `packaging` 26.2 and 26.3: `ValueError` for a version of more than 4,300 digits, Python's limit on the
conversion of a decimal string to an integer, `KeyError` for `'x' ~= '3.*'`, `SyntaxError` for `python_version == '\'`;
each also ended `cra sbom --installed --transitive` of 0.13.0 with a traceback, exit 1). Measured on 034ed13 on 20/11/2026 (Python 3.11.2, `packaging` 26.2): `python_version >= '3'`
inside 2,000 pairs of parentheses ended the call with `RecursionError`; with 400 pairs the fallback alone did, where
`packaging` answers `True` — there the fallback is now `None`, not `packaging`'s boolean, which the rule above allows
(with 100 pairs both answer `True`).
The fallback reads its tokens in one pass (rule 12 applied to it): until 0.13.0 it copied the rest of the text at each
token, and 100,000 conditions joined by `and` (1.9 MB) took 72.6 s.
