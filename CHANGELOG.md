# Changelog

## 0.13.2 — 2026-11-27 — a secret that comes in never goes out

**Windows: the ledger is written there.** Until 0.13.1 `Ledger.append` took `fcntl.flock`, which Windows does not
have, and refused every append there ("exclusive lock unavailable on this filesystem"): every command with a ledger
failed on Windows. It now takes Windows' equivalent, `msvcrt.locking` on one byte far past the end, held until the
handle closes. Found by the secret-leaks job on windows-latest (Python 3.9 to 3.14), the first job of this repository
to run the commands there; `tests/test_ledger_windows_lock_20261127.py` plays msvcrt on every system (fails on 0.13.1).

**Windows: a full non-blocking stdout is waited for.** Until 0.13.1 the receipt writer waited with `select`, which on
Windows takes sockets only: a non-blocking pipe that was full when the receipt came was exit 74, `receipt not written:
stdout is non-blocking and cannot be waited for: [WinError 10093]` (measured on windows-latest, Python 3.13, CI run
45968134390). Windows now sleeps 10 ms and writes again, as a blocking write would wait. Found when the CI started to
run the whole suite on macOS and Windows (Python 3.9 to 3.14, with and without the extras): `NonBlockingStdout` and
`InProcess.test_unflushed_caller_text_on_a_full_nonblocking_pipe` in `tests/test_receipt_design_20261013.py` fail on
0.13.1 there (measured on Python 3.12 and later, where `os.set_blocking` takes a Windows pipe).

**Windows, before Python 3.12: a full non-blocking stdout reported as ENOSPC is waited for too.** There the interpreter
raises `OSError` ENOSPC, not `BlockingIOError`, for a full PIPE_NOWAIT pipe: the receipt writer now treats that errno as
"full" only on a descriptor that is a pipe (GetFileType), and writes in pieces of 4096 bytes there (a `BufferedWriter`
handed part of a larger piece to the pipe before raising and the part came twice: measured in ap2-evidence-pack, same
author). The tests now make the pipe non-blocking with `SetNamedPipeHandleState` on every Windows Python and pass on
3.9 to 3.11 (CI run 45979434746); on 0.13.1 they did not run there (skipped), so the failure before is not measured here.

**Windows: a receipt outside the ANSI code page is written.** Python gives a pipe the ANSI code page (cp1252) on Windows:
`cra verify` of a path with `✓` exited 74, `receipt not written: 'charmap' codec can't encode character '\u2713'`, for a
user who set nothing (CI run 45979434746, Windows, Python 3.9; `DefaultEncoding` in
`tests/test_receipt_design_20261013.py`). The receipt is now UTF-8 unless `PYTHONIOENCODING` names an encoding, as the
JS, Go and Rust verifiers write it. This holds on every system: with a UTF-8 locale, and with C or POSIX (which Python
turns into UTF-8), the bytes are those of 0.13.1 (measured on Linux, Python 3.9 and 3.13). Under a locale that is not
UTF-8 the receipt changes: 0.13.1 wrote it in the locale's encoding and exited 74 when it held a character outside it
(`cra verify` under `en_US.ISO-8859-1`: `'latin-1' codec can't encode character '\u2026'`); 0.13.2 writes UTF-8, and a
non-ASCII path the receipt repeats is the locale's reading of its bytes written in UTF-8 (`dé` arrives as `dÃ©`), where
0.13.1 gave back its bytes.

**The four verifiers on Windows agree** (the differential oracle ran there for the first time, CI run 45979434746; 17
divergences, all now cases of `verifiers/differential.py` on the three systems):
- the Rust verifier joined a stored source document's path with `/` to a verbatim `\\?\` path from `canonicalize`,
  where `/` is not a separator (os error 123): every ingested SBOM's stored source read as unusable. It now joins with
  the system's separator.
- a pack path ending with a separator or a `.` component (`p.json/`, `p.json/.`): POSIX answers ENOTDIR, while on
  Windows Node read `p.json/` and Go refused `p.json/.`, which Python read. The four now refuse such a path
  (`pack-json` FAIL) before the OS sees it.
- a full non-blocking stdout on Windows (PIPE_NOWAIT, which takes 0 bytes and reports success): the Rust verifier
  exited 74 ("failed to write whole buffer") and the Go verifier spun at one CPU second per second until the reader
  came (CI run 46013986663, `NonBlockingStdout.test_verifiers`). Both now wait 10 ms between tries on a pipe there; a
  console or a file is written by the language's own stdout as before (on a console it writes UTF-16: bytes written
  straight to it would be read in the console's code page).
- Node reports a name too long for the file system as ENOENT on Windows: a 263-character sidecar name read as "not
  signed" there while the three others refuse it. A last component above 255 UTF-16 units is never "absent" now.

The class found on 25-26/11/2026 in ap2-evidence-pack 1.11.2 and cryptovalid-opencore 0.29.1 (same author), searched
here on 27/11/2026. The inputs that take a secret, counted with `grep` on the sources: the seed files of `--key` (`sign`,
`attest`) and `--tip-key` (every command with a ledger, `seal`), the seed `keygen` writes, `--aws-creds-file`, the
variables `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, `AWS_SESSION_TOKEN` and `AWS_KMS_ENDPOINT`, the arguments of
`KMSSigner`, the names of a `--trust-store` and the private key of a long-term `Signer`. `tests/test_secrets.py` puts a
canary into each and searches standard output and error, every file written, the exception, and the environment and
argv of the one child process (openssl), raw and in hex, HEX, decimal, base64 and base64url at the three offsets. On
0.13.1 15 of its 27 tests fail (16 on 0.12.0); the outputs where the canary was found:

- **A KMS endpoint with user information is refused before the network**, without repeating the URL. 0.13.1 accepted
  `https://u:PASSWORD@host/` in `AWS_KMS_ENDPOINT` (or `endpoint=`): http.client read `PASSWORD@host` as a port, and the
  traceback of `cra sign` / `cra attest` printed it on stderr; `https://PASSWORD@host/` sent `PASSWORD@host` to the
  name resolver.
- **A failed KMS request says its kind, errno and HTTP status, never its text** (`OSError`, no chained traceback).
- **openssl runs without the four AWS variables** in its environment; 0.13.1 passed the whole environment.
- **A key file that cannot be read is not named**: a seed given in place of the path of `--key` or `--tip-key`, or a
  secret in place of `--aws-creds-file`, was printed in the `FileNotFoundError` of the traceback. The error now says
  `the key file cannot be read (FileNotFoundError)`, with its errno.
- **No message repeats a secret typed in place of an argument.** A run of 40 or more base64 / hex / path characters of
  an argument (an AWS secret key has 40) is not repeated on standard error nor in the outcome on standard output unless
  it names a path: one that exists, or one whose folder part exists and is not a root (`/` + 39 characters is not
  repeated; a name with no folder part that does not exist is not repeated either). An AWS access key id (`AKIA` /
  `ASIA` + 16) is never repeated there. 0.13.1 printed it in usage errors (`cra verify p.json SECRET`, an extra
  argument, an invalid choice), in the errors of a missing file given as the pack, envelope, drop file, VEX, trust
  store, `--renew`, `--from-cyclonedx`, `--fields`, and in the errors of an invalid instant (`--aware`,
  `--support-period-end`). The values the outcome repeats by contract stay as given (`--pack-sha3`, `--log-pubkey`,
  `--sealer-pubkey`, `--token-b64`, `--product`, `--version`, `--id`, `--signer-id`, `--component`, `--srp-reference`,
  `--filed-at`, `--filed-by`, `--source-version`, `--divergence-reason`, `--shorter-use-reason`, `--case-reference`,
  `--aws-kms-key-id`, `--aws-region`, `--installed`).
- **An argument that holds the secret of the run refuses the run** (exit 2, nothing written, the secret not named): the
  seed of `--key` or `--tip-key` (hex, HEX, base64, base64url) or an AWS credential, inside a `--signer-id`, a
  `--product` or any other argument. 0.13.1 wrote a seed given as `--signer-id` into the sidecar.
- **The AWS credentials file is closed**: a line that is not blank, a `#` comment, or one of `AWS_ACCESS_KEY_ID`,
  `AWS_SECRET_ACCESS_KEY`, `AWS_SESSION_TOKEN` once with a value is refused by its line number, never repeated
  (`export NAME=…` and `AWS_REGION=…` included: refused, where 0.13.1 ignored them in silence); a file that is not
  UTF-8 is refused without naming the byte.
- **A key file that is not a seed is refused without naming one of its bytes** (0.13.1: `can't decode byte 0x.. in
  position N`).
- **`--aws-region` must be a region name** (`[a-z0-9]+(-[a-z0-9]+)+`): `evil.example/` moved the host of the signed
  request (`kms.evil.example`), with its session token.
- **A name of more than 32 characters is named by its length** (`of 43 characters`) in the reasons of
  `verify-attestation` about a trust store key, and in the duplicate-key error of the strict JSON reader (ledger lines,
  trust stores, notice fields, envelopes); 0.13.1 repeated up to 80 characters of a trust store name, or the whole name
  of a duplicate key, on stdout or stderr.

Found clean on 0.13.1: the seed in `keygen`'s output, in the sidecar, tip, ledger and seal; the content of a seed file
that is UTF-8 but not a seed; the private key of an ephemeral or given `Signer` in a seal; the credentials of a creds file or of the
environment in the output of a KMS request that fails.
A private key given as the value of a public key (`--log-pubkey`, `--sealer-pubkey`, a trust store value) is not
repeated by `verify`, `verify-seal` and `verify-attestation` (measured on 0.13.1 and here, `tests/test_secrets.py`).
Not covered: a secret this run does not hold, typed as one of the values the outcome repeats by contract (above), is
recorded and printed as typed; a run of 39 characters or fewer is repeated.

## 0.13.1 — 2026-11-20 — text of a third party is read in time proportional to its length; the ledger's state file is written like every other file

Found by a security review of commit 034ed13 (0.13.0) on 20/11/2026 and measured that day on that commit with Python
3.11.2; `spec/SBOM_INGEST.md`, amendment of 20/11/2026 (rules 12 and 13), written before the code. No verdict, record or
exit code changes for a document that was read before; `tests/test_sentry_20261120.py`.

- **The `Tool:` item of an SPDX document's `creationInfo.creators` is split into name and version in one pass** (rules
  12 and 13(2)). 0.13.0 used a regular expression whose time grew with the square of the item's length: `Tool: ` followed
  by `1.1` repeated 2,000 / 4,000 / 8,000 / 16,000 times and `!` (6 to 48 kB) took 0.25 / 0.98 / 4.43 / 22.7 s in
  `sbom_from_spdx` (24 kB of letters: 0.004 s), and `cra sbom --from-spdx` on the 24 kB document 10.5 s. Now the 48 kB
  document takes 0.005 s and a 1 MB one under 0.3 s. `source.generator` and `source.generator_version` are the same as
  before on every input: compared with the expression of 0.13.0 on every string of up to 7 characters over
  `1.-a !` and line feed (960,800 strings), up to 6 over a second alphabet with a non-ASCII decimal digit, `²`, `_`
  and other white space (299,593), 40,000 seeded random strings, and the creators of the documents in `tests/fixtures`
  with 400 changes each.
- **The name of an SPDX `supplier` or `originator` is read in one pass** (rules 12 and 13(1); SPDX 2.3.1 §7.5 and
  §7.6: "organization name and optional `(<email>)`"). 0.13.0 removed the trailing e-mail with a regular expression
  that was quadratic: a supplier of `Organization: (`, `@` repeated 25,000 / 50,000 / 100,000 times and `x(` took
  0.95 / 3.76 / 15.1 s (200 kB of letters: 0.021 s). Now the 100 kB document takes 0.011 s and a 1 MB one under 0.3 s.
  The name is the same as before on every input: compared with the expression of 0.13.0 on every string of up to 7
  characters over `(@) a` and line feed (335,923 strings), up to 6 over a second alphabet with other white space
  (137,257), 40,000 seeded random strings, and the supplier, originator and creator strings of the documents in
  `tests/fixtures` with 400 changes each.
- **The ledger's append state is written to a new file of a random name and renamed** (`outputs.write_tmp`:
  `O_EXCL | O_NOFOLLOW`, as the pack, the sidecar, the tip and the stored sources already were). 0.13.0 opened
  `<ledger>.append-state.json.tmp` with `open(..., "wb")`: a symbolic link left at that name by anyone who can write
  in the ledger's folder was followed and the file it pointed to was overwritten with the state (measured on a file next
  to the ledger); a FIFO at that name blocked `append` for good after the record was
  already in the ledger. The state is a cache and nothing else changes: same name, same content, a state that cannot
  be written is still a warning and a full read at the next append. Every other file the package creates was checked
  the same day: an audit hook in the test records each file opened with `O_CREAT` while the package appends, stores a
  source document, writes a pack, a signed tip and a signature, and each is the ledger itself (the caller's file,
  opened for append) or is created with `O_EXCL`. The files `time_anchor` gives to `openssl` are inside a
  `tempfile.mkdtemp` folder; `scripts/` and `verifiers/` (development tools) were not changed.
- **A licence expression is split at its operators in one pass** (rules 12 and 13(3); found by measuring the other
  expressions of the package after the two above). `is_spdx_expression` — reached by `record_sbom` with the licence of
  each component of an ingested document — split with a regular expression that was quadratic in a run of white space:
  a `licenseConcluded` of `a`, 4,000 / 8,000 / 16,000 / 32,000 spaces and `b` took 0.10 / 0.37 / 1.46 / 5.83 s in
  `record_sbom` (32 kB of letters: 0.015 s). Now 0.014 s for the 32 kB one, and a 1 MB one is recorded within the
  test's ceiling. The parts and the answer are the same as before: compared on every sequence of up to 6 pieces among
  space, line feed, `OR`, `AND`, `WITH`, `x`, `(`, `O` (299,593), 40,000 seeded random strings and the licences of
  the documents in `tests/fixtures` with 200 changes each.
- **`marker_applies` answers `None` for a marker nested deeper than the interpreter follows, and the fallback reads its
  tokens in one pass** (`spec/SBOM_INGEST.md`, "Markers of the installed floor: nesting and length"; the text is the
  `Requires-Dist` of an installed distribution, `cra sbom --installed`). 0.13.0: `python_version >= '3'` inside 2,000
  pairs of parentheses ended the call with `RecursionError` (with `packaging` 26.2 and with the fallback; the fallback
  already with 400 pairs), although the rule says the answer is always `True`, `False` or `None`; and the fallback
  copied the rest of the text at each token: 12,500 / 25,000 / 50,000 / 100,000 conditions joined by `and` (0.24 to
  1.9 MB) took 2.35 / 7.01 / 20.6 / 72.6 s, now 0.05 / 0.09 / 0.18 / 0.36 s. The tokens are the same as before (compared
  on 75,595 short strings and 40,000 seeded random ones), and up to 39 pairs of parentheses around a marker do not
  change its answer (called from a shallow stack with the default recursion limit: from a caller already about 900
  frames deep the fallback answers `None`). With `packaging` installed, `marker_applies` also answers `None` where
  `packaging` raises any other exception: 0.13.0 ended `cra sbom --installed --transitive` with a traceback (exit 1) on
  a `Requires-Dist` marker with a version of more than 4,300 digits (`ValueError`), `'x' ~= '3.*'` (`KeyError`) or
  `python_version == '\'` (`SyntaxError`), measured with `packaging` 26.2 and 26.3.
- **The other expressions of the package that read text of a third party were measured the same day** — a search, not
  a proof: for each, strings made of a prefix, a piece repeated n times and a suffix, n doubled up to 300 kB or 0.4 s,
  flagged when the time more than triples at a doubling. 52 expressions and procedures, 20 of them the distinct
  `pattern` values of the bundled CycloneDX, SPDX and OpenVEX schemas as `ecma_pattern` compiles them. The bench flags
  the two expressions of 0.13.0 above (its positive control). On this tree the four procedures changed here are not
  flagged; three expressions are, at times of 0.08 to 0.14 s, near the bench's threshold (`IRI_REFERENCE`, `URI`, and
  the recognition of SPDX tag-value, which is given the first 4,096 bytes only): re-measured on eleven shapes at four
  lengths from 0.5 MB up, each double the one before (best of three runs), their time is at most 2.43 times at each
  doubling. The `format` checks of
  `jsonschema` and what `openssl` reads were not measured.

## 0.13.0 — 2026-11-19 — SBOMs checked against the rules of their specification text, not only its schema

- **An SPDX 2.2 or 2.3 document that repeats an `SPDXID` is not conformant** (`spec/SBOM_INGEST.md`, SPDX rule 8, written
  before the code; changes verdicts). §6.3, §7.2, §8.2 and §9.1 of the text: `SPDXRef-[idstring]` "where [idstring] is a
  unique string"; the JSON schemas cannot say it and 0.12.0 recorded such a document as conformant (measured on
  18/11/2026 on a real release SBOM with one identifier repeated: exit 0, no warning). Refused with `SPDX not conformant
  to SPDX-2.x §7.2 (SPDXID unique): '<value>' appears <n> times`; recorded with `--allow-nonconformant`, floor not met;
  `source.spdxid_repeated` and `source.spdxid_repeated_examples`. None of the 18 SPDX 2.3 release SBOMs measured that
  day repeats an identifier.
- **"conformant" names the schema, and the rules of the SPDX text the schema does not express are reported with their
  section** (SPDX rule 9; reported, not refused). `source.schema_check` says `conformant to <schema file>` and nothing
  more; `source.spec_rules` lists, for an SPDX 2.x document, each rule not met with its section, a count and the first
  three cases: §8.1 a file name is relative, §8.4 a file has a SHA1 checksum, §11.1 DESCRIBES when there is more than
  one package, and for SPDX 2.2 the idstring of §7.2 (for 2.3 the 2.3.1 schema refuses it). Measured on the 18 SPDX 2.3
  release SBOMs of 18/11/2026: derailed/k9s v0.51.0 (§8.1 once, §8.4 three files), DeusData/codebase-memory-mcp v0.12.1
  (§11.1) and the SPDX document inside docker/compose v5.8.0's Statement (§8.4, one file) are reported; `pyspdxtools`
  0.8.5 reports the first two the same way. Three other findings of `pyspdxtools` on those documents are not taken (an
  undeclared `LicenseRef-`, `file://` cross references, a licence identifier read as an exception): the text does not
  support them.
- **The SPDX 2.3.1 schema refuses two release SBOMs that 0.12.0 accepted** (a consequence of SPDX rule 6, above;
  measured after that entry was written). grafana/grafana v13.3.1 (30 of 3,819 identifiers) and grafana/loki v3.7.10
  (9 of 486) have `SPDXID` values with `+` or `_`, which §7.2 does not allow ("letters, numbers, `.` and/or `-`"); the
  2.3 schema had no pattern, the 2.3.1 schema has `^SPDXRef-[a-zA-Z0-9.-]+$`. They are refused with the schema's
  message, or recorded with `--allow-nonconformant`. The sentence above about 63 documents holds for those 63; these
  two are outside them.
- **An SBOM inside an in-toto Statement is read** (rule 10). A JSON object whose `_type` is the in-toto Statement v1 or
  v0.1 and whose `predicateType` is `https://cyclonedx.org/bom` or `https://spdx.dev/Document` (also with `/v<version>`)
  is ingested through its `predicate`; the stored bytes and the sha256 are the Statement's; `source.wrapper`,
  `source.wrapper_predicate_type`, `source.wrapper_subjects`. The Statement is not a signature and nothing says who
  made it; a DSSE envelope, another `_type` or another predicate type is refused by name. Measured: the SBOM
  docker/compose attaches to v5.8.0 (refused by 0.12.0) is recorded, floor met.
- **Formats not read are refused with the way to convert them** (rule 11). Syft JSON is named and refused with `syft
  convert <file> -o cyclonedx-json`; SPDX tag-value with `pyspdxtools -i <file>.spdx -o <file>.spdx.json --novalidation`
  (spdx/tools-python); CycloneDX XML with `cyclonedx convert --input-file <file>.xml --output-file <file>.json`
  (CycloneDX/cyclonedx-cli). Measured on 18/11/2026 with spdx-tools 0.8.5: the tag-value SBOMs of istio 1.32.0 and
  minikube v1.39.0, converted with that command, are recorded (`conformant to spdx-schema-v2.3.1.json`, floor met). The
  cyclonedx-cli command is the one of its README, not run here (the tool is 80 MB). Reading CycloneDX XML and SPDX
  tag-value directly is not done in 0.13.0.
- **The SBOM floor counts versions, not ranges, and not CI actions** (changes verdicts). A component whose version
  contains `<`, `>`, `=`, `,`, `|`, `^`, `*` or white space, or starts with `~`, and a component whose purl is
  `pkg:githubactions/…`, are no longer resolved components; `source.versions_not_resolved` and `source.ci_components`
  count them. Measured: the SPDX document GitHub's dependency graph gave for psf/requests on 18/11/2026 had 16
  "resolved" components in 0.12.0, 10 of them GitHub Actions and 4 ranges; here 2 (the pinned development packages).
  The number of resolved components of the 26 release SBOMs accepted before and after this change is the same.
- **A notice of BSI TR-03183-2 v2.1.0** (never a refusal). `source.bsi_tr_03183_2.format_minimum_met` is false for
  CycloneDX 1.2–1.5 and SPDX 2.x: §4 of the TR asks CycloneDX 1.6 or SPDX 3.0.1 "or higher". The CRA does not make the
  TR binding and no other field of the TR is checked.
- **A document attached to a vulnerability record is checked for the format it declares; `cra vex`, `cra vuln --vex`**
  (`spec/VEX.md`, written before the code; changes what the API accepts). Until 0.12.0
  `record_vulnerability(attachments=…)` kept any JSON object under any of the five labels: measured on 13 documents
  found on GitHub, 39 of 39 (document, label) pairs tried were accepted, wrong labels and the OpenVEX JSON-LD context
  among them. Now `openvex` is the `@context` of 0.2.0 and the OpenVEX 0.2.0 JSON schema (openvex/spec `93139bd`,
  CC0-1.0, in `omega_cra_evol/data/openvex/`); `cyclonedx-vex` and `cyclonedx-sbom` a CycloneDX BOM as `cra sbom` checks
  it (a VEX needs a non-empty `vulnerabilities`); `spdx-3.0` the SPDX 3.0.1 schema; `csaf-2.0` the form only (the
  five required properties of `document`): the CSAF schema is not shipped (the oasis-tcs/csaf repository is under the
  OASIS IPR policy; GitHub reports no licence) and `schema_check` says `form only (CSAF 2.0 schema not shipped)`. A
  document that is not of its declared format is refused with the reason and nothing is recorded; the entry kept gains
  `schema_check`. A value that does not meet a `format` of the OpenVEX schema is reported (`format_not_met`), not
  refused: in JSON Schema 2020-12 `format` is an annotation. On the 13 documents: 8 accepted as `openvex`, 5 refused
  (four with an empty `statements`, the JSON-LD context), and all 13 refused under each of the other four labels.
  `cra vex FILE --format LABEL` checks a file and records nothing (exit 0 or 2); `cra vuln --vex FILE --vex-format
  LABEL` attaches it. VEX statements are not compared with the record or with an SBOM.
- **`cra vuln --component`: the vulnerability record names the component of the recorded SBOM**
  (`spec/RECORD_LINKS.md` §1, written before the code). Each query (a purl, `NAME` or `NAME@VERSION`) is looked up in
  the last SBOM record of the product and version; the record gains `affected_components` (query, `in_sbom`, the
  matches) and `sbom_record` (which SBOM record). No SBOM recorded: exit 2, nothing recorded. A component that is not
  in the SBOM is recorded as such and the command exits 1 (`--allow-not-in-sbom`: 0). A record written without
  `--component` has the keys it always had. No vulnerability database is queried with the SBOM.
- **`cra notice` says where the notice disagrees with the ledger** (`spec/RECORD_LINKS.md` §2). `ledger_consistency`
  in the output, and one warning line each on stderr: no vulnerability record for the notice's CVE / EUVD id, a
  deadline already passed when the notice is prepared, a product version that is not the ledger's, a `component_name`
  that names no component of the recorded SBOM. Measured with 0.12.0: a notice with all of the first, second and
  fourth was recorded with exit 0 and no warning. The record and the drop file do not change; the exit code changes
  only with `--strict`.
- **`cra verify-seal`: the seals of a ledger are verified from the command line** (`spec/TIME_ANCHOR.md` §10). Until
  0.12.0 a seal was verified when made, or through the Python API. The command verifies the ledger, then for each
  sealed digest the last seal record: signatures, order, algorithm policy at `--at`, and with `--tsa-cert` the RFC 3161
  time of every record; `--sealer-pubkey` pins who sealed. Without `--tsa-cert` the output says the times are ASSUMED.
  Exit 0, 1, or 74 when openssl cannot be run and no seal fails on what openssl is not needed for (signatures, the
  sealer pin, order, policy, a record with no token under `--tsa-cert`: those are exit 1 without openssl too).
  `cra verify` is unchanged.
- **A generator document is opened as a regular file only** (`cra sbom`, `cra vex`, `cra vuln --vex`). Until now
  `cra sbom --from-cyclonedx` on a FIFO waited forever and on `/dev/zero` read until the process was killed (measured
  on 0.12.0 and on the first 0.13.0 code); it is refused before a byte is read, exit 2.
- **Every file a caller names is read as a regular file within a bound** (`ledger.read_regular`; the same class,
  searched in the whole package after the review of 18/11/2026). Until now these waited forever on a FIFO:
  `cra seal --renew FILE`, the seed file of `--key` / `--tip-key` (`signing.load_key`), the pack of `cra sign`
  (`signing.sign_pack`), `--aws-creds-file` (`kms.load_creds_file`), `sbom.source_fingerprint`, the `source_path` of
  `EvidenceLocker.record_sbom`, and a FIFO left in place of the ledger's `.append-state.json` cache blocked every
  append. A `--tsa-cert` file, a stored source document and a stored sbomify document compared with new bytes are read
  the same way. Files the package ships (schemas) and files it has just written are read as before.
- **An API that takes a list refuses a string or a dictionary** (the same class as `components="left-pad"`, which
  recorded one query per character). `feeds.exploitation_signal("CVE-…")` answered "not exploited" for an identifier
  in the catalogue (it compared the characters); `sbom_from_installed(p, v, "pip")` listed the components `p` and `i`;
  `LongTermEvidence.verify(trusted_pubs=<string>)` accepted any key the string contains;
  `record_vulnerability(attachments="")` or `{}` meant "no attachment". Each is a `ValueError` now, as are
  `match_components`, `record_vulnerability(components=…)` and `feeds.osv_query_batch` (an `AttributeError` before).
  The command line always passed lists: no command changes.
- **The Commission guidance is cited as published** (`spec/LEGAL_BASIS.md`, re-check of 18/11/2026): C/2026/6013, OJ C,
  17.11.2026 (the draft was C(2026) 5252), §8 "not binding", §210, §213, §217, §218, §233 read; Regulation (EU) 2025/327,
  Article 104, which replaces Art. 13(4) and 31(3) of the CRA and inserts Art. 32(5a), is recorded (no effect on what
  this tool computes). `cra obligations` prints `guidance_published` (`applicability.GUIDANCE_PUBLISHED`); the
  `interpretation` text written into every vulnerability record still cites the draft, §217 with the same words: its
  bytes are those of the records the art14-filing vectors are generated from, and they do not change.
- **Positive controls of the tests added on 18/11/2026 (evening)**, each file run on the code of commit `c215a64` (before
  these changes; Python 3.11, jsonschema, cryptography): `test_sbom_rules_20261118b` 6 failures and 15 errors of 24
  tests (1 skipped: the network), `test_vex_declared_format_20261118` 5 failures and 14 errors of 21 (2 skipped),
  `test_record_links_20261118` 1 failure and 12 errors of 13, `test_verify_seal_20261118` 3 failures and 3 errors of 6;
  on this code all four pass. 30 mutants chosen by hand on the new lines of `sbom.py`, `vex.py`, `locker.py` and
  `cli.py`: 27 killed by these four files as first written, the other 3 after one case each was added (an id in lower
  case in the notice, `--strict` on a complete notice, the seal evaluated after a renewal). With `CRA_REAL_NET=1` the two network tests read 18 release SBOMs and 13 VEX documents
  by URL, check each sha256 and the verdict written next to it (run on 18/11/2026: pass).
- **Review of 18/11/2026 (night) on the 0.13.0 branch**, its eight findings corrected and the two classes searched in
  the whole package (the three entries above on regular files, lists and `cra verify-seal` without openssl; a scoped
  npm name with a version in a notice's `component_name` is no longer "not in the SBOM"; two README sentences and the
  CSAF note in `vex.py` reworded). `.gitleaksignore` gains the line for `SIGNING.md` of commit `d9d4aff`: the value
  gitleaks reports there is the SHA-256 of the public release key printed on the line above it (recomputed). With
  gitleaks 8.24.3 (the CI's binary, same sha256) on the whole history of a clone of this branch: exit 1 without the
  line, 0 with it. Positive control: `tests/test_review_20261118c.py` on the code of `f7e9072` gives 11 failures and
  1 error of 14 tests (the two controls pass), and `test_sbom_sources.test_ingest_reads_the_file_once`, rewritten to
  count the reads through `read_regular`, fails there; here they pass. 24 mutants chosen by hand on the changed lines:
  23 killed (4 of them after a case was added), 1 equivalent (the read of a `--tsa-cert` file, which `os.path.isfile`
  already guards). One defect of the review's own patch was found and corrected before the commit: without openssl
  it turned a valid renewed chain into exit 1, where "not checked" (74) is the answer.
- **SBOMs from microsoft/sbom-tool are no longer refused; SPDX 2.2 and 2.3 are checked with the schemas SPDX corrected**
  (`spec/SBOM_INGEST.md`, SPDX rule 6, written before the code; changes verdicts). 0.11.0 to 0.12.0 checked an SPDX-2.2
  document with the schema of the tag `v2.2.2` of spdx/spdx-spec, which points at a 2.2.1-era commit (`a05c12a`, its
  index reads "Version 2.2.1") whose `referenceCategory` enum is `OTHER`, `SECURITY`, `PACKAGE_MANAGER`, while §7.21 of
  the text says `SECURITY | PACKAGE-MANAGER | PERSISTENT-ID | OTHER`. SPDX corrected the schema on `development/v2.2.2`
  (spdx-spec#798, PR #836 merged 2023-03-10). Measured on 18/11/2026: the 4 SPDX 2.2 SBOMs of sbom-tool v4.1.5
  (235 and 258 references, all `PACKAGE-MANAGER`) were refused 4 of 4; the corrected schema finds 0 errors in them. An
  SPDX-2.2 document is now checked with `spdx-schema-v2.2.2-4694d1f.json` (head of `development/v2.2.2`: both spellings of
  the categories, as SPDX's correction; as the text, `documentNamespace`, `creationInfo.creators`, a file's `checksums`
  and `licenseInfoInFiles` and a snippet's `ranges` required, snippet `name` optional, relationship `AMENDS`), an SPDX-2.3
  document with `spdx-schema-v2.3.1.json` (tag `v2.3.1`, the maintenance release the specification site serves under
  `v2.3`; JSON Schema 2019-09): `primaryPackagePurpose: OPERATING-SYSTEM` (§7.24), refused by 0.12.0, is accepted and the
  2.3 schema's `OPERATING_SYSTEM` refused; `PACKAGE_MANAGER`/`PERSISTENT_ID` are accepted; `documentNamespace`, the
  `SPDXID`, checksum and date patterns are required. On 63 SPDX 2.3 documents (50 release SBOMs of 13 projects,
  6 generator outputs of the September bench, 7 fixtures and controls of the tests) the verdict of 2.3 and 2.3.1 is the same for every one; on the 6 SPDX 2.2 documents only
  the 4 of sbom-tool change (refused → accepted). `tests/data/sbom_tool_415/` keeps one of them (MIT).
- **An SPDX 2.x `seeAlsos` value must be a URL** (SPDX rule 7; changes verdicts). §10.4 of the text: "Format: Uniform
  Resource Locator", RFC 3986 a normative reference. A value that is not an RFC 3986 `URI` is not conformant (refused
  with `SPDX not conformant to SPDX-2.3 §10.4 at hasExtractedLicensingInfos/<i>/seeAlsos/<j>: not a URL …`; recorded
  with `--allow-nonconformant`, floor not met). A URL whose scheme is not http/https — Syft's `file://$GOPATH/pkg/mod/…`,
  1,312 values in the measured documents, none of them refused — is reported in `source.see_also_not_web` with the first
  three in `source.see_also_not_web_examples`. No measured release SBOM has a seeAlsos value that is not a URI.
- **A CycloneDX 1.4–1.7 document that repeats a `bom-ref` is not conformant** (CycloneDX rule 5; changes verdicts). The
  JSON schemas of 1.4–1.7 say every bom-ref "MUST"/"must be unique within the BOM", ECMA-424 (2nd edition, December
  2025) "shall be unique" and lets a consumer raise an error on a non-conforming BOM; the XML schema of every version
  1.2–1.7 declares it `xs:unique`; 0.12.0 recorded such a document as conformant, floor met. Refused with `CycloneDX not
  conformant to bom-<v> (bom-ref unique within the BOM): '<value>' appears <n> times`; recorded with
  `--allow-nonconformant`, floor not met. In 1.2–1.3, whose JSON text says only "should be unique", it is reported, not
  refused: `source.bom_ref_repeated` (distinct repeated values) and `source.bom_ref_repeated_examples` (first three), in
  every version. Refused now: the cdxgen 12.8.4 fixtures (cdxgen repeats its tool component as
  `annotations[0].annotator.component`) and two `valid-*` JSON files of the official suite whose XML twins do not repeat
  the value (`valid-formulation-1.5.json`, `valid-citations-1.7.json`; the suite checks its JSON files with the JSON
  schema only, which cannot express uniqueness).
- **Unresolved CycloneDX references are counted on every reference field** (CycloneDX rule 6; reported, not refused:
  no requirement keyword and no `xs:keyref`). `source.dangling_by_field` counts the values of `dependencies[].ref`,
  `dependsOn`, `provides` and `compositions[].assemblies`, `dependencies`, `vulnerabilities` that name no `bom-ref`;
  `source.dangling_refs` lists the first ten of them; a BOM-Link (`urn:cdx:`) is not counted. The known identifiers are
  those of every object: 0.12.0 knew only components and `metadata.component`, so an edge to a service was reported as
  dangling.
- **SECURITY.md and SUPPORT.md: no fixed response times.** The 72-hour acknowledgement and 14-day fix promises are
  replaced by "as soon as possible, with no SLA or fixed deadline": one maintainer, non-commercial, consistent with
  SIGNING.md.

- **An RFC 3161 token whose TSA names its signer by subjectKeyIdentifier is verified instead of refused**
  (`spec/TIME_ANCHOR.md` §5 step 8, amended before the code). RFC 5652 §5.3 allows a SignerInfo to name its signer by
  subjectKeyIdentifier; `openssl ts -verify` reads the token as PKCS #7 and refuses that form with an ASN.1 error, so
  0.12.0 refused a valid token of this form as `not_issued_by_pinned_tsa`, in `make_timestamp_trust_fn` and in
  `cra seal --tsa-cert` (nothing recorded). For that form the checks of `ts -verify` are now made one by one, ported from
  cryptovalid-opencore's SPEC §11 step 7 (v0.10, same author): exactly one SignerInfo with signed attributes; the ESS
  signingCertificate or signingCertificateV2 attribute, its shape closed, with exactly one ESSCertID whose certHash and
  issuerSerial name the signer certificate; the TSTInfo `tsa` field (one GeneralName: the signer's subject or one of
  its subjectAltName); names compared as OpenSSL's `X509_NAME_cmp` compares them; `openssl verify -purpose
  timestampsign -partial_chain -attime <genTime> -no-CApath -no-CAstore` with the pinned certificates and those of the
  token, so no system certificate takes part. An openssl that does not know these options (before 3.0) raises
  `TimeAnchorNotRun`, never a refusal. A token naming its signer by issuerAndSerialNumber is checked as in 0.12.0. The
  closed list of reasons does not change. **Changes verdicts**: a record refused by 0.12.0 can be accepted.
  Positive control: the class `SealedKeyId` of `tests/test_time_anchor_key_id_20261117.py`, run on the tree of v0.12.0
  (OpenSSL 3.0.22), fails 4 of its 7 tests, each a valid key-identified record refused; here the file's 30 tests pass.
  Negatives: another certificate's key identifier, another TSA's key, no ESS attribute, a certificate without
  timeStamping, a `tsa` field naming another TSA, a system certificate directory trusting another CA, two SignerInfos,
  an openssl without `-no-CAstore`. Generative: every DER element of the token dropped, duplicated, retagged, given a
  stranger element or flipped (the step never raises; every change inside the ESS attribute that leaves it invalid is
  refused). 31 of 31 mutants chosen by hand on the changed lines are killed.
- **An RFC 3161 token whose signer certificate is nowhere to be found is "not evaluated", no longer "invalid"**
  (`spec/TIME_ANCHOR.md` §5 step 7, written before the code; new reason `signer_certificate_absent`, logged with
  `"ok": None`). When `openssl cms -verify` stops at the signer lookup and every certificate of the token and every
  pinned one was read and none is the one the SignerInfo names (issuerAndSerialNumber or subjectKeyIdentifier), the
  signature was not evaluated (ETSI EN 319 102-1 §5.2.3.3): the record is not attested and the log says to pin the TSA
  certificate. A token openssl cannot parse stays `signature_invalid` (§5.3.4); the absence is never presumed.
- **More than one ESSCertID** (`spec/TIME_ANCHOR.md` §5 step 8; changes verdicts). RFC 2634 §5.4 / RFC 5035 §3: the
  first ESSCertID is the signer certificate, the ones after it limit the certificates the path may use. `openssl ts
  -verify` asks every listed certificate to be in the chain it built, so a token listing signer, CA and root with the
  CA pinned (the shape of Sectigo's TSA) was refused; such a token is now checked as for a subjectKeyIdentifier signer
  (ported from cryptovalid-opencore SPEC §11 step 7, v0.11): every ESSCertID's shape closed (hash length, known
  algorithm, one directoryName, a certificate listed twice refused), the chain built only from the listed
  certificates. Two attributes (v1 and v2) limit together.
- **genTime is the authority for the order of anchored records** (`spec/TIME_ANCHOR.md` §3; changes verdicts). `t` is a
  double: two genTime values closer than 2^-22 s had the same `t`, and a later record with an earlier genTime passed
  the order check. The order of two anchored rfc3161 records now compares their exact genTime values (fractions, no
  float); a record whose `t` is not the rendering of its genTime is ordered by `t` as before.
- **`cra attest` and `cra verify-attestation` read the notice file once** (`spec/art14-filing` v0.1 §4.2; 9479ab2).
  0.12.0 read the drop file three times, so a file changed between two reads was signed with a predicate of other bytes
  than the subject digest binds. The digests, the predicate and `check_notice` now see the same bytes;
  `notice_check.check_notice` gains the keyword `raw=` (API: experimental tier, added argument). A notice nested
  200 000 deep is `drop_unreadable`, no longer a `RecursionError` traceback.
- **The trust store of `verify-attestation` is checked whole** (`spec/art14-filing` v0.1 §5; changes verdicts). One
  broken key (not 64 lower-case hex, small order or non-canonical, a name or a key that is not a string) refuses the
  store, each broken key named, before any signature is tried. 0.12.0 checked a key only when a signature tried it, so
  the verdict depended on the keyid and on the alphabetical order of the names.
- **PEP 508 markers without `packaging`** (`spec/SBOM_INGEST.md`, installed floor; changes the installed SBOM where
  `packaging` is absent). The fallback is now a parser of the "Dependency specifiers" grammar: a quoted string is one
  token, `and` binds tighter than `or`, versions compare as PEP 440 releases (`3.11 == 3.11.0`, `.*` prefixes), and
  every answer that is a boolean is `packaging`'s; anything else is `None` (kept and counted). 0.12.0 split the text on
  ` and ` / ` or ` (`os_name == 'nt or posix'` was `None`) and left out of the SBOM a dependency marked
  `python_version == '3.*'`. With `packaging`, `UndefinedComparison` (`os_name ~= "posix"`) was a traceback; it is
  `None`. Differential test: 6000 random markers against `packaging.markers` 26.3, every boolean answer equal.
- Positive controls (18/11/2026, Python 3.11, jsonschema, cryptography, packaging): on 9479ab2 the new files fail —
  `tests/test_art14_trust_store_20261118.py` 2 failures + 1 error of 6, `tests/test_marker_fallback_20261118.py`
  5 errors of 6, `tests/test_time_anchor_ess_absent_20261118.py` 7 failures + 2 errors of 10; here they pass.
- **Qualified time stamps** (`spec/TIME_ANCHOR.md` §7): the qcStatements extension with `esi4-qtstStatement-1` that
  Implementing Regulation (EU) 2025/1929 requires in a token declared qualified, and the EU trusted lists, are not
  read; this tool never reports a token as qualified (it did not before either: the word appears nowhere in its output).
- **Legal basis re-checked on 17/11/2026** (`spec/LEGAL_BASIS.md`), on the Official Journal texts and CELLAR: the CRA
  corrigenda of 05/12/2024, 02/07/2025 (Art. 64(10): the derogation from the fines now starts at paragraph 2, so micro
  and small manufacturers are not fined for missing the 24 h early warnings of Art. 14(2)(a) and 14(4)(a); the
  deadlines stay) and 17/10/2025; Implementing Regulation (EU) 2025/2392 (technical description of important and
  critical products, in force 21/12/2025); Delegated Regulations (EU) 2025/1535 (vehicles of Regulation 168/2013
  excluded, in force 18/11/2025) and 2026/881 (when the CSIRT may delay dissemination, in force 10/05/2026). A table
  says, paragraph by paragraph of Art. 14, what this tool supports and what it does not (it does not determine the
  coordinating CSIRT of 14(7), the enterprise size of Art. 64(10) or a product's class). No verdict changes.
- **NIST IR 8547 is cited as final** (October 2026, §4.1.1 Table 2) in `longterm.py` and `spec/LEGAL_BASIS.md`, no longer
  as the initial public draft. Its dates are unchanged ("Deprecated after 2030", "Disallowed after 2035").
- **The NIST IR 8547 instants follow the final text** (changes verdicts). §4.1.1 puts "deprecate … after 2030" in
  place of the disallowance SP 800-57 had projected "on January 1, 2031"; read as from January 1, 2031, so
  `NIST_IR_8547_DEPRECATED_AFTER` is now 2031-01-01T00:00:00Z and `NIST_IR_8547_DISALLOWED_AFTER`
  2036-01-01T00:00:00Z; from 0.1.0 to 0.12.0 they were 2030-01-01 and 2035-01-01, one year earlier. The default policy
  `AlgorithmPolicy.nist_ir_8547()` uses the second: an Ed25519 outer seal checked with `now` in 2035, or a renewal made
  in 2035 over an Ed25519 record, was refused and is now accepted; from 2036-01-01 it is refused as before. The first
  constant is exported and decides no verdict here. `tests/test_nist_ir_8547_dates_20261117.py` checks each boundary one
  day before, at the instant and one day after, on the policy, `verify` and `renewal_due`; positive control: its 6
  tests fail on the constants of 0.12.0.
- **SIGNING.md**: which keys sign the releases and how to check a release (the evidence pack with `cra verify`, the
  attestations, `SHA256SUMS`, the SSH signatures). Each statement was read on 17/11/2026 against the 19 releases.
  `THIRD_PARTY_NOTICES.md` now names the ENISA page kept as a fixture, the quoted EU acts and NIST IR 8547, the sbomify
  responses (sbomify is Apache-2.0 with the Commons Clause condition; the fixtures are its output on synthetic data)
  and the port from cryptovalid-opencore.
- Full suite (18/11/2026, locally, each test file of `tests/`): 631 tests on Python 3.9, 3.11 and 3.13 with jsonschema,
  cryptography and cryptovalid installed, OK, 1 to 3 skipped depending on the machine; without any optional dependency
  (Python 3.13), 631 tests, OK, 148 skipped.
  Not yet run in the CI on this branch.

## 0.12.0 — 2026-11-16 — supply chain of the release measurable by third parties

- **A seal's RFC 3161 token is bound to its record and can be verified** (`spec/TIME_ANCHOR.md`,
  `cra-lta-time-anchor/1`, written before the code). Until now `cra seal` stored a token whose imprint was the bare
  sealed digest and nothing in the package verified it: `LongTermEvidence.verify` needed a `timestamp_trust_fn` the
  caller had to write, and the package's own tests passed `lambda r: True`, which accepts a record whose token is
  the string `not base64!` (shown in the new test). Now the token of a `rfc3161` record stamps SHA-256 or SHA3-256 of a
  domain line, the evidence digest, every previous record and the record's own fields (a renewal's token covers the
  chain before it, as RFC 4998 §5.2's hash-tree renewal does); the record's `t` is the token's genTime; the record
  carries `"anchor": "cra-lta-time-anchor/1"`. `omega_cra_evol.time_anchor.make_timestamp_trust_fn(lte, tsa_certs)`
  checks each record against the TSA certificates the verifier pins (openssl `cms -verify` and `ts -verify
  -partial_chain -attime genTime`) and refuses with a closed reason (`digest_only_binding`, `imprint_mismatch`,
  `t_not_gen_time`, `signature_invalid`, `not_issued_by_pinned_tsa`, …); openssl that cannot run raises
  `TimeAnchorNotRun`, never a refusal. `cra seal --print-imprint` prints what to stamp (it needs `--tip-key`),
  `--tsa-hash` chooses SHA-256 (default) or SHA3-256, `--tsa-cert PEM` verifies the new seal against a pinned TSA.
  **Changed:** a token over the bare digest, the only shape `cra seal` accepted from 0.9.0 to 0.11.1, is refused at
  seal (exit 1, nothing recorded); seals written before verify as before without a function, and are refused by the
  new function with `digest_only_binding`. Measured on 15/11/2026: freetsa.org and timestamp.digicert.com answer
  `Rejected` to a SHA3-256 query and `Granted` to a SHA-256 one, so the SHA3-256-only shape of 0.9.0–0.11.1 could not
  be used with them; SHA-256 is admitted. The tests that injected `lambda r: True` (`test_council_r2.py`,
  `test_council_r3.py`) now seal with a TSA made on the machine and inject the new function; 12 of 12 mutants chosen
  by hand on the new lines are killed. Proposed by Athena's review of 15/11/2026. The NEMESIS review of 15/11/2026
  closed four gaps before the release: an anchored record with a field outside the list of §5 step 3 (`unknown_field`),
  a `token_sha3` that is not the token's digest (`token_sha3_mismatch`), or a `t` written in another form than §3's
  string (`" 1.0"`, `"+1.0"`, `"1"`) was verified; a pinned file that is not shaped as a certificate made every token
  `signature_invalid` (now `ValueError`, exit 2), and an unreadable one was a traceback; `cra seal --tsa-cert` recorded
  a seal it then refused (exit 1: a retry recorded it twice) — it now checks the token first and records nothing on a
  refusal, and refuses `--tsa-cert` without `--ts-source rfc3161` (exit 2).
- **Supply chain of the release, measurable by third parties.** `release-build.yml` builds the wheel and the sdist on a
  GitHub-hosted runner from the tag, with the build front-end and setuptools pinned by hash
  (`.github/build-requirements.txt`, `pip install --require-hashes`, `python -m build --no-isolation`), and signs SLSA
  build provenance for both files (`actions/attest`, Sigstore; SLSA v1.0 Build Level 2 per GitHub's documentation); the
  bundle is kept as `build-provenance.sigstore.json`. `gh attestation verify <file> --repo <owner>/<repo>` checks it.
- **CI hygiene.** Every `uses:` of the workflows is pinned to a commit SHA (the tag in a comment); the CI workflow runs
  with a read-only token (`permissions: contents: read`); `scorecard.yml` publishes the OpenSSF Scorecard result;
  `.github/dependabot.yml` proposes weekly updates of the pinned actions and the Python dependencies.
- **Licence metadata (PEP 639).** `license = "AGPL-3.0-or-later"` as an SPDX expression and `license-files` in
  `pyproject.toml` (setuptools ≥ 77, which builds wheels itself: `wheel` is no longer a build requirement); the
  licence classifier, which PEP 639 does not allow next to an expression, is removed; the wheel's METADATA carries
  `License-Expression` and the licence file.
- **The AWS KMS custom endpoint is https, or http to a loopback host, and nothing else** (NEMESIS review, 15/11/2026):
  the check let any scheme through towards a loopback host (`file://localhost/...`, `ftp://localhost/...`), as
  cryptovalid-opencore's before its rule of 15/11/2026. A record of a seal whose `hash` is not a string is now
  `malformed` in `LongTermEvidence.verify` (it raised TypeError).
- **Behind a corporate proxy.** A loopback AWS KMS endpoint (a local emulator) is reached directly: with `HTTP_PROXY` set,
  the signed request went to the proxy, which cannot reach this host's loopback. AWS itself still goes through the
  environment proxy. The test of `srp_glossary.fetch` excludes its loopback server from the proxy (`no_proxy`): it
  failed with `HTTP_PROXY` set from the start.
- **The AWS KMS signing path runs in the tests.** `tests/test_kms_local_20261115.py` drives GetPublicKey and Sign
  against a KMS emulator on loopback, checks the Ed25519 signature with the key the signer read, and the refusals (a
  key that is not Ed25519, a signature that is not 64 bytes, an http endpoint that is not loopback); the end-to-end
  case runs in a new interpreter with a proxy that cannot be reached in its environment from the start, and fails
  on the code before this change.
- **`verifiers/rust/Cargo.lock` is in the repository** and the CI builds with `--locked` (36 external crates, among them
  ed25519-dalek 2.2.0).
- **An append no longer re-reads the whole ledger.** After each append the writer keeps, next to the ledger, a state
  file (`<ledger>.append-state.json`: the file's size, the SHA-256 of its bytes, the chain state at its end). The
  next append hashes those bytes again and, only if they are unchanged byte for byte, parses just the lines added
  since; otherwise — a changed, removed or added byte, a smaller file, a state file missing, malformed or of another
  version — it reads the whole ledger with the same refusals as before. The state file is a cache, not evidence: no
  verifier reads it, and deleting it costs one full read. The state is used only if the ledger's first and last
  entries agree with its `first`, `last` and `n` (NEMESIS review, 15/11/2026: a state file with the right SHA-256 and
  another `last` made the writer append an entry that broke the chain for good). Measured on one machine: an append to a 10 000-entry
  ledger took 444–529 ms and now 10–26 ms; to a 50 000-entry ledger 2.2–3.7 s and now 30–43 ms (the first append
  after the change still reads everything). `tests/test_ledger_append_state_20261115.py` compares, on 40 generated
  sequences of 60 steps with eleven kinds of outside changes to the ledger and to the state file, every append with
  a full read of the same file: 0 differences; with the SHA-256 check removed the same generator finds 162.
- **The sdist is complete and reproducible.** `MANIFEST.in` puts in it every file git tracks (the 0.11.1 sdist held
  the package and its 47 test files, 105 entries, without fixtures, specifications, examples, scripts or verifiers),
  and the whole suite runs from the unpacked sdist. `release-build.yml` sets `SOURCE_DATE_EPOCH` to the commit time and
  rewrites the sdist with `scripts/repro_sdist.py` (sorted members, fixed times and owners, no gzip time; the
  content is checked unchanged): two builds of the same commit give the same sdist and the same wheel.
- **The binaries the CI downloads are checked by SHA-256** before they run: gitleaks 8.24.3 against the checksum file
  of its release; cyclonedx-cli 0.33.1, whose release publishes no checksum, against the digest of the binary as
  downloaded on 15/11/2026.
- SECURITY.md said `examples/self_evidence/` holds the project's own evidence; it is the worked example made by 0.4.0, and
  each release's own SBOM, ledger and signed pack are among its release assets: the text now says so.
- **No commercial offer.** The README no longer offers evaluation pilots or a commercial licence: none is offered at
  present; the project is free and open-source software, provided without warranty as the licence states.
- **The public API is declared** (`API.md`): three tiers — stable (the twelve names of `omega_cra_evol.__all__`),
  provisional (the `__all__` of each module, now a literal list in all 20 modules), private (everything else); SemVer
  and the deprecation rule for the 0.x line; the conditions for 1.0. The stable and provisional names are fully
  annotated; `tests/test_api_surface_20261115.py` compares the interface with a versioned snapshot
  (`tests/data/api_surface.txt`, regenerated with `scripts/api_surface.py`) and lets the private signatures without
  annotation only decrease. `canonical.deep_recursion.__exit__` returns `None` instead of `False` (same behaviour:
  the exception is never suppressed), which also lets a type checker see that the code after its `with` blocks is
  unreachable. `py.typed` is not shipped yet: `mypy` reports 82 errors in the package (15/11/2026). The interface
  and its tests were proposed by Athena's review of 15/11/2026.
- **Governance files.** `CONTRIBUTING.md` (reports, interoperability results and documents welcome; code
  contributions not accepted at present; the maintainer's commits carry a DCO 1.1 sign-off since 15/11/2026),
  `GOVERNANCE.md` (one maintainer, what is not met today: no second reviewer), `SUPPORT.md` (only the latest release
  is fixed; no paid support), `.github/CODEOWNERS`, `DCO` (byte for byte the text of developercertificate.org).
  Drafted by Athena's review of 15/11/2026, without the contributor licence agreement it proposed: no commercial
  licence is offered, and no external code is accepted.
- **Install from PyPI** first in the README. SECURITY.md also names GitHub's private vulnerability reporting, enabled
  on the repository on 15/11/2026.

## 0.11.1 — 2026-11-15 — the container image of the release builds

The image of 0.11.0 was not published: its build (`.github/workflows/container.yml`, run 43717002856) stopped at
`COPY container/requirements-schema.txt`, because `.dockerignore` lets into the build context only the files it names and
did not name that file, added to the Dockerfile in 0.11.0 to install the `[schema]` extra. `.dockerignore` now names
it; built locally from this commit with the 0.11.0 wheel, the image prints `omega-cra-evol 0.11.0` for both commands
and imports jsonschema and cryptography. The Python package is unchanged from 0.11.0 but for the version number; the
action's default image and the README's container commands name 0.11.1.

## 0.11.0 — 2026-11-15 — CycloneDX and SPDX documents are checked against the official schema of their version

### SPDX (rules written before the code, 15/11/2026)

`cra sbom --from-spdx` (`sbom_from_spdx`) validates the document against the official JSON schema of the version it
declares, shipped in the wheel (`omega_cra_evol/data/spdx/`, SHA-256 and sources in `SOURCES.txt`):

| the document declares | schema | source |
|---|---|---|
| `"spdxVersion": "SPDX-2.2"` | `spdx-schema-v2.2.2.json` (draft-07) | spdx/spdx-spec tag `v2.2.2` (`a05c12a`), `schemas/spdx-schema.json`, CC-BY-3.0 |
| `"spdxVersion": "SPDX-2.3"` | `spdx-schema-v2.3.json` (draft-07) | spdx/spdx-spec tag `v2.3` (`aadf3b0`), `schemas/spdx-schema.json`, CC-BY-3.0 |
| `@context` `https://spdx.org/rdf/3.0.1/spdx-context.jsonld` (the string, or an array holding it) | `spdx-json-schema-3.0.1.json` (2020-12) | `https://spdx.org/schema/3.0.1/spdx-json-schema.json`, the URL the SPDX 3.0.1 specification names (Serializations, "JSON-LD validation"), fetched 15/11/2026 (served with `Last-Modified: Fri, 21 Nov 2025 22:44:05 GMT`); Community-Spec-1.0 |

The schemas of the released versions are used: the later tag `v2.3.1` of spdx/spdx-spec (no release; draft 2019-09,
`documentNamespace` required, a date pattern without fractions) is not, a document says `SPDX-2.3`; the copy of the
3.0.1 schema on `spdx.github.io/spdx-spec/v3.0.1/rdf/schema.json` is not either: it is a later regeneration that the
SPDX maintainers found to fail their own validation (spdx/spdx-spec#1318).

1. A document that fails the schema is refused with the reason (`SPDX not conformant to <schema> at <path>:
   <message>`), nothing recorded. With `--allow-nonconformant` it is recorded with `source.schema_check` = `not
   conformant to <schema> at <path>: <message>`, and `sbom_floor_met` is false. The same rule as CycloneDX rule 1 below.
2. A version without a schema here is refused with the reason (`SPDX not checked: no official schema here for
   spdxVersion 'SPDX-2.1' (SPDX-2.2, SPDX-2.3)`; for SPDX 3, `… for @context …`), nothing recorded: `SPDX-2.1`,
   `SPDX-2.2.1`, a missing or non-string `spdxVersion`, an SPDX 3 document whose context is 3.0.0, 3.1 or another.
   With `--allow-nonconformant` it is recorded with `source.schema_check` = `not checked: no official schema here for
   …`, and `sbom_floor_met` is false.
3. Without the extra `[schema]` (no jsonschema, or one without a JSON Schema 2020-12 validator) the document is recorded with `source.schema_check` = `not checked: <reason>`, and `sbom_floor_met` is false, as
   CycloneDX rule 2. The SPDX schemas use no `format` keyword (counted on the three files), so no format checker is
   needed for them.
4. A conformant document is recorded with `source.schema_check` = `conformant to <schema>`; the floor is then decided
   as before (at least one resolved component). `record_sbom` re-derives `schema_check` from the stored bytes, so a
   forged value is refused. `--allow-nonconformant` now applies to `--from-cyclonedx` and `--from-spdx`; with
   `--installed` it is a usage error.
5. **SPDX 3 `@context`.** JSON-LD 1.1 (W3C Recommendation, §9.16 Keywords) admits for `@context` "null, an IRI
   reference, a context definition, or an array composed of any of these". The SPDX 3.0.1 specification (Serializations,
   "JSON-LD context file" and "JSON-LD validation") says that every SPDX document in JSON-LD "must include a reference
   to the SPDX global context file at the top level", shows the construct `"@context":
   "https://spdx.org/rdf/3.0.1/spdx-context.jsonld"`, says "Additional namespace mappings may be defined within a
   separate object within the context", and requires "Structural validation: The JSON-LD document must structurally
   validate against the SPDX JSON Schema"; that schema reads `"@context": {"const":
   "https://spdx.org/rdf/3.0.1/spdx-context.jsonld"}`. Our reading: the schema is normative for 3.0.1, so an array
   `@context` (even `["https://spdx.org/rdf/3.0.1/spdx-context.jsonld"]`) is not conformant to 3.0.1 and is refused by
   rule 1, with `--allow-nonconformant` as the way to record it. Divergence, dated: spdx/spdx-spec#1312 (opened
   18/11/2025) and spdx/spdx-3-model#1476 (opened 15/10/2026) ask that arrays be allowed, an SPDX maintainer agreed in
   #1476 on 15/10/2026, and the schema published for 3.1 (`spdx.github.io/spdx-spec/v3.1/rdf/schema.json`, read
   15/11/2026) accepts an array that contains the 3.1 context. A 3.1 document has no schema here today (rule 2); when
   3.1 is released its schema becomes the rule for 3.1 documents, not for 3.0.1 ones.

Time (measured 15/11/2026, CPython 3.12, jsonschema 4.26.0, a loaded host): an SPDX 2.3 document of 17 MB (jaeger's
release SBOM, 10,281 packages) is checked in about 4 s; the 3.0.1 schema costs much more per element, because every
`@graph` element is matched against every class of the schema with `unevaluatedProperties`: a synthetic 3.0.1 document
with 1,000 packages took 14 s, with 5,000 packages 130 s (under a varying load: the growth between the two is not
established as linear).

Why: measured on 15/11/2026 on the SPDX JSON files of other projects downloaded for the test round of 14/11 (their
own examples, fixtures and expected outputs): of 138 SPDX 2.2 / 2.3 documents, 34 (32 distinct) fail the schema of their
version, among them documents their authors call invalid (spdx/tools-java `BadJSON.spdx.json`, spdx/tools-python
`tests/spdx/data/invalid/…`, sbomqs `spdx-no-timestamp`, `spdx-no-authors`), and 4 more declare a version without a
schema (`SPDX-2.1`, `SPDX-2.2.1` of tools-java `SPDXWrongVersion`, `2`, none); the code before this change recorded
the conformant and the non-conformant alike, floor met when a component resolved. Of 126 SPDX 3 JSON-LD documents,
47 pass the 3.0.1 schema; 62 have an array `@context` (60 of sbomqs, 2 of spdx-3-model), and 61 of those fail the
schema also when the array is replaced by the string; 15 declare the 3.0.0 context; 2 fail by structure. The 34 SPDX
2.3 JSON documents published with the releases of 16 projects (argo-cd, external-secrets, flux, goreleaser, k6, loki,
guac, jaeger, kubescape, nginx-gateway-fabric, ocm, opentelemetry-collector-releases, vexctl, cosign, fulcio, rekor)
are conformant, 34 of 34.

### `iri-reference` in linear time (15/11/2026)

The `iri-reference` format of the CycloneDX schemas is checked by a regular expression written from the ABNF of RFC
3987 §2.2 (with the rules it takes from RFC 3986), matched whole (`fullmatch`, so a trailing newline is not accepted),
instead of the Earley parser of `rfc3987-syntax` that jsonschema[format-nongpl] calls. The other four formats stay
jsonschema's, and the condition for `not checked` (CycloneDX rule 2) is unchanged. The regular expression has no nested
unbounded repetition over overlapping characters, so its time is linear in the length of the string.

Why: protobom's `juice-shop-11.1.2.cdx.json` (742 KB, 840 components, 2,476 URLs) took 220 s through `cra sbom` on
15/11/2026 (load 16), against 8 s for cyclonedx-cli 0.33.1; about 0.1 s per URL in `rfc3987_syntax`. The answer is
the same on every string the schemas check as `iri-reference` in the 359 suite files, the 1,125 real files of 14/11 and
the candidates (8,869 distinct strings, 0 differences). It differs where `rfc3987-syntax` 1.1.0 departs from the RFC:
it refuses IPv6 literals with fewer than seven groups before `::` (`http://[::1]/`), characters of the supplementary
planes in `ucschar` and `iprivate`, and an upper-case `V` in `IPvFuture` (ABNF strings are case-insensitive, RFC 2234
§2.3); these are now accepted, as the RFC says.

### `pattern` read as an ECMA-262 regular expression (rule written before the code, 15/11/2026)

JSON Schema says which regular expressions a schema holds: draft-07 Validation §4.3 ("These regular expressions SHOULD
be valid according to the ECMA 262 [ecma262] regular expression dialect"; §6.3.3, `pattern`, says the same), 2020-12 Core §6.4 ("SHOULD be valid according to the
regular expression dialect described in ECMA-262, section 21.2.1", "SHOULD be built with the \"u\" flag"), 2020-12
Validation §6.3.3 (`pattern`: "according to the ECMA-262 regular expression dialect"). jsonschema runs them with
Python's `re.search`, which reads some tokens differently. The schema check of CycloneDX and SPDX documents now reads
every `pattern` of the shipped schemas as ECMA-262 with the `u` flag:

1. Translated with the ECMA meaning: `$` outside a class is the end of the input (Python also matches before a final
   `\n`); `.` is any character but `\n`, `\r`, U+2028, U+2029 (Python: any but `\n`); `\d` is `[0-9]` and `\w` is
   `[A-Za-z0-9_]` (Python: Unicode digits and letters); `\s` is ECMA's WhiteSpace and LineTerminator set (Python's also
   holds U+001C ... U+001F and U+0085, and lacks U+FEFF). Literal characters, classes, ranges, groups `(?:`, lookaheads
   `(?=` `(?!`, alternation, quantifiers (also lazy) and the escapes `\t \n \r \f \v`, `\xHH`, `\uHHHH` outside
   U+D800 ... U+DFFF and the identity escapes ECMA-262 allows with `u` (`\^ \$ \\ \. \* \+ \? \( \) \[ \] \{ \} \| \/`,
   and `\-` in a class) keep their meaning.
2. Any other construct (back-references, `\b`, `\p{…}`, `\u{…}`, a surrogate escape `\uD800` ... `\uDFFF`, which with
   `u` joins its pair into one code point, lookbehind, named groups, inline flags…) is not translated, nor is a pattern
   ECMA-262 refuses with `u` while Python's `re` gives it a meaning (a `{`, `}` or `]` that is not syntax, an escape of
   another character such as `\-` outside a class, a quantifier after a quantifier, after an assertion or after
   nothing, a class escape in a range), nor is `patternProperties` (jsonschema reads it again inside `additionalProperties` and
   `unevaluatedProperties`): a schema that holds one makes the check `not checked: <reason>` for the document (rule 2
   of each format: recorded, never floor met), never a guess. The shipped schemas hold none: 17 distinct `pattern`
   values, no `patternProperties` (listed in the tests).
3. Oracle: Node's own ECMA-262 engine (`new RegExp(pattern, "u")`) on the 17 patterns: every string of up to 300
   characters, keys included, in the JSON files of `tests/data` and `examples` (2021 on 15/11/2026), as it is and with a
   final newline; 150 generated strings per pattern; every code point up to U+30FF through `\s`, `\d`, `\w` and `.`;
   3315 generated patterns, of which the 585 translated are each accepted by Node and match the same 47 strings. No
   difference (`tests/test_ecma_pattern_20261115.py`, which also checks that Python's own `re` differs on more than
   50 of the same cases).

### `cra sbom`: a refused document exits 2 with one line (15/11/2026)

A document `cra sbom` refuses (malformed, not conformant, a version without a schema, not JSON) exits **2** ("unusable
input", the code `cra verify` gives) with one line on stderr, `cra sbom: refused, nothing recorded: <reason>`, and
nothing is written: no ledger line, no stored copy. Before, it exited 1 with a Python traceback, the code of "recorded,
SBOM floor not met", so a script could not tell "nothing recorded" from "recorded". A document that is not JSON is
named when it is recognised: `SPDX tag-value is not supported: give the SPDX JSON document`, `CycloneDX XML is not
supported: give the CycloneDX JSON document`, `SPDX RDF/XML is not supported: give the SPDX JSON document`, otherwise
`not JSON`. Recorded with the floor not met still exits 1; the other subcommands are unchanged.

### `cra verify-attestation`: `predicate_type` is never a default (15/11/2026)

The receipt's `predicate_type` is the `predicateType` the statement declares, once its payload has been read after a
trusted signature (truncated to 200 characters; any string, also one that is not an `art14-filing` TypeURI, which is
then refused with the reason `predicate_type`, as before). Before that point (an envelope not trusted, not decodable,
or another `payloadType`), and when the statement has no string `predicateType`, it is `"not_evaluated"`. Before, the
receipt wrote the v0.1 TypeURI in those cases (art14-filing v0.2 §5 said so, to keep v0.1 receipts byte for byte):
measured on 15/11/2026 on 270 envelopes of other tools (SLSA provenance v0.2 and v1, cosign, CycloneDX, VSA), each
receipt named `…/art14-filing/v0.1` although 156 of the envelopes declare another type. Spec art14-filing v0.2 §5 is
amended (the statement format and the reasons are unchanged); the receipts of 0.8.0 on the v0.1 vectors stay the
same in every other key: of the 51 v0.1 vectors whose receipt 0.8.0 kept, 41 are byte for byte the same, 10 differ
only in `predicate_type` (`"not_evaluated"`, the statement not read from a trusted envelope).

### CycloneDX (rule written before the code, 14/11/2026)

**Rule (written before the code, 14/11/2026).** `cra sbom --from-cyclonedx` (`sbom_from_cyclonedx`) validates the
document against the official JSON schema of its declared
`specVersion` (1.2 … 1.7: `bom-<v>.schema.json` of CycloneDX/specification at `6470e34`, with `spdx.schema.json`,
`jsf-0.82.schema.json` and `cryptography-defs.schema.json`, shipped in the wheel), JSON Schema draft-07 with the
`format` keyword asserted for the five defined formats the schemas use (`date`, `date-time`, `idn-email`,
`iri-reference`, `uri`; `bom-1.2` also writes `"format": "string"` four times, not a format draft-07 defines, which no
validator asserts). `uniqueItems` is checked in linear time with jsonschema's equality, and the check runs under the
recursion allowance of the parser, so every document the parser accepts (nesting up to 512) can be checked.

1. A document the schema rejects is refused with the reason (`CycloneDX not conformant to bom-<v>.schema.json at
   <path>: <message>`), and nothing is recorded — as any other malformed document. With `--allow-nonconformant`
   (`allow_nonconformant=True`) it is recorded instead, with `source.schema_check` = `not conformant to
   bom-<v>.schema.json at <path>: <message>`, and `sbom_floor_met` is false. This is the default and the switch of
   Dependency-Track (`bom.validation.mode`, `ENABLED` by default, `ConfigPropertyConstants.java` at `be365f9`).
2. The check needs the extra `[schema]` (`jsonschema[format-nongpl]` 4.25 or later — the first whose `format-nongpl`
   checks `iri-reference` —: the format checkers without the GPL `rfc3987`;
   measured on 14/11/2026 to give the same verdicts as `jsonschema[format]` on the 359 suite files and on the 1,127 files
   below, the same 277 refused). Without it, with a jsonschema older than 4.25, or when a checker for one of the five
   formats is missing (jsonschema skips a format it cannot check without saying so), the document is recorded with
   `source.schema_check` = `not checked: <reason>`, and `sbom_floor_met` is false: an unchecked document never
   evidences the Annex I floor.
3. A conformant document is recorded with `source.schema_check` = `conformant to bom-<v>.schema.json`; the floor is
   then decided as before (at least one resolved component).
4. The installed floor is not affected (SPDX documents: see the SPDX rules above, 15/11/2026); entries recorded before
   this change are verified as before.

Why: on 14/11/2026, 0.10.0 recorded 135 of the 141 invalid files (139 `invalid-*`, 2 `skip_invalid-*`) of the
official CycloneDX test suite (1.2 … 1.7, 359 JSON files at `6470e34`) and 103 of them as floor met; only the 6 with
a wrong `bomFormat` were refused. The official schemas with the format checks give the suite's answer on 359/359
files; without the format checks the 6 `invalid-metadata-timestamp-*` files
validate. Real generator files are not all conformant: among 1,127 CycloneDX JSON files (900 distinct by SHA-256) of 19 external projects downloaded for
the test round (generators, libraries, consumers), 277 fail their schema and 2 declare no specVersion from 1.2 to 1.7;
most are deliberately invalid test inputs,
but expected outputs and fixtures of scancode-toolkit (`null` strings), osv-scanner (`type: ""`), dep-scan (`null`
arrays), Dependency-Track (`version` missing in 1.4) and one of cdxgen fail too — hence the switch of rule 1.
Second oracle: the official `cyclonedx-cli` 0.33.1 (release asset sha256 `bfc8b253…3c58746`, equal to the one GitHub
publishes) gives the suite's answer on all 359 suite files (each given its `specVersion`) and agrees with this check on
1,124 of the 1,125 real files above. The one it accepts, CycloneDX sbom-utility's
`cdx-1-4-validate-err-components-format-iri-reference.json` (`git@github.com:indutny/asn1.js` as an `iri-reference`), is an
expected validation error by its own name; `cyclonedx-cli` does not assert that format.

## 0.10.0 — 2026-11-13 — renamed to omega-cra-evol

Renamed from `cra-evidence` to `omega-cra-evol`. The name was changed on purpose, so that this project is not mistaken for other products with a similar name; it is not affiliated with any of them. The earlier name was also not available as a PyPI project name. Formats,
exit codes and verification are unchanged; packs, ledgers and attestations made with earlier versions verify as before.

- **Distribution** `omega-cra-evol`, **package** `omega_cra_evol`, **commands** `cra` (as before) and `omega-cra-evol`
  (the same entry point; the name `pipx run` and `uvx` look for). `cra --version` prints `omega-cra-evol 0.10.0`.
- **Class**: the locker class is `EvidenceLocker`; its earlier name is not kept (an import of it is an ImportError:
  import `EvidenceLocker`, the same class with the same methods).
- **Deprecated aliases, removed in a release on or after 2027-03-31:** the import name `cra_evidence` (every submodule,
  `from cra_evidence.ledger import Ledger` and the like, gives the same module object as under `omega_cra_evol`),
  and `python -m cra_evidence.cli` (runs the same command). Each emits a `DeprecationWarning`. `from cra_evidence
  import *` gives the public names of the package, the locker class as `EvidenceLocker`. An unknown name is refused
  under the earlier name exactly as under the new one.
- **Container image** `ghcr.io/robertolocatelli81-dev/omega-cra-evol`, labels `org.opencontainers.image.source` and
  `.title` with the new name; the image build checks both commands. **GitHub Action**
  `robertolocatelli81-dev/omega-cra-evol@v0.10.0`; it verifies the provenance against
  `robertolocatelli81-dev/omega-cra-evol/.github/workflows/container.yml` at the tag.
- **Release assets** are named `omega-cra-evol-<version>-…` (wheel `omega_cra_evol-<version>-py3-none-any.whl`); the
  product id of the release's own evidence pack is `omega-cra-evol`.
- **Names written by the tool:** `metadata.tools` of the CycloneDX export of an SBOM record names `omega-cra-evol`; the
  User-Agent of `cra feeds` is `omega-cra-evol/<version>`; the logger is `omega_cra_evol.ledger`; the Go verifier's
  module path is `github.com/robertolocatelli81-dev/omega-cra-evol/verifiers/go`.
- **Identifiers kept as they are** (they are inside evidence already written and signed; tests/test_frozen_identifiers.py
  checks each one): the pack `kind` `cra_evidence_pack/1`; the CycloneDX property names `cra-evidence:*`, the profile
  value `cra-evidence-min` and the generator `cra-evidence:importlib.metadata`; the states vocabulary
  `cra-evidence/states-1` of `cra verify`; the TypeURIs of `art14-filing` v0.1 and v0.2
  (`https://github.com/robertolocatelli81-dev/cra-evidence/tree/master/spec/art14-filing/v0.x`); the value
  `"cra-evidence"` of `source.tool` / `declaredBy` for a notice built by this tool (spec v0.1 §4, `cra-srp/3`
  `source.tool`); the reason texts of the receipts; the attestation vectors and their seed strings, the committed
  example `examples/self_evidence/` (made by 0.4.0) and the vendored fixtures.

What breaks, and what to change:

- `uses: robertolocatelli81-dev/cra-evidence@…` stops working when the repository is renamed (GitHub does not redirect
  actions of a renamed repository): change it to `robertolocatelli81-dev/omega-cra-evol@v0.10.0`.
- `pip install … cra-evidence` keeps installing 0.9.0 and will not see newer versions: install `omega-cra-evol`.
- `docker pull ghcr.io/robertolocatelli81-dev/cra-evidence:<tag>` holds up to 0.9.0; newer versions are only in
  `ghcr.io/robertolocatelli81-dev/omega-cra-evol`, and the action's `version` input takes 0.10.0 or later.
- `import cra_evidence` works with a `DeprecationWarning` until a release on or after 2027-03-31.
- Code that imports the locker class by its earlier name: import `EvidenceLocker`.
- Anything that compares the output of `cra --version`, or the tool name in `metadata.tools` of an SBOM export, sees the
  new name.
- The Go verifier's module path changed.
- Nothing changes in the formats of packs, ledgers, sidecars, seals, notices and attestations, nor in the exit codes
  (messages that suggest an install now name `omega-cra-evol[sign]`).

## 0.9.0 — 2026-11-13 — art14-filing v0.2: the CVE / EUVD identifiers of the notice and a declared case reference

Specification written before the code: `spec/art14-filing/v0.2/README.md` (a delta over v0.1).

- **Predicate type `art14-filing` v0.2** (new TypeURI `…/spec/art14-filing/v0.2`), two optional fields:
  `vulnerabilityIds`, a closed list of `{scheme, id}` with `scheme` `cve` or `euvd`, at most one per scheme, `cve`
  first, no empty list (the key is omitted); the CVE form is the `cveId` pattern of the CVE JSON record format
  (`^CVE-[0-9]{4}-[0-9]{4,19}$`, read 13/11/2026 at cve-schema `ce5f5c8`), the EUVD form is our reading written in the
  spec (`EUVD-`, four-digit year, 1 to 19 digits: ENISA publishes no grammar), both full matches on ASCII digits, no
  normalisation; `caseReference`, a closed `{issuer, id}` (1 to 255 characters, no control character, no leading or
  trailing space), always "declared by the signer, not checkable".
- **Rule 5.** With `--drop`, the identifiers of a v0.2 statement must equal the notice's (`cve_id` / `euvd_id`, from
  `fields`, else `previous_fields`): one more, one fewer, a different one, or none in the statement while the notice
  has some — refused (`vulnerability_ids`, the reason lists what is only in the statement and only in the notice).
  Without `--drop` the receipt lists them as `declared, not checked (no drop file given)`.
- **`cra verify-attestation`** accepts v0.1 and v0.2. The receipt of a v0.2 statement has `vulnerability_ids`
  (`declared`, `notice`, `result`) and `case_reference`; a v0.1 statement keeps the receipt of 0.8.0 byte for byte:
  measured on the 52 v0.1 vectors of 0.8.0, 51 identical receipts; the 52nd, `predicate_type_wrong`, used the v0.2
  TypeURI as its wrong value and is now read as a v0.2 statement without identifiers: with its drop file it is
  refused by rule 5 (the drop file carries a `cve_id`), without the drop file it verifies (exit 0). That vector
  now uses `…/v0.3`. The reason text of a statement refused with `predicate_type` now lists both TypeURIs. The receipts of 0.8.0 are vendored in `tests/fixtures/art14_v01_receipts_080/` and compared by a
  test.
- **`cra attest`** writes v0.2 by default, with the identifiers read from the notice (an identifier out of its form is
  refused, nothing written; there is no option to type others: rule 5 would refuse them as soon as the notice is
  given), `--case-reference ISSUER ID` (given twice: usage error, exit 2), and `--predicate v0.1` for the statement
  of 0.8.0 (the same bytes; for a notice built by cra-evidence, cra-srp/2, `source.toolVersion` is the version that
  writes the statement, spec v0.1 §4, so 0.9.0 there; for an imported notice, cra-srp/3, it is the source's and the
  bytes are those of 0.8.0; for a verifier of 0.8.0, or to say nothing about identifiers, e.g. under embargo). A
  notice whose `cve_id` / `euvd_id` is not in its form (e.g. lower case, which `cra notice` records) was attested by
  0.8.0 and is now refused by default; `--predicate v0.1` attests it as before. The library default of
  `build_statement` stays v0.1.
- **`cra seal`:** `--ts-source` is one of `asserted`, `rfc3161`, `ots` (until 0.8.0 any text was recorded as the
  seal's time source); a `rfc3161` token must be, in standard base64, an RFC 3161 TimeStampResp (granted) or
  TimeStampToken whose content is a TSTInfo with a SHA3-256 messageImprint over the sealed digest; an `ots` token
  must start with the OpenTimestamps file header; `asserted` takes no token. Anything else is refused (exit 1,
  nothing recorded). Until 0.8.0 any non-empty string was stored (measured: `--token-b64 AAAA` gave `ok: true`).
  The token's signature, TSA certificate and time are still not verified: the verdict stays `temporal_trust`
  ASSUMED.
- **Vectors** `spec/art14-filing/v0.2/vectors/`: 53 (10 valid, 43 refused), built by
  `scripts/gen_art14_v02_vectors.py` from v0.1 statements without the v0.2 producer; the producer gives the same
  payload bytes but `source.toolVersion` (test). The vector generators write `source.toolVersion` 0.8.0 whatever the
  package version (`VECTORS_TOOL_VERSION`), so a release does not change the published vectors; the tests compare
  every published vector file with its sha256 (`tests/fixtures/art14_vectors_published_sha256.txt`). Synthetic notices carrying real identifiers (CVE-2024-3094 / EUVD-2024-31700, CVE-2021-44228 /
  EUVD-2021-34768, CVE-2024-21762 / EUVD-2024-19376, read on ENISA's EUVD API on 13/11/2026, digests in the spec).
- **Canonical profile and RFC 8785.** `canonical.py` now says what was measured: the profile gives the bytes of JCS
  only when every character is in U+0000..U+007E (U+007F and non-ASCII are escaped here, raw UTF-8 in JCS; beyond the
  BMP the member order differs). Test `tests/test_canonical_vs_jcs_20261113.py` (two JCS encoders, the test data of
  RFC 8785 §3.2.3 re-read). No profile change, no digest change. The JS, Go and Rust verifiers canonicalise like the
  Python reference on these characters (a ledger with U+007F, C1 controls, U+2028, keys U+E000 and U+10000: same
  verdict in the four; each of them mutated to write U+007F raw, and the JS one to sort by UTF-16, fails). The art14
  statement payload is JCS (all member names ASCII): measured on 101 of the 105 v0.1 and v0.2 vectors, the 4 others
  being refused vectors whose payload has a duplicate key, a float or no base64.
- **Docstrings:** `canonical.py` "independent cryptovalid checkers" → "by the same author"; `longterm.seal` no longer
  reads as if the stored RFC 3161 / OTS token were verified (a caller-injected `timestamp_trust_fn` is the only
  verification; cra-evidence ships none).
- **Tests:** test files committed before the code (red: 10186 failures and 5 errors on the 0.8.0 code), generative
  refusals (an unknown key in every new object, every wrong JSON type on every new leaf, 6000 random identifiers and
  4000 random references against oracles written without regular expressions); 30 hand mutants of the new rules, each
  failing at least one test.

## 0.8.0 — 2026-11-13 — notices recorded in sbomify imported as cra-srp/3; in-toto attestations of an Art. 14 notice (art14-filing v0.1)

Specifications written before the code: `spec/art14-filing/v0.1/README.md` and, in `spec/SRP_FIELDS.md`, the amendment of
13/11/2026 (rules 9 and 10) and "Importing from sbomify".

- **Stages `intermediate` and `users_informed`** (rule 9, srp-notice/2 glossaries only): judged by rules 1, 4 and 5;
  `complete` is `null`, `missing_required` `[]`, the deadline `null`. A notice with an awareness instant in the future
  is still refused at these stages, as at the other three.
- **`cra import sbomify --report R --filing F [--filing F …] --ledger L --product P --version V --drop-dir D
  --source-version COMMIT`.** Reads the JSON of sbomify's CRA reporting API as received (measured at commit 4ef6128 on
  3 reports and 9 filings of synthetic data, all five stages, now in `tests/fixtures/sbomify_4ef6128/` byte for byte),
  records the event once per report, then one notice per filing in `filed_at` order, written as `cra-srp/3` drop files
  (`source`, `filing`). Each document is closed: an unknown key, a wrong JSON type or a duplicate key anywhere is
  refused; so are a snapshot pair the 39-row mapping does not place, a value that does not convert (product type,
  Member State code, PEC text, a date without offset), a filing recorded before 2026-10-21T00:00:00Z, a filing its
  report does not list or lists differently, a filing already imported. A refusal exits 1 and writes nothing (no
  ledger line, no drop file, no stored source). The report and filing documents are kept byte for byte in
  `<ledger>.sources/` and in the drop folder. Rows 1, 4, 7a and 41 are in no pair of sbomify's filing documents (the
  notification type is the report's `kind`, recorded as the notice's `stream`): they are listed in `absent_at_source`
  and never filled in; rows 1 and 4 are required at the early warning, so an imported early warning is recorded as
  incomplete. A date id inside `srp_fields` (a second pair for one field) and a date outside the years 1-9999 are
  refused. `filing` is what
  sbomify recorded: a declaration, not a proof of submission.
- **`cra check-notice`** reads `cra-srp/3` (closed `source` and `filing` blocks; with `--ledger`, the kept source
  document must hash to `document_sha256` and re-derive the same notice). `cra-srp/1` and `cra-srp/2` files are read as
  before (receipts compared below); an early warning and a 72 h notification written by 0.7.1's `cra notice` and by
  this one verify with both checkers, ledger included (measured 13/11/2026).
- **`cra attest DROP --ledger L (--key K | --aws-kms-key-id …) --signer-id ID --out X`** and
  **`cra verify-attestation X --trust-store T [--drop D] [--ledger L]`**: predicate type `art14-filing` v0.1, in-toto
  Statement v1 in a DSSE envelope, Ed25519, about a `cra-srp/2` notice (built by `cra notice`: source `cra-evidence`,
  filing null unless declared with `--filed-at` [`--srp-reference`] [`--filed-by`]) or a `cra-srp/3` one (imported).
  The `cra_srp_notice` ledger record now carries `product_id` and `product_version`: `cra attest` takes the product
  from it (`--product`/`--version` only for records written before) and the verifier compares the statement's
  `product` with it (`product: PASS` / `FAIL`; `not_evaluated` without a ledger or for an older record). Exit 0 trusted
  and every check run passed, 1 refused or not verified (reason codes in the receipt), 2 usage. A `keyid` narrows the
  keys tried to the one it names; a signature without `keyid` (or with an empty one) is tried with every key of the
  trust store (DSSE). Without `--ledger` the
  receipt says `ledger: not_evaluated`.
- **Vectors** `spec/art14-filing/v0.1/vectors/`: 52 (10 valid, 42 each breaking one rule of §2-§5), from
  `scripts/gen_art14_vectors.py` with two test-only keys derived from fixed public strings; `manifest.json` gives each
  expected verdict, exit code and exact set of reason codes.
- **Tests:** 400 (65 new: the zero-loss test, committed before the importer and failing then, with a positive control
  that removes one mapping entry; the vectors; generative refusals — an unknown key in every object, a wrong type on
  every leaf, a duplicate key in every object of the real documents; 21 from the review before the release). Measured 13/11/2026: OK on Python 3.9.25, 3.11.2
  and 3.12.15 with `[sign]`, jsonschema and referencing (2 skipped: live feeds, cryptovalid wheel absent), and on 3.12.15
  with no optional dependency (66 skipped). 23 hand mutants of the new code, each failing at least one test; a random
  sample of 75 line mutants of `sbomify_import.py` (35) and `art14_attest.py` (40): 60 failed the suite before the
  review, 12 fail the tests the review added, 2 are equivalent (a docstring; base64 `validate`, which the alphabet check
  before it leaves nothing to reject), 1 changes only the length of a message. The
  checker of 0.7.1 and this one give byte-identical receipts on the 5 `cra-srp/1` / `cra-srp/2` drop files of the
  repository (3 of them also against their ledger).
- **sbomify `member_states`:** a Member State given twice ("AT, AT", or "GR, EL": two codes of Greece) is refused,
  never de-duplicated.
- **Limits.** The ledger is append-only: if appending fails midway through an import (a full disk: exit 74), the
  records already appended stay; the receipt lists them and the filings not recorded, whose drop files are removed, to
  import again alone (the event already recorded is reused). Drop files carry no product: a notice recorded by 0.7.1 or earlier can be attested only with a declared
  `--product`/`--version`, which no record confirms (`product: not_evaluated`). An event with no CVE or EUVD id
  (sbomify incidents, a report whose `cve_id` was cleared) is recorded under `sbomify-report:<id>`, and rule 8 binds no
  notice to it.

## 0.7.1 — 2026-11-13 — installable without PyPI: a container image with verified provenance, and a GitHub Action

The package's code is that of 0.7.0; only the version changes. New:

- **Container image** `ghcr.io/robertolocatelli81-dev/cra-evidence:<version>` (Linux x86_64), built by
  `.github/workflows/container.yml` on every published release from the release's own wheel, checked against its
  `SHA256SUMS` (nothing rebuilt). Base image `python:3.12-slim` pinned by digest; the `[sign]` extra
  (`cryptography`, `cffi`, `pycparser`) pinned by hash in `container/requirements-sign.txt` and installed with
  `--require-hashes`; build context limited to the wheel and that file (`.dockerignore`); runs as uid 10001. Before
  the push the workflow runs the image on the release's own evidence pack (`trusted-signed`) and on a tampered copy
  (exit 1); after the push it attests the image's build provenance (Sigstore, stored in the registry):
  `gh attestation verify oci://ghcr.io/robertolocatelli81-dev/cra-evidence:<version> --repo robertolocatelli81-dev/cra-evidence
  --signer-workflow robertolocatelli81-dev/cra-evidence/.github/workflows/container.yml --source-ref refs/tags/v<version>`.
  Run by hand, the workflow refuses to build unless it runs from the tag it publishes.
- **GitHub Action** (`action.yml`): `uses: robertolocatelli81-dev/cra-evidence@v0.7.1` with `args:`. It pulls the image,
  verifies the provenance of the pulled digest (signer: `container.yml` of this repository, run for the tag
  `v<version>` on a GitHub-hosted runner) and runs `cra` from that digest as the runner's user, in the workspace,
  without network unless `network: bridge` (needed by `cra feeds` and `cra sign --aws-kms-key-id`); arguments are
  split on whitespace and never pass through a shell. Linux runners with docker.
- `tests/test_distribution_20261113.py`: the pins above (digest, hashes, actions by commit, build context, the
  action's default version = the package version) and the action's two steps run with bash against docker/gh stubs
  (digest of this repository, exact signer identity, no shell, network `none`, exit code); every parser and both
  steps have a positive control on a broken copy.

## 0.7.0 — 2026-11-13 — ENISA SRP glossary "Version 1.6" (21/10/2026); the glossary recorded in every notice; drift check

- **Why a minor version.** The same input gets a different verdict: a 72 h or final-report payload that
  repeats the early-warning fields was accepted by 0.6.0 and is refused now; a 72 h AEV notification without v26a was
  incomplete under 0.6.0 and is complete now. Notices recorded by 0.4.0–0.6.0 keep their verdict (below).
- **The glossary of 21/10/2026, measured on 12/11/2026.** Page fetched 2026-11-12T20:06:53Z (sha256
  fb24151b…c2fbc33), extracted with the new `scripts/srp_glossary.py` — the method of the earlier snapshots, which it
  reproduces byte for byte from their raw pages (15/09 via the copy of 20/09, 29/09, and the page of 01/10/2026) — into
  `spec/sources/enisa_srp_glossary_20261112.json`: 49 rows, 43 numbered fields. Against the snapshot of 29/09/2026,
  row by row: rows 7a "Additional Information", 40 "AR Note", 41 "CSIRT Note" added; 8 labels renamed (1, 5, 11, v24,
  v25, v26, i37, v28); at 72 h, 17 cells pass from "By default copied from previous step, or updated" to N/A, at the
  final report 25; i38 at 72 h from Required to Optional; v26a at 72 h from Required to "By default copied from previous
  step"; v22, v29, v30 become conditional; v26 and i37 read "Mandatory"; i31 becomes free text (max 255). The page of
  01/10/2026 ("Version 1.4", saved 10/10/2026) is vendored too: it already had rows 40 and 41. ENISA numbered two
  different tables "Version 1.3" (10/09 and 25/09/2026): a version is therefore named by its snapshot.
- **Rules written in `spec/SRP_FIELDS.md` before the code (`srp-notice/2`).** Refused with a reason, nothing written,
  exit 1: a key that is not a field of the stream (also in `previous_fields`; an old label is unknown); a field present
  at a stage where the glossary says N/A (the earlier-stage fields go in `--previous`, and N/A fields are never copied
  forward); v22 without v17, v29/v30 without v28; `csirt_note` (row 41 is "entered by the designated CSIRT"); a JSON
  type other than a string (text, date) or a list of strings (lists); a duplicate key in `--fields`/`--previous`. A
  missing required field keeps the notice incomplete (written, `complete: false`, exit 1), as before. At 72 h the
  deadline and the binding to the vulnerability record read the awareness instant and the CVE/EUVD ids from
  `--previous`. New fields: `additional_information` (7a), `ar_note` (40), `csirt_note` (41); `cra schema --template`
  leaves `csirt_note` out.
- **The glossary is recorded, and old notices are checked under theirs.** Drop files are `cra-srp/2` with
  `glossary_version` and `previous_fields`; the ledger record `cra_srp_notice` gains `glossary_version`. `cra notice`
  builds a new notice under the newest glossary only; `cra schema --glossary` prints the schema of any vendored one. New `cra check-notice DROP
  [--ledger LEDGER]` rebuilds a notice under the recorded glossary and compares `complete`, `missing_required`,
  `deadline_utc`, `notice_sha3`; with the ledger, also the chain, the record and the file's `drop_sha3`. A `cra-srp/1`
  file is read under the glossary named by its exact `glossary_source` string; its rules (`srp-notice/1`) are frozen as
  in 0.6.0. A `cra-srp/2` file naming an `srp-notice/1` glossary is refused (no release writes that combination). Verified: the repository's example (written by 0.4.0), an early warning and a 72 h notification written
  by 0.6.0 on 12/11/2026 (`tests/fixtures/srp_legacy_060/`), and an early warning written by 0.3.3 and one by 0.6.0 that
  carries an N/A field and integer values (`tests/fixtures/srp_legacy_nemesis/`). The 72 h one was built with `--previous`, whose payload
  0.6.0 hashed but did not write: its `notice_sha3` cannot be recomputed from the file and it verifies through the
  ledger's `drop_sha3` only. The external verifiers (JS, Go, Rust, Java) do not read notice fields: unchanged, and a
  record with the new key still verifies with them, since records are digested as written.
- **Drift check.** `scripts/srp_glossary.py check` (standard library only) fetches the page, extracts it and compares it
  with the newest snapshot: exit 0 identical, 1 different (field-by-field diff), 2 not fetched or no glossary table.
  HTTP 429/5xx and network errors are retried (3 attempts): ENISA answered 429 to repeated fetches of its FAQ on
  12/11/2026. `.github/workflows/srp-glossary-drift.yml` is scheduled every Monday at 06:17 UTC and runs on demand
  (`permissions: contents: read`, no secrets, `actions/checkout` pinned by commit SHA). Tested offline on the saved page
  (equal: 0; a cell, a label, a length or a removed row changed: 1, with the row named; no table, another table or two
  tables: 2; an unreachable URL: 2). Run live on 12/11/2026 at 20:35:14Z: 0 against the new snapshot; at 20:35:22Z
  against the snapshot of 29/09/2026: 1, 71 differences listed.
- **Tests.** `tests/test_srp_glossary_16.py` (21 tests): the tables of each glossary derived from its snapshot (with
  controls: the old snapshot, the 1.4 page, an altered cell and an unknown cell text all fail), `spec/SRP_FIELDS.md`
  tables equal to `scripts/gen_srp_fields.py`'s output, the rules over every stream × stage × field (86 N/A cells, the 30
  Required cells other than the two awareness ones, more than 500 wrong-type values, unknown keys in `fields` and `previous_fields`), `check-notice`
  round trips and tampering, the legacy fixtures. `tests/test_srp_glossary_drift.py` (6 tests): the extractor and the
  drift check, the workflow's pinning. On origin/master (f18097e) the first fails at import (no `notice_check`); a
  behaviour probe of 18 rules passes 3 there and 18 here. 30 mutants of the new lines, each disabling one rule: 30
  killed by the suites (a 31st, NBSP handling, is equivalent — Python's `\s` already matches NBSP — and is not counted). The tests that encode the rules of 0.4.0–0.6.0 now build their notices under
  `enisa_srp_glossary_20260929` explicitly and pass unchanged.
- **Review of 12/11/2026** (`tests/test_srp_notice_review_20261112.py`): `cra check-notice` gives a reason, never a
  traceback, for a value the canonical profile refuses (a float, an integer beyond 2^53−1) and refuses a `generated_utc`
  that is not an instant; `complete`, `missing_required` and `deadline_utc` are compared as JSON (`1` is not `true`); a
  notice whose awareness instant contradicts the recorded vulnerability event is refused before its drop file is written
  (0.6.0 wrote the file, then refused the ledger record); the drift check also compares the page's version line and the
  notes after the table (the pages of 10/09, 25/09 and 01/10/2026 qualified v26 and i37 in two footnotes there) and
  exits 2, never 1, when a local file cannot be read. New tests for the paths the first ones left open: the frozen
  `srp-notice/1` rules on a 0.6.0 notice, the ledger's negative answers, the submission statement, an unknown
  `glossary_version`, the hash covering `glossary_version`, the fetch retry.
- **Test hygiene.** `tests/test_tree_hygiene_20260929.py` skipped the `.git` directory but not the `.git` file of a git
  worktree, which names the main repository's path: the suite failed 1 of 261 on origin/master when run from a
  worktree. Fixed.

## 0.6.0 — 2026-10-19 — the receipt says one thing per question; who is bound from when; the Art. 14 trigger

### The receipt of `cra verify`: admission, states, policy (`spec/RECEIPT.md`, written before the code)

- The Python verifier's receipt carries, beside the 0.5.1 fields: `admission` (`admitted` | `refused` |
  `not_evaluated`), `refusal_class` (`format_unsupported`: `kind` is not `cra_evidence_pack/1`; `unknown_member`: a
  top-level key outside the closed list; `malformed`: the file is not one JSON object, or `honest_scope`, the digest or
  `ledger_file` is unusable — checked in that order), `states_vocabulary` (`cra-evidence/states-1`), `states` (five
  subjects: `sealed_content`, `ledger_anchor`, `signed_tip`, `source_documents`, `producer_signature`; each `verified`,
  `contradicted` or `not_evaluated` with closed reasons, precedence contradicted > instrument failure > other not
  evaluated > verified, as ap2-evidence-pack 1.6.0) and `policy` (`met`, `unmet` ∈ `trusted_signer`, `ledger_required`,
  `tip_required`, `sources_required`, `authenticity_basis`). A refused pack has no `states`/`policy`; the verifier's own
  exception is `not_evaluated` with no states.
- `ok` is computed as in 0.5.1, never from the states; on every admitted receipt it equals "no subject contradicted,
  no element `instrument_failure` or `unreadable`, `policy.met`" — measured by `verifiers/states_bench.py` (below).
- **Not additive (two cases, both on a host without `cryptography`):** (1) `cra verify --log-pubkey` with a
  well-formed signed tip reported the tip as a `FAIL` judged against the pack (`tip_unchecked`, exit 1); the layer now
  carries `assessed: false`, so the run is `assessed: false` and exits 77 when no other layer judged against the pack.
  Measured on 0.5.1 (`7643845`): exit 1; test `test_tip_unchecked_without_cryptography_is_instrument_failure_exit_77`.
  A tip that is not a well-formed `cryptovalid_tip/1` is `tip_invalid` on every host (exit 1, as in 0.5.1). (2) A
  producer-signature sidecar with a field missing, mistyped or malformed was "not checkable here" (`assessed: false`,
  exit 77); it is now judged as on a host with the library (`sidecar_malformed` / `signature_invalid`, exit 1).
  `ok` and `authenticity` unchanged in both (tests in `tests/test_review_findings_20261019.py`).
- **Where the giro-unico design does not fit (stopped, why):** (1) exit 74 with a complete receipt for a check that
  could not run is NOT applied — cra-evidence already exits 77 with the complete receipt for that case (since 0.3.3) and
  74 means "the receipt was not written" (since 0.5.1); moving it would change four verifiers' exit codes and merge two
  meanings. (2) The Go, JS and Rust verifiers and the differential oracle do not carry `admission`/`states`/`policy` in
  0.6.0 (three more implementations of the table and an oracle that compares them: not done).
- The bench (`python verifiers/states_bench.py [--old <0.5.1 tree>]`): three base packs (signed with a signed tip and a
  stored source document; unsigned and anchored; the committed example) mutated at every top-level key (removed, 12
  values of another type), 6 unknown top-level keys, every sidecar key, the sidecar / ledger / tip / source document
  removed, cut, retyped, a directory or `chmod 000`, a pack re-hashed after a change, a chain rewritten consistently;
  each file under 48 verifier inputs (4 trust stores × 3 log keys × `--require-sources` × `--ledger`), a share with
  `cryptography` made unimportable. Controls: closed shape; the `ok` equation; `assessed`; no `verified` and no
  `contradicted` that the independent JS verifier's layers do not confirm; pins never change the set of contradicted
  subjects; an unknown top-level key is `unknown_member`; every 0.5.1 field equal to 0.5.1's on every input but the
  declared cases. Measured on 19/10/2026 (the release's `verify_pack`/`signing`, with
  `--old` = `git archive 7643845`): 746 files, 41 776 receipts (32 536 admitted, 9 240 refused), 27 888 runs of the JS
  verifier, **0 violations**; the 0.5.1 fields equal on 39 620 receipts, the two declared cases on 2 156, 0 other differences;
  every one of the 31 (subject, reason) cells of the table (22 distinct reason names) produced at least once.
  Each of 8 sabotages of the verifier (precedence reversed, self-asserted as verified, tip without key as verified,
  instrument failure as contradicted, not anchored as verified, hash-only as verified, a refused pack with states, an
  unknown key admitted) turns the bench red (quick mode, measured 19/10/2026). In CI: the quick bench without JS and one
  sabotage (`tests/test_receipt_states_20261019.py`, 13 tests, each red on 0.5.1).

### `cra obligations` and the Art. 14 trigger — contributed by Athena, the project's confined research agent, reviewed by Noûs

- Athena's work of 17/10/2026 (module `cra_evidence/applicability.py`, subcommand `cra obligations`, 15 tests, entries
  in `spec/LEGAL_BASIS.md` and here) was written in a session without a shell; it was applied unchanged (commit
  `e9ac860`), its 15 tests then ran green on the first run, and it was reviewed against the primary texts, fetched on
  19/10/2026: Regulation (EU) 2024/2847 from the Official Journal XHTML of the Publications Office (sha256
  `fe0cca4a…71ed`; she had read a secondary reproduction), Regulation 1182/71, and the Commission guidance C(2026) 5252
  annex (sha256 `fe209c25…8234`).
- Corrected in review: Art. 24(3) extends to stewards Art. 14(3) **and 14(8)** for severe incidents (the draft named
  14(3) only); a date of the Regulation was read as 00:00 UTC alone — now every threshold is computed at 00:00 UTC and at
  00:00 Europe/Brussels (11/09/2026: 2026-09-10T22:00:00Z; 11/12/2027: 2027-12-10T23:00:00Z; the module's Brussels rule
  equals the IANA zone on every day 2000–2040 and at every transition instant, tested) and between the two the result is
  `depends_on_time_zone_reading` with both answers (Roberto's decision of 18/10/2026: never one picked in silence); the
  year horizons (13(8) five years, 13(9) and 13(13) ten years) follow Reg. 1182/71 Art. 3(1) and 3(2)(c) — the day of the
  event excluded, the period ends at the expiry of the same date (the draft ended it at the same clock time, up to a day
  early for an "at least" horizon) — under both readings, `latest_until_utc` the later; Art. 3(4) (weekend/holiday
  extension) is not applied, stated. The guidance is cited as non-binding, Art. 71(2) as the norm. Two readings only:
  the local time of the Member States at UTC+3 in September (Bulgaria, Cyprus, Estonia, Finland, Greece, Latvia,
  Lithuania, Romania: 2026-09-10T21:00:00Z) and of the outermost regions (UTC−4 to UTC+4) is not computed, so a net
  answer is net between these two readings, not across every local time of the Union. The 24 h, 72 h, 14-day and
  one-month counts of Art. 14 (`cra vuln`) run from the instant itself, as before: they do not apply 1182/71 Art. 3
  (which would not count the hour or the day of the event and would end them up to one hour, or one day, later).
- `cra obligations` (review): for a product placed before 11 December 2027 and not substantially modified from that
  date, the requirements — Art. 13 included — do not apply (Art. 69(2)); its support period, retention and update
  horizons are still computed but carry `requirements_apply: false` and a short support period is not a finding
  (exit 0).
- New: the trigger is the awareness of the ACTIVE EXPLOITATION (or of the severe incident), separate from the awareness
  of the vulnerability (guidance §217): `art14_obligation()`, `cra obligations --exploitation-aware
  [--vulnerability-aware]` (`obligation` / `no_obligation` / `depends_on_time_zone_reading`); `--at`,
  `--placed-on-market` and `--update-issued` can each be given alone.
- **Not additive:** `VulnerabilityRecord.overdue()` (and so `cra vuln` and the `overdue` block of new `cra_vuln`
  records) carries `art14_obligation`; an actively exploited vulnerability whose exploitation was known before both
  readings of 11/09/2026 is no longer overdue (`reporting_applicable: false`, `cra vuln` exit 0; 0.5.1: exit 1, measured
  on `7643845` with an awareness of 2026-09-01). Between the readings `reporting_applicable` is `null`, `time_zone_reading`
  gives both answers, and `any_overdue` is true when one reading is overdue (exit 1). Three earlier tests that used an
  awareness of 1 January 2026 as "overdue" now use 15 September 2026. Ledger records already written are unchanged.
- Not re-read in review: the ENISA SRP FAQ and the EN 40000 standardisation status Athena cites (secondary trackers);
  the record format still holds one awareness instant (`awareness_utc`, read as the awareness of the exploitation for an
  actively exploited vulnerability): a separate vulnerability-awareness field in the record is not added.

### Mutants

- 36 mutants on the changed lines (`verify_pack`, `signing`, `applicability`, `vuln`, `cli`) + an identity mutant: on
  `005ed3f` 8 survived; tests were added for 7 (a ledger or sidecar that is a directory vs unreadable, an unknown entry
  key in a consistent chain, a declared ledger state that is not the ledger's, the sources not looked at, the Brussels
  transition instants, a support period below the minimum under one reading); on `631f80c` 35 of 36 are killed, the
  identity mutant survives (null control), and the survivor (the order in which `day_start` tries the two offsets) is
  equivalent: no two offsets can both fit a midnight, and the day-by-day test against the IANA zone passes with it.

### Known limitations

- A run under a file size limit can leave Python's own bytecode cache cut (measured 2026-10-19 on `005ed3f`).
  CPython 3.9 and 3.11 write each `.pyc` with one raw write: from a copy without `__pycache__`, one run of
  `python -m cra_evidence.cli verify` under a limit smaller than a `.pyc` left it cut (13 `.pyc` written; 11 to 13 cut
  under limits of 512 B to 4 KiB; 5 on 3.9.25 and 9 on 3.11.2 still cut under 16 KiB — `sbom`'s is 37 527 and 72 230
  bytes on 3.9.25 and 3.11.2 under the path measured — a `.pyc` holds its source path, so the size
  varies with it) — and every later run exited 1 with `EOFError: marshal data too short` (nothing on stdout: measured on 3.11.2). Exit 1 is also this tool's code for
  a finding against the pack: the failure is loud (a traceback on stderr, no receipt), but its exit code alone does not
  tell it from a finding. It lasts until `cra_evidence/__pycache__` is removed (`python -B` on a later run does not end
  it: measured), and is avoided by running with `python -B` or `PYTHONDONTWRITEBYTECODE=1` from the start. Python
  3.13.15 wrote no cut file in the same runs; a cut file put there stops it as well (exit 1). A wheel installed with
  pip's default settings has its `.pyc` compiled at install time (measured: 15 of 15 modules; the `cra` console script
  run under a 1 KiB limit and then normally gave the same exit both times).

## 0.5.1 — 2026-10-12

### A receipt that could not be written exits 74

- Measured on 0.5.0 (2026-10-12, every subcommand that prints an outcome, valid and invalid input where the subcommand
  has both, two runs each; `feeds` with its two fetch functions replaced, no network): with stdout on `/dev/full`, on
  a pipe whose reader exits at once, or closed (`>&-`), the outcome was computed and lost. The Python CLI exited 120
  (the interpreter's own flush at exit, "Exception ignored" on stderr) on the full disk and the closed pipe, and with
  the outcome's own code (0 or 1) and nothing on stderr with stdout closed. The JS verifier exited 0 or 1 with
  nothing on stderr on the full disk and the closed pipe; the Go verifier the same on the full disk and 141 (SIGPIPE)
  on the closed pipe; the Rust verifier 101 with nothing on stderr (`println!` panicked, the panic hook kept the
  message) on both. None of 120, 101, 141 is an exit code this package documents.
- Now: `cra` (every subcommand) and the JS, Go and Rust verifiers exit 74 (sysexits `EX_IOERR`) when the receipt was
  not written whole, whatever the outcome, with a `receipt not written: <reason>` line on stderr (still 74 when stderr
  is closed too). Python writes and flushes the receipt itself before choosing the exit code; JS listens for the
  stream's `error` event; Go checks the write's error with SIGPIPE ignored; Rust uses `writeln!` and `flush` with their
  `Result` (until the entry "13 October" below: a write loop of its own on fd 1). 0, 1, 2 and 77 are unchanged when the receipt is written (receipts byte-identical to 0.5.0's where their
  content does not depend on the clock, a random id or a key). Ledger records are appended before the outcome is
  printed: after a 74 for the printed outcome from `sbom`, `vuln`, `notice`, `pack` or `seal` the record is in the
  ledger (since the entry "13 October" below, a ledger line or a stored SBOM copy that cannot be written is 74 too,
  with nothing recorded, and the line says so). Started with stdout
  closed, Node, Go and Rust reopen it on `/dev/null` before the verifier runs, which the verifier cannot tell from
  `>/dev/null`; the Python CLI exits 74 there.
- The files a subcommand promises — the pack of `pack --out`, the sidecar of `sign`, the drop file of `notice`, the
  seed of `keygen` — follow the same rule (new module `cra_evidence/outputs.py`, `OutputNotWritten`): a file that
  cannot be written exits 74 with the same line, no traceback, and the ledger is unchanged. Measured on 0.5.0: a path
  under a regular file, a directory in the file's place, or the pack's bytes on a full disk each ended in a traceback
  with exit 1, and `pack --out <a directory>` appended the pack's anchor to the ledger before failing to rename the pack
  over the directory (and left `<path>.tmp`). Now the pack, the sidecar and the drop file are written to `<path>.tmp`
  (a name nobody can predict since the entry "13 October" below) and renamed only once complete (the temporary file is removed on failure), `pack --out` refuses a directory before
  reading the ledger, and a seed that failed half-way is removed (`keygen` creates it with `O_EXCL`, so a stub would block
  the next run; by code reading, not reproduced). If the rename of the pack fails after its anchor was appended — not
  reproduced: the directory case is refused earlier — the error says the anchor is in the ledger and the complete pack
  stays at `<path>.tmp`. An existing seed file is still refused as before (`FileExistsError`, exit 1), not counted as a
  failed write (until the entry "13 October" below: one line, no traceback, exit 1 still).
- The ledger and its signed tip (`--tip-key`). Measured on 0.5.0 and on the first 0.5.1 commits: with the tip's path
  unwritable (a directory in its place), `pack` appended the anchor, then deleted the pack it names and exited 1 with a
  traceback (an anchor whose pack exists nowhere); `sbom`, `vuln`, `notice` and `seal` appended the record and exited 1,
  the code of an overdue deadline or an unmet floor. A ledger line cut by a full disk or a file size limit (`ulimit -f
  2`, an SBOM record) stayed in the ledger as half a line, and the next append made the chain fail for good. Now a line
  is written whole or not at all (a failed write truncates the ledger back to the bytes it had, under the same lock), a
  tip that cannot be replaced exits 74 with the line naming the record that is in the ledger, `pack` then keeps the
  pack at its path, and no `.tip.json.tmp` is left; after that 74 the record is in the chain and the signed tip still
  names the previous entry. A record that could not be appended at all still exits 1 with a traceback, as before, and
  the ledger is left as it was (until the entry "13 October" below: 74, nothing recorded).
- A regular file that stops taking bytes part-way (a file size limit): measured with `ulimit -f 4` and a 201 502-byte
  receipt, the JS verifier (Node 22 and 24) wrote 4 096 bytes and exited with the verdict's code and nothing on stderr
  (Node's stream does one write on a regular file and drops the rest after a short write), and the Rust verifier was
  killed by `SIGXFSZ` (exit 153). The JS verifier now writes a regular file itself, every byte, and the Rust verifier
  ignores `SIGXFSZ`: both exit 74, like the Python CLI and the Go verifier already did on this code.
- Exit 74 also when stderr cannot take the line: measured with stdout and stderr both on `/dev/full`, valid and invalid
  pack, three runs each (0.5.0: 120 from the Python CLI, the verdict's 0/1 from the JS and Go verifiers, 101 from Rust;
  now 74 in the four). Python points both descriptors at `/dev/null` after the failure, so its own flush at exit cannot
  fail again; the JS verifier also listens for `error` on stderr (without that listener, measured on a mutant, it exits 1).
- The JS verifier set `process.exitCode` instead of calling `process.exit()` right after `console.log` (local commit
  of the same day, made as a precaution after the same defect in ap2-evidence-pack's JS verifier, where it was
  described as not reproduced here). Measured afterwards, it was reproducible: on 0.5.0 a 201 502-byte receipt (a pack
  whose `kind` is 200 000 characters) reached a pipe as 65 536 bytes, exit 1, nothing on stderr; it now arrives whole,
  as it already did from the Python CLI and the Go and Rust verifiers.
- `tests/test_receipt_not_written_20261012.py` runs every case as a real process (stdout to a file, to `/dev/full`, to
  a pipe whose reader is already gone, closed, a receipt above 64 KiB through a slow pipe and into a file that stops at
  4 KiB, the ledger under a file size limit, the tip unwritable, a stdout that cannot encode the receipt); Go and Rust
  run when `CRA_VERIFY_GO` / `CRA_VERIFY_RUST` name a built binary, as in the CI verifiers job. On 0.5.0 it fails 21 of
  its 22 tests, the JS verifier on the slow pipe included (the one that passes is the Python slow-pipe test, a guard
  against a regression). The closed pipe is a pipe whose read end is closed before the command starts: with `| head -c 0` the
  reader races the writer, and a small receipt can land in the pipe buffer first (measured on this code, 50 runs each
  on an invalid pack: started together, Go and Rust exited 1 once each, the receipt written to the pipe and discarded by
  `head`; with the producer started 0.2 s after `head`, and with the read end closed first, 74 in all 50 for Python, JS,
  Go and Rust).

### 13 October: the receipt whole or 74 in the cases the first 0.5.1 commits did not reach

- Measured on the first 0.5.1 commits (2026-10-13, real processes, Python 3.11.2, Node 22 and 24, Go 1.27, Rust 1.98):
  with `PYTHONUNBUFFERED=1` (or `-u`) stdout is a raw file whose short write the text layer dropped in silence, so
  appended to a file under `ulimit -f 1` that still took 24 bytes, `cra schema` exited 0 and `cra verify` 1 with 24
  bytes of the receipt; on a non-blocking stdout read one second late, a 201 502-byte receipt reached the pipe as
  65 536 bytes with exit 74 (exit 1 unbuffered), and the Rust verifier did the same with its 201 189-byte receipt — a
  reader that is slow, not gone; with stdout open read-only (`1<file`) the Rust verifier exited with the verdict's
  code and no receipt (Rust's standard stdout treats `EBADF` as success). A usage error, an unreadable trust store or
  `keygen` on an existing seed, with stderr full or its reader gone, exited 120 (Python; 1 under `-u`), 101 (Rust, `eprintln!`
  panicking) or was killed by SIGPIPE (Go, 141 in a shell); with stderr closed the Python usage (104 bytes) and the
  trust-store message (98 bytes) went to STDOUT. `cra --version` and `cra --help` on a full stdout or a closed pipe
  exited 120 (1 under `-u`). A refusal printed as a traceback (`seal` of a digest no pack anchored, an SBOM file that does not
  exist) exited 120 with stderr full instead of 1.
- Now the Python CLI encodes the receipt as its stdout text layer would (that layer's encoding and error handler, a
  byte order mark only where that layer writes one as the first thing written: `str.encode` would put one on a pipe
  too; in process, after text the caller wrote to a `utf-8-sig` pipe, the receipt carries a second one) and writes it to
  `sys.stdout.buffer` in a loop that sees the count: a short count continues, a full non-blocking stdout is waited for
  in `select` (measured on Linux, not on macOS; on Windows `select` waits on sockets only, so there it would be 74 —
  not measured), 0 bytes taken
  is an error; a stdout with no descriptor (`io.StringIO`, an `io.TextIOWrapper` over `io.BytesIO` as pytest's capsys)
  gets the receipt in process. argparse prints through a stderr writer that never raises: a usage error keeps exit 2,
  a refusal its own code (1 or 2), nothing reaches stdout; `--help` and `--version` are the command's output, 74 when
  lost. `keygen` on an existing seed is one line, `keygen refused: <path> already exists …`, still exit 1. The refusals
  raised as exceptions (`seal` of a digest no pack anchored, an SBOM file that does not exist) keep their traceback
  and exit 1, now also with stderr lost (one line per refusal, exit 2, is left for a
  minor version: it changes exit codes). The Go verifier ignores SIGPIPE from the start of `main`; the Rust verifier
  writes stderr lines with `writeln!` and its result ignored, never `eprintln!`, and writes the receipt to fd 1 in a
  loop that waits in `poll(2)` on `WouldBlock` and reports `EBADF`. The JS verifier needed no change (measured).
- What a subcommand promises besides stdout: a ledger line that cannot be written (a full disk, a file size limit) and
  the copy of an ingested SBOM document that cannot be stored (also when the folder of the copies cannot be created)
  now exit 74 with a line that says nothing was recorded
  (they exited 1 with a traceback, the code of an overdue deadline or an unmet floor); the ledger is left as it was.
  The temporary file of the pack, the sidecar, the drop file, the signed tip and the stored copy is
  `<path>.<16 random hex>.tmp`, created with `O_CREAT|O_EXCL|O_NOFOLLOW`, written in a loop, fsynced and closed
  inside the same `try`: a symlink planted at `<path>.tmp` was followed (the pack was written into its target) and a
  FIFO there blocked the run.
- Receipts unchanged where they are written: the 186 cases of the differential oracle through the Python CLI, the JS
  verifier (Node 22 and 24), Go and Rust, plus 17 runs of `schema`, `--help`, usage errors, `sbom`, `vuln`, `notice`,
  `pack`, `keygen` and `feeds` (offline), compared with 0.5.0 (6113d94): 947 of 947 identical (exit code, stdout and
  stderr byte for byte; `notice`, `pack` and `keygen` by shape, as they hold a time, an id or a key); the comparator
  sees 517 differences when 0.5.0's Python and JS indentation is altered.
- `tests/test_receipt_design_20261013.py` (24 tests, real processes): unbuffered Python in every losing mode,
  a non-blocking stdout already full at start (the process must sleep: under 0.2 s of CPU in a one-second window,
  then the receipt whole), stdout read-only, usage and refusals with stderr full, closed or gone, `--version` and
  `--help` lost, six encodings and one error handler to a file, appended and to a pipe against Python's own text
  layer, `main()` in process (also with the caller's unflushed text on a full non-blocking pipe), the planted temporary, the ledger line and the stored copy not written (also its folder not
  created), the `vuln --source` feed refusals with stderr lost, a regular file or a FIFO at the very temporary name
  drawn, an error reported by `close()`. On the first 0.5.1 commits 19 of its 24 tests fail, on 0.5.0 23; 34 mutants
  of the new lines, 34 killed (Python 3.11, Go 1.27, Rust 1.98); a review's own 25 mutants (20 Python, 4 Rust, 1 Go):
  23 killed once 4 tests were added for the 4 that survived (`O_EXCL` replaced by `O_TRUNC`, `close()` left out, the
  two feed refusals printed with `print`), 2 equivalent (`O_NOFOLLOW` under `O_EXCL`; `/dev/null` on descriptor 1
  when stdout was closed at start, as nothing holds descriptor 1 there); 2 more on the review's correction of the
  caller's unflushed text (not waited for, retried in a spin): killed. The CI verifiers job runs it with the Go and Rust binaries.

## 0.5.0 — 2026-10-11

- `cra notice --previous` and `cra seal --renew` read their JSON through an `open()` they did not close; both now
  use a `with` block. `tests/test_open_handles.py` holds every `open()`/`urlopen()` in `cra_evidence/` to a `with` item and
  was red on the previous code.

### Closed schema (2026-10-10): a field nobody defined is never silent

- Measured on 0.4.0 (2026-10-10, `examples/self_evidence`): a `.sig.json` sidecar carrying a key nobody defined
  (`x_unknown_2026`) verified `ok: true, authenticity: trusted-signed` with no trace in the receipt — the sidecar
  lies outside every digest, so nothing ever read that key. A pack or a ledger entry written with an extra top-level
  key was caught only indirectly (the signature over the old `pack_sha3`, the `pack-ledger-state` binding), never by
  name.
- Now: the sidecar is a closed object (`signing.SIDECAR_KEYS`: `signed_pack_sha3`, `signer_id`, `signed_utc`,
  `public_key_hex`, `signature_hex`, `alg`, `fingerprint`) — any other key is `producer-signature FAIL` naming it;
  the pack's top level is a closed object (`verify_pack.PACK_KEYS`, the 14 keys `locker.build_pack` writes) checked by
  the new `pack-schema` layer; every ledger entry's top level is `idx, ts, data, prev_hash, self_hash` (`ENTRY_KEYS`),
  checked by the new `ledger-schema` layer. Record payloads (`data.*`) keep their own rules (`SRP_FIELDS.md`).
- **Go, JS and Rust aligned (2026-10-11).** `verifiers/go/main.go`, `verifiers/js/cra-verify.mjs` and
  `verifiers/rust/src/main.rs` apply the three closures with the same lists and the same words: the `pack-schema` layer
  after `pack-kind` (`unknown top-level field(s): <keys>` / `top-level fields in the closed schema`), the `ledger-schema`
  FAIL before `ledger-chain` when an entry carries a top-level key nobody defined (`N entry(ies) with a top-level field
  outside the closed schema, first at idx I: <keys>`, judged on the entries read, none when a line could not be taken —
  as the reference), the sidecar refused before any field is read (`sidecar field not in the closed schema: <keys>`);
  keys in code-point order, cut as the reference cuts them. Measured on 0b83a3f before the alignment with the oracle
  below: 39/178 divergences (the 6 the previous entry announced — `pack_depth_512`, `pack_key_named___proto__`, the two
  `*_digest_untouched`, the two `*_hash_untouched`, where the reference now also names `pack-schema` / `ledger-schema` —
  plus seven of the nine `closed_*` cases, on which the three ports said `signed` / `anchored`; the other two are controls
  that stay PASS). After: 186 cases, 0 divergences (JS, Go, Rust). The idx that the `ledger-schema` detail prints is the
  entry's idx when it is a JSON integer within ±(2^53−1), `None` otherwise, in the four (review of 2026-10-11: `true`,
  `"7"`, `null` and an object were printed four different ways; four `closed_ledger_entry_unknown_key_idx_*` cases;
  three `*_long_keys_cut` cases compare the WHOLE detail text — each cut, the code-point order with a key outside the BMP —
  and one puts an unreadable line after the foreign key, where no `ledger-schema` layer is due). `verifiers/differential.py` carries the nine `closed_*` cases with a DECLARED outcome each (verdict,
  failing layers and the detail that names the key; `CRA_VERIFY_JS` points its Node column at another tree, like
  `CRA_VERIFY_GO` / `CRA_VERIFY_RUST`). `verifiers/closed_schema_mutants.py` is a generative, differential bench over the
  same rule (random keys in the sidecar, at the pack's top level — re-hashed and re-signed —, in an entry appended after
  the anchor; duplicates; the controls that must stay PASS: a legacy sidecar without `fingerprint`, a key inside a
  record's `data`): 90 mutations GREEN over Python, JS, Go and Rust (seed 20261011), 31 silent passes in each of the three
  ports of 0b83a3f; `tests/test_closed_schema_mutants.py` runs it in CI (the jobs with `cryptography`; the bench signs its
  sources, so it is skipped in the no-dependency job) and proves it can go red (a JS copy without the sidecar rule). Not changed: `cargo clippy -D warnings` with clippy 1.98.1 reports four lints on lines older than this
  change (`json.rs` `Float` never constructed, `unhex` `% 2`, a `&` in the `pack-sha3` `format!`, the ledger `loop`);
  identical on 0b83a3f.

## 0.4.0 — 2026-09-29

- **Why 0.4.0 and not 0.3.4.** The glossary change below alters a verdict on the same input: a 72 h AEV
  notification payload that was complete under 0.3.3 is incomplete under this release and `cra notice` exits 1. A
  change of outcome is a minor version, not a patch. Nothing else in the CLI, the pack format or the verifiers changes.
- **ENISA glossary dated 25/09/2026: one field added, v26a.** The CRA SRP Glossary page ("Version 1.3. Last update: 25
  September 2026", read 29/09/2026) carries a new row **v26a, "Date and time when the Actively Exploited Vulnerability
  occurred (UTC time)"**: optional at the early warning, required at the 72 h notification, copied forward at the final
  report. Measured 29/09/2026 against the vendored snapshot of 15/09/2026, extracted from the raw HTML with the same method
  (the method reproduces the 15/09 file byte-exact): header identical; the 44 rows of 15/09 all present, unchanged and in
  the same order; one row inserted between v26 and v27; 45 rows, 40 numbered fields (18 common, 13 AEV, 9 SI). New
  snapshot `spec/sources/enisa_srp_glossary_20260929.json` is the reference; the 15/09 one stays for history. The
  vulnerability schema gains `vulnerability_occurred_datetime_utc` (row v26a, `spec/SRP_FIELDS.md` regenerated from the
  module); `cra schema --template notification` lists it; a 72 h AEV notification without it is now incomplete and
  `cra notice` exits 1 — **a payload complete under 0.3.3 may be incomplete under 0.4.0**; the final report reports it
  missing unless carried with `--previous`. The snapshot test now matches row numbers with a letter suffix: the pattern
  used until 0.3.3 skipped `v26a.` and, measured on the 25/09 snapshot with the 0.3.3 schema, still counted 39 rows and
  stayed green; the new bench fails with the 15/09 snapshot and fails with the 0.3.3 schema (both ablations are tests in
  `tests/test_enisa_v26a_20260929.py`). The footnotes outside the table ([1] on v26, [2] on i37) are not in either
  snapshot; whether they changed is not measured. The Art. 14 deadlines are unchanged.
- **Fixtures and example re-run from a neutral directory (29/09/2026).** The Syft and cdxgen documents of 20/09/2026
  carried the working path of the machine they were generated on (a home directory flattened into a scratch path), and
  the example ledger stored one of them. Both are re-run, not edited. The sample project (`tiny-cra-sample` →
  base64-js 1.5.1) was rebuilt offline from the npm cache and its `package-lock.json` is byte-identical to the one
  scanned on 20/09 (SHA-256 `eae8eaf4…6fea3c1`, the hash Syft recorded then; the dependency is declared `1.5.1` — the
  other specs tried gave other hashes). Syft 1.52.0 (binary from the GitHub release, SHA-256 equal to the release's
  checksums file) and cdxgen 12.8.4 (npm) ran on it in `/tmp/tiny-cra-sample`. Differences to the 20/09 documents,
  measured leaf by leaf: Syft CycloneDX 4 (the lockfile's path, the root `bom-ref`, `timestamp`, `serialNumber`; the
  package ids and the file component's ref are the same), Syft SPDX 2 (`created`, `documentNamespace`), cdxgen 9 in
  each of the two (the path in four places, two timestamps, the annotation text, `serialNumber`, and an empty `services`
  array the 20/09 run had is no longer emitted — not reproduced with `-t npm`, `-t js` or from inside the directory;
  nothing reads it). Trivy's two documents carry no path and are the 20/09 ones. The example
  (`examples/self_evidence/`) is regenerated by its script, which now reads the package version and clears the
  previous run's drop file: 6 ledger entries, `trusted-signed` in Python, JS, Go and Rust (`--require-sources`, exit
  0); with one byte of a ledger line changed the four exit 1 on `ledger-chain`, with one byte of the stored document
  changed the four exit 1 on `source-documents`. A new test walks the whole tree for home-directory and scratch paths
  (`tests/test_tree_hygiene_20260929.py`, positive control included).
- **Review attributions without product names.** The independent AI reviewers of the 0.1.0 and 0.3.0 rounds are
  named by a stable number 1–5 (1–4 from one provider, 5 from another) in this file, the README and the tests; the
  rounds, dates and findings are unchanged.
- Tests: 146 (4 skipped with `cryptography`, on 3.11; 17 skipped without it, on 3.9, 3.11 and 3.13); differential
  oracle 169 cases, 0 divergences over Python, JS, Go and Rust; gitleaks on the whole history: no leaks.

## 0.3.3 — 2026-09-27

- **Exit code 77 when the verifier could not judge.** `cra verify` and the JS, Go and Rust verifiers now exit 77 when
  `assessed` is false — the verifier's own exception, or (Python) no `cryptography` to check a producer signature — and
  no layer judged against the pack; 1 stays the exit code of a finding, 0 of a verified pack, 2 of unusable input. Until
  0.3.2 both "the tool could not judge" and "the pack is bad" exited 1, so a script reading only the exit code could not
  tell them apart; omega-evidence uses 77 for the same case (`omega_evidence/verifier.py`). Measured 27/09/2026: with an
  internal error injected (`CRA_VERIFY_INJECT_FAULT=1`), on an intact and on a tampered pack, the four verifiers exit 77;
  without `cryptography`, the Python CLI exits 77 on a signed intact pack and 1 on the same pack with a ledger line
  edited (the ledger layer judged it). The differential oracle now compares the exit code exactly (before, only "0 if
  and only if ok"): 169 cases, 0 disagreements over Python, JS, Go and Rust; with the JS verifier put back to exit 1 it
  reports the two cases that change (the injected error on the intact and on the tampered pack). A new test covers the host without `cryptography`; both "always 1" and "always 77
  when not ok" make it fail. A caller that checks for a non-zero exit sees no change.

## Corrections (2026-09-26)

- Small-order keys allow a forgery on any message, not on "a share of messages" (correction to the 0.3.2 notes). The
  0.3.2 note said that, for the small-order points other than the identity, a forgery holds only "on a share of
  messages". By the verification equation, that is true of one fixed construction (R = identity, S = 0), but it
  understated the risk: with any small-order public key A, of order n = 2, 4 or 8, anyone can produce a signature on any
  message. Pick S and a guess g for k mod n, set R = [S]B − [g]A, compute k = H(R ‖ A ‖ M) mod L as the verifier does,
  and retry until k ≡ g (mod n); each try succeeds with probability about 1/n. Measured on 2026-09-26 with curve
  arithmetic written for the measurement, not this repository's code: for each of the 8 small-order public keys, a
  signature on one message chosen in advance verified under OpenSSL, through Python `cryptography` (1 to 16 tries) and
  through Node 22 `crypto` (1 to 17 tries) — the same backend, so one measurement, not two independent ones. In the
  Python probe, the same construction against an ordinary key verified 0 times in 2000 (null control). The refusal of
  these keys added in 0.3.2 is unchanged; this corrects only the description of what it prevents. The source comments
  that repeated the wording are corrected too.

## 0.3.2 — 2026-09-26

- An instant must exist (26/09/2026). `signed_utc` in the signature sidecar and `ts` in the signed tip were checked by a
  regular expression only. Measured on `cfd9f11`: a sidecar re-signed by the key holder with `signed_utc`
  2026-02-30T10:00:00+00:00, 2026-09-26T25:61:61+00:00 (hour, minute and second out of range) or 2026-13-01 was PASS in
  all four verifiers; on this release the three are FAIL in the four. The four now require a month 01–12, a day that
  exists in that month and year, hour 00–23, minute and second 00–59 (a leap second is refused: the signer never writes
  one) and an offset of at most ±23:59. The same rule applies to the tip's `ts`: declared, not measured separately; the
  minute/second bounds are measured only in the Python unit test (`tests/test_instants_20260926.py`: 10:60:00 and 10:00:60 refused). Oracle: 5 new cases (4 impossible instants, including
  an offset of +24:00, and 2024-02-29 as the positive control, accepted), 168 cases in all, 0 divergences with Go, JS
  and Rust required. Tests: 134 (4 skipped).
- The JS verifier reads the ledger one line at a time (26/09/2026). `readLinesOrFail` wrapped the streaming reader in
  `Array.from()`, so every line was materialized first: on the code just before this change (`cfd9f11`), a 64 MiB ledger
  of empty lines aborted Node (SIGABRT, peak 2424 MiB) where Python, Go and Rust answered at 22–32 MiB. Now Node answers
  at 65 MiB with `ledger-chain` FAIL `empty_ledger`, the reason measured in Python, Go and Rust too; a real ledger still
  verifies (positive control).

- Small-order Ed25519 keys refused (25/09/2026). With the identity key as public key, R=identity, S=0 is a valid signature on every message; the other small-order points admit such forgeries on a share of messages (the hash depends on R, so not on every one; not measured here); a non-canonical encoding (y >= p) is refused because the key has no unique encoding. Measured with the identity key (`01` followed by 31 zero bytes) through Python `cryptography` and Node: a forged sidecar signed that way, with that key pinned by the relying party, was trusted-signed; the Go and Rust ports received the same guard without a measurement of their behaviour without it. The four verifiers now refuse those keys with the same list (8 small-order encodings, 2 with the sign bit on x = 0, every y >= p; checked against curve arithmetic: 0 disagreements on 48 special and 200 000 random keys). After the change, three new oracle cases (the identity, an order-8 point, a non-canonical encoding, each pinned) are FAIL in Python, JS, Go and Rust.

Files a verifier must not read, a present-and-null fingerprint, and the verifier's own errors — found by the 25/09/2026
malformed-input review (four minds) and re-measured on HEAD `51ecbb3` before any change. The 25/09 numbers below come
from the author's measurement records, which are not part of this repository, and were not re-measured for 0.3.2; the
oracle cases and tests that exercise each rule are in the repository and run with it.

**Files that are not regular files.** A FIFO in place of the pack, the signature sidecar, the signed tip or the trust
store blocked every verifier — the Python library and CLI, JS, Go and Rust (Go and Rust answered the tip case, with the
wrong reason "no tip file"); a symlink to `/dev/zero` in those places was read until memory ran out (under an RLIMIT_DATA
of 1500 MiB: Python `MemoryError` reported as `verifier-exception`, JS abort, Go runtime exit 2, Rust "out of memory").
The comment next to `MAX_SOURCE_BYTES` promised that "a symlink to /dev/zero must not hang a verifier": the guard
covered only `<ledger>.sources/`. Now every file the four verifiers read — pack, sidecar, ledger, tip, trust store,
stored source document — is opened without blocking (`O_NONBLOCK | O_NOCTTY`) and read only if the OPEN descriptor is a
regular file (`fstat`), so the check and the read see the same object. The outcome is the one an unreadable file
already had in that position, with the exact reason `not a regular file`: `pack-json` FAIL, `producer-signature` FAIL,
`ledger-chain` FAIL, `signed-tip` FAIL, exit 2 with no verdict for the trust store. One rule decides presence in the
four: `lstat` ENOENT/ENOTDIR = absent; anything else at the path is present and must read as a regular file. This
changes one verdict on purpose: a ledger named by `ledger_file` that exists but is not a regular file (a FIFO, a device,
a directory, a dangling symlink) was a silent SKIP "ledger not next to the pack" and is now a `ledger-chain` FAIL.

**One declared bound for every JSON document.** `MAX_DOC_BYTES` = `MAX_LINE_BYTES` = 64 MiB (67108864 bytes), the
existing ledger-line bound of the cryptovalid profile, now also bounds the pack, the sidecar, the tip and the trust
store in the four verifiers: a larger file is refused unread — on the size `fstat` reports, and again if more than the
bound can be read — with the reason `larger than 67108864 bytes`. Stored source documents keep their own bound (256 MiB,
hashed, never parsed). The ledger as a whole is bounded per line, not in total.

**Memory under the bound is NOT bounded — measured, not fixed.** A 64 MiB document made of tiny values stays within the
bound and is parsed: on `[{},{},…]`, `[[],…]`, `[0,…]` and `["",…]` it reaches a peak resident memory, measured on 25/09/2026 on HEAD `51ecbb3` with no effective limit (the parse path is unchanged by this change), of 1.8 GB in Python (as recorded) (`[{},…]`), 2.6 GB in Node (`[{},…]` ends in a V8 heap abort), 2.9 GB in Go (`[{},…]`) and 4.0 GB in Rust (`[0,…]`); one 64 MiB string costs 0.2–0.4 GB. Under an RLIMIT_DATA of 1500 MiB, after the change, `[{},…]` ends in a Python `MemoryError` (a `verifier-exception`, `assessed: false`), a Node abort, a Go runtime exit 2 and a Rust allocation abort — a crash, not a verdict, and not the same outcome in the four. The same document fits in a ledger line. Closing this needs a
lower bound or a bound on the number of values — a change to the acceptance profile shared with cryptovalid, left to the
author.

**`fingerprint: null`** in the sidecar passed in the five (Python library and CLI, JS, Go, Rust) while an int, a list or
an object failed. The signer always writes the 16-hex fingerprint, so present-and-null is now malformed like any other
non-match (`producer-signature` FAIL); absent stays "not declared".

**A NUL in `ledger_file`** is now `ledger_file malformed` in the four. Found by re-running the review's attack script on
this change: `os.path.isfile` had silently answered False on the embedded NUL (a SKIP in all five), the new presence check
let `os.lstat` raise ValueError in the reference (a `verifier-exception`) while the three ports failed `ledger-chain` as
unreadable. A NUL never names a file.

**Internal errors in the independent verifiers.** Go (`recover()`) and JS (`catch`) reported their own internal error as
a plain `FAIL`, indistinguishable from a tampered pack; Rust had no guard at all (a panic was exit 101 without a
verdict). The three now return the reference's shape: one `verifier-exception` layer, `ok: false`, `authenticity:
FAIL`, `assessed: false` (Rust: `catch_unwind` with a panic hook that keeps the message and prints nothing). Every
verdict of the four carries `assessed`, and the differential oracle compares it. `CRA_VERIFY_INJECT_FAULT=1` is the
test hook that raises inside the guarded verification, in the four alike; it can only ever produce this inconclusive FAIL.
Exit codes are unchanged (1).

**Oracle.** `verifiers/differential.py` gains 21 cases that carry a DECLARED outcome, checked on every row — the Python
CLI is a row, and a row that merely agrees with the reference but misses the declared reason is red — so a rule is red even when all five rows are wrong the same way (they were): FIFO and `/dev/zero` in
place of pack, sidecar, ledger (with a log key and implicit), tip and trust store, a stored source document on
`/dev/zero`, one byte over the bound for pack / sidecar / tip / trust store, `fingerprint: null` and absent, an
injected internal error on an intact pack, and a `ledger_file` containing a NUL. Hazard rows run with a 20 s timeout and an RLIMIT_DATA of 1500 MiB per child, so a
regression is a red row, never a hung oracle or a host out of memory. `CRA_ORACLE_BIG=1` adds pack / sidecar / tip /
trust store at exactly the bound (accepted). Measured 25/09/2026: the 139-case oracle of HEAD gives 0 divergences on HEAD; the 160-case oracle, with Go, JS and Rust required, gives 0 divergences after the change and, on HEAD, red rows on 20 of the 21 new cases (the twenty-first, the absent-fingerprint positive control, is red on HEAD only in the three ports and only for the missing `assessed`), plus 124 of the 139 old cases red only because the three ports carried no `assessed`. Tests: 121 → 130 (`tests/test_file_objects.py`: 8 of 9 red on HEAD, the ninth is the at-the-bound positive control). Ablation, one control removed at a time in each of the four verifiers: the regular-file check (a `stat` before `open` AND an `fstat` on the descriptor — they back each other up, removing only one turns nothing red) → 13 cases red; `O_NONBLOCK` together with the pre-open `stat` → the 6 FIFO cases (`O_NONBLOCK` alone is covered by the `stat`: it guards the swap between the two); the size bound → the 4 over-the-bound cases; the lstat presence rule → the 6 ledger/tip cases; the fingerprint rule → 1; `assessed` on the exception → 1; the NUL rule → 1. The read cap of `bound + 1` bytes is covered by the `fstat` size check and guards only a file that grows while it is read: no case exercises that race.

`systemd-run --user --scope -p MemoryMax=…` does NOT bound memory on a cgroup-v1 host without a delegated memory
controller: measured on 25/09/2026, 400 MB allocated under `MemoryMax=100M` (the cause is our reading; the effect is what was measured). The measurements above use RLIMIT_DATA (`prlimit
--data`), which is inherited through the scope and was measured to stop Python, Node, Go and Rust.

Version: 0.3.2 in both `pyproject.toml` and `cra_evidence/__init__.py` (0.3.1 had left `__init__` at 0.3.0).

## 0.3.1 — 2026-09-24
A check this host could not run is not a finding about the pack. Two branches, both measured.

**A missing library.** Found while building this very release: a pack signed minutes earlier with the KMS key
verified as `authenticity: FAIL` in a venv without `cryptography` — our own missing library reported with the value
of a bad signature, on our own release artifact. That branch now carries `assessed: false`; `ok` and `authenticity`
stay FAIL (fail-closed), but the run reads as inconclusive rather than adverse. With `cryptography` present the same
pack verifies `trusted-signed`.

**An exception inside the verifier** is not a finding about the pack either. Measured on
`examples/self_evidence/cra_pack.json`, a genuinely signed pack that verifies as `authenticity: signed`: with an
internal error injected it came back `ok=false, authenticity=FAIL`, indistinguishable from a tampered pack — our own
defect reported with the value of theirs. Every return now carries `assessed`, false only in the verifier-exception
branch. `ok` and `authenticity` stay FAIL there (fail-closed: a pack that could not be verified must never read as
verified), but a caller can tell "this verifier broke" from "this pack is bad". The field is on every return on
purpose: one that appeared only on the bad path could not be told from an older build that has no field at all.

The verdict tuple `(ok, authenticity, anchored)` and the exit codes are deliberately unchanged, because those are what
the Go, JS and Rust verifiers are compared against by `verifiers/differential.py`. 121 tests pass; the differential
oracle runs 139 cases with 0 divergences (js, rust).

## 0.3.0 — 2026-09-20
The generator's SBOM document is the evidence. Measured with the real generators (Syft 1.52.0, Trivy 0.74.0, cdxgen
12.8.4 — all emitting CycloneDX 1.7 by default) and sbomqs 2.1.2 on a 419-component npm tree: 0.2.0 stored only its
own re-encoding of an ingested SBOM, which scored below every original (5.3→4.2, 6.6→4.4, 4.8→3.7). Now `cra sbom
--from-cyclonedx/--from-spdx` hashes the document's exact bytes (SHA-256) into the record, copies it to
`<ledger>.sources/<sha256>.json` (`--no-store-source` keeps the hash only; the store never overwrites different bytes;
a file changed between ingest and record is refused), and every verifier — Python, JS, Go, Rust — re-hashes it
(`source-documents` layer: mismatch FAIL, absent SKIP, `--require-sources` makes absence a FAIL). The record's index
now carries component type, CPE and what the document declared (generator + version, spec version, components incl.
nested, duplicates merged, dependency edges, component types); nested `components[].components` are walked; a
malformed hash is dropped as in the SPDX path; SPDX `primaryPackagePurpose` maps to the type and `cpe23Type` refs are
read. Export: CycloneDX 1.6 or 1.7 (official 1.7 schema vendored), with serialNumber, `metadata.tools`, bom-refs
(unique), component types, CPEs, SPDX licence *expressions* (`Apache-2.0 OR BSD-3-Clause`), and `dependencies` only
from edges the producer knows — the installed floor's Requires-Dist graph as walked, with PEP 508 markers evaluated for this interpreter (`packaging` when importable, else a small evaluator; an unevaluable marker keeps the edge and is counted): `dependsOn: []` is emitted only for a component whose metadata was read, everything else is declared an `unknown` composition (CycloneDX's own value for "inconclusive") — never re-invented for an ingested graph; the installed floor reads PEP 639
`License-Expression` (cryptography ships it since 46.0.0 with the legacy `License` field empty, measured on PyPI metadata 20/09/2026 — with such a distribution 0.2.0 recorded no licence).
Validated with the official CycloneDX CLI 0.33.1 and pyspdxtools 0.8.5 (CI steps with positive controls: the workflow ran green on every 0.3.0 push to master; the run on the release tag is named in the release notes) and with jsonschema in the tests.
Six unmodified generator documents vendored as fixtures. Differential oracle: 139 cases (incl. hostile `source.sha256` values: int, object, null, empty, upper-case, traversal, non-ASCII; `--require-sources` with the ledger missing; a stored document made unreadable), and the failing layers must
agree too (ablation caught; before the fix Go/Rust skipped a non-string hash while Python/JS failed — found by self-review and by reviewer 3 in round 1). Interop re-measured against cryptovalid 0.15.0. The independent AI reviewers of these rounds are numbered 1–5 throughout this repository (1–4 from one provider, 5 from another; the tests use the same numbers). Found by the round-1 review (reviewer 1) and fixed: the Python reference parsed pack, sidecar, tip and trust store with plain `json.loads` (duplicate keys accepted, first-wins for a reader, last-wins for the verifier — JS/Go/Rust refuse them) → strict parser everywhere; Python `verify_tip` did not check `kind` / `log_pubkey_hex` (the three did); the Go verifier ignored the scanner error (a line above 64 MiB ended the scan silently and the prefix verified); a `source_path` could be bound to an index not read from it; an ingested SBOM recorded without `source_path` carried a hash nothing re-verified (reviewer 2) — now refused; a generator document nested too deep crashed the ingest instead of raising (reviewer 2) — malformed now; the JS verifier built a 65 M-node string on a 65 MiB pad and died (fast path added); all four verifiers and the producer now share cryptovalid's 64 MiB line bound. Round 2 (reviewers 1, 2): the JS verifier accepted integral floats (`10.0` parses to 10 and hashes alike) while the other
three refused them → number tokens with `.`/`e` refused in JS and in the Python parser (generator documents excepted: they are
bytes, never canonicalised); the trust store was read laxly by JS and Go (a duplicate `signer_id` gave `trusted-signed` there and
a refusal in Python/Rust) → strict object of strings in all four, unreadable = exit 2 everywhere, the oracle's reference now
loads it as the CLI does; Rust ignored a non-string sidecar `fingerprint`; the export said `compositions: incomplete` for
components nothing was read about (that asserts more exist) → `unknown`; the ingest read the file twice (index of one version,
hash of another) → read once; `record_sbom` re-derives the index from the bytes it stores and refuses one that differs (a
mutated index next to the right document verified PASS); the SBOM must belong to the locker's product; stored documents above
256 MiB are refused unread; a non-UTF-8 pack is `pack-json` in all four; CI gained a job with NO optional dependency (the
"three configurations" were measured by hand before; round 3 added the third job, cryptography only — all three enforced now). Oracle cases for each.
Round 3 (reviewers 1, 2, 3): the Rust verifier could still panic on non-ASCII hex / instant strings in the sidecar and the
tip (byte slices) → ASCII guards; tip field types were not the same in the four (Python `int("3")`, `log_pubkey_hex` empty or
non-string read four ways) → one rule: `entries` a JSON integer ≥ 0, `ledger_id`/`tip_sha256` 64-hex, `ts` an instant,
`log_pubkey_hex` absent/null/"" = not checked (cryptovalid's rule), anything else must equal the trusted key; a non-string
`signer_id` reached `trusted-signed` in JS only → must be a string in all four and in `sign_pack`; the 64 MiB line bound was
off by one across the four (with/without the terminator) → content bytes, terminator excluded, boundary cases at exactly
64 MiB (accepted) and +1 (refused); the re-derivation in `record_sbom` did not cover `edges`/`depth` (a forged dependency
graph and profile label rode through with the right document) → covered; generator documents are bounded (256 MiB) before
being read at ingest and at record time; an anchor is matched only against a 64-hex `pack_sha3` (a pack without one matched
an anchor without one in three verifiers); a stale `__pycache__` had stamped the day's scored exports as 0.2.0 → cache
cleared, exports regenerated and re-scored (Syft 5.3, cdxgen 5.5, Trivy 4.8, installed floor 4.5); 39 fields vs 44 glossary
rows reconciled in the texts; CI runs three dependency configurations. Oracle after round 3: 66 cases, 70 with
`CRA_ORACLE_BIG=1`, 0 divergences.
Round 4 (reviewers 1, 2, 3) — input hygiene was still four rules, not one: a blank ledger line was ASCII-whitespace in
Python and Unicode-whitespace in the three (a U+00A0 line broke the chain in the reference and passed elsewhere) → blank =
ASCII space/tab only; the line terminator was "any run of `\r`/`\n`" in Python (66 MiB of `\r` padding verified there and
was refused by the three) → exactly one `\n`, then at most one `\r`, and the reference reads lines bounded (never buffers a
hostile line whole); integers outside ±(2^53-1) were refused at parse in Go/Rust and only at hashing in Python/JS (a signed
sidecar or tip with such a field was `trusted-signed` in two verifiers) → refused at parse in all four; the JS verifier
decoded every input but the pack lossily (one invalid byte in a sidecar read as `signed`/`trusted-signed`) and dropped a
UTF-8 BOM (a pack with a BOM verified in JS only) → strict decoding, BOM kept, on every input; Go and Rust treated a sidecar
that exists but cannot be read (directory, mode 0, not UTF-8) as "not signed" → SKIP only when there is no sidecar; the Rust
JSON module accepted `+10`, `010` and raw control characters in strings (canonical form unchanged, so a byte-tampered pack
verified `signed` in Rust alone) → RFC 8259 grammar (the same module is cryptovalid's: to be fixed there too); `ledger_file`
was resolved four ways (a non-string, an array, a trailing slash) → must be a plain file name in all four, else FAIL;
`honest_scope` must be a string; a lone surrogate escape in a pack failed at different layers → refused at parse
everywhere; a sidecar missing `signed_utc` (or with a non-string field) threw past the JS signature check → an invalid
signature; the tip `ts` is checked by shape in all four (JS validated the calendar alone). A public sentence "Round 4: no
material issues" had been written before round 4 ran — removed; this paragraph is what round 4 found. Oracle after round 4:
93 cases, 98 with `CRA_ORACLE_BIG=1`, 0 divergences.
Round 5 (reviewers 1, 2, 3): the Python reference could not parse the profile's own nesting bound — with the strict hooks
CPython's JSON scanner stopped at depth 332 (the three verifiers accept 512), so a record the producer had written (a
verbatim CSAF/VEX attachment, a deep `details`) verified in JS/Go/Rust and failed in the reference, and the next append
crashed → linear depth pre-scan (exactly the verifiers' rule) before parsing, recursion limit raised locally while
(de)serialising, the LINE's depth bounded at append, `RecursionError` never escapes; an aborted record scan was reported as
"a digest does not match" → stated as an aborted scan; Go's `bufio.ScanLines` already drops one `\r`, the manual strip
removed a second (a `\r\r\n` line was blank in Go alone) → removed; a sidecar that is a dangling symlink was "not signed"
in Python/JS and unreadable in Go/Rust → `lstat` rule everywhere; SPDX documents with a list where an id string is expected
crashed the ingest (`TypeError`) → type guards on every SPDX field; the writer's own tail reader now uses the verifiers'
line rules (bounded, one terminator, ASCII blank); without `cryptography` a valid signature was reported "invalid"
(`ModuleNotFoundError` caught as an invalid signature) → "present but NOT checkable here", with a vendored signed fixture
(its tests were hidden from CI by a misplaced `__main__` block until round 7 — CI now runs `unittest discover` and asserts that every TestCase class ran); `--ledger ""` is a usage error in all four; `WITH` exceptions carrying a version
(`Classpath-exception-2.0`) are recognised as SPDX expressions. Oracle after round 5: 99 cases, 104 with
`CRA_ORACLE_BIG=1`, 0 divergences.
Round 6 (reviewers 1, 4 — reviewers 2 and 3 found nothing; the two found the same three and one more each): the JS
verifier's key-dropping copy lost an own `__proto__` key (a pack or entry with such a key verified in JS alone — and a
`__proto__` added with the digest untouched verified as bound in JS alone) → `Object.fromEntries`, cases with a `zz_extra`
control (cryptovalid's `cvverify.mjs` has the same function: to be fixed there); hex decoding of signatures was four rules
(`bytes.fromhex` skips spaces, `Buffer.from(…, "hex")` truncates at the first non-hex, Rust takes `+`) → lower-case hex of
exact length before decoding, in sidecar, tip and `--log-pubkey`, in all four; a CLI flag with an empty value or no value
(`--trust-store ""`, `--log-pubkey "$KEY"` with the variable unset, a trailing `--ledger`) was silently dropped by one
verifier or another → usage error (exit 2) in all four, and the Python CLI is now a row of the oracle for these; the Go
and Rust payload builders signed a MISSING `signed_utc` as `null` (a sidecar without the time verified there) → every
signed field must be a non-empty string and `signed_utc` an instant, in all four and in `sign_pack`; SPDX `SPDXID` as a
list crashed the ingest and hostile non-string fields (`name: ["a"]`) were stringified into data → never coerced; an
ingested-format record without a hash passed `--require-sources` → malformed; the writer's tail reader bounds the
content length; the store compares sizes before bytes; an unreadable ledger is `ledger-chain` in the reference too;
the README sentence "until a round found nothing material" was not true of the record → replaced by the dated outcome.
Oracle after round 6: 122 cases, 127 with `CRA_ORACLE_BIG=1`, 0 divergences.
Round 7 (reviewers 1, 4; reviewers 2 and 3 found nothing): "is there a sidecar?" was four rules (a legal 250-byte pack name
makes the sidecar name exceed NAME_MAX: `verifier-exception` in Python, "not signed" in JS/Rust, unreadable in Go) → one rule,
lstat ENOENT/ENOTDIR = no sidecar, any other error = FAIL, with a case; a run of spaces above 64 MiB was a blank line in JS/Rust
and a refusal in Python/Go → the bound comes before the blank test everywhere (two gated cases); the two tests of the vendored
signed fixture had never run in CI (a `__main__` block above the class) → moved, CI runs `unittest discover` and asserts that
every TestCase class ran; two README sentences were false of the code ("four processes appending at once — is a named FAIL":
they produce one valid chain; the seal policy "defaults to the NIST IR 8547 dates for both the signature and the hash": the
default bounds Ed25519 only and the verdict says the hash is not bounded) → rewritten; `version` is bounded to the schema's
maxLength (1024) at ingest and the product version refused above it (an 1100-character version made a schema-invalid
export); the index's `metadata.component.type` is the generator's (Syft declares the scanned directory as `file`; the SPDX branch
followed in round 10), not a default; an SPDX 3.0 `identifier` list was still stringified into `cpe` → never; a lone surrogate escape in a generator
document was a `TypeError` at record time → malformed at ingest; the verifier reads the ledger once (chain, binding, anchor,
sources and tip judge one snapshot); the example pack is now signed (an ephemeral key, its public key in `trust.json`) as
its README already said; oracle hygiene: a stale Rust binary is refused like a stale Go one, the Python-CLI rows run from the
repo root. Oracle after round 7: 123 cases, 130 with `CRA_ORACLE_BIG=1`, 0 divergences.
Round 8 (reviewers 1, 4; reviewers 2 and 3 found nothing): the CI guard "every TestCase class ran" could not match the
`unittest -v` line format of Python 3.11/3.12 (the first push would have gone red on two of three rows) → matches both
formats, with a fake-class positive control; an unknown flag, an abbreviation (`--require-source`, `--log`) or a second
positional was silently taken as the pack by the three verifiers (a typo verified PASS on an absent source document) and
abbreviations were expanded by the reference → usage error in all four (`allow_abbrev=False` on every subparser), and
`--flag=value` is one grammar in the four; the ledger next to a pack reached through a symlink and `..` was found by Rust
alone → the pack's directory is resolved through the filesystem (`realpath`) in all four (Node's JS `realpathSync` resolved
`..` before the symlink: its `.native` variant does not); a component the generator declared without a version exported
`version: ""` → omitted; a `kind` that is not a string crashed `evidence_pack` → ignored in the counts; verifiers/README
listed five gated big-line cases for seven; `SECURITY.md` pointed at a file that does not exist; the README claim "no wall
clock in tests" was broader than the tests → "the deadline arithmetic never reads the wall clock". Oracle after round 8:
129 cases, 136 with `CRA_ORACLE_BIG=1`, 0 divergences.
Round 9 (reviewers 1, 2; reviewer 3 found nothing; reviewer 4 also ran but its reports were discarded unread when its use was revoked; 21/09/2026): the full-dependency CI job piped `unittest` into `tee` without
`pipefail` — it could not go red → `shell: bash`, `set -o pipefail`, and the guard asserts the suite ended `OK`; the
reference read the pack through `pathlib`, which normalises `p.json/` to `p.json` (the three answer ENOTDIR) → OS path
semantics in the reference, sidecar = the argument + `.sig.json`, two cases; a declared-but-NOT-INSTALLED name was exported
as a component with the fabricated version `NOT-INSTALLED` (and inflated `component_count`) → named in a
`cra-evidence:declared_not_installed` property, never a component; the installed floor's version is bounded like the two
ingest paths; a record tampered with its `record_sha3` left stale and the whole chain re-linked coherently was caught by
the four but exercised by no test or case (the test that claimed to test the binding was caught by the chain) → oracle
case and unit test on the binding layer alone; a value flag followed by a flag, and a pack named `-`, are usage errors in
all four; a stored copy is removed if the append that records it fails; the README's "five models in three rounds"
now says it is 0.1.0's history. Oracle after round 9: 134 cases, 141 with `CRA_ORACLE_BIG=1`, 0 divergences.
Round 10 (reviewers 1, 2; reviewer 3 found nothing): after round 9 a parent whose declared child is not installed kept a
positive `dependsOn` list with the child silently dropped (the product's own list read "no dependencies" while one was
declared) → such a parent is left out of the graph and declared `unknown`; the SPDX ingest never set the product's type
(the same Syft scan gave `file` from CycloneDX and the default `application` from SPDX) → the root's
`primaryPackagePurpose` / `software_primaryPurpose` maps to `metadata.component.type`, a purpose without a CycloneDX
counterpart is kept as declared in `source.root_purpose_declared`; a stored source path that exists but is not a
regular file (a directory, a symlink to one, a dangling symlink) was reported as honest absence in all four → FAIL, three
cases; `record_id` must be a UUID (it becomes the schema-patterned `serialNumber`); the texts said "measured 20/09" and
"in CI" of cases that exist since 21/09 and of a workflow not yet run on 0.3.0 → dated 21/09/2026, and "in CI" is stated
only where this release's CI run is green on the tag. Oracle: 137 cases, 144 with `CRA_ORACLE_BIG=1`, 0 divergences.
Round 11 (reviewers 1, 2; reviewer 3 found nothing): the CHANGELOG line above had said "run green on the v0.3.0 tag" before any
tag existed — the same premature-sentence class as rounds 4 and 10 — → replaced by the measured run (master, all jobs
green); the JS verifier read the whole ledger into memory before the per-line bound (Python and Go stream; Rust did not either,
found in round 12) → a bounded
line reader (the oracle caught two bugs of the new reader before it was right: the bound was applied to the raw line, and
an open failure escaped as an exception); a failed `record_sbom` could delete a stored document that a concurrent,
already-recorded call relied on → the copy is removed only if no record references its hash; the tip's SKIP wording said
"tail truncation" where a rewritten or extended tail is equally unseen without the tip key → "tail not sealed"; an SPDX
root purpose without a CycloneDX counterpart is now declared in the export too (`cra-evidence:root_purpose_declared`);
stale type hints fixed. Oracle after round 11: 137 cases, 144 with `CRA_ORACLE_BIG=1`, 0 divergences.
Round 12 (reviewers 1, 2; reviewer 3 found nothing): the Rust verifier read the whole ledger into memory too (the round-11 sentence
"the other three stream" was false of it) → a bounded `BufReader` line reader; measured on a ledger with one 600 MiB line,
peak RSS: Python 149 MB, JS 126 MB, Go 195 MB, Rust 68 MB, all four `ledger-chain` FAIL; the `.sources` path was built with
`path.join` / `filepath.Join` in JS/Go, which resolve `..` lexically before a symlink (with `--ledger d/sym/../l.jsonl` and
a tampered copy at the real location, JS and Go verified PASS) → plain concatenation in all four, two cases; the
`NOT-INSTALLED` sentinel is applied to the installed floor only (an ingested document's literal string is a version);
the round-11 CHANGELOG sentence named a CI run of the previous commit as if it covered the current one → no commit hash in
this file, the release tag's run is named in the release notes. Oracle: 139 cases, 146 with `CRA_ORACLE_BIG=1`, 0
divergences.
The review was stopped here by the author on 21/09/2026 after round 12: no round of the twelve ended without a finding;
rounds 10–12 found edge cases (a 600 MiB ledger line, an explicit ledger path through a symlink and `..`) and premature
sentences in this file, not verdict divergences on ordinary input. A thirteenth round had been started and was cancelled
unread. What is stated above is what was measured on the code as released. Legal basis re-read 20/09/2026 (ENISA
FAQ: no API at initial release; glossary unchanged; Digital Omnibus 2025/0360(COD) still a proposal).

## 0.2.0 — 2026-09-15
SPDX ingest: `sbom_from_spdx()` / `cra sbom --from-spdx` read SPDX 2.2/2.3 JSON (`packages`, purl external refs,
SHA-256 checksums, supplier/originator, concluded→declared licence) and SPDX 3.0 JSON-LD (`software_Package`,
`software_packageUrl`, `verifiedUsing` Hash, `suppliedBy` resolved to the agent, licences via hasConcludedLicense /
hasDeclaredLicense relationships); the product described by the document is not a component; `NOASSERTION` versions
are not resolved and never meet the Annex I floor. Field names checked on the official spdx/spdx-examples documents,
vendored as fixtures. Suggested by the competitor review of 15/09/2026 by reviewer 5 (Yocto and other industrial
generators emit SPDX natively).

## 0.1.1 — 2026-09-15
Independent verifiers in JavaScript (Node, no dependencies), Go (standard library) and Rust (pure-Rust JSON/SHA-256/
SHA3-256 + ed25519-dalek) with the same CLI and verdict as `cra verify`; differential oracle on 26 intact/tampered
fixtures (0 divergences), required in CI. `cra sign --aws-kms-key-id`: Ed25519 signing in AWS KMS (SigV4, standard
library; derivation validated on the official AWS vector). Release packs signed with the author's KMS key; trust
store published with each release. Clean-clone bench: 5 passes, 7/7 suites (67 tests) each.

## 0.1.0 — 2026-09-15
First public release. SBOM records (schema-valid CycloneDX 1.6 subset; ingest of any CycloneDX; VEX/CSAF documents
embedded content-bound), Art. 14 clock on recorded submission instants (vulnerabilities and severe incidents; calendar
month per Art. 14(4)(c)), SRP-aligned notices (39-field ENISA glossary derived from a vendored dated snapshot, per-stage
R/O/A/C rules, PEC options), hash-chained ledger in the cryptovalid profile (flock fail-closed, torn tail refused,
floats/NaN/unportable ints/lone surrogates refused, signed chain tip), evidence pack anchored + Ed25519 sidecar whose
signature covers signer and time, crypto-agile seal (renewable chain, pinned key, hash named per record, NIST IR 8547
dates as default policy, time token stored when given), offline verifier with layers and authenticity levels (tip
checked with a trusted log key), OSV (chunked, paginated, aliases, aligned to input) / CISA KEV / ENISA EUVD feeds with
positive controls (OSV aliases resolved per id, since the batch endpoint is condensed). Seal signs its own fields;
hash policy applied to every record; carried-forward SRP fields copied from the previous stage or counted missing;
incident final-report deadline never invented in a notice; licences exported as SPDX id or free-text name; pack
written atomically after its anchor; a required ledger that is missing is a FAIL. Interop measured against
cryptovalid v0.11.4. Three council rounds (five models, two providers): 44 findings → tests.
