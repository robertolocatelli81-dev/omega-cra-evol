# Links between the records of one ledger — version 0.13.0 (2026-11-18)

Status: normative for `cra vuln --component`, `EvidenceLocker.record_vulnerability(components=…)`,
`EvidenceLocker.notice_consistency` and the `ledger_consistency` member `cra notice` prints, from 0.13.0. Written
before the code (18/11/2026).

Origin, measured on 18/11/2026 with 0.12.0 on a ledger holding the release SBOM of goreleaser 1.21.2 and a
vulnerability record for CVE-2023-44487: (1) nothing in the vulnerability record says which component of the recorded
SBOM is affected (golang.org/x/net v0.15.0 was found by hand), while the Commission guidelines on the CRA
(C/2026/6013, OJ C, 17/11/2026, §218) make "contained in the product" the deciding point for a third-party component;
(2) `cra notice` recorded, with exit 0 and no warning, a notice naming another CVE (CVE-2021-44228), a component
absent from the SBOM (`log4j-core 2.14.1`) and an awareness instant whose 24-hour deadline had already passed.

## 1. `cra vuln --component <query>` — the component of the recorded SBOM

`--component` may be given more than once. Each query is looked up in the **last** `cra_sbom` record of the ledger
whose `product_id` and `product_version` are the command's (`--product`, `--version`), among the components of its
`sbom` (the CycloneDX index the record holds: `name`, `version`, `purl`).

- A query that starts with `pkg:` is a package URL. With a version (`@` after the name) it matches a component whose
  `purl`, cut at the first `?` or `#`, is the query cut the same way (exact strings); without a version it matches the
  components whose `purl`, cut at the first `@`, `?` or `#`, is the query.
- Any other query is `name` or `name@version` (the version is what follows the last `@` that is not the first
  character, so `@scope/pkg@1.2.3` is `@scope/pkg` and `1.2.3`): the name is compared exactly with a component's
  `name`, the version, when given, exactly with its `version`.
- An empty query, or one longer than 1,024 characters, is refused (exit 2, nothing recorded).
- In the API the queries are a list (or tuple) of strings: a bare string, a dictionary or anything else is refused
  (`ValueError`) before anything is written — a string would otherwise be read one character at a time.

No `cra_sbom` record of that product and version in the ledger: refused, exit 2, nothing recorded (`no SBOM recorded
for <product> <version>: record it with cra sbom first`) — a link to nothing is not written.

The vulnerability record gains (only when `--component` / `components=` is given; a record without it has the keys it
always had):

```
"affected_components": [{"query": <string>, "in_sbom": <bool>, "match_count": <n>,
                         "matches": [{"name", "version", "purl"}, … first ten]}, …],
"sbom_record": {"idx": <ledger index of the SBOM record>, "record_sha3": <its record_sha3>,
                "serial_number": <serialNumber of its index>, "source_sha256": <of the ingested document, or "">}
```

A query that matches nothing is recorded with `in_sbom: false` (the manufacturer's statement and the SBOM disagree:
the record says so, it does not hide it) and the command exits 1; `--allow-not-in-sbom` makes that exit 0. Nothing
here decides that a product is affected or exploitable: the link says which recorded component the manufacturer named.

Not done: no vulnerability database is queried with the SBOM's components (`cra feeds` takes identifiers only).

## 2. `cra notice` — what the notice says against what the ledger holds

Unchanged (srp-notice/2, rule 8): an awareness instant that differs from the vulnerability record's is refused unless
`--divergence-reason` is given. New: after the binding and before the drop file is written, the notice is compared
with the ledger, and the findings are printed in `ledger_consistency` (`{"findings": [{"code", "detail"}, …],
"checked": [<codes of the checks that could be made>]}`) and, one line each, on stderr (`cra notice: warning: …`).

| code | finding |
|---|---|
| `no_vulnerability_record` | the notice names a `cve_id` / `euvd_id` (its own or the previous stage's) for which the ledger has no `cra_vuln` record of this product: the Art. 14 clock of this notice is not in the ledger |
| `deadline_passed` | the stage has a deadline (early warning, notification) and it is earlier than the instant the notice is prepared: `due <deadline>, prepared <now>` |
| `product_version_differs` | the notice's `product_version` field is present and is not the ledger's product version |
| `component_not_in_sbom` | the notice's `component_name` is present, the ledger has a `cra_sbom` record of this product and version, and no component name of its last one is the field's value or one of its tokens (split at white space, `@`, `,`, `;`, `:`, `(`, `)`; case ignored; a piece split only at white space, `,`, `;`, `:`, `(`, `)` is also read as `name@version` as in §1, so `@scope/pkg@1.2.3` names `@scope/pkg`). A name comparison only: another spelling of the same component is reported too |

`checked` lists a check only when its inputs exist (no id in the notice: `no_vulnerability_record` is not checked; no
SBOM record: `component_not_in_sbom` is not checked).

The record and the drop file are written as before and their content does not change (the findings are a function of
the notice and the ledger: they can be computed again). Exit code: as before (0 complete, 1 incomplete); with
`--strict`, findings make it 1. Default not changed in 0.13.0 because a notice prepared after its deadline — every
notice of a test vector with a fixed date, and a late notice that still has to be filed — must stay recordable.
