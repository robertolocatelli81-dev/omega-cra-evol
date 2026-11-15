# The public API of omega-cra-evol and how it changes

This page declares what other code may rely on. It is kept true by tests, not by intention:
`tests/test_api_surface_20261115.py` compares the declared interface with a versioned snapshot, so a change of the
API is a line of diff that someone approves.

## Three tiers

| Tier | What is in it | What you can rely on |
|---|---|---|
| **Stable** | The twelve names of `omega_cra_evol.__all__`: `EvidenceLocker`, `SBOMRecord`, `SBOMComponent`, `sbom_from_cyclonedx`, `sbom_from_spdx`, `sbom_from_installed`, `VulnerabilityRecord`, `SRPNotice`, `DryRunDrop`, `srp_schema`, `verify_pack`, `__version__` — with their public methods and signatures. The commands `cra` / `omega-cra-evol`: their sub-commands, options and exit codes. The **formats**, below. | Breaks only as "Versioning" says, after a deprecation period. |
| **Provisional** | The names in the `__all__` of each module (`omega_cra_evol.ledger`, `.signing`, `.canonical`, `.art14_attest`, …). | Importable and annotated. May change in a minor release; the change is named in `CHANGELOG.md`. No deprecation period is promised. |
| **Private** | Everything else: any name that starts with an underscore, any name not listed in an `__all__`, the internals of `omega_cra_evol.cli` other than `main`, everything under `scripts/`, `tests/` and `verifiers/`. | Nothing. It changes without notice. |

`import omega_cra_evol` and take the names from there whenever they are in the stable tier.

The deprecated import name `cra_evidence` is an alias of the package, outside these tiers: it warns, and is removed
in a release on or after 2027-03-31.

## Formats

What the tool writes into evidence is a stronger promise than the Python API, because evidence outlives the code
that made it: ledger lines, evidence packs, signature sidecars and signed tips, receipts and their reason codes,
Art. 14 attestations, notice records.

- A format is **never changed in place**. A change that an existing verifier would read differently gets a new
  identifier (a new `kind`, profile value or type URI), and the earlier one keeps being verified.
- The identifiers written before the rename of the project are frozen (`tests/test_frozen_identifiers.py`).
- The written specifications are in `spec/`; the verifiers in `verifiers/` are separate implementations of them.

## Types

Every name of the stable and provisional tiers has complete annotations (no parameter or return without one):
`tests/test_api_surface_20261115.py` checks it, and the number of private signatures without one may only decrease.
The package does not ship the marker file `py.typed` yet: on 15/11/2026 `mypy` (non-strict) still reports 82 errors in
the package, most of them in code paths a type checker cannot narrow. `py.typed` ships in the release in which

- the package passes `mypy --strict`, and a client that uses only the stable tier passes `mypy --strict` against
  the installed wheel, both run in CI with a client that must be refused;
- many values stay `Dict[str, Any]`: records and receipts are JSON objects whose shape is given by the written
  formats, not by Python types. Narrowing them (`TypedDict`) is a compatible change and may happen in a minor
  release;
- an annotation made more precise is not a breaking change, even though a strict type checker may then report code
  that was wrong before.

## Versioning

The version is `MAJOR.MINOR.PATCH`, read as Semantic Versioning 2.0.0 with the stricter rules below for major
version 0 (SemVer itself allows anything to change in 0.y.z; an adopter needs more than that).

- **PATCH** (0.11.0 → 0.11.1): fixes only. Nothing in the stable tier changes.
- **MINOR** (0.11 → 0.12): additions; changes to the provisional tier; new deprecations; and — while the major
  version is 0 — removals from the stable tier **whose deprecation period has ended**, listed under a "Breaking"
  heading in `CHANGELOG.md`.
- **MAJOR**: from 1.0.0 on, a removal from the stable tier happens only in a major release.

A security fix may break the API without a deprecation period when there is no other way to fix it; the changelog
says so.

## Deprecation

Before something in the stable tier is removed or changes meaning:

1. it is marked deprecated in a release: a `DeprecationWarning` at run time naming the replacement and the earliest
   removal date, and a line in `CHANGELOG.md`;
2. it keeps working for **at least one further minor release and at least 90 days**, whichever is longer;
3. the removal is listed under "Breaking" in the changelog of the release that makes it.

The first use of this rule is the alias `cra_evidence`: deprecated on 2026-11-13, removed not before 2027-03-31
(138 days).

For a command-line option or an exit code the warning is a line on standard error, never on standard output
(standard output carries the receipt).

## When 1.0

Not yet. Between 2026-09-15 and 2026-11-15 the project published 18 releases; an API that moved that fast would
not honestly be called stable. 1.0.0 is released when all of these hold:

1. `mypy --strict` on the package and the client check have been green in CI for two consecutive minor releases;
2. no removal from the stable tier in those two releases;
3. the alias `cra_evidence` has been removed (so not before 2027-03-31);
4. at least one organisation other than the author uses the tool and says so publicly, or in writing to the
   maintainer.

At 1.0.0 the support policy (`SUPPORT.md`) is revised: a major line needs a stated period of security fixes.
