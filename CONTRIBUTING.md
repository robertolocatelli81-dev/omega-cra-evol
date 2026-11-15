# Contributing

Thank you for looking at omega-cra-evol. This page says what is welcome today and how.

## Welcome

- **Reports of defects** you can reproduce: open an [issue](https://github.com/robertolocatelli81-dev/omega-cra-evol/issues)
  with the version (`cra --version`), the exact command, the input (or a minimal one that shows the same result), what
  you expected and what you got.
- **Interoperability reports and divergences** found by your own verifier or generator, and questions: open a thread in
  [Discussions](https://github.com/robertolocatelli81-dev/omega-cra-evol/discussions).
- **Vulnerabilities**: privately, as [SECURITY.md](SECURITY.md) says — never in an issue or a discussion.
- **Documents that the tool should read** (an SBOM your generator writes, a notice it refuses wrongly): attach them to
  the issue if you may share them and they contain no personal data.

## Code contributions

Pull requests with code are **not accepted at present**. The project has one maintainer, who answers for every line
it publishes; until there is a reviewer other than the author and a written rule for the rights in contributed code,
a report with a reproducer is the way to get a change made. A pull request is closed with a pointer to this section;
its idea is welcome as an issue.

## How the maintainer's own changes are made

- Since 15/11/2026 every commit carries a `Signed-off-by:` line (earlier commits do not): the author certifies the [Developer Certificate of Origin 1.1](DCO)
  (the text in this repository is the one published at https://developercertificate.org/).
- Changes written with the help of an AI agent say so in the commit message (`Assisted-by:` line); the maintainer
  reviews them and is accountable for them.
- A rule of a format changes first in its written specification (`spec/`), with a version, then in the code.
- A change comes with a test that fails on the code before it; the whole CI ([`.github/workflows/ci.yml`](.github/workflows/ci.yml))
  is run before it is pushed.
