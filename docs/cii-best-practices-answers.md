# OpenSSF Best Practices Badge — Answer Draft

Working draft for the [OpenSSF Best Practices "Passing" tier](https://www.bestpractices.dev/) self-attestation. Sign in with GitHub at <https://www.bestpractices.dev>, start a new project entry for `https://github.com/Dashtid/dicom-fuzzer`, then paste from below.

The form auto-fills several fields from the GitHub repo (description, license, etc.); the entries below cover the rest.

After the badge is awarded:

- OpenSSF Scorecard's `CII-Best-Practices` check picks it up automatically within ~24h (0/10 → 10/10).
- Optional: add the badge to README. The form gives you the markdown.
- This draft file can stay as a record of what was attested, or be deleted.

Format below: **criterion** → answer + evidence URL or short justification.

## Basics

- **Project URL** → `https://github.com/Dashtid/dicom-fuzzer`
- **Project description** → Mutation-based fuzzer for DICOM medical imaging viewers and parsers. Generates malformed DICOM files and feeds them into target applications to find crashes and vulnerabilities.
- **Interaction** → GitHub Issues (`https://github.com/Dashtid/dicom-fuzzer/issues`); security via SECURITY.md.
- **Contribution guide** → `CONTRIBUTING.md` at repo root.
- **License** → MIT (`LICENSE` at repo root). Confirmed OSI-approved.
- **License location** → `https://github.com/Dashtid/dicom-fuzzer/blob/main/LICENSE`
- **Documentation: basic** → `README.md` covers install, quickstart, CLI reference.
- **Documentation: interface** → `docs/QUICKSTART.md` and `docs/ARCHITECTURE.md`; CLI help via `dicom-fuzzer --help`.

## Change Control

- **Public version control** → Git on GitHub.
- **Repository URL** → `https://github.com/Dashtid/dicom-fuzzer`
- **Interim versions** → All commits public via GitHub.
- **Unique version numbers** → Semver in `pyproject.toml` (currently `1.11.0`); each PyPI release tagged.
- **Release notes** → `CHANGELOG.md` updated per release; `release.yml` workflow auto-extracts the relevant section into GitHub Release notes.
- **Release notes vulnerabilities** → CHANGELOG flags security-relevant fixes; SECURITY.md describes disclosure process.

## Reporting

- **Bug reporting process** → `CONTRIBUTING.md` references GitHub Issues; issue templates in `.github/ISSUE_TEMPLATE/` if present (verify on form).
- **Bug report response** → Solo-maintained; commits to acknowledge within reasonable time per `SECURITY.md`.
- **Vulnerability reporting** → `SECURITY.md` defines the private disclosure channel.
- **Vulnerability response** → SECURITY.md commits to a reasonable response window.

## Quality

- **Working build system** → `uv build` produces wheel + sdist; CI verifies on every PR (`build` job in `.github/workflows/ci.yml`).
- **Automated test suite** → `pytest` (~4900+ tests), runs in CI on Python 3.11–3.14.
- **New functionality testing** → Tests required for new features per `CONTRIBUTING.md`; mutation testing also runs (`mutation-testing.yml`).
- **Warning flags** → ruff (lint + format), mypy (type checking), Bandit (security), all gating in CI.

## Security

- **Secure development knowledge** → Maintainer has security background (security testing tooling, CVE auditing, SBOM tooling are core to this project's value proposition).
- **Used cryptography** → Yes, indirectly: `cryptography` package used for TLS testing in network fuzzing module. Direct-use crypto pinned to `>=46.0.7`.
- **Secure key management** → No project-managed keys; CI uses GitHub OIDC trusted publishing for PyPI (no long-lived secrets).
- **Cryptographic algorithms** → Modern only: TLS 1.2+ via `cryptography`; no MD5/SHA1 for security; SHA-256+ for hashing.
- **Secure delivery** → PyPI distribution over HTTPS; releases signed via PEP 740 attestations (sigstore) — see `release.yml`.
- **Vulnerabilities fixed** → No outstanding known vulnerabilities. Dependabot + Trivy + Grype run continuously; KEV catalog enrichment via sbom-sentinel; weekly SBOM scan via `sbom-scan.yml`. Remaining unpatchable: pip CVE-2026-3219 (no upstream fix yet, tracked in BACKLOG).
- **Static code analysis** → Yes: CodeQL (`codeql.yml`), Semgrep (`security.yml`), Bandit (`ci.yml`).
- **Dynamic code analysis** → Mutation testing via mutmut (`mutation-testing.yml`); fuzzing roadmap: atheris targets and a fuzz workflow planned (BACKLOG / inflight PR).

## Analysis

- **Static analysis** → CodeQL runs on every PR + scheduled; results uploaded to GitHub Code Scanning.
- **Static analysis fixes** → Findings triaged via Code Scanning UI; high-severity fixed before merge.
- **Dynamic analysis** → Bandit (security-focused static + dynamic patterns), mutation testing (mutmut). Fuzzing roadmap as above.

## Notes

- Many fields auto-populate from the GitHub repo (license, readme, etc.) once the project URL is entered.
- For "Unknown" or "Unmet" answers (if any), the form lets you mark them and explain — not all criteria are gating for the "passing" tier.
- If a question doesn't apply (e.g., "project meetings"), select **N/A** with a one-line justification ("solo-maintained, no meetings").
