# Changelog

Format: Keep a Changelog; versions follow SemVer.

## [0.0.1] - unreleased

### Added (M0: contracts)
- Threat model, scope format, data flow, CLI contract, fixture format and the abuse-case test matrix (`docs/`).
- `DECISIONS.md` (D-E01 to D-E23, all proposed, none approved) and `LIMITATIONS.md`.
- Fixtures: three scope files, three fixture packs (healthy, misconfigured, poisoned), a library of injection
  payloads and the golden normalised observations for each pack.
- Tooling: Python 3.13, uv, strict mypy, Ruff, pytest with a 90% coverage gate, SHA-pinned GitHub Actions, gitleaks
  over history, CodeQL, Dependabot.
