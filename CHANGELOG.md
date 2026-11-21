# Changelog

Format: Keep a Changelog; versions follow SemVer.

## [0.0.1] - unreleased

### Added (M1: domain and storage, and AI-system scopes)
- The strict scope parser (canonical hosts and paths, limits, expiry, hash, plan), the run and finding state machines, SQLite with
  Alembic (constraints, composite foreign keys and append-only audit triggers enforced by the database), a hash-chained audit trail,
  an atomically reserved request budget, a private content-addressed artifact store, structured logging and the commands `db upgrade`,
  `scope validate`, `runs list` and `audit verify`.
- Scopes for AI systems (`ai_targets`): the application layer only, four fixed rules, a reviewed probe library, limits the plan must fit,
  AI observation payloads, and target kinds in the schema.
- 1268 tests, 99% coverage, 425 mutants all killed.

### Added (M0: contracts)
- Threat model, scope format, data flow, CLI contract, fixture format and the abuse-case test matrix (`docs/`).
- `DECISIONS.md` and `LIMITATIONS.md`. Decisions D-E28 to D-E47 are approved (2026-11-20); D-E01 to D-E27, D-E48 to D-E55
  and D-E56 to D-E60 are proposed and await review.
- Fixtures: three scope files, three fixture packs (healthy, misconfigured, poisoned), a library of injection
  payloads and the golden normalised observations for each pack.
- Tooling: Python 3.13, uv, strict mypy, Ruff, pytest with a 90% coverage gate, SHA-pinned GitHub Actions, gitleaks
  over history, CodeQL, Dependabot.
