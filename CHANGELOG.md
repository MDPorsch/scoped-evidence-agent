# Changelog

Format: Keep a Changelog; versions follow SemVer.

## [0.0.1] - unreleased

### Added (M2: offline collectors)
- `scoped-agent run --scope FILE --fixture PACK` collects DNS, TLS, HTTP and AI-system evidence from a fixture pack, one operation at a
  time in plan order, with no socket. `scoped-agent observations show RUN` prints what was stored. `--live` is refused.
- Fixture packs: a strict, size-capped YAML file whose keys are canonical, whose entries are checked when used, and whose
  malformed answers become recorded errors for that operation. A pack can simulate a failure (`error:`) and carry a binary body
  (`body_base64`).
- Redaction before anything is stored: sensitive header names, token shapes, `Bearer`/`Basic`, `key=value` secrets, private-key blocks
  and e-mail addresses (the target's own are kept). The stored `source_hash` covers the redacted entry only.
- Parsers for `security.txt`, `robots.txt`, OpenAPI summaries, model lists and OpenAI-compatible replies: bounded facts only, JSON depth
  capped, nothing free-form copied, nothing fetched or followed.
- Compressed and binary bodies are never decoded: a placeholder with the size is stored, marked `metadata_only`.
- Every run ends with its coverage; an operation that errored, timed out, ran out of budget or had no answer makes the run incomplete
  (exit `2`). Cancelling or a crash keeps what was collected and the audit chain intact.

- 1723 tests, 100% line and branch coverage, 666 mutants all killed (225 new).

### Fixed (found while testing M2)
- A private-key block preceded by a second `BEGIN` marker could leave the key body unredacted (the end marker was matched by the tail
  of the second `BEGIN` line). The end marker is now the whole `-----END ... PRIVATE KEY-----` line.
- A certificate whose `san_dns` held a non-text entry made the TLS adapter raise instead of recording a parse error.
- A large but valid `robots.txt` or OpenAPI document was refused by the 8 KiB schema limit; the parsed facts are now shortened to fit.

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
