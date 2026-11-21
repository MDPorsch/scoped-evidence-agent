# Changelog

Format: Keep a Changelog; versions follow SemVer.

## [0.0.1] - unreleased

### Added (M6: live remote mode; built, not yet exercised on a real container)
- `scoped-agent live run` collects DNS, TLS, HTTP, AI model-list and API evidence from the hosts a `mode: live` scope declares, inside an
  isolated container that installs a default-deny firewall, proves it with a self-test and drops every privilege **before** it is sent a job;
  the controller refuses to continue unless every check passed (`docs/remote-live-design.md`). `run` still never opens a socket.
- A live scope declares an `authorization` (engagement and window) and optional `egress` (private ranges, rate). A run needs the window
  open, `--ack-authorization` on every run, an approval bound to the scope hash (`approvals grant|list|revoke`) and an image pinned by digest.
- Each host is resolved once and every address judged (public by default, private only if listed, metadata, link-local, multicast and
  IPv4-embedding IPv6 never); a refused host is not contacted and its operations are recorded as refused. A credential is named
  by `--credential NAME=ENVVAR`, reaches only the declared host over verified TLS, and a leak guard fails the run if any form of it is in any
  stored byte. What the sandbox returns is untrusted: only two kinds of file, strict envelopes, re-redacted artifacts.
- Migration `0005`: append-only `approvals`, `approval_revocations` and `live_runs`. Decisions D-E74 to D-E80.

### Added (M5: API-target scopes, offline)
- A scope may list `api_targets` (`docs/api-targets.md`): REST APIs with a base path, named principals, explicit `GET`/`HEAD` endpoints
  whose `{name}` segments take a listed value list (at most five values, never a range), CORS origins to try, and a request limit. The
  plan, the hash and the limits are exact; a spec lists inventory and never widens the scope.
- Three new observations, `api_spec`, `api_read` and `api_options`, read from a fixture pack's new `api` section: for each principal's
  answer, the status, redacted headers, the **shape** of a JSON body (never a value) with a digest of its structure, and three flags
  (stack trace, debug switch, echoed credential). The spec document is kept as a redacted artifact with an inventory. No artifact is
  kept for a read, and no rule reads API evidence yet, so a run drafts nothing.
- Migration `0004` rebuilds `targets` and `observations` (D-E70, **review-gated**): every row is copied unchanged in one transaction that
  checks nothing was lost, and `db upgrade` copies the database file aside first and says where.
- Decisions D-E70 to D-E73 (the rebuild, facts only, the CORS credentials header, the pack key).

### Fixed (found while building M5)
- `Access-Control-Allow-Credentials: true` was redacted by name (it contains "credential"), so the credentials branch of rule R-CORS-01
  could never fire on stored data. Only that exact header name is now exempt (D-E72), with a regression test through the real pipeline.

### Added (M4: the optional model adapter, off by default)
- `ai enable|status|disable|test` and `findings reword RUN [--finding ID]` (`docs/ai-adapter.md`). The model is Claude through the official
  `anthropic` SDK (an optional extra: `pip install "scoped-evidence-agent[ai]"`) or an offline stand-in that makes no connection. It may
  only **reword** a draft's rule sentences; the rule's text stays authoritative and is shown first, and a wording is labelled as not
  verified in `findings show` and in reports.
- Enabling is one command that shows what is sent and asks you to type `enable`; the configuration is a private `ai.json` with no secret in
  it; the API key comes from an environment variable and is never stored, printed or logged. `run` never calls a model.
- Every answer is checked item by item by code: exact reply shape, plain characters only, length, every number, date, version, header, path
  and host of the original kept, no verdict or escalation word added, no key. A failure keeps the rule's text and is recorded.
- A budget per run (calls, output tokens, total tokens), host names masked by default, an append-only record of every call
  (`model_calls`) and wording (`finding_wordings`), and an audit event per call. Migration `0003`.
- Decisions D-E66 to D-E69.

### Added (M3: drafts, review and reports)
- `run` now applies a reviewed catalogue of twelve deterministic rules to what it collected and stores drafts (`docs/correlator.md`):
  TLS weaknesses, missing security headers, version banners, sensitive-looking `robots.txt` paths, insecure or external redirects, exposed
  API descriptions, permissive CORS, DNS aliases outside the scope, and four AI-reply signals. Each draft carries a class from a closed
  list, CWE suggestions, conditions, an exploitability **assessment** (there is no "confirmed"), validation steps and a remediation, and
  waits for a person. Exit code `3` now means a complete collection with drafts to review.
- Validation steps are built from nine typed templates and checked against the scope before storage (six rules, each dropped step
  reported). They are read-only text for a person; the tool runs none of them and writes no exploit, payload or attack chain.
- `findings list|show|review`: a review needs a named reviewer and a reason and the first eight characters of the id typed back; the
  decision (`confirmed`, `not_exploitable`, `inconclusive`) is kept exactly, the reason is redacted, and a refusal is audited.
- `report export RUN --format json|md --output PATH`: one local file built from the database, no artifact content, byte-reproducible,
  new regular file only (never replaces, follows a link, or writes into the data directory), mode `0600`, sha256 printed.
- Migration `0002`: immutable finding details, append-only reviews, `runs.planned_operations`.
- Decisions D-E61 to D-E65 (the rules, storage, review mapping, report contents and CLI) are approved (2026-11-21).

### Fixed (found while testing M3)
- A long value quoted from a target (a host or banner at the allowed shape's maximum length) could exceed the schema's fact limit and fail
  the whole run, so a hostile target could stop drafting. A fact is now quoted only when the finished text fits, and titles and
  conditions are bounded.

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
- `LIMITATIONS.md`. The design rules (D-E01 onward) are stated in the documents that apply them.
- Fixtures: three scope files, three fixture packs (healthy, misconfigured, poisoned), a library of injection
  payloads and the golden normalised observations for each pack.
- Tooling: Python 3.13, uv, strict mypy, Ruff, pytest with a 90% coverage gate, SHA-pinned GitHub Actions, gitleaks
  over history, CodeQL, Dependabot.
