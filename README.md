# scoped-evidence-agent

An auditable, **local-first** assistant that collects bounded reconnaissance evidence from explicitly scoped
targets, keeps that evidence tamper-evident and redacted, and drafts observations that **a human must review**.
It is not an autonomous exploitation agent and it never decides that something is a vulnerability.

**Status: pre-alpha, milestones M0 and M1 only.** Nothing collects data yet. What exists is the contract
(`docs/`), the decisions awaiting review (`DECISIONS.md`), and the scope, storage, audit and state-machine
foundations. It is **offline-only**: it opens no network connection, and live mode is deliberately not built.

## Why it is shaped this way

* **What was observed, how, what is inferred, and what is unverified** are kept apart. A timeout or a DNS failure
  is an error, never "clean"; an incomplete collection never exits `0`.
* **Scope is a restriction, not proof of authorization.** The tool refuses an expired, ambiguous or wildcard scope
  and never widens it from a redirect, a CNAME or a sentence inside a web page. A human confirms authorization
  outside the tool.
* **Target content is hostile.** Prompt injection, secrets in headers and oversized bodies are primary threats.
  The model (when one is added) has no tools, no authority over targets and no way to mark anything verified.
* **Evidence is redacted before it is stored,** content-addressed, private on disk, short-lived by default, and
  recorded in an append-only, hash-chained audit trail.

## Read first

| | |
|---|---|
| `docs/threat-model.md` | what can go wrong and which control and test answers each threat |
| `docs/scope-format.md` | the scope file contract and the canonical host rules |
| `docs/data-flow.md` | what is stored, redacted, retained and sent |
| `docs/cli.md` | the commands and the exit codes |
| `docs/fixture-format.md` | fixture packs and the normalised observation schema |
| `docs/test-matrix.md` | the 20 abuse cases and what covers each |
| `DECISIONS.md`, `LIMITATIONS.md` | the choices awaiting review, and what this does not do |

## Develop

```bash
uv sync
uv run pytest -q
uv run ruff check . && uv run ruff format --check . && uv run mypy
```

Python 3.13. Apache-2.0. Use it only on systems you own or are authorized to assess.
