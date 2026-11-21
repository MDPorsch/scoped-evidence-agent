# scoped-evidence-agent

An auditable, **local-first** assistant that collects bounded reconnaissance evidence from explicitly scoped
targets, keeps that evidence tamper-evident and redacted, and drafts observations that **a human must review**.
It is not an autonomous exploitation agent and it never decides that something is a vulnerability.

**Status: pre-alpha, milestones M0 and M1 only.** Nothing collects data yet. What exists is the contract
(`docs/`), the decisions awaiting review (`DECISIONS.md`), and the scope, storage, audit and state-machine
foundations. It is **offline-only**: it opens no network connection, and live mode is deliberately not built.

## What it does

You give it a **scope**: a file naming exactly which hosts (and, for AI systems, which endpoints) you may look at, which
kinds of look are allowed, how many requests it may spend, and when the permission ends. It then collects **evidence** about
those targets and keeps it in a form you can defend afterwards:

1. **Checks the scope first.** Wildcards, IP addresses, redirects, expired dates and ambiguous names are refused, never
   guessed at. The scope's hash is recorded, and a scope edited after approval is refused.
2. **Collects only what the scope allows**, and nothing that a target tells it to: DNS records, the TLS certificate's facts,
   HTTP headers and a few well-known files (`security.txt`, `robots.txt`, an OpenAPI document), for an **API** the endpoints
   the scope lists (read-only, as each test user, recording the shape of the answers and never the values), and, for an AI
   system, its model list and a few fixed, benign probes. A redirect or a CNAME to somewhere else is written down and **not** followed.
3. **Redacts and stores it safely.** Cookies, keys and tokens are replaced before anything is written; every artifact is named by its
   hash; the files are private; evidence expires after 30 days unless you say otherwise.
4. **Logs everything tamper-evidently.** Every step, and every refused attempt, is a hash-chained audit entry.
5. **Drafts findings, and stops.** It names the kind of flaw, the evidence behind it, the conditions under which it matters, whether
   the evidence supports a way in (an assessment, never a confirmation) and the read-only steps a person can run to check it
   (`docs/finding-assessment.md`). It never writes an exploit. A draft is never a finding: only a human reviewer can validate one, and an AI model (optional,
   off by default) has no way to choose targets, run tools or mark anything verified.

It is for the *evidence* part of an assessment: what was observed, how, when, and what is still unverified. It is not a scanner,
not an exploit tool and not an autonomous agent.

**Where it is today.** Only the foundations exist (scope checking, the database, the audit trail, the state machines). It does
not collect anything yet: the offline collectors are the next milestone, and live remote collection is an approved design
(`docs/remote-live-design.md`) that is built last, after the offline collectors, and reviewed again before use.

## Install and try it

Python 3.13. It is not on PyPI yet; install from GitHub:

```bash
uv tool install git+https://github.com/MDPorsch/scoped-evidence-agent     # or: pipx install git+https://github.com/MDPorsch/scoped-evidence-agent
scoped-agent --version
```

What works today, none of it touching a network:

```bash
scoped-agent scope init scope.yaml        # write a valid starter scope on a reserved .invalid host, then edit it
scoped-agent scope validate scope.yaml    # parse it, show its hash and the operations it would plan
scoped-agent db upgrade                   # create the local evidence database (private files, ~/.local/share/scopedagent)
scoped-agent runs list                    # list recorded runs
scoped-agent audit verify RUN_ID          # recompute a run's tamper-evident audit chain
```

`scope validate` is the useful one today: it refuses wildcards, IP addresses, expired dates, redirects and ambiguous names with a
stable error code. **It cannot collect anything yet**: the offline collectors are the next milestone, so there are no runs to list
until then. The commands and exit codes are in `docs/cli.md`.

## Contributing

See `CONTRIBUTING.md`. Security problems: `SECURITY.md`. Please read `DECISIONS.md` first: it records what the project has decided
(and what it will never do), and a change that contradicts it needs a new decision.

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
