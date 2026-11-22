# scoped-evidence-agent

An auditable, **local-first** assistant that collects bounded reconnaissance evidence from explicitly scoped
targets, keeps that evidence tamper-evident and redacted, and drafts observations that **a human must review**.
It is not an autonomous exploitation agent and it never decides that something is a vulnerability.

**Status: pre-alpha, milestones M0 to M5.** It collects and stores redacted evidence from **fixture packs** (recorded answers in a
YAML file), drafts findings from it with reviewed rules, lets a person review them, and exports a report. It is **offline-only**: `run`
opens no network connection, and live mode is deliberately not built. The one optional exception is an AI wording step that is **off by
default** (below). The contract is in `docs/`; each document states the rules it applies.

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
5. **Drafts findings, and stops.** (Built: twelve rules, `docs/correlator.md`.) It names the kind of flaw, the evidence behind it, the conditions under which it matters, whether
   the evidence supports a way in (an assessment, never a confirmation) and the read-only steps a person can run to check it
   (`docs/finding-assessment.md`). It never writes an exploit. A draft is never a finding: only a human reviewer can validate one, and an AI model (optional,
   off by default) has no way to choose targets, run tools or mark anything verified.

It is for the *evidence* part of an assessment: what was observed, how, when, and what is still unverified. It is not a scanner,
not an exploit tool and not an autonomous agent.

**Where it is today.** Scope checking, the database, the audit trail and the state machines exist, and so do the offline collectors,
the rule catalogue, review and reports. DNS, TLS, HTTP and AI-reply evidence is read from a fixture pack, redacted and stored; rules
draft findings from it (each a draft, with a class, conditions, an assessment and read-only validation steps); a person reviews each
draft; a report can be exported. A scope can also name APIs (`api_targets`): each principal's answer is recorded as facts (the shape of a body, never a value; `docs/api-targets.md`). An optional, off-by-default model may reword a draft's sentences (`docs/ai-adapter.md`). Every run reports its coverage (an operation that errored or had no answer makes it exit `2`), and a
complete collection with drafts exits `3`. No draft is not proof that nothing is wrong: twelve rules cover only some flaws
(`LIMITATIONS.md`). Live remote collection is an approved design (`docs/remote-live-design.md`) that is built last and reviewed
again before use.

## Install and try it

Python 3.13. It is not on PyPI yet; install from GitHub:

```bash
uv tool install git+https://github.com/MDPorsch/scoped-evidence-agent     # or: pipx install git+https://github.com/MDPorsch/scoped-evidence-agent
scoped-agent --version
```

The commands below touch no network:

```bash
scoped-agent scope init scope.yaml        # write a valid starter scope on a reserved .invalid host, then edit it
scoped-agent scope validate scope.yaml    # parse it, show its hash and the operations it would plan
scoped-agent db upgrade                   # create the local evidence database (private files, ~/.local/share/scopedagent)
scoped-agent run --scope scope.yaml --fixture pack.yaml   # collect from a fixture pack; prints the coverage
scoped-agent runs list                    # list recorded runs
scoped-agent findings list RUN_ID         # the drafts of a run, each labelled a draft
scoped-agent findings show ID             # one draft in full: conditions, assessment, validation steps
scoped-agent findings review ID --decision confirmed --reviewer NAME --reason TEXT   # a person decides (you type the id back)
scoped-agent report export RUN_ID --format md --output report.md   # a new file only, no artifact content
scoped-agent observations show RUN_ID     # the redacted observations of one run
scoped-agent audit verify RUN_ID          # recompute a run's tamper-evident audit chain
```

The fixtures are not part of the installed package. To see a run, use a clone, which holds scopes and packs for a healthy, a
misconfigured and a poisoned lab host and for an AI support bot (all on reserved `.invalid` names, with synthetic secrets):

```bash
git clone https://github.com/MDPorsch/scoped-evidence-agent && cd scoped-evidence-agent && uv sync
uv run scoped-agent db upgrade
uv run scoped-agent run --scope fixtures/approved_scope/lab-misconfigured.yaml --fixture fixtures/web_responses/misconfigured.yaml
uv run scoped-agent observations show RUN_ID      # RUN_ID is printed by the run; `runs list` shows it again
uv run scoped-agent findings list RUN_ID          # the misconfigured lab host gives eight drafts
uv run scoped-agent findings show ID              # ID is the first eight characters from the list
```

`scope validate` refuses wildcards, IP addresses, expired dates, redirects and ambiguous names with a stable error code. The
commands, a real example and the exit codes are in `docs/cli.md`; the pack format and what is redacted are in `docs/fixture-format.md`.

## Optional: AI wording (off by default)

A rule writes every sentence of a draft. If you want them reworded to read more plainly, you can switch on a model that does **only that**:

```bash
uv tool install "scoped-evidence-agent[ai] @ git+https://github.com/MDPorsch/scoped-evidence-agent"   # adds the Anthropic SDK
export ANTHROPIC_API_KEY=...                  # the key stays in your environment: it is never stored or printed
scoped-agent ai enable                        # shows what is sent, asks you to type "enable"
scoped-agent ai test                          # one small request to check the key and the model
scoped-agent findings reword RUN_ID           # then: findings show ID, or a report, shows the wording under the rule's text
scoped-agent ai disable                       # off again; saved wordings stay
```

Only a draft's rule sentences are sent (host names are replaced by placeholders), never anything a target said. Every answer is checked
by code, a sentence that changes a number, a name or a host or adds a verdict word is dropped, and the rule's own text is always shown
first with the wording labelled as not verified. `run` never calls a model. Try the whole path with no key: `scoped-agent ai enable --provider offline`.

## Contributing

See `CONTRIBUTING.md`. Security problems: `SECURITY.md`. Please read `docs/` and `LIMITATIONS.md` first: they record what the project does
(and what it will never do). References such as D-E59 name a design rule; the document that applies it states the rule in full.

## Why it is shaped this way

* **What was observed, how, what is inferred, and what is unverified** are kept apart. A timeout or a DNS failure
  is an error, never "clean"; an incomplete collection never exits `0`.
* **Scope is a restriction, not proof of authorization.** The tool refuses an expired, ambiguous or wildcard scope
  and never widens it from a redirect, a CNAME or a sentence inside a web page. A human confirms authorization
  outside the tool.
* **Target content is hostile.** Prompt injection, secrets in headers and oversized bodies are primary threats.
  The optional model has no tools, no authority over targets, is never shown a target's words and has no way to mark anything verified.
* **Evidence is redacted before it is stored,** content-addressed, private on disk, short-lived by default, and
  recorded in an append-only, hash-chained audit trail.

## Read first

| | |
|---|---|
| `docs/threat-model.md` | what can go wrong and which control and test answers each threat |
| `docs/scope-format.md` | the scope file contract and the canonical host rules |
| `docs/data-flow.md` | what is stored, redacted, retained and sent |
| `docs/cli.md` | the commands and the exit codes |
| `docs/ai-adapter.md` | the optional model: what it may do, what it is sent, how its answer is checked |
| `docs/fixture-format.md` | fixture packs and the normalised observation schema |
| `docs/test-matrix.md` | the 20 abuse cases and what covers each |
| `LIMITATIONS.md` | what this does not do |

## Develop

```bash
uv sync
uv run pytest -q
uv run ruff check . && uv run ruff format --check . && uv run mypy
```

Python 3.13. Apache-2.0. Use it only on systems you own or are authorized to assess.
