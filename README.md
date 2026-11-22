# scoped-evidence-agent

A **local-first** command-line tool for the *evidence* part of a security assessment. You tell it exactly what it may look at; it
collects a small, bounded set of facts about those targets, redacts and stores them so they can be defended afterwards, drafts
observations from them with reviewed rules, and **stops for a person to decide**. It never exploits anything, never writes an exploit,
and never decides on its own that something is a vulnerability.

> **Status: pre-alpha, not on PyPI.** Everything below works on recorded answers (fixture packs) without touching a network.
> Collecting from real hosts (`live run`) is built and has been run once end to end, against its author's own site, with the container's
> isolation proof passing. That is one run on one host: it must not be pointed at anything you do not own. See
> [what is and is not proved](#what-is-and-is-not-proved).

## What it does, in order

```text
 scope file ──► checked & hashed ──► collect ──► redact ──► store ──► draft ──► human review ──► report
 (what you may   (refused, never     (only what   (before    (hash-    (rules,   (a person        (drafts
  look at)        guessed at)         it lists)    storage)   named,    never a   decides)         labelled,
                                                              audited)  model)                     no secrets)
```

1. **A scope comes first.** A YAML file names the hosts (and, for APIs and AI systems, the endpoints) you may look at, which kinds of look
   are allowed, how many requests it may spend and when the permission ends. Wildcards, IP addresses, redirects, expired dates and
   ambiguous names are refused with a stable error code, never guessed at. The scope's hash is recorded, and a scope edited afterwards is refused.
2. **It collects only what the scope allows,** and nothing a target tells it to:
   * **web hosts:** DNS records, the TLS certificate's facts, HTTP headers and a few well-known files (`security.txt`, `robots.txt`, an OpenAPI document);
   * **APIs** (`api_targets`): the read-only endpoints the scope lists, once per test user, recording the *shape* of each answer and never a value;
   * **AI systems:** the model list and a few fixed, benign probes.

   A redirect or a CNAME that leads elsewhere is written down and **not** followed.
3. **It redacts before it stores.** Cookies, keys and tokens are replaced before anything is written. Every artifact is named by its hash,
   files are private (`0600`), and evidence expires after 30 days unless you say otherwise.
4. **It logs everything tamper-evidently.** Each step, and each refused attempt, is an entry in a hash-chained audit trail (`audit verify` recomputes it).
5. **It drafts, and stops.** Twelve reviewed rules (TLS, security headers, version disclosure, sensitive `robots.txt` paths, insecure
   redirects, exposed API descriptions, permissive CORS, external DNS aliases and four AI-system cases) turn observations into **drafts**.
   A draft names the flaw class, the evidence behind it, the conditions under which it matters, an exploitability *assessment* (never a
   confirmation) and **read-only steps a person can run to check it**. Only a human reviewer can validate a draft.
6. **It names the OWASP category beside each rule** (Top 10 2025, API Security Top 10 2023, LLM Top 10 2026), as the closest match and never a
   verdict, and `benchmarks status` shows which categories have **no** rule yet and how recently the lists were checked (`docs/benchmarks.md`).
7. **It reports its coverage honestly.** A timeout, a DNS failure or a refused operation is an error, never "clean": an incomplete
   collection never exits `0`.

## A run, for real

Output from the shipped fixtures (a deliberately misconfigured lab host on a reserved `.invalid` name; ids differ on every run):

```text
$ scoped-agent run --scope fixtures/approved_scope/lab-misconfigured.yaml --fixture fixtures/web_responses/misconfigured.yaml
run e08c5152b28d47bd999f882dc0244737   state: DRAFTED
scope sha256: 9de5beb7651f062e64cd09bff2abf44aaaa797f8f5b52a7e27c9d7ae6c7157a1
planned operations: 6   observations recorded: 6   artifacts stored: 3   redactions: 2
coverage: complete
findings drafted: 8 (awaiting review)
note: a draft is not a finding: a person must review each one (findings list RUN, findings show ID, findings review ID).
note: no draft is not proof that nothing is wrong: only what the scope lists was collected, and only the rules in docs/correlator.md were applied.
note: the scope file is a restriction, not proof of authorization. This tool cannot verify that anyone authorized the test: confirm authorization outside it.
$ echo $?
3

$ scoped-agent findings list e08c5152b28d47bd999f882dc0244737
id        status                 class                                confidence  title
12ba45d8  DRAFT: not validated   tls_misconfiguration                       0.90  TLS configuration weaknesses on bad.example.invalid:443
f48fbb58  DRAFT: not validated   missing_security_header                    0.70  Missing security headers on bad.example.invalid:443
aa1a111a  DRAFT: not validated   information_disclosure                     0.80  Software version disclosed by bad.example.invalid:443
...

$ scoped-agent findings show 12ba45d8
conditions:
  - The service negotiated TLSv1.0, a protocol version that is deprecated.
  - The certificate expired on 2026-01-01T00:00:00Z, before this observation was collected.
  ...
exploitability: conditional (an assessment, not a confirmation)
validation steps (read-only, run by a person):
  1. read_recorded_observation ...
     if the condition holds: The recorded values match the condition.
     if it does not: ... treat the draft as not supported.
     must not: contact the target, change anything
```

Exit codes: `0` complete and nothing drafted (not proof that nothing is wrong), `1` a refusal (bad or expired scope, broken audit chain, a
refused live gate), `2` the collection is incomplete or could not run, `3` complete and drafts await review.

Then a person decides, typing the finding's id back to confirm, and exports a report (a new file only, drafts labelled, no artifact content):

```bash
scoped-agent findings review 12ba45d8 --decision confirmed --reviewer NAME --reason "ran the steps; the client reported an expired certificate"
scoped-agent report export RUN_ID --format md --output report.md
```

## Install and try it

Python 3.13. Clone it (the fixtures live in the repository, not in an installed package):

```bash
git clone https://github.com/MDPorsch/scoped-evidence-agent && cd scoped-evidence-agent && uv sync
uv run scoped-agent db upgrade                    # create the local evidence database (private files, ~/.local/share/scopedagent)
uv run scoped-agent scope init scope.yaml         # a valid starter scope on a reserved .invalid host; then edit it
uv run scoped-agent scope validate scope.yaml     # parse it, show its hash and the operations it would plan
uv run scoped-agent run --scope fixtures/approved_scope/lab-misconfigured.yaml --fixture fixtures/web_responses/misconfigured.yaml
uv run scoped-agent runs list                     # RUN_ID is printed by the run; this shows it again
uv run scoped-agent observations show RUN_ID      # the redacted observations of one run
uv run scoped-agent findings list RUN_ID          # the misconfigured lab host gives eight drafts
uv run scoped-agent audit verify RUN_ID           # recompute the run's tamper-evident audit chain
```

The commands, with exit codes and a worked example of each, are in `docs/cli.md`; the scope contract in `docs/scope-format.md`; the pack
format and what is redacted in `docs/fixture-format.md`. `run` never opens a socket.

## Three targets, one pipeline

| Target | Scope key | What is recorded | Where to read more |
|---|---|---|---|
| Web host | `allowed_targets` | DNS, TLS facts, headers, well-known files | `docs/scope-format.md` |
| API | `api_targets` | for each test user, GET/HEAD/OPTIONS facts: status, headers, the *shape* of the body, never a value | `docs/api-targets.md` |
| AI system | `ai_targets` | model list, fixed benign probes, flags such as "the canary was repeated" | `docs/ai-targets.md` |

Evidence from an API is recorded as facts; no rule drafts from it yet. A new scope kind changes the database schema: `db upgrade` copies
your database file aside before it migrates.

## Optional: AI wording (off by default)

A rule writes every sentence of a draft. If you want them reworded to read more plainly, you can switch on a model that does **only that**:

```bash
uv sync --extra ai                            # or: uv tool install "scoped-evidence-agent[ai] @ git+https://github.com/MDPorsch/scoped-evidence-agent"
export ANTHROPIC_API_KEY=...                  # the key stays in your environment: it is never stored or printed
scoped-agent ai enable                        # shows what is sent, asks you to type "enable"
scoped-agent findings reword RUN_ID           # the rule's text stays first; the wording is labelled as not verified
scoped-agent ai disable                       # off again; saved wordings stay
```

Only a draft's rule sentences are sent (host names become placeholders), never anything a target said. Every answer is checked by code:
a sentence that changes a number, a name or a host, or adds a verdict word, is dropped. The model has no tools, cannot choose targets and
cannot mark anything verified. `run` never calls a model. To try the path with no key: `scoped-agent ai enable --provider offline`.

## Live remote collection (built; run once, against the author's own site)

`live run` is the only command that can send anything to a network you do not control, and it refuses to start unless **all** of these hold:

* the scope says `mode: live` and carries an `authorization` block (an engagement reference and a time window; a declaration, which the tool cannot verify);
* you grant an **approval** bound to that exact scope's hash (`approvals grant`, with a typed confirmation) and pass `--ack-authorization` on every run;
* each host is resolved once and judged address by address: link-local and cloud-metadata addresses are never contacted, and private and loopback ranges only if the scope lists them;
* collection runs **inside a container** that installs a default-deny firewall allowing only the pinned address and port, proves that with a
  self-test and drops its privileges, and only then is sent the job. The controller checks the proof before it sends anything.

```bash
scoped-agent approvals grant --scope live.yaml --until 2026-12-01T00:00:00Z
docker build -f docker/collector/Dockerfile -t scopedagent-collector:local .
scoped-agent live run --scope live.yaml --approval-id ID --image sha256:IMAGE_ID --ack-authorization
```

Collection is serial and rate limited, TLS is verified before anything is sent, a credential (`--credential NAME=ENVVAR`, https only) is
read from an environment variable and checked against every stored byte. What comes back goes through the same redaction, storage, rules and
review as an offline run. Design and threat model: `docs/remote-live-design.md`.

## What is and is not proved

* **Proved by tests:** the scope checks, redaction, the audit chain, the state machines, the rules, the review gates, the AI-wording checks and
  the live gates (over 3,000 tests with 100% line and branch coverage, and a mutation suite of about 1,500 deliberately broken variants).
* **Run for real:** the container's firewall and isolation proof (positive and negative controls) in CI on a Linux runner and on a Mac with
  Colima, and one `live run` end to end against the author's own site (DNS, TLS and three GETs), whose proof passed.
* **Not proved:** a second host, a login, an API or AI target, IPv6, other container runtimes (Docker Desktop, Podman, rootless). Nothing here
  proves anyone authorized anything: the scope file is a restriction, not proof of authorization, and the tool says so in every output.
* **Where it is going:** active vulnerability checks, API testing and live AI probes are planned in stages, each reviewed before it is
  merged (`docs/active-testing-roadmap.md`). Until a stage is merged the tool sends only read-only requests.
* **What it will not do:** write or run an exploit, a payload or an attack chain; discover hosts or walk ranges; follow what a target tells it
  to do; decide that something is a vulnerability. No draft is not proof that nothing is wrong: twelve rules cover only some flaws (`LIMITATIONS.md`).

## Why it is shaped this way

* **What was observed, how, what is inferred and what is unverified** are kept apart in every record.
* **Target content is hostile.** Prompt injection, secrets in headers and oversized bodies are primary threats; the optional model is never shown a target's words.
* **Evidence is redacted before it is stored,** content-addressed, private on disk, short-lived by default and recorded in an append-only, hash-chained audit trail.

## Read first

| | |
|---|---|
| `docs/threat-model.md` | what can go wrong and which control and test answers each threat |
| `docs/scope-format.md` | the scope file contract and the canonical host rules |
| `docs/data-flow.md` | what is stored, redacted, retained and sent |
| `docs/cli.md` | the commands and the exit codes |
| `docs/correlator.md` | the twelve rules and how a draft is made |
| `docs/benchmarks.md` | the OWASP editions the rules are mapped to, and how that is kept current |
| `docs/active-testing-roadmap.md` | the plan to add active checks, API testing and live AI probes, and the decisions behind it |
| `docs/api-targets.md`, `docs/ai-targets.md` | the API and AI-system scopes |
| `docs/ai-adapter.md` | the optional model: what it may do, what it is sent, how its answer is checked |
| `docs/remote-live-design.md` | live collection: the controls, the container and what is not yet proved |
| `docs/test-matrix.md` | the abuse cases and what covers each |
| `LIMITATIONS.md` | what this does not do |

## Contributing and development

See `CONTRIBUTING.md`; security problems: `SECURITY.md`. References such as D-E59 name a design rule; the document that applies it states the rule in full.

```bash
uv sync
uv run pytest -q
uv run ruff check . && uv run ruff format --check . && uv run mypy
```

Apache-2.0. Use it only on systems you own or are authorized to assess.
