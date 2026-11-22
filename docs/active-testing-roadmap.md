# From evidence collection to active testing: the plan and the owner's decisions

Until now this tool sent nothing to a target but read-only requests and never sent any input of its own. On 2026-11-22 the owner asked for it
to become more flexible: more live hosts, vulnerability checks, API testing, live AI probe questions, all organised by the OWASP benchmarks
and kept up to date. That changes what the tool sends, so it is built **in stages, each its own pull request with tests and a stop for review.**

## Decisions (approved by the owner on 2026-11-22 unless marked)

| ID | Decision |
|---|---|
| D-E83 | **Probe limits.** Read-only checks (GET, HEAD, OPTIONS) **plus harmless injection probes:** inert marker strings placed only in parameters the scope lists, from a fixed list kept and reviewed in the repository, to see whether an input is reflected or a database error appears. This narrowly relaxes the earlier "no payloads" rule. **Still never, whatever the scope says:** exploitation, chaining attacks, extracting data, brute forcing or guessing logins, flooding or load, requests that change state (POST, PUT, PATCH, DELETE), post-exploitation, discovering hosts, or following redirects. |
| D-E84 | **Stages.** 1: the live host cap and the benchmark catalogue (this change). 2: safe web and API checks, including the marker probes. 3: AI probe questions in live mode. 4: the update process. |
| D-E85 | **AI probe texts are drafted by the assistant and reviewed by the owner, one by one, before any goes live.** They stay fixed and benign (canary markers, not real attacks). |
| D-E86 | **Live mode names at most 20 hosts** (was 10). Done in stage 1. |
| D-E87 | **Benchmarks are kept current by reviewed updates plus a scheduled check** that looks for new OWASP releases and opens a pull request for review. Nothing downloads at run time (`docs/benchmarks.md`). |
| D-E88 | **The catalogue design** (pending your approval): a data file of editions, categories and a mapping per rule; labels derived when shown, never stored in a finding; a report lists the editions used; a mapping is the closest category; gaps are shown, not hidden. |

## The stages

1. **Host cap and OWASP catalogue (built).** `benchmarks status` and `benchmarks rules`, the OWASP category beside every rule in
   `findings show` and in reports, and 20 live hosts. No new request is sent.
2. **Safe web and API checks (next, needs your review of its design first).** Checks that need no change of state: cookie flags, error
   verbosity, default and exposed files from a fixed list, access control on the API endpoints you list by comparing two test users (the
   OWASP API list's top categories), and the marker probes of D-E83. A scope must **opt in** to anything beyond collection, and every check
   will name its OWASP category and its limits.
3. **AI probes in live mode.** The probe questions, covering more of the OWASP LLM list, written for you to read and approve first.
4. **The update process.** The scheduled check for new OWASP releases, and the status command's staleness warning (the warning exists now).

## What stays out of this tool

It will not write or run exploit code, chain attacks, extract data, brute force, flood a server, or discover hosts. It will not decide
that something is a vulnerability: a check produces a draft and a person decides. It cannot prove that anyone authorized the test.
