# Command line contract

`scoped-agent` is a local, single-user tool (D-E07). Every command takes `--data-dir PATH` (default
`~/.local/share/scopedagent`). Messages never print secret values; errors carry a stable code.

## Commands

| Command | Does | Security rule |
|---|---|---|
| `db upgrade` | Creates or migrates the database. The **only** command that changes the schema. When it has to change a database that already holds a schema, it first copies the file aside (`evidence.sqlite.before-<revision>`, mode `0600`, never replacing an older copy) and says where. | Never runs implicitly (D-E10). |
| `--version` | Prints the version and exits. | |
| `scope init FILE [--force]` | Writes a valid offline starter scope on a reserved `.invalid` host, expiring in 30 days, with comments on what to edit. Never follows a link, never replaces a file without `--force`, never creates directories. | Contacts nothing; the starter is parsed before it is written. |
| `scope validate FILE` | Parses, normalises and prints the scope, its hash and the planned operation count. | Exit `1` on any refusal; nothing is stored. |
| `run --scope FILE --fixture PACK [--live]` | Offline run: validate the scope, record the engagement, collect from the fixture pack (one YAML file), store redacted evidence, apply the rule catalogue and store drafts, and print the coverage and how many drafts await review. | No socket; deterministic, one operation at a time in plan order. `--live` is refused in 0.x. |
| `runs list [--limit N --offset M]` | Local run history. | Bounded pagination (limit at most 100). |
| `observations show RUN [--limit N --offset M --json]` | The redacted observations of one run in collection order: a table, or with `--json` each stored payload as one line. | Bounded pagination (limit at most 100); stored data is already redacted, so nothing here can print a raw secret. |
| `findings list RUN` | The drafts of one run, each labelled as a draft. (Replaces the contract's `findings draft RUN`: `run` already drafts, D-E65.) | Read-only. |
| `findings show ID` | One draft in full: class, CWE suggestions, conditions, quoted target data, exploitability assessment, validation steps with both branches, decision guide, remediation and reviews. `ID` is a full id or its first eight characters or more. | Read-only; nothing a target said appears except quoted data of a strict shape. |
| `findings review ID --decision confirmed\|not_exploitable\|inconclusive --reviewer NAME --reason TEXT` | Record a person's decision. | You type the first eight characters of the finding id to confirm; there is no flag that skips it. Refuses a worker or a model, a blank reason or reviewer, and a finding that is not waiting for review. Redacts the reason, audits the decision. |
| `report export RUN --format json\|md --output PATH` | One local report file built from the database. | A new file only: refused if it exists, if the directory does not exist, if a part of the path is a symbolic link or `..`, or if it is inside the data directory. Mode `0600`. Drafts labelled, no artifact content, no export time. Prints the file's sha256. |
| `ai status` | Whether the optional model is on, the provider, the model, whether the key variable is set (never its value), the limits and what is sent. | Read-only. Off by default. |
| `ai enable [--provider anthropic\|offline] [--model NAME] [--key-env VAR] [--no-mask-hosts] [--yes]` | Turn the model on: shows what is sent, asks you to type `enable`, writes `<data-dir>/ai.json` (mode `0600`, no secret in it). `--provider offline` needs no question and no key. | A typed confirmation unless `--yes`; the key is read from an environment variable and is never stored; a broken or unsafe `ai.json` is refused, never replaced. |
| `ai disable` | Turn it off. The file and every saved wording stay. | |
| `ai test` | One fixed sample sentence through the configured model, to check the key, the model and the checks. Nothing is stored. | Prints the status and a sanitized detail on failure; never a key or a reply that failed. |
| `findings reword RUN [--finding ID]` | Ask the model to reword the sentences of a run's drafts that have no wording yet. The rule's text stays and is shown first; a wording is stored beside it, labelled as not verified. | The only command that calls a model besides `ai test`. Needs AI on and its key; a budget per run; every answer is checked item by item (`docs/ai-adapter.md`). |
| `approvals grant --scope FILE --until TIME` | Record that live runs of exactly this scope are allowed until a UTC time (`2026-12-01T00:00:00Z`). You type the first eight characters of the scope hash to confirm. | Bound to the scope hash (editing the scope invalidates it); the end may not pass the scope's expiry or the authorization's `not_after`; append-only; audited. |
| `approvals list` / `approvals revoke ID --reason TEXT` | Every approval and whether it is valid, expired or revoked / end one. | A revoked approval is kept and never valid again. |
| `live run --scope FILE --approval-id ID --image REF --ack-authorization [--credential NAME=ENVVAR]...` | Collect from the declared hosts inside an isolated container that proves its isolation first. **The only command that can leave this machine** (besides `ai test` and `findings reword` with a model on). | Needs a live scope, a window that is open, `--ack-authorization` on every run, a valid approval for this exact scope, an image pinned by digest, and every credential promised. `run` never does any of this (D-E37). |
| `artifacts purge --before DATE` | Retention cleanup. | Only recorded sha256 files under the artifact root; symlinks refused; writes a receipt. |
| `audit verify RUN` | Recomputes the audit hash chain of one run. | Read-only; exit `1` on a broken chain. |

M6 adds live remote collection: `approvals` and `live run` (`docs/remote-live-design.md`); `run` refuses a live scope and `run --live` is refused.
M5 adds API-target scopes: `scope validate` and `run` handle `api_targets` (`docs/api-targets.md`), and `db upgrade` moves a database to revision `0004`.

M1 delivers `--version`, `db upgrade`, `scope init`, `scope validate`, `runs list` and `audit verify`. M2 adds `run` and
`observations show`. M3 adds drafting inside `run`, `findings list|show|review` and `report export`. M4 adds the optional model:
`ai status|enable|disable|test` and `findings reword`. `run` never calls a model, with it on or off; when it is on and there are drafts, `run`
ends with one line saying so.

## Exit codes (D-E09)

| Code | Meaning |
|---|---|
| `0` | The collection was complete and no draft was made. That is not proof that nothing is wrong: only what the scope lists was collected, and only the rules in `docs/correlator.md` were applied. |
| `1` | Validation or policy failure: bad scope, expired scope, refused mode, changed scope file, broken audit chain; for live mode a refused gate (`LIVE-002`: authorization, acknowledgement, approval, window or credential) or an image that is not pinned (`LIVE-001`). |
| `2` | The run could not do its job (live mode: no container runtime `LIVE-001`, a failed isolation proof `LIVE-003`, a sandbox output that was refused `LIVE-004`): infrastructure failure, or any operation that errored, timed out, was refused or ran out of budget, so the collection is **incomplete**. |
| `3` | The collection was complete and there are drafts that need human review (`findings list RUN`). |

Incomplete is never `0`. The report states the coverage: planned operations, completed, errored, refused.

`findings reword` exits `0` when every call succeeded (even if some sentences were kept as the rule wrote them), `2` when any call was
unavailable, refused, invalid or over budget, and `1` for a policy failure (AI off, key not set, no such run, a broken `ai.json`).
`ai test` exits `1` when the answer is refused, unavailable, invalid or fails a check.

## Example (M1)

```text
$ scoped-agent scope validate fixtures/approved_scope/lab-healthy.yaml
engagement: lab-healthy-001   mode: offline   expires: 2026-12-31T23:59:00Z
scope sha256: 3f9c...e1
targets: 1   planned operations: 5 (dns 1, tls 1, http 3)   max_requests: 12
note: the scope file is a restriction, not proof of authorization. Confirm authorization outside this tool.
$ echo $?
0

$ scoped-agent scope validate bad.yaml
error SCOPE-005: allowed_targets[0].host: a wildcard is not allowed
$ echo $?
1
```

## Example (M2)

Real output from the shipped fixtures (ids and hashes differ on every run of your own):

```text
$ scoped-agent run --scope fixtures/approved_scope/lab-misconfigured.yaml --fixture fixtures/web_responses/misconfigured.yaml
run ef90e2875ca04a8080ee1a34b8a0d589   state: DRAFTED
scope sha256: 9de5beb7651f062e64cd09bff2abf44aaaa797f8f5b52a7e27c9d7ae6c7157a1
planned operations: 6   observations recorded: 6   artifacts stored: 3   redactions: 2
coverage: complete
note: correlation and findings are not built yet: this run collected evidence only, and exit code 0 means the collection was complete, not that nothing is wrong.
note: the scope file is a restriction, not proof of authorization. This tool cannot verify that anyone authorized the test: confirm authorization outside it.
$ echo $?
0

$ scoped-agent observations show ef90e2875ca04a8080ee1a34b8a0d589 --limit 3
  #  type            status            subject
  1  dns_metadata    ok                bad.example.invalid
  2  tls_metadata    ok                bad.example.invalid:443
  3  http_metadata   ok                https://bad.example.invalid:443/

$ scoped-agent run --scope fixtures/approved_scope/lab-healthy.yaml --fixture only-dns.yaml
run e4b2eb1d4e744d9cb4431ce7482367a4   state: DRAFTED
scope sha256: f3ca4567e594147e8b4d4ecfb9e123d13a1182e4c74074807c257b8fc148604d
planned operations: 5   observations recorded: 5   artifacts stored: 0   redactions: 0
coverage: incomplete (adapter_error: 4)
...
$ echo $?
2
```

The second run's pack answers only DNS, so the other four operations are recorded as `adapter_error` and the run is incomplete (exit `2`),
never a quiet success. `state: DRAFTED` is the end of the pipeline today; nothing is drafted until M3.

## Example (M3): drafts, a review and a report

Real output from the shipped fixtures (ids, hashes and times differ on every run of your own):

```text
$ scoped-agent run --scope fixtures/approved_scope/lab-misconfigured.yaml --fixture fixtures/web_responses/misconfigured.yaml
run a0d2557b700a46e2bcb45c579c38e7d1   state: DRAFTED
scope sha256: 9de5beb7651f062e64cd09bff2abf44aaaa797f8f5b52a7e27c9d7ae6c7157a1
planned operations: 6   observations recorded: 6   artifacts stored: 3   redactions: 2
coverage: complete
findings drafted: 8 (awaiting review)
note: a draft is not a finding: a person must review each one (findings list RUN, findings show ID, findings review ID).
note: no draft is not proof that nothing is wrong: only what the scope lists was collected, and only the rules in docs/correlator.md were applied.
note: the scope file is a restriction, not proof of authorization. This tool cannot verify that anyone authorized the test: confirm authorization outside it.
$ echo $?
3

$ scoped-agent findings list a0d2557b700a46e2bcb45c579c38e7d1
id        status                 class                                confidence  title
b7ae063f  DRAFT: not validated   tls_misconfiguration                       0.90  TLS configuration weaknesses on bad.example.invalid:443
99bd32bc  DRAFT: not validated   missing_security_header                    0.70  Missing security headers on bad.example.invalid:443
0dd186e4  DRAFT: not validated   information_disclosure                     0.80  Software version disclosed by bad.example.invalid:443
...

$ scoped-agent findings show b7ae063f
DRAFT: not validated
title: TLS configuration weaknesses on bad.example.invalid:443
...
conditions:
  - The service negotiated TLSv1.0, a protocol version that is deprecated.
  - The certificate expired on 2026-01-01T00:00:00Z, before this observation was collected.
  ...
exploitability: conditional (an assessment, not a confirmation)
...
validation steps (read-only, run by a person):
  2. inspect_certificate_field
     command: openssl s_client -connect bad.example.invalid:443 -servername bad.example.invalid -verify_return_error
     if the condition holds: The client reports what the condition says, or the certificate fields show it.
     if it does not: The certificate verifies and its fields differ from the condition. ...
     must not: send credentials, disable certificate verification, send application data, repeat more than once
...

$ scoped-agent findings review b7ae063f --decision confirmed --reviewer alice --reason "ran the steps; the client reported an expired certificate"
Type the first 8 characters of the finding id (b7ae063f) to confirm: b7ae063f
finding b7ae063f: confirmed -> VALIDATED (reviewer alice)

$ scoped-agent report export a0d2557b700a46e2bcb45c579c38e7d1 --format md --output report.md
wrote report.md (31814 bytes)
sha256: d924733d7540983f67f1c5d7f57d2bbf2805cdd13b6ecb83c65dcd6518c69824
$ scoped-agent report export a0d2557b700a46e2bcb45c579c38e7d1 --format md --output report.md
error REPORT-001: the output file already exists: nothing was written
$ echo $?
1
```

`confirmed` validates the finding, `not_exploitable` closes it as a false positive (the review keeps the exact decision) and
`inconclusive` records the review and leaves it open. The first review of a run moves the run to `HUMAN_REVIEW`. A run is never
moved to `EXPORTED` in 0.x, so an export can be repeated, and exporting does not change the run or its audit trail.

