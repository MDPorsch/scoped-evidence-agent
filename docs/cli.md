# Command line contract

`scoped-agent` is a local, single-user tool (D-E07). Every command takes `--data-dir PATH` (default
`~/.local/share/scopedagent`). Messages never print secret values; errors carry a stable code.

## Commands

| Command | Does | Security rule |
|---|---|---|
| `db upgrade` | Creates or migrates the database. The **only** command that changes the schema. | Never runs implicitly (D-E10). |
| `--version` | Prints the version and exits. | |
| `scope init FILE [--force]` | Writes a valid offline starter scope on a reserved `.invalid` host, expiring in 30 days, with comments on what to edit. Never follows a link, never replaces a file without `--force`, never creates directories. | Contacts nothing; the starter is parsed before it is written. |
| `scope validate FILE` | Parses, normalises and prints the scope, its hash and the planned operation count. | Exit `1` on any refusal; nothing is stored. |
| `run --scope FILE --fixture PACK [--live]` | Offline run: validate the scope, record the engagement, collect from the fixture pack (one YAML file), store redacted evidence, and print the coverage. Correlation and drafts arrive in M3. | No socket; deterministic, one operation at a time in plan order. `--live` is refused in 0.x. |
| `runs list [--limit N --offset M]` | Local run history. | Bounded pagination (limit at most 100). |
| `observations show RUN [--limit N --offset M --json]` | The redacted observations of one run in collection order: a table, or with `--json` each stored payload as one line. | Bounded pagination (limit at most 100); stored data is already redacted, so nothing here can print a raw secret. |
| `findings draft RUN` | Evidence-linked drafts with confidence, assumptions and unknowns. | A draft is labelled a draft. |
| `findings review ID --decision D --reviewer NAME --reason TEXT` | Human review. | Prompts for typed confirmation; refuses non-human actors; audited. |
| `report export RUN --format json\|md --output PATH` | Local report. | Safe-path checks, no overwrite, drafts labelled, hashes included. |
| `artifacts purge --before DATE` | Retention cleanup. | Only recorded sha256 files under the artifact root; symlinks refused; writes a receipt. |
| `audit verify RUN` | Recomputes the audit hash chain of one run. | Read-only; exit `1` on a broken chain. |

M1 delivers `--version`, `db upgrade`, `scope init`, `scope validate`, `runs list` and `audit verify`. M2 adds `run` and
`observations show`. The rest arrive with the milestone that owns their data: drafts and reports (M3), the model (M4).

## Exit codes (D-E09)

| Code | Meaning |
|---|---|
| `0` | The collection was complete and there is nothing for a human to review. Until M3 there is no correlation, so a complete collection is `0` and says so: *no findings drafted is not a finding of no problems*. |
| `1` | Validation or policy failure: bad scope, expired scope, refused mode, changed scope file, broken audit chain. |
| `2` | The run could not do its job: infrastructure failure, or any operation that errored, timed out, was refused or ran out of budget, so the collection is **incomplete**. |
| `3` | The collection was complete and there are drafts that need human review. |

Incomplete is never `0`. The report states the coverage: planned operations, completed, errored, refused.

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
