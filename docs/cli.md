# Command line contract

`scoped-agent` is a local, single-user tool (D-E07). Every command takes `--data-dir PATH` (default
`~/.local/share/scopedagent`). Messages never print secret values; errors carry a stable code.

## Commands

| Command | Does | Security rule |
|---|---|---|
| `db upgrade` | Creates or migrates the database. The **only** command that changes the schema. | Never runs implicitly (D-E10). |
| `scope validate FILE` | Parses, normalises and prints the scope, its hash and the planned operation count. | Exit `1` on any refusal; nothing is stored. |
| `run --scope FILE --fixture DIR` | Offline run: validate, record the engagement, collect from the pack, correlate, draft. | No socket; deterministic. `--live` is refused in 0.x. |
| `runs list [--limit N --offset M]` | Local run history. | Bounded pagination (limit at most 100). |
| `observations show RUN` | Redacted observations of one run. | Never prints a raw secret. |
| `findings draft RUN` | Evidence-linked drafts with confidence, assumptions and unknowns. | A draft is labelled a draft. |
| `findings review ID --decision D --reviewer NAME --reason TEXT` | Human review. | Prompts for typed confirmation; refuses non-human actors; audited. |
| `report export RUN --format json\|md --output PATH` | Local report. | Safe-path checks, no overwrite, drafts labelled, hashes included. |
| `artifacts purge --before DATE` | Retention cleanup. | Only recorded sha256 files under the artifact root; symlinks refused; writes a receipt. |
| `audit verify RUN` | Recomputes the audit hash chain of one run. | Read-only; exit `1` on a broken chain. |

M1 delivers `db upgrade`, `scope validate`, `runs list` and `audit verify`. The rest arrive with the milestone
that owns their data: collection (M2), drafts and reports (M3), the model (M4).

## Exit codes (D-E09)

| Code | Meaning |
|---|---|
| `0` | The collection was complete and there is nothing for a human to review. |
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
