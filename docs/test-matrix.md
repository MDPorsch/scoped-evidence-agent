# Test matrix

The spec's abuse cases AE-01 to AE-20, each with the control, the tests that cover it, and its status.
**Status is updated only after the test exists and has been run.** *Covered* means the behaviour is tested at the layer
this milestone builds. *Partial* names the layer that is still missing, so a case is never claimed beyond what ran.

Paths are under `tests/`. `unit/` and `integration/` are the ordinary suites, `adversarial/` and `property/` the hostile and
generated inputs, `negative/` the "this must be impossible" checks.

| Case | Input / failure | Expected | Covered by | Status |
|---|---|---|---|---|
| AE-01 | Expired scope, missing approval, scope changed after validation | fail before any adapter | `unit/test_authorization.py`, `unit/test_scope_schema.py` (expiry), `integration/test_runs.py` (a run cannot be created from an expired engagement) | **Covered** at the policy and run layer. M2 adds "before the first adapter call" |
| AE-02 | Redirect to localhost or an external host | recorded, never followed | `unit/test_scope_schema.py` (`follow_redirects: true` is refused); fixture `misconfigured` holds the redirect | **Partial**: the schema layer. The adapter that records it is M2 |
| AE-03 | DNS answer is loopback, private, link-local, metadata, IPv6-mapped | live denied | none | **Deferred to M5**: there is no live mode |
| AE-04 | Host with IDN, trailing dot, upper case, userinfo, mixed encoding | canonical or refused | `unit/test_scope_hosts_paths.py`, `adversarial/test_hostile_scope_input.py`, `property/test_properties.py` | **Covered** |
| AE-05 | CNAME to an unapproved domain | recorded, scope never expands | fixture `misconfigured` holds the CNAME | **Planned (M2)** |
| AE-06 | Response contains prompt injection | no change to tools, scope or secrets | fixture `poisoned` and `fixtures/poisoned_text/` | **Planned (M2, M4)** |
| AE-07 | Headers contain cookies or API keys | redacted before storage and before a model | `unit/test_logs.py` (logs only); fixtures hold synthetic secrets | **Planned (M2)**: redaction of observations is M2 |
| AE-08 | Model returns invalid JSON or a hostile schema | rejected, bounded retry or fallback | none | **Planned (M4)** |
| AE-09 | Model asserts a vulnerability with no evidence | kept as draft or marked unsupported | `unit/test_state_machine.py`, `integration/test_observations_findings.py` (the model cannot create a draft or move any state; a draft needs evidence) | **Partial**: authority is covered. Claim validation is M4 |
| AE-10 | Timeout, HTTP error, DNS failure | recorded as an error, run incomplete (exit 2), never clean | `unit/test_errors_and_outcome.py` (coverage, exit codes, a Hypothesis property) | **Partial**: the taxonomy and exit codes. The adapters that raise them are M2 |
| AE-11 | Crash between artifact write and row, or a DB failure | atomic store, no orphan, no dangling row | `integration/test_artifacts.py` (failed rename, failed fsync, database failure after the write) | **Covered** |
| AE-12 | Racing workers share one budget | no overshoot | `integration/test_budget.py` (four threads, 120 attempts, 40 units), `property/test_properties.py` | **Covered**. "Shared" is read as one run's budget across workers |
| AE-13 | 1 MB body, zip bomb, huge header, malformed certificate | hard caps, safe errors | `unit/test_scope_schema.py` (limits), `unit/test_observation_schemas.py` (header, body, record caps), `integration/test_artifacts.py` (size cap) | **Partial**: the caps. Parsing real hostile responses is M2 |
| AE-14 | Export or purge path such as `../../secret` | traversal refused, no overwrite | `integration/test_artifacts.py` (forged path, symlinks, non-digest names) | **Partial**: artifacts and purge. Report export is M3 |
| AE-15 | Cancel mid-run, then retry | no lost audit, new attempt, history kept | `integration/test_runs.py` | **Covered** for the state machine and audit. Resuming collection is M2 |
| AE-16 | A stale observation cited by a newer run | refused by the database | `integration/test_observations_findings.py`, `integration/test_database.py` (composite foreign key) | **Covered** |
| AE-17 | Model provider unavailable | deterministic offline fallback | none | **Planned (M4)** |
| AE-18 | Non-GET, or a query carrying a token | refused | `unit/test_scope_hosts_paths.py`, `unit/test_observation_schemas.py` (method is GET or HEAD, no query in a path) | **Partial**: scope and schema. The adapter is M2 |
| AE-19 | Two aliases for one host | duplicates refused in the scope; correlation dedupes only within scope | `unit/test_scope_schema.py` | **Partial**: scope. Correlation is M3 |
| AE-20 | Content asks to widen the scope | refused and noted | fixture `poisoned` | **Planned (M2, M4)** |

## Additional invariants (not in the spec's list)

| ID | Invariant | Covered by | Status |
|---|---|---|---|
| X-01 | No socket is opened; no network client library is loaded or declared | `conftest.py` (an autouse guard on every test), `negative/test_no_network.py` | **Covered** |
| X-02 | The audit trail cannot be edited or deleted, and a broken chain is detected | `integration/test_database.py` (triggers), `integration/test_audit.py` | **Covered** |
| X-03 | An unredacted artifact cannot be inserted | `integration/test_database.py`, `integration/test_artifacts.py` | **Covered** |
| X-04 | Files and directories have the documented permissions, and a looser store is refused | `integration/test_database.py`, `integration/test_artifacts.py` | **Covered** |
| X-05 | The model can perform no state transition; a worker cannot validate | `unit/test_state_machine.py` (every pair), `integration/*`, `property/test_properties.py` | **Covered** |
| X-06 | The application never migrates on startup and refuses an unknown schema revision | `integration/test_database.py` | **Covered** |
| X-07 | Every golden observation conforms to the payload schemas and round-trips exactly | `unit/test_observation_schemas.py` | **Covered** |
| X-08 | The migration and the models describe the same schema, including CHECK constraints | `integration/test_database.py` | **Covered** |

## AI-system scopes (D-E28 to D-E36)

| ID | Invariant | Covered by | Status |
|---|---|---|---|
| AI-01 | A scope naming the provider layer is refused | `unit/test_scope_ai_targets.py` | **Covered** |
| AI-02 | A rule that is missing, not `forbidden`, or `allowed` is refused (`allowed` as "not available in this version") | same | **Covered** |
| AI-03 | A probe set that is not in the reviewed library is refused; the library cannot change at run time | same, `unit/test_probes.py` | **Covered** |
| AI-04 | A probe set whose category the target does not authorize is refused | `unit/test_scope_ai_targets.py` | **Covered** |
| AI-05 | Planned probes that exceed the request cap, or whose worst-case tokens exceed the total, are refused (both boundaries exact) | same | **Covered** |
| AI-06 | Production needs a reference, and only production may have one | same | **Covered** |
| AI-07 | A reply that contains injection text is recorded as data and never leaves as an instruction | `unit/test_ai_observation_schemas.py` (the fixture and its golden) | **Partial**: the fixture and schema. The collector is M2 and the model boundary M4 |
| AI-08 | Whether a canary appeared is a recorded fact, recomputed independently from the pack | `unit/test_ai_observation_schemas.py` | **Partial**: goldens are consistent; the adapter that produces them is M2 |
| AI-09 | Markup, links, code blocks and URLs in a reply are flagged as structure, never as a verdict, and no verdict field exists | same | **Partial**: schema and fixture; the adapter is M2 |
| AI-10 | A reply that claims a tool was used is text, not an action | fixture only | **Planned (M2, M4)** |
| AI-11 | Two AI targets with the same id or endpoint are refused, not merged | `unit/test_scope_ai_targets.py` | **Covered** |
| AI-12 | Secrets in a reply are redacted before storage | none | **Planned (M2)** |
| AI-13 | An AI observation cannot be filed under a web target and a web observation cannot be filed under an AI target, in the application and in the database | `integration/test_ai_targets_storage.py` | **Covered** |
| AI-14 | A scope without AI targets keeps its hash | `unit/test_scope_schema.py`, `unit/test_scope_ai_targets.py` | **Covered** |

## What this table does not say

A *covered* case has tests; it is not a proof. Mutation testing (`tools/mutation.py`) checks that the tests notice a deliberate
bug in each guarded line, and its result for M1 is in `docs/milestones/M1.md`.
