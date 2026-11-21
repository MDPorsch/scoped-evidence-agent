# Test matrix

The spec's abuse cases AE-01 to AE-20, each with the control, the tests that cover it, and its status.
**Status is updated only after the test exists and has been run.** *Covered* means the behaviour is tested at the layer
this milestone builds. *Partial* names the layer that is still missing, so a case is never claimed beyond what ran.

Paths are under `tests/`. `unit/` and `integration/` are the ordinary suites, `adversarial/` and `property/` the hostile and
generated inputs, `negative/` the "this must be impossible" checks.

| Case | Input / failure | Expected | Covered by | Status |
|---|---|---|---|---|
| AE-01 | Expired scope, missing approval, scope changed after validation | fail before any adapter | `unit/test_authorization.py`, `unit/test_scope_schema.py` (expiry), `integration/test_runs.py`, `integration/test_collection.py` (a live scope, and a scope that expired after it was loaded, are refused before anything is stored) | **Covered** |
| AE-02 | Redirect to localhost or an external host | recorded, never followed | `unit/test_scope_schema.py` (`follow_redirects: true` is refused), `adversarial/test_hostile_responses.py` (the redirect is data and nothing is contacted), the `misconfigured` golden | **Covered** offline. The live check that a followed redirect cannot leave the scope is M5 |
| AE-03 | DNS answer is loopback, private, link-local, metadata, IPv6-mapped | live denied | none | **Deferred to M5**: there is no live mode |
| AE-04 | Host with IDN, trailing dot, upper case, userinfo, mixed encoding | canonical or refused | `unit/test_scope_hosts_paths.py`, `adversarial/test_hostile_scope_input.py`, `property/test_properties.py` | **Covered** |
| AE-05 | CNAME to an unapproved domain | recorded, scope never expands | `adversarial/test_hostile_responses.py` (a CNAME never becomes a target), the `misconfigured` golden | **Covered** |
| AE-06 | Response contains prompt injection | no change to tools, scope or secrets | `adversarial/test_hostile_responses.py` (every payload in `fixtures/poisoned_text/` is kept as data and changes nothing else), `integration/test_collection.py` (the poisoned pack) | **Covered** for collection. The model boundary is M4 |
| AE-07 | Headers contain cookies or API keys | redacted before storage and before a model | `unit/test_redact.py`, `integration/test_collection.py` (a secret in a header, a body and a reply is stored nowhere; the source hash ignores a removed secret), `unit/test_logs.py` | **Covered** for storage. The model boundary is M4 |
| AE-08 | Model returns invalid JSON or a hostile schema | rejected, bounded retry or fallback | `unit/test_ai_validation.py` (a reply that is not exactly the requested shape, too large, with wrong or repeated ids), `unit/test_ai_adapters.py` (wrong shape, no text, cut off), `integration/test_reword.py` (wrong or extra ids change nothing) | **Covered**: the reply is invalid as a whole and the rule's text stands. The SDK's own two retries are the only retry (SE-35) |
| AE-09 | Model asserts a vulnerability with no evidence | keep draft / mark unsupported | `unit/test_state_machine.py`, `integration/test_observations_findings.py` (the model cannot create a draft or move any state; a draft needs evidence), `integration/test_review.py` (a model cannot review), `integration/test_findings_storage.py` (a step may cite only the draft's own evidence) | **Covered** for what exists: a draft is made only by a rule and cites its evidence. A model's wording is checked item by item: `unit/test_ai_validation.py` (a verdict word, a changed number, name or host is refused), `integration/test_reword.py` (an item that fails is dropped and the others are kept) |
| AE-10 | Timeout, HTTP error, DNS failure | recorded as an error, run incomplete (exit 2), never clean | `unit/test_errors_and_outcome.py`, `unit/test_offline_adapters.py` (every odd entry), `integration/test_collection.py` (a missing answer, a declared failure, an exhausted budget, a crashing adapter) | **Covered** |
| AE-11 | Crash between artifact write and row, or a DB failure | atomic store, no orphan, no dangling row | `integration/test_artifacts.py` (failed rename, failed fsync, database failure after the write) | **Covered** |
| AE-12 | Racing workers share one budget | no overshoot | `integration/test_budget.py` (four threads, 120 attempts, 40 units), `property/test_properties.py` | **Covered**. "Shared" is read as one run's budget across workers |
| AE-13 | 1 MB body, zip bomb, huge header, malformed certificate | hard caps, safe errors | `adversarial/test_hostile_responses.py` (over the limit, exactly at it, header caps, compressed and binary bodies, deep nesting, pathological text), `unit/test_observation_schemas.py`, `unit/test_parse.py`, `integration/test_artifacts.py` | **Covered** |
| AE-14 | Export or purge path such as `../../secret` | traversal refused, no overwrite | `integration/test_artifacts.py` (forged path, symlinks, non-digest names), `integration/test_report.py` (`..`, symlinks, an existing file, a race, the data directory, a missing directory, a pipe) | **Covered**: artifacts, purge and report export |
| AE-15 | Cancel mid-run, then retry | no lost audit, new attempt, history kept | `integration/test_runs.py`, `integration/test_collection.py` (cancelling mid-run keeps what was collected and the audit trail; a fresh run completes) | **Covered** |
| AE-16 | A stale observation cited by a newer run | refused by the database | `integration/test_observations_findings.py`, `integration/test_database.py` (composite foreign key) | **Covered** |
| AE-17 | Model provider unavailable | deterministic offline fallback | `unit/test_ai_adapters.py` (API errors, a refusal, a connection failure, a missing key, a missing SDK), `integration/test_reword.py` (a failed call is recorded and the next finding is still tried), `integration/test_ai_cli.py` (exit `2`, the rule's text stands) | **Covered**: every failure keeps the rule's text and is recorded |
| AE-18 | Non-GET, or a query carrying a token | refused | `unit/test_scope_hosts_paths.py`, `unit/test_observation_schemas.py`, `unit/test_pack.py` (a pack key with a query is refused; a key has no way to name another method) | **Covered** offline: the adapter only answers `GET` keys. The live adapter is M5 |
| AE-19 | Two aliases for one host | duplicates refused in the scope; correlation dedupes only within scope | `unit/test_scope_schema.py`, `unit/test_rules.py` (drafts are grouped per target and cite every observation that fired) | **Covered** |
| AE-20 | Content asks to widen the scope | refused and noted | `adversarial/test_hostile_responses.py`, `integration/test_collection.py` (the poisoned pack adds no target and changes nothing but its own observations) | **Covered** for collection. The model boundary is M4 |

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
| AI-07 | A reply that contains injection text is recorded as data and never leaves as an instruction | `unit/test_ai_observation_schemas.py`, `adversarial/test_hostile_responses.py` | **Covered** for collection. The model boundary is M4 |
| AI-08 | Whether a canary appeared is a recorded fact, recomputed independently from the pack | `unit/test_offline_adapters.py`, the goldens | **Covered** |
| AI-09 | Markup, links, code blocks and URLs in a reply are flagged as structure, never as a verdict, and no verdict field exists | `unit/test_parse.py`, `unit/test_ai_observation_schemas.py`, the goldens | **Covered** |
| AI-10 | A reply that claims a tool was used is text, not an action | `integration/test_collection.py` (the AI reply that says to call a tool is stored as text; nothing else changes) | **Partial**: collection. The model boundary is M4 |
| AI-11 | Two AI targets with the same id or endpoint are refused, not merged | `unit/test_scope_ai_targets.py` | **Covered** |
| AI-12 | Secrets in a reply are redacted before storage | `integration/test_collection.py`, `unit/test_offline_adapters.py` | **Covered** |
| AI-13 | An AI observation cannot be filed under a web target and a web observation cannot be filed under an AI target, in the application and in the database | `integration/test_ai_targets_storage.py` | **Covered** |
| AI-14 | A scope without AI targets keeps its hash | `unit/test_scope_schema.py`, `unit/test_scope_ai_targets.py` | **Covered** |

## Validation steps (D-E58, D-E59), built with the correlator in M3 (`docs/correlator.md`)

| ID | Invariant | Status |
|---|---|---|
| VS-01 | A step whose kind is not on the closed list, or whose intrusiveness does not match its kind, is dropped and reported | `unit/test_steps.py`, `unit/test_finding_models.py` | **Covered** |
| VS-02 | A step naming a host, port, path, origin or probe that is not in the scope is dropped (a port 80 step with no port 80 in the scope) | `unit/test_steps.py` (every kind, port 80, scheme, operation not allowed, unlisted path, probe index, an origin no scope can declare yet) | **Covered** |
| VS-03 | No step contains a shell metacharacter, `-k`/`--insecure`, a body flag, a method other than GET, HEAD or OPTIONS, or a credential; checked over every rule's output and by Hypothesis over target-derived strings | `unit/test_steps.py` (a Hypothesis property over arbitrary hosts, paths, record types, methods, origins and field names; the value checks also with the scope check switched off), `adversarial/test_hostile_findings.py` | **Covered** |
| VS-04 | A value that came from a target appears only as quoted data and never in `action` or `example_invocation` (poisoned fixture) | `unit/test_steps.py`, `unit/test_rules.py`, `adversarial/test_hostile_findings.py` (a Hypothesis property over every target-controlled field; the pack that says one phrase everywhere) | **Covered** |
| VS-05 | A draft has at most 8 steps, each at most 400 characters, each citing an observation of its own run, each with both branches | `unit/test_steps.py`, `unit/test_finding_models.py`, `integration/test_findings_pipeline.py` | **Covered** |
| VS-06 | A dropped step is reported in `validation_steps_dropped` with its rule; nothing disappears silently | `unit/test_steps.py`, `integration/test_findings_pipeline.py` (no step of any shipped pack is dropped), `integration/test_report.py` and `integration/test_findings_cli.py` (dropped steps are shown) | **Covered** |
| VS-07 | The tool never runs a validation step in offline mode (no socket opens: the global guard) | `conftest.py` (the guard on every test), `negative/test_no_network.py`; a step is text, and no code path executes one | **Covered** |
| VS-08 | Mutation check over the rule catalogue and the step checker | `tools/mutation.py` (the `steps_*`, `rules_*` and `findings_*` mutants) | **Covered** |

## What this table does not say

A *covered* case has tests; it is not a proof. Mutation testing (`tools/mutation.py`) checks that the tests notice a deliberate
bug in each guarded line, and its result for M1 is in `docs/milestones/M1.md`.

## Findings, review and reports (M3; D-E56 to D-E65)

| ID | Invariant | Covered by | Status |
|---|---|---|---|
| FN-01 | A draft's class, assessment, severity suggestion and step kinds come from closed vocabularies; the assessment has no `confirmed`; the tool's own severity is always `unknown` | `unit/test_finding_models.py` | **Covered** |
| FN-02 | Every shipped pack produces exactly its hand-derived drafts, in catalogue order, each citing the right observations | `integration/test_findings_pipeline.py`, `fixtures/expected_findings/` | **Covered** |
| FN-03 | Each rule fires on its condition and on none other (every threshold, both sides of every edge, every shape) | `unit/test_rules.py` | **Covered** |
| FN-04 | What a target says reaches a draft only as quoted data of a strict shape and bounded length; a long or odd value is not quoted and never breaks the draft | `unit/test_rules.py`, `adversarial/test_hostile_findings.py` | **Covered** |
| FN-05 | Drafting is all or nothing; a crashing or invalid rule fails the run with the evidence kept and no draft stored | `integration/test_findings_pipeline.py` | **Covered** |
| FN-06 | A finding's details cannot be changed or deleted, and a review cannot be changed or deleted, by anyone with the database | `integration/test_findings_pipeline.py` (the triggers) | **Covered** |
| FN-07 | Only a human with a name and a reason reviews; `confirmed`, `not_exploitable` and `inconclusive` map as documented; a closed finding cannot be reviewed again; a refusal is audited | `integration/test_review.py` | **Covered** |
| FN-08 | A review needs the id typed back and there is no way to skip it | `integration/test_findings_cli.py` | **Covered** |
| FN-09 | A secret typed into a reason is stored and reported redacted | `integration/test_review.py`, `integration/test_report.py` | **Covered** |
| FN-10 | A report holds no artifact content, no raw header or body, no starter's name, no export time and no path; the same run exports byte-identical files in both formats | `integration/test_report.py` | **Covered** |
| FN-11 | Markdown cannot be made to carry markup, a link or HTML by anything stored | `integration/test_report.py`, `adversarial/test_hostile_findings.py` | **Covered** |
| FN-12 | A report is written to a new private file only, atomically, and never inside the data directory | `integration/test_report.py` | **Covered** |
| FN-13 | A database from the previous revision upgrades and keeps its data | `integration/test_findings_pipeline.py` | **Covered** |

## The optional model (M4; D-E66 to D-E69, `docs/ai-adapter.md`)

| ID | Invariant | Covered by | Status |
|---|---|---|---|
| MD-01 | The model is off until `ai enable`; with it off every command behaves as before and a report is byte-identical | `integration/test_ai_cli.py`, `integration/test_reword.py` (a report without wordings has no key and no note) | **Covered** |
| MD-02 | Enabling the Claude provider shows what is sent and needs the typed word `enable` (any other answer changes nothing); `--yes` skips it; the offline provider needs neither question nor key | `integration/test_ai_cli.py` | **Covered** |
| MD-03 | The configuration holds no secret, is private, atomic, closed-schema, size-capped, and a link, a loose mode, another owner, a directory or a bad file is refused and never read as enabled | `unit/test_ai_config.py`, `integration/test_ai_cli.py` | **Covered** |
| MD-04 | The key comes from an environment variable only; it is never printed, stored, logged, sent anywhere but the fixed endpoint, or accepted back in a reply | `unit/test_ai_adapters.py`, `integration/test_ai_cli.py`, `negative/test_ai_boundaries.py` | **Covered** |
| MD-05 | Only `findings reword` and `ai test` can call a model; `run` never builds an adapter; the SDK is imported in one file and only inside a function; it is an optional extra | `negative/test_ai_boundaries.py`, `negative/test_no_network.py`, `integration/test_ai_cli.py` | **Covered** |
| MD-06 | What is sent is rule sentences only, with hosts masked (and put back), and never a title, fact, step, guide, observation or artifact | `integration/test_reword.py`, `unit/test_ai_validation.py` | **Covered** |
| MD-07 | The request has exactly the documented shape: fixed endpoint whatever the environment says, no sampling parameter, tool, thinking or prefill | `unit/test_ai_adapters.py` | **Covered** |
| MD-08 | A wording is accepted only if every check passes (characters, length, protected tokens, verdict words, key); an item that fails is dropped and the rest are kept | `unit/test_ai_validation.py`, `integration/test_reword.py` | **Covered** |
| MD-09 | A budget per run (calls and tokens) is enforced before a call, counts earlier commands, and a refusal is recorded | `integration/test_reword.py` | **Covered** |
| MD-10 | A wording is stored beside the rule's text, once per item, append-only; the model cannot store anything; a call row and an audit event are written for every call and never hold a sentence or a key | `integration/test_reword.py`, `integration/test_database.py` | **Covered** |
| MD-11 | `findings show` and reports print the rule's text first and the wording labelled as not verified, naming the model and prompt version | `integration/test_ai_cli.py`, `integration/test_reword.py` | **Covered** |
| MD-12 | A database at revision `0002` upgrades to `0003` and keeps its data | `integration/test_findings_pipeline.py` | **Covered** |

## API targets (M5; D-E48 to D-E55, `docs/api-targets.md`)

| ID | Invariant | Covered by | Status |
|---|---|---|---|
| AP-01 | The plan holds only what the scope lists, in a fixed order; a spec adds no request, path or target | `unit/test_scope_api_targets.py`, `integration/test_api_collection.py` (a spy over every adapter call), `unit/test_api_adapters.py` | **Covered** |
| AP-02 | An OpenAPI document is recorded as inventory (counts, scheme names, server URLs as data); its text is never copied into a field | `unit/test_api_parse.py`, `unit/test_api_adapters.py`, `integration/test_api_collection.py` | **Covered** |
| AP-03 | Only `GET` and `HEAD` can be listed for an endpoint; every rule is required and only `forbidden` is accepted | `unit/test_scope_api_targets.py` | **Covered** |
| AP-04 | A parameter lists 1 to 5 values from a closed alphabet, 4 parameters at most, and every `{name}` has a list and every list a `{name}` | `unit/test_scope_api_targets.py` (with a property test of the plan size) | **Covered** |
| AP-05 | A filled-in path is canonical, at most 256 characters, and never keeps a brace | `unit/test_scope_api_targets.py`, `property/test_api_properties.py` | **Covered** |
| AP-06 | The plan must fit `max_api_requests` exactly (11 fits 11, not 10); a smaller global budget ends a run incomplete | `unit/test_scope_api_targets.py`, `integration/test_api_collection.py` | **Covered** |
| AP-07 | No value from a response body is in any row, hash input, report or file; a read keeps no artifact | `integration/test_api_collection.py`, `unit/test_api_adapters.py`, `property/test_api_properties.py` | **Covered** |
| AP-08 | Two principals' answers can be compared by the digest of their structure | `unit/test_api_parse.py`, `integration/test_api_collection.py` | **Covered** |
| AP-09 | A hostile key, a map of identifiers, a huge or deeply nested body, a non-JSON body and a compressed or binary one are recorded, bounded and unable to carry text | `unit/test_api_parse.py`, `property/test_api_properties.py`, `integration/test_api_collection.py` | **Covered** |
| AP-10 | Each principal is answered from its own entry; a missing answer is a recorded `adapter_error` | `unit/test_api_adapters.py`, `integration/test_api_collection.py` | **Covered** |
| AP-11 | Production needs an approval reference and only production may have one; ids, hosts, ports, origins and labels are strict | `unit/test_scope_api_targets.py` | **Covered** |
| AP-12 | Migration `0004` keeps every row, restores the trigger, is atomic, refuses to run with foreign keys on, and `db upgrade` copies the database aside first | `integration/test_api_migration.py` | **Covered** |
| AP-13 | The pack's `api` keys are one spelling per request, and an `OPTIONS` key carries its origin | `unit/test_api_pack.py` | **Covered** |
| AP-14 | A scope without API targets keeps its hash; every API field is part of the hash; the order of a `params` mapping changes neither hash nor plan | `unit/test_scope_api_targets.py` | **Covered** |
| AP-15 | `access-control-allow-credentials` survives redaction and reaches rule R-CORS-01; only that exact name is exempt | `unit/test_redact.py`, `integration/test_findings_pipeline.py` | **Covered** |

## Live remote mode (M6; D-E37 to D-E47, `docs/remote-live-design.md`)

| ID | Invariant | Covered by | Status |
|---|---|---|---|
| LV-01 | A live scope declares an authorization; an offline scope may not; `run` refuses a live scope and `live run` an offline one; the window, the acknowledgement and a matching approval are all required, each before anything is resolved or started | `unit/test_scope_live.py`, `unit/test_authorization.py`, `integration/test_live_controller.py`, `integration/test_live_cli.py` | **Covered** |
| LV-02 | An approval is a human's record bound to one scope hash, with an expiry, revocable, never editable; editing the scope invalidates it | `integration/test_approvals.py` | **Covered** |
| LV-03 | Every address a host resolves to must pass; one bad one refuses the host; a refused host is not contacted and its operations are recorded as refused; each host is resolved once | `unit/test_live_addresses.py`, `unit/test_live_small_parts.py`, `integration/test_live_controller.py` | **Covered** |
| LV-04 | Live mode names at most ten hosts and cannot list `ai_probe` | `unit/test_scope_live.py` | **Covered** |
| LV-05 | The firewall is default deny both ways and permits exactly the pinned pairs; the self-test must show forbidden destinations unreachable, no name resolution, no capability, and every pair permitted | `unit/test_live_isolation_runtime.py`; on a real container: `container/test_container_isolation.py` | **Covered** by logic tests; **the real container is not yet exercised** (SE-41) |
| LV-06 | The collector connects only to the pinned address, confirms the peer, verifies TLS 1.2+ before sending anything, follows no redirect, sends a credential only when given, and records a failure | `unit/test_live_collector.py` (loopback) | **Covered** |
| LV-07 | The controller refuses to send the job unless every check passed and the allow-list is the one it sent; a failed proof leaves no run | `integration/test_live_controller.py` | **Covered** |
| LV-08 | Only result and artifact files are accepted, validated against what was planned, hashed, re-redacted and size capped; a stray file, a link or a swapped envelope refuses the whole directory | `unit/test_live_outputcheck.py`, `integration/test_live_controller.py` | **Covered** |
| LV-09 | A credential reaches only the declared host, by variable name, and is in no stored byte; an echo of it (plain or encoded) fails the run | `unit/test_live_small_parts.py`, `integration/test_live_controller.py` | **Covered** |
| LV-10 | The request budget is a hard stop for what is sent, and the rate comes from the scope | `integration/test_live_controller.py`, `unit/test_live_small_parts.py` | **Covered** |
| LV-11 | The container command holds the whole posture (image by digest, read-only root, no new privileges, capabilities dropped, limits, one mount, credentials by name) | `unit/test_live_isolation_runtime.py` | **Covered** |
| LV-12 | The package opens no network socket outside three named modules, and `run` reaches no live code | `negative/test_no_network.py` | **Covered** |
| LV-13 | A database at `0004` upgrades to `0005` and keeps its data | `integration/test_approvals.py` | **Covered** |

