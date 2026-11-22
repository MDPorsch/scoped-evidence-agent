# Scopes for pentesting APIs (contract)

Status: **approved by the owner on 2026-11-21 (D-E48 to D-E55); built in M5 (offline)**. Offline fixtures only until the live design
(`remote-live-design.md`, approved) is built, and then only inside its isolation. It shares its structure with the AI-target scopes.
The decisions that make the build concrete are at the end (D-E70 to D-E73); D-E70 is review-gated.

## What this adds, and where it stops

A scope can describe an engagement against **APIs an organisation operates and has authorized you to test**, in a third list,
`api_targets`, next to `allowed_targets` (web) and `ai_targets` (AI systems). The tool collects **evidence about the API
surface**: what is exposed, how it answers with and without credentials, and what it reveals in headers, errors and shapes.

**The line with `boundarycheck`.** `boundarycheck` answers "does this API enforce the authorization policy I wrote?" by
comparing what each test user may see with an independent policy. This tool does **not** judge authorization. It records what
each principal got back as **facts** (status, headers, the shape of the answer) so a human can read them, and leaves the
verdict to the human and to `boundarycheck`. A later bridge can attach a `boundarycheck` report to an engagement as evidence
(D-E54); this tool never runs it.

**What it will not do, in 0.x:** change anything (no `POST`/`PUT`/`PATCH`/`DELETE`), enumerate or fuzz (no ID ranges, no wordlists,
no parameter guessing), brute-force or spray credentials, follow what a spec or a response says to other hosts, or exploit
anything. It reads, exactly as far as the scope says.

## Why APIs need their own rules

| Risk | The rule |
|---|---|
| **A spec lists far more than you may touch** | An OpenAPI document is **inventory, never scope**. Only endpoints the scope lists are contacted; a hostile or generous spec cannot widen it (D-E49) |
| **Reads can still hurt** | `GET` can have side effects and cost; limits are required, methods are `GET`/`HEAD`/`OPTIONS` only (D-E50) |
| **Guessing is scanning** | Parameter values are **listed**, at most 5 per parameter. No ranges, no sequences, no wildcards (D-E50) |
| **Responses hold other people's data** | By default only the **shape** of a body is recorded (field names, JSON types, lengths), never values (D-E52) |
| **Several identities** | Each endpoint lists which principals call it; credentials come from the environment, per the AI-target rules (D-E51) |
| **A principal's token is dangerous** | Same handling as D-E42: environment only, only to the declared host, only over verified TLS, leak-guarded |

## The format

```yaml
allowed_operations: [api_spec, api_read, api_options]   # the single global switch, as for AI operations
api_targets:                                             # 1 to 10 entries
  - id: orders-api                                       # [a-z0-9][a-z0-9-]{1,39}, unique in this scope
    kind: rest                                           # rest (graphql arrives later, with library queries only)
    environment: staging                                 # test | staging | production (+ production_approval_ref)
    host: api.staging.example.invalid
    scheme: https
    port: 443
    base_path: /v1                                       # an exact prefix every endpoint path lives under
    operations: [api_spec, api_read, api_options]
    spec_paths: ['/openapi.json']                        # exact GET paths of the spec; required for api_spec
    principals:                                          # test identities; `anonymous` always exists and needs no entry
      - id: tenant-a-user                                # [a-z0-9][a-z0-9-]{1,39}
        label: Tenant A, editor                          # free text for the report
        # the credential is NOT written here: it is named in the live run (D-E51) and held in the environment
    endpoints:                                           # explicit, 1 to 40; nothing is inferred from the spec
      - id: list-projects
        method: GET                                      # GET | HEAD
        path: /projects                                  # exact, or a template with {name} parameters
        params:                                          # a value list for every template parameter, 1 to 5 each
          project_id: ['p-1001', 'p-1002']               # values the assessor created; never a range
        principals: [anonymous, tenant-a-user]           # who calls it: 1 to 4 (anonymous counts)
        expect_auth: required                            # required | none | unknown: the assessor's expectation, recorded, never enforced
    cors_origins: ['https://untrusted.example.invalid']  # origins for api_options; required for api_options (1 to 3)
    limits:
      max_api_requests: 60                               # 1 to 400; every planned request counts
      max_response_bytes: 100000                         # 1024 to 1_000_000, per response
    rules:                                               # every one REQUIRED, the only accepted value is `forbidden`
      state_changing_methods: forbidden
      enumeration_or_fuzzing: forbidden
      response_values_in_evidence: forbidden             # shapes only (D-E52)
      spec_widens_scope: forbidden
```

### Rules, in the order they are checked

1. Strict like the rest of the scope. Canonical host and path rules as elsewhere; two API targets at the same scheme, host and
   port, or with the same `id`, are refused (`SCOPE-005`). The same host may also be a web or an AI target (D-E34).
2. `rules`: all four required, only `forbidden` accepted; `allowed` is refused as "not available in this version" (`SCOPE-011`).
3. `environment: production` needs `production_approval_ref`, and only production may have one (`SCOPE-011`).
4. `base_path` is an exact canonical path. Every endpoint `path` is canonical, and each `{name}` in it has a `params` list
   (`SCOPE-006`); a `params` key with no matching `{name}` is refused, so a value can never reach a place nobody declared.
5. `method` is `GET` or `HEAD`. Anything else is refused as "state-changing or unsupported methods are not available" (`SCOPE-011`).
6. `params` value lists have 1 to 5 entries of at most 64 characters from `[A-Za-z0-9._~-]`. No ranges or patterns exist in the
   format to write (`SCOPE-006` if a value has other characters).
7. `principals` on an endpoint are ids that exist in the target (or `anonymous`), unique, 1 to 4 (`SCOPE-009`).
8. `api_spec` needs `spec_paths`; `api_read` needs `endpoints`; `api_options` needs `cors_origins` (and `endpoints`); each field
   is valid only with its operation (`SCOPE-009`). Origins are canonical `https://host[:port]` with no path and are **only sent
   as a header value**, never contacted.
9. Operations are a subset of the global `allowed_operations`, and a globally allowed API operation no target uses is refused
   (`SCOPE-009`).
10. **The plan must fit the limit.** The endpoints times their parameter combinations times their principals, plus the spec reads
    and the OPTIONS requests, must be at most `max_api_requests` (`SCOPE-007`). A smaller global `max_requests` still just ends a
    run incomplete.

## What is recorded (facts, never verdicts)

* **`api_spec`**: status, headers, and a bounded inventory from the document: version, number of operations, the server URLs
  **as data** (never contacted), the names of security schemes, and how many operations declare no security. The document is parsed
  as untrusted input (size and depth caps, no external reference followed).
* **`api_read`**: for one (endpoint, parameter values, principal): status, redacted headers, `content-type`, the size, and the
  **shape** of a JSON body (every field path with its JSON type and, for strings and arrays, a length), plus a digest of the shape
  so two principals' answers can be compared for *structure* without storing a value. Flags for structure that matters to a
  reviewer: `has_stack_trace_markers`, `has_debug_markers`, `echoes_request_headers`. Whether the shape is a leak is a human's call.
* **`api_options`**: the `Allow` header and the CORS answer to each declared origin (`access-control-allow-origin`,
  `-credentials`, `-methods`, `-headers`), as headers.

Response **values** are not stored (`response_values_in_evidence: forbidden`). A reviewer who needs a body to prove a finding
raises that as a separate, human decision; it is not a flag a model or a worker can set.

## The hash and the plan

The API targets join the normalised scope (key omitted when the list is empty, so older scopes keep their hash). After the web and
AI entries, each API target in file order contributes: its spec reads, then for each endpoint in file order and each combination
of its parameter lists (in the order given) one `api_read` per listed principal, then one `api_options` per endpoint per origin.
An API target contributes no dns, tls or http operation; list the host as a web target for those.

## What a human still decides

Whether the engagement is authorized, whether a difference between two principals is an authorization flaw (that question belongs
to `boundarycheck` or a reviewer), how serious anything is, and whether any response value may be kept as evidence.

## How it is built (M5)

* **Request path.** `base_path` followed by the endpoint `path` with each `{name}` filled in (`/v1` and `/projects/{project_id}` give
  `/v1/projects/p-1001`; a base path of `/` adds no slash). A `spec_paths` entry is absolute, not under the base path. A placeholder is a
  whole path segment with a name of `a-z`, `0-9` and `_`, listed once; a filled-in path may not pass 256 characters, and the host,
  the longest path and the longest origin together may not pass 400, so the recorded request line fits its field.
* **Order.** Each endpoint's parameters vary in the order the path names them (not the order of the `params` mapping, so the hash and the
  plan always agree), each parameter's values in the order given, and for each combination every listed principal in order.
  `OPTIONS` uses the first listed value of each parameter, once per origin, as `anonymous`.
* **Parameters.** At most four per endpoint, 1 to 5 listed values each, each 1 to 64 characters of letters, digits and `. _ ~ -`. Dots
  are allowed, so `1..100` is one literal value, not a range: nothing in the tool expands a value.
* **Principals.** `anonymous` always exists and may not be declared. No credential is read in 0.x: offline, a pack holds one recorded
  answer per principal and request. Credentials from the environment arrive with live mode, under the rules of
  `docs/remote-live-design.md` (D-E42).
* **The three flags** are plain pattern matches, never a judgement. `has_stack_trace_markers`: a Python, Java, Node or Go trace in the
  text, or a key named `stacktrace`, `stack_trace`, `traceback` or `trace`. `has_debug_markers`: `debug` set to true or 1, `DEBUG = True`,
  or a key named `debug`. `echoes_request_headers`: a key named `authorization`, `proxy-authorization`, `cookie`, `set-cookie` or
  `x-api-key` anywhere in the JSON.
* **Operations without security.** An operation counts when its own `security` is an empty list, or when it has none and the document has
  no top-level `security`. An operation that lists schemes counts as secured, whatever the schemes allow.
* **No rule reads API evidence yet.** A run of an API scope drafts nothing and exits `0` when complete: this milestone records facts
  (D-E52) and leaves reading them to a person and to `boundarycheck` (D-E54). A later change may add rules, each reviewed on its own.

## Decisions made in the build (to review)

Status (2026-11-21): **D-E70 (the migration) and D-E73 (the pack key) are approved. D-E71 (facts only) and D-E72 (the CORS credentials header) are not yet approved.**

| ID | Decision |
|---|---|
| D-E70 | **Migration `0004` rebuilds two tables.** SQLite cannot widen a CHECK list, so `targets` (its `kind`) and `observations` (its type and adapter lists) are recreated with the new values and every row is copied unchanged, in one transaction that checks no row was lost or orphaned. `db upgrade` first copies the database file aside (`evidence.sqlite.before-0003`, mode `0600`) and says where. This is the first migration that rewrites existing records, so it is **review-gated** (`docs/migrations.md`). *Approved by the owner, 2026-11-21.* |
| D-E71 | **API evidence is facts only and no rule reads it in M5.** A read stores the shape of a body, never a value, and no artifact; the source hash covers the shape, not the body. |
| D-E72 | **`access-control-allow-credentials` is not redacted by name.** It contains the word "credential" but holds `true` or nothing else; redacting it hid the one fact a CORS review needs and made the credentials branch of rule R-CORS-01 unreachable on stored data. Only that exact name is exempt. |
| D-E73 | **A key of a fixture pack's `api` section is `principal\|METHOD\|url` (and `\|origin` for `OPTIONS`),** one spelling per request, so a pack can give each principal its own answer. *Approved by the owner, 2026-11-21.* |
