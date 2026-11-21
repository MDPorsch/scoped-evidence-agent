# The correlator, drafts, review and reports (M3 contract)

Status: **built in M3. D-E56 to D-E60 are approved; D-E61 to D-E65 (below) are proposed and wait for the owner's review.** This file
makes `docs/finding-assessment.md` concrete: which rules exist, what each one reads and says, how a step is checked, how a draft is
stored and reviewed, and what a report contains. Nothing here sends a request; the correlator reads stored observations only.

## The pipeline

```text
run: collect (M2) ──► CORRELATING ──► rules read the run's stored observations ──► step checker ──► drafts stored ──► DRAFTED
                                          (deterministic, no model, no network)       (D-E58)       (immutable details)
findings list|show ──► a person reads ──► findings review (typed confirmation) ──► report export
```

* A rule reads **observations of this run only** (the database already forbids a stale one, AE-16) and the run's scope. It never
  resolves, requests or fetches anything. Its inputs are the stored payloads and the time each was collected, so the same
  observations always give the same drafts (ids and timestamps aside).
* A rule that raises ends the run `FAILED` (`unexpected_error`, exit `2`) with everything collected kept, as a crashing adapter does.
* An observation whose `error_status` is not `ok` produces no draft: a failed look is not a finding. Coverage already says so.
* **Order:** by rule (the catalogue order below), then by the first cited observation in collection order. Every draft is stored
  `NEEDS_VALIDATION` (the worker's deterministic step); nothing is `VALIDATED` until a person says so.
* **Exit code of `run`:** `2` if the collection was incomplete or the run failed; else `3` if at least one draft awaits review; else `0`.

## The closed list of classes

`tls_misconfiguration`, `missing_security_header`, `information_disclosure`, `insecure_redirect`, `exposed_api_documentation`,
`permissive_cors`, `dns_external_reference`, `ai_prompt_injection_susceptibility`, `ai_system_prompt_leakage`,
`ai_sensitive_information_disclosure`, `ai_output_handling`. A class not on this list cannot be stored (schema and database).

## The rule catalogue (version 1)

Every rule has an id, reads one observation type, and states each condition it found as a plain sentence. "Quoted data" means a
value that came from the target; it is shown only after it matches a strict shape (below) and never in `action` or
`example_invocation`.

| Rule | Class | Reads | Fires when | CWE suggestions | Assessment | Suggested severity | Confidence |
|---|---|---|---|---|---|---|---|
| R-TLS-01 | `tls_misconfiguration` | one `tls_metadata` with status `ok` | at least one of: protocol is `TLSv1.0`/`TLSv1.1`; `not_after` is before the observation's collection time; `not_before` is after it; `self_signed`; RSA key under 2048 bits, DSA, or EC under 224 bits; signature algorithm contains `sha1` or `md5`; the host is not covered by `san_dns` (or by `subject_cn` when `san_dns` is empty; a `*.` wildcard covers one label) | CWE-295 (expired, not yet valid, self-signed, name mismatch), CWE-326 (weak key), CWE-327 (legacy protocol, weak signature) | `conditional` | `medium` with three or more conditions, else `low` | 0.90 (0.80 when only the protocol version fired) |
| R-HDR-01 | `missing_security_header` | every `http_metadata` of one target with status 200 to 399 (`ok`) | `strict-transport-security` (https only), `x-content-type-options` or `content-security-policy` is absent from **every** such response | CWE-693; CWE-319 as well when HSTS is missing | `conditional` if HSTS is missing, else `unlikely` | `low` if HSTS is missing, else `info` | 0.70 |
| R-INFO-01 | `information_disclosure` | every `http_metadata` of one target | a `server`, `x-powered-by` or `x-generator` header whose value has the shape `product/version` (strict: `[A-Za-z][A-Za-z0-9_.-]{0,30}/[0-9][A-Za-z0-9._-]{0,20}` optionally followed by `(word)`) | CWE-200 | `unlikely` | `info` | 0.80 |
| R-INFO-02 | `information_disclosure` | one `http_metadata` whose parsed document has `disallow` | a `Disallow` path contains `admin`, `backup`, `config`, `.git`, `.env`, `internal`, `private`, `secret` or `debug` (the path is quoted only if it is an exact canonical path) | CWE-200 | `unlikely` | `info` | 0.60 |
| R-REDIR-01 | `insecure_redirect` | one `http_metadata` with a `redirect_location` | the location is `http://`, or its host is not a host the scope lists (recorded, never followed) | CWE-319 (http), CWE-610 (other host) | `conditional` | `low` | 0.85 |
| R-API-01 | `exposed_api_documentation` | one `http_metadata` whose parsed document has `openapi` | the document names a server host other than the target's own | CWE-200 | `conditional` | `low` | 0.75 |
| R-CORS-01 | `permissive_cors` | one `http_metadata` | `access-control-allow-origin` is `*` or `null` | CWE-942 | `conditional` with `access-control-allow-credentials: true`, else `unlikely` | `medium` with credentials, else `low` | 0.70 |
| R-DNS-01 | `dns_external_reference` | one `dns_metadata` | a `CNAME` points to a name that is neither a listed host nor below one | none | `not_assessed`: judging it needs resolving a name outside the scope, which the tool will not do | `info` | 0.50 |
| R-AI-01 | `ai_prompt_injection_susceptibility` | `ai_probe`, category `prompt_injection`, one draft per target | `canary_present` is true | CWE-1427 | `conditional` | `medium` | 0.60 |
| R-AI-02 | `ai_system_prompt_leakage` | `ai_probe`, category `system_prompt_leakage`, one per target | `canary_present` is true | CWE-200 | `conditional` | `medium` | 0.60 |
| R-AI-03 | `ai_sensitive_information_disclosure` | `ai_probe`, category `sensitive_information_disclosure`, one per target | `canary_present` is true | CWE-200 | `conditional` | `medium` | 0.60 |
| R-AI-04 | `ai_output_handling` | `ai_probe`, category `output_handling`, one per target | any of `contains_html`, `contains_markdown_link`, `contains_code_block`, `contains_url` is true | CWE-116 | `conditional` | `low` | 0.70 |

"One draft per target" cites **every** observation that fired, so duplicates are grouped, not repeated. A rule never says an
absence is proof: R-HDR-01 lists, as unknowns, the paths that were not collected. The assessment `likely_if_conditions_hold` is in
the vocabulary and unused by version 1: no rule's evidence is strong enough to say it. **Not covered in version 1** (so "no draft"
is not "no flaw", SE-07): an expired `security.txt`, cookie attributes (cookie values are redacted whole), cache headers, CSP quality,
mixed content, certificate chain validity beyond the flags above, anything that needs a request the scope does not list.

A draft's title is built from the class label and the scope-validated host (and port): `TLS configuration weaknesses on
bad.example.invalid:443`. It never contains target text.

## What a draft stores (`finding_details`, immutable)

Strict JSON, validated when written and when read: `rule_id`, `rule_version`, `vulnerability_class`, `cwe_candidates` (suggestions
to verify), `conditions` (1 to 8 sentences), `exploitability` (`assessment`, `preconditions`, `attacker_position`, `unknowns`,
`basis`), `validation_steps` (at most 8), `validation_steps_dropped` (each with the rule that dropped it), `decision_guide` (three
outcomes mapped to the three reviewer decisions), `remediation`, `suggested_severity` (`value`, `basis`), `severity` (always
`unknown`: only a person sets one, and nothing in 0.x stores it), `facts` (quoted target data, at most six of at most 80
characters), `assumptions`. The database refuses an update or a delete of a details row. The mutable parts of a finding are its
status and its reviews.

## Validation steps (D-E58, D-E59)

The closed kinds, intrusiveness and invocation templates are in `docs/finding-assessment.md`. M3 builds the checker and the
renderer. **A rule supplies a typed `StepSpec`** (kind, target, path or record type or probe, the observations it cites, the one
condition tested); the **renderer** supplies every sentence from a fixed template per kind. The checks, in order, each with a rule id
recorded if a step is dropped:

| Id | A step is dropped when |
|---|---|
| VS-01 | its kind is not on the list, or its intrusiveness does not match its kind |
| VS-02 | its target, port, scheme, path, origin or probe is not in the scope for an operation the scope allows (a request step for a path the scope does not list, a certificate step for a port the scope does not list, an origin the scope does not declare: **no scope can declare one until API targets exist, so `check_cors_for_declared_origin` is always dropped in 0.x**) |
| VS-03 | a value to be placed in a template is not shell-safe (a host must be a canonical host, a path an exact canonical path, a port 1 to 65535, a record type from `A AAAA CNAME NS MX TXT CAA`) or the rendered invocation holds a forbidden character or flag |
| VS-04 | it would put target-derived text in `action` or `example_invocation` (not representable: only `record` takes quoted data) |
| VS-05 | it cites no observation of this run, a compare step cites fewer than two, or either branch is empty |
| VS-06 | it is the ninth step, or its `action` is over 400 characters |

`validation_steps_dropped` lists every dropped step with its id: nothing disappears silently. An invocation exists only for
`inspect_certificate_field`, `rerequest_listed_path`, `re_resolve_name`, `read_public_document` and
`check_cors_for_declared_origin`, from these templates (verification on, no body, no credential, no redirects, one request):

```text
inspect_certificate_field   openssl s_client -connect HOST:PORT -servername HOST -verify_return_error
rerequest_listed_path       curl --silent --show-error --dump-header - --output /dev/null --max-time 10 --max-redirs 0 SCHEME://HOST[:PORT]PATH
                            (with --head instead of the output flags when the recorded request was HEAD)
read_public_document        curl --silent --show-error --max-time 10 --max-redirs 0 SCHEME://HOST[:PORT]PATH
re_resolve_name             dig +noall +answer HOST TYPE
check_cors_for_declared_origin  curl --silent --show-error --head --request OPTIONS --header 'Origin: ORIGIN' --max-time 10 SCHEME://HOST[:PORT]PATH
```

`rerun_library_probe` and `owner_confirmation` have no invocation. `rerun_library_probe` says plainly that it needs the tool's live
mode, which this version does not have: it is shown so the reviewer knows what would settle the question, not as something to run.

## Review (D-E57, D-E63)

`findings review ID --decision confirmed|not_exploitable|inconclusive --reviewer NAME --reason TEXT` asks the person to **type the
first eight characters of the finding id** (there is no flag that skips this). The decision is recorded in `finding_reviews`
(append-only) and in the audit trail, and is applied like this:

| Decision | Finding status | Meaning |
|---|---|---|
| `confirmed` | `VALIDATED` | the reviewer ran the steps (or their own method) and the condition holds in this engagement |
| `not_exploitable` | `FALSE_POSITIVE` | the evidence is true but there is nothing to act on here; the review row keeps the exact decision |
| `inconclusive` | unchanged (`NEEDS_VALIDATION`) | the review is recorded and the finding stays open |

A reason is required, the reviewer must be named, and only a human may review (the state machine already refuses a worker or a
model). The first review of a run moves the run to `HUMAN_REVIEW`. A run is never moved to `EXPORTED` in 0.x: exports are
repeatable and read-only (LIMITATIONS SE-24).

## Reports (D-E64)

`report export RUN --format json|md --output PATH` writes **one file** built only from the database. Contents: the tool version; the
run (id, state, attempt, timestamps); the engagement label and the scope hash, expiry and mode; **coverage** (planned, ok, every
other status counted, the observations recorded); every observation (id, type, status, subject, `source_hash`,
`normalized_input_hash`, collection time); every artifact (sha256, mime, size, redaction status; **never its content**); every
finding with everything above, its status, its evidence ids and its reviews; the audit trail length, whether its chain verified and its
head hash; and fixed notes (a draft is not a finding; authorization is the operator's; what was not collected).

* **Privacy:** no artifact content, no raw header or body is in a report. A reviewer's name and reason, which a person typed, pass
  through the redactor before they are written. Markdown output escapes every dynamic string and shows quoted target data only in code spans.
* **Reproducible:** the report holds no export time, no path and no host name. The same run exports byte-identical files
  (JSON with sorted keys; Markdown from the same data). The command prints the file's sha256.
* **Path rules (AE-14):** the output is a new regular file: refused if it exists, if the parent directory does not exist, if any
  part of the path is a symlink or `..`, or if it is inside the data directory. Created `0600`, atomically (written to a temporary
  file, then linked into place so an existing file can never be replaced).
* **Drafts are labelled** `DRAFT: not validated` in both formats until a person validates them.

## Decisions proposed for this milestone

| ID | Decision | Status |
|---|---|---|
| D-E61 | **The closed class list and the version-1 rule catalogue above.** Adding a class or a rule is a reviewed change with its tests and mutants. | Proposed |
| D-E62 | **Storage:** a finding's details are immutable (`finding_details`, update and delete refused); reviews are append-only (`finding_reviews`); a run records `planned_operations`. Migration `0002`. `category` holds the class id and now allows `_`. | Proposed |
| D-E63 | **Review mapping, typed confirmation and run state** as in the Review section; `confirmed`/`not_exploitable`/`inconclusive` map to `VALIDATED`/`FALSE_POSITIVE`/unchanged. | Proposed (review-gated: who may validate) |
| D-E64 | **Report contents, privacy, reproducibility and path rules** as in the Reports section. | Proposed (review-gated: reporting privacy) |
| D-E65 | **CLI:** `run` also correlates; `findings list RUN` and `findings show ID` replace the contract's `findings draft RUN` (a run already drafts); exit `3` means a complete collection with drafts to review. | Proposed |
