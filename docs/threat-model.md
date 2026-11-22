# Threat model

Status: M0, before any collection code. Every threat names the control, where it is tested (AE ids refer to
`docs/test-matrix.md`) and what is left over. A control with no test is a wish, so none is listed without one.

## 1. What is being protected

| Asset | Why it matters |
|---|---|
| **The authorized target set** | Touching anything outside it is the worst outcome this tool can cause: it is unauthorized access. |
| **Collected evidence** | Headers, cookies, banners and bodies can contain credentials, personal data and a client's internal names. |
| **The audit trail** | It is the only answer to "what did the tool do, and who allowed it". |
| **Reviewer authority** | A finding that says "validated" must mean a person decided so. |
| **The operator's machine** | The tool parses hostile text; it must not be a way in. |

## 2. Actors and what each can do

| Actor | Trusted? | Can |
|---|---|---|
| **Operator** | Trusted, fallible | Write a scope, start an offline run. Cannot validate a finding. |
| **Reviewer** | Trusted, fallible | Review drafts, approve exports. A different role in the workflow, the same OS user in practice (D-E07). |
| **Target** (and everything it returns) | **Hostile** | Returns headers, bodies, certificates, DNS answers, redirects. Controls all of that text. |
| **Fixture author** | Semi-trusted | Writes a fixture pack; a pack from elsewhere is untrusted input like a target. |
| **LLM** (optional, M4, off by default) | **Not an authority** | Rewords a draft's rule sentences; its text is checked by code and shown under the rule's, labelled. Cannot choose targets, tools, severity, truth or export. |
| **Local attacker** with the operator's file access | Out of scope | See LIMITATIONS SE-03 and SE-04. |

## 3. Trust boundaries

```text
 operator ──► [B1 scope file] ──► policy engine ──► adapters ──► [B2 target data: HOSTILE]
                                       │                                │
                                       │                        normalize + redact
                                       ▼                                │
                                 [B3 SQLite + artifacts] ◄──────────────┘
                                       │
                          deterministic correlator (rules)
                                       │
                         [B4 prompt boundary: untrusted text] ──► optional model
                                       │                                │
                                       ◄──────── typed claims, validated┘
                                       │
                                 [B5 human review] ──► [B6 export]
```

| Boundary | Crossing | Defence |
|---|---|---|
| **B1** file → policy | an operator's YAML | strict loader, unknown keys refused, canonical hash, expiry, caps |
| **B2** target → tool | any response text | treated as data; size caps; redaction before storage; never executed, never followed |
| **B3** tool → disk | evidence and audit | redacted only, `0600`/`0700`, atomic writes, append-only chained audit |
| **B4** evidence → model | prompt | labelled untrusted, redacted, capped, schema-typed output, no tools |
| **B5** draft → finding | a decision | human actor and reason required, model excluded |
| **B6** run → export | a file path | safe-path checks, no overwrite, drafts labelled |

## 4. The four primary threats

### T1. Unauthorized scope (touching what was not approved)

| Vector | Control | Tests |
|---|---|---|
| Expired or missing approval | refused before any adapter, `now < expires_at` | AE-01 |
| Ambiguous host (case, trailing dot, IDN, userinfo, mixed encoding) | canonical or refused (D-E04) | AE-04 |
| Wildcard or IP literal | refused (D-E04) | AE-04 |
| Redirect to another host or to localhost | never followed; target recorded as data (D-E03) | AE-02 |
| CNAME to an unapproved name | recorded, never added to the scope | AE-05 |
| Content asks for scope expansion | refused and noted; scope is immutable per run (hash checked) | AE-20 |
| Method or query outside the contract | scope allows GET/HEAD metadata on exact paths only | AE-18 |
| Two aliases for one host | duplicates after canonicalization refused | AE-19 |
| Scope edited between validate and run | the run records the scope hash and refuses a changed file | AE-01 |

*Residual:* the operator can write a scope for something they have no right to test. The tool cannot know (SE-02).

### T2. SSRF and unsafe egress

In 0.x **no socket is ever opened** (D-E01), so the classic SSRF paths do not exist; the tests prove it by
blocking the socket module during a run. When live mode is ever built it must meet all of: exact scope
allowlist, the DNS answers **and the connected peer** checked against private, loopback, link-local, metadata
and IPv4-embedding IPv6 ranges, redirects denied, and **real egress isolation** (container or OS firewall).
A hostname regex or an `ipaddress` check alone is not accepted as the boundary (AE-03, deferred to M5).

*Residual:* none today, because there is no egress. A future live mode needs its own review.

### T3. Prompt injection and model authority

| Vector | Control | Tests |
|---|---|---|
| Target text tells the model to ignore scope, add hosts, run commands, reveal secrets | the model has **no tools** and no authority over targets; its input is labelled untrusted; its output is a typed schema | AE-06, AE-20 |
| A response that looks like a tool call or model output | parsed as text only; the tool registry is fixed and deterministic | AE-06 |
| Model output invented or malformed | every claim must cite a known observation id; unknown ids and invalid JSON are rejected, with a deterministic fallback | AE-08, AE-09, AE-17 |
| Model promotes its own output to "verified" | the model actor can perform no state transition (D-E08) | AE-09 |
| Hidden instructions in Unicode (bidi, zero-width, tag characters) | normalised and flagged before they reach a prompt | AE-06 |

*Residual:* a model can still be misled into a wrong *draft*. That is why a draft is never a finding and a human
decides (SE-06).

### T4. Evidence leakage

| Vector | Control | Tests |
|---|---|---|
| Cookies, API keys, authorization headers in responses | redacted before persistence and before any model call | AE-07 |
| Raw bodies uploaded to a model | no body, header, observation or artifact is ever sent: only a draft's rule sentences (`docs/ai-adapter.md`) | AE-07, MD-06 |
| Evidence readable by other local users | `0600` files, `0700` directories, database `0600` | M1 tests |
| Evidence kept forever | 30-day default retention, purge with receipt (D-E13) | M1 tests |
| A hash that lets someone guess a low-entropy value | keyed HMAC fingerprints only (D-E14) | M2 tests |
| Secrets in logs | structured logging, no header or body values logged | M2 tests |
| Report or export written outside the intended place | safe-path checks, no overwrite | AE-14 |

*Residual:* redaction is best effort (SE-05); a person must read anything before it leaves the machine.

### T5. Testing AI systems (approved design: `docs/ai-targets.md`)

| Vector | Control | Tests |
|---|---|---|
| Testing a model provider's own service | `layer: application` is the only accepted value | `unit/test_scope_ai_targets.py` |
| A probe that makes an agent act, writes memory, or carries personal data | `tool_invocation`, `persistent_state_writes`, `personal_data_in_probes` are required and only `forbidden` is accepted | same |
| Probes written at run time by an operator, a target or a model | a scope names probe sets from a reviewed library; it cannot define one | `unit/test_probes.py`, `unit/test_scope_ai_targets.py` |
| Unbounded cost to the client | request and token limits are required and the worst case must fit them | same |
| A model's reply read as instructions by our own assistant model (nested injection) | the reply is stored as a redacted artifact and recorded as facts; `target_output_to_assistant_model` is `forbidden` | fixtures; adapters in M2, model in M4 |
| Production systems tested by mistake | `environment` is required; production needs a reference and only production may have one | `unit/test_scope_ai_targets.py` |

*Residual:* the probe texts do not exist yet (M2) and nothing has been run against a real AI system.

### T6. The optional model (M4; `docs/ai-adapter.md`)

| Vector | Control | Tests |
|---|---|---|
| The key sent somewhere else (a changed base URL, a proxy variable, a bearer token in the environment) | the endpoint is a constant, the key is passed explicitly so the SDK reads no credential variable, the key is accepted nowhere in a reply | MD-04, MD-07 |
| The key written to a file, a log, a report, an error or the database | it is read from the environment at the moment of a call; the configuration holds only the variable's *name*; errors are reduced to a class name | MD-03, MD-04 |
| The model turned on by accident or by someone else | off by default, a typed word to enable, a private closed-schema file, a bad file is refused rather than read as enabled | MD-01 to MD-03 |
| A model reached from `run`, a report or a review | only two commands build an adapter, checked in the source | MD-05 |
| Engagement data leaving the machine | rule sentences only, hosts masked by default, nothing a target said | MD-06 |
| A model that adds a verdict, a fact, a number, a link or markup | per-item checks by code; a failure is dropped and the rule's text stands | MD-08 |
| A model that returns a hostile or malformed reply | exact shape or invalid as a whole; sizes capped; ids compared | AE-08 |
| Unbounded spend | per-run limits on calls and tokens, refused before the call | MD-09 |
| A model's wording read as the finding | stored beside the rule's text, labelled as not verified, never in place of it; the model cannot write or review | MD-10, MD-11 |

*Residual:* a wording can pass every check and still shift the meaning (SE-32); sentences go to a third party once enabled (SE-33).

### T7. Testing APIs (M5; `docs/api-targets.md`)

| Vector | Control | Tests |
|---|---|---|
| A spec that lists far more than the scope allows, or names other hosts | the spec is inventory: only the endpoints the scope lists are planned, and a server URL in it is stored as data and never contacted | AP-01, AP-02 |
| A request that changes something | endpoint methods are `GET` or `HEAD` only (`OPTIONS` only through the origin list); `rules.state_changing_methods` can only be `forbidden` | AP-03 |
| Guessing or enumerating identifiers | a parameter value is listed (1 to 5, 4 parameters at most), drawn from a closed alphabet; no range, pattern or wordlist exists in the format, and a spec cannot add one | AP-04, AP-05 |
| Cost and load | `max_api_requests` is required and the whole plan must fit it before a run starts; the global budget still applies and ends a run incomplete | AP-06 |
| Other people's data in the evidence | a body is reduced to its shape; no value is stored, hashed or reported, and a read keeps no artifact | AP-07, AP-08 |
| A response that carries instructions or a smuggled identifier in a field name | a name that is not short and plain is recorded as `?`, the keys of a large object as `{key}`; flags are pattern matches only | AP-09 |
| One principal given another's answer | each principal is answered from its own entry; a missing one is a recorded error | AP-10 |
| A production system tested by mistake | `environment` is required; production needs a reference and only production may have one | AP-11 |
| A migration that damages recorded evidence | revision `0004` is one transaction that copies every row, checks nothing was lost or orphaned, and is preceded by a copy of the database file | AP-12 |

*Residual:* nothing has been run against a real API; the pack is mine (SE-37). A short field name can itself be an identifier (SE-38).

## 5. Other threats

| Threat | Control | Tests |
|---|---|---|
| **Misleading "clean"**: a timeout, DNS failure or parse error read as "no finding" | errors are recorded as errors; the run is incomplete and exits `2` (D-E09) | AE-10 |
| **Oversized or hostile input**: 1 MB body, zip bomb, huge header, malformed certificate | hard caps, safe errors, nothing decompressed | AE-13 |
| **Partial writes**: crash between an artifact write and its row | atomic store; an orphan file is cleaned up; a row never points at a missing file | AE-11 |
| **Budget overshoot** by racing workers | one conditional UPDATE reserves a permit | AE-12 |
| **Cancel and resume lose history** | every transition is audited in the same transaction; a retry is a new run | AE-15 |
| **Stale evidence in a new run** | composite foreign keys tie an observation, a finding and a link to one run (D-E16) | AE-16 |
| **Audit tampering** | append-only triggers and a hash chain (D-E11) | M1 tests |
| **Fixture path traversal** (`../` in a pack or an export path) | a path is resolved and must stay under its root; symlinks refused | AE-14 |
| **Malformed YAML** (aliases, duplicate keys, deep nesting, huge files) | strict loader, size and depth caps | M1 tests |
| **Supply chain** | locked and hash-pinned dependencies, pip-audit, SHA-pinned Actions, gitleaks over history | CI |

## 6. What this model does not cover

A hostile operator, a compromised machine, the operating system's own permissions model, and the correctness of
anyone's authorization to test a system. These are named in LIMITATIONS so nobody has to guess.
