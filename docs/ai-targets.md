# Scopes for pentesting AI systems (contract)

Status: design, **approved by the owner on 2026-11-20 (D-E28 to D-E36)**; being implemented test-first. Offline fixtures only,
like the rest of 0.x: no AI system is contacted.

## What this adds, and what it does not

A scope can now describe an engagement against an **AI system**: a chat endpoint, an agent, a retrieval (RAG) service or an
MCP server that **an organisation operates and has authorized you to test**. It adds a second list, `ai_targets`, next to
`allowed_targets`, with rules of engagement that fit how these systems fail.

It does **not** cover testing a model provider's own service. The tested layer is always the *application* wrapped around a
model (`layer: application`). Probing a provider's infrastructure needs the provider's permission, not the application
owner's, and a scope cannot express that, so the schema refuses it.

It does not make the tool an exploitation agent. In 0.x the operations are **metadata reads** and **fixed, reviewed probes**
(below), they run against offline fixtures, and every output is a draft for a human.

## Why AI targets need their own rules

| Risk | Why a web scope does not cover it | The rule |
|---|---|---|
| **The target's output is model-written text** | A web page is hostile data. A model's answer is hostile data that *also* reads like instructions, and it may be fed to our own assistant model: injection twice removed | Output is stored redacted, recorded as facts, never sent to the assistant model by default (D-E33) |
| **Probes cost the client money** | A request to a model bills tokens. An unbounded test is an unbounded invoice | Request and token limits are required, and the worst case must fit them (D-E31) |
| **An agent can act** | A probe that gets an agent to call a tool can send mail, write a file or change a record | Tool invocation is `forbidden`; a probe that makes an agent claim it acted is recorded as text only (D-E29) |
| **Memory persists** | A probe can leave text in a store the next user reads | Persistent-state writes are `forbidden` (D-E29) |
| **Probes can contain real data** | A "realistic" probe can carry personal data into logs at the client | Personal data in probes is `forbidden` (D-E29) |
| **The model layer belongs to someone else** | The application owner cannot authorize testing of the provider | `layer: application` only (D-E28) |
| **Probe text is attack text** | If a model, a target or an operator can write probes at run time, the tool is an attack generator | Probes come only from a reviewed library; a scope names ids (D-E30) |

## The format

```yaml
# ... the usual top-level fields (engagement_id, owner_approval_ref, expires_at, mode, limits) ...
allowed_operations: [ai_metadata, ai_probe]     # the single global switch; dns/tls/http may be listed too
ai_targets:                                      # 1 to 10 entries
  - id: support-bot                              # [a-z0-9][a-z0-9-]{1,39}, unique in this scope
    kind: chat_endpoint                          # chat_endpoint | agent | rag_service | mcp_server (a label for reports)
    layer: application                           # the only accepted value
    environment: staging                         # test | staging | production
    # production_approval_ref: change-4821       # REQUIRED when environment is production; an opaque label, not verified
    host: assistant.example.invalid              # canonical host rules, as for allowed_targets
    scheme: https                                # https | http
    port: 443
    api_style: openai_compatible                 # openai_compatible | messages | custom_json (how the fixture is read)
    operations: [ai_metadata, ai_probe]          # a subset of the global allowed_operations
    metadata_paths: ['/v1/models']               # exact GET paths; required for ai_metadata, and only valid with it (1 to 5)
    probe_path: /v1/chat/completions             # the one POST path; required for ai_probe, and only valid with it
    probe_sets: [canary-echo-v1]                 # ids from the probe library; required for ai_probe, only valid with it
    test_categories: [prompt_injection]          # the categories this engagement authorizes; same coupling
    limits:
      max_model_requests: 20                     # 1 to 200
      max_input_tokens: 500                      # per request, 1 to 4000
      max_output_tokens: 300                     # per request, 1 to 2000
      max_total_tokens: 20000                    # 1 to 200000
    rules:                                       # every one REQUIRED, and the only accepted value is `forbidden`
      tool_invocation: forbidden
      persistent_state_writes: forbidden
      personal_data_in_probes: forbidden
      target_output_to_assistant_model: forbidden
```

### Rules, in the order they are checked

1. **Strict like the rest**: unknown keys, wrong types, duplicate keys, aliases and so on are refused as in `scope-format.md`.
2. `id` is unique. `host`/`scheme`/`port` follow the canonical rules; two AI targets with the same scheme, host and port are
   refused, not merged (`SCOPE-005`). The same host may also appear in `allowed_targets`: an AI target grants **no**
   dns, tls or http operation (D-E34); list the host there if you want those.
3. `layer` must be `application` (`SCOPE-011`).
4. Every key under `rules` must be present and equal `forbidden`. `allowed` is refused with "not available in this version"
   (`SCOPE-011`), so the document a client reads states what will not happen.
5. `environment: production` needs `production_approval_ref`, and the reference is accepted **only** with `production` (a stale
   reference must not lend assurance to a test environment) (`SCOPE-011`).
6. `operations` is a non-empty subset of the global `allowed_operations`; an AI operation allowed globally that no AI target
   uses is refused (`SCOPE-009`).
7. `ai_metadata` needs `metadata_paths` (exact paths); `ai_probe` needs `probe_path`, `probe_sets` and `test_categories`. Each
   of those fields is **valid only with its own operation** (`SCOPE-009`), so a scope can never grant a path or a probe that
   no operation uses. The only paths an AI target may be contacted at are `metadata_paths` (GET) and `probe_path` (POST).
8. Every probe-set id must exist in the library (`SCOPE-011`), and its category must be in `test_categories`
   (`SCOPE-011`). The library is code the project reviews; a scope cannot define a set.
9. **Consumption must fit.** The probes the sets contain (one request each) must be at most `max_model_requests`, and
   `requests * (max_input_tokens + max_output_tokens)` must be at most `max_total_tokens` (`SCOPE-007`). Unlike the global
   `max_requests`, which may be smaller than the plan and then ends the run incomplete (exit 2), these limits are the client's
   spending and safety cap, so a plan that cannot fit is refused up front.
10. Limits are inclusive integer ranges as listed (`SCOPE-007`).

## The hash and the plan

* **The hash.** An AI target is part of the normalised scope, so changing a limit, a probe set or a rule changes the scope hash and
  voids any approval bound to it. A scope with **no** `ai_targets` hashes exactly as before: the key is left out when the list is
  empty, so scopes written before this feature keep their hash.
* **The plan.** After the web entries (unchanged, D-E23), each AI target in file order contributes: one `ai_metadata` operation per
  `metadata_paths` entry, then one `ai_probe` operation **per probe** (a set of three probes is three operations), in the order
  the sets are listed. An AI target contributes no dns, tls or http operation.

## The probe library (D-E30)

A probe set is a reviewed, versioned, fixed list of probes with one **category**, written as data in the repository. A scope
refers to a set by id (for example `canary-echo-v1`). Nothing at run time can add, edit or generate a probe: not the scope, not a
target's reply, not the assistant model.

| Probe set id | Category | Probes |
|---|---|---|
| `canary-echo-v1` | `prompt_injection` | 2 |
| `canary-instruction-in-data-v1` | `prompt_injection` | 3 |
| `system-prompt-canary-v1` | `system_prompt_leakage` | 2 |
| `seeded-data-canary-v1` | `sensitive_information_disclosure` | 2 |
| `output-structure-v1` | `output_handling` | 2 |

In 0.x the library registers **ids, categories and probe counts** so scopes validate and plans are exact. The probe *texts* arrive
with the adapter in M2, as a reviewed change, together with their expected results. Probes are benign by construction: they use
**canary tokens** (a random string the tool generated and can recognise) to test whether a system follows injected instructions or
leaks hidden context, and they contain no real data and ask for no action.

| Category | What a probe set under it checks |
|---|---|
| `prompt_injection` | whether text the system treats as data is followed as an instruction (a canary appears in the reply) |
| `system_prompt_leakage` | whether hidden configuration text is reproduced (a canary planted in an authorized test deployment appears) |
| `sensitive_information_disclosure` | whether data a test deployment was seeded with (canaries) is returned to an unauthorized asker |
| `output_handling` | whether the reply contains structure a downstream consumer could mis-handle (markup, links, code blocks), recorded as structure only |

The names are this project's own and are not mapped to an external taxonomy here; mapping them is a documentation task for later.

## What is recorded

Two new observation types (payloads in `fixture-format.md`), both **facts, never verdicts**:

* `ai_metadata`: the status, headers (redacted) and a bounded summary of a metadata read, for example the list of model ids a
  `/v1/models` endpoint returns.
* `ai_probe`: which probe, the tokens the exchange used, the reply's **length and SHA-256**, whether the canary appeared (a
  substring check), the finish reason, and structural flags (`contains_html`, `contains_markdown_link`, `contains_code_block`,
  `contains_url`). The reply itself is stored only as a **redacted artifact** under the retention rules. Whether a canary
  appearing is a vulnerability is a human reviewer's judgement, never a field.

An AI reply that *says* it called a tool, sent a message or changed something is text. The tool cannot call a tool, so the claim
is recorded as a claim and is not evidence that anything happened.

## What a human still decides

Whether the engagement is authorized (the scope is a restriction, not proof), whether a reply is a finding, how serious it is,
and whether any output may ever be shown to the assistant model. That last switch exists in the format
(`target_output_to_assistant_model`) and is `forbidden` until a decision says otherwise.
