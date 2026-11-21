# Fixture packs and the observation schema

A **fixture pack** is one YAML file that stands in for the network: it answers DNS, TLS and HTTP questions for
the hosts a scope names. An offline adapter reads it; nothing else supplies data (D-E01). Packs are untrusted
input, like a real target: they are parsed with the same strict loader and size caps as a scope.

```text
fixtures/
  approved_scope/        scope files that validate (healthy, misconfigured, poisoned)
  web_responses/         the packs: healthy.yaml, misconfigured.yaml, poisoned.yaml
  poisoned_text/         a library of injection payloads used by the adversarial tests
  expected_observations/ the golden normalised output for each pack
```

## Pack layout

```yaml
pack: healthy                              # a name, [a-z0-9-]{3,40}
dns:
  lab.example.invalid:
    status: ok                             # ok | nxdomain | no_data | timeout | error
    records: {A: ["192.0.2.10"], AAAA: ["2001:db8::10"]}
tls:
  "lab.example.invalid:443":
    status: ok                             # ok | handshake_failed | timeout | error
    version: TLSv1.3
    certificate:
      subject_cn: lab.example.invalid
      issuer_cn: Example Lab CA
      san_dns: [lab.example.invalid]
      not_before: '2026-06-01T00:00:00Z'
      not_after: '2027-06-01T00:00:00Z'
      signature_algorithm: ecdsa-with-SHA256
      public_key: {type: ec, bits: 256}
      self_signed: false
      sha256_fingerprint: "<64 hex>"
http:
  "https://lab.example.invalid:443/robots.txt":
    status: 200
    headers: {content-type: ["text/plain"], server: ["lab"]}
    body: "User-agent: *\nDisallow: /admin\n"
```

Only documentation addresses (`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`, `2001:db8::/32`) and reserved
names (`.invalid`, `.example`) appear in fixtures. A fixture never contains a real credential: secrets are
obvious placeholders (`SYNTHETIC-COOKIE-0001`) and the tests build token-shaped values at run time, so the
secret scanner never has a real-looking secret in history to find.

A request the pack does not answer is a **recorded error** (`adapter_error`), never an empty success.

## The normalised observation (what adapters must emit)

Every observation has an envelope and a typed payload. Payload models are strict (unknown fields refused).

| Envelope field | Meaning |
|---|---|
| `adapter` | `offline_dns`, `offline_tls`, `offline_http` |
| `observation_type` | `dns_metadata`, `tls_metadata`, `http_metadata` |
| `target` | `{host, scheme, port}` canonical |
| `normalized_input` | the request answered, for example `GET https://lab.example.invalid:443/robots.txt` |
| `error_status` | `ok`, `timeout`, `dns_failure`, `tls_failure`, `http_error`, `refused_by_policy`, `budget_exhausted`, `size_limit`, `parse_error`, `adapter_error` |
| `payload` | the typed document below |

**`dns_metadata`**: `host`, `status`, `records` (`A`, `AAAA`, `CNAME`, `NS`, `MX`, `TXT`, `CAA`; each at most 32
entries of at most 255 characters).

**`tls_metadata`**: `host`, `port`, `status`, `tls_version` or null, `certificate` or null (`subject_cn`,
`issuer_cn`, `san_dns`, `not_before`, `not_after`, `signature_algorithm`, `public_key {type, bits}`,
`self_signed`, `sha256_fingerprint`). It holds **facts**, never "expired": whether a certificate is expired is
a rule evaluated later against the run's clock, so a stored observation never goes stale.

**`http_metadata`**: `host`, `port`, `scheme`, `path`, `method` (`GET` or `HEAD`), `http_status` or null,
`headers` (lower-case names, at most 64, values redacted by name and shape), `redirect_location` (recorded, never
followed), `body` or null (`size_bytes`, `truncated`, `content_type`, `artifact_sha256`, `parsed`).
`parsed` is a small bounded document extracted from known paths (security.txt fields, an OpenAPI summary, robots
directives); it is never executed or fetched from.

## AI-system packs

A pack may also hold an `ai:` section (`docs/ai-targets.md`). Its keys are an exact metadata URL or a probe key
`probe:<ai target id>:<probe set>:<index>`:

```yaml
ai:
  "https://assistant.example.invalid:443/v1/models":
    status: 200
    headers: {content-type: ["application/json"]}
    body: '{"object": "list", "data": [{"id": "support-bot-1"}]}'
  "probe:support-bot:canary-echo-v1:0":
    canary: "CANARY-5A1E9C02"          # the string the probe planted; null when the probe plants none
    status: 200
    headers: {content-type: ["application/json"]}
    body: '{"choices": [{"message": {"role": "assistant", "content": "..."}, "finish_reason": "stop"}],
            "usage": {"prompt_tokens": 120, "completion_tokens": 14}}'
```

Two more observation types, **facts, never verdicts**:

**`ai_metadata`**: `host`, `port`, `scheme`, `path`, `http_status` or null, `headers`, `model_ids` (at most 50 names of at most 128
characters, read from a `data[].id` list), `body` (as for HTTP) or null.

**`ai_probe`**: `ai_target_id`, `probe_set`, `probe_index`, `category`, `http_status` or null, `input_tokens` and `output_tokens`
(the target's own `usage`, or null), `finish_reason` or null, `output_chars` (the reply's length as received) or null,
`canary_present` (a substring check, null when the probe plants no canary) or null, `flags` (`contains_html`,
`contains_markdown_link`, `contains_code_block`, `contains_url`: structure present in the reply, nothing more) or null, and
`artifact_sha256` of the redacted reply or null. Nothing says a reply is a vulnerability.

## Plan order

For each target entry in file order: one DNS lookup (recorded against the first target row of that host), one TLS
handshake per `https` port, then one HTTP request per `allowed_paths` entry in file order (D-E23). The goldens list
observations in exactly this order.

## Goldens

`expected_observations/<pack>.json` lists, in order, the envelope fields without the time-dependent ones
(`collected_at`, row ids) for the scope of the same name. M1 checks that every golden **conforms to the payload
schemas**; M2 checks that the adapters **reproduce them exactly**. A change to a golden is a reviewed change to
the contract.
