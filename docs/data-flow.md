# Data flow

What enters, what is kept, what leaves, and for how long. Offline mode only (D-E01).

```text
scope.yaml ──► load (strict) ──► normalise ──► scope_sha256 ──► policy checks (expiry, mode, caps)
                                                                          │
fixture pack ──► offline adapter (dns | tls | http | ai) ◄─ budget permit ┘
                        │                                  (one conditional UPDATE)
                  raw fixture text   (hostile; held in memory only; collected one operation at a time, in plan order)
                        │
                  normalise ──► redact ──► typed Observation payload
                        │                         │
              redacted body bytes          observations row + audit event   (one transaction)
                        │
            artifact file (content-addressed, atomic)  +  artifacts row
                        │
              deterministic correlator ──► finding drafts (linked to observations)
                        │
              [M4: redacted, capped, typed prompt] ──► model ──► validated claims
                        │
              human review ──► report export (JSON, Markdown)
```

## What is stored, where, and for how long

| Data | Stored? | Where | Form | Retention |
|---|---|---|---|---|
| Scope file | the **normalised** scope and its hash | `engagements` | canonical JSON | until the engagement is deleted |
| Approval reference | yes, as typed | `engagements.owner_approval_ref` | opaque text | with the engagement |
| Raw fixture response | **never** | memory only; the stored `source_hash` covers the *redacted* entry | | n/a |
| Header values | redacted | `observations.normalized_json` | sensitive names become `[REDACTED]` | with the run |
| Response body | **redacted** bytes only | `artifacts` + file | content-addressed file, `0600` | **30 days** by default (1 to 365), then purged with a receipt |
| A compressed or binary body | **never** (a placeholder with its size is stored, marked `metadata_only`) | `artifacts` + file | | as above |
| Cookies, API keys, authorization values | **never** (replaced before storage) | | `[REDACTED]` or a keyed fingerprint | n/a |
| Prompt sent to a model (M4) | hash only by default | `audit_events` | model name, prompt version, input hash, budget | with the run |
| Audit events | yes, append-only, chained | `audit_events` | | with the run |
| Reviewer decision | yes | `finding_drafts`, `audit_events` | reviewer id, reason, evidence ids | with the run |

## What leaves the machine

In 0.x, **nothing**. There is no network call. An optional model adapter (M4) is disabled by default; when
enabled it receives only redacted, truncated, structured observations of one run, labelled untrusted, and never
raw bodies unless the operator sets `send_raw_body` explicitly. A report is a local file the operator exports.

## Permissions on disk

| Path | Mode | Notes |
|---|---|---|
| data directory | `0700` | `~/.local/share/scopedagent` by default, or `--data-dir` |
| `evidence.sqlite` | `0600` | created under a restrictive umask, then checked |
| `artifacts/<2 hex>/` | `0700` | |
| `artifacts/<2 hex>/<sha256>` | `0600` | written to a temporary file in the same directory, fsynced, renamed |
| `hmac.key` | `0600` | random 32 bytes, created on first need, never printed |

A permission found looser than this is a refusal to start (`STORE-003`), not a warning.

## Provenance

Every observation carries `source_hash`, the SHA-256 of the canonical JSON of the **redacted** entry it was derived from (never of a secret), and
`normalized_input_hash`, the SHA-256 of the request it answers (for example `GET https://host:443/path`).
Every artifact is named by its own SHA-256. A report lists both, so a reader can check a file against the
database and a finding against its evidence.
