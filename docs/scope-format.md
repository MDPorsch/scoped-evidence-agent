# Scope file format (contract)

A scope file is a **restriction**, not authorization (D-E02). It is parsed strictly, normalised, hashed, and then
immutable for the run. A file that is ambiguous is refused; there is no "best effort".

```yaml
engagement_id: lab-001                    # [a-z0-9][a-z0-9._-]{2,63}
owner_approval_ref: local-lab-consent     # an opaque label, 3-128 chars [A-Za-z0-9._:/#-]; NOT verified
expires_at: '2026-12-31T23:59:00Z'        # quoted, UTC-aware; now < expires_at <= now + 366 days
mode: offline                             # offline | live (live parses; `run` refuses it in 0.x)
allowed_targets:                          # 1 to 20 entries
  - host: lab.example.invalid
    schemes: [https]                      # https and/or http; tls_metadata needs https
    ports: [443]                          # 1 to 8 ports, 1-65535
    allowed_paths: ['/.well-known/security.txt', '/openapi.json']   # exact; 0 to 20; needed for http_metadata
allowed_operations: [dns_metadata, tls_metadata, http_metadata]
max_requests: 12                          # 1 to 500; every operation costs 1
max_parallelism: 2                        # 1 to 4
per_request_timeout_seconds: 5            # 1 to 30
max_response_bytes: 100000                # 1024 to 1000000
follow_redirects: false                   # must be false
```

## Loader rules

| Rule | Why |
|---|---|
| File at most 64 KiB, nesting at most 16 | a scope is small; hostile files are not |
| No YAML aliases, anchors or merge keys; no duplicate keys; keys must be strings | no hidden expansion, no silent override |
| Timestamps must be **quoted** strings, then parsed | an unquoted timestamp becomes a `datetime` in YAML and hides a missing time zone |
| Unknown keys are an error at every level | a typo must not silently drop a restriction |
| Text fields are printable ASCII; control and bidi characters refused | reports and logs stay readable and injection-free |

## Host canonicalization (D-E04)

Input is accepted only if, after the steps below, it is a valid name.

1. Lower-case it. 2. Drop **one** trailing dot (two is an error). 3. Split on `.`: each label is 1 to 63 characters,
`[a-z0-9]` at the ends, `-` allowed inside, **or** an `xn--` label that decodes with the IDNA codec. 4. The whole
name is at most 253 characters and has at least two labels.

Refused outright: `*`, an IP literal (v4 or v6, bracketed or not), `@`, `:`, `/`, `?`, `#`, `%`, `\`, whitespace,
any non-ASCII character (write the `xn--` form), an empty label. Two entries that become the same
`(scheme, host, port)` are an error, never merged silently.

## Paths (D-E05)

Each `allowed_paths` entry matches **exactly**. It starts with `/`, is at most 256 characters, uses only
`[A-Za-z0-9._~/-]`, and has no `?`, `#`, `%`, `//`, `.` or `..` segment. Matching a request is a string comparison
after the same rules; there is no prefix match.

## Cross-field rules

* An entry with more than one scheme **and** more than one port is refused (D-E22): write one entry per pair.
* `tls_metadata` requires `https` in that target's `schemes`.
* `http_metadata` requires at least one `allowed_paths` entry on the target.
* `dns_metadata` needs only the host.
* `max_requests` may be smaller than the number of operations the scope could issue (one DNS lookup and one TLS
  handshake per target port, one HTTP request per scheme, port and path). That is allowed: the run then ends with
  the remaining operations recorded as `budget_exhausted`, the collection is incomplete and the exit code is `2`.
  `scope validate` prints the planned operation count and warns when it exceeds the budget.
* `mode: live` is accepted by the schema and refused by `run` (D-E01).

## The scope hash

`scope_sha256` is the SHA-256 of the **normalised** scope: a canonical JSON document (sorted keys, no
whitespace, hosts canonical, timestamps in UTC `Z` form, lists in the order given). Reformatting the YAML does
not change it; changing what it allows does. The hash is stored with the engagement, shown in every report,
and checked again at run time, so a file edited after validation is refused.

## Errors

A refusal carries a stable code and a path to the field, never the offending value for secrets-like fields:

| Code | Meaning |
|---|---|
| `SCOPE-001` | file unreadable, too large, not UTF-8, or not valid YAML |
| `SCOPE-002` | forbidden YAML construct (alias, anchor, duplicate key, non-string key, too deep) |
| `SCOPE-003` | unknown field or wrong type |
| `SCOPE-004` | expired, not yet valid, or expiry too far ahead |
| `SCOPE-005` | ambiguous or forbidden host |
| `SCOPE-006` | bad port, scheme or path, or an ambiguous scheme and port combination |
| `SCOPE-007` | a limit is out of range |
| `SCOPE-008` | `follow_redirects` is not `false` |
| `SCOPE-009` | cross-field rule broken (operation needs something the target lacks) |
| `SCOPE-010` | the scope file changed after it was validated |
