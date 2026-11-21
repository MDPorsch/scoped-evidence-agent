"""The starter scope that `scoped-agent scope init` writes.

It is a *valid* offline scope on a reserved `.invalid` host, so a new user can validate it at once, and its comments say
what to edit and what a scope is not (D-E02). It contains no real host and no secret.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

STARTER_DAYS = 30

_STARTER = """# scoped-agent starter scope. EDIT BEFORE USE.
#   - A scope is a restriction. It is not proof that you are authorized to test anything:
#     confirm authorization outside this tool.
#   - Replace app.example.invalid with a host you are authorized to assess, and owner_approval_ref
#     with your own reference (a ticket or contract id). The tool does not verify either.
#   - Offline mode never contacts the host: it reads fixture packs. The format is in docs/scope-format.md.
engagement_id: example-engagement
owner_approval_ref: replace-with-your-reference
expires_at: '{expires_at}'
mode: offline
allowed_targets:
  - host: app.example.invalid
    schemes: [https]
    ports: [443]
    allowed_paths: ['/robots.txt', '/.well-known/security.txt']
allowed_operations: [dns_metadata, tls_metadata, http_metadata]
max_requests: 12
max_parallelism: 2
per_request_timeout_seconds: 5
max_response_bytes: 100000
follow_redirects: false
"""


def starter_scope(now: datetime) -> str:
    expires = (now + timedelta(days=STARTER_DAYS)).astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
    return _STARTER.format(expires_at=expires)
