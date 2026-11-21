# Decisions

IDs are `D-E<nn>` (E for evidence agent). **Proposed** means I chose it so the work could proceed; it is not an
approval. **Review-gated** means the owner's standing rule applies (auth, egress, token handling, reporting
privacy, release credentials): it needs an explicit yes before anything is merged or published. Nothing here has
been approved yet.

## Scope and egress

| ID | Decision | Status |
|---|---|---|
| D-E01 | **Collection is offline-only in 0.x.** The only data source is a fixture pack read from disk; no socket is opened. Live mode (spec M5) is a separate, human-reviewed change that may never be built. `mode: live` parses in a scope file so files written for the future validate, but `run` refuses it with exit 1. | Proposed, **review-gated** (egress) |
| D-E02 | **A scope file is a restriction, never proof of authorization.** `owner_approval_ref` is an opaque label the operator types; the tool cannot verify it, and every report says so. | Proposed, **review-gated** (egress) |
| D-E03 | **Redirects are never followed**, and a CNAME or redirect target outside the scope is recorded as an observation, never added to the scope. `follow_redirects: true` is a validation error, not an option. | Proposed |
| D-E04 | **Host names are canonical or refused.** Accepted: ASCII letters, digits and hyphens in labels, or `xn--` labels that decode as IDNA; upper case is lowered and one trailing dot is dropped. Refused: wildcards, IP literals (no override in 0.x), userinfo, a port or path in the host field, `%`, backslash, empty labels, non-ASCII text (write the `xn--` form), more than 253 characters, and two entries that canonicalize to the same scheme, host and port. | Proposed |
| D-E05 | **`allowed_paths` are exact paths.** No prefix matching, no query, no fragment, no `..`, no `//`, no escapes. The spec's table calls the stored column `allowed_path_prefixes`; I keep that column name and store the exact paths in it. **Owner question: exact (my choice, safest) or prefix?** | Proposed |
| D-E06 | **Time.** Timestamps are UTC-aware; a naive one is refused. A scope is valid only while `now < expires_at <= now + 366 days`. The clock is injected so tests never depend on the date; the CLI uses the system clock and records the time it used. | Proposed |

## Identity, review and the model

| ID | Decision | Status |
|---|---|---|
| D-E07 | **Single-user local CLI; no pretence of enterprise auth.** `created_by` and `reviewer_id` are the operating-system user name: attribution, not authentication. The separation of operator and reviewer is a workflow rule (review commands need an explicit `--reviewer` and a typed confirmation), not access control. A web UI would need real accounts, resource ownership and sessions, and is out of scope. | Proposed, **review-gated** (auth) |
| D-E08 | **Findings: only a human reviewer can validate.** Transitions to `VALIDATED`, `FALSE_POSITIVE`, `REMEDIATED` and `VERIFIED` require a human actor, a reviewer id, a reason and at least one linked observation. A worker may create a draft and move it to `NEEDS_VALIDATION`. The model actor can perform no transition at all. | Proposed, **review-gated** (model authority) |
| D-E09 | **Exit codes.** `0` complete collection and nothing for review; `1` validation or policy failure; `2` the run could not finish its job (infrastructure failure, or any operation that errored, timed out or was refused, so the collection is incomplete); `3` complete collection with drafts that need human review. Incomplete is never `0`. | Proposed |

## Storage and evidence

| ID | Decision | Status |
|---|---|---|
| D-E10 | **SQLite through SQLAlchemy 2, migrations through Alembic, applied only by an explicit `scoped-agent db upgrade`.** The tool never migrates on startup and refuses to run against a schema version it does not know. Foreign keys are enforced on every connection and every write transaction starts with `BEGIN IMMEDIATE`. | Proposed |
| D-E11 | **The audit trail is append-only and hash-chained.** Triggers abort any UPDATE or DELETE on `audit_events`; each event stores the hash of the previous event of its run, so a removed or edited row is detectable. This is tamper-evident, not tamper-proof: someone who can replace the whole file can rewrite the chain. Adds `prev_hash` and `entry_hash` to the spec's columns. | Proposed |
| D-E12 | **Only redacted content is stored.** A CHECK constraint allows `artifacts.redaction_status` to be `redacted` or `metadata_only` and nothing else, so an unredacted artifact cannot be inserted by mistake. Files are content-addressed (`artifacts/<2 hex>/<sha256>`), written atomically (temporary file in the same directory, fsync, rename), directories `0700`, files `0600`, the database `0600`. | Proposed, **review-gated** (evidence privacy) |
| D-E13 | **Retention is short by default: 30 days** (allowed 1 to 365). `artifacts purge` deletes only files named by a recorded SHA-256 under the artifact root, refuses symlinks and anything outside the root, and writes a receipt event. | Proposed, **review-gated** (evidence privacy) |
| D-E14 | **Secrets are never stored and never sent to a model.** Where a stable match is genuinely needed, a keyed HMAC-SHA256 fingerprint is used with a random per-install key (`0600`); a bare hash of a low-entropy value is never published. By default a redacted value is the literal `[REDACTED]`. | Proposed, **review-gated** (token handling) |

## State, idempotency, budget

| ID | Decision | Status |
|---|---|---|
| D-E15 | **Run states exactly as the spec**, plus `RETRIED` as the terminal marker of a failed run that was retried. A retry is a **new run row** with `retry_of_run_id` and `attempt` (extra columns), so earlier attempts are preserved. Every transition is a compare-and-set in the same transaction as its audit event. | Proposed |
| D-E16 | **Evidence links are a table with foreign keys**, not a JSON list: `finding_evidence(run_id, finding_id, observation_id)` with composite keys that force the observation and the finding to belong to the same run. A finding cannot cite another run's observation (AE-16). The spec's `evidence_ids` is exposed as a property. | Proposed |
| D-E17 | **Idempotency:** `UNIQUE(run_id, adapter, target_id, normalized_input_hash)` on observations; adds a `normalized_input_hash` column the spec's table lacks. | Proposed |
| D-E18 | **Budget in 0.x is requests only.** A permit is reserved by one conditional UPDATE (`budget_spent + n <= total_budget`, state `COLLECTING`), so racing workers cannot overshoot. A token budget arrives with the AI adapter (M4) as an additive migration. | Proposed |

## Repository

| ID | Decision | Status |
|---|---|---|
| D-E19 | **Names:** repository `scoped-evidence-agent`, package `scopedagent`, command `scoped-agent`; Python 3.13, `uv`, `src` layout, strict mypy, Ruff, SHA-pinned GitHub Actions, gitleaks over history, CodeQL. Developed in a private repository first; going public is the owner's call. | Proposed |
| D-E20 | **Licence: Apache-2.0, copyright Mohammed Orunsolu**, the same as the other two repositories. | Proposed (please confirm for this repository) |
| D-E21 | **Layout deviations from the spec:** `LIMITATIONS.md` and `DECISIONS.md` at the root (the shared standard says so) instead of `docs/limitations.md`; extra `docs/test-matrix.md`, `docs/cli.md`, `docs/fixture-format.md`. | Proposed |
| D-E22 | **A target entry may not have more than one scheme and more than one port.** The product of the two lists would grant pairs nobody asked for (`http` on 443, `https` on 80). Write one entry per pair. Target rows are the schemes times the ports of an entry, which is at most the longer list. | Proposed |
| D-E23 | **Plan order is fixed:** for each target entry in file order, one DNS lookup, then one TLS handshake per `https` port, then one HTTP request per `allowed_paths` entry in file order. DNS is a host-level question and is recorded against the first target row of that host. A plan is therefore reproducible from the scope alone. | Proposed |
