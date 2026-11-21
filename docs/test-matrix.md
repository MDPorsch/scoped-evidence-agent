# Test matrix

The spec's abuse cases AE-01 to AE-20, each with the milestone that owns it, the control, and its status.
**Status is updated only after the test exists and has been run.** `planned` means no test yet; I do not list a
case as covered because a design says it should be.

| Case | Input / failure | Expected | Owner | Status |
|---|---|---|---|---|
| AE-01 | Expired scope, missing approval, scope changed after validation | fail before any adapter | M1 (policy), M2 (before adapters) | planned |
| AE-02 | Redirect to localhost or an external host | recorded, never followed | M1 (`follow_redirects`), M2 | planned |
| AE-03 | DNS answer is loopback, private, link-local, metadata, IPv6-mapped | live denied | **M5** (no live mode in 0.x) | deferred |
| AE-04 | Host with IDN, trailing dot, upper case, userinfo, mixed encoding | canonical or refused | M1 | planned |
| AE-05 | CNAME to an unapproved domain | recorded, scope never expands | M2 | planned |
| AE-06 | Response contains prompt injection | no change to tools, scope or secrets | M2 (adapters), M4 (model) | planned |
| AE-07 | Headers contain cookies or API keys | redacted before storage and before a model | M2 | planned |
| AE-08 | Model returns invalid JSON or a hostile schema | rejected, bounded retry or deterministic fallback | M4 | planned |
| AE-09 | Model asserts a vulnerability with no evidence | kept as draft or marked unsupported | M4 (and M1: the model cannot transition) | planned |
| AE-10 | Timeout, HTTP error, DNS failure | recorded as an error, run incomplete (exit 2), never clean | M1 (taxonomy, exit codes), M2 | planned |
| AE-11 | Crash between artifact write and row, or a DB failure | atomic store, no orphan, no dangling row | M1 | planned |
| AE-12 | Two runs or workers race for one budget | no overshoot | M1 | planned |
| AE-13 | 1 MB body, zip bomb, huge header, malformed certificate | hard caps, safe errors | M1 (limits), M2 | planned |
| AE-14 | Export or purge path such as `../../secret` | traversal refused, no overwrite | M1 (artifacts, purge), M3 (export) | planned |
| AE-15 | Cancel mid-run, then retry | no lost audit, new attempt, history kept | M1 (state machine), M2 | planned |
| AE-16 | A stale observation cited by a newer run | refused by the database | M1 | planned |
| AE-17 | Model provider unavailable | deterministic offline fallback | M4 | planned |
| AE-18 | Non-GET, or a query carrying a token | refused | M1 (scope), M2 | planned |
| AE-19 | Two aliases for one host | duplicates refused in the scope; correlation dedupes only within scope | M1, M3 | planned |
| AE-20 | Content asks to widen the scope | refused and noted | M2, M4 | planned |

## Additional invariants (not in the spec's list)

| ID | Invariant | Owner | Status |
|---|---|---|---|
| X-01 | No socket is opened during an offline run | M1 (guard fixture), M2 | planned |
| X-02 | The audit trail cannot be edited or deleted, and a broken chain is detected | M1 | planned |
| X-03 | An unredacted artifact cannot be inserted | M1 | planned |
| X-04 | Files and directories have the documented permissions, and a looser store is refused | M1 | planned |
| X-05 | The model actor cannot perform any state transition; a worker cannot validate | M1 | planned |
| X-06 | The application never migrates on startup and refuses an unknown schema version | M1 | planned |
| X-07 | Every golden observation conforms to the payload schemas | M1 | planned |
