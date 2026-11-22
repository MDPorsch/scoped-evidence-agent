# Stage 2 design: safe web and API checks (for the owner to read BEFORE any code is written)

**Status: approved by the owner on 2026-11-22 (D-E89 to D-E94, as written). Piece 2a (group A) is built (`docs/milestones/M7-2a.md`); the rest is not.** Nothing in this document changes the tool by
itself. It describes what Stage 2 adds, what each check sends to a target and what it records. It is built in the pieces named in section 8,
each its own pull request that the owner reviews and merges.

## 1. What Stage 2 adds, in one paragraph

Today the tool asks a site for a handful of pages and reads what comes back. Stage 2 makes it look harder at what it already has, ask for a few
more things the site was always free to answer, send a very small set of harmless marker strings, and, for APIs, compare what different test
users can see. Every check is tied to an OWASP category (the catalogue from Stage 1), produces a **draft** for a person to review, and is **off
unless the scope switches it on.**

## 2. What stays forbidden (D-E83), whatever the scope says

Exploitation of any kind; chaining attacks; extracting data (a response body is never stored: only yes/no facts about it); guessing or
brute-forcing logins or ids; bursts of requests or anything resembling load; any request that changes state (**GET, HEAD and OPTIONS only**:
today the scope and the job format enforce it, and Stage 2 adds the collector as a third check); request bodies; finding hosts; following redirects; making the target
contact a third party (no "fetch this URL" tests).

## 3. The checks

Four groups. Each row says what is sent, what is recorded, and the OWASP category it answers.

### Group A. Read what we already collect more carefully (sends nothing new)

| Check | OWASP | Looks at | Draft says |
|---|---|---|---|
| A1 Cookie flags | Top 10 A02 | the `Set-Cookie` headers already collected: name and the `Secure`, `HttpOnly`, `SameSite` flags (**never the value**, which is redacted today) | "a cookie named X lacks Secure / HttpOnly" |
| A2 Header quality | Top 10 A02 | headers already collected: a Content-Security-Policy with `unsafe-inline` or `unsafe-eval`, a short or missing HSTS `max-age`, a missing Referrer-Policy | "the policy allows X" (your site's CSP allows both today) |
| A3 Spec drift | API9 | the API description already collected, compared with the endpoints your scope lists | "N documented endpoints are not in the scope" |

### Group B. A few extra read-only requests (needs the scope's opt-in)

| Check | OWASP | Sends | Records | Draft says |
|---|---|---|---|---|
| B1 Exposed files | Top 10 A02 | one GET each for a **fixed list of 8 paths** (section 5) | status, size, and **yes/no: did the start of the answer match the known signature** (never the content) | "/.git/HEAD answers like a git repository" |
| B2 Error page | Top 10 A02, A10 | one GET to a made-up path, `/sea-` plus a random token | status, and yes/no flags: does the page show a stack trace, a product and version, or a debug message | "an unknown path shows a stack trace" |
| B3 Allowed methods | Top 10 A02 | one OPTIONS to each listed path (APIs already have this) | the `Allow` list | "TRACE is allowed" |

### Group C. Harmless marker probes (D-E83; needs the scope's opt-in and its own acknowledgement)

For each parameter **you list** on a path **you list**, up to 3 requests, each a GET with one inert value from the fixed list in section 5:

| Check | OWASP | Sends | Records | Draft says |
|---|---|---|---|---|
| C1 Reflection | Top 10 A05 | the plain token | yes/no: does it come back in the page, and is the surrounding text HTML | "the input is reflected" (not yet a weakness) |
| C2 Encoding | Top 10 A05 | the token with `"` and `<` `>` in it | yes/no: did the characters come back **unencoded** | "angle brackets are reflected unencoded: a possible cross-site scripting point, check by hand" |
| C3 Database error | Top 10 A05 | the token with one `'` in it | yes/no flags for the named database-error and stack-trace patterns, and whether the page changed a lot from C1 | "a lone quote produces a database error message" |

These send nothing that could run, steal or change anything: no script tags, no SQL keywords, no path tricks, no URLs. A reflection is a
reason to look, never a finding.

### Group D. API checks across test users (needs two or more test accounts; GET only)

| Check | OWASP | How it works | Draft says |
|---|---|---|---|
| D1 Object access | API1 | your scope says which object belongs to which test user; the tool asks for user B's object **as user A** and compares the *shape* of the answers | "user A could read an object that belongs to user B" |
| D2 No login | API2 | the scope marks an endpoint as needing a login; the tool asks for it with no credential | "an endpoint that should need a login answered without one" |
| D3 Sensitive properties | API3 | the property **names** in answers (already recorded as the shape) against a fixed list: `password`, `password_hash`, `secret`, `token`, `api_key`, `ssn`, `card_number`, `private_key` | "a response includes a property named X" |
| D4 Admin endpoints | API5 | the scope says which role an endpoint needs and which role each test user has; the tool asks as users who lack it | "a user without the role got a normal answer from an admin endpoint" |

Not covered by Stage 2, and `benchmarks status` will keep saying so: API4 (resource consumption: it would mean load), API6 (business
flows), API7 (server-side request forgery: it would make the target contact a third party), API10 (unsafe consumption), and most of
the web list (access control beyond the API, authentication flows, integrity, supply chain).

## 4. How a scope switches this on (D-E90)

Nothing is on by default: **a scope with no `checks` block behaves exactly as today.** A proposed shape:

```yaml
checks:
  passive: [cookie_flags, header_quality, spec_drift]            # group A: no new request
  extra_requests: [exposed_files, error_page, allowed_methods]   # group B
  markers:                                                       # group C: only where you name the path and the parameter
    - {host: breachrr.com, path: /search, params: [q]}
api_targets:
  - id: orders-api
    authz_checks: [object_access, no_login, sensitive_properties, admin_endpoints]   # group D
    principals: [{id: tenant-a-user, role: editor}, {id: tenant-b-user, role: viewer}]
    endpoints:
      - {id: project, method: GET, path: '/projects/{id}', requires_login: true, owned_by: {tenant-a-user: ['p1'], tenant-b-user: ['p2']}}
```

* The block joins the scope's hash, so an approval covers exactly these checks and a changed scope needs a new approval.
* `approvals grant` prints the checks the scope switches on before you confirm.
* A live run that includes group C needs its own flag, **`--ack-active-probes`**, as well as `--ack-authorization`.
* Every probe request counts against `max_requests`, so the budget is still a hard stop.
* Test-account tokens are named by environment variable (`--credential`), as today: never in a file, never in chat.

## 5. The fixed lists (D-E91): the only things the tool may send that you did not write

A scope names a check; it can never supply a value. The texts live in the repository and change only by a reviewed pull request, like the AI
probe library. The job sent to the container carries a probe **id**, and the collector reads the text from its own copy inside the image.

**Marker values** (`T` is `sea` plus 12 random lowercase hex characters, new for every run, shown in the report):

| Id | Sent as the parameter's value |
|---|---|
| `marker-plain-v1` | `T` |
| `marker-quote-v1` | `T'` (one single quote) |
| `marker-chars-v1` | `T"<>` (a double quote and angle brackets) |

**Exposed files** (GET, first 4 KiB inspected inside the container, only a yes/no leaves it):

| Path | Matches if it starts or contains |
|---|---|
| `/.git/HEAD` | `ref: refs/` |
| `/.env` | at least two `NAME=value` lines |
| `/.DS_Store` | the file's fixed signature bytes (`Bud1`) |
| `/server-status` | `Apache Server Status` |
| `/phpinfo.php` | `PHP Version` |
| `/actuator/env` | `propertySources` |
| `/metrics` | `# HELP` |
| `/debug/pprof/` | `Types of profiles available` |

This is a small wordlist, which the earlier design avoided; here it is eight fixed, reviewed paths with signatures, and you decide whether to allow it.

## 6. Safety rails

* **Pace:** 1 request per second by default, never above the scope's rate cap; no retries; no parallel requests to one host.
* **A circuit breaker (D-E93):** after 3 answers in a row that are server errors (5xx) or "slow down" (429), or 2 timeouts in a row, the tool
  stops sending probes to that host, marks the run **incomplete** and says why. It never pushes on.
* **Nothing stored but facts:** no response body from a probe is kept; flags and sizes only.
* **Hostile answers stay data:** the existing rule that nothing a target says is obeyed, quoted or fed to a model applies to every probe answer.
* **Every probe is in the audit trail:** the check id, the probe id, the parameter name and the status.
* **Offline first:** every check is built against recorded answers (fixture packs) with tests, including a target that tries to inject text into its
  answers, before it ever runs live.

## 7. How I would verify it before touching any real host

1. All tests and the mutation suite, as for every change.
2. Run it against **the lab you built** (the vulnerable variant of tenant-boundary-lab, which has known flaws) through the real container
   (the Docker bridge range listed in `egress.allowed_networks`), and check it finds the flaws it should and nothing it should not.
3. Only then your own site, starting with groups A and B; group C only if you say so.

## 8. How to build it: four pull requests

I recommend this order, each its own reviewed pull request:

1. **2a, group A.** No new request at all, so it is the safest first step and the quickest to show value.
2. **2d, group D (API).** Uses only the kind of request the API scope already allows (GET as different test users).
3. **2b, group B.** The extra read-only requests and the fixed path list.
4. **2c, group C.** The marker probes and their acknowledgement flag, last, because they are the part that sends input.

## 9. Honest limits

Reflection is not a vulnerability, and an absent reflection is not proof of safety (a firewall, a script-rendered page or a different parameter
changes it). Group D finds only the problems your declared ownership and roles can express. False positives and negatives are certain, which
is why every result is a draft with steps a person runs by hand. The tool will still not "cover the OWASP Top 10".

## 10. Decisions (all approved by the owner, 2026-11-22: "agree with all")

| ID | Decision | Status |
|---|---|---|
| D-E89 | The four groups of checks and what each sends, as tables 3A to 3D | approved |
| D-E90 | A `checks` block that is off by default, joins the scope hash, is printed at approval, plus `--ack-active-probes` for group C | approved |
| D-E91 | The fixed lists: the three marker values and the eight exposed-file paths, exactly as in section 5 | approved |
| D-E92 | Group D needs you to declare, in the scope, which test user owns which object and which role each user has | approved |
| D-E93 | The circuit breaker thresholds (3 server errors or 429s, or 2 timeouts, in a row) | approved |
| D-E94 | The build order 2a, 2d, 2b, 2c | approved |

The owner approved all six, including the three marker values and the eight paths exactly as listed, and the build order. A group can still be dropped later by saying so.
