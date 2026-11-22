# Live remote mode: design for your review

**Status: approved by the owner on 2026-11-20 (D-E37 to D-E47). Built in M6 (this change), as the last milestone, and stopped for
review. The controller has been exercised against loopback servers with the container replaced by a stand-in, and once end to end through a real
container against the owner's own site. The container isolation has been run for real in CI and on a Mac (seven tests, see
`docs/milestones/M6.md`); nothing else has been targeted (D-E46; see "How it is built" at the end).** By D-E47 it is built last, after the offline collectors,
test-first, and then stops again for review. You asked for this tool to work
against remote, authorized targets too. That changes **egress** (the tool opens connections to networks you do not control),
**token handling** (an AI endpoint's API key crosses a network) and, for AI probes, **what the tool sends** (a POST). You told me
to stop and review changes like these before they ship, and the spec says the same: live mode is optional, separate, and not
labelled safe until it has been exercised under real isolation.

It is built **last** (spec M5), after the offline milestones pass, and as its own change. Offline mode stays exactly as it is: no
socket, deterministic, and the autouse test guard that blocks sockets keeps protecting it.

## 1. Goal and non-goals

**Goal.** Collect the same bounded evidence (DNS, TLS, HTTP metadata, AI endpoint metadata and fixed probes) from the **exact
hosts a scope lists**, and keep the guarantees that make it safe to point at someone else's system: it cannot be talked into a
different host, network, protocol, volume or action than the assessor wrote down, and a hostile response cannot reach the
operator's machine or the rest of the network.

**Non-goals.** Discovery, crawling, subdomain or port scanning, brute force, credential attacks, exploitation, following
redirects or CNAMEs, proxies, cookies or login flows, invoking an AI agent's tools, turning certificate verification off for
anything that sends data, and any third-party or model call that carries target data.

## 2. The idea in one picture

```text
 HOST (controller: trusted, small)                      CONTAINER (collector: assumed hostile-input-exposed)
 ----------------------------------                     -------------------------------------------------
 scope + approval record + --ack     ──validate──►      (starts with NO network)
 resolve each declared host ONCE
 judge EVERY address (policy 4.3)
 compute allow-list = pinned IP:port   ──────────────►  firewall applied from the allow-list, capabilities dropped
                                                         self-test: forbidden destinations must FAIL  ──► proof
 refuse to continue unless proof passed ◄───────────────
                                                         connect ONLY to a pinned IP, verify peer, TLS
                                                         parse + normalise + redact the hostile response
 accept only schema-valid observations  ◄── one-way ──   write observations + redacted artifacts (size-capped)
 re-validate, store, audit
```

Two layers must agree before a byte leaves: the **controller's policy** (which addresses are acceptable at all) and the
**container's firewall** (which addresses are reachable at all). A bug in the first is caught by the second, which the spec
requires: a hostname check alone is not accepted as an SSRF defence.

## 3. What changes, and what does not

| | Offline (0.x today) | Live |
|---|---|---|
| Entry point | `run --fixture` | **`live run`** only. `run` never opens a socket |
| Data source | fixture pack | the declared hosts, through the container |
| Methods | n/a | `GET`/`HEAD` for metadata; **one `POST` per `ai_probe`**, built only from the reviewed probe library |
| Hosts | the scope's list | the scope's list (at most **10** in live mode), each exact, none discovered |
| Addresses | n/a | public by default; private only if listed; metadata, link-local and IPv4-embedding IPv6 never (4.3) |
| Authorization | a scope's `owner_approval_ref` label | **block + `--ack-authorization` every run + an approval record bound to the scope hash** (4.2) |
| Credentials | none | AI targets only, from an environment variable, sent only to the declared host over verified TLS (4.5) |
| Redirects, CNAMEs | recorded | **recorded, never followed or resolved** |
| Parsing hostile data | in the test process | **inside the container only** (4.7) |

## 4. The controls

### 4.1 Hosts: exact, listed, capped

Live mode uses the scope's own exact `allowed_targets` and `ai_targets` (no wildcard, no IP literal unless listed in
`allowed_networks`, canonical names only). At most 10 distinct hosts. Anything the target says about *other* hosts (a CNAME, a
redirect `Location`, a name inside a JSON body) is recorded as data and never contacted, so scope cannot grow while it runs.

### 4.2 Authorization: three things, all required

```yaml
mode: live
authorization:                       # new, required for mode: live
  engagement: "ACME-2026-114"        # your reference; free text
  not_before: '2026-11-20T00:00:00Z' # optional
  not_after:  '2026-12-04T23:59:59Z' # required, at most 366 days after not_before
egress:                              # new, optional
  allowed_networks: [10.20.0.0/16]   # private ranges reached over a VPN; never covers the always-refused ranges
  max_requests_per_second: 2         # default 2, at most 10
```

1. The **block** is what the report quotes: *"Authorization was declared by the operator for engagement ACME-2026-114 and is not
   verified by the tool."*
2. `--ack-authorization` on **every** `live run` is the human saying "yes, now". A scope copied into CI does nothing without it.
3. An **approval record**, created by a human command (`scoped-agent approvals grant --scope-sha256 ... --until ...`, which asks
   for typed confirmation), is stored with the scope hash, the OS user and an expiry no later than the scope's. `live run
   --approval-id ID` refuses a missing, expired, revoked record or one whose hash no longer matches the scope. Editing the scope
   invalidates the approval. In a single-user tool the approver and the operator are the same account; the record is a
   deliberate pause and an audit entry, not a second person (LIMITATIONS SE-03).

The run also refuses outside the window, and a loopback-only scope needs none of this, as in `boundarycheck`.

### 4.3 Which addresses it will connect to

The controller resolves each declared name **once**. **Every** returned address must pass or that host is not contacted at all.
The allow-list handed to the container is the set of pinned `IP:port` pairs, so there is no second lookup to rebind.

* **Always refused, even if listed:** `0.0.0.0/8`, link-local `169.254.0.0/16` and `fe80::/10` (cloud metadata lives here),
  multicast, broadcast, the unspecified address, any IPv6 form that **embeds** an IPv4 address (IPv4-mapped, NAT64, 6to4,
  Teredo), and IPv6 zone ids.
* **Allowed by default:** globally routable addresses.
* **Only if the scope lists the range:** loopback, RFC 1918, `100.64/10`, unique-local `fc00::/7`.
* After connecting, the **peer address is read back** from the socket and must equal the pinned address.

### 4.4 Real egress isolation (the spec's requirement)

The collector runs in a container started by the controller from an image **pinned by digest** (`name@sha256:...`, or, for an image
you built on this machine, its bare `sha256:...` ID: see D-E81), with: a read-only root
filesystem, a tmpfs scratch area, no mounts except one write-only output directory, `no-new-privileges`, all capabilities dropped
after setup, a non-root user, a CPU, memory and process-count limit, and a wall-clock limit enforced from outside.

Networking: the container starts with no route out. The controller passes the pinned `IP:port` allow-list; a setup step with
`NET_ADMIN` installs a **default-deny OUTPUT policy that permits only those pairs** (and loopback), then drops the capability
before the collector starts. The container has **no DNS access**; the controller did the resolving.

**Proof before collection.** The first thing the container does is a self-test: connecting to a documentation address
(`192.0.2.1`), to the host's gateway address, to a private range and to a metadata address must **fail**, and connecting to a
pinned address must be **permitted by the rules** (checked by reading them, without contacting the target). The result is sent to
the controller, which **refuses to continue unless every check passed** and records the proof in the audit trail and the report.
There is no "I promise this is isolated" flag.

*Platform honesty.* This needs a Linux network namespace: Linux CI, or Docker through Colima on macOS (a Linux VM). A machine
without a working container runtime cannot run live mode at all; it fails closed with `LIVE-001` and offline mode is unaffected.
Docker's own networking and your VM's firewall are part of the trust base; the self-test is what shows they behaved.

### 4.5 TLS and credentials

* **No application data is ever sent on a connection whose certificate failed verification.** Verification uses the system trust
  store plus an optional `ca_bundle` (which adds trust, never removes verification); the host name checked and sent as SNI/`Host`
  is the declared one while the TCP connection goes to the pinned address. TLS 1.2 or newer.
* `tls_metadata` is the one operation that may complete a handshake with a certificate that **fails** verification, because it
  sends nothing after the handshake: it records the certificate facts and **the verification result as a fact** (expired,
  self-signed, name mismatch), which is exactly the evidence an assessor wants. It cannot enumerate old protocol versions; that is
  a scanner's job and out of scope.
* **Credentials exist only for AI targets** that need an API key: `credential: {env: NAME}` with a bearer token or one named
  header (never `Host`, `Cookie` or framing headers). The value is read from the environment, sent only to the declared host over
  verified TLS, held only inside the container's memory, never written to disk, a log, a report or an artifact, and never sent to
  a model. Every stored byte (reports, artifacts, logs, audit reasons) is scanned for the value before it is accepted, and a
  match fails the run. No cookies, no login flows, no keychain in the first live version.

### 4.6 Load, redirects and proxies

Default **2 requests per second** across the run, at most **10**, serial, one connection per operation, the scope's per-request
timeout and byte cap, the scope's request budget (a hard stop, reserved atomically as in M1). AI targets also stay inside their
own `max_model_requests` and token limits (`docs/ai-targets.md`). A 3xx is recorded with its `Location` as data and never
followed. Proxy environment variables are ignored; a proxy is not supported.

### 4.7 Hostile data stays in the sandbox

The container does the network I/O **and** the parsing, normalising and redaction of what comes back. It writes only
**observation envelopes** and **redacted artifacts** to the output directory. The controller treats that directory as untrusted:
it re-validates every envelope against the strict schemas, caps the file count and sizes, refuses anything else, and only then
stores, hashes and audits. A response that breaks a parser compromises a throwaway container with no network and no secrets
beyond the one API key, not the machine holding the evidence database.

### 4.8 What lands on disk

Unchanged from offline: redacted artifacts only, `0600`/`0700`, content-addressed, 30-day default retention, an append-only chain
of audit events. A live run adds to the report: each host, the addresses it resolved and pinned, the engagement reference, the
approval record id, and the **isolation self-test result**. The report states whether the proof passed; a run that could not
produce it does not exist.

## 5. Threats this design answers

| # | Threat | Answered by |
|---|---|---|
| L1 | A typo or copied scope sends traffic or a key to the wrong host | 4.1 exact hosts, 4.2 three-part authorization |
| L2 | SSRF: the name resolves to loopback, a private range or the metadata address | 4.3 policy **and** 4.4 firewall |
| L3 | DNS rebinding | 4.3 one resolution, pinned addresses, peer re-check, no DNS in the container |
| L4 | The policy code has a bug | 4.4: the firewall still refuses, and the self-test proves it |
| L5 | A redirect or CNAME widens scope | 4.1, 4.6: recorded as data, never followed |
| L6 | A hostile response attacks the parser or the operator | 4.7 sandbox, schema re-validation, size caps |
| L7 | A key leaks into evidence | 4.5 leak guard over every stored byte |
| L8 | A key goes over a broken or downgraded connection | 4.5 verified TLS before any data |
| L9 | An AI probe has a side effect | no tool invocation, fixed library probes, per-target limits (`ai-targets.md`) |
| L10 | Load or cost on the client | 4.6 rate, budget and token limits |
| L11 | Run outside the engagement, or by accident from CI | 4.2 window, `--ack`, approval record |
| L12 | The tool becomes a scanner | 4.1: no discovery, at most 10 listed hosts, nothing learned from a target is ever contacted |

## 6. What this does not guarantee

* **Authorization.** The tool cannot verify you may test a host. You attest; the report says so.
* **A compromised machine or a compromised container runtime.** Isolation relies on the kernel, the runtime and the VM; it is
  strong, not absolute.
* **CDNs and shared hosting.** A public address cannot be pinned to "the client's" machine.
* **What a probe causes on the client's side.** Probes are benign and bounded, but a target can behave unexpectedly; the scope's
  `environment` and your own judgement matter.
* **Old TLS versions, cipher inventories, vulnerability proof.** Out of scope on purpose.
* **Your clock.** The window uses the local clock.

## 7. Tests this design commits to (written first, red first)

Policy: every always-refused address form, private ranges refused unless listed, one private address among public ones refuses the
host, a second DNS answer never used. Isolation (real container, Linux): the self-test blocks `192.0.2.1`, the gateway, a private
range and a metadata address; a collector that tries to connect elsewhere **fails at the firewall even when the policy is
bypassed on purpose**; the run refuses when the self-test fails or the runtime is missing. TLS: good, untrusted CA, wrong name,
expired, plaintext, downgrade: no data and no key received by the server in any refusal; `tls_metadata` records the failure as a
fact. Credentials: the key reaches only the declared host, appears in no stored byte, and a seeded leak fails the run. Sandbox: an
output directory with an extra file, an oversized artifact, a malformed envelope and a path traversal are all refused. Authorization:
no block, no flag, expired, not yet valid, a changed scope invalidating its approval. AI: only library probes are sent, nothing
outside the scope's limits. First **real** exercise: against a local lab target the owner controls (the project-1 lab in a
container), before anything is called safe.

## 8. Decisions I need from you

| ID | Decision | My recommendation |
|---|---|---|
| D-E37 | Live only through `live run`; `run` never opens a socket | yes |
| D-E38 | Real egress isolation is mandatory and proved by a self-test before collection; no promise flag | yes |
| D-E39 | Address policy as in `boundarycheck` (public default, private only if listed, metadata/link-local/embedding IPv6 never), one resolution, pinned addresses | yes |
| D-E40 | Verified TLS before any data; `tls_metadata` may observe a failing certificate because it sends nothing | yes |
| D-E41 | Authorization = block + `--ack-authorization` each run + an approval record bound to the scope hash | yes |
| D-E42 | Credentials only for AI targets, from the environment, bearer or one named header, leak-guarded | yes |
| D-E43 | `ai_probe` is the only non-GET live operation: one POST of a library probe, limits from the scope | yes |
| D-E44 | Hostile data is parsed only inside the sandbox; the controller accepts schema-valid output only | yes |
| D-E45 | Rate default 2/s, cap 10/s, at most 10 hosts in live mode | yes; tell me your clients' usual limits |
| D-E46 | Not called safe until the isolation has been exercised on a real container and a lab target; the report states the proof | yes |
| D-E47 | Built last (M5), after offline M2 to M4, as a separate reviewed change | yes |

## 9. Rollout

1. You review and approve (or change) D-E37 to D-E47. Nothing else moves live mode forward.
2. Offline M2 (adapters), M3 (correlator, reports) and M4 (optional AI) are built and verified first.
3. M5 implements this design, tests first, then the real-container exercise on the lab target, then stops again for your review.
4. Any real remote use, including a client system, is your decision and happens after that.

## 10. How it is built (M6) and what is not yet proved

| Piece | Where | What it does |
|---|---|---|
| Address policy | `live/addresses.py` | The `boundarycheck` rules: public by default, private only if the scope lists the range, a few ranges never; every address of a host must pass |
| Scope blocks | `policy/scope.py` | `authorization` (engagement, window) and `egress` (ranges, rate) in a `mode: live` scope; at most 10 hosts; they join the hash |
| Approvals | `storage/approvals.py`, migration `0005` | `approvals grant\|list\|revoke`: bound to one scope hash, an expiry, append-only, typed confirmation |
| Controller | `live/controller.py` | gates, one resolution per host, the proof gate, validation of the sandbox output, then the **same run pipeline** as an offline run |
| Container | `live/runtime.py`, `live/isolation.py`, `docker/collector/Dockerfile` | the whole posture in one command; firewall, self-test, privilege drop, proof, then the job |
| Collector | `live/collector.py` | the only program that connects: pinned address, peer read back, verified TLS first, serial, rate limited, normalised by the offline adapters |
| Validation | `live/outputcheck.py`, `live/leakguard.py` | only `result-N.json` and `artifact-N.bin`, strict, re-redacted, scanned for every credential in six encodings |

The order inside a run: gates (scope mode, window, `--ack-authorization`, a matching unexpired approval, every `--credential` present) →
each host resolved **once** and judged → the container is started with no route out and given only the allow-list → it installs the
firewall, runs the self-test, drops every privilege and reports → the controller refuses to continue unless every check passed and the
allow-list is the one it sent → only then is the job sent → the output is validated and scanned → stored through `execute_run` (budget,
observations, artifacts, rules, audit) → the proof, the hosts and the approval are recorded with the run and quoted in the report.
A run whose proof fails never exists.

### Decisions made in the build (approved; the stop for review is D-E47)

Status (2026-11-22): **D-E74 to D-E81 are approved by the owner (2026-11-21); D-E82 is new and pending.** That approves the decisions, not use: live mode still stops at D-E47 (not merged, and not to be used on a host you do not own, until one `live run` against a lab you own has worked end to end).

| ID | Decision |
|---|---|
| D-E74 | **`ai_probe` is refused in live mode in this version** (`SCOPE-011`). The probe texts need their own reviewed change (D-E30); nothing that a model or a scope could shape is sent. Live mode collects DNS, TLS, HTTP, AI model lists (GET) and API reads (GET, HEAD, OPTIONS). *Approved by the owner, 2026-11-21.* |
| D-E75 | **Credentials are named on the command line, never in the scope:** `--credential support-bot=ENVVAR` for an AI target, `--credential orders-api/tenant-a-user=ENVVAR` for an API principal (D-E51). The value is read from the environment, passed to the container by variable name (never in an argument), sent only as `Authorization: Bearer` to the declared host over verified TLS, and guarded. A principal other than `anonymous` without one is refused before anything starts. *Approved by the owner, 2026-11-21.* |
| D-E76 | **The collector speaks HTTP/1.0 with a `Host` header,** `Connection: close`, `Accept-Encoding: identity`: no chunked framing, no keep-alive, no redirects, no proxy, no cookie. It is deliberately the smallest client that can do the job. *Approved by the owner, 2026-11-21.* |
| D-E77 | **The stored adapter names stay `offline_*`:** they name the normalisers, which are shared. A live run is marked by `runs.mode = live` and its `live_runs` row. In a live run the stored source hash is the SHA-256 of the sandbox's own source-hash line (the controller never sees the bytes). *Approved by the owner, 2026-11-21.* |
| D-E78 | **The controller proves before it sends:** the allow-list goes in first, the proof comes out, and the job (with its credentials' *names*) is sent only after the proof is verified. There is no flag that skips it. *Approved by the owner, 2026-11-21.* |
| D-E79 | **Certificates are parsed with `cryptography`, installed in the container image only** (the `live` extra); the controller and the offline tool do not need it. *Approved by the owner, 2026-11-21.* |
| D-E80 | **Not called safe.** The container isolation has been run for real in CI (a GitHub-hosted Ubuntu runner) and on the owner's Mac (Colima), and one `live run` has gone end to end against the owner's own site (`breachrr.com`, 3 GETs, DNS and TLS), with the proof passing. No other runtime or host was tried, nothing with a login, an API or an AI endpoint was targeted, and a clean first run proves nothing about the next one. The report of a live run states the proof it got. *Approved by the owner, 2026-11-21.* |
| D-E81 | **A locally built image is pinned by its ID.** The first real CI build showed that the documented form `name@sha256:<image id>` makes Docker try to *pull* `name` from a registry: a repository digest exists only after a push. `--image` therefore also accepts the bare `sha256:<64 hex>` ID of an image built here, which is a hash of the image's content and so as fixed as a digest. A tag is still refused. (Found by the first real run of the container job.) *Approved by the owner, 2026-11-21.* |
| D-E82 | **The collector proves it can write to its output directory, and the work directory lives in the data directory.** The first run on a Mac failed because the output directory was in the system temp folder, which a VM-based Docker (Colima, Docker Desktop) does not share; the controller could only say "exited with status 1". Now the container adds one check to its proof (it writes and removes a probe file as the unprivileged user), so a mis-mounted directory ends the run with `LIVE-003` before anything is sent, and the controller keeps its per-run directory under `<data dir>/live-work` (mode `0700`, emptied after each run). A data directory outside your home still fails, clearly. (Found by the first real run; **pending your approval**.) |
