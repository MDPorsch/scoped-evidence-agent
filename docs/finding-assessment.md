# What a draft finding says: class, exploitability assessment, validation steps

Status: **approved by the owner on 2026-11-21 (D-E56 to D-E60).** Built in M3, with the correlator, after the collectors exist.
The validation steps (below) were made more detailed at the owner's request, within the limits of D-E58 and D-E59.

You asked for the tool to decide what kind of flaw something is, name the vulnerability, say whether it is exploitable and say how
to exploit it. Most of that is the right job for this tool and is in the design below. One part is not, and the reason is written
here so you can overrule it with the facts in front of you.

## What the tool will say about every draft

| Field | What it holds | Where it comes from |
|---|---|---|
| `vulnerability_class` | one value from a closed list (for example `tls_misconfiguration`, `missing_security_header`, `information_disclosure`, `exposed_api_documentation`, `permissive_cors`, `ai_output_handling`, `ai_prompt_injection_susceptibility`) | a reviewed rule that matched the evidence |
| `cwe_candidates` | CWE ids that usually describe this class, marked as suggestions to verify | a fixed table in the rule |
| `evidence` | the observation ids behind it (already enforced by the database) | the rule |
| `conditions` | what must be true for this to matter, in plain statements | the rule, filled from the evidence |
| `exploitability.assessment` | `not_assessed`, `unlikely`, `conditional` or `likely_if_conditions_hold`. **There is no `confirmed`** | the rule |
| `exploitability.preconditions`, `attacker_position`, `unknowns`, `basis` | what an attacker would need, from where, what the evidence does not tell us, and which rule says so | the rule |
| `validation_steps` | ordered, non-destructive, read-only checks a human can run inside the engagement's rules to confirm or refute the conditions | the rule, **checked against the scope** |
| `remediation` | the usual fix, in a sentence or two | the rule |
| `suggested_severity` and `confidence` | a suggestion with its basis, and how strongly the evidence supports the class; the tool's own `severity` stays `unknown` until a person sets it | the rule |

Example, from the `misconfigured` fixture: an expired, self-signed 1024-bit RSA certificate on TLS 1.0 becomes **one**
`tls_misconfiguration` draft citing the three TLS facts. Its conditions say a client that does not pin the certificate could be
presented with a forged one and that the presented certificate cannot be chained to a trusted authority. Its assessment is
`conditional`: it matters only to clients that accept the certificate or can be downgraded. Its validation steps say to open the
service in a client that verifies certificates and record the error, and to compare the presented chain with the one on record.
Whether it is exploitable **in this engagement** is the reviewer's decision, recorded as a reviewer confirmation.

## Who decides "exploitable"

The tool states whether the *evidence* supports a way in, under which conditions, and what is unknown. It does not state that
something **is** exploitable, because it has not tried to exploit it and will not (offline it cannot; live it reads). A reviewer
runs the validation steps, or others of their own, and records `confirmed`, `not_exploitable` or `inconclusive` with a reason. That
is the only way a finding gets the word *validated*, and it is the human-only transition D-E08 already requires.

## What it will not produce, and why

The tool will **not** write exploit code, attack payloads, step-by-step attack chains, instructions that change state on a target,
guidance for abusing a specific software version, or any step that reaches a host or path outside the scope. This holds whoever
asks, including a configuration option.

* **Your own specification excludes it.** The out-of-scope list is "exploitation, ... autonomous vulnerability confirmation,
  arbitrary shell tools", and the standing rule is that a model's output is never promoted to verified fact.
* **A tool that writes attacks for any host an operator names, with only the operator's word that it is authorized, is an attack
  assistant.** The scope is a restriction, not proof of authorization (D-E02); the tool cannot tell a client engagement from a
  stranger's server. Reproduction steps that only re-check a recorded condition are different: they are what a pentest report
  needs, they cannot do harm the original request did not, and they are limited to the scope's own targets.
* **It is not what makes a report useful.** A reader needs the class, the evidence, the conditions, the impact and the fix. How an
  attacker would build a working exploit is the tester's craft, done by a person, with their own tools, under the engagement's rules.

## How the text is produced

A reviewed **rule catalogue** in the repository (data plus small functions), one rule per class, each with its tests and its
mutation check. A rule reads observations and returns the fields above. Nothing else writes them.

The optional model (M4) may **rephrase** a rule's sentences for readability and may not add a class, a condition, a step, a severity or
an evidence id. Its output is validated against the rule's output; anything the rule did not say is dropped, and a draft that fails
validation falls back to the rule's own text. The model is not told the target's replies (D-E33).

## Validation steps in detail (within D-E58 and D-E59)

A validation step is a short, ordered instruction a **person** follows to confirm or refute one condition of a draft. It is built
from a **typed template**, never from free text, so nothing a target says can become an instruction.

### What every step contains

```yaml
- order: 2
  kind: inspect_certificate_field          # one of the closed list below
  intrusiveness: single_read               # none | single_read | repeated_read (a step never exceeds this)
  target: {host: bad.example.invalid, port: 443}   # drawn from the scope; checked against it before the draft is stored
  cites: [obs-3f9a]                         # at least one observation the step is about
  condition: "the certificate has expired"  # the one condition this step tests
  action: "Connect once with a TLS client that verifies the chain and sends no application data. Use bad.example.invalid as the name. Record who issued the certificate, who it was issued to, its validity dates and the verification error."
  example_invocation: "openssl s_client -connect bad.example.invalid:443 -servername bad.example.invalid -verify_return_error"
  if_condition_holds: "The validity end date is in the past, or the client reports a verification error such as an expired or untrusted certificate."
  if_it_does_not: "The certificate is valid and verifies. The recorded observation is stale; re-collect before concluding anything."
  record: "Issuer, subject, not-before, not-after, the client's verification message, the time of the check."
  must_not: ["send credentials", "disable certificate verification", "send application data", "repeat more than once"]
  stop_if: "the connection is refused or times out twice: stop and note the target as unreachable"
```

Every step has **both branches** (what you see if the condition holds, what you see if it does not), what to record, a list of
things it must not do, and when to stop. After the steps there is a **decision guide** that maps their outcomes onto the three
reviewer decisions (`confirmed`, `not_exploitable`, `inconclusive`). The guide advises; a person decides.

### The closed list of step kinds

| Kind | What it is | Network | Intrusiveness |
|---|---|---|---|
| `read_recorded_observation` | Open a stored observation (and its redacted artifact) and note specific fields | none | none |
| `compare_recorded_observations` | Compare two stored observations, for example two principals' answers, field by field | none | none |
| `rerequest_listed_path` | Repeat one recorded `GET` or `HEAD` of a path the scope lists, once, and compare one named header or the status with the recording | one request | single_read |
| `check_cors_for_declared_origin` | Send one `OPTIONS` with one `Origin` the scope declares, and record the CORS headers | one request | single_read |
| `inspect_certificate_field` | One verifying TLS handshake that sends no application data; record certificate fields and the verification result | one connection | single_read |
| `re_resolve_name` | Resolve one declared name and compare the answer with the recording | one lookup | single_read |
| `read_public_document` | Read one public document the scope lists (for example `security.txt`) and note named fields | one request | single_read |
| `rerun_library_probe` | Re-run **one** probe of a library set through the tool (live mode, inside its isolation and budget) to check that a recorded result repeats | one request | single_read |
| `owner_confirmation` | Ask the system's owner a specific question (is this host in use, is this endpoint meant to be public, what version is deployed) and record the answer | none | none |

There is no step kind that sends a payload, a credential guess, a request body of the tester's choosing, a request to an unlisted
path or host, a request that changes state, or a request repeated to apply load. A step cannot be written outside this list.

### The checker (run before a draft is stored; a failing step is removed and the draft says so)

1. The `kind` is on the list and the `intrusiveness` matches the kind.
2. `target` and every path, origin and probe it names are **in the scope**, for an operation the scope allows, and in a
   `GET`/`HEAD`/`OPTIONS` shape. A step for port 80 is dropped when the scope does not list port 80.
3. Placeholders accept only **scope-validated** values (canonical hosts, exact paths), which are shell-safe by construction. A value
   that came from a target (a banner, a header, a model id) appears only inside `record` or `cites` as **quoted data**, never in
   `action` or `example_invocation`.
4. `example_invocation` is allowed only for `inspect_certificate_field`, `rerequest_listed_path`, `check_cors_for_declared_origin`,
   `re_resolve_name` and `read_public_document`, built from a **fixed template** for a standard read-only client, with verification
   **on**, no credentials, no body, redirects **off**, and no shell metacharacters (`; | & $ \` > < ( )`, newlines, `-k`/`--insecure`,
   `--data`, `-X` other than the allowed method). A step that would need a credential says "use the credential for principal NAME" and
   never prints one.
5. Text limits: at most 8 steps per draft, `action` at most 400 characters, control and bidirectional characters removed.
6. Each step cites at least one observation of the same run (the database already forbids a stale one) and states both branches.
7. A step that fails any rule is dropped; the draft shows `validation_steps_dropped: N` with the rule that dropped each, so nothing
   disappears silently.

### Worked examples (from the fixtures)

**Expired, self-signed certificate** (`misconfigured` pack, class `tls_misconfiguration`, assessment `conditional`)

1. `read_recorded_observation`: open the TLS observation; note `not_after`, `self_signed` and the verification result. *Holds:* the
   end date is before the run's time. *Not:* it is later; stop and re-collect.
2. `inspect_certificate_field`: the handshake step above. *Holds:* the client reports an expired or untrusted certificate. *Not:* the
   chain verifies.
3. `compare_recorded_observations`: compare the presented fingerprint with the recorded one. *Holds:* they match, so the observation
   is current. *Not:* they differ; the certificate was replaced; re-collect.
4. `owner_confirmation`: ask whether the service is in use and whether any client pins this certificate. *Guide:* in use and not
   pinned means a client that does not verify is exposed, which supports `confirmed` for "expired certificate in service"; a
   decommissioned host supports `not_exploitable`; no answer is `inconclusive`.

**Missing HSTS and security headers** (class `missing_security_header`)

1. `read_recorded_observation`: note that `strict-transport-security` is absent in the recorded response.
2. `rerequest_listed_path`: one `HEAD` of the listed path over verified TLS; record whether the header is present now. *Holds:* absent.
   *Not:* present (the configuration changed since the run).
3. `owner_confirmation`: ask whether plain HTTP is served at all and whether a redirect to HTTPS exists. (Probing port 80 yourself is
   not a step unless the scope lists it.) *Guide:* header absent and plain HTTP served supports `confirmed` for the downgrade
   condition; HTTPS only with a preload entry supports `not_exploitable`.

**Server banner with a version** (class `information_disclosure`)

1. `compare_recorded_observations`: note the banner as recorded (quoted data) in two responses; are they consistent?
2. `owner_confirmation`: ask for the real deployed version and whether the banner is overridden by a front-end. The tool does **not**
   map a version to known exploits (D-E59); the reviewer can read the vendor's advisories for the version the owner confirms.

**API endpoint that answers without credentials though `expect_auth` is `required`** (`api-targets.md`, assessment `conditional`)

1. `compare_recorded_observations`: compare the anonymous answer with the principal's answer: same status? same field shape?
2. `rerequest_listed_path`: repeat the listed anonymous request **once**, with the same listed parameter values, and compare the
   status and the shape digest. *Holds:* it answers the same way. *Not:* it now refuses; the first answer was transient.
3. `owner_confirmation`: ask whether this endpoint is meant to be public. *Guide:* not meant to be public and the shape contains
   fields the owner considers sensitive supports `confirmed`; meant to be public supports `not_exploitable`.

**AI reply followed a planted canary** (`ai_prompt_injection_susceptibility`, assessment `conditional`)

1. `read_recorded_observation`: open the probe result and its redacted reply; note `canary_present: true` and the finish reason.
2. `rerun_library_probe`: re-run the same probe once through the tool (live mode, inside the isolation, counting against
   `max_model_requests`). *Holds:* the canary appears again. *Not:* it does not; the first result may be non-repeatable.
3. `owner_confirmation`: ask how the system prompt and the retrieval content are separated, and whether this deployment gives the
   model any tools. *Guide:* repeatable, and the deployment gives the model tools or privileged data supports `confirmed`; repeatable
   with no tools and no sensitive data is recorded as a lower-impact `confirmed`; not repeatable is `inconclusive`.

### What a step never does, even in these examples

It never contains an attack string, a crafted request body, a credential, an unlisted host or path, a state-changing method, a
repeated request meant as load, or an instruction to exploit a version. If a draft would need one to be useful, it ships with fewer
steps and the reviewer uses their own method.

## What this does not guarantee

A rule can miss a real flaw (no finding is not no flaw: SE-07). A rule can match something harmless. The CWE list is a suggestion.
The assessment is only as good as the conditions the rule states, which is why they are printed. A human reads every draft.

## Decisions (all approved on 2026-11-21)

| ID | Decision | Status |
|---|---|---|
| D-E56 | A draft carries a proposed class from a closed list, evidence, conditions and CWE suggestions; never a verdict | Approved |
| D-E57 | Exploitability is an assessment with preconditions, attacker position, unknowns and basis; its vocabulary has **no** `confirmed`; only a human reviewer records confirmation, with a reason | Approved |
| D-E58 | A draft carries validation steps: non-destructive, read-only, scope-checked, human-run; the tool does not run them offline | Approved |
| D-E59 | The tool never produces exploit code, attack payloads, attack chains, state-changing instructions or version-specific abuse guidance, whoever asks | Approved |
| D-E60 | All text comes from a reviewed deterministic rule catalogue; the optional model may only rephrase, validated against the rule output | Approved |
