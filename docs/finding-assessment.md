# What a draft finding says: class, exploitability assessment, validation steps

Status: **proposed**, for your review (D-E56 to D-E60). Built in M3, with the correlator, after the collectors exist.

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

## Validation steps are checked, not trusted

Before a draft is stored, each step is checked: it may name only an operation, host, path or endpoint that is in the scope, it
must be a read, and it must be one of a small set of step kinds (compare a header, compare two recorded answers, re-request a listed
path, inspect a certificate field). A step that fails the check is removed and the draft says so. The tool never runs a validation
step itself in offline mode; in live mode it runs only the scope's own operations, inside the isolation (`remote-live-design.md`).

## What this does not guarantee

A rule can miss a real flaw (no finding is not no flaw: SE-07). A rule can match something harmless. The CWE list is a suggestion.
The assessment is only as good as the conditions the rule states, which is why they are printed. A human reads every draft.

## Decisions I need from you

| ID | Decision | My recommendation |
|---|---|---|
| D-E56 | A draft carries a proposed class from a closed list, evidence, conditions and CWE suggestions; never a verdict | yes |
| D-E57 | Exploitability is an assessment with preconditions, attacker position, unknowns and basis; its vocabulary has **no** `confirmed`; only a human reviewer records confirmation, with a reason | yes |
| D-E58 | A draft carries validation steps: non-destructive, read-only, scope-checked, human-run; the tool does not run them offline | yes |
| D-E59 | The tool never produces exploit code, attack payloads, attack chains, state-changing instructions or version-specific abuse guidance, whoever asks | yes (and I would not build around it) |
| D-E60 | All text comes from a reviewed deterministic rule catalogue; the optional model may only rephrase, validated against the rule output | yes |
