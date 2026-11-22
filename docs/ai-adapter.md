# The optional model adapter (M4)

Status: **built in M4, off by default.** Nothing in the tool needs it; every draft, every report and every exit code is the same with it
off. This file is the contract: what the model may do, what it is sent, how its answer is checked, how it is switched on.

## What it does, and the one thing it may not

A rule writes the sentences of a draft (`docs/correlator.md`). The model may **reword** some of them so they read more plainly. That is
all. It cannot add a class, a condition, a step, a severity, an evidence id or a fact; it cannot change a status, review anything,
choose a target, run a tool or see what a target said. Its output is a *second wording* stored beside the rule's text, labelled as
model-written and unverified; **the rule's sentence stays the authoritative one** everywhere it is shown (D-E60).

| The model may reword | It is never sent |
|---|---|
| a draft's conditions, preconditions, unknowns, attacker position, basis, remediation and severity basis | facts quoted from a target, observation payloads, artifacts, headers, bodies, replies, certificates, any credential, the scope file, the reviewer's name or reason |

The sentences are fixed rule templates filled with numbers, dates, protocol names and scope-validated hosts and paths. With
`mask_hosts` on (the default) each host is replaced by a placeholder (`HOST_A`) before sending and put back after, so the model never
sees an engagement's host names either.

## Providers

* **`anthropic`** (the default when you enable it): the official `anthropic` Python SDK, installed with
  `pip install "scoped-evidence-agent[ai]"` (or `uv tool install "scoped-evidence-agent[ai]"`). Model `claude-opus-5-5` unless you choose
  another with `--model` (a smaller model such as `claude-haiku-5-5` costs less and is enough for rewording). The request carries a
  system prompt, one user message of JSON, `output_config.format` (a JSON schema, so the reply is valid JSON of the exact shape),
  `output_config.effort` `low`, and a token cap. It sends no prefill, no sampling parameters and no tools.
* **`offline`**: a deterministic stand-in that opens no connection. It puts "Put simply: " in front of each sentence so you can try the
  whole path (enable, reword, show, report) without a key. It is also what the tests use.

The **API key** is read from an environment variable (`ANTHROPIC_API_KEY` unless you name another with `--key-env`). It is never written to
the configuration, the database, a log, a report or an error message, is passed only to the SDK client for `https://api.anthropic.com`
(the base URL is fixed in code and an `ANTHROPIC_BASE_URL` in the environment cannot redirect it), and a reply that contains the key
is discarded.

## How it is switched on (and off)

```text
scoped-agent ai enable            # shows what is sent, asks you to type "enable", writes <data-dir>/ai.json (0600)
scoped-agent ai status            # on or off, provider, model, whether the key variable is set (never its value), limits
scoped-agent ai test              # one small request, to check the key and the model work
scoped-agent findings reword RUN  # reword the drafts of a run (add --finding ID for one)
scoped-agent ai disable           # off again; the saved wordings stay
```

`run` never opens a connection, with the model on or off (`docs/cli.md`). If AI is enabled and there are drafts, `run` ends with a one-line
hint to run `findings reword`. `ai enable --provider offline` needs no key and asks nothing; `ai enable --yes` skips the typed word (for
scripts); `--model`, `--key-env` and `--no-mask-hosts` change what is saved. Enabling tells you at once whether the key variable is set.

`findings reword` exits `0` when every call succeeded (a sentence the checks dropped is not a failure; it is counted as kept), `2` when any
call was unavailable, refused, invalid or over budget, and `1` for a policy failure (AI off, key not set, no such run, a broken `ai.json`).
A missing key stops it before any call.

## How the answer is checked (`ai/validation.py`)

The reply is accepted **item by item**. An item that fails is dropped and the rule's own sentence is what shows. Every check is
deterministic code; the model is never asked whether its own answer is acceptable.

1. The reply is JSON of the exact shape (`items`: a list of `{id, text}`), with exactly the ids that were sent, each once.
2. The text is one plain line of letters, digits, space and `. , : ; ' ( ) / _ * ~ -` only: no markup, link, code, brackets, braces,
   `$`, `<`, `>`, quote marks or non-ASCII characters.
3. Its length is within the field's limit and at most twice the original's plus 60.
4. **Protected tokens** (numbers and dates, versions such as `TLSv1.0`, CWE ids, header names such as `Strict-Transport-Security`,
   paths such as `/openapi.json`, host placeholders) that are in the original must all be in the reworded sentence, and the reworded
   sentence may contain none that is not in the original. The model cannot change a number, a date, a header or a host.
5. It may not add a word of verdict or escalation that the original does not use: `confirmed`, `verified`, `proven`, `exploit`,
   `exploitable`, `critical`, `severe`, `definitely`, `certainly`, `guaranteed`, `urgent`, `immediately`, `payload`, `bypass`.
6. It does not contain the API key.

A refusal, a network or API error, a missing key, an unparsable or invalid reply, or a spent budget never stops anything: the draft keeps
its rule text, and the call is recorded as `unavailable`, `refused`, `invalid` or `budget_exhausted` (AE-17).

## What is stored

* `finding_wordings` (append-only): the field and item, the SHA-256 of the original sentence, the wording, the model and the prompt
  version. One wording per item: running `findings reword` again skips what is already worded.
* `model_calls` (append-only): the run, the finding, the provider and model, the prompt version, the SHA-256 of what was sent, items
  sent, accepted and rejected, the token counts, the status, and a short sanitized detail (an error class, never a message that could
  hold a key or a sentence). The prompt itself is **not** stored.
* The audit trail records each call (`model.reword`): who asked, the model, the prompt version, the input hash, the tokens and the
  outcome.

The model has no actor of its own that can write: storing a wording as the model is refused and audited, like any other action the model
cannot take (D-E08).

## Budget (D-E18)

Per run: `max_calls_per_run` (default 25), `max_output_tokens` per call (default 2048) and `max_total_tokens` (default 60000, input
estimated before the call and measured after). Before a call the next one is refused if it could exceed the total; the draft keeps its
rule text and the refusal is recorded. The count includes calls made by earlier `findings reword` commands on the same run. The SDK retries
a failed request twice by itself; a retry is not a separate call here, so the provider's spending limit is the real ceiling (SE-35).

## Reports and screens

`findings show` prints the rule's text and, under it, `wording by a model (not verified; the rule's text above is authoritative):` with one
line per reworded sentence (`condition 2`, `remediation`, ...) and the model and prompt version that wrote them. A report adds a `wordings` list to
each finding (JSON) or a section with the same label (Markdown), plus one note. A report built before a reword, or with AI never used, has no
`wordings` key and no note: it is byte-identical to one built before M4.

## Decisions for this milestone

Status (2026-11-21): **D-E66 to D-E69 are approved by the owner.**

| ID | Decision |
|---|---|
| D-E66 | **The model is an optional rewording step and nothing more**, enforced by the checks above. It is Claude through the official SDK, or the offline stand-in; no other provider in 0.x. *Approved by the owner, 2026-11-21.* |
| D-E67 | **Activation is explicit and easy:** `ai enable` (a typed confirmation that names what is sent), a private `ai.json` with no secret in it, and `findings reword` as the only command that calls a model. `run` stays free of connections. *Approved by the owner, 2026-11-21.* |
| D-E68 | **What is sent is limited to rule sentences with hosts masked by default;** the key comes from an environment variable and goes only to the SDK client for the fixed Anthropic endpoint. *Approved by the owner, 2026-11-21.* |
| D-E69 | **A budget per run** (calls, output tokens, total tokens) and **every failure falls back to the rule's text.** *Approved by the owner, 2026-11-21.* |

These are built at the owner's instruction (2026-11-21) and touch egress and token handling, so the pull request stays open for the
owner's review before it is merged.
