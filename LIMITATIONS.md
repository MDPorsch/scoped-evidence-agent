# Limitations

What this project does not do and what a reader should not conclude from it. Written at M0; it grows with each
milestone. Residual risks are listed, not hidden.

* **SE-01 Offline only.** Nothing here reconnoitres a real target. It collects from fixture packs on disk. The
  spec's live mode is not built (D-E01); until it is, "it works" means "it works on fixtures".
* **SE-02 The scope is the operator's word.** The tool checks that a scope file is well-formed, unexpired and
  bounded. It cannot check that anyone consented to testing. Authorization is confirmed by a human, outside the tool.
* **SE-03 Attribution is not authentication.** The user name recorded on a run or a review is the operating-system
  user. Anyone who can run the command as that user can act as them. This is a single-user local tool.
* **SE-04 Tamper-evident is not tamper-proof.** The audit chain detects an edited or removed row. Someone who can
  replace the whole database file can rewrite it consistently. Filesystem permissions are the only barrier to that.
* **SE-05 Redaction is best effort.** It removes what it recognises: sensitive header names, known credential shapes,
  e-mail addresses. A secret in an unusual place or shape can survive. Nothing stored should be treated as safe to
  publish without a person reading it.
* **SE-06 A draft is not a finding.** Every output is a draft until a human reviewer says otherwise. Severity is not
  assigned by the model and not asserted without evidence.
* **SE-07 "No issue observed" means within the collected coverage.** An operation that errored, timed out or was
  refused is recorded as such, makes the run incomplete (exit code 2), and is never read as clean.
* **SE-08 One observation per operation.** No retries inside a run and no statistics; a flaky target yields an
  error, not a verdict.
* **SE-09 SQLite and one writer.** Transactions are serialised (`BEGIN IMMEDIATE`). This is correct for a local CLI
  and not a design for many concurrent users.
* **SE-10 Python 3.13 on macOS (development) and Linux (CI) only.** Windows is not tested; file-permission
  guarantees (`0600`, `0700`) are POSIX behaviour and do not hold the same way there.
* **SE-11 Only the audit trail and the artifacts are tamper-evident.** Observation and finding rows are protected by constraints
  and by who may write them, not by a hash. Someone who edits `observations.normalized_json` in the database is not detected by
  anything in 0.x. The audit chain would show the row was written, not that it was later changed.
* **SE-12 The audit chain cannot detect the loss of its newest events.** Each event commits to the one before it, so a removed or
  edited event in the middle breaks a link; removing the last few events leaves nothing after them to notice. Detecting that
  needs a head hash kept somewhere the database's owner cannot write, which a local single-user tool does not have.
* **SE-13 The clock is the machine's.** Expiry is checked against the system clock. Anyone who can change the clock can extend a
  scope. The clock is injected into the code (so tests never depend on the date) but is not an environment variable, so a
  stray variable cannot change it.
* **SE-14 Internationalised names are not checked for look-alikes.** A host written as `xn--...` is accepted if it is valid
  IDNA. The tool does not detect that it looks like another name, so a confusable name that is typed into a scope is the
  operator's to notice.
* **SE-15 A purge deletes files before its transaction commits.** If the commit then fails, rows remain whose files are gone and
  reading them reports a missing artifact (it never returns wrong bytes). The receipt counts what was deleted.
* **SE-16 The probe library holds ids, not texts, and nothing has met a real AI system.** A scope can name a reviewed probe set and its
  plan is exact. In 0.x the offline adapter answers a probe from a recorded reply and sends nothing, so no probe text exists yet; the
  texts arrive with live mode (M5).
* **SE-17 AI facts are simple checks, not judgements.** "A canary appeared" is a substring test and the structure flags are pattern
  matches. A canary echoed inside a refusal still counts as present, and a flag says nothing about whether the structure is
  dangerous. A human decides.
* **SE-18 Probe consumption is bounded by the scope, not measured live.** The worst case is computed from the limits you wrote. A
  target that bills differently, counts tokens differently or ignores a token limit is outside what this tool can see.
* **SE-19 A complete collection with no draft is exit code 0.** A run that collected everything it planned and applied every rule, and
  found nothing, exits `0` and drafts nothing. That is not evidence that nothing is wrong; the run prints a note saying so (SE-24).
* **SE-20 Redaction is pattern-based.** A secret in a shape no pattern knows (a custom token format, a password in prose, a value
  split across lines) is stored. Header names, key=value pairs, private-key blocks and common token shapes are covered; see
  `docs/fixture-format.md`. Review what a run stored (`observations show`) before sharing it.
* **SE-21 The target's own e-mail addresses are kept.** An address at the target's host or a subdomain (a `security.txt` contact) is
  public by design and is stored. A personal address at the target's own domain is stored too.
* **SE-22 Offline collection is sequential.** Operations run one at a time in plan order so a run is reproducible. Parallelism arrives
  with live mode, where the scope's `max_parallelism` applies.
* **SE-23 A parsed document keeps only a few named facts, and the longest lists are cut to fit.** A very large `robots.txt` or OpenAPI
  document is summarised (first entries kept, last dropped) so it is collected rather than refused; the stored artifact keeps the
  redacted text up to the scope's byte limit.
* **SE-24 No draft is not no flaw.** The version-1 catalogue has twelve rules (`docs/correlator.md`). It does not cover an expired
  `security.txt`, cookie attributes (cookie values are redacted whole), cache headers, CSP quality, mixed content, certificate chain
  validity beyond the flags listed, authorization flaws, or anything that needs a request the scope does not list. A rule can also fire
  on something harmless: every draft is for a person to read.
* **SE-25 Facts are quoted only when they have a strict shape.** A banner, a path, a host or a scheme name that is long or unusual is
  counted in the draft's condition but not shown, so a reader may need `observations show` to see what a target sent.
* **SE-26 Severity is not decided.** A draft carries a suggested severity with its basis; the tool's own severity is `unknown`, and
  nothing in 0.x stores a person's. Confidence is a rule's table value, not a measured probability.
* **SE-27 `not_exploitable` is recorded as a false positive.** The status `FALSE_POSITIVE` closes the finding; the review row keeps the
  exact decision and the reason. `inconclusive` leaves it open and can be repeated.
* **SE-28 Identity is typed.** `--reviewer` is a name the person gives, in line with identity as attribution (D-E06); the typed
  confirmation stops an accident or a script by habit, not a determined person with the database.
* **SE-29 Reports are not audited, and a run is never closed.** Exporting changes nothing, so it adds no audit event; the run is never
  moved to `EXPORTED`. Who exported what is the file system's business. A reviewer's name and reason are included, redacted for secrets
  but otherwise as typed.
* **SE-30 A path through a symbolic link is refused for a report,** including a system directory that is itself a link (`/tmp` on macOS).
  Use the real path.
* **SE-31 The step list is advice.** Validation steps are text built from templates. The tool does not run them (offline it cannot), and
  `rerun_library_probe` and `check_cors_for_declared_origin` cannot be acted on in 0.x (they need live mode, and a scope that declares
  an origin, which arrives with API targets).
* **SE-37 API targets are offline and rule-free in 0.x.** An API scope is validated, planned and answered from a fixture pack: no API is
  contacted, no credential is read, and no rule reads the evidence, so a run drafts nothing (exit `0` when complete). Whether two
  principals' answers show an authorization flaw is a person's call (or `boundarycheck`'s); the tool records the facts side by side.
* **SE-38 A shape can still reveal.** Field names, types and lengths are kept; values are not. A field name is data from the target: a
  short plain name is stored, a longer or odd one as `?`, the keys of an object with more than sixteen as `{key}`. A short key that
  is itself an identifier (an object with a few keys named by user id) is stored as written.
* **SE-39 The three flags are pattern matches.** A trace that no pattern knows, or a harmless word that looks like a switch, is
  missed or flagged. They tell a reviewer where to look; they decide nothing.
* **SE-40 The `{name}` values are listed, not discovered.** Only the values the scope lists are asked, up to five per parameter and four
  parameters per endpoint. The tool never walks a range, a sequence or a wordlist, and a spec's own endpoints are inventory, never a
  request.
* **SE-41 The container isolation has been run for real in two places and live mode once.** Seven tests pass on a GitHub-hosted Ubuntu runner and
  on a Mac with Colima (the proof, the firewall against forbidden addresses with the policy bypassed, a positive control for an allowed pair, the
  posture, a stray job refused, an unwritable output directory failing the proof), and one `live run` (DNS, TLS and three GETs) has gone end to
  end through the real container against the author's own site. Not exercised: IPv6, Docker Desktop, rootless Docker, Podman, an API, AI or
  authenticated target, a multi-host scope. A clean run is not a guarantee about the next one (D-E46).
* **SE-42 The address policy cannot tell whose address it is.** A public address may belong to a CDN, a shared host or a client's
  neighbour. The scope's hosts are the ones you wrote; the tool pins what they resolve to and cannot know who else answers there.
* **SE-43 Authorization is a declaration.** The block, the flag and the approval are a deliberate pause and a record; in a single-user tool
  they are the same person. The tool cannot verify that anyone authorized the test (SE-03).
* **SE-44 Live mode collects only a little in this version.** DNS, TLS, HTTP metadata, AI model lists and API reads; `ai_probe` is refused
  (D-E74); a credential is a bearer token for one declared host; there are no cookies, logins, proxies, redirects or keychain support.
* **SE-45 The clock is yours.** The authorization window and approval expiry use the local clock.
* **SE-46 What a CNAME or a redirect says is data.** It is recorded and never contacted: a target that points elsewhere is a finding for a
  person, and the scope grows only when you edit it.
* **SE-32 The model can only reword, and it can reword badly.** The checks keep every number, date, version, header name, path and host
  of the rule's sentence and refuse verdict words, markup and anything over the length limit, but they cannot tell that a sentence still
  *means* the same. A plausible but slightly wrong wording passes. That is why the rule's own text is always shown first and the wording
  is labelled as not verified (`docs/ai-adapter.md`).
* **SE-33 Switching the model on sends rule sentences to a third party.** Only after `ai enable`, only from `findings reword` and
  `ai test`, only the fixed sentences of a draft with hosts masked by default, to `api.anthropic.com`. A sentence may still name a
  technology the engagement would rather not share (a protocol version, a header, a path); `--no-mask-hosts` sends host names too. The
  provider's own retention and terms apply. Nothing is sent while AI is off, and a person can read exactly what would be sent in
  `docs/ai-adapter.md` before typing `enable`.
* **SE-34 The key lives in an environment variable.** The tool never stores, logs or prints it and discards a reply that contains it, but
  anything else that can read the process environment can read it. A secret manager integration is not part of 0.x.
* **SE-35 Calls are bounded per run, not per day.** `max_calls_per_run`, `max_output_tokens` and `max_total_tokens` stop a run; running
  `findings reword` on many runs, or the SDK's own two retries of a failed request, can spend more in total. The provider's spending limit
  is the real ceiling.
* **SE-36 One model family, no fallback between providers.** 0.x supports Claude through the official SDK and an offline stand-in. If the
  provider is down the drafts keep the rule's text and the call is recorded as `unavailable`.
