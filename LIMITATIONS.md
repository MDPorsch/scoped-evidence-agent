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
* **SE-19 A complete collection with no correlation is exit code 0.** Until the correlator exists (M3), a run that collected everything
  it planned exits `0` and drafts nothing. That is not evidence that nothing is wrong; the run prints a note saying so.
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
