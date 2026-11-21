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
