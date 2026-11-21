# Security policy

## Reporting a vulnerability

Please report privately, not in a public issue: use GitHub's **Report a vulnerability** button on the repository's Security tab
(https://github.com/MDPorsch/scoped-evidence-agent/security/advisories/new). Include what you did, what you expected and what
happened. Expect an acknowledgement; this is a single-maintainer project, so there is no response-time guarantee.

## What is in scope

Anything that lets scope be widened, a secret be stored or leaked, the audit trail be altered unnoticed, a model
or a response change what the tool does, or a path escape its directory. Offline use is the only supported mode
today (see `DECISIONS.md`, D-E01); there is no network code to attack.

## What is not

* Authorization to test a third-party system. This tool never grants it: a scope file is a restriction.
* Operating-system-level attacks by someone who already has your account (`LIMITATIONS.md`, SE-03 and SE-04).

## Supported versions

Pre-alpha: only the latest `main`.
